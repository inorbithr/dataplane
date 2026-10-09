//! The local API, phase 1 subset (RFC 0100.4 1.6; RFC 0090.1): the same paths and shapes
//! as the platform's public API for what this agent holds, answered from this machine, with
//! no network at all.
//!
//! | Route | Public operation | Answered from |
//! |---|---|---|
//! | `GET /v1/accounts/orgs/{org}/monitors` | `ConnectionsService.ListMonitors` | `checks.toml` and the trial store |
//! | `GET /v1/accounts/orgs/{org}/monitors/{id}` | `ConnectionsService.GetMonitor` | the same |
//! | `GET /v1/accounts/orgs/{org}/monitors/{id}/runs` | `ConnectionsService.ListMonitorRuns` | the trial store |
//! | `GET /v1/accounts/orgs/{org}/agents/{agent}` | `AgentsService.GetAgent` | the agent's state |
//! | `GET /v1/accounts/orgs/{org}/agents/{agent}/host` | agent only | the host sampler and the trial store |
//! | `GET /v1/agents/{agent}/ledger` | ADR 0049 | the egress ledger |
//! | `GET /v1/accounts/orgs/{org}/agents/{agent}/share` | agent only | the policy's `[share]` |
//!
//! Every answer carries `"where": "agent"` (RFC 0090.1 §3: a local-only field is added,
//! never renamed). Errors follow the response contract (RFC 0033): `{code, error,
//! details, request_id}`. Another account's or another agent's id is `not_found`, never a
//! refusal that confirms it exists.
//!
//! Always signed in: unlike the read-only page, the API answers only with the page's
//! token (a bearer, or the session cookie `/auth` gives a browser), on loopback too. The
//! caller in [`super::handle`] checks that before calling [`route`].

use std::fmt::Write as _;

use serde_json::{Value, json};

use super::Context;
use crate::state::JobRecord;

/// Runs per page by default, and the most.
const DEFAULT_PAGE: usize = 50;
/// Ledger entries returned.
const LEDGER_PAGE: usize = 200;
/// Host readings returned.
const HOST_PAGE: usize = 120;
/// The id prefix of a monitor this agent declared.
pub(super) const LOCAL_MONITOR: &str = "local-";

/// An answer: status and JSON body.
pub(super) type Answer = (u16, String);

/// Whether the path is the local API's.
#[must_use]
pub(super) fn is_api(path: &str) -> bool {
    path.starts_with("/v1/")
}

/// The local API's answer for a GET, or a 404 in the response contract.
#[must_use]
pub(super) fn route(ctx: &Context, path: &str, query: &str) -> Answer {
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').skip(1).collect();
    let q = Query::parse(query);
    let agent_id = ctx.state.snapshot().agent.agent_id.unwrap_or_default();
    match parts.as_slice() {
        ["v1", "agents", agent, "ledger"] => {
            if *agent != agent_id {
                return not_found("agent");
            }
            ledger(ctx, &q)
        }
        ["v1", "accounts", "orgs", org, rest @ ..] => {
            if *org != ctx.account_id || ctx.account_id.is_empty() {
                return not_found("account");
            }
            match rest {
                ["monitors"] => list_monitors(ctx, &q, &agent_id),
                ["monitors", id] => match monitor(ctx, id, &agent_id) {
                    Some(m) => ok(&json!({"monitor": m})),
                    None => not_found("monitor"),
                },
                ["monitors", id, "runs"] => runs(ctx, id, &q),
                ["agents", agent] if *agent == agent_id => agent_doc(ctx),
                ["agents", agent, "host"] if *agent == agent_id => host(ctx),
                ["agents", agent, "share"] if *agent == agent_id => share(ctx),
                ["agents", _] | ["agents", _, "host" | "share"] => not_found("agent"),
                _ => not_found("route"),
            }
        }
        _ => not_found("route"),
    }
}

/// `401` in the response contract.
#[must_use]
pub(super) fn unauthenticated() -> Answer {
    error(
        401,
        "unauthenticated",
        "sign in with this agent's token: `iohr agent page --open`, or send it as a bearer",
    )
}

/// `405`: the local API is read-only in phase 1.
#[must_use]
pub(super) fn read_only() -> Answer {
    error(
        405,
        "unimplemented",
        "the local API is read-only in this version; change checks in checks.toml",
    )
}

fn ok(v: &Value) -> Answer {
    (200, v.to_string())
}

fn not_found(what: &str) -> Answer {
    error(404, "not_found", &format!("no such {what} on this agent"))
}

fn error(status: u16, code: &str, msg: &str) -> Answer {
    (
        status,
        json!({
            "code": code,
            "error": msg,
            "details": [],
            "request_id": uuid::Uuid::now_v7().to_string(),
        })
        .to_string(),
    )
}

#[derive(Debug, Default)]
struct Query {
    page_size: Option<usize>,
    page_token: Option<String>,
    status: Option<String>,
    agent_id: Option<String>,
    category: Option<String>,
}

impl Query {
    fn parse(q: &str) -> Self {
        let mut out = Self::default();
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = url::form_urlencoded::parse(format!("v={v}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            match k {
                "page_size" => out.page_size = v.parse().ok(),
                "page_token" if !v.is_empty() => out.page_token = Some(v),
                "status" if !v.is_empty() => out.status = Some(v.to_ascii_lowercase()),
                "agent_id" if !v.is_empty() => out.agent_id = Some(v),
                "category" if !v.is_empty() => out.category = Some(v),
                _ => {}
            }
        }
        out
    }
}

/// The health a declared check's runs give: `down` after `fail_after` failures in a
/// row, `up` after a success, `unknown` with no runs.
fn health(runs: &[JobRecord], fail_after: u8) -> &'static str {
    let Some(last) = runs.last() else {
        return "unknown";
    };
    if last.verdict == "ok" {
        return "up";
    }
    let n = usize::from(fail_after.max(1));
    if runs.len() >= n && runs.iter().rev().take(n).all(|r| r.verdict != "ok") {
        "down"
    } else {
        "up"
    }
}

fn monitor(ctx: &Context, id: &str, agent_id: &str) -> Option<Value> {
    let key = id.strip_prefix(LOCAL_MONITOR)?;
    let checks = ctx.checks.as_ref()?;
    let c = checks.entries.iter().find(|c| c.key == key)?;
    let runs = ctx.state.check_runs().remove(key).unwrap_or_default();
    let wire = c.to_wire();
    let mut check = serde_json::Map::new();
    for f in ["surface", "target", "expect", "refuse_by"] {
        if let Some(v) = wire.get(f) {
            check.insert(f.into(), v.clone());
        }
    }
    Some(json!({
        "monitor_id": format!("{LOCAL_MONITOR}{}", c.key),
        "connection_id": "",
        "managed_by": agent_id,
        "agent_id": agent_id,
        "check": Value::Object(check),
        "rfc": c.rfc.clone().unwrap_or_default(),
        "name": c.label.clone().unwrap_or_else(|| c.key.clone()),
        "interval_secs": c.every_secs,
        "fail_after": c.fail_after,
        "state": "active",
        "health": health(&runs, c.fail_after),
        "executor": {"kind": "agent", "agent_id": agent_id},
        "last_run_at": runs.last().map(|r| r.at.clone()).unwrap_or_default(),
        "category": c.category.clone().unwrap_or_default(),
        "tags": c.tags,
        "where": "agent",
    }))
}

fn list_monitors(ctx: &Context, q: &Query, agent_id: &str) -> Answer {
    if q.agent_id.as_deref().is_some_and(|a| a != agent_id) {
        return ok(&json!({"monitors": [], "next_page_token": "", "where": "agent"}));
    }
    let monitors: Vec<Value> = ctx
        .checks
        .as_ref()
        .map(|c| {
            c.entries
                .iter()
                .filter(|c| {
                    q.category
                        .as_deref()
                        .is_none_or(|w| c.category.as_deref() == Some(w))
                })
                .filter_map(|c| monitor(ctx, &format!("{LOCAL_MONITOR}{}", c.key), agent_id))
                .collect()
        })
        .unwrap_or_default();
    ok(&json!({"monitors": monitors, "next_page_token": "", "where": "agent"}))
}

fn run_json(id: i64, r: &JobRecord) -> Value {
    json!({
        "run_id": format!("run-{id}"),
        "at": r.at,
        "status": r.verdict,
        "ok": r.verdict == "ok",
        "latency_ms": r.latency_ms,
        "status_code": r.status_code,
        "error_class": r.error_class.clone().or_else(|| r.reason.clone()).unwrap_or_default(),
        "invariant": "",
        "failure": "",
    })
}

fn runs(ctx: &Context, id: &str, q: &Query) -> Answer {
    let Some(key) = id.strip_prefix(LOCAL_MONITOR) else {
        return not_found("monitor");
    };
    if !ctx
        .checks
        .as_ref()
        .is_some_and(|c| c.entries.iter().any(|c| c.key == key))
    {
        return not_found("monitor");
    }
    let size = q
        .page_size
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, crate::store::MAX_PAGE);
    let ok_only = match q.status.as_deref() {
        Some("ok" | "passed" | "up") => Some(true),
        Some("failed" | "down" | "not_ok") => Some(false),
        _ => None,
    };
    let Some(store) = ctx.state.store() else {
        // No trial store: what is in memory, newest first, one page.
        let mem = ctx.state.check_runs().remove(key).unwrap_or_default();
        let runs: Vec<Value> = mem
            .iter()
            .rev()
            .filter(|r| ok_only.is_none_or(|o| (r.verdict == "ok") == o))
            .take(size)
            .enumerate()
            .map(|(i, r)| run_json(i64::try_from(i).unwrap_or(0), r))
            .collect();
        return ok(&json!({"runs": runs, "next_page_token": "", "where": "agent"}));
    };
    let before = q.page_token.as_deref().and_then(|t| t.parse::<i64>().ok());
    match store.runs(key, size + 1, before, ok_only) {
        Ok(mut rows) => {
            let next = if rows.len() > size {
                rows.truncate(size);
                rows.last().map(|r| r.id.to_string()).unwrap_or_default()
            } else {
                String::new()
            };
            let runs: Vec<Value> = rows.iter().map(|r| run_json(r.id, &r.record)).collect();
            ok(&json!({"runs": runs, "next_page_token": next, "where": "agent"}))
        }
        Err(e) => error(500, "internal", &e.to_string()),
    }
}

fn agent_doc(ctx: &Context) -> Answer {
    let s = ctx.state.snapshot();
    ok(&json!({
        "agent": {
            "agent_id": s.agent.agent_id,
            "name": s.agent.name,
            "environment": s.agent.environment,
            "version": s.agent.version,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "status": if s.revoked { "revoked" } else if s.connected { "connected" } else { "offline" },
            "domains": s.policy.domains,
            "capabilities": s.policy.capabilities,
            "policy_hash": s.policy.hash,
            "last_seen_at": s.last_heartbeat_at,
            "where": "agent",
            "store": ctx.state.store().map(|st| json!({
                "kind": "trial",
                "note": "trial storage, not for production",
                "path": st.path().display().to_string(),
            })),
        }
    }))
}

fn host(ctx: &Context) -> Answer {
    let s = ctx.state.snapshot();
    let readings = ctx
        .state
        .store()
        .and_then(|st| st.host(HOST_PAGE).ok())
        .unwrap_or_default();
    ok(&json!({
        "host": {
            "latest": s.host,
            "report": s.host_report,
            "readings": readings,
        },
        "where": "agent",
    }))
}

fn share(ctx: &Context) -> Answer {
    let share = ctx.policy.share();
    let mut v = serde_json::to_value(&share).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.insert("where".into(), json!("agent"));
    }
    ok(&json!({"share": v, "where": "agent"}))
}

fn ledger(ctx: &Context, q: &Query) -> Answer {
    let Some(l) = &ctx.ledger else {
        return ok(&json!({
            "entries": [],
            "totals": {},
            "kept": false,
            "where": "agent",
        }));
    };
    let n = q.page_size.unwrap_or(LEDGER_PAGE).clamp(1, LEDGER_PAGE);
    let entries = l.recent(n);
    let (seq, head) = l.head();
    let mut problem = String::new();
    if let Some(p) = l.problem() {
        let _ = write!(problem, "{p}");
    }
    ok(&json!({
        "entries": entries,
        "totals": l.totals(),
        "head": {"seq": seq, "hash": head},
        "problem": problem,
        "kept": true,
        "where": "agent",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(v: &str) -> JobRecord {
        JobRecord {
            verdict: v.into(),
            ..JobRecord::default()
        }
    }

    #[test]
    fn health_follows_fail_after() {
        assert_eq!(health(&[], 2), "unknown");
        assert_eq!(health(&[rec("ok")], 2), "up");
        assert_eq!(health(&[rec("ok"), rec("failed")], 2), "up");
        assert_eq!(health(&[rec("failed"), rec("failed")], 2), "down");
        assert_eq!(health(&[rec("failed"), rec("ok")], 2), "up");
    }

    #[test]
    fn query_parses_and_decodes() {
        let q = Query::parse("page_size=5&page_token=12&status=FAILED&agent_id=agt%5F1");
        assert_eq!(q.page_size, Some(5));
        assert_eq!(q.page_token.as_deref(), Some("12"));
        assert_eq!(q.status.as_deref(), Some("failed"));
        assert_eq!(q.agent_id.as_deref(), Some("agt_1"));
    }
}
