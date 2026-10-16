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
//! | `GET /v1/agents/self` | agent only | which account and agent answer here |
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
use super::auth::Person;
use super::configs;
use crate::checks_file::{DeclaredCheck, Kind, RefuseBy};
use crate::policy::Role;
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
pub(super) fn route(
    ctx: &Context,
    path: &str,
    query: &str,
    person: &Person,
    csrf: Option<&str>,
) -> Answer {
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').skip(1).collect();
    let q = Query::parse(query);
    let agent_id = ctx.state.snapshot().agent.agent_id.unwrap_or_default();
    match parts.as_slice() {
        ["v1", "agents", "self"] => self_doc(ctx, &agent_id, person, csrf),
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
                ["monitors", ..]
                    if !crate::extensions::running("inorbit/monitors", &ctx.policy, &ctx.lock) =>
                {
                    not_found("monitor (inorbit/monitors is not installed on this agent)")
                }
                ["monitors"] => list_monitors(ctx, &q, &agent_id),
                ["monitors", id] => match monitor(ctx, id, &agent_id) {
                    Some(m) => ok(&json!({"monitor": m})),
                    None => not_found("monitor"),
                },
                ["monitors", id, "runs"] => runs(ctx, id, &q),
                ["agents", agent] if *agent == agent_id => agent_doc(ctx),
                ["agents", agent, "host"] if *agent == agent_id => host(ctx),
                ["agents", agent, "share"] if *agent == agent_id => share(ctx),
                ["agents", agent, "config", "files"] if *agent == agent_id => {
                    config_files(ctx, person)
                }
                ["agents", agent, "config", "files", name] if *agent == agent_id => {
                    config_file(ctx, person, name)
                }
                ["agents", agent, "config", "files", name, "versions"] if *agent == agent_id => {
                    config_versions(ctx, name)
                }
                ["agents", agent, "config", "files", name, "versions", id]
                    if *agent == agent_id =>
                {
                    config_version(ctx, name, id)
                }
                ["agents", agent, "config", "export"] if *agent == agent_id => {
                    ok(&json!({"text": configs::export(ctx), "where": "agent"}))
                }
                ["agents", agent, "extensions"] if *agent == agent_id => extensions(ctx, person),
                ["agents", agent, "audit"] if *agent == agent_id => audit(ctx, person),
                ["agents", agent, "verifications", ..]
                    if *agent == agent_id
                        && !crate::extensions::running(
                            "inorbit/verify",
                            &ctx.policy,
                            &ctx.lock,
                        ) =>
                {
                    not_found("verification (inorbit/verify is not installed on this agent)")
                }
                ["agents", agent, "verifications"] if *agent == agent_id => verifications(ctx),
                ["agents", agent, "verifications", id] if *agent == agent_id => {
                    verification(ctx, id)
                }
                ["agents", ..] => not_found("agent"),
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

/// `403` in the response contract.
#[must_use]
pub(super) fn forbidden(msg: &str) -> Answer {
    error(403, "permission_denied", msg)
}

/// `405`: what the local API does not change.
#[must_use]
pub(super) fn read_only() -> Answer {
    error(
        405,
        "unimplemented",
        "this route of the local API is read-only",
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
    from: Option<String>,
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
                "from" if !v.is_empty() => out.from = Some(v),
                "agent_id" if !v.is_empty() => out.agent_id = Some(v),
                "category" if !v.is_empty() => out.category = Some(v),
                _ => {}
            }
        }
        out
    }
}

/// Whether a run passed (`docs/checks.md`): a `[[check]]` when the target answered as
/// expected (`ok`); a `[[refuse]]` when the target was refused, by the policy (`refused`)
/// or by the target's own answer in `expect` (`ok`).
fn passed(kind: Kind, refuse_by: Option<RefuseBy>, r: &JobRecord) -> bool {
    match (kind, refuse_by) {
        (Kind::Check, _) | (Kind::Refuse, Some(RefuseBy::Answer) | None) => r.verdict == "ok",
        (Kind::Refuse, Some(RefuseBy::Policy | RefuseBy::Platform)) => r.verdict == "refused",
    }
}

/// Whether a run of `c` passed (for the verifier).
pub(super) fn passed_for(c: &DeclaredCheck, r: &JobRecord) -> bool {
    passed(c.kind, c.refuse_by, r)
}

/// The health a declared check's runs give: `down` after `fail_after` failures in a
/// row, `up` after a pass, `unknown` with no runs.
fn health(runs: &[JobRecord], fail_after: u8, ok: impl Fn(&JobRecord) -> bool) -> &'static str {
    let Some(last) = runs.last() else {
        return "unknown";
    };
    if ok(last) {
        return "up";
    }
    let n = usize::from(fail_after.max(1));
    if runs.len() >= n && runs.iter().rev().take(n).all(|r| !ok(r)) {
        "down"
    } else {
        "up"
    }
}

fn declared<'a>(ctx: &'a Context, key: &str) -> Option<&'a DeclaredCheck> {
    ctx.checks.as_ref()?.entries.iter().find(|c| c.key == key)
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
        "health": health(&runs, c.fail_after, |r| passed(c.kind, c.refuse_by, r)),
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

fn run_json(id: i64, r: &JobRecord, ok: bool) -> Value {
    json!({
        "run_id": format!("run-{id}"),
        "at": r.at,
        "status": r.verdict,
        "ok": ok,
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
    let Some(c) = declared(ctx, key) else {
        return not_found("monitor");
    };
    let pass = |r: &JobRecord| passed(c.kind, c.refuse_by, r);
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
            .filter(|r| ok_only.is_none_or(|o| pass(r) == o))
            .filter(|r| q.from.as_deref().is_none_or(|f| r.at.as_str() >= f))
            .take(size)
            .enumerate()
            .map(|(i, r)| run_json(i64::try_from(i).unwrap_or(0), r, pass(r)))
            .collect();
        return ok(&json!({"runs": runs, "next_page_token": "", "where": "agent"}));
    };
    let before = q.page_token.as_deref().and_then(|t| t.parse::<i64>().ok());
    // What "passed" is stored as for this check: `ok`, or `refused` for a policy guard.
    let pass_verdict = match (c.kind, c.refuse_by) {
        (Kind::Refuse, Some(RefuseBy::Policy | RefuseBy::Platform)) => "refused",
        _ => "ok",
    };
    let verdict = ok_only.map(|o| (pass_verdict, o));
    match store.runs(key, size + 1, before, verdict, q.from.as_deref()) {
        Ok(mut rows) => {
            let next = if rows.len() > size {
                rows.truncate(size);
                rows.last().map(|r| r.id.to_string()).unwrap_or_default()
            } else {
                String::new()
            };
            let runs: Vec<Value> = rows
                .iter()
                .map(|r| run_json(r.id, &r.record, pass(&r.record)))
                .collect();
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

/// `GET /v1/agents/self` (agent only): who answers here, so a console that opens on this
/// agent knows which `{org_id}` and `{agent_id}` to ask for.
fn self_doc(ctx: &Context, agent_id: &str, person: &Person, csrf: Option<&str>) -> Answer {
    let s = ctx.state.snapshot();
    let running: Vec<&str> = crate::extensions::builtins()
        .iter()
        .filter(|m| crate::extensions::running(m.id, &ctx.policy, &ctx.lock))
        .map(|m| m.id)
        .collect();
    ok(&json!({
        "viewer": {
            "who": person.who,
            "name": person.name,
            "role": person.role.as_str(),
            "mode": person.mode,
        },
        "csrf": csrf,
        "extensions": running,
        "account_id": ctx.account_id,
        "agent_id": agent_id,
        "name": s.agent.name,
        "environment": s.agent.environment,
        "version": s.agent.version,
        "connected": s.connected,
        "store": if ctx.state.store().is_some() { "trial" } else { "memory" },
        "where": "agent",
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

// ---- configuration management (configs.rs) --------------------------------------------

fn file_of(ctx: &Context, name: &str) -> Option<configs::Managed> {
    configs::managed(ctx).into_iter().find(|f| f.name == name)
}

fn config_files(ctx: &Context, person: &Person) -> Answer {
    let files: Vec<Value> = configs::managed(ctx)
        .iter()
        .map(|f| {
            let text = configs::read(&f.path).unwrap_or_default();
            let versions = ctx
                .state
                .store()
                .and_then(|s| s.versions(f.name, 1).ok())
                .and_then(|v| v.into_iter().next());
            json!({
                "name": f.name,
                "what": f.what,
                "sha": configs::sha(&text),
                "lines": text.lines().count(),
                "edit_role": f.edit.as_str(),
                "can_edit": person.role >= f.edit,
                "last_change": versions,
            })
        })
        .collect();
    ok(&json!({"files": files, "where": "agent"}))
}

fn config_file(ctx: &Context, person: &Person, name: &str) -> Answer {
    let Some(f) = file_of(ctx, name) else {
        return not_found("file");
    };
    match configs::read(&f.path) {
        Ok(text) => ok(&json!({
            "name": f.name,
            "what": f.what,
            "sha": configs::sha(&text),
            "text": text,
            "edit_role": f.edit.as_str(),
            "can_edit": person.role >= f.edit,
            "where": "agent",
        })),
        Err(e) => error(500, "internal", &format!("{name}: {e}")),
    }
}

fn config_versions(ctx: &Context, name: &str) -> Answer {
    if file_of(ctx, name).is_none() {
        return not_found("file");
    }
    let versions = ctx
        .state
        .store()
        .and_then(|s| s.versions(name, 200).ok())
        .unwrap_or_default();
    ok(&json!({"versions": versions, "kept": ctx.state.store().is_some(), "where": "agent"}))
}

fn config_version(ctx: &Context, name: &str, id: &str) -> Answer {
    let Some(f) = file_of(ctx, name) else {
        return not_found("file");
    };
    let Some(v) = id
        .parse::<i64>()
        .ok()
        .and_then(|id| ctx.state.store()?.version(name, id).ok().flatten())
    else {
        return not_found("version");
    };
    let now = configs::read(&f.path).unwrap_or_default();
    let diff = configs::diff_json(&now, v.text.as_deref().unwrap_or(""));
    ok(&json!({"version": v, "diff_from_current": diff, "where": "agent"}))
}

// ---- extensions ------------------------------------------------------------------------

fn extensions(ctx: &Context, person: &Person) -> Answer {
    let list: Vec<Value> = crate::extensions::builtins()
        .iter()
        .map(|m| {
            json!({
                "manifest": m,
                "state": crate::extensions::state(m, &ctx.policy, &ctx.lock),
                "can_change": person.role >= Role::Admin && !m.required,
            })
        })
        .collect();
    ok(&json!({
        "extensions": list,
        "catalogue": {
            "available": false,
            "why": "the full catalogue is read with your own InOrbit sign-in, which the local console does not have yet; it is at https://console.inorbit.hr/extensions/",
        },
        "where": "agent",
    }))
}

// ---- verify (verify.rs) ----------------------------------------------------------------

fn verifications(ctx: &Context) -> Answer {
    let Some(store) = ctx.state.store() else {
        return ok(&json!({"verifications": [], "kept": false, "where": "agent"}));
    };
    match store.verifications(100, None) {
        Ok(vs) => {
            let list: Vec<Value> = vs
                .into_iter()
                .map(|v| super::verify::with_record(ctx, v))
                .collect();
            ok(&json!({"verifications": list, "kept": true, "where": "agent"}))
        }
        Err(e) => error(500, "internal", &e.to_string()),
    }
}

fn verification(ctx: &Context, id: &str) -> Answer {
    let Some(id) = id.strip_prefix("ver-").and_then(|i| i.parse::<i64>().ok()) else {
        return not_found("verification");
    };
    match ctx
        .state
        .store()
        .and_then(|s| s.verifications(1, Some(id)).ok())
        .and_then(|v| v.into_iter().next())
    {
        Some(v) => {
            ok(&json!({"verification": super::verify::with_record(ctx, v), "where": "agent"}))
        }
        None => not_found("verification"),
    }
}

fn create_verification(ctx: &Context, person: &Person, body: &[u8]) -> (u16, WriteOut) {
    if !crate::extensions::running("inorbit/verify", &ctx.policy, &ctx.lock) {
        return out(not_found(
            "verification (inorbit/verify is not installed on this agent)",
        ));
    }
    if person.role < Role::Member {
        return noted(
            forbidden("starting a verification needs the member role"),
            "verify.create",
            "-",
            "refused: role",
            "",
        );
    }
    let Ok(n) = serde_json::from_slice::<super::verify::NewVerification>(body) else {
        return out(error(
            400,
            "invalid_argument",
            "send {\"name\", \"claims\": [check names], \"change_at\", \"window_secs\", \"reason\"}",
        ));
    };
    let change_at = match super::verify::check(ctx, &n) {
        Ok(t) => t,
        Err(e) => return out(error(400, "invalid_argument", &e)),
    };
    let Some(store) = ctx.state.store() else {
        return out(error(
            412,
            "failed_precondition",
            "verifications are kept in the trial store, which is off ([local] store)",
        ));
    };
    let v = crate::store::Verification {
        id: 0,
        name: n.name.trim().into(),
        claims: n.claims,
        change_at,
        window_secs: n.window_secs,
        who: person.who.clone(),
        by_name: person.name.clone(),
        reason: n.reason.clone(),
        at: crate::enroll::now_rfc3339(),
        record: None,
    };
    match store.create_verification(&v) {
        Ok(id) => {
            let v = crate::store::Verification { id, ..v };
            let target = format!("ver-{id}");
            noted(
                ok(&json!({"verification": super::verify::with_record(ctx, v)})),
                "verify.create",
                &target,
                "ok",
                &n.reason,
            )
        }
        Err(e) => out(error(500, "internal", &e.to_string())),
    }
}

// ---- the audit log ---------------------------------------------------------------------

fn audit(ctx: &Context, person: &Person) -> Answer {
    if person.role < Role::Member {
        return forbidden("the audit log is for members and above");
    }
    let Some(a) = &ctx.audit else {
        return ok(&json!({"entries": [], "kept": false, "where": "agent"}));
    };
    let chain = match a.verify() {
        Ok(n) => json!({"ok": true, "entries": n}),
        Err(e) => json!({"ok": false, "problem": e}),
    };
    ok(&json!({"entries": a.recent(200), "chain": chain, "kept": true, "where": "agent"}))
}

// ---- writes ----------------------------------------------------------------------------

/// What a write asks the server to note in the audit log.
#[derive(Debug, Default)]
pub(super) struct AuditNote {
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub reason: String,
}

/// A write's answer, and what the audit log gets.
#[derive(Debug, Default)]
pub(super) struct WriteOut {
    pub body: String,
    pub audit: Option<AuditNote>,
}

fn out(a: Answer) -> (u16, WriteOut) {
    (
        a.0,
        WriteOut {
            body: a.1,
            audit: None,
        },
    )
}

fn noted(a: Answer, action: &str, target: &str, outcome: &str, reason: &str) -> (u16, WriteOut) {
    (
        a.0,
        WriteOut {
            body: a.1,
            audit: Some(AuditNote {
                action: action.into(),
                target: target.into(),
                outcome: outcome.into(),
                reason: reason.into(),
            }),
        },
    )
}

#[derive(Debug, serde::Deserialize)]
struct ApplyBody {
    text: String,
    #[serde(default)]
    base_sha: Option<String>,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ReasonBody {
    #[serde(default)]
    reason: String,
}

/// A POST or PUT on the local API, by `person`.
pub(super) async fn write(
    ctx: &Context,
    person: &Person,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, WriteOut) {
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').skip(1).collect();
    let agent_id = ctx.state.snapshot().agent.agent_id.unwrap_or_default();
    let ["v1", "accounts", "orgs", org, "agents", agent, rest @ ..] = parts.as_slice() else {
        return out(read_only());
    };
    if *org != ctx.account_id || *agent != agent_id || ctx.account_id.is_empty() {
        return out(not_found("agent"));
    }
    match (method, rest) {
        ("POST", ["config", "files", name, "validate"]) => {
            let Ok(b) = serde_json::from_slice::<ApplyBody>(body) else {
                return out(error(400, "invalid_argument", "send {\"text\": …}"));
            };
            let Some(f) = file_of(ctx, name) else {
                return out(not_found("file"));
            };
            let now = configs::read(&f.path).unwrap_or_default();
            let problems = configs::validate(ctx, name, &b.text);
            out(ok(&json!({
                "problems": problems,
                "valid": problems.iter().all(|p| p.level != "error"),
                "diff": configs::diff_json(&now, &b.text),
                "sha": configs::sha(&now),
                "model": configs::model(&b.text),
            })))
        }
        ("PUT", ["config", "files", name]) => {
            let Ok(b) = serde_json::from_slice::<ApplyBody>(body) else {
                return out(error(
                    400,
                    "invalid_argument",
                    "send {\"text\": …, \"base_sha\": …, \"reason\": …}",
                ));
            };
            apply(
                ctx,
                person,
                name,
                &b.text,
                b.base_sha.as_deref(),
                &b.reason,
                "apply",
            )
            .await
        }
        ("POST", ["config", "files", name, "versions", id, "restore"]) => {
            let b: ReasonBody = serde_json::from_slice(body).unwrap_or_default();
            let Some(v) = id
                .parse::<i64>()
                .ok()
                .and_then(|id| ctx.state.store()?.version(name, id).ok().flatten())
            else {
                return out(not_found("version"));
            };
            let reason = if b.reason.trim().is_empty() {
                format!("restore version {}", v.id)
            } else {
                b.reason
            };
            apply(
                ctx,
                person,
                name,
                v.text.as_deref().unwrap_or(""),
                None,
                &reason,
                "restore",
            )
            .await
        }
        ("POST", ["verifications"]) => create_verification(ctx, person, body),
        (
            "POST",
            [
                "extensions",
                publisher,
                ext,
                action @ ("enable" | "disable"),
            ],
        ) => {
            let b: ReasonBody = serde_json::from_slice(body).unwrap_or_default();
            toggle(
                ctx,
                person,
                &format!("{publisher}/{ext}"),
                *action == "enable",
                &b.reason,
            )
            .await
        }
        _ => out(read_only()),
    }
}

/// Validates, writes atomically, reloads the agent, and rolls back when it refuses.
#[allow(clippy::too_many_lines)] // the steps of one change, in order
async fn apply(
    ctx: &Context,
    person: &Person,
    name: &str,
    text: &str,
    base_sha: Option<&str>,
    reason: &str,
    action: &str,
) -> (u16, WriteOut) {
    let Some(f) = file_of(ctx, name) else {
        return out(not_found("file"));
    };
    let audit_action = format!("config.{action}");
    if person.role < f.edit {
        return noted(
            forbidden(&format!(
                "changing {name} needs the {} role",
                f.edit.as_str()
            )),
            &audit_action,
            name,
            "refused: role",
            reason,
        );
    }
    let problems = configs::validate(ctx, name, text);
    if problems.iter().any(|p| p.level == "error") {
        return out((
            422,
            json!({
                "code": "failed_precondition",
                "error": format!("{name} has errors; nothing was changed"),
                "problems": problems,
                "details": [],
                "request_id": uuid::Uuid::now_v7().to_string(),
            })
            .to_string(),
        ));
    }
    let before = match configs::read(&f.path) {
        Ok(t) => t,
        Err(e) => return out(error(500, "internal", &format!("{name}: {e}"))),
    };
    if base_sha.is_some_and(|b| b != configs::sha(&before)) {
        return out(error(
            409,
            "aborted",
            &format!("{name} changed since you opened it; load it again and redo your change"),
        ));
    }
    if before == text {
        return out(ok(
            &json!({"applied": false, "message": "nothing changed", "sha": configs::sha(text)}),
        ));
    }
    let store = ctx.state.store();
    let record = |text: &str, who: &str, name_: &str, role: &str, act: &str, why: &str| {
        store.and_then(|s| {
            s.record_version(&crate::store::ConfigVersion {
                id: 0,
                file: f.name.into(),
                sha: configs::sha(text),
                text: Some(text.into()),
                who: who.into(),
                name: name_.into(),
                role: role.into(),
                action: act.into(),
                reason: why.into(),
                at: crate::enroll::now_rfc3339(),
            })
            .ok()
        })
    };
    // The text as found, so the first change can be rolled back to it too.
    if store.is_some_and(|s| s.versions(f.name, 1).is_ok_and(|v| v.is_empty())) {
        record(
            &before,
            "file",
            "The file on disk",
            "-",
            "found",
            "as found before the first change from the console",
        );
    }
    if let Err(e) = configs::write_atomic(&f.path, text) {
        return out(error(500, "internal", &format!("{name}: {e}")));
    }
    // Reload: a new generation with the new files, in this process.
    let reloaded = match &ctx.reload {
        None => Ok("written (no running agent to reload)".to_owned()),
        Some(tx) => {
            let (reply, rx) = tokio::sync::oneshot::channel();
            if tx.send(crate::agent::Reload { reply }).await.is_err() {
                Err("the agent did not take the reload".to_owned())
            } else {
                match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                    Ok(Ok(r)) => r,
                    _ => Err("the agent did not answer the reload in time".to_owned()),
                }
            }
        }
    };
    match reloaded {
        Err(e) => {
            // Back to what was there: the agent never left it.
            let _ = configs::write_atomic(&f.path, &before);
            noted(
                (
                    422,
                    json!({
                        "code": "failed_precondition",
                        "error": format!("the agent refused the new {name}, so it was put back: {e}"),
                        "rolled_back": true,
                        "details": [],
                        "request_id": uuid::Uuid::now_v7().to_string(),
                    })
                    .to_string(),
                ),
                &audit_action,
                name,
                "rolled back",
                reason,
            )
        }
        Ok(msg) => {
            let id = record(
                text,
                &person.who,
                &person.name,
                person.role.as_str(),
                action,
                reason,
            );
            if name == "policy.toml"
                && let Some(l) = &ctx.ledger
            {
                let payload = crate::checks_file::canonical_json(&json!({
                    "from": configs::sha(&before),
                    "to": configs::sha(text),
                    "by": person.who,
                }));
                if let Err(e) = l.record(crate::ledger::Record {
                    kind: "policy_set",
                    payload: payload.as_bytes(),
                    rule: "operator.console.policy",
                    destination: "local: policy.toml (nothing sent)",
                    job_id: None,
                }) {
                    tracing::warn!(error = %e, "the policy change was not noted in the ledger");
                }
            }
            noted(
                ok(&json!({
                    "applied": true,
                    "message": msg,
                    "version": id,
                    "sha": configs::sha(text),
                    "problems": problems,
                })),
                &audit_action,
                name,
                "ok",
                reason,
            )
        }
    }
}

/// Installs (adds to the lock) or removes an extension, then reloads. The licence and the
/// policy are not the console's to change: an extension they do not admit is refused.
async fn toggle(
    ctx: &Context,
    person: &Person,
    id: &str,
    enable: bool,
    reason: &str,
) -> (u16, WriteOut) {
    let action = if enable {
        "extension.enable"
    } else {
        "extension.disable"
    };
    let Some(m) = crate::extensions::builtins()
        .into_iter()
        .find(|m| m.id == id)
    else {
        return out(not_found("extension"));
    };
    if person.role < Role::Admin {
        return noted(
            forbidden("installing and removing extensions needs the admin role"),
            action,
            id,
            "refused: role",
            reason,
        );
    }
    if m.required && !enable {
        return out(error(
            412,
            "failed_precondition",
            &format!("{id} is what the agent runs on; it cannot be removed"),
        ));
    }
    let st = crate::extensions::state(&m, &ctx.policy, &ctx.lock);
    if enable && (!st.licence.ok || !st.policy.ok) {
        let why = if st.licence.ok {
            st.policy.why
        } else {
            st.licence.why
        };
        return noted(
            error(412, "failed_precondition", &why),
            action,
            id,
            "refused: not admitted",
            reason,
        );
    }
    let dir = std::path::Path::new(&ctx.state_dir);
    let mut lock = match crate::extensions::Lock::load_or_init(dir) {
        Ok(l) => l,
        Err(e) => return out(error(500, "internal", &e.to_string())),
    };
    if enable == lock.has(id) {
        return out(ok(&json!({"changed": false})));
    }
    let before = lock.clone();
    if enable {
        lock.extensions.push(crate::extensions::LockEntry {
            id: id.into(),
            version: m.version.into(),
            installed_by: format!("{} ({})", person.name, person.role.as_str()),
            at: crate::enroll::now_rfc3339(),
        });
    } else {
        lock.extensions.retain(|e| e.id != id);
    }
    if let Err(e) = lock.save(dir) {
        return out(error(500, "internal", &e.to_string()));
    }
    if let Some(tx) = &ctx.reload {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let r = if tx.send(crate::agent::Reload { reply }).await.is_ok() {
            tokio::time::timeout(std::time::Duration::from_secs(30), rx)
                .await
                .ok()
                .and_then(std::result::Result::ok)
                .unwrap_or_else(|| Err("no answer".into()))
        } else {
            Err("the agent did not take the reload".into())
        };
        if let Err(e) = r {
            let _ = before.save(dir);
            return noted(
                error(
                    422,
                    "failed_precondition",
                    &format!("the agent refused it, so nothing changed: {e}"),
                ),
                action,
                id,
                "rolled back",
                reason,
            );
        }
    }
    noted(
        ok(&json!({"changed": true, "installed": enable})),
        action,
        id,
        "ok",
        reason,
    )
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
        let ok = |r: &JobRecord| passed(Kind::Check, None, r);
        assert_eq!(health(&[], 2, ok), "unknown");
        assert_eq!(health(&[rec("ok")], 2, ok), "up");
        assert_eq!(health(&[rec("ok"), rec("failed")], 2, ok), "up");
        assert_eq!(health(&[rec("failed"), rec("failed")], 2, ok), "down");
        assert_eq!(health(&[rec("failed"), rec("ok")], 2, ok), "up");
    }

    #[test]
    fn a_refuse_check_passes_when_the_target_is_refused() {
        let by_policy = |r: &JobRecord| passed(Kind::Refuse, Some(RefuseBy::Policy), r);
        assert_eq!(health(&[rec("refused")], 1, by_policy), "up");
        assert_eq!(
            health(&[rec("ok")], 1, by_policy),
            "down",
            "a guard that stopped guarding"
        );
        let by_answer = |r: &JobRecord| passed(Kind::Refuse, Some(RefuseBy::Answer), r);
        assert_eq!(health(&[rec("ok")], 1, by_answer), "up");
    }

    #[test]
    fn query_parses_and_decodes() {
        let q = Query::parse(
            "page_size=5&page_token=12&status=FAILED&agent_id=agt%5F1&from=2026-10-09T00%3A00%3A00Z",
        );
        assert_eq!(q.from.as_deref(), Some("2026-10-09T00:00:00Z"));
        assert_eq!(q.page_size, Some(5));
        assert_eq!(q.page_token.as_deref(), Some("12"));
        assert_eq!(q.status.as_deref(), Some("failed"));
        assert_eq!(q.agent_id.as_deref(), Some("agt_1"));
    }
}
