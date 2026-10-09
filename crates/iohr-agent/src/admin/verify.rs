//! Verify, in the agent (PRD 0008, the `inorbit/verify` extension): did a change hold?
//!
//! A verification names a change (when it happened), its claims (declared checks that must
//! keep passing) and a window. Each claim is judged from the runs the agent kept: the window
//! before the change against the window after it.
//!
//! | Verdict | When |
//! |---|---|
//! | `held` | runs after the change, passing at least as often as before |
//! | `broke` | every run before passed, and one after failed |
//! | `worse` | it passed less often after than before |
//! | `not_measured` | no run before or after: nothing is claimed |
//!
//! The whole is `pass` when every claim held, `fail` when any broke or got worse, and
//! `incomplete` otherwise; while the after-window is still open it is `measuring`. Once the
//! window has passed, the evidence record (counts, rates and the first failing runs) is
//! frozen in the trial store and never recomputed. Nothing here sends anything anywhere,
//! and no confidence score is ever made up: counts and rates only.

use serde_json::{Value, json};

use super::Context;
use crate::store::{StoredRun, Verification};

/// The shortest and the longest window.
pub(super) const WINDOW: std::ops::RangeInclusive<i64> = 60..=86_400;
/// The most claims a verification names.
pub(super) const MAX_CLAIMS: usize = 20;

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn parse(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// One side of the change.
fn side(runs: &[StoredRun], pass: &dyn Fn(&crate::state::JobRecord) -> bool) -> Value {
    let passed = runs.iter().filter(|r| pass(&r.record)).count();
    let failing: Vec<Value> = runs
        .iter()
        .filter(|r| !pass(&r.record))
        .take(3)
        .map(|r| {
            json!({
                "run_id": format!("run-{}", r.id),
                "at": r.record.at,
                "status": r.record.verdict,
                "status_code": r.record.status_code,
                "error_class": r.record.error_class,
            })
        })
        .collect();
    #[allow(clippy::cast_precision_loss)] // run counts are small
    let rate = (!runs.is_empty()).then(|| passed as f64 / runs.len() as f64);
    json!({"runs": runs.len(), "passed": passed, "pass_rate": rate, "first_failures": failing})
}

/// The evidence record of `v`, as of now.
pub(super) fn evaluate(ctx: &Context, v: &Verification) -> Value {
    let Some(change) = parse(&v.change_at) else {
        return json!({"verdict": "incomplete", "why": "the change's time does not parse"});
    };
    let window = time::Duration::seconds(v.window_secs);
    let (from, to) = (rfc3339(change - window), rfc3339(change + window));
    let now = time::OffsetDateTime::now_utc();
    let measuring = now < change + window;
    let mut claims = Vec::new();
    let (mut held, mut failed, mut unmeasured) = (0, 0, 0);
    for key in &v.claims {
        let Some(c) = ctx
            .checks
            .as_ref()
            .and_then(|c| c.entries.iter().find(|e| &e.key == key))
        else {
            unmeasured += 1;
            claims.push(json!({"claim": key, "verdict": "not_measured", "why": "no such check in checks.toml now"}));
            continue;
        };
        let pass = |r: &crate::state::JobRecord| super::api::passed_for(c, r);
        let (before, after) = ctx.state.store().map_or((Vec::new(), Vec::new()), |s| {
            (
                s.runs_between(key, &from, &v.change_at).unwrap_or_default(),
                s.runs_between(key, &v.change_at, &to).unwrap_or_default(),
            )
        });
        let b = side(&before, &pass);
        let a = side(&after, &pass);
        let (br, ar) = (b["pass_rate"].as_f64(), a["pass_rate"].as_f64());
        let verdict = match (br, ar) {
            (_, None) | (None, _) => "not_measured",
            (Some(b), Some(_))
                if (b - 1.0).abs() < f64::EPSILON && after.iter().any(|r| !pass(&r.record)) =>
            {
                "broke"
            }
            (Some(b), Some(a)) if a + f64::EPSILON < b => "worse",
            _ => "held",
        };
        match verdict {
            "held" => held += 1,
            "not_measured" => unmeasured += 1,
            _ => failed += 1,
        }
        claims.push(json!({
            "claim": key,
            "name": c.label.clone().unwrap_or_else(|| c.key.clone()),
            "verdict": verdict,
            "before": b,
            "after": a,
        }));
    }
    let verdict = if measuring {
        "measuring"
    } else if failed > 0 {
        "fail"
    } else if unmeasured > 0 || held == 0 {
        "incomplete"
    } else {
        "pass"
    };
    json!({
        "verdict": verdict,
        "measuring_until": if measuring { Some(to.clone()) } else { None },
        "before": {"from": from, "to": v.change_at},
        "after": {"from": v.change_at, "to": to},
        "claims": claims,
        "held": held,
        "failed": failed,
        "not_measured": unmeasured,
        "judged_at": rfc3339(now),
        "method": "each claim's runs in the window before the change against the window after it; counts and pass rates, no estimate",
    })
}

/// A verification with its record: the frozen one, or as of now (frozen once complete).
#[allow(clippy::needless_pass_by_value)] // consumed into the answer
pub(super) fn with_record(ctx: &Context, v: Verification) -> Value {
    let record = v.record.clone().unwrap_or_else(|| {
        let r = evaluate(ctx, &v);
        if r["verdict"] != "measuring"
            && let Some(s) = ctx.state.store()
            && let Err(e) = s.freeze_verification(v.id, &r)
        {
            tracing::warn!(error = %e, "a verification's record was not frozen");
        }
        r
    });
    let mut out = serde_json::to_value(&v).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut out {
        m.insert("record".into(), record);
        m.insert("verification_id".into(), json!(format!("ver-{}", v.id)));
    }
    out
}

/// The body of a new verification.
#[derive(Debug, serde::Deserialize)]
pub(super) struct NewVerification {
    pub name: String,
    pub claims: Vec<String>,
    #[serde(default)]
    pub change_at: Option<String>,
    #[serde(default = "default_window")]
    pub window_secs: i64,
    #[serde(default)]
    pub reason: String,
}

fn default_window() -> i64 {
    900
}

/// Checks a new verification; the change's time defaults to now.
pub(super) fn check(ctx: &Context, n: &NewVerification) -> Result<String, String> {
    if n.name.trim().is_empty() || n.name.len() > 120 {
        return Err("name the change in 1 to 120 characters".into());
    }
    if n.claims.is_empty() || n.claims.len() > MAX_CLAIMS {
        return Err(format!("name 1 to {MAX_CLAIMS} checks as its claims"));
    }
    for k in &n.claims {
        if !ctx
            .checks
            .as_ref()
            .is_some_and(|c| c.entries.iter().any(|e| &e.key == k))
        {
            return Err(format!("{k} is not a check in checks.toml"));
        }
    }
    if !WINDOW.contains(&n.window_secs) {
        return Err("the window is 60 seconds to 24 hours".into());
    }
    match &n.change_at {
        None => Ok(rfc3339(time::OffsetDateTime::now_utc())),
        Some(s) => parse(s)
            .map(rfc3339)
            .ok_or_else(|| "change_at is an RFC 3339 time".to_owned()),
    }
}
