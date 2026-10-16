//! `iohr-agent run --once`: run the declared checks one time and exit with a verdict a
//! CI pipeline can gate on (RFC 0040.1, PRD 0008).
//!
//! No daemon, no session and no platform: the checks run on this machine under the same
//! local policy, ceilings and secret rules as the daemon's jobs, through the same
//! [`Executor`]. Nothing is sent to InOrbit, so the egress ledger has nothing to record;
//! `--evidence` writes the run, signed with this agent's key, to a local file instead.
//!
//! Exit codes: 0 every selected check passed, 1 at least one failed, 2 nothing failed but
//! something could not be judged (a refusal, an unknown check name, a bad file).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::checks_file::{DeclaredCheck, DeclaredChecks, Kind, RefuseBy};
use crate::config::AgentConfig;
use crate::error::{Error, Result};
use crate::executor::{Admission, Executor};
use crate::policy::Policy;
use crate::protocol::{Job, ResultStatus};
use crate::secrets::SecretResolver;
use crate::tls::TlsContext;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum Format {
    /// A table and a summary for people.
    #[default]
    Text,
    /// One JSON document.
    Json,
    /// `JUnit` XML, read by most CI systems as test results.
    Junit,
    /// SARIF 2.1.0, for code-scanning views.
    Sarif,
}

/// What makes the run fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum FailOn {
    /// A check that failed (the default).
    #[default]
    Down,
    /// Also a check that passed but used more than 80% of its `max_ms`.
    Degraded,
}

/// What one check came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It passed.
    Pass,
    /// It passed, close to its latency bound.
    Degraded,
    /// It failed.
    Fail,
    /// It could not be judged here (refused by a ceiling, a bad secret, a timeout of the run).
    Error,
    /// It is not judged on this machine (host sensors, `[[refuse]] by = "platform"`).
    Skipped,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Degraded => "degraded",
            Self::Fail => "fail",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }
}

/// One check's line in the report. Never a response body, never a secret.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// `name` in checks.toml.
    pub name: String,
    /// `check` or `refuse`.
    pub kind: &'static str,
    /// The surface.
    pub surface: String,
    /// The verdict.
    pub outcome: Outcome,
    /// Wall time, ms.
    pub latency_ms: u64,
    /// The HTTP status, when one came back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// The class of error, when it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Why, in words (refusals, skips, errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Its tags.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

/// The whole run.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    /// This agent's version.
    pub agent_version: String,
    /// The policy's hash: which rules the run was held to.
    pub policy_hash: String,
    /// The agent's name from agent.toml.
    pub agent: String,
    /// The environment from agent.toml.
    pub environment: String,
    /// RFC 3339.
    pub started_at: String,
    /// RFC 3339.
    pub finished_at: String,
    /// Counts by outcome.
    pub summary: BTreeMap<&'static str, usize>,
    /// The exit code this run ends with.
    pub exit_code: u8,
    /// Every selected check.
    pub checks: Vec<CheckReport>,
}

/// What to run and how to report it.
#[derive(Debug, Clone)]
pub struct Options {
    /// Only these names (empty: all).
    pub names: Vec<String>,
    /// Only checks with every one of these tags.
    pub tags: Vec<(String, String)>,
    /// The checks file (default: agent.toml's).
    pub checks: Option<PathBuf>,
    /// The policy (default: agent.toml's).
    pub policy: Option<PathBuf>,
    /// The whole run's time limit.
    pub timeout: Duration,
    /// The format.
    pub format: Format,
    /// What fails the run.
    pub fail_on: FailOn,
    /// Write the report here as well as standard output.
    pub out: Option<PathBuf>,
    /// Write the report signed with the agent's key (a compact JWS) here.
    pub evidence: Option<PathBuf>,
}

/// Parses `key=value`.
///
/// # Errors
/// When there is no `=`.
pub fn parse_tag(s: &str) -> std::result::Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("{s:?} is not key=value"))?;
    if k.trim().is_empty() {
        return Err(format!("{s:?} has an empty key"));
    }
    Ok((k.trim().to_owned(), v.trim().to_owned()))
}

/// Runs the selected checks once and prints the report.
///
/// # Errors
/// When agent.toml, the policy or the checks file cannot be read: the caller exits 2.
pub fn run(config_path: &Path, opts: &Options) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let policy_path = opts.policy.clone().unwrap_or_else(|| cfg.policy.clone());
    let checks_path = opts.checks.clone().unwrap_or_else(|| cfg.checks.clone());
    let policy = Policy::load(&policy_path)?;
    let checks = DeclaredChecks::load(&checks_path)?
        .ok_or_else(|| Error::Config(format!("no checks file at {}", checks_path.display())))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Config(format!("the runtime: {e}")))?;
    let report = rt.block_on(run_checks(&cfg, policy, checks, opts))?;
    emit(&report, opts, &cfg)?;
    Ok(ExitCode::from(report.exit_code))
}

fn select<'a>(checks: &'a DeclaredChecks, opts: &Options) -> (Vec<&'a DeclaredCheck>, Vec<String>) {
    let mut unknown = Vec::new();
    for n in &opts.names {
        if !checks.entries.iter().any(|e| &e.key == n) {
            unknown.push(n.clone());
        }
    }
    let picked = checks
        .entries
        .iter()
        .filter(|e| opts.names.is_empty() || opts.names.contains(&e.key))
        .filter(|e| {
            opts.tags
                .iter()
                .all(|(k, v)| e.tags.get(k).is_some_and(|t| t == v))
        })
        .collect();
    (picked, unknown)
}

async fn run_checks(
    cfg: &AgentConfig,
    policy: Policy,
    checks: DeclaredChecks,
    opts: &Options,
) -> Result<RunReport> {
    let started_at = now();
    let deadline = Instant::now() + opts.timeout;
    let policy_hash = policy.hash();
    let tls = TlsContext::new(cfg.tls.ca_file.as_deref())?;
    let secrets = SecretResolver::new(cfg.secrets.clone(), tls.clone());
    let checks = Arc::new(checks);
    let executor = Arc::new(
        Executor::new(Arc::new(policy), tls, secrets).with_checks(Some(Arc::clone(&checks))),
    );
    let (picked, unknown) = select(&checks, opts);
    let mut reports: Vec<CheckReport> = unknown
        .into_iter()
        .map(|name| CheckReport {
            name,
            kind: "check",
            surface: String::new(),
            outcome: Outcome::Error,
            latency_ms: 0,
            status_code: None,
            error_class: None,
            reason: Some("no check by this name in the checks file".into()),
            tags: BTreeMap::new(),
        })
        .collect();
    let mut tasks = tokio::task::JoinSet::new();
    for (i, entry) in picked.into_iter().enumerate() {
        let entry = entry.clone();
        let executor = Arc::clone(&executor);
        tasks.spawn(async move { (i, judge(&executor, &entry, deadline).await) });
    }
    let mut done: Vec<(usize, CheckReport)> = Vec::new();
    let remaining = deadline.saturating_duration_since(Instant::now());
    let collected = tokio::time::timeout(remaining, async {
        while let Some(r) = tasks.join_next().await {
            if let Ok(pair) = r {
                done.push(pair);
            }
        }
    })
    .await;
    if collected.is_err() {
        tasks.abort_all();
    }
    done.sort_by_key(|(i, _)| *i);
    let finished: std::collections::BTreeSet<String> =
        done.iter().map(|(_, r)| r.name.clone()).collect();
    reports.extend(done.into_iter().map(|(_, r)| r));
    if collected.is_err() {
        for e in &checks.entries {
            let selected = (opts.names.is_empty() || opts.names.contains(&e.key))
                && opts
                    .tags
                    .iter()
                    .all(|(k, v)| e.tags.get(k).is_some_and(|t| t == v));
            if selected && !finished.contains(&e.key) {
                reports.push(CheckReport {
                    name: e.key.clone(),
                    kind: e.kind.as_str(),
                    surface: e.spec.surface.as_str().into(),
                    outcome: Outcome::Error,
                    latency_ms: 0,
                    status_code: None,
                    error_class: Some("timeout".into()),
                    reason: Some(format!(
                        "the run's --timeout ({}s) ended before this check finished",
                        opts.timeout.as_secs()
                    )),
                    tags: e.tags.clone(),
                });
            }
        }
    }
    let mut summary: BTreeMap<&'static str, usize> = BTreeMap::new();
    for o in [
        Outcome::Pass,
        Outcome::Degraded,
        Outcome::Fail,
        Outcome::Error,
        Outcome::Skipped,
    ] {
        summary.insert(
            o.as_str(),
            reports.iter().filter(|r| r.outcome == o).count(),
        );
    }
    let exit_code = exit_code(&reports, opts.fail_on);
    Ok(RunReport {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        policy_hash,
        agent: cfg.name.clone(),
        environment: cfg.environment.clone(),
        started_at,
        finished_at: now(),
        summary,
        exit_code,
        checks: reports,
    })
}

/// 1 when anything failed (or was degraded under `--fail-on degraded`), else 2 when
/// anything could not be judged, else 0. Skipped checks never change it.
#[must_use]
pub fn exit_code(reports: &[CheckReport], fail_on: FailOn) -> u8 {
    let failed = reports.iter().any(|r| {
        r.outcome == Outcome::Fail
            || (fail_on == FailOn::Degraded && r.outcome == Outcome::Degraded)
    });
    if failed {
        1
    } else if reports.iter().any(|r| r.outcome == Outcome::Error) {
        2
    } else {
        0
    }
}

async fn judge(executor: &Executor, entry: &DeclaredCheck, deadline: Instant) -> CheckReport {
    let mut report = CheckReport {
        name: entry.key.clone(),
        kind: entry.kind.as_str(),
        surface: entry.spec.surface.as_str().into(),
        outcome: Outcome::Error,
        latency_ms: 0,
        status_code: None,
        error_class: None,
        reason: None,
        tags: entry.tags.clone(),
    };
    if entry.spec.surface.is_host() {
        report.outcome = Outcome::Skipped;
        report.reason = Some(
            "host sensor checks judge a window of readings; the running agent judges them".into(),
        );
        return report;
    }
    if entry.kind == Kind::Refuse && entry.refuse_by == Some(RefuseBy::Platform) {
        report.outcome = Outcome::Skipped;
        report.reason =
            Some("refused by the platform, not by this machine: judged by the platform".into());
        return report;
    }
    let job = Job {
        job_id: format!("once-{}", entry.key),
        kind: "check".into(),
        spec: entry.to_wire(),
        deadline_ms: None,
    };
    // A ceiling refusal (jobs per minute, jobs at once) is a queue, not a verdict: wait.
    let admitted = loop {
        match executor.admit(&job) {
            Admission::Run(a) => break Ok(a),
            Admission::Refuse(reason) if reason.starts_with("ceiling:") => {
                if Instant::now() >= deadline {
                    break Err(reason);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Admission::Refuse(reason) => break Err(reason),
        }
    };
    let by_policy = entry.kind == Kind::Refuse && entry.refuse_by == Some(RefuseBy::Policy);
    let admitted = match admitted {
        Ok(a) => a,
        Err(reason) => {
            if by_policy && !reason.starts_with("ceiling:") {
                report.outcome = Outcome::Pass;
                report.reason = Some(format!(
                    "refused by the local policy, as declared: {reason}"
                ));
            } else {
                report.outcome = Outcome::Error;
                report.error_class = Some("refused_by_policy".into());
                report.reason = Some(reason);
            }
            return report;
        }
    };
    let done = executor.execute(job.job_id.clone(), *admitted).await;
    verdict(report, entry, by_policy, &done.result)
}

/// What an executed job comes to.
fn verdict(
    mut report: CheckReport,
    entry: &DeclaredCheck,
    by_policy: bool,
    result: &crate::protocol::JobResult,
) -> CheckReport {
    let d = &result.detail;
    report.latency_ms = d.latency_ms;
    report.status_code = d.status_code;
    report.error_class = d.error_class.and_then(|c| {
        serde_json::to_value(c)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
    });
    let refusal = result.refusal.as_ref().map(|r| r.reason.clone());
    if by_policy {
        // The network rules are applied as the job runs, before anything is sent: a
        // refusal there is this entry passing; a job that ran means the guard is open.
        if result.status == ResultStatus::Refused {
            report.outcome = Outcome::Pass;
            report.error_class = None;
            report.reason = Some(format!(
                "refused by the local policy, as declared: {}",
                refusal.unwrap_or_default()
            ));
        } else {
            report.outcome = Outcome::Fail;
            report.error_class = Some("guard_open".into());
            report.reason =
                Some("the local policy let this through; it is declared to refuse it".into());
        }
        return report;
    }
    report.outcome = match result.status {
        ResultStatus::Ok => match entry.spec.expect.max_ms {
            Some(max) if d.latency_ms.saturating_mul(10) > max.saturating_mul(8) => {
                report.reason = Some(format!(
                    "passed in {} ms, over 80% of its max_ms ({max} ms)",
                    d.latency_ms
                ));
                Outcome::Degraded
            }
            _ => Outcome::Pass,
        },
        ResultStatus::Failed => Outcome::Fail,
        ResultStatus::Refused => {
            report.reason = refusal;
            Outcome::Error
        }
    };
    report
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn emit(report: &RunReport, opts: &Options, cfg: &AgentConfig) -> Result<()> {
    let text = render(report, opts.format);
    {
        use std::io::Write as _;
        let _ = std::io::stdout().lock().write_all(text.as_bytes());
    }
    if let Some(path) = &opts.out {
        std::fs::write(path, &text).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
    }
    if let Some(path) = &opts.evidence {
        let key = crate::keys::AgentKey::load(&cfg.key).map_err(|e| {
            Error::Config(format!(
                "--evidence signs with this agent's key ({}): {e}",
                cfg.key.display()
            ))
        })?;
        let claims = json!({
            "typ": "iohr.run-once/1",
            "kid": key.kid(),
            "iat": chrono::Utc::now().timestamp(),
            "report": report,
        });
        std::fs::write(path, key.sign_jwt(&claims)).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

/// The report in the chosen format.
#[must_use]
pub fn render(report: &RunReport, format: Format) -> String {
    match format {
        Format::Json => {
            let mut s = serde_json::to_string_pretty(report).unwrap_or_default();
            s.push('\n');
            s
        }
        Format::Text => render_text(report),
        Format::Junit => render_junit(report),
        Format::Sarif => render_sarif(report),
    }
}

fn render_text(r: &RunReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let width = r
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    for c in &r.checks {
        let detail = match (&c.status_code, &c.error_class, &c.reason) {
            (_, _, Some(reason)) => reason.clone(),
            (Some(code), None, None) => format!("HTTP {code}"),
            (code, Some(class), None) => match code {
                Some(code) => format!("{class}, HTTP {code}"),
                None => class.clone(),
            },
            (None, None, None) => String::new(),
        };
        let _ = writeln!(
            s,
            "{:<9} {:<width$}  {:>6} ms  {}",
            c.outcome.as_str(),
            c.name,
            c.latency_ms,
            detail
        );
    }
    let counts: Vec<String> = r
        .summary
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    let _ = writeln!(
        s,
        "\n{} checks: {}. exit {}",
        r.checks.len(),
        if counts.is_empty() {
            "none".into()
        } else {
            counts.join(", ")
        },
        r.exit_code
    );
    s
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_junit(r: &RunReport) -> String {
    use std::fmt::Write as _;
    let n = |k: &str| r.summary.get(k).copied().unwrap_or_default();
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        s,
        "<testsuites name=\"iohr-agent run --once\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\">",
        r.checks.len(),
        n("fail"),
        n("error"),
        n("skipped")
    );
    let _ = writeln!(
        s,
        "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" timestamp=\"{}\">",
        xml(&r.agent),
        r.checks.len(),
        n("fail"),
        n("error"),
        n("skipped"),
        xml(&r.started_at)
    );
    for c in &r.checks {
        #[allow(clippy::cast_precision_loss)]
        let secs = c.latency_ms as f64 / 1000.0;
        let _ = write!(
            s,
            "    <testcase classname=\"{}\" name=\"{}\" time=\"{secs:.3}\"",
            xml(&c.surface),
            xml(&c.name)
        );
        let msg = xml(c
            .reason
            .as_deref()
            .or(c.error_class.as_deref())
            .unwrap_or(""));
        match c.outcome {
            Outcome::Pass | Outcome::Degraded => s.push_str("/>\n"),
            Outcome::Fail => {
                let _ = writeln!(s, ">\n      <failure message=\"{msg}\"/>\n    </testcase>");
            }
            Outcome::Error => {
                let _ = writeln!(s, ">\n      <error message=\"{msg}\"/>\n    </testcase>");
            }
            Outcome::Skipped => {
                let _ = writeln!(s, ">\n      <skipped message=\"{msg}\"/>\n    </testcase>");
            }
        }
    }
    s.push_str("  </testsuite>\n</testsuites>\n");
    s
}

fn render_sarif(r: &RunReport) -> String {
    let results: Vec<Value> = r
        .checks
        .iter()
        .filter(|c| matches!(c.outcome, Outcome::Fail | Outcome::Error | Outcome::Degraded))
        .map(|c| {
            json!({
                "ruleId": format!("iohr-check/{}", c.name),
                "level": match c.outcome {
                    Outcome::Fail | Outcome::Error => "error",
                    _ => "warning",
                },
                "message": {"text": format!(
                    "{} {}: {}",
                    c.name,
                    c.outcome.as_str(),
                    c.reason.as_deref().or(c.error_class.as_deref()).unwrap_or("")
                )},
                "properties": {"surface": c.surface, "latency_ms": c.latency_ms, "status_code": c.status_code},
            })
        })
        .collect();
    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "iohr-agent",
                "version": r.agent_version,
                "informationUri": "https://developers.inorbit.hr/",
            }},
            "results": results,
        }],
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(name: &str, outcome: Outcome) -> CheckReport {
        CheckReport {
            name: name.into(),
            kind: "check",
            surface: "http".into(),
            outcome,
            latency_ms: 12,
            status_code: Some(200),
            error_class: None,
            reason: None,
            tags: BTreeMap::new(),
        }
    }

    #[test]
    fn exit_codes_follow_the_worst_outcome() {
        use Outcome::*;
        assert_eq!(exit_code(&[rep("a", Pass)], FailOn::Down), 0);
        assert_eq!(
            exit_code(&[rep("a", Pass), rep("b", Skipped)], FailOn::Down),
            0
        );
        assert_eq!(
            exit_code(&[rep("a", Pass), rep("b", Error)], FailOn::Down),
            2
        );
        assert_eq!(
            exit_code(&[rep("a", Fail), rep("b", Error)], FailOn::Down),
            1
        );
        assert_eq!(exit_code(&[rep("a", Degraded)], FailOn::Down), 0);
        assert_eq!(exit_code(&[rep("a", Degraded)], FailOn::Degraded), 1);
        assert_eq!(exit_code(&[], FailOn::Down), 0);
    }

    #[test]
    fn tags_parse_as_key_value() {
        assert_eq!(
            parse_tag("env=prod").unwrap(),
            ("env".into(), "prod".into())
        );
        assert!(parse_tag("prod").is_err());
        assert!(parse_tag("=prod").is_err());
    }

    fn report(checks: Vec<CheckReport>) -> RunReport {
        RunReport {
            agent_version: "0.1.0".into(),
            policy_hash: "sha256:00".into(),
            agent: "ci <one>".into(),
            environment: "prod".into(),
            started_at: "2026-10-10T00:00:00.000Z".into(),
            finished_at: "2026-10-10T00:00:01.000Z".into(),
            summary: BTreeMap::from([("pass", 1), ("fail", 1)]),
            exit_code: 1,
            checks,
        }
    }

    #[test]
    fn junit_escapes_and_marks_failures() {
        let mut bad = rep("api&<x>", Outcome::Fail);
        bad.reason = Some("status \"500\"".into());
        let x = render(&report(vec![rep("ok", Outcome::Pass), bad]), Format::Junit);
        assert!(x.contains("name=\"api&amp;&lt;x&gt;\""), "{x}");
        assert!(
            x.contains("<failure message=\"status &quot;500&quot;\"/>"),
            "{x}"
        );
        assert!(x.contains("name=\"ci &lt;one&gt;\""), "{x}");
        assert!(x.contains("failures=\"1\""), "{x}");
    }

    #[test]
    fn sarif_lists_only_problems() {
        let v: Value = serde_json::from_str(&render(
            &report(vec![rep("ok", Outcome::Pass), rep("down", Outcome::Fail)]),
            Format::Sarif,
        ))
        .unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "iohr-check/down");
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn text_names_the_exit_code() {
        let t = render(&report(vec![rep("ok", Outcome::Pass)]), Format::Text);
        assert!(t.contains("exit 1"), "{t}");
        assert!(t.starts_with("pass"), "{t}");
    }
}
