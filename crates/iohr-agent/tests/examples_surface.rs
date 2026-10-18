//! The `examples` surface (RFC 0165, slice 4) through the executor: the agent runs a named
//! set from its own checkout, a declared check reads the latest run, and only derived
//! fields leave. The set's command is a shell one-liner that writes `examples-results.json`
//! (schema 1) the way the SDK's `tools/run-examples.py` does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use iohr_agent::checks_file::DeclaredChecks;
use iohr_agent::config::SecretsConfig;
use iohr_agent::executor::{Admission, Executor};
use iohr_agent::policy::{Policy, TargetShare};
use iohr_agent::protocol::Job;
use iohr_agent::secrets::SecretResolver;
use iohr_agent::tls::TlsContext;

const CHECKS: &str = r#"
[[check]]
name = "sdk-examples"
surface = "examples"
target = { set = "sdk" }
every = "5m"
fail_after = 1
"#;

fn policy(dir: &std::path::Path, script: &str, surfaces: &str) -> Policy {
    Policy::from_toml(&format!(
        r#"environment = "production"
[work]
checks = true
surfaces = [{surfaces}]

[examples.sdk]
dir = "{}"
command = ["sh", "-c", {script:?}]
every_secs = 60
timeout_secs = 20
"#,
        dir.display()
    ))
    .unwrap()
}

fn executor(p: Policy) -> (Arc<Executor>, Arc<DeclaredChecks>, Arc<Policy>) {
    let p = Arc::new(p);
    let tls = TlsContext::new(None).unwrap();
    let secrets = SecretResolver::new(SecretsConfig::default(), tls.clone());
    let checks = Arc::new(DeclaredChecks::from_toml(CHECKS).unwrap());
    let ex = Arc::new(
        Executor::new(Arc::clone(&p), tls, secrets).with_checks(Some(Arc::clone(&checks))),
    );
    (ex, checks, p)
}

fn job(checks: &DeclaredChecks) -> Job {
    Job {
        job_id: "j1".into(),
        kind: "check".into(),
        spec: checks.entries[0].to_wire(),
        deadline_ms: None,
    }
}

/// Admits and runs the declared check once; a refusal is the `Err`.
async fn run_check(ex: &Executor, checks: &DeclaredChecks) -> Result<serde_json::Value, String> {
    let job = job(checks);
    match ex.admit(&job) {
        Admission::Run(a) => {
            let done = ex.execute(job.job_id.clone(), *a).await;
            Ok(serde_json::to_value(&done.result).unwrap())
        }
        Admission::Refuse(r) => Err(r),
        Admission::RunAction(_) => Err("action".into()),
    }
}

/// Starts the loop and waits until a finished run can be read.
async fn after_first_run(
    ex: &Arc<Executor>,
    checks: &DeclaredChecks,
    p: &Arc<Policy>,
) -> serde_json::Value {
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(iohr_agent::examples::run_loop(
        Arc::clone(p),
        ex.examples_store(),
        rx,
    ));
    let mut last = serde_json::Value::Null;
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let v = run_check(ex, checks).await.unwrap();
        // Before the first run finishes the check carries no invariants and no class.
        if v["detail"]["ok"] == true || v["detail"]["invariants"].is_array() {
            let _ = stop.send(true);
            return v;
        }
        last = v;
    }
    let _ = stop.send(true);
    panic!("no finished run was readable: {last}");
}

#[tokio::test]
async fn a_failing_example_makes_the_check_fail_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let script = r#"echo CANARY-STDOUT; printf '{"schema":1,"commit":"x","results":[{"language":"go","example":"unary-get","status":"pass","ok":true},{"language":"python","example":"unary-get","status":"fail","ok":false,"note":"CANARY-NOTE"}]}' > examples-results.json"#;
    let (ex, checks, p) = executor(policy(dir.path(), script, "\"http\", \"examples\""));
    let v = after_first_run(&ex, &checks, &p).await;
    assert_eq!(v["status"], "failed", "{v}");
    assert_eq!(v["detail"]["ok"], false, "{v}");
    assert_eq!(v["detail"]["error_class"], "examples", "{v}");
    let inv = &v["detail"]["invariants"];
    assert_eq!(inv[0]["name"], "python/unary-get", "{v}");
    assert_eq!(inv[0]["status"], "failed");
    assert_eq!(inv[1]["name"], "go/unary-get");
    assert_eq!(inv[1]["status"], "ok");
    // Only names and statuses leave: not the command's output, not a note, not the path.
    let wire = v.to_string();
    assert!(!wire.contains("CANARY"), "{wire}");
    assert!(!wire.contains(dir.path().to_str().unwrap()), "{wire}");
}

#[tokio::test]
async fn a_passing_run_is_green() {
    let dir = tempfile::tempdir().unwrap();
    let script = r#"printf '{"schema":1,"results":[{"language":"go","example":"unary-get","status":"pass","ok":true}]}' > examples-results.json"#;
    let (ex, checks, p) = executor(policy(dir.path(), script, "\"examples\""));
    let v = after_first_run(&ex, &checks, &p).await;
    assert_eq!(v["status"], "ok", "{v}");
    assert_eq!(v["detail"]["ok"], true, "{v}");
    assert!(v["detail"]["error_class"].is_null(), "{v}");
}

#[tokio::test]
async fn a_run_that_writes_no_results_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (ex, checks, p) = executor(policy(dir.path(), "true", "\"examples\""));
    let v = after_first_run(&ex, &checks, &p).await;
    assert_eq!(v["detail"]["ok"], false, "{v}");
    assert_eq!(v["detail"]["invariants"][0]["name"], "run/missing", "{v}");
}

#[tokio::test]
async fn before_any_run_has_finished_the_check_does_not_pass() {
    let dir = tempfile::tempdir().unwrap();
    let (ex, checks, _p) = executor(policy(dir.path(), "true", "\"examples\""));
    let v = run_check(&ex, &checks).await.unwrap();
    assert_ne!(v["detail"]["ok"], true, "{v}");
    assert_ne!(v["status"], "ok", "{v}");
}

#[tokio::test]
async fn the_surface_is_refused_unless_listed_and_configured() {
    let dir = tempfile::tempdir().unwrap();
    // Not in [work] surfaces.
    let (ex, checks, _p) = executor(policy(dir.path(), "true", "\"http\""));
    let r = run_check(&ex, &checks).await;
    assert!(r.is_err(), "{r:?}");
    // Listed, but the policy has no set.
    let none = Policy::from_toml(
        "environment = \"production\"\n[work]\nchecks = true\nsurfaces = [\"examples\"]\n",
    )
    .unwrap();
    let (ex, checks, _p) = executor(none);
    let r = run_check(&ex, &checks).await;
    assert!(r.is_err(), "{r:?}");
}

#[test]
fn the_platform_sees_the_set_as_a_label_never_a_hash() {
    let checks = DeclaredChecks::from_toml(CHECKS).unwrap();
    let w = iohr_agent::share::wire(&checks.entries[0], TargetShare::Hash, b"k");
    assert_eq!(w["target_shared"], "label", "{w}");
    assert!(w.get("target_hash").is_none(), "{w}");
    assert!(w.get("target").is_none(), "{w}");
}

#[test]
fn a_set_the_policy_does_not_have_fails_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let bad = format!(
        "environment = \"production\"\n[examples.sdk]\ndir = \"{}\"\ncommand = []\n",
        dir.path().display()
    );
    assert!(Policy::from_toml(&bad).is_err());
    let relative =
        "environment = \"production\"\n[examples.sdk]\ndir = \"rel\"\ncommand = [\"true\"]\n";
    assert!(Policy::from_toml(relative).is_err());
}
