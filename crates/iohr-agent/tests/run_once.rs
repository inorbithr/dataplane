//! `iohr-agent run --once`: the real binary against local targets, as a CI pipeline runs it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use iohr_agent::config::AgentConfig;
use url::Url;

/// A target answering `/ok` 200, `/down` 500 and `/denied` 401.
fn web_target() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let status = if req.starts_with("GET /ok") || req.starts_with("HEAD /ok") {
                "200 OK"
            } else if req.contains(" /denied") {
                "401 Unauthorized"
            } else {
                "500 Internal Server Error"
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
            );
        }
    });
    addr
}

struct Setup {
    _dir: tempfile::TempDir,
    config: std::path::PathBuf,
}

fn setup(checks: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AgentConfig::new(
        Url::parse("https://api.example.invalid/").unwrap(),
        "ci".into(),
        "staging".into(),
    );
    std::fs::write(
        dir.path().join("policy.toml"),
        "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.0/8\"]\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("checks.toml"), checks).unwrap();
    cfg.resolve_paths(dir.path());
    let config = dir.path().join("agent.toml");
    std::fs::write(&config, cfg.to_toml().unwrap()).unwrap();
    Setup { _dir: dir, config }
}

fn run(config: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_iohr-agent"))
        .arg("--config")
        .arg(config)
        .args(["run", "--once"])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn checks(web: SocketAddr) -> String {
    format!(
        r#"
[[check]]
name = "home"
surface = "http"
target = "http://{web}/ok"
every = "5m"
expect = {{ status = 200 }}
tags = {{ tier = "front" }}

[[check]]
name = "orders"
surface = "http"
target = "http://{web}/down"
every = "5m"
expect = {{ status = 200 }}

[[refuse]]
name = "metadata-guard"
by = "policy"
surface = "http"
target = "http://169.254.169.254/latest/meta-data/"
every = "5m"

[[refuse]]
name = "admin-needs-a-token"
surface = "http"
target = "http://{web}/denied"
every = "5m"
expect = {{ status = 401 }}

[[refuse]]
name = "outside-our-domains"
by = "platform"
surface = "http"
target = "https://example.org/"
every = "5m"
"#
    )
}

#[test]
fn a_failing_check_fails_the_run_and_every_check_is_reported() {
    let web = web_target();
    let s = setup(&checks(web));
    let (code, out) = run(&s.config, &["--format", "json"]);
    assert_eq!(code, 1, "{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let by_name = |n: &str| {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap_or_else(|| panic!("{n} missing: {out}"))
            .clone()
    };
    assert_eq!(by_name("home")["outcome"], "pass");
    assert_eq!(by_name("home")["status_code"], 200);
    assert_eq!(by_name("orders")["outcome"], "fail");
    assert_eq!(by_name("orders")["error_class"], "status");
    assert_eq!(by_name("metadata-guard")["outcome"], "pass", "{out}");
    assert_eq!(by_name("admin-needs-a-token")["outcome"], "pass", "{out}");
    assert_eq!(by_name("outside-our-domains")["outcome"], "skipped");
    assert_eq!(v["exit_code"], 1);
    assert_eq!(v["summary"]["fail"], 1);
    // Nothing a target said, never a body.
    assert!(!out.contains("Internal Server Error"), "{out}");
}

#[test]
fn selecting_only_passing_checks_exits_zero() {
    let web = web_target();
    let s = setup(&checks(web));
    let (code, out) = run(&s.config, &["--tag", "tier=front"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("1 checks: 1 pass. exit 0"), "{out}");
    let (code, out) = run(&s.config, &["--check", "home", "--check", "metadata-guard"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn an_unknown_check_name_cannot_be_judged() {
    let web = web_target();
    let s = setup(&checks(web));
    let (code, out) = run(&s.config, &["--check", "home", "--check", "nope"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("no check by this name"), "{out}");
}

#[test]
fn a_missing_config_is_exit_two_not_one() {
    let (code, _) = run(Path::new("/nonexistent/agent.toml"), &[]);
    assert_eq!(code, 2);
}

#[test]
fn junit_output_carries_the_failure() {
    let web = web_target();
    let s = setup(&checks(web));
    let (code, out) = run(&s.config, &["--format", "junit"]);
    assert_eq!(code, 1);
    assert!(out.starts_with("<?xml"), "{out}");
    assert!(
        out.contains("<testcase classname=\"http\" name=\"orders\""),
        "{out}"
    );
    assert!(out.contains("<failure"), "{out}");
    assert!(out.contains("<skipped"), "{out}");
}

#[test]
fn an_open_guard_fails_the_run() {
    let web = web_target();
    let s = setup(&format!(
        r#"
[[refuse]]
name = "guard-that-does-not-guard"
by = "policy"
surface = "http"
target = "http://{web}/ok"
every = "5m"
"#
    ));
    let (code, out) = run(&s.config, &["--format", "json"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("guard_open"), "{out}");
}

#[test]
fn evidence_is_the_report_signed_with_the_agent_key() {
    let web = web_target();
    let s = setup(&checks(web));
    let cfg = AgentConfig::load(&s.config).unwrap();
    let key = iohr_agent::keys::AgentKey::generate(iohr_agent::keys::KeyAlg::Es256).unwrap();
    key.save(&cfg.key, false).unwrap();
    let evidence = s.config.parent().unwrap().join("run.jws");
    let (code, _) = run(
        &s.config,
        &["--check", "home", "--evidence", evidence.to_str().unwrap()],
    );
    assert_eq!(code, 0);
    let jws = std::fs::read_to_string(&evidence).unwrap();
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWS");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(claims["typ"], "iohr.run-once/1");
    assert_eq!(claims["kid"], key.kid());
    assert_eq!(claims["report"]["checks"][0]["name"], "home");
    assert_eq!(claims["report"]["exit_code"], 0);
}
