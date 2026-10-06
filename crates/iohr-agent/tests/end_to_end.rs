//! The agent against a fake control plane that speaks the shared contract: enroll, a
//! token endpoint that verifies the `private_key_jwt` assertion's signature with the
//! enrolled public key, and the WebSocket session.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

mod common;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::json;

use common::*;
use iohr_agent::checks_file::DeclaredChecks;
use iohr_agent::enroll::enroll;
use iohr_agent::keys::{AgentKey, KeyAlg};
use iohr_agent::token::TokenSource;

#[tokio::test]
async fn enroll_token_session_job_result() {
    for alg in [KeyAlg::Es256, KeyAlg::Ed25519] {
        let mut h = harness(alg).await;
        let (agent, stop, task) = start(&h).await;

        let (n, hello) = next(&mut h.frames, "hello").await;
        assert_eq!(n, 1);
        assert_eq!(hello["policy_hash"], h.policy.hash());
        assert_eq!(hello["domains"], json!(["example.com"]));
        assert!(
            hello.get("checks").is_none() && hello.get("checks_hash").is_none(),
            "no checks file, no checks: {hello}"
        );
        let t = hello["agent_time"].as_str().unwrap();
        let t =
            time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).unwrap();
        assert!((time::OffsetDateTime::now_utc() - t).abs() < time::Duration::minutes(1));
        let caps: Vec<&str> = hello["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            caps,
            ["check:http", "check:tcp", "check:tls", "check:grpc_health"]
        );

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let web = http_target().await;
        let secret_ref = format!(
            "file:{}",
            h.cfg.policy.with_file_name("check-token").display()
        );
        h.cmds
            .send(job(
                "j-tcp",
                "check",
                json!({"surface": "tcp", "target": {"host": "127.0.0.1", "port": tcp_addr.port()}}),
            ))
            .ok();
        h.cmds.send(job("j-http", "check", json!({"surface": "http", "target": {"url": format!("http://{web}/healthz?token=in-the-query")}, "expect": {"status": 204}}))).ok();
        h.cmds.send(job("j-auth", "check", json!({"surface": "http", "target": {"url": format!("http://{web}/private")}, "auth": {"scheme": "Bearer", "secret": secret_ref}}))).ok();
        h.cmds
            .send(job(
                "j-down",
                "check",
                json!({"surface": "tcp", "target": {"host": "127.0.0.1", "port": 1}}),
            ))
            .ok();
        let r = results(&mut h.frames, 4).await;

        assert_eq!(r["j-tcp"]["status"], "ok");
        assert_eq!(r["j-tcp"]["detail"]["ok"], true);
        assert_eq!(r["j-http"]["status"], "ok");
        assert_eq!(r["j-http"]["detail"]["status_code"], 204);
        assert_eq!(r["j-auth"]["status"], "ok", "{}", r["j-auth"]);
        assert_eq!(r["j-down"]["status"], "failed");
        assert_eq!(r["j-down"]["detail"]["error_class"], "connect");
        for f in r.values() {
            let text = f.to_string();
            assert!(!text.contains("secret body"), "a body travelled: {text}");
            assert!(!text.contains("in-the-query"), "a URL travelled: {text}");
            assert!(!text.contains("e2e-secret"), "a secret travelled: {text}");
            assert!(f["started_at"].is_string() && f["finished_at"].is_string());
        }
        let (_, hb) = next(&mut h.frames, "heartbeat").await;
        assert!(hb["seq"].as_u64().unwrap() >= 1);

        let snap = agent.state.snapshot();
        assert!(snap.connected);
        assert_eq!(snap.sent.results_ok, 3);
        assert_eq!(snap.sent.results_failed, 1);
        assert!(
            snap.recent_jobs
                .iter()
                .all(|j| j.target_host.as_deref() == Some("127.0.0.1"))
        );
        assert_eq!(h.fake.rejected_assertions.load(Ordering::SeqCst), 0);

        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn hello_declares_the_checks_file() {
    let mut h = harness(KeyAlg::Es256).await;
    std::fs::write(
        &h.cfg.checks,
        r#"
[[check]]
name = "api"
surface = "http"
target = "https://api.example.com/healthz"
every = "60s"
expect = { status = 200, max_ms = 2000 }
rfc = "0029"

[[refuse]]
name = "private-is-refused"
target = "https://db.internal/"
by = "policy"
every = "5m"

[[refuse]]
name = "api-needs-a-token"
target = "https://api.example.com/v1/me"
expect = { status = 401 }
every = "5m"
"#,
    )
    .unwrap();
    let declared = DeclaredChecks::load(&h.cfg.checks).unwrap().unwrap();
    let (agent, stop, task) = start(&h).await;

    let (_, hello) = next(&mut h.frames, "hello").await;
    assert_eq!(hello["checks_hash"], declared.hash.as_str());
    assert!(
        hello["checks_hash"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    );
    assert_eq!(
        hello["checks"],
        json!([
            {"key": "api", "kind": "check", "surface": "http",
             "target": {"url": "https://api.example.com/healthz"},
             "every_secs": 60, "fail_after": 2,
             "expect": {"status": 200, "max_ms": 2000}, "rfc": "0029"},
            {"key": "private-is-refused", "kind": "refuse", "refuse_by": "policy",
             "surface": "http", "target": {"url": "https://db.internal/"},
             "every_secs": 300, "fail_after": 1},
            {"key": "api-needs-a-token", "kind": "refuse", "refuse_by": "answer",
             "surface": "http", "target": {"url": "https://api.example.com/v1/me"},
             "every_secs": 300, "fail_after": 1, "expect": {"status": 401}}
        ])
    );
    assert!(hello["agent_time"].as_str().unwrap().ends_with('Z'));
    let snap = agent.state.snapshot();
    assert_eq!(snap.policy.checks, 3);
    assert_eq!(
        snap.policy.checks_hash.as_deref(),
        Some(declared.hash.as_str())
    );

    // A job for a declared check is an ordinary job: the policy still decides.
    h.cmds
        .send(job(
            "j-declared",
            "check",
            json!({"surface": "http", "target": {"url": "https://db.internal/"}}),
        ))
        .ok();
    let r = results(&mut h.frames, 1).await;
    assert_eq!(r["j-declared"]["status"], "refused");
    assert_eq!(
        r["j-declared"]["detail"]["error_class"],
        "refused_by_policy"
    );

    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn policy_refusals_reach_the_platform() {
    let mut h = harness(KeyAlg::Es256).await;
    let (agent, stop, task) = start(&h).await;
    next(&mut h.frames, "hello").await;
    let web = http_target().await;
    h.cmds
        .send(job(
            "r-net",
            "check",
            json!({"surface": "tcp", "target": {"host": "10.255.255.1", "port": 22}}),
        ))
        .ok();
    h.cmds
        .send(job(
            "r-name",
            "check",
            json!({"surface": "http", "target": {"url": "https://evil.example.net/"}}),
        ))
        .ok();
    h.cmds.send(job("r-fault", "fault", json!({}))).ok();
    h.cmds.send(job("r-load", "load", json!({}))).ok();
    h.cmds.send(job("r-secret", "check", json!({"surface": "http", "target": {"url": format!("http://{web}/private")}, "auth": {"secret": "env:HOME"}}))).ok();
    h.cmds
        .send(job(
            "r-meta",
            "check",
            json!({"surface": "tcp", "target": {"host": "169.254.169.254", "port": 80}}),
        ))
        .ok();
    h.cmds
        .send(job("r-junk", "check", json!({"surface": "smtp"})))
        .ok();
    let r = results(&mut h.frames, 7).await;
    let reason = |id: &str| r[id]["refusal"]["reason"].as_str().unwrap().to_owned();
    for (id, f) in &r {
        assert_eq!(f["status"], "refused", "{id}: {f}");
        assert_eq!(f["detail"]["error_class"], "refused_by_policy");
    }
    assert!(
        reason("r-net").contains("networks.allow"),
        "{}",
        reason("r-net")
    );
    assert!(reason("r-name").contains("bound domain"));
    assert!(reason("r-fault").contains("faults"));
    assert!(reason("r-load").contains("load"));
    assert!(reason("r-secret").contains("[secrets] allow"));
    assert!(reason("r-meta").contains("networks.deny"));
    assert_eq!(agent.state.snapshot().sent.results_refused, 7);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn reconnects_and_stops_work_when_disconnected() {
    let mut h = harness(KeyAlg::Es256).await;
    let (agent, stop, task) = start(&h).await;
    assert_eq!(next(&mut h.frames, "hello").await.0, 1);
    // A target that accepts and never answers: the job hangs until its deadline.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = VecDeque::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push_back(s);
        }
    });
    h.cmds.send(Cmd::Send(json!({"type": "job", "job_id": "hang", "kind": "check", "deadline_ms": 3000,
        "spec": {"surface": "grpc_health", "target": {"host": "127.0.0.1", "port": silent_addr.port(), "tls": false}}}))).ok();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.cmds.send(Cmd::Close).ok();

    let (n, hello) = next(&mut h.frames, "hello").await;
    assert_eq!(n, 2, "the agent reconnects");
    assert_eq!(hello["policy_hash"], h.policy.hash());
    assert!(h.fake.issued.lock().await.len() <= 2);
    // The hanging job was stopped with the first session: no result ever arrives.
    let late = tokio::time::timeout(Duration::from_secs(4), next(&mut h.frames, "result")).await;
    assert!(late.is_err(), "a job outlived its session: {late:?}");
    assert_eq!(agent.state.snapshot().received.sessions, 2);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn revoked_agent_stops_for_good() {
    let mut h = harness(KeyAlg::Es256).await;
    let (agent, _stop, task) = start(&h).await;
    next(&mut h.frames, "hello").await;
    h.cmds
        .send(Cmd::Send(
            json!({"type": "revoked", "reason": "revoked in the console"}),
        ))
        .ok();
    let end = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(end, Err(iohr_agent::Error::Revoked(_))), "{end:?}");
    assert!(agent.state.snapshot().revoked);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        h.fake.sessions.load(Ordering::SeqCst),
        1,
        "no reconnect after revocation"
    );
}

#[tokio::test]
async fn a_foreign_key_cannot_get_a_token() {
    let h = harness(KeyAlg::Es256).await;
    let enrollment = enroll_agent(&h).await;
    let stranger = AgentKey::generate(KeyAlg::Es256).unwrap();
    let src = TokenSource::new(
        reqwest::Client::new(),
        Arc::new(enrollment),
        Arc::new(stranger),
    );
    assert!(src.access_token().await.is_err());
    assert_eq!(h.fake.rejected_assertions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn enrollment_refuses_a_wrong_environment_and_reuse() {
    let mut h = harness(KeyAlg::Es256).await;
    h.cfg.environment = "production".into();
    let http = reqwest::Client::new();
    let e = enroll(params(&h, &http, ENROLL_TOKEN)).await.unwrap_err();
    assert!(e.to_string().contains("environment"), "{e}");
    assert!(
        !h.cfg.key.exists(),
        "no key is kept after a refused enrollment"
    );
    let e = enroll(params(&h, &http, "ioe_WRONGWRONGWRONGWRONGWRONG"))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("401"), "{e}");
    assert!(
        !e.to_string().contains("WRONG"),
        "the token is never echoed"
    );
}
