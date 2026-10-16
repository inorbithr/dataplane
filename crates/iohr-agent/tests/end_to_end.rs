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
    let mut h = harness_with(KeyAlg::Es256, "[share]\ntargets = \"full\"\n").await;
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
    // The hash is over the checks exactly as sent.
    let sent_hash = iohr_agent::ledger::sha256_hex(
        iohr_agent::checks_file::canonical_json(&hello["checks"]).as_bytes(),
    );
    assert_eq!(hello["checks_hash"], sent_hash.as_str());
    assert_eq!(declared.entries.len(), 3);
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
             "expect": {"status": 200, "max_ms": 2000}, "rfc": "0029",
             "label": "api", "target_shared": "full"},
            {"key": "private-is-refused", "kind": "refuse", "refuse_by": "policy",
             "surface": "http", "target": {"url": "https://db.internal/"},
             "every_secs": 300, "fail_after": 1,
             "label": "private-is-refused", "target_shared": "full"},
            {"key": "api-needs-a-token", "kind": "refuse", "refuse_by": "answer",
             "surface": "http", "target": {"url": "https://api.example.com/v1/me"},
             "every_secs": 300, "fail_after": 1, "expect": {"status": 401},
             "label": "api-needs-a-token", "target_shared": "full"}
        ])
    );
    assert!(hello["agent_time"].as_str().unwrap().ends_with('Z'));
    let snap = agent.state.snapshot();
    assert_eq!(snap.policy.checks, 3);
    assert_eq!(snap.policy.checks_hash.as_deref(), Some(sent_hash.as_str()));

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

#[tokio::test]
async fn hello_reports_metadata_without_what_stays_local() {
    let mut h = harness(KeyAlg::Es256).await;
    let m = &mut h.cfg.metadata;
    m.placement.country = Some("DE".to_owned().try_into().unwrap());
    m.placement.site_id = Some("FRA-DC2".into());
    m.placement.rack = Some("B12".into());
    m.organisation.team = Some("payments-sre".into());
    m.security.trust_domain = Some("example/fra-dc2/payments".into());
    m.security.secrets_backend = Some("vault:kv/prod".into());
    m.network.ntp = Some("ntp.example.internal".into());
    m.operations.runbook = Some("https://runbooks.example.internal/payments".into());
    let (_agent, stop, task) = start(&h).await;

    let (_, hello) = next(&mut h.frames, "hello").await;
    let meta = &hello["metadata"];
    assert_eq!(meta["placement"]["country"], "DE", "{hello}");
    assert_eq!(meta["placement"]["site_id"], "FRA-DC2");
    assert_eq!(meta["organisation"]["team"], "payments-sre");
    assert_eq!(meta["security"]["trust_domain"], "example/fra-dc2/payments");
    let text = meta.to_string();
    for local in ["rack", "secrets_backend", "ntp", "operations", "runbook"] {
        assert!(
            !text.contains(&format!("\"{local}\":")),
            "{local} left the machine: {text}"
        );
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn hello_carries_no_metadata_when_reporting_is_off_or_nothing_is_set() {
    let mut h = harness(KeyAlg::Es256).await;
    let (_agent, stop, task) = start(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    assert!(hello.get("metadata").is_none(), "{hello}");
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();

    h.cfg.metadata.placement.country = Some("HR".to_owned().try_into().unwrap());
    h.cfg.metadata.report = false;
    let (_agent, stop, task) = start(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    assert!(hello.get("metadata").is_none(), "{hello}");
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

/// Starts the agent with its host sampler reading the captured TRX40 tree instead of `/`.
async fn start_on_fixture(
    h: &Harness,
) -> (
    Arc<iohr_agent::agent::Agent>,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<iohr_agent::Result<()>>,
) {
    use iohr_agent::host::{sampler::Sampler, sysfs::Root};
    let enrollment = match iohr_agent::enroll::Enrollment::load(&h.cfg.state_dir).unwrap() {
        Some(e) => e,
        None => enroll_agent(h).await,
    };
    let key = AgentKey::load(&h.cfg.key).unwrap();
    let agent = Arc::new(
        iohr_agent::agent::Agent::new(
            h.cfg.clone(),
            h.policy.clone(),
            DeclaredChecks::load(&h.cfg.checks).unwrap(),
            enrollment,
            key,
        )
        .unwrap(),
    );
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40/root");
    *agent
        .host
        .as_ref()
        .expect("[work] host builds a sampler")
        .lock()
        .unwrap() = Sampler::new(Root::at(&root), Duration::from_secs(60));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(Arc::clone(&agent).run(rx));
    (agent, tx, task)
}

/// RFC 0102: the heartbeat carries the host summary only when `[share] host` says so,
/// and then only coarse numbers and labels: here the captured TRX40, whose arrays and
/// NVMe controllers the platform can show.
#[tokio::test]
async fn the_heartbeat_carries_the_host_only_when_shared() {
    for (share, carried) in [("", false), ("host = true\n", true)] {
        let mut h = harness_with(
            KeyAlg::Es256,
            &format!(
                "[work]\nhost = true\nsurfaces = [\"http\", \"hwmon\"]\n[host]\nsample_secs = 5\nwindow_secs = 60\n[share]\ntargets = \"full\"\n{share}"
            ),
        )
        .await;
        let (_agent, stop, task) = start_on_fixture(&h).await;
        next(&mut h.frames, "hello").await;
        let (_, hb) = next(&mut h.frames, "heartbeat").await;
        assert_eq!(hb["seq"], 1);
        assert_eq!(hb.get("host").is_some(), carried, "{share:?}: {hb}");
        if carried {
            let host = &hb["host"];
            let md0 = host["arrays"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["name"] == "md0")
                .unwrap();
            assert_eq!(md0["level"], "raid0");
            assert!(host["controllers"].as_array().unwrap().len() >= 4);
            assert!(
                host["temperatures"]
                    .as_array()
                    .is_some_and(|t| !t.is_empty())
            );
            let text = host.to_string();
            for never in ["serial", "model", "firmware", "Samsung", "KINGSTON"] {
                assert!(!text.contains(never), "{never} left the machine: {text}");
            }
        }
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn an_hwmon_check_runs_from_the_sampler_and_survives_a_restart() {
    let mut h = harness_with(
        KeyAlg::Es256,
        "[work]\nhost = true\nsurfaces = [\"http\", \"hwmon\"]\n[host]\nsample_secs = 5\nwindow_secs = 60\n[share]\ntargets = \"full\"\n",
    )
    .await;
    std::fs::write(
        &h.cfg.checks,
        r#"
[[check]]
name = "chipset-temp"
surface = "hwmon"
target = { sensor = "asusec/Chipset" }
every = "60s"
warn = 100
crit = 108
fail_after = 1
"#,
    )
    .unwrap();
    let (agent, stop, task) = start_on_fixture(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    let caps: Vec<&str> = hello["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.as_str())
        .collect();
    assert!(caps.contains(&"check:hwmon"), "{caps:?}");
    assert_eq!(
        hello["checks"][0]["target"],
        json!({"sensor": "asusec/temp/Chipset"})
    );
    let first_hash = hello["checks_hash"].clone();

    // Let the sampler take its first reading.
    for _ in 0..50 {
        if agent
            .host
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .now_ms()
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let spec = json!({"surface": "hwmon", "target": {"sensor": "asusec/temp/Chipset"}, "key": "chipset-temp"});
    h.cmds.send(job("j-hw", "check", spec)).ok();
    // A job that is not the declared check is refused: thresholds come from checks.toml only.
    h.cmds
        .send(job(
            "j-hw-undeclared",
            "check",
            json!({"surface": "hwmon", "target": {"sensor": "asusec/temp/Chipset"}}),
        ))
        .ok();
    let r = results(&mut h.frames, 2).await;
    assert_eq!(r["j-hw"]["status"], "ok", "{}", r["j-hw"]);
    let reading = &r["j-hw"]["detail"]["reading"];
    assert_eq!(reading["sensor"], "asusec/temp/Chipset");
    assert_eq!(reading["value"], 107_000);
    assert_eq!(reading["level"], "warn");
    assert_eq!(reading["unit"], "millicelsius");
    assert_eq!(r["j-hw-undeclared"]["status"], "refused");
    let sessions = h.fake.sessions.load(Ordering::SeqCst);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();

    // Restart on the same state: the same identity (no new enrollment), the same declared
    // checks under the same hash, so the platform keeps one monitor per key.
    let (_agent, stop, task) = start_on_fixture(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    assert_eq!(hello["checks_hash"], first_hash);
    assert!(h.fake.sessions.load(Ordering::SeqCst) > sessions);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

/// ADR 0049: every frame the platform received has a ledger entry with its exact size and
/// SHA-256, in order, chained; the token requests and the session opening are recorded
/// too; the chain verifies, and an edit breaks it.
#[tokio::test]
async fn every_upstream_frame_has_a_ledger_entry() {
    let mut h = harness(KeyAlg::Es256).await;
    let (agent, stop, task) = start(&h).await;
    next(&mut h.frames, "hello").await;
    h.cmds.send(job("j-refused", "load", json!({}))).ok();
    next(&mut h.frames, "result").await;
    next(&mut h.frames, "heartbeat").await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();

    let dir = iohr_agent::ledger::dir_in(&h.cfg.state_dir);
    let v = iohr_agent::ledger::verify(&dir);
    assert!(v.ok(), "{v:?}");
    let mut out = Vec::new();
    iohr_agent::ledger::export(&dir, &mut out).unwrap();
    let entries: Vec<iohr_agent::ledger::Entry> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let frames: Vec<&iohr_agent::ledger::Entry> = entries
        .iter()
        .filter(|e| ["hello", "heartbeat", "result"].contains(&e.kind.as_str()))
        .collect();
    let raw = h.fake.raw.lock().unwrap().clone();
    assert_ne!(raw, [] as [std::string::String; 0]);
    // The agent may have recorded a frame the platform never read (sent at shutdown);
    // never the other way round.
    assert!(
        frames.len() >= raw.len(),
        "{} entries, {} frames",
        frames.len(),
        raw.len()
    );
    for (e, r) in frames.iter().zip(&raw) {
        assert_eq!(
            e.sha256,
            iohr_agent::ledger::sha256_hex(r.as_bytes()),
            "{e:?}"
        );
        assert_eq!(e.bytes, r.len() as u64);
        assert_eq!(e.policy, h.policy.hash());
        assert!(e.destination.ends_with("/v1/agents/session"), "{e:?}");
    }
    let refused = frames.iter().find(|e| e.kind == "result").unwrap();
    assert_eq!(refused.rule, "contract.refusal");
    assert_eq!(refused.job_id.as_deref(), Some("j-refused"));
    assert!(
        entries
            .iter()
            .any(|e| e.kind == "token_request" && e.rule == "contract.token")
    );
    assert!(entries.iter().any(|e| e.kind == "session_open"));
    // The ledger knows nothing of payloads: no field holds the frames' content.
    let text = serde_json::to_string(&entries).unwrap();
    assert!(!text.contains("agent_version") && !text.contains("client_assertion"));
    // The page shows the same head.
    let (seq, head) = agent.ledger.as_ref().unwrap().head();
    assert_eq!(Some(seq), v.last_seq);
    assert_eq!(Some(head), v.head);
}

/// RFC 0100 D11 and D13: the hello carries only what `[share]` allows, at every level;
/// a job names a hidden check by its key; a refusal leaves without the target; and the
/// ledger records the hello that left.
#[tokio::test]
async fn the_hello_shares_only_what_the_policy_allows() {
    let web = http_target().await;
    for (share, level) in [
        ("", "hash"),
        ("[share]\ntargets = \"hash\"\n", "hash"),
        ("[share]\ntargets = \"label\"\n", "label"),
        ("[share]\ntargets = \"full\"\nhostname = true\n", "full"),
    ] {
        let mut h = harness_with(KeyAlg::Es256, share).await;
        std::fs::write(
            &h.cfg.checks,
            format!(
                r#"
[[check]]
name = "web"
label = "the web tier"
target = "http://{web}/healthz"
every = "60s"

[[refuse]]
name = "orders-db-closed"
surface = "tcp"
target = "10.9.8.7:5432"
by = "policy"
every = "5m"
"#
            ),
        )
        .unwrap();
        let (_agent, stop, task) = start(&h).await;
        let (_, hello) = next(&mut h.frames, "hello").await;
        let raw = h.fake.raw.lock().unwrap()[0].clone();
        let hidden = level != "full";
        assert_eq!(raw.contains(&web.to_string()), !hidden, "{level}: {raw}");
        assert_eq!(raw.contains("10.9.8.7"), !hidden, "{level}: {raw}");
        assert_eq!(
            raw.contains("hmac-sha256:"),
            level == "hash",
            "{level}: {raw}"
        );
        assert_eq!(hello["checks"][0]["label"], "the web tier");
        assert_eq!(hello["checks"][0]["target_shared"], level);
        assert_eq!(hello.get("hostname").is_some(), level == "full", "{level}");
        if level == "full" {
            assert_eq!(hello["hostname"], iohr_agent::host::sysfs::host_name());
        }

        // A job by key alone: the target comes from checks.toml.
        let mut spec = json!({"surface": "http", "key": "web"});
        if level == "hash" {
            spec["target_hash"] = hello["checks"][0]["target_hash"].clone();
        }
        if level == "full" {
            spec["target"] = json!({"url": format!("http://{web}/healthz")});
        }
        h.cmds.send(job("j-web", "check", spec)).ok();
        let r = results(&mut h.frames, 1).await;
        assert_eq!(r["j-web"]["status"], "ok", "{level}: {}", r["j-web"]);
        if level == "hash" {
            // A hash that is not this check's is refused.
            h.cmds
                .send(job(
                    "j-forged",
                    "check",
                    json!({"surface": "http", "key": "web", "target_hash": "hmac-sha256:00"}),
                ))
                .ok();
            let r = results(&mut h.frames, 1).await;
            assert_eq!(r["j-forged"]["status"], "refused");
        }
        // A refusal by policy leaves without the address the policy refused.
        let mut spec = json!({"surface": "tcp", "key": "orders-db-closed"});
        if level == "full" {
            spec["target"] = json!({"host": "10.9.8.7", "port": 5432});
        }
        h.cmds.send(job("j-db", "check", spec)).ok();
        let r = results(&mut h.frames, 1).await;
        assert_eq!(r["j-db"]["status"], "refused", "{level}: {}", r["j-db"]);
        let reason = r["j-db"]["refusal"]["reason"].as_str().unwrap().to_owned();
        assert_eq!(reason.contains("10.9.8.7"), !hidden, "{level}: {reason}");

        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        // The ledger recorded the hello exactly as it left.
        let dir = iohr_agent::ledger::dir_in(&h.cfg.state_dir);
        let mut out = Vec::new();
        iohr_agent::ledger::export(&dir, &mut out).unwrap();
        let hello_entry: iohr_agent::ledger::Entry = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<iohr_agent::ledger::Entry>(l).unwrap())
            .find(|e| e.kind == "hello")
            .unwrap();
        assert_eq!(
            hello_entry.sha256,
            iohr_agent::ledger::sha256_hex(raw.as_bytes())
        );
        assert!(iohr_agent::ledger::verify(&dir).ok());
    }
}

/// The owner's way to change what InOrbit sees on a running agent: `[share]` is set
/// through the local page (as `iohr agent share` does, with this run's token), the policy
/// file keeps the rest, the agent reloads without a restart and greets the platform again
/// saying what the new policy shares, and both choices are on the ledger.
#[tokio::test]
async fn a_share_change_reloads_the_running_agent() {
    let mut h = harness(KeyAlg::Es256).await;
    let web = http_target().await;
    std::fs::write(
        &h.cfg.checks,
        format!("[[check]]\nname = \"web\"\ntarget = \"http://{web}/healthz\"\nevery = \"60s\"\n"),
    )
    .unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    h.cfg.admin.listen = format!("127.0.0.1:{port}").parse().unwrap();
    let enrollment = enroll_agent(&h).await;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(iohr_agent::agent::supervise(h.cfg.clone(), enrollment, rx));

    let (_, hello) = next(&mut h.frames, "hello").await;
    assert_eq!(hello["checks"][0]["target_shared"], "hash");
    assert!(hello.get("hostname").is_none());

    let token = std::fs::read_to_string(h.cfg.state_dir.join("admin.token")).unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/policy/share"))
        .bearer_auth(token.trim())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("targets=full&hostname=on")
        .send()
        .await
        .unwrap();
    let status = r.status();
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(status.is_success(), "{status} {body}");
    assert_eq!(body["ok"], true, "{body}");

    // A new session, its hello sharing what the new policy says.
    let (n, hello) = next(&mut h.frames, "hello").await;
    assert_eq!(n, 2, "a second session");
    assert_eq!(hello["checks"][0]["target_shared"], "full");
    assert_eq!(
        hello["checks"][0]["target"]["url"],
        format!("http://{web}/healthz")
    );
    assert_eq!(hello["hostname"], iohr_agent::host::sysfs::host_name());
    let text = std::fs::read_to_string(&h.cfg.policy).unwrap();
    assert!(
        text.contains("[share]") && text.contains("targets = \"full\""),
        "{text}"
    );
    assert!(
        text.starts_with(common::POLICY.trim_start_matches('\n'))
            || text.contains("bound = [\"example.com\"]"),
        "the rest kept: {text}"
    );

    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    let dir = iohr_agent::ledger::dir_in(&h.cfg.state_dir);
    assert!(iohr_agent::ledger::verify(&dir).ok());
    let mut out = Vec::new();
    iohr_agent::ledger::export(&dir, &mut out).unwrap();
    let kinds: Vec<String> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<iohr_agent::ledger::Entry>(l)
                .unwrap()
                .kind
        })
        .filter(|k| k == "share_set")
        .collect();
    assert_eq!(kinds.len(), 2, "the first choice and the change");
}

/// RFC 0088.1: the hello carries the inventory (what the policy admits, the ceilings and
/// the extensions `iohr-ext.lock` pins) unless `[share] inventory = false`; never an
/// address or a host name.
#[tokio::test]
async fn the_hello_carries_the_inventory_unless_turned_off() {
    let digest = format!("sha256:{}", "ab".repeat(32));
    for (share, sent) in [("", true), ("[share]\ninventory = false\n", false)] {
        let mut h = harness_with(KeyAlg::Es256, share).await;
        let lock = h.cfg.policy.parent().unwrap().join("iohr-ext.lock");
        std::fs::write(
            &lock,
            format!(
                "version = 2\n[[extension]]\nname = \"capture\"\nversion = \"0.1.0-alpha.10\"\ndigest = \"{digest}\"\nsigner = \"https://github.com/inorbithr/dataplane/.github/workflows/release.yml\"\nprivileges = [\"cap_bpf\"]\n"
            ),
        )
        .unwrap();
        h.cfg.extensions_lock = Some(lock);
        let (_agent, stop, task) = start(&h).await;
        let (_, hello) = next(&mut h.frames, "hello").await;
        if sent {
            let inv = &hello["inventory"];
            assert_eq!(inv["format"], 1, "{hello}");
            assert_eq!(inv["work"]["checks"], true);
            assert_eq!(inv["work"]["load"], false);
            assert!(
                inv["surfaces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s == "http")
            );
            assert!(inv["ceilings"]["max_concurrent_jobs"].as_u64().unwrap() >= 1);
            assert_eq!(inv["extensions"][0]["name"], "capture");
            assert_eq!(inv["extensions"][0]["digest"], digest);
            assert_eq!(inv["extensions"][0]["privileges"][0], "cap_bpf");
        } else {
            assert!(hello.get("inventory").is_none(), "{hello}");
        }
        assert!(hello.get("hostname").is_none());
        let _ = stop.send(true);
        let _ = task.await;
    }
}
