//! DAT-10 evidence: captured traffic stays on the host.
//!
//! A companion that misbehaves on purpose answers the agent's `counts` request with names,
//! paths, SNI, DNS names, addresses and pod identifiers mixed into every field it can,
//! plus a full `tables` section. The agent runs with `[work] capture = true`, OTLP export
//! on (to a fake collector) and a fake platform, sends its hello, runs a job, serves its
//! admin page. The test fails if any of those values appears in:
//!
//! - any frame the platform received (hello, heartbeats, results),
//! - the admin page HTML or `status.json`,
//! - any OTLP export (traces, metrics, logs; bodies are protobuf, strings are raw bytes),
//!
//! and it checks the agent never asked for `tables`, while the hello does carry the
//! `capture:*` capability strings and the admin page does carry the counts (so the test is
//! not vacuous). `docs/capture/install.md` ("What capture never does") cites this test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

mod common;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde_json::{Value, json};

use common::*;
use iohr_agent::config::TelemetryConfig;
use iohr_agent::keys::KeyAlg;

/// Values a capture snapshot can hold. None may leave the companion's socket.
const CANARIES: [&str; 8] = [
    "canary-sni.example",
    "canary-host.example",
    "canary-dns.example",
    "/canary/path",
    "10.99.88.77",
    "canary-pod-0a1b2c3d",
    "canary-process",
    "canary-version",
];

fn poisoned_answer() -> Value {
    let rows = |k: &str| json!([{"key": k, "count": 7, "error": 0}]);
    json!({
        "version": 1,
        "companion_version": "canary-version",
        "interface": "canary-host.example",
        "updated_unix_ms": iohr_agent::capture::now_ms(),
        "layers": ["headers", "protocols", "owners", "tcp", "canary-dns.example"],
        "headers": {"ingress": {"packets": 424_242, "bytes": 99}, "egress": {"packets": 7, "bytes": 8},
                    "note": "canary-sni.example"},
        "drops": {"rate_limited": 0, "ring_buffer_full": 0, "flows_evicted": 0, "who": "10.99.88.77"},
        "protocols": {"http1_requests": 31_337, "tls_client_hellos": 2, "dns_queries": 3,
                      "http2_connections": 1, "grpc_calls": 1, "top_path": "/canary/path"},
        "owners": {"sockets": 5, "owners": 1, "flows_owned": 3, "flows_unowned": 0, "pod": "canary-pod-0a1b2c3d"},
        "tcp": {"established": 1, "listening": 2, "retransmits_sampled": 0, "resets_in": 0, "resets_out": 0,
                "host": {"listen_overflows": 0}, "process": "canary-process"},
        "tables": {
            "tls": {"sni": rows("canary-sni.example")},
            "http1": {"hosts": rows("canary-host.example"), "paths": rows("GET /canary/path")},
            "dns": {"names": rows("canary-dns.example")},
            "remote_addresses": rows("10.99.88.77"),
            "owners": [{"owner": "kubernetes:pod canary-pod-0a1b2c3d", "process": "canary-process"}],
        }
    })
}

/// A companion on a Unix socket that always sends the poisoned answer and counts what it
/// was asked.
async fn companion(path: std::path::PathBuf, asked: Arc<StdMutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let l = tokio::net::UnixListener::bind(&path).unwrap();
    loop {
        let Ok((mut s, _)) = l.accept().await else {
            continue;
        };
        let asked = Arc::clone(&asked);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req: Value =
                serde_json::from_slice(buf[..n].split(|b| *b == b'\n').next().unwrap_or_default())
                    .unwrap_or_default();
            asked
                .lock()
                .unwrap()
                .push(req["request"].as_str().unwrap_or("").to_owned());
            let _ = s.write_all(poisoned_answer().to_string().as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

/// A fake OTLP/HTTP collector on its own thread and runtime (it must outlive the agent's
/// runtime: exporters flush at shutdown). Returns its base URL and what it received.
/// What the fake collector received: `(path, body)`.
type Exports = Arc<StdMutex<Vec<(String, Vec<u8>)>>>;

fn collector() -> (String, Exports) {
    let got: Exports = Arc::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let store = Arc::clone(&got);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            let app = axum::Router::new().fallback(
                move |uri: axum::http::Uri, body: axum::body::Bytes| {
                    let store = Arc::clone(&store);
                    async move {
                        store
                            .lock()
                            .unwrap()
                            .push((uri.path().to_owned(), body.to_vec()));
                        axum::http::StatusCode::OK
                    }
                },
            );
            axum::serve(l, app).await.unwrap();
        });
    });
    let addr = rx.recv().unwrap();
    (format!("http://{addr}"), got)
}

fn leaks(text: &str) -> Vec<&'static str> {
    CANARIES
        .iter()
        .copied()
        .filter(|c| text.contains(c))
        .collect()
}

#[test]
fn dat10_captured_traffic_stays_on_the_host() {
    iohr_agent::tls::install_crypto_provider();
    let (otlp, exported) = collector();
    // OTLP export on, before any runtime (its HTTP client runs on its own threads).
    let telemetry = iohr_agent::telemetry::init(
        &TelemetryConfig {
            enabled: true,
            endpoint: otlp,
            service_name: "iohr-agent-privacy-test".into(),
        },
        false,
    )
    .unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (frames, html, status, asked) = rt.block_on(async {
        let sockdir = tempfile::tempdir().unwrap();
        let sock = sockdir.path().join("aggregates.sock");
        let asked: Arc<StdMutex<Vec<String>>> = Arc::default();
        tokio::spawn(companion(sock.clone(), Arc::clone(&asked)));
        let mut h = harness_with(
            KeyAlg::Es256,
            &format!(
                "[work]\ncapture = true\n[capture]\nsocket = \"{}\"\n",
                sock.display()
            ),
        )
        .await;
        let (agent, stop, task) = start(&h).await;
        let mut frames = Vec::new();
        let (_, hello) = next(&mut h.frames, "hello").await;
        frames.push(hello.clone());
        let web = http_target().await;
        h.cmds
            .send(job(
                "p-http",
                "check",
                json!({"surface": "http", "target": {"url": format!("http://{web}/healthz")}}),
            ))
            .ok();
        let (_, result) = next(&mut h.frames, "result").await;
        frames.push(result);
        let (_, hb) = next(&mut h.frames, "heartbeat").await;
        frames.push(hb);
        let snap = agent.state.snapshot();
        let html = iohr_agent::admin::render_html(&snap);
        let status = serde_json::to_string(&snap).unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        while let Ok((_, f)) = h.frames.try_recv() {
            frames.push(f);
        }
        let asked = asked.lock().unwrap().clone();
        (frames, html, status, asked)
    });
    drop(rt);
    telemetry.shutdown();

    // Not vacuous: the hello announces capture, the page shows the counts.
    let hello = &frames[0];
    let caps: Vec<&str> = hello["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for c in [
        "capture:headers",
        "capture:protocols",
        "capture:owners",
        "capture:tcp",
    ] {
        assert!(caps.contains(&c), "{c} missing from the hello: {caps:?}");
    }
    assert!(
        html.contains("Traffic") && html.contains("424242") && html.contains("31337"),
        "{html}"
    );
    assert!(
        !asked.is_empty() && asked.iter().all(|r| r == "counts"),
        "the agent asked for {asked:?}"
    );

    // Nothing from capture in any frame, the admin page, status.json.
    for f in &frames {
        let text = f.to_string();
        assert!(
            leaks(&text).is_empty(),
            "frame leaks {:?}: {text}",
            leaks(&text)
        );
    }
    assert!(
        leaks(&html).is_empty(),
        "admin page leaks {:?}",
        leaks(&html)
    );
    assert!(
        leaks(&status).is_empty(),
        "status.json leaks {:?}",
        leaks(&status)
    );

    // Nor in any OTLP export. Something was exported (the job's span and metrics).
    let exported = exported.lock().unwrap();
    let paths: Vec<&str> = exported.iter().map(|(p, _)| p.as_str()).collect();
    assert!(
        paths.contains(&"/v1/metrics") && paths.contains(&"/v1/traces"),
        "exported: {paths:?}"
    );
    for (path, body) in exported.iter() {
        let text = String::from_utf8_lossy(body);
        assert!(
            leaks(&text).is_empty(),
            "OTLP {path} leaks {:?}",
            leaks(&text)
        );
    }
}

#[tokio::test]
async fn no_capture_strings_without_the_policy_switch() {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("aggregates.sock");
    let asked: Arc<StdMutex<Vec<String>>> = Arc::default();
    tokio::spawn(companion(sock.clone(), Arc::clone(&asked)));
    // A [capture] section without `[work] capture = true` does nothing.
    let mut h = harness_with(
        KeyAlg::Es256,
        &format!("[capture]\nsocket = \"{}\"\n", sock.display()),
    )
    .await;
    let (agent, stop, task) = start(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    assert!(
        !hello["capabilities"].to_string().contains("capture:"),
        "{hello}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        asked.lock().unwrap().is_empty(),
        "the socket was not even asked"
    );
    assert!(agent.state.snapshot().capture.is_none());
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn no_capture_strings_when_the_companion_is_silent() {
    let sockdir = tempfile::tempdir().unwrap();
    let sock = sockdir.path().join("missing.sock");
    let mut h = harness_with(
        KeyAlg::Es256,
        &format!(
            "[work]\ncapture = true\n[capture]\nsocket = \"{}\"\n",
            sock.display()
        ),
    )
    .await;
    let (agent, stop, task) = start(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    assert!(
        !hello["capabilities"].to_string().contains("capture:"),
        "{hello}"
    );
    let info = agent.state.snapshot().capture.unwrap();
    assert_eq!(info.state, "not answering");
    assert!(iohr_agent::admin::render_html(&agent.state.snapshot()).contains("not answering"));
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
