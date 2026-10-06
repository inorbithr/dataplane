//! The transport surfaces (RFC 0040.2) against local servers, through the whole agent:
//! a fake platform sends each declared check's job by its key, the agent reads the
//! request from its own `checks.toml` and answers with a verdict.
//!
//! Every server answer and every error is poisoned with canary strings (bodies, GraphQL
//! error messages, `error` frames, MQTT payloads, `grpc-message`, MCP tool output and
//! descriptions, header values). The test fails if one of them, or the credential, reaches:
//!
//! - any frame the platform received (hello, results),
//! - the admin page HTML or `status.json`,
//! - any OTLP export (traces, metrics, logs).
//!
//! It also proves the bounds the owner asked for: a job names only the key, a job whose
//! target differs from the entry is refused, a transport surface the policy does not list
//! is refused, and an MCP tool that is not read-only is never called.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use futures_util::StreamExt as _;
use serde_json::{Value, json};

use common::*;
use iohr_agent::config::TelemetryConfig;
use iohr_agent::keys::KeyAlg;

/// What the targets put in their answers and errors. None may leave the agent.
const CANARIES: [&str; 13] = [
    "CANARY-SSE-DATA",
    "CANARY-GQL-DATA",
    "CANARY-GQL-ERROR",
    "CANARY-MCP-DESC",
    "CANARY-MCP-OUTPUT",
    "CANARY-MCP-SESSION",
    "CANARY-WS-DATA",
    "CANARY-WS-ERROR",
    "CANARY-MQTT-PAYLOAD",
    "CANARY-GRPC-MESSAGE",
    "CANARY-HTTP-BODY",
    "CANARY-HEADER",
    // The credential's value.
    "e2e-secret",
];

/// Calls of the write tool: must stay zero.
static WRITE_TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

fn authorized(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer e2e-secret")
}

async fn sse() -> Response {
    (
        [
            ("content-type", "text/event-stream"),
            ("x-canary", "CANARY-HEADER"),
        ],
        ": keep-alive\n\nevent: x\ndata: {\"v\":\"CANARY-SSE-DATA\"}\n\n",
    )
        .into_response()
}

async fn graphql(h: HeaderMap) -> Response {
    let body = if authorized(&h) {
        json!({"data": {"me": "CANARY-GQL-DATA"}})
    } else {
        json!({"data": null, "errors": [{"message": "CANARY-GQL-ERROR for user@example.com"}]})
    };
    axum::Json(body).into_response()
}

async fn mcp(h: HeaderMap, axum::Json(req): axum::Json<Value>) -> Response {
    if !authorized(&h) {
        return (StatusCode::UNAUTHORIZED, "CANARY-HTTP-BODY").into_response();
    }
    let id = req["id"].clone();
    let result = match req["method"].as_str().unwrap_or("") {
        "initialize" => json!({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "CANARY-MCP-DESC", "version": "1"}}),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "tools/list" => json!({"tools": [
            {"name": "read_thing", "description": "CANARY-MCP-DESC", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": true}},
            {"name": "write_thing", "description": "CANARY-MCP-DESC", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": false, "destructiveHint": true}},
        ]}),
        "tools/call" => {
            if req["params"]["name"] == "write_thing" {
                WRITE_TOOL_CALLS.fetch_add(1, Ordering::SeqCst);
            }
            // The answer as an event stream, as streamable HTTP may send it.
            let msg = json!({"jsonrpc": "2.0", "id": id,
                             "result": {"content": [{"type": "text", "text": "CANARY-MCP-OUTPUT"}]}});
            return (
                [("content-type", "text/event-stream")],
                format!("event: message\ndata: {msg}\n\n"),
            )
                .into_response();
        }
        _ => {
            return axum::Json(json!({"jsonrpc": "2.0", "id": id,
                                     "error": {"code": -32601, "message": "CANARY-MCP-DESC"}}))
            .into_response();
        }
    };
    (
        [("mcp-session-id", "CANARY-MCP-SESSION")],
        axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})),
    )
        .into_response()
}

async fn http_post(h: HeaderMap, body: Bytes) -> Response {
    let json = h
        .get("content-type")
        .is_some_and(|v| v.as_bytes() == b"application/json");
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if json && parsed["ping"] == "pong" {
        (StatusCode::OK, "CANARY-HTTP-BODY").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "CANARY-HTTP-BODY").into_response()
    }
}

async fn ws(upgrade: WebSocketUpgrade, h: HeaderMap) -> Response {
    if !authorized(&h) {
        return (StatusCode::UNAUTHORIZED, "CANARY-HTTP-BODY").into_response();
    }
    upgrade.on_upgrade(ws_session)
}

async fn ws_session(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.next().await {
        let Message::Text(t) = msg else { continue };
        let call: Value = serde_json::from_str(t.as_str()).unwrap();
        let id = call["id"].clone();
        let frames = if call["method"] == "pkg.Svc/Ok" {
            vec![
                json!({"type": "data", "id": id, "body": {"v": "CANARY-WS-DATA"}}),
                json!({"type": "end", "id": id}),
            ]
        } else {
            vec![json!({"type": "error", "id": id, "code": "forbidden",
                        "error": "CANARY-WS-ERROR", "details": [{"user": "CANARY-WS-ERROR"}]})]
        };
        for f in frames {
            socket.send(Message::text(f.to_string())).await.unwrap();
        }
    }
}

async fn mqtt(upgrade: WebSocketUpgrade, h: HeaderMap) -> Response {
    if !authorized(&h) {
        return (StatusCode::UNAUTHORIZED, "CANARY-HTTP-BODY").into_response();
    }
    upgrade.protocols(["mqtt"]).on_upgrade(mqtt_session)
}

// A tiny MQTT 5 gateway for the test: CONNACK, SUBACK, PUBACK and one answer per call.
fn varint(out: &mut BytesMut, mut v: usize) {
    loop {
        let mut b = u8::try_from(v & 0x7f).unwrap();
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.put_u8(b);
        if v == 0 {
            break;
        }
    }
}

fn read_varint(b: &mut &[u8]) -> usize {
    let mut v = 0;
    for i in 0.. {
        let x = b.get_u8();
        v |= usize::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            break;
        }
    }
    v
}

fn string(out: &mut BytesMut, s: &[u8]) {
    out.put_u16(u16::try_from(s.len()).unwrap());
    out.put_slice(s);
}

fn take(b: &mut &[u8]) -> Vec<u8> {
    let n = usize::from(b.get_u16());
    let v = b[..n].to_vec();
    b.advance(n);
    v
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u8(first);
    varint(&mut out, body.len());
    out.put_slice(body);
    out.to_vec()
}

async fn mqtt_session(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.next().await {
        let Message::Binary(data) = msg else { continue };
        let mut b: &[u8] = &data;
        let first = b.get_u8();
        let _len = read_varint(&mut b);
        match first >> 4 {
            1 => {
                // CONNACK: no session present, success, a reason string property.
                let mut body = BytesMut::new();
                body.put_u8(0);
                body.put_u8(0);
                let mut props = BytesMut::new();
                props.put_u8(0x1F);
                string(&mut props, b"CANARY-MQTT-PAYLOAD");
                varint(&mut body, props.len());
                body.put_slice(&props);
                socket
                    .send(Message::binary(packet(0x20, &body)))
                    .await
                    .unwrap();
            }
            8 => {
                let id = b.get_u16();
                let mut body = BytesMut::new();
                body.put_u16(id);
                body.put_u8(0);
                body.put_u8(1);
                socket
                    .send(Message::binary(packet(0x90, &body)))
                    .await
                    .unwrap();
            }
            3 => {
                let topic = String::from_utf8(take(&mut b)).unwrap();
                let id = b.get_u16();
                let props_len = read_varint(&mut b);
                let mut props = &b[..props_len];
                let (mut reply, mut corr) = (Vec::new(), Vec::new());
                while !props.is_empty() {
                    match props.get_u8() {
                        0x08 => reply = take(&mut props),
                        0x09 => corr = take(&mut props),
                        0x01 => {
                            props.get_u8();
                        }
                        other => panic!("unexpected property {other}"),
                    }
                }
                let mut ack = BytesMut::new();
                ack.put_u16(id);
                socket
                    .send(Message::binary(packet(0x40, &ack)))
                    .await
                    .unwrap();
                // The answer, QoS 1, with the correlation data, an error mark for a refusal.
                let mut p = BytesMut::new();
                p.put_u8(0x09);
                string(&mut p, &corr);
                if topic != "rpc/x/Ok" {
                    p.put_u8(0x26);
                    string(&mut p, b"error");
                    string(&mut p, b"forbidden");
                }
                let mut body = BytesMut::new();
                string(&mut body, &reply);
                body.put_u16(7);
                varint(&mut body, p.len());
                body.put_slice(&p);
                body.put_slice(br#"{"v":"CANARY-MQTT-PAYLOAD"}"#);
                socket
                    .send(Message::binary(packet(0x32, &body)))
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }
}

async fn web_target() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = Router::new()
        .route("/sse", get(sse))
        .route("/graphql", post(graphql))
        .route("/mcp", post(mcp))
        .route("/echo", any(http_post))
        .route("/v1/ws", get(ws))
        .route("/v1/mqtt", get(mqtt));
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

/// An h2c gRPC server: `pkg.Svc/Ok` answers OK, anything else UNAUTHENTICATED, both with
/// a poisoned `grpc-message` and a poisoned reply message.
async fn grpc_target() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(sock).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let ok = req.uri().path() == "/pkg.Svc/Ok";
                    let resp = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let mut msg = vec![0, 0, 0, 0, 21, 0x0a, 19];
                    msg.extend_from_slice(b"CANARY-GRPC-MESSAGE");
                    send.send_data(Bytes::from(msg), false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", if ok { "0" } else { "16" }.parse().unwrap());
                    trailers.insert("grpc-message", "CANARY-GRPC-MESSAGE".parse().unwrap());
                    send.send_trailers(trailers).unwrap();
                }
            });
        }
    });
    addr
}

fn checks_toml(web: SocketAddr, grpc: SocketAddr, secret: &str) -> String {
    let auth = format!("auth = \"file:{secret}\"\nauth_scheme = \"Bearer\"");
    format!(
        r#"
[[check]]
name = "sse"
surface = "sse"
target = "http://{web}/sse"
every = "15m"
category = "transport"
tags = {{ transport = "sse" }}

[[check]]
name = "graphql"
surface = "graphql"
target = "http://{web}/graphql"
query = "{{ me }}"
every = "15m"
{auth}

[[check]]
name = "graphql-no-token"
surface = "graphql"
target = "http://{web}/graphql"
every = "15m"

[[check]]
name = "mcp"
surface = "mcp"
target = "http://{web}/mcp"
min_tools = 2
tool = "read_thing"
args = {{ q = "x" }}
every = "15m"
{auth}

[[check]]
name = "mcp-write"
surface = "mcp"
target = "http://{web}/mcp"
tool = "write_thing"
every = "15m"
{auth}

[[check]]
name = "mcp-too-few"
surface = "mcp"
target = "http://{web}/mcp"
min_tools = 3
every = "15m"
{auth}

[[check]]
name = "ws"
surface = "ws"
target = "http://{web}/v1/ws"
method = "pkg.Svc/Ok"
params = {{ message = "hi" }}
every = "15m"
{auth}

[[check]]
name = "ws-refused"
surface = "ws"
target = "http://{web}/v1/ws"
method = "pkg.Svc/No"
expect_error = "forbidden"
every = "15m"
{auth}

[[check]]
name = "ws-error"
surface = "ws"
target = "http://{web}/v1/ws"
method = "pkg.Svc/No"
every = "15m"
{auth}

[[check]]
name = "ws-no-token"
surface = "ws"
target = "http://{web}/v1/ws"
method = "pkg.Svc/Ok"
every = "15m"

[[check]]
name = "mqtt"
surface = "mqtt"
target = "http://{web}/v1/mqtt"
topic = "rpc/x/Ok"
params = {{ message = "hi" }}
every = "15m"
{auth}

[[check]]
name = "mqtt-error"
surface = "mqtt"
target = "http://{web}/v1/mqtt"
topic = "rpc/x/No"
every = "15m"
{auth}

[[check]]
name = "grpc"
surface = "grpc"
target = {{ host = "127.0.0.1", port = {gport}, tls = false }}
method = "pkg.Svc/Ok"
every = "15m"

[[check]]
name = "grpc-unauthenticated"
surface = "grpc"
target = {{ host = "127.0.0.1", port = {gport}, tls = false }}
method = "pkg.Svc/Private"
expect_code = 16
every = "15m"

[[check]]
name = "http-post"
surface = "http"
target = "http://{web}/echo"
method = "POST"
body = {{ ping = "pong" }}
expect = {{ status = 200 }}
every = "15m"
"#,
        gport = grpc.port()
    )
}

/// The job the platform sends for a declared check: surface, target and key only.
fn keyed(key: &str, surface: &str, target: Value) -> Value {
    json!({"surface": surface, "target": target, "key": key})
}

/// (job id, spec, expected status, expected error class).
fn jobs(
    web: SocketAddr,
    grpc: SocketAddr,
) -> Vec<(&'static str, Value, &'static str, Option<&'static str>)> {
    let url = |path: &str| json!({"url": format!("http://{web}{path}")});
    let g = json!({"host": "127.0.0.1", "port": grpc.port()});
    vec![
        ("sse", keyed("sse", "sse", url("/sse")), "ok", None),
        (
            "graphql",
            keyed("graphql", "graphql", url("/graphql")),
            "ok",
            None,
        ),
        (
            "graphql-no-token",
            keyed("graphql-no-token", "graphql", url("/graphql")),
            "failed",
            Some("answer"),
        ),
        ("mcp", keyed("mcp", "mcp", url("/mcp")), "ok", None),
        (
            "mcp-write",
            keyed("mcp-write", "mcp", url("/mcp")),
            "refused",
            Some("refused_by_policy"),
        ),
        (
            "mcp-too-few",
            keyed("mcp-too-few", "mcp", url("/mcp")),
            "failed",
            Some("answer"),
        ),
        ("ws", keyed("ws", "ws", url("/v1/ws")), "ok", None),
        (
            "ws-refused",
            keyed("ws-refused", "ws", url("/v1/ws")),
            "ok",
            None,
        ),
        (
            "ws-error",
            keyed("ws-error", "ws", url("/v1/ws")),
            "failed",
            Some("answer"),
        ),
        (
            "ws-no-token",
            keyed("ws-no-token", "ws", url("/v1/ws")),
            "failed",
            Some("status"),
        ),
        ("mqtt", keyed("mqtt", "mqtt", url("/v1/mqtt")), "ok", None),
        (
            "mqtt-error",
            keyed("mqtt-error", "mqtt", url("/v1/mqtt")),
            "failed",
            Some("answer"),
        ),
        ("grpc", keyed("grpc", "grpc", g.clone()), "ok", None),
        (
            "grpc-unauthenticated",
            keyed("grpc-unauthenticated", "grpc", g),
            "ok",
            None,
        ),
        (
            "http-post",
            keyed("http-post", "http", url("/echo")),
            "ok",
            None,
        ),
        // A job whose target differs from its entry: refused, nothing sent.
        (
            "mismatch",
            keyed("ws", "ws", url("/elsewhere")),
            "refused",
            Some("refused_by_policy"),
        ),
        // A transport job without a key carries no request: refused.
        (
            "no-key",
            json!({"surface": "ws", "target": url("/v1/ws")}),
            "refused",
            Some("refused_by_policy"),
        ),
        // A key the file does not have.
        (
            "unknown-key",
            keyed("nope", "sse", url("/sse")),
            "refused",
            Some("refused_by_policy"),
        ),
    ]
}

fn leaks(text: &str) -> Vec<&'static str> {
    CANARIES
        .iter()
        .copied()
        .filter(|c| text.contains(c))
        .collect()
}

type Exports = Arc<StdMutex<Vec<(String, Vec<u8>)>>>;

/// A fake OTLP collector on its own runtime (exporters flush at shutdown).
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
            let app = Router::new().fallback(move |uri: axum::http::Uri, body: Bytes| {
                let store = Arc::clone(&store);
                async move {
                    store
                        .lock()
                        .unwrap()
                        .push((uri.path().to_owned(), body.to_vec()));
                    StatusCode::OK
                }
            });
            axum::serve(l, app).await.unwrap();
        });
    });
    let addr = rx.recv().unwrap();
    (format!("http://{addr}"), got)
}

#[test]
fn transport_checks_report_verdicts_and_nothing_the_target_said() {
    iohr_agent::tls::install_crypto_provider();
    let (otlp, exported) = collector();
    let telemetry = iohr_agent::telemetry::init(
        &TelemetryConfig {
            enabled: true,
            endpoint: otlp,
            service_name: "iohr-agent-transport-test".into(),
        },
        false,
    )
    .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (frames, html, status) = rt.block_on(async {
        let web = web_target().await;
        let grpc = grpc_target().await;
        let mut h = harness_with(
            KeyAlg::Es256,
            "[work]\nsurfaces = [\"http\", \"sse\", \"ws\", \"mqtt\", \"mcp\", \"graphql\", \"grpc\"]\n",
        )
        .await;
        let secret = h.cfg.policy.parent().unwrap().join("check-token");
        std::fs::write(&h.cfg.checks, checks_toml(web, grpc, &secret.display().to_string())).unwrap();
        let (agent, stop, task) = start(&h).await;
        let mut frames = Vec::new();
        let (_, hello) = next(&mut h.frames, "hello").await;
        frames.push(hello.clone());
        let expected = jobs(web, grpc);
        for (id, spec, _, _) in &expected {
            h.cmds.send(job(id, "check", spec.clone())).ok();
            // One at a time: the policy allows four jobs at once.
            let (_, r) = next(&mut h.frames, "result").await;
            assert_eq!(r["job_id"], *id);
            frames.push(r);
        }
        for ((id, _, want, class), r) in expected.iter().zip(&frames[1..]) {
            assert_eq!(r["status"], *want, "{id}: {r}");
            assert_eq!(r["detail"]["error_class"].as_str(), *class, "{id}: {r}");
        }
        let snap = agent.state.snapshot();
        let html = iohr_agent::admin::render_html(&snap);
        let status = serde_json::to_string(&snap).unwrap();
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        while let Ok((_, f)) = h.frames.try_recv() {
            frames.push(f);
        }
        (frames, html, status)
    });
    drop(rt);
    telemetry.shutdown();

    assert_eq!(
        WRITE_TOOL_CALLS.load(Ordering::SeqCst),
        0,
        "a tool that is not read-only was called"
    );
    // Not vacuous: the hello announces the surfaces and carries the labels.
    let hello = &frames[0];
    for s in [
        "check:sse",
        "check:ws",
        "check:mqtt",
        "check:mcp",
        "check:graphql",
        "check:grpc",
    ] {
        assert!(
            hello["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == s),
            "{s}: {hello}"
        );
    }
    let sse = hello["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "sse")
        .unwrap();
    assert_eq!(sse["category"], "transport");
    assert_eq!(sse["tags"], json!({"transport": "sse"}));
    // No request travels in any frame either: no query, method, topic, tool or body.
    for f in &frames {
        let text = f.to_string();
        for s in [
            "{ me }",
            "pkg.Svc/Ok",
            "rpc/x/Ok",
            "read_thing",
            "write_thing",
            "pong",
        ] {
            assert!(!text.contains(s), "a frame carries {s}: {text}");
        }
    }
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
async fn transport_surfaces_are_refused_until_the_policy_lists_them() {
    let mut h = harness(KeyAlg::Es256).await;
    let web = web_target().await;
    let grpc = grpc_target().await;
    let secret = h.cfg.policy.parent().unwrap().join("check-token");
    std::fs::write(
        &h.cfg.checks,
        checks_toml(web, grpc, &secret.display().to_string()),
    )
    .unwrap();
    let (_agent, stop, task) = start(&h).await;
    let (_, hello) = next(&mut h.frames, "hello").await;
    let caps = hello["capabilities"].to_string();
    assert!(
        !caps.contains("check:sse") && caps.contains("check:http"),
        "{caps}"
    );
    h.cmds
        .send(job(
            "off",
            "check",
            keyed("sse", "sse", json!({"url": format!("http://{web}/sse")})),
        ))
        .ok();
    let (_, r) = next(&mut h.frames, "result").await;
    assert_eq!(r["status"], "refused", "{r}");
    assert!(
        r["refusal"]["reason"]
            .as_str()
            .unwrap()
            .contains("[work] surfaces"),
        "{r}"
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
