//! The agent against a fake control plane that speaks the shared contract: enroll, a
//! token endpoint that verifies the `private_key_jwt` assertion's signature with the
//! enrolled public key, and the WebSocket session.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, watch};
use url::Url;

use iohr_agent::agent::Agent;
use iohr_agent::config::AgentConfig;
use iohr_agent::enroll::{EnrollParams, Enrollment, enroll};
use iohr_agent::keys::{AgentKey, KeyAlg};
use iohr_agent::policy::Policy;
use iohr_agent::token::TokenSource;

const ENROLL_TOKEN: &str = "ioe_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CLIENT_ID: &str = "agent-client-1";
const AGENT_ID: &str = "agt_01TEST";

enum Cmd {
    Send(Value),
    Close,
}

struct Fake {
    base: Url,
    jwk: Mutex<Option<Value>>,
    issued: Mutex<HashSet<String>>,
    jtis: Mutex<HashSet<String>>,
    sessions: AtomicUsize,
    rejected_assertions: AtomicUsize,
    frames: mpsc::UnboundedSender<(usize, Value)>,
    cmds: Mutex<mpsc::UnboundedReceiver<Cmd>>,
}

struct Harness {
    fake: Arc<Fake>,
    frames: mpsc::UnboundedReceiver<(usize, Value)>,
    cmds: mpsc::UnboundedSender<Cmd>,
    _dir: tempfile::TempDir,
    cfg: AgentConfig,
    policy: Policy,
}

async fn fake_control_plane() -> (
    Arc<Fake>,
    mpsc::UnboundedReceiver<(usize, Value)>,
    mpsc::UnboundedSender<Cmd>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ftx, frx) = mpsc::unbounded_channel();
    let (ctx, crx) = mpsc::unbounded_channel();
    let fake = Arc::new(Fake {
        base: Url::parse(&format!("http://{addr}/")).unwrap(),
        jwk: Mutex::new(None),
        issued: Mutex::new(HashSet::new()),
        jtis: Mutex::new(HashSet::new()),
        sessions: AtomicUsize::new(0),
        rejected_assertions: AtomicUsize::new(0),
        frames: ftx,
        cmds: Mutex::new(crx),
    });
    let app = Router::new()
        .route("/v1/agents/enroll", post(enroll_route))
        .route("/oauth2/token", post(token_route))
        .route("/v1/agents/session", get(session_route))
        .with_state(Arc::clone(&fake));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (fake, frx, ctx)
}

async fn enroll_route(State(f): State<Arc<Fake>>, Json(body): Json<Value>) -> Response {
    if body["token"] != ENROLL_TOKEN {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"title": "invalid token"})),
        )
            .into_response();
    }
    let jwk = body["public_jwk"].clone();
    assert!(jwk.get("d").is_none(), "the private key must never be sent");
    assert_eq!(jwk["use"], "sig");
    assert!(body["policy_hash"].as_str().unwrap().starts_with("sha256:"));
    *f.jwk.lock().await = Some(jwk);
    Json(json!({
        "agent_id": AGENT_ID,
        "account_id": "acc_1",
        "client_id": CLIENT_ID,
        "token_endpoint": f.base.join("oauth2/token").unwrap(),
        "audience": "iohr-api",
        "scope": "agents:session",
        "environment": "staging",
        "domains": ["example.com"],
    }))
    .into_response()
}

fn verify(jwt: &str, jwk: &Value) -> Option<Value> {
    let (input, sig) = jwt.rsplit_once('.')?;
    let sig = B64.decode(sig).ok()?;
    let header: Value = serde_json::from_slice(&B64.decode(input.split('.').next()?).ok()?).ok()?;
    if header["alg"] != jwk["alg"] || header["kid"] != jwk["kid"] {
        return None;
    }
    let ok = match jwk["kty"].as_str()? {
        "EC" => {
            use p256::ecdsa::signature::Verifier as _;
            let x = B64.decode(jwk["x"].as_str()?).ok()?;
            let y = B64.decode(jwk["y"].as_str()?).ok()?;
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok()?;
            vk.verify(
                input.as_bytes(),
                &p256::ecdsa::Signature::from_slice(&sig).ok()?,
            )
            .is_ok()
        }
        "OKP" => {
            let x: [u8; 32] = B64.decode(jwk["x"].as_str()?).ok()?.try_into().ok()?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&x).ok()?;
            vk.verify_strict(
                input.as_bytes(),
                &ed25519_dalek::Signature::from_slice(&sig).ok()?,
            )
            .is_ok()
        }
        _ => false,
    };
    if !ok {
        return None;
    }
    serde_json::from_slice(&B64.decode(input.split('.').nth(1)?).ok()?).ok()
}

async fn token_route(
    State(f): State<Arc<Fake>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let deny = |f: &Fake| {
        f.rejected_assertions.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response()
    };
    if form.get("grant_type").map(String::as_str) != Some("client_credentials")
        || form.get("client_assertion_type").map(String::as_str)
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        || form.get("scope").map(String::as_str) != Some("agents:session")
    {
        return deny(&f);
    }
    let Some(jwk) = f.jwk.lock().await.clone() else {
        return deny(&f);
    };
    let Some(claims) = verify(
        form.get("client_assertion").map_or("", String::as_str),
        &jwk,
    ) else {
        return deny(&f);
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token_endpoint = f.base.join("oauth2/token").unwrap();
    let exp = claims["exp"].as_i64().unwrap_or(0);
    let iat = claims["iat"].as_i64().unwrap_or(0);
    if claims["iss"] != CLIENT_ID
        || claims["sub"] != CLIENT_ID
        || claims["aud"] != token_endpoint.as_str()
        || exp <= now
        || exp - iat > 300
        || !f
            .jtis
            .lock()
            .await
            .insert(claims["jti"].as_str().unwrap_or("").to_owned())
    {
        return deny(&f);
    }
    let n = f.issued.lock().await.len();
    let token = format!("at-{n}");
    f.issued.lock().await.insert(token.clone());
    Json(json!({"access_token": token, "token_type": "bearer", "expires_in": 900})).into_response()
}

async fn session_route(
    State(f): State<Arc<Fake>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    match bearer {
        Some(t) if f.issued.lock().await.contains(&t) => ws.on_upgrade(move |s| session(f, s)),
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn session(f: Arc<Fake>, socket: WebSocket) {
    let n = f.sessions.fetch_add(1, Ordering::SeqCst) + 1;
    let (mut tx, mut rx) = socket.split();
    let Some(Ok(Message::Text(hello))) = rx.next().await else {
        return;
    };
    let hello: Value = serde_json::from_str(hello.as_str()).unwrap();
    assert_eq!(hello["type"], "hello");
    let _ = f.frames.send((n, hello));
    let welcome =
        json!({"type": "welcome", "agent_id": AGENT_ID, "heartbeat_secs": 1, "server_time": "now"});
    tx.send(Message::Text(welcome.to_string().into()))
        .await
        .unwrap();
    let mut cmds = f.cmds.lock().await;
    loop {
        tokio::select! {
            m = rx.next() => match m {
                Some(Ok(Message::Text(t))) => { let _ = f.frames.send((n, serde_json::from_str(t.as_str()).unwrap())); }
                Some(Ok(_)) => {}
                _ => return,
            },
            c = cmds.recv() => match c {
                Some(Cmd::Send(v)) => { let _ = tx.send(Message::Text(v.to_string().into())).await; }
                Some(Cmd::Close) | None => { let _ = tx.send(Message::Close(None)).await; return; }
            },
        }
    }
}

const POLICY: &str = r#"
environment = "staging"
[domains]
bound = ["example.com"]
[networks]
allow = ["127.0.0.0/8"]
"#;

async fn harness(alg: KeyAlg) -> Harness {
    iohr_agent::tls::install_crypto_provider();
    let (fake, frames, cmds) = fake_control_plane().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AgentConfig::new(fake.base.clone(), "e2e".into(), "staging".into());
    cfg.key_alg = alg;
    cfg.admin.listen = "127.0.0.1:0".parse().unwrap();
    cfg.session.backoff_min_ms = 20;
    cfg.session.backoff_max_ms = 200;
    let secret = dir.path().join("check-token");
    std::fs::write(&secret, "e2e-secret\n").unwrap();
    let policy_text = format!(
        "{POLICY}[secrets]\nallow = [\"file:{}\"]\n",
        secret.display()
    );
    std::fs::write(dir.path().join("policy.toml"), policy_text).unwrap();
    cfg.resolve_paths(dir.path());
    cfg.validate().unwrap();
    let policy = Policy::load(&cfg.policy).unwrap();
    Harness {
        fake,
        frames,
        cmds,
        _dir: dir,
        cfg,
        policy,
    }
}

async fn enroll_agent(h: &Harness) -> Enrollment {
    let http = reqwest::Client::new();
    enroll(EnrollParams {
        api: &h.cfg.api,
        token: ENROLL_TOKEN,
        name: &h.cfg.name,
        environment: &h.cfg.environment,
        policy_hash: &h.policy.hash(),
        key_alg: h.cfg.key_alg,
        key_path: &h.cfg.key,
        state_dir: &h.cfg.state_dir,
        replace: false,
        http: &http,
    })
    .await
    .unwrap()
}

async fn start(
    h: &Harness,
) -> (
    Arc<Agent>,
    watch::Sender<bool>,
    tokio::task::JoinHandle<iohr_agent::Result<()>>,
) {
    let enrollment = match Enrollment::load(&h.cfg.state_dir).unwrap() {
        Some(e) => e,
        None => enroll_agent(h).await,
    };
    let key = AgentKey::load(&h.cfg.key).unwrap();
    let agent = Arc::new(Agent::new(h.cfg.clone(), h.policy.clone(), enrollment, key).unwrap());
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&agent).run(rx));
    (agent, tx, task)
}

/// The next frame of `kind`, skipping heartbeats unless asked for.
async fn next(frames: &mut mpsc::UnboundedReceiver<(usize, Value)>, kind: &str) -> (usize, Value) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (n, f) = frames.recv().await.expect("fake control plane gone");
            if f["type"] == kind {
                return (n, f);
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} frame in time"))
}

async fn results(
    frames: &mut mpsc::UnboundedReceiver<(usize, Value)>,
    count: usize,
) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    while out.len() < count {
        let (_, f) = next(frames, "result").await;
        out.insert(f["job_id"].as_str().unwrap().to_owned(), f);
    }
    out
}

fn job(id: &str, kind: &str, spec: Value) -> Cmd {
    Cmd::Send(json!({"type": "job", "job_id": id, "kind": kind, "spec": spec, "deadline_ms": 5000}))
}

async fn http_target() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async { (StatusCode::NO_CONTENT, "secret body that must not travel") }),
        )
        .route(
            "/private",
            get(|h: HeaderMap| async move {
                if h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer e2e-secret")
                {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }),
        );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn enroll_token_session_job_result() {
    for alg in [KeyAlg::Es256, KeyAlg::Ed25519] {
        let mut h = harness(alg).await;
        let (agent, stop, task) = start(&h).await;

        let (n, hello) = next(&mut h.frames, "hello").await;
        assert_eq!(n, 1);
        assert_eq!(hello["policy_hash"], h.policy.hash());
        assert_eq!(hello["domains"], json!(["example.com"]));
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

fn params<'a>(h: &'a Harness, http: &'a reqwest::Client, token: &'a str) -> EnrollParams<'a> {
    EnrollParams {
        api: &h.cfg.api,
        token,
        name: "x",
        environment: &h.cfg.environment,
        policy_hash: "sha256:00",
        key_alg: KeyAlg::Es256,
        key_path: &h.cfg.key,
        state_dir: &h.cfg.state_dir,
        replace: false,
        http,
    }
}
