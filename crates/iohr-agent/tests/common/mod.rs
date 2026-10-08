//! A fake control plane that speaks the shared contract (enroll, a token endpoint that
//! verifies the `private_key_jwt` assertion's signature with the enrolled public key, and
//! the WebSocket session), shared by the integration tests.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

use std::collections::{HashMap, HashSet};
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
use iohr_agent::checks_file::DeclaredChecks;
use iohr_agent::config::AgentConfig;
use iohr_agent::enroll::{EnrollParams, Enrollment, enroll};
use iohr_agent::keys::{AgentKey, KeyAlg};
use iohr_agent::policy::Policy;

pub const ENROLL_TOKEN: &str = "ioe_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const CLIENT_ID: &str = "agent-client-1";
pub const AGENT_ID: &str = "agt_01TEST";

pub enum Cmd {
    Send(Value),
    Close,
}

pub struct Fake {
    pub base: Url,
    pub jwk: Mutex<Option<Value>>,
    pub issued: Mutex<HashSet<String>>,
    pub jtis: Mutex<HashSet<String>>,
    pub sessions: AtomicUsize,
    pub rejected_assertions: AtomicUsize,
    pub frames: mpsc::UnboundedSender<(usize, Value)>,
    pub cmds: Mutex<mpsc::UnboundedReceiver<Cmd>>,
    /// Every text frame exactly as received, for comparing with the agent's ledger.
    pub raw: std::sync::Mutex<Vec<String>>,
}

pub struct Harness {
    pub fake: Arc<Fake>,
    pub frames: mpsc::UnboundedReceiver<(usize, Value)>,
    pub cmds: mpsc::UnboundedSender<Cmd>,
    pub _dir: tempfile::TempDir,
    pub cfg: AgentConfig,
    pub policy: Policy,
}

pub async fn fake_control_plane() -> (
    Arc<Fake>,
    mpsc::UnboundedReceiver<(usize, Value)>,
    mpsc::UnboundedSender<Cmd>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ftx, frx) = mpsc::unbounded_channel();
    let (ctx, crx) = mpsc::unbounded_channel();
    let fake = Arc::new(Fake {
        raw: std::sync::Mutex::new(Vec::new()),
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

pub async fn enroll_route(State(f): State<Arc<Fake>>, Json(body): Json<Value>) -> Response {
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

pub fn verify(jwt: &str, jwk: &Value) -> Option<Value> {
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
            let point = p256::Sec1Point::from_affine_coordinates(
                x.as_slice().try_into().ok()?,
                y.as_slice().try_into().ok()?,
                false,
            );
            let vk = p256::ecdsa::VerifyingKey::from_sec1_point(&point).ok()?;
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

pub async fn token_route(
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

pub async fn session_route(
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

pub async fn session(f: Arc<Fake>, socket: WebSocket) {
    let n = f.sessions.fetch_add(1, Ordering::SeqCst) + 1;
    let (mut tx, mut rx) = socket.split();
    let Some(Ok(Message::Text(hello))) = rx.next().await else {
        return;
    };
    f.raw.lock().unwrap().push(hello.as_str().to_owned());
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
                Some(Ok(Message::Text(t))) => { f.raw.lock().unwrap().push(t.as_str().to_owned()); let _ = f.frames.send((n, serde_json::from_str(t.as_str()).unwrap())); }
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

pub const POLICY: &str = r#"
environment = "staging"
[domains]
bound = ["example.com"]
[networks]
allow = ["127.0.0.0/8"]
"#;

pub async fn harness(alg: KeyAlg) -> Harness {
    harness_with(alg, "").await
}

/// A harness whose policy has `extra` appended (more TOML sections).
pub async fn harness_with(alg: KeyAlg, extra: &str) -> Harness {
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
        "{POLICY}[secrets]\nallow = [\"file:{}\"]\n{extra}",
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

pub async fn enroll_agent(h: &Harness) -> Enrollment {
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

pub async fn start(
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
    let agent = Arc::new(
        Agent::new(
            h.cfg.clone(),
            h.policy.clone(),
            DeclaredChecks::load(&h.cfg.checks).unwrap(),
            enrollment,
            key,
        )
        .unwrap(),
    );
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&agent).run(rx));
    (agent, tx, task)
}

/// The next frame of `kind`, skipping heartbeats unless asked for.
pub async fn next(
    frames: &mut mpsc::UnboundedReceiver<(usize, Value)>,
    kind: &str,
) -> (usize, Value) {
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

pub async fn results(
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

pub fn job(id: &str, kind: &str, spec: Value) -> Cmd {
    Cmd::Send(json!({"type": "job", "job_id": id, "kind": kind, "spec": spec, "deadline_ms": 5000}))
}

pub async fn http_target() -> SocketAddr {
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

pub fn params<'a>(h: &'a Harness, http: &'a reqwest::Client, token: &'a str) -> EnrollParams<'a> {
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
