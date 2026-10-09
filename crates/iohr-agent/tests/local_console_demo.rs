//! A demonstration of the console in the agent (RFC 0100.4 slices 1 and 2), run by hand
//! (with `cargo test`: nextest stops a test after two minutes):
//!
//! ```text
//! DEMO_DIR=/tmp/demo DEMO_CONSOLE_DIR=<core>/ui/console/out-agent \
//!   cargo test -p iohr-agent --test local_console_demo -- --ignored
//! ```
//!
//! A real agent against the fake control plane (`tests/common`), through a link that can be
//! cut: it runs declared checks against local targets, keeps the runs in its trial store,
//! then loses the platform and goes on serving the local console from this machine alone.
//! While it holds each phase it writes `<DEMO_DIR>/phase` (`connected`, then `offline`)
//! and the admin page's address and token, so screenshots can be taken against it. Nothing
//! here reaches anything beyond 127.0.0.1.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use serde_json::json;

use common::*;
use iohr_agent::keys::KeyAlg;

/// A TCP forwarder to the fake platform that can be cut: then the agent is offline.
async fn link(to: SocketAddr, up: Arc<AtomicBool>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut a, _)) = l.accept().await else {
                break;
            };
            if !up.load(Ordering::SeqCst) {
                continue; // dropped: connection refused for the agent
            }
            let up = Arc::clone(&up);
            tokio::spawn(async move {
                let Ok(mut b) = tokio::net::TcpStream::connect(to).await else {
                    return;
                };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut a, &mut b) => {}
                    () = async { while up.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(50)).await } } => {}
                }
            });
        }
    });
    addr
}

/// Two endpoints: one always answers, one fails every fourth call, and every second one
/// once `worse` is set (the change the demo verifies).
async fn targets(worse: Arc<AtomicBool>) -> SocketAddr {
    let n = Arc::new(AtomicUsize::new(0));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/orders",
            get(move || {
                let n = Arc::clone(&n);
                let every = if worse.load(Ordering::SeqCst) { 2 } else { 4 };
                async move {
                    if n.fetch_add(1, Ordering::SeqCst) % every == every - 1 {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::OK
                    }
                }
            }),
        );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

/// A company identity provider that signs everyone in at once as Ana, a member of
/// engineering (the demo's stand-in for the customer's own identity provider).
async fn idp() -> String {
    use axum::extract::Query;
    use axum::response::Redirect;
    use axum::routing::post;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let iss = format!("http://{}", l.local_addr().unwrap());
    let nonce = Arc::new(std::sync::Mutex::new(String::new()));
    let (iss2, iss3, n2, n3) = (
        iss.clone(),
        iss.clone(),
        Arc::clone(&nonce),
        Arc::clone(&nonce),
    );
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let iss = iss2.clone();
                async move {
                    axum::Json(json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/authorize"),
                        "token_endpoint": format!("{iss}/token"),
                    }))
                }
            }),
        )
        .route(
            "/authorize",
            get(
                move |Query(q): Query<std::collections::HashMap<String, String>>| {
                    *n2.lock().unwrap() = q.get("nonce").cloned().unwrap_or_default();
                    let to = format!(
                        "{}?code=demo&state={}",
                        q.get("redirect_uri").cloned().unwrap_or_default(),
                        q.get("state").cloned().unwrap_or_default()
                    );
                    async move { Redirect::to(&to) }
                },
            ),
        )
        .route(
            "/token",
            post(move || {
                let (iss, n) = (iss3.clone(), n3.lock().unwrap().clone());
                async move {
                    use base64::Engine as _;
                    let claims = json!({
                        "iss": iss, "aud": "iohr-agent-console", "sub": "u-ana",
                        "name": "Ana Example", "nonce": n, "groups": ["engineering"],
                        "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 600,
                    });
                    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    axum::Json(
                        json!({"id_token": format!("e30.{}.x", b64.encode(claims.to_string()))}),
                    )
                }
            }),
        );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    iss
}

#[tokio::test]
#[ignore = "a demonstration, run by hand; holds for DEMO_SECS"]
async fn local_console_demo() {
    let out = std::path::PathBuf::from(std::env::var("DEMO_DIR").expect("DEMO_DIR"));
    std::fs::create_dir_all(&out).unwrap();
    let hold = Duration::from_secs(
        std::env::var("DEMO_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(90),
    );
    let up = Arc::new(AtomicBool::new(true));

    let iss = idp().await;
    let secret_dir = tempfile::tempdir().unwrap();
    let secret = secret_dir.path().join("oidc-secret");
    std::fs::write(&secret, "demo-secret\n").unwrap();
    let mut h = harness_with(
        KeyAlg::Es256,
        &format!(
            "[share]\ntargets = \"full\"\n[console]\nusers = [\"oidc\", \"machine\"]\n[console.oidc]\nissuer = \"{iss}\"\nname = \"Example SSO\"\nclient_id = \"iohr-agent-console\"\nclient_secret = \"file:{}\"\nroles = {{ member = [\"engineering\"], admin = [\"sre-leads\"] }}\n",
            secret.display()
        ),
    )
    .await;
    // Through the cuttable link.
    let fake_addr: SocketAddr = format!(
        "{}:{}",
        h.fake.base.host_str().unwrap(),
        h.fake.base.port().unwrap()
    )
    .parse()
    .unwrap();
    let via = link(fake_addr, Arc::clone(&up)).await;
    h.cfg.api = url::Url::parse(&format!("http://{via}/")).unwrap();
    h.cfg.admin.listen = std::env::var("DEMO_ADMIN")
        .unwrap_or_else(|_| "127.0.0.1:7790".into())
        .parse()
        .unwrap();
    h.cfg.admin.require_token = Some(true);
    if let Ok(dir) = std::env::var("DEMO_CONSOLE_DIR") {
        h.cfg.admin.console_dir = Some(dir.into());
    }
    let worse = Arc::new(AtomicBool::new(false));
    let t = targets(Arc::clone(&worse)).await;
    std::fs::write(
        &h.cfg.checks,
        format!(
            r#"
[[check]]
name = "storefront"
label = "Storefront"
surface = "http"
target = "http://{t}/healthz"
every = "60s"
expect = {{ status = 200, max_ms = 2000 }}
category = "availability"

[[check]]
name = "orders-api"
label = "Orders API"
surface = "http"
target = "http://{t}/orders"
every = "60s"
fail_after = 2
expect = {{ status = 200 }}
category = "availability"

[[refuse]]
name = "cloud-metadata-closed"
label = "Cloud metadata stays closed"
surface = "tcp"
target = "169.254.169.254:80"
by = "policy"
every = "5m"
category = "security"
"#
        ),
    )
    .unwrap();

    // Supervised, as `iohr agent run` runs it, so the console's changes reload the agent.
    let enrollment = enroll_agent(&h).await;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(iohr_agent::agent::supervise(h.cfg.clone(), enrollment, rx));
    let _hello = next(&mut h.frames, "hello").await;
    // Three dozen runs per check, as the platform would send them; halfway, a change makes
    // the orders API worse.
    let mut change_at = String::new();
    for i in 0..36 {
        if i == 18 {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            change_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            tokio::time::sleep(Duration::from_millis(1200)).await;
            worse.store(true, Ordering::SeqCst);
        }
        for (key, spec) in [
            (
                "storefront",
                json!({"key": "storefront", "surface": "http", "target": {"url": format!("http://{t}/healthz")}, "expect": {"status": 200}}),
            ),
            (
                "orders-api",
                json!({"key": "orders-api", "surface": "http", "target": {"url": format!("http://{t}/orders")}, "expect": {"status": 200}}),
            ),
            (
                "cloud-metadata-closed",
                json!({"key": "cloud-metadata-closed", "surface": "tcp", "target": {"host": "169.254.169.254", "port": 80}}),
            ),
        ] {
            h.cmds
                .send(job(&format!("j-{key}-{i}"), "check", spec))
                .ok();
        }
        let _ = results(&mut h.frames, 3).await;
    }

    let token = std::fs::read_to_string(h.cfg.state_dir.join("admin.token")).unwrap();
    // The change, verified: its two API checks before and after.
    let http = reqwest::Client::new();
    let base = format!("http://{}", h.cfg.admin.listen);
    let me: serde_json::Value = http
        .get(format!("{base}/v1/agents/self"))
        .bearer_auth(token.trim())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org = me["account_id"].as_str().unwrap().to_owned();
    let _ = http
        .post(format!(
            "{base}/v1/accounts/orgs/{org}/agents/{AGENT_ID}/verifications"
        ))
        .bearer_auth(token.trim())
        .json(&json!({
            "name": "Retry fix deployed to the orders API",
            "claims": ["storefront", "orders-api"],
            "change_at": change_at,
            "window_secs": 60,
            "reason": "PR 418",
        }))
        .send()
        .await
        .unwrap();
    std::fs::write(out.join("admin"), format!("{}\n", h.cfg.admin.listen)).unwrap();
    std::fs::write(out.join("token"), token.trim()).unwrap();
    std::fs::write(out.join("phase"), "connected").unwrap();
    tokio::time::sleep(hold).await;

    // The platform goes away: the console keeps working from this machine.
    up.store(false, Ordering::SeqCst);
    h.cmds.send(Cmd::Close).ok();
    for _ in 0..100 {
        let me: serde_json::Value = http
            .get(format!("{base}/v1/agents/self"))
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if me["connected"] == false {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    std::fs::write(out.join("phase"), "offline").unwrap();
    tokio::time::sleep(hold).await;

    std::fs::write(out.join("phase"), "done").unwrap();
    stop.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
