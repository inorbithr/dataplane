//! The page's security properties, each against a live listener: rebinding, cross-site
//! requests, read-only, headers, the token, limits, and no secret in any answer.

use super::*;
use crate::state::{AgentInfo, JobRecord, PolicyInfo};
use proptest::prelude::*;

const POLICY: &str = r#"
environment = "staging"
[networks]
allow = ["10.0.0.0/8", "*.example.com"]
[secrets]
allow = ["env:CHECK_*"]
"#;

const CHECKS: &str = r#"
[[check]]
name = "api"
target = "https://api.example.com/healthz"
every = "60s"
auth = "env:CHECK_TOKEN"
auth_scheme = "Bearer"

[[refuse]]
name = "metadata-closed"
surface = "tcp"
target = "169.254.169.254:80"
by = "policy"
every = "5m"
"#;

fn context(dir: &Path, require_token: bool) -> Arc<Context> {
    let policy = Policy::from_toml(POLICY).unwrap();
    let checks = DeclaredChecks::from_toml(CHECKS).unwrap();
    let state = Arc::new(AgentState::new(
        AgentInfo {
            name: "test-agent".into(),
            environment: "staging".into(),
            agent_id: Some("agt_01TEST".into()),
            ..AgentInfo::default()
        },
        PolicyInfo {
            hash: policy.hash(),
            ..PolicyInfo::default()
        },
        "stop".into(),
    ));
    let ledger =
        Ledger::open(&dir.join("ledger"), LedgerConfig::default(), &policy.hash()).unwrap();
    let admin = AdminConfig {
        require_token: Some(require_token),
        ..AdminConfig::default()
    };
    Arc::new(Context {
        state,
        policy: Arc::new(policy),
        checks: Some(Arc::new(checks)),
        ledger: Some(Arc::new(ledger)),
        ledger_config: LedgerConfig::default(),
        api: "https://api.example.com/".into(),
        admin,
        state_dir: dir.display().to_string(),
        token: Some(write_token(dir).unwrap()),
    })
}

async fn start(ctx: Arc<Context>) -> (SocketAddr, watch::Sender<bool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(serve(l, ctx, None, rx));
    (addr, tx)
}

async fn send(addr: SocketAddr, req: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    out
}

fn get(path: &str, host: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n")
}

fn status(r: &str) -> u16 {
    r.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[tokio::test]
async fn host_header_rebinding_attempts_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(context(d.path(), false)).await;
    let port = addr.port();
    for ok in [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("LOCALHOST:{port}"),
        format!("[::1]:{port}"),
    ] {
        assert_eq!(status(&send(addr, &get("/", &ok, "")).await), 200, "{ok}");
    }
    for bad in [
        format!("attacker.example:{port}"),
        "attacker.example".to_owned(),
        format!("127.0.0.1.nip.io:{port}"),
        format!("localhost.attacker.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "127.0.0.1".to_owned(),
        "localhost".to_owned(),
        format!("10.0.0.1:{port}"),
        format!("127.0.0.2:{port}"),
        String::new(),
    ] {
        let r = send(addr, &get("/status.json", &bad, "")).await;
        assert_eq!(status(&r), 421, "Host {bad:?}: {r}");
        assert!(!r.contains("agent_id"), "Host {bad:?} read the status");
    }
    // No Host, or two of them: refused before anything is read.
    let r = send(addr, "GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(status(&r), 400);
    let r = send(
        addr,
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: attacker.example\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&r), 400);
    // An absolute-form target naming another host.
    let r = send(
        addr,
        &format!("GET http://attacker.example/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&r), 400);
}

#[tokio::test]
async fn a_cross_origin_post_is_refused_and_nothing_writes() {
    let d = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(context(d.path(), false)).await;
    let host = addr.to_string();
    // A form posted from another site.
    let r = send(
        addr,
        &format!("POST / HTTP/1.1\r\nHost: {host}\r\nOrigin: https://attacker.example\r\nSec-Fetch-Site: cross-site\r\nContent-Length: 0\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    let r = send(
        addr,
        &format!("POST /status.json HTTP/1.1\r\nHost: {host}\r\nOrigin: null\r\n\r\n"),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // Same origin, still nothing that writes.
    for m in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let r = send(
            addr,
            &format!("{m} / HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nSec-Fetch-Site: same-origin\r\n\r\n"),
        )
        .await;
        assert_eq!(status(&r), 405, "{m}: {r}");
        assert!(!r.contains("Access-Control-"), "{m}: {r}");
    }
    // A body is never accepted.
    let r = send(
        addr,
        &format!("GET / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\n\r\nhello"),
    )
    .await;
    assert_eq!(status(&r), 413, "{r}");
    // A script on another site reading the JSON: refused by fetch metadata or Origin.
    let r = send(
        addr,
        &get(
            "/api/v1/overview.json",
            &host,
            "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    let r = send(
        addr,
        &get(
            "/status.json",
            &host,
            "Origin: https://attacker.example\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // Same-site is not same-origin (another port on localhost).
    let r = send(
        addr,
        &get(
            "/ledger.jsonl",
            &host,
            "Sec-Fetch-Site: same-site\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: script\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // A link followed from another site opens the page (it cannot read it), never JSON.
    let nav =
        "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n";
    assert_eq!(status(&send(addr, &get("/", &host, nav)).await), 200);
    assert_eq!(
        status(&send(addr, &get("/status.json", &host, nav)).await),
        403
    );
    assert_eq!(
        status(&send(addr, &get("/auth?token=x", &host, nav)).await),
        403
    );
    // Framing it: the CSP and X-Frame-Options forbid it.
    let r = send(
        addr,
        &get(
            "/",
            &host,
            "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: iframe\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 403);
}

#[tokio::test]
async fn every_answer_carries_the_security_headers_and_no_cors() {
    let d = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(context(d.path(), false)).await;
    let host = addr.to_string();
    for path in [
        "/",
        "/checks",
        "/policy",
        "/ledger",
        "/jobs",
        "/host",
        "/logs",
        "/status.json",
        "/api/v1/overview.json",
        "/ledger.jsonl",
        "/favicon.svg",
        "/nope",
        "/../etc/passwd",
        "/%2e%2e/agent.key",
        "//etc/passwd",
    ] {
        let r = send(
            addr,
            &get(path, &host, "Origin: https://attacker.example\r\n"),
        )
        .await;
        let r2 = send(addr, &get(path, &host, "")).await;
        for r in [&r, &r2] {
            let head = r.split("\r\n\r\n").next().unwrap();
            assert!(
                head.contains("Content-Security-Policy: default-src 'none';"),
                "{path}: {head}"
            );
            assert!(head.contains("frame-ancestors 'none'"), "{path}");
            assert!(head.contains("script-src 'none'"), "{path}");
            assert!(head.contains("X-Content-Type-Options: nosniff"), "{path}");
            assert!(head.contains("Referrer-Policy: no-referrer"), "{path}");
            assert!(head.contains("Cache-Control: no-store"), "{path}");
            assert!(
                !head.to_ascii_lowercase().contains("access-control-"),
                "{path}: {head}"
            );
        }
        if path.contains("..") || path.starts_with("//") || path == "/nope" {
            assert_eq!(status(&r2), 404, "{path}");
        }
    }
    // The stylesheet's hash in the CSP is the stylesheet served.
    let r = send(addr, &get("/", &host, "")).await;
    let css = r
        .split("<style>")
        .nth(1)
        .unwrap()
        .split("</style>")
        .next()
        .unwrap();
    let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(css));
    assert!(
        r.contains(&format!("'sha256-{hash}'")),
        "the CSP names the stylesheet"
    );
    assert!(!r.contains("<script"), "no script on the page");
}

use base64::Engine as _;
use sha2::Digest as _;

#[tokio::test]
async fn the_token_opens_the_page_once_required() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), true);
    let token = ctx.token.clone().unwrap();
    // Written for the operator only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(d.path().join(TOKEN_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let r = send(addr, &get("/status.json", &host, "")).await;
    assert_eq!(status(&r), 401);
    assert!(!r.contains("agt_01TEST"));
    let r = send(addr, &get("/ledger.jsonl", &host, "")).await;
    assert_eq!(status(&r), 401);
    // A wrong token, a prefix of the right one, a forged cookie: still locked.
    for t in ["nope", &token[..63], &format!("{token}0")] {
        let r = send(addr, &get(&format!("/auth?token={t}"), &host, "")).await;
        assert_eq!(status(&r), 401, "{t}");
        assert!(!r.contains("Set-Cookie"));
    }
    let r = send(
        addr,
        &get("/", &host, &format!("Cookie: {COOKIE}={token}\r\n")),
    )
    .await;
    assert_eq!(status(&r), 401);
    // The right token: a cookie scripts cannot read and other sites never send.
    let r = send(
        addr,
        &get(
            &format!("/auth?token={token}"),
            &host,
            "Sec-Fetch-Site: none\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 303, "{r}");
    let cookie = r
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: "))
        .unwrap()
        .to_owned();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    assert!(!cookie.contains(&token), "the cookie is not the token");
    let session = cookie.split(';').next().unwrap();
    let r = send(
        addr,
        &get("/status.json", &host, &format!("Cookie: {session}\r\n")),
    )
    .await;
    assert_eq!(status(&r), 200);
    // A local client may present the token as a bearer; a wrong one is refused.
    let r = send(
        addr,
        &get(
            "/status.json",
            &host,
            &format!("Authorization: Bearer {token}\r\n"),
        ),
    )
    .await;
    assert_eq!(status(&r), 200);
    let r = send(
        addr,
        &get("/status.json", &host, "Authorization: Bearer nope\r\n"),
    )
    .await;
    assert_eq!(status(&r), 401);
    // The token itself never appears on a page.
    let r = send(addr, &get("/", &host, &format!("Cookie: {session}\r\n"))).await;
    assert!(!r.contains(&token));
}

#[test]
fn constant_time_comparison() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abx"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(constant_time_eq(b"", b""));
}

#[tokio::test]
async fn bounded_requests_and_rate() {
    let d = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(context(d.path(), false)).await;
    let host = addr.to_string();
    // Headers past 8 KiB.
    let big = format!("X-Pad: {}\r\n", "a".repeat(MAX_REQUEST));
    assert_eq!(status(&send(addr, &get("/", &host, &big)).await), 400);
    // A burst past the bucket is slowed down (judged without I/O, so a slow test machine
    // refilling the bucket cannot hide it), and one client's burst leaves others alone.
    let srv = Server {
        ctx: context(d.path(), false),
        local: Some(addr),
        tls: false,
        sessions: Mutex::new(Vec::new()),
        buckets: Mutex::new(HashMap::new()),
        slots: Arc::new(Semaphore::new(1)),
    };
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let allowed = (0..200).filter(|_| srv.rate_ok(ip)).count();
    assert!((40..200).contains(&allowed), "{allowed}");
    assert!(srv.rate_ok("127.0.0.2".parse().unwrap()));
}

#[tokio::test]
async fn a_slow_client_is_cut_off() {
    let d = tempfile::tempdir().unwrap();
    let (addr, _stop) = start(context(d.path(), false)).await;
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let mut out = String::new();
    let read = tokio::time::timeout(READ_TIMEOUT * 2, s.read_to_string(&mut out)).await;
    assert!(read.is_ok(), "the server closed the connection");
    assert_eq!(status(&out), 400);
}

#[test]
fn never_lists_what_the_policy_turns_off() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let never: Vec<String> = page::never(&ctx)
        .into_iter()
        .map(|(w, why)| format!("{w} ({why})"))
        .collect();
    let all = never.join("\n");
    assert!(
        all.contains("Generate load. ([work] load = false)"),
        "{all}"
    );
    assert!(all.contains("Inject faults."), "{all}");
    assert!(all.contains("169.254.0.0/16"), "{all}");
    assert!(
        all.contains("grpc, sse, ws, mqtt, mcp, graphql, hwmon"),
        "{all}"
    );
    assert!(
        all.contains("Accept a connection from the platform"),
        "{all}"
    );
    assert!(
        all.contains("journalctl") || all.contains("sensors"),
        "{all}"
    );
    assert!(
        all.contains("host name. ([share] hostname = false)"),
        "{all}"
    );
    assert!(all.contains("[share] targets = \"hash\""), "{all}");
    let page = render_all(&ctx);
    assert!(page.contains("What the platform is told"));
    assert!(page.contains("a keyed hash; the target stays on this agent"));
}

/// Shapes of secrets that could reach the agent's memory: a bearer token, a password in
/// an error, a private key, cloud and Git tokens, an enrollment token.
fn secret() -> impl Strategy<Value = (String, String)> {
    let tail = "[A-Za-z0-9]{24,40}";
    prop_oneof![
        tail.prop_map(|t| (format!("ioe_{t}"), format!("ioe_{t}"))),
        "[A-Z0-9]{16}".prop_map(|t| (format!("AKIA{t}"), format!("AKIA{t}"))),
        tail.prop_map(|t| (format!("ghp_{t}"), format!("ghp_{t}"))),
        tail.prop_map(|t| (format!("Bearer eyJ{t}.eyJ{t}.{t}"), format!("eyJ{t}"))),
        tail.prop_map(|t| (format!("password={t}"), t)),
        tail.prop_map(|t| (format!("\"client_assertion\": \"{t}\""), t)),
        tail.prop_map(|t| (format!("x-api-key: {t}"), t)),
        tail.prop_map(|t| (
            format!("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI{t}\n-----END EC PRIVATE KEY-----"),
            format!("MHcCAQEEI{t}")
        )),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    /// Secrets planted everywhere the page reads from never come out of any page or API.
    #[test]
    fn no_secret_in_any_page_or_api_answer((planted, needle) in secret(), path in "[a-z]{3,8}") {
        let d = tempfile::tempdir().unwrap();
        let ctx = context(d.path(), false);
        // A log line, an error, a job from the platform, a result, the ledger.
        crate::logbuf::push("WARN", &format!("check failed: {planted}"));
        tracing::warn!(detail = %planted, "a check said something");
        ctx.state.disconnected(Some(format!("session failed: {planted}")));
        ctx.state.result_sent(
            JobRecord {
                at: crate::enroll::now_rfc3339(),
                kind: format!("check {planted}"),
                surface: Some(planted.clone()),
                target_host: Some(format!("{planted}.example.com")),
                verdict: "refused".into(),
                latency_ms: 0,
                job_id: Some(planted.clone()),
                key: Some("api".into()),
                reason: Some(format!("refused: {planted}")),
                error_class: Some(planted.clone()),
                status_code: None,
                tls_expires_at: Some(planted.clone()),
            },
            crate::protocol::ResultStatus::Refused,
        );
        ctx.ledger.as_ref().unwrap().record(crate::ledger::Record {
            kind: "result",
            payload: planted.as_bytes(),
            rule: "contract.refusal",
            destination: "wss://api.example.com/v1/agents/session",
            job_id: Some(&planted),
        }).unwrap();
        let all = render_all(&ctx);
        prop_assert!(!all.contains(&needle), "{needle} leaked on {path}");
        // The token and the reference a check's header comes from are never shown.
        prop_assert!(!all.contains(ctx.token.as_deref().unwrap()));
        prop_assert!(!all.contains("env:CHECK_TOKEN"));
    }
}

#[tokio::test]
async fn the_ledger_export_is_the_files_and_verifies() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let l = ctx.ledger.clone().unwrap();
    for i in 0..3u8 {
        l.record(crate::ledger::Record {
            kind: "heartbeat",
            payload: &[i],
            rule: "contract.heartbeat",
            destination: "wss://api.example.com/v1/agents/session",
            job_id: None,
        })
        .unwrap();
    }
    let (addr, _stop) = start(ctx).await;
    let r = send(addr, &get("/ledger.jsonl", &addr.to_string(), "")).await;
    assert_eq!(status(&r), 200);
    let body = r.split("\r\n\r\n").nth(1).unwrap();
    let mut exported = Vec::new();
    crate::ledger::export(l.dir(), &mut exported).unwrap();
    assert_eq!(body.as_bytes(), exported.as_slice());
    assert_eq!(body.lines().count(), 3);
}
