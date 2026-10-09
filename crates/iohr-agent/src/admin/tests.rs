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
    context_with(dir, require_token, None)
}

fn context_with(
    dir: &Path,
    require_token: bool,
    reload: Option<tokio::sync::mpsc::Sender<crate::agent::Reload>>,
) -> Arc<Context> {
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
        reload,
        share_key: vec![9; 32],
        policy_path: dir.join("policy.toml"),
        account_id: "acc_TEST".into(),
        checks_path: dir.join("checks.toml"),
        audit: Some(Arc::new(
            crate::audit::Audit::open(&dir.join("audit")).unwrap(),
        )),
        http: None,
        secrets: None,
        lock: crate::extensions::Lock::load_or_init(dir).unwrap(),
    })
}

/// A supervisor stand-in: answers every reload, and counts them.
fn reloader() -> (
    tokio::sync::mpsc::Sender<crate::agent::Reload>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::agent::Reload>(4);
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&n);
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = r.reply.send(Ok("reloaded with policy sha256:test".into()));
        }
    });
    (tx, n)
}

fn post(path: &str, host: &str, extra: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
}

/// Signs in with the token; the session cookie.
async fn sign_in(addr: SocketAddr, token: &str) -> String {
    let r = send(
        addr,
        &get(&format!("/auth?token={token}"), &addr.to_string(), ""),
    )
    .await;
    r.lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

/// The "What InOrbit sees" form: only from this machine, signed in, from this page's
/// origin with the form's token; the platform has no way in. A good change rewrites
/// `[share]` and reloads the agent.
#[tokio::test]
#[allow(clippy::too_many_lines)] // every refusal, then the change
async fn what_inorbit_sees_changes_only_from_this_machine_signed_in() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("policy.toml"), POLICY).unwrap();
    let (tx, reloads) = reloader();
    let ctx = context_with(d.path(), false, Some(tx));
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let origin = format!("Origin: http://{host}\r\nSec-Fetch-Site: same-origin\r\n");
    let form = "targets=full&hostname=on";

    // Not signed in: refused, nothing written.
    let r = send(addr, &post("/policy/share", &host, &origin, form)).await;
    assert_eq!(status(&r), 401, "{r}");
    // Another site's form, even with a stolen cookie name: refused before anything.
    let cookie = sign_in(addr, &token).await;
    let r = send(
        addr,
        &post(
            "/policy/share",
            &host,
            &format!("Origin: https://attacker.example\r\nCookie: {cookie}\r\n"),
            form,
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // A browser POST without an Origin, or without the form's token: refused.
    let r = send(
        addr,
        &post(
            "/policy/share",
            &host,
            &format!("Cookie: {cookie}\r\n"),
            form,
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    let r = send(
        addr,
        &post(
            "/policy/share",
            &host,
            &format!("{origin}Cookie: {cookie}\r\n"),
            &format!("{form}&csrf=0000"),
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // A form too large, or a body on any other path: refused.
    let r = send(
        addr,
        &post("/policy/share", &host, &origin, &"x".repeat(600)),
    )
    .await;
    assert_eq!(status(&r), 413, "{r}");
    let r = send(addr, &post("/checks", &host, &origin, "a=b")).await;
    assert_eq!(status(&r), 413, "{r}");
    assert_eq!(
        std::fs::read_to_string(d.path().join("policy.toml")).unwrap(),
        POLICY
    );
    assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 0);

    // Signed in, the page's own form: the policy changes and the agent reloads.
    let page = send(
        addr,
        &get("/policy", &host, &format!("Cookie: {cookie}\r\n")),
    )
    .await;
    assert!(
        page.contains("formaction=/policy/share"),
        "an Apply button when signed in"
    );
    let csrf = page
        .split("name=csrf value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let r = send(
        addr,
        &post(
            "/policy/share",
            &host,
            &format!("{origin}Cookie: {cookie}\r\n"),
            &format!("{form}&csrf={csrf}"),
        ),
    )
    .await;
    assert_eq!(status(&r), 303, "{r}");
    assert!(r.contains("Location: /policy?applied=1"));
    let text = std::fs::read_to_string(d.path().join("policy.toml")).unwrap();
    assert!(
        text.starts_with(POLICY),
        "the rest of the file is kept: {text}"
    );
    let p = Policy::from_toml(&text).unwrap();
    assert_eq!(p.share().targets, crate::policy::TargetShare::Full);
    assert!(p.share().hostname);
    assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 1);

    // `iohr agent share`: the token as a bearer, JSON back.
    let r = send(
        addr,
        &post(
            "/policy/reload",
            &host,
            &format!("Authorization: Bearer {token}\r\n"),
            "",
        ),
    )
    .await;
    assert_eq!(status(&r), 200, "{r}");
    assert!(r.contains("\"ok\":true"), "{r}");
    let r = send(
        addr,
        &post(
            "/policy/reload",
            &host,
            "Authorization: Bearer nope\r\n",
            "",
        ),
    )
    .await;
    assert_eq!(status(&r), 401, "{r}");
    // Not signed in: the page offers no Apply, only the way to sign in.
    let page = send(addr, &get("/policy", &host, "")).await;
    assert!(!page.contains("formaction=/policy/share") && page.contains("iohr agent page --open"));
}

#[test]
fn a_change_is_refused_beyond_loopback() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let token = ctx.token.clone().unwrap();
    let (_keep, rx) = watch::channel(ctx);
    let srv = Server {
        ctx: rx,
        local: Some("10.0.0.5:7790".parse().unwrap()),
        tls: true,
        sessions: Mutex::new(Vec::new()),
        pending: Mutex::new(Vec::new()),
        buckets: Mutex::new(HashMap::new()),
        conn_buckets: Mutex::new(HashMap::new()),
        slots: Arc::new(Semaphore::new(1)),
    };
    let req = parse(format!("POST /policy/reload HTTP/1.1\r\nHost: 10.0.0.5:7790\r\nAuthorization: Bearer {token}\r\n\r\n").as_bytes()).unwrap();
    let c = srv.ctx();
    let r = change_refused(&srv, &c, &req, "10.0.0.9:5000".parse().unwrap(), b"");
    assert_eq!(r.map(|(code, _)| code), Some(403));
    let r = change_refused(&srv, &c, &req, "127.0.0.1:5000".parse().unwrap(), b"");
    assert_eq!(
        r.map(|(code, _)| code),
        Some(403),
        "the listener itself is not on loopback"
    );
}

#[test]
fn the_preview_shows_exactly_what_the_next_hello_would_carry() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let view = page::View {
        query: "targets=label".into(),
        ..page::View::default()
    };
    let (_, html) = page::route(&ctx, "/policy", None, &view).unwrap();
    assert!(
        html.contains("Preview: the next hello, if you apply this"),
        "{html}"
    );
    assert!(
        !html.contains("api.example.com/healthz"),
        "label: no target anywhere on the page"
    );
    let view = page::View {
        query: "targets=full".into(),
        ..page::View::default()
    };
    let (_, html) = page::route(&ctx, "/policy", None, &view).unwrap();
    assert!(
        html.contains("&quot;url&quot;: &quot;https://api.example.com/healthz&quot;"),
        "{html}"
    );
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
            // same-origin, not no-referrer: with no-referrer a browser posts the page's own
            // form with `Origin: null`, which the origin check refuses.
            assert!(head.contains("Referrer-Policy: same-origin"), "{path}");
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
    let (_keep, ctx) = watch::channel(context(d.path(), false));
    let srv = Server {
        ctx,
        local: Some(addr),
        tls: false,
        sessions: Mutex::new(Vec::new()),
        pending: Mutex::new(Vec::new()),
        buckets: Mutex::new(HashMap::new()),
        conn_buckets: Mutex::new(HashMap::new()),
        slots: Arc::new(Semaphore::new(1)),
    };
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let allowed = (0..200).filter(|_| srv.rate_ok(ip)).count();
    assert!((40..200).contains(&allowed), "{allowed}");
    // Connections have a looser bucket of their own (a console page loads dozens of
    // files), still bounded.
    let conns = (0..2000).filter(|_| srv.conn_rate_ok(ip)).count();
    assert!((400..2000).contains(&conns), "{conns}");
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
    assert!(page.contains("What InOrbit sees"));
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

// ---- the local API and the console bundle (RFC 0100.4, slice 1) ----------------------

fn body(r: &str) -> &str {
    r.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn json_of(r: &str) -> serde_json::Value {
    serde_json::from_str(body(r)).unwrap()
}

fn bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
}

/// The context with a trial store holding `n` runs of `api`, the last one failed.
fn context_with_store(dir: &Path, n: usize) -> Arc<Context> {
    let ctx = context(dir, false);
    let store = crate::store::Store::open(&dir.join("store"), 30).unwrap();
    for i in 0..n {
        store
            .record_run(&JobRecord {
                at: crate::enroll::now_rfc3339(),
                kind: "check".into(),
                surface: Some("http".into()),
                target_host: Some("api.example.com".into()),
                verdict: if i + 1 == n { "failed" } else { "ok" }.into(),
                latency_ms: 10 + i as u64,
                key: Some("api".into()),
                status_code: Some(if i + 1 == n { 503 } else { 200 }),
                ..JobRecord::default()
            })
            .unwrap();
    }
    ctx.state.attach_store(Arc::new(store));
    ctx
}

/// Unlike the page, the API always asks for the token, on loopback too, and answers in
/// the response contract.
#[tokio::test]
async fn the_local_api_always_needs_the_token() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let path = "/v1/accounts/orgs/acc_TEST/monitors";
    let r = send(addr, &get(path, &host, "")).await;
    assert_eq!(status(&r), 401, "{r}");
    let e = json_of(&r);
    assert_eq!(e["code"], "unauthenticated");
    assert!(e["request_id"].as_str().is_some_and(|s| !s.is_empty()));
    let r = send(addr, &get(path, &host, &bearer("not-the-token"))).await;
    assert_eq!(status(&r), 401);
    let r = send(addr, &get(path, &host, &bearer(&token))).await;
    assert_eq!(status(&r), 200, "{r}");
    assert!(r.contains("Content-Type: application/json"));
    assert!(!r.to_ascii_lowercase().contains("access-control-allow"));
    // The browser's way: the session cookie from /auth works too.
    let cookie = sign_in(addr, &token).await;
    let r = send(addr, &get(path, &host, &format!("Cookie: {cookie}\r\n"))).await;
    assert_eq!(status(&r), 200);
}

/// Same paths and shapes as the public API; another account or agent is not found.
#[tokio::test]
async fn monitors_and_runs_have_the_public_shapes() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context_with_store(d.path(), 3);
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let auth = bearer(&token);

    let list = json_of(
        &send(
            addr,
            &get("/v1/accounts/orgs/acc_TEST/monitors", &host, &auth),
        )
        .await,
    );
    let ms = list["monitors"].as_array().unwrap();
    assert_eq!(ms.len(), 2, "a `[[check]]` and a `[[refuse]]`: {list}");
    let m = ms.iter().find(|m| m["monitor_id"] == "local-api").unwrap();
    let refuse = ms
        .iter()
        .find(|m| m["monitor_id"] == "local-metadata-closed")
        .unwrap();
    assert_eq!(refuse["check"]["refuse_by"], "policy");
    assert_eq!(m["monitor_id"], "local-api");
    assert_eq!(m["agent_id"], "agt_01TEST");
    assert_eq!(m["interval_secs"], 60);
    assert_eq!(m["where"], "agent");
    assert_eq!(m["executor"]["kind"], "agent");
    assert_eq!(m["check"]["surface"], "http");
    // The check's secret reference never appears.
    assert!(!list.to_string().contains("CHECK_TOKEN"));

    let one = json_of(
        &send(
            addr,
            &get(
                "/v1/accounts/orgs/acc_TEST/monitors/local-api",
                &host,
                &auth,
            ),
        )
        .await,
    );
    assert_eq!(one["monitor"]["name"], "api");

    let runs = json_of(
        &send(
            addr,
            &get(
                "/v1/accounts/orgs/acc_TEST/monitors/local-api/runs?page_size=2",
                &host,
                &auth,
            ),
        )
        .await,
    );
    let rs = runs["runs"].as_array().unwrap();
    assert_eq!(rs.len(), 2);
    assert_eq!(rs[0]["ok"], false, "newest first: {runs}");
    assert_eq!(rs[0]["status_code"], 503);
    let next = runs["next_page_token"].as_str().unwrap();
    assert_ne!(next, "");
    let page2 = json_of(
        &send(
            addr,
            &get(
                &format!("/v1/accounts/orgs/acc_TEST/monitors/local-api/runs?page_size=2&page_token={next}"),
                &host,
                &auth,
            ),
        )
        .await,
    );
    assert_eq!(page2["runs"].as_array().unwrap().len(), 1);
    assert_eq!(page2["next_page_token"], "");
    let failed = json_of(
        &send(
            addr,
            &get(
                "/v1/accounts/orgs/acc_TEST/monitors/local-api/runs?status=failed",
                &host,
                &auth,
            ),
        )
        .await,
    );
    assert_eq!(failed["runs"].as_array().unwrap().len(), 1);

    for p in [
        "/v1/accounts/orgs/acc_OTHER/monitors",
        "/v1/accounts/orgs/acc_TEST/monitors/local-nope",
        "/v1/accounts/orgs/acc_TEST/monitors/mon_platform",
        "/v1/accounts/orgs/acc_TEST/agents/agt_OTHER",
        "/v1/agents/agt_OTHER/ledger",
        "/v1/accounts/orgs/acc_TEST/billing",
    ] {
        let r = send(addr, &get(p, &host, &auth)).await;
        assert_eq!(status(&r), 404, "{p}: {r}");
        assert_eq!(json_of(&r)["code"], "not_found");
    }
}

/// The agent, its host, its ledger and its share settings, all from this machine.
#[tokio::test]
async fn agent_host_ledger_and_share_answer_locally() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context_with_store(dir.path(), 1);
    ctx.state.host_sampled(crate::state::HostInfo {
        sensors: 12,
        last_sample_at: crate::enroll::now_rfc3339(),
        chipset_millicelsius: Some(110_000),
        ..crate::state::HostInfo::default()
    });
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let auth = bearer(&token);
    let me = json_of(&send(addr, &get("/v1/agents/self", &host, &auth)).await);
    assert_eq!(me["account_id"], "acc_TEST");
    assert_eq!(me["agent_id"], "agt_01TEST");
    assert_eq!(me["store"], "trial");
    let agent = json_of(
        &send(
            addr,
            &get("/v1/accounts/orgs/acc_TEST/agents/agt_01TEST", &host, &auth),
        )
        .await,
    );
    assert_eq!(agent["agent"]["agent_id"], "agt_01TEST");
    assert_eq!(
        agent["agent"]["status"], "offline",
        "no platform session: {agent}"
    );
    assert_eq!(agent["agent"]["store"]["kind"], "trial");
    let host_doc = json_of(
        &send(
            addr,
            &get(
                "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/host",
                &host,
                &auth,
            ),
        )
        .await,
    );
    assert_eq!(host_doc["host"]["latest"]["sensors"], 12);
    assert_eq!(host_doc["host"]["readings"].as_array().unwrap().len(), 1);
    let ledger_doc = json_of(&send(addr, &get("/v1/agents/agt_01TEST/ledger", &host, &auth)).await);
    assert_eq!(ledger_doc["kept"], true);
    assert!(ledger_doc["entries"].is_array());
    let share_doc = json_of(
        &send(
            addr,
            &get(
                "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/share",
                &host,
                &auth,
            ),
        )
        .await,
    );
    assert_eq!(share_doc["where"], "agent");
}

/// Read-only in this phase: every other method is 405 with the contract's body.
#[tokio::test]
async fn the_local_api_is_read_only() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    for m in ["DELETE", "PATCH", "PUT"] {
        let r = send(
            addr,
            &format!(
                "{m} /v1/accounts/orgs/acc_TEST/monitors/local-api HTTP/1.1\r\nHost: {host}\r\n{}\r\n",
                bearer(&token)
            ),
        )
        .await;
        assert_eq!(status(&r), 405, "{m}: {r}");
    }
}

/// A web page elsewhere cannot read the API, even with the browser's cookie.
#[tokio::test]
async fn another_site_cannot_read_the_api() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let cookie = sign_in(addr, &token).await;
    let r = send(
        addr,
        &get(
            "/v1/accounts/orgs/acc_TEST/monitors",
            &host,
            &format!(
                "Cookie: {cookie}\r\nOrigin: https://evil.example\r\nSec-Fetch-Site: cross-site\r\n"
            ),
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
}

/// History survives a restart: a new state over the same store has the runs back.
#[test]
fn check_history_survives_a_restart() {
    let d = tempfile::tempdir().unwrap();
    {
        let _ = context_with_store(d.path(), 4);
    }
    let state = AgentState::default();
    state.attach_store(Arc::new(
        crate::store::Store::open(&d.path().join("store"), 30).unwrap(),
    ));
    assert_eq!(state.check_runs()["api"].len(), 4);
}

/// The console bundle: served from `console_dir` with its own CSP by hash, nothing
/// without it, and `/auth?next=` goes back only to a console page.
#[tokio::test]
async fn the_console_bundle_is_served_with_its_own_csp() {
    let d = tempfile::tempdir().unwrap();
    let bundle = d.path().join("bundle");
    std::fs::create_dir_all(bundle.join("monitors")).unwrap();
    std::fs::write(
        bundle.join("index.html"),
        "<html><script>self.x=1</script><body>local console</body></html>",
    )
    .unwrap();
    std::fs::write(bundle.join("monitors/index.html"), "<p>monitors</p>").unwrap();

    // No console_dir: 404.
    let (addr, _stop) = start(context(d.path(), false)).await;
    assert_eq!(
        status(&send(addr, &get("/console/", &addr.to_string(), "")).await),
        404
    );

    let mut ctx = Arc::try_unwrap(context(d.path(), false)).unwrap();
    ctx.admin.console_dir = Some(bundle);
    let token = ctx.token.clone().unwrap();
    let (addr, _stop2) = start(Arc::new(ctx)).await;
    let host = addr.to_string();
    let r = send(addr, &get("/console/", &host, "")).await;
    assert_eq!(status(&r), 200, "{r}");
    assert!(r.contains("local console"));
    let csp = r
        .lines()
        .find_map(|l| l.strip_prefix("Content-Security-Policy: "))
        .unwrap();
    assert!(csp.contains("script-src 'self' 'sha256-"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    assert_eq!(
        status(&send(addr, &get("/console/monitors/", &host, "")).await),
        200
    );
    assert_eq!(
        status(&send(addr, &get("/console/../admin.token", &host, "")).await),
        404
    );

    // Signing in returns to the console page that asked, and only to one.
    let r = send(
        addr,
        &get(
            &format!("/auth?token={token}&next=/console/monitors/"),
            &host,
            "",
        ),
    )
    .await;
    assert!(r.contains("Location: /console/monitors/"), "{r}");
    let r = send(
        addr,
        &get(
            &format!("/auth?token={token}&next=https://evil.example/"),
            &host,
            "",
        ),
    )
    .await;
    assert!(r.contains("Location: /\r\n"), "{r}");
}

/// The default listener is loopback: the API and the console add no listener of their
/// own and nothing is reachable from another machine unless the operator says so.
#[test]
fn nothing_listens_beyond_loopback_by_default() {
    let admin = AdminConfig::default();
    assert!(admin.listen.ip().is_loopback());
    assert!(!admin.allow_non_loopback);
    assert!(admin.console_dir.is_none());
}

// ---- slice 2: sign-in, roles, configuration management, extensions ---------------------

/// A supervisor stand-in that refuses every reload, as the agent does with files it
/// cannot start on.
fn refusing_reloader() -> tokio::sync::mpsc::Sender<crate::agent::Reload> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::agent::Reload>(4);
    tokio::spawn(async move {
        while let Some(r) = rx.recv().await {
            let _ = r
                .reply
                .send(Err("checks: api: every = \"1s\": must be 60s to 24h".into()));
        }
    });
    tx
}

fn put_json(path: &str, host: &str, extra: &str, body: &str) -> String {
    format!(
        "PUT {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
}

fn post_json(path: &str, host: &str, extra: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
}

const CHECKS_PATH: &str = "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/config/files/checks.toml";

/// A change goes through the checks, is written, reloads the agent and is versioned and
/// audited; a broken one is never written; one the agent refuses is put back.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one change after another, in order
async fn a_config_change_is_checked_applied_versioned_and_rolled_back() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("checks.toml"), CHECKS).unwrap();
    let (tx, reloads) = reloader();
    let ctx = Arc::try_unwrap(context_with(d.path(), false, Some(tx))).unwrap();
    let store = Arc::new(crate::store::Store::open(&d.path().join("store"), 30).unwrap());
    ctx.state.attach_store(Arc::clone(&store));
    let token = ctx.token.clone().unwrap();
    let audit = ctx.audit.clone().unwrap();
    let (addr, _stop) = start(Arc::new(ctx)).await;
    let host = addr.to_string();
    let auth = bearer(&token);

    // Read it, with its fingerprint.
    let file = json_of(&send(addr, &get(CHECKS_PATH, &host, &auth)).await);
    assert_eq!(file["can_edit"], true);
    let sha = file["sha"].as_str().unwrap().to_owned();

    // A broken file: refused with the lint's words, nothing written.
    let broken =
        serde_json::json!({"text": "[[check]]\nname = \"x\"\n", "base_sha": sha, "reason": "x"});
    let r = send(
        addr,
        &put_json(CHECKS_PATH, &host, &auth, &broken.to_string()),
    )
    .await;
    assert_eq!(status(&r), 422, "{r}");
    assert!(
        json_of(&r)["problems"]
            .as_array()
            .is_some_and(|p| !p.is_empty())
    );
    assert_eq!(
        std::fs::read_to_string(d.path().join("checks.toml")).unwrap(),
        CHECKS
    );

    // Validate shows the diff before anything is applied.
    let new_text = CHECKS.replace("every = \"60s\"", "every = \"120s\"");
    let v = json_of(
        &send(
            addr,
            &post_json(
                &format!("{CHECKS_PATH}/validate"),
                &host,
                &auth,
                &serde_json::json!({"text": new_text}).to_string(),
            ),
        )
        .await,
    );
    assert_eq!(v["valid"], true, "{v}");
    assert_eq!(v["diff"]["added"], 1);

    // A good one: applied, the agent reloaded, a version and an audit line.
    let good =
        serde_json::json!({"text": new_text, "base_sha": sha, "reason": "every two minutes"});
    let r = json_of(
        &send(
            addr,
            &put_json(CHECKS_PATH, &host, &auth, &good.to_string()),
        )
        .await,
    );
    assert_eq!(r["applied"], true, "{r}");
    assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read_to_string(d.path().join("checks.toml")).unwrap(),
        new_text
    );
    let versions = store.versions("checks.toml", 10).unwrap();
    assert_eq!(versions.len(), 2, "the file as found, then the change");
    assert_eq!(versions[0].reason, "every two minutes");
    assert_eq!(versions[0].who, "machine");
    assert_eq!(audit.recent(1)[0].action, "config.apply");
    assert_eq!(audit.verify(), Ok(1));

    // A stale base: the conflict is named, nothing written.
    let stale = serde_json::json!({"text": CHECKS, "base_sha": sha, "reason": "x"});
    assert_eq!(
        status(
            &send(
                addr,
                &put_json(CHECKS_PATH, &host, &auth, &stale.to_string())
            )
            .await
        ),
        409
    );

    // One click back to the version as found.
    let found = versions[1].id;
    let r = json_of(
        &send(
            addr,
            &post_json(
                &format!("{CHECKS_PATH}/versions/{found}/restore"),
                &host,
                &auth,
                "{}",
            ),
        )
        .await,
    );
    assert_eq!(r["applied"], true, "{r}");
    assert_eq!(
        std::fs::read_to_string(d.path().join("checks.toml")).unwrap(),
        CHECKS
    );

    // The agent refuses the next one: the file is put back as it was.
    let d2 = tempfile::tempdir().unwrap();
    std::fs::write(d2.path().join("checks.toml"), CHECKS).unwrap();
    let ctx2 = context_with(d2.path(), false, Some(refusing_reloader()));
    let token2 = ctx2.token.clone().unwrap();
    let (addr2, _stop2) = start(ctx2).await;
    let body = serde_json::json!({"text": new_text, "reason": "try"}).to_string();
    let r = send(
        addr2,
        &put_json(CHECKS_PATH, &addr2.to_string(), &bearer(&token2), &body),
    )
    .await;
    assert_eq!(status(&r), 422, "{r}");
    assert_eq!(json_of(&r)["rolled_back"], true);
    assert_eq!(
        std::fs::read_to_string(d2.path().join("checks.toml")).unwrap(),
        CHECKS
    );
}

/// A browser's write needs the session's own form token and this page's origin.
#[tokio::test]
async fn a_browser_write_needs_the_sessions_csrf_token() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("checks.toml"), CHECKS).unwrap();
    let (tx, _) = reloader();
    let ctx = context_with(d.path(), false, Some(tx));
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let cookie = sign_in(addr, &token).await;
    let me = json_of(
        &send(
            addr,
            &get("/v1/agents/self", &host, &format!("Cookie: {cookie}\r\n")),
        )
        .await,
    );
    let csrf = me["csrf"].as_str().unwrap().to_owned();
    assert_eq!(me["viewer"]["role"], "owner");
    let body =
        serde_json::json!({"text": CHECKS.replace("60s", "120s"), "reason": "r"}).to_string();
    let origin = format!("Origin: http://{host}\r\n");
    // No token.
    let r = send(
        addr,
        &put_json(
            CHECKS_PATH,
            &host,
            &format!("Cookie: {cookie}\r\n{origin}"),
            &body,
        ),
    )
    .await;
    assert_eq!(status(&r), 403, "{r}");
    // Another session's token.
    let r = send(
        addr,
        &put_json(
            CHECKS_PATH,
            &host,
            &format!(
                "Cookie: {cookie}\r\n{origin}X-CSRF-Token: {}\r\n",
                csrf_for("other")
            ),
            &body,
        ),
    )
    .await;
    assert_eq!(status(&r), 403);
    // Its own: applied.
    let r = send(
        addr,
        &put_json(
            CHECKS_PATH,
            &host,
            &format!("Cookie: {cookie}\r\n{origin}X-CSRF-Token: {csrf}\r\n"),
            &body,
        ),
    )
    .await;
    assert_eq!(status(&r), 200, "{r}");
    // Signing out ends the session.
    let r = send(
        addr,
        &post(
            "/auth/logout",
            &host,
            &format!("Cookie: {cookie}\r\n{origin}"),
            "",
        ),
    )
    .await;
    assert_eq!(status(&r), 303);
    let r = send(
        addr,
        &get("/v1/agents/self", &host, &format!("Cookie: {cookie}\r\n")),
    )
    .await;
    assert_eq!(status(&r), 401);
}

/// The company's identity provider: a person signs in with PKCE, their groups give them a
/// role, and the role decides what they may change.
#[tokio::test]
#[allow(clippy::too_many_lines)] // an identity provider, then each sign-in
async fn people_sign_in_with_the_company_idp_and_their_role_decides() {
    use axum::routing::{get as aget, post as apost};
    crate::tls::install_crypto_provider();
    let nonce = Arc::new(std::sync::Mutex::new(String::new()));
    let groups = Arc::new(std::sync::Mutex::new(vec!["engineering".to_owned()]));
    let idp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let iss = format!("http://{}", idp.local_addr().unwrap());
    let (n2, g2, iss2) = (Arc::clone(&nonce), Arc::clone(&groups), iss.clone());
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            aget({
                let iss = iss.clone();
                move || {
                    let iss = iss.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "issuer": iss,
                            "authorization_endpoint": format!("{iss}/authorize"),
                            "token_endpoint": format!("{iss}/token"),
                        }))
                    }
                }
            }),
        )
        .route(
            "/token",
            apost(move |body: String| {
                let (n, g, iss) = (n2.lock().unwrap().clone(), g2.lock().unwrap().clone(), iss2.clone());
                async move {
                    assert!(body.contains("code_verifier="), "PKCE verifier sent");
                    assert!(body.contains("client_secret=s3cret"), "the secret from its reference");
                    let claims = serde_json::json!({
                        "iss": iss, "aud": "iohr-agent-console", "sub": "u-7", "name": "Ana",
                        "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                        "nonce": n, "groups": g,
                    });
                    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    axum::Json(serde_json::json!({"id_token": format!("e30.{}.x", b64.encode(claims.to_string()))}))
                }
            }),
        );
    tokio::spawn(async move { axum::serve(idp, app).await.unwrap() });

    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("secret"), "s3cret\n").unwrap();
    std::fs::write(d.path().join("checks.toml"), CHECKS).unwrap();
    let policy_text = format!(
        "{POLICY}[console]\nusers = [\"machine\", \"oidc\"]\n[console.oidc]\nissuer = \"{iss}\"\nname = \"Example SSO\"\nclient_id = \"iohr-agent-console\"\nclient_secret = \"file:{}\"\nroles = {{ member = [\"engineering\"], admin = [\"sre-leads\"] }}\n",
        d.path().join("secret").display()
    );
    std::fs::write(d.path().join("policy.toml"), &policy_text).unwrap();
    let (tx, _) = reloader();
    let mut ctx = Arc::try_unwrap(context_with(d.path(), false, Some(tx))).unwrap();
    ctx.policy = Arc::new(Policy::from_toml(&policy_text).unwrap());
    ctx.http = Some(reqwest::Client::new());
    ctx.secrets = Some(crate::secrets::SecretResolver::new(
        crate::config::SecretsConfig::default(),
        crate::tls::TlsContext::new(None).unwrap(),
    ));
    let (addr, _stop) = start(Arc::new(ctx)).await;
    let host = addr.to_string();

    let opts = json_of(&send(addr, &get("/auth/options", &host, "")).await);
    assert_eq!(opts["modes"], serde_json::json!(["machine", "oidc"]));
    assert_eq!(opts["oidc"]["name"], "Example SSO");

    // Sign in as a member of engineering.
    let sign_in_oidc = |groups_now: Vec<&str>| {
        let (nonce, groups) = (Arc::clone(&nonce), Arc::clone(&groups));
        let host = host.clone();
        let groups_now: Vec<String> = groups_now.into_iter().map(str::to_owned).collect();
        async move {
            *groups.lock().unwrap() = groups_now;
            let r = send(addr, &get("/auth/oidc/start?next=/console/", &host, "")).await;
            let loc = r
                .lines()
                .find_map(|l| l.strip_prefix("Location: "))
                .unwrap()
                .to_owned();
            let u = url::Url::parse(&loc).unwrap();
            let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
            assert_eq!(q["code_challenge_method"], "S256");
            *nonce.lock().unwrap() = q["nonce"].clone();
            // The identity provider sends the browser back: a cross-site navigation.
            send(
                addr,
                &get(
                    &format!("/auth/oidc/callback?code=c1&state={}", q["state"]),
                    &host,
                    "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n",
                ),
            )
            .await
        }
    };
    let r = sign_in_oidc(vec!["engineering"]).await;
    assert!(r.contains("Location: /console/"), "{r}");
    let cookie = r
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let me = json_of(
        &send(
            addr,
            &get("/v1/agents/self", &host, &format!("Cookie: {cookie}\r\n")),
        )
        .await,
    );
    assert_eq!(me["viewer"]["role"], "member");
    assert_eq!(me["viewer"]["name"], "Ana");
    let csrf = me["csrf"].as_str().unwrap().to_owned();
    let h = format!("Cookie: {cookie}\r\nOrigin: http://{host}\r\nX-CSRF-Token: {csrf}\r\n");
    // A member changes checks, not the policy.
    let body =
        serde_json::json!({"text": CHECKS.replace("60s", "120s"), "reason": "r"}).to_string();
    assert_eq!(
        status(&send(addr, &put_json(CHECKS_PATH, &host, &h, &body)).await),
        200
    );
    let pol = "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/config/files/policy.toml";
    let body = serde_json::json!({"text": policy_text, "reason": "r"}).to_string();
    assert_eq!(
        status(&send(addr, &put_json(pol, &host, &h, &body)).await),
        403
    );
    // Nor extensions.
    let ext = "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/extensions/inorbit/host/disable";
    assert_eq!(
        status(&send(addr, &post_json(ext, &host, &h, "{}")).await),
        403
    );

    // Groups that name no role: no session at all.
    let r = sign_in_oidc(vec!["visitors"]).await;
    assert!(
        r.contains("Location: /console/signin/?error=no_role"),
        "{r}"
    );
    assert!(!r.contains("Set-Cookie"));
    // A cross-site fetch of the callback (not a navigation) is still refused.
    let r = send(
        addr,
        &get(
            "/auth/oidc/callback?code=c1&state=x",
            &host,
            "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: cors\r\n",
        ),
    )
    .await;
    assert_eq!(status(&r), 403);
    // A replayed or unknown state.
    let r = send(
        addr,
        &get("/auth/oidc/callback?code=c1&state=forged", &host, ""),
    )
    .await;
    assert!(r.contains("error=expired"), "{r}");
}

/// Extensions: an admin installs and removes them; the licence and the policy are not the
/// console's to override; the agent core cannot be removed; the console itself is one.
#[tokio::test]
async fn extensions_need_three_yeses_and_an_admin() {
    let d = tempfile::tempdir().unwrap();
    let (tx, reloads) = reloader();
    let ctx = context_with(d.path(), false, Some(tx));
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let auth = bearer(&token);
    let base = "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/extensions";
    let list = json_of(&send(addr, &get(base, &host, &auth)).await);
    let console = list["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["manifest"]["id"] == "inorbit/console")
        .unwrap();
    assert_eq!(console["state"]["running"], true, "{console}");
    assert_eq!(console["manifest"]["delivery"], "web");
    // Remove the monitors: the lock changes and the agent reloads.
    let r = json_of(
        &send(
            addr,
            &post_json(
                &format!("{base}/inorbit/monitors/disable"),
                &host,
                &auth,
                "{\"reason\":\"not here\"}",
            ),
        )
        .await,
    );
    assert_eq!(r["changed"], true, "{r}");
    assert!(
        !crate::extensions::Lock::load_or_init(d.path())
            .unwrap()
            .has("inorbit/monitors")
    );
    assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The core cannot go; verify cannot come (no licence, and the policy refuses load).
    assert_eq!(
        status(
            &send(
                addr,
                &post_json(
                    &format!("{base}/inorbit/agent-core/disable"),
                    &host,
                    &auth,
                    "{}"
                )
            )
            .await
        ),
        412
    );
    let r = send(
        addr,
        &post_json(&format!("{base}/inorbit/chaos/enable"), &host, &auth, "{}"),
    )
    .await;
    assert_eq!(status(&r), 412, "{r}");
}

/// The console is served only while `inorbit/console` is installed.
#[tokio::test]
async fn the_console_is_an_extension() {
    let d = tempfile::tempdir().unwrap();
    let bundle = d.path().join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(bundle.join("index.html"), "<p>console</p>").unwrap();
    let mut ctx = Arc::try_unwrap(context(d.path(), false)).unwrap();
    ctx.admin.console_dir = Some(bundle);
    ctx.lock.extensions.retain(|e| e.id != "inorbit/console");
    let (addr, _stop) = start(Arc::new(ctx)).await;
    let r = send(addr, &get("/console/", &addr.to_string(), "")).await;
    assert_eq!(status(&r), 404);
    assert!(r.contains("inorbit/console"));
}

/// Verify: a change's claims judged before and after from the kept runs, frozen as an
/// evidence record once its window has passed.
#[tokio::test]
async fn a_verification_judges_each_claim_before_and_after() {
    let d = tempfile::tempdir().unwrap();
    let ctx = context(d.path(), false);
    let store = Arc::new(crate::store::Store::open(&d.path().join("store"), 30).unwrap());
    ctx.state.attach_store(Arc::clone(&store));
    let fmt = |t: time::OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let change = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    for (offset, verdict) in [(-300, "ok"), (-200, "ok"), (200, "ok"), (300, "failed")] {
        store
            .record_run(&JobRecord {
                at: fmt(change + time::Duration::seconds(offset)),
                kind: "check".into(),
                verdict: verdict.into(),
                key: Some("api".into()),
                status_code: Some(if verdict == "ok" { 200 } else { 503 }),
                ..JobRecord::default()
            })
            .unwrap();
    }
    let token = ctx.token.clone().unwrap();
    let (addr, _stop) = start(ctx).await;
    let host = addr.to_string();
    let auth = bearer(&token);
    let base = "/v1/accounts/orgs/acc_TEST/agents/agt_01TEST/verifications";
    // A claim that is not a check is refused.
    let bad = serde_json::json!({"name": "x", "claims": ["nope"]}).to_string();
    assert_eq!(
        status(&send(addr, &post_json(base, &host, &auth, &bad)).await),
        400
    );
    let body = serde_json::json!({
        "name": "Retry change in the API client",
        "claims": ["api"],
        "change_at": fmt(change),
        "window_secs": 600,
        "reason": "PR 42",
    })
    .to_string();
    let r = json_of(&send(addr, &post_json(base, &host, &auth, &body)).await);
    let rec = &r["verification"]["record"];
    assert_eq!(rec["verdict"], "fail", "{r}");
    assert_eq!(rec["claims"][0]["verdict"], "broke");
    assert_eq!(rec["claims"][0]["before"]["runs"], 2);
    assert_eq!(rec["claims"][0]["after"]["passed"], 1);
    assert_eq!(
        rec["claims"][0]["after"]["first_failures"][0]["status_code"],
        503
    );
    // Frozen: a later run in the window does not change the record.
    store
        .record_run(&JobRecord {
            at: fmt(change + time::Duration::seconds(400)),
            kind: "check".into(),
            verdict: "ok".into(),
            key: Some("api".into()),
            ..JobRecord::default()
        })
        .unwrap();
    let id = r["verification"]["verification_id"].as_str().unwrap();
    let again = json_of(&send(addr, &get(&format!("{base}/{id}"), &host, &auth)).await);
    assert_eq!(
        again["verification"]["record"]["claims"][0]["after"]["runs"],
        2
    );
    // A change still inside its window is measuring.
    let body =
        serde_json::json!({"name": "now", "claims": ["api"], "window_secs": 600}).to_string();
    let r = json_of(&send(addr, &post_json(base, &host, &auth, &body)).await);
    assert_eq!(r["verification"]["record"]["verdict"], "measuring");
    let list = json_of(&send(addr, &get(base, &host, &auth)).await);
    assert_eq!(list["verifications"].as_array().unwrap().len(), 2);
}
