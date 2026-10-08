//! The local agent page: what this agent is, what it may do, what it did and what left
//! this machine, for the people who run it to check without trusting InOrbit
//! (`docs/security/admin-page.md` is its threat model).
//!
//! A small hand-written HTTP/1.1 responder keeps a server framework out of the dependency
//! tree. Every rule here is about one thing: nobody but the operator on this machine
//! reads it, and nothing reached through it changes the agent.
//!
//! - **Loopback only** by default; beyond loopback only with `admin.allow_non_loopback`,
//!   TLS and the page's token (checked at startup, [`crate::config::AdminConfig::check`]).
//! - **Read-only**: GET and HEAD; no endpoint changes state. The one exchange that sets
//!   anything, `/auth`, turns the page's token into a cookie for this browser.
//! - **DNS rebinding and CSRF**: the `Host` header must be one of `127.0.0.1:<port>`,
//!   `localhost:<port>`, `[::1]:<port>` (plus `admin.hosts`), else 421; an `Origin` that is
//!   not this page and a `Sec-Fetch-Site` other than `same-origin`/`none` are refused with
//!   403 (a cross-site top-level navigation to an HTML page is let through: it cannot read
//!   the answer); no CORS header is ever sent.
//! - **Headers**: a CSP with `default-src 'none'`, the one stylesheet by hash, no script
//!   at all; `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `no-store`.
//! - **Never shown**: the private key, enrollment tokens, secret values, check auth
//!   headers; every body passes through [`crate::redact`] last.
//! - **Bounded**: 8 KiB of request headers, no bodies, 5 s to send them, 10 s per write,
//!   64 connections, a token bucket per client address, embedded assets only.

mod page;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::checks_file::DeclaredChecks;
use crate::config::AdminConfig;
use crate::error::{Error, Result};
use crate::ledger::{Ledger, LedgerConfig};
use crate::policy::Policy;
use crate::state::AgentState;

pub use page::render_all;

/// Largest request head.
const MAX_REQUEST: usize = 8 * 1024;
/// Most header lines.
const MAX_HEADERS: usize = 64;
/// Time to send the request head.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Time for each write to the client.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once; more are closed.
const MAX_CONNECTIONS: usize = 64;
/// Requests a client may burst.
const BURST: f64 = 40.0;
/// Requests a client may make per second, sustained.
const PER_SECOND: f64 = 10.0;
/// Client addresses tracked by the rate limit.
const MAX_CLIENTS: usize = 1024;
/// Browser sessions kept after `/auth`.
const MAX_SESSIONS: usize = 16;
/// How long one lasts.
const SESSION_TTL: Duration = Duration::from_hours(12);
/// The session cookie.
const COOKIE: &str = "iohr_agent_page";
/// The token file in the state directory.
pub const TOKEN_FILE: &str = "admin.token";

/// What the page reads. Never the private key, never the enrollment.
pub struct Context {
    /// The agent's live state.
    pub state: Arc<AgentState>,
    /// The policy in force.
    pub policy: Arc<Policy>,
    /// The declared checks.
    pub checks: Option<Arc<DeclaredChecks>>,
    /// The egress ledger, when kept.
    pub ledger: Option<Arc<Ledger>>,
    /// `[ledger]`.
    pub ledger_config: LedgerConfig,
    /// The platform's API.
    pub api: String,
    /// `[admin]`.
    pub admin: AdminConfig,
    /// The state directory.
    pub state_dir: String,
    /// The page's token.
    pub token: Option<String>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("api", &self.api)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// The server's own bookkeeping: sessions, rate limits, connection slots.
#[derive(Debug)]
struct Server {
    ctx: Arc<Context>,
    local: Option<SocketAddr>,
    tls: bool,
    sessions: Mutex<Vec<(String, Instant)>>,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    slots: Arc<Semaphore>,
}

/// TLS for the page, when `admin.tls_cert` and `admin.tls_key` are set.
///
/// # Errors
/// When they cannot be read.
pub fn server_tls(admin: &AdminConfig) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let (Some(cert), Some(key)) = (&admin.tls_cert, &admin.tls_key) else {
        return Ok(None);
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| Error::Tls(format!("admin.tls_cert {}: {e}", cert.display())))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Tls(format!("admin.tls_cert {}: {e}", cert.display())))?;
    if certs.is_empty() {
        return Err(Error::Tls(format!(
            "admin.tls_cert {} holds no certificate",
            cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| Error::Tls(format!("admin.tls_key {}: {e}", key.display())))?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(format!("admin TLS: {e}")))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg))))
}

/// Makes this run's page token and writes it to `<state_dir>/admin.token` (0600), where
/// `iohr agent page --open` reads it. A new one every start.
///
/// # Errors
/// When the random source or the file fails.
pub fn write_token(state_dir: &Path) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| Error::Config(format!("random: {e}")))?;
    let token = raw.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    std::fs::create_dir_all(state_dir).map_err(|e| Error::io(state_dir, e))?;
    let path = state_dir.join(TOKEN_FILE);
    let _ = std::fs::remove_file(&path);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&path).map_err(|e| Error::io(&path, e))?;
    std::io::Write::write_all(&mut f, token.as_bytes()).map_err(|e| Error::io(&path, e))?;
    crate::redact::register(&token);
    Ok(token)
}

/// Equal without telling, by its timing, how much of it matched.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0xff);
    }
    diff == 0
}

/// Serves until `shutdown` turns true.
pub async fn serve(
    listener: TcpListener,
    ctx: Arc<Context>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    let server = Arc::new(Server {
        ctx,
        local: listener.local_addr().ok(),
        tls: tls.is_some(),
        sessions: Mutex::new(Vec::new()),
        buckets: Mutex::new(HashMap::new()),
        slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
    });
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                let Ok((sock, peer)) = accepted else { continue };
                // Over the connection limit: closed at once, nothing read.
                let Ok(permit) = Arc::clone(&server.slots).try_acquire_owned() else {
                    drop(sock);
                    continue;
                };
                let server = Arc::clone(&server);
                let tls = tls.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tls {
                        Some(acceptor) => {
                            if let Ok(Ok(stream)) = tokio::time::timeout(READ_TIMEOUT, acceptor.accept(sock)).await {
                                let _ = handle(stream, peer, &server).await;
                            }
                        }
                        None => {
                            let _ = handle(sock, peer, &server).await;
                        }
                    }
                });
            }
        }
    }
}

/// A parsed request head.
#[derive(Debug, Default)]
struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(k, _)| k == name).count()
    }

    fn query_param(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(self.query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == "cookie")
            .flat_map(|(_, v)| v.split(';'))
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
    }
}

/// What went wrong with a request, and the status it gets.
fn parse(buf: &[u8]) -> std::result::Result<Request, (u16, &'static str)> {
    let text = std::str::from_utf8(buf).map_err(|_| (400, "bad request"))?;
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, target, version) = (
        first.next().unwrap_or_default(),
        first.next().unwrap_or_default(),
        first.next().unwrap_or_default(),
    );
    if first.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err((400, "bad request"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut req = Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers: Vec::new(),
    };
    for line in lines {
        let (k, v) = line.split_once(':').ok_or((400, "bad request"))?;
        if k.is_empty() || k.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err((400, "bad request"));
        }
        req.headers
            .push((k.to_ascii_lowercase(), v.trim().to_owned()));
        if req.headers.len() > MAX_HEADERS {
            return Err((431, "too many headers"));
        }
    }
    if req.count("host") != 1 || req.count("origin") > 1 {
        return Err((400, "bad request"));
    }
    // No request bodies at all: nothing here takes input beyond the URL.
    if req.header("transfer-encoding").is_some()
        || req
            .header("content-length")
            .is_some_and(|l| l.trim() != "0")
    {
        return Err((413, "request bodies are not accepted"));
    }
    Ok(req)
}

impl Server {
    /// The `Host` values this page answers to.
    fn allowed_hosts(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(l) = self.local {
            let port = l.port();
            out.push(format!("127.0.0.1:{port}"));
            out.push(format!("localhost:{port}"));
            out.push(format!("[::1]:{port}"));
            if !l.ip().is_loopback() && !l.ip().is_unspecified() {
                out.push(match l.ip() {
                    IpAddr::V4(ip) => format!("{ip}:{port}"),
                    IpAddr::V6(ip) => format!("[{ip}]:{port}"),
                });
            }
        }
        out.extend(self.ctx.admin.hosts.iter().cloned());
        out
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts()
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        let scheme = if self.tls { "https://" } else { "http://" };
        origin
            .strip_prefix(scheme)
            .is_some_and(|h| self.host_allowed(h))
    }

    /// A token bucket per client address.
    fn rate_ok(&self, ip: IpAddr) -> bool {
        let mut b = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        if b.len() >= MAX_CLIENTS && !b.contains_key(&ip) {
            b.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(10));
            if b.len() >= MAX_CLIENTS {
                return false;
            }
        }
        let (tokens, last) = b.entry(ip).or_insert((BURST, now));
        let refill = now.duration_since(*last).as_secs_f64() * PER_SECOND;
        *tokens = (*tokens + refill).min(BURST);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }

    fn session_ok(&self, req: &Request) -> bool {
        // A local client (`iohr agent status`) may present the token itself. A browser
        // cannot add this header cross-site without a CORS preflight, which is never
        // answered.
        if let (Some(given), Some(token)) = (
            req.header("authorization")
                .and_then(|a| a.strip_prefix("Bearer ")),
            &self.ctx.token,
        ) {
            return constant_time_eq(token.as_bytes(), given.trim().as_bytes());
        }
        let Some(id) = req.cookie(COOKIE) else {
            return false;
        };
        let mut s = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.retain(|(_, t)| t.elapsed() < SESSION_TTL);
        // Compare against every session, each in constant time.
        s.iter().fold(false, |ok, (k, _)| {
            constant_time_eq(k.as_bytes(), id.as_bytes()) | ok
        })
    }

    fn new_session(&self) -> String {
        let mut raw = [0u8; 32];
        let _ = getrandom::fill(&mut raw);
        let id = raw.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let mut s = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if s.len() >= MAX_SESSIONS {
            s.remove(0);
        }
        s.push((id.clone(), Instant::now()));
        id
    }
}

/// Fetch metadata: a request from another site is refused, except a top-level
/// navigation to an HTML page, which cannot read what it opens.
fn fetch_site_ok(req: &Request) -> bool {
    match req.header("sec-fetch-site") {
        None | Some("same-origin" | "none") => true,
        Some(_) => {
            req.method == "GET"
                && req.header("sec-fetch-mode") == Some("navigate")
                && req.header("sec-fetch-dest") == Some("document")
                && page::is_html_route(&req.path)
        }
    }
}

async fn read_head<S: AsyncRead + Unpin>(sock: &mut S) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        let mut chunk = [0u8; 1024];
        loop {
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if buf.len() > MAX_REQUEST {
                return None;
            }
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(());
            }
        }
    })
    .await;
    matches!(read, Ok(Some(()))).then_some(buf)
}

#[allow(clippy::too_many_lines)] // every rule in the order it is applied
async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut sock: S,
    peer: SocketAddr,
    srv: &Server,
) -> std::io::Result<()> {
    if !srv.rate_ok(peer.ip()) {
        return respond(
            &mut sock,
            srv,
            429,
            "text/plain",
            b"slow down\n",
            &[],
            false,
        )
        .await;
    }
    let Some(buf) = read_head(&mut sock).await else {
        return respond(
            &mut sock,
            srv,
            400,
            "text/plain",
            b"bad request\n",
            &[],
            false,
        )
        .await;
    };
    let req = match parse(&buf) {
        Ok(r) => r,
        Err((code, msg)) => {
            return respond(
                &mut sock,
                srv,
                code,
                "text/plain",
                format!("{msg}\n").as_bytes(),
                &[],
                false,
            )
            .await;
        }
    };
    let head = req.method == "HEAD";
    // DNS rebinding: a page on another name that resolves here is refused.
    if !req.header("host").is_some_and(|h| srv.host_allowed(h)) {
        return respond(
            &mut sock,
            srv,
            421,
            "text/plain",
            b"wrong host\n",
            &[],
            head,
        )
        .await;
    }
    // CSRF and cross-site reads.
    if req.header("origin").is_some_and(|o| !srv.origin_allowed(o)) || !fetch_site_ok(&req) {
        return respond(
            &mut sock,
            srv,
            403,
            "text/plain",
            b"cross-site requests are refused\n",
            &[],
            head,
        )
        .await;
    }
    if req.method != "GET" && !head {
        return respond(
            &mut sock,
            srv,
            405,
            "text/plain",
            b"read-only\n",
            &[("Allow", "GET, HEAD")],
            false,
        )
        .await;
    }
    match req.path.as_str() {
        "/healthz" => return respond(&mut sock, srv, 200, "text/plain", b"ok\n", &[], head).await,
        "/favicon.svg" => {
            return respond(
                &mut sock,
                srv,
                200,
                "image/svg+xml",
                page::FAVICON.as_bytes(),
                &[],
                head,
            )
            .await;
        }
        "/auth" => return auth(&mut sock, srv, &req, head).await,
        _ => {}
    }
    if srv.ctx.admin.token_required() && !srv.session_ok(&req) {
        let body = page::locked(&srv.ctx);
        return respond(
            &mut sock,
            srv,
            401,
            "text/html; charset=utf-8",
            body.as_bytes(),
            &[],
            head,
        )
        .await;
    }
    if req.path == "/ledger.jsonl" {
        return export(&mut sock, srv, head).await;
    }
    match page::route(&srv.ctx, &req.path, srv.local) {
        Some((ctype, body)) => {
            // Last line of defence: whatever reached the agent's memory, no secret
            // leaves through this page.
            let body = crate::redact::redact(&body);
            respond(&mut sock, srv, 200, ctype, body.as_bytes(), &[], head).await
        }
        None => respond(&mut sock, srv, 404, "text/plain", b"not found\n", &[], head).await,
    }
}

/// `/auth?token=…`: the token from `<state_dir>/admin.token` becomes a cookie for this
/// browser (`HttpOnly`, SameSite=Strict, Secure over TLS), then back to the page.
async fn auth<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
    head: bool,
) -> std::io::Result<()> {
    let given = req.query_param("token").unwrap_or_default();
    let ok = srv
        .ctx
        .token
        .as_ref()
        .is_some_and(|t| constant_time_eq(t.as_bytes(), given.as_bytes()));
    if !ok {
        let body = page::locked(&srv.ctx);
        return respond(
            sock,
            srv,
            401,
            "text/html; charset=utf-8",
            body.as_bytes(),
            &[],
            head,
        )
        .await;
    }
    let id = srv.new_session();
    let cookie = format!(
        "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_TTL.as_secs(),
        if srv.tls { "; Secure" } else { "" }
    );
    respond(
        sock,
        srv,
        303,
        "text/plain",
        b"signed in\n",
        &[("Location", "/"), ("Set-Cookie", &cookie)],
        head,
    )
    .await
}

/// `/ledger.jsonl`: the ledger files as they are, oldest first, streamed.
async fn export<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    head: bool,
) -> std::io::Result<()> {
    let Some(ledger) = &srv.ctx.ledger else {
        return respond(
            sock,
            srv,
            404,
            "text/plain",
            b"the egress ledger is off\n",
            &[],
            head,
        )
        .await;
    };
    let files = crate::ledger::export_files(ledger.dir());
    let total: u64 = files
        .iter()
        .map(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
        .sum();
    let header = headers(
        srv,
        200,
        "application/x-ndjson",
        total,
        &[(
            "Content-Disposition",
            "attachment; filename=\"iohr-agent-ledger.jsonl\"",
        )],
    );
    write_timed(sock, header.as_bytes()).await?;
    if !head {
        let mut sent = 0u64;
        for p in files {
            let Ok(mut f) = tokio::fs::File::open(&p).await else {
                break;
            };
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let n = f.read(&mut chunk).await?;
                if n == 0 || sent >= total {
                    break;
                }
                // Never more than announced: a file that grew since is cut here.
                let n = n.min(usize::try_from(total - sent).unwrap_or(n));
                write_timed(sock, chunk.get(..n).unwrap_or_default()).await?;
                sent += n as u64;
            }
        }
    }
    sock.shutdown().await
}

async fn write_timed<S: AsyncWrite + Unpin>(sock: &mut S, bytes: &[u8]) -> std::io::Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, sock.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "slow client"))?
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

/// The response head: the same security headers on every answer, and never a CORS one.
fn headers(srv: &Server, status: u16, ctype: &str, len: u64, extra: &[(&str, &str)]) -> String {
    let mut h = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\n\
Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\nContent-Security-Policy: {}\r\n\
Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()\r\n",
        reason(status),
        page::csp()
    );
    if srv.tls {
        h.push_str("Strict-Transport-Security: max-age=31536000\r\n");
    }
    for (k, v) in extra {
        let _ = write!(h, "{k}: {v}\r\n");
    }
    h.push_str("Connection: close\r\n\r\n");
    h
}

async fn respond<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    status: u16,
    ctype: &str,
    body: &[u8],
    extra: &[(&str, &str)],
    head: bool,
) -> std::io::Result<()> {
    let header = headers(srv, status, ctype, body.len() as u64, extra);
    write_timed(sock, header.as_bytes()).await?;
    if !head {
        write_timed(sock, body).await?;
    }
    sock.shutdown().await
}

#[cfg(test)]
mod tests;
