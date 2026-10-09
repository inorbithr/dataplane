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
//! - **Read-only, but for one choice**: GET and HEAD everywhere. The one thing the page
//!   changes is `[share]` in the policy ("What InOrbit sees", `POST /policy/share`), and
//!   `POST /policy/reload` loads the files again: only from this machine (the listener and
//!   the client both on loopback), only signed in (the page's token as a session cookie, or
//!   as a bearer for `iohr agent share`), a browser's from this page's own origin with the
//!   form's token. The platform has no way to call either. `/auth` turns the token into a
//!   cookie for this browser.
//! - **DNS rebinding and CSRF**: the `Host` header must be one of `127.0.0.1:<port>`,
//!   `localhost:<port>`, `[::1]:<port>` (plus `admin.hosts`), else 421; an `Origin` that is
//!   not this page and a `Sec-Fetch-Site` other than `same-origin`/`none` are refused with
//!   403 (a cross-site top-level navigation to an HTML page is let through: it cannot read
//!   the answer); no CORS header is ever sent.
//! - **Headers**: a CSP with `default-src 'none'`, the one stylesheet by hash, no script
//!   at all; `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: same-origin` (no referrer to
//!   any other site; `no-referrer` would make browsers send `Origin: null` on the page's own
//!   form), `no-store`.
//! - **Never shown**: the private key, enrollment tokens, secret values, check auth
//!   headers; every body passes through [`crate::redact`] last.
//! - **Bounded**: 8 KiB of request headers, no bodies, 5 s to send them, 10 s per write,
//!   64 connections, a token bucket per client address, embedded assets only.

mod api;
mod auth;
mod configs;
mod console;
mod page;
mod verify;

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
/// Every connection, the console's files included (a page of the console loads a few dozen
/// small files): a looser bucket checked before the request is read.
const CONN_BURST: f64 = 400.0;
/// Connections a client may open per second, sustained.
const CONN_PER_SECOND: f64 = 100.0;
/// Client addresses tracked by the rate limit.
const MAX_CLIENTS: usize = 1024;
/// Browser sessions kept at once.
const MAX_SESSIONS: usize = 64;
/// How long one lasts at most (the cookie's own lifetime).
const SESSION_TTL: Duration = auth::ABSOLUTE;
/// The session cookie.
const COOKIE: &str = "iohr_agent_page";
/// The token file in the state directory.
pub const TOKEN_FILE: &str = "admin.token";
/// The only paths that take a POST.
const CHANGE_PATHS: [&str; 2] = ["/policy/share", "/policy/reload"];
/// The sign-in forms: the machine's token, and signing out.
const AUTH_FORMS: [&str; 2] = ["/auth", "/auth/logout"];
/// The largest JSON body a local API write takes (a managed file and its reason).
const MAX_JSON: usize = configs::MAX_TEXT + 16 * 1024;
/// The largest form accepted.
const MAX_FORM: usize = 512;
/// How long a change waits for the agent to reload.
const RELOAD_WAIT: Duration = Duration::from_secs(20);

/// The form token for a session: tied to it, so another session's form or a guessed one
/// does not pass.
fn csrf_for(session: &str) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(format!("iohr-agent-page-form:{session}").as_bytes());
    d.iter()
        .take(16)
        .fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

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
    /// Asks the running agent to load its policy and checks again; `None` when the agent
    /// runs without a supervisor (tests), and then nothing can be changed here.
    pub reload: Option<tokio::sync::mpsc::Sender<crate::agent::Reload>>,
    /// The key target hashes are made with, for the preview (never shown).
    pub share_key: Vec<u8>,
    /// The policy file `[share]` is written to.
    pub policy_path: std::path::PathBuf,
    /// The account this agent belongs to: the `{org_id}` the local API answers for.
    pub account_id: String,
    /// The checks file the console edits.
    pub checks_path: std::path::PathBuf,
    /// The local audit log (RFC 0100.2), when it could be opened.
    pub audit: Option<Arc<crate::audit::Audit>>,
    /// For the company's identity provider (sign-in) only.
    pub http: Option<reqwest::Client>,
    /// Resolves `[console.oidc] client_secret`.
    pub secrets: Option<crate::secrets::SecretResolver>,
    /// The extensions lock this generation runs with.
    pub lock: crate::extensions::Lock,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("api", &self.api)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("share_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The server's own bookkeeping: sessions, rate limits, connection slots.
#[derive(Debug)]
struct Server {
    ctx: watch::Receiver<Arc<Context>>,
    local: Option<SocketAddr>,
    tls: bool,
    sessions: Mutex<Vec<auth::Session>>,
    pending: Mutex<Vec<auth::Pending>>,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    conn_buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
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

/// Serves one context until `shutdown` turns true.
pub async fn serve(
    listener: TcpListener,
    ctx: Arc<Context>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: watch::Receiver<bool>,
) {
    let (_keep, rx) = watch::channel(ctx);
    serve_watch(listener, rx, tls, shutdown).await;
}

/// Serves until `shutdown` turns true, each request against the newest context: the
/// supervisor swaps it when the agent reloads, and the page, its token and the browser
/// sessions stay.
pub async fn serve_watch(
    listener: TcpListener,
    ctx: watch::Receiver<Arc<Context>>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    let server = Arc::new(Server {
        ctx,
        local: listener.local_addr().ok(),
        tls: tls.is_some(),
        sessions: Mutex::new(Vec::new()),
        pending: Mutex::new(Vec::new()),
        buckets: Mutex::new(HashMap::new()),
        conn_buckets: Mutex::new(HashMap::new()),
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
    content_length: usize,
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
        content_length: 0,
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
    // No request bodies but the one small form that changes `[share]`.
    let len = match req
        .header("content-length")
        .map(|l| l.trim().parse::<usize>())
    {
        None => 0,
        Some(Ok(n)) => n,
        Some(Err(_)) => return Err((400, "bad request")),
    };
    let form_post = req.method == "POST"
        && (CHANGE_PATHS.contains(&req.path.as_str()) || AUTH_FORMS.contains(&req.path.as_str()));
    let json_write = matches!(req.method.as_str(), "POST" | "PUT") && api::is_api(&req.path);
    if req.header("transfer-encoding").is_some() || (len > 0 && !form_post && !json_write) {
        return Err((413, "request bodies are not accepted"));
    }
    if (form_post && len > MAX_FORM) || (json_write && len > MAX_JSON) {
        return Err((413, "the body is too large"));
    }
    req.content_length = len;
    Ok(req)
}

impl Server {
    fn ctx(&self) -> Arc<Context> {
        Arc::clone(&self.ctx.borrow())
    }

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
        out.extend(self.ctx().admin.hosts.iter().cloned());
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

    /// The page's token bucket per client address: every request but the console's files.
    fn rate_ok(&self, ip: IpAddr) -> bool {
        bucket_ok(&self.buckets, ip, BURST, PER_SECOND)
    }

    /// The looser bucket every connection takes from, before its request is read.
    fn conn_rate_ok(&self, ip: IpAddr) -> bool {
        bucket_ok(&self.conn_buckets, ip, CONN_BURST, CONN_PER_SECOND)
    }
}

/// A token bucket per client address in `buckets`: `burst` at most, `per_second` back.
fn bucket_ok(
    buckets: &Mutex<HashMap<IpAddr, (f64, Instant)>>,
    ip: IpAddr,
    burst: f64,
    per_second: f64,
) -> bool {
    {
        let mut b = match buckets.lock() {
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
        let (tokens, last) = b.entry(ip).or_insert((burst, now));
        let refill = now.duration_since(*last).as_secs_f64() * per_second;
        *tokens = (*tokens + refill).min(burst);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

impl Server {
    /// Who is asking: the machine's token as a bearer (the CLI), or a live session's
    /// cookie (a browser), with the session's id. A session's idle time restarts here.
    fn person(&self, req: &Request) -> Option<(Option<String>, auth::Person)> {
        // A local client (`iohr agent status`) may present the token itself. A browser
        // cannot add this header cross-site without a CORS preflight, which is never
        // answered.
        if let (Some(given), Some(token)) = (
            req.header("authorization")
                .and_then(|a| a.strip_prefix("Bearer ")),
            &self.ctx().token,
        ) {
            return constant_time_eq(token.as_bytes(), given.trim().as_bytes())
                .then(|| (None, auth::Person::machine()));
        }
        let id = req.cookie(COOKIE)?;
        let mut s = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.retain(auth::Session::alive);
        // Compare against every session, each in constant time.
        let mut found = None;
        for (i, x) in s.iter().enumerate() {
            if constant_time_eq(x.id.as_bytes(), id.as_bytes()) {
                found = Some(i);
            }
        }
        let i = found?;
        s[i].last = Instant::now();
        Some((Some(s[i].id.clone()), s[i].person.clone()))
    }

    fn session_ok(&self, req: &Request) -> bool {
        self.person(req).is_some()
    }

    /// The form token for the session this request's cookie names.
    fn csrf(&self, req: &Request) -> Option<String> {
        self.person(req)
            .and_then(|(id, _)| id)
            .map(|id| csrf_for(&id))
    }

    fn new_session(&self, person: auth::Person) -> String {
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
        s.retain(auth::Session::alive);
        if s.len() >= MAX_SESSIONS {
            s.remove(0);
        }
        let now = Instant::now();
        s.push(auth::Session {
            id: id.clone(),
            person,
            created: now,
            last: now,
        });
        id
    }

    fn end_session(&self, id: &str) {
        let mut s = match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.retain(|x| !constant_time_eq(x.id.as_bytes(), id.as_bytes()));
    }

    fn audit(&self, p: &auth::Person, action: &str, target: &str, outcome: &str, reason: &str) {
        if let Some(a) = &self.ctx().audit
            && let Err(e) = a.record(crate::audit::Record {
                who: &p.who,
                name: &p.name,
                role: p.role.as_str(),
                action,
                target,
                outcome,
                reason,
            })
        {
            tracing::warn!(error = %e, "the audit log could not be written");
        }
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
    if !srv.conn_rate_ok(peer.ip()) {
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
    // The page's own budget for everything but the console's files, which a page of the
    // console loads by the dozen (they took from the connection's bucket above).
    if !console::is_console(&req.path) && !srv.rate_ok(peer.ip()) {
        return respond(&mut sock, srv, 429, "text/plain", b"slow down\n", &[], head).await;
    }
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
    if req.method == "POST" && CHANGE_PATHS.contains(&req.path.as_str()) {
        let Some(body) = read_body(&mut sock, &buf, req.content_length).await else {
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
        return change(&mut sock, srv, &req, peer, &body).await;
    }
    // The sign-in forms: the machine's token, and signing out.
    if req.method == "POST" && AUTH_FORMS.contains(&req.path.as_str()) {
        let Some(body) = read_body(&mut sock, &buf, req.content_length).await else {
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
        return if req.path == "/auth" {
            auth(&mut sock, srv, &req, Some(&body), false).await
        } else {
            logout(&mut sock, srv, &req).await
        };
    }
    // Writes to the local API: a person with a role, and from a browser the session's
    // CSRF token and this page's own origin.
    if matches!(req.method.as_str(), "POST" | "PUT") && api::is_api(&req.path) {
        let Some((sid, person)) = srv.person(&req) else {
            let (code, body) = api::unauthenticated();
            return respond(
                &mut sock,
                srv,
                code,
                "application/json",
                body.as_bytes(),
                &[],
                false,
            )
            .await;
        };
        if let Some(sid) = &sid {
            let token_ok = req
                .header("x-csrf-token")
                .is_some_and(|t| constant_time_eq(t.as_bytes(), csrf_for(sid).as_bytes()));
            if !token_ok || req.header("origin").is_none() {
                let (code, body) = api::forbidden("this change needs the page's own form token");
                return respond(
                    &mut sock,
                    srv,
                    code,
                    "application/json",
                    body.as_bytes(),
                    &[],
                    false,
                )
                .await;
            }
        }
        let Some(body) = read_body(&mut sock, &buf, req.content_length).await else {
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
        let ctx = srv.ctx();
        let (code, out) = api::write(&ctx, &person, &req.method, &req.path, &body).await;
        if let Some(a) = out.audit {
            srv.audit(&person, &a.action, &a.target, &a.outcome, &a.reason);
        }
        let out = crate::redact::redact(&out.body);
        return respond(
            &mut sock,
            srv,
            code,
            "application/json",
            out.as_bytes(),
            &[],
            false,
        )
        .await;
    }
    if req.method != "GET" && !head && api::is_api(&req.path) {
        let (code, body) = api::read_only();
        return respond(
            &mut sock,
            srv,
            code,
            "application/json",
            body.as_bytes(),
            &[("Allow", "GET, HEAD, POST, PUT")],
            false,
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
        "/auth" => return auth(&mut sock, srv, &req, None, head).await,
        "/auth/options" => {
            let body = auth_options(&srv.ctx());
            return respond(
                &mut sock,
                srv,
                200,
                "application/json",
                body.as_bytes(),
                &[],
                head,
            )
            .await;
        }
        "/auth/oidc/start" => return oidc_start(&mut sock, srv, &req).await,
        "/auth/oidc/callback" => return oidc_callback(&mut sock, srv, &req).await,
        _ => {}
    }
    let ctx = srv.ctx();
    // The local API: always signed in, loopback too (RFC 0100.4 1.6).
    if api::is_api(&req.path) {
        let (code, body) = match srv.person(&req) {
            Some((sid, person)) => {
                let csrf = sid.as_deref().map(csrf_for);
                api::route(&ctx, &req.path, &req.query, &person, csrf.as_deref())
            }
            None => api::unauthenticated(),
        };
        let body = crate::redact::redact(&body);
        return respond(
            &mut sock,
            srv,
            code,
            "application/json",
            body.as_bytes(),
            &[],
            head,
        )
        .await;
    }
    // The console bundle: code, no data (every datum comes through the API above, which
    // always asks who is there), so its pages load for the sign-in page to show. It is an
    // extension like any other (RFC 0073.1): served only when licence, policy and lock
    // all admit `inorbit/console`.
    if console::is_console(&req.path) {
        if !crate::extensions::running("inorbit/console", &ctx.policy, &ctx.lock) {
            return respond(
                &mut sock,
                srv,
                404,
                "text/plain",
                b"the local console (inorbit/console) is not installed on this agent\n",
                &[],
                head,
            )
            .await;
        }
        let found = ctx
            .admin
            .console_dir
            .as_deref()
            .and_then(|dir| console::file(dir, &req.path));
        return match found {
            Some(f) => respond_csp(&mut sock, srv, 200, f.ctype, &f.body, &f.csp, head).await,
            None => respond(&mut sock, srv, 404, "text/plain", b"not found\n", &[], head).await,
        };
    }
    if ctx.admin.token_required() && !srv.session_ok(&req) {
        let body = page::locked(&ctx);
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
    let view = page::View {
        query: req.query.clone(),
        csrf: srv.csrf(&req),
        signed_in: srv.session_ok(&req),
        can_change: srv.local.is_some_and(|l| l.ip().is_loopback())
            && peer.ip().is_loopback()
            && ctx.reload.is_some(),
        flash: None,
    };
    match page::route(&ctx, &req.path, srv.local, &view) {
        Some((ctype, body)) => {
            // Last line of defence: whatever reached the agent's memory, no secret
            // leaves through this page.
            let body = crate::redact::redact(&body);
            respond(&mut sock, srv, 200, ctype, body.as_bytes(), &[], head).await
        }
        None => respond(&mut sock, srv, 404, "text/plain", b"not found\n", &[], head).await,
    }
}

/// Where a sign-in goes back to: a console page that asked, never anywhere else.
fn next_of(n: Option<String>) -> String {
    n.filter(|n| console::is_console(n) && !n.contains("//") && !n.contains('\\'))
        .unwrap_or_else(|| "/".to_owned())
}

/// The session cookie for `id`, or one that clears it.
fn session_cookie(srv: &Server, id: &str, max_age: u64) -> String {
    format!(
        "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if srv.tls { "; Secure" } else { "" }
    )
}

/// `/auth?token=…` (a link from `iohr agent page --open`) or `POST /auth` with the token in
/// a form: the token from `<state_dir>/admin.token` becomes a session for the machine's
/// owner (`HttpOnly`, SameSite=Strict, Secure over TLS), then back to the page.
async fn auth<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
    form: Option<&[u8]>,
    head: bool,
) -> std::io::Result<()> {
    let fields: HashMap<String, String> = form
        .map(|b| url::form_urlencoded::parse(b).into_owned().collect())
        .unwrap_or_default();
    let field = |k: &str| fields.get(k).cloned().or_else(|| req.query_param(k));
    let given = field("token").unwrap_or_default();
    let ctx = srv.ctx();
    let machine_ok = ctx
        .policy
        .console()
        .users
        .contains(&crate::policy::SignInMode::Machine);
    let ok = machine_ok
        && ctx
            .token
            .as_ref()
            .is_some_and(|t| constant_time_eq(t.as_bytes(), given.trim().as_bytes()));
    if !ok {
        if form.is_some() {
            return respond(
                sock,
                srv,
                303,
                "text/plain",
                b"not signed in\n",
                &[("Location", "/console/signin/?error=token")],
                head,
            )
            .await;
        }
        let body = page::locked(&ctx);
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
    let person = auth::Person::machine();
    srv.audit(&person, "sign_in", "machine token", "ok", "");
    let id = srv.new_session(person);
    let next = next_of(field("next"));
    let cookie = session_cookie(srv, &id, SESSION_TTL.as_secs());
    respond(
        sock,
        srv,
        303,
        "text/plain",
        b"signed in\n",
        &[("Location", &next), ("Set-Cookie", &cookie)],
        head,
    )
    .await
}

/// `POST /auth/logout`: ends this browser's session.
async fn logout<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
) -> std::io::Result<()> {
    if let Some((Some(id), p)) = srv.person(req) {
        srv.audit(&p, "sign_out", p.mode, "ok", "");
        srv.end_session(&id);
    }
    let cookie = session_cookie(srv, "", 0);
    respond(
        sock,
        srv,
        303,
        "text/plain",
        b"signed out\n",
        &[("Location", "/console/signin/"), ("Set-Cookie", &cookie)],
        false,
    )
    .await
}

/// `GET /auth/options`: the ways in this machine's policy allows, for the sign-in page.
fn auth_options(ctx: &Context) -> String {
    let c = ctx.policy.console();
    serde_json::json!({
        "modes": c.users,
        "oidc": c.oidc.as_ref().map(|o| serde_json::json!({
            "name": o.name.clone().unwrap_or_else(|| o.issuer.host_str().unwrap_or("your identity provider").to_owned()),
        })),
    })
    .to_string()
}

/// The redirect URI this request's host gives (the host was already checked).
fn redirect_uri(srv: &Server, req: &Request) -> String {
    format!(
        "{}://{}/auth/oidc/callback",
        if srv.tls { "https" } else { "http" },
        req.header("host").unwrap_or("127.0.0.1")
    )
}

/// `GET /auth/oidc/start`: off to the company's identity provider, with PKCE.
async fn oidc_start<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
) -> std::io::Result<()> {
    let ctx = srv.ctx();
    let c = ctx.policy.console();
    let (Some(o), Some(http)) = (c.oidc.as_ref(), ctx.http.as_ref()) else {
        return oidc_fail(sock, srv, "not_configured").await;
    };
    if !c.users.contains(&crate::policy::SignInMode::Oidc) {
        return oidc_fail(sock, srv, "not_configured").await;
    }
    let d = match auth::discover(http, o).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "sign-in: the identity provider's discovery failed");
            return oidc_fail(sock, srv, "unreachable").await;
        }
    };
    let pending = auth::Pending {
        state: auth::random(),
        verifier: auth::random(),
        nonce: auth::random(),
        next: next_of(req.query_param("next")),
        created: Instant::now(),
    };
    let url = auth::authorize_url(&d, o, &redirect_uri(srv, req), &pending);
    {
        let mut p = match srv.pending.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        p.retain(auth::Pending::alive);
        if p.len() >= auth::MAX_PENDING {
            p.remove(0);
        }
        p.push(pending);
    }
    respond(
        sock,
        srv,
        303,
        "text/plain",
        b"to the identity provider\n",
        &[("Location", url.as_str())],
        false,
    )
    .await
}

/// `GET /auth/oidc/callback?code=…&state=…`: the code for a person, a role and a session.
async fn oidc_callback<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
) -> std::io::Result<()> {
    let ctx = srv.ctx();
    let c = ctx.policy.console();
    let (Some(o), Some(http), Some(secrets)) =
        (c.oidc.as_ref(), ctx.http.as_ref(), ctx.secrets.as_ref())
    else {
        return oidc_fail(sock, srv, "not_configured").await;
    };
    let state = req.query_param("state").unwrap_or_default();
    let pending = {
        let mut p = match srv.pending.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        p.retain(auth::Pending::alive);
        let i = p
            .iter()
            .position(|x| constant_time_eq(x.state.as_bytes(), state.as_bytes()));
        i.map(|i| p.remove(i))
    };
    let Some(pending) = pending else {
        return oidc_fail(sock, srv, "expired").await;
    };
    let Some(code) = req.query_param("code") else {
        return oidc_fail(sock, srv, "refused").await;
    };
    let secret = match o.client_secret.parse::<crate::secrets::SecretRef>() {
        Ok(r) => secrets.resolve(&r).await,
        Err(e) => Err(e),
    };
    let Ok(secret) = secret else {
        tracing::warn!("sign-in: [console.oidc] client_secret could not be read");
        return oidc_fail(sock, srv, "not_configured").await;
    };
    let person = match auth::discover(http, o).await {
        Ok(d) => {
            auth::finish(
                http,
                &d,
                o,
                &secret,
                &redirect_uri(srv, req),
                &pending,
                &code,
            )
            .await
        }
        Err(e) => Err(e),
    };
    match person {
        Ok(p) => {
            srv.audit(&p, "sign_in", "oidc", "ok", "");
            let id = srv.new_session(p);
            let cookie = session_cookie(srv, &id, auth::ABSOLUTE.as_secs());
            respond(
                sock,
                srv,
                303,
                "text/plain",
                b"signed in\n",
                &[("Location", &pending.next), ("Set-Cookie", &cookie)],
                false,
            )
            .await
        }
        Err(e) => {
            tracing::info!(reason = %e, "sign-in refused");
            let why = if e.contains("no role") {
                "no_role"
            } else {
                "refused"
            };
            oidc_fail(sock, srv, why).await
        }
    }
}

async fn oidc_fail<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    why: &str,
) -> std::io::Result<()> {
    let to = format!("/console/signin/?error={why}");
    respond(
        sock,
        srv,
        303,
        "text/plain",
        b"not signed in\n",
        &[("Location", &to)],
        false,
    )
    .await
}

/// `/ledger.jsonl`: the ledger files as they are, oldest first, streamed.
async fn export<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    head: bool,
) -> std::io::Result<()> {
    let ctx = srv.ctx();
    let Some(ledger) = &ctx.ledger else {
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
        page::csp(),
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

/// The body after the head: what `read_head` already holds, and the rest within the
/// read timeout.
async fn read_body<S: AsyncRead + Unpin>(sock: &mut S, buf: &[u8], len: usize) -> Option<Vec<u8>> {
    let start = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let mut body: Vec<u8> = buf.get(start..).unwrap_or_default().to_vec();
    if body.len() > len {
        return None;
    }
    let rest = tokio::time::timeout(READ_TIMEOUT, async {
        while body.len() < len {
            let mut chunk = vec![0u8; len - body.len()];
            let n = sock.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            body.extend_from_slice(chunk.get(..n).unwrap_or_default());
        }
        Some(())
    })
    .await;
    matches!(rest, Ok(Some(()))).then_some(body)
}

/// Why a change is refused, before anything is written; `None` when it may go ahead.
fn change_refused(
    srv: &Server,
    ctx: &Context,
    req: &Request,
    peer: SocketAddr,
    body: &[u8],
) -> Option<(u16, String)> {
    // Only on this machine: both ends on loopback.
    if !srv.local.is_some_and(|l| l.ip().is_loopback()) || !peer.ip().is_loopback() {
        return Some((
            403,
            "the policy changes only from the agent's own machine".into(),
        ));
    }
    if !srv.session_ok(req) {
        return Some((
            401,
            "sign in first: `iohr agent page --open` on this machine".into(),
        ));
    }
    if req.header("authorization").is_none() {
        // A browser: this page's own origin, and the form's token for this session.
        if !req.header("origin").is_some_and(|o| srv.origin_allowed(o)) {
            return Some((403, "the form must come from this page".into()));
        }
        let given = url::form_urlencoded::parse(body)
            .find(|(k, _)| k == "csrf")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        if !srv
            .csrf(req)
            .is_some_and(|c| constant_time_eq(c.as_bytes(), given.as_bytes()))
        {
            return Some((403, "the form has expired; open the page again".into()));
        }
    }
    if ctx.reload.is_none() {
        return Some((
            503,
            "this agent cannot reload; restart it after editing policy.toml".into(),
        ));
    }
    None
}

/// `POST /policy/share` and `POST /policy/reload`: the page's one change. Every rule is
/// checked before anything is written; the policy file is changed in place
/// ([`crate::share::write_policy`]), then the agent reloads, and the change is on the
/// ledger when the new policy starts.
async fn change<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    req: &Request,
    peer: SocketAddr,
    body: &[u8],
) -> std::io::Result<()> {
    let ctx = srv.ctx();
    let json = req.header("authorization").is_some();
    let answer = |code: u16, msg: String, ok: bool| -> (u16, &'static str, String) {
        if json {
            let v = serde_json::json!({ "ok": ok, "message": msg });
            (
                code,
                "application/json",
                crate::redact::redact(&v.to_string()),
            )
        } else {
            let view = page::View {
                flash: Some((ok, msg)),
                signed_in: srv.session_ok(req),
                can_change: true,
                csrf: srv.csrf(req),
                query: String::new(),
            };
            let html = page::route(&ctx, "/policy", srv.local, &view)
                .map(|(_, b)| b)
                .unwrap_or_default();
            (
                code,
                "text/html; charset=utf-8",
                crate::redact::redact(&html),
            )
        }
    };
    let outcome: std::result::Result<String, (u16, String)> = async {
        if let Some(r) = change_refused(srv, &ctx, req, peer, body) {
            return Err(r);
        }
        if req.path == "/policy/share" {
            let form: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(body).into_owned().collect();
            let targets = match form.get("targets").map(String::as_str) {
                Some("full") => crate::policy::TargetShare::Full,
                Some("hash") => crate::policy::TargetShare::Hash,
                Some("label") => crate::policy::TargetShare::Label,
                _ => return Err((400, "targets: full, hash or label".into())),
            };
            let hostname = matches!(
                form.get("hostname").map(String::as_str),
                Some("on" | "true" | "1")
            );
            // The host summary is set in the policy file; the form keeps it.
            let share = crate::policy::SharePolicy {
                targets,
                hostname,
                host: ctx.policy.share().host,
            };
            crate::share::write_policy(&ctx.policy_path, &share).map_err(|e| {
                (
                    409,
                    format!(
                        "{e}. If the agent's user cannot write it, run on this machine: sudo iohr agent share {} --hostname {}",
                        targets.as_str(),
                        if hostname { "on" } else { "off" }
                    ),
                )
            })?;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sent = match &ctx.reload {
            Some(r) => r.send(crate::agent::Reload { reply: tx }).await.is_ok(),
            None => false,
        };
        if !sent {
            return Err((409, "saved, but not applied: the agent is not running its supervisor".into()));
        }
        tokio::time::timeout(RELOAD_WAIT, rx)
            .await
            .map_err(|_| (409, "saved, but not applied: the agent did not answer in time".to_owned()))?
            .map_err(|_| (409, "saved, but not applied: the agent stopped".to_owned()))?
            .map_err(|e| (409, format!("saved, but not applied: {e}")))
    }
    .await;
    match outcome {
        Ok(_) if !json => {
            respond(
                sock,
                srv,
                303,
                "text/plain",
                b"applied\n",
                &[("Location", "/policy?applied=1")],
                false,
            )
            .await
        }
        Ok(msg) => {
            let (code, ctype, out) = answer(200, msg, true);
            respond(sock, srv, code, ctype, out.as_bytes(), &[], false).await
        }
        Err((code, msg)) => {
            let (code, ctype, out) = answer(code, msg, false);
            respond(sock, srv, code, ctype, out.as_bytes(), &[], false).await
        }
    }
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
        500 => "Internal Server Error",
        _ => "Error",
    }
}

/// The response head: the same security headers on every answer, and never a CORS one.
fn headers(
    srv: &Server,
    status: u16,
    ctype: &str,
    len: u64,
    extra: &[(&str, &str)],
    csp: &str,
) -> String {
    let mut h = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\n\
Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
Referrer-Policy: same-origin\r\nContent-Security-Policy: {}\r\n\
Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()\r\n",
        reason(status),
        csp
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
    let header = headers(srv, status, ctype, body.len() as u64, extra, page::csp());
    write_timed(sock, header.as_bytes()).await?;
    if !head {
        write_timed(sock, body).await?;
    }
    sock.shutdown().await
}

/// [`respond`] with a CSP of its own (the console bundle's).
async fn respond_csp<S: AsyncWrite + Unpin>(
    sock: &mut S,
    srv: &Server,
    status: u16,
    ctype: &str,
    body: &[u8],
    csp: &str,
    head: bool,
) -> std::io::Result<()> {
    let header = headers(srv, status, ctype, body.len() as u64, &[], csp);
    write_timed(sock, header.as_bytes()).await?;
    if !head {
        write_timed(sock, body).await?;
    }
    sock.shutdown().await
}

#[cfg(test)]
mod tests;
