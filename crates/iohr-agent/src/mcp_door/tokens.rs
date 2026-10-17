//! The one holder of the OAuth token chain for the platform's MCP, and the one that
//! refreshes it. Hydra rotates refresh tokens and gives a reuse grace of 30 seconds, so many
//! sessions each refreshing their own copy of one credential were treated as theft and the
//! whole chain was revoked. Here one lock serializes every refresh, and the chain lives in
//! the keychain, never in a file or a log.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use zeroize::Zeroize as _;

use super::store::Store;
use super::{DoorConfig, Notifier};

/// Refresh when this little is left on the access token.
const REFRESH_BELOW_S: f64 = 120.0;

/// Seconds since the epoch.
#[must_use]
pub fn now_s() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// A random URL-safe string of `n` bytes of entropy.
#[must_use]
pub fn random_urlsafe(n: usize) -> String {
    let mut buf = vec![0_u8; n];
    // No randomness means no safe verifier, state or local secret: stop rather than use zeros.
    if getrandom::fill(&mut buf).is_err() {
        tracing::error!("the operating system has no randomness; stopping");
        std::process::abort();
    }
    let s = URL_SAFE_NO_PAD.encode(&buf);
    buf.zeroize();
    s
}

/// The chain as stored.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TokenSet {
    /// The bearer sent upstream.
    #[serde(default)]
    pub access_token: String,
    /// The rotating refresh token.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Epoch seconds the access token ends.
    #[serde(default)]
    pub expires_at: f64,
    /// Granted scope.
    #[serde(default)]
    pub scope: String,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for TokenSet {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(r) = self.refresh_token.as_mut() {
            r.zeroize();
        }
    }
}

/// Signed in or not, and why not.
#[derive(Debug, Clone, Default)]
pub struct AuthState {
    /// Signed in.
    pub ok: bool,
    /// Why not, when not.
    pub why: String,
}

#[derive(Debug)]
struct Login {
    state: String,
    started: Instant,
    url: String,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

enum TokenErr {
    Status(u16, String),
    Other(String),
}

/// The holder.
pub struct Tokens {
    cfg: Arc<DoorConfig>,
    store: Arc<Store>,
    http: reqwest::Client,
    notifier: Arc<Notifier>,
    tok: Mutex<TokenSet>,
    state: Mutex<AuthState>,
    refresh_lock: tokio::sync::Mutex<()>,
    login: Mutex<Option<Login>>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Tokens {
    /// Loads the chain from the store.
    pub async fn load(
        cfg: Arc<DoorConfig>,
        store: Arc<Store>,
        http: reqwest::Client,
        notifier: Arc<Notifier>,
    ) -> Self {
        let tok = match store.get(&cfg.token_item).await {
            Ok(Some(raw)) => serde_json::from_str::<TokenSet>(&raw).unwrap_or_default(),
            Ok(None) => TokenSet::default(),
            Err(e) => {
                tracing::error!("token: {e}");
                TokenSet::default()
            }
        };
        let has = tok.refresh_token.as_deref().is_some_and(|r| !r.is_empty());
        let state = AuthState {
            ok: has,
            why: if has {
                String::new()
            } else {
                "not signed in yet: iohr-agent mcp login".into()
            },
        };
        Self {
            cfg,
            store,
            http,
            notifier,
            tok: Mutex::new(tok),
            state: Mutex::new(state),
            refresh_lock: tokio::sync::Mutex::new(()),
            login: Mutex::new(None),
        }
    }

    /// Test and status access: replaces the chain in memory.
    pub fn set_for_test(&self, access: &str, refresh: &str, expires_at: f64) {
        *lock(&self.tok) = TokenSet {
            access_token: access.into(),
            refresh_token: Some(refresh.into()),
            expires_at,
            scope: String::new(),
        };
        *lock(&self.state) = AuthState {
            ok: true,
            why: String::new(),
        };
    }

    /// The signed-in state.
    pub fn auth(&self) -> AuthState {
        lock(&self.state).clone()
    }

    /// Seconds left on the access token, and whether a refresh token is held.
    pub fn left(&self) -> (i64, bool) {
        let t = lock(&self.tok);
        #[allow(clippy::cast_possible_truncation)]
        let left = (t.expires_at - now_s()) as i64;
        (
            left.max(0),
            t.refresh_token.as_deref().is_some_and(|r| !r.is_empty()),
        )
    }

    /// Whether a sign-in is waiting for the browser.
    pub fn login_pending(&self) -> bool {
        lock(&self.login).is_some()
    }

    fn set_state(&self, ok: bool, why: &str) {
        *lock(&self.state) = AuthState {
            ok,
            why: why.into(),
        };
    }

    async fn persist(&self, t: &TokenSet) {
        let json = match serde_json::to_string(t) {
            Ok(j) => zeroize::Zeroizing::new(j),
            Err(_) => return,
        };
        if let Err(e) = self.store.set(&self.cfg.token_item, &json).await {
            tracing::error!("token: {e} (kept in memory)");
        }
    }

    async fn store_reply(&self, r: TokenReply) {
        let t = {
            let old = lock(&self.tok).refresh_token.clone();
            #[allow(clippy::cast_precision_loss)]
            let exp = now_s() + r.expires_in.unwrap_or(3600) as f64;
            TokenSet {
                access_token: r.access_token.clone(),
                refresh_token: r.refresh_token.clone().or(old),
                expires_at: exp,
                scope: r.scope.clone().unwrap_or_default(),
            }
        };
        *lock(&self.tok) = t.clone();
        self.persist(&t).await;
        self.set_state(true, "");
    }

    async fn post_token(&self, form: &[(&str, &str)]) -> Result<TokenReply, TokenErr> {
        let resp = self
            .http
            .post(self.cfg.token_url())
            .header("Accept", "application/json")
            .form(form)
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(|e| TokenErr::Other(error_class(&e)))?;
        let code = resp.status().as_u16();
        if !(200..300).contains(&code) {
            let body = resp.text().await.unwrap_or_default();
            return Err(TokenErr::Status(code, body.chars().take(300).collect()));
        }
        resp.json::<TokenReply>()
            .await
            .map_err(|e| TokenErr::Other(error_class(&e)))
    }

    /// Refreshes when the access token is near its end (or was refused). One caller at a
    /// time; a caller that waited on the lock and finds a newer token than the one refused
    /// (`seen`) uses it instead. Returns whether a usable token is held afterwards.
    pub async fn refresh(&self, force: bool, seen: Option<&str>) -> bool {
        let _guard = self.refresh_lock.lock().await;
        let t = lock(&self.tok).clone();
        let Some(rt) = t.refresh_token.clone().filter(|r| !r.is_empty()) else {
            self.set_state(false, "not signed in: iohr-agent mcp login");
            return false;
        };
        if seen.is_some_and(|s| t.access_token != s) {
            return true;
        }
        if !force && t.expires_at - now_s() > REFRESH_BELOW_S {
            return true;
        }
        let still_valid = !t.access_token.is_empty() && t.expires_at > now_s();
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
        ];
        match self.post_token(&form).await {
            Ok(r) => {
                self.store_reply(r).await;
                tracing::info!("token: refreshed");
                true
            }
            Err(TokenErr::Status(code, body))
                if (code == 400 || code == 401)
                    && ["invalid_grant", "invalid_client", "revoked"]
                        .iter()
                        .any(|k| body.contains(k)) =>
            {
                *lock(&self.tok) = TokenSet::default();
                if let Err(e) = self.store.set(&self.cfg.token_item, "{}").await {
                    tracing::error!("token: {e}");
                }
                self.set_state(false, "the sign-in was revoked; iohr-agent mcp login");
                tracing::error!("token: refresh refused ({code})");
                self.notifier
                    .send(
                        "InOrbit MCP needs a sign-in",
                        "The door's sign-in was revoked. A browser tab opens on the next call.",
                    )
                    .await;
                false
            }
            Err(TokenErr::Status(code, _)) => {
                tracing::warn!("token: refresh failed {code}, will retry");
                still_valid
            }
            Err(TokenErr::Other(class)) => {
                tracing::warn!("token: refresh unreachable ({class}), will retry");
                still_valid
            }
        }
    }

    /// The bearer to send, refreshed first when it is about to end.
    pub async fn access(&self) -> Option<zeroize::Zeroizing<String>> {
        if lock(&self.tok).expires_at - now_s() < REFRESH_BELOW_S {
            self.refresh(false, None).await;
        }
        let t = lock(&self.tok);
        if t.access_token.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(t.access_token.clone()))
        }
    }

    /// Refreshes ahead of the end so no call waits on the token endpoint; call every minute.
    pub async fn keep_fresh_tick(&self) {
        let due = {
            let t = lock(&self.tok);
            t.refresh_token.as_deref().is_some_and(|r| !r.is_empty())
                && t.expires_at - now_s() < 600.0
        };
        if due {
            self.refresh(true, None).await;
        }
    }

    /// The scope to ask for, read from the server now (see [`super::scopes`]).
    async fn scope(&self) -> String {
        let resource = match self.cfg.resource_meta_url() {
            Some(u) => super::scopes::scopes_supported(&self.http, &u).await,
            None => None,
        };
        let grantable =
            super::scopes::scopes_supported(&self.http, &self.cfg.auth_meta_url()).await;
        let (scope, source) = super::scopes::wanted_scopes(resource, grantable);
        tracing::info!(source, "login: scope chosen");
        scope
    }

    /// Starts a PKCE sign-in with the registered loopback redirect and returns its URL;
    /// at most one is pending per `login_every`, and it opens the browser once.
    pub async fn start_login(self: &Arc<Self>) -> String {
        if let Some(l) = lock(&self.login).as_ref()
            && l.started.elapsed() < self.cfg.login_every
        {
            return l.url.clone();
        }
        let scope = self.scope().await;
        let (url, verifier, state) = {
            let mut slot = lock(&self.login);
            if let Some(l) = slot.as_ref()
                && l.started.elapsed() < self.cfg.login_every
            {
                return l.url.clone();
            }
            let verifier = random_urlsafe(64);
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            let state = random_urlsafe(24);
            let Ok(mut url) = url::Url::parse(&format!("{}/oauth2/auth", self.cfg.issuer)) else {
                tracing::warn!("login: the issuer is not a URL");
                return String::new();
            };
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", &self.cfg.redirect())
                .append_pair("scope", &scope)
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("resource", &self.cfg.upstream);
            let url = url.to_string();
            *slot = Some(Login {
                state: state.clone(),
                started: Instant::now(),
                url: url.clone(),
            });
            (url, verifier, state)
        };
        let me = Arc::clone(self);
        tokio::spawn(async move { me.callback_server(verifier, state).await });
        if self.cfg.open_browser {
            open_in_browser(&url);
        }
        tracing::info!("login: started");
        url
    }

    async fn callback_server(self: Arc<Self>, verifier: String, state: String) {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.cfg.redirect_port));
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("login: callback port {} busy ({e})", self.cfg.redirect_port);
                return;
            }
        };
        let end = Instant::now() + self.cfg.login_every;
        while Instant::now() < end {
            let Ok(Ok((mut sock, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                continue;
            };
            let done = tokio::time::timeout(
                Duration::from_secs(20),
                self.one_callback(&mut sock, &verifier, &state),
            )
            .await
            .unwrap_or(false);
            if done {
                break;
            }
        }
        let mut slot = lock(&self.login);
        if slot.as_ref().is_some_and(|l| l.state == state) {
            *slot = None;
        }
    }

    /// Answers one request on the redirect port; true when the sign-in is over.
    async fn one_callback(
        &self,
        sock: &mut tokio::net::TcpStream,
        verifier: &str,
        state: &str,
    ) -> bool {
        let mut buf = vec![0_u8; 8192];
        let mut n = 0;
        while n < buf.len() {
            match sock.read(&mut buf[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    n += k;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        let target = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/");
        let q: std::collections::HashMap<String, String> =
            url::Url::parse(&format!("http://localhost{target}"))
                .map(|u| u.query_pairs().into_owned().collect())
                .unwrap_or_default();
        let (mut ok, mut msg) = (false, "Sign-in failed.");
        let errored = q.contains_key("error");
        if q.get("state").is_some_and(|s| s == state)
            && let Some(code) = q.get("code")
        {
            let redirect = self.cfg.redirect();
            let form = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect.as_str()),
                ("client_id", self.cfg.client_id.as_str()),
                ("code_verifier", verifier),
            ];
            if let Ok(r) = self.post_token(&form).await {
                self.store_reply(r).await;
                *lock(&self.login) = None;
                ok = true;
                msg = "InOrbit MCP is signed in. You can close this tab.";
                tracing::info!("login: signed in");
                self.notifier
                    .send(
                        "InOrbit MCP signed in",
                        "The door is signed in for every session.",
                    )
                    .await;
            } else {
                tracing::error!("login: code exchange failed");
            }
        } else if errored {
            msg = "Sign-in was not completed.";
        }
        let body =
            format!("<!doctype html><meta charset=utf-8><title>InOrbit MCP</title><p>{msg}</p>");
        let resp = format!(
            "HTTP/1.1 {} X\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
            if ok { 200 } else { 400 },
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
        ok || errored
    }
}

/// A reqwest error as a class: no URL, no body.
#[must_use]
pub fn error_class(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_decode() {
        "decode"
    } else if e.is_body() {
        "body"
    } else if e.is_request() {
        "request"
    } else {
        "error"
    };
    kind.into()
}

fn open_in_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
