//! What the door does with one MCP message: forward it with the sign-in, retry only what is
//! safe to retry, and answer from a cache when the platform cannot be reached.
//!
//! A tool call is sent at most once once it has left the machine. If its reply is lost the
//! caller is told so and decides; resending could run the tool twice.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::tokens::{Tokens, error_class, now_s};
use super::{DoorConfig, write_state};

/// Edge says the origin is down: always worth another try, even for a call.
const EDGE_DOWN: [u16; 4] = [521, 522, 523, 530];
/// Worth another try for a call that is safe to repeat.
const TRANSIENT: [u16; 7] = [429, 500, 502, 503, 504, 520, 524];
/// How long a `server/discover` answer is replayed.
const DISCOVER_TTL_S: f64 = 3600.0;
/// Least time between background `initialize` refreshes.
const INIT_REFRESH: Duration = Duration::from_secs(600);
const FALLBACK_PROTOCOL: &str = "2025-06-18";

/// An answer for the local caller.
#[derive(Debug, Clone)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Content type.
    pub ctype: String,
    /// Body.
    pub body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            ctype: "application/json".into(),
            body: serde_json::to_vec(v).unwrap_or_default(),
        }
    }

    fn accepted() -> Self {
        Self {
            status: 202,
            ctype: "application/json".into(),
            body: Vec::new(),
        }
    }
}

struct Raw {
    code: u16,
    ctype: String,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Upstream {
    state: &'static str,
    why: String,
    at: f64,
}

#[derive(Debug, Clone)]
struct Discover {
    code: u16,
    ctype: String,
    data: String,
    at: f64,
}

/// The door's logic.
pub struct Bridge {
    cfg: Arc<DoorConfig>,
    http: reqwest::Client,
    tokens: Arc<Tokens>,
    cache: Mutex<HashMap<String, Value>>,
    discover: Mutex<Option<Discover>>,
    upstream: Mutex<Upstream>,
    init_at: Mutex<Option<Instant>>,
    cache_path: PathBuf,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge").finish_non_exhaustive()
    }
}

/// Marks an error whose request was sent but whose reply never arrived.
const REPLY_LOST: &str = " (reply lost)";

fn lost_reply_note(why: &str) -> String {
    format!(
        "The InOrbit API did not answer in time ({why}). The call was sent and may have run: check the result before trying again."
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn rpc_error(id: &Value, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": msg}})
}

fn tool_error(id: &Value, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": msg}], "isError": true}})
}

impl Bridge {
    /// A door over `tokens`, reading its cache file when there is one.
    #[must_use]
    pub fn new(cfg: Arc<DoorConfig>, http: reqwest::Client, tokens: Arc<Tokens>) -> Self {
        let cache_path = cfg.cache_path();
        let mut cache = HashMap::new();
        let mut discover = None;
        if let Some(Value::Object(m)) = std::fs::read(&cache_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            for k in ["initialize", "tools"] {
                if let Some(v) = m.get(k) {
                    cache.insert(k.to_owned(), v.clone());
                }
            }
            discover = m.get("discover").and_then(|d| {
                Some(Discover {
                    code: u16::try_from(d["code"].as_u64()?).ok()?,
                    ctype: d["ctype"].as_str()?.to_owned(),
                    data: d["data"].as_str()?.to_owned(),
                    at: d["at"].as_f64()?,
                })
            });
        }
        Self {
            cfg,
            http,
            tokens,
            cache: Mutex::new(cache),
            discover: Mutex::new(discover),
            upstream: Mutex::new(Upstream {
                state: "unknown",
                why: String::new(),
                at: 0.0,
            }),
            init_at: Mutex::new(None),
            cache_path,
        }
    }

    /// The token holder.
    #[must_use]
    pub fn tokens(&self) -> &Arc<Tokens> {
        &self.tokens
    }

    /// Test hook: forget the cached answers and hold back the background refresh.
    pub fn reset_for_test(&self) {
        lock(&self.cache).clear();
        *lock(&self.discover) = None;
        *lock(&self.init_at) = Some(Instant::now());
    }

    /// The `/status` document: no token, no content.
    #[must_use]
    pub fn status(&self) -> Value {
        let auth = self.tokens.auth();
        let (left, refresh) = self.tokens.left();
        let up = lock(&self.upstream).clone();
        let tools = lock(&self.cache)
            .get("tools")
            .and_then(|t| t["tools"].as_array().map(Vec::len))
            .unwrap_or(0);
        json!({
            "auth": if auth.ok { "ok" } else { "unauthenticated" },
            "auth_why": auth.why,
            "token_left_s": left,
            "refresh": refresh,
            "upstream": {"state": up.state, "why": up.why, "at": up.at},
            "cached_tools": tools,
            "login_pending": self.tokens.login_pending(),
        })
    }

    /// Starts a sign-in, returning its address.
    #[must_use]
    pub async fn login(&self) -> String {
        self.tokens.start_login().await
    }

    fn save_cache(&self) {
        let mut doc = serde_json::Map::new();
        for (k, v) in lock(&self.cache).iter() {
            doc.insert(k.clone(), v.clone());
        }
        if let Some(d) = lock(&self.discover).as_ref() {
            doc.insert(
                "discover".into(),
                json!({"code": d.code, "ctype": d.ctype, "data": d.data, "at": d.at}),
            );
        }
        if let Ok(b) = serde_json::to_vec(&Value::Object(doc))
            && let Err(e) = write_state(&self.cache_path, &b)
        {
            tracing::warn!("cache: not saved ({})", e.kind());
        }
    }

    fn set_upstream(&self, state: &'static str, why: &str) {
        *lock(&self.upstream) = Upstream {
            state,
            why: why.into(),
            at: now_s(),
        };
    }

    /// One attempt at a time through the backoff list. `Ok` is an answer the caller should
    /// look at; `Err` is why the platform could not be reached.
    async fn forward(
        &self,
        body: &[u8],
        token: &str,
        pv: Option<&str>,
        timeout: Duration,
        may_resend: bool,
    ) -> Result<Raw, String> {
        let mut last = String::new();
        for attempt in 0..=self.cfg.backoff.len() {
            if attempt > 0 {
                tokio::time::sleep(self.cfg.backoff[attempt - 1]).await;
            }
            let mut req = self
                .http
                .post(&self.cfg.upstream)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .bearer_auth(token)
                .timeout(timeout)
                .body(body.to_vec());
            if let Some(pv) = pv {
                req = req.header("MCP-Protocol-Version", pv);
            }
            match req.send().await {
                Ok(resp) => {
                    let code = resp.status().as_u16();
                    let ctype = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/json")
                        .to_owned();
                    let data = match resp.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            // Sent, and the reply was lost on the way back.
                            last = error_class(&e);
                            if may_resend {
                                continue;
                            }
                            return Err(format!("{last}{REPLY_LOST}"));
                        }
                    };
                    let transient = TRANSIENT.contains(&code) || EDGE_DOWN.contains(&code);
                    if transient && (may_resend || EDGE_DOWN.contains(&code)) {
                        last = format!("HTTP {code}");
                        continue;
                    }
                    self.set_upstream("ok", "");
                    return Ok(Raw { code, ctype, data });
                }
                Err(e) => {
                    last = error_class(&e);
                    // Never connected: nothing was sent, so trying again cannot repeat it.
                    if e.is_connect() || may_resend {
                        continue;
                    }
                    return Err(last);
                }
            }
        }
        self.set_upstream("unreachable", &last);
        Err(last)
    }

    fn cached_initialize(&self, id: &Value, pv: &str) -> Option<Value> {
        let mut r = lock(&self.cache).get("initialize")?.clone();
        r["protocolVersion"] = json!(pv);
        Some(json!({"jsonrpc": "2.0", "id": id, "result": r}))
    }

    /// `initialize` and `tools/list` still answer when the platform cannot.
    fn offline_answer(&self, method: &str, id: &Value, pv: &str) -> Option<Value> {
        match method {
            "initialize" => Some(self.cached_initialize(id, pv).unwrap_or_else(|| {
                json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": pv,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "inorbit (bridge, offline)", "version": "0"}
                }})
            })),
            "tools/list" => {
                let r = lock(&self.cache)
                    .get("tools")
                    .cloned()
                    .unwrap_or_else(|| json!({"tools": []}));
                Some(json!({"jsonrpc": "2.0", "id": id, "result": r}))
            }
            _ => None,
        }
    }

    fn remember(&self, method: &str, v: &Value) {
        let key = match method {
            "initialize" => "initialize",
            "tools/list" => "tools",
            _ => return,
        };
        if let Some(r) = v.get("result") {
            lock(&self.cache).insert(key.into(), r.clone());
            self.save_cache();
        }
    }

    fn not_signed_in(&self, method: &str, id: &Value, pv: &str, url: &str) -> Reply {
        if let Some(v) = self.offline_answer(method, id, pv) {
            return Reply::json(200, &v);
        }
        let short: String = url.chars().take(60).collect();
        let note = format!(
            "The InOrbit MCP door is not signed in. A sign-in tab was opened in the browser; if it did not open, run: iohr-agent mcp login ({short}...)"
        );
        if method == "tools/call" {
            Reply::json(200, &tool_error(id, &note))
        } else {
            Reply::json(200, &rpc_error(id, &note))
        }
    }

    /// Handles one POST /mcp body.
    pub async fn handle(self: &Arc<Self>, body: &[u8], pv: Option<&str>) -> Reply {
        let Ok(msg) = serde_json::from_slice::<Value>(body) else {
            return Reply::json(
                400,
                &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}),
            );
        };
        if msg.is_array() {
            return self.handle_batch(&msg, body, pv).await;
        }
        let started = Instant::now();
        let method = msg["method"].as_str().unwrap_or("").to_owned();
        let name = msg["params"]["name"].as_str().unwrap_or("").to_owned();
        let reply = self.handle_one(&msg, &method, body, pv).await;
        tracing::info!(
            method = %method,
            tool = %name,
            status = reply.status,
            ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "mcp"
        );
        reply
    }

    async fn handle_batch(&self, msg: &Value, body: &[u8], pv: Option<&str>) -> Reply {
        let items = msg.as_array().cloned().unwrap_or_default();
        let may_resend = !items.iter().any(|m| m["method"] == "tools/call");
        let fail = |why: &str| {
            let errs: Vec<Value> = items
                .iter()
                .filter(|m| m.get("id").is_some())
                .map(|m| rpc_error(&m["id"], why))
                .collect();
            Reply::json(200, &Value::Array(errs))
        };
        let Some(tok) = self.tokens.access().await.filter(|_| self.tokens.auth().ok) else {
            self.tokens.start_login().await;
            return fail("the InOrbit MCP door is not signed in: iohr-agent mcp login");
        };
        match self
            .forward(body, &tok, pv, Duration::from_secs(180), may_resend)
            .await
        {
            Ok(r) => Reply {
                status: r.code,
                ctype: r.ctype,
                body: r.data,
            },
            Err(why) => fail(&format!("InOrbit API unreachable: {why}")),
        }
    }

    async fn handle_one(
        self: &Arc<Self>,
        msg: &Value,
        method: &str,
        body: &[u8],
        pv: Option<&str>,
    ) -> Reply {
        let Some(id) = msg.get("id").filter(|i| !i.is_null()).cloned() else {
            // A notification: acknowledge at once, forward when there is a sign-in. A
            // `tools/call` without an id is never resent either.
            if self.tokens.auth().ok {
                let me = Arc::clone(self);
                let may_resend = method != "tools/call";
                let (body, pv) = (body.to_vec(), pv.map(str::to_owned));
                tokio::spawn(async move {
                    if let Some(t) = me.tokens.access().await {
                        let _ = me
                            .forward(&body, &t, pv.as_deref(), Duration::from_secs(5), may_resend)
                            .await;
                    }
                });
            }
            return Reply::accepted();
        };
        let client_pv = msg["params"]["protocolVersion"]
            .as_str()
            .or(pv)
            .unwrap_or(FALLBACK_PROTOCOL)
            .to_owned();

        if method == "initialize"
            && let Some(v) = self.cached_initialize(&id, &client_pv)
        {
            self.refresh_initialize_later(body, pv);
            return Reply::json(200, &v);
        }
        if method == "server/discover"
            && let Some(d) = lock(&self.discover).clone()
            && now_s() - d.at < DISCOVER_TTL_S
        {
            return replay_discover(&d, &id);
        }
        if !self.tokens.auth().ok {
            let url = self.tokens.start_login().await;
            return self.not_signed_in(method, &id, &client_pv, &url);
        }
        let Some(tok) = self.tokens.access().await.filter(|_| self.tokens.auth().ok) else {
            let url = self.tokens.start_login().await;
            return self.not_signed_in(method, &id, &client_pv, &url);
        };
        let timeout = match method {
            "initialize" => Duration::from_secs(20),
            "tools/call" => Duration::from_secs(180),
            _ => Duration::from_secs(30),
        };
        let may_resend = method != "tools/call";
        let mut result = self.forward(body, &tok, pv, timeout, may_resend).await;
        if let Ok(r) = &result
            && r.code == 401
        {
            if self.tokens.refresh(true, Some(&tok)).await
                && let Some(t2) = self.tokens.access().await
            {
                result = self.forward(body, &t2, pv, timeout, may_resend).await;
            } else {
                let url = self.tokens.start_login().await;
                return self.not_signed_in(method, &id, &client_pv, &url);
            }
            if result.as_ref().is_ok_and(|r| r.code == 401) {
                let url = self.tokens.start_login().await;
                return self.not_signed_in(method, &id, &client_pv, &url);
            }
        }
        match result {
            Err(why) => {
                if let Some(v) = self.offline_answer(method, &id, &client_pv) {
                    return Reply::json(200, &v);
                }
                if method == "tools/call" && why.ends_with(REPLY_LOST) {
                    Reply::json(200, &tool_error(&id, &lost_reply_note(&why)))
                } else if method == "tools/call" {
                    Reply::json(
                        200,
                        &tool_error(
                            &id,
                            &format!(
                                "The InOrbit API could not be reached ({why}); the door retried for {} s. Try again shortly.",
                                self.cfg
                                    .backoff
                                    .iter()
                                    .map(Duration::as_secs_f64)
                                    .sum::<f64>()
                                    .round()
                            ),
                        ),
                    )
                } else {
                    Reply::json(
                        200,
                        &rpc_error(&id, &format!("InOrbit API unreachable: {why}")),
                    )
                }
            }
            Ok(r) => self.finish(method, &id, &client_pv, r),
        }
    }

    fn finish(&self, method: &str, id: &Value, pv: &str, r: Raw) -> Reply {
        let json_body = serde_json::from_slice::<Value>(&r.data).ok();
        if method == "server/discover" && [200, 400, 404].contains(&r.code) && json_body.is_some() {
            let d = Discover {
                code: r.code,
                ctype: r.ctype.clone(),
                data: String::from_utf8_lossy(&r.data).into_owned(),
                at: now_s(),
            };
            *lock(&self.discover) = Some(d);
            self.save_cache();
        }
        if r.code == 200
            && let Some(v) = &json_body
        {
            self.remember(method, v);
        }
        if (200..300).contains(&r.code) || json_body.is_some() {
            return Reply {
                status: r.code,
                ctype: r.ctype,
                body: r.data,
            };
        }
        // An HTML or empty error page from the edge: say what it was, not what it said.
        let msg = format!("The InOrbit API answered {}", r.code);
        if let Some(v) = self.offline_answer(method, id, pv) {
            return Reply::json(200, &v);
        }
        if method == "tools/call" {
            Reply::json(200, &tool_error(id, &msg))
        } else {
            Reply::json(200, &rpc_error(id, &msg))
        }
    }

    fn refresh_initialize_later(self: &Arc<Self>, body: &[u8], pv: Option<&str>) {
        {
            let mut at = lock(&self.init_at);
            if at.is_some_and(|t| t.elapsed() < INIT_REFRESH) {
                return;
            }
            *at = Some(Instant::now());
        }
        if !self.tokens.auth().ok {
            return;
        }
        let me = Arc::clone(self);
        let (body, pv) = (body.to_vec(), pv.map(str::to_owned));
        tokio::spawn(async move {
            let Some(t) = me.tokens.access().await else {
                return;
            };
            if let Ok(r) = me
                .forward(&body, &t, pv.as_deref(), Duration::from_secs(30), true)
                .await
                && r.code == 200
                && let Ok(v) = serde_json::from_slice::<Value>(&r.data)
            {
                me.remember("initialize", &v);
            }
        });
    }
}

fn replay_discover(d: &Discover, id: &Value) -> Reply {
    match serde_json::from_str::<Value>(&d.data) {
        Ok(mut v) => {
            v["id"] = id.clone();
            Reply {
                status: d.code,
                ctype: d.ctype.clone(),
                body: serde_json::to_vec(&v).unwrap_or_default(),
            }
        }
        Err(_) => Reply::json(200, &rpc_error(id, "no discover answer cached")),
    }
}
