//! The door without the network or the keychain: a fake platform on a local port, the
//! keychain replaced by memory, state in a temporary folder. Each test is one way the
//! `inorbit` MCP used to fail for a session.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use super::dns::FallbackResolver;
use super::store::Store;
use super::tokens::Tokens;
use super::{Bridge, Door, DoorConfig, Notifier, http_client, serve_on};

const SECRET: &str = "test-local-secret";

fn tools() -> Value {
    json!({"tools": [{"name": "platform_status", "inputSchema": {"type": "object"}}]})
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Ok,
    Drop,
    Busy,
}

#[derive(Clone)]
struct Fake {
    mode: Arc<Mutex<Mode>>,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl Fake {
    fn set(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
    }
    fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.0.clone())
            .collect()
    }
}

async fn fake_platform() -> (SocketAddr, Fake) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let fake = Fake {
        mode: Arc::new(Mutex::new(Mode::Ok)),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let f = fake.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let f = f.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                let (head, body) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if buf.len() >= p + 4 + len {
                            break (head, buf[p + 4..p + 4 + len].to_vec());
                        }
                    }
                };
                let msg: Value = serde_json::from_slice(&body).unwrap();
                let auth = head
                    .lines()
                    .find_map(|l| l.strip_prefix("authorization:"))
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let method = msg["method"].as_str().unwrap_or("").to_owned();
                f.seen.lock().unwrap().push((method.clone(), auth));
                let mode = *f.mode.lock().unwrap();
                let (code, out) = match mode {
                    Mode::Drop => return, // read the call, then lose the reply
                    Mode::Busy => (503, json!({"error": "busy"})),
                    Mode::Ok => {
                        let res = match method.as_str() {
                            "initialize" => {
                                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "inorbit", "version": "0.1.0"}})
                            }
                            "tools/list" => tools(),
                            _ => {
                                json!({"content": [{"type": "text", "text": "up"}], "isError": false})
                            }
                        };
                        (
                            200,
                            json!({"jsonrpc": "2.0", "id": msg["id"], "result": res}),
                        )
                    }
                };
                let out = out.to_string();
                let resp = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    (addr, fake)
}

struct Rig {
    door: SocketAddr,
    fake: Fake,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
}

async fn rig() -> Rig {
    crate::tls::install_crypto_provider();
    let (api, fake) = fake_platform().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = Arc::new(DoorConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: format!("http://{api}/mcp"),
        issuer: "http://127.0.0.1:9".into(),
        client_id: "test".into(),
        redirect_port: 0,
        scope: "mcp:read".into(),
        state_dir: dir.path().to_path_buf(),
        notify: None,
        backoff: vec![Duration::from_millis(50), Duration::from_millis(50)],
        dns_names: Vec::new(),
        login_every: Duration::from_secs(600),
        open_browser: false,
        token_item: "t".into(),
        secret_item: "s".into(),
    });
    let http = http_client(&cfg).unwrap();
    let tokens = Arc::new(
        Tokens::load(
            cfg.clone(),
            Arc::new(Store::memory()),
            http.clone(),
            Arc::new(Notifier::new(None)),
        )
        .await,
    );
    tokens.set_for_test("at", "rt", 4e9);
    let bridge = Arc::new(Bridge::new(cfg, http.clone(), tokens));
    bridge.reset_for_test();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let door_addr = l.local_addr().unwrap();
    let d = Door::new(bridge, Zeroizing::new(SECRET.to_owned()));
    tokio::spawn(serve_on(l, d));
    Rig {
        door: door_addr,
        fake,
        http: reqwest::Client::new(),
        _dir: dir,
    }
}

impl Rig {
    async fn raw(&self, body: &Value, edit: impl Fn(&mut Vec<(&str, String)>)) -> (u16, Value) {
        let mut h = vec![
            ("Host", format!("127.0.0.1:{}", self.door.port())),
            ("X-Iohr-Bridge", SECRET.to_owned()),
            ("Content-Type", "application/json".to_owned()),
        ];
        edit(&mut h);
        let mut req = self
            .http
            .post(format!("http://{}/mcp", self.door))
            .body(body.to_string());
        for (k, v) in h {
            if !v.is_empty() {
                req = req.header(k, v);
            }
        }
        let r = req.send().await.unwrap();
        let code = r.status().as_u16();
        let bytes = r.bytes().await.unwrap();
        (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post(&self, body: &Value) -> (u16, Value) {
        self.raw(body, |_| {}).await
    }
}

fn call(id: u32, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method})
}

#[tokio::test]
async fn the_local_door_needs_the_secret_and_no_browser() {
    let r = rig().await;
    let c = call(1, "tools/list");
    let set = |k: &'static str, v: &'static str| {
        move |h: &mut Vec<(&str, String)>| {
            h.retain(|(n, _)| *n != k);
            h.push((k, v.to_owned()));
        }
    };
    assert_eq!(r.raw(&c, set("X-Iohr-Bridge", "")).await.0, 403);
    assert_eq!(r.raw(&c, set("X-Iohr-Bridge", "wrong")).await.0, 403);
    assert_eq!(r.raw(&c, set("Origin", "https://evil.test")).await.0, 403);
    assert_eq!(r.raw(&c, set("Host", "evil.test")).await.0, 403);
    assert_eq!(r.fake.methods().len(), 0);
    assert_eq!(r.post(&c).await.0, 200);
    assert_eq!(
        *r.fake.seen.lock().unwrap(),
        vec![("tools/list".to_owned(), "bearer at".to_owned())]
    );
}

#[tokio::test]
async fn a_session_starts_with_its_tools_when_the_api_is_down() {
    let r = rig().await;
    r.post(&call(1, "tools/list")).await;
    r.post(&call(9, "initialize")).await;
    r.fake.set(Mode::Busy);
    let mut init = call(2, "initialize");
    init["params"] = json!({"protocolVersion": "2025-06-18"});
    let (code, v) = r.post(&init).await;
    assert_eq!(
        (code, &v["result"]["capabilities"]),
        (200, &json!({"tools": {}}))
    );
    let (code, v) = r.post(&call(3, "tools/list")).await;
    assert_eq!((code, v["result"].clone()), (200, tools()));
}

#[tokio::test]
async fn no_cache_and_no_api_still_connects() {
    let r = rig().await;
    r.fake.set(Mode::Busy);
    let (_, v) = r.post(&call(1, "tools/list")).await;
    assert_eq!(v["result"], json!({"tools": []}));
    let (_, v) = r.post(&call(2, "initialize")).await;
    assert_eq!(v["result"]["capabilities"], json!({"tools": {}}));
}

#[tokio::test]
async fn initialize_answers_from_cache_at_once() {
    let r = rig().await;
    let mut first = call(1, "initialize");
    first["params"] = json!({"protocolVersion": "2025-06-18"});
    r.post(&first).await;
    let before = r.fake.methods().len();
    let mut second = call(7, "initialize");
    second["params"] = json!({"protocolVersion": "2025-11-25"});
    let (_, v) = r.post(&second).await;
    assert_eq!(
        (v["id"].clone(), v["result"]["protocolVersion"].clone()),
        (json!(7), json!("2025-11-25"))
    );
    assert_eq!(v["result"]["serverInfo"]["name"], "inorbit");
    assert_eq!(r.fake.methods().len(), before);
}

#[tokio::test]
async fn a_tool_call_whose_reply_was_lost_is_never_sent_twice() {
    let r = rig().await;
    r.fake.set(Mode::Drop);
    let mut c = call(1, "tools/call");
    c["params"] = json!({"name": "platform_status"});
    let (_, v) = r.post(&c).await;
    assert_eq!(v["result"]["isError"], json!(true));
    assert_eq!(r.fake.methods(), vec!["tools/call"]);
}

#[tokio::test]
async fn a_list_whose_reply_was_lost_is_retried() {
    let r = rig().await;
    r.fake.set(Mode::Drop);
    r.post(&call(1, "tools/list")).await;
    assert_eq!(r.fake.methods(), vec!["tools/list"; 3]);
}

#[tokio::test]
async fn status_has_no_secret_and_no_token() {
    let r = rig().await;
    let body = r
        .http
        .get(format!("http://{}/status", r.door))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["auth"], "ok");
    assert!(!body.contains(SECRET) && !body.contains(":\"at\"") && !body.contains(":\"rt\""));
    let other = r
        .http
        .delete(format!("http://{}/mcp", r.door))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status().as_u16(), 405);
}

#[tokio::test]
async fn a_dns_miss_falls_back_to_the_last_good_address() {
    let dir = tempfile::tempdir().unwrap();
    let up = Arc::new(Mutex::new(true));
    let u = up.clone();
    let system: super::dns::Lookup = Arc::new(move |_| {
        let ok = *u.lock().unwrap();
        Box::pin(async move {
            if ok {
                Ok(vec!["127.0.0.1".parse().unwrap()])
            } else {
                Err(std::io::Error::other("nodename nor servname provided"))
            }
        })
    });
    let r = FallbackResolver::new(
        vec!["api.inorbit.hr".into()],
        dir.path().join("dns.json"),
        system,
        Vec::new(),
    );
    r.lookup("api.inorbit.hr").await.unwrap();
    *up.lock().unwrap() = false;
    let got = r.lookup("api.inorbit.hr").await.unwrap();
    assert_eq!(got, vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]);
    // A name that was not configured gets the system's answer, failure included.
    assert!(r.lookup("example.test").await.is_err());
}
