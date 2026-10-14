//! The local door: a small HTTP/1.1 responder on the loopback address. It speaks only to
//! processes on this machine that hold the local secret: no browser page can reach it (an
//! `Origin` header is refused and the `Host` must be the door's own), and a request without
//! the secret gets a 403 before anything is forwarded.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::bridge::{Bridge, Reply};
use crate::admin::constant_time_eq;
use crate::error::{Error, Result};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;

/// The door: the logic and the secret that guards it.
pub struct Door {
    bridge: Arc<Bridge>,
    secret: Zeroizing<String>,
}

impl std::fmt::Debug for Door {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Door").finish_non_exhaustive()
    }
}

impl Door {
    /// A door guarded by `secret`.
    #[must_use]
    pub fn new(bridge: Arc<Bridge>, secret: Zeroizing<String>) -> Self {
        Self { bridge, secret }
    }
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Serves `listener` until the future is dropped.
///
/// # Errors
/// The listener failed.
pub async fn serve_on(listener: TcpListener, door: Door) -> Result<()> {
    let local = listener
        .local_addr()
        .map_err(|e| Error::Config(format!("listener: {e}")))?;
    let hosts = Arc::new(vec![
        format!("127.0.0.1:{}", local.port()),
        format!("localhost:{}", local.port()),
    ]);
    let door = Arc::new(door);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (sock, _) = listener
            .accept()
            .await
            .map_err(|e| Error::Config(format!("accept: {e}")))?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let (door, hosts) = (door.clone(), hosts.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(Duration::from_secs(300), connection(sock, &door, &hosts))
                .await;
        });
    }
}

async fn read_request(sock: &mut TcpStream) -> std::result::Result<Request, u16> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 4096];
    let head_end = tokio::time::timeout(HEAD_TIMEOUT, async {
        loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok::<usize, u16>(p);
            }
            if buf.len() > MAX_HEAD {
                return Err(431);
            }
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err(400),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .map_err(|_| 408_u16)??;
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (
        first.next().unwrap_or("").to_owned(),
        first.next().unwrap_or("").to_owned(),
    );
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let mut req = Request {
        method,
        path,
        headers,
        body: Vec::new(),
    };
    if req.header("transfer-encoding").is_some() {
        return Err(501);
    }
    let len: usize = req
        .header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    tokio::time::timeout(BODY_TIMEOUT, async {
        while body.len() < len {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err(400_u16),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| 408_u16)??;
    body.truncate(len);
    req.body = body;
    Ok(req)
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

async fn respond(sock: &mut TcpStream, r: &Reply) {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        r.status,
        reason(r.status),
        r.ctype,
        r.body.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(&r.body).await;
    let _ = sock.shutdown().await;
}

fn plain(status: u16, v: &serde_json::Value) -> Reply {
    Reply {
        status,
        ctype: "application/json".into(),
        body: serde_json::to_vec(v).unwrap_or_default(),
    }
}

async fn connection(mut sock: TcpStream, door: &Door, hosts: &[String]) {
    let reply = match read_request(&mut sock).await {
        Err(code) => plain(code, &serde_json::json!({"error": "bad request"})),
        Ok(req) => route(&req, door, hosts).await,
    };
    respond(&mut sock, &reply).await;
}

async fn route(req: &Request, door: &Door, hosts: &[String]) -> Reply {
    let path = req.path.split('?').next().unwrap_or("");
    if req.method == "GET" && path == "/status" {
        return plain(200, &door.bridge.status());
    }
    if req.method != "POST" {
        return plain(405, &serde_json::json!({"error": "method not allowed"}));
    }
    if path != "/mcp" && path != "/login" {
        return plain(404, &serde_json::json!({"error": "not found"}));
    }
    let host_ok = req
        .header("host")
        .is_some_and(|h| hosts.iter().any(|a| a == h));
    let secret_ok = req
        .header("x-iohr-bridge")
        .is_some_and(|s| constant_time_eq(s.as_bytes(), door.secret.as_bytes()));
    if req.header("origin").is_some() || !host_ok || !secret_ok {
        return plain(
            403,
            &serde_json::json!({"error": "local secret missing or wrong"}),
        );
    }
    if path == "/login" {
        return plain(200, &serde_json::json!({"url": door.bridge.login()}));
    }
    door.bridge
        .handle(&req.body, req.header("mcp-protocol-version"))
        .await
}
