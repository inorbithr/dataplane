//! The two local sockets (`docs/capture/design-phase1.md`):
//!
//! - **aggregates** (0660, group `iohr-agent`): one JSON request line, one JSON answer
//!   (`counts`, or `tables` for a person), bounded in size and time; peers are checked
//!   with `SO_PEERCRED`.
//! - **control** (0600, root only): reserved for pcap on request (phase 2); every request
//!   is answered `not_available`.
//!
//! Neither is a network listener. Logs say who asked what and the outcome, never what
//! the answer held.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

use crate::engine::{Engine, WIRE_VERSION};

/// Longest request line.
pub(crate) const MAX_REQUEST: usize = 1024;
/// Largest answer.
pub(crate) const MAX_ANSWER: usize = 1024 * 1024;
/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Who may read the aggregates socket.
#[derive(Debug, Clone, Default)]
pub(crate) struct Access {
    /// This process's uid (always allowed).
    pub(crate) own_uid: u32,
    /// The agent's user, by uid.
    pub(crate) agent_uid: Option<u32>,
    /// The socket's group and its members' uids.
    pub(crate) group_gid: Option<u32>,
    pub(crate) group_members: Vec<u32>,
}

impl Access {
    /// Looks up the agent user and the socket group in `/etc/passwd` and `/etc/group`.
    pub(crate) fn lookup(agent_user: &str, group: &str, own_uid: u32) -> Self {
        let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
        let groups = fs::read_to_string("/etc/group").unwrap_or_default();
        Self::from_files(&passwd, &groups, agent_user, group, own_uid)
    }

    pub(crate) fn from_files(
        passwd: &str,
        groups: &str,
        agent_user: &str,
        group: &str,
        own_uid: u32,
    ) -> Self {
        let users = crate::owners::users(passwd);
        let uid_of = |name: &str| users.iter().find(|(_, n)| *n == name).map(|(u, _)| *u);
        let mut a = Self {
            own_uid,
            agent_uid: uid_of(agent_user),
            ..Self::default()
        };
        for line in groups.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.first() == Some(&group) {
                a.group_gid = f.get(2).and_then(|g| g.parse().ok());
                a.group_members = f
                    .get(3)
                    .map(|m| m.split(',').filter_map(uid_of).collect())
                    .unwrap_or_default();
            }
        }
        a
    }

    /// Whether a peer with this uid and primary gid may read the aggregates.
    pub(crate) fn allows(&self, uid: u32, gid: u32) -> bool {
        uid == 0
            || uid == self.own_uid
            || Some(uid) == self.agent_uid
            || Some(gid) == self.group_gid
            || self.group_members.contains(&uid)
    }
}

/// Both sockets, bound (before the capability drop: filesystem work only).
#[derive(Debug)]
pub(crate) struct Bound {
    pub(crate) aggregates: std::os::unix::net::UnixListener,
    pub(crate) control: std::os::unix::net::UnixListener,
    pub(crate) paths: [PathBuf; 2],
}

impl Drop for Bound {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = fs::remove_file(p);
        }
    }
}

/// Binds a socket at `path` with `mode`, replacing a stale socket file; never replaces
/// anything that is not a socket.
fn bind_one(
    path: &Path,
    mode: u32,
    gid: Option<u32>,
) -> io::Result<std::os::unix::net::UnixListener> {
    if let Some(dir) = path.parent()
        && !dir.exists()
    {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "{} is served by another process (is iohr-capture already running?)",
                        path.display()
                    ),
                ));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(_) => {}
    }
    let l = std::os::unix::net::UnixListener::bind(path)?;
    if let Some(g) = gid {
        std::os::unix::fs::chown(path, None, Some(g))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Binds both sockets: aggregates 0660 with the group (0600 when the group is unknown),
/// control 0600.
pub(crate) fn bind(aggregates: &Path, control: &Path, group_gid: Option<u32>) -> io::Result<Bound> {
    let mode = if group_gid.is_some() { 0o660 } else { 0o600 };
    let a = bind_one(aggregates, mode, group_gid)?;
    let c = bind_one(control, 0o600, None)?;
    Ok(Bound {
        aggregates: a,
        control: c,
        paths: [aggregates.to_owned(), control.to_owned()],
    })
}

/// Serves the aggregates socket until the task is dropped.
pub(crate) async fn serve_aggregates(
    l: UnixListener,
    engine: Arc<Mutex<Engine>>,
    access: Arc<Access>,
) {
    loop {
        let Ok((sock, _)) = l.accept().await else {
            continue;
        };
        let engine = Arc::clone(&engine);
        let access = Arc::clone(&access);
        tokio::spawn(async move {
            let _ = aggregates_conn(sock, &engine, &access).await;
        });
    }
}

async fn aggregates_conn(
    mut sock: UnixStream,
    engine: &Mutex<Engine>,
    access: &Access,
) -> io::Result<()> {
    let cred = sock.peer_cred()?;
    // Read the request either way: closing with unread bytes would reset the connection
    // before the client reads the answer.
    let request = read_request(&mut sock).await;
    if !access.allows(cred.uid(), cred.gid()) {
        tracing::warn!(uid = cred.uid(), pid = ?cred.pid(), "aggregates socket: peer refused");
        let a = json!({"version": WIRE_VERSION, "error": "forbidden", "message": "this user may not read capture aggregates (join the iohr-agent group)"});
        return write(&mut sock, &a).await;
    }
    let answer = answer(request.as_ref(), engine);
    tracing::debug!(uid = cred.uid(), request = ?request.as_ref().ok().and_then(|v| v["request"].as_str()), ok = answer.get("error").is_none(), "aggregates socket");
    write(&mut sock, &answer).await
}

/// The answer to one request (pure, for tests).
pub(crate) fn answer(request: Result<&Value, &String>, engine: &Mutex<Engine>) -> Value {
    let req = match request {
        Ok(v) => v,
        Err(e) => return json!({"version": WIRE_VERSION, "error": "bad_request", "message": e}),
    };
    if req["version"].as_u64() != Some(u64::from(WIRE_VERSION)) {
        return json!({"version": WIRE_VERSION, "error": "unsupported_version", "message": "this companion speaks version 1"});
    }
    let e = match engine.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match req["request"].as_str() {
        Some("counts") => e.counts(),
        Some("tables") => e.tables(),
        _ => {
            json!({"version": WIRE_VERSION, "error": "unknown_request", "message": "ask for \"counts\" or \"tables\""})
        }
    }
}

async fn read_request(sock: &mut UnixStream) -> Result<Value, String> {
    let mut buf = Vec::with_capacity(128);
    let read = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut chunk = [0u8; 256];
        loop {
            let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if buf.contains(&b'\n') {
                return Ok(());
            }
            if buf.len() > MAX_REQUEST {
                return Err("request longer than 1 KiB".to_owned());
            }
        }
    })
    .await
    .map_err(|_| "no request within 2 s".to_owned())?;
    read?;
    let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
    serde_json::from_slice(line).map_err(|e| format!("not JSON: {e}"))
}

async fn write(sock: &mut UnixStream, v: &Value) -> io::Result<()> {
    let mut body = serde_json::to_vec(v).unwrap_or_default();
    if body.len() > MAX_ANSWER {
        body = serde_json::to_vec(&json!({"version": WIRE_VERSION, "error": "too_large"}))
            .unwrap_or_default();
    }
    body.push(b'\n');
    sock.write_all(&body).await?;
    sock.shutdown().await
}

/// Serves the control socket: root only, and nothing is available in phase 1.
pub(crate) async fn serve_control(l: UnixListener) {
    loop {
        let Ok((mut sock, _)) = l.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let uid = sock.peer_cred().map(|c| c.uid()).ok();
            let _ = read_request(&mut sock).await;
            let a = if uid == Some(0) {
                json!({"version": WIRE_VERSION, "error": "not_available", "message": "pcap on request arrives in a later version (phase 2)"})
            } else {
                json!({"version": WIRE_VERSION, "error": "forbidden", "message": "the control socket is for root only"})
            };
            tracing::info!(uid = ?uid, "control socket: request answered not_available");
            let _ = write(&mut sock, &a).await;
        });
    }
}

/// A client of the aggregates socket (`iohr-capture stats`).
pub(crate) async fn query(path: &Path, request: &str) -> io::Result<Value> {
    let mut s = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(path))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let line = format!("{}\n", json!({"version": WIRE_VERSION, "request": request}));
    s.write_all(line.as_bytes()).await?;
    let mut out = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        (&mut s).take(MAX_ANSWER as u64 + 2).read_to_end(&mut out),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer in time"))??;
    serde_json::from_slice(&out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Layers, Settings};
    use crate::privileges::Dropped;

    fn engine() -> Arc<Mutex<Engine>> {
        Arc::new(Mutex::new(Engine::new(
            Settings {
                interface: "lo".into(),
                layers: Layers::parse("headers,protocols").unwrap(),
                max_flows: 16,
                idle: Duration::from_secs(60),
            },
            &Dropped::for_tests(),
        )))
    }

    #[test]
    fn access_rules() {
        let passwd = "root:x:0:0::/:/bin/sh\niohr-agent:x:998:998::/:/bin/false\nalice:x:1000:1000::/:/bin/sh\nbob:x:1001:1001::/:/bin/sh\n";
        let groups = "iohr-agent:x:998:alice\n";
        let a = Access::from_files(passwd, groups, "iohr-agent", "iohr-agent", 997);
        assert!(a.allows(0, 0));
        assert!(a.allows(997, 997));
        assert!(a.allows(998, 998));
        assert!(a.allows(1000, 1000), "a member of the group");
        assert!(!a.allows(1001, 1001), "anyone else");
        assert!(a.allows(1001, 998), "primary group");
    }

    #[test]
    fn answers() {
        let e = engine();
        let ok = answer(Ok(&json!({"version": 1, "request": "counts"})), &e);
        assert_eq!(ok["version"], 1);
        assert!(ok.get("tables").is_none());
        let t = answer(Ok(&json!({"version": 1, "request": "tables"})), &e);
        assert!(t.get("tables").is_some());
        assert_eq!(
            answer(Ok(&json!({"version": 2, "request": "counts"})), &e)["error"],
            "unsupported_version"
        );
        assert_eq!(
            answer(Ok(&json!({"version": 1, "request": "pcap"})), &e)["error"],
            "unknown_request"
        );
        assert_eq!(answer(Err(&"x".to_owned()), &e)["error"], "bad_request");
    }

    #[tokio::test]
    async fn round_trip_over_a_socket_and_control_refuses() {
        let dir = std::env::temp_dir().join(format!("iohr-capture-server-{}", std::process::id()));
        let agg = dir.join("a.sock");
        let ctl = dir.join("c.sock");
        let bound = bind(&agg, &ctl, None).unwrap();
        let mode = fs::metadata(&ctl).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let own = rustix::process::getuid().as_raw();
        let access = Arc::new(Access {
            own_uid: own,
            ..Access::default()
        });
        let a = UnixListener::from_std(bound.aggregates.try_clone().unwrap()).unwrap();
        let c = UnixListener::from_std(bound.control.try_clone().unwrap()).unwrap();
        let e = engine();
        tokio::spawn(serve_aggregates(a, e, access));
        tokio::spawn(serve_control(c));
        let v = query(&agg, "counts").await.unwrap();
        assert_eq!(v["packet_unit"], "skb");
        let v = query(&ctl, "pcap").await.unwrap();
        let expected = if own == 0 {
            "not_available"
        } else {
            "forbidden"
        };
        assert_eq!(v["error"], expected);
        drop(bound);
        assert!(!agg.exists(), "sockets are removed on exit");
        let _ = fs::remove_dir_all(&dir);
    }
}
