//! The two local sockets (`docs/capture/design-phase1.md`):
//!
//! - **aggregates** (0660, group `iohr-capture-read`): one JSON request line, one JSON
//!   answer (`counts`, or `tables` for a person, never for the agent's user), bounded in
//!   size, time and concurrency; peers are checked with `SO_PEERCRED`.
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

    /// Whether `uid` is the agent's user (which may read counts only). Root is never
    /// treated as the agent: a person with sudo may read the tables.
    pub(crate) fn is_agent(&self, uid: u32) -> bool {
        uid != 0 && Some(uid) == self.agent_uid
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

/// Prepares the directory the sockets live in, before the capability drop: created if
/// missing; with a read group, owned by that group and set-group-id (02750), so every
/// socket made in it later belongs to the group without any `chown` (the unit's system
/// call filter forbids `chown`; under the unit the directory already has the group, so
/// nothing is changed but the mode).
pub(crate) fn prepare_dir(dir: &Path, gid: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let mode = match gid {
        Some(g) => {
            if fs::metadata(dir)?.gid() != g
                && let Err(e) = std::os::unix::fs::chown(dir, None, Some(g))
            {
                // Under the unit the directory has the unit's Group= already; a different
                // --socket-group there cannot be applied (no chown) and is reported.
                tracing::warn!(error = %e, dir = %dir.display(), "the socket directory keeps its group");
            }
            0o2750
        }
        None => 0o755,
    };
    // Only when it differs: the unit creates the directory 2750 itself and forbids
    // setting the set-group-id bit (RestrictSUIDSGID).
    if fs::metadata(dir)?.mode() & 0o7777 != mode {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Binds a socket at `path` with `mode`, replacing a stale socket file; never replaces
/// anything that is not a socket, nor a socket another process still serves.
fn bind_one(path: &Path, mode: u32) -> io::Result<std::os::unix::net::UnixListener> {
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
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Binds both sockets: aggregates 0660 (its group is the directory's, see
/// [`prepare_dir`]), control 0600.
pub(crate) fn bind(aggregates: &Path, control: &Path) -> io::Result<Bound> {
    let a = bind_one(aggregates, 0o660)?;
    let c = bind_one(control, 0o600)?;
    Ok(Bound {
        aggregates: a,
        control: c,
        paths: [aggregates.to_owned(), control.to_owned()],
    })
}

/// Connections served at once; more are closed right away.
const MAX_CONNECTIONS: usize = 16;
/// How long writing an answer may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Accepts with a back-off on errors (for example `EMFILE`), so a failing accept never
/// spins.
async fn accept(l: &UnixListener) -> UnixStream {
    let mut delay = Duration::from_millis(50);
    loop {
        match l.accept().await {
            Ok((s, _)) => return s,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed; backing off");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// Serves the aggregates socket until the task is dropped.
pub(crate) async fn serve_aggregates(
    l: UnixListener,
    engine: Arc<Mutex<Engine>>,
    access: Arc<Access>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let sock = accept(&l).await;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!("aggregates socket: too many connections at once; one closed");
            drop(sock);
            continue;
        };
        let engine = Arc::clone(&engine);
        let access = Arc::clone(&access);
        tokio::spawn(async move {
            let _permit = permit;
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
        let a = json!({"version": WIRE_VERSION, "error": "forbidden", "message": "this user may not read capture aggregates (join the iohr-capture-read group)"});
        return write(&mut sock, &a).await;
    }
    let answer = answer(request.as_ref(), engine, access.is_agent(cred.uid()));
    tracing::debug!(
        uid = cred.uid(),
        request = ?request.as_ref().ok().and_then(|v| v["request"].as_str()),
        error = answer.get("error").and_then(serde_json::Value::as_str).unwrap_or("none"),
        "aggregates socket"
    );
    write(&mut sock, &answer).await
}

/// The answer to one request (pure, for tests). The agent may only ever have `counts`:
/// the companion enforces that names, paths and addresses never reach it (DAT-10).
pub(crate) fn answer(
    request: Result<&Value, &String>,
    engine: &Mutex<Engine>,
    peer_is_agent: bool,
) -> Value {
    let req = match request {
        Ok(v) => v,
        Err(e) => return json!({"version": WIRE_VERSION, "error": "bad_request", "message": e}),
    };
    if req["version"].as_u64() != Some(u64::from(WIRE_VERSION)) {
        return json!({"version": WIRE_VERSION, "error": "unsupported_version", "message": "this companion speaks version 1"});
    }
    match req["request"].as_str() {
        Some("counts") => lock(engine).counts(),
        Some("tables") if peer_is_agent => {
            json!({"version": WIRE_VERSION, "error": "forbidden", "message": "the agent may read counts only"})
        }
        Some("tables") => lock(engine).tables(),
        _ => {
            json!({"version": WIRE_VERSION, "error": "unknown_request", "message": "ask for \"counts\" or \"tables\""})
        }
    }
}

fn lock(e: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    match e.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
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
    tokio::time::timeout(WRITE_TIMEOUT, async {
        sock.write_all(&body).await?;
        sock.shutdown().await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the client did not read the answer",
        )
    })?
}

/// Serves the control socket: root only, and nothing is available in phase 1.
pub(crate) async fn serve_control(l: UnixListener) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let mut sock = accept(&l).await;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let uid = sock.peer_cred().map(|c| c.uid()).ok();
            let _ = read_request(&mut sock).await;
            let (code, message) = if uid == Some(0) {
                (
                    "not_available",
                    "pcap on request arrives in a later version (phase 2)",
                )
            } else {
                ("forbidden", "the control socket is for root only")
            };
            tracing::info!(uid = ?uid, answer = code, "control socket");
            let a = json!({"version": WIRE_VERSION, "error": code, "message": message});
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
                companion_kept: Vec::new(),
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
        assert!(a.is_agent(998) && !a.is_agent(0) && !a.is_agent(1000));
    }

    #[test]
    fn answers() {
        let e = engine();
        let ok = answer(Ok(&json!({"version": 1, "request": "counts"})), &e, true);
        assert_eq!(ok["version"], 1);
        assert!(ok.get("tables").is_none());
        let t = answer(Ok(&json!({"version": 1, "request": "tables"})), &e, false);
        assert!(t.get("tables").is_some());
        assert_eq!(
            answer(Ok(&json!({"version": 2, "request": "counts"})), &e, false)["error"],
            "unsupported_version"
        );
        assert_eq!(
            answer(Ok(&json!({"version": 1, "request": "pcap"})), &e, false)["error"],
            "unknown_request"
        );
        assert_eq!(
            answer(Err(&"x".to_owned()), &e, false)["error"],
            "bad_request"
        );
        // The agent's user never gets the tables, whatever it asks.
        let agent = answer(Ok(&json!({"version": 1, "request": "tables"})), &e, true);
        assert_eq!(agent["error"], "forbidden");
        assert!(agent.get("tables").is_none());
    }

    #[tokio::test]
    async fn round_trip_over_a_socket_and_control_refuses() {
        let dir = std::env::temp_dir().join(format!("iohr-capture-server-{}", std::process::id()));
        let agg = dir.join("a.sock");
        let ctl = dir.join("c.sock");
        prepare_dir(&dir, None).unwrap();
        let bound = bind(&agg, &ctl).unwrap();
        let mode = fs::metadata(&agg).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
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
