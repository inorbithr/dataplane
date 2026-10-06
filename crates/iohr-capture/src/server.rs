//! The two local sockets (`docs/capture/design-phase1.md`):
//!
//! - **aggregates** (0660, group `iohr-capture-read`): one JSON request line, one JSON
//!   answer (`counts`, or `tables` for a person, never for the agent's user; in version 2
//!   also `lookup`, numbers for one owner and route), bounded in size, time and
//!   concurrency; peers are checked with `SO_PEERCRED` (`docs/capture/design-phase2.md`).
//! - **control** (0600, root only by `SO_PEERCRED`): pcap files on request and the packet
//!   buffer's `status`; `not_available` when packets are off.
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

use crate::engine::{Engine, WIRE_VERSION, WIRE_VERSION_2};
use crate::pcap;

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

    /// Says loudly when the guard that keeps the tables from the agent cannot work.
    pub(crate) fn warn_if_unguarded(&self, agent_user: &str) {
        match self.agent_uid {
            None => tracing::warn!(
                agent_user,
                "the agent's user does not exist: the guard that gives it counts only is off until it does (set --agent-user)"
            ),
            Some(0) => tracing::warn!(
                agent_user,
                "the agent's user is root: root may read the tables, so the guard that gives the agent counts only is off"
            ),
            Some(_) => {}
        }
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
pub(crate) fn prepare_dir(dir: &Path, owner: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let meta = fs::metadata(dir)?;
    let owner = owner.filter(|u| *u != meta.uid());
    let group = gid.filter(|g| *g != meta.gid());
    if (owner.is_some() || group.is_some())
        && let Err(e) = std::os::unix::fs::chown(dir, owner, group)
    {
        // Under the unit the directory has the unit's user and Group= already; a different
        // --socket-group there cannot be applied (no chown) and is reported.
        tracing::warn!(error = %e, dir = %dir.display(), "the socket directory keeps its owner and group");
    }
    let mode = if gid.is_some() { 0o2750 } else { 0o755 };
    let meta = fs::metadata(dir)?;
    if meta.mode() & 0o7777 != mode
        && let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(mode))
    {
        // The unit creates the directory itself and forbids setting the set-group-id bit
        // (RestrictSUIDSGID). If the group is right, a different mode (a drop-in's
        // RuntimeDirectoryMode=) must not stop the start: it is reported.
        if gid.is_some_and(|g| g == meta.gid()) {
            tracing::warn!(
                error = %e,
                dir = %dir.display(),
                mode = format!("{:o}", meta.mode() & 0o7777),
                "the socket directory keeps its mode; 2750 is expected"
            );
        } else {
            return Err(e);
        }
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
    if request
        .as_ref()
        .is_ok_and(|r| r["request"].as_str() == Some("lookup"))
        && !LOOKUPS.allow(cred.uid())
    {
        let a = json!({"version": WIRE_VERSION_2, "error": "rate_limited", "message": "at most 50 lookups a second"});
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

/// Longest owner key in a lookup.
const MAX_OWNER: usize = 256;
/// Longest route in a lookup (`METHOD template`).
const MAX_ROUTE: usize = 300;
/// Lookups per peer uid per second.
const LOOKUPS_PER_SEC: u32 = 50;

/// A per-uid budget of lookups per second (bounded: a few uids may ever connect).
#[derive(Debug, Default)]
struct Limiter {
    seen: Mutex<std::collections::HashMap<u32, (std::time::Instant, u32)>>,
}

impl Limiter {
    fn allow(&self, uid: u32) -> bool {
        let mut m = match self.seen.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if m.len() > 1024 {
            m.clear();
        }
        let now = std::time::Instant::now();
        let e = m.entry(uid).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(1) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= LOOKUPS_PER_SEC
    }
}

static LOOKUPS: std::sync::LazyLock<Limiter> = std::sync::LazyLock::new(Limiter::default);

/// The answer to one request (pure, for tests). The agent may only ever have counts:
/// `counts` and, in version 2, `lookup` (numbers for a key it already holds); the
/// companion enforces that names, paths and addresses never reach it (DAT-10).
pub(crate) fn answer(
    request: Result<&Value, &String>,
    engine: &Mutex<Engine>,
    peer_is_agent: bool,
) -> Value {
    let req = match request {
        Ok(v) => v,
        Err(e) => return json!({"version": WIRE_VERSION, "error": "bad_request", "message": e}),
    };
    let version = match req["version"].as_u64() {
        Some(1) => WIRE_VERSION,
        Some(2) => WIRE_VERSION_2,
        _ => {
            return json!({"version": WIRE_VERSION_2, "error": "unsupported_version", "supported": [1, 2], "message": "this companion speaks versions 1 and 2"});
        }
    };
    let mut a = match req["request"].as_str() {
        Some("counts") => lock(engine).counts(),
        Some("tables") if peer_is_agent => {
            json!({"error": "forbidden", "message": "the agent may read counts only"})
        }
        Some("tables") => lock(engine).tables(),
        Some("lookup") if version == WIRE_VERSION => {
            json!({"error": "unknown_request", "message": "lookup needs version 2"})
        }
        Some("lookup") => {
            let owner = req["owner"].as_str().unwrap_or_default();
            let route = req["route"].as_str().unwrap_or_default();
            if owner.is_empty()
                || route.is_empty()
                || owner.len() > MAX_OWNER
                || route.len() > MAX_ROUTE
                || !route.contains(' ')
            {
                json!({"error": "bad_request", "message": "lookup needs owner (at most 256 bytes) and route (\"METHOD template\", at most 300 bytes)"})
            } else {
                lock(engine).lookup(owner, route)
            }
        }
        _ => {
            json!({"error": "unknown_request", "message": "ask for \"counts\", \"tables\" or (version 2) \"lookup\""})
        }
    };
    a["version"] = version.into();
    a
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

/// The control socket's protocol version.
pub(crate) const CONTROL_VERSION: u32 = 1;

/// Serves the control socket: root only (by `SO_PEERCRED`; the companion's own user is
/// refused too). `packets` is `None` when layer 3 is off: everything is `not_available`.
pub(crate) async fn serve_control(l: UnixListener, packets: Option<Arc<Mutex<pcap::State>>>) {
    // At most a few connections; one request served at a time (a pcap file is written
    // whole before the next is taken), the others are answered `busy`.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let one = Arc::new(tokio::sync::Semaphore::new(1));
    loop {
        let mut sock = accept(&l).await;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        let packets = packets.clone();
        let one = Arc::clone(&one);
        tokio::spawn(async move {
            let _permit = permit;
            let uid = sock.peer_cred().map(|c| c.uid()).ok();
            let request = read_request(&mut sock).await;
            let serving = one.try_acquire_owned();
            let a = if uid != Some(0) {
                json!({"version": CONTROL_VERSION, "error": "forbidden", "message": "the control socket is for root only"})
            } else if serving.is_err() {
                json!({"version": CONTROL_VERSION, "error": "busy", "message": "another control request is being served"})
            } else {
                control_answer(request.as_ref(), packets).await
            };
            drop(serving);
            // Who, what, outcome; never the filter or the file's content.
            tracing::info!(
                uid = ?uid,
                request = request.as_ref().ok().and_then(|v| v["request"].as_str()).unwrap_or("?"),
                answer = a.get("error").and_then(serde_json::Value::as_str).unwrap_or("ok"),
                packets = a.get("packets").and_then(serde_json::Value::as_u64),
                "control socket"
            );
            let _ = write(&mut sock, &a).await;
        });
    }
}

/// A root peer's control request.
pub(crate) async fn control_answer(
    request: Result<&Value, &String>,
    packets: Option<Arc<Mutex<pcap::State>>>,
) -> Value {
    let refuse = |code: &str, message: &str| json!({"version": CONTROL_VERSION, "error": code, "message": message});
    let req = match request {
        Ok(v) => v,
        Err(e) => return refuse("bad_request", e),
    };
    if req["version"].as_u64() != Some(u64::from(CONTROL_VERSION)) {
        let mut a = refuse("unsupported_version", "the control socket speaks version 1");
        a["supported"] = json!([1]);
        return a;
    }
    let Some(state) = packets else {
        return refuse(
            "not_available",
            "packets are off: start iohr-capture with --packets (IOHR_CAPTURE_PACKETS=true)",
        );
    };
    let lock_state = || match state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut a = match req["request"].as_str() {
        Some("status") => {
            let s = lock_state();
            let mut v = serde_json::to_value(s.info()).unwrap_or_default();
            v["writing"] = s.files.writing().into();
            v
        }
        Some("pcap") => {
            let prepared = {
                let mut s = lock_state();
                match pcap::request(req, &s.files.settings) {
                    Err(r) => Err(r),
                    Ok(r) if r.next => {
                        let offset = s.offset;
                        s.files.next(&r, offset).map(Ok)
                    }
                    Ok(r) => {
                        let offset = s.offset;
                        let pcap::State { buffer, files, .. } = &mut *s;
                        files.prepare_last(&r, buffer, offset).map(Err)
                    }
                }
            };
            // A `last` file is written off the lock and off the runtime's thread.
            let done = match prepared {
                Err(r) => Err(r),
                Ok(Ok(answer)) => Ok(answer),
                Ok(Err(p)) => tokio::task::spawn_blocking(move || p.write())
                    .await
                    .unwrap_or_else(|_| Err(pcap::Refused::new("io", "the writer failed"))),
            };
            match done {
                Ok(v) => v,
                Err(r) => refuse(r.code, &r.message),
            }
        }
        _ => refuse("unknown_request", "ask for \"pcap\" or \"status\""),
    };
    a["version"] = CONTROL_VERSION.into();
    a
}

/// A client of the aggregates socket (`iohr-capture stats`).
pub(crate) async fn query(path: &Path, request: &str) -> io::Result<Value> {
    send(
        path,
        &json!({"version": WIRE_VERSION, "request": request}),
        Duration::from_secs(5),
    )
    .await
}

/// Sends one request (a JSON object) and reads the answer, within `wait`.
pub(crate) async fn send(path: &Path, request: &Value, wait: Duration) -> io::Result<Value> {
    let mut s = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(path))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
    let line = format!("{request}\n");
    if line.len() > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request longer than 1 KiB",
        ));
    }
    s.write_all(line.as_bytes()).await?;
    let mut out = Vec::new();
    tokio::time::timeout(
        wait,
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
                packets: false,
            },
            &Dropped::for_tests(),
        )))
    }

    #[test]
    fn lookups_are_rate_limited_per_uid() {
        let l = Limiter::default();
        assert!((0..LOOKUPS_PER_SEC).all(|_| l.allow(7)));
        assert!(!l.allow(7));
        assert!(l.allow(8), "another uid has its own budget");
    }

    #[tokio::test]
    async fn control_answers_for_root() {
        // Off: not available.
        let r = json!({"version": 1, "request": "pcap"});
        assert_eq!(control_answer(Ok(&r), None).await["error"], "not_available");
        let dir = std::env::temp_dir().join(format!("iohr-ctl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        pcap::prepare_dir(&dir, None).unwrap();
        let state = Arc::new(Mutex::new(pcap::State::new(
            1 << 20,
            pcap::Settings {
                dir: dir.clone(),
                max_bytes: 1 << 20,
                dir_max_bytes: 1 << 22,
                retention: Duration::from_secs(60),
                linktype: 1,
                snaplen: 65535,
                interface: "lo".into(),
            },
        )));
        let ok = control_answer(
            Ok(&json!({"version": 1, "request": "pcap", "seconds": 10})),
            Some(Arc::clone(&state)),
        )
        .await;
        assert_eq!(ok["version"], 1);
        assert_eq!(ok["packets"], 0);
        assert!(std::path::Path::new(ok["path"].as_str().unwrap()).exists());
        let st = control_answer(
            Ok(&json!({"version": 1, "request": "status"})),
            Some(Arc::clone(&state)),
        )
        .await;
        assert_eq!(st["pcaps_written"], 1);
        assert_eq!(
            control_answer(
                Ok(&json!({"version": 2, "request": "status"})),
                Some(Arc::clone(&state))
            )
            .await["error"],
            "unsupported_version"
        );
        assert_eq!(
            control_answer(
                Ok(&json!({"version": 1, "request": "pcap", "seconds": 999})),
                Some(state)
            )
            .await["error"],
            "bad_request"
        );
        let _ = fs::remove_dir_all(&dir);
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
        let v3 = answer(Ok(&json!({"version": 3, "request": "counts"})), &e, false);
        assert_eq!(v3["error"], "unsupported_version");
        assert_eq!(v3["supported"], json!([1, 2]));
        let v2 = answer(Ok(&json!({"version": 2, "request": "counts"})), &e, true);
        assert_eq!(v2["version"], 2);
        assert!(v2.get("timing").is_some() && v2.get("error").is_none());
        assert_eq!(
            answer(Ok(&json!({"version": 1, "request": "pcap"})), &e, false)["error"],
            "unknown_request"
        );
        // Lookup: version 2 only, for the agent too, numbers only, never a list.
        assert_eq!(
            answer(
                Ok(&json!({"version": 1, "request": "lookup", "owner": "o", "route": "GET /"})),
                &e,
                true
            )["error"],
            "unknown_request"
        );
        let l = answer(
            Ok(
                &json!({"version": 2, "request": "lookup", "owner": "cgroup:/web", "route": "GET /items/{id}"}),
            ),
            &e,
            true,
        );
        assert_eq!(
            (l["version"].as_u64(), l["found"].as_bool()),
            (Some(2), Some(false))
        );
        assert!(!l.to_string().contains("cgroup:/web") && !l.to_string().contains("/items"));
        for bad in [
            json!({"version": 2, "request": "lookup", "owner": "o"}),
            json!({"version": 2, "request": "lookup", "owner": "o", "route": "nospace"}),
            json!({"version": 2, "request": "lookup", "owner": "o".repeat(300), "route": "GET /"}),
        ] {
            assert_eq!(answer(Ok(&bad), &e, true)["error"], "bad_request", "{bad}");
        }
        let agent_v2 = answer(Ok(&json!({"version": 2, "request": "tables"})), &e, true);
        assert_eq!(agent_v2["error"], "forbidden");
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
        prepare_dir(&dir, None, None).unwrap();
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
        tokio::spawn(serve_control(c, None));
        let v = query(&agg, "counts").await.unwrap();
        assert_eq!(v["packet_unit"], "skb");
        let v = send(
            &ctl,
            &json!({"version": 1, "request": "pcap", "seconds": 5}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        // Not root: refused by SO_PEERCRED although this user owns the socket file.
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
