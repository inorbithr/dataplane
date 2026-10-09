//! The parser process (privilege separation, ADR 0002).
//!
//! `iohr-capture run` keeps the capabilities some kernels still need after attaching
//! (`CAP_NET_ADMIN` to remove netlink filters before 6.6, `CAP_BPF` to read maps before 6.5)
//! and does nothing with packet bytes but copy them. It starts this process
//! (`iohr-capture worker`, internal) with a pipe as standard input and writes framed
//! ring-buffer records and map readings into it. The worker drops every capability before
//! anything else, so all parsing, the flow table, `sock_diag`, the cgroup walk, both
//! sockets, the packet buffer and the pcap files (layer 3) run with an empty capability
//! set on every kernel. When the pipe closes it prints its last `counts` answer (numbers
//! only) on standard output and exits.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::thread::CapabilitySet;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::engine::{Engine, KernelReading, Layers, Settings};
use crate::owners::CgroupIndex;
use crate::{pcap, privileges, procnet, server, sockdiag};

/// Frame kinds on the pipe.
pub(crate) const FRAME_RECORD: u8 = 1;
pub(crate) const FRAME_KERNEL: u8 = 2;
/// A whole packet from the packets ring buffer (layer 3).
pub(crate) const FRAME_PACKET: u8 = 3;
/// Largest frame accepted.
pub(crate) const MAX_FRAME: usize = 1024 * 1024;

/// Appends one frame (kind, little-endian length, payload). A payload larger than
/// [`MAX_FRAME`] is not framed (the reader would refuse it); returns whether it was.
pub(crate) fn frame(kind: u8, payload: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(len) = u32::try_from(payload.len())
        .ok()
        .filter(|l| *l as usize <= MAX_FRAME)
    else {
        return false;
    };
    out.push(kind);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    true
}

/// Reads one frame; `None` at end of input.
///
/// # Errors
/// When the stream breaks or a frame is larger than [`MAX_FRAME`].
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<u8>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    buf.resize(len, 0);
    r.read_exact(buf).await?;
    Ok(Some(head[0]))
}

/// What the worker is told (one JSON argument).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    /// The interfaces joined with commas, for people.
    pub(crate) interface: String,
    /// The interfaces in slot order.
    #[serde(default)]
    pub(crate) interfaces: Vec<String>,
    pub(crate) layers: String,
    pub(crate) max_flows: usize,
    pub(crate) poll_ms: u64,
    pub(crate) aggregates: PathBuf,
    pub(crate) control: PathBuf,
    pub(crate) group: String,
    pub(crate) agent_user: String,
    pub(crate) companion_kept: Vec<String>,
    /// Layer 3: `None` when packets are off.
    #[serde(default)]
    pub(crate) packets: Option<PacketsConfig>,
}

/// Layer 3 settings for the parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PacketsConfig {
    pub(crate) buffer_bytes: usize,
    pub(crate) dir: PathBuf,
    pub(crate) max_bytes: u64,
    pub(crate) dir_max_bytes: u64,
    pub(crate) retention_secs: u64,
    pub(crate) snaplen: u32,
    /// 1 (Ethernet) or 101 (raw IP).
    pub(crate) linktype: u16,
}

/// Runs the worker; returns the last `counts` answer.
///
/// # Errors
/// When the capabilities cannot be dropped, the sockets cannot be bound, or the pipe
/// breaks.
pub(crate) fn run(config: &str) -> Result<serde_json::Value, String> {
    let cfg: Config = serde_json::from_str(config).map_err(|e| format!("worker config: {e}"))?;
    // Never parse as root, even with no capability: root owns /etc and /run.
    if rustix::process::geteuid().is_root() {
        return Err(
            "the parser refuses to run as root (`run` starts it as iohr-capture or nobody)".into(),
        );
    }
    // Only standard input, output and error may come from `run`.
    let inherited = inherited_fds();
    if !inherited.is_empty() {
        return Err(format!(
            "the parser inherited open files {inherited:?}; refusing"
        ));
    }
    // First thing, while single-threaded: no capability at all from here on.
    let (_, dropped) =
        privileges::drop_all_but(CapabilitySet::empty()).map_err(|e| e.to_string())?;
    if !dropped.kept.is_empty() {
        return Err(format!("parser kept {:?}", dropped.kept));
    }
    let layers = Layers::parse(&cfg.layers)?;
    let engine = Arc::new(Mutex::new(Engine::new(
        Settings {
            interface: cfg.interface.clone(),
            interfaces: cfg.interfaces.clone(),
            layers,
            max_flows: cfg.max_flows,
            idle: Duration::from_secs(60),
            companion_kept: cfg.companion_kept.clone(),
            packets: cfg.packets.is_some(),
        },
        &dropped,
    )));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(serve(&cfg, layers, &engine))?;
    let counts = lock(&engine).counts();
    Ok(counts)
}

/// File descriptors above 2 open at start, other than the one listing them.
fn inherited_fds() -> Vec<u32> {
    let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| {
            let fd: u32 = e.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(e.path()).ok()?;
            // The directory being read shows up as an open file of its own.
            (fd > 2 && !target.to_string_lossy().contains("/fd")).then_some(fd)
        })
        .collect()
}

fn lock_packets(p: &Mutex<pcap::State>) -> std::sync::MutexGuard<'_, pcap::State> {
    match p.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock(e: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    match e.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

#[allow(clippy::too_many_lines)] // the parser's tasks, started and stopped in one place
async fn serve(cfg: &Config, layers: Layers, engine: &Arc<Mutex<Engine>>) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};
    // The privileged process decides when to stop: it closes the pipe. A signal to the
    // whole group (systemd, Ctrl-C) must not cut the last answer short.
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let bound = server::bind(&cfg.aggregates, &cfg.control).map_err(|e| format!("sockets: {e}"))?;
    let packets = cfg.packets.as_ref().map(|p| {
        let mut state = pcap::State::new(
            p.buffer_bytes,
            pcap::Settings {
                dir: p.dir.clone(),
                max_bytes: p.max_bytes,
                dir_max_bytes: p.dir_max_bytes,
                retention: Duration::from_secs(p.retention_secs),
                linktype: p.linktype,
                snaplen: p.snaplen,
                interface: cfg.interface.clone(),
            },
        );
        // Files a previous run left past their retention go now.
        state.files.sweep();
        Arc::new(Mutex::new(state))
    });
    let own_uid = rustix::process::getuid().as_raw();
    let access = server::Access::lookup(&cfg.agent_user, &cfg.group, own_uid);
    let agg = tokio::net::UnixListener::from_std(
        bound.aggregates.try_clone().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let ctl =
        tokio::net::UnixListener::from_std(bound.control.try_clone().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let servers = [
        tokio::spawn(server::serve_aggregates(
            agg,
            Arc::clone(engine),
            Arc::new(access),
        )),
        tokio::spawn(server::serve_control(ctl, packets.clone())),
    ];
    let ignore_signals = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
    });
    let poller = {
        let engine = Arc::clone(engine);
        let packets = packets.clone();
        let poll_ms = cfg.poll_ms;
        tokio::spawn(async move {
            let new_index = || {
                CgroupIndex::new(
                    std::path::Path::new("/sys/fs/cgroup"),
                    std::path::Path::new("/proc"),
                )
            };
            let mut cgroups = Some(new_index());
            let users = Arc::new(crate::owners::users(
                &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
            ));
            let deep = layers.owners || layers.tcp;
            let mut poll = tokio::time::interval(Duration::from_millis(poll_ms));
            loop {
                poll.tick().await;
                if deep && let Some(mut idx) = cgroups.take() {
                    // Netlink, /proc and the cgroup walk block: on their own thread, and the
                    // engine is locked only to apply the result, so frames keep flowing.
                    let engine = Arc::clone(&engine);
                    let users = Arc::clone(&users);
                    let back = tokio::task::spawn_blocking(move || {
                        let dump = sockdiag::dump();
                        let host = procnet::read(std::path::Path::new("/proc"));
                        let resolved = match &dump {
                            Ok(socks) => crate::owners::resolve(socks, &mut idx),
                            Err(_) => std::collections::HashMap::new(),
                        };
                        lock(&engine).sockets(dump, host, &resolved, &users);
                        idx
                    })
                    .await;
                    cgroups = Some(back.unwrap_or_else(|_| new_index()));
                }
                if let Some(p) = &packets {
                    let info = {
                        let mut st = lock_packets(p);
                        st.tick();
                        st.info()
                    };
                    lock(&engine).packets = info;
                }
                lock(&engine).tick();
            }
        })
    };
    // Frames are read in this loop only (reading a frame is not cancel-safe, so nothing
    // races it).
    let mut stdin = tokio::io::BufReader::with_capacity(256 * 1024, tokio::io::stdin());
    let mut buf = Vec::with_capacity(4096);
    let result = loop {
        match read_frame(&mut stdin, &mut buf).await {
            Ok(None) => break Ok(()),
            Ok(Some(FRAME_RECORD)) => lock(engine).ingest(&buf),
            Ok(Some(FRAME_PACKET)) => {
                if let (Some(p), Some(packet)) = (&packets, pcap::Packet::parse(&buf)) {
                    lock_packets(p).push(packet);
                }
            }
            Ok(Some(FRAME_KERNEL)) => match serde_json::from_slice::<KernelReading>(&buf) {
                Ok(r) => lock(engine).kernel(r),
                Err(e) => tracing::warn!(error = %e, "a map reading did not parse"),
            },
            Ok(Some(_)) => {}
            Err(e) => break Err(format!("pipe from the privileged process: {e}")),
        }
    };
    ignore_signals.abort();
    poller.abort();
    for s in servers {
        s.abort();
    }
    drop(bound);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_bound() {
        let mut out = Vec::new();
        assert!(frame(FRAME_RECORD, b"abc", &mut out));
        assert!(frame(FRAME_KERNEL, b"{}", &mut out));
        let mut none = Vec::new();
        assert!(!frame(FRAME_RECORD, &vec![0; MAX_FRAME + 1], &mut none));
        assert_eq!(none, Vec::<u8>::new());
        let mut r = &out[..];
        let mut buf = Vec::new();
        assert_eq!(
            read_frame(&mut r, &mut buf).await.unwrap(),
            Some(FRAME_RECORD)
        );
        assert_eq!(buf, b"abc");
        assert_eq!(
            read_frame(&mut r, &mut buf).await.unwrap(),
            Some(FRAME_KERNEL)
        );
        assert_eq!(read_frame(&mut r, &mut buf).await.unwrap(), None);
        let mut big = vec![FRAME_RECORD];
        big.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut r = &big[..];
        assert!(read_frame(&mut r, &mut buf).await.is_err());
    }
}
