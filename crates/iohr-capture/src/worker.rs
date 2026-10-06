//! The parser process (privilege separation, ADR 0002).
//!
//! `iohr-capture run` keeps the capabilities some kernels still need after attaching
//! (`CAP_NET_ADMIN` to remove netlink filters before 6.6, `CAP_BPF` to read maps before 6.5)
//! and does nothing with packet bytes but copy them. It starts this process
//! (`iohr-capture worker`, internal) with a pipe as standard input and writes framed
//! ring-buffer records and map readings into it. The worker drops every capability before
//! anything else, so all parsing, the flow table, `sock_diag`, the cgroup walk and both
//! sockets run with an empty capability set on every kernel. When the pipe closes it
//! prints its last `counts` answer (numbers only) on standard output and exits.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::thread::CapabilitySet;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::engine::{Engine, KernelReading, Layers, Settings};
use crate::owners::CgroupIndex;
use crate::{privileges, procnet, server, sockdiag};

/// Frame kinds on the pipe.
pub(crate) const FRAME_RECORD: u8 = 1;
pub(crate) const FRAME_KERNEL: u8 = 2;
/// Largest frame accepted.
pub(crate) const MAX_FRAME: usize = 1024 * 1024;

/// One frame: kind, little-endian length, payload.
pub(crate) fn frame(kind: u8, payload: &[u8], out: &mut Vec<u8>) {
    out.push(kind);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(payload);
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
    pub(crate) interface: String,
    pub(crate) layers: String,
    pub(crate) max_flows: usize,
    pub(crate) poll_ms: u64,
    pub(crate) aggregates: PathBuf,
    pub(crate) control: PathBuf,
    pub(crate) group: String,
    pub(crate) agent_user: String,
    pub(crate) companion_kept: Vec<String>,
}

/// Runs the worker; returns the last `counts` answer.
///
/// # Errors
/// When the capabilities cannot be dropped, the sockets cannot be bound, or the pipe
/// breaks.
pub(crate) fn run(config: &str) -> Result<serde_json::Value, String> {
    let cfg: Config = serde_json::from_str(config).map_err(|e| format!("worker config: {e}"))?;
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
            layers,
            max_flows: cfg.max_flows,
            idle: Duration::from_secs(60),
            companion_kept: cfg.companion_kept.clone(),
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

fn lock(e: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    match e.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

async fn serve(cfg: &Config, layers: Layers, engine: &Arc<Mutex<Engine>>) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};
    // The privileged process decides when to stop: it closes the pipe. A signal to the
    // whole group (systemd, Ctrl-C) must not cut the last answer short.
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let bound = server::bind(&cfg.aggregates, &cfg.control).map_err(|e| format!("sockets: {e}"))?;
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
        tokio::spawn(server::serve_control(ctl)),
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
        let poll_ms = cfg.poll_ms;
        tokio::spawn(async move {
            let mut cgroups = CgroupIndex::new(
                std::path::Path::new("/sys/fs/cgroup"),
                std::path::Path::new("/proc"),
            );
            let users =
                crate::owners::users(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
            let deep = layers.owners || layers.tcp;
            let mut poll = tokio::time::interval(Duration::from_millis(poll_ms));
            loop {
                poll.tick().await;
                if deep {
                    let dump = sockdiag::dump();
                    let host = procnet::read(std::path::Path::new("/proc"));
                    lock(&engine).sockets(dump, host, &mut cgroups, &users);
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
        frame(FRAME_RECORD, b"abc", &mut out);
        frame(FRAME_KERNEL, b"{}", &mut out);
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
