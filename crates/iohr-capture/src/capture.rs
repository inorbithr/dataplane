//! Load, attach, drop privileges, count, report, detach.
//!
//! Order matters and is the point of the phase 0 spike:
//!
//! 1. refuse kernels older than 5.8 or without BTF;
//! 2. load both classifiers and attach them to ingress and egress (TCX on 6.6+, netlink
//!    filters before, after removing filters a killed run left behind);
//! 3. drop capabilities while still single-threaded: everything on TCX; on netlink keep
//!    `CAP_NET_ADMIN` to remove the filters on exit, and before 6.5 also `CAP_BPF`, because
//!    those kernels check it on every `bpf()` call when unprivileged BPF is disabled;
//! 4. only then start the (current-thread) runtime, wait, read the per-CPU counters;
//! 5. detach and print the totals.

use std::{fs, io, time::Duration};

use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray},
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        tc::{self, NlOptions, TcAttachOptions},
    },
};
use iohr_capture_common::{
    COUNTERS_MAP, Counters, EGRESS, EGRESS_PROGRAM, INGRESS, INGRESS_PROGRAM,
};
use rustix::thread::CapabilitySet;
use serde::Serialize;

use crate::{
    AttachMode,
    kernel::{self, Version},
    privileges::{self, Remaining},
};

/// The eBPF object built by build.rs (aya-build) from crates/iohr-capture-ebpf.
static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/iohr-capture"));

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("{0}")]
    Unsupported(String),
    #[error("loading the eBPF object: {0}")]
    Load(#[from] aya::EbpfError),
    #[error("program {0}: {1}")]
    Program(&'static str, aya::programs::ProgramError),
    #[error("program {0} missing from the eBPF object")]
    MissingProgram(&'static str),
    #[error("map {COUNTERS_MAP} missing from the eBPF object")]
    MissingMap,
    #[error(
        "reading counters: {0} (on Linux before 6.5 with unprivileged BPF disabled this needs CAP_BPF)"
    )]
    Map(#[from] aya::maps::MapError),
    #[error("tc on {0}: {1}")]
    Tc(String, tc::TcError),
    #[error("dropping capabilities: {0}")]
    Drop(#[from] privileges::DropError),
    #[error("runtime: {0}")]
    Runtime(#[from] io::Error),
}

/// Totals per direction.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub(crate) struct Direction {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
}

/// What `run` prints on exit. Counts only.
#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub(crate) interface: String,
    pub(crate) kernel: Version,
    /// `tcx` or `netlink`.
    pub(crate) attach: AttachMode,
    pub(crate) seconds: f64,
    /// Stale filters from an earlier run removed before attaching (netlink only).
    pub(crate) stale_filters_removed: usize,
    /// Always `skb`: one socket buffer as TC sees it; with GRO/TSO it can carry several
    /// packets as they were on the wire, so these are not wire packet counts.
    pub(crate) packet_unit: &'static str,
    pub(crate) ingress: Direction,
    pub(crate) egress: Direction,
    /// Capabilities left while counting, read back after the drop.
    pub(crate) capabilities_after_attach: Remaining,
    pub(crate) detached: bool,
}

/// Runs capture on `interface` for `duration` (or until SIGINT/SIGTERM).
pub(crate) fn run(
    interface: &str,
    duration: Option<Duration>,
    mode: AttachMode,
) -> Result<Report, Error> {
    let version = preflight()?;
    let mode = match mode {
        AttachMode::Auto if version >= kernel::TCX => AttachMode::Tcx,
        AttachMode::Auto => AttachMode::Netlink,
        AttachMode::Tcx if version < kernel::TCX => {
            return Err(Error::Unsupported(format!(
                "TCX needs Linux 6.6 or newer; this is {version}"
            )));
        }
        other => other,
    };
    if version < kernel::MEMCG_ACCOUNTING {
        raise_memlock();
    }

    let mut ebpf = Ebpf::load(EBPF_OBJECT)?;
    let mut stale = 0;
    if mode == AttachMode::Netlink {
        // A clsact qdisc may already be there (ours from before, or someone else's).
        if let Err(e) = tc::qdisc_add_clsact(interface) {
            tracing::debug!(error = %e, "clsact qdisc not added (usually: already present)");
        }
        stale = cleanup(interface)?;
    }
    let mut links = Vec::with_capacity(2);
    for (name, hook) in [
        (INGRESS_PROGRAM, TcAttachType::Ingress),
        (EGRESS_PROGRAM, TcAttachType::Egress),
    ] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(Error::MissingProgram(name))?
            .try_into()
            .map_err(|e| Error::Program(name, e))?;
        program.load().map_err(|e| Error::Program(name, e))?;
        let options = if mode == AttachMode::Tcx {
            TcAttachOptions::TcxOrder(LinkOrder::default())
        } else {
            TcAttachOptions::Netlink(NlOptions::default())
        };
        let link = program
            .attach_with_options(interface, hook, options)
            .map_err(|e| Error::Program(name, e))?;
        links.push((name, link));
    }
    let counters: PerCpuArray<MapData, Counters> = ebpf
        .take_map(COUNTERS_MAP)
        .ok_or(Error::MissingMap)?
        .try_into()?;

    let remaining = privileges::drop_all_but(keep_after_attach(mode, version))?;
    let started = std::time::Instant::now();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(wait(duration, interface, mode, &remaining.kept))?;
    let seconds = started.elapsed().as_secs_f64();

    let ingress = total(&counters, INGRESS)?;
    let egress = total(&counters, EGRESS)?;

    let mut detached = true;
    for (name, link) in links {
        let program: Result<&mut SchedClassifier, _> = ebpf
            .program_mut(name)
            .ok_or(Error::MissingProgram(name))?
            .try_into();
        if let Err(e) = program.and_then(|p| p.detach(link)) {
            tracing::warn!(program = name, error = %e, "detach failed; run `iohr-capture cleanup`");
            detached = false;
        }
    }
    drop(ebpf);

    Ok(Report {
        interface: interface.to_owned(),
        kernel: version,
        attach: mode,
        seconds,
        stale_filters_removed: stale,
        packet_unit: "skb",
        ingress,
        egress,
        capabilities_after_attach: remaining,
        detached,
    })
}

/// Removes filters named like ours from the interface's ingress and egress (netlink mode).
/// Returns how many hooks had one. TCX links need no cleanup: they die with their process.
pub(crate) fn cleanup(interface: &str) -> Result<usize, Error> {
    let mut removed = 0;
    for (name, hook) in [
        (INGRESS_PROGRAM, TcAttachType::Ingress),
        (EGRESS_PROGRAM, TcAttachType::Egress),
    ] {
        match tc::qdisc_detach_program(interface, hook, name) {
            Ok(()) => removed += 1,
            Err(tc::TcError::IoError(e)) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                // No clsact qdisc at all means nothing to clean.
                if is_missing_qdisc(&e) {
                    continue;
                }
                return Err(Error::Tc(interface.to_owned(), e));
            }
        }
    }
    Ok(removed)
}

fn is_missing_qdisc(e: &tc::TcError) -> bool {
    let text = e.to_string();
    text.contains("No such file") || text.contains("Invalid argument")
}

/// What stays effective while counting (see the module docs).
fn keep_after_attach(mode: AttachMode, version: Version) -> CapabilitySet {
    let mut keep = CapabilitySet::empty();
    if mode == AttachMode::Netlink {
        keep |= CapabilitySet::NET_ADMIN;
    }
    let restricted = fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
        .map_or(true, |v| v.trim() != "0");
    if version < kernel::UNPRIVILEGED_MAP_ACCESS && restricted {
        keep |= CapabilitySet::BPF;
    }
    keep
}

fn preflight() -> Result<Version, Error> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| Error::Unsupported(format!("cannot read the kernel version: {e}")))?;
    let version = Version::parse(&release).ok_or_else(|| {
        Error::Unsupported(format!("cannot parse kernel version {}", release.trim()))
    })?;
    if version < kernel::MINIMUM {
        return Err(Error::Unsupported(format!(
            "Linux {version} is older than 5.8; capture needs 5.8 or newer with BTF (`iohr-capture doctor`)"
        )));
    }
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(Error::Unsupported(
            "no BTF (/sys/kernel/btf/vmlinux); capture needs a kernel with CONFIG_DEBUG_INFO_BTF (`iohr-capture doctor`)".into(),
        ));
    }
    Ok(version)
}

/// Best effort: kernels before 5.11 charge maps to `RLIMIT_MEMLOCK`.
fn raise_memlock() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let unlimited = Rlimit {
        current: None,
        maximum: None,
    };
    if let Err(e) = setrlimit(Resource::Memlock, unlimited) {
        tracing::warn!(error = %e, "could not raise RLIMIT_MEMLOCK; set LimitMEMLOCK=infinity");
    }
}

fn total(map: &PerCpuArray<MapData, Counters>, direction: u32) -> Result<Direction, Error> {
    let sum = map
        .get(&direction, 0)?
        .iter()
        .fold(Counters::default(), |acc, c| acc.plus(*c));
    Ok(Direction {
        packets: sum.packets,
        bytes: sum.bytes,
    })
}

/// Waits for the duration or a signal. "attached" is logged only once the signal handlers
/// are in place, so a supervisor that signals right after seeing it gets a clean stop.
async fn wait(
    duration: Option<Duration>,
    interface: &str,
    mode: AttachMode,
    kept: &[&str],
) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tracing::info!(interface, attach = ?mode, kept = ?kept, "attached; capabilities dropped; counting");
    let timer = async {
        match duration {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        () = timer => {}
        _ = term.recv() => tracing::info!("SIGTERM"),
        _ = int.recv() => tracing::info!("SIGINT"),
    }
    Ok(())
}
