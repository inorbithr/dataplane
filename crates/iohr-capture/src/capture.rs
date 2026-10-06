//! Load, attach, bind the sockets, drop privileges, then (and only then) read and parse,
//! serve the aggregates, and on exit detach and print the totals.
//!
//! Order matters (ADR 0002):
//!
//! 1. refuse kernels older than 5.8 or without BTF;
//! 2. load the programs, write their settings, attach them to ingress and egress (TCX on
//!    6.6+, netlink filters before, after removing filters a killed run left behind);
//! 3. take the maps and the ring buffer, bind the two Unix sockets (filesystem work);
//! 4. drop capabilities while still single-threaded: everything on TCX; on netlink keep
//!    `CAP_NET_ADMIN` to remove the filters on exit, and before 6.5 also `CAP_BPF`,
//!    because those kernels check it on every `bpf()` call when unprivileged BPF is
//!    disabled. The drop returns the [`Dropped`] proof the parsing engine needs, so
//!    nothing from the kernel is parsed before this point;
//! 5. start the (current-thread) runtime: read the ring buffer, poll the maps and
//!    `sock_diag`, answer the sockets, until the time is up or a signal arrives;
//! 6. detach and print the totals (counts only: the report goes to the journal).

use std::{
    fs, io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use aya::{
    EbpfLoader,
    maps::{Array, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        tc::{self, NlOptions, TcAttachOptions},
    },
};
use iohr_capture_common::{
    CLASS_SLOTS, CLASSES_MAP, CONFIG_HEADERS, CONFIG_MAP, CONFIG_PROTOCOLS, COUNTERS_MAP, Config,
    Counters, EGRESS, EGRESS_PROGRAM, EVENTS_MAP, FLAG_SLOTS, FLAGS_MAP, INGRESS, INGRESS_PROGRAM,
    PORT_ENTRIES, PORTS_MAP, PortCounters, PortKey, STATS_MAP,
};
use rustix::thread::CapabilitySet;
use serde::Serialize;
use tokio::io::unix::AsyncFd;

use crate::{
    AttachMode,
    engine::{Engine, KernelReading, Layers, Settings},
    kernel::{self, Version},
    owners::CgroupIndex,
    privileges::{self, Dropped, Remaining},
    procnet, server, sockdiag,
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
    #[error("map {0} missing from the eBPF object")]
    MissingMap(&'static str),
    #[error(
        "reading a map: {0} (on Linux before 6.5 with unprivileged BPF disabled this needs CAP_BPF)"
    )]
    Map(#[from] aya::maps::MapError),
    #[error("tc on {0}: {1}")]
    Tc(String, tc::TcError),
    #[error("dropping capabilities: {0}")]
    Drop(#[from] privileges::DropError),
    #[error("sockets: {0}")]
    Socket(io::Error),
    #[error("runtime: {0}")]
    Runtime(#[from] io::Error),
}

/// What `run` is asked to do.
#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub(crate) interface: String,
    pub(crate) duration: Option<Duration>,
    pub(crate) mode: AttachMode,
    pub(crate) layers: Layers,
    /// Copies per second per CPU; 0 = no limit.
    pub(crate) samples_per_sec: u64,
    pub(crate) burst: u64,
    pub(crate) ring_buffer_kib: u32,
    pub(crate) first_packets: u32,
    pub(crate) max_flows: usize,
    pub(crate) poll: Duration,
    pub(crate) aggregates: PathBuf,
    pub(crate) control: PathBuf,
    pub(crate) group: String,
    pub(crate) agent_user: String,
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
    /// The aggregates' `counts` answer at exit (numbers only).
    pub(crate) counts: serde_json::Value,
}

struct Maps {
    counters: PerCpuArray<MapData, Counters>,
    classes: PerCpuArray<MapData, Counters>,
    flags: PerCpuArray<MapData, u64>,
    stats: PerCpuArray<MapData, u64>,
    ports: PerCpuHashMap<MapData, PortKey, PortCounters>,
}

/// Runs capture until the duration ends or SIGINT/SIGTERM.
#[allow(clippy::too_many_lines)] // the privileged sequence reads best in one place
pub(crate) fn run(opts: &Options) -> Result<Report, Error> {
    let version = preflight()?;
    let mode = match opts.mode {
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
    let ring_bytes = ring_bytes(opts.ring_buffer_kib);
    let mut ebpf = EbpfLoader::new()
        .map_max_entries(EVENTS_MAP, ring_bytes)
        .load(EBPF_OBJECT)?;
    {
        let mut config: Array<&mut MapData, Config> = ebpf
            .map_mut(CONFIG_MAP)
            .ok_or(Error::MissingMap(CONFIG_MAP))?
            .try_into()?;
        config.set(0, kernel_config(opts, l2_len(&opts.interface)), 0)?;
    }
    let mut stale = 0;
    if mode == AttachMode::Netlink {
        // A clsact qdisc may already be there (ours from before, or someone else's).
        if let Err(e) = tc::qdisc_add_clsact(&opts.interface) {
            tracing::debug!(error = %e, "clsact qdisc not added (usually: already present)");
        }
        stale = cleanup(&opts.interface)?;
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
            .attach_with_options(&opts.interface, hook, options)
            .map_err(|e| Error::Program(name, e))?;
        links.push((name, link));
    }
    let take = |ebpf: &mut aya::Ebpf, name: &'static str| {
        ebpf.take_map(name).ok_or(Error::MissingMap(name))
    };
    let maps = Maps {
        counters: take(&mut ebpf, COUNTERS_MAP)?.try_into()?,
        classes: take(&mut ebpf, CLASSES_MAP)?.try_into()?,
        flags: take(&mut ebpf, FLAGS_MAP)?.try_into()?,
        stats: take(&mut ebpf, STATS_MAP)?.try_into()?,
        ports: take(&mut ebpf, PORTS_MAP)?.try_into()?,
    };
    let ring: RingBuf<MapData> = take(&mut ebpf, EVENTS_MAP)?.try_into()?;

    let own_uid = rustix::process::getuid().as_raw();
    let access = server::Access::lookup(&opts.agent_user, &opts.group, own_uid);
    if access.group_gid.is_none() {
        tracing::warn!(group = %opts.group, "socket group not found; the aggregates socket is 0600 (only root and this user can read it)");
    }
    let bound =
        server::bind(&opts.aggregates, &opts.control, access.group_gid).map_err(Error::Socket)?;

    let (remaining, dropped) = privileges::drop_all_but(keep_after_attach(mode, version))?;
    let started = std::time::Instant::now();
    let engine = Arc::new(Mutex::new(Engine::new(
        Settings {
            interface: opts.interface.clone(),
            layers: opts.layers,
            max_flows: opts.max_flows,
            idle: Duration::from_secs(60),
        },
        &dropped,
    )));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(
            opts, mode, &dropped, &maps, ring, &bound, &engine, access,
        ))?;
    let seconds = started.elapsed().as_secs_f64();

    let ingress = total(&maps.counters, INGRESS)?;
    let egress = total(&maps.counters, EGRESS)?;
    if let Ok(reading) = read_kernel(&maps) {
        lock(&engine).kernel(reading);
    }
    let counts = lock(&engine).counts();
    drop(bound);

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
        interface: opts.interface.clone(),
        kernel: version,
        attach: mode,
        seconds,
        stale_filters_removed: stale,
        packet_unit: "skb",
        ingress,
        egress,
        capabilities_after_attach: remaining,
        detached,
        counts,
    })
}

fn lock(e: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    match e.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// The ring buffer size: a power of two of at least one page.
fn ring_bytes(kib: u32) -> u32 {
    kib.saturating_mul(1024).max(4096).next_power_of_two()
}

/// Settings for the programs.
fn kernel_config(opts: &Options, l2_len: u32) -> Config {
    let interval_ns = 1_000_000_000u64
        .checked_div(opts.samples_per_sec)
        .map_or(0, |i| i.max(1));
    let mut flags = 0;
    if opts.layers.headers {
        flags |= CONFIG_HEADERS;
    }
    if opts.layers.protocols {
        flags |= CONFIG_PROTOCOLS;
    }
    Config {
        interval_ns,
        burst_ns: interval_ns.saturating_mul(opts.burst.max(1)),
        l2_len,
        first_packets: opts.first_packets,
        flags,
        reserved: 0,
    }
}

/// 14 on interfaces with 6-byte link-layer addresses (Ethernet, Wi-Fi, veth, loopback
/// reports 6 too), 0 on L3 devices (`WireGuard`, tun) that have none.
fn l2_len(interface: &str) -> u32 {
    let valid = !interface.contains('/') && interface != "." && interface != "..";
    let len = valid
        .then(|| fs::read_to_string(format!("/sys/class/net/{interface}/addr_len")).ok())
        .flatten();
    match len.as_deref().map(str::trim) {
        Some("0") => 0,
        _ => 14,
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    opts: &Options,
    mode: AttachMode,
    dropped: &Dropped,
    maps: &Maps,
    ring: RingBuf<MapData>,
    bound: &server::Bound,
    engine: &Arc<Mutex<Engine>>,
    access: server::Access,
) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let agg = tokio::net::UnixListener::from_std(bound.aggregates.try_clone()?)?;
    let ctl = tokio::net::UnixListener::from_std(bound.control.try_clone()?)?;
    let servers = [
        tokio::spawn(server::serve_aggregates(
            agg,
            Arc::clone(engine),
            Arc::new(access),
        )),
        tokio::spawn(server::serve_control(ctl)),
    ];
    let mut ring = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;
    let mut poll = tokio::time::interval(opts.poll);
    let mut cgroups = CgroupIndex::new(
        std::path::Path::new("/sys/fs/cgroup"),
        std::path::Path::new("/proc"),
    );
    let users = crate::owners::users(&fs::read_to_string("/etc/passwd").unwrap_or_default());
    let deep = opts.layers.owners || opts.layers.tcp;
    tracing::info!(
        interface = %opts.interface, attach = ?mode, kept = ?dropped.kept,
        layers = ?opts.layers.names(), aggregates = %opts.aggregates.display(),
        "attached; capabilities dropped; counting"
    );
    let timer = async {
        match opts.duration {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(timer);
    loop {
        tokio::select! {
            () = &mut timer => break,
            _ = term.recv() => { tracing::info!("SIGTERM"); break }
            _ = int.recv() => { tracing::info!("SIGINT"); break }
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let mut e = lock(engine);
                // Bounded per wake-up so the sockets and the poll are served under load.
                for _ in 0..8192 {
                    let Some(item) = guard.get_inner_mut().next() else { break };
                    e.ingest(&item);
                }
                drop(e);
                guard.clear_ready();
            }
            _ = poll.tick() => {
                match read_kernel(maps) {
                    Ok(r) => lock(engine).kernel(r),
                    Err(err) => tracing::warn!(error = %err, "reading the counters failed"),
                }
                if deep {
                    let dump = sockdiag::dump();
                    let host = procnet::read(std::path::Path::new("/proc"));
                    lock(engine).sockets(dump, host, &mut cgroups, &users);
                }
                lock(engine).tick();
            }
        }
    }
    for s in servers {
        s.abort();
    }
    Ok(())
}

fn read_kernel(m: &Maps) -> Result<KernelReading, Error> {
    let mut r = KernelReading::default();
    for d in [INGRESS, EGRESS] {
        let di = d as usize;
        let t = total(&m.counters, d)?;
        r.totals[di] = (t.packets, t.bytes);
        for (i, slot) in r.classes[di].iter_mut().enumerate() {
            let c = sum(&m.classes, d * CLASS_SLOTS + u32::try_from(i).unwrap_or(0))?;
            *slot = (c.packets, c.bytes);
        }
        for (i, slot) in r.flags[di].iter_mut().enumerate() {
            *slot = sum_u64(&m.flags, d * FLAG_SLOTS + u32::try_from(i).unwrap_or(0))?;
        }
    }
    for (i, slot) in r.stats.iter_mut().enumerate() {
        *slot = sum_u64(&m.stats, u32::try_from(i).unwrap_or(0))?;
    }
    for item in m.ports.iter().take(PORT_ENTRIES as usize) {
        let (k, values) = item?;
        let c = values
            .iter()
            .fold(PortCounters::default(), |acc, v| acc.plus(*v));
        r.ports.push((k, c));
    }
    Ok(r)
}

fn sum(map: &PerCpuArray<MapData, Counters>, index: u32) -> Result<Counters, Error> {
    Ok(map
        .get(&index, 0)?
        .iter()
        .fold(Counters::default(), |acc, c| acc.plus(*c)))
}

fn sum_u64(map: &PerCpuArray<MapData, u64>, index: u32) -> Result<u64, Error> {
    Ok(map
        .get(&index, 0)?
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(*c)))
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
    let s = sum(map, direction)?;
    Ok(Direction {
        packets: s.packets,
        bytes: s.bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_sizes_are_powers_of_two() {
        assert_eq!(ring_bytes(0), 4096);
        assert_eq!(ring_bytes(4), 4096);
        assert_eq!(ring_bytes(4096), 4 * 1024 * 1024);
        assert_eq!(ring_bytes(3000), 4 * 1024 * 1024);
    }

    #[test]
    fn token_bucket_settings() {
        let opts = Options {
            interface: "lo".into(),
            duration: None,
            mode: AttachMode::Auto,
            layers: Layers::parse("headers,protocols,owners,tcp").unwrap(),
            samples_per_sec: 2000,
            burst: 500,
            ring_buffer_kib: 4096,
            first_packets: 8,
            max_flows: 16_384,
            poll: Duration::from_secs(2),
            aggregates: "/run/iohr-capture/aggregates.sock".into(),
            control: "/run/iohr-capture/control.sock".into(),
            group: "iohr-agent".into(),
            agent_user: "iohr-agent".into(),
        };
        let c = kernel_config(&opts, 14);
        assert_eq!(c.interval_ns, 500_000);
        assert_eq!(c.burst_ns, 250_000_000);
        assert_eq!(c.flags, CONFIG_HEADERS | CONFIG_PROTOCOLS);
        let unlimited = kernel_config(
            &Options {
                samples_per_sec: 0,
                ..opts
            },
            0,
        );
        assert_eq!(unlimited.interval_ns, 0);
        assert_eq!(unlimited.l2_len, 0);
    }
}
