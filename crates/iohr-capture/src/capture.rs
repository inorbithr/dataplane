//! Load, attach, prepare the sockets' directory, drop privileges, start the parser
//! process, relay, and on exit detach and print the totals.
//!
//! Order matters (ADR 0002):
//!
//! 1. refuse kernels older than 5.8 or without BTF;
//! 2. load the programs, write their settings, attach them to ingress and egress (TCX on
//!    6.6+, netlink filters before, after removing filters a killed run left behind);
//! 3. take the maps and the ring buffers, prepare the sockets' directory and, with
//!    packets on, the pcap directory (filesystem work);
//! 4. drop capabilities while still single-threaded: everything on TCX; on netlink keep
//!    `CAP_NET_ADMIN` to remove the filters on exit, and before 6.5 also `CAP_BPF`,
//!    because those kernels check it on every `bpf()` call when unprivileged BPF is
//!    disabled;
//! 5. start the parser process (`worker`), which drops every capability before it does
//!    anything, and relay ring-buffer records and map readings to it over a pipe until the
//!    time is up or a signal arrives. This process never looks inside a record;
//! 6. close the pipe, take the parser's last `counts`, detach and print the totals
//!    (counts only: the report goes to the journal).

use std::{fs, io, path::PathBuf, time::Duration};

use aya::{
    EbpfLoader,
    maps::{Array, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        tc::{self, NlOptions, TcAttachOptions},
    },
};
use iohr_capture_common::{
    CLASS_SLOTS, CLASSES_MAP, CONFIG_HEADERS, CONFIG_MAP, CONFIG_PACKETS, CONFIG_PROTOCOLS,
    CONFIG_TIMING, COUNTERS_MAP, Config, Counters, EGRESS, EGRESS_PROGRAM, EVENTS_MAP, FLAG_SLOTS,
    FLAGS_MAP, INGRESS, INGRESS_PROGRAM, MAX_SNAPLEN, PACKETS_MAP, PORT_ENTRIES, PORTS_MAP,
    PortCounters, PortKey, STATS_MAP,
};
use rustix::thread::CapabilitySet;
use serde::Serialize;
use tokio::io::unix::AsyncFd;

use crate::{
    AttachMode,
    engine::{KernelReading, Layers, PortRow},
    kernel::{self, Version},
    privileges::{self, Remaining},
    server,
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
    /// Layer 3, `None` when off.
    pub(crate) packets: Option<PacketOptions>,
}

/// Layer 3 settings (`--packets` and friends).
#[derive(Debug, Clone)]
pub(crate) struct PacketOptions {
    pub(crate) snaplen: u32,
    /// Copies per second per CPU; 0 = no limit.
    pub(crate) per_sec: u64,
    pub(crate) burst: u64,
    pub(crate) ring_kib: u32,
    pub(crate) buffer_mib: u32,
    pub(crate) pcap_dir: PathBuf,
    pub(crate) pcap_max_bytes: u64,
    pub(crate) pcap_dir_max_bytes: u64,
    pub(crate) pcap_retention_secs: u64,
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
    let events_size = ring_bytes(opts.ring_buffer_kib);
    // Packets off: the second ring is one page (its programs never reach it).
    let whole_size = opts
        .packets
        .as_ref()
        .map_or(4096, |p| ring_bytes(p.ring_kib.max(256)));
    let mut ebpf = EbpfLoader::new()
        .map_max_entries(EVENTS_MAP, events_size)
        .map_max_entries(PACKETS_MAP, whole_size)
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
    let packet_ring: Option<RingBuf<MapData>> = if opts.packets.is_some() {
        Some(take(&mut ebpf, PACKETS_MAP)?.try_into()?)
    } else {
        None
    };

    // The sockets' directory gets the read group and the set-group-id bit now, while
    // privileged: the parser process creates its sockets there without any chown.
    let own_uid = rustix::process::getuid().as_raw();
    let access = server::Access::lookup(&opts.agent_user, &opts.group, own_uid);
    if access.group_gid.is_none() {
        tracing::warn!(group = %opts.group, "socket group not found; the aggregates socket belongs to this process's group");
    }
    access.warn_if_unguarded(&opts.agent_user);
    // Run by hand as root, the parser still must not be root: it runs as `iohr-capture`
    // (or nobody), and the sockets' directory is made its own.
    let parser = parser_identity(&access);
    for dir in [opts.aggregates.parent(), opts.control.parent()]
        .into_iter()
        .flatten()
    {
        server::prepare_dir(dir, parser.map(|(u, _)| u), access.group_gid)
            .map_err(Error::Socket)?;
    }
    if let Some(p) = &opts.packets {
        crate::pcap::prepare_dir(&p.pcap_dir, parser.map(|(u, _)| u)).map_err(Error::Socket)?;
    }

    let keep = keep_after_attach(mode, version);
    let started = std::time::Instant::now();
    let worker = crate::worker::Config {
        interface: opts.interface.clone(),
        layers: opts.layers.names().join(","),
        max_flows: opts.max_flows,
        poll_ms: u64::try_from(opts.poll.as_millis()).unwrap_or(2000),
        aggregates: opts.aggregates.clone(),
        control: opts.control.clone(),
        group: opts.group.clone(),
        agent_user: opts.agent_user.clone(),
        companion_kept: privileges::NAMED
            .iter()
            .filter(|(c, _)| keep.contains(*c))
            .map(|(_, n)| (*n).to_owned())
            .collect(),
        packets: opts.packets.as_ref().map(|p| crate::worker::PacketsConfig {
            buffer_bytes: p.buffer_mib.clamp(1, 128) as usize * 1024 * 1024,
            dir: p.pcap_dir.clone(),
            max_bytes: p.pcap_max_bytes,
            dir_max_bytes: p.pcap_dir_max_bytes,
            retention_secs: p.pcap_retention_secs,
            snaplen: p.snaplen,
            linktype: if l2_len(&opts.interface) == 14 {
                1
            } else {
                101
            },
        }),
    };
    let (counts, remaining) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            // The parser is started first, while this process may still change its user;
            // then this process drops (still one thread: the runtime has no other).
            let child = spawn_parser(&worker, parser)?;
            let (remaining, _) = privileges::drop_all_but(keep)?;
            let counts = relay(opts, mode, &remaining, &maps, ring, packet_ring, child).await?;
            Ok::<_, Error>((counts, remaining))
        })?;
    let seconds = started.elapsed().as_secs_f64();

    let ingress = total(&maps.counters, INGRESS)?;
    let egress = total(&maps.counters, EGRESS)?;

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

/// The ring buffer size: a power of two of at least one page.
fn ring_bytes(kib: u32) -> u32 {
    // At most 32 MiB (the unit's MemoryMax=256M also holds the flow table), so the power
    // of two never overflows.
    kib.clamp(4, 32 * 1024)
        .saturating_mul(1024)
        .next_power_of_two()
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
    if opts.layers.timing {
        flags |= CONFIG_TIMING;
    }
    let (snaplen, pkt_interval_ns, pkt_burst) = match &opts.packets {
        Some(p) => {
            flags |= CONFIG_PACKETS;
            let i = 1_000_000_000u64
                .checked_div(p.per_sec)
                .map_or(0, |i| i.max(1));
            (p.snaplen.clamp(64, MAX_SNAPLEN), i, p.burst.max(1))
        }
        None => (0, 0, 1),
    };
    Config {
        interval_ns,
        burst_ns: interval_ns.saturating_mul(opts.burst.max(1)),
        l2_len,
        first_packets: opts.first_packets,
        flags,
        snaplen,
        pkt_interval_ns,
        pkt_burst_ns: pkt_interval_ns.saturating_mul(pkt_burst),
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

/// How long one write to the parser may block (a stuck parser must not keep this process
/// from answering SIGTERM within the unit's stop timeout).
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

async fn send(to: &mut tokio::process::ChildStdin, bytes: &[u8]) -> io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    tokio::time::timeout(WRITE_TIMEOUT, to.write_all(bytes))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "the parser process stopped reading",
            )
        })?
}

/// The user and group the parser runs as when this process is root: `iohr-capture`, or
/// nobody, and the read group (`None`: this process is not root, the parser inherits its
/// user, as under the unit).
fn parser_identity(access: &server::Access) -> Option<(u32, u32)> {
    if !rustix::process::geteuid().is_root() {
        return None;
    }
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let (uid, primary) = passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&"iohr-capture"))
                .then(|| Some((f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?)))
                .flatten()
        })
        .unwrap_or((65_534, 65_534));
    Some((uid, access.group_gid.unwrap_or(primary)))
}

/// Starts `iohr-capture worker` with pipes for input and output; as another user when
/// `identity` says so (supplementary groups are cleared).
fn spawn_parser(
    config: &crate::worker::Config,
    identity: Option<(u32, u32)>,
) -> Result<tokio::process::Child, Error> {
    let exe = std::env::current_exe()?;
    let config = serde_json::to_string(config).unwrap_or_default();
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["worker", "--config", &config])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some((uid, gid)) = identity {
        cmd.uid(uid).gid(gid);
    }
    Ok(cmd.spawn()?)
}

/// Records handed to the parser per wake-up of the ring buffer before the other events
/// get a turn.
const BATCH: usize = 8192;
/// And at most this many bytes of them (whole packets are up to 64 KiB each).
const BATCH_BYTES: usize = 1024 * 1024;

type Ring = AsyncFd<RingBuf<MapData>>;

/// Waits until the packets ring has records; never, when packets are off.
async fn readable(
    r: &mut Option<Ring>,
) -> io::Result<tokio::io::unix::AsyncFdReadyMutGuard<'_, RingBuf<MapData>>> {
    match r {
        Some(r) => r.readable_mut().await,
        None => std::future::pending().await,
    }
}

/// Frames up to [`BATCH`] records of a ready ring into `batch`; true when the ring is
/// empty (readiness is cleared then).
fn drain(
    guard: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, RingBuf<MapData>>,
    kind: u8,
    batch: &mut Vec<u8>,
) -> bool {
    batch.clear();
    for _ in 0..BATCH {
        if batch.len() >= BATCH_BYTES {
            return false;
        }
        if let Some(item) = guard.get_inner_mut().next() {
            let _ = crate::worker::frame(kind, &item, batch);
        } else {
            // Readiness is cleared only once the ring is empty: the kernel wakes a reader
            // when the consumer catches up with the producer, so clearing with records
            // left would wait for a wake-up that never comes.
            guard.clear_ready();
            return true;
        }
    }
    false
}

/// The privileged process's loop: copy ring-buffer records and map readings to the parser
/// process (never parse them), until the time is up or a signal arrives; then close the
/// pipe and collect the parser's last `counts`.
#[allow(clippy::too_many_lines)] // one select loop reads best in one place
async fn relay(
    opts: &Options,
    mode: AttachMode,
    remaining: &Remaining,
    maps: &Maps,
    ring: RingBuf<MapData>,
    packet_ring: Option<RingBuf<MapData>>,
    mut child: tokio::process::Child,
) -> Result<serde_json::Value, Error> {
    use crate::worker::{FRAME_KERNEL, FRAME_PACKET, FRAME_RECORD, frame};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut to_parser = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no pipe to the parser"))?;
    let mut from_parser = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no pipe from the parser"))?;
    let mut ring = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)?;
    let mut packet_ring = match packet_ring {
        Some(r) => Some(AsyncFd::with_interest(r, tokio::io::Interest::READABLE)?),
        None => None,
    };
    let mut poll = tokio::time::interval(opts.poll);
    let mut last_warn: Option<std::time::Instant> = None;
    tracing::info!(
        interface = %opts.interface, attach = ?mode, kept = ?remaining.kept,
        parser_pid = ?child.id(), layers = ?opts.layers.names(),
        aggregates = %opts.aggregates.display(),
        "attached; capabilities dropped; the parser process has none; counting"
    );
    let timer = async {
        match opts.duration {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(timer);
    let mut batch: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let outcome: Result<(), Error> = loop {
        tokio::select! {
            () = &mut timer => break Ok(()),
            _ = term.recv() => { tracing::info!("SIGTERM"); break Ok(()) }
            _ = int.recv() => { tracing::info!("SIGINT"); break Ok(()) }
            status = child.wait() => {
                break Err(Error::Runtime(io::Error::other(format!("the parser process exited ({status:?})"))));
            }
            guard = ring.readable_mut() => {
                let mut guard = guard?;
                let drained = drain(&mut guard, FRAME_RECORD, &mut batch);
                drop(guard);
                if let Err(e) = send(&mut to_parser, &batch).await {
                    break Err(Error::Runtime(e));
                }
                if !drained {
                    tokio::task::yield_now().await;
                }
            }
            guard = readable(&mut packet_ring) => {
                let mut guard = guard?;
                let drained = drain(&mut guard, FRAME_PACKET, &mut batch);
                drop(guard);
                if let Err(e) = send(&mut to_parser, &batch).await {
                    break Err(Error::Runtime(e));
                }
                if !drained {
                    tokio::task::yield_now().await;
                }
            }
            _ = poll.tick() => {
                match read_kernel(maps) {
                    Ok(r) => {
                        batch.clear();
                        let _ = frame(FRAME_KERNEL, &serde_json::to_vec(&r).unwrap_or_default(), &mut batch);
                        if let Err(e) = send(&mut to_parser, &batch).await {
                            break Err(Error::Runtime(e));
                        }
                    }
                    Err(err) => {
                        // At most once a minute: a failing read repeats every poll.
                        if last_warn.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                            tracing::warn!(error = %err, "reading the counters failed");
                            last_warn = Some(std::time::Instant::now());
                        }
                    }
                }
            }
        }
    };
    // One last reading, then end of input: the parser answers with its last counts.
    if outcome.is_ok()
        && let Ok(r) = read_kernel(maps)
    {
        batch.clear();
        frame(
            FRAME_KERNEL,
            &serde_json::to_vec(&r).unwrap_or_default(),
            &mut batch,
        );
        let _ = send(&mut to_parser, &batch).await;
    }
    let _ = to_parser.flush().await;
    drop(to_parser);
    let mut out = Vec::new();
    let read = tokio::time::timeout(
        Duration::from_secs(10),
        (&mut from_parser)
            .take(server::MAX_ANSWER as u64)
            .read_to_end(&mut out),
    )
    .await;
    if read.is_err() {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
    outcome?;
    Ok(serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null))
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
        r.ports.push(PortRow {
            port: k.port,
            proto: k.proto,
            direction: k.direction,
            packets: c.packets,
            bytes: c.bytes,
            syn: c.syn,
            rst: c.rst,
        });
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
        assert_eq!(ring_bytes(u32::MAX), 32 * 1024 * 1024);
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
            group: "iohr-capture-read".into(),
            agent_user: "iohr-agent".into(),
            packets: None,
        };
        let c = kernel_config(&opts, 14);
        assert_eq!(c.interval_ns, 500_000);
        assert_eq!(c.burst_ns, 250_000_000);
        assert_eq!(c.flags, CONFIG_HEADERS | CONFIG_PROTOCOLS);
        assert_eq!((c.snaplen, c.pkt_interval_ns), (0, 0));
        let p = kernel_config(
            &Options {
                layers: Layers::parse("headers,protocols,timing").unwrap(),
                packets: Some(PacketOptions {
                    snaplen: 100_000,
                    per_sec: 1000,
                    burst: 200,
                    ring_kib: 8192,
                    buffer_mib: 32,
                    pcap_dir: "/var/lib/iohr-capture/pcap".into(),
                    pcap_max_bytes: 1 << 26,
                    pcap_dir_max_bytes: 1 << 29,
                    pcap_retention_secs: 3600,
                }),
                ..opts.clone()
            },
            14,
        );
        assert_eq!(
            p.flags,
            CONFIG_HEADERS | CONFIG_PROTOCOLS | CONFIG_TIMING | CONFIG_PACKETS
        );
        assert_eq!(p.snaplen, MAX_SNAPLEN);
        assert_eq!(
            (p.pkt_interval_ns, p.pkt_burst_ns),
            (1_000_000, 200_000_000)
        );
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
