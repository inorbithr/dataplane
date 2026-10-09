//! `iohr-capture`, the privileged companion of the InOrbit agent (ADR 0002).
//!
//! `run` attaches TC classifiers to one interface's ingress and egress, drops its
//! capabilities right after attaching, then counts headers (layer 1), recognises protocols
//! from the first bytes of each flow (layer 2), attributes sockets to owners (layer 4),
//! samples TCP health (layer 5) and times requests per route template (layer 7). With
//! `--packets` it keeps whole packets in memory (layer 3) and writes a pcap file when root
//! asks on the control socket (`pcap`). It answers the agent on a local Unix socket with
//! counts, and a person with bounded top-K tables (`stats`). `dissect` runs the host's own
//! `tshark` on a pcap file as the person who asks. `doctor` checks whether this host can
//! run it. `cleanup` removes filters a killed run left behind (kernels before 6.6).
//! Nothing leaves the host; pcap files are kept on it for a retention and deleted.

mod doctor;
mod kernel;

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod flows;
#[cfg(target_os = "linux")]
mod owners;
#[cfg(target_os = "linux")]
mod packet;
#[cfg(target_os = "linux")]
mod pcap;
#[cfg(target_os = "linux")]
mod pcapout;
#[cfg(target_os = "linux")]
mod privileges;
#[cfg(target_os = "linux")]
mod procnet;
#[cfg(target_os = "linux")]
mod proto;
#[cfg(target_os = "linux")]
mod route;
#[cfg(target_os = "linux")]
mod server;
// Linux only; also compiled for unit tests on any Unix (its pure parts are portable).
#[cfg(any(target_os = "linux", all(test, unix)))]
mod service;
#[cfg(target_os = "linux")]
mod sockdiag;
#[cfg(target_os = "linux")]
mod timing;
#[cfg(target_os = "linux")]
mod topk;
#[cfg(target_os = "linux")]
mod worker;

use std::{io::Write as _, path::PathBuf, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "iohr-capture", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Set up or remove the system service, for a companion installed with
    /// `iohr ext install inorbit/capture` instead of the package (root only).
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Attach to an interface, count and recognise until the time is up or a signal
    /// arrives, answer the agent on the aggregates socket, print totals (counts) as JSON.
    Run(Box<RunArgs>),
    /// Internal: the unprivileged parser process `run` starts (privilege separation).
    #[command(hide = true)]
    Worker {
        /// Settings from `run`, as JSON.
        #[arg(long)]
        config: String,
    },
    /// Ask a running companion for its aggregates (the agent asks the same socket).
    Stats {
        /// The aggregates socket.
        #[arg(
            long,
            env = "IOHR_CAPTURE_AGGREGATES_SOCKET",
            default_value = "/run/iohr-capture/aggregates.sock"
        )]
        socket: PathBuf,
        /// Also show the top-K tables (names, paths, addresses, owners): for you, on this host.
        #[arg(long)]
        tables: bool,
        /// Print the answer as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check whether this host can run capture; one line per requirement, with the fix.
    Doctor {
        /// Also check that this interface exists.
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: Option<String>,
        /// Print the checks as JSON.
        #[arg(long)]
        json: bool,
        /// The aggregates socket's group (checked to exist).
        #[arg(
            long,
            env = "IOHR_CAPTURE_SOCKET_GROUP",
            default_value = "iohr-capture-read"
        )]
        socket_group: String,
        /// Whole packets are on (the pcap directory is checked then).
        #[arg(long, env = "IOHR_CAPTURE_PACKETS")]
        packets: bool,
        /// The pcap directory.
        #[arg(
            long,
            env = "IOHR_CAPTURE_PCAP_DIR",
            default_value = "/var/lib/iohr-capture/pcap"
        )]
        pcap_dir: PathBuf,
    },
    /// Remove TC filters a previous run left on an interface (netlink mode; for `ExecStopPost`).
    Cleanup {
        /// Interface to clean.
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: String,
        /// The pcap directory: the companion's own files in it are deleted too (it stopped,
        /// so nothing would expire them; copies made with `pcap --out` are elsewhere).
        #[arg(
            long,
            env = "IOHR_CAPTURE_PCAP_DIR",
            default_value = "/var/lib/iohr-capture/pcap"
        )]
        pcap_dir: PathBuf,
    },
    /// Write a pcap file from the packets a running companion keeps (root only, on this
    /// host; needs `--packets`). The file stays on this host and expires.
    Pcap(PcapArgs),
    /// Run this host's own tshark on a pcap file, as you (never as root unless --as-root).
    Dissect(DissectArgs),
    /// Request timing for one owner and route (aggregates socket, version 2): numbers only.
    Lookup {
        /// The aggregates socket.
        #[arg(
            long,
            env = "IOHR_CAPTURE_AGGREGATES_SOCKET",
            default_value = "/run/iohr-capture/aggregates.sock"
        )]
        socket: PathBuf,
        /// The owner key, as `stats --tables` shows it (`cgroup:/…`, `systemd:….service`).
        #[arg(long)]
        owner: String,
        /// The route: `METHOD template`, for example `GET /orders/{id}`.
        #[arg(long)]
        route: String,
    },
}

/// `pcap`.
#[derive(Debug, clap::Args)]
struct PcapArgs {
    /// The control socket (root only).
    #[arg(
        long,
        env = "IOHR_CAPTURE_CONTROL_SOCKET",
        default_value = "/run/iohr-capture/control.sock"
    )]
    control_socket: PathBuf,
    /// Seconds of traffic: the last ones from memory, or with --next the coming ones (1-300).
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    /// Which packets: `tcp`, `udp`, `icmp`, `ip`, `ip6`, `[src|dst] port N`,
    /// `[src|dst] host ADDR`, joined by `and`, each optionally after `not`.
    #[arg(long)]
    filter: Option<String>,
    /// Largest file, bytes (at most the companion's `IOHR_CAPTURE_PCAP_MAX_BYTES`).
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Capture the next --seconds instead of the last ones; waits until the file is done.
    #[arg(long)]
    next: bool,
    /// Also copy the file here (must not exist), mode 0600, created as the user who ran
    /// sudo, so that user can `dissect` it without root.
    #[arg(long)]
    out: Option<PathBuf>,
    /// The companion's pcap directory: a file is copied only from here.
    #[arg(
        long,
        env = "IOHR_CAPTURE_PCAP_DIR",
        default_value = "/var/lib/iohr-capture/pcap"
    )]
    pcap_dir: PathBuf,
    /// Print the answer as JSON.
    #[arg(long)]
    json: bool,
}

/// `dissect`.
#[derive(Debug, clap::Args)]
struct DissectArgs {
    /// The pcap or pcapng file.
    file: PathBuf,
    /// Allow running tshark as root (it parses untrusted packets; Wireshark advises against it).
    #[arg(long)]
    as_root: bool,
    /// The tshark to run (default: `tshark` on PATH).
    #[arg(long)]
    tshark: Option<PathBuf>,
    /// More tshark options, after `--` (for example `-- -V -Y http`).
    #[arg(last = true)]
    args: Vec<String>,
}

/// `run`.
#[derive(Debug, clap::Args)]
#[allow(clippy::struct_field_names)]
struct RunArgs {
    /// Interface to attach to (ingress and egress).
    #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
    interface: String,
    /// Seconds to run for; without it, until SIGINT or SIGTERM.
    #[arg(long = "for", value_name = "SECS")]
    for_secs: Option<u64>,
    /// How to attach: TCX links (Linux 6.6+), netlink filters, or pick by kernel version.
    #[arg(long, value_enum, default_value_t = AttachMode::Auto)]
    attach: AttachMode,
    /// Layers to run: headers (1), protocols (2), owners (4), tcp (5), timing (7, needs
    /// protocols). Whole packets (3) have their own switch, --packets.
    #[arg(
        long,
        env = "IOHR_CAPTURE_LAYERS",
        default_value = "headers,protocols,owners,tcp,timing"
    )]
    layers: String,
    /// Packet copies to user space per second per CPU (token bucket); 0 = no limit.
    #[arg(long, env = "IOHR_CAPTURE_SAMPLES_PER_SEC", default_value_t = 2000)]
    samples_per_sec: u64,
    /// Token bucket burst, in copies.
    #[arg(long, env = "IOHR_CAPTURE_BURST", default_value_t = 500)]
    burst: u64,
    /// Ring buffer size in KiB (rounded up to a power of two; 4 to 32768).
    #[arg(long, env = "IOHR_CAPTURE_RING_BUFFER_KIB", default_value_t = 4096)]
    ring_buffer_kib: u32,
    /// Payload-carrying packets per flow whose first 512 bytes are copied.
    #[arg(long, env = "IOHR_CAPTURE_FIRST_PACKETS", default_value_t = 8)]
    first_packets: u32,
    /// Flows tracked at once in user space; more evict the oldest (counted). At most 65536.
    #[arg(long, env = "IOHR_CAPTURE_MAX_FLOWS", default_value_t = 16_384)]
    max_flows: usize,
    /// How often the maps, sockets and host counters are read, in milliseconds.
    #[arg(long, env = "IOHR_CAPTURE_POLL_MS", default_value_t = 2000)]
    poll_ms: u64,
    /// The aggregates socket (mode 0660, group --socket-group).
    #[arg(
        long,
        env = "IOHR_CAPTURE_AGGREGATES_SOCKET",
        default_value = "/run/iohr-capture/aggregates.sock"
    )]
    aggregates_socket: PathBuf,
    /// The control socket (mode 0600, root only).
    #[arg(
        long,
        env = "IOHR_CAPTURE_CONTROL_SOCKET",
        default_value = "/run/iohr-capture/control.sock"
    )]
    control_socket: PathBuf,
    /// Group of the aggregates socket; its members may read the aggregates.
    #[arg(
        long,
        env = "IOHR_CAPTURE_SOCKET_GROUP",
        default_value = "iohr-capture-read"
    )]
    socket_group: String,
    /// The agent's user, allowed on the aggregates socket.
    #[arg(long, env = "IOHR_CAPTURE_AGENT_USER", default_value = "iohr-agent")]
    agent_user: String,
    /// Layer 3: keep whole packets in memory, for pcap files root asks for on the control
    /// socket. Off unless set.
    #[arg(long, env = "IOHR_CAPTURE_PACKETS")]
    packets: bool,
    /// Bytes copied per packet (64-65535).
    #[arg(long, env = "IOHR_CAPTURE_SNAPLEN", default_value_t = 65_535)]
    snaplen: u32,
    /// Packet copies per second per CPU (kernel token bucket); 0 = no limit.
    #[arg(long, env = "IOHR_CAPTURE_PACKETS_PER_SEC", default_value_t = 1000)]
    packets_per_sec: u64,
    /// Burst of that bucket, in packets.
    #[arg(long, env = "IOHR_CAPTURE_PACKETS_BURST", default_value_t = 200)]
    packets_burst: u64,
    /// The packets ring buffer in KiB (256 to 32768).
    #[arg(long, env = "IOHR_CAPTURE_PACKETS_RING_KIB", default_value_t = 8192)]
    packets_ring_kib: u32,
    /// Packets kept in memory, MiB (1 to 128; nothing older than 300 s).
    #[arg(long, env = "IOHR_CAPTURE_PACKETS_BUFFER_MIB", default_value_t = 32)]
    packets_buffer_mib: u32,
    /// Where pcap files are written (0700, files 0600).
    #[arg(
        long,
        env = "IOHR_CAPTURE_PCAP_DIR",
        default_value = "/var/lib/iohr-capture/pcap"
    )]
    pcap_dir: PathBuf,
    /// Largest pcap file a request may ask for, bytes (at most 1 GiB).
    #[arg(long, env = "IOHR_CAPTURE_PCAP_MAX_BYTES", default_value_t = 64 * 1024 * 1024)]
    pcap_max_bytes: u64,
    /// Most bytes of pcap files kept at once (at least one largest file, at most 64 GiB;
    /// a request also leaves 64 MiB of the file system free).
    #[arg(long, env = "IOHR_CAPTURE_PCAP_DIR_MAX_BYTES", default_value_t = 512 * 1024 * 1024)]
    pcap_dir_max_bytes: u64,
    /// Seconds a pcap file is kept before it is deleted (1-86400).
    #[arg(long, env = "IOHR_CAPTURE_PCAP_RETENTION_SECS", default_value_t = 3600)]
    pcap_retention_secs: u64,
}

/// How the classifiers are attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AttachMode {
    /// TCX on Linux 6.6 and newer, netlink filters before.
    Auto,
    /// TCX links: removed by the kernel when the process exits.
    Tcx,
    /// clsact qdisc and netlink filters: removed on exit, and by `cleanup` after a crash.
    Netlink,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// The same service the packages install: the program at /usr/local/bin, the system
    /// user and read group, /etc/iohr-capture/capture.env, the unit; then enable and start.
    Install {
        /// The interface to attach to (default: the one the default route uses).
        #[arg(long, short = 'i')]
        interface: Option<String>,
        /// A user that may read the counts (the agent's user); repeatable. `iohr-agent`
        /// joins too when it exists.
        #[arg(long = "agent-user")]
        agent_users: Vec<String>,
        /// Write everything, but don't enable or start the service.
        #[arg(long)]
        no_start: bool,
    },
    /// Stop and remove the service and the program.
    Remove {
        /// Also remove the settings, the user and the read group.
        #[arg(long)]
        purge: bool,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("IOHR_CAPTURE_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor {
            interface,
            json,
            socket_group,
            packets,
            pcap_dir,
        } => {
            let checks = doctor::evaluate(&doctor::Facts::gather(
                interface.as_deref(),
                &socket_group,
                packets.then_some(pcap_dir.as_path()),
            ));
            let text = if json {
                serde_json::to_string_pretty(&checks).unwrap_or_default()
            } else {
                doctor::render(&checks)
            };
            emit(&text);
            if doctor::can_run(&checks) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Service(cmd) => service_cmd(cmd),
        Command::Run(args) => run(&args),
        Command::Worker { config } => worker(&config),
        Command::Stats {
            socket,
            tables,
            json,
        } => stats(&socket, tables, json),
        Command::Cleanup {
            interface,
            pcap_dir,
        } => cleanup(&interface, &pcap_dir),
        Command::Pcap(args) => pcap_cmd(&args),
        Command::Dissect(args) => dissect(&args),
        Command::Lookup {
            socket,
            owner,
            route,
        } => lookup(&socket, &owner, &route),
    }
}

#[cfg(target_os = "linux")]
fn service_cmd(cmd: ServiceCommand) -> ExitCode {
    let result = match cmd {
        ServiceCommand::Install {
            interface,
            agent_users,
            no_start,
        } => service::install(&service::InstallArgs {
            interface,
            agent_users,
            no_start,
        })
        .map(|mut done| {
            done.push(String::new());
            done.push(service::agent_hint().to_string());
            done
        }),
        ServiceCommand::Remove { purge } => service::remove(purge),
    };
    match result {
        Ok(done) => {
            emit(&done.join("\n"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "service");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn service_cmd(_cmd: ServiceCommand) -> ExitCode {
    tracing::error!("the capture service runs on Linux only");
    ExitCode::from(1)
}

fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

#[cfg(target_os = "linux")]
fn run(a: &RunArgs) -> ExitCode {
    let layers = match engine::Layers::parse(&a.layers) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "--layers");
            return ExitCode::from(2);
        }
    };
    let opts = capture::Options {
        interface: a.interface.clone(),
        duration: a.for_secs.map(Duration::from_secs),
        mode: a.attach,
        layers,
        samples_per_sec: a.samples_per_sec,
        burst: a.burst,
        ring_buffer_kib: a.ring_buffer_kib.clamp(4, MAX_RING_KIB),
        first_packets: a.first_packets,
        max_flows: a.max_flows.clamp(1, MAX_FLOWS),
        poll: Duration::from_millis(a.poll_ms.clamp(100, 60_000)),
        aggregates: a.aggregates_socket.clone(),
        control: a.control_socket.clone(),
        group: a.socket_group.clone(),
        agent_user: a.agent_user.clone(),
        packets: a.packets.then(|| capture::PacketOptions {
            snaplen: a.snaplen.clamp(64, 65_535),
            per_sec: a.packets_per_sec.min(1_000_000),
            burst: a.packets_burst.max(1),
            ring_kib: a.packets_ring_kib.clamp(256, MAX_RING_KIB),
            buffer_mib: a.packets_buffer_mib.clamp(1, 128),
            pcap_dir: a.pcap_dir.clone(),
            pcap_max_bytes: a.pcap_max_bytes.clamp(4096, 1 << 30),
            // At least one file of the largest size, at most 64 GiB.
            pcap_dir_max_bytes: a
                .pcap_dir_max_bytes
                .clamp(a.pcap_max_bytes.clamp(4096, 1 << 30), 64 << 30),
            pcap_retention_secs: a.pcap_retention_secs.clamp(1, 86_400),
        }),
    };
    match capture::run(&opts) {
        Ok(report) => {
            emit(&serde_json::to_string_pretty(&report).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "capture failed");
            ExitCode::from(1)
        }
    }
}

/// Upper bounds on the sizes a person can ask for, so the worst case (a 32 MiB ring buffer
/// plus 65536 undecided flows of about 2 KiB) stays well under the unit's MemoryMax=256M.
const MAX_FLOWS: usize = 65_536;
const MAX_RING_KIB: u32 = 32 * 1024;

#[cfg(target_os = "linux")]
fn worker(config: &str) -> ExitCode {
    match worker::run(config) {
        Ok(counts) => {
            emit(&serde_json::to_string(&counts).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "parser process failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn worker(_: &str) -> ExitCode {
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn stats(socket: &std::path::Path, tables: bool, json: bool) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "runtime");
            return ExitCode::from(1);
        }
    };
    let request = if tables { "tables" } else { "counts" };
    match rt.block_on(server::query(socket, request)) {
        Ok(v) if v.get("error").is_some() => {
            tracing::error!(error = %v["error"], message = %v["message"], "the companion refused");
            ExitCode::from(1)
        }
        Ok(v) => {
            if json {
                emit(&serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                emit(&render_stats(&v));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, socket = %socket.display(), "no answer from iohr-capture (is it running? are you in the iohr-capture-read group?)");
            ExitCode::from(1)
        }
    }
}

/// A short text view of an answer.
#[cfg(target_os = "linux")]
fn render_stats(v: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let n = |p: &str| v.pointer(p).cloned().unwrap_or_default();
    let _ = writeln!(
        s,
        "iohr-capture {} on {} (layers: {}), up {} s",
        n("/companion_version"),
        n("/interface"),
        n("/layers"),
        n("/uptime_secs")
    );
    let _ = writeln!(
        s,
        "headers   ingress {} skb / {} B, egress {} skb / {} B",
        n("/headers/ingress/packets"),
        n("/headers/ingress/bytes"),
        n("/headers/egress/packets"),
        n("/headers/egress/bytes")
    );
    let _ = writeln!(
        s,
        "drops     rate limited {}, ring buffer full {}, flows evicted {}",
        n("/drops/rate_limited"),
        n("/drops/ring_buffer_full"),
        n("/drops/flows_evicted")
    );
    let _ = writeln!(
        s,
        "flows     seen {}, active {}, recognised {}, unrecognised {}",
        n("/flows/seen"),
        n("/flows/active"),
        n("/flows/recognised"),
        n("/flows/unrecognised")
    );
    let _ = writeln!(
        s,
        "protocols http/1 {}, tls {}, dns {}, http/2 {}, grpc {}",
        n("/protocols/http1_requests"),
        n("/protocols/tls_client_hellos"),
        n("/protocols/dns_queries"),
        n("/protocols/http2_connections"),
        n("/protocols/grpc_calls")
    );
    let _ = writeln!(
        s,
        "owners    {} sockets, {} owners, flows owned {}, unowned {}",
        n("/owners/sockets"),
        n("/owners/owners"),
        n("/owners/flows_owned"),
        n("/owners/flows_unowned")
    );
    let _ = writeln!(
        s,
        "timing    requests {}, responses {} (2xx {}, 4xx {}, 5xx {}), unanswered {}, flows out of sync {}, keys {}",
        n("/timing/requests"),
        n("/timing/responses"),
        n("/timing/status_classes/2xx"),
        n("/timing/status_classes/4xx"),
        n("/timing/status_classes/5xx"),
        n("/timing/unanswered"),
        n("/timing/unsynced"),
        n("/timing/keys")
    );
    let _ = writeln!(
        s,
        "packets   {}: copied {} ({} B), rate limited {}, ring full {}, in memory {} ({} B), pcap files {}",
        if v.pointer("/packets/enabled") == Some(&serde_json::Value::Bool(true)) {
            "on"
        } else {
            "off"
        },
        n("/packets/copied"),
        n("/packets/bytes_copied"),
        n("/packets/rate_limited"),
        n("/packets/ring_buffer_full"),
        n("/packets/buffered_packets"),
        n("/packets/buffered_bytes"),
        n("/packets/pcap_files")
    );
    let _ = write!(
        s,
        "tcp       established {}, listening {}, retransmits {}, resets in/out {}/{}, listen overflows {}",
        n("/tcp/established"),
        n("/tcp/listening"),
        n("/tcp/retransmits_sampled"),
        n("/tcp/resets_in"),
        n("/tcp/resets_out"),
        n("/tcp/host/listen_overflows")
    );
    if let Some(t) = v.get("tables") {
        let _ = write!(
            s,
            "\n\ntables (top {}):\n{}",
            20,
            serde_json::to_string_pretty(t).unwrap_or_default()
        );
    }
    s
}

#[cfg(target_os = "linux")]
fn cleanup(interface: &str, pcap_dir: &std::path::Path) -> ExitCode {
    let gone = pcap::remove_all(pcap_dir);
    if gone > 0 {
        tracing::info!(files = gone, "pcap files removed: the companion stopped");
    }
    match capture::cleanup(interface) {
        Ok(removed) => {
            tracing::info!(interface, removed, "stale filters removed");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "cleanup failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| tracing::error!(error = %e, "runtime"))
        .ok()
}

#[cfg(target_os = "linux")]
fn lookup(socket: &std::path::Path, owner: &str, route: &str) -> ExitCode {
    let Some(rt) = runtime() else {
        return ExitCode::from(1);
    };
    let req =
        serde_json::json!({"version": 2, "request": "lookup", "owner": owner, "route": route});
    match rt.block_on(server::send(socket, &req, Duration::from_secs(5))) {
        Ok(v) if v.get("error").is_some() => {
            tracing::error!(error = %v["error"], message = %v["message"], "the companion refused");
            ExitCode::from(1)
        }
        Ok(v) => {
            emit(&serde_json::to_string_pretty(&v).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, socket = %socket.display(), "no answer from iohr-capture");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)] // ask, wait, check, copy: one sequence
fn pcap_cmd(a: &PcapArgs) -> ExitCode {
    if !rustix::process::geteuid().is_root() {
        tracing::error!("the control socket is for root only: run `sudo iohr-capture pcap …`");
        return ExitCode::from(2);
    }
    let Some(rt) = runtime() else {
        return ExitCode::from(1);
    };
    let mut req = serde_json::json!({
        "version": server::CONTROL_VERSION, "request": "pcap", "seconds": a.seconds,
        "mode": if a.next { "next" } else { "last" },
    });
    if let Some(f) = &a.filter {
        req["filter"] = f.as_str().into();
    }
    if let Some(m) = a.max_bytes {
        req["max_bytes"] = m.into();
    }
    let answer = match rt.block_on(server::send(
        &a.control_socket,
        &req,
        Duration::from_secs(120),
    )) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, socket = %a.control_socket.display(), "no answer from iohr-capture (is it running?)");
            return ExitCode::from(1);
        }
    };
    if let Some(code) = answer.get("error").and_then(serde_json::Value::as_str) {
        tracing::error!(error = code, message = %answer["message"], "the companion refused");
        return ExitCode::from(1);
    }
    let Some(path) = answer["path"].as_str().map(PathBuf::from) else {
        tracing::error!("the companion's answer has no path");
        return ExitCode::from(1);
    };
    if a.next {
        // Wait for the file to be complete: the companion closes it at `until`.
        let status = serde_json::json!({"version": server::CONTROL_VERSION, "request": "status"});
        let until = answer["until_unix_ms"].as_u64().unwrap_or(0);
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
            if now > until + 1000 {
                let writing = rt
                    .block_on(server::send(
                        &a.control_socket,
                        &status,
                        Duration::from_secs(10),
                    ))
                    .ok()
                    .and_then(|v| v["writing"].as_bool());
                if writing != Some(true) {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    // The parser named the file: nothing in its answer is trusted (pcapout.rs).
    let mut size = answer["bytes"].as_u64().unwrap_or(0);
    if let Some(out) = &a.out {
        let cap = a.max_bytes.unwrap_or(1 << 30).min(1 << 30);
        let src = match pcapout::open_source(&a.pcap_dir, &path.to_string_lossy(), cap) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "not copied");
                return ExitCode::from(1);
            }
        };
        size = src.size;
        // No more socket work: the runtime goes, so this thread is the only one, and root
        // becomes the person before anything is created.
        drop(rt);
        if let Some((uid, gid)) = pcapout::sudo_user()
            && let Err(e) = pcapout::become_user(uid, gid)
        {
            tracing::error!(error = %e, "could not become the sudo user; not copied");
            return ExitCode::from(1);
        }
        match pcapout::copy(src, out) {
            Ok(n) => {
                tracing::info!(out = %out.display(), bytes = n, uid = rustix::process::getuid().as_raw(), "copied");
            }
            Err(e) => {
                tracing::error!(error = %e, out = %out.display(), "copy failed");
                return ExitCode::from(1);
            }
        }
    }
    if a.json {
        let mut v = answer;
        v["bytes"] = size.into();
        emit(&serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        emit(&format!(
            "{} ({} bytes{}{}); deleted by the companion after its retention",
            path.display(),
            size,
            answer["packets"]
                .as_u64()
                .map(|n| format!(", {n} packets"))
                .unwrap_or_default(),
            if answer["truncated"] == serde_json::Value::Bool(true) {
                ", cut at max_bytes"
            } else {
                ""
            }
        ));
    }
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
fn dissect(a: &DissectArgs) -> ExitCode {
    if rustix::process::geteuid().is_root() && !a.as_root {
        tracing::error!(
            "refusing to run tshark as root: it parses untrusted packets. Run `iohr-capture dissect` as yourself (copy the file with `sudo iohr-capture pcap --out FILE`), or pass --as-root"
        );
        return ExitCode::from(2);
    }
    let Some(tshark) = a.tshark.clone().or_else(|| find_on_path("tshark")) else {
        tracing::error!(
            "tshark is not installed. It is a separate program (GPL) that iohr-capture never bundles: `sudo apt install tshark` (Debian, Ubuntu) or `sudo dnf install wireshark-cli` (Fedora, RHEL)"
        );
        return ExitCode::from(3);
    };
    // Opened here, as the person who asks, and handed to tshark as its standard input: it
    // reads exactly the file checked, with that person's rights.
    let file = match std::fs::File::open(&a.file) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, file = %a.file.display(), "cannot read the file as you; `sudo iohr-capture pcap --out FILE` makes a copy you own");
            return ExitCode::from(1);
        }
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        tracing::error!(file = %a.file.display(), "not a regular file");
        return ExitCode::from(1);
    }
    // -n: no name lookups (captured addresses are never sent to a resolver).
    let mut cmd = std::process::Command::new(&tshark);
    cmd.args(["-n", "-r", "-"]).args(&a.args).stdin(file);
    if rustix::process::geteuid().is_root() {
        // --as-root: nothing from the caller's environment but PATH and LANG.
        cmd.env_clear().env("HOME", "/root");
        for k in ["PATH", "LANG"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    }
    let status = cmd.status();
    match status {
        Ok(s) => ExitCode::from(u8::try_from(s.code().unwrap_or(1)).unwrap_or(1)),
        Err(e) => {
            tracing::error!(error = %e, tshark = %tshark.display(), "tshark did not start");
            ExitCode::from(1)
        }
    }
}

/// The first executable `name` on `PATH`.
#[cfg(target_os = "linux")]
fn find_on_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .filter(|d| d.is_absolute())
            .map(|d| d.join(name))
            .find(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    })
}

#[cfg(not(target_os = "linux"))]
fn pcap_cmd(_: &PcapArgs) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn dissect(_: &DissectArgs) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn lookup(_: &std::path::Path, _: &str, _: &str) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn run(_: &RunArgs) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn stats(_: &std::path::Path, _: bool, _: bool) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn cleanup(_: &str, _: &std::path::Path) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}
