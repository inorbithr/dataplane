//! `iohr-capture`, the privileged companion of the InOrbit agent (ADR 0002).
//!
//! Phase 1: `run` attaches TC classifiers to one interface's ingress and egress, drops its
//! capabilities right after attaching, then counts headers (layer 1), recognises protocols
//! from the first bytes of each flow (layer 2), attributes sockets to owners (layer 4) and
//! samples TCP health (layer 5). It answers the agent on a local Unix socket with counts,
//! and a person with bounded top-K tables (`stats`). `doctor` checks whether this host can
//! run it. `cleanup` removes filters a killed run left behind (kernels before 6.6).
//! Nothing is stored and nothing leaves the host.

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
mod privileges;
#[cfg(target_os = "linux")]
mod procnet;
#[cfg(target_os = "linux")]
mod proto;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod sockdiag;
#[cfg(target_os = "linux")]
mod topk;

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
    /// Attach to an interface, count and recognise until the time is up or a signal
    /// arrives, answer the agent on the aggregates socket, print totals (counts) as JSON.
    Run(Box<RunArgs>),
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
        #[arg(long, env = "IOHR_CAPTURE_SOCKET_GROUP", default_value = "iohr-agent")]
        socket_group: String,
    },
    /// Remove TC filters a previous run left on an interface (netlink mode; for `ExecStopPost`).
    Cleanup {
        /// Interface to clean.
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: String,
    },
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
    /// Layers to run: headers (1), protocols (2), owners (4), tcp (5).
    #[arg(
        long,
        env = "IOHR_CAPTURE_LAYERS",
        default_value = "headers,protocols,owners,tcp"
    )]
    layers: String,
    /// Packet copies to user space per second per CPU (token bucket); 0 = no limit.
    #[arg(long, env = "IOHR_CAPTURE_SAMPLES_PER_SEC", default_value_t = 2000)]
    samples_per_sec: u64,
    /// Token bucket burst, in copies.
    #[arg(long, env = "IOHR_CAPTURE_BURST", default_value_t = 500)]
    burst: u64,
    /// Ring buffer size in KiB (rounded up to a power of two).
    #[arg(long, env = "IOHR_CAPTURE_RING_BUFFER_KIB", default_value_t = 4096)]
    ring_buffer_kib: u32,
    /// Payload-carrying packets per flow whose first 512 bytes are copied.
    #[arg(long, env = "IOHR_CAPTURE_FIRST_PACKETS", default_value_t = 8)]
    first_packets: u32,
    /// Flows tracked at once in user space; more evict the oldest (counted).
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
    #[arg(long, env = "IOHR_CAPTURE_SOCKET_GROUP", default_value = "iohr-agent")]
    socket_group: String,
    /// The agent's user, allowed on the aggregates socket.
    #[arg(long, env = "IOHR_CAPTURE_AGENT_USER", default_value = "iohr-agent")]
    agent_user: String,
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
        } => {
            let checks =
                doctor::evaluate(&doctor::Facts::gather(interface.as_deref(), &socket_group));
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
        Command::Run(args) => run(&args),
        Command::Stats {
            socket,
            tables,
            json,
        } => stats(&socket, tables, json),
        Command::Cleanup { interface } => cleanup(&interface),
    }
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
        ring_buffer_kib: a.ring_buffer_kib,
        first_packets: a.first_packets,
        max_flows: a.max_flows.clamp(1, 1_048_576),
        poll: Duration::from_millis(a.poll_ms.clamp(100, 60_000)),
        aggregates: a.aggregates_socket.clone(),
        control: a.control_socket.clone(),
        group: a.socket_group.clone(),
        agent_user: a.agent_user.clone(),
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
            tracing::error!(error = %e, socket = %socket.display(), "no answer from iohr-capture (is it running? are you in the iohr-agent group?)");
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
fn cleanup(interface: &str) -> ExitCode {
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
fn cleanup(_: &str) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}
