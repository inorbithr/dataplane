//! `iohr-capture`, the privileged companion of the InOrbit agent (ADR 0002).
//!
//! Phase 0 (toolchain spike): `run` attaches TC classifiers to one interface's ingress and
//! egress, drops its capabilities right after attaching, counts socket buffers and bytes
//! per direction and prints the totals as JSON on exit. `doctor` checks whether this host
//! can run it. `cleanup` removes filters a killed run left behind (kernels before 6.6).
//! Nothing is stored and nothing leaves the host.

mod doctor;
mod kernel;

#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
mod privileges;

use std::{io::Write as _, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "iohr-capture", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach to an interface, count until the time is up or a signal arrives, print totals as JSON.
    Run {
        /// Interface to attach to (ingress and egress).
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: String,
        /// Seconds to count for; without it, until SIGINT or SIGTERM.
        #[arg(long = "for", value_name = "SECS")]
        for_secs: Option<u64>,
        /// How to attach: TCX links (Linux 6.6+), netlink filters, or pick by kernel version.
        #[arg(long, value_enum, default_value_t = AttachMode::Auto)]
        attach: AttachMode,
    },
    /// Check whether this host can run capture; one line per requirement, with the fix.
    Doctor {
        /// Also check that this interface exists.
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: Option<String>,
        /// Print the checks as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove TC filters a previous run left on an interface (netlink mode; for `ExecStopPost`).
    Cleanup {
        /// Interface to clean.
        #[arg(long, short = 'i', env = "IOHR_CAPTURE_INTERFACE")]
        interface: String,
    },
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
        Command::Doctor { interface, json } => {
            let checks = doctor::evaluate(&doctor::Facts::gather(interface.as_deref()));
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
        Command::Run {
            interface,
            for_secs,
            attach,
        } => run(&interface, for_secs.map(Duration::from_secs), attach),
        Command::Cleanup { interface } => cleanup(&interface),
    }
}

fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

#[cfg(target_os = "linux")]
fn run(interface: &str, duration: Option<Duration>, attach: AttachMode) -> ExitCode {
    match capture::run(interface, duration, attach) {
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
fn run(_: &str, _: Option<Duration>, _: AttachMode) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}

#[cfg(not(target_os = "linux"))]
fn cleanup(_: &str) -> ExitCode {
    tracing::error!("iohr-capture runs on Linux only");
    ExitCode::from(2)
}
