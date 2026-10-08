//! The command line: `init`, `enroll`, `run`, `status`, `policy check`, `checks lint`,
//! `config validate|show|schema`, `capture status`, `atlas observe`, `atlas docs sync|sources`,
//! `page`, `ledger verify|export`. As an iohr
//! extension the same commands are `iohr agent …`.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};
use tokio::sync::watch;
use url::Url;
use zeroize::Zeroizing;

use crate::checks_file::{self, DeclaredChecks, Kind, RefuseBy, Verdict};
use crate::config::{self, AgentConfig, VaultConfig};
use crate::enroll::{self, EnrollParams, Enrollment};
use crate::error::{Error, Result};
use crate::extsock;
use crate::keys::{self, KeyAlg};
use crate::metadata;
use crate::platform;
use crate::policy::{Policy, TargetError};
use crate::tls::{self, TlsContext};

/// The environment variable holding an enrollment token (Helm puts a Secret here).
pub const TOKEN_ENV: &str = "IOHR_AGENT_ENROLLMENT_TOKEN";

/// iohr-agent: the InOrbit data plane. Dials out, obeys a local policy, runs checks.
#[derive(Debug, Parser)]
#[command(name = "iohr-agent", version, about, long_about = None)]
pub struct Cli {
    /// The configuration file (default: `$IOHR_AGENT_CONFIG`, `/etc/iohr-agent/agent.toml`,
    /// or the user's configuration directory).
    #[arg(long, global = true, env = config::CONFIG_ENV)]
    pub config: Option<PathBuf>,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write agent.toml and policy.toml, check them (with the platform when run through
    /// iohr), and enroll.
    Init(Box<InitArgs>),
    /// Make this agent's key and exchange a one-time enrollment token for its identity.
    Enroll(EnrollArgs),
    /// Connect to the platform and run the work the policy allows, until stopped.
    Run(RunArgs),
    /// Show whether the agent is running and connected, and what it has done.
    Status(StatusArgs),
    /// Policy tools.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Declared checks (checks.toml) tools.
    #[command(subcommand)]
    Checks(ChecksCommand),
    /// The capture companion (iohr-capture) on this host.
    #[command(subcommand)]
    Capture(CaptureCommand),
    /// agent.toml tools: validate it, show the effective configuration, print its schema.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Atlas observers: evidence about a checkout and a cluster, never claims.
    #[command(subcommand)]
    Atlas(AtlasCommand),
    /// The local agent page: print its address, or open it signed in (`--open`).
    Page(PageArgs),
    /// What InOrbit sees about your checks and this machine (`[share]` in the policy):
    /// `full`, `hash` (the default) or `label`; without one, what it is now.
    Share(ShareArgs),
    /// The egress ledger: what this agent sent to the platform, recorded here first.
    #[command(subcommand)]
    Ledger(LedgerCommand),
}

/// `share`.
#[derive(Debug, Args)]
pub struct ShareArgs {
    /// `full`: each check's URL or host and port; `hash`: a label and a keyed hash, the
    /// target stays here; `label`: the label only.
    #[arg(value_parser = ["full", "hash", "label"])]
    pub targets: Option<String>,
    /// Send this machine's host name in the hello (`on`), or not (`off`). Unchanged when
    /// not given.
    #[arg(long, value_parser = ["on", "off"])]
    pub hostname: Option<String>,
}

/// `page`.
#[derive(Debug, Args)]
pub struct PageArgs {
    /// Open the page in the browser, signed in with this run's token.
    #[arg(long)]
    pub open: bool,
}

/// `ledger …`.
#[derive(Debug, Subcommand)]
pub enum LedgerCommand {
    /// Check the chain: every entry intact, none removed, inserted or changed. Exit 1 on
    /// any problem.
    Verify(LedgerArgs),
    /// Write every entry, oldest first, as JSON lines (to stdout, or `--out`).
    Export(LedgerExportArgs),
}

/// `ledger verify`.
#[derive(Debug, Args)]
pub struct LedgerArgs {
    /// The ledger directory (default: `ledger` in agent.toml's state directory).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// `ledger export`.
#[derive(Debug, Args)]
pub struct LedgerExportArgs {
    /// The ledger directory (default: `ledger` in agent.toml's state directory).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Write here instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// `config …`.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Check agent.toml with the environment overrides applied; every problem names its
    /// line. Exit 2 on any error.
    Validate,
    /// Print the effective configuration (file plus environment overrides) as TOML, the
    /// Vault token reference redacted.
    Show,
    /// Print the JSON Schema of agent.toml (the repository keeps it at
    /// docs/schema/agent.schema.json).
    Schema,
}

/// `atlas …`.
#[derive(Debug, Subcommand)]
pub enum AtlasCommand {
    /// Read a checkout and/or a cluster and write the evidence as JSON lines. Read-only;
    /// the cluster's API server must pass the policy. Nothing is sent anywhere.
    Observe(AtlasObserveArgs),
    /// Documentation sources (`[[docs.sources]]` in agent.toml): Notion first.
    #[command(subcommand)]
    Docs(AtlasDocsCommand),
}

/// `atlas docs …`.
#[derive(Debug, Subcommand)]
pub enum AtlasDocsCommand {
    /// Read the configured sources into the local content store (only what changed since
    /// the last complete run) and write the evidence as JSON lines. Read-only; each
    /// provider's host and each credential reference must pass the policy. Nothing is
    /// sent anywhere.
    Sync(AtlasDocsSyncArgs),
    /// List the configured sources: provider, credential reference, local store.
    Sources,
}

/// `atlas docs sync`.
#[derive(Debug, Args)]
pub struct AtlasDocsSyncArgs {
    /// Only this source; repeat for more (default: every source).
    #[arg(long = "source")]
    pub sources: Vec<String>,
    /// List everything, not only what changed, and delete local copies of what is no
    /// longer visible. Run it daily; incremental runs cannot see deletions.
    #[arg(long)]
    pub full: bool,
    /// The policy (default: the one agent.toml names).
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Where to write the records (default: standard output).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// What `atlas observe` reads besides a checkout and a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ObserveWhat {
    /// This machine: sensors, PCI, storage, pressure, boots (`[work] host` in the policy).
    Host,
}

/// `atlas observe`.
#[derive(Debug, Args)]
pub struct AtlasObserveArgs {
    /// `host` reads this machine (needs `[work] host = true` in the policy).
    #[arg(value_enum)]
    pub what: Vec<ObserveWhat>,
    /// host: samples to take (1 is one reading; more give rates, peaks and correlations).
    #[arg(long, default_value_t = 1)]
    pub samples: u32,
    /// host: seconds between samples.
    #[arg(long, default_value_t = 10)]
    pub interval: u64,
    /// host: the chipset temperature, °C, at which the derived findings call it hot
    /// (default: the warn of an hwmon check on a `Chipset` sensor in checks.toml, else 100).
    #[arg(long)]
    pub chipset_warn: Option<f64>,
    /// host: print a human report to standard error.
    #[arg(long)]
    pub report: bool,
    /// host: read a captured tree instead of `/` (tests, replays).
    #[arg(long, hide = true)]
    pub host_root: Option<PathBuf>,
    /// host: name PCI devices from this pci.ids (default: the host's).
    #[arg(long, hide = true)]
    pub pci_ids: Option<PathBuf>,
    /// A checkout to read (Cargo manifests, Kubernetes manifests, Envoy routes).
    #[arg(long)]
    pub repo: Option<PathBuf>,
    /// The kubeconfig to read a cluster through (default: `$KUBECONFIG`, then
    /// `~/.kube/config`, when `--kube-context` is given).
    #[arg(long)]
    pub kubeconfig: Option<PathBuf>,
    /// The kubeconfig context (default: its current context).
    #[arg(long)]
    pub kube_context: Option<String>,
    /// A namespace to read; repeat for more (default: the context's, else `default`).
    #[arg(long = "namespace", short = 'n')]
    pub namespaces: Vec<String>,
    /// The policy that must admit the API server (default: the one agent.toml names).
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Where to write the records (default: standard output).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// `capture …`.
#[derive(Debug, Subcommand)]
pub enum CaptureCommand {
    /// Ask iohr-capture what it counted on this host (its aggregates socket); nothing is sent anywhere.
    Status(CaptureStatusArgs),
    /// Request timing for one owner and route (numbers only); nothing is sent anywhere.
    ///
    /// There is no `capture pcap` or `capture dissect` here on purpose: the agent never
    /// handles packets. On the host, root runs `iohr-capture pcap` and a person
    /// `iohr-capture dissect` (docs/capture/install.md).
    Lookup(CaptureLookupArgs),
}

/// `capture lookup`.
#[derive(Debug, Args)]
pub struct CaptureLookupArgs {
    /// The aggregates socket (default: `[capture] socket` in the policy, or /run/iohr-capture/aggregates.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// The owner key, as `iohr-capture stats --tables` shows it (`cgroup:/…`, `systemd:….service`).
    #[arg(long)]
    pub owner: String,
    /// The route: `METHOD template`, for example `GET /orders/{id}`.
    #[arg(long)]
    pub route: String,
}

/// `capture status`.
#[derive(Debug, Args)]
pub struct CaptureStatusArgs {
    /// The aggregates socket (default: `[capture] socket` in the policy, or /run/iohr-capture/aggregates.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Print the answer as JSON.
    #[arg(long)]
    pub json: bool,
    /// Also show the top-K tables (hosts, paths, SNI, DNS names, addresses, owners). For you, on this host.
    #[arg(long)]
    pub tables: bool,
}

/// `checks …`.
#[derive(Debug, Subcommand)]
pub enum ChecksCommand {
    /// Validate checks.toml against the policy, offline; exit 1 on any error.
    Lint(ChecksLintArgs),
}

/// `checks lint`.
#[derive(Debug, Args)]
pub struct ChecksLintArgs {
    /// The checks file (default: the one agent.toml names).
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// The policy file (default: the one agent.toml names).
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Also resolve each name and check its addresses, as a job would.
    #[arg(long)]
    pub resolve: bool,
}

/// `policy …`.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate a policy and print its hash; optionally test a target against it.
    Check(PolicyCheckArgs),
}

/// `init`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct InitArgs {
    /// The environment this agent serves (`staging`, `production`).
    #[arg(long)]
    pub environment: Option<String>,
    /// A bound domain (repeatable). Must be verified in the account.
    #[arg(long = "domain")]
    pub domains: Vec<String>,
    /// A CIDR, address, host name or `*.suffix` the agent may reach (repeatable).
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    /// Where credentials for checks live.
    #[arg(long, value_enum)]
    pub secret_store: Option<SecretStore>,
    /// Vault address (with `--secret-store vault`).
    #[arg(long)]
    pub vault_addr: Option<Url>,
    /// Kubernetes namespace holding check secrets (with `--secret-store k8s`).
    #[arg(long, default_value = "iohr-agent")]
    pub k8s_namespace: String,
    /// A name shown in the console (default: the host name).
    #[arg(long)]
    pub name: Option<String>,
    /// The platform API (default: `$IOHR_EXT_API` or `https://api.inorbit.hr`).
    #[arg(long)]
    pub api: Option<Url>,
    /// The account (personal or team) the agent belongs to; needed to check domains and
    /// create the enrollment through iohr.
    #[arg(long)]
    pub account: Option<String>,
    /// Directory for agent.toml and policy.toml (default: next to the default config).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Directory for the key and the enrollment record (default: <dir>/state).
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Key kind.
    #[arg(long, value_enum, default_value = "es256")]
    pub key_alg: KeyAlg,
    /// Replace existing files.
    #[arg(long)]
    pub force: bool,
    /// Never prompt; fail when something is missing.
    #[arg(long)]
    pub yes: bool,
    /// What InOrbit sees about your declared checks: `full` (each target), `hash` (a label
    /// and a keyed hash; the default) or `label` (the label only). `[share]` in the policy;
    /// change it later on the agent's page or with `iohr agent share`.
    #[arg(long, value_parser = ["full", "hash", "label"])]
    pub share_targets: Option<String>,
    /// Send this machine's host name to InOrbit (`on`); `off`, the default, shows the
    /// agent's name instead.
    #[arg(long, value_parser = ["on", "off"])]
    pub share_hostname: Option<String>,
    /// Skip the platform check and enrollment even when iohr offers a token.
    #[arg(long)]
    pub no_platform: bool,
    /// Create the enrollment but do not enroll; the token is saved 0600 in the state
    /// directory for `enroll --token-file`.
    #[arg(long)]
    pub no_enroll: bool,
}

/// Where check credentials live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SecretStore {
    /// No credentials.
    None,
    /// Environment variables of the agent (`env:IOHR_CHECK_*`).
    Env,
    /// Files on the agent's machine.
    File,
    /// Kubernetes Secrets in one namespace.
    K8s,
    /// HashiCorp Vault KV v2.
    Vault,
}

/// `enroll`.
#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// The one-time token (`ioe_…`). Prefer --token-file or the environment variable:
    /// a command line is visible to other users of the machine.
    #[arg(long, env = TOKEN_ENV, hide_env_values = true)]
    pub token: Option<String>,
    /// Read the token from a file.
    #[arg(long, conflicts_with = "token")]
    pub token_file: Option<PathBuf>,
    /// Replace an existing key and enrollment.
    #[arg(long)]
    pub force: bool,
}

/// `run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Log as JSON lines.
    #[arg(long)]
    pub json_logs: bool,
}

/// `status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Print the status document as JSON.
    #[arg(long)]
    pub json: bool,
    /// Print nothing; exit 0 when the agent is running, 1 when not.
    #[arg(long, short)]
    pub quiet: bool,
}

/// `policy check`.
#[derive(Debug, Args)]
pub struct PolicyCheckArgs {
    /// The policy file (default: the one agent.toml names).
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// A target to test: a URL or host:port. Resolves it as a job would.
    #[arg(long)]
    pub target: Option<String>,
}

/// How the person started this program: `iohr agent` when iohr runs it as an
/// extension (iohr always passes the token socket), `iohr-agent` otherwise. Help,
/// usage and every "run this next" hint name the command they actually typed.
#[must_use]
pub fn invoked_as() -> &'static str {
    if std::env::var_os(extsock::SOCKET_ENV).is_some() {
        "iohr agent"
    } else {
        "iohr-agent"
    }
}

/// Parses arguments and runs; the process exit code.
#[must_use]
pub fn main() -> ExitCode {
    let matches = Cli::command().bin_name(invoked_as()).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    tls::install_crypto_provider();
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(config::default_config_path);
    let result = match cli.command {
        Command::Run(args) => run(&config_path, &args),
        other => {
            let _ = crate::telemetry::init(&config::TelemetryConfig::default(), false);
            match runtime() {
                Ok(rt) => rt.block_on(dispatch(other, &config_path)),
                Err(e) => Err(e),
            }
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "iohr-agent: {e}");
            ExitCode::from(match e {
                Error::Config(_) | Error::Policy(_) | Error::Checks(_) => 2,
                Error::Revoked(_) => 3,
                _ => 1,
            })
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Config(format!("cannot start the runtime: {e}")))
}

async fn dispatch(cmd: Command, config_path: &Path) -> Result<ExitCode> {
    match cmd {
        Command::Init(a) => init(&a, config_path).await,
        Command::Enroll(a) => enroll_cmd(&a, config_path).await,
        Command::Status(a) => status(&a, config_path).await,
        Command::Policy(PolicyCommand::Check(a)) => policy_check(&a, config_path).await,
        Command::Checks(ChecksCommand::Lint(a)) => checks_lint(&a, config_path).await,
        Command::Capture(CaptureCommand::Status(a)) => capture_status(&a, config_path).await,
        Command::Capture(CaptureCommand::Lookup(a)) => capture_lookup(&a, config_path).await,
        Command::Config(ConfigCommand::Validate) => config_validate(config_path),
        Command::Config(ConfigCommand::Show) => config_show(config_path),
        Command::Config(ConfigCommand::Schema) => config_schema(),
        Command::Atlas(AtlasCommand::Observe(a)) => atlas_observe(&a, config_path).await,
        Command::Atlas(AtlasCommand::Docs(AtlasDocsCommand::Sync(a))) => {
            atlas_docs_sync(&a, config_path).await
        }
        Command::Atlas(AtlasCommand::Docs(AtlasDocsCommand::Sources)) => {
            atlas_docs_sources(config_path)
        }
        Command::Page(a) => page(&a, config_path),
        Command::Share(a) => share_cmd(&a, config_path).await,
        Command::Ledger(LedgerCommand::Verify(a)) => ledger_verify(&a, config_path),
        Command::Ledger(LedgerCommand::Export(a)) => ledger_export(&a, config_path),
        Command::Run(_) => Ok(ExitCode::SUCCESS),
    }
}

/// `share`: sets `[share]` in the policy file in place (comments kept), then asks the
/// running agent to reload through its page (with this run's token). An agent that is not
/// running takes it when it starts; either way the change is on the ledger when it does.
async fn share_cmd(args: &ShareArgs, config_path: &Path) -> Result<ExitCode> {
    use crate::policy::{SharePolicy, TargetShare};
    let cfg = AgentConfig::load(config_path)?;
    let policy = Policy::load(&cfg.policy)?;
    let now = policy.share();
    let describe = |s: &SharePolicy| {
        format!(
            "targets {} ({}), host name {}",
            s.targets.as_str(),
            match s.targets {
                TargetShare::Full => "each check's URL or host and port",
                TargetShare::Hash => "a label and a keyed hash; targets stay here",
                TargetShare::Label => "labels only; targets stay here",
            },
            if s.hostname { "sent" } else { "kept here" }
        )
    };
    let Some(t) = &args.targets else {
        if args.hostname.is_some() {
            return Err(Error::Config(
                "name the targets level too: iohr agent share full|hash|label --hostname on|off"
                    .into(),
            ));
        }
        out(&format!(
            "InOrbit sees: {}{}",
            describe(&now),
            if policy.share.is_some() {
                ""
            } else {
                " (the defaults; [share] is not set)"
            }
        ));
        out(&format!("Policy: {}", cfg.policy.display()));
        return Ok(ExitCode::SUCCESS);
    };
    let want = SharePolicy {
        targets: match t.as_str() {
            "full" => TargetShare::Full,
            "label" => TargetShare::Label,
            _ => TargetShare::Hash,
        },
        hostname: args.hostname.as_deref().map_or(now.hostname, |h| h == "on"),
    };
    let changed = crate::share::write_policy(&cfg.policy, &want).map_err(|e| match e {
        Error::Io { .. } => Error::Config(format!(
            "{e}; the policy is not writable by this user: run it with sudo, or as the user that owns {}",
            cfg.policy.display()
        )),
        other => other,
    })?;
    out(&format!(
        "{} {}: {}",
        if changed { "Set" } else { "Already" },
        cfg.policy.display(),
        describe(&want)
    ));
    // Ask the running agent to take it now.
    let mut addr = cfg.admin.listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let token = std::fs::read_to_string(cfg.state_dir.join(crate::admin::TOKEN_FILE)).ok();
    let reloaded = match (cfg.admin.enabled && addr.ip().is_loopback(), token) {
        (true, Some(token)) => {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| Error::Config(e.to_string()))?;
            match client
                .post(format!("http://{addr}/policy/reload"))
                .bearer_auth(token.trim())
                .send()
                .await
            {
                Ok(r) => {
                    let ok = r.status().is_success();
                    let body: serde_json::Value = r.json().await.unwrap_or_default();
                    Some((ok, body["message"].as_str().unwrap_or_default().to_owned()))
                }
                Err(_) => None,
            }
        }
        _ => None,
    };
    match reloaded {
        Some((true, msg)) => out(&format!(
            "The running agent {msg}; the change is in its ledger."
        )),
        Some((false, msg)) => {
            out(&format!("The running agent did not take it: {msg}"));
            return Ok(ExitCode::from(1));
        }
        None => out(
            "No running agent answered on its page: it takes this when it starts, and records it in its ledger then.",
        ),
    }
    Ok(ExitCode::SUCCESS)
}

fn ledger_dir(flag: Option<&PathBuf>, config_path: &Path) -> Result<PathBuf> {
    match flag {
        Some(d) => Ok(d.clone()),
        None => Ok(crate::ledger::dir_in(
            &AgentConfig::load(config_path)?.state_dir,
        )),
    }
}

fn ledger_verify(args: &LedgerArgs, config_path: &Path) -> Result<ExitCode> {
    let dir = ledger_dir(args.dir.as_ref(), config_path)?;
    if !dir.is_dir() {
        return Err(Error::Config(format!(
            "no ledger at {}: the agent has not sent anything yet, or [ledger] is off",
            dir.display()
        )));
    }
    let v = crate::ledger::verify(&dir);
    if args.json {
        out(&serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        out(&format!(
            "{} — {} entries in {} files ({}), from {}",
            if v.ok() { "intact" } else { "BROKEN" },
            v.entries,
            v.files,
            dir.display(),
            v.starts_at
        ));
        if let (Some(seq), Some(head)) = (v.last_seq, &v.head) {
            out(&format!("  head   entry {seq}  {head}"));
        }
        for p in &v.problems {
            out(&format!("  problem  {p}"));
        }
    }
    Ok(if v.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn ledger_export(args: &LedgerExportArgs, config_path: &Path) -> Result<ExitCode> {
    let dir = ledger_dir(args.dir.as_ref(), config_path)?;
    if let Some(path) = &args.out {
        let mut f = std::fs::File::create(path).map_err(|e| Error::io(path, e))?;
        let n = crate::ledger::export(&dir, &mut f)?;
        out(&format!("{n} bytes written to {}", path.display()));
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        crate::ledger::export(&dir, &mut lock)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// `page`: the address, or the browser opened on it with this run's token (which turns
/// into a cookie for that browser and leaves the address bar at once).
fn page(args: &PageArgs, config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    if !cfg.admin.enabled {
        return Err(Error::Config(
            "the admin page is off ([admin] enabled = false)".into(),
        ));
    }
    let mut addr = cfg.admin.listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let scheme = if cfg.admin.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    let host = if addr.ip().is_loopback() {
        format!("127.0.0.1:{}", addr.port())
    } else {
        addr.to_string()
    };
    let base = format!("{scheme}://{host}/");
    if !args.open {
        out(&base);
        if cfg.admin.token_required() {
            out(&format!(
                "It asks for its token: `{} page --open` opens it signed in.",
                invoked_as()
            ));
        }
        return Ok(ExitCode::SUCCESS);
    }
    let token_path = cfg.state_dir.join(crate::admin::TOKEN_FILE);
    let token = std::fs::read_to_string(&token_path).map_err(|e| {
        Error::Config(format!(
            "{}: {e} (is the agent running? the token is written when it starts)",
            token_path.display()
        ))
    })?;
    let url = format!("{base}auth?token={}", token.trim());
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let status = std::process::Command::new(opener)
        .arg(&url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {
            out(&format!("Opened {base} in your browser, signed in."));
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(Error::Config(format!(
            "could not start {opener}; open {base} yourself (the token is in {})",
            token_path.display()
        ))),
    }
}

async fn atlas_observe(args: &AtlasObserveArgs, config_path: &Path) -> Result<ExitCode> {
    let kubeconfig = args.kubeconfig.clone().or_else(|| {
        args.kube_context.as_ref()?;
        std::env::var_os("KUBECONFIG")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".kube/config")))
    });
    let wants_host = args.what.contains(&ObserveWhat::Host);
    let policy = if kubeconfig.is_some() || wants_host {
        let path = match &args.policy {
            Some(p) => p.clone(),
            None => AgentConfig::load(config_path)?.policy,
        };
        Some(Policy::load(&path)?)
    } else {
        None
    };
    let req = crate::atlas::ObserveRequest {
        repo: args.repo.clone(),
        kubeconfig,
        kube_context: args.kube_context.clone(),
        namespaces: args.namespaces.clone(),
        host: if wants_host {
            if !(1..=360).contains(&args.samples) || !(1..=300).contains(&args.interval) {
                return Err(Error::Atlas(
                    "--samples must be 1 to 360 and --interval 1 to 300 seconds".into(),
                ));
            }
            let chipset_warn = match args.chipset_warn {
                Some(c) => crate::host::check::to_raw(crate::host::hwmon::Kind::Temp, c),
                None => chipset_warn_from_checks(config_path),
            };
            Some(crate::atlas::HostRequest {
                root: args.host_root.clone(),
                pci_ids: args.pci_ids.clone(),
                samples: args.samples,
                interval: Duration::from_secs(args.interval),
                chipset_warn,
            })
        } else {
            None
        },
    };
    let (sink, summary) = crate::atlas::observe(&req, policy.as_ref()).await?;
    match &args.out {
        Some(path) => {
            let file = std::fs::File::create(path).map_err(|e| Error::io(path, e))?;
            let mut w = std::io::BufWriter::new(file);
            sink.write_to(&mut w)?;
            w.flush().map_err(|e| Error::io(path, e))?;
        }
        None => sink.write_to(std::io::stdout().lock())?,
    }
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "atlas observe: {} records, {} entities",
        summary.records, summary.entities
    );
    for (m, n) in &summary.per_method {
        let _ = writeln!(err, "  {m:<20} {n}");
    }
    if let Some((all, known)) = summary.components {
        let _ = writeln!(
            err,
            "  manifest: {all} deployments, {known} known at a revision"
        );
    }
    if args.report
        && let Some(r) = &summary.host_report
    {
        let _ = writeln!(err, "\n{r}");
    }
    Ok(ExitCode::SUCCESS)
}

/// The warn of an hwmon check on a `Chipset` temperature in checks.toml, else RFC 0094's
/// 100 °C.
fn chipset_warn_from_checks(config_path: &Path) -> i64 {
    let path = AgentConfig::load(config_path).map(|c| c.checks).ok();
    path.and_then(|p| DeclaredChecks::load(&p).ok().flatten())
        .and_then(|c| {
            c.entries.iter().find_map(|e| {
                let h = e.spec.params.hwmon.as_ref()?;
                (h.sensor.kind == crate::host::hwmon::Kind::Temp
                    && h.sensor.label.eq_ignore_ascii_case("chipset")
                    && !h.below)
                    .then_some(h.warn.or(h.crit))
                    .flatten()
            })
        })
        .unwrap_or(crate::host::derive::DEFAULT_CHIPSET_WARN)
}

async fn atlas_docs_sync(args: &AtlasDocsSyncArgs, config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let policy = Policy::load(args.policy.as_deref().unwrap_or(&cfg.policy))?;
    let (sink, outcomes) =
        crate::atlas::docs::run::sync_configured(&cfg, &policy, &args.sources, args.full).await?;
    match &args.out {
        Some(path) => {
            let file = std::fs::File::create(path).map_err(|e| Error::io(path, e))?;
            let mut w = std::io::BufWriter::new(file);
            sink.write_to(&mut w)?;
            w.flush().map_err(|e| Error::io(path, e))?;
        }
        None => sink.write_to(std::io::stdout().lock())?,
    }
    let mut err = std::io::stderr().lock();
    let mut ok = true;
    for o in &outcomes {
        match (&o.summary, &o.error) {
            (Some(s), _) if s.revoked => {
                ok = false;
                let _ = writeln!(
                    err,
                    "atlas docs {}: the credential was refused; its local copies were deleted",
                    o.id
                );
            }
            (Some(s), _) => {
                ok &= s.complete;
                let _ = writeln!(
                    err,
                    "atlas docs {}: {} listed, {} read ({} changed), {} unchanged, {} gone, {} failed, {}; {} requests, {} retries, {} rate limited",
                    o.id,
                    s.listed,
                    s.fetched,
                    s.changed,
                    s.unchanged,
                    s.gone,
                    s.failed,
                    if s.complete {
                        "complete"
                    } else {
                        "incomplete (the next run continues)"
                    },
                    o.requests.0,
                    o.requests.1,
                    o.requests.2
                );
            }
            (None, Some(e)) => {
                ok = false;
                let _ = writeln!(err, "atlas docs {}: {e}", o.id);
            }
            (None, None) => {}
        }
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn atlas_docs_sources(config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let content = cfg.docs.content_dir(&cfg.state_dir);
    if cfg.docs.sources.is_empty() {
        out("no [[docs.sources]] in agent.toml");
    }
    for s in &cfg.docs.sources {
        let store = content.join(&s.id);
        let held = std::fs::read_dir(store.join("items")).map_or(0, |d| {
            d.filter_map(std::result::Result::ok)
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.ends_with(".md") && !n.ends_with(".comments.md")
                })
                .count()
        });
        out(&format!(
            "{}\t{}\t{}\t{} items in {}",
            s.id,
            s.provider,
            s.token.as_deref().unwrap_or("-"),
            held,
            store.display()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

fn out(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

fn http_client(cfg: Option<&AgentConfig>) -> Result<reqwest::Client> {
    let tls = TlsContext::new(cfg.and_then(|c| c.tls.ca_file.as_deref()))?;
    tls.reqwest_builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Tls(e.to_string()))
}

fn run(config_path: &Path, args: &RunArgs) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let telemetry = crate::telemetry::init(&cfg.telemetry, args.json_logs)?;
    let result = runtime()?.block_on(run_async(cfg));
    telemetry.shutdown();
    result.map(|()| ExitCode::SUCCESS)
}

async fn run_async(cfg: AgentConfig) -> Result<()> {
    let policy = Policy::load(&cfg.policy)?;
    let checks = DeclaredChecks::load(&cfg.checks)?;
    let enrollment = if let Some(e) = Enrollment::load(&cfg.state_dir)? {
        e
    } else {
        {
            let token = std::env::var(TOKEN_ENV).ok().map(Zeroizing::new).ok_or_else(|| {
                Error::Config(format!(
                    "this agent is not enrolled yet: run `{} enroll --token-file <file>` or set {TOKEN_ENV}",
                    invoked_as()
                ))
            })?;
            tracing::info!("not enrolled yet; enrolling with the token from {TOKEN_ENV}");
            let http = http_client(Some(&cfg))?;
            enroll::enroll(EnrollParams {
                api: &cfg.api,
                token: token.trim(),
                name: &cfg.name,
                environment: &cfg.environment,
                policy_hash: &policy.hash(),
                key_alg: cfg.key_alg,
                key_path: &cfg.key,
                state_dir: &cfg.state_dir,
                replace: false,
                http: &http,
            })
            .await?
        }
    };
    if let Ok(t) = std::env::var(TOKEN_ENV) {
        crate::redact::register(t.trim());
    }
    // The policy and checks are read again, and on every reload, by the supervisor.
    drop((policy, checks));
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("stopping");
        let _ = tx.send(true);
    });
    crate::agent::supervise(cfg, enrollment, rx).await
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The aggregates socket: the flag, else the policy's `[capture] socket`, else the default.
fn capture_socket(flag: Option<&PathBuf>, config_path: &Path) -> PathBuf {
    let from_policy = || {
        let cfg = AgentConfig::load(config_path).ok()?;
        let policy = Policy::load(&cfg.policy).ok()?;
        Some(policy.capture.unwrap_or_default().socket)
    };
    flag.cloned()
        .or_else(from_policy)
        .unwrap_or_else(|| PathBuf::from(crate::policy::CAPTURE_SOCKET))
}

async fn capture_lookup(args: &CaptureLookupArgs, config_path: &Path) -> Result<ExitCode> {
    let socket = capture_socket(args.socket.as_ref(), config_path);
    let l = crate::capture::lookup(&socket, &args.owner, &args.route, Duration::from_secs(5))
        .await
        .map_err(|e| Error::Config(format!("{e}; is iohr-capture running (version 2 of its socket), and are you in the iohr-capture-read group? (docs/capture/install.md)")))?;
    out(&serde_json::to_string_pretty(&l).unwrap_or_default());
    Ok(ExitCode::SUCCESS)
}

async fn capture_status(args: &CaptureStatusArgs, config_path: &Path) -> Result<ExitCode> {
    let socket = capture_socket(args.socket.as_ref(), config_path);
    let what = if args.tables { "tables" } else { "counts" };
    let raw = crate::capture::request(&socket, what, Duration::from_secs(5))
        .await
        .map_err(|e| Error::Config(format!("{e}; is iohr-capture running, and are you in the iohr-capture-read group? (docs/capture/install.md)")))?;
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| Error::Config(format!("the companion's answer is not JSON: {e}")))?;
    if let Some(code) = value.get("error").and_then(|v| v.as_str()) {
        return Err(Error::Config(format!(
            "iohr-capture answered {code}: {}",
            value.get("message").and_then(|v| v.as_str()).unwrap_or("")
        )));
    }
    if args.json {
        out(&serde_json::to_string_pretty(&value).unwrap_or_default());
        return Ok(ExitCode::SUCCESS);
    }
    let c = crate::capture::Counts::parse(&raw).map_err(Error::Config)?;
    out(&format!(
        "iohr-capture {} ({}), numbers from {} s ago",
        value
            .get("companion_version")
            .and_then(|v| v.as_str())
            .unwrap_or("?"),
        c.layers.join(", "),
        c.age_secs(crate::capture::now_ms())
    ));
    out(&format!(
        "headers    in {} skb / {} B, out {} skb / {} B",
        c.headers.ingress.packets,
        c.headers.ingress.bytes,
        c.headers.egress.packets,
        c.headers.egress.bytes
    ));
    out(&format!(
        "drops      {} rate limited, {} ring buffer full, {} flows evicted",
        c.drops.rate_limited, c.drops.ring_buffer_full, c.drops.flows_evicted
    ));
    out(&format!(
        "protocols  http/1 {}, tls {}, dns {}, http/2 {} (grpc {})",
        c.protocols.http1_requests,
        c.protocols.tls_client_hellos,
        c.protocols.dns_queries,
        c.protocols.http2_connections,
        c.protocols.grpc_calls
    ));
    out(&format!(
        "owners     {} sockets, {} owners, flows {} owned / {} unowned",
        c.owners.sockets, c.owners.owners, c.owners.flows_owned, c.owners.flows_unowned
    ));
    out(&format!(
        "timing     {} requests, {} answered (2xx {}, 3xx {}, 4xx {}, 5xx {}), {} unanswered, {} routes and owners, {} connections out of sync",
        c.timing.requests,
        c.timing.responses,
        c.timing.status_classes.c2xx,
        c.timing.status_classes.c3xx,
        c.timing.status_classes.c4xx,
        c.timing.status_classes.c5xx,
        c.timing.unanswered,
        c.timing.keys,
        c.timing.unsynced
    ));
    out(&format!(
        "packets    {}: {} copied, {} rate limited, {} ring buffer full, {} pcap files made on this host",
        if c.packets.enabled { "on" } else { "off" },
        c.packets.copied,
        c.packets.rate_limited,
        c.packets.ring_buffer_full,
        c.packets.pcaps_written
    ));
    out(&format!(
        "tcp        {} established, {} listening, {} retransmits, resets {} in / {} out, {} listen overflows",
        c.tcp.established,
        c.tcp.listening,
        c.tcp.retransmits_sampled,
        c.tcp.resets_in,
        c.tcp.resets_out,
        c.tcp.host.listen_overflows
    ));
    if let Some(t) = value.get("tables") {
        out("");
        out(&serde_json::to_string_pretty(t).unwrap_or_default());
    }
    Ok(ExitCode::SUCCESS)
}

async fn enroll_cmd(args: &EnrollArgs, config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let policy = Policy::load(&cfg.policy)?;
    if policy.environment != cfg.environment {
        return Err(Error::Policy(format!(
            "the policy is for {:?} but agent.toml says {:?}",
            policy.environment, cfg.environment
        )));
    }
    let token = match (&args.token, &args.token_file) {
        (Some(t), _) => Zeroizing::new(t.trim().to_owned()),
        (None, Some(f)) => Zeroizing::new(
            std::fs::read_to_string(f)
                .map_err(|e| Error::io(f, e))?
                .trim()
                .to_owned(),
        ),
        (None, None) => {
            return Err(Error::Enroll(format!(
                "pass --token-file <file> or set {TOKEN_ENV}"
            )));
        }
    };
    let http = http_client(Some(&cfg))?;
    let e = enroll::enroll(EnrollParams {
        api: &cfg.api,
        token: &token,
        name: &cfg.name,
        environment: &cfg.environment,
        policy_hash: &policy.hash(),
        key_alg: cfg.key_alg,
        key_path: &cfg.key,
        state_dir: &cfg.state_dir,
        replace: args.force,
        http: &http,
    })
    .await?;
    if let Some(f) = &args.token_file {
        // A used token is worthless, but there is no reason to keep it.
        let _ = std::fs::remove_file(f);
    }
    out(&format!(
        "Enrolled as {} in environment {}.",
        e.agent_id, e.environment
    ));
    out(&format!(
        "Key: {} (mode 0600, never leaves this machine)",
        cfg.key.display()
    ));
    out(&format!("Start it with `{} run`.", invoked_as()));
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_lines)] // one line of output after another
async fn status(args: &StatusArgs, config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let mut addr = cfg.admin.listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let snapshot = if cfg.admin.enabled {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;
        let mut req = client.get(format!("http://{addr}/status.json"));
        // When the page asks for its token, this machine's operator has it.
        if let Ok(t) = std::fs::read_to_string(cfg.state_dir.join(crate::admin::TOKEN_FILE)) {
            req = req.bearer_auth(t.trim());
        }
        match req.send().await {
            Ok(r) if r.status().is_success() => r.json::<crate::state::Snapshot>().await.ok(),
            _ => None,
        }
    } else {
        None
    };
    if args.quiet {
        return Ok(if snapshot.is_some() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    let Some(s) = snapshot else {
        let enrolled = Enrollment::load(&cfg.state_dir)?;
        if args.json {
            out(&serde_json::json!({
                "running": false,
                "enrolled": enrolled.as_ref().map(|e| &e.agent_id),
                "environment": cfg.environment,
            })
            .to_string());
        } else {
            out(&format!("Not running (no admin page at http://{addr}/)."));
            match enrolled {
                Some(e) => out(&format!("Enrolled as {} in {}.", e.agent_id, e.environment)),
                None => out("Not enrolled."),
            }
        }
        return Ok(ExitCode::from(1));
    };
    if args.json {
        out(&serde_json::to_string_pretty(&s).unwrap_or_default());
        return Ok(ExitCode::SUCCESS);
    }
    let state = if s.revoked {
        "revoked"
    } else if s.connected {
        "connected"
    } else {
        "running, not connected"
    };
    out(&format!(
        "{state} — {} {}",
        s.agent.name,
        s.agent.agent_id.as_deref().unwrap_or("")
    ));
    if let Some(since) = &s.connected_since {
        out(&format!("  since        {since}"));
    }
    if let Some(e) = &s.last_error {
        out(&format!("  last error   {e}"));
    }
    out(&format!("  environment  {}", s.agent.environment));
    out(&format!("  policy       {}", s.policy.hash));
    out(&format!(
        "  accepts      {}",
        s.policy.capabilities.join(", ")
    ));
    out(&format!(
        "  sent         {} heartbeats, results: {} ok, {} failed, {} refused",
        s.sent.heartbeat, s.sent.results_ok, s.sent.results_failed, s.sent.results_refused
    ));
    if let Some(hash) = &s.policy.checks_hash {
        out(&format!(
            "  checks       {} declared, {hash}",
            s.policy.checks
        ));
    }
    if let Some(x) = &s.host {
        out(&format!(
            "  host         {} sensors, {} samples, last {} ({} µs){}",
            x.sensors,
            x.samples,
            x.last_sample_at,
            x.last_cost_us,
            x.chipset_millicelsius.map_or_else(String::new, |c| format!(
                ", chipset {}.{} °C",
                c / 1000,
                (c % 1000) / 100
            ))
        ));
    }
    out(&format!("  page         http://{addr}/"));
    Ok(ExitCode::SUCCESS)
}

async fn policy_check(args: &PolicyCheckArgs, config_path: &Path) -> Result<ExitCode> {
    let path = match &args.file {
        Some(f) => f.clone(),
        None => AgentConfig::load(config_path)?.policy,
    };
    let policy = Policy::load(&path)?;
    out(&format!("{}: valid", path.display()));
    out(&format!("  hash         {}", policy.hash()));
    out(&format!("  environment  {}", policy.environment));
    out(&format!(
        "  domains      {}",
        policy.domains.bound.join(", ")
    ));
    out(&format!(
        "  allow        {}",
        policy.networks.allow.join(", ")
    ));
    out(&format!(
        "  work         checks={} load={} faults={}",
        policy.work.checks, policy.work.load, policy.work.faults
    ));
    let Some(target) = &args.target else {
        return Ok(ExitCode::SUCCESS);
    };
    let (host, port) = match Url::parse(target) {
        Ok(u) if u.host_str().is_some() => (
            u.host_str().unwrap_or_default().to_owned(),
            u.port_or_known_default().unwrap_or(443),
        ),
        _ => {
            let (h, p) = target
                .rsplit_once(':')
                .ok_or_else(|| Error::Policy("target must be a URL or host:port".into()))?;
            (
                h.to_owned(),
                p.parse().map_err(|_| Error::Policy("bad port".into()))?,
            )
        }
    };
    match policy
        .resolve_target(&host, port, Duration::from_secs(5))
        .await
    {
        Ok(addr) => {
            out(&format!(
                "  target       {host}:{port} allowed, would connect to {addr}"
            ));
            Ok(ExitCode::SUCCESS)
        }
        Err(TargetError::Refused(r)) => {
            out(&format!("  target       {host}:{port} refused: {r}"));
            Ok(ExitCode::from(1))
        }
        Err(TargetError::Dns(r)) => {
            out(&format!(
                "  target       {host}:{port} does not resolve: {r}"
            ));
            Ok(ExitCode::from(1))
        }
    }
}

async fn checks_lint(args: &ChecksLintArgs, config_path: &Path) -> Result<ExitCode> {
    let cfg = if args.file.is_none() || args.policy.is_none() {
        Some(AgentConfig::load(config_path)?)
    } else {
        None
    };
    let file = match (&args.file, &cfg) {
        (Some(f), _) => f.clone(),
        (None, Some(c)) => c.checks.clone(),
        (None, None) => return Err(Error::Config("no checks file".into())),
    };
    let policy_path = match (&args.policy, &cfg) {
        (Some(p), _) => p.clone(),
        (None, Some(c)) => c.policy.clone(),
        (None, None) => return Err(Error::Config("no policy file".into())),
    };
    let policy = Policy::load(&policy_path)?;
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && args.file.is_none() => {
            out(&format!(
                "{}: no such file; this agent declares no checks",
                file.display()
            ));
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => return Err(Error::io(&file, e)),
    };
    let hint = format!("fix it and run `{} checks lint` again", invoked_as());
    let entries = match checks_file::parse(&text) {
        Ok(e) => e,
        Err(e) => {
            out(&format!("error    {}: {e}", file.display()));
            out(&hint);
            return Ok(ExitCode::from(1));
        }
    };
    let (mut errors, mut warnings) = (0usize, 0usize);
    for (name, entry) in &entries {
        let verdict = match entry {
            Err(e) => Verdict::Error(e.clone()),
            Ok(c) => {
                let v = checks_file::lint_offline(c, &policy);
                if args.resolve {
                    resolve_verdict(c, &policy, v).await
                } else {
                    v
                }
            }
        };
        let label = entry.as_ref().map_or_else(
            |_| name.clone(),
            |c| match c.refuse_by {
                Some(by) => format!("{name} (refuse by {})", by.as_str()),
                None => name.clone(),
            },
        );
        match verdict {
            Verdict::Ok => out(&format!("ok       {label}")),
            Verdict::Warning(w) => {
                warnings += 1;
                out(&format!("warning  {label}: {w}"));
            }
            Verdict::Error(e) => {
                errors += 1;
                out(&format!("error    {label}: {e}"));
            }
            Verdict::NeedsResolve { host, .. } => {
                warnings += 1;
                out(&format!(
                    "warning  {label}: {host} is inside a bound domain; the policy refuses it only if an address is outside networks.allow (check with --resolve)"
                ));
            }
        }
    }
    if errors == 0 {
        match DeclaredChecks::from_toml(&text) {
            Ok(c) => out(&format!(
                "{}: {} entries, {warnings} warnings, {}",
                file.display(),
                c.entries.len(),
                c.hash
            )),
            Err(e) => {
                out(&format!("error    {}: {e}", file.display()));
                errors += 1;
            }
        }
    }
    if errors > 0 {
        out(&format!(
            "{}: {errors} errors, {warnings} warnings; {hint}",
            file.display()
        ));
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

/// Settles a lint verdict with DNS, as the agent would before connecting.
async fn resolve_verdict(
    c: &checks_file::DeclaredCheck,
    policy: &Policy,
    offline: Verdict,
) -> Verdict {
    let Ok(e) = c.spec.endpoint() else {
        return offline;
    };
    if c.spec.surface.is_host() {
        return offline;
    }
    let by_policy = c.kind == Kind::Refuse && c.refuse_by == Some(RefuseBy::Policy);
    let by_platform = c.refuse_by == Some(RefuseBy::Platform);
    if by_platform || matches!(offline, Verdict::Error(_)) {
        return offline;
    }
    if by_policy && offline == Verdict::Ok {
        // Already refused by name, address, surface or secret.
        return offline;
    }
    match policy
        .resolve_target(&e.host, e.port, Duration::from_secs(5))
        .await
    {
        Ok(addr) if by_policy => Verdict::Error(format!(
            "the policy allows this target (it would connect to {addr}), so this refusal would fail (guard_open)"
        )),
        Ok(_) => offline,
        Err(TargetError::Refused(_)) if by_policy => Verdict::Ok,
        Err(TargetError::Refused(r)) => Verdict::Error(format!("the policy refuses it: {r}")),
        Err(TargetError::Dns(r)) => Verdict::Error(format!(
            "does not resolve ({r}); the job would fail, not be refused"
        )),
    }
}

struct Prompter {
    interactive: bool,
}

impl Prompter {
    fn ask(&self, question: &str, default: Option<&str>) -> Result<String> {
        if !self.interactive {
            return default
                .map(str::to_owned)
                .ok_or_else(|| Error::Config(format!("missing: {question} (pass it as a flag)")));
        }
        let mut stderr = std::io::stderr().lock();
        match default {
            Some(d) => {
                let _ = write!(stderr, "{question} [{d}]: ");
            }
            None => {
                let _ = write!(stderr, "{question}: ");
            }
        }
        let _ = stderr.flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| Error::Config(e.to_string()))?;
        let line = line.trim();
        if line.is_empty() {
            default
                .map(str::to_owned)
                .ok_or_else(|| Error::Config(format!("{question} is required")))
        } else {
            Ok(line.to_owned())
        }
    }

    fn list(&self, question: &str, given: &[String], default: &str) -> Result<Vec<String>> {
        if !given.is_empty() {
            return Ok(given.to_vec());
        }
        let answer = self.ask(question, Some(default))?;
        Ok(answer
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect())
    }
}

fn host_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        // macOS has no /etc/hostname and launchd sets no HOSTNAME; ask the kernel.
        .or_else(kernel_host_name)
        .unwrap_or_else(|| "agent".into())
        .chars()
        .take(64)
        .collect()
}

/// The kernel's node name, short form (`mac-17` for `mac-17.local`), the same as
/// `hostname -s` without running a program.
#[cfg(unix)]
fn kernel_host_name() -> Option<String> {
    let uts = rustix::system::uname();
    let name = uts.nodename().to_str().ok()?;
    let short = name.split('.').next().unwrap_or(name).trim();
    (!short.is_empty()).then(|| short.to_owned())
}

#[cfg(not(unix))]
fn kernel_host_name() -> Option<String> {
    None
}

/// The one question about what leaves, asked once at setup with the defaults shown.
fn ask_share(p: &Prompter, a: &InitArgs) -> Result<crate::policy::SharePolicy> {
    use crate::policy::{SharePolicy, TargetShare};
    let targets = match &a.share_targets {
        Some(t) => t.clone(),
        None => {
            if p.interactive {
                out("What InOrbit sees about your checks:");
                out("  full   each check's URL, or host and port");
                out("  hash   a label and a keyed hash; the target stays here (default)");
                out("  label  the label only");
            }
            p.ask("What InOrbit sees (full, hash, label)", Some("hash"))?
        }
    };
    let targets = match targets.trim() {
        "full" => TargetShare::Full,
        "hash" => TargetShare::Hash,
        "label" => TargetShare::Label,
        other => {
            return Err(Error::Config(format!(
                "what InOrbit sees: full, hash or label, not {other:?}"
            )));
        }
    };
    let hostname = match &a.share_hostname {
        Some(h) => h == "on",
        None => matches!(
            p.ask(
                "Send this machine's host name to InOrbit? (yes, no)",
                Some("no")
            )?
            .trim()
            .to_ascii_lowercase()
            .as_str(),
            "yes" | "y" | "on"
        ),
    };
    Ok(SharePolicy { targets, hostname })
}

fn toml_list(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| serde_json::Value::from(s.as_str()).to_string())
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// The policy file `init` writes, with comments a person can follow.
#[must_use]
pub fn policy_text(
    environment: &str,
    domains: &[String],
    allow: &[String],
    secrets: &[String],
) -> String {
    let deny = Policy::from_toml("environment = \"x\"")
        .map(|p| p.networks.deny)
        .unwrap_or_default();
    format!(
        r#"# The local policy of iohr-agent. It wins over anything the platform asks for: work
# outside it is refused and the refusal is shown in the console. Only someone who can edit
# this file changes it; restart the agent to apply a change.
# Reference: https://github.com/inorbithr/dataplane/blob/main/docs/policy.md

# The one environment this agent serves.
environment = "{environment}"

[domains]
# A host under one of these may be checked when every address it resolves to is in
# [networks] allow.
bound = {domains}

[networks]
# CIDRs, addresses, host names or *.suffixes this agent may connect to. A host named
# here may resolve to any address except the denied ones.
allow = {allow}
# Never connected to, even when allowed (link-local and cloud metadata by default).
deny = {deny}

[work]
checks = true
load = false
faults = false
# The transport surfaces read a bounded answer and are off unless listed here:
# "grpc", "sse", "ws", "mqtt", "mcp", "graphql".
surfaces = ["http", "tcp", "tls", "grpc_health"]

[ceilings]
max_concurrent_jobs = 4
max_job_ms = 30000
max_jobs_per_minute = 120

[secrets]
# Secret references a job may name (exact, or ending in *). Empty: no job may use one.
allow = {secrets}

[share]
# What the hello tells the platform about your declared checks: "hash" (a label and a
# keyed hash; the URL, host or address stays here), "label" (the label only) or "full"
# (the target itself). Every message that leaves is in the agent's ledger either way.
targets = "hash"
# Send this machine's host name; false shows the agent's name instead.
hostname = false
"#,
        domains = toml_list(domains),
        allow = toml_list(allow),
        deny = toml_list(&deny),
        secrets = toml_list(secrets),
    )
}

#[allow(clippy::too_many_lines)]
async fn init(a: &InitArgs, config_path: &Path) -> Result<ExitCode> {
    let p = Prompter {
        interactive: !a.yes && std::io::stdin().is_terminal(),
    };
    let dir = a.dir.clone().unwrap_or_else(|| {
        config_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    });
    let cfg_path = dir.join("agent.toml");
    let policy_path = dir.join("policy.toml");
    if !a.force && (cfg_path.exists() || policy_path.exists()) {
        return Err(Error::Config(format!(
            "{} already has a configuration; pass --force to replace it",
            dir.display()
        )));
    }
    let api = if let Some(u) = &a.api {
        u.clone()
    } else {
        let default =
            std::env::var(extsock::API_ENV).unwrap_or_else(|_| config::DEFAULT_API.into());
        Url::parse(&p.ask("Platform API", Some(&default))?)
            .map_err(|e| Error::Config(e.to_string()))?
    };
    let environment = match &a.environment {
        Some(e) => e.clone(),
        None => p.ask(
            "Environment this agent serves (staging, production, …)",
            None,
        )?,
    };
    crate::policy::check_environment(&environment).map_err(Error::Config)?;
    let name = match &a.name {
        Some(n) => n.clone(),
        None => p.ask("Agent name", Some(&host_name()))?,
    };
    let domains = p.list(
        "Bound domains (comma-separated, verified in your account)",
        &a.domains,
        "",
    )?;
    let allow = p.list(
        "Networks and hosts it may reach (CIDRs, hosts, *.suffixes; comma-separated)",
        &a.allow,
        "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
    )?;
    let store = match a.secret_store {
        Some(s) => s,
        None => match p
            .ask(
                "Secret store for check credentials (none, env, file, k8s, vault)",
                Some("none"),
            )?
            .as_str()
        {
            "none" => SecretStore::None,
            "env" => SecretStore::Env,
            "file" => SecretStore::File,
            "k8s" => SecretStore::K8s,
            "vault" => SecretStore::Vault,
            other => return Err(Error::Config(format!("unknown secret store {other}"))),
        },
    };
    let mut cfg = AgentConfig::new(api.clone(), name.clone(), environment.clone());
    cfg.key_alg = a.key_alg;
    let state_dir = a.state_dir.clone().unwrap_or_else(|| dir.join("state"));
    cfg.state_dir = state_dir.clone();
    cfg.key = state_dir.join("agent.key");
    cfg.policy = policy_path.clone();
    let secrets_allow = match store {
        SecretStore::None | SecretStore::File => Vec::new(),
        SecretStore::Env => vec!["env:IOHR_CHECK_*".to_owned()],
        SecretStore::K8s => vec![format!("k8s:{}/*", a.k8s_namespace)],
        SecretStore::Vault => {
            let addr = match &a.vault_addr {
                Some(u) => u.clone(),
                None => Url::parse(&p.ask("Vault address", None)?)
                    .map_err(|e| Error::Config(e.to_string()))?,
            };
            cfg.secrets.vault = Some(VaultConfig {
                addr,
                token: "env:VAULT_TOKEN".into(),
                namespace: None,
            });
            vec![format!("vault:kv/{environment}/*")]
        }
    };

    // Everything is checked before anything is written.
    cfg.validate()?;
    let share = ask_share(&p, a)?;
    let text = crate::share::edit_policy_text(
        &policy_text(&environment, &domains, &allow, &secrets_allow),
        &share,
    )?;
    let policy = Policy::from_toml(&text)?;
    out(&format!("Configuration valid; policy {}", policy.hash()));

    let socket = std::env::var_os(extsock::SOCKET_ENV).map(PathBuf::from);
    let mut new_token: Option<Zeroizing<String>> = None;
    if let (Some(sock), false) = (&socket, a.no_platform) {
        {
            let account = match &a.account {
                Some(acc) => acc.clone(),
                None => p.ask("Account (personal or team) the agent belongs to", None)?,
            };
            let token = extsock::fetch_token(sock, &["domains:read", "agents:write"]).await?;
            let http = http_client(Some(&cfg))?;
            platform::check_domains(&http, &api, &token, &account, &policy.domains.bound).await?;
            out(&format!(
                "Platform check passed: every bound domain is verified in {account}."
            ));
            let created = platform::create_enrollment(
                &http,
                &api,
                &token,
                &account,
                &environment,
                &policy.domains.bound,
                &name,
            )
            .await?;
            out(&format!(
                "Enrollment {} created{}.",
                created.enrollment_id,
                created
                    .expires_at
                    .map(|t| format!(", valid until {t}"))
                    .unwrap_or_default()
            ));
            new_token = Some(created.token);
        }
    }

    keys::create_private_dir(&dir)?;
    keys::write_private(
        &cfg_path,
        header_comment(&cfg.to_toml()?).as_bytes(),
        a.force,
    )?;
    keys::write_private(&policy_path, text.as_bytes(), a.force)?;
    out(&format!(
        "Wrote {} and {}.",
        cfg_path.display(),
        policy_path.display()
    ));

    match new_token {
        Some(token) if a.no_enroll => {
            let f = state_dir.join("enrollment-token");
            keys::write_private(&f, token.as_bytes(), true)?;
            out(&format!(
                "Token saved to {} (0600, single use, one hour). Enroll with: {} --config {} enroll --token-file {}",
                f.display(),
                invoked_as(),
                cfg_path.display(),
                f.display()
            ));
        }
        Some(token) => {
            let http = http_client(Some(&cfg))?;
            let e = enroll::enroll(EnrollParams {
                api: &api,
                token: &token,
                name: &name,
                environment: &environment,
                policy_hash: &policy.hash(),
                key_alg: cfg.key_alg,
                key_path: &cfg.key,
                state_dir: &cfg.state_dir,
                replace: a.force,
                http: &http,
            })
            .await?;
            out(&format!(
                "Enrolled as {}. Start it with: {} run --config {}",
                e.agent_id,
                invoked_as(),
                cfg_path.display()
            ));
        }
        None => {
            out(
                "Next: create an enrollment in the console (Reliability > Agents) for this environment,",
            );
            out(&format!(
                "save the token to a file, and run: {} --config {} enroll --token-file <file>",
                invoked_as(),
                cfg_path.display()
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn config_validate(config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    let overrides = std::env::vars_os()
        .filter(|(k, _)| k.to_string_lossy().starts_with(metadata::ENV_PREFIX))
        .count();
    out(&format!("{}: valid", config_path.display()));
    out(&format!("  api          {}", cfg.api));
    out(&format!("  name         {}", cfg.name));
    out(&format!("  environment  {}", cfg.environment));
    out(&format!(
        "  metadata     {} fields set ({overrides} from the environment), reported: {}",
        cfg.metadata.set_fields(),
        if cfg.metadata.reported().is_some() {
            "yes"
        } else {
            "no"
        }
    ));
    Ok(ExitCode::SUCCESS)
}

fn config_show(config_path: &Path) -> Result<ExitCode> {
    let cfg = AgentConfig::load(config_path)?;
    out(cfg.redacted().to_toml()?.trim_end());
    Ok(ExitCode::SUCCESS)
}

fn config_schema() -> Result<ExitCode> {
    let text = serde_json::to_string_pretty(&config::json_schema())
        .map_err(|e| Error::Config(e.to_string()))?;
    out(&text);
    Ok(ExitCode::SUCCESS)
}

fn header_comment(body: &str) -> String {
    format!(
        "# iohr-agent configuration, written by `iohr-agent init`. What the agent may do is in\n# the policy file, not here. Reference: https://github.com/inorbithr/dataplane\n\n{body}{}",
        metadata::TEMPLATE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_kernel_names_the_host_in_short_form() {
        let name = kernel_host_name().unwrap();
        assert!(!name.is_empty() && !name.contains('.'), "{name}");
    }

    #[test]
    fn generated_policy_is_valid_and_readable() {
        let text = policy_text(
            "staging",
            &["example.com".into()],
            &["10.0.0.0/8".into(), "*.svc.cluster.local".into()],
            &["vault:kv/staging/*".into()],
        );
        let p = Policy::from_toml(&text).unwrap();
        assert_eq!(p.environment, "staging");
        assert_eq!(p.domains.bound, ["example.com"]);
        assert!(p.secret_allowed("vault:kv/staging/x#y"));
        assert!(text.contains("# The local policy"));
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    #[test]
    fn the_written_config_carries_the_metadata_template_and_loads() {
        let cfg = AgentConfig::new(
            Url::parse("https://api.inorbit.hr").unwrap(),
            "a".into(),
            "staging".into(),
        );
        let text = header_comment(&cfg.to_toml().unwrap());
        assert!(text.contains("[metadata.placement]\n# provider ="));
        let back = AgentConfig::parse(
            &text,
            Path::new("agent.toml"),
            std::iter::empty::<(&str, &str)>(),
        )
        .unwrap();
        assert!(back.metadata.is_default());
    }
}
