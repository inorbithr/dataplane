//! The command line: `init`, `enroll`, `run`, `status`, `policy check`. As an iohr
//! extension the same commands are `iohr agent …`.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};
use tokio::sync::watch;
use url::Url;
use zeroize::Zeroizing;

use crate::agent::Agent;
use crate::config::{self, AgentConfig, VaultConfig};
use crate::enroll::{self, EnrollParams, Enrollment};
use crate::error::{Error, Result};
use crate::extsock;
use crate::keys::{self, AgentKey, KeyAlg};
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
                Error::Config(_) | Error::Policy(_) => 2,
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
        Command::Run(_) => Ok(ExitCode::SUCCESS),
    }
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
    let key = AgentKey::load(&cfg.key)?;
    let agent = Arc::new(Agent::new(cfg, policy, enrollment, key)?);
    tracing::info!(
        agent_id = %agent.enrollment.agent_id,
        environment = %agent.config.environment,
        policy_hash = %agent.policy_hash,
        "starting"
    );
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("stopping");
        let _ = tx.send(true);
    });
    agent.run(rx).await
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
        match client
            .get(format!("http://{addr}/status.json"))
            .send()
            .await
        {
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
        .unwrap_or_else(|| "agent".into())
        .chars()
        .take(64)
        .collect()
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
surfaces = ["http", "tcp", "tls", "grpc_health"]

[ceilings]
max_concurrent_jobs = 4
max_job_ms = 30000
max_jobs_per_minute = 120

[secrets]
# Secret references a job may name (exact, or ending in *). Empty: no job may use one.
allow = {secrets}
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
    let text = policy_text(&environment, &domains, &allow, &secrets_allow);
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

fn header_comment(body: &str) -> String {
    format!(
        "# iohr-agent configuration, written by `iohr-agent init`. What the agent may do is in\n# the policy file, not here. Reference: https://github.com/inorbithr/dataplane\n\n{body}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
