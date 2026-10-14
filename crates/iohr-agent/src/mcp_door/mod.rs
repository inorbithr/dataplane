//! The MCP door (RFC 0129): the one local endpoint a person's AI sessions use to reach the
//! platform's MCP, and the one holder of the OAuth sign-in behind it.
//!
//! Why one holder: the identity provider rotates refresh tokens and grants a 30 second
//! reuse window. Many sessions each refreshing their own copy of one credential looked like
//! token theft, and the whole chain was revoked. Here the agent is the OAuth client, the
//! sessions hold no platform credential at all, and they reach it through a loopback door
//! that needs a local secret.
//!
//! The door keeps working when the network blips: it answers `initialize` and `tools/list`
//! from a cache, retries what is safe to retry (never a tool call whose reply was lost),
//! and falls back to the last good addresses when the router's DNS fails.
//!
//! Controls kept: the platform's edge is the only authenticator, the sign-in lives only in
//! the keychain, the local door denies by default, and the log carries methods, tool names,
//! status codes and timings, never content.

mod bridge;
mod claude;
pub mod dns;
mod server;
pub mod store;
#[cfg(test)]
mod tests;
pub mod tokens;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Subcommand};
use zeroize::Zeroizing;

pub use bridge::Bridge;
pub use server::{Door, serve_on};

use crate::error::{Error, Result};
use store::Store;
use tokens::{Tokens, random_urlsafe};

/// Sent upstream; the platform's edge refuses the default client string.
pub const USER_AGENT: &str = "iohr-mcp-door/1";

/// The default local address; sessions are configured with it.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:47821";

/// The names that get a DNS fallback.
const DNS_NAMES: [&str; 2] = ["api.inorbit.hr", "auth.inorbit.hr"];

/// Scopes the door asks for.
const SCOPE: &str = "mcp:read mcp:write mcp:generate connections:read decisions:read decisions:write extensions:read trail:read connections:use offline_access";

/// What the door is made of.
#[derive(Debug, Clone)]
pub struct DoorConfig {
    /// Local address of the door.
    pub listen: SocketAddr,
    /// The platform's MCP endpoint.
    pub upstream: String,
    /// The identity provider.
    pub issuer: String,
    /// The public OAuth client (PKCE, no secret).
    pub client_id: String,
    /// Loopback port the sign-in redirect lands on.
    pub redirect_port: u16,
    /// Requested scope.
    pub scope: String,
    /// Where the cache and DNS memory live.
    pub state_dir: PathBuf,
    /// Notifier program (title, body, `--from`), best effort.
    pub notify: Option<PathBuf>,
    /// Waits between retries of a failed upstream call.
    pub backoff: Vec<Duration>,
    /// Names with a DNS fallback.
    pub dns_names: Vec<String>,
    /// How long a sign-in stays open, and the least time between two.
    pub login_every: Duration,
    /// Open the browser for a sign-in.
    pub open_browser: bool,
    /// Keychain item holding the token chain.
    pub token_item: String,
    /// Keychain item holding the local secret.
    pub secret_item: String,
}

impl DoorConfig {
    /// The token endpoint.
    #[must_use]
    pub fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.issuer)
    }

    /// The sign-in redirect.
    #[must_use]
    pub fn redirect(&self) -> String {
        format!("http://localhost:{}/callback", self.redirect_port)
    }

    /// The cache file.
    #[must_use]
    pub fn cache_path(&self) -> PathBuf {
        self.state_dir.join("mcp-bridge-cache.json")
    }

    /// The remembered addresses.
    #[must_use]
    pub fn dns_path(&self) -> PathBuf {
        self.state_dir.join("mcp-bridge-dns.json")
    }
}

/// Options every `mcp` command shares.
#[derive(Debug, Clone, Args)]
pub struct DoorArgs {
    /// The local address of the door.
    #[arg(long, env = "IOHR_MCP_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// The platform's MCP endpoint.
    #[arg(
        long,
        env = "IOHR_MCP_UPSTREAM",
        default_value = "https://api.inorbit.hr/mcp"
    )]
    pub upstream: String,
    /// The identity provider.
    #[arg(
        long,
        env = "IOHR_MCP_ISSUER",
        default_value = "https://auth.inorbit.hr"
    )]
    pub issuer: String,
    /// The public OAuth client id.
    #[arg(
        long,
        env = "IOHR_MCP_CLIENT_ID",
        default_value = "app_5249a4e900f1c8d305d7a0060352a896"
    )]
    pub client_id: String,
    /// The loopback port the sign-in redirect lands on (registered with the client).
    #[arg(long, env = "IOHR_MCP_REDIRECT_PORT", default_value_t = 60354)]
    pub redirect_port: u16,
    /// The folder for the door's cache (default `~/.inorbit/state`).
    #[arg(long, env = "IOHR_MCP_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// A notifier program called with a title, a body and `--from mcp-door`.
    #[arg(long, env = "IOHR_MCP_NOTIFY")]
    pub notify: Option<PathBuf>,
    /// Keychain item for the token chain.
    #[arg(long, env = "IOHR_MCP_TOKEN_ITEM", default_value = "iohr-mcp-bridge")]
    pub token_item: String,
    /// Keychain item for the local secret.
    #[arg(
        long,
        env = "IOHR_MCP_SECRET_ITEM",
        default_value = "iohr-mcp-bridge-local"
    )]
    pub secret_item: String,
    /// Print the sign-in address instead of opening a browser.
    #[arg(long)]
    pub no_browser: bool,
}

impl DoorArgs {
    /// The effective configuration.
    ///
    /// # Errors
    /// No home directory to default the state folder from.
    pub fn config(&self) -> Result<DoorConfig> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let state_dir = match (&self.state_dir, &home) {
            (Some(d), _) => d.clone(),
            (None, Some(h)) => h.join(".inorbit/state"),
            (None, None) => return Err(Error::Config("HOME is not set; pass --state-dir".into())),
        };
        let notify = self
            .notify
            .clone()
            .or_else(|| home.map(|h| h.join(".inorbit/bin/iohr-notify")))
            .filter(|p| p.exists());
        Ok(DoorConfig {
            listen: self.listen,
            upstream: self.upstream.clone(),
            issuer: self.issuer.trim_end_matches('/').to_owned(),
            client_id: self.client_id.clone(),
            redirect_port: self.redirect_port,
            scope: SCOPE.into(),
            state_dir,
            notify,
            backoff: [0.5, 1.0, 2.0, 4.0, 8.0]
                .map(Duration::from_secs_f64)
                .to_vec(),
            dns_names: DNS_NAMES.map(String::from).to_vec(),
            login_every: Duration::from_secs(600),
            open_browser: !self.no_browser,
            token_item: self.token_item.clone(),
            secret_item: self.secret_item.clone(),
        })
    }
}

/// `iohr-agent mcp ...`
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Run the door (macOS: keeps the sign-in in the keychain). Run it under launchd.
    Serve(DoorArgs),
    /// Print the header sessions send to the door, as JSON (for Claude Code's `headersHelper`).
    Headers(DoorArgs),
    /// Open the sign-in in the browser and wait for it.
    Login(DoorArgs),
    /// One line: signed in or not, token time left, upstream state.
    Status(DoorArgs),
    /// Point Claude Code's `inorbit` MCP server at the door (a backup of the file is kept).
    Register(RegisterArgs),
    /// Print the launchd job that runs `mcp serve`.
    Launchd(LaunchdArgs),
}

/// `mcp register`.
#[derive(Debug, Args)]
pub struct RegisterArgs {
    #[command(flatten)]
    pub door: DoorArgs,
    /// Claude Code's user configuration (default `~/.claude.json`).
    #[arg(long)]
    pub file: Option<PathBuf>,
    /// The agent program the helper runs (default: this program).
    #[arg(long)]
    pub program: Option<PathBuf>,
}

/// `mcp launchd`.
#[derive(Debug, Args)]
pub struct LaunchdArgs {
    #[command(flatten)]
    pub door: DoorArgs,
    /// The agent program the job runs (default: this program).
    #[arg(long)]
    pub program: Option<PathBuf>,
}

/// Runs a command.
///
/// # Errors
/// Whatever the command could not do.
pub async fn run(cmd: McpCommand) -> Result<ExitCode> {
    match cmd {
        McpCommand::Serve(a) => serve(&a).await,
        McpCommand::Headers(a) => headers(&a).await,
        McpCommand::Login(a) => login(&a).await,
        McpCommand::Status(a) => status(&a).await,
        McpCommand::Register(a) => claude::register(&a),
        McpCommand::Launchd(a) => {
            out(&claude::launchd_plist(&a)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub(crate) fn out(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Writes a state file atomically, owner-only.
///
/// # Errors
/// The folder or file could not be written.
pub fn write_state(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Tells the person something, best effort.
#[derive(Debug)]
pub struct Notifier {
    program: Option<PathBuf>,
}

impl Notifier {
    /// A notifier calling `program`, or silent.
    #[must_use]
    pub fn new(program: Option<PathBuf>) -> Self {
        Self { program }
    }

    /// Sends one notification; failures are ignored.
    pub async fn send(&self, title: &str, body: &str) {
        let Some(p) = &self.program else { return };
        let body: String = body.chars().take(120).collect();
        let run = tokio::process::Command::new(p)
            .args([title, &body, "--from", "mcp-door"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status();
        let _ = tokio::time::timeout(Duration::from_secs(10), run).await;
    }
}

/// The local secret: read, or made on first use.
async fn local_secret(
    store: &Store,
    item: &str,
    create: bool,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(s) = store.get(item).await?.filter(|s| !s.is_empty()) {
        return Ok(Some(s));
    }
    if !create {
        return Ok(None);
    }
    let s = Zeroizing::new(random_urlsafe(32));
    store.set(item, &s).await?;
    Ok(Some(s))
}

/// The client every call to the platform goes through: no pooled connections (a reused
/// connection that the edge closed would look like a lost reply), the DNS fallback, the
/// edge-friendly user agent.
fn http_client(cfg: &DoorConfig) -> Result<reqwest::Client> {
    let resolver = dns::FallbackResolver::new(
        cfg.dns_names.clone(),
        cfg.dns_path(),
        dns::system_lookup(),
        dns::DOH.map(String::from).to_vec(),
    );
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(resolver))
        .build()
        .map_err(|e| Error::Config(format!("cannot build the HTTP client: {e}")))
}

async fn serve(args: &DoorArgs) -> Result<ExitCode> {
    let cfg = Arc::new(args.config()?);
    let store = Arc::new(Store::Keychain);
    let secret = local_secret(&store, &cfg.secret_item, true)
        .await?
        .ok_or_else(|| Error::Key("no local secret".into()))?;
    crate::redact::register(&secret);
    let http = http_client(&cfg)?;
    let notifier = Arc::new(Notifier::new(cfg.notify.clone()));
    let tokens = Arc::new(Tokens::load(cfg.clone(), store, http.clone(), notifier).await);
    let bridge = Arc::new(Bridge::new(cfg.clone(), http, tokens.clone()));
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| Error::Config(format!("cannot listen on {}: {e}", cfg.listen)))?;
    tracing::info!(listen = %cfg.listen, "mcp door: serving");
    let keep = tokens.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            keep.keep_fresh_tick().await;
        }
    });
    let door = Door::new(bridge, secret);
    tokio::select! {
        r = serve_on(listener, door) => r.map(|()| ExitCode::SUCCESS),
        _ = tokio::signal::ctrl_c() => Ok(ExitCode::SUCCESS),
    }
}

async fn headers(args: &DoorArgs) -> Result<ExitCode> {
    let cfg = args.config()?;
    let secret = local_secret(&Store::Keychain, &cfg.secret_item, true)
        .await?
        .ok_or_else(|| Error::Key("no local secret".into()))?;
    out(&serde_json::json!({ "X-Iohr-Bridge": secret.as_str() }).to_string());
    Ok(ExitCode::SUCCESS)
}

fn local_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| Error::Config(e.to_string()))
}

async fn fetch_status(cfg: &DoorConfig) -> std::result::Result<serde_json::Value, String> {
    let c = local_client().map_err(|e| e.to_string())?;
    let r = c
        .get(format!("http://{}/status", cfg.listen))
        .send()
        .await
        .map_err(|e| tokens::error_class(&e))?;
    r.json().await.map_err(|e| tokens::error_class(&e))
}

async fn status(args: &DoorArgs) -> Result<ExitCode> {
    let cfg = args.config()?;
    match fetch_status(&cfg).await {
        Err(why) => {
            out(&format!(
                "down: the door is not running ({why}); start it: iohr-agent mcp serve (under launchd)"
            ));
            Ok(ExitCode::from(1))
        }
        Ok(s) => {
            let auth = s["auth"].as_str().unwrap_or("?");
            let why = s["auth_why"].as_str().unwrap_or("");
            let up = &s["upstream"];
            out(&format!(
                "auth {auth} ({why}), token {} min, upstream {} ({}), {} tools cached",
                s["token_left_s"].as_i64().unwrap_or(0) / 60,
                up["state"].as_str().unwrap_or("?"),
                up["why"].as_str().unwrap_or(""),
                s["cached_tools"].as_u64().unwrap_or(0),
            ));
            Ok(if auth == "ok" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

async fn login(args: &DoorArgs) -> Result<ExitCode> {
    let cfg = args.config()?;
    let secret = local_secret(&Store::Keychain, &cfg.secret_item, false)
        .await?
        .ok_or_else(|| Error::Key("the door has no local secret yet; start it first".into()))?;
    let c = local_client()?;
    let host = cfg.listen.to_string();
    let r = c
        .post(format!("http://{host}/login"))
        .header("X-Iohr-Bridge", secret.as_str())
        .body("{}")
        .send()
        .await
        .map_err(|e| {
            Error::Session(format!(
                "the door is not running ({})",
                tokens::error_class(&e)
            ))
        })?;
    let v: serde_json::Value = r.json().await.unwrap_or_default();
    out(&format!(
        "Sign-in opened in the browser. If it did not open:\n{}",
        v["url"].as_str().unwrap_or("")
    ));
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if fetch_status(&cfg).await.is_ok_and(|s| s["auth"] == "ok") {
            out("signed in");
            return Ok(ExitCode::SUCCESS);
        }
    }
    out("not signed in yet (the tab may still be open)");
    Ok(ExitCode::from(1))
}
