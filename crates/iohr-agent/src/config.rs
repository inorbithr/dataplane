//! `agent.toml`: where the platform is, where the agent keeps its files, and the local
//! services it runs (admin page, telemetry, secret stores). What the agent may *do* is in
//! the policy file, not here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};
use crate::keys::KeyAlg;

/// The environment variable that names the configuration file.
pub const CONFIG_ENV: &str = "IOHR_AGENT_CONFIG";
/// The system-wide configuration file used by packages and containers.
pub const SYSTEM_CONFIG: &str = "/etc/iohr-agent/agent.toml";
/// The platform's public API.
pub const DEFAULT_API: &str = "https://api.inorbit.hr";
/// Default address of the local admin page.
pub const DEFAULT_ADMIN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7790);

/// The parsed `agent.toml`. Relative paths are resolved against the file's directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// The platform API base URL.
    pub api: Url,
    /// A name for this agent shown in the console.
    pub name: String,
    /// The environment this agent serves; must equal the policy's.
    pub environment: String,
    /// The policy file.
    #[serde(default = "default_policy")]
    pub policy: PathBuf,
    /// The private key file (mode 0600).
    #[serde(default = "default_key")]
    pub key: PathBuf,
    /// Where the enrollment record lives.
    #[serde(default = "default_state")]
    pub state_dir: PathBuf,
    /// Which key to make at enrollment.
    #[serde(default)]
    pub key_alg: KeyAlg,
    /// The local admin page.
    #[serde(default)]
    pub admin: AdminConfig,
    /// OpenTelemetry export.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Secret stores the agent may read references from.
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// TLS trust.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Session tuning.
    #[serde(default)]
    pub session: SessionConfig,
}

/// The read-only admin page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Serve it at all.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Where it listens. Loopback unless `allow_non_loopback` is set.
    #[serde(default = "default_admin")]
    pub listen: SocketAddr,
    /// Allow a non-loopback address (for a cluster-internal page behind a network policy).
    #[serde(default)]
    pub allow_non_loopback: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: DEFAULT_ADMIN,
            allow_non_loopback: false,
        }
    }
}

/// OpenTelemetry export over OTLP/HTTP. Off unless enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Export traces, metrics and logs.
    #[serde(default)]
    pub enabled: bool,
    /// The collector's OTLP/HTTP base URL; `/v1/traces` etc. are appended.
    #[serde(default = "default_otlp")]
    pub endpoint: String,
    /// `service.name` on everything exported.
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otlp(),
            service_name: default_service_name(),
        }
    }
}

/// Secret stores. A reference is resolved at the moment of the call and dropped after.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// HashiCorp Vault (KV version 2).
    pub vault: Option<VaultConfig>,
    /// Kubernetes Secrets, read with the pod's service account.
    #[serde(default)]
    pub kubernetes: KubernetesConfig,
}

/// HashiCorp Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// The address of Vault, e.g. `https://vault.internal:8200`.
    pub addr: Url,
    /// Where the Vault token comes from: `env:NAME` or `file:/path`.
    #[serde(default = "default_vault_token")]
    pub token: String,
    /// Vault Enterprise namespace.
    pub namespace: Option<String>,
}

/// Kubernetes API access for `k8s:` references.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesConfig {
    /// API server; defaults to the in-cluster address from `KUBERNETES_SERVICE_HOST`.
    pub api: Option<Url>,
    /// The service account token file.
    #[serde(default = "default_sa_token")]
    pub token_file: PathBuf,
    /// The cluster CA bundle.
    #[serde(default = "default_sa_ca")]
    pub ca_file: PathBuf,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            api: None,
            token_file: default_sa_token(),
            ca_file: default_sa_ca(),
        }
    }
}

/// TLS trust beyond the system's roots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// A PEM bundle of extra CA certificates (a company CA).
    pub ca_file: Option<PathBuf>,
}

/// Reconnect timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// First reconnect delay ceiling, in milliseconds.
    #[serde(default = "default_backoff_min")]
    pub backoff_min_ms: u64,
    /// Largest reconnect delay ceiling, in milliseconds.
    #[serde(default = "default_backoff_max")]
    pub backoff_max_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            backoff_min_ms: default_backoff_min(),
            backoff_max_ms: default_backoff_max(),
        }
    }
}

fn yes() -> bool {
    true
}
fn default_policy() -> PathBuf {
    "policy.toml".into()
}
fn default_key() -> PathBuf {
    "agent.key".into()
}
fn default_state() -> PathBuf {
    "state".into()
}
fn default_admin() -> SocketAddr {
    DEFAULT_ADMIN
}
fn default_otlp() -> String {
    "http://127.0.0.1:4318".into()
}
fn default_service_name() -> String {
    "iohr-agent".into()
}
fn default_vault_token() -> String {
    "env:VAULT_TOKEN".into()
}
fn default_sa_token() -> PathBuf {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
}
fn default_sa_ca() -> PathBuf {
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into()
}
fn default_backoff_min() -> u64 {
    1_000
}
fn default_backoff_max() -> u64 {
    60_000
}

impl AgentConfig {
    /// A configuration with defaults for everything but the essentials.
    #[must_use]
    pub fn new(api: Url, name: String, environment: String) -> Self {
        Self {
            api,
            name,
            environment,
            policy: default_policy(),
            key: default_key(),
            state_dir: default_state(),
            key_alg: KeyAlg::default(),
            admin: AdminConfig::default(),
            telemetry: TelemetryConfig::default(),
            secrets: SecretsConfig::default(),
            tls: TlsConfig::default(),
            session: SessionConfig::default(),
        }
    }

    /// Reads, resolves relative paths against the file's directory, and validates.
    ///
    /// # Errors
    /// When the file is missing or invalid.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let mut cfg: Self =
            toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        cfg.resolve_paths(base);
        cfg.validate()?;
        Ok(cfg)
    }

    /// Makes every relative path absolute against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.policy);
        fix(&mut self.key);
        fix(&mut self.state_dir);
        if let Some(ca) = &mut self.tls.ca_file {
            fix(ca);
        }
    }

    /// Checks the rules a file must follow.
    ///
    /// # Errors
    /// The first rule broken.
    pub fn validate(&self) -> Result<()> {
        check_platform_url(&self.api).map_err(|e| Error::Config(format!("api: {e}")))?;
        if self.name.trim().is_empty() || self.name.len() > 64 {
            return Err(Error::Config("name must be 1 to 64 characters".into()));
        }
        crate::policy::check_environment(&self.environment).map_err(Error::Config)?;
        if !self.admin.allow_non_loopback && !self.admin.listen.ip().is_loopback() {
            return Err(Error::Config(format!(
                "admin.listen {} is not a loopback address; set admin.allow_non_loopback = true to serve it beyond this machine",
                self.admin.listen
            )));
        }
        if self.session.backoff_min_ms == 0
            || self.session.backoff_max_ms < self.session.backoff_min_ms
        {
            return Err(Error::Config(
                "session.backoff_min_ms must be > 0 and <= backoff_max_ms".into(),
            ));
        }
        if let Err(e) = Url::parse(&self.telemetry.endpoint) {
            return Err(Error::Config(format!("telemetry.endpoint: {e}")));
        }
        if let Some(v) = &self.secrets.vault {
            check_platform_url(&v.addr)
                .map_err(|e| Error::Config(format!("secrets.vault.addr: {e}")))?;
            if !(v.token.starts_with("env:") || v.token.starts_with("file:")) {
                return Err(Error::Config(
                    "secrets.vault.token must be env:NAME or file:/path".into(),
                ));
            }
        }
        Ok(())
    }

    /// Serialises to TOML.
    ///
    /// # Errors
    /// When serialisation fails.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }
}

/// `https`, or `http` to a loopback address (tests and local development only).
///
/// # Errors
/// A description of what is wrong.
pub fn check_platform_url(url: &Url) -> std::result::Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        "http" => Err(format!(
            "{url} must use https (plain http only to a loopback address)"
        )),
        other => Err(format!("{url}: unsupported scheme {other}")),
    }
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

/// Where the configuration file is when none is named: `$IOHR_AGENT_CONFIG`, then the
/// system file if it exists, then the user's configuration directory.
#[must_use]
pub fn default_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os(CONFIG_ENV) {
        return PathBuf::from(p);
    }
    let system = PathBuf::from(SYSTEM_CONFIG);
    if cfg!(unix) && system.exists() {
        return system;
    }
    user_config_dir().join("iohr-agent").join("agent.toml")
}

fn user_config_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(p) = std::env::var_os("APPDATA")
    {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home).join(".config");
    }
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_file_gets_defaults_and_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(
            &path,
            "api = \"https://api.inorbit.hr\"\nname = \"a\"\nenvironment = \"staging\"\n",
        )
        .unwrap();
        let cfg = AgentConfig::load(&path).unwrap();
        assert_eq!(cfg.policy, dir.path().join("policy.toml"));
        assert_eq!(cfg.key_alg, KeyAlg::Es256);
        assert!(!cfg.telemetry.enabled);
        assert!(cfg.admin.listen.ip().is_loopback());
    }

    #[test]
    fn refuses_plain_http_off_loopback_and_open_admin() {
        let mut cfg = AgentConfig::new(
            Url::parse("http://api.example.com").unwrap(),
            "a".into(),
            "staging".into(),
        );
        assert!(cfg.validate().is_err());
        cfg.api = Url::parse("http://127.0.0.1:9").unwrap();
        assert!(cfg.validate().is_ok());
        cfg.admin.listen = "0.0.0.0:7790".parse().unwrap();
        assert!(cfg.validate().is_err());
        cfg.admin.allow_non_loopback = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn unknown_keys_are_errors() {
        let r: std::result::Result<AgentConfig, _> =
            toml::from_str("api = \"https://a.b\"\nname = \"a\"\nenvironment = \"s\"\nadmn = {}\n");
        assert!(r.is_err());
    }
}
