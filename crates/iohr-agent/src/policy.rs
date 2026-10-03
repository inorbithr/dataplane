//! The local policy (`policy.toml`): what this agent may reach and do. It is owned by the
//! company that runs the agent and wins over anything the platform asks for. See
//! `docs/policy.md` for the reference.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::checks::Surface;
use crate::error::{Error, Result};

/// Hard upper bounds no policy may exceed.
pub mod limits {
    /// Most jobs at once.
    pub const MAX_CONCURRENT_JOBS: u32 = 64;
    /// Longest job, in milliseconds.
    pub const MAX_JOB_MS: u64 = 300_000;
    /// Most jobs per minute.
    pub const MAX_JOBS_PER_MINUTE: u32 = 6_000;
}

/// The parsed, validated policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The one environment this agent serves (`staging`, `production`).
    pub environment: String,
    /// The domains this agent is bound to.
    #[serde(default)]
    pub domains: Domains,
    /// Which addresses and hosts it may connect to.
    #[serde(default)]
    pub networks: Networks,
    /// Which kinds of work it accepts.
    #[serde(default)]
    pub work: Work,
    /// Upper bounds on the work it accepts.
    #[serde(default)]
    pub ceilings: Ceilings,
    /// Which secret references a job may name.
    #[serde(default)]
    pub secrets: SecretsPolicy,
    #[serde(skip)]
    compiled: Compiled,
}

/// `[domains]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domains {
    /// A target named by host must be one of these or under one of them, unless the host
    /// is named in `networks.allow`.
    #[serde(default)]
    pub bound: Vec<String>,
}

/// `[networks]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Networks {
    /// CIDRs (`10.0.0.0/8`), addresses, host names (`db.internal`) or host suffixes
    /// (`*.svc.cluster.local`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// CIDRs never reached, even when allowed. Defaults to link-local and metadata ranges.
    #[serde(default = "default_deny")]
    pub deny: Vec<String>,
}

impl Default for Networks {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: default_deny(),
        }
    }
}

fn default_deny() -> Vec<String> {
    [
        "0.0.0.0/8",
        "169.254.0.0/16",
        "fe80::/10",
        "fd00:ec2::254/128",
        "::/128",
    ]
    .map(String::from)
    .to_vec()
}

/// `[work]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Work {
    /// Surface checks.
    #[serde(default = "yes")]
    pub checks: bool,
    /// Load generation (not in this version; always refused).
    #[serde(default)]
    pub load: bool,
    /// Faults through the proxy (not in this version; always refused).
    #[serde(default)]
    pub faults: bool,
    /// Which check surfaces are accepted.
    #[serde(default = "all_surfaces")]
    pub surfaces: Vec<Surface>,
}

impl Default for Work {
    fn default() -> Self {
        Self {
            checks: true,
            load: false,
            faults: false,
            surfaces: all_surfaces(),
        }
    }
}

fn yes() -> bool {
    true
}

fn all_surfaces() -> Vec<Surface> {
    Surface::ALL.to_vec()
}

/// `[ceilings]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ceilings {
    /// Jobs running at once; more are refused.
    #[serde(default = "default_concurrent")]
    pub max_concurrent_jobs: u32,
    /// Longest a job may run; longer deadlines are cut to this.
    #[serde(default = "default_job_ms")]
    pub max_job_ms: u64,
    /// Jobs accepted per rolling minute; more are refused.
    #[serde(default = "default_per_minute")]
    pub max_jobs_per_minute: u32,
}

impl Default for Ceilings {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: default_concurrent(),
            max_job_ms: default_job_ms(),
            max_jobs_per_minute: default_per_minute(),
        }
    }
}

fn default_concurrent() -> u32 {
    4
}
fn default_job_ms() -> u64 {
    30_000
}
fn default_per_minute() -> u32 {
    120
}

/// `[secrets]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsPolicy {
    /// References a job may name, exact or ending in `*` (`vault:kv/staging/*`). Empty:
    /// no job may use a secret.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct Compiled {
    allow_nets: Vec<IpNet>,
    allow_hosts: Vec<HostPattern>,
    deny_nets: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Exact(String),
    Suffix(String),
}

impl HostPattern {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(h) => host == h,
            Self::Suffix(s) => {
                host.len() > s.len() + 1 && host.ends_with(s.as_str()) && {
                    let dot = host.len() - s.len() - 1;
                    host.as_bytes().get(dot) == Some(&b'.')
                }
            }
        }
    }
}

/// Why a target was not allowed, or that its name did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The policy forbids it; the reason is sent to the platform.
    Refused(String),
    /// The name did not resolve.
    Dns(String),
}

impl Policy {
    /// Reads and validates a policy file.
    ///
    /// # Errors
    /// When the file is missing or invalid.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Self::from_toml(&text).map_err(|e| match e {
            Error::Policy(m) => Error::Policy(format!("{}: {m}", path.display())),
            other => other,
        })
    }

    /// Parses and validates policy TOML.
    ///
    /// # Errors
    /// The first rule broken.
    pub fn from_toml(text: &str) -> Result<Self> {
        let mut p: Self = toml::from_str(text).map_err(|e| Error::Policy(e.to_string()))?;
        p.compile().map_err(Error::Policy)?;
        Ok(p)
    }

    /// Serialises to TOML.
    ///
    /// # Errors
    /// When serialisation fails.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Policy(e.to_string()))
    }

    fn compile(&mut self) -> std::result::Result<(), String> {
        check_environment(&self.environment)?;
        let mut bound = Vec::with_capacity(self.domains.bound.len());
        for d in &self.domains.bound {
            bound.push(normalize_host(d).map_err(|e| format!("domains.bound: {e}"))?);
        }
        self.domains.bound = bound;
        let mut c = Compiled::default();
        for entry in &self.networks.allow {
            if let Some(net) = parse_net(entry) {
                c.allow_nets.push(net);
            } else if let Some(suffix) = entry.strip_prefix("*.") {
                c.allow_hosts.push(HostPattern::Suffix(
                    normalize_host(suffix).map_err(|e| format!("networks.allow: {e}"))?,
                ));
            } else {
                c.allow_hosts.push(HostPattern::Exact(
                    normalize_host(entry).map_err(|e| format!("networks.allow: {e}"))?,
                ));
            }
        }
        for entry in &self.networks.deny {
            c.deny_nets.push(
                parse_net(entry)
                    .ok_or_else(|| format!("networks.deny: {entry} is not a CIDR or address"))?,
            );
        }
        let ce = &self.ceilings;
        if !(1..=limits::MAX_CONCURRENT_JOBS).contains(&ce.max_concurrent_jobs) {
            return Err(format!(
                "ceilings.max_concurrent_jobs must be 1 to {}",
                limits::MAX_CONCURRENT_JOBS
            ));
        }
        if !(100..=limits::MAX_JOB_MS).contains(&ce.max_job_ms) {
            return Err(format!(
                "ceilings.max_job_ms must be 100 to {}",
                limits::MAX_JOB_MS
            ));
        }
        if !(1..=limits::MAX_JOBS_PER_MINUTE).contains(&ce.max_jobs_per_minute) {
            return Err(format!(
                "ceilings.max_jobs_per_minute must be 1 to {}",
                limits::MAX_JOBS_PER_MINUTE
            ));
        }
        for s in &self.secrets.allow {
            let base = s.strip_suffix('*').unwrap_or(s);
            if base.contains('*')
                || !["env:", "file:", "k8s:", "vault:"]
                    .iter()
                    .any(|p| base.starts_with(p))
            {
                return Err(format!(
                    "secrets.allow: {s} must start with env:, file:, k8s: or vault: and may end in one *"
                ));
            }
        }
        self.compiled = c;
        Ok(())
    }

    /// `sha256:<hex>` over the policy's canonical form; what the platform is told.
    #[must_use]
    pub fn hash(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let digest = Sha256::digest(&canonical);
        let mut out = String::with_capacity(7 + 64);
        out.push_str("sha256:");
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Whether a job may name this secret reference.
    #[must_use]
    pub fn secret_allowed(&self, reference: &str) -> bool {
        self.secrets
            .allow
            .iter()
            .any(|p| match p.strip_suffix('*') {
                Some(prefix) => reference.starts_with(prefix),
                None => reference == p,
            })
    }

    /// Whether a surface is accepted.
    #[must_use]
    pub fn surface_allowed(&self, s: Surface) -> bool {
        self.work.checks && self.work.surfaces.contains(&s)
    }

    /// Checks an address against `networks`: deny first, then allow.
    ///
    /// # Errors
    /// The refusal reason.
    pub fn check_ip(&self, ip: IpAddr) -> std::result::Result<(), String> {
        let ip = ip.to_canonical();
        if self.compiled.deny_nets.iter().any(|n| n.contains(&ip)) {
            return Err(format!("{ip} is in networks.deny"));
        }
        if self.compiled.allow_nets.iter().any(|n| n.contains(&ip)) {
            return Ok(());
        }
        Err(format!("{ip} is not in networks.allow"))
    }

    /// Whether a host name may be resolved at all: named in `networks.allow`, or inside a
    /// bound domain. Checked before any DNS query so a refused name is never looked up.
    ///
    /// # Errors
    /// The refusal reason.
    pub fn check_name(&self, host: &str) -> std::result::Result<NameRule, String> {
        if self.compiled.allow_hosts.iter().any(|p| p.matches(host)) {
            return Ok(NameRule::NamedInAllow);
        }
        if self.in_bound_domain(host) {
            return Ok(NameRule::BoundDomain);
        }
        Err(format!(
            "{host} is neither named in networks.allow nor inside a bound domain"
        ))
    }

    fn in_bound_domain(&self, host: &str) -> bool {
        self.domains.bound.iter().any(|d| {
            host == d
                || (host.ends_with(d.as_str())
                    && host.len() > d.len()
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.')
        })
    }

    /// Checks every address a name resolved to and picks the one to connect to. Every
    /// address must pass, so a mixed answer cannot slip a forbidden address in.
    ///
    /// # Errors
    /// The refusal reason.
    pub fn check_resolved(
        &self,
        host: &str,
        rule: NameRule,
        addrs: &[IpAddr],
    ) -> std::result::Result<IpAddr, String> {
        let first = *addrs
            .first()
            .ok_or_else(|| format!("{host} has no address"))?;
        for ip in addrs {
            let ip = ip.to_canonical();
            if self.compiled.deny_nets.iter().any(|n| n.contains(&ip)) {
                return Err(format!(
                    "{host} resolves to {ip}, which is in networks.deny"
                ));
            }
            if rule == NameRule::BoundDomain
                && !self.compiled.allow_nets.iter().any(|n| n.contains(&ip))
            {
                return Err(format!(
                    "{host} resolves to {ip}, which is not in networks.allow"
                ));
            }
        }
        Ok(first.to_canonical())
    }

    /// Resolves a target once and pins the address to connect to, or says why not.
    /// The returned address is the only one the check may use (no second lookup, so no
    /// DNS rebinding between the check and the connection).
    ///
    /// # Errors
    /// A refusal, or a DNS failure.
    pub async fn resolve_target(
        &self,
        host: &str,
        port: u16,
        dns_timeout: Duration,
    ) -> std::result::Result<SocketAddr, TargetError> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check_ip(ip).map_err(TargetError::Refused)?;
            return Ok(SocketAddr::new(ip.to_canonical(), port));
        }
        let name = normalize_host(host).map_err(TargetError::Refused)?;
        let rule = self.check_name(&name).map_err(TargetError::Refused)?;
        let lookup =
            tokio::time::timeout(dns_timeout, tokio::net::lookup_host((name.as_str(), port)))
                .await
                .map_err(|_| TargetError::Dns(format!("{name}: lookup timed out")))?
                .map_err(|e| TargetError::Dns(format!("{name}: {e}")))?;
        let addrs: Vec<IpAddr> = lookup.map(|a| a.ip()).collect();
        let ip = self
            .check_resolved(&name, rule, &addrs)
            .map_err(TargetError::Refused)?;
        Ok(SocketAddr::new(ip, port))
    }
}

/// How a host name was allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRule {
    /// Named in `networks.allow`: any address it resolves to, except denied ones.
    NamedInAllow,
    /// Inside a bound domain: every address must also be in `networks.allow`.
    BoundDomain,
}

fn parse_net(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n.trunc());
    }
    s.parse::<IpAddr>().ok().map(IpNet::from)
}

/// Lower-cases a host name, drops a trailing dot and checks its syntax.
///
/// # Errors
/// What is wrong with it.
pub fn normalize_host(host: &str) -> std::result::Result<String, String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 {
        return Err(format!("{host:?} is not a valid host name"));
    }
    for label in h.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(format!("{host:?} is not a valid host name"));
        }
    }
    Ok(h)
}

/// An environment name: 1 to 32 of `a-z 0-9 -`, starting with a letter.
///
/// # Errors
/// What is wrong with it.
pub fn check_environment(env: &str) -> std::result::Result<(), String> {
    let ok = (1..=32).contains(&env.len())
        && env.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "environment {env:?} must be 1 to 32 characters of a-z, 0-9 and -, starting with a letter"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
environment = "staging"
[domains]
bound = ["Example.COM."]
[networks]
allow = ["10.0.0.0/8", "192.168.1.5", "db.internal", "*.svc.cluster.local"]
[secrets]
allow = ["vault:kv/staging/*", "env:CHECK_TOKEN"]
"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_normalises() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert_eq!(p.domains.bound, ["example.com"]);
        assert!(p.work.checks && !p.work.load && !p.work.faults);
        assert_eq!(p.ceilings.max_concurrent_jobs, 4);
        assert!(p.hash().starts_with("sha256:") && p.hash().len() == 71);
    }

    #[test]
    fn hash_ignores_formatting_but_not_content() {
        let a = Policy::from_toml(POLICY).unwrap();
        let b = Policy::from_toml(&POLICY.replace("  ", " ").replace('\n', "\n\n")).unwrap();
        assert_eq!(a.hash(), b.hash());
        let c = Policy::from_toml(&POLICY.replace("10.0.0.0/8", "10.0.0.0/16")).unwrap();
        assert_ne!(a.hash(), c.hash());
    }

    #[test]
    fn addresses() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert!(p.check_ip(ip("10.1.2.3")).is_ok());
        assert!(p.check_ip(ip("192.168.1.5")).is_ok());
        assert!(p.check_ip(ip("192.168.1.6")).is_err());
        assert!(
            p.check_ip(ip("::ffff:10.0.0.1")).is_ok(),
            "v4-mapped is canonicalised"
        );
        assert!(p.check_ip(ip("8.8.8.8")).is_err());
    }

    #[test]
    fn deny_beats_allow() {
        let p = Policy::from_toml("environment = \"s\"\n[networks]\nallow = [\"0.0.0.0/0\"]\n")
            .unwrap();
        assert!(p.check_ip(ip("1.1.1.1")).is_ok());
        let e = p.check_ip(ip("169.254.169.254")).unwrap_err();
        assert!(e.contains("networks.deny"));
    }

    #[test]
    fn names() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert_eq!(p.check_name("db.internal"), Ok(NameRule::NamedInAllow));
        assert_eq!(
            p.check_name("a.b.svc.cluster.local"),
            Ok(NameRule::NamedInAllow)
        );
        assert!(
            p.check_name("svc.cluster.local").is_err(),
            "suffix needs a label before it"
        );
        assert_eq!(p.check_name("api.example.com"), Ok(NameRule::BoundDomain));
        assert_eq!(p.check_name("example.com"), Ok(NameRule::BoundDomain));
        assert!(p.check_name("badexample.com").is_err());
        assert!(p.check_name("example.com.evil.net").is_err());
    }

    #[test]
    fn resolved_addresses_must_all_pass() {
        let p = Policy::from_toml(POLICY).unwrap();
        // A bound-domain name must resolve inside networks.allow.
        assert_eq!(
            p.check_resolved("api.example.com", NameRule::BoundDomain, &[ip("10.0.0.7")]),
            Ok(ip("10.0.0.7"))
        );
        assert!(
            p.check_resolved(
                "api.example.com",
                NameRule::BoundDomain,
                &[ip("10.0.0.7"), ip("8.8.8.8")]
            )
            .is_err()
        );
        // A name in networks.allow may resolve anywhere except denied ranges.
        assert!(
            p.check_resolved("db.internal", NameRule::NamedInAllow, &[ip("172.16.0.1")])
                .is_ok()
        );
        assert!(
            p.check_resolved(
                "db.internal",
                NameRule::NamedInAllow,
                &[ip("169.254.169.254")]
            )
            .is_err()
        );
        assert!(
            p.check_resolved("db.internal", NameRule::NamedInAllow, &[])
                .is_err()
        );
    }

    #[tokio::test]
    async fn refused_names_are_never_looked_up() {
        let p = Policy::from_toml(POLICY).unwrap();
        let r = p
            .resolve_target("does-not-exist.invalid", 443, Duration::from_millis(1))
            .await;
        assert!(matches!(r, Err(TargetError::Refused(_))), "{r:?}");
        let r = p.resolve_target("[::1]", 80, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(TargetError::Refused(_))));
        let r = p
            .resolve_target("10.9.9.9", 80, Duration::from_secs(1))
            .await;
        assert_eq!(r, Ok("10.9.9.9:80".parse().unwrap()));
    }

    #[test]
    fn secrets() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert!(p.secret_allowed("vault:kv/staging/app#token"));
        assert!(!p.secret_allowed("vault:kv/production/app#token"));
        assert!(p.secret_allowed("env:CHECK_TOKEN"));
        assert!(!p.secret_allowed("env:CHECK_TOKEN_2"));
        assert!(!p.secret_allowed("env:VAULT_TOKEN"));
    }

    #[test]
    fn rejects_bad_policies() {
        for bad in [
            "environment = \"Staging\"",
            "environment = \"s\"\n[ceilings]\nmax_concurrent_jobs = 0",
            "environment = \"s\"\n[ceilings]\nmax_job_ms = 999999999",
            "environment = \"s\"\n[networks]\nallow = [\"not a host\"]",
            "environment = \"s\"\n[networks]\ndeny = [\"example.com\"]",
            "environment = \"s\"\n[secrets]\nallow = [\"*\"]",
            "environment = \"s\"\n[work]\nsurfaces = [\"smtp\"]",
            "environment = \"s\"\nextra = 1",
        ] {
            assert!(Policy::from_toml(bad).is_err(), "{bad}");
        }
    }
}
