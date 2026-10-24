//! Signed HTTP actions (PRD 0117 Slice B): the platform asks this agent to call an API that
//! only it can reach (a self-hosted Grafana first), and the agent answers with a fixed,
//! small shape of what came back.
//!
//! What protects the network the agent sits in (PRD 0117, critique items 7 to 9):
//!
//! - Every job is an envelope signed by the platform with Ed25519. The key is pinned in the
//!   local policy (`[actions] platform_keys`), so a stolen session token alone cannot ask
//!   for anything. The envelope names this agent, the job, the tenant (checked when the
//!   policy names one), when it was issued and when it expires; a job id runs once.
//! - The host must be in `[actions] hosts`, the path must be one of the connector's fixed
//!   routes, the method is `GET`, and the address is resolved once by the policy's
//!   network rules and pinned. Redirects are never followed. Every job has a deadline and
//!   a size cap.
//! - The token is a secret reference, resolved here and sent only to that host. It never
//!   leaves for the platform.
//! - What goes back is shaped by code in this file, never by the job: names and ids of
//!   dashboards and datasources, a dashboard's panels and queries (no data), and for a
//!   query only a summary (how many series and points, which allowed label names). Series
//!   values leave only for a template a user made a sensor here (`[[actions.sensors]]`),
//!   with labels on the allowlist.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::checks::{CheckDetail, ErrorClass};
use crate::policy::{Policy, SecretsPolicy, TargetError, normalize_host};
use crate::secrets::{SecretRef, SecretResolver};
use crate::tls::TlsContext;

/// The job kind this module runs.
pub const KIND: &str = "http_action";
/// The capability announced when `[actions] enabled = true`.
pub const CAPABILITY: &str = "http_action";
/// The only connector this version runs.
pub const GRAFANA: &str = "grafana-self-hosted";

/// Hard bounds no policy and no job may exceed.
pub mod bounds {
    /// Largest answer read from the target (8 MiB).
    pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
    /// The default answer cap (1 MiB).
    pub const DEFAULT_BYTES: u64 = 1024 * 1024;
    /// Largest shaped output sent to the platform (48 KiB): its result frame must fit the
    /// platform's session frame cap (`[session] max_frame_bytes`, 64 KiB by default), or
    /// the platform would close the session. A larger answer fails as `answer`.
    pub const MAX_OUTPUT: usize = 48 * 1024;
    /// Longest an envelope may live, issue to expiry.
    pub const MAX_LIFETIME_SECS: i64 = 600;
    /// How far ahead of this clock an envelope may be issued.
    pub const SKEW_SECS: i64 = 60;
    /// Job ids remembered against replay.
    pub const REPLAY_ENTRIES: usize = 4096;
    /// Longest range a query may cover (7 days).
    pub const MAX_RANGE_SECS: i64 = 7 * 24 * 3600;
    /// Smallest step a query may use.
    pub const MIN_STEP_SECS: i64 = 15;
    /// Most points per series.
    pub const MAX_POINTS: i64 = 1000;
    /// Most series in one answer.
    pub const MAX_SERIES: usize = 50;
    /// Most labels kept per series.
    pub const MAX_LABELS: usize = 16;
    /// Most dashboards or datasources listed.
    pub const MAX_ITEMS: usize = 500;
    /// Most panels kept from one dashboard.
    pub const MAX_PANELS: usize = 200;
    /// Longest query expression kept or sent.
    pub const MAX_EXPR: usize = 4096;
    /// Most sensors in a policy.
    pub const MAX_SENSORS: usize = 64;
}

/// `[actions]` in `policy.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionsPolicy {
    /// Accept action jobs at all. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// The platform's job-signing keys, `ed25519:<base64url public key>`. A job signed by
    /// any other key is refused.
    #[serde(default)]
    pub platform_keys: Vec<String>,
    /// The tenant this agent serves; a job signed for another account is refused. Empty:
    /// the enrollment already binds the agent to one account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// The only hosts an action may call, exact names or addresses. They must also pass
    /// `[networks]`.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Grafana datasource uids a query may use. Empty: no query runs (deny by default).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasources: Vec<String>,
    /// Largest answer read, in bytes (1 MiB by default, at most 8 MiB).
    #[serde(default = "default_bytes")]
    pub max_bytes: u64,
    /// Queries a user made a sensor: they run here on their interval, and only their
    /// series may leave (as signals, or as a query's answer).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensors: Vec<SensorPolicy>,
}

fn default_bytes() -> u64 {
    bounds::DEFAULT_BYTES
}

/// `[[actions.sensors]]`: a Grafana query made a sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorPolicy {
    /// The sensor's name, `a-z 0-9 - _ .`.
    pub name: String,
    /// The connection's saved query template it was made from.
    pub template: String,
    /// The Grafana it reads, `http(s)://host[:port]`.
    pub base_url: String,
    /// The token, as a secret reference (`k8s:observability/grafana-inorbit-sa#token`).
    pub auth: String,
    /// The datasource uid.
    pub datasource_uid: String,
    /// The query.
    pub expr: String,
    /// How often it runs, 15 to 3600 seconds.
    #[serde(default = "sensor_interval")]
    pub interval_secs: u64,
    /// How far back each run looks.
    #[serde(default = "sensor_range")]
    pub range_secs: i64,
    /// The step of the series.
    #[serde(default = "sensor_step")]
    pub step_secs: i64,
    /// Labels kept on its series.
    #[serde(default)]
    pub labels: Vec<String>,
    /// At or past this, `warn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn: Option<f64>,
    /// At or past this, `crit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<f64>,
    /// The thresholds are floors (alert when the value falls to them), not ceilings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub below: bool,
}

fn sensor_interval() -> u64 {
    60
}
fn sensor_range() -> i64 {
    300
}
fn sensor_step() -> i64 {
    60
}

impl ActionsPolicy {
    /// Validates the section; called by [`Policy::from_toml`].
    ///
    /// # Errors
    /// The first rule broken.
    pub fn compile(&mut self, secrets: &SecretsPolicy) -> Result<(), String> {
        if self.enabled && self.platform_keys.is_empty() {
            return Err("actions.platform_keys must pin at least one key when enabled".into());
        }
        for k in &self.platform_keys {
            parse_key(k).map_err(|e| format!("actions.platform_keys: {e}"))?;
        }
        if self.enabled && self.hosts.is_empty() {
            return Err("actions.hosts must name at least one host when enabled".into());
        }
        let mut hosts = Vec::with_capacity(self.hosts.len());
        for h in &self.hosts {
            hosts.push(normalize_host(h).map_err(|e| format!("actions.hosts: {e}"))?);
        }
        self.hosts = hosts;
        for d in &self.datasources {
            if !is_uid(d) {
                return Err(format!(
                    "actions.datasources: {d:?} is not a datasource uid"
                ));
            }
        }
        if !(1024..=bounds::MAX_BYTES).contains(&self.max_bytes) {
            return Err(format!(
                "actions.max_bytes must be 1024 to {}",
                bounds::MAX_BYTES
            ));
        }
        if self.sensors.len() > bounds::MAX_SENSORS {
            return Err(format!("actions.sensors: at most {}", bounds::MAX_SENSORS));
        }
        let mut names = Vec::with_capacity(self.sensors.len());
        for s in &self.sensors {
            let ok_name = (1..=64).contains(&s.name.len())
                && s.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
            if !ok_name || names.contains(&s.name) {
                return Err(format!(
                    "actions.sensors: {:?} must be a unique name of a-z 0-9 - _ .",
                    s.name
                ));
            }
            names.push(s.name.clone());
            if !(15..=3600).contains(&s.interval_secs) {
                return Err(format!(
                    "actions.sensors.{}: interval_secs must be 15 to 3600",
                    s.name
                ));
            }
            check_range(s.range_secs, s.step_secs)
                .map_err(|e| format!("actions.sensors.{}: {e}", s.name))?;
            let base =
                parse_base(&s.base_url).map_err(|e| format!("actions.sensors.{}: {e}", s.name))?;
            if !self.hosts.contains(&base.1) {
                return Err(format!(
                    "actions.sensors.{}: {} is not in actions.hosts",
                    s.name, base.1
                ));
            }
            if !is_uid(&s.datasource_uid) || s.expr.is_empty() || s.expr.len() > bounds::MAX_EXPR {
                return Err(format!(
                    "actions.sensors.{}: needs a datasource uid and an expression of at most {} bytes",
                    s.name,
                    bounds::MAX_EXPR
                ));
            }
            if !self.datasources.contains(&s.datasource_uid) {
                return Err(format!(
                    "actions.sensors.{}: datasource {} is not in actions.datasources",
                    s.name, s.datasource_uid
                ));
            }
            s.auth
                .parse::<SecretRef>()
                .map_err(|e| format!("actions.sensors.{}: {e}", s.name))?;
            if !secret_allowed(secrets, &s.auth) {
                return Err(format!(
                    "actions.sensors.{}: {} is not in [secrets] allow",
                    s.name, s.auth
                ));
            }
        }
        Ok(())
    }

    /// The pinned keys, by key id.
    fn keys(&self) -> Vec<(String, ed25519_dalek::VerifyingKey)> {
        self.platform_keys
            .iter()
            .filter_map(|k| parse_key(k).ok())
            .collect()
    }
}

fn secret_allowed(secrets: &SecretsPolicy, reference: &str) -> bool {
    secrets.allow.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => reference.starts_with(prefix),
        None => reference == p,
    })
}

/// A key's id: the first 16 hex digits of SHA-256 over its 32 bytes. The platform names
/// the key it signed with by this id.
#[must_use]
pub fn key_id(public: &[u8; 32]) -> String {
    let d = Sha256::digest(public);
    d.iter()
        .take(8)
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn parse_key(k: &str) -> Result<(String, ed25519_dalek::VerifyingKey), String> {
    let b64 = k
        .strip_prefix("ed25519:")
        .ok_or_else(|| format!("{k:?} must be ed25519:<base64url public key>"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| format!("{k:?} is not base64url"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| format!("{k:?} is not a 32-byte Ed25519 public key"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| format!("{k:?} is not a valid Ed25519 public key"))?;
    Ok((key_id(&bytes), vk))
}

/// A Grafana uid: 1 to 64 of `A-Z a-z 0-9 - _`.
#[must_use]
pub fn is_uid(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `http(s)://host[:port]` and nothing else: the URL, its host and its port.
fn parse_base(s: &str) -> Result<(url::Url, String, u16), String> {
    let u = url::Url::parse(s).map_err(|e| format!("base_url {s:?}: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(format!("base_url {s:?} must be http or https"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(format!("base_url {s:?} must not carry credentials"));
    }
    if !(u.path().is_empty() || u.path() == "/") || u.query().is_some() || u.fragment().is_some() {
        return Err(format!("base_url {s:?} must be only scheme, host and port"));
    }
    let host = u
        .host_str()
        .ok_or_else(|| format!("base_url {s:?} has no host"))?;
    // The URL keeps a trailing dot while the pinned name would lose it, so the pin
    // would miss and the client would resolve again: one spelling only.
    if host.ends_with('.') {
        return Err(format!("base_url {s:?} must not end its host with a dot"));
    }
    let host =
        normalize_host(host.trim_start_matches('[').trim_end_matches(']')).or_else(|_| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.to_string())
                .map_err(|_| format!("base_url {s:?} has no valid host"))
        })?;
    let port = u
        .port_or_known_default()
        .ok_or_else(|| format!("base_url {s:?} has no port"))?;
    Ok((u, host, port))
}

fn check_range(range: i64, step: i64) -> Result<(), String> {
    if !(1..=bounds::MAX_RANGE_SECS).contains(&range) {
        return Err(format!(
            "the range must be 1 to {} seconds",
            bounds::MAX_RANGE_SECS
        ));
    }
    if step < bounds::MIN_STEP_SECS {
        return Err(format!(
            "the step must be at least {} seconds",
            bounds::MIN_STEP_SECS
        ));
    }
    if range / step + 1 > bounds::MAX_POINTS {
        return Err(format!(
            "range / step gives more than {} points",
            bounds::MAX_POINTS
        ));
    }
    Ok(())
}

/// The job's `spec`: the envelope exactly as signed, its signature and the key's id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    /// The envelope, a JSON text; the signature covers these bytes.
    pub envelope: String,
    /// Ed25519 over `envelope`, base64url.
    pub sig: String,
    /// The signing key's id ([`key_id`]).
    pub key: String,
}

/// What the platform signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Always 1.
    pub v: u32,
    /// The tenant.
    pub account_id: String,
    /// The agent it is for.
    pub agent_id: String,
    /// The job it is for.
    pub job_id: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// The call.
    pub action: ActionSpec,
}

/// The call an envelope asks for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    /// The connector (`grafana-self-hosted`).
    pub connector: String,
    /// The connector's action (`list_dashboards`, `query`, …).
    pub action: String,
    /// The connection's base URL.
    pub base_url: String,
    /// `GET`.
    pub method: String,
    /// One of the connector's fixed routes.
    pub path: String,
    /// Query parameters, in order.
    #[serde(default)]
    pub query: Vec<(String, String)>,
    /// The token, as a secret reference; resolved here, never sent to the platform.
    pub auth: String,
    /// The saved query template a query ran, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Labels a series may keep.
    #[serde(default)]
    pub labels: Vec<String>,
    /// The connection's answer cap, in bytes.
    #[serde(default)]
    pub max_bytes: u64,
}

/// The connector's fixed routes, and the shape each answer gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `/api/search`: dashboards.
    Search,
    /// `/api/dashboards/uid/{uid}`: one dashboard's panels and queries.
    Dashboard,
    /// `/api/datasources`: datasources.
    Datasources,
    /// `/api/datasources/proxy/uid/{uid}/api/v1/query_range`: a Prometheus range query.
    QueryRange,
}

/// Matches a path against the connector's routes; the datasource uid for a query.
///
/// # Errors
/// When the path is none of them.
pub fn route(connector: &str, path: &str) -> Result<(Route, Option<String>), String> {
    if connector != GRAFANA {
        return Err(format!(
            "this agent runs no actions for the connector {connector:?}"
        ));
    }
    let refuse = || format!("the path {path:?} is not one of {GRAFANA}'s routes");
    match path {
        "/api/search" => return Ok((Route::Search, None)),
        "/api/datasources" => return Ok((Route::Datasources, None)),
        _ => {}
    }
    if let Some(uid) = path.strip_prefix("/api/dashboards/uid/") {
        return if is_uid(uid) {
            Ok((Route::Dashboard, None))
        } else {
            Err(refuse())
        };
    }
    if let Some(rest) = path.strip_prefix("/api/datasources/proxy/uid/")
        && let Some(uid) = rest.strip_suffix("/api/v1/query_range")
        && is_uid(uid)
    {
        return Ok((Route::QueryRange, Some(uid.to_owned())));
    }
    Err(refuse())
}

/// An action that passed every check, ready to run.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The connector.
    pub connector: String,
    /// The full URL called.
    pub url: url::Url,
    /// Its host, checked against `[actions] hosts`.
    pub host: String,
    /// Its port.
    pub port: u16,
    /// Which route, so which shape.
    pub route: Route,
    /// The token.
    pub auth: SecretRef,
    /// Labels a series may keep.
    pub labels: Vec<String>,
    /// Series values may leave (the template is a sensor here).
    pub series: bool,
    /// Answer cap.
    pub max_bytes: u64,
    /// When the signed envelope expires (unix seconds): the run ends by then.
    pub expires_at: i64,
}

/// Remembers job ids until their envelope expires, so none runs twice.
#[derive(Debug, Default)]
pub struct Replay {
    seen: Mutex<HashMap<String, i64>>,
}

impl Replay {
    /// Records `job_id` until `expires_at`, or says it was seen.
    ///
    /// # Errors
    /// Seen already, or too many live entries.
    pub fn once(&self, job_id: &str, expires_at: i64, now: i64) -> Result<(), String> {
        let mut seen = match self.seen.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        seen.retain(|_, exp| *exp >= now);
        if seen.contains_key(job_id) {
            return Err(format!("the job {job_id} already ran (replay refused)"));
        }
        if seen.len() >= bounds::REPLAY_ENTRIES {
            return Err("too many action jobs in flight; try again later".into());
        }
        seen.insert(job_id.to_owned(), expires_at);
        Ok(())
    }
}

/// Checks a signed job against the local policy: signature, binding, expiry, replay,
/// host, route, method, query bounds and secret. Nothing is resolved or connected.
///
/// # Errors
/// The refusal reason.
#[allow(clippy::too_many_lines)] // every rule a job passes, top to bottom
pub fn admit(
    policy: &Policy,
    account_id: &str,
    agent_id: &str,
    job_id: &str,
    spec: &Value,
    replay: &Replay,
    now: i64,
) -> Result<Plan, String> {
    let actions = policy
        .actions
        .as_ref()
        .filter(|a| a.enabled)
        .ok_or("actions are not enabled by the local policy ([actions] enabled = false)")?;
    let signed: Signed = serde_json::from_value(spec.clone())
        .map_err(|e| format!("the job is not a signed action: {e}"))?;
    let keys = actions.keys();
    let (_, vk) = keys
        .iter()
        .find(|(id, _)| *id == signed.key)
        .ok_or_else(|| {
            format!(
                "the job is signed by key {}, which is not in [actions] platform_keys",
                signed.key
            )
        })?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signed.sig.trim_end_matches('='))
        .ok()
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .ok_or("the job's signature is malformed")?;
    vk.verify_strict(signed.envelope.as_bytes(), &sig)
        .map_err(|_| "the job's signature does not verify".to_owned())?;
    let env: Envelope = serde_json::from_str(&signed.envelope)
        .map_err(|e| format!("the signed envelope is not one this agent understands: {e}"))?;
    if env.v != 1 {
        return Err(format!("envelope version {} is not supported", env.v));
    }
    if env.agent_id != agent_id {
        return Err("the job is signed for another agent".into());
    }
    if env.job_id != job_id {
        return Err("the job id differs from the one signed".into());
    }
    // The tenant binding is always checked, against the account this agent enrolled
    // in; a policy `account_id` may only repeat it.
    if account_id.is_empty() {
        return Err("this agent has no enrolled account; actions are refused".into());
    }
    if actions
        .account_id
        .as_deref()
        .is_some_and(|a| a != account_id)
    {
        return Err("[actions] account_id differs from the enrolled account".into());
    }
    if env.account_id != account_id {
        return Err("the job is signed for another account".into());
    }
    if env.expires_at <= env.issued_at || env.expires_at - env.issued_at > bounds::MAX_LIFETIME_SECS
    {
        return Err("the envelope's lifetime is out of bounds".into());
    }
    if env.issued_at > now + bounds::SKEW_SECS {
        return Err("the envelope is issued in the future (check the clocks)".into());
    }
    if now > env.expires_at {
        return Err("the envelope has expired".into());
    }
    let a = env.action;
    if a.method != "GET" {
        return Err(format!(
            "the method {} is not allowed; actions read only",
            a.method
        ));
    }
    let (base, host, port) = parse_base(&a.base_url)?;
    if !actions.hosts.contains(&host) {
        return Err(format!(
            "{host} is not in the local policy's [actions] hosts"
        ));
    }
    let (route, datasource) = route(&a.connector, &a.path)?;
    check_query(route, &a.query)?;
    // Deny by default: a query reads only a datasource this machine listed.
    if let Some(ds) = &datasource
        && !actions.datasources.contains(ds)
    {
        return Err(format!(
            "the datasource {ds} is not in the local policy's [actions] datasources"
        ));
    }
    if !policy.secret_allowed(&a.auth) {
        return Err(format!(
            "the secret reference {} is not in the local policy's [secrets] allow",
            a.auth
        ));
    }
    let auth = a.auth.parse::<SecretRef>().map_err(|e| e.to_string())?;
    if a.labels.len() > bounds::MAX_LABELS * 4 {
        return Err("too many labels in the allowlist".into());
    }
    // Series leave only for a sensor this machine declared: same template,
    // same datasource and the very expression it names, and then only with the
    // labels both the job and the sensor allow.
    let expr = a
        .query
        .iter()
        .find(|(k, _)| k == "query")
        .map(|(_, v)| v.as_str());
    let sensor = (route == Route::QueryRange)
        .then(|| {
            a.template.as_ref().and_then(|t| {
                actions.sensors.iter().find(|s| {
                    s.template == *t
                        && s.auth == a.auth
                        && parse_base(&s.base_url).is_ok_and(|(su, sh, sp)| {
                            su.scheme() == base.scheme() && sh == host && sp == port
                        })
                        && Some(s.datasource_uid.as_str()) == datasource.as_deref()
                        && Some(s.expr.as_str()) == expr
                })
            })
        })
        .flatten();
    let series = sensor.is_some();
    let labels: Vec<String> = match sensor {
        Some(s) => a
            .labels
            .into_iter()
            .filter(|l| s.labels.contains(l))
            .collect(),
        None => a.labels,
    };
    let mut url = base;
    url.set_path(&a.path);
    if !a.query.is_empty() {
        url.query_pairs_mut().extend_pairs(a.query.iter());
    }
    let cap = if a.max_bytes == 0 {
        actions.max_bytes
    } else {
        a.max_bytes.min(actions.max_bytes)
    };
    replay.once(&env.job_id, env.expires_at, now)?;
    Ok(Plan {
        connector: a.connector,
        url,
        host,
        port,
        route,
        auth,
        labels,
        series,
        max_bytes: cap,
        expires_at: env.expires_at,
    })
}

/// Each route's query parameters, and the caps on a range query.
fn check_query(route: Route, q: &[(String, String)]) -> Result<(), String> {
    let allowed: &[&str] = match route {
        Route::Search => &["type", "query", "limit"],
        Route::Dashboard | Route::Datasources => &[],
        Route::QueryRange => &["query", "start", "end", "step"],
    };
    let mut seen: Vec<&str> = Vec::with_capacity(q.len());
    for (k, v) in q {
        if !allowed.contains(&k.as_str()) || seen.contains(&k.as_str()) {
            return Err(format!("the query parameter {k:?} is not allowed here"));
        }
        if v.len() > bounds::MAX_EXPR {
            return Err(format!("the query parameter {k:?} is too long"));
        }
        seen.push(k);
    }
    let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    match route {
        Route::Search => {
            if get("type").is_some_and(|t| t != "dash-db") {
                return Err("a search lists dashboards only (type=dash-db)".into());
            }
            if let Some(l) = get("limit")
                && !l
                    .parse::<usize>()
                    .is_ok_and(|n| (1..=bounds::MAX_ITEMS).contains(&n))
            {
                return Err(format!("limit must be 1 to {}", bounds::MAX_ITEMS));
            }
        }
        Route::QueryRange => {
            let num = |k: &str| -> Result<i64, String> {
                get(k)
                    .ok_or_else(|| format!("a query needs {k}"))?
                    .parse::<i64>()
                    .map_err(|_| format!("{k} must be whole seconds"))
            };
            let (start, end, step) = (num("start")?, num("end")?, num("step")?);
            if get("query").is_none_or(str::is_empty) {
                return Err("a query needs its expression".into());
            }
            let range = end
                .checked_sub(start)
                .ok_or("the range between start and end is out of bounds")?;
            check_range(range, step)?;
        }
        Route::Dashboard | Route::Datasources => {}
    }
    Ok(())
}

/// What a fetch failed with.
#[derive(Debug)]
pub enum Fail {
    /// The local policy refused it at run time (the address, the secret).
    Refused(String),
    /// It ran and failed: the class, and the status when one came back.
    Failed(ErrorClass, Option<u16>),
}

/// Calls the plan's URL: the address resolved once by the policy and pinned, no redirect,
/// no proxy, the token as a sensitive header, at most `max_bytes` read. Returns the status
/// and the shaped output.
///
/// # Errors
/// A refusal or a failure.
pub async fn fetch(
    policy: &Policy,
    tls: &TlsContext,
    secrets: &SecretResolver,
    plan: &Plan,
    deadline: Duration,
) -> Result<(u16, Value), Fail> {
    let started = Instant::now();
    let addr = match policy
        .resolve_target(&plan.host, plan.port, Duration::from_secs(5).min(deadline))
        .await
    {
        Ok(a) => a,
        Err(TargetError::Refused(r)) => return Err(Fail::Refused(r)),
        Err(TargetError::Dns(_)) => return Err(Fail::Failed(ErrorClass::Dns, None)),
    };
    let token = secrets
        .resolve(&plan.auth)
        .await
        .map_err(|e| Fail::Refused(format!("could not read the secret on the agent: {e}")))?;
    let remaining = deadline.saturating_sub(started.elapsed());
    let mut builder = tls
        .reqwest_builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(remaining)
        .connect_timeout(remaining)
        .pool_max_idle_per_host(0);
    if plan.url.domain().is_some() {
        builder = builder.resolve(&plan.host, addr);
    }
    let client = builder
        .build()
        .map_err(|_| Fail::Failed(ErrorClass::Tls, None))?;
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
        .map_err(|_| Fail::Refused("the secret is not a valid header value".into()))?;
    bearer.set_sensitive(true);
    drop(token);
    let url = if plan.url.domain().is_some() {
        plan.url.clone()
    } else {
        // An address: connect to the pinned one (the same, canonical).
        let mut u = plan.url.clone();
        let _ = u.set_ip_host(addr.ip());
        u
    };
    let resp = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, bearer)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| Fail::Failed(classify(&e), None))?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        // A redirect is never followed: it would be a second, unchecked target.
        return Err(Fail::Failed(ErrorClass::Status, Some(status)));
    }
    let body = read_capped(resp, plan.max_bytes)
        .await
        .map_err(|c| Fail::Failed(c, Some(status)))?;
    let parsed: Value = serde_json::from_slice(&body)
        .map_err(|_| Fail::Failed(ErrorClass::Answer, Some(status)))?;
    let shaped = shape(plan.route, &parsed, &plan.labels, plan.series)
        .ok_or(Fail::Failed(ErrorClass::Answer, Some(status)))?;
    if serde_json::to_vec(&shaped).map_or(usize::MAX, |b| b.len()) > bounds::MAX_OUTPUT {
        return Err(Fail::Failed(ErrorClass::Answer, Some(status)));
    }
    Ok((status, shaped))
}

fn classify(e: &reqwest::Error) -> ErrorClass {
    if e.is_timeout() {
        ErrorClass::Timeout
    } else if e.is_connect() {
        ErrorClass::Connect
    } else {
        ErrorClass::Answer
    }
}

async fn read_capped(mut resp: reqwest::Response, cap: u64) -> Result<Vec<u8>, ErrorClass> {
    if resp.content_length().is_some_and(|n| n > cap) {
        return Err(ErrorClass::Answer);
    }
    let mut buf = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if (buf.len() + chunk.len()) as u64 > cap {
                    return Err(ErrorClass::Answer);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(buf),
            Err(e) => return Err(classify(&e)),
        }
    }
}

fn s(v: &Value, k: &str) -> Value {
    v.get(k).and_then(Value::as_str).map_or(Value::Null, |x| {
        Value::String(x.chars().take(256).collect())
    })
}

/// The fixed shape each route's answer gets. `None` when the answer is not the shape
/// Grafana gives.
#[must_use]
pub fn shape(route: Route, v: &Value, labels: &[String], series: bool) -> Option<Value> {
    match route {
        Route::Search => {
            let items = v.as_array()?;
            let out: Vec<Value> = items
                .iter()
                .filter(|d| d.get("type").and_then(Value::as_str) == Some("dash-db"))
                .take(bounds::MAX_ITEMS)
                .map(|d| {
                    json!({
                        "uid": s(d, "uid"), "title": s(d, "title"),
                        "folder": s(d, "folderTitle"), "url": s(d, "url"),
                        "tags": d.get("tags").and_then(Value::as_array).map(|t| {
                            t.iter().filter_map(Value::as_str).take(32)
                                .map(|x| Value::String(x.chars().take(64).collect())).collect::<Vec<_>>()
                        }).unwrap_or_default(),
                    })
                })
                .collect();
            Some(json!({ "dashboards": out }))
        }
        Route::Datasources => {
            let items = v.as_array()?;
            let out: Vec<Value> = items
                .iter()
                .take(bounds::MAX_ITEMS)
                .map(|d| {
                    json!({
                        "uid": s(d, "uid"), "name": s(d, "name"), "type": s(d, "type"),
                        "default": d.get("isDefault").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect();
            Some(json!({ "datasources": out }))
        }
        Route::Dashboard => {
            let d = v.get("dashboard")?;
            let meta = v.get("meta").unwrap_or(&Value::Null);
            let mut panels = Vec::new();
            collect_panels(d.get("panels"), &mut panels, 0);
            Some(json!({
                "uid": s(d, "uid"), "title": s(d, "title"),
                "folder": s(meta, "folderTitle"), "url": s(meta, "url"),
                "panels": panels,
            }))
        }
        Route::QueryRange => shape_series(v, labels, series),
    }
}

fn ds_uid(v: Option<&Value>) -> Value {
    match v {
        Some(Value::Object(o)) => o
            .get("uid")
            .and_then(Value::as_str)
            .map_or(Value::Null, |u| Value::String(u.chars().take(64).collect())),
        _ => Value::Null,
    }
}

/// Panels and their queries, rows flattened; never a value.
fn collect_panels(v: Option<&Value>, out: &mut Vec<Value>, depth: u8) {
    let Some(items) = v.and_then(Value::as_array) else {
        return;
    };
    for p in items {
        if out.len() >= bounds::MAX_PANELS || depth > 2 {
            return;
        }
        let queries: Vec<Value> = p
            .get("targets")
            .and_then(Value::as_array)
            .map(|t| {
                t.iter()
                    .take(26)
                    .map(|q| {
                        json!({
                            "ref_id": s(q, "refId"),
                            "expr": q.get("expr").and_then(Value::as_str)
                                .map_or(Value::Null, |e| Value::String(e.chars().take(bounds::MAX_EXPR).collect())),
                            "datasource_uid": ds_uid(q.get("datasource")),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(json!({
            "id": p.get("id").and_then(Value::as_i64),
            "title": s(p, "title"), "type": s(p, "type"),
            "datasource_uid": ds_uid(p.get("datasource")),
            "queries": queries,
        }));
        collect_panels(p.get("panels"), out, depth + 1);
    }
}

/// A Prometheus matrix: the series themselves when `series` (labels on the allowlist,
/// capped), else only how many series and points and which allowed label names.
fn shape_series(v: &Value, labels: &[String], series: bool) -> Option<Value> {
    if v.get("status").and_then(Value::as_str) != Some("success") {
        return None;
    }
    let data = v.get("data")?;
    if data.get("resultType").and_then(Value::as_str) != Some("matrix") {
        return None;
    }
    let result = data.get("result")?.as_array()?;
    if !series {
        let points: usize = result
            .iter()
            .map(|r| {
                r.get("values")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
            })
            .sum();
        let mut names: Vec<&str> = result
            .iter()
            .filter_map(|r| r.get("metric").and_then(Value::as_object))
            .flat_map(|m| m.keys().map(String::as_str))
            .filter(|k| labels.iter().any(|l| l == k))
            .collect();
        names.sort_unstable();
        names.dedup();
        return Some(json!({ "series": result.len(), "points": points, "label_names": names }));
    }
    let out: Vec<Value> = result
        .iter()
        .take(bounds::MAX_SERIES)
        .map(|r| {
            let kept: serde_json::Map<String, Value> = r
                .get("metric")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| labels.iter().any(|l| l == *k))
                        .take(bounds::MAX_LABELS)
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                v.as_str().map_or(Value::Null, |x| {
                                    Value::String(x.chars().take(128).collect())
                                }),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let points: Vec<Value> = r
                .get("values")
                .and_then(Value::as_array)
                .map(|vs| {
                    vs.iter()
                        .take(bounds::MAX_POINTS as usize)
                        .filter_map(|p| {
                            let t = p.get(0)?.as_f64()?;
                            let x = p.get(1)?.as_str()?.parse::<f64>().ok()?;
                            x.is_finite().then(|| json!([t, x]))
                        })
                        .collect()
                })
                .unwrap_or_default();
            json!({ "labels": kept, "points": points })
        })
        .collect();
    Some(json!({ "series": out }))
}

/// A sensor's level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Inside its thresholds.
    Ok,
    /// At or past `warn`.
    Warn,
    /// At or past `crit`.
    Crit,
    /// No value (no series, a failed run).
    Unknown,
}

impl Level {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Crit => "crit",
            Self::Unknown => "unknown",
        }
    }
}

/// Judges a value against a sensor's thresholds.
#[must_use]
pub fn evaluate(value: Option<f64>, warn: Option<f64>, crit: Option<f64>, below: bool) -> Level {
    let Some(v) = value.filter(|v| v.is_finite()) else {
        return Level::Unknown;
    };
    let past = |t: f64| if below { v <= t } else { v >= t };
    if crit.is_some_and(past) {
        Level::Crit
    } else if warn.is_some_and(past) {
        Level::Warn
    } else {
        Level::Ok
    }
}

/// The value a sensor reports: across its series' latest points, the worst one (the
/// highest, or the lowest for floors).
#[must_use]
pub fn latest(shaped: &Value, below: bool) -> Option<f64> {
    let latest = shaped
        .get("series")?
        .as_array()?
        .iter()
        .filter_map(|s| s.get("points")?.as_array()?.last()?.get(1)?.as_f64());
    if below {
        latest.reduce(f64::min)
    } else {
        latest.reduce(f64::max)
    }
}

/// The plan a sensor runs: its own query over its range, series kept.
///
/// # Errors
/// When its base URL no longer parses.
pub fn sensor_plan(s: &SensorPolicy, max_bytes: u64, now: i64) -> Result<Plan, String> {
    let (mut url, host, port) = parse_base(&s.base_url)?;
    url.set_path(&format!(
        "/api/datasources/proxy/uid/{}/api/v1/query_range",
        s.datasource_uid
    ));
    url.query_pairs_mut()
        .append_pair("query", &s.expr)
        .append_pair("start", &(now - s.range_secs).to_string())
        .append_pair("end", &now.to_string())
        .append_pair("step", &s.step_secs.to_string());
    Ok(Plan {
        connector: GRAFANA.into(),
        url,
        host,
        port,
        route: Route::QueryRange,
        auth: s.auth.parse::<SecretRef>().map_err(|e| e.to_string())?,
        labels: s.labels.clone(),
        series: true,
        max_bytes,
        expires_at: now.saturating_add(bounds::MAX_LIFETIME_SECS),
    })
}

/// A sensor's reading, sent as a `signal` frame when the platform accepts them.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    /// The sensor.
    pub sensor: String,
    /// The template it was made from.
    pub template: String,
    /// The value judged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// Its level.
    pub level: Level,
    /// How many series it saw.
    pub series: usize,
    /// When it ran, RFC 3339.
    pub at: String,
    /// The host the reading is about (the agent's id), on the agent's own probes
    /// (`[sensors]`); absent on `[[actions.sensors]]` readings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// The `detail` of an action's result: a status and a class, never a body.
#[must_use]
pub fn detail(started: Instant, status: Option<u16>, class: Option<ErrorClass>) -> CheckDetail {
    CheckDetail {
        ok: class.is_none(),
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        status_code: status,
        error_class: class,
        ..CheckDetail::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    const AGENT: &str = "agt_01TEST";
    const NOW: i64 = 1_800_000_000;

    fn signer() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn pinned(k: &ed25519_dalek::SigningKey) -> String {
        format!(
            "ed25519:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes())
        )
    }

    fn policy(extra: &str) -> Policy {
        Policy::from_toml(&format!(
            r#"
environment = "staging"
[networks]
allow = ["127.0.0.0/8", "grafana.observability.svc.cluster.local"]
deny = []
[secrets]
allow = ["env:GRAFANA_*", "k8s:observability/*"]
[actions]
enabled = true
platform_keys = ["{}"]
account_id = "acct-1"
hosts = ["grafana.observability.svc.cluster.local", "127.0.0.1"]
{extra}
"#,
            pinned(&signer())
        ))
        .unwrap()
    }

    fn action(path: &str, query: &[(&str, &str)]) -> Value {
        json!({
            "connector": GRAFANA, "action": "x",
            "base_url": "http://grafana.observability.svc.cluster.local:3000",
            "method": "GET", "path": path,
            "query": query.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "auth": "k8s:observability/grafana-inorbit-sa#token",
            "labels": ["job"], "max_bytes": 0,
        })
    }

    fn signed_with(k: &ed25519_dalek::SigningKey, env: &Value) -> Value {
        let text = serde_json::to_string(env).unwrap();
        let sig = k.sign(text.as_bytes());
        json!({
            "envelope": text,
            "sig": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            "key": key_id(k.verifying_key().as_bytes()),
        })
    }

    #[allow(clippy::needless_pass_by_value)] // the tests build and hand it over
    fn envelope(job: &str, a: Value) -> Value {
        json!({"v": 1, "account_id": "acct-1", "agent_id": AGENT, "job_id": job,
               "issued_at": NOW - 5, "expires_at": NOW + 55, "action": a})
    }

    fn try_admit(p: &Policy, job: &str, spec: &Value) -> Result<Plan, String> {
        admit(p, "acct-1", AGENT, job, spec, &Replay::default(), NOW)
    }

    #[test]
    fn a_signed_job_on_a_route_is_admitted() {
        let p = policy("");
        let spec = signed_with(
            &signer(),
            &envelope("job_1", action("/api/search", &[("type", "dash-db")])),
        );
        let plan = try_admit(&p, "job_1", &spec).unwrap();
        assert_eq!(plan.route, Route::Search);
        assert_eq!(
            plan.url.as_str(),
            "http://grafana.observability.svc.cluster.local:3000/api/search?type=dash-db"
        );
    }

    #[test]
    fn signature_and_binding_are_checked() {
        let p = policy("");
        let a = action("/api/search", &[]);
        // Another key.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let e = try_admit(
            &p,
            "job_1",
            &signed_with(&other, &envelope("job_1", a.clone())),
        )
        .unwrap_err();
        assert!(e.contains("not in [actions] platform_keys"), "{e}");
        // A changed envelope after signing.
        let mut spec = signed_with(&signer(), &envelope("job_1", a.clone()));
        let tampered = spec["envelope"]
            .as_str()
            .unwrap()
            .replace("/api/search", "/api/datasources");
        spec["envelope"] = Value::String(tampered);
        let e = try_admit(&p, "job_1", &spec).unwrap_err();
        assert!(e.contains("does not verify"), "{e}");
        // Another agent, another job, another account.
        let mut env = envelope("job_1", a.clone());
        env["agent_id"] = json!("agt_OTHER");
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("another agent")
        );
        let env = envelope("job_2", a.clone());
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("job id")
        );
        let mut env = envelope("job_1", a.clone());
        env["account_id"] = json!("acct-2");
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("another account")
        );
        // Expired, from the future, too long-lived.
        let mut env = envelope("job_1", a.clone());
        env["issued_at"] = json!(NOW - 120);
        env["expires_at"] = json!(NOW - 60);
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("expired")
        );
        let mut env = envelope("job_1", a.clone());
        env["issued_at"] = json!(NOW + 300);
        env["expires_at"] = json!(NOW + 400);
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("future")
        );
        let mut env = envelope("job_1", a);
        env["expires_at"] = json!(NOW + 3600);
        assert!(
            try_admit(&p, "job_1", &signed_with(&signer(), &env))
                .unwrap_err()
                .contains("lifetime")
        );
    }

    #[test]
    fn a_job_runs_once() {
        let p = policy("");
        let replay = Replay::default();
        let spec = signed_with(&signer(), &envelope("job_1", action("/api/search", &[])));
        admit(&p, "acct-1", AGENT, "job_1", &spec, &replay, NOW).unwrap();
        let e = admit(&p, "acct-1", AGENT, "job_1", &spec, &replay, NOW).unwrap_err();
        assert!(e.contains("replay"), "{e}");
    }

    #[test]
    fn host_route_and_method_are_allowlisted() {
        let p = policy("");
        let mut a = action("/api/search", &[]);
        a["base_url"] = json!("http://grafana.evil.example:3000");
        let e = try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a))).unwrap_err();
        assert!(
            e.contains("not in the local policy's [actions] hosts"),
            "{e}"
        );
        for path in [
            "/api/admin/users",
            "/api/datasources/proxy/uid/x/api/v1/admin/tsdb/delete_series",
            "/api/dashboards/uid/../../x",
            "/api/datasources/proxy/uid/vm/../../api/admin",
        ] {
            let e = try_admit(
                &p,
                "j",
                &signed_with(&signer(), &envelope("j", action(path, &[]))),
            )
            .unwrap_err();
            assert!(e.contains("not one of"), "{path}: {e}");
        }
        let mut a = action("/api/search", &[]);
        a["method"] = json!("POST");
        let e = try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a))).unwrap_err();
        assert!(e.contains("read only"), "{e}");
        let mut a = action("/api/search", &[]);
        a["base_url"] = json!("http://user:pw@grafana.observability.svc.cluster.local:3000");
        assert!(try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a))).is_err());
        let mut a = action("/api/search", &[]);
        a["auth"] = json!("vault:kv/other#token");
        let e = try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a))).unwrap_err();
        assert!(e.contains("[secrets] allow"), "{e}");
    }

    #[test]
    fn query_bounds_are_enforced() {
        let p = policy(r#"datasources = ["vm"]"#);
        let path = "/api/datasources/proxy/uid/vm/api/v1/query_range";
        let ok = [
            ("query", "up"),
            ("start", "1000"),
            ("end", "4600"),
            ("step", "60"),
        ];
        try_admit(
            &p,
            "j",
            &signed_with(&signer(), &envelope("j", action(path, &ok))),
        )
        .unwrap();
        let cases: [(&[(&str, &str)], &str); 4] = [
            (
                &[
                    ("query", "up"),
                    ("start", "0"),
                    ("end", "1000000"),
                    ("step", "3600"),
                ],
                "range",
            ),
            (
                &[
                    ("query", "up"),
                    ("start", "0"),
                    ("end", "600"),
                    ("step", "1"),
                ],
                "step",
            ),
            (
                &[
                    ("query", "up"),
                    ("start", "0"),
                    ("end", "86400"),
                    ("step", "15"),
                ],
                "points",
            ),
            (
                &[
                    ("query", "up"),
                    ("start", "0"),
                    ("end", "60"),
                    ("step", "15"),
                    ("timeout", "1"),
                ],
                "not allowed",
            ),
        ];
        for (q, want) in cases {
            let e = try_admit(
                &p,
                "j",
                &signed_with(&signer(), &envelope("j", action(path, q))),
            )
            .unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
        let e = try_admit(
            &p,
            "j",
            &signed_with(
                &signer(),
                &envelope(
                    "j",
                    action("/api/datasources/proxy/uid/tempo/api/v1/query_range", &ok),
                ),
            ),
        )
        .unwrap_err();
        assert!(e.contains("[actions] datasources"), "{e}");
    }

    #[test]
    fn disabled_or_unpinned_policies_refuse() {
        let off = Policy::from_toml("environment = \"staging\"\n").unwrap();
        let spec = signed_with(&signer(), &envelope("j", action("/api/search", &[])));
        assert!(
            try_admit(&off, "j", &spec)
                .unwrap_err()
                .contains("not enabled")
        );
        let e = Policy::from_toml(
            "environment = \"staging\"\n[actions]\nenabled = true\nhosts = [\"a\"]\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("platform_keys"), "{e}");
        let e = Policy::from_toml("environment = \"staging\"\n[actions]\nenabled = true\nplatform_keys = [\"ed25519:AAAA\"]\nhosts = [\"a\"]\n").unwrap_err();
        assert!(e.to_string().contains("32-byte"), "{e}");
    }

    #[test]
    fn the_policy_hash_is_unchanged_without_actions() {
        let a = Policy::from_toml("environment = \"staging\"\n").unwrap();
        let canonical = serde_json::to_value(&a).unwrap();
        assert!(canonical.get("actions").is_none());
    }

    #[test]
    fn series_leave_only_for_sensors_with_allowed_labels() {
        let answer = json!({"status": "success", "data": {"resultType": "matrix", "result": [
            {"metric": {"job": "api", "instance": "10.0.0.5:9100", "secret_label": "x"},
             "values": [[1000, "1.5"], [1060, "2.5"]]},
            {"metric": {"job": "db"}, "values": [[1000, "NaN"], [1060, "7"]]}
        ]}});
        let labels = vec!["job".to_owned()];
        let summary = shape(Route::QueryRange, &answer, &labels, false).unwrap();
        assert_eq!(
            summary,
            json!({"series": 2, "points": 4, "label_names": ["job"]})
        );
        let series = shape(Route::QueryRange, &answer, &labels, true).unwrap();
        assert_eq!(series["series"][0]["labels"], json!({"job": "api"}));
        assert_eq!(
            series["series"][0]["points"],
            json!([[1000.0, 1.5], [1060.0, 2.5]])
        );
        assert_eq!(series["series"][1]["points"], json!([[1060.0, 7.0]]));
        assert!(!series.to_string().contains("10.0.0.5"));
        assert_eq!(latest(&series, false), Some(7.0));
        assert_eq!(latest(&series, true), Some(2.5));
    }

    #[test]
    fn a_sensor_template_lets_series_leave() {
        let p = policy(
            r#"
datasources = ["vm"]
[[actions.sensors]]
name = "api-errors"
template = "error-rate"
base_url = "http://grafana.observability.svc.cluster.local:3000"
auth = "k8s:observability/grafana-inorbit-sa#token"
datasource_uid = "vm"
expr = "sum(rate(errors[5m]))"
crit = 5.0
"#,
        );
        let path = "/api/datasources/proxy/uid/vm/api/v1/query_range";
        let q = [
            ("query", "up"),
            ("start", "1000"),
            ("end", "4600"),
            ("step", "60"),
        ];
        let mut a = action(path, &q);
        assert!(
            !try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a.clone())))
                .unwrap()
                .series
        );
        // The sensor's template name alone is not enough: a job that names it
        // but asks another expression gets counts, never series.
        a["template"] = json!("error-rate");
        assert!(
            !try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a)))
                .unwrap()
                .series
        );
        let q = [
            ("query", "sum(rate(errors[5m]))"),
            ("start", "1000"),
            ("end", "4600"),
            ("step", "60"),
        ];
        let mut a = action(path, &q);
        a["template"] = json!("error-rate");
        assert!(
            try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a)))
                .unwrap()
                .series
        );
    }

    #[test]
    fn a_sensor_lets_series_leave_only_from_its_own_grafana_and_token() {
        let p = policy(
            r#"
datasources = ["vm"]
[[actions.sensors]]
name = "api-errors"
template = "error-rate"
base_url = "http://grafana.observability.svc.cluster.local:3000"
auth = "k8s:observability/grafana-inorbit-sa#token"
datasource_uid = "vm"
expr = "sum(rate(errors[5m]))"
crit = 5.0
"#,
        );
        let path = "/api/datasources/proxy/uid/vm/api/v1/query_range";
        let q = [
            ("query", "sum(rate(errors[5m]))"),
            ("start", "1000"),
            ("end", "4600"),
            ("step", "60"),
        ];
        let mut a = action(path, &q);
        a["template"] = json!("error-rate");
        // Another Grafana with the same datasource uid: counts only.
        let mut other = a.clone();
        other["base_url"] = json!("http://127.0.0.1:3000");
        assert!(
            !try_admit(&p, "j", &signed_with(&signer(), &envelope("j", other)))
                .unwrap()
                .series
        );
        // Another port on the same host: counts only.
        let mut port = a.clone();
        port["base_url"] = json!("http://grafana.observability.svc.cluster.local:3001");
        assert!(
            !try_admit(&p, "j", &signed_with(&signer(), &envelope("j", port)))
                .unwrap()
                .series
        );
        // Another token: counts only.
        let mut token = a.clone();
        token["auth"] = json!("k8s:observability/other#token");
        assert!(
            !try_admit(&p, "j", &signed_with(&signer(), &envelope("j", token)))
                .unwrap()
                .series
        );
        assert!(
            try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a)))
                .unwrap()
                .series
        );
    }

    #[test]
    fn a_query_needs_a_listed_datasource() {
        // No [actions] datasources: no query runs at all (deny by default).
        let p = policy("");
        let path = "/api/datasources/proxy/uid/vm/api/v1/query_range";
        let q = [
            ("query", "up"),
            ("start", "1000"),
            ("end", "4600"),
            ("step", "60"),
        ];
        let e = try_admit(
            &p,
            "j",
            &signed_with(&signer(), &envelope("j", action(path, &q))),
        )
        .unwrap_err();
        assert!(e.contains("[actions] datasources"), "{e}");
    }

    #[test]
    fn a_trailing_dot_host_is_refused() {
        let p = policy("");
        let mut a = action("/api/search", &[]);
        a["base_url"] = json!("http://grafana.observability.svc.cluster.local.:3000");
        let e = try_admit(&p, "j", &signed_with(&signer(), &envelope("j", a))).unwrap_err();
        assert!(e.contains("dot"), "{e}");
    }

    #[test]
    fn extreme_timestamps_are_refused_not_wrapped() {
        let p = policy(r#"datasources = ["vm"]"#);
        let path = "/api/datasources/proxy/uid/vm/api/v1/query_range";
        let (max, min) = (i64::MAX.to_string(), i64::MIN.to_string());
        let q = [
            ("query", "up"),
            ("start", max.as_str()),
            ("end", min.as_str()),
            ("step", "60"),
        ];
        let e = try_admit(
            &p,
            "j",
            &signed_with(&signer(), &envelope("j", action(path, &q))),
        )
        .unwrap_err();
        assert!(e.contains("range"), "{e}");
    }

    #[test]
    fn the_enrolled_account_binds_even_without_a_policy_account() {
        let mut p = policy("");
        if let Some(a) = p.actions.as_mut() {
            a.account_id = None;
        }
        let mut env = envelope("j", action("/api/search", &[]));
        env["account_id"] = json!("acct-2");
        let e = try_admit(&p, "j", &signed_with(&signer(), &env)).unwrap_err();
        assert!(e.contains("another account"), "{e}");
        // No enrolled account at all: refused.
        let env = envelope("j", action("/api/search", &[]));
        let e = admit(
            &p,
            "",
            AGENT,
            "j",
            &signed_with(&signer(), &env),
            &Replay::default(),
            NOW,
        )
        .unwrap_err();
        assert!(e.contains("no enrolled account"), "{e}");
    }

    #[test]
    fn dashboards_keep_panels_and_queries_not_data() {
        let answer = json!({"meta": {"folderTitle": "Ops", "url": "/d/abc"}, "dashboard": {
            "uid": "abc", "title": "API",
            "panels": [{"id": 1, "title": "Rate", "type": "timeseries",
                        "datasource": {"uid": "vm", "type": "prometheus"},
                        "targets": [{"refId": "A", "expr": "rate(x[5m])", "datasource": {"uid": "vm"}}],
                        "snapshotData": [1, 2, 3]},
                       {"id": 2, "type": "row", "title": "More", "panels": [{"id": 3, "title": "Inner", "type": "stat"}]}]}});
        let out = shape(Route::Dashboard, &answer, &[], false).unwrap();
        assert_eq!(out["panels"].as_array().unwrap().len(), 3);
        assert_eq!(out["panels"][0]["queries"][0]["expr"], "rate(x[5m])");
        assert!(!out.to_string().contains("snapshotData"));
    }

    mod net {
        use super::*;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        struct Rig {
            _dir: tempfile::TempDir,
            policy: Policy,
            tls: TlsContext,
            secrets: SecretResolver,
            auth: String,
        }

        fn rig(max_bytes: u64) -> Rig {
            crate::tls::install_crypto_provider();
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("token");
            std::fs::write(&file, "s3cret-token\n").unwrap();
            let auth = format!("file:{}", file.display());
            let policy = Policy::from_toml(&format!(
                r#"
environment = "staging"
[networks]
allow = ["127.0.0.0/8"]
deny = []
[secrets]
allow = ["{auth}"]
[actions]
enabled = true
platform_keys = ["{}"]
hosts = ["127.0.0.1"]
datasources = ["vm"]
max_bytes = {max_bytes}
"#,
                pinned(&signer())
            ))
            .unwrap();
            let tls = TlsContext::new(None).unwrap();
            let secrets = SecretResolver::new(crate::config::SecretsConfig::default(), tls.clone());
            Rig {
                _dir: dir,
                policy,
                tls,
                secrets,
                auth,
            }
        }

        fn plan_for(
            r: &Rig,
            server: &MockServer,
            p: &str,
            q: &[(&str, &str)],
            template: Option<&str>,
        ) -> Result<Plan, String> {
            let mut a = action(p, q);
            a["base_url"] = json!(server.uri());
            a["auth"] = json!(r.auth);
            if let Some(t) = template {
                a["template"] = json!(t);
            }
            let job = "job_net";
            let mut env = envelope(job, a);
            env["account_id"] = json!("acct-1");
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            env["issued_at"] = json!(now - 1);
            env["expires_at"] = json!(now + 60);
            admit(
                &r.policy,
                "acct-1",
                AGENT,
                job,
                &signed_with(&signer(), &env),
                &Replay::default(),
                now,
            )
        }

        #[tokio::test]
        async fn lists_dashboards_with_the_token_and_shapes_them() {
            let r = rig(bounds::DEFAULT_BYTES);
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/search"))
                .and(header("authorization", "Bearer s3cret-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {"uid": "abc", "title": "API", "type": "dash-db", "folderTitle": "Ops", "url": "/d/abc", "tags": ["prod"], "orgId": 1},
                    {"uid": "f1", "title": "Folder", "type": "dash-folder"}
                ])))
                .expect(1)
                .mount(&server)
                .await;
            let plan = plan_for(&r, &server, "/api/search", &[("type", "dash-db")], None).unwrap();
            let (code, out) = fetch(&r.policy, &r.tls, &r.secrets, &plan, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(code, 200);
            assert_eq!(
                out,
                json!({"dashboards": [{"uid": "abc", "title": "API", "folder": "Ops", "url": "/d/abc", "tags": ["prod"]}]})
            );
            assert!(!out.to_string().contains("s3cret"));
        }

        #[tokio::test]
        async fn a_redirect_is_never_followed() {
            let r = rig(bounds::DEFAULT_BYTES);
            let server = MockServer::start().await;
            let elsewhere = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .expect(0)
                .mount(&elsewhere)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/datasources"))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("{}/api/datasources", elsewhere.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            let plan = plan_for(&r, &server, "/api/datasources", &[], None).unwrap();
            let e = fetch(&r.policy, &r.tls, &r.secrets, &plan, Duration::from_secs(5))
                .await
                .unwrap_err();
            assert!(
                matches!(e, Fail::Failed(ErrorClass::Status, Some(302))),
                "{e:?}"
            );
            // `expect(0)` on the other server is checked when it drops.
        }

        #[tokio::test]
        async fn an_answer_past_the_cap_fails() {
            let r = rig(2048);
            let server = MockServer::start().await;
            let big: Vec<Value> = (0..200).map(|i| json!({"uid": format!("d{i}"), "name": "x".repeat(40), "type": "prometheus"})).collect();
            Mock::given(method("GET"))
                .and(path("/api/datasources"))
                .respond_with(ResponseTemplate::new(200).set_body_json(big))
                .mount(&server)
                .await;
            let plan = plan_for(&r, &server, "/api/datasources", &[], None).unwrap();
            let e = fetch(&r.policy, &r.tls, &r.secrets, &plan, Duration::from_secs(5))
                .await
                .unwrap_err();
            assert!(matches!(e, Fail::Failed(ErrorClass::Answer, _)), "{e:?}");
        }

        #[tokio::test]
        async fn a_query_without_a_sensor_template_leaves_only_counts() {
            let r = rig(bounds::DEFAULT_BYTES);
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/datasources/proxy/uid/vm/api/v1/query_range"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"status": "success", "data": {"resultType": "matrix", "result": [
                        {"metric": {"job": "api", "pod": "api-7f9"}, "values": [[1000, "3"]]}
                    ]}}),
                ))
                .mount(&server)
                .await;
            let q = [
                ("query", "up"),
                ("start", "1000"),
                ("end", "4600"),
                ("step", "60"),
            ];
            let plan = plan_for(
                &r,
                &server,
                "/api/datasources/proxy/uid/vm/api/v1/query_range",
                &q,
                Some("error-rate"),
            )
            .unwrap();
            assert!(!plan.series);
            let (_, out) = fetch(&r.policy, &r.tls, &r.secrets, &plan, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(
                out,
                json!({"series": 1, "points": 1, "label_names": ["job"]})
            );
        }

        #[tokio::test]
        async fn a_host_outside_the_policy_is_refused_before_connecting() {
            let r = rig(bounds::DEFAULT_BYTES);
            let server = MockServer::start().await;
            let mut a = action("/api/search", &[]);
            a["base_url"] = json!(server.uri().replace("127.0.0.1", "localhost"));
            a["auth"] = json!(r.auth);
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let mut env = envelope("j", a);
            env["issued_at"] = json!(now);
            env["expires_at"] = json!(now + 60);
            let e = admit(
                &r.policy,
                "acct-1",
                AGENT,
                "j",
                &signed_with(&signer(), &env),
                &Replay::default(),
                now,
            )
            .unwrap_err();
            assert!(e.contains("[actions] hosts"), "{e}");
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap_or_default()
                    .is_empty()
            );
        }
    }

    #[test]
    fn thresholds() {
        assert_eq!(evaluate(Some(1.0), Some(5.0), Some(10.0), false), Level::Ok);
        assert_eq!(
            evaluate(Some(5.0), Some(5.0), Some(10.0), false),
            Level::Warn
        );
        assert_eq!(
            evaluate(Some(12.0), Some(5.0), Some(10.0), false),
            Level::Crit
        );
        assert_eq!(evaluate(Some(0.5), Some(1.0), Some(0.9), true), Level::Crit);
        assert_eq!(
            evaluate(Some(0.95), Some(1.0), Some(0.9), true),
            Level::Warn
        );
        assert_eq!(evaluate(None, Some(1.0), None, false), Level::Unknown);
        assert_eq!(
            evaluate(Some(f64::NAN), Some(1.0), None, false),
            Level::Unknown
        );
    }
}
