//! `checks.toml`: the checks this agent declares (RFC 0040.1). The platform turns each
//! entry into a monitor managed by this agent; `[[refuse]]` entries are checks whose
//! success is a refusal. The file is optional; without it the agent declares nothing.
//!
//! The file is the human form (`every = "5m"`, `by = "policy"`); the hello carries the
//! normalized form (`every_secs`, `kind`, `refuse_by`) and `checks_hash`, the SHA-256 of
//! its canonical JSON. See `docs/checks.md`.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::checks::{AuthSpec, CheckSpec, Expect, Params, Surface, Target, bounds};
use crate::error::{Error, Result};
use crate::policy::{NameRule, Policy, normalize_host};

/// Bounds a checks file must respect (the platform enforces the same).
pub mod limits {
    /// Most entries, `[[check]]` and `[[refuse]]` together.
    pub const MAX_CHECKS: usize = 50;
    /// Longest name.
    pub const MAX_NAME: usize = 64;
    /// Shortest interval, in seconds.
    pub const MIN_EVERY_SECS: u64 = 60;
    /// Longest interval, in seconds.
    pub const MAX_EVERY_SECS: u64 = 86_400;
    /// Most failed runs before a monitor goes down.
    pub const MAX_FAIL_AFTER: u8 = 5;
    /// Longest `max_ms`.
    pub const MAX_MS: u64 = 30_000;
    /// Longest `valid_for_days`.
    pub const MAX_VALID_FOR_DAYS: u16 = 365;
    /// Longest URL.
    pub const MAX_URL: usize = 2_048;
    /// Longest gRPC service name.
    pub const MAX_SERVICE: usize = 256;
    /// Largest canonical form; keeps the hello well under the platform's 64 KiB frame.
    pub const MAX_CANONICAL_BYTES: usize = 48 * 1024;
    /// Most tags on one check (the platform's limit).
    pub const MAX_TAGS: usize = 10;
    /// Longest GraphQL query, RPC method, MQTT topic or MCP tool name.
    pub const MAX_QUERY: usize = 8 * 1024;
    /// Longest method, topic or tool name.
    pub const MAX_NAME_FIELD: usize = 256;
}

/// The categories a check may name (the platform's fixed list).
pub const CATEGORIES: [&str; 6] = [
    "availability",
    "transport",
    "contract",
    "security",
    "performance",
    "synthetic",
];

/// `check` or `refuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Passes when the target answers as expected.
    Check,
    /// Passes when the target is refused.
    Refuse,
}

impl Kind {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Refuse => "refuse",
        }
    }
}

/// Who must refuse a `[[refuse]]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseBy {
    /// This agent's policy (the job comes back `refused`, class `refused_by_policy`).
    Policy,
    /// The platform, before the job reaches the agent.
    Platform,
    /// The target itself, with the answer in `expect` (e.g. status 401).
    Answer,
}

impl RefuseBy {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Platform => "platform",
            Self::Answer => "answer",
        }
    }
}

/// One validated entry.
#[derive(Debug, Clone)]
pub struct DeclaredCheck {
    /// `name` in the file, `key` on the wire.
    pub key: String,
    /// `check` or `refuse`.
    pub kind: Kind,
    /// For `refuse`.
    pub refuse_by: Option<RefuseBy>,
    /// What a job for it would carry (surface, target, expect, auth, service).
    pub spec: CheckSpec,
    /// Declared only; the platform judges it from the result's `tls_expires_at`.
    pub valid_for_days: Option<u16>,
    /// Interval, in seconds.
    pub every_secs: u64,
    /// Failed runs before the monitor goes down.
    pub fail_after: u8,
    /// The RFC this check proves (`NNNN` or `NNNN.N`).
    pub rfc: Option<String>,
    /// One of [`CATEGORIES`].
    pub category: Option<String>,
    /// Up to [`limits::MAX_TAGS`] labels, `key = "value"`.
    pub tags: BTreeMap<String, String>,
}

impl DeclaredCheck {
    /// The secret reference, if any.
    #[must_use]
    pub fn auth(&self) -> Option<&str> {
        self.spec.auth.as_ref().map(|a| a.secret.as_str())
    }

    /// The normalized wire form (one element of the hello's `checks`).
    #[must_use]
    pub fn to_wire(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("key", json!(self.key));
        m.insert("kind", json!(self.kind.as_str()));
        if let Some(by) = self.refuse_by {
            m.insert("refuse_by", json!(by.as_str()));
        }
        m.insert("surface", json!(self.spec.surface.as_str()));
        m.insert(
            "target",
            match &self.spec.target {
                Target::Url { url } => json!({"url": url.as_str()}),
                Target::HostPort { host, port, tls } => match tls {
                    Some(t) => json!({"host": host, "port": port, "tls": t}),
                    None => json!({"host": host, "port": port}),
                },
            },
        );
        m.insert("every_secs", json!(self.every_secs));
        m.insert("fail_after", json!(self.fail_after));
        let mut expect = serde_json::Map::new();
        if let Some(s) = self.spec.expect.status {
            expect.insert("status".into(), json!(s));
        }
        if let Some(ms) = self.spec.expect.max_ms {
            expect.insert("max_ms".into(), json!(ms));
        }
        if let Some(d) = self.valid_for_days {
            expect.insert("valid_for_days".into(), json!(d));
        }
        if !expect.is_empty() {
            m.insert("expect", Value::Object(expect));
        }
        if let Some(s) = &self.spec.service {
            m.insert("service", json!(s));
        }
        if let Some(a) = self.auth() {
            m.insert("auth", json!(a));
        }
        if let Some(r) = &self.rfc {
            m.insert("rfc", json!(r));
        }
        if let Some(c) = &self.category {
            m.insert("category", json!(c));
        }
        if !self.tags.is_empty() {
            m.insert("tags", json!(self.tags));
        }
        // What a transport sends (a query, a method, a tool) stays here: the platform's
        // job names the check's key and the agent reads the rest from this file.
        Value::Object(m.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
}

/// A loaded, validated checks file.
#[derive(Debug, Clone)]
pub struct DeclaredChecks {
    /// The file it came from (empty when parsed from text).
    pub path: PathBuf,
    /// Entries in file order.
    pub entries: Vec<DeclaredCheck>,
    /// `sha256:` + lowercase hex over [`canonical_json`] of the wire array.
    pub hash: String,
}

impl DeclaredChecks {
    /// Reads a checks file. A missing file is no checks (`Ok(None)`).
    ///
    /// # Errors
    /// When the file exists but cannot be read or breaks a rule.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::io(path, e)),
        };
        let mut c = Self::from_toml(&text)
            .map_err(|e| Error::Checks(format!("{}: {}", path.display(), strip(&e))))?;
        c.path = path.to_path_buf();
        Ok(Some(c))
    }

    /// Parses and validates checks TOML; the first rule broken is the error.
    ///
    /// # Errors
    /// [`Error::Checks`] with the entry's name and the rule.
    pub fn from_toml(text: &str) -> Result<Self> {
        let parsed = parse(text)?;
        let mut entries = Vec::with_capacity(parsed.len());
        for (name, r) in parsed {
            entries.push(r.map_err(|e| Error::Checks(format!("{name}: {e}")))?);
        }
        let wire: Vec<Value> = entries.iter().map(DeclaredCheck::to_wire).collect();
        let canonical = canonical_json(&Value::Array(wire));
        if canonical.len() > limits::MAX_CANONICAL_BYTES {
            return Err(Error::Checks(format!(
                "the checks take {} bytes; at most {} fit in the hello",
                canonical.len(),
                limits::MAX_CANONICAL_BYTES
            )));
        }
        Ok(Self {
            path: PathBuf::new(),
            entries,
            hash: sha256_hex(canonical.as_bytes()),
        })
    }

    /// The hello's `checks` array.
    #[must_use]
    pub fn wire(&self) -> Vec<Value> {
        self.entries.iter().map(DeclaredCheck::to_wire).collect()
    }
}

fn strip(e: &Error) -> String {
    match e {
        Error::Checks(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Parses the file: file-level problems (syntax, unknown tables, too many entries,
/// duplicate names) are the error; each entry is then validated on its own, so `lint`
/// can report every entry. Entries come back in file order, `[[check]]` and `[[refuse]]`
/// interleaved as written.
///
/// # Errors
/// [`Error::Checks`] for a file-level problem.
pub fn parse(text: &str) -> Result<Vec<(String, std::result::Result<DeclaredCheck, String>)>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FileForm {
        #[serde(default)]
        check: Vec<toml::Spanned<toml::Table>>,
        #[serde(default)]
        refuse: Vec<toml::Spanned<toml::Table>>,
    }
    let f: FileForm = toml::from_str(text).map_err(|e| Error::Checks(e.to_string()))?;
    let mut raw: Vec<(usize, Kind, toml::Table)> = f
        .check
        .into_iter()
        .map(|s| (s.span().start, Kind::Check, s.into_inner()))
        .chain(
            f.refuse
                .into_iter()
                .map(|s| (s.span().start, Kind::Refuse, s.into_inner())),
        )
        .collect();
    raw.sort_by_key(|(at, _, _)| *at);
    if raw.len() > limits::MAX_CHECKS {
        return Err(Error::Checks(format!(
            "{} entries; at most {} checks and refusals together",
            raw.len(),
            limits::MAX_CHECKS
        )));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for (i, (_, kind, table)) in raw.into_iter().enumerate() {
        let label = table
            .get("name")
            .and_then(toml::Value::as_str)
            .map_or_else(|| format!("entry {}", i + 1), str::to_owned);
        if !seen.insert(label.clone()) {
            return Err(Error::Checks(format!("the name {label:?} is used twice")));
        }
        out.push((label, entry(kind, table)));
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    name: String,
    #[serde(default)]
    surface: Option<Surface>,
    target: FileTarget,
    every: String,
    #[serde(default)]
    expect: Option<FileExpect>,
    #[serde(default)]
    fail_after: Option<u8>,
    #[serde(default)]
    by: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    rfc: Option<String>,
    #[serde(default)]
    auth_scheme: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
    // The transport surfaces' requests (RFC 0040.2); each is for the surfaces named.
    /// http: the method; ws, grpc: the RPC's full name.
    #[serde(default)]
    method: Option<String>,
    /// http: a JSON body.
    #[serde(default)]
    body: Option<toml::Value>,
    /// http: `accept` and `content-type` only.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// graphql.
    #[serde(default)]
    query: Option<String>,
    /// graphql.
    #[serde(default)]
    variables: Option<toml::Table>,
    /// mqtt.
    #[serde(default)]
    topic: Option<String>,
    /// ws, mqtt: the call's request message.
    #[serde(default)]
    params: Option<toml::Table>,
    /// sse.
    #[serde(default)]
    events: Option<u32>,
    /// mcp.
    #[serde(default)]
    min_tools: Option<u32>,
    /// mcp.
    #[serde(default)]
    tool: Option<String>,
    /// mcp.
    #[serde(default)]
    args: Option<toml::Table>,
    /// mcp.
    #[serde(default)]
    allow_side_effects: Option<bool>,
    /// ws, mqtt.
    #[serde(default)]
    expect_error: Option<String>,
    /// grpc.
    #[serde(default)]
    expect_code: Option<u32>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FileTarget {
    Text(String),
    Url(UrlTarget),
    HostPort(HostPortTarget),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlTarget {
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostPortTarget {
    host: String,
    port: u16,
    #[serde(default)]
    tls: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileExpect {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    max_ms: Option<u64>,
    #[serde(default)]
    valid_for_days: Option<u16>,
}

impl FileExpect {
    fn is_empty(&self) -> bool {
        self.status.is_none() && self.max_ms.is_none() && self.valid_for_days.is_none()
    }
}

#[allow(clippy::too_many_lines)] // one rule per field, read top to bottom
fn entry(kind: Kind, table: toml::Table) -> std::result::Result<DeclaredCheck, String> {
    let mut e: FileEntry = toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| e.message().to_owned())?;
    check_name(&e.name)?;
    let input = e.params_input();
    let every_secs = parse_every(&e.every)?;
    let refuse_by = match (kind, e.by.as_deref(), &e.expect) {
        (Kind::Check, None, _) => None,
        (Kind::Check, Some(_), _) => return Err("by is only for [[refuse]]".into()),
        (Kind::Refuse, Some(_), Some(_)) => {
            return Err("a [[refuse]] names either by or expect, not both".into());
        }
        (Kind::Refuse, Some("policy"), None) => Some(RefuseBy::Policy),
        (Kind::Refuse, Some("platform"), None) => Some(RefuseBy::Platform),
        (Kind::Refuse, Some(other), None) => {
            return Err(format!(
                "by = {other:?}: must be \"policy\" or \"platform\""
            ));
        }
        (Kind::Refuse, None, Some(x)) if !x.is_empty() => Some(RefuseBy::Answer),
        (Kind::Refuse, None, _) => {
            return Err(
                "a [[refuse]] needs by = \"policy\" or \"platform\", or the refusal it expects in expect"
                    .into(),
            );
        }
    };
    let fail_after = e.fail_after.unwrap_or(match kind {
        Kind::Check => 2,
        Kind::Refuse => 1,
    });
    if !(1..=limits::MAX_FAIL_AFTER).contains(&fail_after) {
        return Err(format!(
            "fail_after must be 1 to {}",
            limits::MAX_FAIL_AFTER
        ));
    }
    let (target, default_surface) = target(e.target, e.surface)?;
    let surface = e.surface.unwrap_or(default_surface);
    let x = e.expect.unwrap_or_default();
    check_expect(&x, surface)?;
    if let Some(s) = &e.service {
        if surface != Surface::GrpcHealth {
            return Err("service is for grpc_health checks".into());
        }
        if s.len() > limits::MAX_SERVICE || s.chars().any(char::is_control) {
            return Err(format!(
                "service must be at most {} printable characters",
                limits::MAX_SERVICE
            ));
        }
    }
    let scheme = match e.auth_scheme {
        None => None,
        Some(_) if e.auth.is_none() => return Err("auth_scheme needs auth".into()),
        Some(s) if (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            Some(s)
        }
        Some(_) => return Err("auth_scheme must be 1 to 32 letters or digits (\"Bearer\")".into()),
    };
    let auth = match e.auth {
        None => None,
        Some(r) => {
            check_reference(&r)?;
            if !surface.takes_auth() {
                return Err("auth is not used by tcp and tls checks".into());
            }
            Some(AuthSpec {
                header: None,
                scheme,
                secret: r,
            })
        }
    };
    if let Some(r) = &e.rfc {
        check_rfc(r)?;
    }
    if let Some(c) = &e.category
        && !CATEGORIES.contains(&c.as_str())
    {
        return Err(format!("category must be one of {}", CATEGORIES.join(", ")));
    }
    check_tags(&e.tags)?;
    let params = params(surface, &input)?;
    let spec = CheckSpec {
        surface,
        target,
        expect: Expect {
            status: x.status,
            max_ms: x.max_ms,
        },
        auth,
        service: e.service,
        method: None,
        key: None,
        params,
    };
    spec.endpoint()?;
    Ok(DeclaredCheck {
        key: e.name,
        kind,
        refuse_by,
        spec,
        valid_for_days: x.valid_for_days,
        every_secs,
        fail_after,
        rfc: e.rfc,
        category: e.category,
        tags: e.tags,
    })
}

/// The request fields of an entry, before they are checked against its surface.
struct ParamsInput {
    method: Option<String>,
    body: Option<toml::Value>,
    headers: BTreeMap<String, String>,
    query: Option<String>,
    variables: Option<toml::Table>,
    topic: Option<String>,
    params: Option<toml::Table>,
    events: Option<u32>,
    min_tools: Option<u32>,
    tool: Option<String>,
    args: Option<toml::Table>,
    allow_side_effects: Option<bool>,
    expect_error: Option<String>,
    expect_code: Option<u32>,
}

impl FileEntry {
    fn params_input(&mut self) -> ParamsInput {
        ParamsInput {
            method: self.method.take(),
            body: self.body.take(),
            headers: std::mem::take(&mut self.headers),
            query: self.query.take(),
            variables: self.variables.take(),
            topic: self.topic.take(),
            params: self.params.take(),
            events: self.events.take(),
            min_tools: self.min_tools.take(),
            tool: self.tool.take(),
            args: self.args.take(),
            allow_side_effects: self.allow_side_effects.take(),
            expect_error: self.expect_error.take(),
            expect_code: self.expect_code.take(),
        }
    }
}

/// Checks each request field against the surfaces it is for and its bounds.
#[allow(clippy::too_many_lines)] // one rule per field, read top to bottom
fn params(surface: Surface, i: &ParamsInput) -> std::result::Result<Params, String> {
    use Surface as S;
    let only = |field: &str, present: bool, for_: &[Surface]| {
        if present && !for_.contains(&surface) {
            let names: Vec<&str> = for_.iter().map(|s| s.as_str()).collect();
            Err(format!("{field} is for {} checks", names.join(" and ")))
        } else {
            Ok(())
        }
    };
    only("method", i.method.is_some(), &[S::Http, S::Ws, S::Grpc])?;
    only("body", i.body.is_some(), &[S::Http])?;
    only("headers", !i.headers.is_empty(), &[S::Http])?;
    only("query", i.query.is_some(), &[S::Graphql])?;
    only("variables", i.variables.is_some(), &[S::Graphql])?;
    only("topic", i.topic.is_some(), &[S::Mqtt])?;
    only("params", i.params.is_some(), &[S::Ws, S::Mqtt])?;
    only("events", i.events.is_some(), &[S::Sse])?;
    only("min_tools", i.min_tools.is_some(), &[S::Mcp])?;
    only("tool", i.tool.is_some(), &[S::Mcp])?;
    only("args", i.args.is_some(), &[S::Mcp])?;
    only(
        "allow_side_effects",
        i.allow_side_effects.is_some(),
        &[S::Mcp],
    )?;
    only("expect_error", i.expect_error.is_some(), &[S::Ws, S::Mqtt])?;
    only("expect_code", i.expect_code.is_some(), &[S::Grpc])?;
    let json =
        |field: &str, v: Option<toml::Value>| -> std::result::Result<Option<Value>, String> {
            let Some(v) = v else { return Ok(None) };
            let v = serde_json::to_value(v).map_err(|e| format!("{field}: {e}"))?;
            if serde_json::to_vec(&v).map_or(usize::MAX, |b| b.len()) > bounds::MAX_REQUEST_BYTES {
                return Err(format!(
                    "{field} must be at most {} bytes as JSON",
                    bounds::MAX_REQUEST_BYTES
                ));
            }
            Ok(Some(v))
        };
    let method = match (&i.method, surface) {
        (None, S::Ws | S::Grpc) => {
            return Err(format!(
                "a {} check names the RPC in method (\"pkg.Service/Method\")",
                surface.as_str()
            ));
        }
        (None, _) => None,
        (Some(m), S::Http) => {
            let m = m.to_ascii_uppercase();
            if !crate::checks::HTTP_METHODS.contains(&m.as_str()) {
                return Err(format!(
                    "method must be one of {}",
                    crate::checks::HTTP_METHODS.join(", ")
                ));
            }
            Some(m)
        }
        (Some(m), _) => {
            let ok = m.len() <= limits::MAX_NAME_FIELD
                && m.split_once('/').is_some_and(|(svc, name)| {
                    !svc.is_empty()
                        && !name.is_empty()
                        && svc
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                });
            if !ok {
                return Err("method must be an RPC's full name, pkg.Service/Method".into());
            }
            Some(m.clone())
        }
    };
    let mut headers = Vec::new();
    for (k, v) in &i.headers {
        let k = k.to_ascii_lowercase();
        if !crate::checks::HTTP_HEADERS.contains(&k.as_str()) {
            return Err(format!(
                "headers may set only {}",
                crate::checks::HTTP_HEADERS.join(" and ")
            ));
        }
        if v.is_empty() || v.len() > 256 || !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(format!("headers.{k} must be 1 to 256 printable characters"));
        }
        headers.push((k, v.clone()));
    }
    if surface == S::Mqtt && i.topic.is_none() {
        return Err("an mqtt check names the topic it publishes the call to".into());
    }
    if let Some(t) = &i.topic
        && (t.is_empty()
            || t.len() > limits::MAX_NAME_FIELD
            || t.contains(['+', '#', '\0'])
            || t.starts_with('$')
            || t.chars().any(char::is_control))
    {
        return Err("topic must be a topic name, no wildcards, at most 256 characters".into());
    }
    if let Some(q) = &i.query
        && (q.trim().is_empty() || q.len() > limits::MAX_QUERY)
    {
        return Err(format!("query must be 1 to {} bytes", limits::MAX_QUERY));
    }
    if let Some(n) = i.events
        && n > bounds::MAX_EVENTS
    {
        return Err(format!("events must be 0 to {}", bounds::MAX_EVENTS));
    }
    if let Some(n) = i.min_tools
        && n > 1000
    {
        return Err("min_tools must be 0 to 1000".into());
    }
    if let Some(t) = &i.tool
        && (t.is_empty()
            || t.len() > 128
            || !t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
    {
        return Err("tool must be 1 to 128 of A-Z, a-z, 0-9, _, - and .".into());
    }
    if i.args.is_some() && i.tool.is_none() {
        return Err("args needs tool".into());
    }
    if let Some(c) = &i.expect_error
        && (c.is_empty() || c.len() > 32 || !c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    {
        return Err("expect_error must be an error code, 1 to 32 of a-z and _".into());
    }
    if let Some(c) = i.expect_code
        && c > 16
    {
        return Err("expect_code must be a gRPC status code, 0 to 16".into());
    }
    let body = match surface {
        S::Http => json("body", i.body.clone())?,
        S::Ws | S::Mqtt => json("params", i.params.clone().map(toml::Value::Table))?,
        S::Graphql => json("variables", i.variables.clone().map(toml::Value::Table))?,
        S::Mcp => json("args", i.args.clone().map(toml::Value::Table))?,
        _ => None,
    };
    Ok(Params {
        method,
        body,
        headers,
        query: i.query.clone(),
        topic: i.topic.clone(),
        events: i.events,
        min_tools: i.min_tools,
        tool: i.tool.clone(),
        allow_side_effects: i.allow_side_effects.unwrap_or(false),
        expect_error: i.expect_error.clone(),
        expect_code: i.expect_code,
    })
}

/// Tags as the platform takes them: at most ten, `^[a-z][a-z0-9_.-]{0,31}$` keys and
/// `^[A-Za-z0-9_.:/-]{1,64}$` values. No customer data belongs in a tag.
fn check_tags(tags: &BTreeMap<String, String>) -> std::result::Result<(), String> {
    if tags.len() > limits::MAX_TAGS {
        return Err(format!("at most {} tags", limits::MAX_TAGS));
    }
    for (k, v) in tags {
        let key_ok = (1..=32).contains(&k.len())
            && k.as_bytes()[0].is_ascii_lowercase()
            && k.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            });
        if !key_ok {
            return Err(format!(
                "tag {k:?}: a key is a-z first, then up to 31 of a-z, 0-9, _, . and -"
            ));
        }
        let value_ok = (1..=64).contains(&v.len())
            && v.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-')
            });
        if !value_ok {
            return Err(format!(
                "tag {k:?}: a value is 1 to 64 of A-Z, a-z, 0-9, _, ., :, / and -"
            ));
        }
    }
    Ok(())
}

fn check_expect(x: &FileExpect, surface: Surface) -> std::result::Result<(), String> {
    if let Some(s) = x.status
        && !(100..=599).contains(&s)
    {
        return Err("expect.status must be 100 to 599".into());
    }
    if let Some(ms) = x.max_ms
        && !(1..=limits::MAX_MS).contains(&ms)
    {
        return Err(format!("expect.max_ms must be 1 to {}", limits::MAX_MS));
    }
    if let Some(d) = x.valid_for_days {
        if !(1..=limits::MAX_VALID_FOR_DAYS).contains(&d) {
            return Err(format!(
                "expect.valid_for_days must be 1 to {}",
                limits::MAX_VALID_FOR_DAYS
            ));
        }
        if !matches!(surface, Surface::Tls | Surface::Http) {
            return Err("expect.valid_for_days is for tls and http checks".into());
        }
    }
    if x.status.is_some() && !surface.has_status() {
        return Err("expect.status is for http, sse, mcp and graphql checks".into());
    }
    Ok(())
}

/// The target and the surface it implies when none is named: `http` for a URL, `tcp`
/// for a host and port.
fn target(
    t: FileTarget,
    surface: Option<Surface>,
) -> std::result::Result<(Target, Surface), String> {
    match t {
        FileTarget::Url(UrlTarget { url }) => Ok((
            Target::Url {
                url: parse_url(&url)?,
            },
            Surface::Http,
        )),
        FileTarget::Text(s) if s.contains("://") => Ok((
            Target::Url {
                url: parse_url(&s)?,
            },
            Surface::Http,
        )),
        FileTarget::Text(s) => {
            let (host, port) = split_host_port(&s)?;
            let port = match (port, surface) {
                (Some(p), _) => p,
                (None, Some(Surface::Tls)) => 443,
                (None, _) => {
                    return Err(format!("target {s:?} needs a port (host:port), or a URL"));
                }
            };
            Ok((
                Target::HostPort {
                    host: check_host(host)?,
                    port,
                    tls: None,
                },
                Surface::Tcp,
            ))
        }
        FileTarget::HostPort(HostPortTarget { host, port, tls }) => Ok((
            Target::HostPort {
                host: check_host(&host)?,
                port,
                tls,
            },
            Surface::Tcp,
        )),
    }
}

fn parse_url(s: &str) -> std::result::Result<Url, String> {
    if s.len() > limits::MAX_URL {
        return Err(format!("the URL is longer than {}", limits::MAX_URL));
    }
    let url = Url::parse(s).map_err(|e| format!("target {s:?}: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the URL carries a user or password; name a secret reference in auth".into());
    }
    if url.fragment().is_some() {
        return Err("the URL has a #fragment, which is never sent".into());
    }
    if let Some(url::Host::Domain(d)) = url.host() {
        normalize_host(d)?;
    }
    Ok(url)
}

fn split_host_port(s: &str) -> std::result::Result<(&str, Option<u16>), String> {
    let bad = || format!("target {s:?} is not a URL, host or host:port");
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(bad)?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((host, Some(p.parse().map_err(|_| bad())?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(bad()),
        };
    }
    if s.parse::<IpAddr>().is_ok() {
        return Ok((s, None));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Ok((h, Some(p.parse().map_err(|_| bad())?))),
        None => Ok((s, None)),
    }
}

fn check_host(host: &str) -> std::result::Result<String, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    normalize_host(host)
}

fn check_name(name: &str) -> std::result::Result<(), String> {
    let ok = (1..=limits::MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "name {name:?} must be 1 to {} of a-z, 0-9 and -",
            limits::MAX_NAME
        ))
    }
}

fn check_reference(r: &str) -> std::result::Result<(), String> {
    let ok = ["env:", "file:", "k8s:", "vault:"]
        .iter()
        .any(|p| r.len() > p.len() && r.starts_with(p))
        && !r.chars().any(char::is_whitespace);
    if ok {
        Ok(())
    } else {
        Err("auth must be a secret reference (env:NAME, file:/path, k8s:ns/name#key, vault:path#key), never a value".into())
    }
}

fn check_rfc(r: &str) -> std::result::Result<(), String> {
    let (num, part) = match r.split_once('.') {
        Some((n, p)) => (n, Some(p)),
        None => (r, None),
    };
    let digits =
        |s: &str, max: usize| (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if num.len() == 4 && digits(num, 4) && part.is_none_or(|p| digits(p, 3)) {
        Ok(())
    } else {
        Err(format!("rfc {r:?} must be NNNN or NNNN.N"))
    }
}

/// `"60s"`, `"5m"`, `"1h"`, `"1d"`: seconds, inside the bounds.
///
/// # Errors
/// What is wrong with it.
pub fn parse_every(s: &str) -> std::result::Result<u64, String> {
    let bad = || format!("every = {s:?}: use a number with s, m, h or d (\"60s\", \"5m\", \"1h\")");
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().map_err(|_| bad())?;
    let secs = match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        _ => return Err(bad()),
    }
    .ok_or_else(bad)?;
    if (limits::MIN_EVERY_SECS..=limits::MAX_EVERY_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err(format!("every = {s:?}: must be 60s to 24h"))
    }
}

/// Canonical JSON: object keys sorted, no whitespace, arrays in order.
#[must_use]
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                if let Some(x) = m.get(k) {
                    write_canonical(x, out);
                }
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------- lint

/// How a lint judged one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Fine.
    Ok,
    /// Fine, with something to know.
    Warning(String),
    /// Will not work as declared.
    Error(String),
    /// Depends on what the name resolves to (`--resolve` decides).
    NeedsResolve {
        /// Host to resolve.
        host: String,
        /// Port.
        port: u16,
    },
}

/// Judges an entry against the policy without the network: a `check` (or a refusal
/// expected from the target's answer) must be allowed by the policy; a `by = "policy"`
/// refusal must be refused by it; a `by = "platform"` refusal should lie outside the
/// policy's bound domains.
#[must_use]
pub fn lint_offline(c: &DeclaredCheck, policy: &Policy) -> Verdict {
    let refused = policy_refusal(c, policy);
    let warning = c
        .spec
        .endpoint()
        .ok()
        .and_then(|e| e.url)
        .filter(|u| u.query().is_some())
        .map(|_| {
            "the URL's query is sent to the platform with the check; keep secrets out of it"
                .to_owned()
        });
    let with_warning = |v: Verdict| match (v, &warning) {
        (Verdict::Ok, Some(w)) => Verdict::Warning(w.clone()),
        (v, _) => v,
    };
    match (c.kind, c.refuse_by) {
        (Kind::Refuse, Some(RefuseBy::Policy)) => match refused {
            Refusal::Refused(_) => Verdict::Ok,
            Refusal::Allowed => Verdict::Error(
                "the policy allows this target, so this refusal would fail (guard_open)".into(),
            ),
            Refusal::ByName { host, port } => Verdict::NeedsResolve { host, port },
        },
        (Kind::Refuse, Some(RefuseBy::Platform)) => {
            let host = c.spec.endpoint().map(|e| e.host).unwrap_or_default();
            if policy.domains.bound.is_empty() || !in_bound(policy, &host) {
                with_warning(Verdict::Ok)
            } else {
                Verdict::Warning(format!(
                    "{host} is inside a bound domain; the platform refuses only targets outside the account's verified domains"
                ))
            }
        }
        _ => match refused {
            Refusal::Refused(r) => Verdict::Error(format!("the policy refuses it: {r}")),
            // Inside a bound domain: allowed when every address is in networks.allow,
            // which `--resolve` checks.
            Refusal::Allowed | Refusal::ByName { .. } => with_warning(Verdict::Ok),
        },
    }
}

fn in_bound(policy: &Policy, host: &str) -> bool {
    policy.domains.bound.iter().any(|d| {
        host == d
            || host
                .strip_suffix(d.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

enum Refusal {
    Refused(String),
    Allowed,
    /// Allowed by name inside a bound domain; the addresses decide.
    ByName {
        host: String,
        port: u16,
    },
}

/// What the agent's admission path would say before any DNS query.
fn policy_refusal(c: &DeclaredCheck, policy: &Policy) -> Refusal {
    if !policy.surface_allowed(c.spec.surface) {
        return Refusal::Refused(format!(
            "the {} surface is not enabled ([work] checks, surfaces)",
            c.spec.surface.as_str()
        ));
    }
    if let Some(r) = c.auth()
        && !policy.secret_allowed(r)
    {
        return Refusal::Refused(format!(
            "the secret reference {r} is not in [secrets] allow"
        ));
    }
    let e = match c.spec.endpoint() {
        Ok(e) => e,
        Err(e) => return Refusal::Refused(e),
    };
    let bare = e.host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match policy.check_ip(ip) {
            Ok(()) => Refusal::Allowed,
            Err(r) => Refusal::Refused(r),
        };
    }
    match normalize_host(&e.host).and_then(|h| policy.check_name(&h)) {
        Ok(NameRule::NamedInAllow) => Refusal::Allowed,
        Ok(NameRule::BoundDomain) => Refusal::ByName {
            host: e.host,
            port: e.port,
        },
        Err(r) => Refusal::Refused(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[[check]]
name = "api"
surface = "http"
target = "https://api.example.com/healthz"
every = "60s"
expect = { status = 200, max_ms = 2000 }
fail_after = 2
rfc = "0029"

[[check]]
name = "api-tls"
surface = "tls"
target = "api.example.com"
every = "1h"
expect = { valid_for_days = 14 }

[[refuse]]
name = "private-is-refused"
target = "https://db.internal/"
by = "policy"
every = "5m"

[[refuse]]
name = "outside-domains-is-refused"
target = "https://example.org/"
by = "platform"
every = "5m"

[[refuse]]
name = "api-needs-a-token"
surface = "http"
target = "https://api.example.com/v1/me"
expect = { status = 401 }
every = "5m"
"#;

    const POLICY: &str = r#"
environment = "staging"
[domains]
bound = ["example.com"]
[networks]
allow = ["10.0.0.0/8", "api.example.com", "cache.internal"]
[secrets]
allow = ["env:CHECK_*"]
"#;

    fn one(toml: &str) -> std::result::Result<DeclaredCheck, String> {
        let parsed = parse(toml).map_err(|e| e.to_string())?;
        parsed.into_iter().next().unwrap().1
    }

    #[test]
    fn the_rfc_example_normalizes_to_the_contract() {
        let c = DeclaredChecks::from_toml(FILE).unwrap();
        let wire = Value::Array(c.wire());
        assert_eq!(
            wire,
            json!([
                {"key": "api", "kind": "check", "surface": "http",
                 "target": {"url": "https://api.example.com/healthz"},
                 "every_secs": 60, "fail_after": 2,
                 "expect": {"status": 200, "max_ms": 2000}, "rfc": "0029"},
                {"key": "api-tls", "kind": "check", "surface": "tls",
                 "target": {"host": "api.example.com", "port": 443},
                 "every_secs": 3600, "fail_after": 2, "expect": {"valid_for_days": 14}},
                {"key": "private-is-refused", "kind": "refuse", "refuse_by": "policy",
                 "surface": "http", "target": {"url": "https://db.internal/"},
                 "every_secs": 300, "fail_after": 1},
                {"key": "outside-domains-is-refused", "kind": "refuse", "refuse_by": "platform",
                 "surface": "http", "target": {"url": "https://example.org/"},
                 "every_secs": 300, "fail_after": 1},
                {"key": "api-needs-a-token", "kind": "refuse", "refuse_by": "answer",
                 "surface": "http", "target": {"url": "https://api.example.com/v1/me"},
                 "every_secs": 300, "fail_after": 1, "expect": {"status": 401}}
            ])
        );
    }

    #[test]
    fn canonical_form_and_hash_are_pinned() {
        let c = DeclaredChecks::from_toml(
            "[[refuse]]\nname = \"b\"\ntarget = \"10.0.0.1:5432\"\nby = \"policy\"\nevery = \"5m\"\n",
        )
        .unwrap();
        let canonical = canonical_json(&Value::Array(c.wire()));
        assert_eq!(
            canonical,
            r#"[{"every_secs":300,"fail_after":1,"key":"b","kind":"refuse","refuse_by":"policy","surface":"tcp","target":{"host":"10.0.0.1","port":5432}}]"#
        );
        assert_eq!(c.hash, sha256_hex(canonical.as_bytes()));
        assert_eq!(
            sha256_hex(b"[]"),
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
        assert_eq!(
            DeclaredChecks::from_toml("").unwrap().hash,
            sha256_hex(b"[]")
        );
        // Formatting and key order in the file do not change the hash; content does.
        let same = DeclaredChecks::from_toml(
            "[[refuse]]\nevery = \"300s\"\nby = \"policy\"\ntarget = \"10.0.0.1:5432\"\nname = \"b\"\n",
        )
        .unwrap();
        assert_eq!(same.hash, c.hash);
        let other = DeclaredChecks::from_toml(
            "[[refuse]]\nname = \"b\"\ntarget = \"10.0.0.1:5433\"\nby = \"policy\"\nevery = \"5m\"\n",
        )
        .unwrap();
        assert_ne!(other.hash, c.hash);
    }

    #[test]
    fn entries_keep_file_order_across_tables() {
        let c = DeclaredChecks::from_toml(
            "[[refuse]]\nname = \"r\"\ntarget = \"10.0.0.1:1\"\nby = \"policy\"\nevery = \"5m\"\n\
             [[check]]\nname = \"c\"\ntarget = \"10.0.0.1:2\"\nevery = \"5m\"\n\
             [[refuse]]\nname = \"s\"\ntarget = \"10.0.0.1:3\"\nby = \"platform\"\nevery = \"5m\"\n",
        )
        .unwrap();
        let keys: Vec<&str> = c.entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["r", "c", "s"]);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_every("60s"), Ok(60));
        assert_eq!(parse_every("5m"), Ok(300));
        assert_eq!(parse_every("1h"), Ok(3_600));
        assert_eq!(parse_every("24h"), Ok(86_400));
        assert_eq!(parse_every("1d"), Ok(86_400));
        for bad in [
            "59s",
            "25h",
            "2d",
            "60",
            "1.5h",
            "m",
            "",
            "5 m",
            "-1h",
            "99999999999999999999h",
        ] {
            assert!(parse_every(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults() {
        let c =
            one("[[check]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nevery = \"1m\"\n")
                .unwrap();
        assert_eq!((c.fail_after, c.spec.surface), (2, Surface::Http));
        let r = one("[[refuse]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nby = \"policy\"\nevery = \"1m\"\n").unwrap();
        assert_eq!((r.fail_after, r.spec.surface), (1, Surface::Http));
        let r = one("[[refuse]]\nname = \"a\"\ntarget = \"db.internal:5432\"\nby = \"policy\"\nevery = \"1m\"\n").unwrap();
        assert_eq!(r.spec.surface, Surface::Tcp);
        let r = one("[[refuse]]\nname = \"a\"\ntarget = { host = \"db.internal\", port = 5432 }\nby = \"platform\"\nevery = \"1m\"\n").unwrap();
        assert_eq!(
            (r.spec.surface, r.refuse_by),
            (Surface::Tcp, Some(RefuseBy::Platform))
        );
    }

    fn numbered(n: u16) -> String {
        use std::fmt::Write as _;
        (0..n).fold(String::new(), |mut s, i| {
            let _ = write!(
                s,
                "[[check]]\nname = \"c{i}\"\ntarget = \"10.0.0.1:{}\"\nevery = \"1m\"\n",
                i + 1
            );
            s
        })
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one case per rule
    fn transport_requests_are_bounded_and_stay_local() {
        let entry = |surface: &str, target: &str, extra: &str| {
            format!(
                "[[check]]\nname = \"t\"\nsurface = \"{surface}\"\ntarget = \"{target}\"\nevery = \"15m\"\n{extra}"
            )
        };
        let c = one(&entry(
            "graphql",
            "https://api.example.com/graphql",
            "query = \"{ me { id } }\"\nvariables = { a = 1 }\nauth = \"env:CHECK_T\"\nauth_scheme = \"Bearer\"\ncategory = \"transport\"\ntags = { transport = \"graphql\", env = \"prod:eu-1\" }\n",
        ))
        .unwrap();
        assert_eq!(c.spec.params.query.as_deref(), Some("{ me { id } }"));
        assert_eq!(c.spec.params.body, Some(json!({"a": 1})));
        assert_eq!(
            c.spec.auth.as_ref().unwrap().scheme.as_deref(),
            Some("Bearer")
        );
        let wire = c.to_wire();
        assert_eq!(wire["category"], "transport");
        assert_eq!(
            wire["tags"],
            json!({"env": "prod:eu-1", "transport": "graphql"})
        );
        assert_eq!(wire["auth"], "env:CHECK_T");
        let text = wire.to_string();
        assert!(
            !text.contains("me { id }") && !text.contains("Bearer"),
            "{text}"
        );
        let c = one(&entry(
            "http",
            "https://api.example.com/v1/x",
            "method = \"post\"\nbody = { a = [1, 2] }\nheaders = { Accept = \"application/json\" }\n",
        ))
        .unwrap();
        assert_eq!(c.spec.params.method.as_deref(), Some("POST"));
        assert_eq!(
            c.spec.params.headers,
            vec![("accept".to_owned(), "application/json".to_owned())]
        );
        let c = one(&entry(
            "grpc",
            "api.example.com:443",
            "method = \"iohr.ledger.v1.LedgerService/Ping\"\nexpect_code = 16\n",
        ))
        .unwrap();
        assert_eq!(c.spec.params.expect_code, Some(16));
        let big = "x".repeat(bounds::MAX_REQUEST_BYTES);
        for (bad, why) in [
            (
                entry("ws", "https://a.example.com/v1/ws", ""),
                "ws needs method",
            ),
            (
                entry("grpc", "a.example.com:443", "method = \"Ping\"\n"),
                "grpc method shape",
            ),
            (
                entry("mqtt", "https://a.example.com/v1/mqtt", ""),
                "mqtt needs topic",
            ),
            (
                entry(
                    "mqtt",
                    "https://a.example.com/v1/mqtt",
                    "topic = \"events/#\"\n",
                ),
                "wildcard topic",
            ),
            (
                entry("sse", "https://a.example.com/s", "events = 21\n"),
                "too many events",
            ),
            (
                entry("sse", "https://a.example.com/s", "query = \"{ a }\"\n"),
                "query on sse",
            ),
            (
                entry("mcp", "https://a.example.com/mcp", "args = { a = 1 }\n"),
                "args without tool",
            ),
            (
                entry("mcp", "https://a.example.com/mcp", "tool = \"a b\"\n"),
                "tool name",
            ),
            (
                entry(
                    "ws",
                    "https://a.example.com/v1/ws",
                    "method = \"a.B/C\"\nexpect_error = \"Forbidden!\"\n",
                ),
                "expect_error",
            ),
            (
                entry(
                    "grpc",
                    "a.example.com:443",
                    "method = \"a.B/C\"\nexpect_code = 17\n",
                ),
                "expect_code",
            ),
            (
                entry("http", "https://a.example.com/", "method = \"TRACE\"\n"),
                "http method",
            ),
            (
                entry(
                    "http",
                    "https://a.example.com/",
                    "headers = { authorization = \"x\" }\n",
                ),
                "header allow-list",
            ),
            (
                entry(
                    "http",
                    "https://a.example.com/",
                    &format!("body = {{ a = \"{big}\" }}\n"),
                ),
                "body size",
            ),
            (
                entry("ws", "a.example.com:443", "method = \"a.B/C\"\n"),
                "ws url",
            ),
            (
                entry("tcp", "a.example.com:5432", "auth = \"env:X\"\n"),
                "auth on tcp",
            ),
            (
                entry(
                    "graphql",
                    "https://a.example.com/",
                    "auth_scheme = \"Bearer\"\n",
                ),
                "scheme without auth",
            ),
            (
                entry(
                    "graphql",
                    "https://a.example.com/",
                    "expect = { status = 200 }\ncategory = \"misc\"\n",
                ),
                "category",
            ),
            (
                entry(
                    "graphql",
                    "https://a.example.com/",
                    "tags = { Env = \"x\" }\n",
                ),
                "tag key",
            ),
            (
                entry(
                    "graphql",
                    "https://a.example.com/",
                    "tags = { env = \"a b\" }\n",
                ),
                "tag value",
            ),
            (
                entry(
                    "graphql",
                    "https://a.example.com/",
                    &format!(
                        "tags = {{ {} }}\n",
                        (0..11)
                            .map(|i| format!("k{i} = \"v\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                "eleven tags",
            ),
            (
                entry(
                    "mqtt",
                    "https://a.example.com/v1/mqtt",
                    "topic = \"rpc/a/B\"\nexpect = { status = 200 }\n",
                ),
                "status on mqtt",
            ),
        ] {
            assert!(one(&bad).is_err(), "{why} accepted");
        }
    }

    #[test]
    fn rules_are_enforced() {
        let base = |extra: &str| {
            format!(
                "[[check]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nevery = \"1m\"\n{extra}"
            )
        };
        for (bad, why) in [
            (base("colour = \"red\"\n"), "unknown key"),
            (base("expect = { status = 99 }\n"), "status"),
            (base("expect = { max_ms = 30001 }\n"), "max_ms"),
            (base("expect = { valid_for_days = 0 }\n"), "valid_for_days"),
            (base("expect = { body = \"x\" }\n"), "unknown expect key"),
            (base("fail_after = 0\n"), "fail_after 0"),
            (base("fail_after = 6\n"), "fail_after 6"),
            (base("by = \"policy\"\n"), "by on a check"),
            (base("auth = \"hunter2\"\n"), "auth value"),
            (base("rfc = \"29\"\n"), "rfc"),
            (base("service = \"x\"\n"), "service on http"),
            (
                "[[check]]\nname = \"Bad_Name\"\ntarget = \"https://a.example.com/\"\nevery = \"1m\"\n".into(),
                "name",
            ),
            (
                "[[check]]\nname = \"a\"\ntarget = \"https://u:p@a.example.com/\"\nevery = \"1m\"\n".into(),
                "userinfo",
            ),
            (
                "[[check]]\nname = \"a\"\ntarget = \"db.internal\"\nevery = \"1m\"\n".into(),
                "tcp without port",
            ),
            (
                "[[check]]\nname = \"a\"\nsurface = \"tcp\"\ntarget = \"10.0.0.1:1\"\nevery = \"1m\"\nexpect = { valid_for_days = 3 }\n".into(),
                "valid_for_days on tcp",
            ),
            (
                "[[refuse]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nevery = \"1m\"\n".into(),
                "refuse without by",
            ),
            (
                "[[refuse]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nby = \"nobody\"\nevery = \"1m\"\n".into(),
                "unknown by",
            ),
            (
                "[[refuse]]\nname = \"a\"\ntarget = \"https://a.example.com/\"\nby = \"policy\"\nexpect = { status = 401 }\nevery = \"1m\"\n".into(),
                "by and expect",
            ),
        ] {
            assert!(one(&bad).is_err(), "{why}: {bad}");
        }
        // File-level rules.
        assert!(DeclaredChecks::from_toml("[[checks]]\nname = \"a\"\n").is_err());
        let twice = format!("{}{}", base(""), base(""));
        assert!(parse(&twice).is_err(), "duplicate names");
        let many = numbered(51);
        assert!(parse(&many).is_err(), "more than 50");
        let fifty = numbered(50);
        assert_eq!(DeclaredChecks::from_toml(&fifty).unwrap().entries.len(), 50);
    }

    #[test]
    fn a_missing_file_is_no_checks() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            DeclaredChecks::load(&dir.path().join("checks.toml"))
                .unwrap()
                .is_none()
        );
        std::fs::write(dir.path().join("checks.toml"), FILE).unwrap();
        let c = DeclaredChecks::load(&dir.path().join("checks.toml"))
            .unwrap()
            .unwrap();
        assert_eq!(c.entries.len(), 5);
        std::fs::write(dir.path().join("checks.toml"), "[[check]]\nname = 1\n").unwrap();
        let e = DeclaredChecks::load(&dir.path().join("checks.toml")).unwrap_err();
        assert!(matches!(e, Error::Checks(_)), "{e}");
    }

    fn lint_all(file: &str) -> Vec<(String, Verdict)> {
        let p = Policy::from_toml(POLICY).unwrap();
        parse(file)
            .unwrap()
            .into_iter()
            .map(|(n, r)| (n, lint_offline(&r.unwrap(), &p)))
            .collect()
    }

    #[test]
    fn lint_against_the_policy() {
        let v = lint_all(FILE);
        assert_eq!(v[0], ("api".into(), Verdict::Ok));
        assert_eq!(v[1].1, Verdict::Ok);
        assert_eq!(v[2].1, Verdict::Ok, "db.internal is refused by the policy");
        assert_eq!(
            v[3].1,
            Verdict::Ok,
            "example.org is outside the bound domains"
        );
        assert_eq!(v[4].1, Verdict::Ok);
    }

    #[test]
    fn lint_catches_a_check_outside_the_policy() {
        let v = lint_all(
            "[[check]]\nname = \"a\"\ntarget = \"https://db.internal/\"\nevery = \"1m\"\n[[check]]\nname = \"b\"\ntarget = \"192.168.0.1:22\"\nevery = \"1m\"\n[[check]]\nname = \"c\"\ntarget = \"https://api.example.com/\"\nauth = \"env:OTHER\"\nevery = \"1m\"\n",
        );
        for (n, verdict) in v {
            assert!(matches!(verdict, Verdict::Error(_)), "{n}: {verdict:?}");
        }
    }

    #[test]
    fn lint_catches_a_policy_refusal_the_policy_would_allow() {
        let v = lint_all(
            "[[refuse]]\nname = \"a\"\ntarget = \"https://cache.internal/\"\nby = \"policy\"\nevery = \"5m\"\n[[refuse]]\nname = \"b\"\ntarget = \"10.1.2.3:5432\"\nby = \"policy\"\nevery = \"5m\"\n",
        );
        for (n, verdict) in v {
            assert!(matches!(verdict, Verdict::Error(_)), "{n}: {verdict:?}");
        }
        // Inside a bound domain the addresses decide; --resolve settles it.
        let v = lint_all(
            "[[refuse]]\nname = \"a\"\ntarget = \"https://www.example.com/\"\nby = \"policy\"\nevery = \"5m\"\n",
        );
        assert!(matches!(v[0].1, Verdict::NeedsResolve { .. }), "{:?}", v[0]);
    }

    #[test]
    fn lint_warns_on_platform_refusals_inside_bound_domains_and_queries() {
        let v = lint_all(
            "[[refuse]]\nname = \"a\"\ntarget = \"https://www.example.com/\"\nby = \"platform\"\nevery = \"5m\"\n[[check]]\nname = \"b\"\ntarget = \"https://api.example.com/x?y=1\"\nevery = \"5m\"\n",
        );
        assert!(matches!(v[0].1, Verdict::Warning(_)), "{:?}", v[0]);
        assert!(matches!(v[1].1, Verdict::Warning(_)), "{:?}", v[1]);
    }
}
