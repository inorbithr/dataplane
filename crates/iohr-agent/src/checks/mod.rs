//! Surface checks: does a service answer, how fast, with which status, and when does its
//! certificate expire. The first four surfaces never read more of a response than its
//! status line and headers (gRPC: the one health message). The transport surfaces (RFC
//! 0040.2: `grpc`, `sse`, `ws`, `mqtt`, `mcp`, `graphql`) read a bounded answer to judge
//! its shape, in memory, and drop it. No surface reports a body, a header value or the
//! text of an error: a result is timings, a status code, an error class and counts.

mod graphql;
mod grpc;
mod http;
mod mcp;
mod mqtt;
mod sse;
mod tcp;
mod tls;
mod ws;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::tls::TlsContext;

pub(crate) use http::{ALLOWED_HEADERS as HTTP_HEADERS, METHODS as HTTP_METHODS};

/// What is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// An HTTP(S) request; status, latency, certificate expiry.
    Http,
    /// A TCP connect.
    Tcp,
    /// A TLS handshake; certificate expiry.
    Tls,
    /// `grpc.health.v1.Health/Check` over HTTP/2.
    GrpcHealth,
    /// A unary gRPC call by full method name with an empty request; the gRPC status.
    Grpc,
    /// A server-sent events stream: opens, delivers N events.
    Sse,
    /// One call on a multiplexed WebSocket (`/v1/ws` frames).
    Ws,
    /// MQTT 5 over WebSocket: connect, subscribe to a reply topic, one RPC.
    Mqtt,
    /// MCP over streamable HTTP: `initialize`, `tools/list`, one read-only `tools/call`.
    Mcp,
    /// A GraphQL query over `POST`; no `errors`.
    Graphql,
    /// A hardware sensor on this host against thresholds in `checks.toml` (needs
    /// `[work] host`); reports the reading and a level, nothing else.
    Hwmon,
}

impl Surface {
    /// Every surface this version can check.
    pub const ALL: [Self; 11] = [
        Self::Http,
        Self::Tcp,
        Self::Tls,
        Self::GrpcHealth,
        Self::Grpc,
        Self::Sse,
        Self::Ws,
        Self::Mqtt,
        Self::Mcp,
        Self::Graphql,
        Self::Hwmon,
    ];

    /// The surfaces on when the policy names none. The transport surfaces read an answer
    /// and are off until `[work] surfaces` lists them.
    pub const DEFAULT: [Self; 4] = [Self::Http, Self::Tcp, Self::Tls, Self::GrpcHealth];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::GrpcHealth => "grpc_health",
            Self::Grpc => "grpc",
            Self::Sse => "sse",
            Self::Ws => "ws",
            Self::Mqtt => "mqtt",
            Self::Mcp => "mcp",
            Self::Graphql => "graphql",
            Self::Hwmon => "hwmon",
        }
    }

    /// Names a URL, never a host and a port.
    #[must_use]
    pub fn needs_url(self) -> bool {
        matches!(
            self,
            Self::Http | Self::Sse | Self::Ws | Self::Mqtt | Self::Mcp | Self::Graphql
        )
    }

    /// Runs only as a declared check: what it sends (a method, a topic) is in
    /// `checks.toml`, never in a job.
    #[must_use]
    pub fn needs_declared(self) -> bool {
        matches!(self, Self::Grpc | Self::Ws | Self::Mqtt | Self::Hwmon)
    }

    /// Reads this host, never the network.
    #[must_use]
    pub fn is_host(self) -> bool {
        matches!(self, Self::Hwmon)
    }

    /// Sends a credential when the check names one (everything but `tcp` and `tls`).
    #[must_use]
    pub fn takes_auth(self) -> bool {
        !matches!(self, Self::Tcp | Self::Tls | Self::Hwmon)
    }

    /// Has an HTTP status to expect.
    #[must_use]
    pub fn has_status(self) -> bool {
        matches!(self, Self::Http | Self::Sse | Self::Mcp | Self::Graphql)
    }
}

/// Bounds on what a transport check sends and reads.
pub mod bounds {
    /// The most bytes of an answer read (then the check fails with `answer`).
    pub const MAX_ANSWER_BYTES: usize = 1024 * 1024;
    /// The most WebSocket or MQTT messages read while waiting for the answer.
    pub const MAX_FRAMES: usize = 32;
    /// The most server-sent events a check may wait for.
    pub const MAX_EVENTS: u32 = 20;
    /// The largest request body, params or variables, as JSON.
    pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
}

/// A check job's `spec`.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckSpec {
    /// What to check.
    pub surface: Surface,
    /// Where.
    pub target: Target,
    /// What counts as healthy.
    #[serde(default)]
    pub expect: Expect,
    /// A header carrying a secret resolved on this machine (HTTP and gRPC only).
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// The gRPC health service name; empty means the whole server.
    #[serde(default)]
    pub service: Option<String>,
    /// HTTP method: `GET` (default) or `HEAD`.
    #[serde(default)]
    pub method: Option<String>,
    /// The declared check this job runs (its `name` in `checks.toml`).
    #[serde(default)]
    pub key: Option<String>,
    /// What the surface sends beyond its target. Only ever from the local `checks.toml`,
    /// never from a job.
    #[serde(skip)]
    pub params: Params,
}

/// A transport check's request, from `checks.toml` only. Every field is bounded when the
/// file is read; none is ever reported.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Params {
    /// `http`: the method. `ws` and `grpc`: the RPC's full name (`pkg.Service/Method`).
    pub method: Option<String>,
    /// `http`: the JSON body. `ws`, `mqtt`: the call's params. `graphql`: the variables.
    /// `mcp`: the tool's arguments.
    pub body: Option<serde_json::Value>,
    /// `http`: request headers from a fixed allow-list (`accept`, `content-type`).
    pub headers: Vec<(String, String)>,
    /// `graphql`: the query.
    pub query: Option<String>,
    /// `mqtt`: the topic the call is published to.
    pub topic: Option<String>,
    /// `sse`: events to receive (default 1; 0 is only the stream opening).
    pub events: Option<u32>,
    /// `mcp`: the fewest tools `tools/list` must offer (default 1).
    pub min_tools: Option<u32>,
    /// `mcp`: one tool to call.
    pub tool: Option<String>,
    /// `hwmon`: the sensor's thresholds.
    pub hwmon: Option<crate::host::check::HwmonSpec>,
    /// `mcp`: call a tool that is not annotated read-only.
    pub allow_side_effects: bool,
    /// `ws`, `mqtt`: the error code the call must end with (a refusal check).
    pub expect_error: Option<String>,
    /// `grpc`: the gRPC status code to expect (default 0, OK).
    pub expect_code: Option<u32>,
}

/// A target: a URL, a host and port, or (for `hwmon`) a sensor on this host.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Target {
    /// `{"sensor": "asusec/Chipset"}`.
    Sensor {
        /// `chip/label` or `chip/kind/label`.
        sensor: String,
    },
    /// `{"url": "https://api.internal/healthz"}`.
    Url {
        /// The URL.
        url: Url,
    },
    /// `{"host": "db.internal", "port": 5432}`.
    HostPort {
        /// Host name or address.
        host: String,
        /// Port.
        port: u16,
        /// For `grpc_health`: use TLS (default true).
        #[serde(default)]
        tls: Option<bool>,
    },
}

/// `expect`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Expect {
    /// The HTTP status that counts as healthy; default any status below 400.
    pub status: Option<u16>,
    /// Slower than this is unhealthy.
    pub max_ms: Option<u64>,
}

/// A header whose value is a secret reference. A job may carry it as the reference alone
/// (`"auth": "env:TOKEN"`) or as `{header?, scheme?, secret}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "AuthWire")]
pub struct AuthSpec {
    /// Header name; default `authorization`.
    #[serde(default)]
    pub header: Option<String>,
    /// Prefix before the value, e.g. `Bearer`.
    #[serde(default)]
    pub scheme: Option<String>,
    /// The reference (`vault:kv/app#token`, `k8s:ns/name#key`, `env:NAME`, `file:/path`).
    pub secret: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthWire {
    Reference(String),
    Spec {
        #[serde(default)]
        header: Option<String>,
        #[serde(default)]
        scheme: Option<String>,
        secret: String,
    },
}

impl From<AuthWire> for AuthSpec {
    fn from(w: AuthWire) -> Self {
        match w {
            AuthWire::Reference(secret) => Self {
                header: None,
                scheme: None,
                secret,
            },
            AuthWire::Spec {
                header,
                scheme,
                secret,
            } => Self {
                header,
                scheme,
                secret,
            },
        }
    }
}

/// Why a check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Slower than allowed, or no answer in time.
    Timeout,
    /// The connection could not be made.
    Connect,
    /// The TLS handshake failed.
    Tls,
    /// The name did not resolve.
    Dns,
    /// It answered with the wrong status.
    Status,
    /// A sensor reading is at or past its critical threshold (or rate).
    Threshold,
    /// The sensor is not on this host, or has no reading yet.
    Sensor,
    /// The local policy refused it.
    RefusedByPolicy,
    /// A transport answered, but not in the shape the check expects: a GraphQL `errors`,
    /// an `error` frame, too few events or tools, an answer past its size bound.
    Answer,
}

/// A check's result `detail`: timings, a status code, a class of error. Never a body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckDetail {
    /// Healthy.
    pub ok: bool,
    /// Wall time of the check, in milliseconds.
    pub latency_ms: u64,
    /// HTTP status, if one was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<ErrorClass>,
    /// The leaf certificate's `notAfter`, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_expires_at: Option<String>,
    /// `hwmon`: the reading, its peak since the previous run, its rate and its level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<crate::host::check::Reading>,
}

impl CheckDetail {
    /// A failure of the given class.
    #[must_use]
    pub fn failed(class: ErrorClass, started: Instant) -> Self {
        Self {
            ok: false,
            latency_ms: elapsed_ms(started),
            error_class: Some(class),
            ..Self::default()
        }
    }

    fn apply_max_ms(mut self, expect: &Expect) -> Self {
        if let Some(max) = expect.max_ms
            && self.ok
            && self.latency_ms > max
        {
            self.ok = false;
            self.error_class = Some(ErrorClass::Timeout);
        }
        self
    }
}

/// Where a check connects, decided before any connection is made.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Host as named in the job (for SNI, the `Host` header and records).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Use TLS.
    pub tls: bool,
    /// The URL, for HTTP.
    pub url: Option<Url>,
}

impl CheckSpec {
    /// The host and port this check reaches, or why the spec is unusable.
    ///
    /// # Errors
    /// A description of what is missing or wrong.
    pub fn endpoint(&self) -> Result<Endpoint, String> {
        match (&self.target, self.surface) {
            (Target::Sensor { sensor }, Surface::Hwmon) => Ok(Endpoint {
                host: format!("sensor:{sensor}"),
                port: 0,
                tls: false,
                url: None,
            }),
            (Target::Sensor { .. }, s) => Err(format!(
                "a sensor target is for hwmon checks, not {}",
                s.as_str()
            )),
            (_, Surface::Hwmon) => Err("an hwmon check names a sensor target".into()),
            (Target::Url { url }, s) => {
                let tls = match url.scheme() {
                    "https" => true,
                    "http" => false,
                    other => return Err(format!("unsupported URL scheme {other}")),
                };
                let host = url.host_str().ok_or("URL has no host")?.to_owned();
                let port = url.port_or_known_default().ok_or("URL has no port")?;
                if s == Surface::Tls && !tls {
                    return Err("a tls check needs an https URL or host and port".into());
                }
                Ok(Endpoint {
                    host,
                    port,
                    tls: tls || s == Surface::Tls,
                    url: Some(url.clone()),
                })
            }
            (Target::HostPort { .. }, s) if s.needs_url() => {
                Err(format!("an {} check needs a URL target", s.as_str()))
            }
            (Target::HostPort { host, port, tls }, s) => Ok(Endpoint {
                host: host.clone(),
                port: *port,
                tls: match s {
                    Surface::Tls => true,
                    Surface::GrpcHealth | Surface::Grpc => tls.unwrap_or(true),
                    _ => false,
                },
                url: None,
            }),
        }
    }
}

/// Inputs to one check after the policy has pinned the address.
#[derive(Debug)]
pub struct Prepared<'a> {
    /// The spec.
    pub spec: &'a CheckSpec,
    /// Where to connect.
    pub endpoint: &'a Endpoint,
    /// The pinned address.
    pub addr: SocketAddr,
    /// The resolved auth header, if any.
    pub auth: Option<(String, Zeroizing<String>)>,
    /// Time allowed.
    pub timeout: Duration,
}

/// Runs a check. The caller enforces the overall deadline as well.
///
/// # Errors
/// A refusal decided only once the target answered (an MCP tool that is not read-only);
/// the reason is the agent's own words, never the target's.
pub async fn run(tls: &TlsContext, p: Prepared<'_>) -> Result<CheckDetail, String> {
    let detail = match p.spec.surface {
        Surface::Http => http::check(tls, &p).await,
        Surface::Tcp => tcp::check(p.addr, p.timeout).await,
        Surface::Tls => tls::check(tls, &p.endpoint.host, p.addr, p.timeout).await,
        Surface::GrpcHealth => grpc::check(tls, &p).await,
        Surface::Grpc => grpc::unary(tls, &p).await,
        Surface::Sse => sse::check(tls, &p).await,
        Surface::Ws => ws::check(tls, &p).await,
        Surface::Mqtt => mqtt::check(tls, &p).await,
        Surface::Mcp => mcp::check(tls, &p).await?,
        Surface::Graphql => graphql::check(tls, &p).await,
        Surface::Hwmon => {
            return Err("an hwmon check reads the host sampler, not the network".into());
        }
    };
    Ok(detail.apply_max_ms(&p.spec.expect))
}

/// Whether an HTTP status meets `expect.status`; without one, any 2xx.
fn status_ok(expect: &Expect, status: u16) -> bool {
    expect
        .status
        .map_or((200..300).contains(&status), |want| want == status)
}

/// A finished check: ok, or failed with `class`, with the status seen.
fn judged(started: Instant, status: Option<u16>, outcome: Result<(), ErrorClass>) -> CheckDetail {
    CheckDetail {
        ok: outcome.is_ok(),
        latency_ms: elapsed_ms(started),
        status_code: status,
        error_class: outcome.err(),
        tls_expires_at: None,
        reading: None,
    }
}

/// The `authorization`-like header and its value, marked sensitive.
fn auth_header(
    p: &Prepared<'_>,
) -> Result<Option<(::http::HeaderName, ::http::HeaderValue)>, ErrorClass> {
    let Some((name, value)) = &p.auth else {
        return Ok(None);
    };
    let name = ::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ErrorClass::Connect)?;
    let mut value =
        ::http::HeaderValue::from_str(value.as_str()).map_err(|_| ErrorClass::Connect)?;
    value.set_sensitive(true);
    Ok(Some((name, value)))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn rfc3339(t: time::OffsetDateTime) -> Option<String> {
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(v: serde_json::Value) -> CheckSpec {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn auth_is_a_reference_or_a_table_and_params_never_come_from_a_job() {
        let s = spec(
            serde_json::json!({"surface": "graphql", "target": {"url": "https://a.example.com/graphql"},
            "auth": "env:TOKEN", "key": "gql", "params": {"query": "{ me { email } }"}}),
        );
        assert_eq!(s.auth.unwrap().secret, "env:TOKEN");
        assert_eq!(s.key.as_deref(), Some("gql"));
        assert_eq!(
            s.params,
            Params::default(),
            "params are read from checks.toml only"
        );
        let s = spec(
            serde_json::json!({"surface": "http", "target": {"url": "https://a.example.com/"},
            "auth": {"scheme": "Bearer", "secret": "env:TOKEN"}}),
        );
        assert_eq!(s.auth.unwrap().scheme.as_deref(), Some("Bearer"));
    }

    #[test]
    fn transport_surfaces_are_off_by_default_and_name_urls() {
        for s in Surface::ALL {
            assert_eq!(
                Surface::DEFAULT.contains(&s),
                !matches!(
                    s,
                    Surface::Grpc
                        | Surface::Sse
                        | Surface::Ws
                        | Surface::Mqtt
                        | Surface::Mcp
                        | Surface::Graphql
                        | Surface::Hwmon
                )
            );
        }
        let s = spec(serde_json::json!({"surface": "ws", "target": {"host": "g", "port": 443}}));
        assert!(s.endpoint().is_err());
        let s = spec(serde_json::json!({"surface": "grpc", "target": {"host": "g", "port": 443}}));
        assert!(s.endpoint().unwrap().tls, "gRPC defaults to TLS");
        let s = spec(
            serde_json::json!({"surface": "mqtt", "target": {"url": "https://a.example.com/v1/mqtt"}}),
        );
        assert_eq!(s.endpoint().unwrap().port, 443);
    }

    #[test]
    fn endpoints() {
        let s = spec(
            serde_json::json!({"surface": "http", "target": {"url": "https://a.example.com/x?q=1"}}),
        );
        let e = s.endpoint().unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.tls),
            ("a.example.com", 443, true)
        );

        let s = spec(
            serde_json::json!({"surface": "grpc_health", "target": {"host": "g", "port": 50051}}),
        );
        assert!(s.endpoint().unwrap().tls, "gRPC defaults to TLS");
        let s = spec(
            serde_json::json!({"surface": "grpc_health", "target": {"host": "g", "port": 50051, "tls": false}}),
        );
        assert!(!s.endpoint().unwrap().tls);
        let s = spec(serde_json::json!({"surface": "http", "target": {"host": "g", "port": 80}}));
        assert!(s.endpoint().is_err());
        let s = spec(serde_json::json!({"surface": "tls", "target": {"url": "http://g"}}));
        assert!(s.endpoint().is_err());
        let s = spec(serde_json::json!({"surface": "tcp", "target": {"url": "ftp://g"}}));
        assert!(s.endpoint().is_err());
    }

    #[test]
    fn detail_wire_form() {
        let d = CheckDetail {
            ok: false,
            latency_ms: 12,
            error_class: Some(ErrorClass::RefusedByPolicy),
            ..CheckDetail::default()
        };
        assert_eq!(
            serde_json::to_value(&d).unwrap(),
            serde_json::json!({"ok": false, "latency_ms": 12, "error_class": "refused_by_policy"})
        );
    }

    #[test]
    fn max_ms_turns_slow_into_timeout() {
        let d = CheckDetail {
            ok: true,
            latency_ms: 50,
            ..CheckDetail::default()
        };
        let d = d.apply_max_ms(&Expect {
            status: None,
            max_ms: Some(10),
        });
        assert!(!d.ok);
        assert_eq!(d.error_class, Some(ErrorClass::Timeout));
    }
}
