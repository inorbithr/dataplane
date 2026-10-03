//! Surface checks: does a service answer, how fast, with which status, and when does its
//! certificate expire. A check never reads more of a response than its status line and
//! headers (gRPC: the one health message), and never reports a body.

mod grpc;
mod http;
mod tcp;
mod tls;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::tls::TlsContext;

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
}

impl Surface {
    /// Every surface this version can check.
    pub const ALL: [Self; 4] = [Self::Http, Self::Tcp, Self::Tls, Self::GrpcHealth];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::GrpcHealth => "grpc_health",
        }
    }
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
}

/// A target: a URL, or a host and port.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Target {
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

/// A header whose value is a secret reference.
#[derive(Debug, Clone, Deserialize)]
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
    /// The local policy refused it.
    RefusedByPolicy,
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
            (Target::HostPort { .. }, Surface::Http) => {
                Err("an http check needs a URL target".into())
            }
            (Target::HostPort { host, port, tls }, s) => Ok(Endpoint {
                host: host.clone(),
                port: *port,
                tls: match s {
                    Surface::Tls => true,
                    Surface::GrpcHealth => tls.unwrap_or(true),
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
pub async fn run(tls: &TlsContext, p: Prepared<'_>) -> CheckDetail {
    let detail = match p.spec.surface {
        Surface::Http => http::check(tls, &p).await,
        Surface::Tcp => tcp::check(p.addr, p.timeout).await,
        Surface::Tls => tls::check(tls, &p.endpoint.host, p.addr, p.timeout).await,
        Surface::GrpcHealth => grpc::check(tls, &p).await,
    };
    detail.apply_max_ms(&p.spec.expect)
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
