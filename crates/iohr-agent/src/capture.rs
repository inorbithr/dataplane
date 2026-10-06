//! The agent's side of capture (`docs/capture/design-phase1.md`): it reads the capture
//! companion's `counts` answer over a local Unix socket and announces `capture:*` in the
//! hello when the policy allows it and the companion answers.
//!
//! Privacy by construction: the answer is parsed into [`Counts`], which has numeric fields
//! only, so names, paths, addresses or owners a companion might send never reach the
//! agent's memory, frames, admin page, logs or telemetry. The `tables` request (top-K
//! names, for a person at the terminal) is only made by `iohr agent capture status
//! --tables`, which prints and exits.
//!
//! Version 2 of the socket adds `lookup` (`docs/capture/design-phase2.md`): numbers for one
//! owner and route the caller already holds (RFC 0070's join). [`lookup`] parses the
//! answer into [`Lookup`], numbers only, the same way. The agent never asks for packets:
//! pcap files are made only for root on the host, over a socket the agent cannot use.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::policy::{CaptureLayer, CapturePolicy};

/// Error codes of the socket protocol (`docs/capture/design-phase1.md`, `design-phase2.md`).
const KNOWN_ERRORS: [&str; 10] = [
    "forbidden",
    "unsupported_version",
    "bad_request",
    "unknown_request",
    "too_large",
    "not_available",
    "rate_limited",
    "busy",
    "no_space",
    "io",
];

/// The socket protocol version this agent asks `counts` in (every companion speaks it).
pub const WIRE_VERSION: u64 = 1;
/// The version `lookup` needs.
pub const WIRE_VERSION_2: u64 = 2;
/// The control socket's name, next to the aggregates socket (root only; its presence is
/// part of `capture:packets`).
pub const CONTROL_SOCKET_NAME: &str = "control.sock";
/// How long the hello waits for the companion.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(1);
/// Largest answer read.
const MAX_ANSWER: u64 = 1024 * 1024;

/// Packets and bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    /// Socket buffers (`skb`), not wire packets.
    #[serde(default)]
    pub packets: u64,
    /// Bytes.
    #[serde(default)]
    pub bytes: u64,
}

/// Layer 1 totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Headers {
    /// Into the interface.
    #[serde(default)]
    pub ingress: Volume,
    /// Out of it.
    #[serde(default)]
    pub egress: Volume,
}

/// Copies the companion could not make.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drops {
    /// Over the copy rate.
    #[serde(default)]
    pub rate_limited: u64,
    /// No room in the ring buffer.
    #[serde(default)]
    pub ring_buffer_full: u64,
    /// Flows pushed out of the full flow table.
    #[serde(default)]
    pub flows_evicted: u64,
}

/// Flow totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flows {
    /// Seen since start.
    #[serde(default)]
    pub seen: u64,
    /// In the table now.
    #[serde(default)]
    pub active: u64,
    /// With a recognised protocol.
    #[serde(default)]
    pub recognised: u64,
}

/// Layer 2 totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protocols {
    /// HTTP/1 requests.
    #[serde(default)]
    pub http1_requests: u64,
    /// TLS client hellos.
    #[serde(default)]
    pub tls_client_hellos: u64,
    /// DNS queries.
    #[serde(default)]
    pub dns_queries: u64,
    /// HTTP/2 cleartext connections.
    #[serde(default)]
    pub http2_connections: u64,
    /// gRPC calls among them.
    #[serde(default)]
    pub grpc_calls: u64,
}

/// Status classes of timed requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusClasses {
    /// 1xx.
    #[serde(default, rename = "1xx")]
    pub c1xx: u64,
    /// 2xx.
    #[serde(default, rename = "2xx")]
    pub c2xx: u64,
    /// 3xx.
    #[serde(default, rename = "3xx")]
    pub c3xx: u64,
    /// 4xx.
    #[serde(default, rename = "4xx")]
    pub c4xx: u64,
    /// 5xx.
    #[serde(default, rename = "5xx")]
    pub c5xx: u64,
    /// The status was not visible.
    #[serde(default)]
    pub unknown: u64,
}

/// Layer 7 totals (over every route and owner; the names stay in the companion).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    /// Requests seen and settled.
    #[serde(default)]
    pub requests: u64,
    /// Of those, answered.
    #[serde(default)]
    pub responses: u64,
    /// Not answered before the connection ended.
    #[serde(default)]
    pub unanswered: u64,
    /// Connections whose timing stopped because a copy was lost.
    #[serde(default)]
    pub unsynced: u64,
    /// Distinct (method, route, owner) keys.
    #[serde(default)]
    pub keys: u64,
    /// Status classes.
    #[serde(default)]
    pub status_classes: StatusClasses,
}

/// Layer 3 numbers: whole packets copied and pcap files made on the host (never the
/// packets or the files).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packets {
    /// Whether the companion keeps whole packets.
    #[serde(default)]
    pub enabled: bool,
    /// Packets copied.
    #[serde(default)]
    pub copied: u64,
    /// Over the packet copy rate.
    #[serde(default)]
    pub rate_limited: u64,
    /// No room in the packets ring buffer.
    #[serde(default)]
    pub ring_buffer_full: u64,
    /// pcap files made on request.
    #[serde(default)]
    pub pcaps_written: u64,
}

/// Layer 4 totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owners {
    /// Sockets seen.
    #[serde(default)]
    pub sockets: u64,
    /// Distinct owners.
    #[serde(default)]
    pub owners: u64,
    /// Flows attributed to an owner.
    #[serde(default)]
    pub flows_owned: u64,
    /// Flows that could not be.
    #[serde(default)]
    pub flows_unowned: u64,
}

/// Host-wide TCP counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpHost {
    /// Accept queue overflows.
    #[serde(default)]
    pub listen_overflows: u64,
}

/// Layer 5 totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tcp {
    /// Established connections now.
    #[serde(default)]
    pub established: u64,
    /// Listening sockets now.
    #[serde(default)]
    pub listening: u64,
    /// Retransmitted segments, sampled.
    #[serde(default)]
    pub retransmits_sampled: u64,
    /// RST received.
    #[serde(default)]
    pub resets_in: u64,
    /// RST sent.
    #[serde(default)]
    pub resets_out: u64,
    /// Host counters.
    #[serde(default)]
    pub host: TcpHost,
}

/// The `counts` answer, as the agent keeps it: numbers and the layer names this agent
/// knows. Nothing else survives parsing (not even the companion's version string).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// Protocol version.
    pub version: u64,
    /// When the companion last read the kernel, ms since the epoch.
    #[serde(default)]
    pub updated_unix_ms: u64,
    /// Layers the companion runs.
    #[serde(default)]
    pub layers: Vec<String>,
    /// Layer 1.
    #[serde(default)]
    pub headers: Headers,
    /// Drops.
    #[serde(default)]
    pub drops: Drops,
    /// Flows.
    #[serde(default)]
    pub flows: Flows,
    /// Layer 2.
    #[serde(default)]
    pub protocols: Protocols,
    /// Layer 4.
    #[serde(default)]
    pub owners: Owners,
    /// Layer 5.
    #[serde(default)]
    pub tcp: Tcp,
    /// Layer 7.
    #[serde(default)]
    pub timing: Timing,
    /// Layer 3.
    #[serde(default)]
    pub packets: Packets,
}

impl Counts {
    /// Parses a `counts` answer, keeping only what [`Counts`] holds; layer names are kept
    /// only when they are ones this agent knows.
    ///
    /// # Errors
    /// The companion's error code, or why the answer is not usable.
    pub fn parse(answer: &[u8]) -> Result<Self, String> {
        // Only codes this agent knows travel on (to the admin page, status.json and the
        // logs); anything else a companion says is `other`.
        error_code(answer)?;
        let mut c: Self = serde_json::from_slice(answer)
            .map_err(|e| format!("not a counts answer ({})", e.classify_name()))?;
        if c.version != WIRE_VERSION {
            return Err(format!("unsupported protocol version {}", c.version));
        }
        c.layers.retain(|l| {
            crate::policy::CaptureLayer::ALL
                .iter()
                .any(|k| k.as_str() == l)
        });
        Ok(c)
    }

    /// Seconds since the companion's last kernel read.
    #[must_use]
    pub fn age_secs(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.updated_unix_ms) / 1000
    }
}

trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}

impl ClassifyName for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        }
    }
}

/// Milliseconds since the epoch.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The capability strings for a fresh, usable answer: `capture:<layer>` for each layer
/// both the policy and the companion name; `capture:packets` also needs the companion's
/// control socket to exist (`control_present`).
///
/// # Errors
/// Why the answer is not usable (too old).
pub fn capabilities(
    policy: &CapturePolicy,
    counts: &Counts,
    control_present: bool,
    now_ms: u64,
) -> Result<Vec<String>, String> {
    let age = counts.age_secs(now_ms);
    if age > policy.max_snapshot_age_secs {
        return Err(format!(
            "the companion's numbers are {age} s old (policy: at most {} s)",
            policy.max_snapshot_age_secs
        ));
    }
    Ok(policy
        .layers
        .iter()
        .filter(|l| counts.layers.iter().any(|c| c == l.as_str()))
        .filter(|l| **l != CaptureLayer::Packets || control_present)
        .map(|l| format!("capture:{}", l.as_str()))
        .collect())
}

/// The control socket next to the aggregates socket.
#[must_use]
pub fn control_socket(aggregates: &Path) -> std::path::PathBuf {
    aggregates.with_file_name(CONTROL_SOCKET_NAME)
}

/// Latency buckets of a lookup (the bounds are fixed by the protocol; only counts travel).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Latency {
    /// Upper bounds in milliseconds; the last bucket is above the last bound.
    pub le_ms: Vec<f64>,
    /// Requests per bucket (not cumulative).
    pub counts: Vec<u64>,
    /// Sum of latencies, milliseconds.
    pub sum_ms: f64,
}

/// TCP health of the owner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct OwnerTcp {
    /// Whether the companion knows the owner.
    pub found: bool,
    /// Retransmitted segments since the companion started.
    pub retransmits: u64,
    /// Resets seen on its flows.
    pub resets: u64,
    /// RTT of its established sockets, `[<1, <10, <100, <1000, >=1000]` ms.
    pub rtt_ms: [u64; 5],
}

/// The `lookup` answer, numbers only.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Lookup {
    /// Whether the companion has timed that owner and route.
    pub found: bool,
    /// Requests settled.
    pub requests: u64,
    /// Answered.
    pub responses: u64,
    /// Not answered before the connection ended.
    pub unanswered: u64,
    /// Status classes.
    pub status_classes: StatusClasses,
    /// gRPC status codes 0 to 16, by code.
    pub grpc_status: [u64; 17],
    /// Latency histogram.
    pub latency: Latency,
    /// TCP health of the owner.
    pub owner_tcp: OwnerTcp,
}

/// Fixed upper bounds of the companion's latency histogram (milliseconds).
const LATENCY_BOUNDS_MS: [f64; 14] = [
    0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];

impl Lookup {
    /// Parses a `lookup` answer. Only numbers survive: gRPC codes are taken only for keys
    /// `0` to `16`, histogram counts only up to the protocol's 15 buckets, and the bounds
    /// are this agent's own constants, never the companion's.
    ///
    /// # Errors
    /// The companion's error code (only known codes; anything else is `other`), or why the
    /// answer is not usable.
    pub fn parse(answer: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Wire {
            version: u64,
            #[serde(default)]
            found: bool,
            #[serde(default)]
            requests: u64,
            #[serde(default)]
            responses: u64,
            #[serde(default)]
            unanswered: u64,
            #[serde(default)]
            status_classes: StatusClasses,
            #[serde(default)]
            grpc_status: std::collections::BTreeMap<String, serde_json::Value>,
            #[serde(default)]
            latency_ms: WireLatency,
            #[serde(default)]
            owner_tcp: WireTcp,
        }
        #[derive(Deserialize, Default)]
        struct WireLatency {
            #[serde(default)]
            counts: Vec<u64>,
            #[serde(default)]
            sum: f64,
        }
        #[derive(Deserialize, Default)]
        struct WireTcp {
            #[serde(default)]
            found: bool,
            #[serde(default)]
            retransmits: u64,
            #[serde(default)]
            resets: u64,
            #[serde(default)]
            rtt_ms: Rtt,
        }
        #[derive(Deserialize, Default)]
        struct Rtt {
            #[serde(default)]
            lt_1: u64,
            #[serde(default)]
            lt_10: u64,
            #[serde(default)]
            lt_100: u64,
            #[serde(default)]
            lt_1000: u64,
            #[serde(default)]
            ge_1000: u64,
        }
        error_code(answer)?;
        let w: Wire = serde_json::from_slice(answer)
            .map_err(|e| format!("not a lookup answer ({})", e.classify_name()))?;
        if w.version != WIRE_VERSION_2 {
            return Err(format!("unsupported protocol version {}", w.version));
        }
        let mut grpc = [0u64; 17];
        for (k, v) in &w.grpc_status {
            if let (Ok(code), Some(n)) = (k.parse::<usize>(), v.as_u64())
                && let Some(slot) = grpc.get_mut(code)
            {
                *slot = n;
            }
        }
        let mut counts = w.latency_ms.counts;
        counts.truncate(LATENCY_BOUNDS_MS.len() + 1);
        let r = &w.owner_tcp.rtt_ms;
        Ok(Self {
            found: w.found,
            requests: w.requests,
            responses: w.responses,
            unanswered: w.unanswered,
            status_classes: w.status_classes,
            grpc_status: grpc,
            latency: Latency {
                le_ms: LATENCY_BOUNDS_MS.to_vec(),
                counts,
                sum_ms: if w.latency_ms.sum.is_finite() {
                    w.latency_ms.sum
                } else {
                    0.0
                },
            },
            owner_tcp: OwnerTcp {
                found: w.owner_tcp.found,
                retransmits: w.owner_tcp.retransmits,
                resets: w.owner_tcp.resets,
                rtt_ms: [r.lt_1, r.lt_10, r.lt_100, r.lt_1000, r.ge_1000],
            },
        })
    }
}

/// `Err` with the companion's code when the answer is an error (known codes only).
fn error_code(answer: &[u8]) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Error {
        error: String,
    }
    if let Ok(e) = serde_json::from_slice::<Error>(answer) {
        let code = KNOWN_ERRORS
            .iter()
            .find(|k| **k == e.error)
            .copied()
            .unwrap_or("other");
        return Err(format!("the companion answered {code}"));
    }
    Ok(())
}

/// Asks the companion (version 2) for the numbers of one owner and route.
///
/// # Errors
/// When the socket cannot be reached, does not answer in time, or refuses.
pub async fn lookup(
    socket: &Path,
    owner: &str,
    route: &str,
    timeout: Duration,
) -> Result<Lookup, String> {
    let line = serde_json::json!({
        "version": WIRE_VERSION_2, "request": "lookup", "owner": owner, "route": route,
    })
    .to_string();
    let raw = send(socket, &line, timeout).await?;
    Lookup::parse(&raw)
}

/// Sends one request to the socket and returns the raw answer (bounded).
///
/// # Errors
/// When the socket cannot be reached or does not answer in time.
pub async fn request(socket: &Path, what: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let line = format!("{{\"version\":{WIRE_VERSION},\"request\":\"{what}\"}}");
    send(socket, &line, timeout).await
}

/// Sends one request line and returns the raw answer (bounded).
async fn send(socket: &Path, line: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let go = async {
            let mut s = tokio::net::UnixStream::connect(socket)
                .await
                .map_err(|e| format!("cannot reach {}: {}", socket.display(), e.kind()))?;
            let line = format!("{line}\n");
            s.write_all(line.as_bytes())
                .await
                .map_err(|e| format!("write: {}", e.kind()))?;
            let mut out = Vec::new();
            (&mut s)
                .take(MAX_ANSWER)
                .read_to_end(&mut out)
                .await
                .map_err(|e| format!("read: {}", e.kind()))?;
            Ok(out)
        };
        tokio::time::timeout(timeout, go)
            .await
            .map_err(|_| format!("no answer from {} in time", socket.display()))?
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, line, timeout);
        Err("capture needs a Unix socket (Linux)".into())
    }
}

/// What the agent knows about capture, for the admin page and `status.json`: counts only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficInfo {
    /// `answering`, `not answering`, `stale`.
    pub state: String,
    /// Why not, when not answering.
    pub reason: Option<String>,
    /// The socket asked.
    pub socket: String,
    /// When asked, RFC 3339.
    pub checked_at: String,
    /// Age of the companion's numbers, seconds.
    pub age_secs: Option<u64>,
    /// What the agent announces now.
    pub capabilities: Vec<String>,
    /// The numbers.
    pub counts: Option<Counts>,
}

/// Asks the companion for counts and decides the capabilities.
pub async fn check(policy: &CapturePolicy, timeout: Duration) -> TrafficInfo {
    let mut info = TrafficInfo {
        socket: policy.socket.display().to_string(),
        checked_at: crate::enroll::now_rfc3339(),
        ..TrafficInfo::default()
    };
    let parsed = request(&policy.socket, "counts", timeout)
        .await
        .and_then(|raw| Counts::parse(&raw));
    match parsed {
        Err(reason) => {
            info.state = "not answering".into();
            info.reason = Some(reason);
        }
        Ok(counts) => {
            let now = now_ms();
            info.age_secs = Some(counts.age_secs(now));
            let control = control_socket(&policy.socket).exists();
            match capabilities(policy, &counts, control, now) {
                Ok(caps) => {
                    info.state = "answering".into();
                    info.capabilities = caps;
                }
                Err(reason) => {
                    info.state = "stale".into();
                    info.reason = Some(reason);
                }
            }
            info.counts = Some(counts);
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CaptureLayer;

    fn answer(updated: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "companion_version": "0.1.0", "interface": "eth0",
            "updated_unix_ms": updated, "layers": ["headers", "protocols", "owners", "tcp", "packets", "timing", "payloads"],
            "headers": {"ingress": {"packets": 10, "bytes": 1000}, "egress": {"packets": 5, "bytes": 500}},
            "protocols": {"http1_requests": 3, "tls_client_hellos": 2},
            "tables": {"tls": {"sni": [{"key": "secret.example", "count": 2}]}},
        }))
        .unwrap()
    }

    #[test]
    fn keeps_numbers_only() {
        let c = Counts::parse(&answer(now_ms())).unwrap();
        assert_eq!(c.headers.ingress.packets, 10);
        assert_eq!(c.protocols.http1_requests, 3);
        assert_eq!(
            c.layers,
            ["headers", "protocols", "owners", "tcp", "packets", "timing"]
        );
        let text = serde_json::to_string(&c).unwrap();
        assert!(
            !text.contains("secret.example") && !text.contains("eth0"),
            "{text}"
        );
    }

    #[test]
    fn capabilities_follow_policy_companion_and_age() {
        let now = now_ms();
        let c = Counts::parse(&answer(now)).unwrap();
        let mut p = CapturePolicy::default();
        assert_eq!(
            capabilities(&p, &c, true, now).unwrap(),
            [
                "capture:headers",
                "capture:protocols",
                "capture:owners",
                "capture:tcp",
                "capture:packets",
                "capture:timing"
            ]
        );
        // No control socket: no packets, whatever the companion says.
        assert!(
            !capabilities(&p, &c, false, now)
                .unwrap()
                .contains(&"capture:packets".to_owned())
        );
        p.layers = vec![CaptureLayer::Tcp];
        assert_eq!(capabilities(&p, &c, true, now).unwrap(), ["capture:tcp"]);
        let old = Counts::parse(&answer(now - 120_000)).unwrap();
        assert!(capabilities(&p, &old, true, now).is_err());
    }

    #[test]
    fn lookup_keeps_numbers_only() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "version": 2, "found": true, "requests": 12, "responses": 11, "unanswered": 1,
            "owner": "cgroup:/secret.slice", "route": "GET /secret/{id}",
            "status_classes": {"2xx": 10, "5xx": 1, "secret": 4},
            "grpc_status": {"0": 3, "14": 1, "99": 5, "secret.example": 7},
            "latency_ms": {"le": ["secret"], "counts": [0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9], "sum": 400.5},
            "owner_tcp": {"found": true, "retransmits": 2, "resets": 1, "rtt_ms": {"lt_1": 3}, "pod": "secret-pod"},
        }))
        .unwrap();
        let l = Lookup::parse(&raw).unwrap();
        assert!(l.found);
        assert_eq!((l.requests, l.responses, l.unanswered), (12, 11, 1));
        assert_eq!(l.status_classes.c2xx, 10);
        assert_eq!((l.grpc_status[0], l.grpc_status[14]), (3, 1));
        assert_eq!(l.latency.counts.len(), 15);
        assert_eq!(l.latency.counts[6], 11);
        assert_eq!(l.owner_tcp.rtt_ms[0], 3);
        let text = serde_json::to_string(&l).unwrap();
        assert!(!text.contains("secret"), "{text}");
        assert!(Lookup::parse(br#"{"version":1}"#).is_err());
        assert_eq!(
            Lookup::parse(br#"{"version":2,"error":"rate_limited"}"#).unwrap_err(),
            "the companion answered rate_limited"
        );
    }

    #[test]
    fn errors_and_other_versions() {
        assert!(
            Counts::parse(br#"{"version":1,"error":"forbidden","message":"x"}"#)
                .unwrap_err()
                .contains("forbidden")
        );
        assert!(Counts::parse(br#"{"version":2}"#).is_err());
        // A code the agent does not know is never repeated (it could carry anything).
        let e = Counts::parse(br#"{"version":1,"error":"canary-sni.example"}"#).unwrap_err();
        assert_eq!(e, "the companion answered other");
        assert!(Counts::parse(b"garbage").is_err());
    }
}
