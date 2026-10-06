//! The agent's side of capture (`docs/capture/design-phase1.md`): it reads the capture
//! companion's `counts` answer over a local Unix socket and announces `capture:*` in the
//! hello when the policy allows it and the companion answers.
//!
//! Privacy by construction: the answer is parsed into [`Counts`], which has numeric fields
//! only, so names, paths, addresses or owners a companion might send never reach the
//! agent's memory, frames, admin page, logs or telemetry. The `tables` request (top-K
//! names, for a person at the terminal) is only made by `iohr agent capture status
//! --tables`, which prints and exits.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::policy::CapturePolicy;

/// Error codes of the socket protocol (`docs/capture/design-phase1.md`).
const KNOWN_ERRORS: [&str; 6] = [
    "forbidden",
    "unsupported_version",
    "bad_request",
    "unknown_request",
    "too_large",
    "not_available",
];

/// The socket protocol version this agent speaks.
pub const WIRE_VERSION: u64 = 1;
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
}

impl Counts {
    /// Parses a `counts` answer, keeping only what [`Counts`] holds; layer names are kept
    /// only when they are ones this agent knows.
    ///
    /// # Errors
    /// The companion's error code, or why the answer is not usable.
    pub fn parse(answer: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Error {
            error: String,
        }
        if let Ok(e) = serde_json::from_slice::<Error>(answer) {
            // Only codes this agent knows travel on (to the admin page, status.json and
            // the logs); anything else a companion says is `other`.
            let code = KNOWN_ERRORS
                .iter()
                .find(|k| **k == e.error)
                .copied()
                .unwrap_or("other");
            return Err(format!("the companion answered {code}"));
        }
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
/// both the policy and the companion name.
///
/// # Errors
/// Why the answer is not usable (too old).
pub fn capabilities(
    policy: &CapturePolicy,
    counts: &Counts,
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
        .map(|l| format!("capture:{}", l.as_str()))
        .collect())
}

/// Sends one request to the socket and returns the raw answer (bounded).
///
/// # Errors
/// When the socket cannot be reached or does not answer in time.
pub async fn request(socket: &Path, what: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let go = async {
            let mut s = tokio::net::UnixStream::connect(socket)
                .await
                .map_err(|e| format!("cannot reach {}: {}", socket.display(), e.kind()))?;
            let line = format!("{{\"version\":{WIRE_VERSION},\"request\":\"{what}\"}}\n");
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
        let _ = (socket, what, timeout);
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
            match capabilities(policy, &counts, now) {
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
            "updated_unix_ms": updated, "layers": ["headers", "protocols", "owners", "tcp", "packets"],
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
        assert_eq!(c.layers, ["headers", "protocols", "owners", "tcp"]);
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
            capabilities(&p, &c, now).unwrap(),
            [
                "capture:headers",
                "capture:protocols",
                "capture:owners",
                "capture:tcp"
            ]
        );
        p.layers = vec![CaptureLayer::Tcp];
        assert_eq!(capabilities(&p, &c, now).unwrap(), ["capture:tcp"]);
        let old = Counts::parse(&answer(now - 120_000)).unwrap();
        assert!(capabilities(&p, &old, now).is_err());
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
