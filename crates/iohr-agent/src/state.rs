//! What the agent has done, for the local admin page and `status`: counts and kinds,
//! never content.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::protocol::ResultStatus;

/// How many recent jobs the page lists.
const RECENT: usize = 200;
/// How far back it lists them.
const WINDOW: time::Duration = time::Duration::days(1);

/// Shared, cheap to lock.
#[derive(Debug, Default)]
pub struct AgentState {
    inner: Mutex<Snapshot>,
}

/// The status document (`/status.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// The agent.
    pub agent: AgentInfo,
    /// The session is up.
    pub connected: bool,
    /// Since when, RFC 3339.
    pub connected_since: Option<String>,
    /// The last session error, if any.
    pub last_error: Option<String>,
    /// The platform revoked this agent.
    pub revoked: bool,
    /// The loaded policy.
    pub policy: PolicyInfo,
    /// What was sent to the platform.
    pub sent: Sent,
    /// What was received.
    pub received: Received,
    /// The most recent jobs in the last day.
    pub recent_jobs: VecDeque<JobRecord>,
    /// How to stop the agent here.
    pub stop: String,
    /// The capture companion, when `[work] capture = true`: counts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<crate::capture::TrafficInfo>,
}

/// Identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Version.
    pub version: String,
    /// `agt_…`, once enrolled.
    pub agent_id: Option<String>,
    /// Name.
    pub name: String,
    /// Environment.
    pub environment: String,
    /// Process id.
    pub pid: u32,
}

/// Policy facts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// `sha256:…`.
    pub hash: String,
    /// The file.
    pub path: String,
    /// Bound domains.
    pub domains: Vec<String>,
    /// Accepted capabilities.
    pub capabilities: Vec<String>,
    /// The checks file.
    #[serde(default)]
    pub checks_path: String,
    /// `sha256:…` of the declared checks; none without a checks file.
    #[serde(default)]
    pub checks_hash: Option<String>,
    /// How many checks and refusals are declared.
    #[serde(default)]
    pub checks: usize,
}

/// Counts of frames sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sent {
    /// Hellos (one per session).
    pub hello: u64,
    /// Heartbeats.
    pub heartbeat: u64,
    /// Results that passed.
    pub results_ok: u64,
    /// Results that failed.
    pub results_failed: u64,
    /// Refusals.
    pub results_refused: u64,
}

/// Counts of frames received.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Received {
    /// Sessions opened.
    pub sessions: u64,
    /// Jobs.
    pub jobs: u64,
    /// Cancels.
    pub cancels: u64,
}

/// One job, as the page shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    /// When it finished, RFC 3339.
    pub at: String,
    /// `check`, …
    pub kind: String,
    /// `http`, …
    pub surface: Option<String>,
    /// Host only: never a path or query, which may carry secrets.
    pub target_host: Option<String>,
    /// `ok`, `failed`, `refused`.
    pub verdict: String,
    /// Milliseconds.
    pub latency_ms: u64,
}

impl AgentState {
    /// Fresh state with the agent's identity.
    #[must_use]
    pub fn new(agent: AgentInfo, policy: PolicyInfo, stop: String) -> Self {
        Self {
            inner: Mutex::new(Snapshot {
                agent,
                policy,
                stop,
                ..Snapshot::default()
            }),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Snapshot) -> R) -> R {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// A copy for rendering.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.with(|s| {
            let cutoff = OffsetDateTime::now_utc() - WINDOW;
            let mut copy = s.clone();
            copy.recent_jobs.retain(|j| {
                OffsetDateTime::parse(&j.at, &time::format_description::well_known::Rfc3339)
                    .is_ok_and(|t| t >= cutoff)
            });
            copy
        })
    }

    /// The session came up.
    pub fn connected(&self, agent_id: &str) {
        self.with(|s| {
            s.connected = true;
            s.connected_since = Some(crate::enroll::now_rfc3339());
            s.last_error = None;
            s.agent.agent_id = Some(agent_id.to_owned());
            s.received.sessions += 1;
            s.sent.hello += 1;
        });
    }

    /// The session went down.
    pub fn disconnected(&self, error: Option<String>) {
        self.with(|s| {
            s.connected = false;
            s.connected_since = None;
            if error.is_some() {
                s.last_error = error;
            }
        });
    }

    /// The platform revoked the agent.
    pub fn revoked(&self) {
        self.with(|s| {
            s.revoked = true;
            s.connected = false;
        });
    }

    /// The latest answer from the capture companion.
    pub fn capture_checked(&self, info: crate::capture::TrafficInfo) {
        self.with(|s| s.capture = Some(info));
    }

    /// A heartbeat went out.
    pub fn heartbeat(&self) {
        self.with(|s| s.sent.heartbeat += 1);
    }

    /// A job arrived.
    pub fn job_received(&self) {
        self.with(|s| s.received.jobs += 1);
    }

    /// A cancel arrived.
    pub fn cancel_received(&self) {
        self.with(|s| s.received.cancels += 1);
    }

    /// A result went out.
    pub fn result_sent(&self, record: JobRecord, status: ResultStatus) {
        self.with(|s| {
            match status {
                ResultStatus::Ok => s.sent.results_ok += 1,
                ResultStatus::Failed => s.sent.results_failed += 1,
                ResultStatus::Refused => s.sent.results_refused += 1,
            }
            if s.recent_jobs.len() == RECENT {
                s.recent_jobs.pop_front();
            }
            s.recent_jobs.push_back(record);
        });
    }
}

/// How to stop the agent where it runs.
#[must_use]
pub fn how_to_stop() -> String {
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        "Kubernetes: scale the agent's StatefulSet to 0 (kubectl scale statefulset/<release>-iohr-agent --replicas=0) or helm uninstall <release>. Revoke it in the console to cut it off for good.".into()
    } else if std::env::var_os("INVOCATION_ID").is_some() {
        "systemd: sudo systemctl stop iohr-agent (and disable it to keep it stopped). Revoke it in the console to cut it off for good.".into()
    } else {
        format!(
            "Press Ctrl-C where `iohr agent run` is running, or kill {}. Revoke it in the console to cut it off for good.",
            std::process::id()
        )
    }
}
