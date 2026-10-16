//! What the agent has done, for the local admin page and `status`: counts and kinds,
//! never content.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::protocol::ResultStatus;

/// How many recent jobs the page lists.
const RECENT: usize = 200;
/// How far back it lists them.
const WINDOW: time::Duration = time::Duration::days(1);
/// Runs kept per declared check (the page's sparkline).
pub const CHECK_HISTORY: usize = 60;
/// Most checks with a history (`checks.toml` allows 50).
const MAX_CHECK_KEYS: usize = 64;
/// Longest string from the platform kept in a record.
const MAX_FIELD: usize = 256;

/// Shared, cheap to lock.
#[derive(Debug)]
pub struct AgentState {
    inner: Mutex<Snapshot>,
    started: Instant,
    /// Runs per declared check, newest last.
    checks: Mutex<BTreeMap<String, VecDeque<JobRecord>>>,
    /// When jobs arrived in the last minute.
    arrivals: Mutex<VecDeque<Instant>>,
    /// The trial store (RFC 0100.1 §5), when the agent keeps one.
    store: std::sync::OnceLock<std::sync::Arc<crate::store::Store>>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new(AgentInfo::default(), PolicyInfo::default(), String::new())
    }
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
    /// The host sampler, when `[work] host = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
    /// The platform's API.
    #[serde(default)]
    pub api: String,
    /// When this process started, RFC 3339.
    #[serde(default)]
    pub started_at: String,
    /// Seconds since then.
    #[serde(default)]
    pub uptime_secs: u64,
    /// When the last heartbeat went out.
    #[serde(default)]
    pub last_heartbeat_at: Option<String>,
    /// Jobs that arrived in the last 60 seconds.
    #[serde(default)]
    pub jobs_last_minute: u64,
    /// Jobs running now.
    #[serde(default)]
    pub running_jobs: u64,
    /// The latest host reading, when `[work] host = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_report: Option<HostReport>,
}

/// A periodic reading of this host for the page: the human report and the findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostReport {
    /// When it was read, RFC 3339.
    pub at: String,
    /// `atlas observe host --report`'s text.
    pub text: String,
    /// Derived findings.
    pub findings: Vec<FindingView>,
}

/// One finding, as the page shows it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingView {
    /// Which derivation.
    pub check: String,
    /// What it is about.
    pub subject: String,
    /// `supported`, `not_supported`, `unknown`.
    pub verdict: String,
    /// Why.
    pub reason: String,
}

/// The host sampler's state, for the admin page and `status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    /// Sensors sampled.
    pub sensors: usize,
    /// Samples in the window.
    pub samples: usize,
    /// When the newest was taken, RFC 3339.
    pub last_sample_at: String,
    /// How long it took to read, microseconds.
    pub last_cost_us: u64,
    /// The slowest sample since the agent started, microseconds.
    pub max_cost_us: u64,
    /// The chipset temperature, when the board has a `Chipset` sensor (milli-degrees).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chipset_millicelsius: Option<i64>,
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
    /// WebSocket pings (empty control frames that keep the session honest).
    #[serde(default)]
    pub pings: u64,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// The platform's id for the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The declared check it ran (`name` in `checks.toml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Why it was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The class of failure (`timeout`, `refused_by_policy`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// HTTP status received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// The certificate's `notAfter`, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_expires_at: Option<String>,
}

fn cap(s: &mut Option<String>) {
    if let Some(v) = s {
        if v.len() > MAX_FIELD {
            let mut cut = MAX_FIELD;
            while !v.is_char_boundary(cut) {
                cut -= 1;
            }
            v.truncate(cut);
        }
        *v = crate::redact::redact(v);
    }
}

impl JobRecord {
    /// Bounds and redacts every field that came from the platform or a target.
    #[must_use]
    pub fn bounded(mut self) -> Self {
        let mut kind = Some(std::mem::take(&mut self.kind));
        cap(&mut kind);
        self.kind = kind.unwrap_or_default();
        cap(&mut self.surface);
        cap(&mut self.target_host);
        cap(&mut self.job_id);
        cap(&mut self.key);
        cap(&mut self.reason);
        cap(&mut self.error_class);
        cap(&mut self.tls_expires_at);
        self
    }
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
                started_at: crate::enroll::now_rfc3339(),
                ..Snapshot::default()
            }),
            started: Instant::now(),
            checks: Mutex::new(BTreeMap::new()),
            arrivals: Mutex::new(VecDeque::new()),
            store: std::sync::OnceLock::new(),
        }
    }

    /// Names the platform's API on the page.
    pub fn set_api(&self, api: &str) {
        self.with(|s| api.clone_into(&mut s.api));
    }

    /// The runs of each declared check, oldest first.
    #[must_use]
    pub fn check_runs(&self) -> BTreeMap<String, Vec<JobRecord>> {
        let g = match self.checks.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.iter()
            .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
            .collect()
    }

    fn arrivals_in_last_minute(&self) -> u64 {
        let mut a = match self.arrivals.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        while a
            .front()
            .is_some_and(|t| now.duration_since(*t).as_secs() >= 60)
        {
            a.pop_front();
        }
        a.len() as u64
    }

    /// The latest host reading.
    pub fn host_reported(&self, r: HostReport) {
        self.with(|s| s.host_report = Some(r));
    }

    /// A WebSocket ping went out.
    pub fn ping(&self) {
        self.with(|s| s.sent.pings += 1);
    }

    /// A job was admitted and is running.
    pub fn job_started(&self) {
        self.with(|s| s.running_jobs += 1);
    }

    /// An admitted job ended.
    pub fn job_finished(&self) {
        self.with(|s| s.running_jobs = s.running_jobs.saturating_sub(1));
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
        let last_minute = self.arrivals_in_last_minute();
        let uptime = self.started.elapsed().as_secs();
        self.with(|s| {
            let cutoff = OffsetDateTime::now_utc() - WINDOW;
            let mut copy = s.clone();
            copy.jobs_last_minute = last_minute;
            copy.uptime_secs = uptime;
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
        let mut error = error;
        cap(&mut error);
        self.with(|s| {
            s.connected = false;
            s.connected_since = None;
            s.running_jobs = 0;
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

    /// The host sampler took a sample.
    pub fn host_sampled(&self, info: HostInfo) {
        if let Some(store) = self.store.get()
            && let Err(e) = store.record_host(&info)
        {
            tracing::warn!(error = %e, "a host reading was not kept in the trial store");
        }
        self.with(|s| s.host = Some(info));
    }

    /// Keeps runs and host readings in `store` from now on, and loads the newest runs of
    /// each check back into memory, so the page's history survives a restart. A second
    /// call is ignored.
    pub fn attach_store(&self, store: std::sync::Arc<crate::store::Store>) {
        match store.recent_by_key(CHECK_HISTORY) {
            Ok(by_key) => {
                let mut g = match self.checks.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                for (key, runs) in by_key.into_iter().take(MAX_CHECK_KEYS) {
                    g.entry(key).or_insert_with(|| runs.into_iter().collect());
                }
            }
            Err(e) => tracing::warn!(error = %e, "the trial store's history could not be read"),
        }
        let _ = self.store.set(store);
    }

    /// The trial store, when kept.
    #[must_use]
    pub fn store(&self) -> Option<&std::sync::Arc<crate::store::Store>> {
        self.store.get()
    }

    /// The latest answer from the capture companion.
    pub fn capture_checked(&self, info: crate::capture::TrafficInfo) {
        self.with(|s| s.capture = Some(info));
    }

    /// A heartbeat went out.
    pub fn heartbeat(&self) {
        self.with(|s| {
            s.sent.heartbeat += 1;
            s.last_heartbeat_at = Some(crate::enroll::now_rfc3339());
        });
    }

    /// A job arrived.
    pub fn job_received(&self) {
        {
            let mut a = match self.arrivals.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            a.push_back(Instant::now());
            // Bounded: the policy allows at most 6000 a minute; a platform sending more
            // only has its oldest arrivals forgotten here (the executor refuses them).
            if a.len() > 10_000 {
                a.pop_front();
            }
        }
        self.with(|s| s.received.jobs += 1);
    }

    /// A cancel arrived.
    pub fn cancel_received(&self) {
        self.with(|s| s.received.cancels += 1);
    }

    /// A result went out.
    pub fn result_sent(&self, record: JobRecord, status: ResultStatus) {
        let record = record.bounded();
        if let Some(store) = self.store.get()
            && let Err(e) = store.record_run(&record)
        {
            tracing::warn!(error = %e, "a run was not kept in the trial store");
        }
        if let Some(key) = &record.key {
            let mut g = match self.checks.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if g.contains_key(key) || g.len() < MAX_CHECK_KEYS {
                let runs = g.entry(key.clone()).or_default();
                if runs.len() == CHECK_HISTORY {
                    runs.pop_front();
                }
                runs.push_back(record.clone());
            }
        }
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
