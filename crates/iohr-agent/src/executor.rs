//! Admits or refuses each job against the local policy, then runs it inside its ceiling.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument as _;

use crate::checks::{self, CheckDetail, CheckSpec, Endpoint, ErrorClass, Prepared, Target};
use crate::checks_file::DeclaredChecks;
use crate::enroll::now_rfc3339;
use crate::policy::{Policy, TargetError};
use crate::protocol::{Job, JobResult, Refusal, ResultStatus};
use crate::secrets::{SecretRef, SecretResolver};
use crate::state::JobRecord;
use crate::tls::TlsContext;

/// Longest a DNS lookup may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs jobs.
#[derive(Debug)]
pub struct Executor {
    policy: Arc<Policy>,
    tls: TlsContext,
    secrets: SecretResolver,
    /// The declared checks: what a transport check sends comes from here, never a job.
    checks: Option<Arc<DeclaredChecks>>,
    /// The host sampler, when the policy turns host observation on.
    host: Option<crate::host::sampler::Shared>,
    /// When each hwmon check last ran (sampler milliseconds): the next run judges the
    /// window since then, so a spike between runs is not missed.
    host_runs: Mutex<std::collections::HashMap<String, u64>>,
    /// `[share] targets`, and the key target hashes are made with.
    share: (crate::policy::TargetShare, Vec<u8>),
    /// `inorbit/monitors` is not installed: check jobs are refused.
    monitors_off: bool,
    slots: Arc<Semaphore>,
    window: Mutex<VecDeque<Instant>>,
    jobs: Counter<u64>,
    duration: Histogram<f64>,
}

/// A job the policy accepted, holding its concurrency slot.
#[derive(Debug)]
pub struct Admitted {
    spec: CheckSpec,
    endpoint: Endpoint,
    secret: Option<SecretRef>,
    deadline: Duration,
    _permit: OwnedSemaphorePermit,
}

/// Run it, or refuse it with a reason.
#[derive(Debug)]
pub enum Admission {
    /// Accepted.
    Run(Box<Admitted>),
    /// Refused; the reason goes to the platform.
    Refuse(String),
}

/// A finished job: what goes to the platform and what the admin page lists.
#[derive(Debug)]
pub struct Finished {
    /// The result frame.
    pub result: JobResult,
    /// The admin page's record.
    pub record: JobRecord,
}

impl Executor {
    /// An executor bound to a policy.
    #[must_use]
    pub fn new(policy: Arc<Policy>, tls: TlsContext, secrets: SecretResolver) -> Self {
        let meter = opentelemetry::global::meter("iohr-agent");
        let slots = Arc::new(Semaphore::new(policy.ceilings.max_concurrent_jobs as usize));
        Self {
            policy,
            tls,
            secrets,
            checks: None,
            host: None,
            host_runs: Mutex::new(std::collections::HashMap::new()),
            share: (crate::policy::TargetShare::Full, Vec::new()),
            monitors_off: false,
            slots,
            window: Mutex::new(VecDeque::new()),
            jobs: meter
                .u64_counter("iohr_agent.jobs")
                .with_description("Jobs finished, by kind, surface and verdict")
                .build(),
            duration: meter
                .f64_histogram("iohr_agent.job.duration")
                .with_unit("ms")
                .with_description("Job wall time")
                .build(),
        }
    }

    /// The declared checks a job may name by its `key`.
    #[must_use]
    pub fn with_checks(mut self, checks: Option<Arc<DeclaredChecks>>) -> Self {
        self.checks = checks;
        self
    }

    /// How much of a declared check's target the platform knows: below `full`, a job
    /// names the check by its key (and may carry its `target_hash`); the target comes
    /// from `checks.toml`, and refusal reasons leave without it.
    #[must_use]
    pub fn with_share(mut self, level: crate::policy::TargetShare, key: Vec<u8>) -> Self {
        self.share = (level, key);
        self
    }

    /// The declared check a job names, when its target is not shared with the platform.
    fn hidden_entry(&self, job: &Job) -> Option<&crate::checks_file::DeclaredCheck> {
        let key = job.spec.get("key")?.as_str()?;
        let entry = self
            .checks
            .as_ref()?
            .entries
            .iter()
            .find(|e| e.key == key)?;
        (crate::share::level_for(entry, self.share.0) != crate::policy::TargetShare::Full)
            .then_some(entry)
    }

    /// A job for a declared check whose target the platform does not know names it by key:
    /// its target is filled in from `checks.toml`. A `target_hash` it carries must match.
    fn fill_target(&self, job: &Job) -> Result<serde_json::Value, String> {
        let mut spec = job.spec.clone();
        let Some(entry) = self.hidden_entry(job) else {
            return Ok(spec);
        };
        if let Some(h) = spec.get("target_hash").and_then(|h| h.as_str())
            && h != crate::share::target_hash(entry, &self.share.1)
        {
            return Err(format!(
                "the job's target_hash does not match the declared check {:?}",
                entry.key
            ));
        }
        if let Some(o) = spec.as_object_mut() {
            o.remove("target_hash");
            if !o.contains_key("target") {
                o.insert("target".into(), entry.to_wire()["target"].clone());
            }
        }
        Ok(spec)
    }

    /// What a refusal tells the platform: without the target when it is not shared.
    #[must_use]
    pub fn reason_for_platform(&self, key: Option<&str>, reason: &str) -> String {
        let entry = key.and_then(|k| self.checks.as_ref()?.entries.iter().find(|e| e.key == k));
        match entry {
            Some(e)
                if crate::share::level_for(e, self.share.0) != crate::policy::TargetShare::Full =>
            {
                crate::share::scrub(reason, e)
            }
            _ => reason.to_owned(),
        }
    }

    /// Takes the target out of a result's refusal reason before it leaves, when the
    /// policy does not share it. The local page keeps the full reason.
    pub fn prepare_for_platform(&self, done: &mut Finished) {
        if let Some(r) = &mut done.result.refusal {
            r.reason = self.reason_for_platform(done.record.key.as_deref(), &r.reason);
        }
    }

    /// Whether `inorbit/monitors` runs here (RFC 0073.1): without it, check jobs are refused.
    #[must_use]
    pub fn with_monitors(mut self, on: bool) -> Self {
        self.monitors_off = !on;
        self
    }

    /// The host sampler `hwmon` checks are judged on.
    #[must_use]
    pub fn with_host(mut self, host: Option<crate::host::sampler::Shared>) -> Self {
        self.host = host;
        self
    }

    /// Fills a job's request from the declared check it names, or refuses it: a job never
    /// carries what a transport sends, and a job whose surface or target differ from the
    /// entry it names is refused.
    fn declared(&self, spec: &mut CheckSpec) -> Result<(), String> {
        let Some(key) = spec.key.clone() else {
            if spec.surface.needs_declared() {
                return Err(format!(
                    "a {} check runs only as a declared check: its request is in checks.toml",
                    spec.surface.as_str()
                ));
            }
            return Ok(());
        };
        let entry = self
            .checks
            .as_ref()
            .and_then(|c| c.entries.iter().find(|e| e.key == key))
            .ok_or_else(|| format!("no declared check named {key:?} in checks.toml"))?;
        let same_target = match (&entry.spec.target, &spec.target) {
            (Target::Url { url: a }, Target::Url { url: b }) => a == b,
            (Target::Sensor { sensor: a }, Target::Sensor { sensor: b }) => a == b,
            (
                Target::HostPort {
                    host: a, port: p, ..
                },
                Target::HostPort {
                    host: b, port: q, ..
                },
            ) => a == b && p == q,
            _ => false,
        };
        if entry.spec.surface != spec.surface || !same_target {
            return Err(format!(
                "the job does not match the declared check {key:?}: its surface or target differ from checks.toml"
            ));
        }
        spec.params.clone_from(&entry.spec.params);
        spec.auth.clone_from(&entry.spec.auth);
        spec.target.clone_from(&entry.spec.target);
        Ok(())
    }

    /// Capabilities to announce: what this version can do and the policy allows.
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        checks::Surface::ALL
            .iter()
            .filter(|s| self.policy.surface_allowed(**s))
            .map(|s| format!("check:{}", s.as_str()))
            .collect()
    }

    /// Decides whether a job may run. Nothing is resolved or connected here.
    pub fn admit(&self, job: &Job) -> Admission {
        match job.kind.as_str() {
            "check" => {}
            "load" if !self.policy.work.load => {
                return Admission::Refuse(
                    "load is not enabled by the local policy ([work] load = false)".into(),
                );
            }
            "fault" | "faults" if !self.policy.work.faults => {
                return Admission::Refuse(
                    "faults are not enabled by the local policy ([work] faults = false)".into(),
                );
            }
            "load" | "fault" | "faults" => {
                return Admission::Refuse(format!(
                    "this agent version ({}) cannot run {} jobs yet",
                    env!("CARGO_PKG_VERSION"),
                    job.kind
                ));
            }
            other => return Admission::Refuse(format!("unknown kind of work {other:?}")),
        }
        if self.monitors_off {
            return Admission::Refuse(
                "the inorbit/monitors extension is not installed on this agent (its Extensions page)".into(),
            );
        }
        if !self.policy.work.checks {
            return Admission::Refuse(
                "checks are not enabled by the local policy ([work] checks = false)".into(),
            );
        }
        let filled = match self.fill_target(job) {
            Ok(s) => s,
            Err(reason) => return Admission::Refuse(reason),
        };
        let mut spec: CheckSpec = match serde_json::from_value(filled) {
            Ok(s) => s,
            Err(e) => {
                return Admission::Refuse(format!(
                    "the job's spec is not a check this agent understands: {e}"
                ));
            }
        };
        if !self.policy.surface_allowed(spec.surface) {
            return Admission::Refuse(format!(
                "the {} surface is not enabled by the local policy ([work] surfaces)",
                spec.surface.as_str()
            ));
        }
        if let Err(reason) = self.declared(&mut spec) {
            return Admission::Refuse(reason);
        }
        let endpoint = match spec.endpoint() {
            Ok(e) => e,
            Err(e) => return Admission::Refuse(format!("invalid target: {e}")),
        };
        let secret = match &spec.auth {
            None => None,
            Some(auth) => {
                if !spec.surface.takes_auth() {
                    return Admission::Refuse("auth is not used by tcp and tls checks".into());
                }
                if !self.policy.secret_allowed(&auth.secret) {
                    return Admission::Refuse(format!(
                        "the secret reference {} is not in the local policy's [secrets] allow",
                        auth.secret
                    ));
                }
                match auth.secret.parse::<SecretRef>() {
                    Ok(r) => Some(r),
                    Err(e) => return Admission::Refuse(e.to_string()),
                }
            }
        };
        if let Err(reason) = self.take_rate_slot() {
            return Admission::Refuse(reason);
        }
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Admission::Refuse(format!(
                "ceiling: {} jobs are already running ([ceilings] max_concurrent_jobs)",
                self.policy.ceilings.max_concurrent_jobs
            ));
        };
        let ceiling = self.policy.ceilings.max_job_ms;
        let deadline =
            Duration::from_millis(job.deadline_ms.map_or(ceiling, |d| d.min(ceiling)).max(1));
        Admission::Run(Box::new(Admitted {
            spec,
            endpoint,
            secret,
            deadline,
            _permit: permit,
        }))
    }

    fn take_rate_slot(&self) -> Result<(), String> {
        let mut w = match self.window.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        while w
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            w.pop_front();
        }
        let max = self.policy.ceilings.max_jobs_per_minute as usize;
        if w.len() >= max {
            return Err(format!(
                "ceiling: {max} jobs in the last minute ([ceilings] max_jobs_per_minute)"
            ));
        }
        w.push_back(now);
        Ok(())
    }

    /// The result for a refused job.
    #[must_use]
    pub fn refused(job: &Job, reason: String) -> Finished {
        let surface = job
            .spec
            .get("surface")
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        let at = now_rfc3339();
        tracing::info!(job_id = %job.job_id, kind = %job.kind, reason = %reason, "job refused by local policy");
        let key = job
            .spec
            .get("key")
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        Finished {
            result: JobResult {
                job_id: job.job_id.clone(),
                status: ResultStatus::Refused,
                started_at: at.clone(),
                finished_at: at.clone(),
                detail: CheckDetail {
                    error_class: Some(ErrorClass::RefusedByPolicy),
                    ..CheckDetail::default()
                },
                refusal: Some(Refusal {
                    reason: reason.clone(),
                }),
            },
            record: JobRecord {
                at,
                kind: job.kind.clone(),
                surface,
                target_host: None,
                verdict: "refused".into(),
                latency_ms: 0,
                job_id: Some(job.job_id.clone()),
                key,
                reason: Some(reason),
                error_class: Some("refused_by_policy".into()),
                status_code: None,
                tls_expires_at: None,
            },
        }
    }

    /// Runs an admitted job to its end or its deadline.
    pub async fn execute(&self, job_id: String, a: Admitted) -> Finished {
        let span = tracing::info_span!("job", job_id = %job_id, kind = "check", surface = a.spec.surface.as_str(), target.host = %a.endpoint.host);
        self.execute_inner(job_id, a).instrument(span).await
    }

    async fn execute_inner(&self, job_id: String, a: Admitted) -> Finished {
        let started_at = now_rfc3339();
        let started = Instant::now();
        let outcome = tokio::time::timeout(a.deadline, self.run(&a, started)).await;
        let (status, detail, refusal) = match outcome {
            Err(_) => (
                ResultStatus::Failed,
                CheckDetail::failed(ErrorClass::Timeout, started),
                None,
            ),
            Ok(Err(reason)) => (
                ResultStatus::Refused,
                CheckDetail {
                    latency_ms: 0,
                    error_class: Some(ErrorClass::RefusedByPolicy),
                    ..CheckDetail::default()
                },
                Some(Refusal { reason }),
            ),
            Ok(Ok(d)) if d.ok => (ResultStatus::Ok, d, None),
            Ok(Ok(d)) => (ResultStatus::Failed, d, None),
        };
        let surface = a.spec.surface.as_str();
        self.jobs.add(
            1,
            &[
                KeyValue::new("kind", "check"),
                KeyValue::new("surface", surface),
                KeyValue::new("verdict", status.as_str()),
            ],
        );
        #[allow(clippy::cast_precision_loss)]
        self.duration.record(
            detail.latency_ms as f64,
            &[KeyValue::new("surface", surface)],
        );
        if let Some(r) = &refusal {
            tracing::info!(reason = %r.reason, "job refused by local policy");
        } else {
            tracing::info!(verdict = status.as_str(), latency_ms = detail.latency_ms, error_class = ?detail.error_class, "job finished");
        }
        let finished_at = now_rfc3339();
        let error_class = detail.error_class.and_then(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        });
        Finished {
            record: JobRecord {
                at: finished_at.clone(),
                kind: "check".into(),
                surface: Some(surface.into()),
                target_host: Some(a.endpoint.host.clone()),
                verdict: status.as_str().into(),
                latency_ms: detail.latency_ms,
                job_id: Some(job_id.clone()),
                key: a.spec.key.clone(),
                reason: refusal.as_ref().map(|r| r.reason.clone()),
                error_class,
                status_code: detail.status_code,
                tls_expires_at: detail.tls_expires_at.clone(),
            },
            result: JobResult {
                job_id,
                status,
                started_at,
                finished_at,
                detail,
                refusal,
            },
        }
    }

    fn run_host(&self, a: &Admitted, started: Instant) -> Result<CheckDetail, String> {
        use crate::host::check::{Level, NoReading, judge};
        let spec = a
            .spec
            .params
            .hwmon
            .as_ref()
            .ok_or("an hwmon check runs only as a declared check")?;
        let shared = self
            .host
            .as_ref()
            .ok_or("host observation is not enabled by the local policy ([work] host)")?;
        let key = a.spec.key.clone().unwrap_or_default();
        let g = match shared.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut runs = match self.host_runs.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        let since = runs.get(&key).copied();
        let detail = match judge(&g, g.chips(), spec, since) {
            Ok(r) => {
                let level = r.level;
                CheckDetail {
                    ok: level != Level::Crit,
                    latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                    error_class: (level == Level::Crit).then_some(ErrorClass::Threshold),
                    reading: Some(r),
                    ..CheckDetail::default()
                }
            }
            Err(NoReading::Missing(_) | NoReading::NotSampled) => {
                CheckDetail::failed(ErrorClass::Sensor, started)
            }
        };
        if let Some(now) = g.now_ms() {
            runs.insert(key, now);
        }
        Ok(detail)
    }

    async fn run(&self, a: &Admitted, started: Instant) -> Result<CheckDetail, String> {
        if a.spec.surface.is_host() {
            return self.run_host(a, started);
        }
        let addr = match self
            .policy
            .resolve_target(
                &a.endpoint.host,
                a.endpoint.port,
                DNS_TIMEOUT.min(a.deadline),
            )
            .await
        {
            Ok(addr) => addr,
            Err(TargetError::Refused(reason)) => return Err(reason),
            Err(TargetError::Dns(_)) => return Ok(CheckDetail::failed(ErrorClass::Dns, started)),
        };
        let auth = match (&a.secret, &a.spec.auth) {
            (Some(r), Some(spec)) => {
                let value = self
                    .secrets
                    .resolve(r)
                    .await
                    .map_err(|e| format!("could not read the secret on the agent: {e}"))?;
                let header = spec
                    .header
                    .clone()
                    .unwrap_or_else(|| "authorization".into());
                let value = match &spec.scheme {
                    Some(s) => zeroize::Zeroizing::new(format!("{s} {}", value.as_str())),
                    None => value,
                };
                Some((header, value))
            }
            _ => None,
        };
        let remaining = a.deadline.saturating_sub(started.elapsed());
        checks::run(
            &self.tls,
            Prepared {
                spec: &a.spec,
                endpoint: &a.endpoint,
                addr,
                auth,
                timeout: remaining,
            },
        )
        .await
    }
}
