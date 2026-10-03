//! Admits or refuses each job against the local policy, then runs it inside its ceiling.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::Instrument as _;

use crate::checks::{self, CheckDetail, CheckSpec, Endpoint, ErrorClass, Prepared};
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
        if !self.policy.work.checks {
            return Admission::Refuse(
                "checks are not enabled by the local policy ([work] checks = false)".into(),
            );
        }
        let spec: CheckSpec = match serde_json::from_value(job.spec.clone()) {
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
        let endpoint = match spec.endpoint() {
            Ok(e) => e,
            Err(e) => return Admission::Refuse(format!("invalid target: {e}")),
        };
        let secret = match &spec.auth {
            None => None,
            Some(auth) => {
                if !matches!(
                    spec.surface,
                    checks::Surface::Http | checks::Surface::GrpcHealth
                ) {
                    return Admission::Refuse(
                        "auth is only used by http and grpc_health checks".into(),
                    );
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
                refusal: Some(Refusal { reason }),
            },
            record: JobRecord {
                at,
                kind: job.kind.clone(),
                surface,
                target_host: None,
                verdict: "refused".into(),
                latency_ms: 0,
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
        Finished {
            record: JobRecord {
                at: finished_at.clone(),
                kind: "check".into(),
                surface: Some(surface.into()),
                target_host: Some(a.endpoint.host.clone()),
                verdict: status.as_str().into(),
                latency_ms: detail.latency_ms,
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

    async fn run(&self, a: &Admitted, started: Instant) -> Result<CheckDetail, String> {
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
        Ok(checks::run(
            &self.tls,
            Prepared {
                spec: &a.spec,
                endpoint: &a.endpoint,
                addr,
                auth,
                timeout: remaining,
            },
        )
        .await)
    }
}
