//! Wires configuration, policy, identity and the session together for `run`.

use std::sync::Arc;

use tokio::sync::watch;

use crate::checks_file::DeclaredChecks;
use crate::config::AgentConfig;
use crate::enroll::Enrollment;
use crate::error::{Error, Result};
use crate::executor::Executor;
use crate::keys::AgentKey;
use crate::policy::Policy;
use crate::secrets::SecretResolver;
use crate::state::{AgentInfo, AgentState, PolicyInfo, how_to_stop};
use crate::tls::TlsContext;
use crate::token::TokenSource;

/// How often the admin page's Traffic section is refreshed.
const CAPTURE_REFRESH: std::time::Duration = std::time::Duration::from_secs(15);

/// Keeps the admin page's Traffic section current (counts only).
async fn watch_capture(
    policy: crate::policy::CapturePolicy,
    state: Arc<AgentState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(CAPTURE_REFRESH);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tick.tick() => {
                let info = crate::capture::check(&policy, crate::capture::HELLO_TIMEOUT).await;
                state.capture_checked(info);
            }
        }
    }
}

/// How often the page's host reading is refreshed.
const HOST_REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Reads the host for the page's Host section (what `atlas observe host --report` prints,
/// and its findings). Local only: none of it is sent.
async fn report_host(
    sampler: crate::host::sampler::Shared,
    policy: crate::policy::HostPolicy,
    state: Arc<AgentState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(HOST_REPORT_EVERY);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tick.tick() => {
                let sampler = Arc::clone(&sampler);
                let journal = policy.journal;
                let read = tokio::task::spawn_blocking(move || {
                    let snap = crate::host::snapshot(&crate::host::Options {
                        root: crate::host::sysfs::Root::host(),
                        journal,
                        ids: None,
                    });
                    let g = match sampler.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    let findings = crate::host::derive::derive(
                        &snap,
                        Some(&g),
                        crate::host::derive::DEFAULT_CHIPSET_WARN,
                    );
                    let text = crate::host::report::text(&snap, &findings, Some(&g));
                    crate::state::HostReport {
                        at: crate::enroll::now_rfc3339(),
                        text,
                        findings: findings
                            .into_iter()
                            .map(|f| crate::state::FindingView {
                                check: f.check.to_owned(),
                                subject: f.subject,
                                verdict: f.verdict.as_str().to_owned(),
                                reason: f.reason,
                            })
                            .collect(),
                    }
                })
                .await;
                if let Ok(r) = read {
                    state.host_reported(r);
                }
            }
        }
    }
}

/// A ready-to-run agent.
#[derive(Debug)]
pub struct Agent {
    /// `agent.toml`.
    pub config: AgentConfig,
    /// The local policy.
    pub policy: Arc<Policy>,
    /// Its hash.
    pub policy_hash: String,
    /// The declared checks (`checks.toml`), if the file exists.
    pub checks: Option<DeclaredChecks>,
    /// The enrollment record.
    pub enrollment: Arc<Enrollment>,
    /// Status for the admin page.
    pub state: Arc<AgentState>,
    /// Access tokens.
    pub tokens: TokenSource,
    /// Runs jobs.
    pub executor: Arc<Executor>,
    /// TLS trust.
    pub tls: TlsContext,
    /// The host sampler (`[work] host`), sampled while the agent runs.
    pub host: Option<crate::host::sampler::Shared>,
    /// The egress ledger (`[ledger]`), when kept.
    pub ledger: Option<Arc<crate::ledger::Ledger>>,
    /// Where session frames go (`wss://…/v1/agents/session`), for the ledger.
    pub session_destination: String,
    /// The declared checks as the hello carries them under `[share]`, and their hash.
    pub shared_checks: Option<(Vec<serde_json::Value>, String)>,
}

impl Agent {
    /// Checks that configuration, policy and enrollment agree, and builds the agent.
    ///
    /// # Errors
    /// When they disagree, or TLS cannot be set up.
    #[allow(clippy::too_many_lines)] // one check after another, then the parts
    pub fn new(
        config: AgentConfig,
        policy: Policy,
        checks: Option<DeclaredChecks>,
        enrollment: Enrollment,
        key: AgentKey,
    ) -> Result<Self> {
        if config.environment != policy.environment {
            return Err(Error::Policy(format!(
                "the policy is for environment {:?} but agent.toml says {:?}",
                policy.environment, config.environment
            )));
        }
        if enrollment.environment != policy.environment {
            return Err(Error::Policy(format!(
                "this agent was enrolled for environment {:?} but the policy says {:?}; enroll again for the right environment",
                enrollment.environment, policy.environment
            )));
        }
        if enrollment.api != config.api {
            return Err(Error::Config(format!(
                "this agent was enrolled with {} but agent.toml names {}",
                enrollment.api, config.api
            )));
        }
        for d in &policy.domains.bound {
            let covered = enrollment
                .domains
                .iter()
                .any(|e| d == e || d.ends_with(&format!(".{e}")));
            if !enrollment.domains.is_empty() && !covered {
                tracing::warn!(domain = %d, "the policy binds a domain the enrollment does not; jobs for it will be refused by the platform");
            }
        }
        let tls = TlsContext::new(config.tls.ca_file.as_deref())?;
        let http = tls
            .reqwest_builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Tls(e.to_string()))?;
        let policy = Arc::new(policy);
        let policy_hash = policy.hash();
        let enrollment = Arc::new(enrollment);
        let ledger = if config.ledger.enabled {
            Some(Arc::new(crate::ledger::Ledger::open(
                &crate::ledger::dir_in(&config.state_dir),
                config.ledger.clone(),
                &policy_hash,
            )?))
        } else {
            tracing::warn!(
                "the egress ledger is off ([ledger] enabled = false): what is sent to the platform is not recorded on this machine"
            );
            None
        };
        let session_destination = crate::session::session_url(&config.api)
            .map(|u| u.to_string())
            .unwrap_or_default();
        let tokens = TokenSource::new(http, Arc::clone(&enrollment), Arc::new(key))
            .with_ledger(ledger.clone());
        let secrets = SecretResolver::new(config.secrets.clone(), tls.clone());
        let share = policy.share();
        let share_key = crate::share::key(&config.state_dir)?;
        let shared_checks = checks.as_ref().map(|c| {
            let wire: Vec<serde_json::Value> = c
                .entries
                .iter()
                .map(|e| crate::share::wire(e, share.targets, &share_key))
                .collect();
            let hash = crate::ledger::sha256_hex(
                crate::checks_file::canonical_json(&serde_json::Value::Array(wire.clone()))
                    .as_bytes(),
            );
            (wire, hash)
        });
        let host = policy.host().map(|h| {
            Arc::new(std::sync::Mutex::new(crate::host::sampler::Sampler::new(
                crate::host::sysfs::Root::host(),
                std::time::Duration::from_secs(h.window_secs),
            )))
        });
        let executor = Arc::new(
            Executor::new(Arc::clone(&policy), tls.clone(), secrets)
                .with_checks(checks.clone().map(Arc::new))
                .with_host(host.clone())
                .with_share(share.targets, share_key),
        );
        let state = Arc::new(AgentState::new(
            AgentInfo {
                version: env!("CARGO_PKG_VERSION").into(),
                agent_id: Some(enrollment.agent_id.clone()),
                name: config.name.clone(),
                environment: config.environment.clone(),
                pid: std::process::id(),
            },
            PolicyInfo {
                hash: policy_hash.clone(),
                path: config.policy.display().to_string(),
                domains: policy.domains.bound.clone(),
                capabilities: executor.capabilities(),
                checks_path: config.checks.display().to_string(),
                checks_hash: shared_checks.as_ref().map(|(_, h)| h.clone()),
                checks: checks.as_ref().map_or(0, |c| c.entries.len()),
            },
            how_to_stop(),
        ));
        state.set_api(config.api.as_str());
        Ok(Self {
            config,
            policy,
            policy_hash,
            checks,
            enrollment,
            state,
            tokens,
            executor,
            tls,
            host,
            ledger,
            session_destination,
            shared_checks,
        })
    }

    /// Records a message in the egress ledger before it is sent.
    ///
    /// # Errors
    /// When the ledger is kept and cannot record it: the message must not be sent.
    pub fn ledger_record(&self, r: crate::ledger::Record<'_>) -> Result<()> {
        if let Some(l) = &self.ledger {
            l.record(r)?;
        }
        Ok(())
    }

    /// What the admin page reads.
    #[must_use]
    pub fn admin_context(&self, token: Option<String>) -> crate::admin::Context {
        crate::admin::Context {
            state: Arc::clone(&self.state),
            policy: Arc::clone(&self.policy),
            checks: self.checks.clone().map(Arc::new),
            ledger: self.ledger.clone(),
            ledger_config: self.config.ledger.clone(),
            api: self.config.api.to_string(),
            admin: self.config.admin.clone(),
            state_dir: self.config.state_dir.display().to_string(),
            token,
        }
    }

    /// Serves the admin page (if enabled) and runs sessions until shutdown or revocation.
    ///
    /// # Errors
    /// When the admin address cannot be bound, or the agent is revoked.
    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> Result<()> {
        if self.config.admin.enabled {
            let admin = &self.config.admin;
            let tls = crate::admin::server_tls(admin)?;
            let token = crate::admin::write_token(&self.config.state_dir)?;
            let listener = tokio::net::TcpListener::bind(admin.listen)
                .await
                .map_err(|e| Error::Config(format!("admin.listen {}: {e}", admin.listen)))?;
            if let Ok(addr) = listener.local_addr() {
                let scheme = if tls.is_some() { "https" } else { "http" };
                tracing::info!(%addr, "admin page at {scheme}://{addr}/");
                if !addr.ip().is_loopback() {
                    let warning = format!(
                        "WARNING: the admin page listens on {addr}, beyond this machine (admin.allow_non_loopback). It is served over TLS and asks for its token, but anyone who can reach {addr} can try. Prefer 127.0.0.1 and an SSH tunnel."
                    );
                    tracing::warn!("{warning}");
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("\n{}\n{warning}\n{}\n", "!".repeat(78), "!".repeat(78));
                    }
                }
            }
            tokio::spawn(crate::admin::serve(
                listener,
                Arc::new(self.admin_context(Some(token))),
                tls,
                shutdown.clone(),
            ));
        }
        if let Some(policy) = self.policy.capture() {
            tokio::spawn(watch_capture(
                policy,
                Arc::clone(&self.state),
                shutdown.clone(),
            ));
        }
        if let (Some(h), Some(p)) = (&self.host, self.policy.host()) {
            let state = Arc::clone(&self.state);
            tokio::spawn(crate::host::sampler::run(
                Arc::clone(h),
                std::time::Duration::from_secs(p.sample_secs),
                shutdown.clone(),
                move |s| {
                    let chipset = crate::host::derive::chipset_sensor(s.chips())
                        .and_then(|(c, x)| s.latest(&c.key(x)));
                    state.host_sampled(crate::state::HostInfo {
                        sensors: s.sensor_count(),
                        samples: s.samples().len(),
                        last_sample_at: crate::enroll::now_rfc3339(),
                        last_cost_us: u64::try_from(s.last_cost.as_micros()).unwrap_or(u64::MAX),
                        max_cost_us: u64::try_from(s.max_cost.as_micros()).unwrap_or(u64::MAX),
                        chipset_millicelsius: chipset,
                    });
                },
            ));
        }
        if let (Some(h), Some(p)) = (&self.host, self.policy.host()) {
            tokio::spawn(report_host(
                Arc::clone(h),
                p,
                Arc::clone(&self.state),
                shutdown.clone(),
            ));
        }
        crate::session::run(self, shutdown).await
    }
}
