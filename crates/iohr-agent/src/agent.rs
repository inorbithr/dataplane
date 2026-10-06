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
}

impl Agent {
    /// Checks that configuration, policy and enrollment agree, and builds the agent.
    ///
    /// # Errors
    /// When they disagree, or TLS cannot be set up.
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
        let tokens = TokenSource::new(http, Arc::clone(&enrollment), Arc::new(key));
        let secrets = SecretResolver::new(config.secrets.clone(), tls.clone());
        let executor = Arc::new(
            Executor::new(Arc::clone(&policy), tls.clone(), secrets)
                .with_checks(checks.clone().map(Arc::new)),
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
                checks_hash: checks.as_ref().map(|c| c.hash.clone()),
                checks: checks.as_ref().map_or(0, |c| c.entries.len()),
            },
            how_to_stop(),
        ));
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
        })
    }

    /// Serves the admin page (if enabled) and runs sessions until shutdown or revocation.
    ///
    /// # Errors
    /// When the admin address cannot be bound, or the agent is revoked.
    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) -> Result<()> {
        if self.config.admin.enabled {
            let listener = tokio::net::TcpListener::bind(self.config.admin.listen)
                .await
                .map_err(|e| {
                    Error::Config(format!("admin.listen {}: {e}", self.config.admin.listen))
                })?;
            if let Ok(addr) = listener.local_addr() {
                tracing::info!(%addr, "admin page at http://{addr}/");
            }
            tokio::spawn(crate::admin::serve(
                listener,
                Arc::clone(&self.state),
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
        crate::session::run(self, shutdown).await
    }
}
