//! `atlas docs sync`: every configured source (or the ones asked for), one after another.
//! Each credential is checked against the policy's `[secrets] allow`, read from its store
//! at the moment of the run and dropped after it; each provider's host must pass the
//! policy's `[networks]`. One source failing does not stop the others.

use iohr_evidence::time::Timestamp;

use super::Provider;
use super::config::{DEFAULT_MAX_ITEMS, DocsSourceConfig};
use super::http::Limits;
use super::notion::{self, Notion};
use super::sync::{SyncOptions, SyncSummary, sync_source};
use crate::atlas::common::ObservedNow;
use crate::atlas::record::{DocsSourceRef, Record, RunRecord, Sink};
use crate::config::AgentConfig;
use crate::error::{Error, Result};
use crate::policy::Policy;
use crate::secrets::{SecretRef, SecretResolver};
use crate::tls::TlsContext;

/// What one source's run came to.
#[derive(Debug)]
pub struct SourceOutcome {
    /// The source's id.
    pub id: String,
    /// Its counts, when it ran.
    pub summary: Option<SyncSummary>,
    /// Why it did not run, or stopped.
    pub error: Option<String>,
    /// Requests sent and retried, and answers that were 429.
    pub requests: (u64, u64, u64),
}

/// Runs `atlas docs sync` over the configured sources (all of them when `only` is empty).
///
/// # Errors
/// `only` names a source that is not configured, or nothing is configured.
pub async fn sync_configured(
    cfg: &AgentConfig,
    policy: &Policy,
    only: &[String],
    full: bool,
) -> Result<(Sink, Vec<SourceOutcome>)> {
    if cfg.docs.sources.is_empty() {
        return Err(Error::Config(
            "no [[docs.sources]] in agent.toml (docs/docs-connectors.md)".into(),
        ));
    }
    for name in only {
        if !cfg.docs.sources.iter().any(|s| &s.id == name) {
            return Err(Error::Config(format!(
                "no docs source {name:?} in agent.toml"
            )));
        }
    }
    let chosen: Vec<&DocsSourceConfig> = cfg
        .docs
        .sources
        .iter()
        .filter(|s| only.is_empty() || only.contains(&s.id))
        .collect();
    let tls = TlsContext::new(cfg.tls.ca_file.as_deref())?;
    let resolver = SecretResolver::new(cfg.secrets.clone(), tls.clone());
    let content = cfg.docs.content_dir(&cfg.state_dir);
    let clock = ObservedNow::now();
    let started = chrono::Utc::now();

    let mut sink = Sink::default();
    let mut refs = Vec::new();
    let mut outcomes = Vec::new();
    for s in chosen {
        let mut outcome = SourceOutcome {
            id: s.id.clone(),
            summary: None,
            error: None,
            requests: (0, 0, 0),
        };
        match run_one(
            s, policy, &tls, &resolver, &content, started, full, &mut sink, &clock,
        )
        .await
        {
            Ok((summary, counts)) => {
                refs.push(DocsSourceRef {
                    id: s.id.clone(),
                    provider: s.provider.to_string(),
                    workspace: summary.workspace.clone(),
                });
                outcome.summary = Some(summary);
                outcome.requests = counts;
            }
            Err(e) => {
                tracing::warn!(source = %s.id, error = %e, "docs: source not read");
                outcome.error = Some(e.to_string());
            }
        }
        outcomes.push(outcome);
    }
    sink.prepend(Record::Run(RunRecord {
        started_at: started,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        repository: None,
        cluster: None,
        docs: refs,
    }));
    Ok((sink, outcomes))
}

#[allow(clippy::too_many_arguments)] // one source's whole context, passed once
async fn run_one(
    s: &DocsSourceConfig,
    policy: &Policy,
    tls: &TlsContext,
    resolver: &SecretResolver,
    content: &std::path::Path,
    started: Timestamp,
    full: bool,
    sink: &mut Sink,
    clock: &ObservedNow,
) -> Result<(SyncSummary, (u64, u64, u64))> {
    let reference = s
        .token
        .as_deref()
        .ok_or_else(|| Error::Config(format!("docs source {}: no token reference", s.id)))?;
    if !policy.secret_allowed(reference) {
        return Err(Error::Policy(format!(
            "docs source {}: the policy's [secrets] allow does not list {reference}",
            s.id
        )));
    }
    let r: SecretRef = reference.parse()?;
    let token = resolver.resolve(&r).await?;
    let opts = SyncOptions {
        source_id: s.id.clone(),
        full,
        max_items: usize::try_from(s.max_items.unwrap_or(DEFAULT_MAX_ITEMS)).unwrap_or(usize::MAX),
        store: content.join(&s.id),
        now: started,
    };
    match s.provider {
        Provider::Notion => {
            let limits = Limits::for_rate(s.requests_per_minute.unwrap_or(notion::RATE_PER_MINUTE));
            let src = Notion::connect(s.base_url.clone(), &token, policy, tls, limits, s.comments)
                .await
                .map_err(|e| Error::Atlas(format!("docs source {}: {e}", s.id)))?;
            drop(token);
            let summary = sync_source(&src, &opts, sink, clock).await?;
            let st = src.client().stats();
            Ok((summary, (st.requests(), st.retries(), st.rate_limited())))
        }
    }
}
