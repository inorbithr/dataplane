//! `atlas observe`: the first Atlas observers. They produce evidence only (observations,
//! artefacts, a manifest), never a claim or a proof; Atlas core decides what the
//! evidence proves (ADR 0005 and ADR 0023 in inorbithr/core). Read-only: a checkout on
//! disk and, through the local policy, the Kubernetes API of one context. Output is one
//! JSON record per line ([`record::Record`]), every record built through
//! `iohr_evidence`'s validating constructors. `atlas docs sync` reads a company's
//! documentation sources the same way ([`docs`]).

pub mod common;
pub mod decided;
pub mod docs;
pub mod host;
pub mod k8s;
pub mod kube;
pub mod record;
pub mod repo;
pub mod snapshot;

use std::collections::BTreeMap;
use std::path::PathBuf;

use iohr_evidence::method::MethodCategory;
use iohr_evidence::observer::ObserverClass;

use crate::error::{Error, Result};
use crate::policy::Policy;
use common::{Ctx, ObservedNow, method};
use record::{ClusterRef, Record, RepositoryRef, RunRecord, Sink};

/// What to observe.
#[derive(Debug, Clone, Default)]
pub struct ObserveRequest {
    /// A checkout to read.
    pub repo: Option<PathBuf>,
    /// A kubeconfig to read a cluster through.
    pub kubeconfig: Option<PathBuf>,
    /// The context in it (default: its current context).
    pub kube_context: Option<String>,
    /// The namespaces to read (default: the context's, else `default`).
    pub namespaces: Vec<String>,
    /// Read this host (needs a policy with `[work] host = true`).
    pub host: Option<HostRequest>,
}

/// How to read the host.
#[derive(Debug, Clone)]
pub struct HostRequest {
    /// A captured tree instead of `/` (tests, replays).
    pub root: Option<PathBuf>,
    /// `pci.ids` to name devices with (default: the host's).
    pub pci_ids: Option<PathBuf>,
    /// Samples to take (1: one reading; more: rates, peaks, correlations).
    pub samples: u32,
    /// Between samples.
    pub interval: std::time::Duration,
    /// The chipset threshold for the derived findings, milli-degrees.
    pub chipset_warn: i64,
}

/// What a run found: counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Records written.
    pub records: usize,
    /// Distinct entities named.
    pub entities: usize,
    /// Evidence items per method.
    pub per_method: BTreeMap<String, usize>,
    /// What the checkout held.
    pub repository: Option<repo::Found>,
    /// Components in the manifest, and how many are known at a revision.
    pub components: Option<(usize, usize)>,
    /// A human report of the host reading.
    pub host_report: Option<String>,
}

/// Runs the observers and returns the records with a summary. A cluster is read only
/// with a policy, and only when the policy admits the API server.
///
/// # Errors
/// Nothing to observe, a cluster asked for without a policy, the policy's refusal, or
/// any read or record failure.
#[allow(clippy::too_many_lines)] // repository, host, cluster, in order
pub async fn observe(req: &ObserveRequest, policy: Option<&Policy>) -> Result<(Sink, Summary)> {
    if req.repo.is_none() && req.kubeconfig.is_none() && req.host.is_none() {
        return Err(Error::Atlas(
            "nothing to observe: pass host, --repo and/or --kubeconfig".into(),
        ));
    }
    let host_policy = match &req.host {
        None => None,
        Some(_) => Some(
            policy
                .ok_or_else(|| {
                    Error::Policy(
                        "reading the host needs a policy: pass --policy or name one in agent.toml"
                            .into(),
                    )
                })?
                .host()
                .ok_or_else(|| {
                    Error::Policy(
                        "the policy does not allow host observation ([work] host = true)".into(),
                    )
                })?,
        ),
    };
    let clock = ObservedNow::now();
    let mut sink = Sink::default();
    let mut summary = Summary::default();

    let repository = match &req.repo {
        Some(path) => Some(repo::Repo::open(path)?),
        None => None,
    };
    let context = match &req.kubeconfig {
        Some(path) => Some(kube::KubeContext::load(path, req.kube_context.as_deref())?),
        None => None,
    };
    let namespaces: Vec<String> = if req.namespaces.is_empty() {
        vec![
            context
                .as_ref()
                .and_then(|c| c.namespace.clone())
                .unwrap_or_else(|| "default".to_owned()),
        ]
    } else {
        req.namespaces.clone()
    };
    sink.push(Record::Run(RunRecord {
        started_at: chrono::Utc::now(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        repository: repository.as_ref().map(|r| RepositoryRef {
            name: r.name.clone(),
            commit: r.commit.clone(),
        }),
        cluster: context.as_ref().map(|c| ClusterRef {
            context: c.name.clone(),
            namespaces: namespaces.clone(),
        }),
        docs: Vec::new(),
        host: None,
    }));

    if let (Some(h), Some(hp)) = (&req.host, &host_policy) {
        let (snap, window) = read_host(h, hp).await?;
        if let Some(Record::Run(run)) = sink.records().first().cloned() {
            let mut run = run;
            run.host = Some(record::HostRef {
                name: snap.host.clone(),
                boot_id: snap.boot.boot_id.clone(),
                kernel: snap.kernel.clone(),
                samples: h.samples,
                interval_secs: h.interval.as_secs(),
            });
            sink.replace_first(Record::Run(run));
        }
        let findings = host::observe(&snap, window.as_ref(), h.chipset_warn, &mut sink, &clock)?;
        summary.host_report = Some(crate::host::report::text(&snap, &findings, window.as_ref()));
    }

    if let Some(r) = &repository {
        summary.repository = Some(repo::observe(r, &mut sink, &clock)?);
    }

    if let Some(c) = &context {
        let policy = policy.ok_or_else(|| {
            Error::Policy(
                "reading a cluster needs a policy: pass --policy or name one in agent.toml".into(),
            )
        })?;
        let client = c.client(policy).await?;
        let ctx = Ctx::new(
            &mut sink,
            "k8s-reader",
            ObserverClass::ExternalSystem,
            method(kube::METHOD, MethodCategory::RuntimeState)?,
            &c.user,
            &["list"],
            &clock,
        )?;
        let mut facts = BTreeMap::new();
        for ns in &namespaces {
            let state = kube::read_namespace(&client, ns).await?;
            facts.extend(kube::observe(&ctx, &state, &mut sink)?);
        }
        let manifest = snapshot::build(&facts, ctx.observer.id, chrono::Utc::now())?;
        let known = manifest
            .snapshot()
            .components()
            .filter(|(_, s)| matches!(s, iohr_evidence::snapshot::ComponentState::Known { .. }))
            .count();
        summary.components = Some((facts.len(), known));
        sink.push(Record::Manifest(manifest));
    }

    summary.records = sink.records().len();
    summary.entities = sink
        .records()
        .iter()
        .filter(|r| matches!(r, Record::Entity { .. }))
        .count();
    summary.per_method = sink.per_method();
    Ok((sink, summary))
}

async fn read_host(
    h: &HostRequest,
    hp: &crate::policy::HostPolicy,
) -> Result<(crate::host::Snapshot, Option<crate::host::sampler::Sampler>)> {
    use crate::host::{Options, sampler::Sampler, snapshot, sysfs::Root};
    let root = h.root.as_deref().map_or_else(Root::host, Root::at);
    let ids = match &h.pci_ids {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| Error::io(p, e))?),
        None => None,
    };
    let samples = h.samples.max(1);
    let window = if samples > 1 {
        let span = h.interval * (samples + 1);
        let mut w = Sampler::new(root.clone(), span);
        for i in 0..samples {
            if i > 0 {
                tokio::time::sleep(h.interval).await;
            }
            w.tick();
        }
        Some(w)
    } else {
        None
    };
    let snap = snapshot(&Options {
        root,
        journal: hp.journal,
        ids,
    });
    Ok((snap, window))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nothing_to_observe_is_an_error() {
        let e = observe(&ObserveRequest::default(), None).await.unwrap_err();
        assert!(e.to_string().contains("nothing to observe"), "{e}");
    }

    #[tokio::test]
    async fn a_cluster_is_never_read_without_a_policy() {
        let dir = tempfile::tempdir().unwrap();
        let kc = dir.path().join("kubeconfig");
        std::fs::write(
            &kc,
            "clusters: [{name: c, cluster: {server: http://127.0.0.1:1}}]\nusers: [{name: u, user: {token: t}}]\ncontexts: [{name: x, context: {cluster: c, user: u}}]\ncurrent-context: x\n",
        )
        .unwrap();
        let req = ObserveRequest {
            kubeconfig: Some(kc),
            ..ObserveRequest::default()
        };
        let e = observe(&req, None).await.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
    }
}
