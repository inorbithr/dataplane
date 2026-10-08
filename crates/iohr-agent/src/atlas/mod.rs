//! `atlas observe`: the first Atlas observers. They produce evidence only (observations,
//! artefacts, a manifest), never a claim or a proof; Atlas core decides what the
//! evidence proves (ADR 0005 and ADR 0023 in inorbithr/core). Read-only: a checkout on
//! disk and, through the local policy, the Kubernetes API of one context. Output is one
//! JSON record per line ([`record::Record`]), every record built through
//! `iohr_evidence`'s validating constructors. `atlas docs sync` reads a company's
//! documentation sources the same way ([`docs`]).

pub mod common;
pub mod docs;
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
}

/// Runs the observers and returns the records with a summary. A cluster is read only
/// with a policy, and only when the policy admits the API server.
///
/// # Errors
/// Nothing to observe, a cluster asked for without a policy, the policy's refusal, or
/// any read or record failure.
pub async fn observe(req: &ObserveRequest, policy: Option<&Policy>) -> Result<(Sink, Summary)> {
    if req.repo.is_none() && req.kubeconfig.is_none() {
        return Err(Error::Atlas(
            "nothing to observe: pass --repo and/or --kubeconfig".into(),
        ));
    }
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
    }));

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
