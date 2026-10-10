//! The safe reader: the only way the extension talks to a cluster. Each request passes
//! the policy, the rate cap and the path guard, is written to the query ledger, and only
//! then is sent; its outcome goes to the audit. A refusal by the cluster's RBAC is an
//! answer, not an error.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use super::KubernetesPolicy;
use super::audit::{Audit, Line, Outcome};
use super::facts::{self, Event, Pod, Revision, Workload};
use super::kinds::{self, Kind};
use crate::atlas::kube::{KubeClient, Listed};
use crate::error::{Error, Result};
use crate::ledger::{Ledger, Record};

/// The ledger's kind for a query.
pub const LEDGER_KIND: &str = "k8s.read";

/// What one namespace looks like, as typed facts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NamespaceFacts {
    /// The namespace.
    pub namespace: String,
    /// Deployments, statefulsets and daemonsets.
    pub workloads: Vec<Workload>,
    /// Pods.
    pub pods: Vec<Pod>,
    /// Each deployment's revisions, newest first.
    pub rollouts: Vec<Revision>,
    /// Events, newest first.
    pub events: Vec<Event>,
    /// Kinds the cluster's RBAC refused.
    pub denied: Vec<Kind>,
    /// Kinds the policy leaves out.
    pub skipped: Vec<Kind>,
}

/// The evidence one read produced.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// What made it.
    pub method: &'static str,
    /// The extension.
    pub extension: &'static str,
    /// When, RFC 3339.
    pub observed_at: String,
    /// The API server, `host:port`.
    pub server: String,
    /// One entry per namespace.
    pub namespaces: Vec<NamespaceFacts>,
}

/// The reader.
#[derive(Debug)]
pub struct SafeReader {
    client: KubeClient,
    rules: KubernetesPolicy,
    server: String,
    ledger: Option<Ledger>,
    audit: Option<Audit>,
    sent: Mutex<VecDeque<Instant>>,
}

impl SafeReader {
    /// A reader over `client` for the API server `server` under `rules`. Without a ledger
    /// (tests) requests are not recorded before they are sent.
    #[must_use]
    pub fn new(
        client: KubeClient,
        server: String,
        rules: KubernetesPolicy,
        ledger: Option<Ledger>,
        audit: Option<Audit>,
    ) -> Self {
        Self {
            client,
            rules,
            server,
            ledger,
            audit,
            sent: Mutex::new(VecDeque::new()),
        }
    }

    fn note(
        &self,
        kind: Kind,
        namespace: &str,
        path: &str,
        outcome: Outcome,
        items: usize,
        status: Option<u16>,
    ) {
        if let Some(a) = &self.audit {
            let line = Line {
                at: crate::enroll::now_rfc3339(),
                kind: kind.as_str().into(),
                namespace: namespace.into(),
                path: path.into(),
                outcome,
                items,
                status,
            };
            if let Err(e) = a.append(&line) {
                tracing::warn!(error = %e, "kubernetes audit not written");
            }
        }
    }

    fn take_slot(&self) -> bool {
        let mut q = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= self.rules.queries_per_minute as usize {
            return false;
        }
        q.push_back(now);
        true
    }

    /// Lists `kind` in `namespace`: `Ok(None)` when the cluster refused it.
    ///
    /// # Errors
    /// The policy, the rate cap or the guard refused it, the ledger could not record it,
    /// or the request failed.
    pub async fn list(&self, kind: Kind, namespace: &str) -> Result<Option<Vec<Value>>> {
        if !self.rules.allows(kind, namespace) {
            self.note(kind, namespace, "", Outcome::Refused, 0, None);
            return Err(Error::Policy(format!(
                "the policy's [kubernetes] does not allow {} in {namespace:?}",
                kind.as_str()
            )));
        }
        let path = match kinds::list_path(kind, namespace, self.rules.max_items) {
            Ok(p) => p,
            Err(e) => {
                self.note(kind, namespace, "", Outcome::Refused, 0, None);
                return Err(e);
            }
        };
        if !self.take_slot() {
            self.note(kind, namespace, &path, Outcome::Limited, 0, None);
            return Err(Error::Policy(format!(
                "over {} Kubernetes queries a minute ([kubernetes] queries_per_minute)",
                self.rules.queries_per_minute
            )));
        }
        if let Some(l) = &self.ledger {
            let line = format!("GET {path}");
            l.record(Record {
                kind: LEDGER_KIND,
                payload: line.as_bytes(),
                rule: &format!("kubernetes.{}", kind.as_str()),
                destination: &self.server,
                job_id: None,
            })?;
        }
        match self.client.try_list(&path).await {
            Ok(Listed::Items(items)) => {
                self.note(kind, namespace, &path, Outcome::Read, items.len(), None);
                Ok(Some(items))
            }
            Ok(Listed::Refused(code)) => {
                let o = if code == 404 {
                    Outcome::Missing
                } else {
                    Outcome::Denied
                };
                self.note(kind, namespace, &path, o, 0, Some(code));
                Ok(None)
            }
            Err(e) => {
                self.note(kind, namespace, &path, Outcome::Failed, 0, None);
                Err(e)
            }
        }
    }

    /// Reads one namespace: every kind the policy allows, reduced to facts.
    ///
    /// # Errors
    /// As [`Self::list`], for anything but a refusal by the cluster.
    pub async fn namespace(&self, namespace: &str) -> Result<NamespaceFacts> {
        let mut f = NamespaceFacts {
            namespace: namespace.into(),
            ..NamespaceFacts::default()
        };
        if !self.rules.namespaces.iter().any(|n| n == namespace) {
            return Err(Error::Policy(format!(
                "the policy's [kubernetes] does not name the namespace {namespace:?}"
            )));
        }
        let mut deployments = Vec::new();
        for kind in Kind::ALL {
            if !self.rules.kinds.contains(&kind) {
                f.skipped.push(kind);
                continue;
            }
            let Some(items) = self.list(kind, namespace).await? else {
                f.denied.push(kind);
                continue;
            };
            match kind {
                Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets => {
                    if kind == Kind::Deployments {
                        deployments = items
                            .iter()
                            .filter_map(crate::atlas::k8s::name)
                            .map(str::to_owned)
                            .collect();
                    }
                    f.workloads
                        .extend(items.iter().filter_map(|v| facts::workload(kind, v)));
                }
                Kind::ReplicaSets => {
                    for d in &deployments {
                        f.rollouts.extend(facts::rollout(d, &items));
                    }
                }
                Kind::Pods => f.pods = items.iter().filter_map(facts::pod).collect(),
                Kind::Events => f.events = facts::events(&items, self.rules.max_events as usize),
            }
        }
        Ok(f)
    }

    /// Reads every namespace the policy names.
    ///
    /// # Errors
    /// As [`Self::namespace`].
    pub async fn read_all(&self) -> Result<Evidence> {
        let mut namespaces = Vec::new();
        for ns in &self.rules.namespaces {
            namespaces.push(self.namespace(ns).await?);
        }
        Ok(Evidence {
            method: "k8s.ext.read",
            extension: super::ID,
            observed_at: crate::enroll::now_rfc3339(),
            server: self.server.clone(),
            namespaces,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::kube::KubeContext;
    use crate::policy::Policy;
    use axum::Router;
    use axum::http::{StatusCode, Uri};
    use axum::routing::get;
    use std::sync::Arc;

    /// A fake API server: answers deployments and replicasets, refuses pods with 403,
    /// and records every path it was asked for.
    async fn fake(seen: Arc<Mutex<Vec<String>>>) -> url::Url {
        let app = Router::new().fallback(get(move |uri: Uri| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(uri.to_string());
                let p = uri.path();
                let body = if p.ends_with("/deployments") {
                    serde_json::json!({"items": [{"metadata": {"name": "web", "generation": 1},
                        "spec": {"replicas": 1}, "status": {"observedGeneration": 1, "readyReplicas": 1,
                        "updatedReplicas": 1, "availableReplicas": 1}}]})
                } else if p.ends_with("/replicasets") {
                    serde_json::json!({"items": [{"metadata": {"name": "web-1",
                        "annotations": {"deployment.kubernetes.io/revision": "2"},
                        "ownerReferences": [{"kind": "Deployment", "name": "web"}]}}]})
                } else if p.ends_with("/pods") {
                    return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({"kind": "Status"})));
                } else if p.ends_with("/events") {
                    serde_json::json!({"items": [{"type": "Warning", "reason": "BackOff",
                        "involvedObject": {"kind": "Pod", "name": "web-1"},
                        "message": "password=Zx9!kq2Lr8#vT4mW from 10.0.0.7"}]})
                } else {
                    serde_json::json!({"items": []})
                };
                (StatusCode::OK, axum::Json(body))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url::Url::parse(&format!("http://{addr}/")).unwrap()
    }

    fn policy(extra: &str) -> Policy {
        Policy::from_toml(&format!(
            "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1\"]\n[kubernetes]\nnamespaces = [\"shop\"]\n{extra}"
        ))
        .unwrap()
    }

    async fn reader(server: &url::Url, p: &Policy, dir: &std::path::Path) -> SafeReader {
        let ctx = KubeContext::plain_for_tests(server.clone());
        let client = ctx.client(p).await.unwrap();
        let ledger = Ledger::open(
            &dir.join("ledger"),
            crate::ledger::LedgerConfig::default(),
            &p.hash(),
        )
        .unwrap();
        SafeReader::new(
            client,
            server.authority().to_owned(),
            p.kubernetes.clone().unwrap(),
            Some(ledger),
            Some(Audit::open(dir).unwrap()),
        )
    }

    #[tokio::test]
    async fn reads_facts_maps_403_to_denied_and_records_every_query() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let url = fake(seen.clone()).await;
        let p = policy("");
        let d = tempfile::tempdir().unwrap();
        let r = reader(&url, &p, d.path()).await;
        let e = r.read_all().await.unwrap();
        let ns = &e.namespaces[0];
        assert_eq!(ns.workloads.len(), 1);
        assert!(ns.workloads[0].healthy());
        assert_eq!(ns.rollouts[0].revision, 2);
        assert_eq!(ns.denied, [Kind::Pods]);
        assert!(ns.pods.is_empty());
        let msg = &ns.events[0].message;
        assert!(
            !msg.contains("Zx9!kq2Lr8") && !msg.contains("10.0.0.7"),
            "{msg}"
        );
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), Kind::ALL.len());
        for s in &seen {
            assert!(kinds::guard(s.trim_start_matches('/')).is_ok(), "{s}");
            assert!(
                s.contains("/namespaces/shop/") && s.ends_with("?limit=500"),
                "{s}"
            );
        }
        let v = crate::ledger::verify(&d.path().join("ledger"));
        assert!(v.ok() && v.entries == seen.len() as u64, "{v:?}");
        let audit = super::super::audit::recent(d.path(), 50);
        assert_eq!(audit.len(), seen.len());
        assert!(
            audit
                .iter()
                .any(|l| l.outcome == Outcome::Denied && l.status == Some(403))
        );
    }

    #[tokio::test]
    async fn the_policy_and_the_rate_cap_refuse_before_anything_is_sent() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let url = fake(seen.clone()).await;
        let p = policy("kinds = [\"events\"]\nqueries_per_minute = 2\n");
        let d = tempfile::tempdir().unwrap();
        let r = reader(&url, &p, d.path()).await;
        assert!(r.list(Kind::Pods, "shop").await.is_err());
        assert!(r.list(Kind::Events, "kube-system").await.is_err());
        assert!(r.namespace("kube-system").await.is_err());
        assert!(r.list(Kind::Events, "shop").await.unwrap().is_some());
        assert!(r.list(Kind::Events, "shop").await.unwrap().is_some());
        assert!(r.list(Kind::Events, "shop").await.is_err());
        assert_eq!(seen.lock().unwrap().len(), 2);
        let out = super::super::audit::recent(d.path(), 10);
        assert_eq!(out[0].outcome, Outcome::Limited);
        assert_eq!(
            out.iter().filter(|l| l.outcome == Outcome::Refused).count(),
            2
        );
    }

    #[tokio::test]
    async fn a_server_the_network_policy_refuses_is_never_reached() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let url = fake(seen.clone()).await;
        let p = Policy::from_toml(
            "environment = \"staging\"\n[networks]\nallow = [\"10.0.0.0/8\"]\n[kubernetes]\nnamespaces = [\"shop\"]\n",
        )
        .unwrap();
        let ctx = KubeContext::plain_for_tests(url);
        assert!(ctx.client(&p).await.is_err());
        assert!(seen.lock().unwrap().is_empty());
    }
}
