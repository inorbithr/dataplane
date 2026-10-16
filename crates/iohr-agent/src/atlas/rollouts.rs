//! Rollouts as evidence: every `ReplicaSet` a `Deployment` owns is one rollout, with the time
//! the control plane created it, its revision and image. An investigation needs "what
//! changed, and when" as observations, not as somebody's memory of a deploy; the
//! `ReplicaSet` history is what the cluster itself recorded. Read-only (`list`), through
//! the same policy-admitted client as [`super::kube`].

use std::collections::BTreeMap;

use iohr_evidence::vocabulary::Value as EvValue;
use serde_json::Value;

use super::common::Ctx;
use super::kube::KubeClient;
use super::record::Sink;
use crate::error::Result;

/// The method this reader writes through.
pub const METHOD: &str = "k8s.api.replicasets";

/// Reads the `ReplicaSet`s of one namespace.
///
/// # Errors
/// The list call failed.
pub async fn read(client: &KubeClient, namespace: &str) -> Result<Vec<Value>> {
    client
        .list(&format!("apis/apps/v1/namespaces/{namespace}/replicasets"))
        .await
}

/// One rollout, as observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollout {
    /// `rollout/<ns>/<deployment>/<replicaset>`.
    pub key: String,
    /// `deployment/<ns>/<deployment>`.
    pub deployment: String,
    /// When the control plane created the `ReplicaSet` (RFC 3339, UTC).
    pub created: String,
    /// `deployment.kubernetes.io/revision`, when set.
    pub revision: Option<i64>,
}

/// Turns `ReplicaSet`s into rollout observations: `rolls_out` (the deployment),
/// `rolled_at` (creation time), `revision`, `runs_image` and `serving` (whether it still
/// has replicas). `ReplicaSet`s no `Deployment` owns are skipped: they are not rollouts.
/// Returns the rollouts per deployment, oldest first.
///
/// # Errors
/// An observation could not be built.
pub fn observe(
    ctx: &Ctx,
    namespace: &str,
    replicasets: &[Value],
    sink: &mut Sink,
) -> Result<BTreeMap<String, Vec<Rollout>>> {
    let mut out: BTreeMap<String, Vec<Rollout>> = BTreeMap::new();
    for rs in replicasets {
        let Some(name) = rs.pointer("/metadata/name").and_then(Value::as_str) else {
            continue;
        };
        let Some(owner) = rs
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array)
            .and_then(|o| {
                o.iter()
                    .find(|r| r.get("kind").and_then(Value::as_str) == Some("Deployment"))
            })
            .and_then(|r| r.get("name").and_then(Value::as_str))
        else {
            continue;
        };
        let Some(created) = rs
            .pointer("/metadata/creationTimestamp")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let deployment = format!("deployment/{namespace}/{owner}");
        let key = format!("rollout/{namespace}/{owner}/{name}");
        let dep_entity = sink.entity(&deployment);
        ctx.observe(sink, &key, "rolls_out", EvValue::Entity(dep_entity), &[])?;
        ctx.observe(
            sink,
            &key,
            "rolled_at",
            EvValue::Text(created.to_owned()),
            &[],
        )?;
        let revision = rs
            .pointer("/metadata/annotations/deployment.kubernetes.io~1revision")
            .and_then(Value::as_str)
            .and_then(|r| r.parse::<i64>().ok());
        if let Some(r) = revision {
            ctx.observe(sink, &key, "revision", EvValue::Int(r), &[])?;
        }
        if let Some(images) = rs
            .pointer("/spec/template/spec/containers")
            .and_then(Value::as_array)
        {
            for image in images
                .iter()
                .filter_map(|c| c.get("image").and_then(Value::as_str))
            {
                ctx.observe(
                    sink,
                    &key,
                    "runs_image",
                    EvValue::Text(image.to_owned()),
                    &[],
                )?;
            }
        }
        let serving = rs
            .pointer("/status/replicas")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            > 0;
        ctx.observe(sink, &key, "serving", EvValue::Bool(serving), &[])?;
        out.entry(deployment.clone()).or_default().push(Rollout {
            key,
            deployment,
            created: created.to_owned(),
            revision,
        });
    }
    for v in out.values_mut() {
        v.sort_by(|a, b| a.created.cmp(&b.created));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::common::{ObservedNow, method};
    use crate::atlas::record::Record;
    use iohr_evidence::method::MethodCategory;
    use iohr_evidence::observer::ObserverClass;
    use serde_json::json;

    fn ctx(sink: &mut Sink) -> Ctx {
        Ctx::new(
            sink,
            "rollout-reader",
            ObserverClass::ExternalSystem,
            method(METHOD, MethodCategory::RuntimeState).unwrap(),
            "probe",
            &["list"],
            &ObservedNow::now(),
        )
        .unwrap()
    }

    #[test]
    fn replicasets_become_rollouts_in_time_order_and_orphans_are_skipped() {
        // The agents rollout of 2026-10-08T21:54:49Z (core#670) and its predecessor, as
        // the API answered them; an orphan ReplicaSet is not a rollout.
        let rs = vec![
            json!({"metadata": {"name": "agents-7d9", "creationTimestamp": "2026-10-08T21:54:49Z",
                "annotations": {"deployment.kubernetes.io/revision": "41"},
                "ownerReferences": [{"kind": "Deployment", "name": "agents"}]},
                "spec": {"template": {"spec": {"containers": [{"image": "tbd/agents:dev"}]}}},
                "status": {"replicas": 1}}),
            json!({"metadata": {"name": "agents-5c1", "creationTimestamp": "2026-10-08T19:02:10Z",
                "annotations": {"deployment.kubernetes.io/revision": "40"},
                "ownerReferences": [{"kind": "Deployment", "name": "agents"}]},
                "spec": {"template": {"spec": {"containers": [{"image": "tbd/agents:dev"}]}}},
                "status": {"replicas": 0}}),
            json!({"metadata": {"name": "lonely", "creationTimestamp": "2026-10-08T00:00:00Z"}}),
        ];
        let mut sink = Sink::default();
        let c = ctx(&mut sink);
        let out = observe(&c, "tbd", &rs, &mut sink).unwrap();
        let agents = &out["deployment/tbd/agents"];
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].revision, Some(40));
        assert_eq!(agents[1].created, "2026-10-08T21:54:49Z");
        assert!(!out.keys().any(|k| k.contains("lonely")));
        let serving: Vec<bool> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Observation(o) if o.statement().predicate.name.as_str() == "serving" => {
                    match o.statement().value {
                        EvValue::Bool(b) => Some(b),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(serving, vec![true, false]);
    }
}
