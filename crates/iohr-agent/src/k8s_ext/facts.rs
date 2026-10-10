//! Objects reduced to typed facts: counts, states and reasons. What the reducers drop is
//! the point: environment variables, commands, arguments, volumes, annotations (but the
//! rollout revision and change cause), labels, pod and node addresses, and every message
//! but an event's, which is masked.

use serde::Serialize;
use serde_json::Value;

use super::kinds::Kind;
use super::mask::mask;
use crate::atlas::k8s::name;

/// One condition: type, status, reason. Never its message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Condition {
    /// `Available`, `Progressing`, …
    pub kind: String,
    /// `True`, `False`, `Unknown`.
    pub status: String,
    /// The machine-readable reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A deployment, statefulset or daemonset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Workload {
    /// `deployments`, `statefulsets`, `daemonsets`.
    pub kind: Kind,
    /// Its name.
    pub name: String,
    /// Replicas asked for (pods scheduled, for a daemonset).
    pub desired: i64,
    /// Ready.
    pub ready: i64,
    /// On the current template.
    pub updated: i64,
    /// Available.
    pub available: i64,
    /// The controller has seen the latest spec.
    pub observed: bool,
    /// Container images, as written.
    pub images: Vec<String>,
    /// Conditions, without messages.
    pub conditions: Vec<Condition>,
}

impl Workload {
    /// Everything asked for is ready, available and on the current template.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.observed
            && self.ready >= self.desired
            && self.available >= self.desired
            && self.updated >= self.desired
    }
}

/// A pod: where it is in its life, never what runs in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pod {
    /// Its name.
    pub name: String,
    /// The owning controller, `Kind/name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// `Pending`, `Running`, `Succeeded`, `Failed`, `Unknown`.
    pub phase: String,
    /// Every container ready.
    pub ready: bool,
    /// Restarts across its containers.
    pub restarts: i64,
    /// Why a container waits (`CrashLoopBackOff`, `ImagePullBackOff`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting: Option<String>,
    /// Why a container last ended (`OOMKilled`, `Error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<String>,
}

/// One revision of a deployment, from its replicaset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revision {
    /// The deployment.
    pub deployment: String,
    /// `deployment.kubernetes.io/revision`.
    pub revision: i64,
    /// The replicaset.
    pub replicaset: String,
    /// Its images.
    pub images: Vec<String>,
    /// Replicas it runs now.
    pub replicas: i64,
    /// Ready.
    pub ready: i64,
    /// When it was made.
    pub created: String,
    /// `kubernetes.io/change-cause`, masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_cause: Option<String>,
}

/// An event, with its message masked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// `Normal` or `Warning`.
    pub kind: String,
    /// The machine-readable reason.
    pub reason: String,
    /// What it is about, `Kind/name`.
    pub object: String,
    /// The message, masked.
    pub message: String,
    /// How many times it happened.
    pub count: i64,
    /// When it last happened.
    pub last_seen: String,
}

fn int(v: &Value, ptr: &str) -> i64 {
    v.pointer(ptr).and_then(Value::as_i64).unwrap_or(0)
}

fn text(v: &Value, ptr: &str) -> Option<String> {
    v.pointer(ptr).and_then(Value::as_str).map(str::to_owned)
}

fn images(v: &Value) -> Vec<String> {
    v.pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c.get("image").and_then(Value::as_str))
                .map(|i| crate::redact::redact(i))
                .collect()
        })
        .unwrap_or_default()
}

fn conditions(v: &Value) -> Vec<Condition> {
    v.pointer("/status/conditions")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .map(|c| Condition {
                    kind: text(c, "/type").unwrap_or_default(),
                    status: text(c, "/status").unwrap_or_default(),
                    reason: text(c, "/reason"),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A deployment, statefulset or daemonset.
#[must_use]
pub fn workload(kind: Kind, v: &Value) -> Option<Workload> {
    let n = name(v)?.to_owned();
    let observed = int(v, "/status/observedGeneration") >= int(v, "/metadata/generation");
    let (desired, ready, updated, available) = match kind {
        Kind::Deployments | Kind::StatefulSets => (
            v.pointer("/spec/replicas")
                .and_then(Value::as_i64)
                .unwrap_or(1),
            int(v, "/status/readyReplicas"),
            int(v, "/status/updatedReplicas"),
            int(v, "/status/availableReplicas"),
        ),
        Kind::DaemonSets => (
            int(v, "/status/desiredNumberScheduled"),
            int(v, "/status/numberReady"),
            int(v, "/status/updatedNumberScheduled"),
            int(v, "/status/numberAvailable"),
        ),
        _ => return None,
    };
    Some(Workload {
        kind,
        name: n,
        desired,
        ready,
        updated,
        available,
        observed,
        images: images(v),
        conditions: conditions(v),
    })
}

/// A pod.
#[must_use]
pub fn pod(v: &Value) -> Option<Pod> {
    let statuses = v
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let owner = v
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .and_then(|o| {
            o.iter()
                .find(|r| r.get("controller") == Some(&Value::Bool(true)))
        })
        .and_then(|r| {
            Some(format!(
                "{}/{}",
                r.get("kind")?.as_str()?,
                r.get("name")?.as_str()?
            ))
        });
    Some(Pod {
        name: name(v)?.to_owned(),
        owner,
        phase: text(v, "/status/phase").unwrap_or_else(|| "Unknown".into()),
        ready: !statuses.is_empty()
            && statuses
                .iter()
                .all(|s| s.get("ready") == Some(&Value::Bool(true))),
        restarts: statuses.iter().map(|s| int(s, "/restartCount")).sum(),
        waiting: statuses
            .iter()
            .find_map(|s| text(s, "/state/waiting/reason")),
        last_exit: statuses
            .iter()
            .find_map(|s| text(s, "/lastState/terminated/reason")),
    })
}

/// Every revision of `deployment` among `replicasets`, newest first.
#[must_use]
pub fn rollout(deployment: &str, replicasets: &[Value]) -> Vec<Revision> {
    let mut out: Vec<Revision> = replicasets
        .iter()
        .filter(|rs| {
            rs.pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .is_some_and(|o| {
                    o.iter().any(|r| {
                        r.get("kind").and_then(Value::as_str) == Some("Deployment")
                            && r.get("name").and_then(Value::as_str) == Some(deployment)
                    })
                })
        })
        .filter_map(|rs| {
            let ann = rs.pointer("/metadata/annotations");
            Some(Revision {
                deployment: deployment.to_owned(),
                revision: ann
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(Value::as_str)
                    .and_then(|r| r.parse().ok())
                    .unwrap_or(0),
                replicaset: name(rs)?.to_owned(),
                images: images(rs),
                replicas: int(rs, "/status/replicas"),
                ready: int(rs, "/status/readyReplicas"),
                created: text(rs, "/metadata/creationTimestamp").unwrap_or_default(),
                change_cause: ann
                    .and_then(|a| a.get("kubernetes.io/change-cause"))
                    .and_then(Value::as_str)
                    .map(mask),
            })
        })
        .collect();
    out.sort_by(|a, b| b.revision.cmp(&a.revision));
    out
}

/// An event.
#[must_use]
pub fn event(v: &Value) -> Option<Event> {
    let obj = v.get("involvedObject").or_else(|| v.get("regarding"))?;
    Some(Event {
        kind: text(v, "/type").unwrap_or_else(|| "Normal".into()),
        reason: text(v, "/reason").unwrap_or_default(),
        object: format!(
            "{}/{}",
            text(obj, "/kind").unwrap_or_default(),
            text(obj, "/name").unwrap_or_default()
        ),
        message: mask(
            &text(v, "/message")
                .or_else(|| text(v, "/note"))
                .unwrap_or_default(),
        ),
        count: v
            .get("count")
            .and_then(Value::as_i64)
            .or_else(|| v.pointer("/series/count").and_then(Value::as_i64))
            .unwrap_or(1),
        last_seen: text(v, "/lastTimestamp")
            .or_else(|| text(v, "/eventTime"))
            .or_else(|| text(v, "/metadata/creationTimestamp"))
            .unwrap_or_default(),
    })
}

/// Events, newest first, at most `max`.
#[must_use]
pub fn events(items: &[Value], max: usize) -> Vec<Event> {
    let mut out: Vec<Event> = items.iter().filter_map(event).collect();
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    out.truncate(max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deployment() -> Value {
        json!({
            "kind": "Deployment",
            "metadata": {"name": "web", "generation": 4, "annotations": {"secret-hint": "s3cr3t"}},
            "spec": {"replicas": 3, "template": {"spec": {"containers": [{
                "name": "web", "image": "registry.example.com/web:1.4.2",
                "env": [{"name": "DB_PASSWORD", "value": "hunter2-planted"}],
                "args": ["--token=planted-arg-token"]
            }]}}},
            "status": {"observedGeneration": 4, "readyReplicas": 2, "updatedReplicas": 3,
                "availableReplicas": 2, "conditions": [{"type": "Available", "status": "False",
                "reason": "MinimumReplicasUnavailable", "message": "contact ops@example.com"}]}
        })
    }

    #[test]
    fn workloads_keep_counts_and_drop_env_args_and_messages() {
        let w = workload(Kind::Deployments, &deployment()).unwrap();
        assert_eq!((w.desired, w.ready, w.updated, w.available), (3, 2, 3, 2));
        assert!(w.observed && !w.healthy());
        assert_eq!(w.images, ["registry.example.com/web:1.4.2"]);
        assert_eq!(
            w.conditions[0].reason.as_deref(),
            Some("MinimumReplicasUnavailable")
        );
        let out = serde_json::to_string(&w).unwrap();
        for leaked in [
            "hunter2",
            "planted-arg-token",
            "DB_PASSWORD",
            "s3cr3t",
            "ops@example.com",
        ] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        let ds = json!({"metadata": {"name": "agent"}, "status": {"desiredNumberScheduled": 2,
            "numberReady": 2, "updatedNumberScheduled": 2, "numberAvailable": 2}});
        assert!(workload(Kind::DaemonSets, &ds).unwrap().healthy());
        assert!(workload(Kind::Pods, &ds).is_none());
    }

    #[test]
    fn pods_say_why_they_wait() {
        let p = pod(&json!({
            "metadata": {"name": "web-1", "ownerReferences": [{"kind": "ReplicaSet", "name": "web-7d", "controller": true}]},
            "status": {"phase": "Running", "podIP": "10.42.0.9", "containerStatuses": [
                {"ready": false, "restartCount": 7, "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off"}},
                 "lastState": {"terminated": {"reason": "OOMKilled"}}}]}
        }))
        .unwrap();
        assert_eq!(p.owner.as_deref(), Some("ReplicaSet/web-7d"));
        assert_eq!((p.ready, p.restarts), (false, 7));
        assert_eq!(p.waiting.as_deref(), Some("CrashLoopBackOff"));
        assert_eq!(p.last_exit.as_deref(), Some("OOMKilled"));
        assert!(!serde_json::to_string(&p).unwrap().contains("10.42"));
    }

    #[test]
    fn rollout_history_comes_from_owned_replicasets() {
        let rs = |n: &str, rev: &str, owner: &str, cause: &str| {
            json!({
                "metadata": {"name": n, "creationTimestamp": "2026-10-09T10:00:00Z",
                    "annotations": {"deployment.kubernetes.io/revision": rev, "kubernetes.io/change-cause": cause},
                    "ownerReferences": [{"kind": "Deployment", "name": owner}]},
                "spec": {"template": {"spec": {"containers": [{"image": format!("web:{rev}")}]}}},
                "status": {"replicas": 1, "readyReplicas": 1}
            })
        };
        let r = rollout(
            "web",
            &[
                rs("web-a", "1", "web", "first"),
                rs(
                    "web-c",
                    "3",
                    "web",
                    "kubectl set image by ana@example.com from 10.1.2.3",
                ),
                rs("api-b", "2", "api", "other"),
            ],
        );
        assert_eq!(r.iter().map(|r| r.revision).collect::<Vec<_>>(), [3, 1]);
        assert_eq!(r[0].images, ["web:3"]);
        assert_eq!(
            r[0].change_cause.as_deref(),
            Some("kubectl set image by [email] from [ip]")
        );
    }

    #[test]
    fn event_messages_are_masked_and_newest_come_first() {
        let items = [
            json!({"type": "Warning", "reason": "Unhealthy", "count": 12, "lastTimestamp": "2026-10-10T08:00:00Z",
                "involvedObject": {"kind": "Pod", "name": "web-1"},
                "message": "Liveness probe failed: Get http://10.42.0.9:8080/ token=ghp_0123456789abcdefghijABCDEFGHIJ012345 owner ana@example.com"}),
            json!({"type": "Normal", "reason": "Pulled", "lastTimestamp": "2026-10-10T09:00:00Z",
                "involvedObject": {"kind": "Pod", "name": "web-2"}, "message": "pulled"}),
        ];
        let e = events(&items, 10);
        assert_eq!(e[0].reason, "Pulled");
        let w = &e[1];
        assert_eq!(
            (w.kind.as_str(), w.count, w.object.as_str()),
            ("Warning", 12, "Pod/web-1")
        );
        for leaked in ["10.42.0.9", "ghp_0123", "ana@example.com"] {
            assert!(!w.message.contains(leaked), "{leaked} in {}", w.message);
        }
        assert_eq!(events(&items, 1).len(), 1);
    }
}
