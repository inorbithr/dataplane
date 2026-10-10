//! The Kubernetes extension (RFC 0112): cluster evidence, read-only by design.
//!
//! What it reads is decided in three places, and all three must agree: the policy's
//! `[kubernetes]` section (namespaces and kinds), the RBAC the customer applied (printed
//! by [`rbac::generate`], never applied by the agent), and [`kinds::guard`], which refuses
//! every path that is not a list of a known kind in one namespace. Secrets, config maps,
//! exec, attach, port-forward, logs, proxies and tokens have no path at all.
//!
//! Every request is written to a chained query ledger before it is sent, and to an audit
//! with its outcome after. Messages are masked (secrets, tokens, emails, IP addresses)
//! before they become facts. Nothing leaves this machine in this slice: `data.leaves` is
//! empty, so the platform is told nothing about the cluster.

pub mod audit;
pub mod facts;
pub mod kinds;
pub mod mask;
pub mod rbac;
pub mod read;

use serde::{Deserialize, Serialize};

use kinds::{Kind, valid_name};

/// The extension's manifest (RFC 0073.1). Built in: it ships with the agent and is still
/// off until the policy names what it may read.
pub const MANIFEST: &str = "\
kind: agent-plugin
delivery: builtin
id: inorbit/kubernetes
version: 0.1.0
entitlement: kubernetes.read
where: [agent, console]
policy: [kubernetes]
data:
  reads: [k8s:deployments, k8s:statefulsets, k8s:daemonsets, k8s:replicasets, k8s:pods, k8s:events]
  writes: [state:kubernetes/ledger, state:kubernetes/audit.jsonl]
  leaves: []
privileges: []
console:
  routes: [\"/kubernetes\"]
  permissions: {read: [viewer, member, admin, owner], write: []}
api: \">=2026.10 <2027.01\"
";

/// The extension's id.
pub const ID: &str = "inorbit/kubernetes";

/// Default most objects per list.
const fn default_max_items() -> u32 {
    500
}

/// Default most requests a minute.
const fn default_per_minute() -> u32 {
    60
}

/// Default most events kept per namespace.
const fn default_max_events() -> u32 {
    200
}

fn default_kinds() -> Vec<Kind> {
    Kind::ALL.to_vec()
}

/// `[kubernetes]` in the policy: what the extension may read. Without the section it reads
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesPolicy {
    /// The namespaces it may read. Required; there is no "all namespaces".
    pub namespaces: Vec<String>,
    /// The kinds it may read (default: all the extension knows).
    #[serde(default = "default_kinds")]
    pub kinds: Vec<Kind>,
    /// Most objects one list asks for (1 to 2000, default 500).
    #[serde(default = "default_max_items")]
    pub max_items: u32,
    /// Most requests a minute (1 to 600, default 60).
    #[serde(default = "default_per_minute")]
    pub queries_per_minute: u32,
    /// Most events kept per namespace (1 to 2000, default 200).
    #[serde(default = "default_max_events")]
    pub max_events: u32,
}

impl KubernetesPolicy {
    /// Checks the section; sorts and dedups the lists.
    ///
    /// # Errors
    /// No namespace, a bad name, or a limit out of range.
    pub fn validate(&mut self) -> std::result::Result<(), String> {
        if self.namespaces.is_empty() {
            return Err("name at least one namespace in `namespaces`".into());
        }
        for n in &self.namespaces {
            if !valid_name(n) || n.len() > 63 {
                return Err(format!("namespaces: {n:?} is not a namespace name"));
            }
        }
        self.namespaces.sort();
        self.namespaces.dedup();
        if self.kinds.is_empty() {
            return Err("name at least one kind in `kinds`".into());
        }
        self.kinds.sort();
        self.kinds.dedup();
        if !(1..=kinds::MAX_LIMIT).contains(&self.max_items) {
            return Err("max_items must be 1 to 2000".into());
        }
        if !(1..=600).contains(&self.queries_per_minute) {
            return Err("queries_per_minute must be 1 to 600".into());
        }
        if !(1..=2000).contains(&self.max_events) {
            return Err("max_events must be 1 to 2000".into());
        }
        Ok(())
    }

    /// Whether `kind` in `namespace` is allowed.
    #[must_use]
    pub fn allows(&self, kind: Kind, namespace: &str) -> bool {
        self.kinds.contains(&kind) && self.namespaces.iter().any(|n| n == namespace)
    }
}

/// Where the extension keeps its query ledger and audit.
#[must_use]
pub fn state_dir(agent_state: &std::path::Path) -> std::path::PathBuf {
    agent_state.join("kubernetes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    const BASE: &str = "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1\"]\n";

    #[test]
    fn the_manifest_reads_and_sends_nothing_out() {
        let v: serde_json::Value = serde_yaml_ng::from_str(MANIFEST).unwrap();
        assert_eq!(v["id"], ID);
        assert_eq!(v["data"]["leaves"], serde_json::json!([]));
        assert_eq!(v["privileges"], serde_json::json!([]));
        let reads = v["data"]["reads"].as_array().unwrap();
        assert_eq!(reads.len(), Kind::ALL.len());
        for r in reads {
            let r = r.as_str().unwrap();
            assert!(Kind::parse(r.trim_start_matches("k8s:")).is_some(), "{r}");
        }
    }

    #[test]
    fn the_policy_section_is_optional_and_validated() {
        let p = Policy::from_toml(BASE).unwrap();
        assert!(p.kubernetes.is_none());
        let hash = p.hash();
        let p = Policy::from_toml(&format!(
            "{BASE}[kubernetes]\nnamespaces = [\"shop\", \"payments\", \"shop\"]\n"
        ))
        .unwrap();
        let k = p.kubernetes.as_ref().unwrap();
        assert_eq!(k.namespaces, ["payments", "shop"]);
        assert_eq!(k.kinds, Kind::ALL);
        assert!(k.allows(Kind::Pods, "shop") && !k.allows(Kind::Pods, "kube-system"));
        assert_ne!(p.hash(), hash);
        for bad in [
            "[kubernetes]\nnamespaces = []\n",
            "[kubernetes]\nnamespaces = [\"Shop\"]\n",
            "[kubernetes]\nnamespaces = [\"a\"]\nkinds = [\"secrets\"]\n",
            "[kubernetes]\nnamespaces = [\"a\"]\nkinds = [\"configmaps\"]\n",
            "[kubernetes]\nnamespaces = [\"a\"]\nmax_items = 0\n",
            "[kubernetes]\nnamespaces = [\"a\"]\nwrite = true\n",
        ] {
            assert!(Policy::from_toml(&format!("{BASE}{bad}")).is_err(), "{bad}");
        }
    }
}
