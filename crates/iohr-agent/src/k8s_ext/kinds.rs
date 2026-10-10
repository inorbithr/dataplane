//! The kinds the extension may read, and the paths it may ask for. Every request is built
//! here from a [`Kind`] and checked names; nothing else reaches the API server. Secrets,
//! config maps, exec, attach, port-forward, proxies and token requests have no `Kind`, so
//! there is no path to them, and [`guard`] refuses them again in case one is ever added.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A kind of object the extension reads. All namespaced; cluster-wide kinds (nodes) need a
/// ClusterRole and come later (RFC, slice 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// `apps/v1` deployments.
    Deployments,
    /// `apps/v1` statefulsets.
    StatefulSets,
    /// `apps/v1` daemonsets.
    DaemonSets,
    /// `apps/v1` replicasets: rollout history.
    ReplicaSets,
    /// `v1` pods: phase, readiness, restarts. Never logs, exec or attach.
    Pods,
    /// `v1` events, with redacted messages.
    Events,
}

impl Kind {
    /// Every kind, in a stable order.
    pub const ALL: [Self; 6] = [
        Self::Deployments,
        Self::StatefulSets,
        Self::DaemonSets,
        Self::ReplicaSets,
        Self::Pods,
        Self::Events,
    ];

    /// The API group (`""` for the core group).
    #[must_use]
    pub const fn group(self) -> &'static str {
        match self {
            Self::Deployments | Self::StatefulSets | Self::DaemonSets | Self::ReplicaSets => "apps",
            Self::Pods | Self::Events => "",
        }
    }

    /// The resource name in paths and RBAC rules.
    #[must_use]
    pub const fn resource(self) -> &'static str {
        match self {
            Self::Deployments => "deployments",
            Self::StatefulSets => "statefulsets",
            Self::DaemonSets => "daemonsets",
            Self::ReplicaSets => "replicasets",
            Self::Pods => "pods",
            Self::Events => "events",
        }
    }

    /// The policy's name for it (the resource name).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.resource()
    }

    /// Parses a policy or command-line name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    fn prefix(self) -> &'static str {
        if self.group().is_empty() {
            "api/v1"
        } else {
            "apis/apps/v1"
        }
    }
}

/// Resources, subresources and verbs the extension never asks for and never puts in RBAC.
pub const FORBIDDEN: [&str; 14] = [
    "secrets",
    "configmaps",
    "serviceaccounts",
    "token",
    "exec",
    "attach",
    "portforward",
    "proxy",
    "log",
    "ephemeralcontainers",
    "eviction",
    "binding",
    "certificatesigningrequests",
    "tokenreviews",
];

/// Most objects one list asks for.
pub const MAX_LIMIT: u32 = 2_000;

/// A Kubernetes name (RFC 1123 subdomain): what a namespace or object name may be.
#[must_use]
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
}

/// The list path for `kind` in `namespace`, at most `limit` objects.
///
/// # Errors
/// The namespace is not a valid name, or the limit is outside 1..=[`MAX_LIMIT`].
pub fn list_path(kind: Kind, namespace: &str, limit: u32) -> Result<String> {
    if !valid_name(namespace) {
        return Err(Error::Policy(format!(
            "not a namespace name: {namespace:?}"
        )));
    }
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::Policy(format!(
            "limit {limit} is outside 1..={MAX_LIMIT}"
        )));
    }
    let path = format!(
        "{}/namespaces/{namespace}/{}?limit={limit}",
        kind.prefix(),
        kind.resource()
    );
    guard(&path)?;
    Ok(path)
}

/// The last line before a request leaves: only a list of a known kind in one namespace,
/// with no forbidden segment, no traversal and no query beyond `limit`.
///
/// # Errors
/// The path is anything else.
pub fn guard(path: &str) -> Result<()> {
    let refuse = |why: &str| {
        Err(Error::Policy(format!(
            "refused Kubernetes path {path:?}: {why}"
        )))
    };
    let (p, query) = path.split_once('?').unwrap_or((path, ""));
    if !query.is_empty()
        && !(query.starts_with("limit=") && query[6..].bytes().all(|b| b.is_ascii_digit()))
    {
        return refuse("only ?limit= is asked");
    }
    let segs: Vec<&str> = p.split('/').collect();
    if segs
        .iter()
        .any(|s| s.is_empty() || *s == "." || *s == ".." || s.contains('%'))
    {
        return refuse("not a plain path");
    }
    for s in &segs {
        if FORBIDDEN.contains(s) {
            return refuse("a forbidden resource");
        }
    }
    let rest = match segs.as_slice() {
        ["api", "v1", rest @ ..] => rest,
        ["apis", "apps", "v1", rest @ ..] => rest,
        _ => return refuse("not a core or apps/v1 path"),
    };
    match rest {
        ["namespaces", ns, res] if valid_name(ns) => {
            let known = Kind::ALL
                .iter()
                .any(|k| k.resource() == *res && path.starts_with(k.prefix()));
            if known {
                Ok(())
            } else {
                refuse("not a kind the extension reads")
            }
        }
        _ => refuse("only a list in one namespace"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_built_only_for_known_kinds() {
        assert_eq!(
            list_path(Kind::Deployments, "shop", 500).unwrap(),
            "apis/apps/v1/namespaces/shop/deployments?limit=500"
        );
        assert_eq!(
            list_path(Kind::Events, "shop", 10).unwrap(),
            "api/v1/namespaces/shop/events?limit=10"
        );
        assert!(list_path(Kind::Pods, "../kube-system", 10).is_err());
        assert!(list_path(Kind::Pods, "Shop", 10).is_err());
        assert!(list_path(Kind::Pods, "shop", 0).is_err());
        assert!(list_path(Kind::Pods, "shop", MAX_LIMIT + 1).is_err());
    }

    #[test]
    fn the_guard_refuses_secrets_exec_logs_and_everything_else() {
        for p in [
            "api/v1/namespaces/shop/secrets",
            "api/v1/namespaces/shop/configmaps",
            "api/v1/namespaces/shop/pods/web-1/exec",
            "api/v1/namespaces/shop/pods/web-1/attach",
            "api/v1/namespaces/shop/pods/web-1/portforward",
            "api/v1/namespaces/shop/pods/web-1/log",
            "api/v1/namespaces/shop/pods/web-1/proxy",
            "api/v1/namespaces/shop/serviceaccounts/default/token",
            "api/v1/secrets",
            "api/v1/pods",
            "api/v1/nodes/n1/proxy",
            "api/v1/namespaces/shop/pods/web-1",
            "api/v1/namespaces/shop/../kube-system/secrets",
            "api/v1/namespaces/shop/%73ecrets",
            "api/v1/namespaces/shop/pods?watch=true",
            "api/v1/namespaces/shop/pods?limit=5&fieldSelector=x",
            "apis/rbac.authorization.k8s.io/v1/namespaces/shop/roles",
            "apis/apps/v1/namespaces/shop/pods",
            "api/v1/namespaces/shop/deployments",
            "/api/v1/namespaces/shop/pods",
        ] {
            assert!(guard(p).is_err(), "{p} passed the guard");
        }
        for p in [
            "api/v1/namespaces/shop/pods?limit=5",
            "api/v1/namespaces/shop/events",
            "apis/apps/v1/namespaces/shop/replicasets?limit=2000",
        ] {
            assert!(guard(p).is_ok(), "{p} was refused");
        }
    }

    #[test]
    fn no_kind_is_forbidden() {
        for k in Kind::ALL {
            assert!(!FORBIDDEN.contains(&k.resource()));
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("secrets"), None);
    }
}
