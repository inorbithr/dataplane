//! Reading Kubernetes objects, whether they came from a manifest in a checkout or from
//! the API: names, labels, selectors, egress rules, image digests and secret references,
//! rendered the same way from both so an observation reads alike whichever source made it.

use std::collections::BTreeMap;

use iohr_evidence::digest::ContentDigest;
use serde_json::Value;

/// `metadata.name`.
#[must_use]
pub fn name(v: &Value) -> Option<&str> {
    v.pointer("/metadata/name").and_then(Value::as_str)
}

/// `kind`.
#[must_use]
pub fn kind(v: &Value) -> Option<&str> {
    v.get("kind").and_then(Value::as_str)
}

/// A label map, or empty.
#[must_use]
pub fn labels(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// The labels a workload's pods carry (`spec.template.metadata.labels`).
#[must_use]
pub fn pod_labels(workload: &Value) -> BTreeMap<String, String> {
    labels(workload.pointer("/spec/template/metadata/labels"))
}

/// `k=v,k=v`, sorted.
#[must_use]
pub fn render_labels(l: &BTreeMap<String, String>) -> String {
    l.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn expressions(sel: &Value) -> impl Iterator<Item = (&str, &str, Vec<&str>)> {
    sel.get("matchExpressions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| {
            let key = e.get("key").and_then(Value::as_str).unwrap_or("");
            let op = e.get("operator").and_then(Value::as_str).unwrap_or("");
            let values = e
                .get("values")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            (key, op, values)
        })
}

/// A label selector (`matchLabels` and `matchExpressions`), rendered compactly; `{}` is
/// every pod.
#[must_use]
pub fn render_selector(sel: &Value) -> String {
    let mut parts = Vec::new();
    let ml = labels(sel.get("matchLabels"));
    if !ml.is_empty() {
        parts.push(render_labels(&ml));
    }
    for (key, op, values) in expressions(sel) {
        parts.push(format!("{key} {op} [{}]", values.join(",")));
    }
    if parts.is_empty() {
        "{}".into()
    } else {
        parts.join("; ")
    }
}

/// Whether a pod with `labels_of` is selected by `sel` (`matchLabels`, and `In`, `NotIn`,
/// `Exists`, `DoesNotExist` expressions). An unknown operator selects nothing.
#[must_use]
pub fn selector_matches(sel: &Value, labels_of: &BTreeMap<String, String>) -> bool {
    let ml = labels(sel.get("matchLabels"));
    if !ml.iter().all(|(k, v)| labels_of.get(k) == Some(v)) {
        return false;
    }
    expressions(sel).all(|(key, op, values)| {
        let have = labels_of.get(key).map(String::as_str);
        match op {
            "In" => have.is_some_and(|v| values.contains(&v)),
            "NotIn" => !have.is_some_and(|v| values.contains(&v)),
            "Exists" => have.is_some(),
            "DoesNotExist" => have.is_none(),
            _ => false,
        }
    })
}

/// Whether a plain label map (a Service's `spec.selector`) selects these labels. An empty
/// selector selects nothing.
#[must_use]
pub fn plain_selector_matches(
    sel: &BTreeMap<String, String>,
    labels_of: &BTreeMap<String, String>,
) -> bool {
    !sel.is_empty() && sel.iter().all(|(k, v)| labels_of.get(k) == Some(v))
}

/// One egress rule, rendered: `to=[peers] ports=[ports]`.
#[must_use]
pub fn render_egress(rule: &Value) -> String {
    let mut to = Vec::new();
    for peer in rule
        .get("to")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(ip) = peer.get("ipBlock") {
            let cidr = ip.get("cidr").and_then(Value::as_str).unwrap_or("?");
            let except: Vec<&str> = ip
                .get("except")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            to.push(if except.is_empty() {
                format!("cidr:{cidr}")
            } else {
                format!("cidr:{cidr} except [{}]", except.join(","))
            });
        }
        if let Some(ns) = peer.get("namespaceSelector") {
            to.push(format!("namespace:{}", render_selector(ns)));
        }
        if let Some(ps) = peer.get("podSelector") {
            to.push(format!("pod:{}", render_selector(ps)));
        }
    }
    let ports: Vec<String> = rule
        .get("ports")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|p| {
                    let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
                    match p.get("port") {
                        Some(Value::Number(n)) => format!("{n}/{proto}"),
                        Some(Value::String(s)) => format!("{s}/{proto}"),
                        _ => format!("any/{proto}"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    format!(
        "to=[{}] ports=[{}]",
        if to.is_empty() {
            "any".to_owned()
        } else {
            to.join(", ")
        },
        if ports.is_empty() {
            "any".to_owned()
        } else {
            ports.join(", ")
        }
    )
}

/// The `sha256:` digest in a container `imageID` (`registry/name@sha256:hex`), if any.
#[must_use]
pub fn image_digest(image_id: &str) -> Option<ContentDigest> {
    let (_, hex) = image_id.rsplit_once("sha256:")?;
    ContentDigest::try_from(format!("sha256:{hex}")).ok()
}

/// The images a workload's containers run (`spec.template.spec.containers[].image`).
#[must_use]
pub fn images(workload: &Value) -> Vec<&str> {
    containers(workload)
        .filter_map(|c| c.get("image").and_then(Value::as_str))
        .collect()
}

fn containers(workload: &Value) -> impl Iterator<Item = &Value> {
    [
        "/spec/template/spec/containers",
        "/spec/template/spec/initContainers",
    ]
    .into_iter()
    .filter_map(|p| workload.pointer(p).and_then(Value::as_array))
    .flatten()
}

/// The Secrets a workload reads, as `(secret name, key)`; the key is empty for a whole
/// `envFrom` secret. Sorted, without duplicates.
#[must_use]
pub fn secret_refs(workload: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in containers(workload) {
        for env in c.get("env").and_then(Value::as_array).into_iter().flatten() {
            if let Some(r) = env.pointer("/valueFrom/secretKeyRef") {
                let secret = r.get("name").and_then(Value::as_str).unwrap_or("");
                let key = r.get("key").and_then(Value::as_str).unwrap_or("");
                if !secret.is_empty() {
                    out.push((secret.to_owned(), key.to_owned()));
                }
            }
        }
        for from in c
            .get("envFrom")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(secret) = from.pointer("/secretRef/name").and_then(Value::as_str) {
                out.push((secret.to_owned(), String::new()));
            }
        }
    }
    for v in workload
        .pointer("/spec/template/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(secret) = v.pointer("/secret/secretName").and_then(Value::as_str) {
            out.push((secret.to_owned(), String::new()));
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn image_digests_and_selectors() {
        let d = image_digest(
            "ghcr.io/inorbithr/iohr-labs@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert!(d.to_hex().ends_with("52b855"));
        assert!(image_digest("docker.io/library/nginx:latest").is_none());
        let sel = json!({"matchLabels": {"app": "a"}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["web", "api"]}]});
        let mut l = BTreeMap::new();
        l.insert("app".to_owned(), "a".to_owned());
        assert!(!selector_matches(&sel, &l));
        l.insert("tier".to_owned(), "api".to_owned());
        assert!(selector_matches(&sel, &l));
        assert_eq!(render_selector(&sel), "app=a; tier In [web,api]");
        assert_eq!(render_selector(&json!({})), "{}");
        assert!(
            selector_matches(&json!({}), &l),
            "an empty selector selects every pod"
        );
        assert!(
            !plain_selector_matches(&BTreeMap::new(), &l),
            "an empty service selector selects none"
        );
        let not_in =
            json!({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["api"]}]});
        assert!(!selector_matches(&not_in, &l));
        let odd =
            json!({"matchExpressions": [{"key": "tier", "operator": "Like", "values": ["api"]}]});
        assert!(
            !selector_matches(&odd, &l),
            "an unknown operator selects nothing"
        );
    }

    #[test]
    fn egress_rules_render_cidrs_exceptions_and_ports() {
        let rule = json!({"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}], "ports": [{"protocol": "TCP", "port": 443}]});
        assert_eq!(
            render_egress(&rule),
            "to=[cidr:0.0.0.0/0 except [10.0.0.0/8]] ports=[443/TCP]"
        );
        assert_eq!(render_egress(&json!({})), "to=[any] ports=[any]");
        let ns = json!({"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}], "ports": [{"protocol": "UDP", "port": 53}]});
        assert_eq!(
            render_egress(&ns),
            "to=[namespace:kubernetes.io/metadata.name=kube-system, pod:k8s-app=kube-dns] ports=[53/UDP]"
        );
    }

    #[test]
    fn secret_references_come_from_env_envfrom_and_volumes() {
        let d = json!({"spec": {"template": {"spec": {
            "containers": [{"image": "a", "env": [
                {"name": "URL", "valueFrom": {"secretKeyRef": {"name": "labs-db", "key": "database-url"}}},
                {"name": "PLAIN", "value": "x"}
            ], "envFrom": [{"secretRef": {"name": "labs-env"}}]}],
            "volumes": [{"name": "tls", "secret": {"secretName": "labs-tls"}}]
        }}}});
        assert_eq!(
            secret_refs(&d),
            vec![
                ("labs-db".to_owned(), "database-url".to_owned()),
                ("labs-env".to_owned(), String::new()),
                ("labs-tls".to_owned(), String::new()),
            ]
        );
        assert_eq!(images(&d), vec!["a"]);
    }
}
