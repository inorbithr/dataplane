//! `atlas observe` end to end: a checkout on disk and a fake Kubernetes API, read through
//! the policy, and the redacted sample from a real run on InOrbit's own platform
//! (`tests/fixtures/atlas-inorbit-sample.jsonl`) read back through the public types.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use axum::Json;
use axum::Router;
use axum::extract::Path as UrlPath;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use iohr_agent::atlas::record::Record;
use iohr_agent::atlas::{ObserveRequest, observe};
use iohr_agent::error::Error;
use iohr_agent::policy::Policy;
use iohr_evidence::evidence::EvidenceRef;
use iohr_evidence::observer::ObserverClass;
use iohr_evidence::snapshot::ComponentState;
use iohr_evidence::vocabulary::Value as EvValue;
use serde_json::{Value, json};

const TOKEN: &str = "test-token";

/// Who says what about whom: `(subject key, predicate, value as text or key, method)`.
fn facts(records: &[Record]) -> BTreeSet<(String, String, String, String)> {
    let keys: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Entity { id, key } => Some((*id, key.clone())),
            _ => None,
        })
        .collect();
    let methods: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Evidence(i) => match i.reference {
                EvidenceRef::Observation(o) => Some((o, i.method.name.to_string())),
                _ => None,
            },
            _ => None,
        })
        .collect();
    records
        .iter()
        .filter_map(|r| match r {
            Record::Observation(o) => {
                let s = o.statement();
                let value = match &s.value {
                    EvValue::Entity(e) => keys[e].clone(),
                    EvValue::Text(t) => t.clone(),
                    EvValue::Int(i) => i.to_string(),
                    EvValue::Digest(d) => d.to_hex(),
                    other => format!("{other:?}"),
                };
                Some((
                    keys[&s.subject].clone(),
                    s.predicate.name.as_str().to_owned(),
                    value,
                    methods[&o.id()].clone(),
                ))
            }
            _ => None,
        })
        .collect()
}

fn has(
    all: &BTreeSet<(String, String, String, String)>,
    subject: &str,
    predicate: &str,
    value: &str,
    method: &str,
) -> bool {
    all.contains(&(
        subject.to_owned(),
        predicate.to_owned(),
        value.to_owned(),
        method.to_owned(),
    ))
}

#[test]
fn the_inorbit_sample_reads_back_and_holds_both_rfc_0086_chains() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atlas-inorbit-sample.jsonl"),
    )
    .unwrap();
    let records: Vec<Record> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect();
    // Every observation and artefact has its evidence item, and no model or person
    // produced anything here.
    let mut items = BTreeSet::new();
    for r in &records {
        match r {
            Record::Evidence(i) => {
                assert!(i.method.category.may_prove(), "{:?}", i.method);
                items.insert(i.reference);
            }
            Record::Observer(o) => assert!(o.class.is_deterministic(), "{o:?}"),
            _ => {}
        }
    }
    for r in &records {
        match r {
            Record::Observation(o) => assert!(items.contains(&EvidenceRef::Observation(o.id()))),
            Record::Artifact(a) => assert!(items.contains(&EvidenceRef::Artifact(a.id()))),
            _ => {}
        }
    }
    let f = facts(&records);
    // Test 1: the public route reaches labs through the protocol gateway, labs' gRPC
    // route reaches the labs Service, which targets the deployment that reads its
    // database secret.
    let route = "envoy.route/console/path_separated_prefix:/v1/labs";
    assert!(has(
        &f,
        route,
        "routes_to",
        "envoy.cluster/protocol",
        "envoy.route"
    ));
    let grpc = "envoy.route/all/prefix:/iohr.labs.v1.LabsService/_grpc";
    assert!(has(
        &f,
        grpc,
        "routes_to",
        "envoy.cluster/labs",
        "envoy.route"
    ));
    assert!(has(
        &f,
        "envoy.cluster/labs",
        "upstream_service",
        "service/tbd/labs",
        "envoy.route"
    ));
    for m in ["k8s.manifest", "k8s.api.read"] {
        assert!(
            has(&f, "service/tbd/labs", "targets", "deployment/tbd/labs", m),
            "{m}"
        );
    }
    assert!(has(
        &f,
        "deployment/tbd/labs",
        "reads_secret",
        "secret/tbd/labs-db",
        "k8s.manifest"
    ));
    assert!(has(
        &f,
        "deployment/tbd/labs",
        "reads_secret_key",
        "labs-db/database-url",
        "k8s.manifest"
    ));
    // Test 2: the internet-egress policy applies to paging and allows any public host on 443.
    let np = "networkpolicy/tbd/egress-internet-https";
    for m in ["k8s.networkpolicy", "k8s.api.read"] {
        assert!(has(&f, np, "applies_to", "deployment/tbd/paging", m), "{m}");
    }
    assert!(
        f.iter()
            .any(|(s, p, v, _)| s == np && p == "allows_egress" && v.ends_with("ports=[443/TCP]")),
        "no 443 egress rule"
    );
    // The manifest names running deployments, each pinned and each source resolving.
    let manifest = records
        .iter()
        .find_map(|r| match r {
            Record::Manifest(m) => Some(m),
            _ => None,
        })
        .unwrap();
    let observed: BTreeSet<_> = records
        .iter()
        .filter_map(|r| match r {
            Record::Observation(o) => Some(o.id()),
            _ => None,
        })
        .collect();
    let mut with_commit = 0;
    for (key, state) in manifest.snapshot().components() {
        let ComponentState::Known { revisions } = state else {
            panic!("{key:?} unknown");
        };
        if revisions
            .iter()
            .any(|r| matches!(r, iohr_evidence::snapshot::Revision::Commit(_)))
        {
            with_commit += 1;
        }
        for s in manifest.sources(key) {
            assert!(
                observed.contains(&s.observation),
                "{key:?} cites a missing observation"
            );
        }
    }
    assert!(
        with_commit >= 10,
        "only {with_commit} deployments carry a commit"
    );
}

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn checkout(root: &Path) {
    write(
        root,
        "docs/adrs/0067-paging-reaches-only-apple.md",
        "---\ntitle: Paging reaches only Apple's push service\nkind: adr\nstatus: proposed\npublic: false\n---\n\n## Decision\n\nThe paging service must reach only Apple's push service.\n\n```decided\n[[decided]]\nsubject = \"deployment/tbd/labs\"\npredicate = \"egress_only\"\ntext = \"api.push.apple.com:443\"\n```\n",
    );
    write(root, "docs/adrs/README.md", "# ADRs\n\nMust not be read.\n");
    write(
        root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/*\"]\n",
    );
    write(
        root,
        "crates/labs/Cargo.toml",
        "[package]\nname = \"tbd-labs\"\n[dependencies]\ntbd-common = { path = \"../common\" }\nserde = \"1\"\n",
    );
    write(
        root,
        "crates/common/Cargo.toml",
        "[package]\nname = \"tbd-common\"\n",
    );
    write(
        root,
        "k8s/base/kustomization.yaml",
        "namespace: tbd\nresources: [labs.yaml]\n",
    );
    write(
        root,
        "k8s/base/labs.yaml",
        r"apiVersion: apps/v1
kind: Deployment
metadata: { name: labs }
spec:
  selector: { matchLabels: { app.kubernetes.io/name: labs } }
  template:
    metadata: { labels: { app.kubernetes.io/name: labs } }
    spec:
      containers:
        - name: labs
          image: ghcr.io/inorbithr/iohr-labs:dev
          env:
            - name: LABS_DATABASE_URL
              valueFrom: { secretKeyRef: { name: labs-db, key: database-url, optional: true } }
---
apiVersion: v1
kind: Service
metadata: { name: labs }
spec:
  selector: { app.kubernetes.io/name: labs }
  ports: [{ port: 50073 }]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: egress-internet-https }
spec:
  podSelector:
    matchExpressions: [{ key: app.kubernetes.io/name, operator: In, values: [paging, labs] }]
  egress:
    - to: [{ ipBlock: { cidr: 0.0.0.0/0, except: [10.0.0.0/8] } }]
      ports: [{ protocol: TCP, port: 443 }]
",
    );
    write(
        root,
        "charts/x/templates/broken.yaml",
        "kind: {{ .Values.kind }}\n",
    );
    write(
        root,
        "devops/envoy/envoy.yaml",
        r#"static_resources:
  listeners:
    - name: edge
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: console
                      routes:
                        - match: { path_separated_prefix: "/v1/labs" }
                          route: { cluster: labs }
  clusters:
    - name: labs
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint: { address: { socket_address: { address: labs, port_value: 50073 } } }
"#,
    );
}

async fn fake_api() -> String {
    async fn list(
        UrlPath(rest): UrlPath<String>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, StatusCode> {
        if headers.get("authorization").and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {TOKEN}"))
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let labs = json!({"app.kubernetes.io/name": "labs"});
        let items = if rest.ends_with("/deployments") {
            json!([{
                "metadata": {"name": "labs", "annotations": {"inorbit.hr/commit": "4e749a9dd42380ba8f54ffb6c8598c3fcd8b6241"}},
                "spec": {"selector": {"matchLabels": labs}, "template": {"metadata": {"labels": labs},
                         "spec": {"containers": [{"image": "ghcr.io/inorbithr/iohr-labs:dev"}]}}},
                "status": {"readyReplicas": 1}
            }])
        } else if rest.ends_with("/pods") {
            json!([{"metadata": {"labels": labs}, "status": {"containerStatuses": [{"imageID":
                "ghcr.io/inorbithr/iohr-labs@sha256:1491aa0d304e501eed580c08cd222120d61d91ac1b1d441ec619bd8cf1ef0019"}]}}])
        } else if rest.ends_with("/services") {
            json!([{"metadata": {"name": "labs"}, "spec": {"selector": labs, "ports": [{"port": 50073}]}}])
        } else {
            json!([])
        };
        Ok(Json(json!({"items": items})))
    }
    let app = Router::new().route("/{*rest}", get(list));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn kubeconfig(dir: &Path, server: &str, token: &str) -> std::path::PathBuf {
    let p = dir.join("kubeconfig");
    std::fs::write(
        &p,
        format!(
            "clusters: [{{name: c, cluster: {{server: \"{server}\"}}}}]\nusers: [{{name: robot, user: {{token: {token}}}}}]\ncontexts: [{{name: test, context: {{cluster: c, user: robot, namespace: tbd}}}}]\ncurrent-context: test\n"
        ),
    )
    .unwrap();
    p
}

#[tokio::test]
async fn a_checkout_and_a_cluster_give_one_linked_record_set() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("core");
    checkout(&repo);
    let server = fake_api().await;
    let policy =
        Policy::from_toml("environment = \"test\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
            .unwrap();
    let req = ObserveRequest {
        repo: Some(repo),
        kubeconfig: Some(kubeconfig(dir.path(), &server, TOKEN)),
        kube_context: None,
        namespaces: Vec::new(),
        host: None,
        decided: None,
        metrics: None,
    };
    let (sink, summary) = observe(&req, Some(&policy)).await.unwrap();
    let records = sink.records();
    assert!(matches!(records[0], Record::Run(_)));
    let classes: BTreeSet<_> = records
        .iter()
        .filter_map(|r| match r {
            Record::Observer(o) => Some(o.class),
            _ => None,
        })
        .collect();
    assert_eq!(
        classes,
        BTreeSet::from([
            ObserverClass::DeterministicExtractor,
            ObserverClass::ExternalSystem
        ])
    );
    for m in [
        "cargo.metadata",
        "k8s.manifest",
        "k8s.networkpolicy",
        "envoy.route",
        "docs.decided",
        "k8s.api.read",
    ] {
        assert!(
            summary.per_method.get(m).is_some_and(|n| *n > 0),
            "{m}: {:?}",
            summary.per_method
        );
    }
    let found = summary.repository.unwrap();
    assert_eq!(found.cargo_manifests, 3);
    assert_eq!(found.envoy_routes, 1);
    assert_eq!(found.decided.documents, 1, "the README is not a document");
    assert_eq!(found.decided.decided, 1);
    assert_eq!(found.decided.constraints, 1);
    assert!(
        found.decided.refused.is_empty(),
        "{:?}",
        found.decided.refused
    );
    assert_eq!(summary.components, Some((1, 1)));
    let f = facts(records);
    assert!(has(
        &f,
        "crate/tbd-labs",
        "depends_on",
        "crate/tbd-common",
        "cargo.metadata"
    ));
    assert!(
        !f.iter().any(|(_, _, v, _)| v == "crate/serde"),
        "a registry crate is not a component"
    );
    // The kustomization's namespace applies to manifests without one.
    let route = "envoy.route/console/path_separated_prefix:/v1/labs";
    assert!(has(
        &f,
        route,
        "routes_to",
        "envoy.cluster/labs",
        "envoy.route"
    ));
    assert!(has(
        &f,
        "envoy.cluster/labs",
        "upstream_service",
        "service/tbd/labs",
        "envoy.route"
    ));
    assert!(has(
        &f,
        "service/tbd/labs",
        "targets",
        "deployment/tbd/labs",
        "k8s.manifest"
    ));
    assert!(has(
        &f,
        "service/tbd/labs",
        "targets",
        "deployment/tbd/labs",
        "k8s.api.read"
    ));
    assert!(has(
        &f,
        "deployment/tbd/labs",
        "reads_secret",
        "secret/tbd/labs-db",
        "k8s.manifest"
    ));
    assert!(has(
        &f,
        "networkpolicy/tbd/egress-internet-https",
        "applies_to",
        "deployment/tbd/labs",
        "k8s.networkpolicy"
    ));
    assert!(has(
        &f,
        "deployment/tbd/labs",
        "built_from_commit",
        "4e749a9dd42380ba8f54ffb6c8598c3fcd8b6241",
        "k8s.api.read"
    ));
    // Every fact from the checkout cites the file it was read from, by repository-relative
    // location, never by absolute path.
    for r in records {
        if let Record::Artifact(a) = r {
            assert!(
                a.artifact().location.starts_with("core:"),
                "{}",
                a.artifact().location
            );
        }
        if let Record::Evidence(i) = r
            && i.method.name.to_string() != "k8s.api.read"
            && matches!(i.reference, EvidenceRef::Observation(_))
        {
            assert!(!i.ancestors.is_empty(), "{i:?} cites no artefact");
        }
    }
    let mut out = Vec::new();
    sink.write_to(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains(TOKEN), "the token never reaches the output");
    assert!(
        !text.contains(dir.path().to_str().unwrap()),
        "no local path reaches the output"
    );
}

#[tokio::test]
async fn the_policy_decides_whether_the_api_server_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let server = fake_api().await;
    let req = ObserveRequest {
        kubeconfig: Some(kubeconfig(dir.path(), &server, TOKEN)),
        ..ObserveRequest::default()
    };
    let closed = Policy::from_toml("environment = \"test\"\n").unwrap();
    let e = observe(&req, Some(&closed)).await.unwrap_err();
    assert!(matches!(e, Error::Policy(_)), "{e}");
    let open =
        Policy::from_toml("environment = \"test\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
            .unwrap();
    let wrong = ObserveRequest {
        kubeconfig: Some(kubeconfig(dir.path(), &server, "wrong")),
        ..ObserveRequest::default()
    };
    let e = observe(&wrong, Some(&open)).await.unwrap_err();
    assert!(e.to_string().contains("401"), "{e}");
    assert!(
        !e.to_string().contains("wrong"),
        "the token is not in the error: {e}"
    );
}
