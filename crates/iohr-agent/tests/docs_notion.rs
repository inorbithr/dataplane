//! `atlas docs sync` against Notion, end to end through the agent's configuration and
//! policy, with Notion played by wiremock from fixtures shaped like the API's documented
//! answers (`tests/fixtures/notion/`). The real API is never called.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use iohr_agent::atlas::docs::Provider;
use iohr_agent::atlas::docs::config::{DocsConfig, DocsSourceConfig};
use iohr_agent::atlas::docs::run::sync_configured;
use iohr_agent::atlas::record::{Record, Sink};
use iohr_agent::config::AgentConfig;
use iohr_agent::policy::Policy;
use iohr_evidence::digest::ContentDigest;
use iohr_evidence::evidence::EvidenceRef;
use iohr_evidence::method::MethodCategory;
use iohr_evidence::observer::ObserverClass;
use iohr_evidence::vocabulary::Value as EvValue;
use serde_json::Value;
use wiremock::matchers::{
    body_partial_json, header, method, path, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "ntn_test_token_never_logged";
const P: &str = "11111111-1111-4111-8111-111111111111";
const C: &str = "22222222-2222-4222-8222-222222222222";
const D: &str = "33333333-3333-4333-8333-333333333333";
const R: &str = "44444444-4444-4444-8444-444444444444";
const T: &str = "55555555-5555-4555-8555-555555555555";
const TB: &str = "66666666-6666-4666-8666-666666666666";

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/notion")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn ok(name: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(fixture(name))
}

/// Every request must carry the token and the API version; anything else falls through
/// to wiremock's 404, which the test would see as a gone item.
fn notion(m: &str, p: &str) -> wiremock::MockBuilder {
    Mock::given(method(m))
        .and(path(p))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("notion-version", "2025-09-03"))
}

async fn workspace() -> MockServer {
    let s = MockServer::start().await;
    notion("GET", "/v1/users/me")
        .respond_with(ok("users_me.json"))
        .mount(&s)
        .await;
    notion("POST", "/v1/search")
        .and(body_partial_json(
            serde_json::json!({"filter": {"value": "page"}}),
        ))
        .respond_with(ok("search_pages.json"))
        .mount(&s)
        .await;
    notion("POST", "/v1/search")
        .and(body_partial_json(
            serde_json::json!({"filter": {"value": "data_source"}}),
        ))
        .respond_with(ok("search_sources.json"))
        .mount(&s)
        .await;
    for (id, f) in [
        (P, "page_runbook.json"),
        (C, "page_architecture.json"),
        (R, "page_row_labs.json"),
    ] {
        notion("GET", &format!("/v1/pages/{id}"))
            .respond_with(ok(f))
            .mount(&s)
            .await;
    }
    notion("GET", &format!("/v1/blocks/{P}/children"))
        .and(query_param_is_missing("start_cursor"))
        .respond_with(ok("blocks_runbook_1.json"))
        .mount(&s)
        .await;
    notion("GET", &format!("/v1/blocks/{P}/children"))
        .and(query_param("start_cursor", "cursor-2"))
        .respond_with(ok("blocks_runbook_2.json"))
        .mount(&s)
        .await;
    notion("GET", &format!("/v1/blocks/{T}/children"))
        .respond_with(ok("blocks_toggle.json"))
        .mount(&s)
        .await;
    notion("GET", &format!("/v1/blocks/{TB}/children"))
        .respond_with(ok("blocks_table.json"))
        .mount(&s)
        .await;
    for id in [C, R] {
        notion("GET", &format!("/v1/blocks/{id}/children"))
            .respond_with(ok("blocks_empty.json"))
            .mount(&s)
            .await;
    }
    notion("GET", "/v1/comments")
        .and(query_param("block_id", P))
        .respond_with(ok("comments_runbook.json"))
        .mount(&s)
        .await;
    notion("GET", "/v1/comments")
        .and(query_param("block_id", C))
        .respond_with(ok("comments_empty.json"))
        .mount(&s)
        .await;
    // The integration may not read comments on the row: a 403 turns comments off.
    notion("GET", "/v1/comments")
        .and(query_param("block_id", R))
        .respond_with(ResponseTemplate::new(403).set_body_json(fixture("error_403.json")))
        .mount(&s)
        .await;
    notion("GET", &format!("/v1/data_sources/{D}"))
        .respond_with(ok("data_source_services.json"))
        .mount(&s)
        .await;
    s
}

struct Setup {
    _dir: tempfile::TempDir,
    cfg: AgentConfig,
    policy: Policy,
    store: std::path::PathBuf,
}

fn setup(server: &MockServer, secrets_allow: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("notion-token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let mut cfg = AgentConfig::new(
        "https://api.inorbit.hr".parse().unwrap(),
        "docs-test".into(),
        "staging".into(),
    );
    cfg.state_dir = dir.path().join("state");
    cfg.docs = DocsConfig {
        content_dir: None,
        sources: vec![DocsSourceConfig {
            id: "acme-notion".into(),
            provider: Provider::Notion,
            token: Some(format!("file:{}", token_file.display())),
            base_url: Some(server.uri().parse().unwrap()),
            account: None,
            spaces: Vec::new(),
            comments: true,
            requests_per_minute: Some(60_000),
            max_items: None,
        }],
    };
    cfg.validate().unwrap();
    let policy = Policy::from_toml(&format!(
        "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n[secrets]\nallow = [\"{secrets_allow}\"]\n"
    ))
    .unwrap();
    let store = dir.path().join("state/docs/acme-notion");
    Setup {
        _dir: dir,
        cfg,
        policy,
        store,
    }
}

fn jsonl(sink: &Sink) -> String {
    let mut out = Vec::new();
    sink.write_to(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// `(subject key, predicate, value)` for every observation.
fn facts(records: &[Record]) -> BTreeSet<(String, String, String)> {
    let keys: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Entity { id, key } => Some((*id, key.clone())),
            _ => None,
        })
        .collect();
    records
        .iter()
        .filter_map(|r| match r {
            Record::Observation(o) => {
                let s = o.statement();
                let v = match &s.value {
                    EvValue::Entity(e) => keys[e].clone(),
                    EvValue::Text(t) => t.clone(),
                    EvValue::Int(i) => i.to_string(),
                    other => format!("{other:?}"),
                };
                Some((
                    keys[&s.subject].clone(),
                    s.predicate.name.as_str().to_owned(),
                    v,
                ))
            }
            _ => None,
        })
        .collect()
}

fn stored(store: &Path, id: &str) -> String {
    let name = &ContentDigest::of_bytes(id.as_bytes()).to_hex()[7..39];
    std::fs::read_to_string(store.join("items").join(format!("{name}.md"))).unwrap()
}

#[tokio::test]
async fn a_notion_workspace_becomes_documentation_evidence() {
    let server = workspace().await;
    let s = setup(&server, "file:*");
    let (sink, outcomes) = sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    let o = &outcomes[0];
    assert!(o.error.is_none(), "{:?}", o.error);
    let sum = o.summary.as_ref().unwrap();
    assert_eq!(
        (sum.listed, sum.fetched, sum.changed, sum.failed, sum.gone),
        (4, 4, 4, 0, 0),
        "{sum:?}"
    );
    assert!(sum.complete);
    assert_eq!(sum.workspace.as_deref(), Some("Acme Engineering"));

    let records = sink.records();
    let Record::Run(run) = &records[0] else {
        panic!("the run record comes first")
    };
    assert_eq!(run.docs.len(), 1);
    assert_eq!(run.docs[0].provider, "notion");

    // Every evidence item: a documentation method of a deterministic reader, never proving.
    let mut methods = BTreeSet::new();
    for r in records {
        if let Record::Evidence(i) = r {
            assert_eq!(i.method.category, MethodCategory::Documentation);
            assert!(!i.method.category.may_prove());
            assert_eq!(i.class, ObserverClass::DeterministicExtractor);
            methods.insert(i.method.name.to_string());
        }
        if let Record::Observer(ob) = r {
            assert_eq!(ob.name, "notion-reader");
        }
    }
    for m in [
        "notion.page.read",
        "notion.row.read",
        "notion.database.read",
        "notion.comment.read",
        "notion.space.read",
    ] {
        assert!(methods.contains(m), "{m} in {methods:?}");
    }

    // The runbook: markdown in the store, its digest in the evidence.
    let runbook = stored(&s.store, P);
    for want in [
        "# Labs runbook",
        "## Restart",
        "[dashboard](https://grafana.acme.example/d/labs)",
        "```bash\nkubectl -n tbd rollout restart deploy/labs\n```",
        "- [x] Tell #ops",
        "- Why it happens\n  *The pool runs out of connections.*",
        "| Signal | Action |\n|---|---|\n| 503 \\| burst | restart |",
        "[file: design.pdf]",
        "[image: Architecture](https://cdn.acme.example/arch.png)",
        "- [page: Labs architecture]",
    ] {
        assert!(runbook.contains(want), "{want:?} missing from:\n{runbook}");
    }
    let digest = ContentDigest::of_bytes(runbook.as_bytes());
    assert!(records.iter().any(|r| matches!(r, Record::Artifact(a)
        if a.artifact().digest == digest
            && a.artifact().location == format!("notion:acme-notion/page/{P}@2026-10-07T10:00:00Z"))));

    let f = facts(records);
    let doc = |id: &str| format!("doc/acme-notion/{id}");
    for (s_, p, v) in [
        (doc(P), "doc.title", "Labs runbook".to_owned()),
        (
            doc(P),
            "doc.links_to",
            "https://grafana.acme.example/d/labs".to_owned(),
        ),
        (doc(P), "doc.mentions", doc(R)),
        (doc(P), "doc.mentions", doc(C)),
        (doc(P), "doc.author", "person/acme-notion/u-1".to_owned()),
        (
            doc(P),
            "doc.in_space",
            "space/acme-notion/workspace".to_owned(),
        ),
        (doc(P), "doc.comment_count", "1".to_owned()),
        (doc(C), "doc.parent", doc(P)),
        (doc(R), "doc.kind", "row".to_owned()),
        (doc(R), "doc.in_database", doc(D)),
        (doc(R), "doc.field.status", "Done".to_owned()),
        (doc(R), "doc.field.tier", "critical".to_owned()),
        (doc(R), "doc.field.owner", "user u-5".to_owned()),
        (doc(R), "doc.field.sla", "99.9".to_owned()),
        (doc(R), "doc.mentions", doc(P)),
        (
            doc(R),
            "doc.links_to",
            "https://github.com/acme/labs".to_owned(),
        ),
        (doc(D), "doc.kind", "database".to_owned()),
        (
            doc(D),
            "doc.field.status",
            "status: Planned, Done".to_owned(),
        ),
        (doc(D), "doc.parent", doc(P)),
        (
            "space/acme-notion/workspace".to_owned(),
            "space.name",
            "Acme Engineering".to_owned(),
        ),
        (
            "attachment/acme-notion/a0000000-0000-4000-8000-000000000005".to_owned(),
            "attachment.name",
            "design.pdf".to_owned(),
        ),
    ] {
        assert!(
            f.contains(&(s_.clone(), p.to_owned(), v.clone())),
            "missing ({s_}, {p}, {v})"
        );
    }
    // Every observation cites the artefact it was read from.
    for r in records {
        if let Record::Evidence(i) = r
            && matches!(i.reference, EvidenceRef::Observation(_))
        {
            assert_eq!(i.ancestors.len(), 1);
        }
    }

    // What never leaves the store: the body, the signed file link, contact fields, the token.
    let out = jsonl(&sink);
    assert!(
        !out.contains("kubectl -n tbd rollout restart"),
        "content stays in the store"
    );
    assert!(!out.contains("X-Amz-Signature") && !runbook.contains("X-Amz-Signature"));
    let row = stored(&s.store, R);
    for leak in ["oncall-labs@acme.example", "+385 1 555 0100"] {
        assert!(!out.contains(leak) && !row.contains(leak), "{leak}");
    }
    assert!(!out.contains(TOKEN));
    let state = std::fs::read_to_string(s.store.join("state.json")).unwrap();
    assert!(!state.contains(TOKEN) && !state.contains("kubectl"));

    // The 403 on the row's comments turned comments off: no request for D's.
    let comment_calls = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/comments")
        .count();
    assert_eq!(comment_calls, 3);
}

#[tokio::test]
async fn the_second_run_reads_nothing_that_did_not_change() {
    let server = workspace().await;
    let s = setup(&server, "file:*");
    sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    let before = server.received_requests().await.unwrap().len();
    let (_, outcomes) = sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    let sum = outcomes[0].summary.as_ref().unwrap();
    assert_eq!((sum.listed, sum.fetched), (0, 0), "{sum:?}");
    assert!(sum.complete);
    let after = server.received_requests().await.unwrap();
    let new: Vec<String> = after[before..]
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect();
    assert!(
        new.iter()
            .all(|r| r == "GET /v1/users/me" || r == "POST /v1/search"),
        "{new:?}"
    );
    // A full run lists everything again and still reads nothing unchanged.
    let (_, outcomes) = sync_configured(&s.cfg, &s.policy, &[], true).await.unwrap();
    let sum = outcomes[0].summary.as_ref().unwrap();
    assert_eq!(
        (sum.listed, sum.fetched, sum.unchanged, sum.gone),
        (4, 0, 4, 0),
        "{sum:?}"
    );
}

#[tokio::test]
async fn a_revoked_token_deletes_the_local_copies() {
    let server = workspace().await;
    let s = setup(&server, "file:*");
    sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    assert!(s.store.join("state.json").exists());
    Mock::given(path("/v1/users/me"))
        .respond_with(ResponseTemplate::new(401).set_body_json(fixture("error_401.json")))
        .with_priority(1)
        .mount(&server)
        .await;
    let (_, outcomes) = sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    assert!(outcomes[0].summary.as_ref().unwrap().revoked);
    assert!(!s.store.exists(), "the store is gone with the credential");
}

#[tokio::test]
async fn the_policy_decides_which_credentials_and_hosts_are_used() {
    let server = workspace().await;
    let s = setup(&server, "env:OTHER");
    let (_, outcomes) = sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    let e = outcomes[0].error.as_deref().unwrap();
    assert!(e.contains("[secrets] allow"), "{e}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "nothing is asked before the policy agrees"
    );

    let mut s = setup(&server, "file:*");
    s.policy =
        Policy::from_toml("environment = \"staging\"\n[secrets]\nallow = [\"file:*\"]\n").unwrap();
    let (_, outcomes) = sync_configured(&s.cfg, &s.policy, &[], false)
        .await
        .unwrap();
    let e = outcomes[0].error.as_deref().unwrap();
    assert!(e.contains("refused"), "{e}");
    assert!(server.received_requests().await.unwrap().is_empty());

    let e = sync_configured(&s.cfg, &s.policy, &["nope".into()], false)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("no docs source"), "{e}");
}
