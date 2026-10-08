//! `atlas docs sync` against Confluence Cloud (REST v2), end to end through the agent's
//! configuration and policy, with Confluence played by wiremock from fixtures shaped like
//! the API's documented answers (`tests/fixtures/confluence/`, `__SITE__` replaced by the
//! mock's address). The real API is never called.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use iohr_agent::atlas::docs::Provider;
use iohr_agent::atlas::docs::config::{DocsConfig, DocsSourceConfig};
use iohr_agent::atlas::docs::run::sync_configured;
use iohr_agent::atlas::record::Record;
use iohr_agent::config::AgentConfig;
use iohr_agent::policy::Policy;
use iohr_evidence::digest::ContentDigest;
use iohr_evidence::method::MethodCategory;
use iohr_evidence::vocabulary::Value as EvValue;
use serde_json::Value;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCOUNT: &str = "atlas-reader@acme.example";
const TOKEN: &str = "ATATT-test-token-never-logged";

fn fixture(site: &str, name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/confluence")
        .join(name);
    let text = std::fs::read_to_string(p)
        .unwrap()
        .replace("__SITE__", site);
    serde_json::from_str(&text).unwrap()
}

async fn site() -> MockServer {
    let s = MockServer::start().await;
    let uri = s.uri();
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{ACCOUNT}:{TOKEN}"))
    );
    let ok = |name: &str| ResponseTemplate::new(200).set_body_json(fixture(&uri, name));
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(p.to_owned()))
            .and(header("authorization", basic.as_str()))
    };
    get("/wiki/rest/api/user/current")
        .respond_with(ok("user_current.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/spaces")
        .and(query_param("keys", "ENG"))
        .respond_with(ok("spaces.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages")
        .and(query_param("sort", "-modified-date"))
        .and(query_param("space-id", "98304"))
        .and(query_param_is_missing("cursor"))
        .respond_with(ok("pages_1.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages")
        .and(query_param("cursor", "c2"))
        .respond_with(ok("pages_2.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/blogposts")
        .and(query_param("space-id", "98304"))
        .respond_with(ok("blogposts.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages/101")
        .and(query_param("body-format", "atlas_doc_format"))
        .respond_with(ok("page_101.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages/102")
        .and(query_param("body-format", "atlas_doc_format"))
        .respond_with(ok("page_102.json"))
        .mount(&s)
        .await;
    // Deleted between the listing and the read.
    get("/wiki/api/v2/pages/103")
        .respond_with(ResponseTemplate::new(404).set_body_json(fixture(&uri, "error_404.json")))
        .mount(&s)
        .await;
    get("/wiki/api/v2/blogposts/201")
        .respond_with(ok("blogpost_201.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages/101/labels")
        .respond_with(ok("labels_101.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages/101/attachments")
        .respond_with(ok("attachments_101.json"))
        .mount(&s)
        .await;
    get("/wiki/api/v2/pages/101/footer-comments")
        .respond_with(ok("comments_101.json"))
        .mount(&s)
        .await;
    // The token may not read comments here: comments are off for the rest of the run.
    get("/wiki/api/v2/pages/102/footer-comments")
        .respond_with(ResponseTemplate::new(403).set_body_json(fixture(&uri, "error_403.json")))
        .mount(&s)
        .await;
    for p in [
        "/wiki/api/v2/pages/102/labels",
        "/wiki/api/v2/pages/102/attachments",
        "/wiki/api/v2/blogposts/201/labels",
        "/wiki/api/v2/blogposts/201/attachments",
        "/wiki/api/v2/blogposts/201/footer-comments",
    ] {
        get(p).respond_with(ok("empty.json")).mount(&s).await;
    }
    s
}

fn setup(server: &MockServer) -> (tempfile::TempDir, AgentConfig, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("confluence-token");
    std::fs::write(&token_file, TOKEN).unwrap();
    let mut cfg = AgentConfig::new(
        "https://api.inorbit.hr".parse().unwrap(),
        "t".into(),
        "staging".into(),
    );
    cfg.state_dir = dir.path().join("state");
    cfg.docs = DocsConfig {
        content_dir: None,
        sources: vec![DocsSourceConfig {
            id: "acme-wiki".into(),
            provider: Provider::Confluence,
            token: Some(format!("file:{}", token_file.display())),
            base_url: Some(server.uri().parse().unwrap()),
            account: Some(ACCOUNT.into()),
            spaces: vec!["ENG".into()],
            comments: true,
            requests_per_minute: Some(60_000),
            max_items: None,
        }],
    };
    cfg.validate().unwrap();
    let policy = Policy::from_toml(
        "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n[secrets]\nallow = [\"file:*\"]\n",
    )
    .unwrap();
    (dir, cfg, policy)
}

#[tokio::test]
async fn a_confluence_space_becomes_documentation_evidence() {
    let server = site().await;
    let (dir, cfg, policy) = setup(&server);
    let (sink, outcomes) = sync_configured(&cfg, &policy, &[], false).await.unwrap();
    let o = &outcomes[0];
    assert!(o.error.is_none(), "{:?}", o.error);
    let sum = o.summary.as_ref().unwrap();
    assert_eq!(
        (sum.listed, sum.fetched, sum.gone, sum.failed),
        (4, 3, 1, 0),
        "{sum:?}"
    );
    assert!(sum.complete);

    let records = sink.records();
    let keys: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Entity { id, key } => Some((*id, key.clone())),
            _ => None,
        })
        .collect();
    let mut facts = BTreeSet::new();
    let mut methods = BTreeSet::new();
    for r in records {
        match r {
            Record::Observation(ob) => {
                let s = ob.statement();
                let v = match &s.value {
                    EvValue::Entity(e) => keys[e].clone(),
                    EvValue::Text(t) => t.clone(),
                    EvValue::Int(i) => i.to_string(),
                    other => format!("{other:?}"),
                };
                facts.insert((
                    keys[&s.subject].clone(),
                    s.predicate.name.as_str().to_owned(),
                    v,
                ));
            }
            Record::Evidence(i) => {
                assert_eq!(i.method.category, MethodCategory::Documentation);
                methods.insert(i.method.name.to_string());
            }
            _ => {}
        }
    }
    for m in [
        "confluence.page.read",
        "confluence.comment.read",
        "confluence.space.read",
    ] {
        assert!(methods.contains(m), "{m} in {methods:?}");
    }
    let uri = server.uri();
    let d = |id: &str| format!("doc/acme-wiki/{id}");
    for (s, p, v) in [
        (d("101"), "doc.title", "Deploy runbook".to_owned()),
        (
            d("101"),
            "doc.url",
            format!("{uri}/wiki/spaces/ENG/pages/101/Deploy+runbook"),
        ),
        (d("101"), "doc.parent", d("102")),
        (d("101"), "doc.mentions", d("102")),
        (
            d("101"),
            "doc.links_to",
            "https://ci.acme.example/labs".to_owned(),
        ),
        (d("101"), "doc.in_space", "space/acme-wiki/98304".to_owned()),
        (
            d("101"),
            "doc.author",
            "person/acme-wiki/u-editor".to_owned(),
        ),
        (d("101"), "doc.field.labels", "deploy, runbook".to_owned()),
        (d("101"), "doc.comment_count", "1".to_owned()),
        (d("blogpost:201"), "doc.title", "October freeze".to_owned()),
        (
            "attachment/acme-wiki/att9".to_owned(),
            "attachment.media_type",
            "image/png".to_owned(),
        ),
        (
            "attachment/acme-wiki/att9".to_owned(),
            "attachment.size_bytes",
            "2048".to_owned(),
        ),
        (
            "space/acme-wiki/98304".to_owned(),
            "space.name",
            "Engineering (ENG)".to_owned(),
        ),
    ] {
        assert!(
            facts.contains(&(s.clone(), p.to_owned(), v.clone())),
            "missing ({s}, {p}, {v})"
        );
    }
    assert!(records.iter().any(|r| matches!(r, Record::Artifact(a)
        if a.artifact().location == "confluence:acme-wiki/page/101@v3")));

    let name = &ContentDigest::of_bytes(b"101").to_hex()[7..39];
    let store = dir.path().join("state/docs/acme-wiki/items");
    let md = std::fs::read_to_string(store.join(format!("{name}.md"))).unwrap();
    for want in [
        "# Deploy runbook",
        "## Before you deploy",
        "```sh\nmake deploy ENV=prod\n```",
        "> Never on Fridays.",
        "@user:u-oncall",
    ] {
        assert!(md.contains(want), "{want:?} in\n{md}");
    }
    let mut out = Vec::new();
    sink.write_to(&mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(
        !out.contains("make deploy ENV=prod"),
        "content stays in the store"
    );
    for leak in ["Dana", TOKEN, "Atlas Reader"] {
        assert!(!out.contains(leak) && !md.contains(leak), "{leak}");
    }

    let reqs = server.received_requests().await.unwrap();
    let comments = reqs
        .iter()
        .filter(|r| r.url.path().ends_with("/footer-comments"))
        .count();
    assert_eq!(
        comments, 2,
        "the 403 on page 102 turned comments off for the blog post"
    );
    assert!(
        reqs.iter().all(|r| r.method == wiremock::http::Method::GET),
        "reads only"
    );

    // Nothing changed: the second run reads nothing.
    let before = reqs.len();
    let (_, outcomes) = sync_configured(&cfg, &policy, &[], false).await.unwrap();
    let sum = outcomes[0].summary.as_ref().unwrap();
    assert_eq!((sum.listed, sum.fetched), (0, 0), "{sum:?}");
    let after = server.received_requests().await.unwrap();
    assert!(
        after[before..]
            .iter()
            .all(|r| !r.url.path().contains("/pages/1")),
        "no page read again"
    );
}

#[tokio::test]
async fn a_revoked_token_deletes_the_local_copies() {
    let server = site().await;
    let (dir, cfg, policy) = setup(&server);
    sync_configured(&cfg, &policy, &[], false).await.unwrap();
    let store = dir.path().join("state/docs/acme-wiki");
    assert!(store.join("state.json").exists());
    Mock::given(path("/wiki/rest/api/user/current"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&server)
        .await;
    let (_, outcomes) = sync_configured(&cfg, &policy, &[], false).await.unwrap();
    assert!(outcomes[0].summary.as_ref().unwrap().revoked);
    assert!(!store.exists());
}
