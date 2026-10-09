//! `atlas docs sync` over a static documentation site, end to end through the agent's
//! configuration and policy: robots.txt first, the sitemap index and sitemap it names, then
//! Docusaurus-, `MkDocs`- and Sphinx-shaped pages, all served by wiremock from
//! `tests/fixtures/site/` (`__SITE__` replaced by the mock's address).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use iohr_agent::atlas::docs::Provider;
use iohr_agent::atlas::docs::config::{DocsConfig, DocsSourceConfig};
use iohr_agent::atlas::docs::run::sync_configured;
use iohr_agent::atlas::record::Record;
use iohr_agent::config::AgentConfig;
use iohr_agent::policy::Policy;
use iohr_evidence::digest::ContentDigest;
use iohr_evidence::method::MethodCategory;
use iohr_evidence::vocabulary::Value as EvValue;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture(site: &str, name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/site")
        .join(name);
    std::fs::read_to_string(p)
        .unwrap()
        .replace("__SITE__", site)
}

async fn site() -> MockServer {
    let s = MockServer::start().await;
    let uri = s.uri();
    for (p, f, ty) in [
        ("/robots.txt", "robots.txt", "text/plain"),
        ("/sitemap-index.xml", "sitemap-index.xml", "application/xml"),
        ("/sitemap-docs.xml", "sitemap-docs.xml", "application/xml"),
        ("/docs/intro/", "intro.html", "text/html"),
        ("/docs/deploy/", "deploy.html", "text/html"),
        ("/docs/api.html", "api.html", "text/html"),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_raw(fixture(&uri, f), ty))
            .mount(&s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/docs/moved/"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "/docs/deploy/"))
        .mount(&s)
        .await;
    s
}

fn setup(server: &MockServer) -> (tempfile::TempDir, AgentConfig, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AgentConfig::new(
        "https://api.inorbit.hr".parse().unwrap(),
        "t".into(),
        "staging".into(),
    );
    cfg.state_dir = dir.path().join("state");
    cfg.docs = DocsConfig {
        content_dir: None,
        sources: vec![DocsSourceConfig {
            id: "acme-docs".into(),
            provider: Provider::Site,
            token: None,
            base_url: Some(format!("{}/docs/", server.uri()).parse().unwrap()),
            account: None,
            spaces: Vec::new(),
            comments: false,
            requests_per_minute: Some(60_000),
            max_items: None,
        }],
    };
    cfg.validate().unwrap();
    let policy =
        Policy::from_toml("environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
            .unwrap();
    (dir, cfg, policy)
}

#[tokio::test]
async fn a_docs_site_is_read_through_robots_and_its_sitemap() {
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

    let reqs = server.received_requests().await.unwrap();
    let paths: Vec<String> = reqs.iter().map(|r| r.url.path().to_owned()).collect();
    assert_eq!(
        paths[0], "/robots.txt",
        "robots.txt comes before anything else: {paths:?}"
    );
    for never in [
        "/docs/private/keys/",
        "/blog/launch/",
        "/sitemap-blog.xml.gz",
    ] {
        assert!(
            !paths.iter().any(|p| p == never),
            "{never} was requested: {paths:?}"
        );
    }
    assert!(reqs.iter().all(|r| r.method == wiremock::http::Method::GET));

    let records = sink.records();
    let keys: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Entity { id, key } => Some((*id, key.clone())),
            _ => None,
        })
        .collect();
    let mut facts = BTreeSet::new();
    for r in records {
        match r {
            Record::Observation(ob) => {
                let s = ob.statement();
                let v = match &s.value {
                    EvValue::Entity(e) => keys[e].clone(),
                    EvValue::Text(t) => t.clone(),
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
                assert!(
                    i.method.name.to_string().starts_with("site."),
                    "{}",
                    i.method.name
                );
            }
            _ => {}
        }
    }
    let uri = server.uri();
    let d = |p: &str| format!("doc/acme-docs/{p}");
    for (s, p, v) in [
        (d("/docs/intro/"), "doc.title", "Introduction".to_owned()),
        (d("/docs/intro/"), "doc.url", format!("{uri}/docs/intro/")),
        (d("/docs/intro/"), "doc.mentions", d("/docs/deploy/")),
        (
            d("/docs/intro/"),
            "doc.links_to",
            "https://backstage.acme.example/catalog".to_owned(),
        ),
        (
            d("/docs/intro/"),
            "doc.updated_at",
            "2026-10-01T09:00:00Z".to_owned(),
        ),
        (d("/docs/deploy/"), "doc.title", "Deploy".to_owned()),
        (d("/docs/deploy/"), "doc.mentions", d("/docs/intro/")),
        (d("/docs/api.html"), "doc.title", "API reference".to_owned()),
    ] {
        assert!(
            facts.contains(&(s.clone(), p.to_owned(), v.clone())),
            "missing ({s}, {p}, {v}) in {facts:?}"
        );
    }
    // No navigation link (Blog) became a fact.
    assert!(!facts.iter().any(|(_, _, v)| v.contains("/blog/")));

    let store = dir.path().join("state/docs/acme-docs/items");
    let read = |id: &str| {
        let name = &ContentDigest::of_bytes(id.as_bytes()).to_hex()[7..39];
        std::fs::read_to_string(store.join(format!("{name}.md"))).unwrap()
    };
    let intro = read("/docs/intro/");
    assert!(
        intro.starts_with("# Introduction\n\nAcme runs **labs** behind Envoy."),
        "{intro}"
    );
    for chrome in ["Sidebar", "Copyright", "Next", "never-read", "Docs\n"] {
        assert!(!intro.contains(chrome), "{chrome:?} in {intro}");
    }
    let deploy = read("/docs/deploy/");
    assert!(
        deploy.contains("```sh\nmake deploy ENV=prod CANARY-site-body\n```"),
        "{deploy}"
    );
    assert!(
        deploy.contains("1. Check CI\n1. Watch the dashboard"),
        "{deploy}"
    );
    assert!(!deploy.contains('¶'));
    let api = read("/docs/api.html");
    assert!(
        api.contains("acme.deploy(env)") && api.contains("Deploys to *env*."),
        "{api}"
    );

    let mut out = Vec::new();
    sink.write_to(&mut out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains("CANARY-site-body"));

    // Second run: only the page without a lastmod is read again, and it did not change.
    let (_, outcomes) = sync_configured(&cfg, &policy, &[], false).await.unwrap();
    let sum = outcomes[0].summary.as_ref().unwrap();
    assert_eq!((sum.listed, sum.fetched, sum.changed), (1, 1, 0), "{sum:?}");
}

#[tokio::test]
async fn a_site_that_disallows_everything_is_not_read() {
    let s = MockServer::start().await;
    Mock::given(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("User-agent: iohr-agent\nDisallow: /\n", "text/plain"),
        )
        .mount(&s)
        .await;
    Mock::given(path("/sitemap.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!("<urlset><url><loc>{}/docs/a/</loc></url></urlset>", s.uri()),
            "application/xml",
        ))
        .mount(&s)
        .await;
    let (_dir, cfg, policy) = setup(&s);
    let (_, outcomes) = sync_configured(&cfg, &policy, &[], false).await.unwrap();
    let sum = outcomes[0].summary.as_ref().unwrap();
    assert_eq!((sum.listed, sum.fetched), (0, 0), "{sum:?}");
    let paths: Vec<String> = s
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert!(!paths.iter().any(|p| p.starts_with("/docs/")), "{paths:?}");
}
