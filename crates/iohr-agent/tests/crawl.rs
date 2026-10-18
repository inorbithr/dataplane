//! `atlas crawl` (RFC 0163) over a local fixture site: two hosts of one registrable domain
//! (`localhost:A` and `docs.localhost:B`, both served by wiremock on 127.0.0.1), links,
//! a subdomain, redirects in and out of scope, a robots.txt disallow, a sitemap, an API
//! document, a page that only has content after JavaScript (rendered by a stand-in
//! browser script), a budget stop and a resumed run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::BTreeSet;

use iohr_agent::atlas::docs::crawl::{
    Budgets, CrawlConfig, CrawlResult, Render, crawl, scope::LinkClass,
};
use iohr_agent::policy::Policy;
use iohr_agent::tls::TlsContext;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Site {
    main: MockServer,
    docs: MockServer,
}

impl Site {
    fn main_url(&self) -> String {
        format!("http://localhost:{}", self.main.address().port())
    }
    fn docs_url(&self) -> String {
        format!("http://docs.localhost:{}", self.docs.address().port())
    }
}

async fn page(s: &MockServer, p: &str, body: String) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/html; charset=utf-8"))
        .mount(s)
        .await;
}

async fn redirect(s: &MockServer, p: &str, to: &str) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(301).insert_header("location", to))
        .mount(s)
        .await;
}

async fn site() -> Site {
    let main = MockServer::start().await;
    let docs = MockServer::start().await;
    let site = Site { main, docs };
    let m = site.main_url();
    let d = site.docs_url();
    let s = &site.main;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!("User-agent: *\nDisallow: /private/\n\nSitemap: {m}/sitemap.xml\n"),
            "text/plain",
        ))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/sitemap.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(
                "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\
                 <url><loc>{m}/from-sitemap</loc></url>\
                 <url><loc>https://partner.example/landing</loc></url></urlset>"
            ),
            "application/xml",
        ))
        .mount(s)
        .await;
    page(
        s,
        "/",
        format!(
            "<html><head><title>Acme</title></head><body>\
             <nav><a href=\"/about?utm_source=nav#team\">About</a><a href=\"/private/keys\">Keys</a>\
             <a href=\"/old\">Old</a><a href=\"/out\">Out</a><a href=\"{d}/\">Docs</a>\
             <a href=\"/js\">App</a><a rel=\"nofollow\" href=\"/login\">Sign in</a></nav>\
             <img src=\"/logo.png\"><a href=\"/press/photo.jpg\">Photo</a>\
             <a href=\"https://www.linkedin.com/company/acme\">LinkedIn</a>\
             <a href=\"mailto:hi@acme.example\">Mail</a>\
             <p>Acme builds tools for people who build things, and says so here at length.</p>\
             </body></html>"
        ),
    )
    .await;
    page(
        s,
        "/about",
        "<html><head><title>About</title></head><body><p>About Acme, a company of some size and some age.</p><a href=\"/\">Home</a></body></html>".into(),
    )
    .await;
    page(
        s,
        "/from-sitemap",
        "<html><head><title>Listed</title></head><body><p>Only the sitemap links to this page; no other page on the site does.</p></body></html>".into(),
    )
    .await;
    page(
        s,
        "/moved",
        "<html><head><title>Moved</title></head><body><p>The page that the old address now points to, with enough words to count as text.</p></body></html>".into(),
    )
    .await;
    page(
        s,
        "/private/keys",
        "<html><body>never read</body></html>".into(),
    )
    .await;
    page(
        s,
        "/js",
        "<html><head><title>App</title><script src=\"/app.js\"></script></head><body><div id=\"root\"></div></body></html>".into(),
    )
    .await;
    page(
        s,
        "/from-js",
        "<html><head><title>Reached by script</title></head><body><p>A page that only the rendered DOM links to, never the static HTML.</p></body></html>".into(),
    )
    .await;
    redirect(s, "/old", "/moved").await;
    redirect(s, "/out", "https://gitlab.com/acme").await;

    let s = &site.docs;
    page(
        s,
        "/",
        "<html><head><title>Docs</title></head><body><p>The documentation for the Acme tools, with a reference.</p>\
         <a href=\"/api\">API</a><a href=\"/openapi.yaml\">OpenAPI</a>\
         <a href=\"https://github.com/acme\">Code</a><a href=\"https://github.com/acme/tools/issues\">Issues</a></body></html>"
            .into(),
    )
    .await;
    redirect(s, "/api", "/api/").await;
    page(
        s,
        "/api/",
        "<html><head><title>API reference</title></head><body><p>Every endpoint of the Acme API, described with its parameters and answers.</p></body></html>".into(),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "openapi: 3.0.3\ninfo:\n  title: Acme API\n  version: 1.2.0\nservers:\n  - url: https://api.acme.example\npaths:\n  /things:\n    get: {}\n    post: {}\n  /things/{id}:\n    get: {}\n",
            "application/yaml",
        ))
        .mount(s)
        .await;
    site
}

/// A stand-in for Chrome's `--dump-dom`: prints the DOM a script would have built.
fn fake_browser(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("chrome");
    std::fs::write(
        &p,
        "#!/bin/sh\ncat <<'EOF'\n<html><head><title>App</title></head><body><main><h1>The app</h1>\
         <p>Built in the browser by a script, with a link the static page did not have.</p>\
         <a href=\"/from-js\">More</a></main></body></html>\nEOF\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

fn policy() -> Policy {
    Policy::from_toml("environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
        .unwrap()
}

fn config(site: &Site, dir: &std::path::Path, budgets: Budgets) -> CrawlConfig {
    CrawlConfig {
        start: format!("{}/", site.main_url()).parse().unwrap(),
        budgets,
        render: Render::Auto(Some(fake_browser(dir))),
        state: Some(dir.join("state.json")),
        per_minute: 60_000,
    }
}

fn titles(r: &CrawlResult) -> BTreeSet<String> {
    r.pages
        .iter()
        .filter(|p| !p.title.is_empty())
        .map(|p| p.title.clone())
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn a_site_and_its_subdomain_are_crawled_within_scope() {
    let site = site().await;
    let dir = tempfile::tempdir().unwrap();
    let tls = TlsContext::new(None).unwrap();
    let r = crawl(
        &config(&site, dir.path(), Budgets::default()),
        &policy(),
        &tls,
    )
    .await
    .unwrap();
    let m = site.main_url();
    let d = site.docs_url();

    assert_eq!(r.scope, "localhost");
    assert!(r.complete, "{:?}", r.stopped_by);
    assert_eq!(
        titles(&r),
        [
            "API reference",
            "About",
            "Acme",
            "App",
            "Docs",
            "Listed",
            "Moved",
            "Reached by script"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    );

    // The JavaScript-only page was rendered; nothing else was.
    let rendered: Vec<&str> = r
        .pages
        .iter()
        .filter(|p| p.rendered)
        .map(|p| p.url.as_str())
        .collect();
    assert_eq!(rendered, vec![format!("{m}/js")]);
    assert_eq!(r.used.renders, 1);

    // Redirects: in scope followed (and `/api` to `/api/` although the keys are equal),
    // out of scope recorded as an outgoing link.
    let old = r
        .pages
        .iter()
        .find(|p| p.url == format!("{m}/old"))
        .unwrap();
    assert_eq!(
        (old.status, old.redirected_to.as_deref()),
        (301, Some(format!("{m}/moved").as_str()))
    );
    assert!(
        r.pages
            .iter()
            .any(|p| p.url == format!("{d}/api/") && p.status == 200)
    );
    let gitlab = r
        .links
        .iter()
        .find(|l| l.url == "https://gitlab.com/acme")
        .unwrap();
    assert_eq!(
        (gitlab.class, gitlab.in_scope),
        (LinkClass::CodeHost, false)
    );

    // robots.txt: the disallowed page is listed as blocked and never requested.
    assert!(
        r.blocked
            .iter()
            .any(|b| b.url == format!("{m}/private/keys") && b.reason == "robots.txt")
    );
    let main_paths: Vec<String> = site
        .main
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|q| q.url.path().to_owned())
        .collect();
    assert_eq!(main_paths[0], "/robots.txt", "{main_paths:?}");
    for never in [
        "/private/keys",
        "/login",
        "/logo.png",
        "/press/photo.jpg",
        "/app.js",
    ] {
        assert!(
            !main_paths.iter().any(|p| p == never),
            "{never}: {main_paths:?}"
        );
    }
    let docs_paths: Vec<String> = site
        .docs
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|q| q.url.path().to_owned())
        .collect();
    assert_eq!(docs_paths[0], "/robots.txt", "{docs_paths:?}");

    // The tracking parameter and fragment were dropped: About was read once.
    assert_eq!(r.pages.iter().filter(|p| p.title == "About").count(), 1);
    assert!(main_paths.iter().all(|p| !p.contains("utm_")));

    // Hosts.
    let hosts: BTreeSet<&str> = r.hosts.iter().map(|h| h.host.as_str()).collect();
    assert_eq!(hosts, BTreeSet::from(["localhost", "docs.localhost"]));
    let main_host = r.hosts.iter().find(|h| h.host == "localhost").unwrap();
    assert_eq!(
        (main_host.robots.as_str(), main_host.disallowed),
        ("rules", 1)
    );
    assert_eq!(
        main_host.media_skipped, 1,
        "only <a> links count; the <img> is not followed: {main_host:?}"
    );
    assert_eq!(
        r.hosts
            .iter()
            .find(|h| h.host == "docs.localhost")
            .unwrap()
            .robots,
        "none"
    );

    // Outgoing links and their classes; nofollow listed, not followed.
    let login = r
        .links
        .iter()
        .find(|l| l.url == format!("{m}/login"))
        .unwrap();
    assert!(login.nofollow && login.in_scope);
    let partner = r
        .links
        .iter()
        .find(|l| l.url == "https://partner.example/landing")
        .unwrap();
    assert_eq!(partner.class, LinkClass::Other);
    assert!(r.links.iter().any(|l| l.url.contains("linkedin.com")));
    assert!(r.links.iter().all(|l| !l.url.starts_with("mailto:")));

    // The API document: requested as a page (not HTML, so recorded with its type), then
    // read as a listing and reduced to counts.
    let spec_page = r
        .pages
        .iter()
        .find(|p| p.url == format!("{d}/openapi.yaml"))
        .unwrap();
    assert_eq!(spec_page.content_type, "application/yaml");
    let spec = r.listings.iter().find(|l| l.kind == "openapi").unwrap();
    assert!(spec.error.is_none(), "{spec:?}");
    assert_eq!(spec.fields["title"], "Acme API");
    assert_eq!(spec.fields["operations"], 3);
    assert_eq!(spec.fields["servers"], 1);

    // Two links to one GitHub account are one listing, read from the API URL; this
    // test's policy does not bind api.github.com, so it is recorded as refused.
    let orgs: Vec<_> = r
        .listings
        .iter()
        .filter(|l| l.kind == "github_org")
        .collect();
    assert_eq!(orgs.len(), 1, "{orgs:?}");
    assert_eq!(
        orgs[0].url,
        "https://api.github.com/orgs/acme/repos?per_page=100"
    );
    assert_eq!(orgs[0].error.as_deref(), Some("refused by policy"));

    // Derived results only: no page text in the output.
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("company of some size"));
    assert!(r.used.requests > 0 && r.used.bytes > 0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_budget_stops_the_crawl_and_a_second_run_continues_it() {
    let site = site().await;
    let dir = tempfile::tempdir().unwrap();
    let tls = TlsContext::new(None).unwrap();
    let small = Budgets {
        pages: 3,
        ..Budgets::default()
    };
    let first = crawl(&config(&site, dir.path(), small), &policy(), &tls)
        .await
        .unwrap();
    assert!(!first.complete);
    assert_eq!(first.stopped_by, vec!["pages".to_owned()]);
    assert_eq!(first.pages.len(), 3);
    assert!(dir.path().join("state.json").is_file());

    let second = crawl(
        &config(&site, dir.path(), Budgets::default()),
        &policy(),
        &tls,
    )
    .await
    .unwrap();
    assert!(second.complete, "{:?}", second.stopped_by);
    assert_eq!(second.stopped_by, Vec::<String>::new());
    assert!(second.titles_contain("Reached by script"));
    let urls: Vec<&str> = second.pages.iter().map(|p| p.url.as_str()).collect();
    let unique: BTreeSet<&str> = urls.iter().copied().collect();
    assert_eq!(urls.len(), unique.len(), "a page was read twice: {urls:?}");
    assert!(second.used.requests > first.used.requests);

    // A state file of another crawl is refused, not mixed in.
    let mut other = config(&site, dir.path(), Budgets::default());
    other.start = format!("{}/", site.docs_url()).parse().unwrap();
    assert!(crawl(&other, &policy(), &tls).await.is_err());
}

#[tokio::test]
async fn a_host_the_policy_refuses_is_recorded_not_read() {
    let site = site().await;
    let dir = tempfile::tempdir().unwrap();
    let tls = TlsContext::new(None).unwrap();
    let deny =
        Policy::from_toml("environment = \"staging\"\n[networks]\nallow = [\"10.0.0.0/8\"]\n")
            .unwrap();
    let mut cfg = config(&site, dir.path(), Budgets::default());
    cfg.render = Render::Off;
    cfg.state = None;
    let r = crawl(&cfg, &deny, &tls).await.unwrap();
    assert_eq!(r.pages.len(), 0);
    assert_eq!(r.blocked.len(), 1);
    assert!(r.blocked[0].reason.starts_with("policy"), "{:?}", r.blocked);
    assert!(r.hosts[0].refused);
    assert!(site.main.received_requests().await.unwrap().is_empty());
}

trait Titles {
    fn titles_contain(&self, t: &str) -> bool;
}

impl Titles for CrawlResult {
    fn titles_contain(&self, t: &str) -> bool {
        self.pages.iter().any(|p| p.title == t)
    }
}
