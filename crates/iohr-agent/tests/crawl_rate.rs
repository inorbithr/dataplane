//! `atlas crawl --rate` and `--progress` (RFC 0163): the pace a crawl keeps per host, a
//! robots.txt `Crawl-delay` that is slower winning over it, and the progress lines, with
//! and without a sitemap. The library tests play one site with wiremock and stamp every
//! request as it arrives; the last tests run the real binary against a small server of
//! their own, as a caller such as `iohr init --crawl` does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iohr_agent::atlas::docs::crawl::progress::{Phase, Progress};
use iohr_agent::atlas::docs::crawl::{
    Budgets, CrawlConfig, CrawlResult, DEFAULT_RATE, MAX_RATE, MIN_RATE, Render, crawl_reporting,
    per_minute_for_rate,
};
use iohr_agent::policy::Policy;
use iohr_agent::tls::TlsContext;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

type Log = Arc<Mutex<Vec<(String, Instant)>>>;
type Routes = BTreeMap<&'static str, (u16, String, &'static str)>;

/// Answers by path and stamps the time of every request it gets.
struct Site {
    log: Log,
    routes: Routes,
}

impl Respond for Site {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let path = r.url.path().to_owned();
        let answer = self.routes.get(path.as_str());
        self.log.lock().unwrap().push((path, Instant::now()));
        match answer {
            Some((status, body, ct)) => {
                ResponseTemplate::new(*status).set_body_raw(body.clone(), ct)
            }
            None => ResponseTemplate::new(404),
        }
    }
}

fn html(links: &[&str]) -> String {
    let links: String = links
        .iter()
        .map(|l| format!("<a href=\"{l}\">link</a>"))
        .collect::<Vec<_>>()
        .concat();
    format!(
        "<html><head><title>T</title></head><body><p>Enough words here to count as a page \
         with text, so that nothing is tried in a browser.</p>{links}</body></html>"
    )
}

fn route(routes: &mut Routes, p: &'static str, body: String, ct: &'static str) {
    routes.insert(p, (200, body, ct));
}

struct Ran {
    result: CrawlResult,
    lines: Vec<Progress>,
    log: Log,
}

/// Crawls a site `routes` describes (it is given the site's origin, whose port is known
/// only once the server is up) and keeps every progress line.
async fn run(routes: impl FnOnce(&str) -> Routes, per_minute: u32, pages: usize) -> Ran {
    run_keeping(routes, per_minute, pages, None).await
}

/// [`run`], keeping the pages under `keep` when it is given.
async fn run_keeping(
    routes: impl FnOnce(&str) -> Routes,
    per_minute: u32,
    pages: usize,
    keep: Option<std::path::PathBuf>,
) -> Ran {
    let log: Log = Arc::default();
    let server = MockServer::start().await;
    let origin = format!("http://localhost:{}", server.address().port());
    Mock::given(any())
        .respond_with(Site {
            log: Arc::clone(&log),
            routes: routes(&origin),
        })
        .mount(&server)
        .await;
    let cfg = CrawlConfig {
        start: format!("{origin}/").parse().unwrap(),
        budgets: Budgets {
            pages,
            ..Budgets::default()
        },
        render: Render::Off,
        state: None,
        per_minute,
        keep_pages: keep,
    };
    let policy =
        Policy::from_toml("environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
            .unwrap();
    let tls = TlsContext::new(None).unwrap();
    let mut lines = Vec::new();
    let result = crawl_reporting(&cfg, &policy, &tls, &mut |p| lines.push(p.clone()))
        .await
        .unwrap();
    Ran { result, lines, log }
}

fn robots(extra: &str) -> String {
    format!("User-agent: *\nAllow: /\n{extra}")
}

/// A start page that links to `n` pages, each of which exists.
fn linked_site(n: usize, robots_txt: String) -> Routes {
    const NAMES: [&str; 8] = ["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"];
    let mut r = Routes::new();
    route(&mut r, "/robots.txt", robots_txt, "text/plain");
    route(&mut r, "/", html(&NAMES[..n]), "text/html");
    for p in &NAMES[..n] {
        route(&mut r, p, html(&[]), "text/html");
    }
    r
}

fn gaps(log: &Log, keep: impl Fn(&str) -> bool) -> Vec<Duration> {
    let log = log.lock().unwrap();
    let at: Vec<Instant> = log
        .iter()
        .filter(|(p, _)| keep(p))
        .map(|(_, t)| *t)
        .collect();
    at.windows(2).map(|w| w[1] - w[0]).collect()
}

#[test]
fn the_rate_is_per_second_and_bounded() {
    assert_eq!((MIN_RATE, DEFAULT_RATE, MAX_RATE), (1, 10, 50));
    assert_eq!(per_minute_for_rate(DEFAULT_RATE), 600);
    assert_eq!(per_minute_for_rate(1), 60);
    assert_eq!(per_minute_for_rate(0), 60, "never slower than one a second");
    assert_eq!(per_minute_for_rate(50), 3_000);
    assert_eq!(per_minute_for_rate(5_000), 3_000, "never past the ceiling");
}

#[tokio::test]
async fn requests_are_spaced_to_the_rate_asked() {
    for (rate, slack) in [(10_u32, 0.8_f64), (20, 0.8)] {
        let r = run(
            |_| linked_site(5, robots("")),
            per_minute_for_rate(rate),
            100,
        )
        .await;
        assert!(r.result.complete, "{:?}", r.result.stopped_by);
        // robots.txt, the sitemap that is not there, the start page and five more.
        assert_eq!(r.log.lock().unwrap().len(), 8);
        let gaps = gaps(&r.log, |_| true);
        let interval = Duration::from_secs(1).div_f64(f64::from(rate));
        let least = interval.mul_f64(slack);
        assert!(
            gaps.iter().all(|g| *g >= least),
            "rate {rate}: a gap under {least:?} in {gaps:?}"
        );
        // And not slower than it was asked to be: 7 gaps of one interval, with room for a
        // loaded machine, and a long way below the 7 s a request a second would take.
        let span: Duration = gaps.iter().sum();
        assert!(
            span < interval * 7 + Duration::from_millis(1_500),
            "rate {rate}: {span:?}"
        );
    }
}

#[tokio::test]
async fn a_slower_crawl_delay_wins_over_the_rate() {
    // 10 a second would be 100 ms apart; the site asks for a second.
    let r = run(
        |_| linked_site(2, robots("Crawl-delay: 1\n")),
        per_minute_for_rate(DEFAULT_RATE),
        100,
    )
    .await;
    assert!(r.result.complete, "{:?}", r.result.stopped_by);
    let pages = gaps(&r.log, |p| p != "/robots.txt" && p != "/sitemap.xml");
    assert_eq!(pages.len(), 2, "the start page and two more");
    assert!(
        pages.iter().all(|g| *g >= Duration::from_millis(900)),
        "{pages:?}"
    );
    assert_eq!(r.result.hosts[0].crawl_delay, Some(1));
}

#[tokio::test]
async fn the_slowest_rate_is_one_request_a_second() {
    let r = run(
        |_| linked_site(1, robots("")),
        per_minute_for_rate(MIN_RATE),
        100,
    )
    .await;
    let gaps = gaps(&r.log, |_| true);
    assert_eq!(
        gaps.len(),
        3,
        "robots.txt, the sitemap, the start page and one more"
    );
    assert!(
        gaps.iter().all(|g| *g >= Duration::from_millis(900)),
        "{gaps:?}"
    );
}

fn sitemap(origin: &str, paths: &[&str]) -> String {
    let urls: String = paths
        .iter()
        .map(|p| format!("<url><loc>{origin}{p}</loc></url>"))
        .collect::<Vec<_>>()
        .concat();
    format!(
        "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">{urls}</urlset>"
    )
}

/// The sitemap lists the start page (which is queued already), /a, /b and /c; /c is a
/// 404. The start page also links to /d, which no sitemap lists.
fn site_with_sitemap(origin: &str) -> Routes {
    let mut r = Routes::new();
    route(&mut r, "/robots.txt", robots(""), "text/plain");
    route(
        &mut r,
        "/sitemap.xml",
        sitemap(origin, &["/", "/a", "/b", "/c"]),
        "application/xml",
    );
    route(&mut r, "/", html(&["/d"]), "text/html");
    for p in ["/a", "/b", "/d"] {
        route(&mut r, p, html(&[]), "text/html");
    }
    r.insert("/c", (404, String::new(), "text/html"));
    r
}

#[tokio::test]
async fn progress_gives_a_total_once_a_sitemap_has_said() {
    let r = run(site_with_sitemap, 60_000, 100).await;

    let first = r.lines.first().unwrap();
    assert_eq!(
        (
            first.phase,
            first.read,
            first.failed,
            first.queued,
            first.total
        ),
        (Phase::Pages, 0, 0, 1, None),
        "nothing is known before the sitemap is read"
    );
    assert_eq!(first.scope, "localhost");

    // The start page is read first (its robots.txt is what names the sitemap), so by the
    // time the sitemap is read the start page is done and /d, /a, /b and /c wait.
    let known = r.lines.iter().position(|p| p.total.is_some()).unwrap();
    assert_eq!(
        (
            r.lines[known].read,
            r.lines[known].queued,
            r.lines[known].total
        ),
        (1, 4, Some(5))
    );
    assert!(
        r.lines[known..].iter().all(|p| p.total.is_some()),
        "a total that has been given stays"
    );

    for w in r.lines.windows(2) {
        assert!(w[1].read + w[1].failed >= w[0].read + w[0].failed, "{w:?}");
    }
    for p in &r.lines {
        assert_eq!(p.cap, 100);
        if let Some(t) = p.total {
            assert!(p.read + p.failed <= t, "past the total: {p:?}");
            assert!(t <= p.cap);
        }
    }

    // /d is on no sitemap, so the total grows to hold it; /c is a 404.
    let last = r.lines.last().unwrap();
    assert_eq!(last.phase, Phase::Listings);
    assert_eq!(
        (last.read, last.failed, last.queued, last.total),
        (4, 1, 0, Some(5))
    );
    assert_eq!(r.result.pages.len(), 5);
}

#[tokio::test]
async fn a_sitemap_counts_the_start_page_once() {
    // A start page with no links, and a sitemap that lists it and /a, /b, /c: four pages.
    let r = run(
        |origin| {
            let mut routes = site_with_sitemap(origin);
            route(&mut routes, "/", html(&[]), "text/html");
            routes
        },
        60_000,
        100,
    )
    .await;
    let totals: Vec<usize> = r.lines.iter().filter_map(|p| p.total).collect();
    assert_ne!(totals.len(), 0, "a total was reported");
    assert!(totals.iter().all(|t| *t == 4), "{totals:?}");
    let last = r.lines.last().unwrap();
    assert_eq!((last.read, last.failed, last.queued), (3, 1, 0));
}

#[tokio::test]
async fn a_site_without_a_sitemap_has_no_total_only_a_count() {
    let r = run(|_| linked_site(3, robots("")), 60_000, 100).await;
    assert!(r.result.complete);
    assert!(
        r.lines.iter().all(|p| p.total.is_none()),
        "{:?}",
        r.lines.iter().map(|p| p.total).collect::<Vec<_>>()
    );
    let last = r.lines.last().unwrap();
    assert_eq!((last.read, last.failed, last.queued), (4, 0, 0));
    // The count climbs a page at a time and the queue is what is left.
    assert!(r.lines.iter().any(|p| p.read == 1 && p.queued == 3));
}

#[tokio::test]
async fn the_total_is_never_more_than_the_page_budget() {
    let r = run(
        |origin| {
            let names = ["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"];
            let mut routes = Routes::new();
            route(&mut routes, "/robots.txt", robots(""), "text/plain");
            route(
                &mut routes,
                "/sitemap.xml",
                sitemap(origin, &names),
                "application/xml",
            );
            route(&mut routes, "/", html(&[]), "text/html");
            for p in names {
                route(&mut routes, p, html(&[]), "text/html");
            }
            routes
        },
        60_000,
        3,
    )
    .await;
    assert_eq!(r.result.stopped_by, vec!["pages".to_owned()]);
    let totals: Vec<usize> = r.lines.iter().filter_map(|p| p.total).collect();
    assert_ne!(totals.len(), 0, "a total was reported");
    assert!(totals.iter().all(|t| *t == 3), "{totals:?}");
    let last = r.lines.last().unwrap();
    assert_eq!((last.read, last.cap), (3, 3));
}

#[tokio::test]
async fn a_progress_line_holds_the_scope_and_counts_and_no_url() {
    let r = run(site_with_sitemap, 60_000, 100).await;
    assert_ne!(r.lines.len(), 0, "progress lines were reported");
    for p in &r.lines {
        let line = p.line();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        for k in v.as_object().unwrap().keys() {
            assert!(
                [
                    "event", "v", "scope", "phase", "read", "failed", "queued", "total", "cap"
                ]
                .contains(&k.as_str()),
                "{k} in {line}"
            );
        }
        assert_eq!(v["event"], "progress");
        assert_eq!(v["v"], 1);
        assert_eq!(v["scope"], "localhost");
        assert!(!line.contains("http") && !line.contains('/'), "{line}");
    }
}

// The real binary, as `iohr init --crawl` runs it.

/// Serves `/robots.txt`, `/sitemap.xml` (the start page and `pages` more), the start page
/// and the pages, stamping every request; ends with the test process.
fn serve(pages: usize) -> (u16, Log) {
    use std::io::{BufRead as _, BufReader, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut line = String::new();
            if BufReader::new(&s).read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split(' ').nth(1).unwrap_or("/").to_owned();
            seen.lock().unwrap().push((path.clone(), Instant::now()));
            let origin = format!("http://localhost:{port}");
            let names: Vec<String> = (1..=pages).map(|i| format!("/p{i}")).collect();
            let (status, ct, body) = match path.as_str() {
                "/robots.txt" => (
                    "200 OK",
                    "text/plain",
                    format!("User-agent: *\nAllow: /\nSitemap: {origin}/sitemap.xml\n"),
                ),
                "/sitemap.xml" => {
                    let mut all = vec!["/".to_owned()];
                    all.extend(names.clone());
                    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
                    ("200 OK", "application/xml", sitemap(&origin, &refs))
                }
                "/" => {
                    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                    ("200 OK", "text/html", html(&refs))
                }
                p if names.iter().any(|n| n == p) => ("200 OK", "text/html", html(&[])),
                _ => ("404 Not Found", "text/plain", String::new()),
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\ncontent-type: {ct}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, log)
}

struct Cli {
    code: i32,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

fn crawl_cli(port: u16, extra: &[&str]) -> Cli {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        "environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n",
    )
    .unwrap();
    let out = dir.path().join("crawl.json");
    let t = Instant::now();
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_iohr-agent"))
        .args(["atlas", "crawl", &format!("http://localhost:{port}/")])
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&out)
        .args(["--render", "off"])
        .args(extra)
        .output()
        .unwrap();
    Cli {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        elapsed: t.elapsed(),
    }
}

fn progress_lines(stderr: &str) -> Vec<serde_json::Value> {
    stderr
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn the_binary_keeps_the_rate_and_reports_progress() {
    let (port, log) = serve(8);
    let c = crawl_cli(port, &["--rate", "20", "--progress"]);
    assert_eq!(c.code, 0, "{}", c.stderr);
    assert_eq!(c.stdout, "", "the result went to --out");

    // robots.txt, the sitemap, the start page and eight more: 11 requests, 10 gaps of 50 ms.
    let at: Vec<Instant> = log.lock().unwrap().iter().map(|(_, t)| *t).collect();
    assert_eq!(at.len(), 11);
    let gaps: Vec<Duration> = at.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.iter().all(|g| *g >= Duration::from_millis(40)),
        "{gaps:?}"
    );
    assert!(c.elapsed >= Duration::from_millis(450), "{:?}", c.elapsed);

    let lines = progress_lines(&c.stderr);
    assert!(lines.len() >= 10, "{}", c.stderr);
    assert!(
        lines
            .iter()
            .all(|l| l["event"] == "progress" && l["v"] == 1)
    );
    assert!(lines[0].get("total").is_none());
    assert!(lines.iter().any(|l| l["total"] == 9), "{}", c.stderr);
    let last = lines.last().unwrap();
    assert_eq!(
        (
            last["read"].as_u64(),
            last["failed"].as_u64(),
            last["queued"].as_u64(),
            last["phase"].as_str()
        ),
        (Some(9), Some(0), Some(0), Some("listings"))
    );
    assert!(
        c.stderr
            .lines()
            .filter(|l| l.starts_with('{'))
            .all(|l| !l.contains("http") && !l.contains("/p")),
        "a progress line named a URL"
    );
    // The usual summary is still there, as text.
    assert!(
        c.stderr.contains("atlas crawl localhost: 9 pages"),
        "{}",
        c.stderr
    );
}

#[test]
fn the_binary_says_nothing_extra_without_progress() {
    let (port, _) = serve(2);
    let c = crawl_cli(port, &["--rate", "50"]);
    assert_eq!(c.code, 0, "{}", c.stderr);
    assert!(progress_lines(&c.stderr).is_empty(), "{}", c.stderr);
}

#[test]
fn the_default_rate_is_ten_a_second() {
    let (port, log) = serve(5);
    let c = crawl_cli(port, &[]);
    assert_eq!(c.code, 0, "{}", c.stderr);
    // 8 requests, 7 gaps of 100 ms: more than the 7 s of the old fixed pace is out.
    let at: Vec<Instant> = log.lock().unwrap().iter().map(|(_, t)| *t).collect();
    let gaps: Vec<Duration> = at.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps.len(), 7);
    assert!(
        gaps.iter().all(|g| *g >= Duration::from_millis(80)),
        "{gaps:?}"
    );
    assert!(c.elapsed < Duration::from_secs(4), "{:?}", c.elapsed);
}

#[test]
fn a_rate_out_of_range_is_refused() {
    let (port, log) = serve(1);
    for bad in ["0", "51", "1000", "-1", "fast"] {
        let c = crawl_cli(port, &[&format!("--rate={bad}")]);
        assert_eq!(c.code, 2, "--rate {bad}: {}", c.stderr);
        assert!(c.stderr.contains("--rate"), "{}", c.stderr);
    }
    assert!(log.lock().unwrap().is_empty(), "nothing was requested");
}

#[tokio::test]
async fn kept_pages_are_the_html_read_under_a_name_from_the_url() {
    let dir = tempfile::tempdir().unwrap();
    let ran = run_keeping(
        |_| linked_site(2, robots("")),
        60_000,
        10,
        Some(dir.path().to_path_buf()),
    )
    .await;
    let html_pages: Vec<&str> = ran
        .result
        .pages
        .iter()
        .filter(|p| p.status == 200)
        .map(|p| p.url.as_str())
        .collect();
    assert_eq!(html_pages.len(), 3, "the start page and two linked pages");
    for url in html_pages {
        let file = dir.path().join("pages").join(format!(
            "{}.html",
            iohr_agent::atlas::docs::crawl::kept_name(url)
        ));
        let body = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert!(body.contains("Enough words here"), "{url}");
    }
    assert_eq!(
        iohr_agent::atlas::docs::crawl::kept_name("https://a.test/").len(),
        16
    );
}
