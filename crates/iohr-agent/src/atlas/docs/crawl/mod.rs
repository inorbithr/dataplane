//! A whole-site crawl (RFC 0163): breadth first from a start URL and the sitemaps its
//! robots.txt names, over the registrable domain (Public Suffix List) and every
//! subdomain a link or redirect reaches. It reuses the site reader's robots.txt and
//! sitemap parsing ([`super::site`]), the HTML tokenizer ([`super::html::outline`]) and
//! the policy-pinned client ([`super::http::ApiClient`]): one client per origin, at most
//! one request a second per host, one at a time.
//!
//! What it keeps is derived only: per page its URL, status, title, type, size, depth and
//! whether it was rendered; per host its robots.txt outcome and counts; every outgoing
//! link with its class; a few public fields of the app store pages, GitHub
//! organisations, packages and API documents it found; the budgets used; and whether it
//! finished. Page text never leaves the process. Public pages only: no credentials are
//! sent, and it runs in the agent, never hosted.

pub mod listings;
pub mod render;
pub mod scope;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{HeaderName, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::DocsError;
use super::html::{self, looks_like_spec};
use super::http::{self, ApiClient, Fetched, Limits, TEXT};
pub use super::site::RATE_PER_MINUTE;
use super::site::{Robots, sitemap_entries};
use crate::policy::Policy;
use crate::tls::TlsContext;
use listings::Target;
use scope::{LinkClass, classify, in_scope, is_media, key, registrable};

/// Most pages a crawl may be given.
pub const MAX_PAGES: usize = 20_000;
/// Longest a crawl may be given, in minutes.
pub const MAX_MINUTES: u64 = 240;
/// Most redirects followed from one URL.
pub const MAX_HOPS: u8 = 10;
/// Most sitemaps read (an index and the sitemaps it lists).
const MAX_SITEMAPS: usize = 50;
/// Most listing reads.
const MAX_LISTINGS: usize = 100;
/// Below this much visible text, with no links, a page is tried in a browser.
const EMPTY_TEXT: usize = 40;
/// The state file is written after this many pages.
const SAVE_EVERY: usize = 25;
/// Accept header for sitemaps.
const XML: &str = "application/xml,text/xml;q=0.9,*/*;q=0.5";
/// Accept header for JSON APIs (GitHub, registries).
const JSON_API: &str = "application/vnd.github+json,application/json;q=0.9";
/// Accept header for API documents.
const ANY: &str = "application/json,application/yaml,text/yaml,text/plain;q=0.8,*/*;q=0.5";

/// The `User-Agent` every request carries: names InOrbit and links a page about it.
#[must_use]
pub fn user_agent() -> String {
    format!(
        "{}/{} (InOrbit; +https://inorbit.hr)",
        super::site::ROBOT,
        env!("CARGO_PKG_VERSION")
    )
}

/// What a crawl may spend. A budget that runs out stops the crawl, which is then marked
/// incomplete and names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budgets {
    /// Page requests (redirects and failures included).
    pub pages: usize,
    /// Distinct hosts read.
    pub hosts: usize,
    /// Wall-clock minutes, summed over resumed runs.
    pub minutes: u64,
    /// Bytes read, robots.txt, sitemaps and listings included.
    pub bytes: u64,
    /// Largest page read, in bytes; a larger one is recorded as too large.
    pub page_bytes: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            pages: 2_000,
            hosts: 50,
            minutes: 30,
            bytes: 200 * 1024 * 1024,
            page_bytes: 5 * 1024 * 1024,
        }
    }
}

impl Budgets {
    /// These budgets within the hard caps (20,000 pages, 4 hours) and at least 1 each.
    #[must_use]
    pub fn capped(self) -> Self {
        Self {
            pages: self.pages.clamp(1, MAX_PAGES),
            hosts: self.hosts.max(1),
            minutes: self.minutes.clamp(1, MAX_MINUTES),
            bytes: self.bytes.max(1),
            page_bytes: self.page_bytes.max(1024),
        }
    }
}

/// Whether pages with no text and no links are tried in a browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Render {
    /// Never.
    Off,
    /// With this browser, or the first Chrome or Chromium found ([`render::find_browser`]).
    Auto(Option<PathBuf>),
}

/// One crawl.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    /// Where it starts; its registrable domain is the scope.
    pub start: Url,
    /// What it may spend.
    pub budgets: Budgets,
    /// The render fallback.
    pub render: Render,
    /// A state file: written as the crawl goes, and resumed from when it exists.
    pub state: Option<PathBuf>,
    /// Requests a minute per host. RFC 0163 sets 60 ([`RATE_PER_MINUTE`]) and the command
    /// line keeps it; only tests against a local fixture raise it.
    pub per_minute: u32,
}

/// One page request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRecord {
    /// The URL requested.
    pub url: String,
    /// The HTTP status (0 when there was no answer).
    pub status: u16,
    /// `<title>`, for HTML.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// The `Content-Type`, without parameters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// Bytes read, or `Content-Length` for a type that was not read.
    pub size: u64,
    /// Links from the start (sitemap entries are at depth 1).
    pub depth: u32,
    /// Whether the page was read through the browser fallback.
    pub rendered: bool,
    /// `<link rel="canonical">`, when it names another URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    /// Where a redirect pointed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirected_to: Option<String>,
    /// Why the page was not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One host the crawl read from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    /// The host name.
    pub host: String,
    /// robots.txt: `rules`, `none`, `deny_all` (401 or 403) or `unreachable`.
    pub robots: String,
    /// robots.txt `Crawl-delay`, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_delay: Option<u64>,
    /// Pages requested.
    pub pages: usize,
    /// Links robots.txt disallowed.
    pub disallowed: usize,
    /// Media links not requested.
    pub media_skipped: usize,
    /// Whether the agent's policy refused the host.
    pub refused: bool,
}

/// A URL in scope that was not requested, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocked {
    /// The URL.
    pub url: String,
    /// `robots.txt`, `policy` or `hosts budget`.
    pub reason: String,
}

/// A link the crawl did not follow: out of scope, `nofollow`, or an API document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outgoing {
    /// The link, without fragment and tracking parameters.
    pub url: String,
    /// What it points at.
    pub class: LinkClass,
    /// The first page it was found on.
    pub from: String,
    /// Whether it was marked `nofollow`.
    pub nofollow: bool,
    /// Whether it is inside the crawl's scope.
    pub in_scope: bool,
}

/// Public fields of one listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listing {
    /// What was read.
    pub url: String,
    /// `app_store`, `github_org`, `npm`, `pypi`, `crate` or `openapi`.
    pub kind: String,
    /// The fields read.
    pub fields: BTreeMap<String, Value>,
    /// Why it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What the crawl spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Used {
    /// The budgets it ran under.
    pub limits: Option<Budgets>,
    /// Page requests.
    pub pages: usize,
    /// Hosts read.
    pub hosts: usize,
    /// Bytes read.
    pub bytes: u64,
    /// Wall-clock seconds.
    pub seconds: u64,
    /// HTTP requests of every kind, retries left out.
    pub requests: u64,
    /// Pages tried in a browser.
    pub renders: usize,
}

/// What a crawl found: derived results only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CrawlResult {
    /// The start URL.
    pub start: String,
    /// The registrable domain in scope.
    pub scope: String,
    /// Whether the crawl ran out of URLs (rather than budget).
    pub complete: bool,
    /// The budgets that stopped it.
    pub stopped_by: Vec<String>,
    /// Every page request, in order.
    pub pages: Vec<PageRecord>,
    /// Every host read.
    pub hosts: Vec<HostRecord>,
    /// URLs in scope not requested.
    pub blocked: Vec<Blocked>,
    /// Links not followed.
    pub links: Vec<Outgoing>,
    /// Listing reads.
    pub listings: Vec<Listing>,
    /// What was spent.
    pub used: Used,
}

impl CrawlResult {
    /// Pages read as HTML with status 200.
    #[must_use]
    pub fn html_pages(&self) -> usize {
        self.pages
            .iter()
            .filter(|p| p.status == 200 && p.content_type.contains("html"))
            .count()
    }

    /// Outgoing links per class.
    #[must_use]
    pub fn link_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for l in &self.links {
            *m.entry(l.class.as_str()).or_insert(0) += 1;
        }
        m
    }
}

/// One URL waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Queued {
    url: String,
    depth: u32,
    hops: u8,
}

/// What a state file holds: the result so far and what is left to do.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    result: CrawlResult,
    queue: VecDeque<Queued>,
    seen: Vec<String>,
    sitemaps: VecDeque<String>,
    sitemaps_seen: Vec<String>,
    origins_seen: Vec<String>,
    listing_targets: Vec<String>,
    seconds: u64,
}

/// Why a crawl could not run at all. A crawl that ran records its failures instead.
#[derive(Debug)]
pub enum CrawlError {
    /// The start URL is not an http(s) URL with a host.
    Start(String),
    /// The state file cannot be read or written.
    State(String),
}

impl fmt::Display for CrawlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(e) => write!(f, "start URL: {e}"),
            Self::State(e) => write!(f, "state file: {e}"),
        }
    }
}

impl std::error::Error for CrawlError {}

/// A body type the crawler reads: HTML, or no type at all.
fn html_or_untyped(ct: &str) -> bool {
    ct.is_empty() || ct.contains("html")
}

/// Any type.
fn anything(_: &str) -> bool {
    true
}

fn origin_of(u: &Url) -> String {
    u.origin().ascii_serialization()
}

fn path_of(u: &Url) -> String {
    let mut p = u.path().to_owned();
    if let Some(q) = u.query() {
        p.push('?');
        p.push_str(q);
    }
    p
}

fn status_of(e: &DocsError) -> u16 {
    match e {
        DocsError::NotFound(_) => 404,
        DocsError::Forbidden(_) => 403,
        DocsError::Unauthorized(_) => 401,
        DocsError::RateLimited { .. } => 429,
        DocsError::Malformed(m) => m
            .rsplit(' ')
            .next()
            .and_then(|s| s.parse().ok())
            .filter(|s| (400..600).contains(s))
            .unwrap_or(0),
        _ => 0,
    }
}

struct Crawler<'a> {
    policy: &'a Policy,
    tls: &'a TlsContext,
    budgets: Budgets,
    per_minute: u32,
    browser: Option<PathBuf>,
    scope: String,
    clients: HashMap<String, Arc<ApiClient>>,
    robots: HashMap<String, Robots>,
    origins_seen: HashSet<String>,
    result: CrawlResult,
    queue: VecDeque<Queued>,
    seen: HashSet<String>,
    sitemaps: VecDeque<String>,
    sitemaps_seen: HashSet<String>,
    link_keys: HashSet<String>,
    listing_targets: BTreeSet<String>,
    started: Instant,
    prior_seconds: u64,
    requests: u64,
    since_save: usize,
}

/// Crawls `cfg.start`'s registrable domain under `policy`.
///
/// # Errors
/// The start URL is unusable, or the state file cannot be read or written.
pub async fn crawl(
    cfg: &CrawlConfig,
    policy: &Policy,
    tls: &TlsContext,
) -> Result<CrawlResult, CrawlError> {
    let start = scope::clean(&cfg.start);
    if !matches!(start.scheme(), "http" | "https") {
        return Err(CrawlError::Start("not http or https".into()));
    }
    if !start.username().is_empty() || start.password().is_some() {
        return Err(CrawlError::Start("must not carry credentials".into()));
    }
    let host = start
        .host_str()
        .ok_or_else(|| CrawlError::Start("no host".into()))?;
    let budgets = cfg.budgets.capped();
    let browser = match &cfg.render {
        Render::Off => None,
        Render::Auto(Some(p)) => Some(p.clone()),
        Render::Auto(None) => render::find_browser(),
    };
    let mut c = Crawler {
        policy,
        tls,
        budgets,
        per_minute: cfg.per_minute.max(1),
        browser,
        scope: registrable(host),
        clients: HashMap::new(),
        robots: HashMap::new(),
        origins_seen: HashSet::new(),
        result: CrawlResult::default(),
        queue: VecDeque::new(),
        seen: HashSet::new(),
        sitemaps: VecDeque::new(),
        sitemaps_seen: HashSet::new(),
        link_keys: HashSet::new(),
        listing_targets: BTreeSet::new(),
        started: Instant::now(),
        prior_seconds: 0,
        requests: 0,
        since_save: 0,
    };
    let resumed = match &cfg.state {
        Some(p) => c.load(p, &start)?,
        None => false,
    };
    if !resumed {
        c.result.start = start.to_string();
        c.result.scope.clone_from(&c.scope);
        c.seen.insert(key(&start));
        c.queue.push_back(Queued {
            url: start.to_string(),
            depth: 0,
            hops: 0,
        });
    }
    c.result.complete = false;
    c.result.stopped_by.clear();
    c.result.used.limits = Some(budgets);
    c.run(cfg.state.as_deref()).await?;
    Ok(c.result)
}

impl Crawler<'_> {
    fn seconds(&self) -> u64 {
        self.prior_seconds + self.started.elapsed().as_secs()
    }

    fn stop(&mut self, budget: &str) {
        if !self.result.stopped_by.iter().any(|b| b == budget) {
            self.result.stopped_by.push(budget.to_owned());
        }
    }

    /// The time or bytes budget that has run out, if one has.
    fn spent(&self) -> Option<&'static str> {
        if self.seconds() >= self.budgets.minutes.saturating_mul(60) {
            return Some("minutes");
        }
        if self.result.used.bytes >= self.budgets.bytes {
            return Some("bytes");
        }
        None
    }

    fn host_mut(&mut self, host: &str) -> &mut HostRecord {
        let at = if let Some(i) = self.result.hosts.iter().position(|h| h.host == host) {
            i
        } else {
            self.result.hosts.push(HostRecord {
                host: host.to_owned(),
                robots: "none".into(),
                ..HostRecord::default()
            });
            self.result.hosts.len() - 1
        };
        &mut self.result.hosts[at]
    }

    fn in_scope(&self, u: &Url) -> bool {
        u.host_str().is_some_and(|h| in_scope(h, &self.scope))
    }

    fn note_link(&mut self, u: &Url, from: &str, nofollow: bool) {
        let k = key(u);
        if listings::target_of(u).is_some() {
            self.listing_targets.insert(scope::clean(u).to_string());
        }
        if !self.link_keys.insert(k) {
            return;
        }
        let in_scope = self.in_scope(u);
        self.result.links.push(Outgoing {
            url: scope::clean(u).to_string(),
            class: classify(u),
            from: from.to_owned(),
            nofollow,
            in_scope,
        });
    }

    fn enqueue(&mut self, u: &Url, depth: u32) {
        if self.seen.insert(key(u)) {
            self.queue.push_back(Queued {
                url: scope::clean(u).to_string(),
                depth,
                hops: 0,
            });
        }
    }

    async fn client(&mut self, origin: &Url) -> Result<Arc<ApiClient>, DocsError> {
        let o = origin_of(origin);
        if let Some(c) = self.clients.get(&o) {
            return Ok(Arc::clone(c));
        }
        let base = Url::parse(&o).map_err(|_| DocsError::Refused("no origin".into()))?;
        let ua = HeaderValue::from_str(&user_agent())
            .map_err(|_| DocsError::Refused("user agent".into()))?;
        let headers: Vec<(HeaderName, HeaderValue)> = vec![(USER_AGENT, ua)];
        let limits = Limits {
            max_retries: 2,
            max_body: self.budgets.page_bytes,
            ..Limits::for_rate(self.per_minute)
        };
        let c = Arc::new(ApiClient::new(base, self.policy, self.tls, headers, limits).await?);
        self.clients.insert(o, Arc::clone(&c));
        Ok(c)
    }

    /// One counted GET.
    async fn get(
        &mut self,
        u: &Url,
        accept: &'static str,
        wanted: fn(&str) -> bool,
    ) -> Result<Fetched, DocsError> {
        let client = self.client(u).await?;
        self.requests += 1;
        let f = client.get_page(&path_of(u), accept, wanted).await?;
        if let Fetched::Page { body, .. } = &f {
            self.result.used.bytes += body.len() as u64;
        }
        Ok(f)
    }

    /// A GET that follows redirects within scope, for robots.txt and sitemaps.
    async fn get_following(
        &mut self,
        u: &Url,
        accept: &'static str,
    ) -> Result<(Url, Fetched), DocsError> {
        let mut at = u.clone();
        for _ in 0..=MAX_HOPS {
            match self.get(&at, accept, anything).await? {
                Fetched::Redirect { location, .. } => {
                    let next = location.and_then(|l| at.join(&l).ok()).ok_or_else(|| {
                        DocsError::Malformed("a redirect without Location".into())
                    })?;
                    if !self.in_scope(&next) {
                        return Err(DocsError::Redirected(format!("out of scope: {next}")));
                    }
                    at = next;
                }
                f => return Ok((at, f)),
            }
        }
        Err(DocsError::Redirected("more than 10 redirects".into()))
    }

    /// Reads robots.txt for a new origin, sets the pace, and queues its sitemaps.
    async fn ensure_robots(&mut self, u: &Url) -> Result<(), DocsError> {
        let o = origin_of(u);
        if self.robots.contains_key(&o) {
            return Ok(());
        }
        let host = u.host_str().unwrap_or_default().to_owned();
        let robots_url = u
            .join("/robots.txt")
            .map_err(|_| DocsError::Refused("no robots.txt URL".into()))?;
        let (robots, label) = match self.get_following(&robots_url, TEXT).await {
            Ok((_, Fetched::Page { body, content_type })) if !content_type.contains("html") => {
                (Robots::parse(&String::from_utf8_lossy(&body)), "rules")
            }
            Ok(_)
            | Err(
                DocsError::NotFound(_)
                | DocsError::Malformed(_)
                | DocsError::Redirected(_)
                | DocsError::TooLarge(_),
            ) => (Robots::default(), "none"),
            Err(DocsError::Forbidden(_) | DocsError::Unauthorized(_)) => {
                (Robots::deny_all(), "deny_all")
            }
            Err(e @ DocsError::Refused(_)) => return Err(e),
            Err(_) => (Robots::deny_all(), "unreachable"),
        };
        if let Some(pm) = robots.per_minute()
            && let Ok(c) = self.client(u).await
        {
            c.slow_to(pm);
        }
        let first = self.origins_seen.insert(o.clone());
        let named: Vec<Url> = robots
            .sitemaps
            .iter()
            .filter_map(|s| Url::parse(s).ok())
            .collect();
        if first {
            if named.is_empty()
                && self.origins_seen.len() == 1
                && let Ok(s) = u.join("/sitemap.xml")
            {
                self.queue_sitemap(&s);
            }
            for s in &named {
                self.queue_sitemap(s);
            }
        }
        let h = self.host_mut(&host);
        // One origin of a host read means the host is not refused, even
        // when a link to its other scheme was.
        h.refused = false;
        if matches!(h.robots.as_str(), "none" | "refused") || label != "none" {
            label.clone_into(&mut h.robots);
        }
        h.crawl_delay = robots.crawl_delay;
        self.robots.insert(o, robots);
        Ok(())
    }

    fn queue_sitemap(&mut self, s: &Url) {
        if self.in_scope(s)
            && !s.path().to_ascii_lowercase().ends_with(".gz")
            && self.sitemaps_seen.len() < MAX_SITEMAPS
            && self.sitemaps_seen.insert(key(s))
        {
            self.sitemaps.push_back(s.to_string());
        }
    }

    async fn read_sitemap(&mut self, s: &str) {
        let Ok(u) = Url::parse(s) else { return };
        if self.ensure_robots(&u).await.is_err() {
            return;
        }
        let allowed = self
            .robots
            .get(&origin_of(&u))
            .is_none_or(|r| r.allows(&path_of(&u)));
        if !allowed {
            return;
        }
        let Ok((_, Fetched::Page { body, .. })) = self.get_following(&u, XML).await else {
            return;
        };
        let (is_index, entries) = sitemap_entries(&String::from_utf8_lossy(&body));
        for (loc, _) in entries {
            let Ok(e) = Url::parse(&loc) else { continue };
            if is_index {
                self.queue_sitemap(&e);
            } else if self.in_scope(&e) {
                if !is_media(&e) {
                    self.enqueue(&e, 1);
                }
            } else {
                self.note_link(&e, s, false);
            }
        }
    }

    async fn run(&mut self, state: Option<&Path>) -> Result<(), CrawlError> {
        loop {
            if let Some(b) = self.spent() {
                self.stop(b);
                break;
            }
            if let Some(s) = self.sitemaps.pop_front() {
                self.read_sitemap(&s).await;
                continue;
            }
            let Some(next) = self.queue.pop_front() else {
                break;
            };
            if self.result.pages.len() >= self.budgets.pages {
                self.queue.push_front(next);
                self.stop("pages");
                break;
            }
            self.visit(next).await;
            self.since_save += 1;
            if self.since_save >= SAVE_EVERY {
                self.since_save = 0;
                if let Some(p) = state {
                    self.save(p)?;
                }
            }
        }
        self.read_listings().await;
        self.result.complete = self.result.stopped_by.is_empty();
        self.result.used.pages = self.result.pages.len();
        self.result.used.hosts = self.result.hosts.iter().filter(|h| h.pages > 0).count();
        self.result.used.seconds = self.seconds();
        self.result.used.requests += self.requests;
        self.requests = 0;
        if let Some(p) = state {
            self.save(p)?;
        }
        Ok(())
    }

    async fn visit(&mut self, q: Queued) {
        let Ok(u) = Url::parse(&q.url) else { return };
        let host = u.host_str().unwrap_or_default().to_owned();
        let known = self.result.hosts.iter().any(|h| h.host == host);
        if !known && self.result.hosts.len() >= self.budgets.hosts {
            self.stop("hosts");
            self.result.blocked.push(Blocked {
                url: q.url,
                reason: "hosts budget".into(),
            });
            return;
        }
        if let Err(e) = self.ensure_robots(&u).await {
            // An origin is refused once; any other origin of this host in
            // the map was read, so the host itself is not refused.
            let other_read = self
                .robots
                .keys()
                .filter_map(|o| Url::parse(o).ok())
                .any(|o| o.host_str() == Some(host.as_str()));
            let h = self.host_mut(&host);
            if !other_read {
                h.refused = true;
                h.robots = "refused".into();
            }
            self.robots.insert(origin_of(&u), Robots::deny_all());
            self.result.blocked.push(Blocked {
                url: q.url,
                reason: format!("policy: {e}"),
            });
            return;
        }
        let allowed = self
            .robots
            .get(&origin_of(&u))
            .is_none_or(|r| r.allows(&path_of(&u)));
        if !allowed {
            self.host_mut(&host).disallowed += 1;
            self.result.blocked.push(Blocked {
                url: q.url,
                reason: "robots.txt".into(),
            });
            return;
        }
        self.host_mut(&host).pages += 1;
        let mut rec = PageRecord {
            url: q.url.clone(),
            depth: q.depth,
            ..PageRecord::default()
        };
        match self.get(&u, TEXT, html_or_untyped).await {
            Ok(Fetched::Page { body, content_type }) => {
                rec.status = 200;
                rec.size = body.len() as u64;
                rec.content_type = if content_type.is_empty() {
                    "text/html".into()
                } else {
                    content_type
                };
                let text = String::from_utf8_lossy(&body).into_owned();
                drop(body);
                self.read_html(&u, &text, &q, &mut rec).await;
            }
            Ok(Fetched::Skipped { content_type, size }) => {
                rec.status = 200;
                rec.content_type = content_type;
                rec.size = size.unwrap_or(0);
                if looks_like_spec(u.path()) {
                    self.listing_targets.insert(u.to_string());
                }
            }
            Ok(Fetched::Redirect { status, location }) => {
                rec.status = status;
                match location.and_then(|l| u.join(&l).ok()) {
                    None => rec.error = Some("a redirect without Location".into()),
                    Some(next) => {
                        let next = scope::clean(&next);
                        rec.redirected_to = Some(next.to_string());
                        self.follow_redirect(&u, &next, &q, &mut rec);
                    }
                }
            }
            Err(e) => {
                rec.status = status_of(&e);
                rec.error = Some(e.to_string());
            }
        }
        self.result.pages.push(rec);
    }

    fn follow_redirect(&mut self, from: &Url, next: &Url, q: &Queued, rec: &mut PageRecord) {
        if !matches!(next.scheme(), "http" | "https") {
            rec.error = Some("a redirect to another scheme".into());
            return;
        }
        if !self.in_scope(next) {
            self.note_link(next, from.as_str(), false);
            return;
        }
        if q.hops >= MAX_HOPS {
            rec.error = Some("more than 10 redirects".into());
            return;
        }
        if is_media(next) {
            return;
        }
        let k = key(next);
        // A redirect to the same key (`/api` to `/api/`) is followed although the key was
        // seen: the seen URL is the one that redirected.
        if k == key(from) || self.seen.insert(k) {
            self.queue.push_front(Queued {
                url: next.to_string(),
                depth: q.depth,
                hops: q.hops + 1,
            });
        }
    }

    async fn read_html(&mut self, u: &Url, text: &str, q: &Queued, rec: &mut PageRecord) {
        let mut o = html::outline(text, u);
        if o.text_chars < EMPTY_TEXT
            && o.links.is_empty()
            && let Some(browser) = self.browser.clone()
            && self.spent().is_none()
        {
            let host = u.host_str().unwrap_or_default().to_owned();
            let port = u.port_or_known_default().unwrap_or(443);
            if let Ok(addr) = http::resolve(self.policy, &host, port).await {
                self.result.used.renders += 1;
                self.requests += 1;
                if let Ok(dom) = render::dump_dom(
                    &browser,
                    u,
                    addr.ip(),
                    &user_agent(),
                    self.budgets.page_bytes,
                )
                .await
                {
                    self.result.used.bytes += dom.len() as u64;
                    o = html::outline(&dom, u);
                    rec.rendered = true;
                }
            }
        }
        rec.title = o.title;
        rec.canonical = o
            .canonical
            .filter(|c| key(c) != key(u))
            .map(|c| c.to_string());
        for s in &o.specs {
            self.listing_targets.insert(scope::clean(s).to_string());
            self.note_link(s, u.as_str(), false);
        }
        for (link, follow) in o.links {
            if !matches!(link.scheme(), "http" | "https") {
                continue;
            }
            let inside = self.in_scope(&link);
            if inside && is_media(&link) {
                if let Some(h) = link.host_str().map(str::to_owned) {
                    self.host_mut(&h).media_skipped += 1;
                }
                continue;
            }
            if inside && follow {
                if looks_like_spec(link.path()) {
                    self.note_link(&link, u.as_str(), false);
                }
                self.enqueue(&link, q.depth + 1);
            } else {
                self.note_link(&link, u.as_str(), !follow);
            }
        }
    }

    async fn read_listings(&mut self) {
        let mut targets: Vec<String> = std::mem::take(&mut self.listing_targets)
            .into_iter()
            .collect();
        // The site's own accounts first (a link naming the scope's first label),
        // so an anonymous rate limit such as GitHub's 60 an hour is spent on
        // them before third-party accounts a blog post links to.
        let label = self
            .scope
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        targets.sort_by_key(|t| label.is_empty() || !t.to_ascii_lowercase().contains(&label));
        // A listing is keyed by the URL it is read from, so links to one
        // account or app from many pages are read once.
        let mut done: HashSet<String> =
            self.result.listings.iter().map(|l| l.url.clone()).collect();
        for t in targets {
            if done.len() >= MAX_LISTINGS {
                break;
            }
            let Ok(link) = Url::parse(&t) else { continue };
            let Some(target) = listings::target_of(&link) else {
                continue;
            };
            let Some(u) = target.url() else { continue };
            if done.contains(u.as_str()) {
                continue;
            }
            if let Some(b) = self.spent() {
                self.stop(b);
                self.listing_targets.insert(t);
                continue;
            }
            done.insert(u.to_string());
            let listing = self.read_listing(&target, &u).await;
            self.result.listings.push(listing);
        }
    }

    async fn read_listing(&mut self, target: &Target, u: &Url) -> Listing {
        let mut l = Listing {
            url: u.to_string(),
            kind: target.kind().into(),
            fields: BTreeMap::new(),
            error: None,
        };
        let accept = match target {
            Target::Store(_) => TEXT,
            Target::Spec(_) => ANY,
            _ => JSON_API,
        };
        if let Target::Store(_) = target {
            if let Ok(()) = self.ensure_robots(u).await {
                let ok = self
                    .robots
                    .get(&origin_of(u))
                    .is_none_or(|r| r.allows(&path_of(u)));
                if !ok {
                    l.error = Some("disallowed by robots.txt".into());
                    return l;
                }
            } else {
                l.error = Some("refused by policy".into());
                return l;
            }
        }
        let mut res = self.get(u, accept, anything).await;
        if let (Target::GitHubOrg(org), Err(DocsError::NotFound(_))) = (target, &res)
            && let Ok(users) = Url::parse(&format!(
                "https://api.github.com/users/{org}/repos?per_page=100"
            ))
        {
            res = self.get(&users, accept, anything).await;
        }
        let body = match res {
            Ok(Fetched::Page { body, .. }) => body,
            Ok(Fetched::Redirect { status, .. }) => {
                l.error = Some(format!("redirected ({status})"));
                return l;
            }
            Ok(Fetched::Skipped { content_type, .. }) => {
                l.error = Some(format!("not read: {content_type}"));
                return l;
            }
            Err(DocsError::Refused(_)) => {
                l.error = Some("refused by policy".into());
                return l;
            }
            Err(e) => {
                let s = status_of(&e);
                l.error = Some(if s == 0 {
                    e.to_string()
                } else {
                    format!("HTTP {s}")
                });
                return l;
            }
        };
        match target {
            Target::Store(_) => {
                l.fields = listings::store_fields(&String::from_utf8_lossy(&body), u);
            }
            Target::Spec(_) => match listings::spec_fields(&body) {
                Ok(f) => l.fields = f,
                Err(e) => l.error = Some(e),
            },
            Target::GitHubOrg(_) | Target::Npm(_) | Target::PyPi(_) | Target::Crate(_) => {
                match serde_json::from_slice::<Value>(&body) {
                    Ok(v) if matches!(target, Target::GitHubOrg(_)) => {
                        l.fields = listings::github_fields(&v);
                    }
                    Ok(v) => l.fields = listings::registry_fields(target, &v),
                    Err(_) => l.error = Some("not JSON".into()),
                }
            }
        }
        l
    }

    fn load(&mut self, p: &Path, start: &Url) -> Result<bool, CrawlError> {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(CrawlError::State(format!("{}: {e}", p.display()))),
        };
        let s: Saved = serde_json::from_slice(&bytes)
            .map_err(|e| CrawlError::State(format!("{}: {e}", p.display())))?;
        if s.result.start != start.as_str() {
            return Err(CrawlError::State(format!(
                "{} is a crawl of {}, not {start}",
                p.display(),
                s.result.start
            )));
        }
        self.link_keys = s
            .result
            .links
            .iter()
            .filter_map(|l| Url::parse(&l.url).ok())
            .map(|u| key(&u))
            .collect();
        self.result = s.result;
        self.queue = s.queue;
        self.seen = s.seen.into_iter().collect();
        self.sitemaps = s.sitemaps;
        self.sitemaps_seen = s.sitemaps_seen.into_iter().collect();
        self.origins_seen = s.origins_seen.into_iter().collect();
        self.listing_targets = s.listing_targets.into_iter().collect();
        self.prior_seconds = s.seconds;
        Ok(true)
    }

    fn save(&mut self, p: &Path) -> Result<(), CrawlError> {
        let mut result = self.result.clone();
        result.used.requests += self.requests;
        let s = Saved {
            result,
            queue: self.queue.clone(),
            seen: self.seen.iter().cloned().collect(),
            sitemaps: self.sitemaps.clone(),
            sitemaps_seen: self.sitemaps_seen.iter().cloned().collect(),
            origins_seen: self.origins_seen.iter().cloned().collect(),
            listing_targets: self.listing_targets.iter().cloned().collect(),
            seconds: self.seconds(),
        };
        let bytes = serde_json::to_vec(&s).map_err(|e| CrawlError::State(e.to_string()))?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, bytes)
            .and_then(|()| std::fs::rename(&tmp, p))
            .map_err(|e| CrawlError::State(format!("{}: {e}", p.display())))
    }
}
