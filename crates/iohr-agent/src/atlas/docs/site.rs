//! A static documentation site (Docusaurus, `MkDocs`, Sphinx, `ReadMe`, Hugo, an internal
//! handbook), read the way a polite crawler reads it: `robots.txt` first (its rules for
//! `iohr-agent`, else for `*`, and its `Crawl-delay`), then the sitemaps it names (or
//! `/sitemap.xml`), then each page the sitemap lists that sits under the configured root
//! and that robots allows. No link following beyond the sitemap, no JavaScript, no
//! credential: a site that needs a login is not read this way.
//!
//! A page's change time is the sitemap's `<lastmod>`. A page without one is read on every
//! run (its digest says whether it changed). Redirects are not followed: a sitemap entry
//! that redirects is skipped as gone, since the page it points to is listed on its own.

use std::collections::BTreeMap;
use std::sync::Mutex;

use iohr_evidence::time::Timestamp;
use url::Url;

use super::html;
use super::http::{ApiClient, Limits};
use super::{Batch, DocsError, DocsSource, Document, ItemKind, ItemRef, SourceIdentity, Space};
use crate::policy::Policy;
use crate::tls::TlsContext;

/// One request a second, unless robots.txt asks for slower.
pub const RATE_PER_MINUTE: u32 = 60;
/// The name robots.txt rules are matched against.
pub const ROBOT: &str = "iohr-agent";
const PAGE: usize = 200;
/// Most sitemaps followed (an index and the sitemaps it lists).
const MAX_SITEMAPS: usize = 50;
/// Most pages listed from one site.
const MAX_URLS: usize = 50_000;

/// One robots.txt group: its user agents, its rules, its crawl delay.
type Group = (Vec<String>, Vec<(bool, String)>, Option<u64>);
/// The pages a site's sitemaps list, with their change times.
type Listed = Vec<(String, Option<Timestamp>)>;

/// Rules from robots.txt for this agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Robots {
    /// `(allow, path prefix)`, longest prefix wins, allow wins a tie.
    rules: Vec<(bool, String)>,
    /// `Crawl-delay`, in seconds.
    pub crawl_delay: Option<u64>,
    /// `Sitemap:` lines.
    pub sitemaps: Vec<String>,
}

impl Robots {
    /// Parses robots.txt: the group naming `iohr-agent` if there is one, else `*`.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut groups: Vec<Group> = Vec::new();
        let mut sitemaps = Vec::new();
        let mut in_agents = false;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "user-agent" => {
                    if !in_agents {
                        groups.push((Vec::new(), Vec::new(), None));
                    }
                    in_agents = true;
                    if let Some(g) = groups.last_mut() {
                        g.0.push(v.to_ascii_lowercase());
                    }
                }
                "allow" | "disallow" => {
                    in_agents = false;
                    if let Some(g) = groups.last_mut()
                        && !v.is_empty()
                    {
                        g.1.push((k == "allow", v.to_owned()));
                    }
                }
                "crawl-delay" => {
                    in_agents = false;
                    if let Some(g) = groups.last_mut() {
                        g.2 = v.split('.').next().and_then(|s| s.parse().ok());
                    }
                }
                "sitemap" => sitemaps.push(
                    line[line.find(':').map_or(0, |i| i + 1)..]
                        .trim()
                        .to_owned(),
                ),
                _ => in_agents = false,
            }
        }
        let pick = groups
            .iter()
            .find(|g| g.0.iter().any(|a| a == ROBOT))
            .or_else(|| groups.iter().find(|g| g.0.iter().any(|a| a == "*")));
        Self {
            rules: pick.map(|g| g.1.clone()).unwrap_or_default(),
            crawl_delay: pick.and_then(|g| g.2),
            sitemaps,
        }
    }

    /// Whether `path` (with its query) may be fetched: the longest matching rule wins, and
    /// allow wins a tie (RFC 9309). `*` matches any run of characters, `$` ends a rule.
    #[must_use]
    pub fn allows(&self, path: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for (allow, pattern) in &self.rules {
            if robots_match(pattern, path) {
                let better = match best {
                    None => true,
                    Some((len, a)) => pattern.len() > len || (pattern.len() == len && *allow && !a),
                };
                if better {
                    best = Some((pattern.len(), *allow));
                }
            }
        }
        best.is_none_or(|(_, allow)| allow)
    }
}

/// RFC 9309 matching: a prefix match where `*` is any run of characters and a final `$`
/// anchors the end.
fn robots_match(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    let Some((first, rest)) = parts.split_first() else {
        return true;
    };
    let Some(mut tail) = path.strip_prefix(first) else {
        return false;
    };
    for (i, part) in rest.iter().enumerate() {
        let last = i + 1 == rest.len();
        if last && anchored {
            return tail.ends_with(part);
        }
        match tail.find(part) {
            Some(at) => tail = &tail[at + part.len()..],
            None => return false,
        }
    }
    !anchored || tail.is_empty()
}

/// `(loc, lastmod)` pairs of a urlset, or the locs of a sitemap index.
fn sitemap_entries(xml: &str) -> (bool, Vec<(String, Option<Timestamp>)>) {
    let index = xml.contains("<sitemapindex");
    let tag = if index { "sitemap" } else { "url" };
    let mut out = Vec::new();
    let open = format!("<{tag}>");
    let open_attr = format!("<{tag} ");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(start) = rest.find(&open).or_else(|| rest.find(&open_attr)) {
        let body = &rest[start..];
        let end = body.find(&close).unwrap_or(body.len());
        let entry = &body[..end];
        if let Some(loc) = inner(entry, "loc") {
            let lastmod = inner(entry, "lastmod").and_then(|t| parse_lastmod(&t));
            out.push((loc, lastmod));
        }
        rest = &body[end.min(body.len())..];
        if end == body.len() {
            break;
        }
        rest = &rest[close.len().min(rest.len())..];
    }
    (index, out)
}

fn inner(s: &str, tag: &str) -> Option<String> {
    let a = s.find(&format!("<{tag}>"))? + tag.len() + 2;
    let b = s[a..].find(&format!("</{tag}>"))? + a;
    let v = s[a..b].trim();
    let v = v
        .strip_prefix("<![CDATA[")
        .and_then(|x| x.strip_suffix("]]>"))
        .unwrap_or(v);
    Some(html::decode(v.trim()))
}

/// W3C datetime: a full timestamp, or a date (taken as midnight UTC).
fn parse_lastmod(t: &str) -> Option<Timestamp> {
    chrono::DateTime::parse_from_rfc3339(t)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(t.get(..10)?, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|d| d.and_utc())
        })
}

/// A documentation site under one root URL.
#[derive(Debug)]
pub struct Site {
    api: ApiClient,
    root: Url,
    robots: Mutex<Option<Robots>>,
    urls: Mutex<Option<Listed>>,
}

impl Site {
    /// A source over an existing client; `root` is the site (or a section of it).
    #[must_use]
    pub fn new(api: ApiClient, root: Url) -> Self {
        Self {
            api,
            root,
            robots: Mutex::new(None),
            urls: Mutex::new(None),
        }
    }

    /// Connects to `root` after the policy admitted its host. robots.txt's `Crawl-delay`
    /// lowers the pace further when it is read.
    ///
    /// # Errors
    /// The policy refuses the host.
    pub async fn connect(
        root: Url,
        policy: &Policy,
        tls: &TlsContext,
        limits: Limits,
    ) -> Result<Self, DocsError> {
        let mut root = root;
        if !root.path().ends_with('/') {
            let p = format!("{}/", root.path());
            root.set_path(&p);
        }
        let origin: Url = root
            .join("/")
            .map_err(|_| DocsError::Refused("the site URL has no origin".into()))?;
        let api = ApiClient::new(origin, policy, tls, Vec::new(), limits).await?;
        let site = Self::new(api, root);
        // Honour Crawl-delay from the start: read robots.txt before any page.
        let robots = site.robots().await?;
        if let Some(d) = robots.crawl_delay.filter(|d| *d > 0) {
            let per_minute = u32::try_from(60 / d.min(60)).unwrap_or(1).max(1);
            site.api.slow_to(per_minute);
        }
        Ok(site)
    }

    /// The client, for its counts.
    #[must_use]
    pub const fn client(&self) -> &ApiClient {
        &self.api
    }

    async fn robots(&self) -> Result<Robots, DocsError> {
        if let Some(r) = self
            .robots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Ok(r);
        }
        let r = match self.api.get_text("/robots.txt").await {
            Ok(text) => Robots::parse(&text),
            Err(DocsError::NotFound(_) | DocsError::Redirected(_)) => Robots::default(),
            // A site that forbids robots.txt itself is read as forbidding everything.
            Err(DocsError::Forbidden(_) | DocsError::Unauthorized(_)) => Robots {
                rules: vec![(false, "/".into())],
                ..Robots::default()
            },
            Err(e) => return Err(e),
        };
        *self
            .robots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r.clone());
        Ok(r)
    }

    fn under_root(&self, u: &Url) -> bool {
        u.origin() == self.root.origin() && u.path().starts_with(self.root.path())
    }

    /// Every page the sitemaps list under the root that robots allows, read once a run.
    async fn urls(&self) -> Result<Vec<(String, Option<Timestamp>)>, DocsError> {
        if let Some(u) = self
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Ok(u);
        }
        let robots = self.robots().await?;
        let mut queue: Vec<String> = robots
            .sitemaps
            .iter()
            .filter_map(|s| Url::parse(s).ok())
            .filter(|u| u.origin() == self.root.origin())
            .map(|u| u.to_string())
            .collect();
        if queue.is_empty() {
            queue.push(
                self.root
                    .join("/sitemap.xml")
                    .map_err(|_| DocsError::Refused("sitemap URL".into()))?
                    .to_string(),
            );
        }
        let mut seen = 0usize;
        let mut pages: BTreeMap<String, Option<Timestamp>> = BTreeMap::new();
        let mut found_any = false;
        while let Some(sm) = queue.pop() {
            seen += 1;
            if seen > MAX_SITEMAPS {
                tracing::warn!("docs: more sitemaps than the agent follows; the rest are skipped");
                break;
            }
            if std::path::Path::new(&sm)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
            {
                tracing::warn!("docs: a gzipped sitemap is not read; serve it uncompressed");
                continue;
            }
            let xml = match self.api.get_text(&sm).await {
                Ok(x) => x,
                Err(DocsError::NotFound(_) | DocsError::Redirected(_)) => continue,
                Err(e) => return Err(e),
            };
            found_any = true;
            let (index, entries) = sitemap_entries(&xml);
            for (loc, lastmod) in entries {
                let Ok(u) = Url::parse(&loc) else { continue };
                if index {
                    if u.origin() == self.root.origin() {
                        queue.push(u.to_string());
                    }
                    continue;
                }
                let path_q = match u.query() {
                    Some(q) => format!("{}?{q}", u.path()),
                    None => u.path().to_owned(),
                };
                if self.under_root(&u) && robots.allows(&path_q) && pages.len() < MAX_URLS {
                    let mut u = u;
                    u.set_fragment(None);
                    pages.insert(u.to_string(), lastmod);
                }
            }
        }
        if !found_any {
            return Err(DocsError::NotFound(
                "the site has no sitemap the agent can read".into(),
            ));
        }
        let list: Vec<(String, Option<Timestamp>)> = pages.into_iter().collect();
        *self
            .urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(list.clone());
        Ok(list)
    }

    /// An item id: the page's path (and query) under the origin.
    fn id_of(u: &Url) -> String {
        match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_owned(),
        }
    }
}

impl DocsSource for Site {
    fn provider(&self) -> &'static str {
        "site"
    }

    async fn identity(&self) -> Result<SourceIdentity, DocsError> {
        // No credential: the reader is the agent itself, as robots.txt knows it.
        self.robots().await?;
        Ok(SourceIdentity {
            principal: format!("robot:{ROBOT}"),
            workspace: self.root.host_str().map(str::to_owned),
            scopes: vec!["public_read".into()],
        })
    }

    fn spaces(
        &self,
        _cursor: Option<String>,
    ) -> impl std::future::Future<Output = Result<Batch<Space>, DocsError>> + Send {
        std::future::ready(Ok(Batch {
            items: vec![Space {
                id: self.root.host_str().unwrap_or("site").to_owned(),
                name: self.root.host_str().unwrap_or("site").to_owned(),
                url: Some(self.root.to_string()),
            }],
            next: None,
        }))
    }

    async fn changed(
        &self,
        since: Option<Timestamp>,
        cursor: Option<String>,
    ) -> Result<Batch<ItemRef>, DocsError> {
        let urls = self.urls().await?;
        let start: usize = match cursor.as_deref() {
            None => 0,
            Some(c) => c
                .parse()
                .map_err(|_| DocsError::Malformed("a cursor this source never gave".into()))?,
        };
        let page: Vec<ItemRef> = urls
            .iter()
            .skip(start)
            .take(PAGE)
            .filter(|(_, lastmod)| match (since, lastmod) {
                (Some(s), Some(m)) => *m >= s,
                _ => true,
            })
            .filter_map(|(u, lastmod)| {
                Url::parse(u).ok().map(|u| ItemRef {
                    id: Self::id_of(&u),
                    kind: ItemKind::Page,
                    updated: *lastmod,
                })
            })
            .collect();
        let next = (start + PAGE < urls.len()).then(|| (start + PAGE).to_string());
        Ok(Batch { items: page, next })
    }

    async fn fetch(&self, item: &ItemRef) -> Result<Document, DocsError> {
        let url = self.api.url(&item.id)?;
        if !self.under_root(&url) || !self.robots().await?.allows(&item.id) {
            return Err(DocsError::Forbidden(format!(
                "GET {}: outside the root or disallowed by robots.txt",
                url.path()
            )));
        }
        let text = match self.api.get_text(&item.id).await {
            Err(DocsError::Redirected(why)) => return Err(DocsError::NotFound(why)),
            other => other?,
        };
        let page = html::read(&text, &url, &self.root);
        let mentions = page
            .internal
            .iter()
            .filter_map(|l| Url::parse(l).ok())
            .map(|u| Self::id_of(&u))
            .filter(|id| *id != item.id)
            .collect();
        Ok(Document {
            id: item.id.clone(),
            kind: ItemKind::Page,
            title: if page.title.is_empty() {
                item.id.clone()
            } else {
                page.title
            },
            url: Some(url.to_string()),
            parent: None,
            database: None,
            space: self.root.host_str().map(str::to_owned),
            created: None,
            updated: item.updated,
            version: None,
            authors: Vec::new(),
            markdown: page.markdown,
            fields: BTreeMap::new(),
            links: page.links.into_iter().collect(),
            mentions,
            attachments: Vec::new(),
            comments: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_rules_pick_our_group_and_the_longest_match() {
        let r = Robots::parse(
            "User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nUser-agent: iohr-agent\nDisallow: /private/\nAllow: /private/public/\nDisallow: /*.pdf$\nCrawl-delay: 2\nSitemap: https://d.example/sitemap-index.xml\n",
        );
        assert!(r.allows("/guide/"));
        assert!(!r.allows("/private/x"));
        assert!(r.allows("/private/public/y"));
        assert_eq!(r.crawl_delay, Some(2));
        assert_eq!(r.sitemaps, ["https://d.example/sitemap-index.xml"]);
        assert!(!r.allows("/files/a.pdf") && r.allows("/files/a.pdf.html"));
        let star = Robots::parse("User-agent: *\nDisallow: /admin\n");
        assert!(!star.allows("/admin/x") && star.allows("/docs"));
        assert!(Robots::parse("").allows("/anything"));
    }

    #[test]
    fn sitemaps_and_indexes_are_read() {
        let (index, e) = sitemap_entries(
            "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://d.example/a/</loc><lastmod>2026-10-01</lastmod></url><url><loc>https://d.example/b?x=1&amp;y=2</loc></url></urlset>",
        );
        assert!(!index);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].1.unwrap().to_rfc3339(), "2026-10-01T00:00:00+00:00");
        assert_eq!(e[1].0, "https://d.example/b?x=1&y=2");
        let (index, e) = sitemap_entries(
            "<sitemapindex><sitemap><loc>https://d.example/s1.xml</loc></sitemap></sitemapindex>",
        );
        assert!(index && e.len() == 1);
    }
}
