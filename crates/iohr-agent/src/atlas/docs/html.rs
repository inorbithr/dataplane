//! A documentation page's HTML to markdown, deterministically and without a browser: find
//! the main content the way the common generators mark it (Docusaurus and `MkDocs` put it in
//! `<article>`, Sphinx in `role="main"` or `div.body`, `ReadMe` in `.markdown-body` or
//! `.rm-Article`, the rest in `<main>`), drop navigation, scripts and chrome, and render
//! headings, paragraphs, lists, code, tables, quotes and links. Not a general HTML parser:
//! a tolerant tokenizer that never fails, only reads less.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use url::Url;

/// A page, read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// The first `<h1>` of the content, else `<title>`.
    pub title: String,
    /// The content as markdown (without the title).
    pub markdown: String,
    /// Absolute links leaving the site.
    pub links: BTreeSet<String>,
    /// Absolute links to other pages of the site (same origin, under its root).
    pub internal: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Text(String),
    Open {
        name: String,
        attrs: Vec<(String, String)>,
        closed: bool,
    },
    Close(String),
}

const SKIP: [&str; 14] = [
    "script", "style", "noscript", "nav", "header", "footer", "aside", "svg", "form", "button",
    "template", "iframe", "select", "head",
];
const VOID: [&str; 12] = [
    "br", "hr", "img", "input", "meta", "link", "source", "wbr", "area", "base", "col", "embed",
];
/// Classes of chrome inside the content: heading anchors, edit links, pagers, breadcrumbs.
const CHROME: [&str; 9] = [
    "headerlink",
    "hash-link",
    "theme-edit-this-page",
    "pagination-nav",
    "breadcrumbs",
    "md-source-file",
    "theme-doc-toc",
    "rm-Pagination",
    "visually-hidden",
];

fn tokenize(html: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let b = html.as_bytes();
    let mut i = 0;
    let mut text_start = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if text_start < i {
            out.push(Tok::Text(html[text_start..i].to_owned()));
        }
        let rest = &html[i..];
        if rest.starts_with("<!--") {
            i = rest.find("-->").map_or(b.len(), |e| i + e + 3);
            text_start = i;
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            i = rest.find('>').map_or(b.len(), |e| i + e + 1);
            text_start = i;
            continue;
        }
        let Some(end) = tag_end(rest) else {
            // A lone '<' is text.
            i += 1;
            continue;
        };
        let inner = &rest[1..end];
        i += end + 1;
        text_start = i;
        if let Some(name) = inner.strip_prefix('/') {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() {
                out.push(Tok::Close(name));
            }
            continue;
        }
        let closed = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let name_end = inner
            .find(|c: char| c.is_whitespace())
            .unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            continue;
        }
        let attrs = parse_attrs(&inner[name_end..]);
        let raw = matches!(name.as_str(), "script" | "style");
        out.push(Tok::Open {
            name: name.clone(),
            attrs,
            closed: closed || VOID.contains(&name.as_str()),
        });
        if raw {
            // Raw text: skip to the closing tag.
            let close = format!("</{name}");
            let lower = html[i..].to_ascii_lowercase();
            i = lower.find(&close).map_or(b.len(), |p| i + p);
            text_start = i;
        }
    }
    if text_start < b.len() {
        out.push(Tok::Text(html[text_start..].to_owned()));
    }
    out
}

/// The index of the `>` that ends the tag starting at `s[0] == '<'`, outside quotes.
fn tag_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || !(bytes[1].is_ascii_alphabetic() || bytes[1] == b'/') {
        return None;
    }
    let mut quote = 0u8;
    for (at, &ch) in bytes.iter().enumerate().skip(1) {
        match (quote, ch) {
            (0, b'"' | b'\'') => quote = ch,
            (0, b'>') => return Some(at),
            (open, close) if open == close => quote = 0,
            _ => {}
        }
    }
    None
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' {
            i += 1;
        }
        if start == i {
            break;
        }
        let key = s[start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut val = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                s[vs..i].clone_into(&mut val);
                i += 1;
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                s[vs..i].clone_into(&mut val);
            }
        }
        out.push((key, decode(&val)));
    }
    out
}

/// Decodes the entities documentation uses; an unknown one stays as written.
#[must_use]
pub fn decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let name = &rest[1..end];
        let ch = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            "ndash" => Some('–'),
            "mdash" => Some('—'),
            "hellip" => Some('…'),
            "rsquo" => Some('’'),
            "lsquo" => Some('‘'),
            "rdquo" => Some('”'),
            "ldquo" => Some('“'),
            "para" => Some('¶'),
            "copy" => Some('©'),
            _ => name.strip_prefix('#').and_then(|n| {
                let v = match n.strip_prefix(['x', 'X']) {
                    Some(h) => u32::from_str_radix(h, 16).ok(),
                    None => n.parse().ok(),
                };
                v.and_then(char::from_u32)
            }),
        };
        if let Some(c) = ch {
            out.push(c);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

fn attr<'a>(attrs: &'a [(String, String)], k: &str) -> Option<&'a str> {
    attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

fn has_class(attrs: &[(String, String)], c: &str) -> bool {
    attr(attrs, "class").is_some_and(|v| v.split_whitespace().any(|x| x == c))
}

/// The index range of the main content's tokens.
fn main_range(toks: &[Tok]) -> (usize, usize) {
    type Pick = fn(&str, &[(String, String)]) -> bool;
    let picks: [Pick; 5] = [
        |n, _| n == "article",
        |_, a| attr(a, "role") == Some("main"),
        |n, _| n == "main",
        |_, a| {
            [
                "markdown-body",
                "rm-Article",
                "theme-doc-markdown",
                "md-content",
                "body",
                "document",
            ]
            .iter()
            .any(|c| has_class(a, c))
        },
        |n, _| n == "body",
    ];
    for pick in picks {
        for (i, t) in toks.iter().enumerate() {
            if let Tok::Open {
                name,
                attrs,
                closed: false,
            } = t
                && pick(name, attrs)
            {
                return (i + 1, matching_close(toks, i, name));
            }
        }
    }
    (0, toks.len())
}

fn matching_close(toks: &[Tok], open: usize, name: &str) -> usize {
    let mut depth = 0usize;
    for (j, t) in toks.iter().enumerate().skip(open) {
        match t {
            Tok::Open {
                name: n,
                closed: false,
                ..
            } if n == name => depth += 1,
            Tok::Close(n) if n == name => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j;
                }
            }
            _ => {}
        }
    }
    toks.len()
}

struct Out<'a> {
    page: &'a Url,
    root: &'a Url,
    md: String,
    cur: String,
    lists: Vec<bool>,
    quote: usize,
    pre: Option<String>,
    links: BTreeSet<String>,
    internal: BTreeSet<String>,
    anchors: Vec<(usize, Option<String>)>,
    table: Option<Vec<Vec<String>>>,
    cell: Option<String>,
    title: Option<String>,
    heading: Option<usize>,
    /// Nesting of the list item being written, in steps of two spaces.
    indent: usize,
}

impl Out<'_> {
    fn sink(&mut self) -> &mut String {
        match (&mut self.cell, &mut self.pre) {
            (_, Some(p)) => p,
            (Some(c), None) => c,
            (None, None) => &mut self.cur,
        }
    }

    fn text(&mut self, raw: &str) {
        let t = decode(raw);
        if self.pre.is_some() {
            self.sink().push_str(&t);
            return;
        }
        let collapsed: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
        let sink = self.sink();
        let lead =
            t.starts_with(char::is_whitespace) && !sink.is_empty() && !sink.ends_with([' ', '\n']);
        if lead {
            sink.push(' ');
        }
        sink.push_str(&collapsed);
        if t.ends_with(char::is_whitespace) && !collapsed.is_empty() {
            sink.push(' ');
        }
    }

    /// Ends the current block; `tight` for list items (one newline, not a blank line).
    fn flush(&mut self, tight: bool) {
        let line = self.cur.trim().to_owned();
        self.cur.clear();
        if line.is_empty() {
            return;
        }
        let prefix = "> ".repeat(self.quote);
        let indent = "  ".repeat(std::mem::take(&mut self.indent));
        for l in line.lines() {
            let _ = writeln!(self.md, "{prefix}{indent}{l}");
        }
        if !tight {
            self.md.push('\n');
        }
    }

    fn resolve(&self, href: &str) -> Option<Url> {
        if href.starts_with('#') || href.starts_with("javascript:") || href.starts_with("mailto:") {
            return None;
        }
        let mut u = self.page.join(href).ok()?;
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        u.set_fragment(None);
        Some(u)
    }

    fn open(&mut self, name: &str, attrs: &[(String, String)]) {
        match name {
            "p" | "div" | "section" | "dl" | "figure" | "details" => self.flush(false),
            "dt" | "dd" | "summary" => self.flush(true),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.flush(false);
                self.heading = Some(self.cur.len());
                let level = usize::from(name.as_bytes()[1] - b'0');
                if level > 1 || self.title.is_some() {
                    let hashes = "#".repeat((level + 1).min(6));
                    self.cur.push_str(&hashes);
                    self.cur.push(' ');
                }
            }
            "ul" | "ol" => {
                self.flush(!self.lists.is_empty());
                self.lists.push(name == "ol");
            }
            "li" => {
                self.flush(true);
                let depth = self.lists.len().max(1) - 1;
                let marker = if self.lists.last() == Some(&true) {
                    "1."
                } else {
                    "-"
                };
                // The indent is applied at flush: the line itself is trimmed there.
                self.indent = depth;
                let _ = write!(self.cur, "{marker} ");
            }
            "blockquote" => {
                self.flush(false);
                self.quote += 1;
            }
            "pre" => {
                self.flush(false);
                self.pre = Some(String::new());
            }
            "code" => {
                if let Some(p) = &mut self.pre {
                    if p.is_empty()
                        && let Some(lang) = attr(attrs, "class").and_then(|c| {
                            c.split_whitespace().find_map(|x| {
                                x.strip_prefix("language-")
                                    .or_else(|| x.strip_prefix("lang-"))
                            })
                        })
                    {
                        *p = format!("\u{1}{lang}\u{1}");
                    }
                } else {
                    self.sink().push('`');
                }
            }
            "strong" | "b" => self.sink().push_str("**"),
            "em" | "i" => self.sink().push('*'),
            "br" => self.sink().push('\n'),
            "hr" => {
                self.flush(false);
                self.md.push_str("---\n\n");
            }
            "img" => {
                if let Some(alt) = attr(attrs, "alt").filter(|a| !a.trim().is_empty()) {
                    let t = format!("[image: {}]", alt.trim());
                    self.sink().push_str(&t);
                }
            }
            "a" => {
                let target = attr(attrs, "href")
                    .and_then(|h| self.resolve(h))
                    .map(|u| u.to_string());
                let at = self.sink().len();
                self.anchors.push((at, target));
            }
            "table" => {
                self.flush(false);
                self.table = Some(Vec::new());
            }
            "tr" => {
                if let Some(t) = &mut self.table {
                    t.push(Vec::new());
                }
            }
            "td" | "th" => self.cell = Some(String::new()),
            _ => {}
        }
    }

    fn close(&mut self, name: &str) {
        match name {
            "p" | "div" | "section" | "dl" | "figure" | "details" => self.flush(false),
            "dt" | "dd" | "summary" | "li" => self.flush(true),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                if name == "h1" && self.title.is_none() {
                    let start = self.heading.take().unwrap_or(0);
                    let t = self.cur[start.min(self.cur.len())..].trim().to_owned();
                    self.cur.truncate(start.min(self.cur.len()));
                    self.title = Some(t);
                } else {
                    self.heading = None;
                    self.flush(false);
                }
            }
            "ul" | "ol" => {
                self.flush(true);
                self.lists.pop();
                if self.lists.is_empty() {
                    self.md.push('\n');
                }
            }
            "blockquote" => {
                self.flush(false);
                self.quote = self.quote.saturating_sub(1);
            }
            "pre" => {
                if let Some(p) = self.pre.take() {
                    let (lang, code) =
                        match p.strip_prefix('\u{1}').and_then(|r| r.split_once('\u{1}')) {
                            Some((l, c)) => (l.to_owned(), c.to_owned()),
                            None => (String::new(), p),
                        };
                    let _ = write!(
                        self.md,
                        "```{lang}\n{}\n```\n\n",
                        code.trim_end_matches('\n')
                    );
                }
            }
            "code" => {
                if self.pre.is_none() {
                    self.sink().push('`');
                }
            }
            "strong" | "b" => self.sink().push_str("**"),
            "em" | "i" => self.sink().push('*'),
            "a" => {
                if let Some((at, target)) = self.anchors.pop() {
                    let Some(target) = target else { return };
                    let is_internal = target.starts_with(self.root.as_str());
                    if is_internal {
                        self.internal.insert(target.clone());
                    } else {
                        self.links.insert(target.clone());
                    }
                    if self.pre.is_some() {
                        return;
                    }
                    let sink = self.sink();
                    let at = at.min(sink.len());
                    let text = sink[at..].trim().to_owned();
                    if !text.is_empty() {
                        sink.truncate(at);
                        let _ = write!(sink, "[{text}]({target})");
                    }
                }
            }
            "td" | "th" => {
                if let (Some(c), Some(t)) = (self.cell.take(), &mut self.table)
                    && let Some(row) = t.last_mut()
                {
                    row.push(super::markdown::cell(c.trim()));
                }
            }
            "table" => {
                if let Some(rows) = self.table.take() {
                    let rows: Vec<Vec<String>> =
                        rows.into_iter().filter(|r| !r.is_empty()).collect();
                    let width = rows.iter().map(Vec::len).max().unwrap_or(0);
                    for (i, r) in rows.iter().enumerate() {
                        let mut r = r.clone();
                        r.resize(width, String::new());
                        let _ = writeln!(self.md, "| {} |", r.join(" | "));
                        if i == 0 {
                            let _ = writeln!(self.md, "|{}", "---|".repeat(width.max(1)));
                        }
                    }
                    self.md.push('\n');
                }
            }
            _ => {}
        }
    }
}

/// Reads `html`, fetched from `page`, of a site rooted at `root`.
#[must_use]
pub fn read(html: &str, page: &Url, root: &Url) -> Page {
    let toks = tokenize(html);
    let doc_title = toks
        .iter()
        .position(|t| matches!(t, Tok::Open { name, .. } if name == "title"))
        .and_then(|i| match toks.get(i + 1) {
            Some(Tok::Text(t)) => Some(decode(t).split_whitespace().collect::<Vec<_>>().join(" ")),
            _ => None,
        })
        .unwrap_or_default();
    let (from, to) = main_range(&toks);
    let mut o = Out {
        page,
        root,
        md: String::new(),
        cur: String::new(),
        lists: Vec::new(),
        quote: 0,
        pre: None,
        links: BTreeSet::new(),
        internal: BTreeSet::new(),
        anchors: Vec::new(),
        table: None,
        cell: None,
        title: None,
        heading: None,
        indent: 0,
    };
    let mut skip: Option<(String, usize)> = None;
    for t in &toks[from..to.min(toks.len())] {
        if let Some((name, depth)) = &mut skip {
            match t {
                Tok::Open {
                    name: n,
                    closed: false,
                    ..
                } if n == name => *depth += 1,
                Tok::Close(n) if n == name => {
                    *depth -= 1;
                    if *depth == 0 {
                        skip = None;
                    }
                }
                _ => {}
            }
            continue;
        }
        match t {
            Tok::Text(s) => o.text(s),
            Tok::Open {
                name,
                attrs,
                closed,
            } => {
                let chrome = SKIP.contains(&name.as_str())
                    || CHROME.iter().any(|c| has_class(attrs, c))
                    || attr(attrs, "aria-hidden") == Some("true");
                if chrome {
                    if !closed {
                        skip = Some((name.clone(), 1));
                    }
                    continue;
                }
                o.open(name, attrs);
            }
            Tok::Close(name) => o.close(name),
        }
    }
    o.flush(false);
    let title = o
        .title
        .clone()
        .filter(|t| !t.is_empty())
        .unwrap_or(doc_title);
    Page {
        title,
        markdown: super::markdown::normalize(&o.md),
        links: o.links,
        internal: o.internal,
    }
}

/// What a crawler needs from any page: its links, how much text it has, and the API
/// descriptions it names. Unlike [`read`], navigation, headers and footers count (that is
/// where a site links its products, apps and code).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outline {
    /// `<title>`, whitespace folded.
    pub title: String,
    /// `a` and `area` links, absolute (against `<base href>` when there is one), without
    /// fragments, each with whether it may be followed (`rel="nofollow"` or a robots meta
    /// `nofollow` says not).
    pub links: Vec<(Url, bool)>,
    /// `<link rel="canonical">`.
    pub canonical: Option<Url>,
    /// Characters of visible text outside `<head>`, scripts and styles, whitespace left out.
    pub text_chars: usize,
    /// `<script>` elements.
    pub scripts: usize,
    /// `OpenAPI` or Swagger documents the page names, in a link or a script (a Swagger UI or
    /// Redoc page names its document as a string in a script).
    pub specs: Vec<Url>,
}

/// Whether a path names an API description document by its usual names.
#[must_use]
pub fn looks_like_spec(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let doc = [".yaml", ".yml", ".json"].iter().any(|e| p.ends_with(e));
    let named = [
        "openapi", "swagger", "api-docs", "api-spec", "apispec", "asyncapi",
    ]
    .iter()
    .any(|n| p.contains(n));
    doc && named
}

/// The outline of `html`, fetched from `page`.
#[must_use]
pub fn outline(html: &str, page: &Url) -> Outline {
    let toks = tokenize(html);
    let mut base = page.clone();
    let mut o = Outline::default();
    let mut in_head = 0usize;
    let mut in_title = false;
    let mut nofollow_all = false;
    let mut hrefs: Vec<(String, bool)> = Vec::new();
    for t in &toks {
        match t {
            Tok::Open {
                name,
                attrs,
                closed,
            } => match name.as_str() {
                "head" if !closed => in_head += 1,
                "title" if !closed && o.title.is_empty() => in_title = true,
                "script" => o.scripts += 1,
                "base" => {
                    if let Some(b) = attr(attrs, "href").and_then(|h| page.join(&decode(h)).ok()) {
                        base = b;
                    }
                }
                "meta" => {
                    let robots =
                        attr(attrs, "name").is_some_and(|n| n.eq_ignore_ascii_case("robots"));
                    if robots
                        && attr(attrs, "content")
                            .is_some_and(|c| c.to_ascii_lowercase().contains("nofollow"))
                    {
                        nofollow_all = true;
                    }
                }
                "link" => {
                    let rel = attr(attrs, "rel").unwrap_or_default().to_ascii_lowercase();
                    if rel.split_whitespace().any(|r| r == "canonical") {
                        o.canonical = attr(attrs, "href").and_then(|h| page.join(&decode(h)).ok());
                    }
                }
                "a" | "area" => {
                    if let Some(h) = attr(attrs, "href") {
                        let rel = attr(attrs, "rel").unwrap_or_default().to_ascii_lowercase();
                        let follow = !rel.split_whitespace().any(|r| r == "nofollow");
                        hrefs.push((decode(h), follow));
                    }
                }
                _ => {}
            },
            Tok::Close(name) => match name.as_str() {
                "head" => in_head = in_head.saturating_sub(1),
                "title" => in_title = false,
                _ => {}
            },
            Tok::Text(text) => {
                if in_title {
                    o.title = decode(text)
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                } else if in_head == 0 {
                    o.text_chars += decode(text).chars().filter(|c| !c.is_whitespace()).count();
                }
            }
        }
    }
    let resolve = |h: &str| -> Option<Url> {
        let h = h.trim();
        if h.is_empty() || h.starts_with('#') {
            return None;
        }
        let mut u = base.join(h).ok()?;
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        u.set_fragment(None);
        Some(u)
    };
    let mut seen = BTreeSet::new();
    for (h, follow) in hrefs {
        if let Some(u) = resolve(&h)
            && seen.insert(u.to_string())
        {
            o.links.push((u, follow && !nofollow_all));
        }
    }
    // Strings in scripts and attributes that name an API description.
    let mut specs = BTreeSet::new();
    for s in html.split(['"', '\'', '`']) {
        if s.len() < 300
            && !s.contains(char::is_whitespace)
            && looks_like_spec(s)
            && let Some(u) = resolve(s)
            && specs.insert(u.to_string())
        {
            o.specs.push(u);
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        s.parse().unwrap()
    }

    #[test]
    fn a_docusaurus_page_reads_without_its_chrome() {
        let html = r##"<!DOCTYPE html><html><head><title>Deploy | Acme Docs</title><script>var x = "<article>";</script></head>
<body><nav class="navbar"><a href="/">Home</a></nav>
<div class="main-wrapper"><aside>sidebar</aside><main><div class="container"><article>
<nav class="breadcrumbs">Docs / Deploy</nav>
<div class="theme-doc-markdown markdown"><header><h1>Deploy</h1></header>
<h1>Deploy the service</h1>
<p>Run the <code>make deploy</code> target &amp; watch <a href="https://grafana.acme.example/d/x">Grafana</a>.
See <a href="../operate/rollback#steps">rollback</a>.</p>
<h2 id="checks">Checks<a class="hash-link" href="#checks">#</a></h2>
<ul><li>CI is green</li><li>Freeze is off<ul><li>check the calendar</li></ul></li></ul>
<pre><code class="language-bash">make deploy ENV=prod
</code></pre>
<table><thead><tr><th>Env</th><th>Gate</th></tr></thead><tbody><tr><td>prod</td><td>a | b</td></tr></tbody></table>
<blockquote><p>Never on Fridays.</p></blockquote>
</div><nav class="pagination-nav">Next</nav></article></div></main></div>
<footer>© Acme</footer></body></html>"##;
        let p = read(
            html,
            &u("https://docs.acme.example/guide/deploy/"),
            &u("https://docs.acme.example/"),
        );
        assert_eq!(p.title, "Deploy the service");
        assert_eq!(
            p.markdown,
            "Run the `make deploy` target & watch [Grafana](https://grafana.acme.example/d/x). See [rollback](https://docs.acme.example/guide/operate/rollback).\n\n### Checks\n\n- CI is green\n- Freeze is off\n  - check the calendar\n\n```bash\nmake deploy ENV=prod\n```\n\n| Env | Gate |\n|---|---|\n| prod | a \\| b |\n\n> Never on Fridays.\n"
        );
        assert_eq!(
            p.links.iter().collect::<Vec<_>>(),
            ["https://grafana.acme.example/d/x"]
        );
        assert_eq!(
            p.internal.iter().collect::<Vec<_>>(),
            ["https://docs.acme.example/guide/operate/rollback"]
        );
    }

    #[test]
    fn sphinx_and_mkdocs_mark_their_content_differently() {
        let sphinx = r##"<html><body><div class="sphinxsidebar">x</div><div class="document"><div class="body" role="main"><section><h1>API<a class="headerlink" href="#api">¶</a></h1><p>Calls &#x2192; answers.</p></section></div></div></body></html>"##;
        let p = read(
            sphinx,
            &u("https://d.example/api.html"),
            &u("https://d.example/"),
        );
        assert_eq!(
            (p.title.as_str(), p.markdown.as_str()),
            ("API", "Calls → answers.\n")
        );
        let mkdocs = r#"<html><head><title>Ops - Handbook</title></head><body><div class="md-sidebar">nav</div><article class="md-content__inner md-typeset"><p>Page &lt;b&gt; text</p></article></body></html>"#;
        let p = read(
            mkdocs,
            &u("https://d.example/ops/"),
            &u("https://d.example/"),
        );
        assert_eq!(
            (p.title.as_str(), p.markdown.as_str()),
            ("Ops - Handbook", "Page <b> text\n")
        );
    }

    #[test]
    fn an_outline_keeps_navigation_links_and_finds_api_documents() {
        let html = r##"<html><head><title> Acme  AI </title><base href="https://acme.test/docs/">
            <link rel="canonical" href="https://acme.test/docs/start"><meta name="x" content="y"></head>
            <body><nav><a href="/products">Products</a><a href="api#top">API</a></nav>
            <a rel="nofollow noopener" href="https://play.google.com/store/apps/details?id=com.acme.app">Get it</a>
            <a href="mailto:hi@acme.test">mail</a><a href="#x">here</a>
            <script>loadSwaggerUI('/assets/openapi-specs/search.yaml');</script>
            <footer><a href="https://github.com/acme/">GitHub</a></footer></body></html>"##;
        let o = outline(html, &u("https://acme.test/docs/start"));
        assert_eq!(o.title, "Acme AI");
        assert_eq!(o.canonical, Some(u("https://acme.test/docs/start")));
        let links: Vec<(String, bool)> = o.links.iter().map(|(l, f)| (l.to_string(), *f)).collect();
        assert_eq!(
            links,
            vec![
                ("https://acme.test/products".to_owned(), true),
                ("https://acme.test/docs/api".to_owned(), true),
                (
                    "https://play.google.com/store/apps/details?id=com.acme.app".to_owned(),
                    false
                ),
                ("https://github.com/acme/".to_owned(), true),
            ]
        );
        assert_eq!(
            o.specs,
            vec![u("https://acme.test/assets/openapi-specs/search.yaml")]
        );
        assert_eq!(o.scripts, 1);
        assert!(o.text_chars > 10, "{}", o.text_chars);
        let shell = outline(
            r#"<html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>"#,
            &u("https://acme.test/"),
        );
        assert_eq!(
            (shell.text_chars, shell.links.len(), shell.scripts),
            (0, 0, 1)
        );
        let nofollow = outline(
            r#"<meta name="robots" content="noindex, nofollow"><a href="/x">x</a>"#,
            &u("https://acme.test/"),
        );
        assert_eq!(nofollow.links, vec![(u("https://acme.test/x"), false)]);
    }

    #[test]
    fn broken_html_reads_what_it_can() {
        let p = read(
            "<p>one <b>two <i>three</p><p>four < five",
            &u("https://d.example/"),
            &u("https://d.example/"),
        );
        assert!(p.markdown.contains("one **two *three"), "{}", p.markdown);
        assert!(p.markdown.contains("four < five"), "{}", p.markdown);
        assert_eq!(
            read("", &u("https://d.example/"), &u("https://d.example/")),
            Page::default()
        );
    }
}
