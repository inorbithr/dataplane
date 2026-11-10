//! What a running crawl says about itself (RFC 0163): one JSON object per line, written to
//! standard error under `--progress`, so a caller that started the crawl can show a bar.
//!
//! A line carries counts and the scope (the registrable domain) and nothing else: no page
//! URL, title or text. `total` is there only once the crawl knows it (a sitemap listed
//! the pages), and then it never goes away. Fields are only ever added; a reader ignores
//! the ones it does not know, and `v` changes only if one is removed or changes meaning.

use serde::Serialize;

/// The line format's version.
pub const VERSION: u8 = 1;

/// The `event` of every line.
pub const EVENT: &str = "progress";

/// What the crawl is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Reading pages (and sitemaps and robots.txt).
    Pages,
    /// Reading the public listings the pages linked to, after the last page.
    Listings,
}

/// One progress line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Progress {
    /// Always [`EVENT`].
    pub event: &'static str,
    /// [`VERSION`].
    pub v: u8,
    /// The registrable domain in scope.
    pub scope: String,
    /// What the crawl is doing.
    pub phase: Phase,
    /// Pages answered without an error (redirects included).
    pub read: usize,
    /// Pages that failed: an error, or an HTTP status of 400 and over.
    pub failed: usize,
    /// URLs waiting, not counting sitemaps.
    pub queued: usize,
    /// The pages the crawl expects to request, at most `cap`: the start page and every
    /// sitemap entry, never less than what is read, failed and queued. Absent until a
    /// sitemap has been read, and absent for a site with none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// The page budget (`--max-pages`): the crawl stops here at the latest.
    pub cap: usize,
}

impl Progress {
    /// The line, without its newline.
    #[must_use]
    pub fn line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_the_scope_and_counts_only() {
        let mut p = Progress {
            event: EVENT,
            v: VERSION,
            scope: "acme.example".into(),
            phase: Phase::Pages,
            read: 3,
            failed: 1,
            queued: 9,
            total: None,
            cap: 2000,
        };
        assert_eq!(
            p.line(),
            r#"{"event":"progress","v":1,"scope":"acme.example","phase":"pages","read":3,"failed":1,"queued":9,"cap":2000}"#
        );
        p.total = Some(40);
        p.phase = Phase::Listings;
        assert_eq!(
            p.line(),
            r#"{"event":"progress","v":1,"scope":"acme.example","phase":"listings","read":3,"failed":1,"queued":9,"total":40,"cap":2000}"#
        );
    }
}
