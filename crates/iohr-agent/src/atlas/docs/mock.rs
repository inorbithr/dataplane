//! A [`DocsSource`] held in memory, with every failure a real provider has: a refused
//! credential, a listing cut off by a rate limit or an outage, an item that is gone or
//! cannot be read. The sync engine's tests run against it; so can anyone writing a new
//! connector who wants to see what the engine expects.

use std::collections::BTreeMap;
use std::future::{Future, ready};
use std::sync::Mutex;

use iohr_evidence::time::Timestamp;

use super::{
    Batch, Comment, DocsError, DocsSource, Document, ItemKind, ItemRef, SourceIdentity, Space,
};

/// A document with a title and a markdown body, in space `s1`, by user `u1`.
#[must_use]
pub fn doc(id: &str, kind: ItemKind, updated: Timestamp, title: &str, body: &str) -> Document {
    Document {
        id: id.to_owned(),
        kind,
        title: title.to_owned(),
        url: Some(format!("https://docs.example/{id}")),
        parent: None,
        database: None,
        space: Some("s1".into()),
        created: Some(updated),
        updated: Some(updated),
        version: None,
        authors: vec!["u1".into()],
        markdown: body.to_owned(),
        fields: BTreeMap::new(),
        links: Vec::new(),
        mentions: Vec::new(),
        attachments: Vec::new(),
        comments: Vec::<Comment>::new(),
    }
}

#[derive(Debug, Default)]
struct Inner {
    docs: BTreeMap<String, Document>,
    identity_failure: Option<DocsError>,
    listing_failure: Option<(usize, DocsError)>,
    fetch_failures: BTreeMap<String, DocsError>,
    since_asked: Vec<Option<Timestamp>>,
    fetches: usize,
}

/// An in-memory source.
#[derive(Debug)]
pub struct MockSource {
    provider: &'static str,
    page_size: usize,
    inner: Mutex<Inner>,
}

impl MockSource {
    /// An empty source whose methods are named `<provider>.*`.
    #[must_use]
    pub fn new(provider: &'static str) -> Self {
        Self {
            provider,
            page_size: 100,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// With this document.
    #[must_use]
    pub fn with(self, d: Document) -> Self {
        self.inner().docs.insert(d.id.clone(), d);
        self
    }

    /// Listings return at most `n` items per page.
    #[must_use]
    pub const fn page_size(mut self, n: usize) -> Self {
        self.page_size = n;
        self
    }

    /// Changes a document's body and change time.
    pub fn edit(&self, id: &str, updated: Timestamp, body: &str) {
        if let Some(d) = self.inner().docs.get_mut(id) {
            d.updated = Some(updated);
            body.clone_into(&mut d.markdown);
        }
    }

    /// Deletes a document without a trace (a provider that does not list deletions).
    pub fn remove(&self, id: &str) {
        self.inner().docs.remove(id);
    }

    /// `identity` fails with `e`.
    pub fn fail_identity(&self, e: DocsError) {
        self.inner().identity_failure = Some(e);
    }

    /// Listing pages from index `pages` on fail with `e`.
    pub fn fail_listing_after(&self, pages: usize, e: DocsError) {
        self.inner().listing_failure = Some((pages, e));
    }

    /// Fetching `id` fails with `e`.
    pub fn fail_fetch(&self, id: &str, e: DocsError) {
        self.inner().fetch_failures.insert(id.to_owned(), e);
    }

    /// No more failures.
    pub fn clear_failures(&self) {
        let mut i = self.inner();
        i.identity_failure = None;
        i.listing_failure = None;
        i.fetch_failures.clear();
    }

    /// The `since` of every listing started, in order.
    #[must_use]
    pub fn since_asked(&self) -> Vec<Option<Timestamp>> {
        self.inner().since_asked.clone()
    }

    /// Fetches so far.
    #[must_use]
    pub fn fetches(&self) -> usize {
        self.inner().fetches
    }
}

impl DocsSource for MockSource {
    fn provider(&self) -> &'static str {
        self.provider
    }

    fn identity(&self) -> impl Future<Output = Result<SourceIdentity, DocsError>> + Send {
        ready(self.identity_now())
    }

    fn spaces(
        &self,
        _cursor: Option<String>,
    ) -> impl Future<Output = Result<Batch<Space>, DocsError>> + Send {
        ready(Ok(Batch {
            items: vec![Space {
                id: "s1".into(),
                name: "Engineering".into(),
                url: None,
            }],
            next: None,
        }))
    }

    fn changed(
        &self,
        since: Option<Timestamp>,
        cursor: Option<String>,
    ) -> impl Future<Output = Result<Batch<ItemRef>, DocsError>> + Send {
        ready(self.changed_now(since, cursor.as_deref()))
    }

    fn fetch(&self, item: &ItemRef) -> impl Future<Output = Result<Document, DocsError>> + Send {
        ready(self.fetch_now(item))
    }
}

impl MockSource {
    fn identity_now(&self) -> Result<SourceIdentity, DocsError> {
        if let Some(e) = self.inner().identity_failure.clone() {
            return Err(e);
        }
        Ok(SourceIdentity {
            principal: "bot-1".into(),
            workspace: Some("Example".into()),
            scopes: vec!["read_content".into()],
        })
    }

    fn changed_now(
        &self,
        since: Option<Timestamp>,
        cursor: Option<&str>,
    ) -> Result<Batch<ItemRef>, DocsError> {
        let mut inner = self.inner();
        let page: usize = match cursor {
            None => {
                inner.since_asked.push(since);
                0
            }
            Some(c) => c
                .parse()
                .map_err(|_| DocsError::Malformed("a cursor this source never gave".into()))?,
        };
        if let Some((after, e)) = &inner.listing_failure
            && page >= *after
        {
            return Err(e.clone());
        }
        // Newest first, as providers sort.
        let mut all: Vec<ItemRef> = inner
            .docs
            .values()
            .filter(|d| match (since, d.updated) {
                (Some(s), Some(u)) => u >= s,
                _ => true,
            })
            .map(|d| ItemRef {
                id: d.id.clone(),
                kind: d.kind,
                updated: d.updated,
            })
            .collect();
        all.sort_by(|a, b| (b.updated, &a.id).cmp(&(a.updated, &b.id)));
        let start = page * self.page_size;
        let items: Vec<ItemRef> = all
            .iter()
            .skip(start)
            .take(self.page_size)
            .cloned()
            .collect();
        let next = (start + self.page_size < all.len()).then(|| (page + 1).to_string());
        Ok(Batch { items, next })
    }

    fn fetch_now(&self, item: &ItemRef) -> Result<Document, DocsError> {
        let mut inner = self.inner();
        inner.fetches += 1;
        if let Some(e) = inner.fetch_failures.get(&item.id) {
            return Err(e.clone());
        }
        inner
            .docs
            .get(&item.id)
            .cloned()
            .ok_or_else(|| DocsError::NotFound(format!("GET /{}: 404", item.id)))
    }
}
