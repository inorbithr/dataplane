//! Documentation connectors: a company's internal docs (Notion first) read by the
//! company's own agent, as evidence for Atlas (`docs/docs-connectors.md`).
//!
//! Every provider implements [`DocsSource`]: it names who it reads as, lists what changed
//! since a time (incrementally, with an opaque cursor), and fetches one item as normalized
//! markdown with a stable id, authors (provider user ids, never names or mail), times,
//! links, structured fields and attachment references. [`sync::sync_source`] drives any
//! source the same way: it keeps a local state per source, fetches only what changed,
//! writes each document's bytes to a local content store, and records each reading as an
//! [`iohr_evidence::observation::ArtifactObservation`] in the `documentation` category with
//! the provider's open method name (`notion.page.read`). Documentation never proves a claim
//! (ADR 0016 in inorbithr/core); it supports or suggests one, and Atlas looks for
//! deterministic evidence before it calls anything verified.
//!
//! What may leave: nothing. The records carry ids, digests, titles, links, times and
//! structured fields; the documents themselves stay in the content store on this machine,
//! and a revoked credential or an unshared page deletes the local copy.

pub mod adf;
pub mod config;
pub mod confluence;
pub mod http;
pub mod markdown;
pub mod mock;
pub mod notion;
pub mod run;
pub mod sync;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use iohr_evidence::time::Timestamp;
use serde::{Deserialize, Serialize};

/// What kind of item a source holds. Providers map their own nouns onto these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A page of prose.
    Page,
    /// A table of rows with a schema (a Notion data source, a Coda table).
    Database,
    /// One row of a database: structured fields, and often prose too.
    Row,
}

impl ItemKind {
    /// The noun in method names and entity keys.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Database => "database",
            Self::Row => "row",
        }
    }
}

/// An item a listing returned: enough to decide whether to fetch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    /// The provider's stable id.
    pub id: String,
    /// Its kind.
    pub kind: ItemKind,
    /// When it last changed, as the provider says.
    pub updated: Option<Timestamp>,
}

/// A space: a workspace, a Confluence space, a site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Space {
    /// The provider's stable id.
    pub id: String,
    /// Its name.
    pub name: String,
    /// A link to it, if it has one.
    pub url: Option<String>,
}

/// One page of a listing, and where to continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch<T> {
    /// What this page held.
    pub items: Vec<T>,
    /// The cursor for the next page; `None` when the listing is done.
    pub next: Option<String>,
}

/// Who a source reads as, and what it may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    /// The integration or account, by the provider's id (a bot id, an account id).
    pub principal: String,
    /// The workspace or site it belongs to, by name.
    pub workspace: Option<String>,
    /// The read scopes or capabilities it holds, sorted.
    pub scopes: Vec<String>,
}

/// A file attached to an item. Referenced, never downloaded: a name, a type, a size and,
/// when the link is stable and not itself a credential, the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The provider's stable id.
    pub id: String,
    /// The file name.
    pub name: String,
    /// The media type, when known.
    pub media_type: Option<String>,
    /// The size in bytes, when known.
    pub size: Option<u64>,
    /// A stable link. Signed, expiring links are left out: they are credentials.
    pub url: Option<String>,
}

/// A comment on an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The provider's stable id.
    pub id: String,
    /// Its author, by provider user id.
    pub author: Option<String>,
    /// When it was written.
    pub created: Option<Timestamp>,
    /// Its text, as markdown.
    pub markdown: String,
}

/// One item, read and normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The provider's stable id.
    pub id: String,
    /// Its kind.
    pub kind: ItemKind,
    /// Its title.
    pub title: String,
    /// A link a person can open.
    pub url: Option<String>,
    /// The item it sits under, by provider id.
    pub parent: Option<String>,
    /// The database a row belongs to, by provider id.
    pub database: Option<String>,
    /// The space it belongs to, by provider id.
    pub space: Option<String>,
    /// When it was created.
    pub created: Option<Timestamp>,
    /// When it last changed.
    pub updated: Option<Timestamp>,
    /// The provider's version marker when it has one (a Confluence version number).
    pub version: Option<String>,
    /// Who wrote or edited it, by provider user id, sorted and unique.
    pub authors: Vec<String>,
    /// The content as markdown. Deterministic: the same item reads to the same bytes.
    pub markdown: String,
    /// Structured fields (a row's properties, a database's schema), by name.
    pub fields: BTreeMap<String, String>,
    /// Links to other places (absolute URLs), sorted and unique.
    pub links: Vec<String>,
    /// Other items of the same source it links to, by provider id.
    pub mentions: Vec<String>,
    /// Attached files, by reference.
    pub attachments: Vec<Attachment>,
    /// Its comments, when the source reads them.
    pub comments: Vec<Comment>,
}

/// Why a source could not answer. Messages name the request (method and path) and the
/// status, never a token, a header or a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocsError {
    /// The provider kept answering "too many requests" after every retry.
    #[error("rate limited: {what}")]
    RateLimited {
        /// The request.
        what: String,
        /// How long the provider asked to wait, last time.
        retry_after: Option<Duration>,
    },
    /// The credential was refused: wrong, expired or revoked.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The credential is valid but may not read this (not shared, a missing capability).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The item does not exist, or is no longer visible to the credential.
    #[error("not found: {0}")]
    NotFound(String),
    /// The provider or the network failed after every retry.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// The answer was not what the provider documents.
    #[error("malformed answer: {0}")]
    Malformed(String),
    /// The answer was larger than the agent accepts.
    #[error("too large: {0}")]
    TooLarge(String),
    /// The local policy refused the host, or the configuration is unusable.
    #[error("refused: {0}")]
    Refused(String),
}

impl DocsError {
    /// Whether the item is gone for this credential: deleted, unshared or archived.
    #[must_use]
    pub const fn is_gone(&self) -> bool {
        matches!(self, Self::NotFound(_) | Self::Forbidden(_))
    }
}

/// A documentation provider, as the sync engine sees it.
///
/// Implementations are read-only by construction: every request they make is a read, with
/// a credential that the provider's own setup limits to reading (`docs/docs-connectors.md`
/// lists the scopes per provider). They never log content.
pub trait DocsSource: Send + Sync {
    /// The provider's name in method names: `notion`, `confluence`, `sitemap`.
    fn provider(&self) -> &'static str;

    /// Who this source reads as. A refused credential is [`DocsError::Unauthorized`].
    fn identity(&self) -> impl Future<Output = Result<SourceIdentity, DocsError>> + Send;

    /// The spaces visible to the credential, one page at a time.
    fn spaces(
        &self,
        cursor: Option<String>,
    ) -> impl Future<Output = Result<Batch<Space>, DocsError>> + Send;

    /// Items changed at or after `since` (every visible item when `None`), one page at a
    /// time. May return older items too; the engine skips what it already holds.
    fn changed(
        &self,
        since: Option<Timestamp>,
        cursor: Option<String>,
    ) -> impl Future<Output = Result<Batch<ItemRef>, DocsError>> + Send;

    /// Reads one item. An item that is deleted, unshared or archived is
    /// [`DocsError::NotFound`] or [`DocsError::Forbidden`].
    fn fetch(&self, item: &ItemRef) -> impl Future<Output = Result<Document, DocsError>> + Send;
}

/// A provider this agent can read, as named in `agent.toml`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Notion, through an internal integration's token.
    Notion,
    /// Confluence Cloud (REST API v2), through an Atlassian account's API token.
    Confluence,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Notion => "notion",
            Self::Confluence => "confluence",
        })
    }
}
