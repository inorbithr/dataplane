//! Confluence Cloud, through REST API v2
//! (`https://developer.atlassian.com/cloud/confluence/rest/v2/intro/`), with an Atlassian
//! account's API token over HTTP Basic. Use a scoped token limited to the read scopes
//! below, created for a dedicated account that can see only the spaces Atlas may read. The
//! token lives in the company's secret store and is read by this agent only.
//!
//! The base URL is either the site (`https://<site>.atlassian.net`, for a classic token) or
//! the API gateway (`https://api.atlassian.com/ex/confluence/<cloud id>`, which scoped tokens
//! require). Paths are joined under it, so both work.
//!
//! What it reads, all `GET`:
//! - `wiki/rest/api/user/current`: the account, by id;
//! - `wiki/api/v2/spaces`: spaces (only the configured keys, when `spaces` is set);
//! - `wiki/api/v2/pages` and `wiki/api/v2/blogposts`, `sort=-modified-date`: an
//!   incremental run stops at the first item older than its window;
//! - `.../{id}?body-format=atlas_doc_format`: the content as ADF, rendered to markdown;
//! - `.../{id}/labels`, `.../{id}/attachments`, `.../{id}/footer-comments`.
//!
//! Scopes: `read:page:confluence`, `read:blogpost:confluence`, `read:space:confluence`,
//! `read:label:confluence`, `read:attachment:confluence`, `read:comment:confluence`,
//! `read:confluence-user`. A 403 on comments turns them off for the rest of the run.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use iohr_evidence::time::Timestamp;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::adf::Adf;
use super::http::{ApiClient, Limits, secret_header};
use super::markdown::normalize;
use super::{
    Attachment, Batch, Comment, DocsError, DocsSource, Document, ItemKind, ItemRef, SourceIdentity,
    Space,
};
use crate::policy::Policy;
use crate::tls::TlsContext;

/// A conservative pace: Atlassian's limits are cost-based and unpublished per tenant, and
/// answer 429 with `Retry-After` beyond them.
pub const RATE_PER_MINUTE: u32 = 300;
const PAGE_LIMIT: u32 = 250;
/// The scopes a token needs; the setup guide asks for no others.
pub const SCOPES: [&str; 7] = [
    "read:attachment:confluence",
    "read:blogpost:confluence",
    "read:comment:confluence",
    "read:confluence-user",
    "read:label:confluence",
    "read:page:confluence",
    "read:space:confluence",
];
const BLOG: &str = "blogpost:";

/// A Confluence site, as one account sees it.
#[derive(Debug)]
pub struct Confluence {
    api: ApiClient,
    /// Space keys to read; empty means every space the account sees.
    only: Vec<String>,
    /// The ids of those spaces, once resolved.
    space_ids: Mutex<Option<Vec<String>>>,
    comments: AtomicBool,
}

impl Confluence {
    /// A source over an existing client.
    #[must_use]
    pub fn new(api: ApiClient, only: Vec<String>, comments: bool) -> Self {
        Self {
            api,
            only,
            space_ids: Mutex::new(None),
            comments: AtomicBool::new(comments),
        }
    }

    /// Connects to `base` as `account` with `token`, after the policy admitted the host.
    ///
    /// # Errors
    /// The policy refuses the host, or the credential cannot be a header.
    #[allow(clippy::too_many_arguments)] // one source's whole connection, passed once
    pub async fn connect(
        base: Url,
        account: &str,
        token: &Zeroizing<String>,
        policy: &Policy,
        tls: &TlsContext,
        limits: Limits,
        only: Vec<String>,
        comments: bool,
    ) -> Result<Self, DocsError> {
        let mut base = base;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let pair = Zeroizing::new(format!("{account}:{}", token.as_str()));
        let basic = Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
        ));
        let api = ApiClient::new(
            base,
            policy,
            tls,
            vec![secret_header("authorization", &basic)?],
            limits,
        )
        .await?;
        Ok(Self::new(api, only, comments))
    }

    /// The client, for its counts.
    #[must_use]
    pub const fn client(&self) -> &ApiClient {
        &self.api
    }

    /// A `_links.next` (`/wiki/api/v2/...?cursor=...`) as a path under the base.
    fn next_of(answer: &Value) -> Option<String> {
        answer
            .get("_links")
            .and_then(|l| l.get("next"))
            .and_then(Value::as_str)
            .map(|n| n.trim_start_matches('/').to_owned())
    }

    fn results(answer: &Value, what: &str) -> Result<Vec<Value>, DocsError> {
        answer
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| DocsError::Malformed(format!("{what}: no results")))
    }

    async fn space_ids(&self) -> Result<Option<Vec<String>>, DocsError> {
        if self.only.is_empty() {
            return Ok(None);
        }
        if let Some(ids) = self
            .space_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Ok(Some(ids));
        }
        let mut ids = Vec::new();
        let mut path = Some(format!(
            "wiki/api/v2/spaces?limit={PAGE_LIMIT}&keys={}",
            self.only.join(",")
        ));
        while let Some(p) = path {
            let answer = self.api.get(&p).await?;
            for s in Self::results(&answer, "GET spaces")? {
                ids.push(id_at(&s)?);
            }
            path = Self::next_of(&answer);
        }
        if ids.is_empty() {
            return Err(DocsError::Forbidden(
                "none of the configured spaces is visible to the account".into(),
            ));
        }
        *self
            .space_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ids.clone());
        Ok(Some(ids))
    }

    fn site(&self, answer: &Value) -> Option<String> {
        // `_links.base` is the site's wiki root (`https://acme.atlassian.net/wiki`); without
        // it a site base URL is the best guess, and a gateway URL is no site at all.
        answer
            .get("_links")
            .and_then(|l| l.get("base"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                let b = self.api.base();
                (b.host_str() != Some("api.atlassian.com")).then(|| format!("{}wiki", b.as_str()))
            })
    }

    async fn list(
        &self,
        collection: &str,
        since: Option<Timestamp>,
        path: Option<&str>,
    ) -> Result<(Vec<ItemRef>, Option<String>), DocsError> {
        let path = if let Some(p) = path.filter(|p| !p.is_empty()) {
            p.to_owned()
        } else {
            let mut p = format!(
                "wiki/api/v2/{collection}?limit={PAGE_LIMIT}&sort=-modified-date&status=current"
            );
            if let Some(ids) = self.space_ids().await? {
                p.push_str("&space-id=");
                p.push_str(&ids.join(","));
            }
            p
        };
        let answer = self.api.get(&path).await?;
        let mut items = Vec::new();
        let mut older = false;
        for r in Self::results(&answer, &format!("GET {collection}"))? {
            let id = id_at(&r)?;
            let updated = r.get("version").and_then(|v| time_at(v, "createdAt"));
            if let (Some(s), Some(u)) = (since, updated)
                && u < s
            {
                older = true;
                break;
            }
            items.push(ItemRef {
                id: if collection == "blogposts" {
                    format!("{BLOG}{id}")
                } else {
                    id
                },
                kind: ItemKind::Page,
                updated,
            });
        }
        let next = if older { None } else { Self::next_of(&answer) };
        Ok((items, next))
    }

    async fn all(&self, path: String, what: &str) -> Result<Vec<Value>, DocsError> {
        let mut out = Vec::new();
        let mut path = Some(path);
        while let Some(p) = path {
            let answer = self.api.get(&p).await?;
            out.extend(Self::results(&answer, what)?);
            path = Self::next_of(&answer);
        }
        Ok(out)
    }

    /// An item's labels as one field, sorted; empty when it has none.
    async fn labels(&self, base: &str) -> Result<BTreeMap<String, String>, DocsError> {
        let labels: BTreeSet<String> = self
            .all(format!("{base}/labels?limit={PAGE_LIMIT}"), "GET labels")
            .await?
            .iter()
            .filter_map(|l| l.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut fields = BTreeMap::new();
        if !labels.is_empty() {
            fields.insert(
                "labels".to_owned(),
                labels.into_iter().collect::<Vec<_>>().join(", "),
            );
        }
        Ok(fields)
    }

    /// An item's attachments, by reference.
    async fn attachments(
        &self,
        base: &str,
        site: Option<String>,
    ) -> Result<Vec<Attachment>, DocsError> {
        Ok(self
            .all(
                format!("{base}/attachments?limit={PAGE_LIMIT}"),
                "GET attachments",
            )
            .await?
            .iter()
            .map(|a| Attachment {
                id: a
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                name: a
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                media_type: a
                    .get("mediaType")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                size: a.get("fileSize").and_then(Value::as_u64),
                url: match (&site, a.get("webuiLink").and_then(Value::as_str)) {
                    (Some(b), Some(w)) => Some(format!("{b}{w}")),
                    _ => None,
                },
            })
            .filter(|a| !a.id.is_empty())
            .collect())
    }

    /// An item's footer comments; a 403 turns comments off for the rest of the run.
    async fn comments(&self, base: &str) -> Result<Vec<Comment>, DocsError> {
        if !self.comments.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }
        let list = match self
            .all(
                format!("{base}/footer-comments?limit=100&body-format=atlas_doc_format"),
                "GET footer-comments",
            )
            .await
        {
            Ok(list) => list,
            Err(DocsError::Forbidden(_)) => {
                if self.comments.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        "docs: the Confluence token may not read comments; reading pages without them"
                    );
                }
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let mut out = Vec::with_capacity(list.len());
        for c in list {
            let body = c
                .get("body")
                .and_then(|b| b.get("atlas_doc_format"))
                .and_then(|a| a.get("value"))
                .and_then(Value::as_str)
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .map(|v| normalize(&Adf::render(&v).md))
                .unwrap_or_default();
            out.push(Comment {
                id: id_at(&c)?,
                author: c
                    .get("version")
                    .and_then(|v| v.get("authorId"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                created: c.get("version").and_then(|v| time_at(v, "createdAt")),
                markdown: body,
            });
        }
        Ok(out)
    }
}

impl DocsSource for Confluence {
    fn provider(&self) -> &'static str {
        "confluence"
    }

    async fn identity(&self) -> Result<SourceIdentity, DocsError> {
        let me = self.api.get("wiki/rest/api/user/current").await?;
        let id = me
            .get("accountId")
            .and_then(Value::as_str)
            .ok_or_else(|| DocsError::Malformed("the current user has no accountId".into()))?;
        // An anonymous answer means the credential was not taken.
        if me.get("type").and_then(Value::as_str) == Some("anonymous") {
            return Err(DocsError::Unauthorized(
                "GET user/current: anonymous".into(),
            ));
        }
        Ok(SourceIdentity {
            principal: format!("atlassian-account:{id}"),
            workspace: self.api.base().host_str().map(str::to_owned),
            scopes: SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        })
    }

    async fn spaces(&self, cursor: Option<String>) -> Result<Batch<Space>, DocsError> {
        let path = cursor.unwrap_or_else(|| {
            let mut p = format!("wiki/api/v2/spaces?limit={PAGE_LIMIT}");
            if !self.only.is_empty() {
                p.push_str("&keys=");
                p.push_str(&self.only.join(","));
            }
            p
        });
        let answer = self.api.get(&path).await?;
        let site = self.site(&answer);
        let mut items = Vec::new();
        for s in Self::results(&answer, "GET spaces")? {
            let key = s.get("key").and_then(Value::as_str).unwrap_or_default();
            let name = s.get("name").and_then(Value::as_str).unwrap_or(key);
            let webui = s
                .get("_links")
                .and_then(|l| l.get("webui"))
                .and_then(Value::as_str);
            items.push(Space {
                id: id_at(&s)?,
                name: if key.is_empty() {
                    name.to_owned()
                } else {
                    format!("{name} ({key})")
                },
                url: match (&site, webui) {
                    (Some(b), Some(w)) => Some(format!("{b}{w}")),
                    _ => None,
                },
            });
        }
        Ok(Batch {
            items,
            next: Self::next_of(&answer),
        })
    }

    async fn changed(
        &self,
        since: Option<Timestamp>,
        cursor: Option<String>,
    ) -> Result<Batch<ItemRef>, DocsError> {
        let (phase, inner) = match cursor.as_deref() {
            None => ("pages", None),
            Some(c) => match c.split_once('|') {
                Some(("pages", rest)) => ("pages", Some(rest)),
                Some(("blogposts", rest)) => ("blogposts", Some(rest)),
                _ => {
                    return Err(DocsError::Malformed(
                        "a cursor this source never gave".into(),
                    ));
                }
            },
        };
        let (items, next) = self.list(phase, since, inner).await?;
        let next = match (phase, next) {
            (p, Some(n)) => Some(format!("{p}|{n}")),
            ("pages", None) => Some("blogposts|".to_owned()),
            _ => None,
        };
        Ok(Batch { items, next })
    }

    async fn fetch(&self, item: &ItemRef) -> Result<Document, DocsError> {
        let (collection, id) = match item.id.strip_prefix(BLOG) {
            Some(id) => ("blogposts", id),
            None => ("pages", item.id.as_str()),
        };
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DocsError::Malformed(
                "an id that is not a Confluence id".into(),
            ));
        }
        let base = format!("wiki/api/v2/{collection}/{id}");
        let page = self
            .api
            .get(&format!("{base}?body-format=atlas_doc_format"))
            .await?;
        match page.get("status").and_then(Value::as_str) {
            Some("current") | None => {}
            Some(other) => {
                return Err(DocsError::NotFound(format!(
                    "GET {collection}/{id}: {other}"
                )));
            }
        }
        let adf_text = page
            .get("body")
            .and_then(|b| b.get("atlas_doc_format"))
            .and_then(|a| a.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("{}");
        let adf: Value = serde_json::from_str(adf_text).map_err(|_| {
            DocsError::Malformed(format!("GET {collection}/{id}: the body is not ADF"))
        })?;
        let rendered = Adf::render(&adf);

        let fields = self.labels(&base).await?;

        let site = self.site(&page);
        let attachments = self.attachments(&base, site.clone()).await?;

        let comments = self.comments(&base).await?;

        let parent = (page.get("parentType").and_then(Value::as_str) == Some("page"))
            .then(|| {
                page.get("parentId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        let webui = page
            .get("_links")
            .and_then(|l| l.get("webui"))
            .and_then(Value::as_str);
        Ok(Document {
            id: item.id.clone(),
            kind: ItemKind::Page,
            title: page
                .get("title")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .unwrap_or("Untitled")
                .to_owned(),
            url: match (&site, webui) {
                (Some(b), Some(w)) => Some(format!("{b}{w}")),
                _ => None,
            },
            parent,
            database: None,
            space: page
                .get("spaceId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            created: time_at(&page, "createdAt"),
            updated: page.get("version").and_then(|v| time_at(v, "createdAt")),
            version: page
                .get("version")
                .and_then(|v| v.get("number"))
                .and_then(Value::as_u64)
                .map(|n| format!("v{n}")),
            authors: authors_of(&page),
            markdown: normalize(&rendered.md),
            fields,
            links: rendered.links.into_iter().collect(),
            mentions: rendered.mentions.into_iter().filter(|m| m != id).collect(),
            attachments,
            comments,
        })
    }
}

/// Author, owner and last editor, by account id, sorted and unique.
fn authors_of(page: &Value) -> Vec<String> {
    let mut authors = BTreeSet::new();
    for k in ["authorId", "ownerId"] {
        if let Some(a) = page.get(k).and_then(Value::as_str) {
            authors.insert(a.to_owned());
        }
    }
    if let Some(a) = page
        .get("version")
        .and_then(|v| v.get("authorId"))
        .and_then(Value::as_str)
    {
        authors.insert(a.to_owned());
    }
    authors.into_iter().collect()
}

fn id_at(v: &Value) -> Result<String, DocsError> {
    match v.get("id") {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        _ => Err(DocsError::Malformed("an object without id".into())),
    }
}

fn time_at(v: &Value, k: &str) -> Option<Timestamp> {
    v.get(k)
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}
