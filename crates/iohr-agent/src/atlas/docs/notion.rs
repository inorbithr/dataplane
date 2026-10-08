//! Notion, through the official API (`https://developers.notion.com/reference`), as an
//! internal integration: a workspace admin creates it with read capabilities only and
//! shares the pages and databases Atlas may read with it. The integration's token lives in
//! the company's secret store and is read by this agent only; InOrbit never holds it
//! (`docs/docs-connectors.md` explains why not a public OAuth integration).
//!
//! What it reads, all with `GET` or Notion's read-only `POST`s (search, query):
//! - `GET /v1/users/me`: who the integration is and its workspace's name;
//! - `POST /v1/search`: pages (database rows included) and data sources, newest edit
//!   first, so an incremental run stops at the first item older than its window;
//! - `GET /v1/pages/{id}`: a page's properties (a row's structured fields);
//! - `GET /v1/blocks/{id}/children`: the content, recursively, rendered as markdown;
//! - `GET /v1/data_sources/{id}`: a database's schema;
//! - `GET /v1/comments?block_id={id}`: page comments, when the integration has the "read
//!   comments" capability (a 403 turns them off for the rest of the run).
//!
//! Notion's limit is an average of three requests a second per integration, answered with
//! 429 and `Retry-After` beyond it; the client paces to it. Notion API version `2025-09-03`.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use iohr_evidence::time::Timestamp;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

use super::http::{ApiClient, Limits, secret_header};
use super::markdown::normalize;
use super::{
    Attachment, Batch, Comment, DocsError, DocsSource, Document, ItemKind, ItemRef, SourceIdentity,
    Space,
};
use crate::policy::Policy;
use crate::tls::TlsContext;

/// The public API.
pub const API: &str = "https://api.notion.com";
/// The API version this connector speaks.
pub const VERSION: &str = "2025-09-03";
/// Notion's published average: three requests a second.
pub const RATE_PER_MINUTE: u32 = 180;
/// How deep nested blocks are followed.
const MAX_DEPTH: usize = 8;
/// Most blocks read from one page; beyond it the copy says it was cut.
const MAX_BLOCKS: usize = 20_000;
/// The workspace, as the one space an integration sees.
const WORKSPACE: &str = "workspace";

/// A Notion workspace, as one internal integration sees it.
#[derive(Debug)]
pub struct Notion {
    api: ApiClient,
    comments: AtomicBool,
}

impl Notion {
    /// A source over an existing client (tests point it at a recorded server).
    #[must_use]
    pub const fn new(api: ApiClient, comments: bool) -> Self {
        Self {
            api,
            comments: AtomicBool::new(comments),
        }
    }

    /// Connects to `base` (default [`API`]) with the integration's token, after the policy
    /// admitted the host.
    ///
    /// # Errors
    /// The policy refuses the host, or the token cannot be a header.
    pub async fn connect(
        base: Option<Url>,
        token: &Zeroizing<String>,
        policy: &Policy,
        tls: &TlsContext,
        limits: Limits,
        comments: bool,
    ) -> Result<Self, DocsError> {
        let base = match base {
            Some(b) => b,
            None => API
                .parse()
                .map_err(|_| DocsError::Refused("the Notion API URL".into()))?,
        };
        let bearer = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let headers = vec![
            secret_header("authorization", &bearer)?,
            (
                HeaderName::from_static("notion-version"),
                HeaderValue::from_static(VERSION),
            ),
        ];
        let api = ApiClient::new(base, policy, tls, headers, limits).await?;
        Ok(Self::new(api, comments))
    }

    /// The client, for its counts.
    #[must_use]
    pub const fn client(&self) -> &ApiClient {
        &self.api
    }

    async fn search(
        &self,
        object: &str,
        since: Option<Timestamp>,
        cursor: Option<&str>,
    ) -> Result<(Vec<ItemRef>, Option<String>), DocsError> {
        let mut body = json!({
            "filter": {"property": "object", "value": object},
            "sort": {"direction": "descending", "timestamp": "last_edited_time"},
            "page_size": 100,
        });
        if let Some(c) = cursor.filter(|c| !c.is_empty()) {
            body["start_cursor"] = json!(c);
        }
        let answer = self.api.post("/v1/search", &body).await?;
        let results = answer
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| DocsError::Malformed("POST /v1/search: no results".into()))?;
        let mut items = Vec::with_capacity(results.len());
        let mut older = false;
        for r in results {
            let id = str_at(r, "id")?;
            let updated = time_at(r, "last_edited_time");
            if let (Some(s), Some(u)) = (since, updated)
                && u < s
            {
                older = true;
                break;
            }
            let kind = if object == "data_source" {
                ItemKind::Database
            } else if is_row(r) {
                ItemKind::Row
            } else {
                ItemKind::Page
            };
            items.push(ItemRef {
                id: id.to_owned(),
                kind,
                updated,
            });
        }
        let next = if older || answer.get("has_more").and_then(Value::as_bool) != Some(true) {
            None
        } else {
            answer
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        Ok((items, next))
    }

    async fn fetch_page(&self, item: &ItemRef) -> Result<Document, DocsError> {
        let page = self
            .api
            .get(&format!("/v1/pages/{}", path_id(&item.id)?))
            .await?;
        if gone(&page) {
            return Err(DocsError::NotFound(format!(
                "GET /v1/pages/{}: archived",
                item.id
            )));
        }
        let mut r = Render::default();
        let props = page.get("properties").and_then(Value::as_object);
        let mut title = String::new();
        let mut fields = BTreeMap::new();
        if let Some(props) = props {
            for (name, p) in props {
                if p.get("type").and_then(Value::as_str) == Some("title") {
                    title = r.rich(p.get("title"), false);
                } else if let Some(v) = property_text(p, &mut r) {
                    fields.insert(name.clone(), v);
                }
            }
        }
        let parent = page.get("parent");
        let row = parent.is_some_and(|p| {
            matches!(
                p.get("type").and_then(Value::as_str),
                Some("data_source_id" | "database_id")
            )
        });
        let database = parent.and_then(|p| {
            p.get("data_source_id")
                .or_else(|| p.get("database_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let parent_id = parent.and_then(|p| {
            p.get("page_id")
                .or_else(|| p.get("block_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        self.children(item.id.clone(), 0, &mut r).await?;
        let comments = if self.comments.load(Ordering::Relaxed) {
            self.comments(&item.id).await?
        } else {
            Vec::new()
        };
        let mut authors = BTreeSet::new();
        for k in ["created_by", "last_edited_by"] {
            if let Some(id) = page
                .get(k)
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
            {
                authors.insert(id.to_owned());
            }
        }
        Ok(Document {
            id: item.id.clone(),
            kind: if row { ItemKind::Row } else { ItemKind::Page },
            title: if title.is_empty() {
                "Untitled".into()
            } else {
                title
            },
            url: page.get("url").and_then(Value::as_str).map(str::to_owned),
            parent: if row { None } else { parent_id },
            database: if row { database } else { None },
            space: Some(WORKSPACE.into()),
            created: time_at(&page, "created_time"),
            updated: time_at(&page, "last_edited_time"),
            version: None,
            authors: authors.into_iter().collect(),
            markdown: normalize(&r.md),
            fields,
            links: r.links.into_iter().collect(),
            mentions: r.mentions.into_iter().filter(|m| *m != item.id).collect(),
            attachments: r.attachments,
            comments,
        })
    }

    async fn fetch_source(&self, item: &ItemRef) -> Result<Document, DocsError> {
        let ds = self
            .api
            .get(&format!("/v1/data_sources/{}", path_id(&item.id)?))
            .await?;
        if gone(&ds) {
            return Err(DocsError::NotFound(format!(
                "GET /v1/data_sources/{}: archived",
                item.id
            )));
        }
        let mut r = Render::default();
        let title = r.rich(ds.get("title"), false);
        let description = r.rich(ds.get("description"), true);
        let mut fields = BTreeMap::new();
        if let Some(props) = ds.get("properties").and_then(Value::as_object) {
            for (name, p) in props {
                let ty = p.get("type").and_then(Value::as_str).unwrap_or("unknown");
                let options: Vec<&str> = p
                    .get(ty)
                    .and_then(|t| t.get("options"))
                    .and_then(Value::as_array)
                    .map(|o| {
                        o.iter()
                            .filter_map(|x| x.get("name").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                let v = if options.is_empty() {
                    ty.to_owned()
                } else {
                    format!("{ty}: {}", options.join(", "))
                };
                fields.insert(name.clone(), v);
            }
        }
        let parent = ds
            .get("database_parent")
            .and_then(|p| p.get("page_id").or_else(|| p.get("block_id")))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut authors = BTreeSet::new();
        for k in ["created_by", "last_edited_by"] {
            if let Some(id) = ds.get(k).and_then(|u| u.get("id")).and_then(Value::as_str) {
                authors.insert(id.to_owned());
            }
        }
        Ok(Document {
            id: item.id.clone(),
            kind: ItemKind::Database,
            title: if title.is_empty() {
                "Untitled".into()
            } else {
                title
            },
            url: ds.get("url").and_then(Value::as_str).map(str::to_owned),
            parent,
            database: None,
            space: Some(WORKSPACE.into()),
            created: time_at(&ds, "created_time"),
            updated: time_at(&ds, "last_edited_time"),
            version: None,
            authors: authors.into_iter().collect(),
            markdown: normalize(&description),
            fields,
            links: r.links.into_iter().collect(),
            mentions: r.mentions.into_iter().collect(),
            attachments: Vec::new(),
            comments: Vec::new(),
        })
    }

    /// Renders `id`'s children into `r`, following nested blocks to [`MAX_DEPTH`].
    fn children<'a>(
        &'a self,
        id: String,
        depth: usize,
        r: &'a mut Render,
    ) -> Pin<Box<dyn Future<Output = Result<(), DocsError>> + Send + 'a>> {
        Box::pin(async move {
            let mut cursor: Option<String> = None;
            loop {
                let mut path = format!("/v1/blocks/{}/children?page_size=100", path_id(&id)?);
                if let Some(c) = &cursor {
                    path.push_str("&start_cursor=");
                    path.push_str(&url_component(c));
                }
                let answer = self.api.get(&path).await?;
                let blocks = answer
                    .get("results")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        DocsError::Malformed("GET /v1/blocks/children: no results".into())
                    })?;
                for b in blocks {
                    if r.blocks >= MAX_BLOCKS {
                        if !r.truncated {
                            r.md.push_str(
                                "\n<!-- cut: more blocks than the agent reads from one page -->\n",
                            );
                            r.truncated = true;
                        }
                        return Ok(());
                    }
                    r.blocks += 1;
                    let descend = r.block(b, depth);
                    if descend && depth < MAX_DEPTH {
                        let child = str_at(b, "id")?.to_owned();
                        let transparent = is_transparent(b);
                        self.children(child, if transparent { depth } else { depth + 1 }, r)
                            .await?;
                    }
                }
                if answer.get("has_more").and_then(Value::as_bool) == Some(true) {
                    cursor = answer
                        .get("next_cursor")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if cursor.is_none() {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }
        })
    }

    async fn comments(&self, id: &str) -> Result<Vec<Comment>, DocsError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut path = format!("/v1/comments?block_id={}&page_size=100", path_id(id)?);
            if let Some(c) = &cursor {
                path.push_str("&start_cursor=");
                path.push_str(&url_component(c));
            }
            let answer = match self.api.get(&path).await {
                Ok(a) => a,
                Err(DocsError::Forbidden(_)) => {
                    // The integration lacks "read comments": stop asking for this run.
                    if self.comments.swap(false, Ordering::Relaxed) {
                        tracing::info!(
                            "docs: the Notion integration may not read comments; reading pages without them"
                        );
                    }
                    return Ok(Vec::new());
                }
                Err(e) => return Err(e),
            };
            for c in answer
                .get("results")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let mut r = Render::default();
                let text = r.rich(c.get("rich_text"), true);
                out.push(Comment {
                    id: str_at(c, "id")?.to_owned(),
                    author: c
                        .get("created_by")
                        .and_then(|u| u.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    created: time_at(c, "created_time"),
                    markdown: text,
                });
            }
            if answer.get("has_more").and_then(Value::as_bool) == Some(true) {
                cursor = answer
                    .get("next_cursor")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }
}

impl DocsSource for Notion {
    fn provider(&self) -> &'static str {
        "notion"
    }

    async fn identity(&self) -> Result<SourceIdentity, DocsError> {
        let me = self.api.get("/v1/users/me").await?;
        let id = str_at(&me, "id")?;
        let workspace = me
            .get("bot")
            .and_then(|b| b.get("workspace_name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Notion does not report an integration's capabilities; these are the ones this
        // connector uses, and the setup guide asks for no others.
        let mut scopes = vec!["read_content".to_owned()];
        if self.comments.load(Ordering::Relaxed) {
            scopes.push("read_comments".to_owned());
        }
        Ok(SourceIdentity {
            principal: format!("notion-integration:{id}"),
            workspace,
            scopes,
        })
    }

    async fn spaces(&self, _cursor: Option<String>) -> Result<Batch<Space>, DocsError> {
        let me = self.api.get("/v1/users/me").await?;
        let name = me
            .get("bot")
            .and_then(|b| b.get("workspace_name"))
            .and_then(Value::as_str)
            .unwrap_or("Notion workspace")
            .to_owned();
        Ok(Batch {
            items: vec![Space {
                id: WORKSPACE.into(),
                name,
                url: None,
            }],
            next: None,
        })
    }

    async fn changed(
        &self,
        since: Option<Timestamp>,
        cursor: Option<String>,
    ) -> Result<Batch<ItemRef>, DocsError> {
        // Two listings in turn: pages (rows included), then data sources. The cursor says
        // which, and where in it.
        let (phase, inner) = match cursor.as_deref() {
            None => ("pages", None),
            Some(c) => match c.split_once(':') {
                Some(("pages", rest)) => ("pages", Some(rest)),
                Some(("sources", rest)) => ("sources", Some(rest)),
                _ => {
                    return Err(DocsError::Malformed(
                        "a cursor this source never gave".into(),
                    ));
                }
            },
        };
        if phase == "pages" {
            let (items, next) = self.search("page", since, inner).await?;
            let next = Some(match next {
                Some(n) => format!("pages:{n}"),
                None => "sources:".to_owned(),
            });
            return Ok(Batch { items, next });
        }
        let (items, next) = self.search("data_source", since, inner).await?;
        Ok(Batch {
            items,
            next: next.map(|n| format!("sources:{n}")),
        })
    }

    async fn fetch(&self, item: &ItemRef) -> Result<Document, DocsError> {
        match item.kind {
            ItemKind::Page | ItemKind::Row => self.fetch_page(item).await,
            ItemKind::Database => self.fetch_source(item).await,
        }
    }
}

/// Markdown being built from blocks, with what it links to.
#[derive(Debug, Default)]
struct Render {
    md: String,
    links: BTreeSet<String>,
    mentions: BTreeSet<String>,
    attachments: Vec<Attachment>,
    blocks: usize,
    truncated: bool,
}

impl Render {
    /// Rich text as markdown; `styled` keeps bold, italic, code, strikes and links.
    fn rich(&mut self, v: Option<&Value>, styled: bool) -> String {
        let mut out = String::new();
        for t in v
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let mut text = t
                .get("plain_text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if t.get("type").and_then(Value::as_str) == Some("mention")
                && let Some(m) = t.get("mention")
            {
                for k in ["page", "database", "data_source"] {
                    if let Some(id) = m.get(k).and_then(|p| p.get("id")).and_then(Value::as_str) {
                        self.mentions.insert(id.to_owned());
                    }
                }
            }
            let href = t.get("href").and_then(Value::as_str);
            if let Some(h) = href
                && (h.starts_with("https://") || h.starts_with("http://"))
                && !h.starts_with("https://www.notion.so/")
                && !h.starts_with("https://notion.so/")
            {
                self.links.insert(h.to_owned());
            }
            if styled && !text.trim().is_empty() {
                let a = t.get("annotations");
                let on = |k: &str| a.and_then(|a| a.get(k)).and_then(Value::as_bool) == Some(true);
                if t.get("type").and_then(Value::as_str) == Some("equation") {
                    text = format!("${text}$");
                } else if on("code") {
                    text = format!("`{text}`");
                }
                if on("bold") {
                    text = format!("**{text}**");
                }
                if on("italic") {
                    text = format!("*{text}*");
                }
                if on("strikethrough") {
                    text = format!("~~{text}~~");
                }
                if let Some(h) = href {
                    text = format!("[{text}]({h})");
                }
            }
            out.push_str(&text);
        }
        out
    }

    /// Appends one block; returns whether its children should be read.
    #[allow(clippy::too_many_lines)] // one arm per Notion block type
    fn block(&mut self, b: &Value, depth: usize) -> bool {
        let ty = b.get("type").and_then(Value::as_str).unwrap_or_default();
        let body = b.get(ty);
        let has_children = b.get("has_children").and_then(Value::as_bool) == Some(true);
        let indent = "  ".repeat(depth);
        let text = |r: &mut Self| r.rich(body.and_then(|x| x.get("rich_text")), true);
        let line = match ty {
            "paragraph" => {
                let t = text(self);
                if t.trim().is_empty() {
                    String::new()
                } else {
                    format!("{indent}{t}\n\n")
                }
            }
            "heading_1" | "heading_2" | "heading_3" => {
                let level = 1 + ty.as_bytes()[8] - b'0';
                format!(
                    "{}{} {}\n\n",
                    indent,
                    "#".repeat(usize::from(level)),
                    text(self)
                )
            }
            "bulleted_list_item" | "toggle" => format!("{indent}- {}\n", text(self)),
            "numbered_list_item" => format!("{indent}1. {}\n", text(self)),
            "to_do" => {
                let done =
                    body.and_then(|x| x.get("checked")).and_then(Value::as_bool) == Some(true);
                format!(
                    "{indent}- [{}] {}\n",
                    if done { "x" } else { " " },
                    text(self)
                )
            }
            "quote" | "callout" => format!("{indent}> {}\n\n", text(self)),
            "code" => {
                let lang = body
                    .and_then(|x| x.get("language"))
                    .and_then(Value::as_str)
                    .filter(|l| *l != "plain text")
                    .unwrap_or_default();
                let code = self.rich(body.and_then(|x| x.get("rich_text")), false);
                format!("{indent}```{lang}\n{code}\n{indent}```\n\n")
            }
            "divider" => format!("{indent}---\n\n"),
            "equation" => {
                let e = body
                    .and_then(|x| x.get("expression"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                format!("{indent}$$\n{e}\n$$\n\n")
            }
            "table" => {
                // Rows are the children; a table row is rendered when it comes.
                return has_children;
            }
            "table_row" => {
                let cells: Vec<String> = body
                    .and_then(|x| x.get("cells"))
                    .and_then(Value::as_array)
                    .map(|cells| {
                        cells
                            .iter()
                            .map(|c| super::markdown::cell(&self.rich(Some(c), true)))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut s = format!("| {} |\n", cells.join(" | "));
                if !self.md.ends_with("|\n") {
                    s.push('|');
                    s.push_str(&"---|".repeat(cells.len().max(1)));
                    s.push('\n');
                }
                s
            }
            "image" | "file" | "pdf" | "video" | "audio" => {
                let id = b
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let hosted = body.and_then(|x| x.get("type")).and_then(Value::as_str);
                let external = (hosted == Some("external"))
                    .then(|| {
                        body.and_then(|x| x.get("external"))
                            .and_then(|e| e.get("url"))
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten();
                let name = body
                    .and_then(|x| x.get("name"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .filter(|n| !n.is_empty())
                    .or_else(|| {
                        let c = self.rich(body.and_then(|x| x.get("caption")), false);
                        (!c.is_empty()).then_some(c)
                    })
                    .unwrap_or_else(|| format!("{ty} {id}"));
                // A file Notion hosts comes with a signed link that expires in an hour:
                // a credential, so it is neither kept nor recorded.
                self.attachments.push(Attachment {
                    id,
                    name: name.clone(),
                    media_type: media_type(&name).map(str::to_owned),
                    size: None,
                    url: external.clone(),
                });
                match external {
                    Some(u) => format!("{indent}[{ty}: {name}]({u})\n\n"),
                    None => format!("{indent}[{ty}: {name}]\n\n"),
                }
            }
            "bookmark" | "embed" | "link_preview" => {
                let u = body
                    .and_then(|x| x.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if u.starts_with("https://") || u.starts_with("http://") {
                    self.links.insert(u.clone());
                }
                format!("{indent}<{u}>\n\n")
            }
            "child_page" | "child_database" => {
                let title = body
                    .and_then(|x| x.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or("Untitled");
                if ty == "child_page"
                    && let Some(id) = b.get("id").and_then(Value::as_str)
                {
                    self.mentions.insert(id.to_owned());
                }
                let what = if ty == "child_page" {
                    "page"
                } else {
                    "database"
                };
                // Its content is its own item, read on its own.
                let line = format!("{indent}- [{what}: {title}]\n");
                self.md.push_str(&line);
                return false;
            }
            "link_to_page" => {
                if let Some(id) = body
                    .and_then(|x| x.get("page_id").or_else(|| x.get("database_id")))
                    .and_then(Value::as_str)
                {
                    self.mentions.insert(id.to_owned());
                    format!("{indent}- [link to {id}]\n")
                } else {
                    String::new()
                }
            }
            // Containers: their children are the content.
            "synced_block" | "column_list" | "column" => return has_children,
            // Navigation, templates, buttons and anything newer than this connector.
            _ => return false,
        };
        self.md.push_str(&line);
        has_children
    }
}

/// Containers whose children sit at the same depth.
fn is_transparent(b: &Value) -> bool {
    matches!(
        b.get("type").and_then(Value::as_str),
        Some("synced_block" | "column_list" | "column" | "table")
    )
}

/// A property's value as text; `None` for what is not read (personal contact data,
/// buttons, kinds this connector does not know).
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one arm per property type
fn property_text(p: &Value, r: &mut Render) -> Option<String> {
    let ty = p.get("type").and_then(Value::as_str)?;
    let v = p.get(ty);
    let name_of = |x: Option<&Value>| {
        x.and_then(|s| s.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let ids = |x: Option<&Value>| -> Vec<String> {
        x.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|u| u.get("id").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let out = match ty {
        "rich_text" => r.rich(v, false),
        "number" => v
            .filter(|n| !n.is_null())
            .map(ToString::to_string)
            .unwrap_or_default(),
        "select" | "status" => name_of(v).unwrap_or_default(),
        "multi_select" => v
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.get("name").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        "date" => date_text(v),
        "checkbox" => v.and_then(Value::as_bool).unwrap_or(false).to_string(),
        "url" => {
            let u = v.and_then(Value::as_str).unwrap_or_default().to_owned();
            if u.starts_with("https://") || u.starts_with("http://") {
                r.links.insert(u.clone());
            }
            u
        }
        "people" => ids(v)
            .iter()
            .map(|i| format!("user {i}"))
            .collect::<Vec<_>>()
            .join(", "),
        "created_by" | "last_edited_by" => v
            .and_then(|u| u.get("id"))
            .and_then(Value::as_str)
            .map(|i| format!("user {i}"))
            .unwrap_or_default(),
        "relation" => {
            let rel = ids(v);
            r.mentions.extend(rel.iter().cloned());
            rel.join(", ")
        }
        "files" => v
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.get("name").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        "formula" => {
            let f = v?;
            let fty = f.get("type").and_then(Value::as_str)?;
            match fty {
                "date" => date_text(f.get("date")),
                _ => match f.get(fty)? {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                },
            }
        }
        "rollup" => {
            let f = v?;
            match f.get("type").and_then(Value::as_str)? {
                "number" => f
                    .get("number")
                    .filter(|n| !n.is_null())
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                "date" => date_text(f.get("date")),
                "array" => format!(
                    "{} items",
                    f.get("array").and_then(Value::as_array).map_or(0, Vec::len)
                ),
                _ => return None,
            }
        }
        "created_time" | "last_edited_time" => {
            v.and_then(Value::as_str).unwrap_or_default().to_owned()
        }
        "unique_id" => {
            let n = v
                .and_then(|u| u.get("number"))
                .map(ToString::to_string)
                .unwrap_or_default();
            match v.and_then(|u| u.get("prefix")).and_then(Value::as_str) {
                Some(p) => format!("{p}-{n}"),
                None => n,
            }
        }
        "verification" => v
            .and_then(|x| x.get("state"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        // Personal contact data ("email", "phone_number") is not read, and neither is a
        // button or a kind newer than this connector.
        _ => return None,
    };
    Some(out)
}

fn date_text(v: Option<&Value>) -> String {
    let start = v.and_then(|d| d.get("start")).and_then(Value::as_str);
    let end = v.and_then(|d| d.get("end")).and_then(Value::as_str);
    match (start, end) {
        (Some(s), Some(e)) => format!("{s} to {e}"),
        (Some(s), None) => s.to_owned(),
        _ => String::new(),
    }
}

fn media_type(name: &str) -> Option<&'static str> {
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => return None,
    })
}

fn is_row(r: &Value) -> bool {
    matches!(
        r.get("parent")
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str),
        Some("data_source_id" | "database_id")
    )
}

fn gone(v: &Value) -> bool {
    v.get("in_trash").and_then(Value::as_bool) == Some(true)
        || v.get("archived").and_then(Value::as_bool) == Some(true)
        || v.get("is_archived").and_then(Value::as_bool) == Some(true)
}

fn str_at<'a>(v: &'a Value, k: &str) -> Result<&'a str, DocsError> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| DocsError::Malformed(format!("an object without {k}")))
}

fn time_at(v: &Value, k: &str) -> Option<Timestamp> {
    v.get(k)
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// A Notion id as a path segment: hex digits and dashes only, so an id from an answer can
/// never become another path.
fn path_id(id: &str) -> Result<&str, DocsError> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        Ok(id)
    } else {
        Err(DocsError::Malformed("an id that is not a Notion id".into()))
    }
}

fn url_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_from_answers_cannot_become_paths() {
        assert!(path_id("1f2e3d4c-5b6a-7980-a1b2-c3d4e5f60718").is_ok());
        for bad in ["../users", "a/b", "", "x?y"] {
            assert!(path_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rich_text_keeps_style_links_and_mentions() {
        let mut r = Render::default();
        let v = json!([
            {"type": "text", "plain_text": "Restart ", "annotations": {}},
            {"type": "text", "plain_text": "labs", "annotations": {"bold": true, "code": true}},
            {"type": "text", "plain_text": " per runbook", "href": "https://runbooks.example/labs", "annotations": {}},
            {"type": "mention", "plain_text": "Ops", "mention": {"type": "page", "page": {"id": "abc-1"}}, "href": "https://www.notion.so/abc1", "annotations": {}}
        ]);
        let s = r.rich(Some(&v), true);
        assert_eq!(
            s,
            "Restart **`labs`**[ per runbook](https://runbooks.example/labs)[Ops](https://www.notion.so/abc1)"
        );
        assert!(r.links.contains("https://runbooks.example/labs"));
        assert!(
            !r.links.iter().any(|l| l.contains("notion.so")),
            "internal links are mentions"
        );
        assert!(r.mentions.contains("abc-1"));
    }

    #[test]
    fn hosted_files_never_keep_their_signed_link() {
        let mut r = Render::default();
        let b = json!({
            "id": "f1", "type": "file", "has_children": false,
            "file": {"type": "file", "name": "design.pdf", "file": {"url": "https://s3.example/x?X-Amz-Signature=abc", "expiry_time": "2026-10-08T11:00:00Z"}, "caption": []}
        });
        r.block(&b, 0);
        assert_eq!(r.attachments.len(), 1);
        assert_eq!(r.attachments[0].url, None);
        assert_eq!(
            r.attachments[0].media_type.as_deref(),
            Some("application/pdf")
        );
        assert!(!r.md.contains("Signature"), "{}", r.md);
    }

    #[test]
    fn contact_fields_are_not_read() {
        let mut r = Render::default();
        assert_eq!(
            property_text(&json!({"type": "email", "email": "a@b.c"}), &mut r),
            None
        );
        assert_eq!(
            property_text(
                &json!({"type": "phone_number", "phone_number": "+385"}),
                &mut r
            ),
            None
        );
        assert_eq!(
            property_text(
                &json!({"type": "people", "people": [{"object": "user", "id": "u9"}]}),
                &mut r
            )
            .as_deref(),
            Some("user u9")
        );
    }
}
