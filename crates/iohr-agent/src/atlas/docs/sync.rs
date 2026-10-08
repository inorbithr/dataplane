//! The sync engine: one run over one source. Lists what changed since the last complete
//! run (with an overlap, because provider clocks and search indexes lag), fetches only
//! items whose change time moved, writes each document to the local content store, and
//! records each reading as evidence. A run that is cut short (a rate limit that outlasts
//! the retries, an outage, the per-run item cap, a failed fetch) does not advance the
//! cursor, so the next run picks up the rest. A full run also finds what is no longer
//! visible, and deletes the local copy; a refused credential deletes the source's whole
//! store.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::TimeDelta;
use iohr_evidence::digest::ContentDigest;
use iohr_evidence::ids::ArtifactObservationId;
use iohr_evidence::method::{CoverageModel, DataClass, EvidenceMethod, MethodCategory};
use iohr_evidence::observer::ObserverClass;
use iohr_evidence::time::Timestamp;
use iohr_evidence::vocabulary::Value;
use serde::{Deserialize, Serialize};

use super::markdown::{render, render_comments, slug};
use super::{Batch, DocsError, DocsSource, Document, ItemKind, Space};
use crate::atlas::common::{Ctx, ObservedNow, method};
use crate::atlas::record::Sink;
use crate::error::{Error, Result};

/// How far back an incremental run reaches past the last complete one.
pub const OVERLAP: TimeDelta = TimeDelta::minutes(5);
/// Most links, mentions and fields recorded per document; the content store keeps all.
const MAX_FACTS: usize = 200;
const STATE_VERSION: u32 = 1;

/// What one run is asked to do.
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// The source's id from `agent.toml`.
    pub source_id: String,
    /// List everything, not only what changed, and drop what is no longer visible.
    pub full: bool,
    /// Items fetched in this run at most.
    pub max_items: usize,
    /// This source's directory in the content store.
    pub store: PathBuf,
    /// When this run started; the next incremental run lists from here.
    pub now: Timestamp,
}

/// What one run did, in counts. No titles, no content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SyncSummary {
    /// The source's id.
    pub source: String,
    /// The provider.
    pub provider: String,
    /// The workspace or site, by name, as the provider reported it.
    pub workspace: Option<String>,
    /// Spaces seen.
    pub spaces: usize,
    /// Items the listing returned.
    pub listed: usize,
    /// Items read.
    pub fetched: usize,
    /// Items read whose content differed from the last reading (new ones included).
    pub changed: usize,
    /// Items skipped because they had not changed since the last reading.
    pub unchanged: usize,
    /// Items no longer visible (deleted, unshared, archived): local copies removed.
    pub gone: usize,
    /// Items that could not be read this time.
    pub failed: usize,
    /// Whether the listing finished and every read succeeded; only then does the cursor move.
    pub complete: bool,
    /// The credential was refused: the source's local store was deleted.
    pub revoked: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    version: u32,
    provider: String,
    synced_until: Option<Timestamp>,
    items: BTreeMap<String, ItemState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ItemState {
    kind: ItemKind,
    updated: Option<Timestamp>,
    digest: ContentDigest,
    file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comments: Option<ContentDigest>,
}

impl State {
    fn load(store: &Path, provider: &str) -> Result<Self> {
        let path = store.join("state.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let s: Self = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Atlas(format!("{}: {e}", path.display())))?;
                if s.version != STATE_VERSION || s.provider != provider {
                    return Err(Error::Atlas(format!(
                        "{}: kept for another provider or version; remove the directory to start over",
                        store.display()
                    )));
                }
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                version: STATE_VERSION,
                provider: provider.to_owned(),
                ..Self::default()
            }),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    fn save(&self, store: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Atlas(format!("cannot encode the docs state: {e}")))?;
        write_private(&store.join("state.json"), &bytes)
    }
}

/// A file name for an item id: ids are provider data (a URL, say) and never a path.
fn file_for(id: &str) -> String {
    let hex = ContentDigest::of_bytes(id.as_bytes()).to_hex();
    hex.trim_start_matches("sha256:")[..32].to_owned()
}

fn make_private_dir(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| Error::io(dir, e))
}

/// Writes through a temporary file and a rename, readable by this user only.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        make_private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| Error::io(&tmp, e))?;
    f.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
    f.sync_all().map_err(|e| Error::io(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Removes one item's local copies.
fn forget(store: &Path, item: &ItemState) -> Result<()> {
    let items = store.join("items");
    remove_if_present(&items.join(format!("{}.md", item.file)))?;
    remove_if_present(&items.join(format!("{}.comments.md", item.file)))
}

/// A documentation method of a provider: prose, best effort (a source sees only what it
/// was shared, and search indexes lag), changeable at the source, confidential by default
/// (a company's internal documents).
///
/// # Errors
/// The name breaks the method naming rule.
pub fn docs_method(name: &str) -> Result<EvidenceMethod> {
    let mut m = method(name, MethodCategory::Documentation)?;
    m.coverage = CoverageModel::BestEffort;
    m.classification = DataClass::Confidential;
    m.capabilities = BTreeSet::from(["incremental".to_owned()]);
    Ok(m)
}

fn rfc3339(t: Timestamp) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

struct Readers {
    page: Ctx,
    database: Ctx,
    row: Ctx,
    comment: Ctx,
    space: Ctx,
}

impl Readers {
    fn new(
        sink: &mut Sink,
        provider: &str,
        principal: &str,
        scopes: &[String],
        clock: &ObservedNow,
    ) -> Result<Self> {
        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let mut page = Ctx::new(
            sink,
            &format!("{provider}-reader"),
            ObserverClass::DeterministicExtractor,
            docs_method(&format!("{provider}.page.read"))?,
            principal,
            &scopes,
            clock,
        )?;
        // A source reads only what it was shared: "absent" and "not visible to it" cannot
        // be told apart.
        page.authority.sufficient = false;
        let with = |name: &str| -> Result<Ctx> {
            let mut c = page.clone();
            c.method = docs_method(&format!("{provider}.{name}"))?;
            Ok(c)
        };
        Ok(Self {
            database: with("database.read")?,
            row: with("row.read")?,
            comment: with("comment.read")?,
            space: with("space.read")?,
            page,
        })
    }

    const fn of(&self, kind: ItemKind) -> &Ctx {
        match kind {
            ItemKind::Page => &self.page,
            ItemKind::Database => &self.database,
            ItemKind::Row => &self.row,
        }
    }
}

/// Runs one sync of `source` and writes its evidence into `sink`.
///
/// # Errors
/// The store cannot be read or written, the source failed before listing anything other
/// than by refusing the credential, or a record cannot be built.
#[allow(clippy::too_many_lines)] // one run, read top to bottom
pub async fn sync_source<S: DocsSource>(
    source: &S,
    opts: &SyncOptions,
    sink: &mut Sink,
    clock: &ObservedNow,
) -> Result<SyncSummary> {
    let provider = source.provider();
    let mut summary = SyncSummary {
        source: opts.source_id.clone(),
        provider: provider.to_owned(),
        ..SyncSummary::default()
    };
    let identity = match source.identity().await {
        Ok(i) => i,
        Err(DocsError::Unauthorized(why)) => {
            tracing::warn!(source = %opts.source_id, error = %why, "docs: credential refused; deleting this source's local copies");
            purge(&opts.store)?;
            summary.revoked = true;
            return Ok(summary);
        }
        Err(e) => {
            return Err(Error::Atlas(format!("{}: {e}", opts.source_id)));
        }
    };
    summary.workspace.clone_from(&identity.workspace);
    make_private_dir(&opts.store.join("items"))?;
    let mut state = State::load(&opts.store, provider)?;
    let readers = Readers::new(sink, provider, &identity.principal, &identity.scopes, clock)?;

    // Spaces: a failure here is not fatal; the documents carry their space anyway.
    let mut cursor = None;
    loop {
        match source.spaces(cursor.take()).await {
            Ok(Batch { items, next }) => {
                for s in &items {
                    record_space(&readers.space, sink, &opts.source_id, s)?;
                }
                summary.spaces += items.len();
                match next {
                    Some(n) => cursor = Some(n),
                    None => break,
                }
            }
            Err(e) => {
                tracing::warn!(source = %opts.source_id, error = %e, "docs: cannot list spaces");
                break;
            }
        }
    }

    let since = if opts.full {
        None
    } else {
        state.synced_until.map(|t| t - OVERLAP)
    };
    let mut listed: BTreeSet<String> = BTreeSet::new();
    let mut listing_done = false;
    let mut cut_short = false;
    let mut cursor = None;
    'listing: loop {
        let batch = match source.changed(since, cursor.take()).await {
            Ok(b) => b,
            Err(DocsError::Unauthorized(why)) => {
                tracing::warn!(source = %opts.source_id, error = %why, "docs: credential refused; deleting this source's local copies");
                purge(&opts.store)?;
                summary.revoked = true;
                return Ok(summary);
            }
            Err(e) => {
                tracing::warn!(source = %opts.source_id, error = %e, "docs: listing stopped");
                break;
            }
        };
        for item in batch.items {
            if !listed.insert(item.id.clone()) {
                continue;
            }
            summary.listed += 1;
            if let Some(known) = state.items.get(&item.id)
                && item.updated.is_some()
                && known.updated == item.updated
            {
                summary.unchanged += 1;
                continue;
            }
            if summary.fetched >= opts.max_items {
                tracing::info!(source = %opts.source_id, max = opts.max_items, "docs: per-run item cap reached; the next run continues");
                cut_short = true;
                break 'listing;
            }
            match source.fetch(&item).await {
                Ok(doc) => {
                    summary.fetched += 1;
                    let changed = store_and_record(&readers, sink, opts, &mut state, &doc)?;
                    if changed {
                        summary.changed += 1;
                    }
                }
                Err(e) if e.is_gone() => {
                    if let Some(old) = state.items.remove(&item.id) {
                        forget(&opts.store, &old)?;
                    }
                    summary.gone += 1;
                }
                Err(DocsError::Unauthorized(why)) => {
                    tracing::warn!(source = %opts.source_id, error = %why, "docs: credential refused; deleting this source's local copies");
                    purge(&opts.store)?;
                    summary.revoked = true;
                    return Ok(summary);
                }
                Err(e @ DocsError::RateLimited { .. }) => {
                    tracing::warn!(source = %opts.source_id, item = %item.id, error = %e, "docs: rate limited; the next run continues");
                    summary.failed += 1;
                    cut_short = true;
                    break 'listing;
                }
                Err(e) => {
                    tracing::warn!(source = %opts.source_id, item = %item.id, error = %e, "docs: cannot read an item");
                    summary.failed += 1;
                }
            }
        }
        if let Some(n) = batch.next {
            cursor = Some(n);
        } else {
            listing_done = true;
            break;
        }
    }

    if opts.full && listing_done && !cut_short {
        let unseen: Vec<String> = state
            .items
            .keys()
            .filter(|id| !listed.contains(*id))
            .cloned()
            .collect();
        for id in unseen {
            if let Some(old) = state.items.remove(&id) {
                forget(&opts.store, &old)?;
                summary.gone += 1;
            }
        }
    }
    summary.complete = listing_done && !cut_short && summary.failed == 0;
    if summary.complete {
        state.synced_until = Some(opts.now);
    }
    state.save(&opts.store)?;
    tracing::info!(
        source = %opts.source_id,
        provider,
        listed = summary.listed,
        fetched = summary.fetched,
        changed = summary.changed,
        unchanged = summary.unchanged,
        gone = summary.gone,
        failed = summary.failed,
        complete = summary.complete,
        "docs: sync done"
    );
    Ok(summary)
}

/// Deletes a source's whole local store.
fn purge(store: &Path) -> Result<()> {
    match std::fs::remove_dir_all(store) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(store, e)),
    }
}

fn record_space(ctx: &Ctx, sink: &mut Sink, source_id: &str, s: &Space) -> Result<()> {
    let key = format!("space/{source_id}/{}", s.id);
    let a = ctx.artifact(
        sink,
        &format!("{}:{source_id}/space/{}", ctx_provider(ctx), s.id),
        s.name.as_bytes(),
    )?;
    ctx.observe(sink, &key, "space.name", Value::Text(s.name.clone()), &[a])?;
    if let Some(u) = &s.url {
        ctx.observe(sink, &key, "space.url", Value::Text(u.clone()), &[a])?;
    }
    Ok(())
}

fn ctx_provider(ctx: &Ctx) -> String {
    ctx.method
        .name
        .to_string()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Writes a document's copies and records it; returns whether its content changed.
#[allow(clippy::too_many_lines)] // one fact after another
fn store_and_record(
    readers: &Readers,
    sink: &mut Sink,
    opts: &SyncOptions,
    state: &mut State,
    doc: &Document,
) -> Result<bool> {
    let sid = &opts.source_id;
    let ctx = readers.of(doc.kind);
    let provider = ctx_provider(ctx);
    let file = file_for(&doc.id);
    let items = opts.store.join("items");

    let body = render(doc);
    write_private(&items.join(format!("{file}.md")), body.as_bytes())?;
    let digest = ContentDigest::of_bytes(body.as_bytes());
    let changed = state
        .items
        .get(&doc.id)
        .is_none_or(|old| old.digest != digest);

    let version = doc
        .version
        .clone()
        .or_else(|| doc.updated.map(rfc3339))
        .unwrap_or_else(|| "unversioned".to_owned());
    let location = format!("{provider}:{sid}/{}/{}@{version}", doc.kind.noun(), doc.id);
    let a = ctx.artifact(sink, &location, body.as_bytes())?;
    let from: [ArtifactObservationId; 1] = [a];
    let key = format!("doc/{sid}/{}", doc.id);
    ctx.observe(
        sink,
        &key,
        "doc.title",
        Value::Text(doc.title.clone()),
        &from,
    )?;
    ctx.observe(
        sink,
        &key,
        "doc.kind",
        Value::Text(doc.kind.noun().to_owned()),
        &from,
    )?;
    if let Some(u) = &doc.url {
        ctx.observe(sink, &key, "doc.url", Value::Text(u.clone()), &from)?;
    }
    if let Some(t) = doc.created {
        ctx.observe(sink, &key, "doc.created_at", Value::Text(rfc3339(t)), &from)?;
    }
    if let Some(t) = doc.updated {
        ctx.observe(sink, &key, "doc.updated_at", Value::Text(rfc3339(t)), &from)?;
    }
    for author in &doc.authors {
        let who = sink.entity(&format!("person/{sid}/{author}"));
        ctx.observe(sink, &key, "doc.author", Value::Entity(who), &from)?;
    }
    for (pred, target) in [
        (
            "doc.parent",
            doc.parent.as_ref().map(|p| format!("doc/{sid}/{p}")),
        ),
        (
            "doc.in_database",
            doc.database.as_ref().map(|p| format!("doc/{sid}/{p}")),
        ),
        (
            "doc.in_space",
            doc.space.as_ref().map(|p| format!("space/{sid}/{p}")),
        ),
    ] {
        if let Some(t) = target {
            let e = sink.entity(&t);
            ctx.observe(sink, &key, pred, Value::Entity(e), &from)?;
        }
    }
    for link in doc.links.iter().take(MAX_FACTS) {
        ctx.observe(sink, &key, "doc.links_to", Value::Text(link.clone()), &from)?;
    }
    for m in doc.mentions.iter().take(MAX_FACTS) {
        let e = sink.entity(&format!("doc/{sid}/{m}"));
        ctx.observe(sink, &key, "doc.mentions", Value::Entity(e), &from)?;
    }
    for (name, value) in doc.fields.iter().take(MAX_FACTS) {
        if let Some(s) = slug(name) {
            ctx.observe(
                sink,
                &key,
                &format!("doc.field.{s}"),
                Value::Text(value.clone()),
                &from,
            )?;
        }
    }
    for att in doc.attachments.iter().take(MAX_FACTS) {
        let akey = format!("attachment/{sid}/{}", att.id);
        let e = sink.entity(&akey);
        ctx.observe(sink, &key, "doc.has_attachment", Value::Entity(e), &from)?;
        ctx.observe(
            sink,
            &akey,
            "attachment.name",
            Value::Text(att.name.clone()),
            &from,
        )?;
        if let Some(m) = &att.media_type {
            ctx.observe(
                sink,
                &akey,
                "attachment.media_type",
                Value::Text(m.clone()),
                &from,
            )?;
        }
        if let Some(n) = att.size.and_then(|n| i64::try_from(n).ok()) {
            ctx.observe(sink, &akey, "attachment.size_bytes", Value::Int(n), &from)?;
        }
        if let Some(u) = &att.url {
            ctx.observe(sink, &akey, "attachment.url", Value::Text(u.clone()), &from)?;
        }
    }

    let comments_path = items.join(format!("{file}.comments.md"));
    let comments = if doc.comments.is_empty() {
        remove_if_present(&comments_path)?;
        None
    } else {
        let text = render_comments(&doc.comments);
        write_private(&comments_path, text.as_bytes())?;
        let c = &readers.comment;
        let ca = c.artifact(sink, &format!("{location}#comments"), text.as_bytes())?;
        let n = i64::try_from(doc.comments.len()).unwrap_or(i64::MAX);
        c.observe(sink, &key, "doc.comment_count", Value::Int(n), &[ca])?;
        Some(ContentDigest::of_bytes(text.as_bytes()))
    };

    state.items.insert(
        doc.id.clone(),
        ItemState {
            kind: doc.kind,
            updated: doc.updated,
            digest,
            file,
            comments,
        },
    );
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::TimeZone as _;
    use iohr_evidence::evidence::EvidenceRef;

    use super::super::mock::{MockSource, doc};
    use super::*;
    use crate::atlas::record::Record;

    fn at(s: i64) -> Timestamp {
        // Minutes, so the overlap (five minutes) is small next to the gaps between runs.
        chrono::Utc
            .timestamp_opt(1_800_000_000 + s * 60, 0)
            .unwrap()
    }

    fn opts(dir: &Path, now: i64, full: bool) -> SyncOptions {
        SyncOptions {
            source_id: "eng".into(),
            full,
            max_items: 100,
            store: dir.join("eng"),
            now: at(now),
        }
    }

    async fn run(src: &MockSource, o: &SyncOptions) -> (Sink, SyncSummary) {
        let mut sink = Sink::default();
        let s = sync_source(src, o, &mut sink, &ObservedNow::now())
            .await
            .unwrap();
        (sink, s)
    }

    fn methods(sink: &Sink) -> BTreeSet<(String, MethodCategory)> {
        sink.records()
            .iter()
            .filter_map(|r| match r {
                Record::Evidence(i) => Some((i.method.name.to_string(), i.method.category)),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn each_item_becomes_a_documentation_artefact_that_can_never_prove() {
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock")
            .with(doc(
                "p1",
                ItemKind::Page,
                at(10),
                "Runbook",
                "Restart the **labs** pod.",
            ))
            .with(doc("r1", ItemKind::Row, at(11), "Labs", "Owned by SRE."));
        let (sink, s) = run(&src, &opts(dir.path(), 100, false)).await;
        assert_eq!((s.listed, s.fetched, s.changed, s.failed), (2, 2, 2, 0));
        assert!(s.complete);
        let ms = methods(&sink);
        assert!(ms.contains(&("mock.page.read".into(), MethodCategory::Documentation)));
        assert!(ms.contains(&("mock.row.read".into(), MethodCategory::Documentation)));
        for r in sink.records() {
            if let Record::Evidence(i) = r {
                assert!(!i.method.category.may_prove(), "documentation never proves");
                assert_eq!(i.class, ObserverClass::DeterministicExtractor);
            }
            if let Record::Artifact(a) = r {
                assert!(
                    a.artifact().location.starts_with("mock:eng/"),
                    "{}",
                    a.artifact().location
                );
            }
        }
        let arts = sink
            .records()
            .iter()
            .filter(|r| matches!(r, Record::Artifact(_)))
            .count();
        assert_eq!(arts, 3, "a space and two documents");
        let stored = std::fs::read_to_string(
            dir.path()
                .join("eng/items")
                .join(format!("{}.md", file_for("p1"))),
        )
        .unwrap();
        assert!(stored.contains("Restart the **labs** pod."));
        // The digest in the evidence is the digest of the stored bytes.
        let digest = ContentDigest::of_bytes(stored.as_bytes());
        assert!(
            sink.records()
                .iter()
                .any(|r| matches!(r, Record::Artifact(a) if a.artifact().digest == digest))
        );
        // Every observation cites the artefact it came from.
        for r in sink.records() {
            if let Record::Evidence(i) = r
                && matches!(i.reference, EvidenceRef::Observation(_))
            {
                assert_eq!(i.ancestors.len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn a_second_run_reads_only_what_changed() {
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock")
            .with(doc("p1", ItemKind::Page, at(10), "A", "one"))
            .with(doc("p2", ItemKind::Page, at(20), "B", "two"));
        let (_, s1) = run(&src, &opts(dir.path(), 100, false)).await;
        assert_eq!(s1.fetched, 2);
        src.edit("p2", at(200), "two, edited");
        let (_, s2) = run(&src, &opts(dir.path(), 300, false)).await;
        assert_eq!((s2.fetched, s2.changed, s2.unchanged), (1, 1, 0), "{s2:?}");
        assert_eq!(
            src.since_asked().last().copied().flatten(),
            Some(at(100) - OVERLAP)
        );
        // Touched without a change: read again, same digest.
        src.edit("p2", at(400), "two, edited");
        let (_, s3) = run(&src, &opts(dir.path(), 500, false)).await;
        assert_eq!((s3.fetched, s3.changed), (1, 0), "{s3:?}");
    }

    #[tokio::test]
    async fn an_unshared_item_loses_its_local_copy() {
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock")
            .with(doc("p1", ItemKind::Page, at(10), "A", "one"))
            .with(doc("p2", ItemKind::Page, at(20), "B", "two"));
        run(&src, &opts(dir.path(), 100, false)).await;
        let copy = dir
            .path()
            .join("eng/items")
            .join(format!("{}.md", file_for("p2")));
        assert!(copy.exists());
        // Unshared and touched: the fetch is refused.
        src.fail_fetch("p2", DocsError::Forbidden("GET /p2: 403".into()));
        src.edit("p2", at(200), "two");
        let (_, s) = run(&src, &opts(dir.path(), 300, false)).await;
        assert_eq!(s.gone, 1);
        assert!(!copy.exists());
        src.remove("p2");
        src.clear_failures();
        // Removed without a trace: only a full run notices.
        src.remove("p1");
        let (_, s) = run(&src, &opts(dir.path(), 400, false)).await;
        assert_eq!(s.gone, 0);
        let (_, s) = run(&src, &opts(dir.path(), 500, true)).await;
        assert_eq!(s.gone, 1, "{s:?}");
        assert!(
            !dir.path()
                .join("eng/items")
                .join(format!("{}.md", file_for("p1")))
                .exists()
        );
    }

    #[tokio::test]
    async fn a_revoked_credential_deletes_the_whole_store() {
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock").with(doc("p1", ItemKind::Page, at(10), "A", "one"));
        run(&src, &opts(dir.path(), 100, false)).await;
        assert!(dir.path().join("eng/state.json").exists());
        src.fail_identity(DocsError::Unauthorized("GET /me: 401".into()));
        let (sink, s) = run(&src, &opts(dir.path(), 200, false)).await;
        assert!(s.revoked && !s.complete);
        assert!(sink.records().is_empty());
        assert!(!dir.path().join("eng").exists());
    }

    #[tokio::test]
    async fn a_rate_limit_or_outage_does_not_move_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock")
            .with(doc("p1", ItemKind::Page, at(10), "A", "one"))
            .with(doc("p2", ItemKind::Page, at(20), "B", "two"))
            .page_size(1);
        src.fail_listing_after(
            1,
            DocsError::RateLimited {
                what: "POST /search".into(),
                retry_after: None,
            },
        );
        let (_, s) = run(&src, &opts(dir.path(), 100, false)).await;
        assert!(!s.complete);
        assert_eq!(s.fetched, 1);
        src.clear_failures();
        let (_, s) = run(&src, &opts(dir.path(), 200, false)).await;
        assert!(s.complete, "{s:?}");
        assert_eq!(
            src.since_asked().last().copied().flatten(),
            None,
            "no complete run yet: list from the start"
        );
        assert_eq!((s.fetched, s.unchanged), (1, 1));

        src.fail_fetch("p2", DocsError::Unavailable("GET /p2: 503".into()));
        src.edit("p2", at(300), "two!");
        let (_, s) = run(&src, &opts(dir.path(), 400, false)).await;
        assert_eq!((s.failed, s.complete), (1, false));
        src.clear_failures();
        let (_, s) = run(&src, &opts(dir.path(), 500, false)).await;
        assert_eq!(
            src.since_asked().last().copied().flatten(),
            Some(at(200) - OVERLAP)
        );
        assert_eq!((s.fetched, s.changed), (1, 1));
    }

    #[tokio::test]
    async fn the_item_cap_stops_a_run_and_the_next_one_continues() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = MockSource::new("mock");
        for i in 0..5 {
            src = src.with(doc(&format!("p{i}"), ItemKind::Page, at(i), "T", "x"));
        }
        let mut o = opts(dir.path(), 100, false);
        o.max_items = 3;
        let (_, s) = run(&src, &o).await;
        assert_eq!((s.fetched, s.complete), (3, false));
        let (_, s) = run(&src, &o).await;
        assert_eq!((s.fetched, s.unchanged, s.complete), (2, 3, true));
    }

    #[tokio::test]
    async fn content_never_reaches_the_records_or_the_logs() {
        const CANARY: &str = "CANARY-7f3a9-do-not-leak";
        let dir = tempfile::tempdir().unwrap();
        let src = MockSource::new("mock")
            .with(doc(
                "p1",
                ItemKind::Page,
                at(10),
                "Title",
                &format!("secret body {CANARY}"),
            ))
            .with(doc("p2", ItemKind::Page, at(10), "T2", "x"));
        src.fail_fetch("p2", DocsError::Malformed("GET /p2: not JSON".into()));
        let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
        let w = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || LogWriter(w.clone()))
            .finish();
        let _g = tracing::subscriber::set_default(subscriber);
        let (sink, _) = run(&src, &opts(dir.path(), 100, false)).await;
        let mut out = Vec::new();
        sink.write_to(&mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.contains(CANARY),
            "the records carry digests, never the content"
        );
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("docs: sync done"),
            "the subscriber saw the run: {logs}"
        );
        assert!(!logs.contains(CANARY));
        let state = std::fs::read_to_string(dir.path().join("eng/state.json")).unwrap();
        assert!(!state.contains(CANARY));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let f = dir
                .path()
                .join("eng/items")
                .join(format!("{}.md", file_for("p1")));
            assert_eq!(
                std::fs::metadata(f).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let d = dir.path().join("eng/items");
            assert_eq!(
                std::fs::metadata(d).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[tokio::test]
    async fn another_providers_store_is_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let a = MockSource::new("mock").with(doc("p1", ItemKind::Page, at(10), "A", "one"));
        run(&a, &opts(dir.path(), 100, false)).await;
        let b = MockSource::new("other").with(doc("p1", ItemKind::Page, at(10), "A", "one"));
        let e = sync_source(
            &b,
            &opts(dir.path(), 200, false),
            &mut Sink::default(),
            &ObservedNow::now(),
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("another provider"), "{e}");
    }

    #[derive(Clone)]
    struct LogWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
