//! The decided world as its documents state it (RFC 0086, "Six worlds"): PRDs, ADRs and
//! RFCs, read from a checkout's `docs/prds`, `docs/adrs` and `docs/rfcs`, or from any
//! directory of documents (`atlas observe --decided <dir>`). A deterministic reader, so it
//! reports only what a document says in a form it can read without interpreting:
//!
//! - the front matter: kind, status, title, date, parent, public;
//! - every `decided` block: a fenced block of TOML, one `[[decided]]` table per fact, each
//!   naming a subject by its entity key, a predicate and one typed value (`docs/atlas.md`,
//!   "The decided world"). These are the facts a document decides about the running
//!   system, in the vocabulary the other observers use, so Atlas can set them against what
//!   the code and the cluster say. Each fact is written twice: as `decided.<predicate>` on
//!   its subject, and as a `decision/<document>#<n>` entity that names the document, the
//!   subject, the predicate, the value and the lines it was read from;
//! - the sentences of a `Decision` or `Decisions` section that hold `must`, `only`,
//!   `never` or `always`, as text with their lines: listed, never typed, never compared.
//!   Turning one into a typed fact is a person's job (or a model's proposal a person
//!   confirms), never this reader's.
//!
//! Classified spans (inline and fenced, `docs/rfcs/README.md` in inorbithr/core) are cut
//! before anything is read, keeping line numbers, so nothing inside one reaches an
//! observation; a span that does not close cuts the rest of the document. A block that
//! does not parse is reported as a refusal and read as nothing: the reader never guesses.

use std::path::{Path, PathBuf};

use iohr_evidence::ids::ArtifactObservationId;
use iohr_evidence::vocabulary::Value;
use serde::Deserialize;

use super::common::{Ctx, ObservedNow, method};
use super::record::Sink;
use super::repo::Repo;
use crate::error::Result;

/// The method this reader writes through.
pub const METHOD: &str = "docs.decided";

/// The directories of a checkout read, and the kind a file there is when its front matter
/// names none.
pub const DIRS: [(&str, &str); 3] = [
    ("docs/prds", "prd"),
    ("docs/adrs", "adr"),
    ("docs/rfcs", "rfc"),
];

/// The kinds a file name may start with (`adr-9001-…`).
const KINDS: [&str; 3] = ["prd", "adr", "rfc"];

/// The words that make a sentence of a decision section a constraint.
const CONSTRAINT_WORDS: [&str; 4] = ["must", "only", "never", "always"];

/// The longest sentence kept, in characters.
const MAX_SENTENCE: usize = 600;

/// What reading the documents found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Found {
    /// Documents read.
    pub documents: usize,
    /// Typed facts from `decided` blocks.
    pub decided: usize,
    /// Constraint sentences kept as text.
    pub constraints: usize,
    /// Blocks or facts refused, with why (`path: reason`).
    pub refused: Vec<String>,
}

/// One fact of a `decided` block.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Fact {
    /// The entity the fact is about, by its key (`deployment/tbd/paging`).
    subject: String,
    /// The predicate, without the `decided.` namespace (`egress_only`).
    predicate: String,
    /// Exactly one of the typed values.
    text: Option<String>,
    entity: Option<String>,
    int: Option<i64>,
    bool: Option<bool>,
    /// One line of why, for people; not observed.
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    #[serde(default)]
    decided: Vec<Fact>,
}

/// A fenced block's text and the 1-based lines of its fences in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fenced {
    text: String,
    first: usize,
    last: usize,
}

/// A document's key, from its file name: `adr/0024` for `0024-atlas-store.md` read as an
/// ADR, `rfc/0074.1` for `0074.1-paging.md`, `adr/9001` for `adr-9001-paging.md`.
#[must_use]
pub fn doc_key(kind: &str, file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let rest = KINDS
        .iter()
        .find_map(|k| stem.strip_prefix(k).and_then(|r| r.strip_prefix('-')))
        .unwrap_or(stem);
    let number: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let number = number.trim_end_matches('.');
    if number.is_empty() {
        return None;
    }
    Some(format!("{kind}/{number}"))
}

/// The kind a file name says (`adr-9001-…` is an ADR), if any.
fn kind_in_name(file: &Path) -> Option<&'static str> {
    let stem = file.file_stem()?.to_str()?;
    KINDS
        .iter()
        .copied()
        .find(|k| stem.strip_prefix(k).is_some_and(|r| r.starts_with('-')))
}

/// Cuts classified spans, keeping every line break so line numbers still point at the
/// file: inline `[[classified:…]]…[[/classified]]` and fenced blocks opened by three or
/// more backticks followed by `classified`. An unclosed span cuts to the end.
#[must_use]
pub fn cut_classified(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut fence: Option<usize> = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let ticks = trimmed.bytes().take_while(|&b| b == b'`').count();
        let newline = if line.ends_with('\n') { "\n" } else { "" };
        match fence {
            Some(n) => {
                if ticks >= n && trimmed[ticks..].trim().is_empty() {
                    fence = None;
                }
                kept.push_str(newline);
            }
            None => {
                if ticks >= 3 && trimmed[ticks..].trim_start().starts_with("classified") {
                    fence = Some(ticks);
                    kept.push_str(newline);
                } else {
                    kept.push_str(line);
                }
            }
        }
    }
    let mut out = String::with_capacity(kept.len());
    let mut rest = kept.as_str();
    while let Some(start) = rest.find("[[classified:") {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find("[[/classified]]")
            .map_or(rest.len(), |e| start + e + "[[/classified]]".len());
        let span = &rest[start..end];
        rest = &rest[end..];
        out.extend(std::iter::repeat_n('\n', span.matches('\n').count()));
    }
    out.push_str(rest);
    out
}

/// The front matter's `key: value` lines, and the body with the 1-based line it starts at.
fn split_front_matter(text: &str) -> (Vec<(String, String)>, &str, usize) {
    let Some(after) = text.strip_prefix("---\n") else {
        return (Vec::new(), text, 1);
    };
    let Some(end) = after.find("\n---\n") else {
        return (Vec::new(), text, 1);
    };
    let head = &after[..end];
    let fields = head
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.starts_with(' ') || k.is_empty() {
                return None;
            }
            let v = v.trim().trim_matches('"').trim_matches('\'').to_owned();
            Some((k.trim().to_owned(), v))
        })
        .collect();
    // "---\n" + head + "\n---\n": the body starts after head's lines plus the two fences.
    let body_line = head.lines().count() + 3;
    (fields, &after[end + "\n---\n".len()..], body_line)
}

/// The `decided` blocks of a body: the text between a fence opened by three or more
/// backticks followed by `decided` and the next fence of at least that length, with the
/// fences' lines in the file (`body_line` is the line the body starts at).
fn decided_blocks(body: &str, body_line: usize) -> Vec<Fenced> {
    let mut out = Vec::new();
    let mut open: Option<(usize, usize, String)> = None;
    for (i, line) in body.lines().enumerate() {
        let n = body_line + i;
        let trimmed = line.trim_start();
        let ticks = trimmed.bytes().take_while(|&b| b == b'`').count();
        match &mut open {
            Some((width, first, buf)) => {
                if ticks >= *width && trimmed[ticks..].trim().is_empty() {
                    out.push(Fenced {
                        text: std::mem::take(buf),
                        first: *first,
                        last: n,
                    });
                    open = None;
                } else {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
            None => {
                if ticks >= 3 && trimmed[ticks..].trim() == "decided" {
                    open = Some((ticks, n, String::new()));
                }
            }
        }
    }
    out
}

/// The sentences under a `Decision` or `Decisions` heading (any level) that hold a
/// constraint word, outside code fences, whitespace collapsed, each with the lines it
/// spans.
fn constraint_sentences(body: &str, body_line: usize) -> Vec<(String, usize, usize)> {
    let mut in_section = false;
    let mut section_level = 0usize;
    let mut in_fence = false;
    // Paragraphs of the decision sections: (text, line of each char start).
    let mut paragraphs: Vec<Vec<(usize, String)>> = Vec::new();
    let mut current: Vec<(usize, String)> = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let n = body_line + i;
        let t = line.trim();
        if t.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = t.bytes().take_while(|&b| b == b'#').count();
        if hashes > 0 && t.as_bytes().get(hashes) == Some(&b' ') {
            if !current.is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
            let title = t[hashes..].trim().to_ascii_lowercase();
            if in_section && hashes <= section_level {
                in_section = false;
            }
            if title == "decision" || title == "decisions" {
                in_section = true;
                section_level = hashes;
            }
            continue;
        }
        if !in_section {
            continue;
        }
        if t.is_empty() {
            if !current.is_empty() {
                paragraphs.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push((n, t.to_owned()));
    }
    if !current.is_empty() {
        paragraphs.push(current);
    }
    let mut out = Vec::new();
    for para in paragraphs {
        let mut sentence = String::new();
        let mut first: Option<usize> = None;
        for (n, line) in &para {
            let chars: Vec<char> = line.chars().collect();
            for (i, &c) in chars.iter().enumerate() {
                if first.is_none() && !c.is_whitespace() {
                    first = Some(*n);
                }
                sentence.push(c);
                let ends = matches!(c, '.' | '!' | '?' | ';')
                    && chars.get(i + 1).is_none_or(|x| x.is_whitespace());
                if ends {
                    push_sentence(&mut out, &sentence, first.unwrap_or(*n), *n);
                    sentence.clear();
                    first = None;
                }
            }
            sentence.push(' ');
        }
        if let Some(f) = first {
            let last = para.last().map_or(f, |(n, _)| *n);
            push_sentence(&mut out, &sentence, f, last);
        }
    }
    out
}

fn push_sentence(out: &mut Vec<(String, usize, usize)>, raw: &str, first: usize, last: usize) {
    let s = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > MAX_SENTENCE {
        return;
    }
    let has_word = s
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphabetic())
        .any(|w| CONSTRAINT_WORDS.contains(&w));
    if has_word {
        out.push((s, first, last));
    }
}

/// Turns a fact's value into an evidence value, or says why not.
fn value_of(fact: &Fact, sink: &mut Sink) -> std::result::Result<Value, String> {
    let set = [
        fact.text.is_some(),
        fact.entity.is_some(),
        fact.int.is_some(),
        fact.bool.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if set != 1 {
        return Err(format!(
            "{} {}: exactly one of text, entity, int, bool",
            fact.subject, fact.predicate
        ));
    }
    Ok(if let Some(t) = &fact.text {
        Value::Text(t.clone())
    } else if let Some(e) = &fact.entity {
        Value::Entity(sink.entity(e))
    } else if let Some(n) = fact.int {
        Value::Int(n)
    } else {
        Value::Bool(fact.bool.unwrap_or_default())
    })
}

/// Reads one document and writes what it states. `default_kind` is the kind when neither
/// the front matter nor the file name says one.
///
/// # Errors
/// A record could not be built.
#[allow(clippy::too_many_lines)] // front matter, blocks, sentences, in order
pub fn observe_document(
    ctx: &Ctx,
    sink: &mut Sink,
    rel: &Path,
    default_kind: &str,
    bytes: &[u8],
    artifact: ArtifactObservationId,
    found: &mut Found,
) -> Result<()> {
    let Ok(raw) = std::str::from_utf8(bytes) else {
        found.refused.push(format!("{}: not UTF-8", rel.display()));
        return Ok(());
    };
    let text = cut_classified(&raw.replace("\r\n", "\n"));
    let (fields, body, body_line) = split_front_matter(&text);
    let field = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());
    let kind = field("kind")
        .map(str::to_ascii_lowercase)
        .or_else(|| kind_in_name(rel).map(ToOwned::to_owned))
        .unwrap_or_else(|| default_kind.to_owned());
    let Some(key) = doc_key(&kind, rel) else {
        return Ok(());
    };
    found.documents += 1;
    let doc = format!("document/{key}");
    ctx.observe(
        sink,
        &doc,
        "doc.kind",
        Value::Text(kind.clone()),
        &[artifact],
    )?;
    ctx.observe(
        sink,
        &doc,
        "doc.source",
        Value::Text(rel.to_string_lossy().into_owned()),
        &[artifact],
    )?;
    for (name, pred) in [
        ("status", "doc.status"),
        ("title", "doc.title"),
        ("date", "doc.date"),
    ] {
        if let Some(v) = field(name).filter(|v| !v.is_empty()) {
            ctx.observe(sink, &doc, pred, Value::Text(v.to_owned()), &[artifact])?;
        }
    }
    if let Some(p) = field("public") {
        ctx.observe(
            sink,
            &doc,
            "doc.public",
            Value::Bool(p == "true"),
            &[artifact],
        )?;
    }
    if let Some(parent) = field("parent")
        .filter(|v| !v.is_empty())
        .and_then(|p| doc_key(&kind, Path::new(p)))
    {
        let target = sink.entity(&format!("document/{parent}"));
        ctx.observe(sink, &doc, "doc.parent", Value::Entity(target), &[artifact])?;
    }

    let mut n = 0usize;
    for (i, block) in decided_blocks(body, body_line).into_iter().enumerate() {
        let parsed: Block = match toml::from_str(&block.text) {
            Ok(b) => b,
            Err(e) => {
                found.refused.push(format!(
                    "{}:{}: decided block {}: {}",
                    rel.display(),
                    block.first,
                    i + 1,
                    e.message()
                ));
                continue;
            }
        };
        for fact in parsed.decided {
            let pred = format!("decided.{}", fact.predicate);
            if super::common::predicate(&pred).is_err() || fact.subject.trim().is_empty() {
                found.refused.push(format!(
                    "{}:{}: decided {:?} on {:?}: not a predicate or subject",
                    rel.display(),
                    block.first,
                    fact.predicate,
                    fact.subject
                ));
                continue;
            }
            let value = match value_of(&fact, sink) {
                Ok(v) => v,
                Err(why) => {
                    found
                        .refused
                        .push(format!("{}:{}: {why}", rel.display(), block.first));
                    continue;
                }
            };
            n += 1;
            let decision = format!("decision/{key}#{n}");
            let subject = sink.entity(&fact.subject);
            let document = sink.entity(&doc);
            ctx.observe(sink, &fact.subject, &pred, value.clone(), &[artifact])?;
            ctx.observe(
                sink,
                &decision,
                "decision.document",
                Value::Entity(document),
                &[artifact],
            )?;
            ctx.observe(
                sink,
                &decision,
                "decision.subject",
                Value::Entity(subject),
                &[artifact],
            )?;
            ctx.observe(
                sink,
                &decision,
                "decision.predicate",
                Value::Text(fact.predicate.clone()),
                &[artifact],
            )?;
            ctx.observe(sink, &decision, "decision.value", value, &[artifact])?;
            ctx.observe(
                sink,
                &decision,
                "decision.lines",
                Value::Text(format!("{}-{}", block.first, block.last)),
                &[artifact],
            )?;
            let target = sink.entity(&decision);
            ctx.observe(
                sink,
                &doc,
                "doc.decides",
                Value::Entity(target),
                &[artifact],
            )?;
            found.decided += 1;
        }
    }

    for (s, first, last) in constraint_sentences(body, body_line) {
        let target = format!("statement/{key}@{first}-{last}");
        ctx.observe(sink, &target, "statement.text", Value::Text(s), &[artifact])?;
        ctx.observe(
            sink,
            &target,
            "statement.lines",
            Value::Text(format!("{first}-{last}")),
            &[artifact],
        )?;
        let t = sink.entity(&target);
        ctx.observe(sink, &doc, "doc.states", Value::Entity(t), &[artifact])?;
        found.constraints += 1;
    }
    Ok(())
}

/// Whether `rel` (relative to a checkout) is a document this reader takes, with its
/// default kind.
#[must_use]
pub fn kind_for(rel: &Path) -> Option<&'static str> {
    let parent: PathBuf = rel.parent()?.to_path_buf();
    let name = rel.file_name()?.to_str()?;
    let is_md = Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("md"));
    if !is_md || name.eq_ignore_ascii_case("README.md") {
        return None;
    }
    DIRS.iter()
        .find(|(d, _)| parent == Path::new(d))
        .map(|(_, k)| *k)
}

/// Reads every markdown document under `dir` (READMEs excepted), whatever its layout: the
/// kind comes from the front matter, else the file name (`adr-…`), else the directory
/// (`adrs/`), else `doc`.
///
/// # Errors
/// The directory cannot be read, or a record could not be built.
pub fn observe_dir(dir: &Path, sink: &mut Sink, clock: &ObservedNow) -> Result<Found> {
    let repo = Repo::open(dir)?;
    let principal = std::env::var("USER").unwrap_or_else(|_| "local".to_owned());
    let ctx = Ctx::new(
        sink,
        "decided-document-reader",
        iohr_evidence::observer::ObserverClass::DeterministicExtractor,
        method(METHOD, iohr_evidence::method::MethodCategory::Configuration)?,
        &principal,
        &["read"],
        clock,
    )?;
    let mut found = Found::default();
    for rel in repo.files(&["md"]) {
        if rel
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("README.md"))
        {
            continue;
        }
        let default_kind = rel
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(|n| KINDS.iter().find(|k| n.trim_end_matches('s') == **k))
            .copied()
            .unwrap_or("doc");
        let Some((bytes, artifact)) = repo.read(&ctx, sink, &rel)? else {
            continue;
        };
        observe_document(&ctx, sink, &rel, default_kind, &bytes, artifact, &mut found)?;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::record::Record;
    use iohr_evidence::method::MethodCategory;
    use iohr_evidence::observer::ObserverClass;

    fn ctx(sink: &mut Sink) -> Ctx {
        Ctx::new(
            sink,
            "decided-document-reader",
            ObserverClass::DeterministicExtractor,
            method(METHOD, MethodCategory::Configuration).unwrap(),
            "me",
            &["read"],
            &ObservedNow::now(),
        )
        .unwrap()
    }

    fn observations(sink: &Sink) -> Vec<(String, String, String)> {
        let keys: std::collections::BTreeMap<_, _> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Entity { id, key } => Some((*id, key.clone())),
                _ => None,
            })
            .collect();
        sink.records()
            .iter()
            .filter_map(|r| match r {
                Record::Observation(o) => {
                    let s = o.statement();
                    let v = match &s.value {
                        Value::Text(t) => t.clone(),
                        Value::Entity(e) => keys.get(e).cloned().unwrap_or_default(),
                        Value::Bool(b) => b.to_string(),
                        Value::Int(n) => n.to_string(),
                        other => format!("{other:?}"),
                    };
                    Some((
                        keys.get(&s.subject).cloned().unwrap_or_default(),
                        s.predicate.name.as_str().to_owned(),
                        v,
                    ))
                }
                _ => None,
            })
            .collect()
    }

    fn read(rel: &str, kind: &str, doc: &str) -> (Vec<(String, String, String)>, Found) {
        let mut sink = Sink::default();
        let c = ctx(&mut sink);
        let a = c
            .artifact(&mut sink, &format!("core@x:{rel}"), doc.as_bytes())
            .unwrap();
        let mut found = Found::default();
        observe_document(
            &c,
            &mut sink,
            Path::new(rel),
            kind,
            doc.as_bytes(),
            a,
            &mut found,
        )
        .unwrap();
        (observations(&sink), found)
    }

    fn has(obs: &[(String, String, String)], s: &str, p: &str, v: &str) -> bool {
        obs.iter().any(|(a, b, c)| a == s && b == p && c == v)
    }

    // Line numbers below are of this text: 1 is the first "---".
    const ADR: &str = "---\ntitle: Paging reaches only Apple's push service\nkind: adr\nstatus: proposed\ndate: 2026-10-09\npublic: false\n---\n\n# ADR\n\n## Decision\n\nThe paging service must reach only\nApple's push service. Nothing else changes.\n\n```decided\n[[decided]]\nsubject = \"deployment/tbd/paging\"\npredicate = \"egress_only\"\ntext = \"api.push.apple.com:443\"\n```\n\n## Consequences\n\nIt must be checked always.\n";

    #[test]
    fn a_document_yields_its_front_matter_typed_facts_and_constraint_sentences() {
        let (obs, found) = read("docs/adrs/0067-p.md", "adr", ADR);
        assert!(has(&obs, "document/adr/0067", "doc.status", "proposed"));
        assert!(has(
            &obs,
            "document/adr/0067",
            "doc.source",
            "docs/adrs/0067-p.md"
        ));
        assert!(has(
            &obs,
            "deployment/tbd/paging",
            "decided.egress_only",
            "api.push.apple.com:443"
        ));
        assert!(has(
            &obs,
            "decision/adr/0067#1",
            "decision.document",
            "document/adr/0067"
        ));
        assert!(has(
            &obs,
            "decision/adr/0067#1",
            "decision.subject",
            "deployment/tbd/paging"
        ));
        assert!(has(
            &obs,
            "decision/adr/0067#1",
            "decision.predicate",
            "egress_only"
        ));
        assert!(
            has(&obs, "decision/adr/0067#1", "decision.lines", "16-21"),
            "{obs:?}"
        );
        assert!(has(
            &obs,
            "document/adr/0067",
            "doc.decides",
            "decision/adr/0067#1"
        ));
        assert!(
            has(
                &obs,
                "statement/adr/0067@13-14",
                "statement.text",
                "The paging service must reach only Apple's push service."
            ),
            "{obs:?}"
        );
        assert_eq!(
            found,
            Found {
                documents: 1,
                decided: 1,
                constraints: 1,
                refused: vec![]
            }
        );
    }

    #[test]
    fn classified_spans_never_reach_an_observation_and_keep_the_lines() {
        let doc = "---\nkind: adr\nstatus: accepted\n---\n## Decision\n\nWe must use [[classified:internal reason=\"x\"]]the secret\nhost[[/classified]] for it.\n\n````classified level=internal reason=\"y\"\n```decided\n[[decided]]\nsubject = \"deployment/tbd/secret\"\npredicate = \"egress_only\"\ntext = \"hidden\"\n```\n````\n\n```decided\n[[decided]]\nsubject = \"deployment/tbd/open\"\npredicate = \"egress_only\"\ntext = \"seen\"\n```\n";
        let (obs, found) = read("docs/adrs/0001-a.md", "adr", doc);
        let all = format!("{obs:?}");
        assert!(!all.contains("secret") && !all.contains("hidden"), "{all}");
        assert_eq!(found.decided, 1);
        assert!(
            has(&obs, "decision/adr/0001#1", "decision.lines", "19-24"),
            "{obs:?}"
        );
        assert!(
            has(
                &obs,
                "statement/adr/0001@7-8",
                "statement.text",
                "We must use for it."
            ),
            "{obs:?}"
        );
    }

    #[test]
    fn a_wrong_block_is_refused_whole_and_read_as_nothing() {
        let doc = "---\nkind: rfc\n---\n```decided\n[[decided]]\nsubject = \"a/b\"\npredicate = \"x\"\ntext = \"t\"\nint = 3\n```\n```decided\n[[decided]]\nsubject = \"a/b\"\npredicate = \"x\"\ncolour = \"red\"\n```\n";
        let (_, found) = read("docs/rfcs/0099-a.md", "rfc", doc);
        assert_eq!(found.decided, 0);
        assert_eq!(found.refused.len(), 2, "{:?}", found.refused);
    }

    #[test]
    fn keys_and_kinds_come_from_the_path() {
        assert_eq!(
            doc_key("rfc", Path::new("docs/rfcs/0074.1-paging.md")).as_deref(),
            Some("rfc/0074.1")
        );
        assert_eq!(
            doc_key("adr", Path::new("docs/adrs/0024-atlas-store.md")).as_deref(),
            Some("adr/0024")
        );
        assert_eq!(
            doc_key("adr", Path::new("adr-9001-paging.md")).as_deref(),
            Some("adr/9001")
        );
        assert_eq!(kind_in_name(Path::new("adr-9001-paging.md")), Some("adr"));
        assert_eq!(kind_for(Path::new("docs/adrs/0024-x.md")), Some("adr"));
        assert_eq!(kind_for(Path::new("docs/adrs/README.md")), None);
        assert_eq!(kind_for(Path::new("docs/rfcs/diagrams/x.md")), None);
    }

    #[test]
    fn a_directory_of_documents_is_read_whatever_its_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("adr-9001-paging.md"),
            ADR.replace("kind: adr\n", ""),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# not a document; must be skipped\n",
        )
        .unwrap();
        let mut sink = Sink::default();
        let found = observe_dir(dir.path(), &mut sink, &ObservedNow::now()).unwrap();
        assert_eq!((found.documents, found.decided), (1, 1));
        let obs = observations(&sink);
        assert!(has(&obs, "document/adr/9001", "doc.kind", "adr"));
        assert!(has(
            &obs,
            "deployment/tbd/paging",
            "decided.egress_only",
            "api.push.apple.com:443"
        ));
    }
}
