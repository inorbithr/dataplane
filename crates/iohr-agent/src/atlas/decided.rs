//! The decided world as its documents state it (RFC 0086, "Six worlds"): PRDs, ADRs and
//! RFCs read from a checkout's `docs/prds`, `docs/adrs` and `docs/rfcs`. A deterministic
//! reader, so it reports only what a document says in a form it can read without
//! interpreting:
//!
//! - the front matter: kind, status, title, date, parent, public;
//! - every `decided` block: a fenced block of TOML, one `[[decided]]` table per fact, each
//!   naming a subject by its entity key, a predicate and one typed value. These are the
//!   facts a document decides about the running system, in the vocabulary the other
//!   observers use, so Atlas can set them against what the code and the cluster say;
//! - the sentences of a `Decision` or `Decisions` section that hold `must`, `only`,
//!   `never` or `always`, as text: listed, never typed, never compared. Turning one into a
//!   typed fact is a person's job (or a model's proposal a person confirms), never this
//!   reader's.
//!
//! Classified spans (inline and fenced, `docs/rfcs/README.md`) are cut before anything is
//! read, so nothing inside one reaches an observation; a span that does not close cuts the
//! rest of the document. A block that does not parse is reported as a refusal and read
//! as nothing: the reader never guesses.

use std::path::{Path, PathBuf};

use iohr_evidence::ids::ArtifactObservationId;
use iohr_evidence::vocabulary::Value;
use serde::Deserialize;

use super::common::Ctx;
use super::record::Sink;
use crate::error::Result;

/// The directories read, and the kind a file there is when its front matter names none.
pub const DIRS: [(&str, &str); 3] = [
    ("docs/prds", "prd"),
    ("docs/adrs", "adr"),
    ("docs/rfcs", "rfc"),
];

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

/// A document's key: `adr/0024`, `rfc/0074.1`, `prd/0001`, from its file name.
#[must_use]
pub fn doc_key(kind: &str, file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let number: String = stem
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let number = number.trim_end_matches('.');
    if number.is_empty() {
        return None;
    }
    Some(format!("{kind}/{number}"))
}

/// Cuts classified spans: inline `[[classified:…]]…[[/classified]]` and fenced blocks
/// opened by three or more backticks followed by `classified`. An unclosed span cuts to
/// the end.
#[must_use]
pub fn cut_classified(text: &str) -> String {
    // Fenced blocks first, line by line.
    let mut kept = String::with_capacity(text.len());
    let mut fence: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let ticks = trimmed.bytes().take_while(|&b| b == b'`').count();
        match fence {
            Some(n) => {
                if ticks >= n && trimmed[ticks..].trim().is_empty() {
                    fence = None;
                }
            }
            None => {
                if ticks >= 3 && trimmed[ticks..].trim_start().starts_with("classified") {
                    fence = Some(ticks);
                } else {
                    kept.push_str(line);
                    kept.push('\n');
                }
            }
        }
    }
    // Then inline spans.
    let mut out = String::with_capacity(kept.len());
    let mut rest = kept.as_str();
    while let Some(start) = rest.find("[[classified:") {
        out.push_str(&rest[..start]);
        match rest[start..].find("[[/classified]]") {
            Some(end) => rest = &rest[start + end + "[[/classified]]".len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The front matter's `key: value` lines and the body after it.
fn split_front_matter(text: &str) -> (Vec<(String, String)>, &str) {
    let Some(after) = text.strip_prefix("---\n") else {
        return (Vec::new(), text);
    };
    let Some(end) = after.find("\n---\n") else {
        return (Vec::new(), text);
    };
    let fields = after[..end]
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
    (fields, &after[end + "\n---\n".len()..])
}

/// The `decided` blocks of a body: the text between a fence opened by three or more
/// backticks followed by `decided` and the next fence of at least that length.
fn decided_blocks(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        let ticks = trimmed.bytes().take_while(|&b| b == b'`').count();
        match &mut open {
            Some((n, buf)) => {
                if ticks >= *n && trimmed[ticks..].trim().is_empty() {
                    out.push(std::mem::take(buf));
                    open = None;
                } else {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
            None => {
                if ticks >= 3 && trimmed[ticks..].trim() == "decided" {
                    open = Some((ticks, String::new()));
                }
            }
        }
    }
    out
}

/// The sentences under a `Decision` or `Decisions` heading (any level) that hold a
/// constraint word, outside code fences, whitespace collapsed.
fn constraint_sentences(body: &str) -> Vec<String> {
    let mut in_section = false;
    let mut section_level = 0usize;
    let mut in_fence = false;
    let mut text = String::new();
    for line in body.lines() {
        let t = line.trim_start();
        if t.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = t.bytes().take_while(|&b| b == b'#').count();
        if hashes > 0 && t.as_bytes().get(hashes) == Some(&b' ') {
            let title = t[hashes..].trim().to_ascii_lowercase();
            if in_section && hashes <= section_level {
                in_section = false;
            }
            if title == "decision" || title == "decisions" {
                in_section = true;
                section_level = hashes;
            }
            text.push('\n');
            continue;
        }
        if in_section {
            text.push_str(t);
            text.push(' ');
        }
    }
    let mut out = Vec::new();
    for raw in text.split(['\n']).flat_map(split_sentences) {
        let s = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        if s.is_empty() || s.chars().count() > MAX_SENTENCE {
            continue;
        }
        let lower = s.to_ascii_lowercase();
        let has_word = lower
            .split(|c: char| !c.is_ascii_alphabetic())
            .any(|w| CONSTRAINT_WORDS.contains(&w));
        if has_word {
            out.push(s);
        }
    }
    out
}

fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = text.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        cur.push(c);
        let next_is_space = chars.get(i + 1).is_none_or(|n| n.is_whitespace());
        if matches!(c, '.' | '!' | '?' | ';') && next_is_space {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
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

/// Reads one document and writes what it states.
///
/// # Errors
/// A record could not be built.
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
    let (fields, body) = split_front_matter(&text);
    let field = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());
    let kind = field("kind").unwrap_or(default_kind).to_ascii_lowercase();
    let Some(key) = doc_key(&kind, rel) else {
        return Ok(());
    };
    found.documents += 1;
    let doc = format!("document/{key}");
    ctx.observe(sink, &doc, "doc.kind", Value::Text(kind.clone()), &[artifact])?;
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
        ctx.observe(sink, &doc, "doc.public", Value::Bool(p == "true"), &[artifact])?;
    }
    if let Some(parent) = field("parent")
        .filter(|v| !v.is_empty())
        .and_then(|p| doc_key(&kind, Path::new(p)))
    {
        let target = sink.entity(&format!("document/{parent}"));
        ctx.observe(sink, &doc, "doc.parent", Value::Entity(target), &[artifact])?;
    }

    for (i, block) in decided_blocks(body).into_iter().enumerate() {
        let parsed: Block = match toml::from_str(&block) {
            Ok(b) => b,
            Err(e) => {
                found.refused.push(format!(
                    "{}: decided block {}: {}",
                    rel.display(),
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
                    "{}: decided {:?} on {:?}: not a predicate or subject",
                    rel.display(),
                    fact.predicate,
                    fact.subject
                ));
                continue;
            }
            let value = match value_of(&fact, sink) {
                Ok(v) => v,
                Err(why) => {
                    found.refused.push(format!("{}: {why}", rel.display()));
                    continue;
                }
            };
            ctx.observe(sink, &fact.subject, &pred, value, &[artifact])?;
            let target = sink.entity(&fact.subject);
            ctx.observe(sink, &doc, "doc.decides", Value::Entity(target), &[artifact])?;
            found.decided += 1;
        }
    }

    for s in constraint_sentences(body) {
        ctx.observe(sink, &doc, "doc.states", Value::Text(s), &[artifact])?;
        found.constraints += 1;
    }
    Ok(())
}

/// Whether `rel` is a document this reader takes, with its default kind.
#[must_use]
pub fn kind_for(rel: &Path) -> Option<&'static str> {
    let parent: PathBuf = rel.parent()?.to_path_buf();
    let name = rel.file_name()?.to_str()?;
    if !name.ends_with(".md") || name.eq_ignore_ascii_case("README.md") {
        return None;
    }
    DIRS.iter()
        .find(|(d, _)| parent == Path::new(d))
        .map(|(_, k)| *k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::common::{ObservedNow, method};
    use crate::atlas::record::Record;
    use iohr_evidence::method::MethodCategory;
    use iohr_evidence::observer::ObserverClass;

    fn ctx(sink: &mut Sink) -> Ctx {
        Ctx::new(
            sink,
            "decided-document-reader",
            ObserverClass::DeterministicExtractor,
            method("docs.decided", MethodCategory::Configuration).unwrap(),
            "me",
            &["read"],
            &ObservedNow::now(),
        )
        .unwrap()
    }

    fn observations(sink: &Sink) -> Vec<(String, String, Value)> {
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
                    Some((
                        keys.get(&s.subject).cloned().unwrap_or_default(),
                        s.predicate.name.as_str().to_owned(),
                        s.value.clone(),
                    ))
                }
                _ => None,
            })
            .collect()
    }

    const ADR: &str = "---\ntitle: Paging reaches only Apple's push service\nkind: adr\nstatus: proposed\ndate: 2026-10-09\npublic: false\n---\n\n# ADR\n\n## Decision\n\nThe paging service must reach only Apple's push service. Nothing else changes.\n\n```decided\n[[decided]]\nsubject = \"deployment/tbd/paging\"\npredicate = \"egress_only\"\ntext = \"api.push.apple.com:443\"\n```\n\n## Consequences\n\nIt must be checked always.\n";

    #[test]
    fn a_document_yields_its_front_matter_typed_facts_and_constraint_sentences() {
        let mut sink = Sink::default();
        let c = ctx(&mut sink);
        let a = c.artifact(&mut sink, "core@x:docs/adrs/0067-p.md", ADR.as_bytes()).unwrap();
        let mut found = Found::default();
        observe_document(&c, &mut sink, Path::new("docs/adrs/0067-p.md"), "adr", ADR.as_bytes(), a, &mut found).unwrap();
        let obs = observations(&sink);
        assert!(obs.contains(&("document/adr/0067".into(), "doc.status".into(), Value::Text("proposed".into()))));
        assert!(obs.contains(&("deployment/tbd/paging".into(), "decided.egress_only".into(), Value::Text("api.push.apple.com:443".into()))));
        assert!(obs.iter().any(|(s, p, _)| s == "document/adr/0067" && p == "doc.decides"));
        let states: Vec<_> = obs.iter().filter(|(_, p, _)| p == "doc.states").collect();
        assert_eq!(states.len(), 1, "only the decision section's sentence: {states:?}");
        assert_eq!(found, Found { documents: 1, decided: 1, constraints: 1, refused: vec![] });
    }

    #[test]
    fn classified_spans_never_reach_an_observation() {
        let doc = "---\nkind: adr\nstatus: accepted\n---\n## Decision\n\nWe must use [[classified:internal reason=\"x\"]]the secret host[[/classified]] for it.\n\n```classified level=internal reason=\"y\"\n```decided\n[[decided]]\nsubject = \"deployment/tbd/secret\"\npredicate = \"egress_only\"\ntext = \"hidden\"\n```\n```\n";
        let mut sink = Sink::default();
        let c = ctx(&mut sink);
        let a = c.artifact(&mut sink, "core@x:docs/adrs/0001-a.md", doc.as_bytes()).unwrap();
        let mut found = Found::default();
        observe_document(&c, &mut sink, Path::new("docs/adrs/0001-a.md"), "adr", doc.as_bytes(), a, &mut found).unwrap();
        let all = format!("{:?}", observations(&sink));
        assert!(!all.contains("secret host") && !all.contains("hidden") && !all.contains("deployment/tbd/secret"), "{all}");
        assert_eq!(found.decided, 0);
    }

    #[test]
    fn a_wrong_block_is_refused_whole_and_read_as_nothing() {
        let doc = "---\nkind: rfc\n---\n```decided\n[[decided]]\nsubject = \"a/b\"\npredicate = \"x\"\ntext = \"t\"\nint = 3\n```\n```decided\n[[decided]]\nsubject = \"a/b\"\npredicate = \"x\"\ncolour = \"red\"\n```\n";
        let mut sink = Sink::default();
        let c = ctx(&mut sink);
        let a = c.artifact(&mut sink, "core@x:docs/rfcs/0099-a.md", doc.as_bytes()).unwrap();
        let mut found = Found::default();
        observe_document(&c, &mut sink, Path::new("docs/rfcs/0099-a.md"), "rfc", doc.as_bytes(), a, &mut found).unwrap();
        assert_eq!(found.decided, 0);
        assert_eq!(found.refused.len(), 2, "{:?}", found.refused);
    }

    #[test]
    fn keys_and_kinds_come_from_the_path() {
        assert_eq!(doc_key("rfc", Path::new("docs/rfcs/0074.1-paging.md")).as_deref(), Some("rfc/0074.1"));
        assert_eq!(doc_key("adr", Path::new("docs/adrs/0024-atlas-store.md")).as_deref(), Some("adr/0024"));
        assert_eq!(kind_for(Path::new("docs/adrs/0024-x.md")), Some("adr"));
        assert_eq!(kind_for(Path::new("docs/adrs/README.md")), None);
        assert_eq!(kind_for(Path::new("docs/rfcs/diagrams/x.md")), None);
    }
}
