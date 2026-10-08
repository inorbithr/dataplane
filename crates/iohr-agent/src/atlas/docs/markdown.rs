//! Deterministic markdown: the same item always renders to the same bytes, so its digest
//! changes only when its content does (not when someone merely opened or re-saved it).

use std::fmt::Write as _;

use super::{Comment, Document};

/// Line endings to `\n`, trailing spaces off, at most one blank line in a row, one final
/// newline.
#[must_use]
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 1);
    let mut blank = 0usize;
    for line in text.replace("\r\n", "\n").replace('\r', "\n").lines() {
        let line = line.trim_end();
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    let trimmed = out.trim_start_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut s = trimmed.to_owned();
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Escapes a table cell: pipes and line breaks would break the row.
#[must_use]
pub fn cell(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// The bytes stored and digested for a document: its title, its fields as a table, its
/// body. Times, authors and links are not in it; they are observations of their own.
#[must_use]
pub fn render(doc: &Document) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", doc.title.replace(['\n', '\r'], " ").trim());
    if !doc.fields.is_empty() {
        s.push_str("| Field | Value |\n|---|---|\n");
        for (k, v) in &doc.fields {
            let _ = writeln!(s, "| {} | {} |", cell(k), cell(v));
        }
        s.push('\n');
    }
    s.push_str(&doc.markdown);
    normalize(&s)
}

/// The bytes stored and digested for a document's comments, oldest first; empty when it
/// has none.
#[must_use]
pub fn render_comments(comments: &[Comment]) -> String {
    let mut sorted: Vec<&Comment> = comments.iter().collect();
    sorted.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
    let mut s = String::new();
    for c in sorted {
        let when = c
            .created
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default();
        let who = c.author.as_deref().unwrap_or("unknown");
        let _ = writeln!(
            s,
            "## Comment {} ({when}, user {who})\n\n{}\n",
            c.id,
            c.markdown.trim()
        );
    }
    normalize(&s)
}

/// A provider's field name as a predicate segment: lower-case ASCII letters, digits and
/// `_`, starting with a letter, at most 40 bytes; `None` when nothing is left.
#[must_use]
pub fn slug(name: &str) -> Option<String> {
    let mut s = String::new();
    let mut under = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
            under = false;
        } else if !under && !s.is_empty() {
            s.push('_');
            under = true;
        }
    }
    let s = s.trim_end_matches('_');
    let s = if s.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        format!("f_{s}")
    } else {
        s.to_owned()
    };
    let mut s = s;
    s.truncate(40);
    let s = s.trim_end_matches('_').to_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizing_is_idempotent_and_drops_noise() {
        let raw = "a  \r\n\r\n\r\n\nb\t\n\n";
        let n = normalize(raw);
        assert_eq!(n, "a\n\nb\n");
        assert_eq!(normalize(&n), n);
        assert_eq!(normalize("\n\n"), "");
    }

    #[test]
    fn slugs_are_predicate_segments() {
        assert_eq!(slug("Owner Team").as_deref(), Some("owner_team"));
        assert_eq!(slug("  SLA (p95) ").as_deref(), Some("sla_p95"));
        assert_eq!(slug("3 replicas").as_deref(), Some("f_3_replicas"));
        assert_eq!(slug("Équipe"), Some("quipe".to_owned()));
        assert_eq!(slug("✓✓"), None);
        assert!(slug(&"x".repeat(100)).unwrap().len() <= 40);
    }

    #[test]
    fn table_cells_cannot_break_their_row() {
        assert_eq!(cell("a|b\nc"), "a\\|b c");
    }
}
