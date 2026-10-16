//! Configuration management in the local console: the agent's own files, edited, checked,
//! applied without a restart, versioned, and rolled back.
//!
//! - **The files**: `policy.toml` (admin and owner: the machine's final authority) and
//!   `checks.toml` (member and above). Both are what `iohr agent checks lint` and the agent
//!   itself read; nothing here has a format of its own, so a git workflow keeps working.
//! - **Checked first**: the same rules as the agent's start and `checks lint` (a policy that
//!   parses and keeps this agent's environment; checks that parse and that the *current*
//!   policy admits). A file with an error is never written.
//! - **Applied live**: written atomically (a temporary file, `fsync`, rename), then the
//!   running agent reloads (a new generation with the new files, the same process). When the
//!   reload refuses the files, the previous text is put back and the agent never left it.
//! - **Versioned**: every applied text is kept in the trial store with who, when and why;
//!   any version restores in one step (the same checks, the same reload).
//! - **The policy stays the authority**: checks are judged against the policy in force, so
//!   the console cannot run anything the policy forbids. Only an admin or the owner edits the
//!   policy itself; that edit is audited and noted in the egress ledger (`policy_set`, hashes
//!   only, nothing sent).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::Context;
use crate::checks_file::{self, DeclaredChecks, Verdict};
use crate::policy::{Policy, Role};

/// The largest file accepted.
pub(super) const MAX_TEXT: usize = 128 * 1024;

/// One managed file.
#[derive(Debug, Clone)]
pub(super) struct Managed {
    pub name: &'static str,
    pub path: PathBuf,
    /// The lowest role that may change it.
    pub edit: Role,
    pub what: &'static str,
}

/// The files the console manages.
pub(super) fn managed(ctx: &Context) -> Vec<Managed> {
    vec![
        Managed {
            name: "checks.toml",
            path: ctx.checks_path.clone(),
            edit: Role::Member,
            what: "The checks this agent declares: what it watches, how often, and what counts as a pass.",
        },
        Managed {
            name: "policy.toml",
            path: ctx.policy_path.clone(),
            edit: Role::Admin,
            what: "What this agent may do on this machine: the final authority, above anything the console or InOrbit asks.",
        },
    ]
}

/// One finding.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct Problem {
    /// `error` or `warning`.
    pub level: &'static str,
    /// The entry it is about (a check's name), or "".
    pub entry: String,
    pub message: String,
    /// The line it points at, from 1, when it can be placed (the editor marks it there).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// The column on that line, from 1, when the parser gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

impl Problem {
    fn error(entry: &str, m: impl Into<String>) -> Self {
        Self {
            level: "error",
            entry: entry.to_owned(),
            message: m.into(),
            line: None,
            column: None,
        }
    }
    fn warning(entry: &str, m: impl Into<String>) -> Self {
        Self {
            level: "warning",
            ..Self::error(entry, m)
        }
    }
}

/// Line and column (from 1) of byte `at` in `text`.
fn line_col(text: &str, at: usize) -> (usize, usize) {
    let before = &text[..text.floor_char_boundary(at.min(text.len()))];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, col)
}

/// The key a message is about: a backticked name (the parser's ``unknown field `x` ``),
/// or the word it starts with when that word is followed by ` =` or `:`.
fn key_of(message: &str) -> Option<&str> {
    if let Some(i) = message.find('`')
        && let Some(j) = message[i + 1..].find('`')
    {
        return Some(&message[i + 1..i + 1 + j]);
    }
    let word: &str = message
        .split([' ', ':', '='])
        .next()
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))?;
    let rest = message[word.len()..].trim_start();
    (rest.starts_with('=') || rest.starts_with(':')).then_some(word)
}

/// The key on a `key = value` line, or None.
fn line_key(line: &str) -> Option<&str> {
    let (k, _) = line.split_once('=')?;
    let k = k.trim();
    (!k.is_empty() && !k.starts_with('#') && !k.starts_with('[')).then_some(k)
}

/// Places each problem on a line: a syntax error where the parser stopped, an entry's
/// problem on the key it names inside that entry's block (else the block's header), and
/// a file-level problem that names a `[section]` or a key on that line.
pub(super) fn locate(text: &str, problems: &mut [Problem]) {
    let lines: Vec<&str> = text.lines().collect();
    // Each [[check]] / [[refuse]] block: (header line index, end, its name).
    let mut blocks: Vec<(usize, usize, String)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with('[') {
            if let Some(b) = blocks.last_mut()
                && b.1 == usize::MAX
            {
                b.1 = i;
            }
            if t.starts_with("[[") {
                blocks.push((i, usize::MAX, String::new()));
            }
        } else if line_key(t) == Some("name")
            && let Some(b) = blocks.last_mut()
            && b.1 == usize::MAX
            && let Some(v) = t.split_once('=').map(|(_, v)| v.trim())
            && let Ok(name) = toml::from_str::<toml::Table>(&format!("n = {v}"))
        {
            name["n"].as_str().unwrap_or_default().clone_into(&mut b.2);
        }
    }
    let syntax = toml::from_str::<toml::Table>(text).err();
    for p in problems.iter_mut().filter(|p| p.line.is_none()) {
        if let Some(e) = &syntax
            && let Some(span) = e.span()
        {
            let (l, c) = line_col(text, span.start);
            p.line = Some(l);
            p.column = Some(c);
            continue;
        }
        let key = key_of(&p.message);
        let (from, to) = blocks
            .iter()
            .find(|b| !p.entry.is_empty() && b.2 == p.entry)
            .map_or((0, lines.len()), |b| (b.0, b.1.min(lines.len())));
        let hit = key.and_then(|k| {
            (from..to).find(|&i| {
                let t = lines[i].trim();
                line_key(t) == Some(k) || t == format!("[{k}]")
            })
        });
        let section = p.message.find('[').and_then(|i| {
            let s = &p.message[i..];
            let end = s.find(']')?;
            let header = &s[..=end];
            lines.iter().position(|l| l.trim() == header)
        });
        p.line = hit
            .or(if p.entry.is_empty() {
                section
            } else {
                Some(from)
            })
            .map(|i| i + 1);
    }
}

/// The document as plain JSON, for the console's form view; null when it does not parse.
pub(super) fn model(text: &str) -> serde_json::Value {
    toml::from_str::<toml::Table>(text)
        .ok()
        .and_then(|t| serde_json::to_value(t).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// Checks `text` as `name` would be checked when the agent starts.
pub(super) fn validate(ctx: &Context, name: &str, text: &str) -> Vec<Problem> {
    let mut out = validate_unplaced(ctx, name, text);
    locate(text, &mut out);
    out
}

fn validate_unplaced(ctx: &Context, name: &str, text: &str) -> Vec<Problem> {
    // The console showed this file through the redactor: a value it hid must not be
    // written back in place of the real one.
    if let Some(at) = text.find(crate::redact::MARK) {
        let mut p = Problem::error(
            "",
            format!(
                "{} stands where the console hid a value; change that value on the machine itself",
                crate::redact::MARK
            ),
        );
        let (l, c) = line_col(text, at);
        p.line = Some(l);
        p.column = Some(c);
        return vec![p];
    }
    if text.len() > MAX_TEXT {
        return vec![Problem::error(
            "",
            format!("the file is larger than {} KiB", MAX_TEXT / 1024),
        )];
    }
    match name {
        "policy.toml" => {
            match Policy::from_toml(text) {
                Err(e) => vec![Problem::error("", e.to_string())],
                Ok(p) => {
                    let mut out = Vec::new();
                    if p.environment != ctx.policy.environment {
                        out.push(Problem::error(
                        "",
                        format!(
                            "this agent serves {:?}; a policy for {:?} would stop it (change the environment on the machine, with its enrollment)",
                            ctx.policy.environment, p.environment
                        ),
                    ));
                    }
                    for s in p.ignored_sections() {
                        out.push(Problem::warning(
                        "",
                        format!("[{s}] is not a section this agent version knows; it would be ignored"),
                    ));
                    }
                    out
                }
            }
        }
        "checks.toml" => {
            let entries = match checks_file::parse(text) {
                Ok(e) => e,
                Err(e) => return vec![Problem::error("", e.to_string())],
            };
            let mut out = Vec::new();
            for (entry, c) in &entries {
                match c {
                    Err(e) => out.push(Problem::error(entry, e.clone())),
                    Ok(c) => match checks_file::lint_offline(c, &ctx.policy) {
                        Verdict::Ok => {}
                        Verdict::Warning(w) => out.push(Problem::warning(entry, w)),
                        Verdict::Error(e) => out.push(Problem::error(entry, e)),
                        Verdict::NeedsResolve { host, .. } => out.push(Problem::warning(
                            entry,
                            format!("{host} is inside a bound domain; the policy refuses it only if an address is outside networks.allow"),
                        )),
                    },
                }
            }
            if out.iter().all(|p| p.level != "error")
                && let Err(e) = DeclaredChecks::from_toml(text)
            {
                out.push(Problem::error("", e.to_string()));
            }
            out
        }
        _ => vec![Problem::error("", "not a file this console manages")],
    }
}

/// `sha256:` of a text.
pub(super) fn sha(text: &str) -> String {
    crate::ledger::sha256_hex(text.as_bytes())
}

/// The file's text now, or "" when it does not exist yet.
pub(super) fn read(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Writes `text` to `path` atomically, keeping the file's permissions.
pub(super) fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.iohr-new",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    let mode = std::fs::metadata(path).ok().map(|m| m.permissions());
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    if let Some(m) = mode {
        std::fs::set_permissions(&tmp, m)?;
    }
    std::fs::rename(&tmp, path)
}

/// A line diff: each line with ` `, `-` or `+`, the shortest edit by LCS; files over 2000
/// lines are shown as all removed then all added.
#[allow(clippy::many_single_char_names)] // the textbook LCS names
pub(super) fn diff(old: &str, new: &str) -> Vec<(char, String)> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    if a.len() > 2000 || b.len() > 2000 {
        return a
            .iter()
            .map(|l| ('-', (*l).to_owned()))
            .chain(b.iter().map(|l| ('+', (*l).to_owned())))
            .collect();
    }
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((' ', a[i].to_owned()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(('-', a[i].to_owned()));
            i += 1;
        } else {
            out.push(('+', b[j].to_owned()));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| ('-', (*l).to_owned())));
    out.extend(b[j..].iter().map(|l| ('+', (*l).to_owned())));
    out
}

/// The diff as JSON lines for the console.
pub(super) fn diff_json(old: &str, new: &str) -> serde_json::Value {
    let mut added = 0;
    let mut removed = 0;
    let lines: Vec<serde_json::Value> = diff(old, new)
        .into_iter()
        .map(|(op, l)| {
            match op {
                '+' => added += 1,
                '-' => removed += 1,
                _ => {}
            }
            serde_json::json!({"op": op.to_string(), "line": l})
        })
        .collect();
    serde_json::json!({"lines": lines, "added": added, "removed": removed})
}

/// The export of every managed file, as `name\n----\ntext` blocks: config as code.
pub(super) fn export(ctx: &Context) -> String {
    let mut out = String::new();
    for f in managed(ctx) {
        let text = read(&f.path).unwrap_or_default();
        let _ = write!(out, "# {} ({})\n{}\n", f.name, f.path.display(), text);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKS: &str = "# watched\n[[check]]\nname = \"web\"\ntarget = \"https://example.com\"\nevery = \"60s\"\n\n[[check]]\nname = \"api\"\ntarget = \"https://example.com/api\"\nevery = \"5s\"\nfoo = 1\n";

    #[test]
    fn problems_are_placed_on_their_lines() {
        let mut p = vec![
            Problem::error("api", "every = \"5s\": must be 60s to 24h"),
            Problem::error("api", "unknown field `foo`, expected one of …"),
            Problem::error("api", "missing field `rfc`"),
            Problem::error("web", "the target answers nothing"),
        ];
        locate(CHECKS, &mut p);
        let lines: Vec<_> = p.iter().map(|p| p.line).collect();
        assert_eq!(lines, [Some(10), Some(11), Some(7), Some(2)]);
    }

    #[test]
    fn a_syntax_error_is_placed_where_the_parser_stopped() {
        let mut p = vec![Problem::error("", "bad")];
        locate("[work]\nchecks = yes\n", &mut p);
        assert_eq!(p[0].line, Some(2));
        assert!(p[0].column.is_some());
    }

    #[test]
    fn a_section_named_in_a_message_is_found() {
        let mut p = vec![Problem::warning(
            "",
            "[later] is not a section this agent version knows",
        )];
        locate("environment = \"x\"\n\n[later]\na = 1\n", &mut p);
        assert_eq!(p[0].line, Some(3));
    }

    #[test]
    fn a_value_the_console_hid_is_never_written_back() {
        let mut p = vec![Problem::error("", "x")];
        locate("a = 1\nb = [redacted]\n", &mut p);
        assert_eq!(p[0].line, Some(2));
    }

    #[test]
    fn the_model_is_the_document_as_json() {
        assert_eq!(model(CHECKS)["check"][1]["every"], "5s");
        assert!(model("a = ").is_null());
    }

    #[test]
    fn the_diff_is_minimal() {
        let d = diff("a\nb\nc\n", "a\nx\nc\nd\n");
        let ops: String = d.iter().map(|(o, _)| *o).collect();
        assert_eq!(ops, " -+ +");
        let j = diff_json("a\n", "a\nb\n");
        assert_eq!(j["added"], 1);
        assert_eq!(j["removed"], 0);
    }

    #[test]
    fn an_atomic_write_keeps_permissions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("checks.toml");
        std::fs::write(&p, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        write_atomic(&p, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        assert!(!d.path().join(".checks.toml.iohr-new").exists());
    }
}
