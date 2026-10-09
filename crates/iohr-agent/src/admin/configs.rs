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
}

impl Problem {
    fn error(entry: &str, m: impl Into<String>) -> Self {
        Self {
            level: "error",
            entry: entry.to_owned(),
            message: m.into(),
        }
    }
    fn warning(entry: &str, m: impl Into<String>) -> Self {
        Self {
            level: "warning",
            entry: entry.to_owned(),
            message: m.into(),
        }
    }
}

/// Checks `text` as `name` would be checked when the agent starts.
pub(super) fn validate(ctx: &Context, name: &str, text: &str) -> Vec<Problem> {
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
