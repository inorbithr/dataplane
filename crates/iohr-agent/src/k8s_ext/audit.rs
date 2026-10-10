//! The query audit: one JSON line per request after it was answered, with its outcome.
//! The query ledger (a chained [`crate::ledger::Ledger`] next to it) records each request
//! before it is sent; this file says what came of it.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The file's name in the extension's state directory.
pub const FILE: &str = "audit.jsonl";

/// Largest audit file before it is rotated to `audit.jsonl.1`.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// What came of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Answered with items.
    Read,
    /// The cluster's RBAC refused it (401 or 403).
    Denied,
    /// The kind is not served (404).
    Missing,
    /// The policy or the guard refused it; nothing was sent.
    Refused,
    /// Over the rate cap; nothing was sent.
    Limited,
    /// The request failed.
    Failed,
}

/// One line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// When, RFC 3339.
    pub at: String,
    /// The kind.
    pub kind: String,
    /// The namespace.
    pub namespace: String,
    /// The path asked for (empty when refused before one was built).
    pub path: String,
    /// What came of it.
    pub outcome: Outcome,
    /// Objects returned.
    pub items: usize,
    /// The HTTP status, when there was one other than success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// The audit file.
#[derive(Debug)]
pub struct Audit {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Audit {
    /// The audit in `dir` (created).
    ///
    /// # Errors
    /// The directory cannot be made.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        Ok(Self {
            path: dir.join(FILE),
            lock: Mutex::new(()),
        })
    }

    /// Appends a line.
    ///
    /// # Errors
    /// It cannot be written.
    pub fn append(&self, line: &Line) -> Result<()> {
        let _g = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > MAX_BYTES) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("jsonl.1"));
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::io(&self.path, e))?;
        let mut b = serde_json::to_vec(line).map_err(|e| Error::Config(e.to_string()))?;
        b.push(b'\n');
        f.write_all(&b).map_err(|e| Error::io(&self.path, e))
    }
}

/// The newest `n` lines in `dir`'s audit, newest first.
#[must_use]
pub fn recent(dir: &Path, n: usize) -> Vec<Line> {
    let Ok(f) = std::fs::File::open(dir.join(FILE)) else {
        return Vec::new();
    };
    let mut lines: std::collections::VecDeque<Line> = std::collections::VecDeque::with_capacity(n);
    for l in std::io::BufReader::new(f)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if let Ok(line) = serde_json::from_str(&l) {
            if lines.len() == n {
                lines.pop_front();
            }
            lines.push_back(line);
        }
    }
    lines.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_come_back_newest_first() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::open(d.path()).unwrap();
        for (i, o) in [Outcome::Read, Outcome::Denied, Outcome::Refused]
            .into_iter()
            .enumerate()
        {
            a.append(&Line {
                at: format!("t{i}"),
                kind: "pods".into(),
                namespace: "shop".into(),
                path: String::new(),
                outcome: o,
                items: i,
                status: None,
            })
            .unwrap();
        }
        let r = recent(d.path(), 2);
        assert_eq!(
            r.iter().map(|l| l.outcome).collect::<Vec<_>>(),
            [Outcome::Refused, Outcome::Denied]
        );
        assert!(recent(&d.path().join("none"), 5).is_empty());
    }
}
