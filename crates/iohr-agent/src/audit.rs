//! The local console's audit log (RFC 0100.2, "Every write is on the record"): who
//! changed what on this agent, when, and with what outcome, hash-chained the way the egress
//! ledger is (`ledger.rs`), so an edited or deleted line breaks the chain.
//!
//! `<state_dir>/audit/audit.jsonl`, one JSON object per line, 0600 in a 0700 directory.
//! A line names the person (the identity provider's subject, or `machine`), their role,
//! the action and the record it touched, and the reason they gave: never a file's
//! content, a secret or a token. Nothing here leaves the machine.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

/// The file, in [`dir_in`].
pub const FILE: &str = "audit.jsonl";
/// Entries kept in memory for the console.
const RECENT: usize = 500;
/// The longest reason kept.
const MAX_REASON: usize = 500;

/// Where the log lives.
#[must_use]
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("audit")
}

/// One line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// 1, 2, 3, … for the life of the file.
    pub seq: u64,
    /// RFC 3339 UTC.
    pub at: String,
    /// The person: the identity provider's subject, or `machine`.
    pub who: String,
    /// Their display name, when the identity provider gave one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// `viewer`, `member`, `admin`, `owner`.
    pub role: String,
    /// `sign_in`, `sign_out`, `config.apply`, `config.restore`, `extension.enable`, …
    pub action: String,
    /// What it touched (`checks.toml`, `inorbit/monitors`), never content.
    pub target: String,
    /// `ok`, or why it did not happen.
    pub outcome: String,
    /// The reason the person gave.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// The previous entry's hash (`sha256:` of nothing for the first).
    pub prev: String,
    /// `sha256:` over this entry with `hash` empty.
    pub hash: String,
}

impl Entry {
    fn compute_hash(&self) -> String {
        let mut e = self.clone();
        e.hash = String::new();
        let bytes = serde_json::to_vec(&e).unwrap_or_default();
        format!("sha256:{}", hex(&Sha256::digest(bytes)))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::with_capacity(64), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// What a caller records.
#[derive(Debug, Clone, Default)]
pub struct Record<'a> {
    /// The person.
    pub who: &'a str,
    /// Their name.
    pub name: &'a str,
    /// Their role.
    pub role: &'a str,
    /// The action.
    pub action: &'a str,
    /// The record touched.
    pub target: &'a str,
    /// `ok` or why not.
    pub outcome: &'a str,
    /// Their reason.
    pub reason: &'a str,
}

/// The log the running agent writes.
#[derive(Debug)]
pub struct Audit {
    path: PathBuf,
    inner: Mutex<(u64, String, std::collections::VecDeque<Entry>)>,
}

impl Audit {
    /// Opens (or starts) the log in `dir`, reading its head.
    ///
    /// # Errors
    /// The directory or the file cannot be made or read.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let path = dir.join(FILE);
        let mut seq = 0;
        let mut prev = format!("sha256:{}", hex(&Sha256::digest(b"")));
        let mut recent = std::collections::VecDeque::with_capacity(RECENT);
        if let Ok(f) = std::fs::File::open(&path) {
            for line in std::io::BufReader::new(f)
                .lines()
                .map_while(std::result::Result::ok)
            {
                if let Ok(e) = serde_json::from_str::<Entry>(&line) {
                    seq = e.seq;
                    prev.clone_from(&e.hash);
                    if recent.len() == RECENT {
                        recent.pop_front();
                    }
                    recent.push_back(e);
                }
            }
        }
        Ok(Self {
            path,
            inner: Mutex::new((seq, prev, recent)),
        })
    }

    /// Appends one entry, flushed before it returns.
    ///
    /// # Errors
    /// The file cannot be written: the caller refuses the change it was about to make.
    #[allow(clippy::needless_pass_by_value)] // a small struct of borrows, built at the call
    pub fn record(&self, r: Record<'_>) -> Result<Entry> {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut reason = r.reason.trim().to_owned();
        if reason.len() > MAX_REASON {
            let mut cut = MAX_REASON;
            while !reason.is_char_boundary(cut) {
                cut -= 1;
            }
            reason.truncate(cut);
        }
        let mut e = Entry {
            seq: g.0 + 1,
            at: crate::enroll::now_rfc3339(),
            who: r.who.to_owned(),
            name: r.name.to_owned(),
            role: r.role.to_owned(),
            action: r.action.to_owned(),
            target: r.target.to_owned(),
            outcome: r.outcome.to_owned(),
            reason: crate::redact::redact(&reason),
            prev: g.1.clone(),
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        let line = serde_json::to_string(&e).map_err(|x| Error::Store(x.to_string()))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&self.path)
            .map_err(|x| Error::io(&self.path, x))?;
        writeln!(f, "{line}").map_err(|x| Error::io(&self.path, x))?;
        f.sync_data().map_err(|x| Error::io(&self.path, x))?;
        g.0 = e.seq;
        g.1.clone_from(&e.hash);
        if g.2.len() == RECENT {
            g.2.pop_front();
        }
        g.2.push_back(e.clone());
        Ok(e)
    }

    /// The newest `n` entries, newest first.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<Entry> {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.2.iter().rev().take(n).cloned().collect()
    }

    /// Checks the whole file's chain: `Ok(count)`, or the first broken line.
    ///
    /// # Errors
    /// A line that does not parse, does not hash to itself, or does not follow the one
    /// before it.
    pub fn verify(&self) -> std::result::Result<u64, String> {
        let Ok(f) = std::fs::File::open(&self.path) else {
            return Ok(0);
        };
        let mut prev = format!("sha256:{}", hex(&Sha256::digest(b"")));
        let mut n = 0;
        for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;
            let e: Entry =
                serde_json::from_str(&line).map_err(|x| format!("line {}: {x}", i + 1))?;
            if e.prev != prev || e.hash != e.compute_hash() {
                return Err(format!("line {}: the chain is broken", i + 1));
            }
            prev = e.hash;
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec<'a>(action: &'a str, reason: &'a str) -> Record<'a> {
        Record {
            who: "machine",
            role: "owner",
            action,
            target: "checks.toml",
            outcome: "ok",
            reason,
            ..Record::default()
        }
    }

    #[test]
    fn entries_chain_and_survive_reopening() {
        let d = tempfile::tempdir().unwrap();
        {
            let a = Audit::open(d.path()).unwrap();
            a.record(rec("config.apply", "add the orders check"))
                .unwrap();
            a.record(rec("config.restore", "")).unwrap();
        }
        let a = Audit::open(d.path()).unwrap();
        let e = a.record(rec("sign_out", "")).unwrap();
        assert_eq!(e.seq, 3);
        assert_eq!(a.verify(), Ok(3));
        assert_eq!(a.recent(10)[0].action, "sign_out");
    }

    #[test]
    fn an_edited_line_breaks_the_chain() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::open(d.path()).unwrap();
        a.record(rec("config.apply", "first")).unwrap();
        a.record(rec("config.apply", "second")).unwrap();
        let p = d.path().join(FILE);
        let text = std::fs::read_to_string(&p)
            .unwrap()
            .replace("first", "fiRst");
        std::fs::write(&p, text).unwrap();
        assert!(a.verify().is_err());
    }

    #[test]
    fn a_secret_in_a_reason_is_redacted() {
        let d = tempfile::tempdir().unwrap();
        let a = Audit::open(d.path()).unwrap();
        let e = a
            .record(rec(
                "config.apply",
                "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
            ))
            .unwrap();
        assert!(!e.reason.contains("ghp_0123456789"), "{}", e.reason);
    }
}
