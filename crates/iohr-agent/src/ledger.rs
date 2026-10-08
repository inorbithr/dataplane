//! The egress ledger (ADR 0049 in inorbithr/core, phase 1): before the agent sends the
//! platform anything, it appends one line to a local, append-only, hash-chained file: the
//! time, the message kind, its size in bytes, the SHA-256 of the exact bytes sent, the
//! policy (by hash) and the rule that allowed it, and the destination. Each entry carries
//! the hash of the one before it, so a removed or edited entry breaks the chain, which
//! `iohr agent ledger verify` checks.
//!
//! Phase 1 keeps metadata only: never the payload. The files are JSON lines, one per UTC
//! day (`ledger-2026-10-08.jsonl`), mode 0600 in a 0700 directory under the state
//! directory, kept for `[ledger] retain_days` and at most `[ledger] max_mb`. When the
//! oldest file is removed for retention, its last entry is kept in `anchor.json` so the
//! chain that remains still verifies from where it starts.
//!
//! If an entry cannot be written, the message is not sent: the ledger fails closed.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

/// The chain's first `prev`.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// Entries kept in memory for the page.
pub const RECENT: usize = 1000;
/// Most problems a verification lists.
const MAX_PROBLEMS: usize = 20;
/// Longest line read back; anything longer is not an entry.
const MAX_ENTRY_LINE: usize = 4096;

/// `[ledger]` in `agent.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerConfig {
    /// Keep the ledger. On by default; turning it off is shown on the page.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Days of ledger files kept (1 to 3650).
    #[serde(default = "default_retain_days")]
    pub retain_days: u32,
    /// Most megabytes the ledger may use (1 to 10240); the oldest days go first.
    #[serde(default = "default_max_mb")]
    pub max_mb: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retain_days: default_retain_days(),
            max_mb: default_max_mb(),
        }
    }
}

fn yes() -> bool {
    true
}
fn default_retain_days() -> u32 {
    30
}
fn default_max_mb() -> u64 {
    256
}

impl LedgerConfig {
    /// Whether this is the default (left out of a printed configuration).
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Problems with the values.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if !(1..=3650).contains(&self.retain_days) {
            p.push("ledger.retain_days must be 1 to 3650".into());
        }
        if !(1..=10_240).contains(&self.max_mb) {
            p.push("ledger.max_mb must be 1 to 10240".into());
        }
        p
    }
}

/// One ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// 1, 2, 3, … across files and restarts.
    pub seq: u64,
    /// When it was recorded (just before sending), RFC 3339 UTC.
    pub at: String,
    /// `hello`, `heartbeat`, `result`, `session_open`, `token_request`.
    pub kind: String,
    /// Size of the payload in bytes.
    pub bytes: u64,
    /// `sha256:` of the exact payload bytes.
    pub sha256: String,
    /// The policy in force (`sha256:` of `policy.toml`'s canonical form).
    pub policy: String,
    /// The rule that allowed it (`contract.heartbeat`, `work.surfaces.http`, …).
    pub rule: String,
    /// Where it went (no credentials, no query).
    pub destination: String,
    /// The job a result answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The previous entry's `hash`.
    pub prev: String,
    /// `sha256:` over this entry serialised with `hash` empty.
    pub hash: String,
}

impl Entry {
    /// The hash this entry should carry.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut copy = self.clone();
        copy.hash = String::new();
        sha256_hex(&serde_json::to_vec(&copy).unwrap_or_default())
    }
}

/// `sha256:<hex>` of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let d = Sha256::digest(bytes);
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// What is being recorded.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// Message kind.
    pub kind: &'a str,
    /// The exact bytes sent.
    pub payload: &'a [u8],
    /// The rule that allowed it.
    pub rule: &'a str,
    /// Destination.
    pub destination: &'a str,
    /// The job, for results.
    pub job_id: Option<&'a str>,
}

/// Totals since the agent started, by kind.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    /// Messages.
    pub messages: u64,
    /// Bytes.
    pub bytes: u64,
}

/// The ledger the running agent writes.
#[derive(Debug)]
pub struct Ledger {
    dir: PathBuf,
    cfg: LedgerConfig,
    policy: String,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    seq: u64,
    head: String,
    day: String,
    file: Option<File>,
    recent: VecDeque<Entry>,
    totals: BTreeMap<String, Totals>,
    problem: Option<String>,
}

/// The ledger's directory under the state directory.
#[must_use]
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("ledger")
}

fn today() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

fn file_name(day: &str) -> String {
    format!("ledger-{day}.jsonl")
}

/// The ledger files in `dir`, oldest first, with their day.
fn files(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let day = name.strip_prefix("ledger-")?.strip_suffix(".jsonl")?;
            (day.len() == 10).then(|| (day.to_owned(), e.path()))
        })
        .collect();
    out.sort();
    out
}

fn create_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::io(dir, e))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))
    }
}

fn open_append(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| Error::io(path, e))
}

/// Drops a last line that was never finished (the agent stopped mid-write; that message
/// was never sent, since the entry is written first).
fn drop_torn_tail(path: &Path) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let len = f.metadata().map_err(|e| Error::io(path, e))?.len();
    if len == 0 {
        return Ok(());
    }
    let back = len.min(64 * 1024);
    f.seek(SeekFrom::Start(len - back))
        .map_err(|e| Error::io(path, e))?;
    let mut tail = Vec::with_capacity(usize::try_from(back).unwrap_or(0));
    f.read_to_end(&mut tail).map_err(|e| Error::io(path, e))?;
    if tail.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = tail
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(len - back, |i| len - back + i as u64 + 1);
    tracing::warn!(file = %path.display(), "the ledger's last line was never finished; dropping it");
    f.set_len(keep).map_err(|e| Error::io(path, e))
}

fn read_entries(path: &Path) -> Vec<Entry> {
    let Ok(f) = File::open(path) else {
        return Vec::new();
    };
    BufReader::new(f)
        .lines()
        .map_while(std::result::Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Anchor {
    seq: u64,
    hash: String,
    file: String,
}

impl Ledger {
    /// Opens (or starts) the ledger in `dir`, continuing its chain.
    ///
    /// # Errors
    /// When the directory or the newest file cannot be used.
    pub fn open(dir: &Path, cfg: LedgerConfig, policy_hash: &str) -> Result<Self> {
        create_dir(dir)?;
        let existing = files(dir);
        let mut seq = 0;
        let mut head = GENESIS.to_owned();
        let mut recent = VecDeque::with_capacity(RECENT);
        // The newest files hold the head; read back far enough to fill the page's list.
        for (_, path) in existing.iter().rev().take(2).rev() {
            drop_torn_tail(path)?;
            for e in read_entries(path) {
                seq = e.seq;
                head.clone_from(&e.hash);
                if recent.len() == RECENT {
                    recent.pop_front();
                }
                recent.push_back(e);
            }
        }
        if seq == 0
            && let Some(a) = read_anchor(dir)
        {
            seq = a.seq;
            head = a.hash;
        }
        let ledger = Self {
            dir: dir.to_owned(),
            cfg,
            policy: policy_hash.to_owned(),
            inner: Mutex::new(Inner {
                seq,
                head,
                day: String::new(),
                file: None,
                recent,
                totals: BTreeMap::new(),
                problem: None,
            }),
        };
        ledger.prune()?;
        Ok(ledger)
    }

    /// Where it is.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Its settings.
    #[must_use]
    pub fn config(&self) -> &LedgerConfig {
        &self.cfg
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Appends one entry for a message about to be sent.
    ///
    /// # Errors
    /// When it cannot be written; the caller must then not send the message.
    pub fn record(&self, r: Record<'_>) -> Result<Entry> {
        let mut g = self.lock();
        let day = today();
        if g.file.is_none() || g.day != day {
            let path = self.dir.join(file_name(&day));
            g.file = Some(open_append(&path)?);
            let rotated = !g.day.is_empty();
            g.day.clone_from(&day);
            if rotated {
                drop(g);
                self.prune()?;
                g = self.lock();
            }
        }
        let mut e = Entry {
            seq: g.seq + 1,
            at: crate::enroll::now_rfc3339(),
            kind: r.kind.to_owned(),
            bytes: r.payload.len() as u64,
            sha256: sha256_hex(r.payload),
            policy: self.policy.clone(),
            rule: r.rule.to_owned(),
            destination: r.destination.to_owned(),
            job_id: r
                .job_id
                .map(|j| crate::redact::redact(&j.chars().take(128).collect::<String>())),
            prev: g.head.clone(),
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        let mut line = serde_json::to_vec(&e).map_err(|x| Error::Config(x.to_string()))?;
        line.push(b'\n');
        let path = self.dir.join(file_name(&day));
        let written = g
            .file
            .as_mut()
            .ok_or_else(|| Error::Config("ledger file not open".into()))
            .and_then(|f| {
                f.write_all(&line)
                    .and_then(|()| f.flush())
                    .map_err(|x| Error::io(&path, x))
            });
        if let Err(x) = written {
            g.problem = Some(x.to_string());
            g.file = None;
            return Err(Error::Session(format!(
                "the egress ledger could not record the message, so it was not sent: {x}"
            )));
        }
        g.problem = None;
        g.seq = e.seq;
        g.head.clone_from(&e.hash);
        if g.recent.len() == RECENT {
            g.recent.pop_front();
        }
        g.recent.push_back(e.clone());
        let t = g.totals.entry(e.kind.clone()).or_default();
        t.messages += 1;
        t.bytes += e.bytes;
        Ok(e)
    }

    /// The newest `n` entries, newest first.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<Entry> {
        self.lock().recent.iter().rev().take(n).cloned().collect()
    }

    /// Messages and bytes since the agent started, by kind.
    #[must_use]
    pub fn totals(&self) -> BTreeMap<String, Totals> {
        self.lock().totals.clone()
    }

    /// The chain head and its sequence number.
    #[must_use]
    pub fn head(&self) -> (u64, String) {
        let g = self.lock();
        (g.seq, g.head.clone())
    }

    /// The last write error, if the last write failed.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        self.lock().problem.clone()
    }

    /// The files, oldest first, with their sizes.
    #[must_use]
    pub fn files(&self) -> Vec<(String, PathBuf, u64)> {
        files(&self.dir)
            .into_iter()
            .map(|(d, p)| {
                let len = std::fs::metadata(&p).map_or(0, |m| m.len());
                (d, p, len)
            })
            .collect()
    }

    /// Removes files past retention or past the size cap, oldest first, never today's.
    fn prune(&self) -> Result<()> {
        let all = files(&self.dir);
        let cutoff =
            time::OffsetDateTime::now_utc() - time::Duration::days(i64::from(self.cfg.retain_days));
        let cutoff = format!(
            "{:04}-{:02}-{:02}",
            cutoff.year(),
            u8::from(cutoff.month()),
            cutoff.day()
        );
        let today = today();
        let mut total: u64 = all
            .iter()
            .map(|(_, p)| std::fs::metadata(p).map_or(0, |m| m.len()))
            .sum();
        let max = self.cfg.max_mb * 1024 * 1024;
        for (day, path) in &all {
            if *day == today {
                break;
            }
            let len = std::fs::metadata(path).map_or(0, |m| m.len());
            if *day >= cutoff && total <= max {
                break;
            }
            if let Some(last) = read_entries(path).pop() {
                write_anchor(
                    &self.dir,
                    &Anchor {
                        seq: last.seq,
                        hash: last.hash,
                        file: file_name(day),
                    },
                )?;
            }
            std::fs::remove_file(path).map_err(|e| Error::io(path, e))?;
            tracing::info!(file = %path.display(), "ledger file past retention removed");
            total = total.saturating_sub(len);
        }
        Ok(())
    }
}

fn read_anchor(dir: &Path) -> Option<Anchor> {
    let text = std::fs::read_to_string(dir.join("anchor.json")).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_anchor(dir: &Path, a: &Anchor) -> Result<()> {
    let path = dir.join("anchor.json");
    let tmp = dir.join("anchor.json.tmp");
    let mut o = OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|e| Error::io(&tmp, e))?;
    f.write_all(&serde_json::to_vec(a).unwrap_or_default())
        .map_err(|e| Error::io(&tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))
}

/// What `ledger verify` found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Verification {
    /// Files read.
    pub files: usize,
    /// Entries read.
    pub entries: u64,
    /// The first entry's sequence number.
    pub first_seq: Option<u64>,
    /// The last entry's sequence number.
    pub last_seq: Option<u64>,
    /// The last entry's hash: the chain head.
    pub head: Option<String>,
    /// Where the chain starts: `genesis`, or the anchor left by retention.
    pub starts_at: String,
    /// What is wrong, at most twenty.
    pub problems: Vec<String>,
}

impl Verification {
    /// No problem found.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Reads every file in `dir` and checks the chain: each line an entry, each entry's hash
/// its own, each `prev` the hash before it, sequence numbers without gaps.
#[must_use]
#[allow(clippy::too_many_lines)] // one pass over the lines, each rule in place
pub fn verify(dir: &Path) -> Verification {
    let mut v = Verification::default();
    let anchor = read_anchor(dir);
    let mut prev: Option<(u64, String)> = None;
    let problem = |v: &mut Verification, p: String| {
        if v.problems.len() < MAX_PROBLEMS {
            v.problems.push(p);
        } else if v.problems.len() == MAX_PROBLEMS {
            v.problems.push("… more problems not listed".into());
        }
    };
    for (_, path) in files(dir) {
        v.files += 1;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Ok(f) = File::open(&path) else {
            problem(&mut v, format!("{name}: cannot be read"));
            continue;
        };
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        let mut n = 0u64;
        loop {
            line.clear();
            match reader
                .by_ref()
                .take(MAX_ENTRY_LINE as u64 + 1)
                .read_line(&mut line)
            {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    problem(&mut v, format!("{name}: unreadable after line {n}"));
                    break;
                }
            }
            n += 1;
            if line.len() > MAX_ENTRY_LINE {
                problem(&mut v, format!("{name}:{n}: too long to be an entry"));
                // Skip the rest of that line.
                let mut rest = Vec::new();
                let _ = reader.read_until(b'\n', &mut rest);
                prev = None;
                continue;
            }
            let Ok(e) = serde_json::from_str::<Entry>(line.trim_end()) else {
                problem(&mut v, format!("{name}:{n}: not a ledger entry"));
                prev = None;
                continue;
            };
            v.entries += 1;
            if e.compute_hash() != e.hash {
                problem(
                    &mut v,
                    format!(
                        "{name}:{n}: entry {} was changed (its hash does not match)",
                        e.seq
                    ),
                );
            }
            match &prev {
                None if v.first_seq.is_none() => {
                    v.first_seq = Some(e.seq);
                    if e.prev == GENESIS && e.seq == 1 {
                        v.starts_at = "genesis".into();
                    } else if let Some(a) = anchor
                        .as_ref()
                        .filter(|a| a.hash == e.prev && a.seq + 1 == e.seq)
                    {
                        v.starts_at = format!(
                            "entry {} (earlier entries removed by retention with {})",
                            e.seq, a.file
                        );
                    } else {
                        problem(
                            &mut v,
                            format!(
                                "{name}:{n}: the chain starts at entry {} but nothing records why the entries before it are gone",
                                e.seq
                            ),
                        );
                    }
                }
                None => {}
                Some((seq, hash)) => {
                    if e.prev != *hash {
                        problem(
                            &mut v,
                            format!(
                                "{name}:{n}: entry {} does not follow entry {seq} (an entry was removed, inserted or changed)",
                                e.seq
                            ),
                        );
                    } else if e.seq != seq + 1 {
                        problem(
                            &mut v,
                            format!("{name}:{n}: entry {} follows entry {seq}", e.seq),
                        );
                    }
                }
            }
            v.last_seq = Some(e.seq);
            v.head = Some(e.hash.clone());
            prev = Some((e.seq, e.hash));
        }
    }
    if v.entries == 0 && v.starts_at.is_empty() {
        v.starts_at = "empty".into();
    }
    v
}

/// Copies every file, oldest first, into `out` (JSON lines).
///
/// # Errors
/// When a file cannot be read or `out` cannot be written.
pub fn export(dir: &Path, out: &mut dyn std::io::Write) -> Result<u64> {
    let mut n = 0;
    for (_, path) in files(dir) {
        let mut f = File::open(&path).map_err(|e| Error::io(&path, e))?;
        n += std::io::copy(&mut f, out).map_err(|e| Error::io(&path, e))?;
    }
    Ok(n)
}

/// The files `export` would copy, oldest first.
#[must_use]
pub fn export_files(dir: &Path) -> Vec<PathBuf> {
    files(dir).into_iter().map(|(_, p)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec<'a>(kind: &'a str, payload: &'a [u8]) -> Record<'a> {
        Record {
            kind,
            payload,
            rule: "contract.heartbeat",
            destination: "wss://api.example/v1/agents/session",
            job_id: None,
        }
    }

    fn ledger(dir: &Path) -> Ledger {
        Ledger::open(dir, LedgerConfig::default(), "sha256:00").unwrap()
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn every_record_chains_and_verifies() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        let a = l.record(rec("hello", b"{\"type\":\"hello\"}")).unwrap();
        let b = l.record(rec("heartbeat", b"{\"seq\":1}")).unwrap();
        assert_eq!(a.prev, GENESIS);
        assert_eq!(b.prev, a.hash);
        assert_eq!(b.seq, 2);
        assert_eq!(a.sha256, sha256_hex(b"{\"type\":\"hello\"}"));
        assert_eq!(a.bytes, 16);
        let v = verify(d.path());
        assert!(v.ok(), "{v:?}");
        assert_eq!((v.entries, v.starts_at.as_str()), (2, "genesis"));
        // It continues across a restart.
        drop(l);
        let l = ledger(d.path());
        let c = l.record(rec("heartbeat", b"x")).unwrap();
        assert_eq!((c.seq, c.prev), (3, b.hash));
        assert!(verify(d.path()).ok());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ledger");
        let l = ledger(&dir);
        l.record(rec("hello", b"x")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&l.files()[0].1), 0o600);
    }

    fn file_of(d: &Path) -> PathBuf {
        export_files(d).pop().unwrap()
    }

    #[test]
    fn an_edited_entry_breaks_the_chain() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        for i in 0..5u8 {
            l.record(rec("heartbeat", &[i])).unwrap();
        }
        let path = file_of(d.path());
        let text = std::fs::read_to_string(&path).unwrap();
        // A changed size.
        let edited = text.replacen("\"bytes\":1", "\"bytes\":0", 1);
        std::fs::write(&path, &edited).unwrap();
        let v = verify(d.path());
        assert!(!v.ok());
        assert!(v.problems[0].contains("was changed"), "{v:?}");
        // A changed size with its hash recomputed: the next entry no longer follows.
        let mut lines: Vec<Entry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[2].bytes = 9;
        lines[2].hash = lines[2].compute_hash();
        let rewritten: String = lines
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect();
        std::fs::write(&path, rewritten).unwrap();
        let v = verify(d.path());
        assert!(
            v.problems.iter().any(|p| p.contains("does not follow")),
            "{v:?}"
        );
    }

    #[test]
    fn a_removed_or_added_line_breaks_the_chain() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        for i in 0..4u8 {
            l.record(rec("heartbeat", &[i])).unwrap();
        }
        let path = file_of(d.path());
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(!verify(d.path()).ok());
        // Removing the first line: the chain no longer starts at genesis.
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(0);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let v = verify(d.path());
        assert!(v.problems[0].contains("nothing records why"), "{v:?}");
        // An unknown field smuggled into an entry.
        let added = text.replacen("\"kind\"", "\"extra\":1,\"kind\"", 1);
        std::fs::write(&path, added).unwrap();
        assert!(!verify(d.path()).ok());
    }

    #[test]
    fn a_torn_last_line_is_dropped_on_open() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        l.record(rec("heartbeat", b"a")).unwrap();
        drop(l);
        let path = file_of(d.path());
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":2,\"at\"").unwrap();
        let l = ledger(d.path());
        l.record(rec("heartbeat", b"b")).unwrap();
        assert!(verify(d.path()).ok());
    }

    #[test]
    fn retention_leaves_an_anchor_the_rest_verifies_from() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        for i in 0..3u8 {
            l.record(rec("heartbeat", &[i])).unwrap();
        }
        drop(l);
        // Make today's file an old one.
        let path = file_of(d.path());
        std::fs::rename(&path, d.path().join("ledger-2000-01-01.jsonl")).unwrap();
        let l = ledger(d.path());
        assert!(l.files().is_empty(), "the old day was removed");
        let e = l.record(rec("heartbeat", b"z")).unwrap();
        assert_eq!(e.seq, 4);
        let v = verify(d.path());
        assert!(v.ok(), "{v:?}");
        assert!(v.starts_at.contains("retention"), "{v:?}");
    }

    #[test]
    fn bounded_in_memory() {
        let d = tempfile::tempdir().unwrap();
        let l = ledger(d.path());
        for _ in 0..(RECENT + 5) {
            l.record(rec("heartbeat", b"x")).unwrap();
        }
        assert_eq!(l.recent(usize::MAX).len(), RECENT);
        assert_eq!(l.totals()["heartbeat"].messages, (RECENT + 5) as u64);
    }
}
