//! The agent's trial storage (RFC 0100.1 §5): check runs and host samples kept on this
//! machine in SQLite, so the local console has history that survives a restart and works
//! with no network at all.
//!
//! "Trial storage, not for production": with no `[stores]` (the customer's own Postgres
//! and `ClickHouse`, a later phase) the agent writes here, in `<state_dir>/store/agent.sqlite`,
//! mode 0600. Nothing in it ever leaves the machine; the platform never reads it.
//!
//! What a row holds is what the admin page already shows: verdicts, timings, status codes,
//! classes of error, host names, never a path, a query, a body or a secret (every field
//! passed through [`crate::state::JobRecord::bounded`] first). Bounded: runs older than
//! `[local] retain_days`, and more than [`MAX_RUNS`] in all, are deleted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::state::{HostInfo, JobRecord};

/// The file, in [`dir_in`].
pub const FILE: &str = "agent.sqlite";
/// Most runs kept, all checks together.
pub const MAX_RUNS: i64 = 200_000;
/// Most host samples kept.
pub const MAX_HOST: i64 = 50_000;
/// At most one host row per this interval (the sampler ticks every few seconds).
const HOST_EVERY: Duration = Duration::from_secs(60);
/// Prune after this many writes.
const PRUNE_EVERY: u32 = 500;
/// Most rows one read returns.
pub const MAX_PAGE: usize = 500;

/// Where the store lives.
#[must_use]
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("store")
}

/// One stored run, with its row id (the page token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRun {
    /// Row id, increasing.
    pub id: i64,
    /// The run.
    pub record: JobRecord,
}

/// One stored host reading.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostRow {
    /// When, RFC 3339.
    pub at: String,
    /// Sensors sampled.
    pub sensors: i64,
    /// The chipset temperature, milli-degrees, when the board has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chipset_millicelsius: Option<i64>,
    /// How long the read took, microseconds.
    pub cost_us: i64,
}

/// The trial store. Cheap to share; one connection behind a lock (the writes are a few a
/// minute, the reads are a person looking at a page).
#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
    path: PathBuf,
    retain: Duration,
    writes: Mutex<u32>,
    last_host: Mutex<Option<Instant>>,
}

impl Store {
    /// Opens (or creates) the store in `dir`, keeping runs for `retain_days`.
    ///
    /// # Errors
    /// The directory or the database cannot be created or opened.
    pub fn open(dir: &Path, retain_days: u32) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let path = dir.join(FILE);
        let conn = Connection::open(&path).map_err(sql)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS runs (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               key TEXT,
               at TEXT NOT NULL,
               kind TEXT NOT NULL,
               surface TEXT,
               target_host TEXT,
               verdict TEXT NOT NULL,
               latency_ms INTEGER NOT NULL,
               job_id TEXT,
               reason TEXT,
               error_class TEXT,
               status_code INTEGER,
               tls_expires_at TEXT
             );
             CREATE INDEX IF NOT EXISTS runs_key_id ON runs (key, id);
             CREATE INDEX IF NOT EXISTS runs_at ON runs (at);
             CREATE TABLE IF NOT EXISTS host (
               at TEXT PRIMARY KEY,
               sensors INTEGER NOT NULL,
               chipset_millicelsius INTEGER,
               cost_us INTEGER NOT NULL
             );",
        )
        .map_err(sql)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path,
            retain: Duration::from_secs(u64::from(retain_days.max(1)) * 86_400),
            writes: Mutex::new(0),
            last_host: Mutex::new(None),
        })
    }

    /// The database file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Keeps one run. A failure is logged by the caller and never stops a job.
    ///
    /// # Errors
    /// SQLite refused the write.
    pub fn record_run(&self, r: &JobRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO runs (key, at, kind, surface, target_host, verdict, latency_ms,
                   job_id, reason, error_class, status_code, tls_expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    r.key,
                    r.at,
                    r.kind,
                    r.surface,
                    r.target_host,
                    r.verdict,
                    i64::try_from(r.latency_ms).unwrap_or(i64::MAX),
                    r.job_id,
                    r.reason,
                    r.error_class,
                    r.status_code,
                    r.tls_expires_at,
                ],
            )
            .map_err(sql)?;
        self.wrote();
        Ok(())
    }

    /// Keeps a host reading, at most one a minute.
    ///
    /// # Errors
    /// SQLite refused the write.
    pub fn record_host(&self, h: &HostInfo) -> Result<()> {
        {
            let mut last = match self.last_host.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if last.is_some_and(|t| t.elapsed() < HOST_EVERY) {
                return Ok(());
            }
            *last = Some(Instant::now());
        }
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO host (at, sensors, chipset_millicelsius, cost_us)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    h.last_sample_at,
                    i64::try_from(h.sensors).unwrap_or(i64::MAX),
                    h.chipset_millicelsius,
                    i64::try_from(h.last_cost_us).unwrap_or(i64::MAX),
                ],
            )
            .map_err(sql)?;
        self.wrote();
        Ok(())
    }

    fn wrote(&self) {
        let due = {
            let mut n = match self.writes.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *n += 1;
            if *n >= PRUNE_EVERY {
                *n = 0;
                true
            } else {
                false
            }
        };
        if due && let Err(e) = self.prune() {
            tracing::warn!(error = %e, "the trial store could not delete old rows");
        }
    }

    /// Deletes what is past retention or over the caps.
    ///
    /// # Errors
    /// SQLite refused the delete.
    pub fn prune(&self) -> Result<()> {
        let cutoff = cutoff(self.retain);
        let c = self.conn();
        c.execute("DELETE FROM runs WHERE at < ?1", params![cutoff])
            .map_err(sql)?;
        c.execute(
            "DELETE FROM runs WHERE id <= (SELECT MAX(id) FROM runs) - ?1",
            params![MAX_RUNS],
        )
        .map_err(sql)?;
        c.execute("DELETE FROM host WHERE at < ?1", params![cutoff])
            .map_err(sql)?;
        c.execute(
            "DELETE FROM host WHERE at NOT IN (SELECT at FROM host ORDER BY at DESC LIMIT ?1)",
            params![MAX_HOST],
        )
        .map_err(sql)?;
        Ok(())
    }

    /// A check's runs, newest first: up to `limit`, older than row `before` when given,
    /// with `verdict` given as `(v, true)` only runs whose verdict is `v`, as `(v, false)`
    /// only runs whose verdict is not, and at or after `from` (RFC 3339) when given.
    ///
    /// # Errors
    /// SQLite refused the read.
    pub fn runs(
        &self,
        key: &str,
        limit: usize,
        before: Option<i64>,
        verdict: Option<(&str, bool)>,
        from: Option<&str>,
    ) -> Result<Vec<StoredRun>> {
        let limit = i64::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(50);
        let before = before.unwrap_or(i64::MAX);
        let from = from.unwrap_or("");
        let (want, equal) = verdict.unwrap_or(("", true));
        let c = self.conn();
        let mut stmt = c
            .prepare(
                "SELECT id, at, kind, surface, target_host, verdict, latency_ms, job_id, reason,
                        error_class, status_code, tls_expires_at
                 FROM runs
                 WHERE key = ?1 AND id < ?2
                   AND (?3 = '' OR (?6 = 1 AND verdict = ?3) OR (?6 = 0 AND verdict <> ?3))
                   AND at >= ?5
                 ORDER BY id DESC LIMIT ?4",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(params![key, before, want, limit, from, equal], |row| {
                Ok(StoredRun {
                    id: row.get(0)?,
                    record: JobRecord {
                        at: row.get(1)?,
                        kind: row.get(2)?,
                        surface: row.get(3)?,
                        target_host: row.get(4)?,
                        verdict: row.get(5)?,
                        latency_ms: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
                        job_id: row.get(7)?,
                        key: Some(key.to_owned()),
                        reason: row.get(8)?,
                        error_class: row.get(9)?,
                        status_code: row.get(10)?,
                        tls_expires_at: row.get(11)?,
                    },
                })
            })
            .map_err(sql)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)
    }

    /// The newest `n` runs of every check, oldest first: the in-memory history after a
    /// restart.
    ///
    /// # Errors
    /// SQLite refused the read.
    pub fn recent_by_key(&self, n: usize) -> Result<BTreeMap<String, Vec<JobRecord>>> {
        let keys: Vec<String> = {
            let c = self.conn();
            let mut stmt = c
                .prepare("SELECT DISTINCT key FROM runs WHERE key IS NOT NULL")
                .map_err(sql)?;
            let rows = stmt.query_map([], |r| r.get(0)).map_err(sql)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sql)?
        };
        let mut out = BTreeMap::new();
        for k in keys {
            let mut runs: Vec<JobRecord> = self
                .runs(&k, n, None, None, None)?
                .into_iter()
                .map(|r| r.record)
                .collect();
            runs.reverse();
            out.insert(k, runs);
        }
        Ok(out)
    }

    /// The last run of a check.
    ///
    /// # Errors
    /// SQLite refused the read.
    pub fn last_run_at(&self, key: &str) -> Result<Option<String>> {
        self.conn()
            .query_row(
                "SELECT at FROM runs WHERE key = ?1 ORDER BY id DESC LIMIT 1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)
    }

    /// Host readings, newest first.
    ///
    /// # Errors
    /// SQLite refused the read.
    pub fn host(&self, limit: usize) -> Result<Vec<HostRow>> {
        let limit = i64::try_from(limit.clamp(1, MAX_PAGE)).unwrap_or(60);
        let c = self.conn();
        let mut stmt = c
            .prepare(
                "SELECT at, sensors, chipset_millicelsius, cost_us FROM host
                 ORDER BY at DESC LIMIT ?1",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(HostRow {
                    at: r.get(0)?,
                    sensors: r.get(1)?,
                    chipset_millicelsius: r.get(2)?,
                    cost_us: r.get(3)?,
                })
            })
            .map_err(sql)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)
    }
}

fn cutoff(retain: Duration) -> String {
    let t = time::OffsetDateTime::now_utc()
        - time::Duration::seconds(i64::try_from(retain.as_secs()).unwrap_or(i64::MAX));
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[allow(clippy::needless_pass_by_value)] // the shape `map_err` takes
fn sql(e: rusqlite::Error) -> Error {
    Error::Store(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(key: &str, verdict: &str, at: &str) -> JobRecord {
        JobRecord {
            at: at.into(),
            kind: "check".into(),
            surface: Some("http".into()),
            target_host: Some("api.internal".into()),
            verdict: verdict.into(),
            latency_ms: 12,
            key: Some(key.into()),
            status_code: Some(200),
            ..JobRecord::default()
        }
    }

    fn now() -> String {
        crate::enroll::now_rfc3339()
    }

    #[test]
    fn runs_survive_reopening_and_page_newest_first() {
        let dir = tempdir();
        {
            let s = Store::open(&dir, 30).unwrap();
            for i in 0..5 {
                let v = if i == 2 { "failed" } else { "ok" };
                s.record_run(&run("api", v, &now())).unwrap();
            }
            s.record_run(&run("other", "ok", &now())).unwrap();
        }
        let s = Store::open(&dir, 30).unwrap();
        let all = s.runs("api", 10, None, None, None).unwrap();
        assert_eq!(all.len(), 5);
        assert!(all[0].id > all[4].id, "newest first");
        let page = s.runs("api", 2, Some(all[1].id), None, None).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, all[2].id);
        assert_eq!(
            s.runs("api", 10, None, Some(("ok", false)), None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            s.runs("api", 10, None, Some(("ok", true)), None)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            s.runs("api", 10, None, None, Some("2999-01-01T00:00:00Z"))
                .unwrap()
                .len(),
            0
        );
        let by_key = s.recent_by_key(60).unwrap();
        assert_eq!(by_key["api"].len(), 5);
        assert_eq!(by_key["other"].len(), 1);
    }

    #[test]
    fn old_rows_are_pruned() {
        let dir = tempdir();
        let s = Store::open(&dir, 1).unwrap();
        s.record_run(&run("api", "ok", "2001-01-01T00:00:00Z"))
            .unwrap();
        s.record_run(&run("api", "ok", &now())).unwrap();
        s.prune().unwrap();
        assert_eq!(s.runs("api", 10, None, None, None).unwrap().len(), 1);
    }

    #[test]
    fn host_rows_are_kept_at_most_once_a_minute() {
        let dir = tempdir();
        let s = Store::open(&dir, 30).unwrap();
        for i in 0..3 {
            s.record_host(&HostInfo {
                sensors: 7,
                last_sample_at: format!("2099-01-01T00:00:0{i}Z"),
                chipset_millicelsius: Some(110_000),
                ..HostInfo::default()
            })
            .unwrap();
        }
        assert_eq!(s.host(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let s = Store::open(&dir, 30).unwrap();
        let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn tempdir() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("iohr-store-test-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
