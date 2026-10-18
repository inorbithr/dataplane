//! The `examples` check surface (RFC 0165, slice 4): this machine runs a named set of the
//! SDK's examples on a timer from its own checkout, and a declared check reads the latest
//! finished run.
//!
//! The run takes minutes and a check job waits seconds, so the two are apart: a background
//! loop ([`run_loop`]) runs the set's command and keeps the outcome; the check
//! ([`Store::judge`]) only reads it. The command is the operator's, from `policy.toml`
//! `[examples.<key>]`; a job and `checks.toml` name only the key. The command's output is
//! never kept. The results file is `examples-results.json`, schema 1 (the SDK's
//! `tools/run-examples.py`); only the derived fields below ever leave this machine.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::checks::{CheckDetail, ErrorClass, Invariant, InvariantStatus};

/// The most examples one run reports; past it the rest are dropped, failures first.
pub const MAX_ROWS: usize = 64;
/// The largest results file read.
const MAX_RESULTS_BYTES: u64 = 4 * 1024 * 1024;
/// The longest a slug (a language or an example name) can be.
const MAX_SLUG: usize = 48;

/// `[examples]`: the sets this machine can run, by key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExamplesPolicy(pub BTreeMap<String, SetPolicy>);

/// `[examples.<key>]`: one named set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPolicy {
    /// The checkout the command runs in (absolute).
    pub dir: PathBuf,
    /// The command and its arguments, no shell (for example `["mise", "run", "examples:run"]`).
    pub command: Vec<String>,
    /// The results file, relative to `dir`.
    #[serde(default = "default_results")]
    pub results: PathBuf,
    /// Seconds between the starts of two runs.
    #[serde(default = "default_every")]
    pub every_secs: u64,
    /// A run still going after this many seconds is stopped and counts as `run/timeout`.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// A finished run older than this reads as `run/stale`. Default: twice the interval
    /// plus the timeout.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
}

fn default_results() -> PathBuf {
    PathBuf::from("examples-results.json")
}
fn default_every() -> u64 {
    3600
}
fn default_timeout() -> u64 {
    1800
}

impl SetPolicy {
    /// The age past which a finished run is stale.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        Duration::from_secs(
            self.max_age_secs
                .unwrap_or(self.every_secs.saturating_mul(2) + self.timeout_secs),
        )
    }

    /// Checks one set.
    ///
    /// # Errors
    /// What is wrong with it.
    pub fn validate(&self) -> Result<(), String> {
        if !self.dir.is_absolute() {
            return Err("dir must be an absolute path".into());
        }
        if self.command.first().is_none_or(|c| c.trim().is_empty()) {
            return Err("command must name a program".into());
        }
        if self.command.len() > 32 || self.command.iter().any(|a| a.len() > 512) {
            return Err("command is too long".into());
        }
        let r = &self.results;
        if r.is_absolute()
            || r.as_os_str().is_empty()
            || r.components().any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("results must be a relative path inside dir, without ..".into());
        }
        if !(60..=86_400).contains(&self.every_secs) {
            return Err("every_secs must be 60 to 86400".into());
        }
        if !(10..=7200).contains(&self.timeout_secs) {
            return Err("timeout_secs must be 10 to 7200".into());
        }
        if self.max_age_secs.is_some_and(|m| m < self.every_secs) {
            return Err("max_age_secs must be at least every_secs".into());
        }
        Ok(())
    }
}

impl ExamplesPolicy {
    /// Checks every set and its key.
    ///
    /// # Errors
    /// The first problem, naming the set.
    pub fn validate(&self) -> Result<(), String> {
        for (k, s) in &self.0 {
            if !is_slug(k) {
                return Err(format!(
                    "[examples.{k}]: the key is letters, digits, - and _ (up to {MAX_SLUG})"
                ));
            }
            s.validate().map_err(|e| format!("[examples.{k}]: {e}"))?;
        }
        Ok(())
    }
}

/// A set key, a language or an example name: short, and safe to put in a result.
#[must_use]
pub fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SLUG
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// One example's verdict, from a results row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    status: InvariantStatus,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ended {
    /// The command ran and the file parsed.
    Rows(Vec<Row>),
    /// A run-level problem: the slug says which.
    Broke(&'static str),
}

#[derive(Debug, Clone)]
struct Outcome {
    at: Instant,
    ended: Ended,
}

/// The latest finished run of each set. Shared by the loop and the executor.
#[derive(Debug, Default)]
pub struct Store {
    runs: Mutex<HashMap<String, Outcome>>,
}

impl Store {
    fn put(&self, key: &str, ended: Ended) {
        let mut g = match self.runs.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.insert(
            key.to_owned(),
            Outcome {
                at: Instant::now(),
                ended,
            },
        );
    }

    /// The check's answer for set `key` now: failing examples first, or one run-level
    /// invariant. `Err` while no run has finished yet (the platform shows it as unknown,
    /// not down).
    ///
    /// # Errors
    /// No run of this set has finished since the agent started.
    pub fn judge(
        &self,
        key: &str,
        set: &SetPolicy,
        started: Instant,
    ) -> Result<CheckDetail, String> {
        let found = {
            let g = match self.runs.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.get(key).cloned()
        };
        let Some(out) = found else {
            return Err("no run of this example set has finished yet".into());
        };
        let age = out.at.elapsed();
        let mut detail = CheckDetail {
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
            error_class: Some(ErrorClass::Examples),
            ..CheckDetail::default()
        };
        let broke = |slug: &str| Invariant::failed(format!("run/{slug}"));
        match out.ended {
            Ended::Broke(slug) => detail.invariants = vec![broke(slug)],
            Ended::Rows(_) if age > set.max_age() => detail.invariants = vec![broke("stale")],
            Ended::Rows(mut rows) => {
                rows.sort_by_key(|r| (r.status != InvariantStatus::Failed, r.name.clone()));
                rows.truncate(MAX_ROWS);
                let failing = rows.iter().any(|r| r.status == InvariantStatus::Failed);
                let ran = rows.iter().any(|r| r.status == InvariantStatus::Ok);
                detail.invariants = rows
                    .into_iter()
                    .map(|r| Invariant::new(r.name, r.status))
                    .collect();
                if failing {
                    // keep the class: the platform opens an incident on the first failure.
                } else if ran {
                    detail.ok = true;
                    detail.error_class = None;
                } else {
                    // Nothing ran: a green check would say nothing.
                    detail.invariants = vec![broke("empty")];
                }
            }
        }
        Ok(detail)
    }
}

#[derive(Deserialize)]
struct File {
    schema: u32,
    results: Vec<FileRow>,
}

#[derive(Deserialize)]
struct FileRow {
    language: String,
    example: String,
    status: String,
}

/// Parses `examples-results.json` (schema 1). Extra fields are tolerated; a name that is
/// not a short slug, or a status that is not `pass`, `fail` or `skip`, is `malformed`.
fn parse(bytes: &[u8]) -> Ended {
    let Ok(f) = serde_json::from_slice::<File>(bytes) else {
        return Ended::Broke("malformed");
    };
    if f.schema != 1 {
        return Ended::Broke("malformed");
    }
    let mut rows = Vec::with_capacity(f.results.len());
    for r in f.results {
        if !is_slug(&r.language) || !is_slug(&r.example) {
            return Ended::Broke("malformed");
        }
        let status = match r.status.as_str() {
            "pass" => InvariantStatus::Ok,
            "fail" => InvariantStatus::Failed,
            "skip" => InvariantStatus::Skipped,
            _ => return Ended::Broke("malformed"),
        };
        rows.push(Row {
            name: format!("{}/{}", r.language, r.example),
            status,
        });
    }
    Ended::Rows(rows)
}

/// Runs the set's command once and reads the results file. The command's output goes
/// nowhere. A results file older than this run does not count (`run/missing`).
async fn run_once(set: &SetPolicy) -> Ended {
    use tokio::process::Command;
    let started = std::time::SystemTime::now();
    let mut cmd = Command::new(&set.command[0]);
    cmd.args(&set.command[1..])
        .current_dir(&set.dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let Ok(mut child) = cmd.spawn() else {
        return Ended::Broke("exit");
    };
    let status = match tokio::time::timeout(Duration::from_secs(set.timeout_secs), child.wait())
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Ended::Broke("exit"),
        Err(_) => {
            let _ = child.kill().await;
            return Ended::Broke("timeout");
        }
    };
    // A failing example makes the runner exit non-zero but still write the file: the file
    // decides. Without a fresh file the exit status is the only thing to report.
    let path = set.dir.join(&set.results);
    match read_fresh(&path, started).await {
        Some(bytes) => parse(&bytes),
        None if status.success() => Ended::Broke("missing"),
        None => Ended::Broke("exit"),
    }
}

async fn read_fresh(path: &Path, since: std::time::SystemTime) -> Option<Vec<u8>> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    if !meta.is_file() || meta.len() > MAX_RESULTS_BYTES {
        return None;
    }
    // A little slack: file times are coarse on some file systems.
    let fresh = meta
        .modified()
        .ok()
        .is_some_and(|m| m + Duration::from_secs(2) >= since);
    if !fresh {
        return None;
    }
    tokio::fs::read(path).await.ok()
}

/// Runs every configured set on its timer, for as long as the agent lives. Each set has
/// its own task, so a slow set does not hold another; a set never overlaps itself.
pub async fn run_loop(
    policy: Arc<crate::policy::Policy>,
    store: Arc<Store>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let Some(sets) = policy.examples() else {
        return;
    };
    let mut tasks = tokio::task::JoinSet::new();
    for (key, set) in sets.0.clone() {
        let store = Arc::clone(&store);
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(set.every_secs));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let ended = run_once(&set).await;
                tracing::info!(set = %key, "example set finished");
                store.put(&key, ended);
            }
        });
    }
    // A stopped agent stops the runs: dropping the set aborts the tasks, and a running
    // command is killed with its task (`kill_on_drop`).
    let _ = shutdown.wait_for(|stop| *stop).await;
    tasks.abort_all();
}

#[cfg(test)]
impl Store {
    fn put_rows(&self, key: &str, rows: &[(&str, InvariantStatus)]) {
        self.put(
            key,
            Ended::Rows(
                rows.iter()
                    .map(|(n, s)| Row {
                        name: (*n).into(),
                        status: *s,
                    })
                    .collect(),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(dir: &Path, cmd: &[&str]) -> SetPolicy {
        SetPolicy {
            dir: dir.to_path_buf(),
            command: cmd.iter().map(|s| (*s).to_owned()).collect(),
            results: default_results(),
            every_secs: 60,
            timeout_secs: 10,
            max_age_secs: None,
        }
    }

    fn judged(store: &Store, s: &SetPolicy) -> CheckDetail {
        store.judge("sdk", s, Instant::now()).expect("a run")
    }

    #[test]
    fn a_passing_run_is_ok_and_names_every_example() {
        let st = Store::default();
        st.put_rows(
            "sdk",
            &[
                ("go/unary-get", InvariantStatus::Ok),
                ("rust/unary-get", InvariantStatus::Skipped),
            ],
        );
        let d = judged(&st, &set(Path::new("/x"), &["true"]));
        assert!(d.ok);
        assert_eq!(d.error_class, None);
        assert_eq!(d.invariants.len(), 2);
    }

    #[test]
    fn a_failing_example_comes_first_and_is_not_ok() {
        let st = Store::default();
        st.put_rows(
            "sdk",
            &[
                ("go/a", InvariantStatus::Ok),
                ("python/b", InvariantStatus::Failed),
            ],
        );
        let d = judged(&st, &set(Path::new("/x"), &["true"]));
        assert!(!d.ok);
        assert_eq!(d.error_class, Some(ErrorClass::Examples));
        assert_eq!(d.invariants[0].name, "python/b");
        assert_eq!(d.invariants[0].status, InvariantStatus::Failed);
    }

    #[test]
    fn nothing_ran_is_not_green() {
        let st = Store::default();
        st.put_rows("sdk", &[("go/a", InvariantStatus::Skipped)]);
        let d = judged(&st, &set(Path::new("/x"), &["true"]));
        assert!(!d.ok);
        assert_eq!(d.invariants[0].name, "run/empty");
    }

    #[test]
    fn no_run_yet_is_unknown_not_down() {
        let st = Store::default();
        assert!(st
            .judge("sdk", &set(Path::new("/x"), &["true"]), Instant::now())
            .is_err());
    }

    #[test]
    fn an_old_run_is_stale() {
        let st = Store::default();
        st.put_rows("sdk", &[("go/a", InvariantStatus::Ok)]);
        let mut s = set(Path::new("/x"), &["true"]);
        s.every_secs = 60;
        s.timeout_secs = 10;
        s.max_age_secs = Some(60);
        // Age the run by rewriting its time.
        {
            let mut g = st.runs.lock().unwrap();
            let o = g.get_mut("sdk").unwrap();
            o.at = Instant::now() - Duration::from_secs(120);
        }
        let d = judged(&st, &s);
        assert!(!d.ok);
        assert_eq!(d.invariants[0].name, "run/stale");
    }

    #[test]
    fn parse_reads_schema_one_and_tolerates_extra_fields() {
        let ok = br#"{"schema":1,"commit":"abc","dirty":false,"results":[
            {"language":"go","example":"unary-get","status":"pass","ok":true,"duration_ms":5,"commit":"abc","note":"x"},
            {"language":"rust","example":"unary-get","status":"fail","ok":false}]}"#;
        let Ended::Rows(rows) = parse(ok) else {
            panic!("rows")
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].status, InvariantStatus::Failed);
    }

    #[test]
    fn parse_refuses_what_is_not_schema_one() {
        for bad in [
            &b"not json"[..],
            br#"{"schema":2,"results":[]}"#,
            br#"{"schema":1,"results":[{"language":"go","example":"a b","status":"pass"}]}"#,
            br#"{"schema":1,"results":[{"language":"go","example":"a","status":"maybe"}]}"#,
            br#"{"schema":1,"results":[{"language":"../x","example":"a","status":"pass"}]}"#,
        ] {
            assert_eq!(parse(bad), Ended::Broke("malformed"), "{bad:?}");
        }
    }

    #[test]
    fn the_policy_refuses_unsafe_sets() {
        let good = set(Path::new("/srv/sdk"), &["mise", "run", "examples:run"]);
        assert!(good.validate().is_ok());
        let mut b = good.clone();
        b.dir = PathBuf::from("relative");
        assert!(b.validate().is_err());
        let mut b = good.clone();
        b.results = PathBuf::from("../etc/passwd");
        assert!(b.validate().is_err());
        let mut b = good.clone();
        b.results = PathBuf::from("/abs.json");
        assert!(b.validate().is_err());
        let mut b = good.clone();
        b.command.clear();
        assert!(b.validate().is_err());
        let mut b = good.clone();
        b.timeout_secs = 99_999;
        assert!(b.validate().is_err());
        let mut p = ExamplesPolicy::default();
        p.0.insert("bad key".into(), good);
        assert!(p.validate().is_err());
    }

    #[tokio::test]
    async fn a_command_that_writes_the_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let s = set(
            dir.path(),
            &[
                "sh",
                "-c",
                r#"printf '{"schema":1,"results":[{"language":"go","example":"a","status":"fail"}]}' > examples-results.json; exit 1"#,
            ],
        );
        let Ended::Rows(rows) = run_once(&s).await else {
            panic!("rows")
        };
        assert_eq!(rows[0].status, InvariantStatus::Failed);
    }

    #[tokio::test]
    async fn a_run_that_writes_nothing_is_missing_or_exit() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            run_once(&set(dir.path(), &["true"])).await,
            Ended::Broke("missing")
        );
        assert_eq!(
            run_once(&set(dir.path(), &["false"])).await,
            Ended::Broke("exit")
        );
        assert_eq!(
            run_once(&set(dir.path(), &["no-such-program-x"])).await,
            Ended::Broke("exit")
        );
    }

    #[tokio::test]
    async fn an_old_file_is_not_this_runs_answer() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("examples-results.json");
        std::fs::write(&f, br#"{"schema":1,"results":[]}"#).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(
            run_once(&set(dir.path(), &["true"])).await,
            Ended::Broke("missing")
        );
    }

    #[tokio::test]
    async fn a_run_past_its_timeout_is_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = set(dir.path(), &["sleep", "30"]);
        s.timeout_secs = 10;
        // The real minimum is 10 s; shorten for the test through a direct call.
        s.timeout_secs = 1;
        assert_eq!(run_once(&s).await, Ended::Broke("timeout"));
    }

    #[tokio::test]
    async fn only_derived_fields_leave() {
        let dir = tempfile::tempdir().unwrap();
        let s = set(
            dir.path(),
            &[
                "sh",
                "-c",
                r#"echo SECRET-OUTPUT; printf '{"schema":1,"results":[{"language":"go","example":"a","status":"pass","note":"SECRET-NOTE"}]}' > examples-results.json"#,
            ],
        );
        let st = Store::default();
        st.put("sdk", run_once(&s).await);
        let d = st.judge("sdk", &s, Instant::now()).unwrap();
        let wire = serde_json::to_string(&d).unwrap();
        assert!(!wire.contains("SECRET"), "{wire}");
        assert!(!wire.contains(dir.path().to_str().unwrap()), "{wire}");
        assert!(d.ok);
    }
}
