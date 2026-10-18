//! Infrastructure connection kinds on the agent (RFC 0150.1, slice C8): `kubectl`, `helm`,
//! `ansible`, `tofu` and `ssh`.
//!
//! A connection names a binary (an absolute path), a working directory, a fixed argv
//! prefix and the environment the tool needs (kubeconfig, inventory, keys, cloud
//! credentials). All of that stays on the agent; none of it is sent upstream.
//!
//! A request is an argv. [`verbs::classify`] parses it against the kind's table into one
//! of three classes:
//!
//! - read: runs at once, audited;
//! - plan: works out a change and saves a plan artifact; the artifact's sha256 is the
//!   plan hash;
//! - apply: runs the saved plan's apply form, and only when the caller presents an
//!   approval pinned to that plan's hash (RFC 0153) and the [`ApprovalCheck`] spends it.
//!
//! What runs is built from the parsed words, never the caller's text, and is started by
//! argv with no shell, a cleared environment, no stdin, a deadline and an output cap.
//! Output is redacted ([`crate::redact`]) before it is returned.
//!
//! The approval source here is an interface and a test double; the real `ClaimRun`
//! wiring is slice C4.

pub mod approval;
pub mod exec;
pub mod store;
pub mod verbs;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use approval::{Approval, ApprovalCheck, Denied, DenyAll, FedApprovals};
use store::{Plan, Store, sha256_of};
use verbs::{Arg, Class, Command};

use crate::audit::{Audit, Record};
use crate::redact;

/// The tool a connection runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// `kubectl`.
    Kubectl,
    /// `helm` (with the `diff` plugin for `diff upgrade`).
    Helm,
    /// `ansible-playbook`, and `ansible-inventory` as the aux binary.
    Ansible,
    /// `tofu`.
    Tofu,
    /// `ssh`, to a fixed set of read commands.
    Ssh,
}

impl Kind {
    /// The kind's name as it is written in configuration and audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubectl => "kubectl",
            Self::Helm => "helm",
            Self::Ansible => "ansible",
            Self::Tofu => "tofu",
            Self::Ssh => "ssh",
        }
    }
}

const fn default_timeout() -> u64 {
    60
}
const fn default_cap() -> usize {
    1 << 20
}

/// One configured connection. Everything here stays on the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conn {
    /// The connection's name.
    pub name: String,
    /// Its kind.
    pub kind: Kind,
    /// The binary, an absolute path (never looked up on `PATH`).
    pub bin: PathBuf,
    /// For ansible: `ansible-inventory`'s absolute path.
    #[serde(default)]
    pub aux_bin: Option<PathBuf>,
    /// Where it runs; plan inputs are read from here.
    pub workdir: PathBuf,
    /// A fixed argv prefix (`--kubeconfig`, `-i inventory`, ssh's `-i key user@host`).
    #[serde(default)]
    pub prefix: Vec<String>,
    /// The only environment the process gets.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// A deadline, seconds (1 to 900).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Bytes kept per stream (1 KiB to 8 MiB).
    #[serde(default = "default_cap")]
    pub max_output: usize,
}

impl Conn {
    /// Checks the configuration.
    ///
    /// # Errors
    /// A path is not absolute, a bound is out of range, or a prefix word is empty.
    pub fn validate(&self) -> Result<(), String> {
        let abs = |p: &Path, what: &str| {
            if p.is_absolute() {
                Ok(())
            } else {
                Err(format!("{}: {what} must be an absolute path", self.name))
            }
        };
        abs(&self.bin, "bin")?;
        abs(&self.workdir, "workdir")?;
        if let Some(a) = &self.aux_bin {
            abs(a, "aux_bin")?;
        }
        if !(1..=900).contains(&self.timeout_secs) {
            return Err(format!("{}: timeout_secs must be 1 to 900", self.name));
        }
        if !(1024..=8 << 20).contains(&self.max_output) {
            return Err(format!("{}: max_output must be 1 KiB to 8 MiB", self.name));
        }
        if self.prefix.iter().any(String::is_empty) {
            return Err(format!("{}: an empty prefix word", self.name));
        }
        Ok(())
    }
}

/// Why a request did not run to a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InfraError {
    /// The argv is not in the verb table.
    #[error("refused: {0}")]
    Refused(String),
    /// An apply without a valid, matching, unspent approval.
    #[error("denied: {0}")]
    Denied(String),
    /// It was allowed and failed (exit code, timeout, I/O). Carries no output.
    #[error("failed: {0}")]
    Failed(String),
}

/// What a run returns. Output is already redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The verb's class.
    pub class: Class,
    /// The verb.
    pub verb: &'static str,
    /// The exit code.
    pub code: i32,
    /// Standard output, redacted.
    pub stdout: String,
    /// Standard error, redacted.
    pub stderr: String,
    /// Output was cut at the cap.
    pub truncated: bool,
    /// For a plan: its hash.
    pub plan_hash: Option<String>,
}

/// Runs one connection's requests.
#[derive(Debug)]
pub struct Runner {
    conn: Conn,
    store: Store,
    audit: Arc<Audit>,
    approvals: Arc<dyn ApprovalCheck>,
}

impl Runner {
    /// A runner for `conn`, saving plans under `plans_dir`. Applies are denied until an
    /// [`ApprovalCheck`] is set with [`Runner::with_approvals`].
    ///
    /// # Errors
    /// The connection is misconfigured or the plan directory cannot be made.
    pub fn new(conn: Conn, plans_dir: &Path, audit: Arc<Audit>) -> Result<Self, String> {
        conn.validate()?;
        std::fs::create_dir_all(plans_dir).map_err(|e| format!("{}: {e}", plans_dir.display()))?;
        for (k, v) in &conn.env {
            let up = k.to_ascii_uppercase();
            if ["TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL"]
                .iter()
                .any(|w| up.contains(w))
            {
                redact::register(v);
            }
        }
        Ok(Self {
            conn,
            store: Store::new(plans_dir.to_owned()),
            audit,
            approvals: Arc::new(DenyAll),
        })
    }

    /// Sets where approvals are spent.
    #[must_use]
    pub fn with_approvals(mut self, a: Arc<dyn ApprovalCheck>) -> Self {
        self.approvals = a;
        self
    }

    fn note(&self, who: &str, c: &Command, target: &str, outcome: &str) -> Result<(), InfraError> {
        let action = format!("infra.{}.{}", self.conn.kind.as_str(), c.class.as_str());
        self.audit
            .record(Record {
                who,
                action: &action,
                target,
                outcome,
                ..Record::default()
            })
            .map(|_| ())
            .map_err(|_| InfraError::Failed("the audit log cannot be written".into()))
    }

    /// Classifies `argv` and runs it.
    ///
    /// # Errors
    /// [`InfraError`]: refused by the table, denied for want of an approval, or failed.
    pub async fn run(
        &self,
        who: &str,
        argv: &[String],
        approval: Option<&Approval>,
    ) -> Result<Report, InfraError> {
        let cmd = match verbs::classify(self.conn.kind, argv) {
            Ok(c) => c,
            Err(e) => {
                let action = format!("infra.{}.refused", self.conn.kind.as_str());
                let _ = self.audit.record(Record {
                    who,
                    action: &action,
                    target: &self.conn.name,
                    outcome: "refused",
                    reason: &e.0,
                    ..Record::default()
                });
                return Err(InfraError::Refused(e.0));
            }
        };
        let target = format!("{}/{}", self.conn.name, cmd.verb);
        match cmd.class {
            Class::Read => {
                let r = self
                    .exec(&cmd, &self.conn.workdir, &self.conn.workdir, None)
                    .await;
                self.finish(who, &cmd, &target, r, None)
            }
            Class::Plan => self.plan(who, &cmd, &target).await,
            Class::Apply => self.apply(who, &cmd, &target, approval).await,
        }
    }

    fn finish(
        &self,
        who: &str,
        c: &Command,
        target: &str,
        r: Result<exec::Output, InfraError>,
        plan_hash: Option<String>,
    ) -> Result<Report, InfraError> {
        match r {
            Ok(o) => {
                let code = o.code.unwrap_or(-1);
                let ok = o.code.is_some_and(|x| c.ok_codes.contains(&x));
                let outcome = if o.timed_out {
                    "timeout".to_owned()
                } else if ok {
                    "ok".to_owned()
                } else {
                    format!("exit {code}")
                };
                self.note(who, c, target, &outcome)?;
                let report = Report {
                    class: c.class,
                    verb: c.verb,
                    code,
                    stdout: clean(&o.stdout),
                    stderr: clean(&o.stderr),
                    truncated: o.truncated,
                    plan_hash,
                };
                if o.timed_out {
                    Err(InfraError::Failed(
                        "the deadline passed and the process was killed".into(),
                    ))
                } else if ok || c.class == Class::Read {
                    Ok(report)
                } else {
                    Err(InfraError::Failed(format!(
                        "exit {code}: {}",
                        first_line(&report.stderr)
                    )))
                }
            }
            Err(e) => {
                self.note(who, c, target, "failed")?;
                Err(e)
            }
        }
    }

    /// Resolves table words to real arguments. `files` is where `File` words live.
    fn resolve(
        &self,
        args: &[Arg],
        files: &Path,
        plan_file: &Path,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        out.extend(self.conn.prefix.iter().cloned());
        for a in args {
            out.push(match a {
                Arg::Lit(s) => s.clone(),
                Arg::File(rel) => files.join(rel).to_string_lossy().into_owned(),
                Arg::PlanOut | Arg::PlanIn => plan_file.to_string_lossy().into_owned(),
            });
        }
        out
    }

    async fn exec(
        &self,
        c: &Command,
        cwd: &Path,
        files: &Path,
        plan_file: Option<&Path>,
    ) -> Result<exec::Output, InfraError> {
        let bin = if c.aux {
            self.conn.aux_bin.as_deref().unwrap_or(&self.conn.bin)
        } else {
            &self.conn.bin
        };
        if c.class == Class::Read {
            // Read-class files (ansible list-hosts) must stay inside the working directory.
            for a in &c.args {
                if let Arg::File(rel) = a {
                    inside(&self.conn.workdir, rel)?;
                }
            }
        }
        let none = PathBuf::new();
        let argv = self.resolve(&c.args, files, plan_file.unwrap_or(&none));
        exec::run(
            bin,
            &argv,
            cwd,
            &self.conn.env,
            Duration::from_secs(self.conn.timeout_secs),
            self.conn.max_output,
        )
        .await
        .map_err(|e| InfraError::Failed(format!("the process did not start: {}", e.kind())))
    }

    async fn plan(&self, who: &str, c: &Command, target: &str) -> Result<Report, InfraError> {
        let io = |e: std::io::Error| InfraError::Failed(format!("plan store: {}", e.kind()));
        let scratch = self.store.scratch().map_err(io)?;
        let result = self.plan_in(who, c, target, &scratch).await;
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&scratch);
        }
        result
    }

    async fn plan_in(
        &self,
        who: &str,
        c: &Command,
        target: &str,
        scratch: &Path,
    ) -> Result<Report, InfraError> {
        let io = |e: std::io::Error| InfraError::Failed(format!("plan store: {}", e.kind()));
        let files_dir = scratch.join("files");
        let mut files = BTreeMap::new();
        for a in &c.args {
            if let Arg::File(rel) = a {
                let src = inside(&self.conn.workdir, rel)?;
                let bytes = std::fs::read(&src)
                    .map_err(|_| InfraError::Failed(format!("{rel} cannot be read")))?;
                if c.kind == Kind::Kubectl && mentions_secret(&bytes) {
                    return Err(InfraError::Refused(format!(
                        "{rel} holds a Secret; plans never carry secret data"
                    )));
                }
                let dst = files_dir.join(rel);
                if let Some(p) = dst.parent() {
                    std::fs::create_dir_all(p).map_err(io)?;
                }
                std::fs::write(&dst, &bytes).map_err(io)?;
                files.insert(rel.clone(), sha256_of(&bytes));
            }
        }
        let plan_file = scratch.join("plan.tfplan");
        let cwd = if files.is_empty() {
            &self.conn.workdir
        } else {
            &files_dir
        };
        let out = self.exec(c, cwd, &files_dir, Some(&plan_file)).await;
        let out = match out {
            Ok(o) if !o.timed_out && o.code.is_some_and(|x| c.ok_codes.contains(&x)) => o,
            other => return self.finish(who, c, target, other, None),
        };
        let (so, se) = (clean(&out.stdout), clean(&out.stderr));
        let mut plan = Plan {
            kind: c.kind,
            verb: c.verb.to_owned(),
            apply: c.apply.clone().unwrap_or_default(),
            files,
            output_sha256: sha256_of(format!("{so}\n{se}").as_bytes()),
            hash: String::new(),
        };
        plan.hash = if c.kind == Kind::Tofu {
            let bytes = std::fs::read(&plan_file)
                .map_err(|_| InfraError::Failed("tofu wrote no plan file".into()))?;
            sha256_of(&bytes)
        } else {
            plan.compute_hash()
        };
        self.store.commit(scratch, &plan).map_err(io)?;
        let hash = plan.hash.clone();
        self.finish(who, c, target, Ok(out), Some(hash))
    }

    async fn apply(
        &self,
        who: &str,
        c: &Command,
        target: &str,
        approval: Option<&Approval>,
    ) -> Result<Report, InfraError> {
        let deny = |why: &str| {
            let _ = self.audit.record(Record {
                who,
                action: &format!("infra.{}.apply", self.conn.kind.as_str()),
                target,
                outcome: "denied",
                reason: why,
                ..Record::default()
            });
            Err(InfraError::Denied(why.to_owned()))
        };
        let Some(ap) = approval else {
            return deny("an apply needs an approval pinned to a saved plan's hash");
        };
        let (plan, dir) = match self.store.load(&ap.plan_hash) {
            Ok(p) => p,
            Err(e) => return deny(&e),
        };
        if plan.kind != c.kind || plan.apply != c.args {
            return deny("this apply is not the apply the saved plan describes");
        }
        if let Err(Denied(e)) = self.approvals.spend(ap, &plan.hash) {
            return deny(&e);
        }
        self.note(who, c, target, &format!("approved {}", plan.hash))?;
        let (cwd, files) = if c.kind == Kind::Tofu {
            (self.conn.workdir.clone(), dir.join("files"))
        } else {
            (dir.join("files"), dir.join("files"))
        };
        let r = self
            .exec(c, &cwd, &files, Some(&dir.join("plan.tfplan")))
            .await;
        self.finish(who, c, target, r, Some(plan.hash))
    }
}

/// A relative path resolved inside `root`; a symlink that leaves it is refused.
fn inside(root: &Path, rel: &str) -> Result<PathBuf, InfraError> {
    let root = root
        .canonicalize()
        .map_err(|_| InfraError::Failed("the working directory is missing".into()))?;
    let p = root
        .join(rel)
        .canonicalize()
        .map_err(|_| InfraError::Refused(format!("{rel} does not exist")))?;
    if p.starts_with(&root) {
        Ok(p)
    } else {
        Err(InfraError::Refused(format!(
            "{rel} leaves the working directory"
        )))
    }
}

fn mentions_secret(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).lines().any(|l| {
        let l = l.trim().to_ascii_lowercase();
        l.strip_prefix("kind:")
            .is_some_and(|k| k.trim().trim_matches(['"', '\'']) == "secret")
    })
}

fn clean(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let t = s.trim_start();
    let s = if t.starts_with('{') || t.starts_with('[') {
        redact::redact_json(&s)
    } else {
        s.into_owned()
    };
    redact::redact(&s)
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(200).collect()
}
