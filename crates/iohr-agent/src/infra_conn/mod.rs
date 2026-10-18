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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "test-approvals"))]
pub use approval::FedApprovals;
pub use approval::{Approval, ApprovalCheck, Denied, DenyAll};
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
const fn default_ttl() -> u64 {
    1800
}

/// Options every ssh connection runs with, ahead of its own prefix (ssh keeps the first
/// value it is given for an option): no config file, no prompts, a known host key only,
/// no shared master connection.
const SSH_FORCED: &[&str] = &[
    "-F",
    "/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ControlPath=none",
];

/// The largest key file read to learn its contents for redaction.
const KEY_FILE_MAX: u64 = 64 << 10;

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
    /// The top of the trusted tree the working directory sits in (default: the working
    /// directory). No directory from the working directory up to it may be writable by
    /// the agent or by group or others, or plans and reads are refused.
    #[serde(default)]
    pub root: Option<PathBuf>,
    /// kubectl: the resource types this connection may name or apply, as types
    /// (`deployments`, `configmaps`); none set means every type but secrets.
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    /// helm: the registries an `oci://` chart may come from; empty refuses OCI charts.
    #[serde(default)]
    pub oci_registries: Vec<String>,
    /// ssh: the systemd units this connection may read; none set means any.
    #[serde(default)]
    pub units: Option<Vec<String>>,
    /// How long a saved plan may be applied, seconds (1 to 86400; default 1800).
    #[serde(default = "default_ttl")]
    pub plan_ttl_secs: u64,
}

impl Conn {
    /// A connection with the defaults: no prefix, no environment, no allow-lists.
    #[must_use]
    pub fn new(name: &str, kind: Kind, bin: PathBuf, workdir: PathBuf) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            bin,
            aux_bin: None,
            workdir,
            prefix: Vec::new(),
            env: BTreeMap::new(),
            timeout_secs: default_timeout(),
            max_output: default_cap(),
            root: None,
            resources: None,
            oci_registries: Vec::new(),
            units: None,
            plan_ttl_secs: default_ttl(),
        }
    }

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
        if let Some(r) = &self.root {
            abs(r, "root")?;
            if !self.workdir.starts_with(r) {
                return Err(format!("{}: root must contain workdir", self.name));
            }
        }
        if !(1..=86_400).contains(&self.plan_ttl_secs) {
            return Err(format!("{}: plan_ttl_secs must be 1 to 86400", self.name));
        }
        if self.kind == Kind::Ssh && self.prefix.iter().any(|w| w == "-F" || w.starts_with("-F")) {
            return Err(format!(
                "{}: an ssh prefix may not name a config file",
                self.name
            ));
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
    /// This connection's secret values: env secrets and key file contents.
    redactor: redact::Redactor,
    /// The plan hash whose apply is running; one apply per connection at a time.
    applying: Mutex<Option<String>>,
    /// ansible: an empty config file, so no `ansible.cfg` from the tree is loaded.
    ansible_cfg: PathBuf,
}

/// Releases the apply lock when an apply ends, however it ends.
struct Applying<'a>(&'a Mutex<Option<String>>);

impl Drop for Applying<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
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
        let redactor = redact::Redactor::new();
        learn_secrets(&conn, &redactor);
        let ansible_cfg = plans_dir.join("ansible.cfg");
        if conn.kind == Kind::Ansible {
            std::fs::write(&ansible_cfg, b"")
                .map_err(|e| format!("{}: {e}", ansible_cfg.display()))?;
        }
        Ok(Self {
            conn,
            store: Store::new(plans_dir.to_owned()),
            audit,
            approvals: Arc::new(DenyAll),
            redactor,
            applying: Mutex::new(None),
            ansible_cfg,
        })
    }

    /// The environment a process gets: the connection's, and for ansible the settings
    /// that keep it from loading plugins, config or vars from the tree.
    fn env(&self) -> BTreeMap<String, String> {
        let mut env = self.conn.env.clone();
        if self.conn.kind == Kind::Ansible {
            env.insert("ANSIBLE_INVENTORY_ENABLED".into(), "yaml,ini".into());
            env.insert("ANSIBLE_VARS_ENABLED".into(), "host_group_vars".into());
            env.insert(
                "ANSIBLE_CONFIG".into(),
                self.ansible_cfg.to_string_lossy().into_owned(),
            );
        }
        env
    }

    /// What the plan was made against: the prefix and the kube context settings and
    /// kubeconfig contents. An apply under another context is denied.
    fn context_sha256(&self) -> String {
        let mut parts: Vec<String> = self.conn.prefix.clone();
        for k in ["KUBECONFIG", "KUBECONTEXT", "HELM_KUBECONTEXT"] {
            let v = self.conn.env.get(k).cloned().unwrap_or_default();
            if k == "KUBECONFIG" {
                for f in v.split(':').filter(|f| !f.is_empty()) {
                    parts.push(std::fs::read(f).map_or_else(|_| "-".into(), |b| sha256_of(&b)));
                }
            }
            parts.push(format!("{k}={v}"));
        }
        sha256_of(&serde_json::to_vec(&parts).unwrap_or_default())
    }

    fn redacted(&self, b: &[u8]) -> String {
        let s = String::from_utf8_lossy(b);
        let t = s.trim_start();
        if t.starts_with('{') || t.starts_with('[') {
            // Cut JSON is not JSON: redact_json falls back to text there.
            self.redactor.redact_json(&s)
        } else {
            self.redactor.redact(&s)
        }
    }

    fn refuse(&self, who: &str, target: &str, why: String) -> InfraError {
        let action = format!("infra.{}.refused", self.conn.kind.as_str());
        let _ = self.audit.record(Record {
            who,
            action: &action,
            target,
            outcome: "refused",
            reason: &why,
            ..Record::default()
        });
        InfraError::Refused(why)
    }

    /// The connection's allow-lists: resource types, OCI registries, units.
    fn check_policy(&self, c: &Command) -> Result<(), String> {
        if let Some(allow) = &self.conn.resources {
            let allow: Vec<String> = allow.iter().map(|a| verbs::normal_type(a)).collect();
            if let Some(r) = c
                .values
                .resources
                .iter()
                .find(|r| !allow.contains(&verbs::normal_type(r)))
            {
                return Err(format!("{r} is not a resource type this connection allows"));
            }
        }
        if let Some(verbs::ChartRef::Oci { registry }) =
            c.values.chart.as_deref().and_then(verbs::chart_ref)
            && !self
                .conn
                .oci_registries
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&registry))
        {
            return Err(format!(
                "{registry} is not a registry this connection allows"
            ));
        }
        if let Some(allow) = &self.conn.units {
            let base = |u: &str| u.strip_suffix(".service").unwrap_or(u).to_owned();
            if let Some(u) = c
                .values
                .units
                .iter()
                .find(|u| !allow.iter().any(|a| base(a) == base(u)))
            {
                return Err(format!("{u} is not a unit this connection allows"));
            }
        }
        Ok(())
    }

    /// Plans and reads run tools that load content from the working directory (playbooks,
    /// roles, plugins, kustomizations, providers). That tree must hold trusted content:
    /// no directory from the working directory up to the root may be writable by the
    /// agent's user, or by group or others.
    #[cfg(unix)]
    fn trusted_tree(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        let uid = rustix::process::getuid().as_raw();
        if uid == 0 {
            return Err("the agent runs as root, which can change the working directory; run it as its own user".into());
        }
        let work = self
            .conn
            .workdir
            .canonicalize()
            .map_err(|_| "the working directory is missing".to_owned())?;
        let root = self
            .conn
            .root
            .as_deref()
            .unwrap_or(&self.conn.workdir)
            .canonicalize()
            .map_err(|_| "the connection root is missing".to_owned())?;
        if !work.starts_with(&root) {
            return Err("the working directory is not inside the connection root".into());
        }
        let mut at = Some(work.as_path());
        while let Some(d) = at {
            let m = std::fs::metadata(d)
                .map_err(|_| "a directory of the tree cannot be read".to_owned())?;
            let mode = m.mode();
            if (m.uid() == uid && mode & 0o200 != 0) || mode & 0o022 != 0 {
                return Err("the working directory, or a directory above it up to the connection root, is writable by the agent or by others; plans and reads only run from a tree the agent cannot change".into());
            }
            if d == root {
                break;
            }
            at = d.parent();
        }
        Ok(())
    }

    #[cfg(not(unix))]
    #[allow(clippy::unused_self)]
    fn trusted_tree(&self) -> Result<(), String> {
        Err("plans and reads need a unix host to check the working directory".into())
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
            Err(e) => return Err(self.refuse(who, &self.conn.name, e.0)),
        };
        let target = format!("{}/{}", self.conn.name, cmd.verb);
        if let Err(e) = self.check_policy(&cmd) {
            return Err(self.refuse(who, &target, e));
        }
        if cmd.class != Class::Apply
            && let Err(e) = self.trusted_tree()
        {
            return Err(self.refuse(who, &target, e));
        }
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
                    stdout: self.redacted(&o.stdout),
                    stderr: self.redacted(&o.stderr),
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
    fn resolve(&self, args: &[Arg], files: &Path, plan_file: &Path) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if self.conn.kind == Kind::Ssh {
            out.extend(SSH_FORCED.iter().map(|w| (*w).to_owned()));
        }
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
            &self.env(),
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
        // A committed plan was moved away; anything left is a failed or listing-only run.
        let _ = std::fs::remove_dir_all(&scratch);
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
                if c.kind == Kind::Kubectl {
                    self.check_manifest(who, target, rel, &bytes)?;
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
        let Some(apply) = c.apply.clone() else {
            // A listing (ansible --list-hosts, --list-tasks) loads the playbook like a plan
            // but has no apply, so nothing is saved.
            return self.finish(who, c, target, Ok(out), None);
        };
        let (so, se) = (self.redacted(&out.stdout), self.redacted(&out.stderr));
        let mut plan = Plan {
            kind: c.kind,
            verb: c.verb.to_owned(),
            apply,
            files,
            output_sha256: sha256_of(format!("{so}\n{se}").as_bytes()),
            hash: String::new(),
            conn: self.conn.name.clone(),
            context_sha256: self.context_sha256(),
            chart: c.values.chart.clone(),
            version: c.values.version.clone(),
            created_at: now_secs(),
            record_sha256: String::new(),
        };
        if c.kind == Kind::Tofu {
            let bytes = std::fs::read(&plan_file)
                .map_err(|_| InfraError::Failed("tofu wrote no plan file".into()))?;
            plan.hash = sha256_of(&bytes);
            plan.record_sha256 = plan.compute_hash();
        } else {
            plan.hash = plan.compute_hash();
        }
        if self
            .applying
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            == Some(plan.hash.as_str())
        {
            return Err(self.refuse(
                who,
                target,
                "the apply of this same plan is running; plan again when it ends".into(),
            ));
        }
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
        if plan.conn != self.conn.name {
            return deny("the saved plan was made on another connection");
        }
        if now_secs().saturating_sub(plan.created_at) > self.conn.plan_ttl_secs {
            return deny("the saved plan is older than this connection's plan TTL; plan again");
        }
        if plan.kind != c.kind || plan.apply != c.args {
            return deny("this apply is not the apply the saved plan describes");
        }
        if plan.context_sha256 != self.context_sha256() {
            return deny("the connection's context changed since the plan; plan again");
        }
        let _lock = {
            let mut held = self.applying.lock().unwrap_or_else(PoisonError::into_inner);
            if held.is_some() {
                drop(held);
                return deny("another apply on this connection is running");
            }
            *held = Some(plan.hash.clone());
            Applying(&self.applying)
        };
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

impl Runner {
    /// A kubectl manifest: never a Secret (in YAML, JSON or a `List`), and only the
    /// resource types the connection allows. A Secret refusal is audited with its
    /// namespace and kind, never its values.
    fn check_manifest(
        &self,
        who: &str,
        target: &str,
        rel: &str,
        bytes: &[u8],
    ) -> Result<(), InfraError> {
        let text = String::from_utf8_lossy(bytes);
        let kinds = key_values(&text, "kind");
        if kinds.iter().any(|k| verbs::normal_type(k) == "secret") {
            let ns = key_values(&text, "namespace");
            let ns = if ns.is_empty() {
                "-".to_owned()
            } else {
                ns.join(",")
            };
            return Err(self.refuse(
                who,
                target,
                format!("{rel} holds kind Secret, namespace {ns}; plans never carry secret data"),
            ));
        }
        if let Some(allow) = &self.conn.resources {
            let allow: Vec<String> = allow.iter().map(|a| verbs::normal_type(a)).collect();
            if let Some(k) = kinds
                .iter()
                .find(|k| !allow.contains(&verbs::normal_type(k)))
            {
                return Err(self.refuse(
                    who,
                    target,
                    format!("{rel} holds kind {k}, which this connection does not allow"),
                ));
            }
        }
        Ok(())
    }
}

/// Every value of `key` in YAML or JSON text: the word `key` (not part of a longer
/// name), an optional quote, a colon, an optional quote, then the value's name
/// characters. Covers `kind: Secret # note`, `"kind": "Secret"`, `- kind: Secret` and
/// flow maps; a comment or a string that mentions one counts too, on the safe side.
fn key_values(text: &str, key: &str) -> Vec<String> {
    let b = text.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.';
    let mut out: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(i) = text.get(from..).and_then(|t| t.find(key)) {
        let s = from + i;
        let mut j = s + key.len();
        from = j;
        if s > 0 && b.get(s - 1).copied().is_some_and(word) {
            continue;
        }
        if b.get(j).copied().is_some_and(|c| c == b'"' || c == b'\'') {
            j += 1;
        }
        while b.get(j) == Some(&b' ') || b.get(j) == Some(&b'\t') {
            j += 1;
        }
        if b.get(j) != Some(&b':') {
            continue;
        }
        j += 1;
        while b.get(j) == Some(&b' ') || b.get(j) == Some(&b'\t') {
            j += 1;
        }
        if b.get(j).copied().is_some_and(|c| c == b'"' || c == b'\'') {
            j += 1;
        }
        let v0 = j;
        while b.get(j).copied().is_some_and(word) {
            j += 1;
        }
        if let Some(v) = text.get(v0..j).filter(|v| !v.is_empty())
            && !out.iter().any(|o| o == v)
        {
            out.push(v.to_owned());
        }
    }
    out
}

/// Registers what this connection holds secret with its redactor: env values under
/// secret-looking names, values of secret flags in the prefix, and the contents of key
/// files (prefix key flags and env values that are absolute paths to small files).
fn learn_secrets(conn: &Conn, r: &redact::Redactor) {
    for (k, v) in &conn.env {
        let up = k.to_ascii_uppercase();
        if ["TOKEN", "SECRET", "KEY", "PASS", "CREDENTIAL"]
            .iter()
            .any(|w| up.contains(w))
        {
            r.register(v);
        }
        if Path::new(v).is_absolute() {
            learn_file(Path::new(v), r);
        }
    }
    let key_flags: &[&str] = if conn.kind == Kind::Ssh {
        &["-i", "--private-key", "--key-file", "--client-key"]
    } else {
        &["--private-key", "--key-file", "--client-key"]
    };
    let value_flags = ["--token", "--password"];
    let mut words = conn.prefix.iter().peekable();
    while let Some(w) = words.next() {
        if let Some((f, v)) = w.split_once('=') {
            if key_flags.contains(&f) {
                learn_file(Path::new(v), r);
            } else if value_flags.contains(&f) {
                r.register(v);
            }
        } else if key_flags.contains(&w.as_str()) {
            if let Some(v) = words.next() {
                learn_file(Path::new(v), r);
            }
        } else if value_flags.contains(&w.as_str())
            && let Some(v) = words.next()
        {
            r.register(v);
        }
    }
}

/// A key file's whole contents, each line of 16 characters or more, and each such value
/// after a `key:` or `key=` inside it (a kubeconfig's token), as redactor values.
fn learn_file(p: &Path, r: &redact::Redactor) {
    let small = std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() <= KEY_FILE_MAX);
    if !small {
        return;
    }
    let Ok(text) = std::fs::read_to_string(p) else {
        return;
    };
    r.register(text.trim());
    for line in text.lines() {
        let line = line.trim();
        if line.len() >= 16 {
            r.register(line);
        }
        if let Some((_, v)) = line.split_once([':', '=']) {
            let v = v.trim().trim_matches(['"', '\'']);
            if v.len() >= 16 {
                r.register(v);
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(200).collect()
}
