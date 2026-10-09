//! Agent extensions (RFC 0073.1): every area of the agent and its local console is an
//! extension with one manifest, and nothing runs unless three things admit it:
//!
//! 1. **the licence** entitles it (no licence system ships yet: the built-in Free licence
//!    covers InOrbit's core areas, and the console says what the others need);
//! 2. **the machine's policy** allows it: `[extensions] allow` (default `inorbit/*`) and the
//!    `[work]` kinds its manifest needs;
//! 3. **the agent's lock** lists it: `<state_dir>/extensions.lock`, written on first start
//!    with InOrbit's core areas and changed by an admin on the console's Extensions page,
//!    each entry with who installed it and when.
//!
//! The built-ins are code inside the signed agent binary (`delivery: builtin`), and the
//! console bundle is one too (`delivery: web`, flavour `bundle`): it used to be wired
//! straight into the admin listener, and now it runs only when its three say yes.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy::Policy;

/// The lock file, in the state directory.
pub const LOCK_FILE: &str = "extensions.lock";

/// What an extension reads, writes and may send up.
#[derive(Debug, Clone, Serialize)]
pub struct Data {
    pub reads: &'static [&'static str],
    pub writes: &'static [&'static str],
    /// Message kinds it may send to InOrbit, each a ledger rule.
    pub leaves: &'static [&'static str],
}

/// An extension's manifest (RFC 0073.1, the fields the agent uses).
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub kind: &'static str,
    /// `builtin`, `web`, `program`, `wasm`.
    pub delivery: &'static str,
    pub version: &'static str,
    /// The licence feature that grants it.
    pub entitlement: &'static str,
    /// Where it runs and shows.
    #[serde(rename = "where")]
    pub where_: &'static [&'static str],
    /// The `[work]` kinds it needs from the policy.
    pub policy: &'static [&'static str],
    pub data: Data,
    /// Linux capabilities it needs (RFC 0061).
    pub privileges: &'static [&'static str],
    /// The console routes it brings.
    pub routes: &'static [&'static str],
    /// Roles that read and change it.
    pub permissions: Permissions,
    /// The agent cannot run without it.
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Permissions {
    pub read: &'static [&'static str],
    pub write: &'static [&'static str],
}

const ALL: &[&str] = &["viewer", "member", "admin", "owner"];
const ADMINS: &[&str] = &["admin", "owner"];
const MEMBERS: &[&str] = &["member", "admin", "owner"];
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// InOrbit's built-ins, in the order the console lists them.
#[must_use]
#[allow(clippy::too_many_lines)] // six manifests, one after another
pub fn builtins() -> Vec<Manifest> {
    vec![
        Manifest {
            id: "inorbit/agent-core",
            name: "Agent core",
            summary: "Identity, the session with InOrbit, the policy and the egress ledger: what everything else runs on.",
            kind: "agent-plugin",
            delivery: "builtin",
            version: VERSION,
            entitlement: "agent.core",
            where_: &["agent", "console"],
            policy: &[],
            data: Data {
                reads: &["agent.toml", "policy.toml"],
                writes: &["ledger/", "audit/"],
                leaves: &["hello", "heartbeat"],
            },
            privileges: &[],
            routes: &["/", "/egress/", "/settings/"],
            permissions: Permissions {
                read: ALL,
                write: ADMINS,
            },
            required: true,
        },
        Manifest {
            id: "inorbit/console",
            name: "Local console",
            summary: "This console: InOrbit's own pages, served by the agent on this machine and reading only from it.",
            kind: "web",
            delivery: "web",
            version: VERSION,
            entitlement: "console.local",
            where_: &["console"],
            policy: &[],
            data: Data {
                reads: &["the local API"],
                writes: &[],
                leaves: &[],
            },
            privileges: &[],
            routes: &["/console/"],
            permissions: Permissions {
                read: ALL,
                write: ADMINS,
            },
            required: false,
        },
        Manifest {
            id: "inorbit/monitors",
            name: "Monitors",
            summary: "The checks declared in checks.toml, their runs and their health, kept on this machine.",
            kind: "agent-plugin",
            delivery: "builtin",
            version: VERSION,
            entitlement: "monitors.local",
            where_: &["agent", "console"],
            policy: &["checks"],
            data: Data {
                reads: &["checks.toml", "store: runs"],
                writes: &["store: runs"],
                leaves: &["result (verdict, timings, status code, class of error)"],
            },
            privileges: &[],
            routes: &["/monitors/", "/monitor/"],
            permissions: Permissions {
                read: ALL,
                write: MEMBERS,
            },
            required: false,
        },
        Manifest {
            id: "inorbit/host",
            name: "Host observers",
            summary: "Sensors, disks, PCI devices, pressure and boots, read-only from /sys and /proc.",
            kind: "agent-plugin",
            delivery: "builtin",
            version: VERSION,
            entitlement: "host.local",
            where_: &["agent", "console"],
            policy: &["host"],
            data: Data {
                reads: &["/sys (read-only)", "/proc (read-only)"],
                writes: &["store: host readings"],
                leaves: &["host summary in the heartbeat, only with [share] host = true"],
            },
            privileges: &[],
            routes: &["/host/"],
            permissions: Permissions {
                read: ALL,
                write: ADMINS,
            },
            required: false,
        },
        Manifest {
            id: "inorbit/capture",
            name: "Traffic capture",
            summary: "How the services on this host talk to each other, seen from the kernel. Packet contents never leave the host.",
            kind: "agent-plugin",
            delivery: "program",
            version: VERSION,
            entitlement: "capture",
            where_: &["agent"],
            policy: &["capture"],
            data: Data {
                reads: &["network traffic on this host (headers and timings)"],
                writes: &["the companion's aggregates (in memory)"],
                leaves: &["capture:* capabilities in the hello"],
            },
            privileges: &["CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN"],
            routes: &[],
            permissions: Permissions {
                read: ALL,
                write: ADMINS,
            },
            required: false,
        },
        Manifest {
            id: "inorbit/verify",
            name: "Chaos and verify",
            summary: "Load, faults and before-and-after verification of a change, with an evidence record (RFC 0047.2, PRD 0008).",
            kind: "agent-plugin",
            delivery: "program",
            version: VERSION,
            entitlement: "verify",
            where_: &["agent", "console"],
            policy: &["load", "faults"],
            data: Data {
                reads: &["checks.toml", "scenarios"],
                writes: &["store: runs, verdicts, evidence records"],
                leaves: &["verdicts (pass, fail, per claim)"],
            },
            privileges: &[],
            routes: &["/verify/"],
            permissions: Permissions {
                read: ALL,
                write: ADMINS,
            },
            required: false,
        },
    ]
}

/// The built-in Free licence's features (RFC 0100.4 1.4: built-in Free when none).
const FREE: &[&str] = &[
    "agent.core",
    "console.local",
    "monitors.local",
    "host.local",
];
/// What the lock holds on first start.
const FIRST_START: &[&str] = &[
    "inorbit/agent-core",
    "inorbit/console",
    "inorbit/monitors",
    "inorbit/host",
];

/// One installed extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockEntry {
    pub id: String,
    pub version: String,
    /// `agent (first start)`, or the person on the console.
    pub installed_by: String,
    pub at: String,
}

/// `<state_dir>/extensions.lock`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lock {
    pub extensions: Vec<LockEntry>,
}

impl Lock {
    /// The lock's path.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(LOCK_FILE)
    }

    /// Reads the lock, writing the first-start one when there is none.
    ///
    /// # Errors
    /// The file cannot be read, parsed or written.
    pub fn load_or_init(state_dir: &Path) -> Result<Self> {
        let p = Self::path(state_dir);
        match std::fs::read_to_string(&p) {
            Ok(t) => {
                serde_json::from_str(&t).map_err(|e| Error::Config(format!("{}: {e}", p.display())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let at = crate::enroll::now_rfc3339();
                let lock = Self {
                    extensions: FIRST_START
                        .iter()
                        .map(|id| LockEntry {
                            id: (*id).into(),
                            version: VERSION.into(),
                            installed_by: "agent (first start)".into(),
                            at: at.clone(),
                        })
                        .collect(),
                };
                lock.save(state_dir)?;
                Ok(lock)
            }
            Err(e) => Err(Error::io(&p, e)),
        }
    }

    /// Writes the lock atomically, 0600.
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        let p = Self::path(state_dir);
        let tmp = state_dir.join(".extensions.lock.iohr-new");
        let text = serde_json::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(&tmp, text).map_err(|e| Error::io(&tmp, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &p).map_err(|e| Error::io(&p, e))
    }

    #[must_use]
    pub fn has(&self, id: &str) -> bool {
        self.extensions.iter().any(|e| e.id == id)
    }
}

/// One of the three yeses, with why not.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Yes {
    pub ok: bool,
    pub why: String,
}

/// An extension's state on this machine.
#[derive(Debug, Clone, Serialize)]
pub struct State {
    pub licence: Yes,
    pub policy: Yes,
    pub lock: Yes,
    /// All three.
    pub running: bool,
}

/// Judges one extension against the licence, the policy and the lock.
#[must_use]
pub fn state(m: &Manifest, policy: &Policy, lock: &Lock) -> State {
    let licence = if FREE.contains(&m.entitlement) {
        Yes {
            ok: true,
            why: "included in the built-in Free licence".into(),
        }
    } else {
        Yes {
            ok: false,
            why: format!(
                "needs a licence with {} (licences are not installed on agents yet, RFC 0061.1)",
                m.entitlement
            ),
        }
    };
    let ext = policy.extensions();
    let missing: Vec<&str> = m
        .policy
        .iter()
        .copied()
        .filter(|k| !work_enabled(policy, k))
        .collect();
    let policy_yes = if !ext.allows(m.id) {
        Yes {
            ok: false,
            why: format!("[extensions] allow does not list {}", m.id),
        }
    } else if m.policy.contains(&"load") || m.policy.contains(&"faults") {
        Yes {
            ok: false,
            why: "needs [work] load or faults, which this agent version refuses outright".into(),
        }
    } else if !missing.is_empty() {
        Yes {
            ok: false,
            why: format!(
                "needs {} in [work]",
                missing
                    .iter()
                    .map(|k| format!("{k} = true"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    } else {
        Yes {
            ok: true,
            why: "allowed by policy.toml".into(),
        }
    };
    let lock_yes = lock.extensions.iter().find(|e| e.id == m.id).map_or_else(
        || Yes {
            ok: false,
            why: "not installed on this agent".into(),
        },
        |e| Yes {
            ok: true,
            why: format!("installed by {} on {}", e.installed_by, e.at),
        },
    );
    let running = licence.ok && policy_yes.ok && lock_yes.ok;
    State {
        licence,
        policy: policy_yes,
        lock: lock_yes,
        running,
    }
}

fn work_enabled(p: &Policy, kind: &str) -> bool {
    match kind {
        "checks" => p.work.checks,
        "host" => p.work.host,
        "capture" => p.work.capture,
        "load" => p.work.load,
        "faults" => p.work.faults,
        _ => false,
    }
}

/// Whether `id` runs here.
#[must_use]
pub fn running(id: &str, policy: &Policy, lock: &Lock) -> bool {
    builtins()
        .iter()
        .find(|m| m.id == id)
        .is_some_and(|m| state(m, policy, lock).running)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(extra: &str) -> Policy {
        Policy::from_toml(&format!("environment = \"staging\"\n{extra}")).unwrap()
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn three_yeses_or_nothing_runs() {
        let d = tempfile::tempdir().unwrap();
        let lock = Lock::load_or_init(d.path()).unwrap();
        assert!(lock.has("inorbit/monitors"));
        let p = policy("");
        assert!(running("inorbit/monitors", &p, &lock));
        // The policy says no.
        let p = policy("[extensions]\nallow = [\"inorbit/agent-core\"]\n");
        let s = state(&builtins()[2], &p, &lock);
        assert!(!s.running && !s.policy.ok && s.licence.ok && s.lock.ok);
        // Not in the lock.
        let mut l = lock.clone();
        l.extensions.retain(|e| e.id != "inorbit/monitors");
        assert!(!running("inorbit/monitors", &policy(""), &l));
        // Host needs [work] host.
        assert!(!running("inorbit/host", &policy(""), &lock));
        assert!(running(
            "inorbit/host",
            &policy("[work]\nhost = true\n"),
            &lock
        ));
        // Verify needs load or faults, refused by this version, and a licence.
        let v = state(&builtins()[5], &policy(""), &lock);
        assert!(!v.running && !v.licence.ok && !v.policy.ok);
    }

    #[test]
    fn the_lock_survives_and_is_private() {
        let d = tempfile::tempdir().unwrap();
        let mut lock = Lock::load_or_init(d.path()).unwrap();
        lock.extensions.retain(|e| e.id != "inorbit/host");
        lock.save(d.path()).unwrap();
        assert!(!Lock::load_or_init(d.path()).unwrap().has("inorbit/host"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(Lock::path(d.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
