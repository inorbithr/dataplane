//! The agent's inventory (RFC 0088.1): what this agent's policy admits, how much work it
//! takes, what it observes and which extensions run beside it, sent in the hello so the
//! platform sends only work the agent can run and can draw the fleet.
//!
//! Built from the local policy and the machine's `iohr-ext.lock` (the SDK's format); never
//! from a job, never an identity. Bounded: anything past the bounds is dropped and counted.
//! No addresses, no host name, no precise location: those stay off unless the policy says
//! otherwise elsewhere.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::checks::Surface;
use crate::policy::Policy;

/// The inventory format.
pub const FORMAT: u32 = 1;
/// Most extensions reported.
pub const MAX_EXTENSIONS: usize = 64;
/// Longest name, version or signer reported.
pub const MAX_FIELD: usize = 128;
/// Most privileges reported per extension.
pub const MAX_PRIVILEGES: usize = 16;
/// The largest lock file read.
const MAX_LOCK_BYTES: u64 = 1024 * 1024;
/// The lock's file name (the SDK's `iohr-ext.lock`).
pub const LOCK_FILE: &str = "iohr-ext.lock";

/// What the policy admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // one per `[work]` switch, as the policy names them
pub struct Work {
    /// `[work] checks`.
    pub checks: bool,
    /// `[work] load`.
    pub load: bool,
    /// `[work] faults`.
    pub faults: bool,
    /// `[work] host`.
    pub host: bool,
    /// `[work] capture`.
    pub capture: bool,
}

/// The policy's ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceilings {
    /// Jobs at once.
    pub max_concurrent_jobs: u32,
    /// Jobs per rolling minute.
    pub max_jobs_per_minute: u32,
    /// Longest job.
    pub max_job_ms: u64,
}

/// One installed extension, as its lock entry pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// `sha256:` and 64 lowercase hex: the image index it was installed from.
    pub digest: String,
    /// Who signed it.
    pub signer: String,
    /// The privileges the person confirmed for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privileges: Vec<String>,
}

/// The inventory sent in the hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// [`FORMAT`].
    pub format: u32,
    /// `linux`, `macos`, `windows`.
    pub os: String,
    /// `x86_64`, `aarch64`.
    pub arch: String,
    /// The work kinds the policy admits.
    pub work: Work,
    /// The check surfaces the policy admits.
    pub surfaces: Vec<String>,
    /// The policy's ceilings.
    pub ceilings: Ceilings,
    /// The observers it runs (`host` with `[work] host`).
    pub observers: Vec<String>,
    /// Extensions installed on this machine, from the lock.
    pub extensions: Vec<Extension>,
    /// Entries dropped for breaking a bound or a format rule; never their content.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Deserialize)]
struct LockWire {
    version: u32,
    #[serde(default, rename = "extension")]
    extensions: Vec<LockEntry>,
}

#[derive(Debug, Deserialize)]
struct LockEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    signer: String,
    #[serde(default)]
    privileges: Vec<String>,
}

/// The inventory for this policy and these extensions.
#[must_use]
pub fn build(policy: &Policy, extensions: (Vec<Extension>, u32)) -> Inventory {
    let surfaces = Surface::ALL
        .iter()
        .filter(|s| policy.surface_allowed(**s))
        .map(|s| s.as_str().to_owned())
        .collect();
    let mut observers = Vec::new();
    if policy.work.host {
        observers.push("host".to_owned());
    }
    Inventory {
        format: FORMAT,
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        work: Work {
            checks: policy.work.checks,
            load: policy.work.load,
            faults: policy.work.faults,
            host: policy.work.host,
            capture: policy.work.capture,
        },
        surfaces,
        ceilings: Ceilings {
            max_concurrent_jobs: policy.ceilings.max_concurrent_jobs,
            max_jobs_per_minute: policy.ceilings.max_jobs_per_minute,
            max_job_ms: policy.ceilings.max_job_ms,
        },
        observers,
        extensions: extensions.0,
        dropped: extensions.1,
    }
}

fn digest_ok(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn field_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_FIELD && !s.chars().any(char::is_control)
}

/// Reads a lock's text: the valid entries, and how many were dropped. A lock that isn't
/// one (unknown version, not TOML) yields nothing and counts as one drop.
#[must_use]
pub fn parse_lock(text: &str) -> (Vec<Extension>, u32) {
    let Ok(w) = toml::from_str::<LockWire>(text) else {
        return (Vec::new(), 1);
    };
    if w.version != 1 && w.version != 2 {
        return (Vec::new(), 1);
    }
    let mut out = Vec::new();
    let mut dropped = 0u32;
    for e in w.extensions {
        let ok = field_ok(&e.name)
            && field_ok(&e.version)
            && field_ok(&e.signer)
            && digest_ok(&e.digest)
            && e.privileges.len() <= MAX_PRIVILEGES
            && e.privileges.iter().all(|p| field_ok(p));
        if !ok || out.len() >= MAX_EXTENSIONS {
            dropped = dropped.saturating_add(1);
            continue;
        }
        out.push(Extension {
            name: e.name,
            version: e.version,
            digest: e.digest,
            signer: e.signer,
            privileges: e.privileges,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, dropped)
}

/// Reads the lock at `path`; a missing file is no extensions, not an error.
#[must_use]
pub fn read_lock(path: &Path) -> (Vec<Extension>, u32) {
    match std::fs::metadata(path) {
        Err(_) => (Vec::new(), 0),
        Ok(m) if m.len() > MAX_LOCK_BYTES => (Vec::new(), 1),
        Ok(_) => std::fs::read_to_string(path).map_or((Vec::new(), 1), |t| parse_lock(&t)),
    }
}

/// Where this machine's lock is: `extensions_lock` in agent.toml, else `IOHR_DATA_DIR`,
/// else, when this agent runs as an iohr extension, iohr's own data directory.
#[must_use]
pub fn lock_path(configured: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = configured {
        return Some(p.to_path_buf());
    }
    if let Some(d) = std::env::var_os("IOHR_DATA_DIR") {
        return Some(PathBuf::from(d).join("extensions").join(LOCK_FILE));
    }
    std::env::var_os(crate::extsock::SOCKET_ENV)?;
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let data = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/hr.InOrbit.iohr")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map_or_else(|| home.join(".local/share"), PathBuf::from)
            .join("iohr")
    };
    Some(data.join("extensions").join(LOCK_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_lock_is_read_bounded_and_sorted() {
        let text = format!(
            r#"
version = 2
[[extension]]
name = "capture"
version = "0.1.0-alpha.10"
digest = "{D}"
signer = "https://github.com/inorbithr/dataplane/.github/workflows/release.yml"
privileges = ["cap_bpf"]

[[extension]]
name = "agent"
version = "0.1.0"
digest = "{D}"
signer = "key:sha256:ab"

[[extension]]
name = "bad-digest"
version = "1"
digest = "md5:00"
signer = "x"

[[extension]]
name = "bad\u0007name"
version = "1"
digest = "{D}"
signer = "x"
"#
        );
        let (ext, dropped) = parse_lock(&text);
        assert_eq!(dropped, 2);
        assert_eq!(
            ext.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["agent", "capture"]
        );
        assert_eq!(ext[1].privileges, ["cap_bpf"]);
    }

    #[test]
    fn not_a_lock_is_one_drop_and_nothing_else() {
        assert_eq!(parse_lock("version = 9\n"), (Vec::new(), 1));
        assert_eq!(parse_lock("this is not toml ["), (Vec::new(), 1));
        assert_eq!(
            read_lock(Path::new("/nonexistent/iohr-ext.lock")),
            (Vec::new(), 0)
        );
    }

    #[test]
    fn too_many_extensions_are_counted_not_sent() {
        use std::fmt::Write as _;
        let mut text = String::from("version = 1\n");
        for i in 0..(MAX_EXTENSIONS + 3) {
            let _ = write!(
                text,
                "[[extension]]\nname = \"e{i:03}\"\nversion = \"1\"\ndigest = \"{D}\"\nsigner = \"s\"\n"
            );
        }
        let (ext, dropped) = parse_lock(&text);
        assert_eq!(ext.len(), MAX_EXTENSIONS);
        assert_eq!(dropped, 3);
    }

    #[test]
    fn the_inventory_follows_the_policy() {
        let policy = Policy::from_toml(
            "environment = \"prod\"\n[work]\nsurfaces = [\"http\", \"tcp\"]\nhost = true\n[ceilings]\nmax_concurrent_jobs = 2\n",
        )
        .unwrap();
        let inv = build(&policy, (Vec::new(), 0));
        assert!(inv.surfaces.contains(&"http".to_owned()));
        assert!(inv.surfaces.contains(&"tcp".to_owned()));
        assert!(!inv.surfaces.contains(&"grpc".to_owned()));
        assert_eq!(inv.observers, ["host"]);
        assert_eq!(inv.ceilings.max_concurrent_jobs, 2);
        assert!(!inv.work.load);
        let v = serde_json::to_value(&inv).unwrap();
        // No address, host name or location field exists to leak.
        for k in ["hostname", "ip", "mac", "address", "latitude", "longitude"] {
            assert!(v.get(k).is_none(), "{k}");
        }
        assert!(v.get("dropped").is_none(), "zero drops are left out");
    }
}
