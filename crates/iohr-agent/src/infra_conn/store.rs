//! Saved plans: each a directory under the agent's state, named by its hash, holding the
//! plan record and a snapshot of every input file. An apply runs from the snapshot, so a
//! file edited between plan and apply changes nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::Kind;
use super::verbs::Arg;

/// `sha256:` and the hex digest of `bytes`.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("sha256:");
    for b in Sha256::digest(bytes) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A plan's record. For tofu the plan hash is the plan file's sha256; for the others it
/// is the sha256 of this record's canonical JSON with `hash` empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The connection kind.
    pub kind: Kind,
    /// The plan verb that made it.
    pub verb: String,
    /// The argv the apply will run, in table form.
    pub apply: Vec<Arg>,
    /// Snapshot files: relative path to sha256.
    pub files: BTreeMap<String, String>,
    /// sha256 of the redacted plan output.
    pub output_sha256: String,
    /// The plan hash; empty while it is being computed.
    pub hash: String,
}

impl Plan {
    /// The hash of a record: its canonical JSON with the hash field empty.
    ///
    /// # Panics
    /// Never: the record is plain data.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut c = self.clone();
        c.hash = String::new();
        sha256_of(&serde_json::to_vec(&c).unwrap_or_default())
    }
}

/// The plan store of one connection.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// A directory name for a hash: its hex part only.
fn dir_name(hash: &str) -> Option<&str> {
    let h = hash.strip_prefix("sha256:")?;
    (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())).then_some(h)
}

impl Store {
    /// A store rooted at `root`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// A fresh scratch directory for a plan in progress.
    ///
    /// # Errors
    /// The directory cannot be made.
    pub fn scratch(&self) -> std::io::Result<PathBuf> {
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).map_err(std::io::Error::other)?;
        let name = id.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let p = self.root.join(format!(".work-{name}"));
        make_private(&p.join("files"))?;
        Ok(p)
    }

    /// Moves a finished scratch directory to its hash's name and writes the record.
    ///
    /// # Errors
    /// The record cannot be written or the directory moved.
    pub fn commit(&self, scratch: &Path, plan: &Plan) -> std::io::Result<PathBuf> {
        let name = dir_name(&plan.hash).ok_or_else(|| std::io::Error::other("bad plan hash"))?;
        std::fs::write(scratch.join("plan.json"), serde_json::to_vec_pretty(plan)?)?;
        let dest = self.root.join(name);
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        std::fs::rename(scratch, &dest)?;
        Ok(dest)
    }

    /// The saved plan for `hash`, its directory, after checking that its files and its
    /// hash still match what was saved.
    ///
    /// # Errors
    /// No such plan, or what is on disk no longer matches its hash.
    pub fn load(&self, hash: &str) -> Result<(Plan, PathBuf), String> {
        let name = dir_name(hash).ok_or("the plan hash is not a sha256")?;
        let dir = self.root.join(name);
        let raw = std::fs::read(dir.join("plan.json"))
            .map_err(|_| "no saved plan has that hash".to_owned())?;
        let plan: Plan =
            serde_json::from_slice(&raw).map_err(|_| "the saved plan is unreadable".to_owned())?;
        if plan.hash != hash {
            return Err("the saved plan's hash differs from its name".into());
        }
        for (rel, want) in &plan.files {
            let got = std::fs::read(dir.join("files").join(rel))
                .map_err(|_| format!("snapshot {rel} is missing"))?;
            if &sha256_of(&got) != want {
                return Err(format!("snapshot {rel} changed since the plan"));
            }
        }
        if plan.kind == Kind::Tofu {
            let got = std::fs::read(dir.join("plan.tfplan"))
                .map_err(|_| "the plan file is missing".to_owned())?;
            if sha256_of(&got) != hash {
                return Err("the plan file changed since the plan".into());
            }
        } else if plan.compute_hash() != hash {
            return Err("the saved plan record changed since the plan".into());
        }
        Ok((plan, dir))
    }
}

fn make_private(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut cur = Some(p);
        for _ in 0..2 {
            if let Some(d) = cur {
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
                cur = d.parent();
            }
        }
    }
    Ok(())
}
