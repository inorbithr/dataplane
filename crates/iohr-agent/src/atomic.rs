//! One way to replace a file: write a new, randomly named, owner-only file beside it,
//! flush it, then rename it over the old one. A reader sees the old file or the new one,
//! never half of one, and no one else can open the new text while it is being written.

use std::fs::{OpenOptions, Permissions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Replaces `path` with `bytes`, readable and writable by this user only (0600).
/// Creates the parent folder, owner-only (0700), when missing.
///
/// # Errors
/// The folder or file cannot be written.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    stage(path, bytes)?.commit()
}

/// Writes `bytes` beside `path` as [`write`] does, without replacing `path` yet:
/// [`Staged::commit`] renames it into place, and dropping it uncommitted removes it.
/// For a file that must be safe on disk before something else happens, and in place
/// only once that succeeded (the agent key during enrollment).
///
/// # Errors
/// The folder or file cannot be written.
pub fn stage(path: &Path, bytes: &[u8]) -> std::io::Result<Staged> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        crate::keys::create_private_dir(dir).map_err(|e| match e {
            crate::error::Error::Io { source, .. } => source,
            other => std::io::Error::other(other.to_string()),
        })?;
    }
    stage_with(path, bytes, None)
}

/// A new file written beside its destination, not yet renamed over it.
#[derive(Debug)]
#[must_use = "dropping it removes the file; call commit to put it in place"]
pub struct Staged {
    tmp: PathBuf,
    path: PathBuf,
}

impl Staged {
    /// Renames the new file over its destination.
    ///
    /// # Errors
    /// The rename fails; the new file is removed.
    pub fn commit(self) -> std::io::Result<()> {
        std::fs::rename(&self.tmp, &self.path)?;
        std::mem::forget(self);
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// Replaces `path` with `bytes`, keeping the permissions the file has now (0600 when it
/// does not exist yet).
///
/// # Errors
/// The file cannot be written.
pub fn write_keeping_mode(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mode = std::fs::metadata(path).ok().map(|m| m.permissions());
    replace(path, bytes, mode)
}

fn replace(path: &Path, bytes: &[u8], mode: Option<Permissions>) -> std::io::Result<()> {
    stage_with(path, bytes, mode)?.commit()
}

fn stage_with(path: &Path, bytes: &[u8], mode: Option<Permissions>) -> std::io::Result<Staged> {
    let staged = Staged {
        tmp: temp_beside(path),
        path: path.to_path_buf(),
    };
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    // A failure below drops `staged`, which removes whatever was written.
    let mut f = o.open(&staged.tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    if let Some(m) = mode {
        std::fs::set_permissions(&staged.tmp, m)?;
    }
    Ok(staged)
}

/// `.<name>.<random>.tmp` in the same folder, so the rename stays on one file system.
fn temp_beside(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = format!(".{name}.{}.tmp", crate::random::hex(8));
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from(&tmp), |d| d.join(&tmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many temporary files `temp_beside` names are left in `dir`.
    fn leftovers(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| Path::new(n).extension().is_some_and(|x| x == "tmp"))
            .count()
    }

    #[test]
    fn a_new_file_is_owner_only_and_leaves_no_temporary_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub").join("state.json");
        write(&p, b"one").unwrap();
        write(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(leftovers(p.parent().unwrap()), 0);
    }

    #[test]
    fn a_stale_temporary_file_does_not_block_or_leak_into_the_write() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("checks.toml");
        // A file at the old fixed temporary name, owned by someone else's mistake.
        std::fs::write(d.path().join(".checks.toml.iohr-new"), "planted").unwrap();
        write_keeping_mode(&p, b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert_eq!(
            std::fs::read_to_string(d.path().join(".checks.toml.iohr-new")).unwrap(),
            "planted"
        );
        assert_eq!(leftovers(d.path()), 0);
    }
}
