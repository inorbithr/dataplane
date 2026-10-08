//! Reading `/sys` and `/proc` under a root: `/` on a host, a captured tree in tests. Every
//! read is bounded, nothing is written, and no program runs. A read that fails says why
//! (missing, denied), so an observer can report "not observed, needs privilege" instead
//! of guessing.

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The most bytes read from one file (`/proc/diskstats` on a large host is a few KiB;
/// `/proc/self/mountinfo` with many containers is the largest).
pub const MAX_FILE: u64 = 4 * 1024 * 1024;

/// Why a file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// It does not exist (the kernel does not expose it here).
    Missing,
    /// It exists but this process may not read it.
    Denied,
    /// Another error (an I/O error from a driver, say).
    Failed,
}

impl ReadError {
    /// A short reason for a "not observed" record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "not exposed by the kernel",
            Self::Denied => "permission denied",
            Self::Failed => "read failed",
        }
    }
}

impl From<&std::io::Error> for ReadError {
    fn from(e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Self::Missing,
            std::io::ErrorKind::PermissionDenied => Self::Denied,
            _ => Self::Failed,
        }
    }
}

/// The root the host is read under.
#[derive(Debug, Clone)]
pub struct Root {
    base: PathBuf,
}

impl Default for Root {
    fn default() -> Self {
        Self::host()
    }
}

impl Root {
    /// The running host (`/`).
    #[must_use]
    pub fn host() -> Self {
        Self {
            base: PathBuf::from("/"),
        }
    }

    /// A captured tree (tests, `--root`). The path is made absolute and canonical so
    /// links inside it resolve inside it.
    #[must_use]
    pub fn at(base: &Path) -> Self {
        Self {
            base: std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf()),
        }
    }

    /// Whether this is the running host.
    #[must_use]
    pub fn is_host(&self) -> bool {
        self.base == Path::new("/")
    }

    /// The real path of a host path (`/sys/class/hwmon`).
    #[must_use]
    pub fn path(&self, abs: &str) -> PathBuf {
        self.base.join(abs.trim_start_matches('/'))
    }

    /// A file's bytes, at most [`MAX_FILE`].
    ///
    /// # Errors
    /// Why it could not be read.
    pub fn bytes(&self, abs: &str) -> Result<Vec<u8>, ReadError> {
        let f = std::fs::File::open(self.path(abs)).map_err(|e| ReadError::from(&e))?;
        let mut out = Vec::new();
        f.take(MAX_FILE)
            .read_to_end(&mut out)
            .map_err(|e| ReadError::from(&e))?;
        Ok(out)
    }

    /// A file as trimmed text.
    ///
    /// # Errors
    /// Why it could not be read.
    pub fn text(&self, abs: &str) -> Result<String, ReadError> {
        let b = self.bytes(abs)?;
        Ok(String::from_utf8_lossy(&b).trim().to_owned())
    }

    /// A file as trimmed text, or `None`.
    #[must_use]
    pub fn read(&self, abs: &str) -> Option<String> {
        self.text(abs).ok().filter(|s| !s.is_empty())
    }

    /// A file holding one integer (decimal or `0x` hex).
    #[must_use]
    pub fn int(&self, abs: &str) -> Option<i64> {
        parse_int(&self.read(abs)?)
    }

    /// The names in a directory, sorted; empty when it is missing.
    #[must_use]
    pub fn list(&self, abs: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.path(abs))
            .map(|rd| {
                rd.filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| natural(a, b));
        out
    }

    /// Where a link (or a path through links) leads, as a host path
    /// (`/sys/devices/pci0000:40/...`); `None` when it does not resolve inside the root.
    #[must_use]
    pub fn resolve(&self, abs: &str) -> Option<String> {
        let real = std::fs::canonicalize(self.path(abs)).ok()?;
        let inside = real.strip_prefix(&self.base).ok()?;
        Some(format!("/{}", inside.to_string_lossy()))
    }

    /// The last component of a link's target, without resolving it (`driver` → `nvme`).
    #[must_use]
    pub fn link_name(&self, abs: &str) -> Option<String> {
        let t = std::fs::read_link(self.path(abs)).ok()?;
        t.file_name().map(|n| n.to_string_lossy().into_owned())
    }

    /// Whether a path exists.
    #[must_use]
    pub fn exists(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }
}

/// An integer as sysfs writes it: decimal, or hex with `0x`.
#[must_use]
pub fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Orders `temp2` before `temp10`, `hwmon9` before `hwmon10`.
#[must_use]
pub fn natural(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(s: &str) -> (&str, Option<u64>) {
        let i = s.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        (&s[..i], s[i..].parse().ok())
    }
    let (pa, na) = split(a);
    let (pb, nb) = split(b);
    pa.cmp(pb).then(na.cmp(&nb)).then(a.cmp(b))
}

/// The host's name, from the kernel.
#[must_use]
pub fn host_name() -> String {
    #[cfg(unix)]
    {
        let uts = rustix::system::uname();
        if let Ok(n) = uts.nodename().to_str()
            && !n.is_empty()
        {
            return n.split('.').next().unwrap_or(n).to_owned();
        }
    }
    "localhost".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ints_and_ordering() {
        assert_eq!(parse_int("0x1022"), Some(0x1022));
        assert_eq!(parse_int(" -40000\n"), Some(-40_000));
        assert_eq!(parse_int("x"), None);
        let mut v = vec!["temp10", "temp2", "temp1", "fan1"];
        v.sort_by(|a, b| natural(a, b));
        assert_eq!(v, ["fan1", "temp1", "temp2", "temp10"]);
    }

    #[test]
    fn a_root_reads_inside_itself() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/devices/x")).unwrap();
        std::fs::write(dir.path().join("sys/devices/x/name"), "chip\n").unwrap();
        std::fs::create_dir_all(dir.path().join("sys/class")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../devices/x", dir.path().join("sys/class/x")).unwrap();
        let r = Root::at(dir.path());
        assert!(!r.is_host());
        assert_eq!(r.read("/sys/devices/x/name").as_deref(), Some("chip"));
        assert_eq!(r.text("/sys/nope"), Err(ReadError::Missing));
        #[cfg(unix)]
        assert_eq!(r.resolve("/sys/class/x").as_deref(), Some("/sys/devices/x"));
    }
}
