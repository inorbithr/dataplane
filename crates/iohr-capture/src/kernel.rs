//! Kernel version parsing (from `/proc/sys/kernel/osrelease`) and the feature thresholds
//! capture depends on.

use std::fmt;

/// A kernel version as `major.minor.patch`; distribution suffixes are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub(crate) struct Version {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) patch: u32,
}

impl Version {
    pub(crate) const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses `5.15.0-91-generic`, `6.8.0`, `6.6.17+`, `4.19.0-cloud-amd64` and the like.
    pub(crate) fn parse(release: &str) -> Option<Self> {
        let mut parts = release.trim().splitn(3, '.');
        let major = leading_number(parts.next()?)?;
        let minor = leading_number(parts.next()?)?;
        let patch = parts.next().and_then(leading_number).unwrap_or(0);
        Some(Self::new(major, minor, patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn leading_number(s: &str) -> Option<u32> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s[..end].parse().ok()
}

/// Oldest kernel capture runs on: `CAP_BPF` and `CAP_PERFMON`, BPF ring buffers, BTF (5.8).
pub(crate) const MINIMUM: Version = Version::new(5, 8, 0);
/// Locked memory is charged to the memory cgroup instead of `RLIMIT_MEMLOCK` from 5.11.
pub(crate) const MEMCG_ACCOUNTING: Version = Version::new(5, 11, 0);
/// TCX links (`bpf_link` based TC attachment) from 6.6.
pub(crate) const TCX: Version = Version::new(6, 6, 0);
/// From 6.5 the `bpf()` syscall checks privileges only when creating maps and loading
/// programs; before, every command (map reads too) needs `CAP_BPF` when
/// `kernel.unprivileged_bpf_disabled` is set.
pub(crate) const UNPRIVILEGED_MAP_ACCESS: Version = Version::new(6, 5, 0);

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn parses_distribution_releases() {
        assert_eq!(
            Version::parse("5.15.0-91-generic\n"),
            Some(Version::new(5, 15, 0))
        );
        assert_eq!(Version::parse("6.8.0"), Some(Version::new(6, 8, 0)));
        assert_eq!(Version::parse("6.6.17+"), Some(Version::new(6, 6, 17)));
        assert_eq!(
            Version::parse("4.19.0-cloud-amd64"),
            Some(Version::new(4, 19, 0))
        );
        assert_eq!(Version::parse("6.14"), Some(Version::new(6, 14, 0)));
        assert_eq!(Version::parse("6.1.0-rc3"), Some(Version::new(6, 1, 0)));
        assert_eq!(Version::parse("garbage"), None);
    }

    #[test]
    fn orders() {
        assert!(Version::new(5, 15, 0) < super::TCX);
        assert!(Version::new(6, 6, 0) >= super::TCX);
        assert!(Version::new(5, 7, 19) < super::MINIMUM);
    }
}
