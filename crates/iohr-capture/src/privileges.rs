//! Dropping capabilities after the programs are attached (ADR 0002). Capabilities are per
//! thread on Linux, so this runs while the process has exactly one thread, before any
//! runtime starts; threads made later inherit the reduced sets.

use std::{fs, io};

use rustix::thread::{self, CapabilitySet, CapabilitySets};
use serde::Serialize;

/// What is left after the drop, read back from the kernel.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Remaining {
    /// Effective set, hex as in /proc/self/status.
    pub(crate) effective: String,
    /// Permitted set, hex.
    pub(crate) permitted: String,
    /// Names of the capabilities still effective (empty after a full drop).
    pub(crate) kept: Vec<&'static str>,
    /// Whether the bounding set was emptied too (needs `CAP_SETPCAP`, which a systemd unit
    /// with a narrow `CapabilityBoundingSet` does not have; that unit's bounding set is
    /// already just the three).
    pub(crate) bounding_set_cleared: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DropError {
    #[error("capabilities must be dropped while single-threaded, found {0} threads")]
    Threads(usize),
    #[error("capset failed: {0}")]
    Capset(io::Error),
    #[error("capabilities still effective after the drop: {0:#x}")]
    Leftover(u64),
}

/// The named capabilities capture uses.
pub(crate) const NAMED: [(CapabilitySet, &str); 3] = [
    (CapabilitySet::BPF, "CAP_BPF"),
    (CapabilitySet::PERFMON, "CAP_PERFMON"),
    (CapabilitySet::NET_ADMIN, "CAP_NET_ADMIN"),
];

/// Reduces effective and permitted to `keep` (usually empty), inheritable and ambient to
/// empty, the bounding set to `keep` where allowed, and sets `no_new_privs`.
pub(crate) fn drop_all_but(keep: CapabilitySet) -> Result<Remaining, DropError> {
    let threads = thread_count();
    if threads != 1 {
        return Err(DropError::Threads(threads));
    }
    let mut bounding_set_cleared = true;
    for bit in 0..64u32 {
        let cap = CapabilitySet::from_bits_retain(1u64 << bit);
        if keep.contains(cap) {
            continue;
        }
        match thread::remove_capability_from_bounding_set(cap) {
            Ok(()) => {}
            // Past the kernel's last capability.
            Err(e) if e == rustix::io::Errno::INVAL => break,
            Err(_) => bounding_set_cleared = false,
        }
    }
    // Ambient capabilities are dropped with permitted anyway; clear them explicitly.
    let _ = thread::clear_ambient_capability_set();
    let _ = thread::set_no_new_privs(true);
    thread::set_capabilities(
        None,
        CapabilitySets {
            effective: keep,
            permitted: keep,
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|e| DropError::Capset(e.into()))?;
    let now = thread::capabilities(None).map_err(|e| DropError::Capset(e.into()))?;
    let leftover = now.effective.difference(keep);
    if !leftover.is_empty() {
        return Err(DropError::Leftover(leftover.bits()));
    }
    Ok(Remaining {
        effective: format!("{:016x}", now.effective.bits()),
        permitted: format!("{:016x}", now.permitted.bits()),
        kept: NAMED
            .iter()
            .filter(|(c, _)| now.effective.contains(*c))
            .map(|(_, n)| *n)
            .collect(),
        bounding_set_cleared,
    })
}

fn thread_count() -> usize {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:").map(|v| v.trim().parse().ok()))
                .flatten()
        })
        .unwrap_or(0)
}
