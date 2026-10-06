//! Types shared by the iohr-capture eBPF programs (kernel side) and the daemon (user
//! space). Everything here is `#[repr(C)]`, `Copy` and free of pointers: the kernel writes
//! these bytes and user space reads them back through a map.
#![no_std]

/// Index of the ingress slot in the counters map.
pub const INGRESS: u32 = 0;
/// Index of the egress slot in the counters map.
pub const EGRESS: u32 = 1;
/// Number of slots in the counters map (one per direction).
pub const DIRECTIONS: u32 = 2;

/// Name of the per-CPU counters map, as the daemon looks it up in the eBPF object.
pub const COUNTERS_MAP: &str = "IOHR_COUNTERS";
/// Name of the TC classifier attached to ingress.
pub const INGRESS_PROGRAM: &str = "iohr_ingress";
/// Name of the TC classifier attached to egress.
pub const EGRESS_PROGRAM: &str = "iohr_egress";

/// Packets and bytes seen in one direction on one CPU.
///
/// A packet here is one socket buffer as TC sees it. With GRO or TSO one socket buffer can
/// carry several packets as they were on the wire, so these counts are never presented as
/// wire packets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Socket buffers seen.
    pub packets: u64,
    /// Bytes in those socket buffers, from the link-layer header on (`skb->len`).
    pub bytes: u64,
}

impl Counters {
    /// Adds another set of counters, saturating.
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self {
            packets: self.packets.saturating_add(other.packets),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }
}

// SAFETY: `Counters` is `#[repr(C)]`, `Copy`, has no padding (two u64) and every bit
// pattern is a valid value, which is what `aya::Pod` requires. This is the narrow
// exception to the workspace's `unsafe` ban recorded in ADR 0002.
#[cfg(all(feature = "user", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe impl aya::Pod for Counters {}

#[cfg(test)]
mod tests {
    use super::Counters;

    #[test]
    fn no_padding() {
        assert_eq!(core::mem::size_of::<Counters>(), 16);
    }

    #[test]
    fn plus_saturates() {
        let a = Counters {
            packets: u64::MAX,
            bytes: 1,
        };
        let b = Counters {
            packets: 1,
            bytes: 2,
        };
        assert_eq!(
            a.plus(b),
            Counters {
                packets: u64::MAX,
                bytes: 3
            }
        );
    }
}
