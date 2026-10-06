//! Types shared by the iohr-capture eBPF programs (kernel side) and the daemon (user
//! space). Everything here is `#[repr(C)]`, `Copy` and free of pointers: the kernel writes
//! these bytes and user space reads them back through a map or the ring buffer.
#![no_std]

/// Index of the ingress slot in the counters map.
pub const INGRESS: u32 = 0;
/// Index of the egress slot in the counters map.
pub const EGRESS: u32 = 1;
/// Number of slots in the counters map (one per direction).
pub const DIRECTIONS: u32 = 2;

/// Name of the per-CPU counters map, as the daemon looks it up in the eBPF object.
pub const COUNTERS_MAP: &str = "IOHR_COUNTERS";
/// Per-CPU packets and bytes per direction and protocol class (`class_slot`).
pub const CLASSES_MAP: &str = "IOHR_CLASSES";
/// Per-CPU TCP flag counts per direction (`flag_slot`).
pub const FLAGS_MAP: &str = "IOHR_TCP_FLAGS";
/// LRU per-CPU hash of [`PortKey`] to [`PortCounters`].
pub const PORTS_MAP: &str = "IOHR_PORTS";
/// Per-CPU counters of the copy path ([`STAT_COPIED`] and friends).
pub const STATS_MAP: &str = "IOHR_STATS";
/// One [`Config`], written by user space before the programs are attached.
pub const CONFIG_MAP: &str = "IOHR_CONFIG";
/// The ring buffer of [`RecordHeader`] + bytes.
pub const EVENTS_MAP: &str = "IOHR_EVENTS";
/// LRU hash of flows (kernel only): how many payload packets were copied per flow.
pub const FLOWS_MAP: &str = "IOHR_FLOWS";
/// Name of the TC classifier attached to ingress.
pub const INGRESS_PROGRAM: &str = "iohr_ingress";
/// Name of the TC classifier attached to egress.
pub const EGRESS_PROGRAM: &str = "iohr_egress";

/// Most header bytes copied per packet (link layer to the end of the transport header).
pub const HEADER_BYTES: u32 = 128;
/// Most payload bytes copied per packet, and only for the first packets of a flow.
pub const PAYLOAD_BYTES: u32 = 512;
/// Size of the data area of one ring-buffer record.
pub const RECORD_DATA: usize = (HEADER_BYTES + PAYLOAD_BYTES) as usize;
/// Default ring buffer size (bytes, a power of two).
pub const DEFAULT_RING_BYTES: u32 = 4 * 1024 * 1024;
/// Entries in the per-port map (LRU: the least recently used port is evicted).
pub const PORT_ENTRIES: u32 = 1024;
/// Entries in the kernel flow map (LRU).
pub const FLOW_ENTRIES: u32 = 16_384;

/// Protocol classes counted per direction: TCP over IPv4.
pub const CLASS_TCP4: u32 = 0;
/// UDP over IPv4.
pub const CLASS_UDP4: u32 = 1;
/// ICMP.
pub const CLASS_ICMP4: u32 = 2;
/// Other IPv4.
pub const CLASS_OTHER4: u32 = 3;
/// TCP over IPv6.
pub const CLASS_TCP6: u32 = 4;
/// UDP over IPv6.
pub const CLASS_UDP6: u32 = 5;
/// `ICMPv6`.
pub const CLASS_ICMP6: u32 = 6;
/// Other IPv6 (including extension headers this version does not walk).
pub const CLASS_OTHER6: u32 = 7;
/// ARP and anything else that is not IP.
pub const CLASS_NON_IP: u32 = 8;
/// Slots per direction in the classes map (room to grow).
pub const CLASS_SLOTS: u32 = 16;
/// Names of the classes, by index.
pub const CLASS_NAMES: [&str; 9] = [
    "tcp4", "udp4", "icmp4", "other4", "tcp6", "udp6", "icmp6", "other6", "non_ip",
];

/// The classes map slot for a direction and class.
#[must_use]
pub const fn class_slot(direction: u32, class: u32) -> u32 {
    direction * CLASS_SLOTS + class
}

/// TCP segments with SYN and without ACK (connection attempts).
pub const FLAG_SYN: u32 = 0;
/// SYN with ACK (accepted attempts).
pub const FLAG_SYN_ACK: u32 = 1;
/// FIN.
pub const FLAG_FIN: u32 = 2;
/// RST.
pub const FLAG_RST: u32 = 3;
/// Slots per direction in the flags map.
pub const FLAG_SLOTS: u32 = 8;
/// Names of the flags, by index.
pub const FLAG_NAMES: [&str; 4] = ["syn", "syn_ack", "fin", "rst"];

/// The flags map slot for a direction and flag.
#[must_use]
pub const fn flag_slot(direction: u32, flag: u32) -> u32 {
    direction * FLAG_SLOTS + flag
}

/// Records written to the ring buffer.
pub const STAT_COPIED: u32 = 0;
/// Of those, records that carry payload bytes.
pub const STAT_PAYLOAD: u32 = 1;
/// Copies skipped by the per-CPU token bucket.
pub const STAT_RATE_LIMITED: u32 = 2;
/// Copies lost because the ring buffer had no room (reserve failed).
pub const STAT_RINGBUF_FULL: u32 = 3;
/// Packets too short or malformed to read the headers of.
pub const STAT_SHORT: u32 = 4;
/// Slots in the stats map.
pub const STATS: u32 = 8;

/// `Config::flags`: copy header records (layer 1).
pub const CONFIG_HEADERS: u32 = 1;
/// `Config::flags`: copy payload prefixes of a flow's first packets (layer 2).
pub const CONFIG_PROTOCOLS: u32 = 2;

/// `RecordHeader::kind`: the record carries payload bytes after the headers.
pub const KIND_PAYLOAD: u8 = 1;
/// `RecordHeader::kind`: a TCP SYN, FIN or RST (flow start or end), headers only.
pub const KIND_LIFECYCLE: u8 = 2;

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

/// Key of the per-port map: the service port of a flow (the lower of its two ports),
/// the IP protocol and the direction.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PortKey {
    /// The lower of source and destination port.
    pub port: u16,
    /// IP protocol number (6 TCP, 17 UDP).
    pub proto: u8,
    /// [`INGRESS`] or [`EGRESS`].
    pub direction: u8,
}

/// What the per-port map counts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounters {
    /// Socket buffers.
    pub packets: u64,
    /// Bytes.
    pub bytes: u64,
    /// TCP SYN without ACK.
    pub syn: u64,
    /// TCP RST.
    pub rst: u64,
}

impl PortCounters {
    /// Adds another set, saturating.
    #[must_use]
    pub const fn plus(self, o: Self) -> Self {
        Self {
            packets: self.packets.saturating_add(o.packets),
            bytes: self.bytes.saturating_add(o.bytes),
            syn: self.syn.saturating_add(o.syn),
            rst: self.rst.saturating_add(o.rst),
        }
    }
}

/// Settings user space writes before attaching.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Token bucket: nanoseconds one copy costs (`1e9 / copies per second`); 0 = no limit.
    pub interval_ns: u64,
    /// Token bucket: how far ahead of now the bucket may run (`burst * interval_ns`).
    pub burst_ns: u64,
    /// Link-layer header length: 14 on Ethernet (and loopback), 0 on L3 devices.
    pub l2_len: u32,
    /// Payload-carrying packets per flow whose payload prefix is copied.
    pub first_packets: u32,
    /// [`CONFIG_HEADERS`] | [`CONFIG_PROTOCOLS`].
    pub flags: u32,
    /// Padding, zero.
    pub reserved: u32,
}

/// Flow key in the kernel's flow map; `local` is this host's end in both directions, so
/// both directions of a flow share one entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowKey {
    /// Local address (IPv4 in the first four bytes).
    pub local: [u8; 16],
    /// Remote address.
    pub remote: [u8; 16],
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// IP protocol number.
    pub proto: u8,
    /// 4 or 6.
    pub family: u8,
    /// Padding, zero.
    pub reserved: [u8; 2],
}

/// The fixed head of a ring-buffer record; the packet bytes follow (see [`Record`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordHeader {
    /// `bpf_ktime_get_ns()` when the packet passed.
    pub ts_ns: u64,
    /// `skb->len`.
    pub skb_len: u32,
    /// How many bytes of `data` are valid.
    pub cap_len: u16,
    /// [`INGRESS`] or [`EGRESS`].
    pub direction: u8,
    /// [`KIND_PAYLOAD`] | [`KIND_LIFECYCLE`].
    pub kind: u8,
    /// `EtherType` of the packet, host order (0x0800 IPv4, 0x86dd IPv6).
    pub ethertype: u16,
    /// Link-layer header length at the start of `data`.
    pub l2_len: u8,
    /// Padding, zero.
    pub reserved: [u8; 5],
}

/// Size of [`RecordHeader`] in bytes.
pub const RECORD_HEADER_BYTES: usize = 24;

/// One ring-buffer record: a header and up to [`RECORD_DATA`] packet bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Record {
    /// The header.
    pub header: RecordHeader,
    /// The first `header.cap_len` bytes of the packet, from the link-layer header on.
    pub data: [u8; RECORD_DATA],
}

// SAFETY (all four): `#[repr(C)]`, `Copy`, no padding (sizes pinned in the tests below)
// and every bit pattern is a valid value, which is what `aya::Pod` requires. This is the
// narrow exception to the workspace's `unsafe` ban recorded in ADR 0002.
#[cfg(all(feature = "user", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe impl aya::Pod for Counters {}
#[cfg(all(feature = "user", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe impl aya::Pod for PortKey {}
#[cfg(all(feature = "user", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe impl aya::Pod for PortCounters {}
#[cfg(all(feature = "user", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe impl aya::Pod for Config {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn no_padding() {
        assert_eq!(size_of::<Counters>(), 16);
        assert_eq!(size_of::<PortKey>(), 4);
        assert_eq!(size_of::<PortCounters>(), 32);
        assert_eq!(size_of::<Config>(), 32);
        assert_eq!(size_of::<FlowKey>(), 40);
        assert_eq!(size_of::<RecordHeader>(), RECORD_HEADER_BYTES);
        assert_eq!(size_of::<Record>(), RECORD_HEADER_BYTES + RECORD_DATA);
    }

    #[test]
    fn slots() {
        assert_eq!(class_slot(EGRESS, CLASS_NON_IP), 24);
        assert!(CLASS_NAMES.len() <= CLASS_SLOTS as usize);
        assert_eq!(flag_slot(EGRESS, FLAG_RST), 11);
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
