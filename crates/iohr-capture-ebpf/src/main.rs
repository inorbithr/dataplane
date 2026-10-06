//! TC classifiers for ingress and egress. They never drop, redirect or change a packet:
//! every path returns `TC_ACT_OK`.
//!
//! Per packet (phase 1):
//!
//! 1. count socket buffers and bytes per direction (phase 0) and per protocol class;
//! 2. for TCP and UDP, count per service port (the lower of the two ports) in an LRU
//!    per-CPU hash, and TCP SYN, SYN-ACK, FIN and RST per direction;
//! 3. copy bytes to the ring buffer, for user space to parse after it dropped its
//!    privileges:
//!    - the headers (at most 128 bytes) plus up to 512 payload bytes of the first
//!      payload-carrying packets of each flow (`Config::first_packets`), and
//!    - the headers only of TCP SYN, FIN and RST (a flow's start and end);
//!
//!    every copy passes a per-CPU token bucket first (`Config::interval_ns`/`burst_ns`);
//!    a copy over the rate, or one the ring buffer has no room for, is counted, never
//!    queued. With `CONFIG_TIMING` (layer 7) every TCP packet with payload has its
//!    payload prefix copied, not only a flow's first ones;
//! 4. with `CONFIG_PACKETS` (layer 3, phase 2), copy the whole packet, up to
//!    `Config::snaplen` bytes, to a second ring buffer, after a second token bucket
//!    (`pkt_interval_ns`/`pkt_burst_ns`). A reservation must be a constant size, so each
//!    packet goes into the smallest record of `PACKET_TIERS` that holds it.
#![no_std]
#![no_main]
// Small helpers are inlined on purpose: one flat program per hook keeps the verifier's
// job simple on old kernels.
#![allow(clippy::inline_always)]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::{Array, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use iohr_capture_common::{
    CLASS_ICMP4, CLASS_ICMP6, CLASS_NON_IP, CLASS_OTHER4, CLASS_OTHER6, CLASS_SLOTS, CLASS_TCP4,
    CLASS_TCP6, CLASS_UDP4, CLASS_UDP6, CONFIG_HEADERS, CONFIG_PACKETS, CONFIG_PROTOCOLS,
    CONFIG_TIMING, Config, Counters, DEFAULT_PACKETS_RING_BYTES, DEFAULT_RING_BYTES, DIRECTIONS,
    EGRESS, FLAG_FIN, FLAG_RST, FLAG_SLOTS, FLAG_SYN, FLAG_SYN_ACK, FLOW_ENTRIES, FlowKey,
    HEADER_BYTES, INGRESS, KIND_LIFECYCLE, KIND_PAYLOAD, PACKET_TIERS, PAYLOAD_BYTES, PORT_ENTRIES,
    PacketRecord, PortCounters, PortKey, RECORD_DATA, Record, STAT_COPIED, STAT_PAYLOAD,
    STAT_PKT_BYTES, STAT_PKT_COPIED, STAT_PKT_RATE_LIMITED, STAT_PKT_RINGBUF_FULL,
    STAT_RATE_LIMITED, STAT_RINGBUF_FULL, STAT_SHORT, STATS,
};

#[map(name = "IOHR_COUNTERS")]
static COUNTERS: PerCpuArray<Counters> = PerCpuArray::with_max_entries(DIRECTIONS, 0);
#[map(name = "IOHR_CLASSES")]
static CLASSES: PerCpuArray<Counters> = PerCpuArray::with_max_entries(DIRECTIONS * CLASS_SLOTS, 0);
#[map(name = "IOHR_TCP_FLAGS")]
static FLAGS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DIRECTIONS * FLAG_SLOTS, 0);
#[map(name = "IOHR_PORTS")]
static PORTS: LruPerCpuHashMap<PortKey, PortCounters> =
    LruPerCpuHashMap::with_max_entries(PORT_ENTRIES, 0);
#[map(name = "IOHR_FLOWS")]
static FLOWS: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(FLOW_ENTRIES, 0);
#[map(name = "IOHR_STATS")]
static STATS_MAP: PerCpuArray<u64> = PerCpuArray::with_max_entries(STATS, 0);
/// The token buckets' "theoretical arrival time" per CPU (GCRA): slot 0 for the copies of
/// layers 1, 2 and 7, slot 1 for whole packets (layer 3).
#[map(name = "IOHR_BUCKET")]
static BUCKET: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
const BUCKET_COPIES: u32 = 0;
const BUCKET_PACKETS: u32 = 1;
#[map(name = "IOHR_CONFIG")]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map(name = "IOHR_EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BYTES, 0);
/// Layer 3: whole packets. User space sets its size (a page when packets are off).
#[map(name = "IOHR_PACKETS")]
static PACKETS: RingBuf = RingBuf::with_byte_size(DEFAULT_PACKETS_RING_BYTES, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Attached to the interface's ingress hook. (`#[classifier]` hands the context by value.)
#[allow(clippy::needless_pass_by_value)]
#[classifier]
fn iohr_ingress(ctx: TcContext) -> i32 {
    handle(&ctx, INGRESS);
    pass()
}

/// Attached to the interface's egress hook.
#[allow(clippy::needless_pass_by_value)]
#[classifier]
fn iohr_egress(ctx: TcContext) -> i32 {
    handle(&ctx, EGRESS);
    pass()
}

#[inline(always)]
// The binding's integer type differs between aya-ebpf-bindings' per-arch files.
#[allow(clippy::cast_possible_wrap, clippy::unnecessary_cast)]
const fn pass() -> i32 {
    // TC_ACT_OK is 0: hand the packet on unchanged.
    TC_ACT_OK as i32
}

/// What the header walk found.
struct Parsed {
    class: u32,
    proto: u8,
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    tcp_flags: u8,
    /// Offset of the transport payload from the start of the packet.
    payload_off: u32,
    /// Transport payload length as the IP header states it.
    payload_len: u32,
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn handle(ctx: &TcContext, direction: u32) {
    let len = ctx.len();
    add_counters(&COUNTERS, direction, len);
    let Some(cfg) = CONFIG.get(0) else { return };
    let ethertype = u16::from_be(ctx.skb.protocol() as u16);
    if cfg.flags & CONFIG_PACKETS != 0 {
        copy_packet(ctx, direction, ethertype, cfg);
    }
    let Some(p) = parse(ctx, ethertype, cfg.l2_len) else {
        add_counters(&CLASSES, direction * CLASS_SLOTS + CLASS_NON_IP, len);
        return;
    };
    add_counters(&CLASSES, direction * CLASS_SLOTS + p.class, len);
    if p.proto != IPPROTO_TCP && p.proto != IPPROTO_UDP {
        return;
    }
    count_port(&p, direction, len);
    let mut lifecycle = false;
    if p.proto == IPPROTO_TCP {
        let f = p.tcp_flags;
        if f & TCP_SYN != 0 {
            let flag = if f & TCP_ACK == 0 {
                FLAG_SYN
            } else {
                FLAG_SYN_ACK
            };
            bump(&FLAGS, direction * FLAG_SLOTS + flag);
            lifecycle = true;
        }
        if f & TCP_FIN != 0 {
            bump(&FLAGS, direction * FLAG_SLOTS + FLAG_FIN);
            lifecycle = true;
        }
        if f & TCP_RST != 0 {
            bump(&FLAGS, direction * FLAG_SLOTS + FLAG_RST);
            lifecycle = true;
        }
    }
    // Layer 7 needs every request and response start of a TCP flow, not only its first
    // packets; the token bucket below bounds it like every other copy.
    let every = cfg.flags & CONFIG_TIMING != 0 && p.proto == IPPROTO_TCP;
    let payload = p.payload_len > 0
        && cfg.flags & CONFIG_PROTOCOLS != 0
        && (every || first_packets(&p, direction, cfg.first_packets));
    let headers = lifecycle && cfg.flags & CONFIG_HEADERS != 0;
    if !payload && !headers {
        return;
    }
    if !take_token(BUCKET_COPIES, cfg.interval_ns, cfg.burst_ns) {
        bump(&STATS_MAP, STAT_RATE_LIMITED);
        return;
    }
    let header_end = if p.payload_off > HEADER_BYTES {
        HEADER_BYTES
    } else {
        p.payload_off
    };
    let mut want = header_end;
    if payload {
        let extra = if p.payload_len > PAYLOAD_BYTES {
            PAYLOAD_BYTES
        } else {
            p.payload_len
        };
        want = header_end + extra;
    }
    let kind = if payload {
        KIND_PAYLOAD
    } else {
        KIND_LIFECYCLE
    };
    copy(ctx, direction, ethertype, cfg.l2_len, want, kind);
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn parse(ctx: &TcContext, ethertype: u16, l2_len: u32) -> Option<Parsed> {
    let l2 = (l2_len & 0xff) as usize;
    let mut p = Parsed {
        class: CLASS_NON_IP,
        proto: 0,
        family: 0,
        src: [0; 16],
        dst: [0; 16],
        sport: 0,
        dport: 0,
        tcp_flags: 0,
        payload_off: 0,
        payload_len: 0,
    };
    let l4: usize;
    let l4_len: u32;
    let mut first_fragment = true;
    if ethertype == ETH_P_IP {
        let vihl: u8 = ctx.load(l2).ok()?;
        let ihl = usize::from(vihl & 0x0f) * 4;
        if ihl < 20 {
            bump(&STATS_MAP, STAT_SHORT);
            return None;
        }
        let total = u16::from_be(ctx.load::<u16>(l2 + 2).ok()?);
        let frag = u16::from_be(ctx.load::<u16>(l2 + 6).ok()?);
        // Fragment offset zero: the first (or only) fragment, which holds the ports.
        first_fragment = frag.trailing_zeros() >= 13;
        p.proto = ctx.load(l2 + 9).ok()?;
        let src: [u8; 4] = ctx.load(l2 + 12).ok()?;
        let dst: [u8; 4] = ctx.load(l2 + 16).ok()?;
        p.src[0] = src[0];
        p.src[1] = src[1];
        p.src[2] = src[2];
        p.src[3] = src[3];
        p.dst[0] = dst[0];
        p.dst[1] = dst[1];
        p.dst[2] = dst[2];
        p.dst[3] = dst[3];
        p.family = 4;
        p.class = match p.proto {
            IPPROTO_TCP => CLASS_TCP4,
            IPPROTO_UDP => CLASS_UDP4,
            IPPROTO_ICMP => CLASS_ICMP4,
            _ => CLASS_OTHER4,
        };
        l4 = l2 + ihl;
        l4_len = u32::from(total).saturating_sub(ihl as u32);
    } else if ethertype == ETH_P_IPV6 {
        let plen = u16::from_be(ctx.load::<u16>(l2 + 4).ok()?);
        p.proto = ctx.load(l2 + 6).ok()?;
        p.src = ctx.load(l2 + 8).ok()?;
        p.dst = ctx.load(l2 + 24).ok()?;
        p.family = 6;
        p.class = match p.proto {
            IPPROTO_TCP => CLASS_TCP6,
            IPPROTO_UDP => CLASS_UDP6,
            IPPROTO_ICMPV6 => CLASS_ICMP6,
            _ => CLASS_OTHER6,
        };
        l4 = l2 + 40;
        l4_len = u32::from(plen);
    } else {
        return None;
    }
    if !first_fragment {
        // A later fragment has no transport header: count the class only.
        p.proto = 0;
        return Some(p);
    }
    if p.proto != IPPROTO_TCP && p.proto != IPPROTO_UDP {
        return Some(p);
    }
    let ports: [u8; 4] = ctx.load(l4).ok()?;
    p.sport = u16::from_be_bytes([ports[0], ports[1]]);
    p.dport = u16::from_be_bytes([ports[2], ports[3]]);
    let hdr_len: u32 = if p.proto == IPPROTO_TCP {
        let off_flags: [u8; 2] = ctx.load(l4 + 12).ok()?;
        p.tcp_flags = off_flags[1];
        u32::from(off_flags[0] >> 4) * 4
    } else {
        8
    };
    // A TCP header is at least 20 bytes (data offset 5); less is malformed.
    if hdr_len < 8 || (p.proto == IPPROTO_TCP && hdr_len < 20) {
        bump(&STATS_MAP, STAT_SHORT);
        return None;
    }
    p.payload_off = l4 as u32 + hdr_len;
    p.payload_len = l4_len.saturating_sub(hdr_len);
    Some(p)
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn count_port(p: &Parsed, direction: u32, len: u32) {
    let port = if p.sport == 0 {
        p.dport
    } else if p.dport == 0 || p.sport < p.dport {
        p.sport
    } else {
        p.dport
    };
    let key = PortKey {
        port,
        proto: p.proto,
        direction: direction as u8,
    };
    let syn = u64::from(p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & TCP_ACK == 0);
    let rst = u64::from(p.tcp_flags & TCP_RST != 0);
    if let Some(slot) = PORTS.get_ptr_mut(key) {
        // SAFETY: a successful lookup in a per-CPU hash returns this CPU's own value slot,
        // non-null and aligned; TC programs do not migrate between CPUs while they run.
        unsafe {
            (*slot).packets = (*slot).packets.wrapping_add(1);
            (*slot).bytes = (*slot).bytes.wrapping_add(u64::from(len));
            (*slot).syn = (*slot).syn.wrapping_add(syn);
            (*slot).rst = (*slot).rst.wrapping_add(rst);
        }
    } else {
        let value = PortCounters {
            packets: 1,
            bytes: u64::from(len),
            syn,
            rst,
        };
        // LRU: a full map evicts its least recently used port instead of failing.
        let _ = PORTS.insert(key, value, 0);
    }
}

/// True while this flow has had fewer than `limit` payload packets copied; counts this one.
#[inline(always)]
fn first_packets(p: &Parsed, direction: u32, limit: u32) -> bool {
    if limit == 0 {
        return false;
    }
    let key = if direction == INGRESS {
        FlowKey {
            local: p.dst,
            remote: p.src,
            local_port: p.dport,
            remote_port: p.sport,
            proto: p.proto,
            family: p.family,
            reserved: [0; 2],
        }
    } else {
        FlowKey {
            local: p.src,
            remote: p.dst,
            local_port: p.sport,
            remote_port: p.dport,
            proto: p.proto,
            family: p.family,
            reserved: [0; 2],
        }
    };
    if let Some(seen) = FLOWS.get_ptr_mut(key) {
        // SAFETY: the pointer comes from a successful lookup and points at the value in
        // the map. Another CPU may update the same flow at the same time; the worst case
        // is one payload copy more or less for that flow, which the bound tolerates.
        unsafe {
            if *seen >= limit {
                return false;
            }
            *seen += 1;
        }
        true
    } else {
        FLOWS.insert(key, 1, 0).is_ok()
    }
}

/// GCRA token bucket per CPU (`slot` of the bucket map): true when a copy may go out now.
#[inline(always)]
fn take_token(slot: u32, interval_ns: u64, burst_ns: u64) -> bool {
    if interval_ns == 0 {
        return true;
    }
    let Some(tat) = BUCKET.get_ptr_mut(slot) else {
        return false;
    };
    // SAFETY: a helper without arguments.
    let now = unsafe { bpf_ktime_get_ns() };
    // SAFETY: this CPU's own slot of a per-CPU array (see `add_counters`).
    unsafe {
        let mut t = *tat;
        if t < now {
            t = now;
        }
        if t - now > burst_ns {
            return false;
        }
        *tat = t + interval_ns;
    }
    true
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn copy(ctx: &TcContext, direction: u32, ethertype: u16, l2_len: u32, want: u32, kind: u8) {
    let skb_len = ctx.len();
    let mut n = if want > skb_len { skb_len } else { want };
    if n > RECORD_DATA as u32 {
        n = RECORD_DATA as u32;
    }
    let Some(mut entry) = EVENTS.reserve::<Record>(0) else {
        bump(&STATS_MAP, STAT_RINGBUF_FULL);
        return;
    };
    let record = entry.as_mut_ptr();
    // SAFETY: `record` points at a reserved ring-buffer slot of `size_of::<Record>()`
    // bytes that only this program writes until it is submitted or discarded. The load
    // writes `len` bytes, 1 <= len <= RECORD_DATA, into the record's data array, which is
    // RECORD_DATA bytes. `len` is written so the verifier can see both bounds on every
    // kernel: masking and adding one gives a minimum of 1 by construction (Linux 5.15 does
    // not learn `n != 0` from a comparison), and the comparison gives the maximum. For
    // 1 <= n <= RECORD_DATA it equals `n`; for n == 0 it is 1024 and nothing is loaded.
    let loaded = unsafe {
        let len = (n.wrapping_sub(1) & 0x3ff) + 1;
        if len > RECORD_DATA as u32 {
            -1
        } else {
            bpf_skb_load_bytes(
                ctx.skb.skb.cast(),
                0,
                core::ptr::addr_of_mut!((*record).data).cast(),
                len,
            )
        }
    };
    if loaded != 0 {
        entry.discard(0);
        bump(&STATS_MAP, STAT_SHORT);
        return;
    }
    // SAFETY: as above; the header fields are plain integers.
    unsafe {
        (*record).header.ts_ns = bpf_ktime_get_ns();
        (*record).header.skb_len = skb_len;
        (*record).header.cap_len = n as u16;
        (*record).header.direction = direction as u8;
        (*record).header.kind = kind;
        (*record).header.ethertype = ethertype;
        (*record).header.l2_len = l2_len as u8;
        (*record).header.reserved = [0; 5];
    }
    entry.submit(0);
    bump(&STATS_MAP, STAT_COPIED);
    if kind == KIND_PAYLOAD {
        bump(&STATS_MAP, STAT_PAYLOAD);
    }
}

/// Layer 3: the whole packet, up to `snaplen` bytes, into the packets ring buffer.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)] // the tiers are constants far below u32::MAX
fn copy_packet(ctx: &TcContext, direction: u32, ethertype: u16, cfg: &Config) {
    if !take_token(BUCKET_PACKETS, cfg.pkt_interval_ns, cfg.pkt_burst_ns) {
        bump(&STATS_MAP, STAT_PKT_RATE_LIMITED);
        return;
    }
    let skb_len = ctx.len();
    let n = if cfg.snaplen < skb_len {
        cfg.snaplen
    } else {
        skb_len
    };
    if n <= PACKET_TIERS[0] as u32 {
        copy_tier::<{ PACKET_TIERS[0] }>(ctx, direction, ethertype, cfg.l2_len, n);
    } else if n <= PACKET_TIERS[1] as u32 {
        copy_tier::<{ PACKET_TIERS[1] }>(ctx, direction, ethertype, cfg.l2_len, n);
    } else if n <= PACKET_TIERS[2] as u32 {
        copy_tier::<{ PACKET_TIERS[2] }>(ctx, direction, ethertype, cfg.l2_len, n);
    } else {
        copy_tier::<{ PACKET_TIERS[3] }>(ctx, direction, ethertype, cfg.l2_len, n);
    }
}

/// One record of tier size `N` (a power of two or not; `n` is at most `N` for the tier
/// the caller picked, and at most 65535 for the last one).
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn copy_tier<const N: usize>(ctx: &TcContext, direction: u32, ethertype: u16, l2_len: u32, n: u32) {
    let Some(mut entry) = PACKETS.reserve::<PacketRecord<N>>(0) else {
        bump(&STATS_MAP, STAT_PKT_RINGBUF_FULL);
        return;
    };
    let record = entry.as_mut_ptr();
    let mask = (N.next_power_of_two() - 1) as u32;
    // The caller's tier check makes the mask below look redundant to LLVM, which then drops
    // it, and the verifier (which does not see that check on the same register) rejects
    // the load as unbounded. Hiding `n` from the optimizer keeps both bounds in the code.
    let n = core::hint::black_box(n);
    // SAFETY: `record` points at a reserved ring-buffer slot of
    // `size_of::<PacketRecord<N>>()` bytes that only this program writes until it is
    // submitted or discarded. The load writes `len` bytes, 1 <= len <= N, into the data
    // array of N bytes: masking and adding one gives the verifier a minimum of 1 and a
    // maximum of the next power of two; the comparison caps it at N. For 1 <= n <= N it
    // equals `n`.
    let (loaded, len) = unsafe {
        let len = (n.wrapping_sub(1) & mask) + 1;
        if len > N as u32 {
            (-1, 0)
        } else {
            (
                bpf_skb_load_bytes(
                    ctx.skb.skb.cast(),
                    0,
                    core::ptr::addr_of_mut!((*record).data).cast(),
                    len,
                ),
                len,
            )
        }
    };
    if loaded != 0 {
        entry.discard(0);
        bump(&STATS_MAP, STAT_SHORT);
        return;
    }
    // SAFETY: as above; the header fields are plain integers.
    unsafe {
        (*record).header.ts_ns = bpf_ktime_get_ns();
        (*record).header.skb_len = ctx.len();
        (*record).header.cap_len = len;
        (*record).header.ethertype = ethertype;
        (*record).header.direction = direction as u8;
        (*record).header.l2_len = l2_len as u8;
        (*record).header.reserved = [0; 4];
    }
    entry.submit(0);
    bump(&STATS_MAP, STAT_PKT_COPIED);
    add(&STATS_MAP, STAT_PKT_BYTES, u64::from(len));
}

#[inline(always)]
fn add_counters(map: &PerCpuArray<Counters>, index: u32, len: u32) {
    if let Some(slot) = map.get_ptr_mut(index) {
        // SAFETY: the pointer comes from a successful lookup in a per-CPU array, so it is
        // non-null, aligned and points at this CPU's own slot; TC programs do not migrate
        // between CPUs while they run, so no other writer touches it concurrently.
        unsafe {
            (*slot).packets = (*slot).packets.wrapping_add(1);
            (*slot).bytes = (*slot).bytes.wrapping_add(u64::from(len));
        }
    }
}

#[inline(always)]
fn bump(map: &PerCpuArray<u64>, index: u32) {
    add(map, index, 1);
}

#[inline(always)]
fn add(map: &PerCpuArray<u64>, index: u32, n: u64) {
    if let Some(slot) = map.get_ptr_mut(index) {
        // SAFETY: as in `add_counters`.
        unsafe {
            *slot = (*slot).wrapping_add(n);
        }
    }
}

// EGRESS is part of the shared contract; the programs only compare against INGRESS.
const _: u32 = EGRESS;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// GPL-compatible, as the kernel requires for programs that use GPL-only helpers.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
