//! Parsing a ring-buffer record (layer 1, user side): the record header the kernel wrote,
//! then the link, network and transport headers of the copied packet bytes. Every read is
//! bounds-checked; a malformed or short record is an `Err`, never a panic.

use std::net::IpAddr;

use iohr_capture_common::{RECORD_DATA, RECORD_HEADER_BYTES};

/// TCP flag bits.
pub(crate) const TCP_FIN: u8 = 0x01;
pub(crate) const TCP_SYN: u8 = 0x02;
pub(crate) const TCP_RST: u8 = 0x04;
pub(crate) const TCP_ACK: u8 = 0x10;
pub(crate) const IPPROTO_TCP: u8 = 6;
pub(crate) const IPPROTO_UDP: u8 = 17;

/// One parsed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Packet<'a> {
    pub(crate) ts_ns: u64,
    pub(crate) direction: u8,
    pub(crate) kind: u8,
    pub(crate) skb_len: u32,
    pub(crate) proto: u8,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) tcp_flags: u8,
    /// TCP sequence number (0 for UDP).
    pub(crate) seq: u32,
    /// The copied transport payload (a prefix of it).
    pub(crate) payload: &'a [u8],
    /// The payload's full length, as the IP header states it.
    pub(crate) payload_len: usize,
}

/// Why a record was not parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Malformed {
    Short,
    NotIp,
    NotTcpUdp,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Parses one record: the 24-byte header (little-endian, as the BPF target writes it)
/// and the packet bytes.
#[allow(clippy::too_many_lines)] // a flat walk down the headers
pub(crate) fn parse(record: &[u8]) -> Result<Packet<'_>, Malformed> {
    let head = record.get(..RECORD_HEADER_BYTES).ok_or(Malformed::Short)?;
    let le64 = |at: usize| {
        head.get(at..at + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let ts_ns = le64(0).ok_or(Malformed::Short)?;
    let skb_len = head
        .get(8..12)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Malformed::Short)?;
    let cap_len = head
        .get(12..14)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(Malformed::Short)?;
    let direction = *head.get(14).ok_or(Malformed::Short)?;
    let kind = *head.get(15).ok_or(Malformed::Short)?;
    let ethertype = head
        .get(16..18)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(Malformed::Short)?;
    let l2 = usize::from(*head.get(18).ok_or(Malformed::Short)?);
    let cap = usize::from(cap_len).min(RECORD_DATA);
    let data = record
        .get(RECORD_HEADER_BYTES..RECORD_HEADER_BYTES + cap)
        .ok_or(Malformed::Short)?;
    let (src, dst, proto, l4, l4_len) = match ethertype {
        0x0800 => {
            let ihl = usize::from(*data.get(l2).ok_or(Malformed::Short)? & 0x0f) * 4;
            if ihl < 20 {
                return Err(Malformed::Short);
            }
            let total = usize::from(be16(data, l2 + 2).ok_or(Malformed::Short)?);
            let frag = be16(data, l2 + 6).ok_or(Malformed::Short)?;
            if frag & 0x1fff != 0 {
                return Err(Malformed::NotTcpUdp);
            }
            let proto = *data.get(l2 + 9).ok_or(Malformed::Short)?;
            let s: [u8; 4] = data
                .get(l2 + 12..l2 + 16)
                .and_then(|s| s.try_into().ok())
                .ok_or(Malformed::Short)?;
            let d: [u8; 4] = data
                .get(l2 + 16..l2 + 20)
                .and_then(|s| s.try_into().ok())
                .ok_or(Malformed::Short)?;
            (
                IpAddr::from(s),
                IpAddr::from(d),
                proto,
                l2 + ihl,
                total.saturating_sub(ihl),
            )
        }
        0x86dd => {
            let plen = usize::from(be16(data, l2 + 4).ok_or(Malformed::Short)?);
            let proto = *data.get(l2 + 6).ok_or(Malformed::Short)?;
            let s: [u8; 16] = data
                .get(l2 + 8..l2 + 24)
                .and_then(|s| s.try_into().ok())
                .ok_or(Malformed::Short)?;
            let d: [u8; 16] = data
                .get(l2 + 24..l2 + 40)
                .and_then(|s| s.try_into().ok())
                .ok_or(Malformed::Short)?;
            (IpAddr::from(s), IpAddr::from(d), proto, l2 + 40, plen)
        }
        _ => return Err(Malformed::NotIp),
    };
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Err(Malformed::NotTcpUdp);
    }
    let sport = be16(data, l4).ok_or(Malformed::Short)?;
    let dport = be16(data, l4 + 2).ok_or(Malformed::Short)?;
    let (hdr, flags, seq) = if proto == IPPROTO_TCP {
        let off = usize::from(*data.get(l4 + 12).ok_or(Malformed::Short)? >> 4) * 4;
        let flags = *data.get(l4 + 13).ok_or(Malformed::Short)?;
        if off < 20 {
            return Err(Malformed::Short);
        }
        let seq = data
            .get(l4 + 4..l4 + 8)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(Malformed::Short)?;
        (off, flags, seq)
    } else {
        (8, 0, 0)
    };
    let start = l4 + hdr;
    // The payload is what was copied, never more than the IP header says exists (Ethernet
    // padding on short frames is not payload).
    let end = data.len().min(l4 + l4_len.max(hdr));
    let payload = if start <= end {
        data.get(start..end).unwrap_or_default()
    } else {
        &[]
    };
    Ok(Packet {
        ts_ns,
        direction,
        kind,
        skb_len,
        proto,
        src,
        dst,
        sport,
        dport,
        tcp_flags: flags,
        seq,
        payload,
        payload_len: l4_len.saturating_sub(hdr),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A record as the kernel writes it, for an Ethernet + IPv4 packet.
    pub(crate) fn record_v4(
        direction: u8,
        proto: u8,
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        tcp_flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        record_v4_at(direction, proto, src, dst, tcp_flags, 1, 7, payload)
    }

    /// As [`record_v4`], with a TCP sequence number and a timestamp (ns).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_v4_at(
        direction: u8,
        proto: u8,
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        tcp_flags: u8,
        seq: u32,
        ts_ns: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x08;
        let l4_len = if proto == IPPROTO_TCP { 20 } else { 8 } + payload.len();
        let total = u16::try_from(20 + l4_len).unwrap_or(u16::MAX);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&src.0);
        ip.extend_from_slice(&dst.0);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&src.1.to_be_bytes());
        pkt.extend_from_slice(&dst.1.to_be_bytes());
        if proto == IPPROTO_TCP {
            pkt.extend_from_slice(&seq.to_be_bytes());
            pkt.extend_from_slice(&[0, 0, 0, 0, 0x50, tcp_flags, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            let ulen = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
            pkt.extend_from_slice(&ulen.to_be_bytes());
            pkt.extend_from_slice(&[0, 0]);
        }
        pkt.extend_from_slice(payload);
        pkt.truncate(RECORD_DATA);
        let mut rec = Vec::with_capacity(RECORD_HEADER_BYTES + pkt.len());
        rec.extend_from_slice(&ts_ns.to_le_bytes());
        rec.extend_from_slice(&u32::try_from(pkt.len()).unwrap_or(0).to_le_bytes());
        rec.extend_from_slice(&u16::try_from(pkt.len()).unwrap_or(0).to_le_bytes());
        rec.push(direction);
        rec.push(u8::from(!payload.is_empty()));
        rec.extend_from_slice(&0x0800u16.to_le_bytes());
        rec.push(14);
        rec.extend_from_slice(&[0; 5]);
        rec.extend_from_slice(&pkt);
        rec
    }

    #[test]
    fn tcp_v4_with_payload() {
        let rec = record_v4(
            0,
            6,
            ([10, 0, 0, 2], 40000),
            ([10, 0, 0, 1], 80),
            0x18,
            b"GET / HTTP/1.1\r\n",
        );
        let p = parse(&rec).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(p.sport, 40000);
        assert_eq!(p.dport, 80);
        assert_eq!(p.src, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(p.payload, b"GET / HTTP/1.1\r\n");
        assert_eq!(p.tcp_flags, 0x18);
    }

    #[test]
    fn udp_and_short_records() {
        let rec = record_v4(1, 17, ([10, 0, 0, 1], 53), ([10, 0, 0, 2], 5353), 0, b"abc");
        let p = parse(&rec).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!((p.proto, p.payload), (17, &b"abc"[..]));
        for cut in [0, 10, 24, 30, 45] {
            assert!(parse(&rec[..cut.min(rec.len())]).is_err(), "cut {cut}");
        }
        let mut arp = rec.clone();
        arp[16] = 0x06;
        assert_eq!(parse(&arp), Err(Malformed::NotIp));
    }

    #[test]
    fn ipv6() {
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x86;
        pkt[13] = 0xdd;
        let mut ip = vec![0x60, 0, 0, 0, 0, 11, 17, 64];
        ip.extend_from_slice(&[0xfd; 16]);
        ip.extend_from_slice(&[0xfe; 16]);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&[0x13, 0x88, 0, 53, 0, 11, 0, 0, b'x', b'y', b'z']);
        let mut rec = Vec::new();
        rec.extend_from_slice(&0u64.to_le_bytes());
        rec.extend_from_slice(&u32::try_from(pkt.len()).unwrap_or(0).to_le_bytes());
        rec.extend_from_slice(&u16::try_from(pkt.len()).unwrap_or(0).to_le_bytes());
        rec.extend_from_slice(&[0, 1]);
        rec.extend_from_slice(&0x86ddu16.to_le_bytes());
        rec.push(14);
        rec.extend_from_slice(&[0; 5]);
        rec.extend_from_slice(&pkt);
        let p = parse(&rec).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(p.dport, 53);
        assert_eq!(p.payload, b"xyz");
        assert!(p.src.is_ipv6());
    }
}
