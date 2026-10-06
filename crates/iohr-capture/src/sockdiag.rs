//! Sockets from the kernel's `sock_diag` netlink interface (what `ss` uses): TCP and UDP
//! sockets in this network namespace with their state, queues, owning uid, cgroup id
//! (Linux 5.9+) and, for TCP, `tcp_info` (RTT, retransmits, bytes). Needs no capability
//! and no kernel probe; it is a sample taken every poll, so a connection that opens and
//! closes between two polls is not in it.

use std::net::IpAddr;

/// `NETLINK_SOCK_DIAG` message type `SOCK_DIAG_BY_FAMILY`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CGROUP_ID: u16 = 21;
/// Most sockets kept from one dump.
pub(crate) const MAX_SOCKETS: usize = 65_536;

/// TCP states (`include/net/tcp_states.h`).
pub(crate) const TCP_ESTABLISHED: u8 = 1;
pub(crate) const TCP_TIME_WAIT: u8 = 6;
pub(crate) const TCP_LISTEN: u8 = 10;
/// UDP sockets report state 7 (`TCP_CLOSE`) unless connected (1).
pub(crate) const UDP_UNCONNECTED: u8 = 7;

/// The fields of `tcp_info` used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TcpInfo {
    /// Smoothed RTT, microseconds.
    pub(crate) rtt_us: u32,
    /// Segments retransmitted over the socket's life.
    pub(crate) total_retrans: u32,
    pub(crate) bytes_acked: u64,
    pub(crate) bytes_received: u64,
}

/// One socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Socket {
    pub(crate) proto: u8,
    pub(crate) state: u8,
    pub(crate) local: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote: IpAddr,
    pub(crate) remote_port: u16,
    pub(crate) cookie: u64,
    /// Listening: connections waiting in the accept queue; otherwise bytes unread.
    pub(crate) rqueue: u32,
    /// Listening: the accept queue's limit (backlog); otherwise bytes unsent.
    pub(crate) wqueue: u32,
    pub(crate) uid: u32,
    pub(crate) cgroup_id: Option<u64>,
    pub(crate) tcp: Option<TcpInfo>,
}

/// The dump request for one family (`AF_INET` 2, `AF_INET6` 10) and protocol.
pub(crate) fn request(family: u8, proto: u8, seq: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(&72u32.to_ne_bytes());
    m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    m.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    // inet_diag_req_v2
    m.push(family);
    m.push(proto);
    m.push(if proto == 6 {
        1 << (INET_DIAG_INFO - 1)
    } else {
        0
    });
    m.push(0);
    m.extend_from_slice(&u32::MAX.to_ne_bytes()); // every state
    m.extend_from_slice(&[0u8; 48]); // inet_diag_sockid: no filter
    m
}

/// What one received buffer held.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Chunk {
    More,
    Done,
    Error(i32),
}

fn ne_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn ne_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn ne_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Parses the netlink messages in one received buffer into `out`.
pub(crate) fn parse(buf: &[u8], proto: u8, seq: u32, out: &mut Vec<Socket>) -> Chunk {
    let mut at = 0;
    while at + 16 <= buf.len() {
        let (Some(len), Some(kind)) = (ne_u32(buf, at), ne_u16(buf, at + 4)) else {
            break;
        };
        let len = len as usize;
        if len < 16 || at + len > buf.len() {
            break;
        }
        let body = buf.get(at + 16..at + len).unwrap_or_default();
        // Only answers to our own request count.
        if ne_u32(buf, at + 8) != Some(seq) {
            at += (len + 3) & !3;
            continue;
        }
        match kind {
            NLMSG_DONE => return Chunk::Done,
            NLMSG_ERROR => {
                let code = body
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                return Chunk::Error(code);
            }
            SOCK_DIAG_BY_FAMILY => {
                if out.len() < MAX_SOCKETS
                    && let Some(s) = socket(body, proto)
                {
                    out.push(s);
                }
            }
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Chunk::More
}

fn socket(b: &[u8], proto: u8) -> Option<Socket> {
    let family = *b.first()?;
    let state = *b.get(1)?;
    let sport = u16::from_be_bytes(b.get(4..6)?.try_into().ok()?);
    let dport = u16::from_be_bytes(b.get(6..8)?.try_into().ok()?);
    let addr = |at: usize| -> Option<IpAddr> {
        if family == 2 {
            let a: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
            Some(IpAddr::from(a))
        } else {
            let a: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
            Some(IpAddr::from(a).to_canonical())
        }
    };
    let local = addr(8)?;
    let remote = addr(24)?;
    let cookie = u64::from(ne_u32(b, 44)?) | (u64::from(ne_u32(b, 48)?) << 32);
    let rqueue = ne_u32(b, 56)?;
    let wqueue = ne_u32(b, 60)?;
    let uid = ne_u32(b, 64)?;
    let mut s = Socket {
        proto,
        state,
        local,
        local_port: sport,
        remote,
        remote_port: dport,
        cookie,
        rqueue,
        wqueue,
        uid,
        cgroup_id: None,
        tcp: None,
    };
    let mut at = 72;
    while at + 4 <= b.len() {
        let len = usize::from(ne_u16(b, at)?);
        let kind = ne_u16(b, at + 2)?;
        if len < 4 || at + len > b.len() {
            break;
        }
        let data = b.get(at + 4..at + len)?;
        match kind {
            INET_DIAG_INFO => s.tcp = tcp_info(data),
            INET_DIAG_CGROUP_ID => s.cgroup_id = ne_u64(data, 0),
            _ => {}
        }
        at += (len + 3) & !3;
    }
    Some(s)
}

/// `struct tcp_info` offsets (include/uapi/linux/tcp.h); older kernels send a shorter
/// struct, so every field is optional.
fn tcp_info(d: &[u8]) -> Option<TcpInfo> {
    Some(TcpInfo {
        rtt_us: ne_u32(d, 68)?,
        total_retrans: ne_u32(d, 100).unwrap_or(0),
        bytes_acked: ne_u64(d, 120).unwrap_or(0),
        bytes_received: ne_u64(d, 128).unwrap_or(0),
    })
}

/// Dumps TCP and UDP sockets of both families over `NETLINK_SOCK_DIAG`.
#[cfg(target_os = "linux")]
pub(crate) fn dump() -> std::io::Result<Vec<Socket>> {
    use rustix::net::{
        AddressFamily, RecvFlags, SendFlags, SocketAddrAny, SocketType, netlink, recvfrom, sendto,
        socket,
        sockopt::{Timeout, set_socket_timeout},
    };
    let fd = socket(
        AddressFamily::NETLINK,
        SocketType::RAW,
        Some(netlink::SOCK_DIAG),
    )?;
    set_socket_timeout(&fd, Timeout::Recv, Some(std::time::Duration::from_secs(2)))?;
    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut seq = 1;
    for proto in [6u8, 17] {
        for family in [2u8, 10] {
            sendto(
                &fd,
                &request(family, proto, seq),
                SendFlags::empty(),
                &kernel,
            )?;
            // Bounded: a dump ends with NLMSG_DONE; stop anyway after this many buffers.
            for _ in 0..4096 {
                let (n, _, from) = recvfrom(&fd, &mut buf[..], RecvFlags::empty())?;
                // Only the kernel (port id 0) answers; anything else is dropped.
                let from_kernel = from
                    .and_then(|a: SocketAddrAny| netlink::SocketAddrNetlink::try_from(a).ok())
                    .is_some_and(|a| a.pid() == 0);
                if !from_kernel {
                    continue;
                }
                match parse(buf.get(..n).unwrap_or_default(), proto, seq, &mut out) {
                    Chunk::More => {}
                    Chunk::Done => break,
                    Chunk::Error(code) => {
                        return Err(std::io::Error::from_raw_os_error(-code));
                    }
                }
            }
            seq += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A `SOCK_DIAG_BY_FAMILY` message for an IPv4 TCP socket, as the kernel sends it.
    pub(crate) fn message(
        state: u8,
        local: ([u8; 4], u16),
        remote: ([u8; 4], u16),
        cgroup: u64,
        rtt_us: u32,
        retrans: u32,
    ) -> Vec<u8> {
        let mut body = vec![2, state, 0, 0];
        body.extend_from_slice(&local.1.to_be_bytes());
        body.extend_from_slice(&remote.1.to_be_bytes());
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&local.0);
        body.extend_from_slice(&a);
        a[..4].copy_from_slice(&remote.0);
        body.extend_from_slice(&a);
        body.extend_from_slice(&0u32.to_ne_bytes()); // if
        body.extend_from_slice(&7u32.to_ne_bytes()); // cookie lo
        body.extend_from_slice(&0u32.to_ne_bytes()); // cookie hi
        body.extend_from_slice(&0u32.to_ne_bytes()); // expires
        body.extend_from_slice(&3u32.to_ne_bytes()); // rqueue
        body.extend_from_slice(&128u32.to_ne_bytes()); // wqueue
        body.extend_from_slice(&33u32.to_ne_bytes()); // uid
        body.extend_from_slice(&99u32.to_ne_bytes()); // inode
        let mut info = vec![0u8; 232];
        info[68..72].copy_from_slice(&rtt_us.to_ne_bytes());
        info[100..104].copy_from_slice(&retrans.to_ne_bytes());
        info[120..128].copy_from_slice(&1000u64.to_ne_bytes());
        body.extend_from_slice(&u16::try_from(4 + info.len()).unwrap().to_ne_bytes());
        body.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        body.extend_from_slice(&info);
        body.extend_from_slice(&12u16.to_ne_bytes());
        body.extend_from_slice(&INET_DIAG_CGROUP_ID.to_ne_bytes());
        body.extend_from_slice(&cgroup.to_ne_bytes());
        let mut m = Vec::new();
        m.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&[0, 0]); // flags
        m.extend_from_slice(&1u32.to_ne_bytes()); // seq
        m.extend_from_slice(&[0, 0, 0, 0]); // pid
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn parses_a_dump() {
        let mut buf = message(
            TCP_LISTEN,
            ([10, 0, 0, 1], 8080),
            ([0, 0, 0, 0], 0),
            4242,
            0,
            0,
        );
        buf.extend(message(
            TCP_ESTABLISHED,
            ([10, 0, 0, 1], 8080),
            ([10, 0, 0, 2], 40000),
            4242,
            1500,
            2,
        ));
        let mut done = vec![0u8; 20];
        done[..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        done[8..12].copy_from_slice(&1u32.to_ne_bytes());
        buf.extend(done);
        let mut out = Vec::new();
        assert_eq!(parse(&buf, 6, 1, &mut out), Chunk::Done);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].state, TCP_LISTEN);
        assert_eq!((out[0].rqueue, out[0].wqueue), (3, 128));
        assert_eq!(out[1].remote, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(out[1].cgroup_id, Some(4242));
        assert_eq!(
            out[1]
                .tcp
                .map(|t| (t.rtt_us, t.total_retrans, t.bytes_acked)),
            Some((1500, 2, 1000))
        );
        assert_eq!(out[1].uid, 33);
    }

    #[test]
    fn truncated_and_error_buffers() {
        let m = message(
            TCP_ESTABLISHED,
            ([1, 2, 3, 4], 1),
            ([5, 6, 7, 8], 2),
            1,
            1,
            1,
        );
        for n in 0..m.len() {
            let mut out = Vec::new();
            let _ = parse(&m[..n], 6, 1, &mut out);
        }
        let mut err = vec![0u8; 20];
        err[..4].copy_from_slice(&20u32.to_ne_bytes());
        err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        err[8..12].copy_from_slice(&1u32.to_ne_bytes());
        err[16..20].copy_from_slice(&(-13i32).to_ne_bytes());
        assert_eq!(parse(&err, 6, 1, &mut Vec::new()), Chunk::Error(-13));
        // A message for another request is ignored.
        assert_eq!(parse(&err, 6, 2, &mut Vec::new()), Chunk::More);
        assert_eq!(request(2, 6, 1).len(), 72);
    }
}
