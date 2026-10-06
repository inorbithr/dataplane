//! DNS (RFC 1035): the question of a query, the response code of an answer. Over UDP each
//! datagram is one message; over TCP a two-byte length comes first (`tcp = true`).

use super::Detect;

/// A query's question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
    /// Lower-cased, without the trailing dot.
    pub(crate) name: String,
    /// `A`, `AAAA`, ... or the number.
    pub(crate) qtype: String,
}

/// A parsed message: a query or a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    Query(Query),
    Response { rcode: u8 },
}

/// Parses one DNS message.
pub(crate) fn message(buf: &[u8], tcp: bool) -> Detect<Message> {
    let msg = if tcp {
        let Some(len) = buf.get(..2) else {
            return Detect::NeedMore;
        };
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if len < 12 {
            return Detect::No;
        }
        buf.get(2..).unwrap_or_default()
    } else {
        buf
    };
    let Some(h) = msg.get(..12) else {
        return if tcp { Detect::NeedMore } else { Detect::No };
    };
    let flags = u16::from_be_bytes([h[2], h[3]]);
    let opcode = (flags >> 11) & 0x0f;
    let qd = u16::from_be_bytes([h[4], h[5]]);
    if opcode > 5 || qd == 0 || qd > 4 {
        return Detect::No;
    }
    let response = flags & 0x8000 != 0;
    let Some((name, end)) = qname(msg, 12) else {
        return if tcp && msg.len() < 300 {
            Detect::NeedMore
        } else {
            Detect::No
        };
    };
    let Some(t) = msg.get(end..end + 4) else {
        return if response {
            Detect::Yes(Message::Response {
                rcode: rcode(flags),
            })
        } else {
            Detect::NeedMore
        };
    };
    let qclass = u16::from_be_bytes([t[2], t[3]]);
    if qclass != 1 && qclass != 255 && qclass & 0x7fff != 1 {
        return Detect::No;
    }
    if response {
        return Detect::Yes(Message::Response {
            rcode: rcode(flags),
        });
    }
    Detect::Yes(Message::Query(Query {
        name,
        qtype: qtype_name(u16::from_be_bytes([t[0], t[1]])),
    }))
}

#[allow(clippy::cast_possible_truncation)]
const fn rcode(flags: u16) -> u8 {
    (flags & 0x0f) as u8
}

/// The question name starting at `at`; uncompressed labels only (questions are never
/// compressed). Returns the name and the offset after it.
fn qname(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let len = usize::from(*msg.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(at..at + len)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*'))
        {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        if name.len() > 253 {
            return None;
        }
        at += len;
    }
    if name.is_empty() {
        name.push('.');
    }
    Some((name, at))
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => n.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIG: &[u8] = include_bytes!("../../tests/fixtures/dns.bin");

    #[test]
    fn dig_query() {
        assert_eq!(
            message(DIG, false),
            Detect::Yes(Message::Query(Query {
                name: "same.dns-e2e.example".into(),
                qtype: "A".into()
            }))
        );
        let mut tcp = u16::try_from(DIG.len()).unwrap_or(0).to_be_bytes().to_vec();
        tcp.extend_from_slice(DIG);
        assert!(matches!(
            message(&tcp, true),
            Detect::Yes(Message::Query(_))
        ));
    }

    #[test]
    fn responses_and_garbage() {
        let mut resp = DIG.to_vec();
        resp[2] |= 0x80;
        resp[3] = (resp[3] & 0xf0) | 3;
        assert_eq!(
            message(&resp, false),
            Detect::Yes(Message::Response { rcode: 3 })
        );
        for n in 0..DIG.len() {
            let _ = message(&DIG[..n], false);
            let _ = message(&DIG[..n], true);
        }
        assert_eq!(
            message(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", false),
            Detect::No
        );
        assert_eq!(message(&[0u8; 12], false), Detect::No);
    }
}
