//! PostgreSQL: what opens a connection (protocol 3 startup, an SSL or GSS encryption
//! request, a cancel request). The startup's user and database names are never read.

use super::Detect;

/// The opening message of a PostgreSQL connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Message {
    Startup,
    SslRequest,
    GssEncRequest,
    CancelRequest,
}

impl Message {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::SslRequest => "ssl_request",
            Self::GssEncRequest => "gssenc_request",
            Self::CancelRequest => "cancel_request",
        }
    }
}

/// Recognises the first message a PostgreSQL client sends.
pub(crate) fn opening(buf: &[u8]) -> Detect<Message> {
    let Some(head) = buf.get(..8) else {
        return Detect::NeedMore;
    };
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let code = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    let m = match (len, code) {
        (8, 80_877_103) => Message::SslRequest,
        (8, 80_877_104) => Message::GssEncRequest,
        (16, 80_877_102) => Message::CancelRequest,
        (9..=10_000, 196_608) => Message::Startup,
        _ => return Detect::No,
    };
    Detect::Yes(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openings() {
        assert_eq!(
            opening(&[0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f]),
            Detect::Yes(Message::SslRequest)
        );
        let mut startup = vec![0, 0, 0, 41, 0, 3, 0, 0];
        startup.extend_from_slice(b"user\0alice\0database\0shop\0\0");
        assert_eq!(opening(&startup), Detect::Yes(Message::Startup));
        assert_eq!(opening(&startup[..5]), Detect::NeedMore);
        assert_eq!(opening(b"GET / HTTP/1.1\r\n"), Detect::No);
    }
}
