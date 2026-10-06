//! HTTP/2 with prior knowledge (cleartext, `h2c`): the client preface, then the frames in
//! the copied bytes. The first HEADERS block of the connection is decoded (HPACK, with an
//! empty dynamic table) for `:method`, `:path`, `:authority` and `content-type`; gRPC is
//! HTTP/2 with `content-type: application/grpc`, its method is the `:path`.
//!
//! Only the connection's first request yields a path. Later HEADERS frames in the copied
//! bytes are counted as streams with the path "unknown" (they may refer to dynamic table
//! entries this decoder did not keep), and anything after the first packets of a flow is
//! not seen in phase 1. HTTP/2 inside TLS is counted by TLS (ALPN `h2`), never decrypted.

use super::{Detect, clean_host, hpack, path_template};

/// The client connection preface (RFC 9113 3.4).
pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADERS: u8 = 0x1;
const FRAME_CONTINUATION: u8 = 0x9;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;
/// Largest header block assembled from HEADERS and CONTINUATION frames.
const MAX_BLOCK: usize = 4096;

/// What the first bytes of an HTTP/2 connection showed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Connection {
    /// `:method` of the first request.
    pub(crate) method: Option<String>,
    /// `:path` of the first request as a template (ids replaced, no query).
    pub(crate) path: Option<String>,
    pub(crate) authority: Option<String>,
    /// `content-type` starts with `application/grpc`.
    pub(crate) grpc: bool,
    /// The gRPC method (`/package.Service/Method`), when `grpc`.
    pub(crate) grpc_method: Option<String>,
    /// HEADERS frames seen in the copied bytes (requests started).
    pub(crate) streams: u32,
}

/// Recognises an HTTP/2 client stream from its first bytes.
pub(crate) fn client(buf: &[u8]) -> Detect<Connection> {
    let n = buf.len().min(PREFACE.len());
    if buf.get(..n) != PREFACE.get(..n) {
        return Detect::No;
    }
    if buf.len() < PREFACE.len() {
        return Detect::NeedMore;
    }
    let mut conn = Connection::default();
    let mut at = PREFACE.len();
    let mut block: Option<Vec<u8>> = None;
    let mut first_done = false;
    while let Some(h) = buf.get(at..at + 9) {
        let len = (usize::from(h[0]) << 16) | (usize::from(h[1]) << 8) | usize::from(h[2]);
        let (kind, flags) = (h[3], h[4]);
        let Some(payload) = buf.get(at + 9..at + 9 + len) else {
            break;
        };
        at += 9 + len;
        match kind {
            FRAME_HEADERS => {
                conn.streams = conn.streams.saturating_add(1);
                if first_done || block.is_some() {
                    continue;
                }
                let Some(fragment) = headers_fragment(payload, flags) else {
                    continue;
                };
                let mut b = fragment.to_vec();
                b.truncate(MAX_BLOCK);
                if flags & FLAG_END_HEADERS != 0 {
                    first_done = true;
                    apply(&mut conn, &b);
                } else {
                    block = Some(b);
                }
            }
            FRAME_CONTINUATION => {
                if let Some(mut b) = block.take() {
                    b.extend_from_slice(payload);
                    b.truncate(MAX_BLOCK);
                    if flags & FLAG_END_HEADERS != 0 {
                        first_done = true;
                        apply(&mut conn, &b);
                    } else {
                        block = Some(b);
                    }
                }
            }
            _ => {}
        }
    }
    if conn.streams == 0 && buf.len() < 512 {
        // The preface and SETTINGS arrived, the first request not yet.
        return Detect::NeedMore;
    }
    Detect::Yes(conn)
}

/// The header block fragment of a HEADERS frame, without padding and priority fields.
fn headers_fragment(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        let pad = usize::from(*payload.first()?);
        start = 1;
        end = end.checked_sub(pad)?;
    }
    if flags & FLAG_PRIORITY != 0 {
        start += 5;
    }
    payload.get(start..end)
}

fn apply(conn: &mut Connection, block: &[u8]) {
    let Ok(fields) = hpack::decode(block) else {
        return;
    };
    let mut raw_path = None;
    for (name, value) in fields {
        match name.as_str() {
            ":method" if value.bytes().all(|b| b.is_ascii_uppercase()) && value.len() <= 16 => {
                conn.method = Some(value);
            }
            ":path" => raw_path = Some(value),
            ":authority" => conn.authority = clean_host(&value),
            "content-type" => conn.grpc = value.starts_with("application/grpc"),
            _ => {}
        }
    }
    if let Some(p) = raw_path {
        if conn.grpc {
            // `/package.Service/Method` names an API, not an object: kept as is (bounded).
            let m: String = p
                .split('?')
                .next()
                .unwrap_or_default()
                .chars()
                .filter(char::is_ascii_graphic)
                .take(128)
                .collect();
            conn.grpc_method = Some(m);
        }
        conn.path = Some(path_template(&p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURL_GRPC: &[u8] = include_bytes!("../../tests/fixtures/h2.bin");

    #[test]
    fn curl_prior_knowledge_grpc() {
        let Detect::Yes(c) = client(CURL_GRPC) else {
            panic!("not recognised")
        };
        assert_eq!(c.method.as_deref(), Some("POST"));
        assert!(c.grpc);
        assert_eq!(c.grpc_method.as_deref(), Some("/e2e.Echo/Say"));
        assert_eq!(c.path.as_deref(), Some("/e2e.Echo/Say"));
        assert_eq!(c.authority.as_deref(), Some("127.0.0.1"));
        assert_eq!(c.streams, 1);
    }

    #[test]
    fn truncations_never_panic() {
        for n in 0..CURL_GRPC.len() {
            assert_ne!(client(&CURL_GRPC[..n]), Detect::No, "{n}");
        }
        assert_eq!(client(b"GET / HTTP/1.1\r\n"), Detect::No);
    }

    #[test]
    fn padded_and_priority_fragments() {
        assert_eq!(
            headers_fragment(&[2, 0x82, 0, 0], FLAG_PADDED),
            Some(&[0x82][..])
        );
        assert_eq!(
            headers_fragment(&[0, 0, 0, 0, 0, 0x82], FLAG_PRIORITY),
            Some(&[0x82][..])
        );
        assert_eq!(headers_fragment(&[9, 0x82], FLAG_PADDED), None);
    }
}
