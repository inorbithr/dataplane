//! HTTP/1.x: the request line and `Host` of the first request on a connection (client
//! side), and the status of the first response (server side). Later requests on a
//! keep-alive connection are not seen in phase 1: only a flow's first packets are copied.

use super::{Detect, clean_host, path_template};

/// Methods recognised; anything else is not HTTP/1.
const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// One request, as counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: &'static str,
    /// The path with ids replaced and no query (see `path_template`).
    pub(crate) path: String,
    /// The `Host` header, lower-cased without port, if present in the copied bytes.
    pub(crate) host: Option<String>,
    /// `HTTP/1.0` or `HTTP/1.1`.
    pub(crate) version: &'static str,
}

/// Recognises the start of an HTTP/1 request.
pub(crate) fn request(buf: &[u8]) -> Detect<Request> {
    let Some(sp) = buf.iter().take(8).position(|&b| b == b' ') else {
        // Could still be a method that has not arrived in full.
        let partial = buf.is_empty()
            || buf.len() < 8 && METHODS.iter().any(|m| m.as_bytes().starts_with(buf));
        return if partial {
            Detect::NeedMore
        } else {
            Detect::No
        };
    };
    let Some(method) = METHODS
        .iter()
        .find(|m| m.as_bytes() == buf.get(..sp).unwrap_or_default())
    else {
        return Detect::No;
    };
    let Some(eol) = find(buf, b"\r\n") else {
        // The request line is cut (the copy is 512 bytes): that is still HTTP/1, with an
        // unknown path, if what we have so far looks right.
        return if buf.len() >= 64 {
            Detect::Yes(Request {
                method,
                path: "unknown".into(),
                host: None,
                version: "HTTP/1.x",
            })
        } else {
            Detect::NeedMore
        };
    };
    let line = buf.get(sp + 1..eol).unwrap_or_default();
    let Some(sp2) = line.iter().rposition(|&b| b == b' ') else {
        return Detect::No;
    };
    let version = match line.get(sp2 + 1..) {
        Some(b"HTTP/1.1") => "HTTP/1.1",
        Some(b"HTTP/1.0") => "HTTP/1.0",
        _ => return Detect::No,
    };
    let target = String::from_utf8_lossy(line.get(..sp2).unwrap_or_default());
    let headers = buf.get(eol + 2..).unwrap_or_default();
    let host = header(headers, b"host").and_then(|h| clean_host(&String::from_utf8_lossy(h)));
    Detect::Yes(Request {
        method,
        path: path_template(&target),
        host,
        version,
    })
}

/// Recognises the start of an HTTP/1 response: `HTTP/1.x NNN`.
pub(crate) fn response(buf: &[u8]) -> Detect<u16> {
    if buf.len() < 12 {
        return if b"HTTP/1.".starts_with(buf.get(..buf.len().min(7)).unwrap_or_default()) {
            Detect::NeedMore
        } else {
            Detect::No
        };
    }
    if !buf.starts_with(b"HTTP/1.") || buf.get(8) != Some(&b' ') {
        return Detect::No;
    }
    let code = buf.get(9..12).unwrap_or_default();
    if !code.iter().all(u8::is_ascii_digit) {
        return Detect::No;
    }
    let status = code
        .iter()
        .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    if (100..=599).contains(&status) {
        Detect::Yes(status)
    } else {
        Detect::No
    }
}

/// The value of the first header named `name` (case-insensitive), within the bytes copied.
fn header<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return None;
        }
        let colon = line.iter().position(|&b| b == b':')?;
        if line.get(..colon)?.eq_ignore_ascii_case(name) {
            return Some(line.get(colon + 1..)?.trim_ascii());
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURL: &[u8] = include_bytes!("../../tests/fixtures/http1.bin");

    #[test]
    fn curl_request() {
        let Detect::Yes(r) = request(CURL) else {
            panic!("not recognised")
        };
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/items/{id}");
        assert_eq!(r.host.as_deref(), Some("web.e2e.test"));
        assert_eq!(r.version, "HTTP/1.1");
        assert!(
            !format!("{r:?}").contains("secret"),
            "the query never survives"
        );
    }

    #[test]
    fn every_truncation_is_safe() {
        for n in 0..CURL.len() {
            match request(&CURL[..n]) {
                Detect::No => panic!("a prefix of a request is never `No` ({n})"),
                Detect::NeedMore | Detect::Yes(_) => {}
            }
        }
        assert_eq!(request(b"SSH-2.0-OpenSSH_9.6\r\n"), Detect::No);
        assert_eq!(request(b"\x16\x03\x01\x02\x00"), Detect::No);
        assert_eq!(request(b"GET / SPDY/3\r\n"), Detect::No);
    }

    #[test]
    fn responses() {
        assert_eq!(response(b"HTTP/1.1 204 No Content\r\n"), Detect::Yes(204));
        assert_eq!(response(b"HTTP/1."), Detect::NeedMore);
        assert_eq!(response(b"HTTP/1.1 9xx bad\r\n"), Detect::No);
        assert_eq!(
            response(b"\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x00\x00"),
            Detect::No
        );
    }
}
