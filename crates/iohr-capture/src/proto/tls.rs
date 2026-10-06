//! TLS: the `ClientHello`'s server name (SNI), offered ALPN protocols and whether TLS 1.3 is
//! offered. Only the plaintext `ClientHello` is read; nothing after the handshake is.
//!
//! A `ClientHello` can span several TCP segments (post-quantum key shares make it longer than
//! one), and only a prefix of each is copied. The walk stops where the contiguous bytes
//! end and reports what it found by then; extensions are usually ordered with the server
//! name early, but a hello cut before it reports no SNI (`truncated`).

use super::Detect;

/// What a `ClientHello` offered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ClientHello {
    pub(crate) sni: Option<String>,
    /// The first ALPN protocol offered (`h2`, `http/1.1`, ...).
    pub(crate) alpn: Option<String>,
    /// TLS 1.3 offered in `supported_versions`.
    pub(crate) tls13: bool,
    /// The bytes ended before the extensions did.
    pub(crate) truncated: bool,
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<usize> {
        let v = u16::from_be_bytes([*self.b.get(self.at)?, *self.b.get(self.at + 1)?]);
        self.at += 2;
        Some(usize::from(v))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }
}

/// Recognises a TLS handshake record carrying a `ClientHello`.
pub(crate) fn client_hello(buf: &[u8]) -> Detect<ClientHello> {
    // Record: type 22 (handshake), version 3.x, length; handshake type 1 (`ClientHello`).
    let head = [0x16u8, 0x03];
    let n = buf.len().min(2);
    if buf.get(..n) != head.get(..n) {
        return Detect::No;
    }
    if buf.len() < 9 {
        return Detect::NeedMore;
    }
    if buf.get(2).is_none_or(|v| *v > 0x04) || buf.get(5) != Some(&0x01) {
        return Detect::No;
    }
    let mut c = Cursor { b: buf, at: 9 };
    let mut hello = ClientHello::default();
    // version(2) random(32)
    if c.take(34).is_none() {
        return if buf.len() < 200 {
            Detect::NeedMore
        } else {
            Detect::No
        };
    }
    let Some(walked) = walk(&mut c, &mut hello) else {
        // Ran out of bytes before the extensions: wait for more, or report what we have.
        hello.truncated = true;
        return Detect::Yes(hello);
    };
    hello.truncated = !walked;
    Detect::Yes(hello)
}

/// Walks session id, ciphers, compression and extensions. `None`: ran out before the
/// extensions; `Some(false)`: ran out inside them; `Some(true)`: complete.
fn walk(c: &mut Cursor<'_>, hello: &mut ClientHello) -> Option<bool> {
    let sid = usize::from(c.u8()?);
    c.take(sid)?;
    let ciphers = c.u16()?;
    c.take(ciphers)?;
    let comp = usize::from(c.u8()?);
    c.take(comp)?;
    let Some(ext_len) = c.u16() else {
        return Some(false);
    };
    let end = c.at.saturating_add(ext_len);
    while c.at + 4 <= end {
        let (Some(kind), Some(len)) = (c.u16(), c.u16()) else {
            return Some(false);
        };
        let Some(data) = c.take(len) else {
            return Some(false);
        };
        match kind {
            0 => hello.sni = server_name(data),
            16 => hello.alpn = first_alpn(data),
            43 => hello.tls13 = offers_tls13(data),
            _ => {}
        }
    }
    Some(true)
}

fn server_name(data: &[u8]) -> Option<String> {
    let mut c = Cursor { b: data, at: 0 };
    let list = c.u16()?;
    let end = c.at + list;
    while c.at < end {
        let kind = c.u8()?;
        let len = c.u16()?;
        let name = c.take(len)?;
        if kind == 0 {
            let valid = !name.is_empty()
                && name.len() <= 253
                && name
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            return valid.then(|| String::from_utf8_lossy(name).to_ascii_lowercase());
        }
    }
    None
}

fn first_alpn(data: &[u8]) -> Option<String> {
    let mut c = Cursor { b: data, at: 0 };
    let _list = c.u16()?;
    let len = usize::from(c.u8()?);
    let p = c.take(len)?;
    p.iter()
        .all(u8::is_ascii_graphic)
        .then(|| String::from_utf8_lossy(p).into_owned())
}

fn offers_tls13(data: &[u8]) -> bool {
    let Some((&len, rest)) = data.split_first() else {
        return false;
    };
    rest.get(..usize::from(len))
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .contains(&[0x03, 0x04])
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENSSL: &[u8] = include_bytes!("../../tests/fixtures/tls.bin");

    #[test]
    fn openssl_client_hello() {
        let Detect::Yes(h) = client_hello(OPENSSL) else {
            panic!("not recognised")
        };
        assert_eq!(h.sni.as_deref(), Some("tls-e2e.example"));
        assert_eq!(h.alpn.as_deref(), Some("h2"));
        assert!(h.tls13);
        assert!(!h.truncated);
    }

    #[test]
    fn truncations_never_panic_and_cut_hellos_say_so() {
        for n in 0..OPENSSL.len() {
            match client_hello(&OPENSSL[..n]) {
                Detect::No => panic!("a prefix of a ClientHello is never `No` ({n})"),
                Detect::Yes(h) => assert!(h.truncated || n == OPENSSL.len()),
                Detect::NeedMore => {}
            }
        }
        assert_eq!(client_hello(b"GET / HTTP/1.1\r\n"), Detect::No);
        assert_eq!(
            client_hello(&[0x16, 0x03, 0x03, 0, 5, 0x02, 0, 0, 1]),
            Detect::No
        );
    }

    #[test]
    fn rejects_bad_names() {
        let mut ext = vec![0, 0];
        let name = b"bad name\x00";
        let len = u16::try_from(name.len() + 3).unwrap_or(0);
        ext[..2].copy_from_slice(&len.to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
        ext.extend_from_slice(name);
        assert_eq!(server_name(&ext), None);
    }
}
