//! Randomness for secrets: page tokens, session ids, OAuth state, verifiers and nonces,
//! local secrets and keys.
//!
//! None of these is safe when the operating system cannot supply randomness, so every
//! helper here stops the process rather than hand out a predictable value.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroize as _;

/// Fills `buf` from the operating system's random source, or stops the process.
pub fn fill(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        tracing::error!("the operating system has no randomness; stopping");
        std::process::abort();
    }
}

/// `n` random bytes, URL-safe base64 without padding.
#[must_use]
pub fn urlsafe(n: usize) -> String {
    let mut buf = vec![0_u8; n];
    fill(&mut buf);
    let s = URL_SAFE_NO_PAD.encode(&buf);
    buf.zeroize();
    s
}

/// `n` random bytes as lower-case hex (`2 * n` characters).
#[must_use]
pub fn hex(n: usize) -> String {
    let mut buf = vec![0_u8; n];
    fill(&mut buf);
    let s = to_hex(&buf);
    buf.zeroize();
    s
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_have_the_asked_length_and_differ() {
        let (a, b) = (hex(32), hex(32));
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        let u = urlsafe(24);
        assert_eq!(u.len(), 32);
        assert!(!u.contains(['+', '/', '=']));
        assert_ne!(u, urlsafe(24));
        assert_eq!(to_hex(&[0, 0xab, 0x10]), "00ab10");
    }
}
