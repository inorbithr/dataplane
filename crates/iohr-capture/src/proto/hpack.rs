//! A bounded HPACK decoder (RFC 7541) for the first header block of an HTTP/2 connection.
//! The dynamic table starts empty there, so the first block decodes without any earlier
//! state; entries it adds are kept (bounded) for the rest of that one block.

use super::huffman::CODES;

/// RFC 7541 Appendix A.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Longest string decoded; longer values are skipped (their names still count).
const MAX_STRING: usize = 1024;
/// Most fields decoded from one block.
const MAX_FIELDS: usize = 64;
/// Most dynamic entries kept.
const MAX_DYNAMIC: usize = 64;

/// Why a block did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// The block ends in the middle of a field.
    Truncated,
    /// Not valid HPACK (bad index, bad Huffman, oversized integer).
    Invalid,
}

/// Decodes one header block into `(name, value)` pairs, bounded.
pub(crate) fn decode(block: &[u8]) -> Result<Vec<(String, String)>, Error> {
    let mut fields = Vec::new();
    let mut dynamic: Vec<(String, String)> = Vec::new();
    let mut at = 0;
    while at < block.len() && fields.len() < MAX_FIELDS {
        let b = block[at];
        if b & 0x80 != 0 {
            let idx = integer(block, &mut at, 7)?;
            fields.push(lookup(idx, &dynamic)?);
        } else if b & 0x40 != 0 {
            let f = literal(block, &mut at, 6, &dynamic)?;
            if dynamic.len() == MAX_DYNAMIC {
                dynamic.pop();
            }
            dynamic.insert(0, f.clone());
            fields.push(f);
        } else if b & 0x20 != 0 {
            let _size = integer(block, &mut at, 5)?;
        } else {
            fields.push(literal(block, &mut at, 4, &dynamic)?);
        }
    }
    Ok(fields)
}

fn lookup(idx: usize, dynamic: &[(String, String)]) -> Result<(String, String), Error> {
    if idx == 0 {
        return Err(Error::Invalid);
    }
    if let Some((n, v)) = STATIC.get(idx - 1) {
        return Ok(((*n).to_owned(), (*v).to_owned()));
    }
    dynamic
        .get(idx - 1 - STATIC.len())
        .cloned()
        .ok_or(Error::Invalid)
}

fn literal(
    block: &[u8],
    at: &mut usize,
    prefix: u32,
    dynamic: &[(String, String)],
) -> Result<(String, String), Error> {
    let idx = integer(block, at, prefix)?;
    let name = if idx == 0 {
        string(block, at)?
    } else {
        lookup(idx, dynamic)?.0
    };
    let value = string(block, at)?;
    Ok((name, value))
}

/// An HPACK integer with an `n`-bit prefix (RFC 7541 5.1).
fn integer(block: &[u8], at: &mut usize, n: u32) -> Result<usize, Error> {
    let max = (1usize << n) - 1;
    let first = usize::from(*block.get(*at).ok_or(Error::Truncated)?) & max;
    *at += 1;
    if first < max {
        return Ok(first);
    }
    let mut value = max;
    let mut shift = 0u32;
    loop {
        let b = *block.get(*at).ok_or(Error::Truncated)?;
        *at += 1;
        if shift > 21 {
            return Err(Error::Invalid);
        }
        value += usize::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

fn string(block: &[u8], at: &mut usize) -> Result<String, Error> {
    let huffman = block.get(*at).ok_or(Error::Truncated)? & 0x80 != 0;
    let len = integer(block, at, 7)?;
    let raw = block
        .get(*at..at.checked_add(len).ok_or(Error::Invalid)?)
        .ok_or(Error::Truncated)?;
    *at += len;
    if len > MAX_STRING {
        return Ok(String::new());
    }
    if huffman {
        huffman_decode(raw)
    } else {
        Ok(String::from_utf8_lossy(raw).into_owned())
    }
}

/// Bit-by-bit Huffman decoding against [`CODES`] (inputs are at most [`MAX_STRING`]).
fn huffman_decode(raw: &[u8]) -> Result<String, Error> {
    let mut out = Vec::with_capacity(raw.len() * 8 / 5);
    let mut code: u32 = 0;
    let mut len: u8 = 0;
    for byte in raw {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len < 5 {
                continue;
            }
            if let Some(sym) = CODES.iter().position(|&(c, l)| l == len && c == code) {
                if sym == 256 {
                    return Err(Error::Invalid);
                }
                out.push(u8::try_from(sym).map_err(|_| Error::Invalid)?);
                code = 0;
                len = 0;
            } else if len > 30 {
                return Err(Error::Invalid);
            }
        }
    }
    // Padding: at most 7 bits, all ones (the EOS prefix).
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(Error::Invalid);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc7541_c3_1_without_huffman() {
        let f = decode(&hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")).unwrap();
        assert_eq!(
            f,
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    #[test]
    fn rfc7541_c4_1_with_huffman() {
        let f = decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")).unwrap();
        assert_eq!(f[3], (":authority".into(), "www.example.com".into()));
    }

    #[test]
    fn rfc7541_c4_2_uses_the_dynamic_table() {
        // The second request of C.4 refers to the first block's dynamic entry (index 62);
        // decoded on its own it is invalid, which is why only a connection's first block
        // yields a path.
        assert_eq!(
            decode(&hex("8286 84be 5886 a8eb 1064 9cbf")),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn truncations_and_garbage() {
        let block = hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff");
        for n in 0..block.len() {
            let _ = decode(&block[..n]);
        }
        assert!(decode(&[0x80]).is_err());
        assert!(decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }
}
