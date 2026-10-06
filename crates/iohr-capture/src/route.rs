//! Route templates: one rule set, shared with the SDKs and the browser recorder (RFC 0070),
//! so wire timing per endpoint and program spans per endpoint land on the same row.
//!
//! The rules, in order (`docs/capture/design-phase2.md`, "Route templates"):
//!
//! 1. `*` stays `*`. An absolute form (`http://host/a`, `https://…`, scheme in any case)
//!    keeps only its path (`/` when it has none). Any other target that does not start
//!    with `/` becomes `{other}`.
//! 2. Everything from the first `?` or `#` is dropped, before any decoding.
//! 3. The path after its leading `/` is split on `/`; empty segments (from `//` or a
//!    trailing slash) are kept as written.
//! 4. Each segment is percent-decoded once: `%HH` with two hex digits becomes that byte,
//!    anything else stays as written. A segment whose decoded bytes are not valid UTF-8
//!    becomes `{id}`. Comparison is case-sensitive.
//! 5. A decoded segment becomes `{id}` when it is all ASCII digits; a UUID (8-4-4-4-12 hex
//!    digits, either case); 16 or more hex digits; a date `YYYY-MM-DD`; 20 or more
//!    characters of the base64url alphabet with at least one digit; or contains `@`.
//! 6. After 8 segments the rest becomes one `{rest}` segment.
//! 7. The template is at most 256 bytes: segments are dropped from the end until
//!    `…/{rest}` fits.
//!
//! The test vectors are `tests/route_vectors.json`, checked against its SHA-256 in
//! `tests/route_vectors.json.sha256`; the SDK's conformance vectors replace that file
//! when they are published (RFC 0070).

/// Most segments kept before `{rest}`.
pub(crate) const MAX_SEGMENTS: usize = 8;
/// Longest template, in bytes.
pub(crate) const MAX_LEN: usize = 256;

const ID: &str = "{id}";
const REST: &str = "{rest}";
const OTHER: &str = "{other}";

/// The route template of a request target (an HTTP/1 request-target or an HTTP/2 `:path`).
pub(crate) fn template(target: &str) -> String {
    let cut = target.find(['?', '#']).map_or(target, |i| &target[..i]);
    if cut == "*" {
        return "*".to_owned();
    }
    let path = match strip_scheme(cut) {
        Some(rest) => rest.find('/').map_or("/", |i| &rest[i..]),
        None => cut,
    };
    let Some(path) = path.strip_prefix('/') else {
        return OTHER.to_owned();
    };
    let raw: Vec<&str> = path.split('/').collect();
    let mut segments: Vec<String> = raw.iter().take(MAX_SEGMENTS).map(|s| classify(s)).collect();
    if raw.len() > MAX_SEGMENTS {
        segments.push(REST.to_owned());
    }
    let joined = join(&segments);
    if joined.len() <= MAX_LEN {
        return joined;
    }
    // Too long: drop segments from the end until the prefix plus `/{rest}` fits.
    let mut keep = segments.len();
    while keep > 0 {
        keep -= 1;
        let mut s = join(&segments[..keep]);
        s.push('/');
        s.push_str(REST);
        if s.len() <= MAX_LEN {
            return s;
        }
    }
    format!("/{REST}")
}

fn join(segments: &[String]) -> String {
    let mut out = String::with_capacity(MAX_LEN);
    for s in segments {
        out.push('/');
        out.push_str(s);
    }
    out
}

/// `http://` or `https://` (any case): the rest after `://`.
fn strip_scheme(t: &str) -> Option<&str> {
    for scheme in ["http://", "https://"] {
        if t.len() >= scheme.len()
            && t.get(..scheme.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(scheme))
        {
            return t.get(scheme.len()..);
        }
    }
    None
}

fn classify(raw: &str) -> String {
    let Ok(decoded) = String::from_utf8(percent_decode(raw)) else {
        return ID.to_owned();
    };
    if is_id(&decoded) {
        ID.to_owned()
    } else {
        decoded
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|x| hex(*x)),
                b.get(i + 2).and_then(|x| hex(*x)),
            )
        {
            out.push(h << 4 | l);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn is_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let b = s.as_bytes();
    b.iter().all(u8::is_ascii_digit)
        || is_uuid(b)
        || (b.len() >= 16 && b.iter().all(u8::is_ascii_hexdigit))
        || is_date(b)
        || (b.len() >= 20
            && b.iter().any(u8::is_ascii_digit)
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_'))
        || s.contains('@')
}

fn is_uuid(b: &[u8]) -> bool {
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn is_date(b: &[u8]) -> bool {
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../tests/route_vectors.json");
    const VECTORS_SHA256: &str = include_str!("../tests/route_vectors.json.sha256");

    #[test]
    fn vectors() {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let cases = v["vectors"].as_array().unwrap();
        assert!(cases.len() >= 40, "{} vectors", cases.len());
        let mut failed = Vec::new();
        for c in cases {
            let input = c["input"].as_str().unwrap();
            let want = c["template"].as_str().unwrap();
            let got = template(input);
            if got != want {
                failed.push(format!("{input:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(failed.is_empty(), "{}", failed.join("\n"));
    }

    #[test]
    fn vectors_match_their_checksum() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(VECTORS.as_bytes());
        let hex = digest.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        let pinned = VECTORS_SHA256.split_whitespace().next().unwrap_or_default();
        assert_eq!(
            hex, pinned,
            "tests/route_vectors.json changed: update route_vectors.json.sha256 in the same change (sha256sum)"
        );
    }

    #[test]
    fn bounded_for_any_input() {
        let long = format!("/{}", "a".repeat(10_000));
        assert!(template(&long).len() <= MAX_LEN);
        let many = "/x".repeat(1000);
        assert_eq!(template(&many), "/x/x/x/x/x/x/x/x/{rest}");
        for s in [
            "",
            "%",
            "%%%",
            "/%ff%fe",
            "/\u{0}",
            "?",
            "#",
            "//",
            "http://",
            "HTTPS://h",
        ] {
            assert!(template(s).len() <= MAX_LEN, "{s:?}");
        }
    }
}
