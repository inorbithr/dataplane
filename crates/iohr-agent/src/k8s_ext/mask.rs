//! Masking for text that comes back from the cluster (event messages, change causes):
//! secrets and tokens through [`crate::redact`], and email and IP addresses, which are
//! personal or topology data the facts do not need.

use std::net::{IpAddr, Ipv4Addr};

/// What an email address becomes.
pub const EMAIL: &str = "[email]";
/// What an IP address becomes.
pub const IP: &str = "[ip]";
/// Longest masked text kept, in characters.
pub const MAX_CHARS: usize = 512;

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@' | ':')
}

fn is_email(w: &str) -> bool {
    let Some((local, domain)) = w.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// The word with an address masked, or `None` when it holds none.
fn mask_word(w: &str) -> Option<String> {
    let core = w.trim_end_matches(['.', ':']);
    let tail = &w[core.len()..];
    if is_email(core) {
        return Some(format!("{EMAIL}{tail}"));
    }
    if core.parse::<IpAddr>().is_ok() {
        return Some(format!("{IP}{tail}"));
    }
    // 10.0.0.1:8080
    if let Some((host, port)) = core.rsplit_once(':')
        && host.parse::<Ipv4Addr>().is_ok()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(format!("{IP}:{port}{tail}"));
    }
    None
}

/// `text` with secrets, tokens, emails and IP addresses masked, cut to [`MAX_CHARS`].
#[must_use]
pub fn mask(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            match mask_word(word) {
                Some(m) => out.push_str(&m),
                None => out.push_str(word),
            }
            word.clear();
        }
    };
    for c in text.chars() {
        if word_char(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            // Brackets around IPv6 ([::1]:80) are kept; the inside is a word.
            out.push(if c.is_control() { ' ' } else { c });
        }
    }
    flush(&mut word, &mut out);
    let r = crate::redact::redact(&out);
    if r.chars().count() > MAX_CHARS {
        let mut cut: String = r.chars().take(MAX_CHARS).collect();
        cut.push('…');
        cut
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_and_addresses_are_masked() {
        assert_eq!(
            mask(
                "Readiness probe failed: Get \"http://10.42.0.15:8080/healthz\": dial tcp 10.42.0.15:8080: connect: connection refused"
            ),
            "Readiness probe failed: Get \"http://[ip]:8080/healthz\": dial tcp [ip]:8080: connect: connection refused"
        );
        assert_eq!(mask("owner ana.k@example.com."), "owner [email].");
        assert_eq!(
            mask("peer fe80::1 and [2001:db8::7]:443"),
            "peer [ip] and [[ip]]:443"
        );
        assert_eq!(
            mask("Pulled image nginx:1.27 in 2.1s"),
            "Pulled image nginx:1.27 in 2.1s"
        );
        assert_eq!(
            mask("Scaled up replica set web-7d9f to 3"),
            "Scaled up replica set web-7d9f to 3"
        );
        assert_eq!(mask("at 10:30:00 on node-a"), "at 10:30:00 on node-a");
    }

    #[test]
    fn planted_secrets_do_not_survive() {
        let planted = [
            "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJzeXN0ZW06c2EifQ.c2lnbmF0dXJlc2lnbmF0dXJl",
            "ghp_0123456789abcdefghijABCDEFGHIJ012345",
            "AKIAIOSFODNN7EXAMPLE",
            "password=Zx9!kq2Lr8#vT4mW",
        ];
        for s in planted {
            let m = mask(&format!("Error: env check failed with {s} while starting"));
            let secret = s.rsplit(['=', ' ']).next().unwrap();
            assert!(!m.contains(secret), "{s} survived as {m}");
        }
    }

    #[test]
    fn long_text_is_cut_and_control_characters_go() {
        let m = mask(&format!("a\u{1b}[31m{}", "x ".repeat(2000)));
        assert!(m.chars().count() <= MAX_CHARS + 1 && !m.contains('\u{1b}'));
    }
}
