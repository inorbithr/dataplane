//! Redaction for everything the local page shows: log lines, error messages, anything a
//! platform frame put into the agent's state. It runs over each value when it is recorded
//! and again over every response body the admin page sends, so a secret that reached the
//! agent's memory by any path is replaced before a browser sees it.
//!
//! No regular-expression engine (a small dependency set): one pass over the text finds
//! the spans of
//!
//! - PEM blocks (`-----BEGIN … PRIVATE KEY-----` to its `END` line, any key or token kind);
//! - the value after a secret-looking key (`password=`, `"access_token": "…"`,
//!   `Authorization: …`) and after `Bearer` / `Basic`;
//! - tokens with a known shape: JWTs, enrollment tokens (`ioe_…`), AWS access keys, GitHub,
//!   GitLab, Slack, Stripe, Google and OpenAI-style keys, Vault tokens;
//! - long high-entropy words (mixed case and digits, 32 characters or more); hashes written
//!   as `sha256:<hex>` and lower-case hex are left alone, so policy hashes, content hashes
//!   and ids stay readable;
//! - exact values registered at run time ([`register`]): the admin page's own token and an
//!   enrollment token from the environment.

use std::sync::{Mutex, OnceLock};

/// What a redacted span becomes.
pub const MARK: &str = "[redacted]";

/// Most exact values kept for [`register`].
const MAX_REGISTERED: usize = 16;

/// Keys whose value is a secret, matched case-insensitively as a suffix of the key name
/// (`db_password`, `X-Api-Key`, `client_assertion`).
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "client_assertion",
    "assertion",
    "passphrase",
    "session_id",
    "sessionid",
];

/// Prefixes of tokens with a known shape, with the shortest tail that makes one.
const PREFIXES: &[(&str, usize)] = &[
    ("ioe_", 16),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 20),
    ("glpat-", 16),
    ("xoxb-", 10),
    ("xoxa-", 10),
    ("xoxp-", 10),
    ("xoxr-", 10),
    ("xoxs-", 10),
    ("sk_live_", 16),
    ("rk_live_", 16),
    ("sk_test_", 16),
    ("sk-", 20),
    ("AIza", 30),
    ("hvs.", 20),
    ("hvb.", 20),
    ("AKIA", 16),
    ("ASIA", 16),
    ("npm_", 30),
    ("pypi-", 30),
];

fn registered() -> &'static Mutex<Vec<String>> {
    static R: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

/// Remembers an exact secret value (8 characters or more) so it is redacted wherever it
/// appears. Bounded: the oldest is forgotten past [`MAX_REGISTERED`].
pub fn register(value: &str) {
    if value.len() < 8 {
        return;
    }
    let mut r = match registered().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if r.iter().any(|v| v == value) {
        return;
    }
    if r.len() == MAX_REGISTERED {
        r.remove(0);
    }
    r.push(value.to_owned());
}

/// `text` with every secret-looking span replaced by [`MARK`].
#[must_use]
pub fn redact(text: &str) -> String {
    let mut spans = Vec::new();
    pem_spans(text, &mut spans);
    keyed_spans(text, &mut spans);
    word_spans(text, &mut spans);
    {
        let r = match registered().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        for v in r.iter() {
            let mut from = 0;
            while let Some(i) = text.get(from..).and_then(|t| t.find(v.as_str())) {
                spans.push((from + i, from + i + v.len()));
                from += i + v.len();
            }
        }
    }
    if spans.is_empty() {
        return text.to_owned();
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in spans {
        if e <= at {
            continue;
        }
        let s = s.max(at);
        out.push_str(text.get(at..s).unwrap_or_default());
        out.push_str(MARK);
        at = e;
    }
    out.push_str(text.get(at..).unwrap_or_default());
    out
}

/// Whether `text` holds anything [`redact`] would replace.
#[must_use]
pub fn has_secret(text: &str) -> bool {
    redact(text) != text
}

fn pem_spans(text: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(i) = text.get(from..).and_then(|t| t.find("-----BEGIN ")) {
        let start = from + i;
        let rest = text.get(start..).unwrap_or_default();
        // The block ends after the END line's closing dashes, or at the end of the text.
        let end = rest.find("-----END ").map_or(text.len(), |j| {
            let after = start + j + "-----END ".len();
            text.get(after..)
                .and_then(|t| t.find("-----"))
                .map_or(text.len(), |k| after + k + 5)
        });
        let header = rest.get(..rest.find('\n').unwrap_or(rest.len()).min(80));
        let is_cert = header.is_some_and(|h| h.contains("CERTIFICATE") && !h.contains("PRIVATE"));
        if !is_cert {
            spans.push((start, end));
        }
        from = end.max(start + 1);
    }
}

const fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b'~')
}

const fn ends_value(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\'' | b',' | b'&' | b';' | b'}' | b']' | b')' | b'<' | b'>' | b'`'
        )
}

/// `key = value`, `key: value`, `"key": "value"`, and `Bearer value`.
#[allow(clippy::many_single_char_names)] // a byte scanner
fn keyed_spans(text: &str, spans: &mut Vec<(usize, usize)>) {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        if !(b.get(i).copied().is_some_and(|c| c.is_ascii_alphabetic())) {
            i += 1;
            continue;
        }
        let ks = i;
        while i < n
            && b.get(i)
                .copied()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            i += 1;
        }
        let key = text.get(ks..i).unwrap_or_default().to_ascii_lowercase();
        let scheme = key == "bearer" || key == "basic";
        let secret_key = SECRET_KEYS.iter().any(|k| key.ends_with(k));
        if !scheme && !secret_key {
            continue;
        }
        let mut j = i;
        if secret_key {
            // Closing quote of a JSON key, spaces, then `=` or `:`.
            if matches!(b.get(j), Some(b'"' | b'\'')) {
                j += 1;
            }
            while matches!(b.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
            if !matches!(b.get(j), Some(b'=' | b':')) {
                continue;
            }
            j += 1;
            // `key: Bearer xyz`: the scheme is handled when the scan reaches it.
            while matches!(b.get(j), Some(b' ' | b'\t')) {
                j += 1;
            }
        } else {
            if !matches!(b.get(j), Some(b' ')) {
                continue;
            }
            j += 1;
        }
        // A quote, or a quote escaped inside a JSON string (`\"`), which must stay whole.
        let escaped = b.get(j) == Some(&b'\\') && matches!(b.get(j + 1), Some(b'"' | b'\''));
        if escaped {
            j += 1;
        }
        let quoted = matches!(b.get(j), Some(b'"' | b'\''));
        if quoted {
            j += 1;
        }
        let vs = j;
        // A structured value (`{`, `[`) or nothing: not a secret value.
        if matches!(b.get(vs), None | Some(b'{' | b'[' | b'\n' | b'\r')) {
            continue;
        }
        let mut ve = vs;
        if quoted {
            while ve < n && !matches!(b.get(ve), Some(b'"' | b'\'' | b'\n' | b'\\')) {
                ve += 1;
            }
        } else {
            while ve < n && !b.get(ve).copied().is_some_and(ends_value) {
                ve += 1;
            }
        }
        let value = text.get(vs..ve).unwrap_or_default();
        if secret_key
            && (value.eq_ignore_ascii_case("bearer") || value.eq_ignore_ascii_case("basic"))
        {
            // `Authorization: Bearer …`: let the scheme rule take the value after it.
            i = vs;
            continue;
        }
        // `Bearer` followed by an ordinary word ("bearer of", "basic check") is prose.
        let short_prose =
            scheme && (value.len() < 12 || !value.bytes().any(|c| c.is_ascii_digit()));
        if ve > vs
            && !short_prose
            && value != MARK
            && !is_harmless_value(value)
            && !is_reference(value)
        {
            spans.push((vs, ve));
        }
        i = ve.max(i);
    }
}

/// A secret reference (`env:NAME`, `file:/path`, `vault:path`, `k8s:name/key`): where a
/// secret lives, which the policy asks for in place of the value. Not a secret itself.
fn is_reference(v: &str) -> bool {
    ["env:", "file:", "vault:", "k8s:"].iter().any(|p| {
        v.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && !rest.bytes().any(|c| c.is_ascii_whitespace()))
    })
}

/// A JSON answer with every string value redacted on its own, so the answer stays JSON
/// (redacting the serialized text could cut through an escaped quote). A value under a
/// secret-looking key is replaced whole, unless it is a secret reference. Text that is
/// not JSON is redacted as text.
#[must_use]
pub fn redact_json(body: &str) -> String {
    fn walk(v: &mut serde_json::Value, secret_key: bool) {
        match v {
            serde_json::Value::String(s) => {
                *s = if secret_key && !is_reference(s) && !is_harmless_value(s) && !s.is_empty() {
                    MARK.to_owned()
                } else {
                    redact(s)
                };
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk(x, secret_key)),
            serde_json::Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    let k = k.to_ascii_lowercase();
                    walk(x, SECRET_KEYS.iter().any(|s| k.ends_with(s)));
                }
            }
            _ => {}
        }
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(mut v) => {
            walk(&mut v, false);
            serde_json::to_string(&v).unwrap_or_else(|_| redact(body))
        }
        Err(_) => redact(body),
    }
}

/// Values after a secret-looking key that are not secrets: booleans, counts, nothing,
/// and the marker itself.
fn is_harmless_value(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "none" | "yes" | "no" | "[redacted]" | "<redacted>"
    ) || v.bytes().all(|c| c.is_ascii_digit())
}

/// Known token shapes and long high-entropy words.
#[allow(clippy::many_single_char_names)] // a byte scanner: text, bytes, length, index
fn word_spans(text: &str, spans: &mut Vec<(usize, usize)>) {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        if !b.get(i).copied().is_some_and(is_word) {
            i += 1;
            continue;
        }
        let s = i;
        while i < n && b.get(i).copied().is_some_and(is_word) {
            i += 1;
        }
        let w = text.get(s..i).unwrap_or_default();
        // The path or name of a secret reference (`file:/…`, `vault:…`) says where a
        // secret lives, not what it is.
        let before = text.get(..s).unwrap_or_default();
        if ["env:", "file:", "vault:", "k8s:"]
            .iter()
            .any(|p| before.ends_with(p))
        {
            continue;
        }
        if let Some(off) = secret_in_word(w) {
            spans.push((s + off.0, s + off.1));
        }
    }
}

/// The span of a secret inside one word, if there is one.
fn secret_in_word(w: &str) -> Option<(usize, usize)> {
    for (p, min) in PREFIXES {
        let mut from = 0;
        while let Some(i) = w.get(from..).and_then(|t| t.find(p)) {
            let at = from + i;
            // A prefix must start the word or follow a separator (`token=ghp_…` is caught
            // as a key; `x.ghp_…` here).
            let boundary = at == 0
                || w.as_bytes()
                    .get(at - 1)
                    .is_some_and(|c| !c.is_ascii_alphanumeric());
            let tail = w
                .get(at + p.len()..)
                .unwrap_or_default()
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
                .count();
            if boundary && tail >= *min {
                return Some((at, at + p.len() + tail));
            }
            from = at + p.len();
        }
    }
    // JWT: three base64url parts, the first two starting with `eyJ`.
    if let Some(i) = w.find("eyJ") {
        let parts: Vec<&str> = w.get(i..).unwrap_or_default().splitn(4, '.').collect();
        if parts.len() >= 3
            && parts
                .get(1)
                .is_some_and(|p| p.starts_with("eyJ") || p.len() > 8)
            && parts.iter().take(3).all(|p| p.len() >= 4)
        {
            return Some((i, w.len()));
        }
    }
    high_entropy(w).then_some((0, w.len()))
}

/// Long, mixed-case, with digits, and spread over many symbols: a key or token, not a word,
/// a path, an id or a hash.
fn high_entropy(w: &str) -> bool {
    let core = w.trim_matches(|c: char| matches!(c, '.' | '-' | '/' | '='));
    if core.len() < 32 || core.starts_with("sha256:") || core.contains("://") {
        return false;
    }
    // Paths and dotted names split into short parts; a secret is one long run.
    if core.split(['/', '.']).all(|part| part.len() < 24) {
        return false;
    }
    let (mut up, mut low, mut dig) = (0usize, 0usize, 0usize);
    let mut seen = [0u32; 128];
    for c in core.bytes() {
        if c.is_ascii_uppercase() {
            up += 1;
        } else if c.is_ascii_lowercase() {
            low += 1;
        } else if c.is_ascii_digit() {
            dig += 1;
        }
        if let Some(s) = seen.get_mut(usize::from(c & 0x7f)) {
            *s += 1;
        }
    }
    if up < 2 || low < 2 || dig < 2 {
        return false;
    }
    #[allow(clippy::cast_precision_loss)]
    let len = core.len() as f64;
    let entropy: f64 = seen
        .iter()
        .filter(|&&k| k > 0)
        .map(|&k| {
            let p = f64::from(k) / len;
            -p * p.log2()
        })
        .sum();
    entropy >= 4.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_answer_stays_json_and_references_stay_readable() {
        let text = "[console.oidc]\nclient_secret = \"file:/var/run/iohr/oidc-secret\"\nissuer = \"https://login.example.com\"\npassword = \"hunter2hunter2\"\n";
        let body =
            serde_json::json!({ "text": text, "access_token": "abc.def.ghi-123456", "n": 3 })
                .to_string();
        let out = redact_json(&body);
        let v: serde_json::Value = serde_json::from_str(&out).expect("still JSON");
        let t = v["text"].as_str().unwrap_or_default();
        assert!(
            t.contains("client_secret = \"file:/var/run/iohr/oidc-secret\""),
            "{t}"
        );
        assert!(!t.contains("hunter2"), "{t}");
        assert_eq!(v["access_token"], MARK);
        assert_eq!(v["n"], 3);
        // Text redaction no longer cuts through an escaped quote either.
        let r = redact(&body);
        assert!(serde_json::from_str::<serde_json::Value>(&r).is_ok(), "{r}");
    }

    #[test]
    fn a_secret_reference_is_not_a_secret() {
        assert_eq!(
            redact("client_secret = \"env:OIDC_SECRET\""),
            "client_secret = \"env:OIDC_SECRET\""
        );
        assert_eq!(
            redact("token=vault:kv/agent/token"),
            "token=vault:kv/agent/token"
        );
        assert_eq!(redact("token=env: x"), format!("token={MARK} x"));
        // A path with long mixed parts after `file:` stays; the same word alone does not.
        let path = "/private/tmp/Session-2eb4edda10df49a08bf1659bdfece5a7XyZ/T/oidc-secret";
        assert_eq!(
            redact(&format!("allow = [\"file:{path}\"]")),
            format!("allow = [\"file:{path}\"]")
        );
        assert_ne!(redact(&format!("x {path}")), format!("x {path}"));
    }

    #[test]
    fn redacts_what_it_should() {
        let cases = [
            "password=hunter2hunter2",
            "db_password: 's3cr3t-value'",
            r#"{"access_token": "abc.def.ghi-123"}"#,
            "Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlX3Rlc3Q",
            "token ioe_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 used",
            "key AKIAIOSFODNN7EXAMPLE here",
            "gh ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 x",
            "random Zx8Kp2Lm9Qr4Tv7Wy1Ab3Cd5Ef6Gh0JkLm2N end",
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----",
            "x-api-key=0123456789abcdef",
            "xoxb-123456789012-abcdefABCDEF",
        ];
        for c in cases {
            let r = redact(c);
            assert!(r.contains(MARK), "{c} -> {r}");
            assert!(has_secret(c), "{c}");
        }
        assert_eq!(
            redact("password=hunter2hunter2 and more"),
            "password=[redacted] and more"
        );
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        let keep = [
            "policy sha256:7c81ff5ded2cedfe80d09f171e264263bd45f8cccfc7728b207209d3e4f81cc7",
            "agent agt_01M4E7PEH00EX92AR21FQC1WN2 connected",
            "/Users/nevio/Library/Application Support/InOrbit/checks.toml",
            "could not reach the token endpoint: connection refused",
            "the secret reference is not allowed",
            "https://api.inorbit.hr/v1/agents/session",
            "job 0192f1e2-7c3a-7b4d-8e9f-0a1b2c3d4e5f finished",
            "a bearer of bad news",
            r#"{"secrets": {"allow": []}, "tokens": 3}"#,
            "max_jobs_per_minute = 120",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ];
        for k in keep {
            assert_eq!(redact(k), k, "{k}");
        }
    }

    #[test]
    fn registered_values_are_redacted_anywhere() {
        register("zzq-registered-value-81");
        assert_eq!(redact("x zzq-registered-value-81y"), format!("x {MARK}y"));
    }
}
