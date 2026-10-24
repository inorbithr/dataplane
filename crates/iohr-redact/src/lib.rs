//! Redaction of secrets in text: log lines, error messages, command lines, anything a
//! worker or agent reports. Shared by the InOrbit agent (inorbithr/dataplane) and Atlas
//! core (inorbithr/core, the infra service), so the first pass on the machine and the
//! second pass in the service apply the same rules (RFC 0150).
//!
//! No regular-expression engine (a small dependency set), no async runtime and no global
//! state: a [`Redactor`] is a value with its own extra keys, token prefixes and registered
//! exact secrets. One pass over the text finds the spans of
//!
//! - PEM blocks (`-----BEGIN … PRIVATE KEY-----` to its `END` line, any key or token kind);
//! - the value after a secret-looking key (`password=`, `"access_token": "…"`,
//!   `Authorization: …`, `AWS_SECRET_ACCESS_KEY=…`) and after `Bearer` / `Basic`;
//! - the argument of a secret flag, separated by a space: `--password foo`,
//!   `--api-key foo`, and `-p foo` (not a port or a path);
//! - the value of a name/value pair whose name is secret: `{"name": "DB_PASSWORD",
//!   "value": "…"}` and the same in YAML;
//! - the password of a URL's user information (`postgres://app:…@host/db`);
//! - tokens with a known shape: JWTs, enrollment tokens (`ioe_…`), AWS access keys,
//!   GitHub, GitLab, Slack, Stripe, Google and OpenAI-style keys, Vault tokens;
//! - long high-entropy words (mixed case and digits, 32 characters or more); hashes
//!   written as `sha256:<hex>` and lower-case hex are left alone, so policy hashes, content
//!   hashes and ids stay readable;
//! - exact values registered with [`Redactor::register`] or [`Redactor::with_exact`].
//!
//! With the `json` feature, [`Redactor::redact_json`] does the same over a
//! `serde_json::Value` (or a JSON body as text), by key and by name/value pair.
//!
//! Changing a key or prefix list is a compliance control change (access to secrets in
//! logs): say so in the commit.
//!
//! Exact values are kept without a cap: an owner registers its key files once and must
//! never lose one.

use std::sync::Mutex;

#[cfg(feature = "json")]
mod json;

/// What a redacted span becomes.
pub const MARK: &str = "[redacted]";

/// How far after a secret `name` its `value` key may sit, in bytes.
const PAIR_WINDOW: usize = 256;

/// Keys whose value is a secret, matched case-insensitively as a suffix of the key name
/// (`db_password`, `X-Api-Key`, `client_assertion`, `AWS_SECRET_ACCESS_KEY`).
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passcode",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "access-key",
    "accesskey",
    "secret_key",
    "secretkey",
    "signing_key",
    "signing-key",
    "encryption_key",
    "encryption-key",
    "master_key",
    "master-key",
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "private_key",
    "private-key",
    "privatekey",
    "client_assertion",
    "assertion",
    "passphrase",
    "session_id",
    "sessionid",
    "connection_string",
    "connectionstring",
    "database_url",
    "amz-signature",
    "_pass",
    "-pass",
    "key_pem",
    "key-pem",
    "key_data",
    "key-data",
];

/// Keys that are secret only as the whole name: short words that end other words.
const SECRET_KEYS_EXACT: &[&str] = &["pass", "auth", "otp", "pin", "jwt", "dsn"];

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

/// A redactor: the built-in rules plus this instance's extra keys, token prefixes and
/// registered exact values. No global state; share one with an `Arc` when several tasks
/// need the same registered values.
#[derive(Default)]
pub struct Redactor {
    extra_keys: Vec<String>,
    extra_prefixes: Vec<(String, usize)>,
    registered: Mutex<Vec<String>>,
    /// Whether a secret reference (`env:NAME`, `file:/path`) after a secret key is left
    /// readable. Off by default: only a policy that names references asks for it.
    references: bool,
}

impl std::fmt::Debug for Redactor {
    // Counts only: the registered values are secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("extra_keys", &self.extra_keys.len())
            .field("extra_prefixes", &self.extra_prefixes.len())
            .field("registered", &self.lock().len())
            .field("references", &self.references)
            .finish()
    }
}

impl Redactor {
    /// A redactor with the built-in rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        match self.registered.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Also treats these key names (suffixes, case-insensitive, like the built-in list) as
    /// secret. Blank names are ignored.
    #[must_use]
    pub fn with_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for k in keys {
            let k = k.as_ref().trim().to_ascii_lowercase();
            if !k.is_empty() && !self.extra_keys.contains(&k) {
                self.extra_keys.push(k);
            }
        }
        self
    }

    /// Also treats a word that starts with `prefix` and has at least `min_tail` more
    /// token characters as a secret (a customer's own token shape). An empty prefix is
    /// ignored.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str, min_tail: usize) -> Self {
        if !prefix.is_empty() {
            self.extra_prefixes.push((prefix.to_owned(), min_tail));
        }
        self
    }

    /// Leaves a secret reference (`env:NAME`, `file:/path`, `vault:path`, `k8s:name/key`)
    /// readable, as it says where a secret lives and is not one. Off by default, so a value
    /// like `password=env:hunter2` is redacted. A reference whose tail has a known token
    /// shape (a prefix such as `ghp_`, or a JWT) is redacted even with this on, and a
    /// scheme must start a word (`dotenv:` and `keyfile:` are not schemes).
    #[must_use]
    pub const fn with_references(mut self) -> Self {
        self.references = true;
        self
    }

    /// Also redacts this exact value wherever it appears (8 characters or more).
    #[must_use]
    pub fn with_exact(self, value: &str) -> Self {
        self.register(value);
        self
    }

    /// Remembers an exact secret value (8 characters or more; a shorter one would hide
    /// ordinary words) so it is redacted wherever it appears. Every value is kept.
    pub fn register(&self, value: &str) {
        if value.len() < 8 {
            return;
        }
        let mut r = self.lock();
        if !r.iter().any(|v| v == value) {
            r.push(value.to_owned());
        }
    }

    /// Whether `key` (any case) names a secret.
    #[must_use]
    pub fn is_secret_key(&self, key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        // A page token is a cursor into a listing, not a credential.
        if k.ends_with("page_token") || k.ends_with("pagetoken") || k.ends_with("page-token") {
            return false;
        }
        SECRET_KEYS_EXACT.contains(&k.as_str())
            || SECRET_KEYS.iter().any(|s| k.ends_with(s))
            || self.extra_keys.iter().any(|s| k.ends_with(s.as_str()))
            || ["access_key", "access-key", "accesskey"]
                .iter()
                .any(|s| k.contains(s))
    }

    /// `text` with every secret-looking span replaced by [`MARK`].
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        self.redact_also(text, &[])
    }

    /// [`Redactor::redact`] with the rules and registered values of `others` too, all found
    /// in ONE pass over the original text and merged. Two passes in a row would let the
    /// first one cut into a value the second one knows whole.
    #[must_use]
    pub fn redact_also(&self, text: &str, others: &[&Self]) -> String {
        let mut spans = Vec::new();
        self.collect(text, &mut spans);
        for o in others {
            o.collect(text, &mut spans);
        }
        render(text, spans)
    }

    /// Every span of `text` this redactor replaces.
    fn collect(&self, text: &str, spans: &mut Vec<(usize, usize)>) {
        pem_spans(text, spans);
        self.keyed_spans(text, spans);
        self.word_spans(text, spans);
        userinfo_spans(text, spans);
        for v in self.lock().iter() {
            let mut from = 0;
            while let Some(i) = text.get(from..).and_then(|t| t.find(v.as_str())) {
                spans.push((from + i, from + i + v.len()));
                from += i + v.len();
            }
        }
    }

    /// Whether `value` is a secret reference this instance leaves readable.
    fn referenced(&self, value: &str) -> bool {
        self.references
            && is_reference(value)
            && !value
                .split(|c: char| !c.is_ascii() || !is_word(c as u8))
                .any(|w| self.shape_in_word(w).is_some())
    }

    /// Whether `text` holds anything [`Redactor::redact`] would replace.
    #[must_use]
    pub fn has_secret(&self, text: &str) -> bool {
        self.redact(text) != text
    }

    /// `key = value`, `key: value`, `"key": "value"`, `--flag value`, `-p value`,
    /// `Bearer value`, and the `value` that follows a secret `name` (or `key`) within
    /// [`PAIR_WINDOW`] bytes.
    #[allow(clippy::many_single_char_names)] // a byte scanner
    fn keyed_spans(&self, text: &str, spans: &mut Vec<(usize, usize)>) {
        let b = text.as_bytes();
        let n = b.len();
        let mut i = 0;
        // The end of the window in which a `value` key is secret, after a secret `name`.
        let mut paired_until: Option<usize> = None;
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
            if (key == "name" || key == "key")
                && let Some((vs, ve)) = value_after(b, i)
            {
                let named = text.get(vs..ve).unwrap_or_default();
                paired_until = self.is_secret_key(named).then_some(ve + PAIR_WINDOW);
                i = ve.max(i);
                continue;
            }
            let scheme = key == "bearer" || key == "basic";
            let paired = key == "value" && paired_until.is_some_and(|end| ks < end);
            let secret_key = paired || self.is_secret_key(&key);
            let long_flag = secret_key && ks >= 2 && b.get(ks - 2..ks) == Some(b"--");
            let short_flag = is_short_flag(b, ks, text.get(ks..i).unwrap_or_default(), text);
            if !scheme && !secret_key && !short_flag {
                continue;
            }
            let mut found = if secret_key || short_flag {
                value_after(b, i)
            } else if matches!(b.get(i), Some(b' ')) {
                value_at(b, i + 1)
            } else {
                None
            };
            if found.is_none() && (long_flag || short_flag) {
                // `--password foo`, `-p foo`: spaces, then the argument (not another flag).
                let mut j = i;
                while matches!(b.get(j), Some(b' ' | b'\t')) {
                    j += 1;
                }
                if j > i && b.get(j).is_some() && !is_flag_like(b, j) {
                    found = value_at(b, j);
                }
            }
            let Some((vs, ve)) = found else {
                continue;
            };
            if paired {
                paired_until = None;
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
            // `-p 8080` and `mkdir -p /tmp/x`: a port or a path, not a password.
            let not_a_password = short_flag && !secret_key && (is_port(value) || is_path(value));
            if ve > vs
                && !short_prose
                && !not_a_password
                && value != MARK
                && !is_harmless_value(value)
                && !self.referenced(value)
            {
                spans.push((vs, ve));
            }
            i = ve.max(i);
        }
    }

    /// Known token shapes and long high-entropy words.
    #[allow(clippy::many_single_char_names)] // a byte scanner: text, bytes, length, index
    fn word_spans(&self, text: &str, spans: &mut Vec<(usize, usize)>) {
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
            // Only when this instance leaves references readable, and only a real scheme
            // (`dotenv:` and `keyfile:` are not); a known token shape is redacted anyway.
            let before = text.get(..s).unwrap_or_default();
            if self.references && after_scheme(before) {
                if let Some(off) = self.shape_in_word(w) {
                    spans.push((s + off.0, s + off.1));
                }
                continue;
            }
            if let Some(off) = self.secret_in_word(w) {
                spans.push((s + off.0, s + off.1));
            }
        }
    }

    /// The span of a secret inside one word, if there is one.
    fn secret_in_word(&self, w: &str) -> Option<(usize, usize)> {
        self.shape_in_word(w)
            .or_else(|| high_entropy(w).then_some((0, w.len())))
    }

    /// The span of a token with a known shape (a prefix, or a JWT) inside one word.
    fn shape_in_word(&self, w: &str) -> Option<(usize, usize)> {
        let extra = self.extra_prefixes.iter().map(|(p, m)| (p.as_str(), *m));
        for (p, min) in PREFIXES.iter().copied().chain(extra) {
            let mut from = 0;
            while let Some(i) = w.get(from..).and_then(|t| t.find(p)) {
                let at = from + i;
                // A prefix must start the word or follow a separator (`token=ghp_…` is
                // caught as a key; `x.ghp_…` here).
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
                if boundary && tail >= min {
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
        None
    }
}

/// Schemes of a secret reference.
const REFERENCE_SCHEMES: [&str; 4] = ["env:", "file:", "vault:", "k8s:"];

/// Tools whose `-p VALUE` is a password. Other tools use `-p` for a path, a patch or a port
/// (`git log -p`, `mkdir -p`, `docker run -p`).
const PASSWORD_TOOLS: &[&str] = &[
    "mysql",
    "mysqldump",
    "mysqladmin",
    "mysqlpump",
    "mariadb",
    "mariadb-dump",
    "sshpass",
    "login",
    "htpasswd",
];

/// A lone `-p` flag: standalone, after a space or at the start, in a command of a tool
/// that takes its password that way. Lower case only: `-P` is a port.
fn is_short_flag(b: &[u8], ks: usize, key: &str, text: &str) -> bool {
    if key != "p"
        || ks < 1
        || b.get(ks - 1) != Some(&b'-')
        || !(ks == 1 || b.get(ks - 2).is_some_and(u8::is_ascii_whitespace))
    {
        return false;
    }
    // The command so far: from the last newline or command separator.
    let head = text.get(..ks - 1).unwrap_or_default();
    let cmd = head
        .rfind(['\n', ';', '|', '&'])
        .map_or(head, |i| head.get(i + 1..).unwrap_or_default());
    cmd.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
        .any(|w| PASSWORD_TOOLS.contains(&w.to_ascii_lowercase().as_str()))
}

/// Whether the argument at `j` is another flag (`--user`, `-v`) rather than a value.
fn is_flag_like(b: &[u8], j: usize) -> bool {
    if b.get(j) != Some(&b'-') {
        return false;
    }
    if b.get(j + 1) == Some(&b'-') {
        return true;
    }
    // `-v`, `-x ` : one letter. `-s3cr3t` is longer and is a value.
    b.get(j + 1).is_none_or(u8::is_ascii_whitespace)
        || (b.get(j + 1).is_some_and(u8::is_ascii_alphanumeric)
            && b.get(j + 2).is_none_or(u8::is_ascii_whitespace))
}

/// Whether `before` ends in a secret-reference scheme that starts a word.
fn after_scheme(before: &str) -> bool {
    REFERENCE_SCHEMES.iter().any(|p| {
        before.strip_suffix(p).is_some_and(|rest| {
            !rest
                .bytes()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        })
    })
}

/// A port or an address piece: digits, `:` and `.`.
fn is_port(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b':' | b'.'))
}

/// Starts like a path.
fn is_path(v: &str) -> bool {
    v.starts_with(['/', '~']) || v.starts_with("./") || v.starts_with("../")
}

/// `text` with the (possibly overlapping) `spans` replaced by one [`MARK`] each.
fn render(text: &str, mut spans: Vec<(usize, usize)>) -> String {
    if spans.is_empty() {
        return text.to_owned();
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s < last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in merged {
        out.push_str(text.get(at..s).unwrap_or_default());
        out.push_str(MARK);
        at = e;
    }
    out.push_str(text.get(at..).unwrap_or_default());
    out
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

/// The value after a key ending at `i`: an optional closing quote, spaces, `=` or `:`,
/// spaces, then a quoted or bare value. `None` when no separator follows or the value is
/// structured (`{`, `[`) or empty.
fn value_after(b: &[u8], mut j: usize) -> Option<(usize, usize)> {
    if matches!(b.get(j), Some(b'"' | b'\'')) {
        j += 1;
    }
    while matches!(b.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    if !matches!(b.get(j), Some(b'=' | b':')) {
        return None;
    }
    j += 1;
    while matches!(b.get(j), Some(b' ' | b'\t')) {
        j += 1;
    }
    value_at(b, j)
}

/// A quoted or bare value starting at `j`.
fn value_at(b: &[u8], mut j: usize) -> Option<(usize, usize)> {
    // A quote, or a quote escaped inside a JSON string (`\"`), which must stay whole.
    if b.get(j) == Some(&b'\\') && matches!(b.get(j + 1), Some(b'"' | b'\'')) {
        j += 1;
    }
    let quoted = matches!(b.get(j), Some(b'"' | b'\''));
    if quoted {
        j += 1;
    }
    let vs = j;
    if matches!(b.get(vs), None | Some(b'{' | b'[' | b'\n' | b'\r')) {
        return None;
    }
    let mut ve = vs;
    if quoted {
        while ve < b.len() && !matches!(b.get(ve), Some(b'"' | b'\'' | b'\n' | b'\\')) {
            ve += 1;
        }
    } else {
        while ve < b.len() && !b.get(ve).copied().is_some_and(ends_value) {
            ve += 1;
        }
    }
    Some((vs, ve))
}

/// A secret reference (`env:NAME`, `file:/path`, `vault:path`, `k8s:name/key`): where a
/// secret lives, which the policy asks for in place of the value. Not a secret itself.
pub(crate) fn is_reference(v: &str) -> bool {
    ["env:", "file:", "vault:", "k8s:"].iter().any(|p| {
        v.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && !rest.bytes().any(|c| c.is_ascii_whitespace()))
    })
}

/// Values after a secret-looking key that are not secrets: booleans, nothing, and the
/// marker itself. Digits are not harmless: a PIN or a numeric password is a secret.
pub(crate) fn is_harmless_value(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "none" | "yes" | "no" | "[redacted]" | "<redacted>"
    )
}

/// `scheme://user:pass@host` becomes `scheme://[redacted]@host`: the userinfo of a URL that
/// carries a password. A bare user (`ssh://git@host`) is a name, not a secret.
fn userinfo_spans(text: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(i) = text.get(from..).and_then(|t| t.find("://")) {
        let start = from + i + 3;
        from = start;
        let rest = text.get(start..).unwrap_or_default();
        let line = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>'))
            .unwrap_or(rest.len());
        let line = rest.get(..line).unwrap_or_default();
        let end = line.find(['/', '?', '#']).unwrap_or(line.len());
        let authority = line.get(..end).unwrap_or_default();
        // A password may hold a raw `/`, `?` or `#`, which would end the authority early:
        // when what precedes it reads `name:word` (a colon, and not a port), the userinfo
        // runs to the last `@` of the token.
        let wide = match authority.split_once(':') {
            Some((_, after)) => {
                !authority.contains('@')
                    && !after.is_empty()
                    && !after.bytes().all(|c| c.is_ascii_digit())
            }
            None => false,
        };
        let scope = if wide { line } else { authority };
        if let Some(at) = scope.rfind('@') {
            let info = scope.get(..at).unwrap_or_default();
            if info.contains(':') {
                spans.push((start, start + at));
            }
        }
    }
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
    fn redact(t: &str) -> String {
        Redactor::new().with_references().redact(t)
    }
    fn has_secret(t: &str) -> bool {
        Redactor::new().with_references().has_secret(t)
    }

    #[test]
    fn flag_arguments_are_redacted() {
        for (i, want) in [
            ("run --password foo123", "run --password [redacted]"),
            (
                "run --db-password 'hunter two' x",
                "run --db-password '[redacted]' x",
            ),
            ("mysql -u root -p hunter2x", "mysql -u root -p [redacted]"),
            (
                "cli --api-key abcdef --verbose",
                "cli --api-key [redacted] --verbose",
            ),
        ] {
            assert_eq!(redact(i), want, "{i}");
        }
        for keep in [
            "mkdir -p /tmp/x",
            "docker run -p 8080:80 img",
            "ps -p 1234",
            "cli --token --verbose",
            "cli --password",
        ] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
    }

    #[test]
    fn broader_keys_are_redacted() {
        for i in [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
            "SECRET_KEY=abcdef12",
            "signing_key: abcdef12",
            "encryption_key=abcdef12",
            "connection_string=Server=db;Pwd=x",
            "auth: abcdef12",
            "passcode=abcdef12",
            "otp=abcdef12",
            "dsn=abcdef12",
        ] {
            assert!(has_secret(i), "{i} -> {}", redact(i));
        }
        for keep in ["author: someone", "the key is missing"] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
    }

    #[test]
    fn url_credentials_are_redacted() {
        assert_eq!(
            redact("dial postgres://app:s3cretpw@db.internal:5432/x failed"),
            "dial postgres://[redacted]@db.internal:5432/x failed"
        );
        assert_eq!(
            redact("clone ssh://git@host/r.git"),
            "clone ssh://git@host/r.git"
        );
    }

    #[test]
    fn name_value_pairs_are_redacted() {
        assert_eq!(
            redact(r#"{"name": "DB_PASSWORD", "value": "hunter2hunter"}"#),
            r#"{"name": "DB_PASSWORD", "value": "[redacted]"}"#
        );
        assert_eq!(
            redact("- name: API_TOKEN\n  value: abcdef12\n- name: HOME\n  value: /root"),
            "- name: API_TOKEN\n  value: [redacted]\n- name: HOME\n  value: /root"
        );
    }

    #[test]
    fn extra_keys_prefixes_and_exact_values_are_per_instance() {
        let r = Redactor::new()
            .with_keys([" Licence ", ""])
            .with_prefix("acme_", 8)
            .with_exact("zzq-exact-value-81");
        assert_eq!(r.redact("licence=abcd1234"), "licence=[redacted]");
        assert_eq!(r.redact("x acme_abcdefgh1 y"), "x [redacted] y");
        assert_eq!(r.redact("a zzq-exact-value-81 b"), "a [redacted] b");
        // Another instance, and the built-in rules, do not see them.
        let plain = Redactor::new();
        assert_eq!(plain.redact("licence=abcd1234"), "licence=abcd1234");
        assert_eq!(plain.redact("x acme_abcdefgh1 y"), "x acme_abcdefgh1 y");
        assert_eq!(
            plain.redact("a zzq-exact-value-81 b"),
            "a zzq-exact-value-81 b"
        );
        assert_eq!(r.redact("password=hunter2hunter2"), "password=[redacted]");
    }

    #[test]
    fn debug_never_shows_a_registered_value() {
        let r = Redactor::new().with_exact("zzq-exact-value-81");
        let shown = format!("{r:?}");
        assert!(!shown.contains("zzq"), "{shown}");
        assert!(shown.contains("registered: 1"), "{shown}");
    }

    #[test]
    fn url_userinfo_is_redacted_and_the_host_stays() {
        assert_eq!(
            redact("clone postgres://admin:s3cret-pw@db.internal:5432/app?x=1 now"),
            "clone postgres://[redacted]@db.internal:5432/app?x=1 now"
        );
        assert_eq!(
            redact("https://u:p%40ss@host/path and https://u:q@other"),
            "https://[redacted]@host/path and https://[redacted]@other"
        );
        // No password, no secret: a bare user and a plain URL stay readable.
        assert_eq!(
            redact("db://admin:pa/ss?w#rd@host:5432/app next"),
            "db://[redacted]@host:5432/app next"
        );
        assert_eq!(redact("ssh://git@host/x"), "ssh://git@host/x");
        assert_eq!(redact("https://host:8443/a@b"), "https://host:8443/a@b");
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
    fn a_redactor_keeps_every_value_it_was_given() {
        let r = Redactor::new();
        let vals: Vec<String> = (0..64).map(|i| format!("zzq-kept-value-{i:03}")).collect();
        for v in &vals {
            r.register(v);
        }
        for v in &vals {
            assert!(
                !r.redact(&format!("a {v} b")).contains(v.as_str()),
                "{v} was evicted"
            );
        }
    }

    fn strict(t: &str) -> String {
        Redactor::new().redact(t)
    }

    #[test]
    fn a_strict_redactor_redacts_references_and_the_lookalike_names_always() {
        for c in [
            "password=env:hunter2",
            "token=vault:hvs.X",
            "secret=k8s:abc",
            "client_secret=file:/x/y",
        ] {
            assert!(strict(c).contains(MARK), "strict: {c}");
        }
        for c in [
            "load dotenv:ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "keyfile:AKIAIOSFODNN7EXAMPLE",
            "load env:ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        ] {
            assert!(strict(c).contains(MARK), "strict: {c}");
            let lenient = redact(c);
            assert!(
                lenient.contains(MARK)
                    && !lenient.contains("AKIAIOSFODNN7")
                    && !lenient.contains("ghp_aBc"),
                "references on: {c} -> {lenient}"
            );
        }
        // With references on, a plain reference stays readable.
        assert_eq!(redact("password=env:DB_PASS"), "password=env:DB_PASS");
        assert_eq!(redact("client_secret=file:/x/y"), "client_secret=file:/x/y");
        // A reference with a token shape in its tail is not a reference.
        let t = "password=vault:hvs.AAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(redact(t).contains(MARK), "{}", redact(t));
    }

    #[test]
    fn registered_values_and_the_rules_merge_in_one_pass() {
        let process = Redactor::new().with_references();
        process.register("my long process secret");
        let own = Redactor::new().with_references();
        for (text, want) in [
            ("auth: my long process secret", format!("auth: {MARK}")),
            (
                "x my long process secret and password=hunter2hunter2",
                format!("x {MARK} and password={MARK}"),
            ),
        ] {
            assert_eq!(own.redact_also(text, &[&process]), want, "{text}");
        }
        // The old order leaked the tail.
        let two_pass = process.redact(&own.redact("auth: my long process secret"));
        assert!(two_pass.contains("process secret"), "{two_pass}");
    }

    #[test]
    fn short_password_flags_need_a_tool_that_takes_one() {
        assert_eq!(redact("git log -p HEAD~3"), "git log -p HEAD~3");
        assert_eq!(redact("mysql -P 3306 -u root"), "mysql -P 3306 -u root");
        assert_eq!(redact("mkdir -p build"), "mkdir -p build");
        assert!(redact("sshpass -p hunter2x ssh h").contains(MARK));
        assert!(redact("docker login -u me -p hunter2x").contains(MARK));
        assert!(redact("mysql -u root -p hunter2x").contains(MARK));
    }

    #[test]
    fn a_flag_value_that_starts_with_a_dash_is_still_a_value() {
        assert_eq!(
            redact("run --password -s3cr3t now"),
            "run --password [redacted] now"
        );
        assert_eq!(redact("run --password --user x"), "run --password --user x");
        assert_eq!(redact("run --password -v"), "run --password -v");
    }

    #[test]
    fn short_exact_keys_redact_prose_too() {
        // Known and accepted: a value under `auth`, `otp`, `pin` or `jwt` is hidden whatever
        // it looks like, because a secret can look like a word.
        assert_eq!(redact("auth: failed"), "auth: [redacted]");
    }
}
