//! Redaction for everything the local page shows: log lines, error messages, anything a
//! platform frame put into the agent's state. It runs over each value when it is recorded
//! and again over every response body the admin page sends, so a secret that reached the
//! agent's memory by any path is replaced before a browser sees it.
//!
//! The rules live in the shared `iohr-redact` crate (the same ones Atlas core applies to
//! worker output, RFC 0150). This module is the agent's seam over it: the process-wide
//! values (the admin page's own token, an enrollment token, the MCP door secret) that
//! [`register`] keeps in one `iohr_redact::Redactor`, and a per-owner [`Redactor`] (an
//! infrastructure connection's key files and tokens) that keeps every value it is given
//! and applies the process-wide ones too.

use std::sync::OnceLock;

pub use iohr_redact::MARK;

/// The process-wide values.
fn process() -> &'static iohr_redact::Redactor {
    static R: OnceLock<iohr_redact::Redactor> = OnceLock::new();
    R.get_or_init(|| iohr_redact::Redactor::new().with_references())
}

/// Remembers an exact secret value (8 characters or more) for the whole process.
pub fn register(value: &str) {
    process().register(value);
}

/// `text` with every secret-looking span replaced by [`MARK`].
#[must_use]
pub fn redact(text: &str) -> String {
    process().redact(text)
}

/// Whether `text` holds anything [`redact`] would replace.
#[must_use]
pub fn has_secret(text: &str) -> bool {
    process().has_secret(text)
}

/// Whether a key names a secret (compared without case).
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    process().is_secret_key(key)
}

/// A JSON answer with every string value redacted on its own, so the answer stays JSON.
/// Text that is not JSON (a cut stream) is redacted as text, by key and by value.
#[must_use]
pub fn redact_json(body: &str) -> String {
    process().redact_json_str(body)
}

/// Exact secret values one owner knows, redacted wherever they appear, on top of the
/// shape and key rules and the process-wide values. Every value given is kept.
#[derive(Debug)]
pub struct Redactor {
    own: iohr_redact::Redactor,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            own: iohr_redact::Redactor::new().with_references(),
        }
    }
}

impl Redactor {
    /// One with no values of its own.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers an exact secret value (8 characters or more).
    pub fn register(&self, value: &str) {
        self.own.register(value);
    }

    /// `text` redacted by the rules, this owner's values and the process-wide ones.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        self.own.redact_also(text, &[process()])
    }

    /// [`redact_json`] with this owner's values too.
    #[must_use]
    pub fn redact_json(&self, body: &str) -> String {
        self.own.redact_json_str_also(body, &[process()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_values_are_redacted_anywhere() {
        register("zzq-registered-value-81");
        assert_eq!(redact("x zzq-registered-value-81y"), format!("x {MARK}y"));
    }

    #[test]
    fn an_owner_applies_its_own_values_and_the_process_wide_ones() {
        register("zzq-process-wide-value-7");
        let r = Redactor::new();
        r.register("zzq-owner-only-value-7");
        let out = r.redact("a zzq-owner-only-value-7 b zzq-process-wide-value-7 c");
        assert_eq!(out, format!("a {MARK} b {MARK} c"));
        // Another owner, and the process, never saw the owner's value.
        assert!(redact("a zzq-owner-only-value-7").contains("zzq-owner-only"));
        let cut = r#"{"a":[{"client_secret":"correcthorse","n":"zzq-owner-only-value-7","m":"#;
        let j = r.redact_json(cut);
        assert!(
            !j.contains("correcthorse") && !j.contains("zzq-owner"),
            "{j}"
        );
    }

    #[test]
    fn the_agent_keys_and_json_answers_still_hold() {
        assert!(is_secret_key("ansible_become_pass") && !is_secret_key("next_page_token"));
        let out = redact_json(r#"{"access_token":"abc.def.ghi-123456","n":3}"#);
        assert!(out.contains(MARK) && out.contains("\"n\":3"), "{out}");
        assert!(has_secret("password=hunter2hunter2"));
    }

    #[test]
    fn a_process_value_is_not_cut_by_the_rules_of_the_owner_pass() {
        register("my long process secret");
        let r = Redactor::new();
        assert_eq!(
            r.redact("auth: my long process secret"),
            format!("auth: {MARK}")
        );
        let j = r.redact_json(r#"{"note":"auth: my long process secret"}"#);
        assert!(!j.contains("process secret") && !j.contains("long"), "{j}");
        // The agent leaves references readable, but not a look-alike.
        assert_eq!(redact("password=env:DB_PASS"), "password=env:DB_PASS");
        assert!(redact("keyfile:AKIAIOSFODNN7EXAMPLE").contains(MARK));
    }
}
