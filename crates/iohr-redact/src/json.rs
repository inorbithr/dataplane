//! Redaction over JSON (the `json` feature): a `serde_json::Value`, or a body as text.

use serde_json::Value;

use crate::{MARK, Redactor, is_harmless_value, is_reference};

impl Redactor {
    /// Redacts `value` in place. A string under a secret-looking key is replaced whole,
    /// unless it is a secret reference or harmless (`true`, `none`); so is a number under
    /// one, and the `value` of an object whose `name` (or `key`) is a secret name. Every
    /// other string goes through [`Redactor::redact`]. A secret key over an object or an
    /// array is not itself a secret, so its contents are walked. Keys are never changed.
    pub fn redact_json(&self, value: &mut Value) {
        self.walk(value, false);
    }

    /// A JSON body with every string value redacted on its own, so the answer stays JSON
    /// (redacting the serialized text could cut through an escaped quote). Text that is
    /// not JSON (a cut stream) is redacted as text, by key and by value.
    #[must_use]
    pub fn redact_json_str(&self, body: &str) -> String {
        match serde_json::from_str::<Value>(body) {
            Ok(mut v) => {
                self.walk(&mut v, false);
                serde_json::to_string(&v).unwrap_or_else(|_| self.redact(body))
            }
            Err(_) => self.redact(body),
        }
    }

    fn walk(&self, v: &mut Value, secret_key: bool) {
        match v {
            Value::String(s) => {
                *s = if secret_key && !is_reference(s) && !is_harmless_value(s) && !s.is_empty() {
                    MARK.to_owned()
                } else {
                    self.redact(s)
                };
            }
            Value::Number(_) if secret_key => *v = Value::String(MARK.to_owned()),
            Value::Array(a) => a.iter_mut().for_each(|x| self.walk(x, secret_key)),
            Value::Object(m) => {
                let named = ["name", "key", "Name", "Key"].iter().any(|k| {
                    m.get(*k)
                        .and_then(Value::as_str)
                        .is_some_and(|s| self.is_secret_key(s))
                });
                for (k, x) in m.iter_mut() {
                    let paired = named && k.eq_ignore_ascii_case("value");
                    self.walk(x, paired || self.is_secret_key(k));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn redact_json(body: &str) -> String {
        Redactor::new().redact_json_str(body)
    }

    #[test]
    fn a_json_answer_stays_json_and_references_stay_readable() {
        let text = "[console.oidc]\nclient_secret = \"file:/var/run/iohr/oidc-secret\"\nissuer = \"https://login.example.com\"\npassword = \"hunter2hunter2\"\n";
        let body =
            json!({ "text": text, "access_token": "abc.def.ghi-123456", "n": 3 }).to_string();
        let out = redact_json(&body);
        let v: Value = serde_json::from_str(&out).expect("still JSON");
        let t = v["text"].as_str().unwrap_or_default();
        assert!(
            t.contains("client_secret = \"file:/var/run/iohr/oidc-secret\""),
            "{t}"
        );
        assert!(!t.contains("hunter2"), "{t}");
        assert_eq!(v["access_token"], MARK);
        assert_eq!(v["n"], 3);
        // Text redaction does not cut through an escaped quote either.
        let r = Redactor::new().redact(&body);
        assert!(serde_json::from_str::<Value>(&r).is_ok(), "{r}");
    }

    #[test]
    fn ansible_keys_in_json_are_secret() {
        let j =
            redact_json(r#"{"ansible_become_pass":"correcthorse","tls_key_pem":"x-correcthorse"}"#);
        assert!(!j.contains("correcthorse"), "{j}");
    }

    #[test]
    fn a_name_value_pair_with_a_secret_name_is_redacted() {
        let j = redact_json(
            r#"{"env":[{"name":"DB_PASSWORD","value":"correcthorse"},{"name":"MODE","value":"fast"}]}"#,
        );
        assert!(!j.contains("correcthorse"), "{j}");
        assert!(j.contains("fast"), "{j}");
        // The same as text, and as YAML.
        let t = Redactor::new().redact(r#"{"env":[{"name":"DB_PASSWORD","value":"correcthorse"}]"#);
        assert!(!t.contains("correcthorse"), "{t}");
        let y = Redactor::new().redact(
            "env:\n  - name: API_TOKEN\n    value: correcthorse\n  - name: MODE\n    value: fast\n",
        );
        assert!(!y.contains("correcthorse"), "{y}");
        assert!(y.contains("fast"), "{y}");
    }

    #[test]
    fn digits_under_a_secret_key_are_redacted() {
        assert!(
            !Redactor::new()
                .redact("pin_password: 48213377")
                .contains("48213377")
        );
        assert!(
            !Redactor::new()
                .redact("ansible_become_pass=123456")
                .contains("123456")
        );
        let j = redact_json(r#"{"db_password": 48213377, "pin_token": "991122"}"#);
        assert!(!j.contains("48213377") && !j.contains("991122"), "{j}");
    }

    #[test]
    fn truncated_json_is_still_redacted_by_key_and_registered_value() {
        let r = Redactor::new();
        r.register("zzq-runner-only-value-42");
        let cut = r#"{"items":[{"client_secret":"correcthorse","note":"zzq-runner-only-value-42","more":"#;
        let out = r.redact_json_str(cut);
        assert!(!out.contains("correcthorse"), "{out}");
        assert!(!out.contains("zzq-runner-only-value-42"), "{out}");
    }

    #[test]
    fn a_value_is_redacted_in_place_and_extra_keys_apply() {
        let mut v = json!({
            "password": "hunter2hunter2",
            "licence": "abcd1234",
            "env": [{"name": "DB_PASSWORD", "value": "hunter2hunter2"}, {"name": "HOME", "value": "/root"}],
            "line": "login failed password=hunter2hunter2 for app",
            "secrets": {"allow": []},
            "tokens": 3,
            "ok": true
        });
        Redactor::new().with_keys(["licence"]).redact_json(&mut v);
        assert_eq!(
            v,
            json!({
                "password": MARK,
                "licence": MARK,
                "env": [{"name": "DB_PASSWORD", "value": MARK}, {"name": "HOME", "value": "/root"}],
                "line": "login failed password=[redacted] for app",
                "secrets": {"allow": []},
                "tokens": 3,
                "ok": true
            })
        );
    }
}
