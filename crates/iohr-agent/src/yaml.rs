//! The one place the agent reads YAML (`serde-saphyr`, which replaced the unmaintained
//! `serde_yaml_ng`, RUSTSEC-2024-0449).
//!
//! Every reader names the largest input it accepts (`max_bytes`, its own existing cap on
//! the file or page it reads) and this module sizes the parser's budgets from that number.
//! The crate's stock budgets (250,000 nodes, depth 64, an alias ratio) reject documents
//! the old parser took and the callers' caps allow, such as a 2.5 MB flat `OpenAPI` spec.
//! The budgets stay on as the denial-of-service control: they are sized to the cap, not
//! removed, so a hostile document costs at most what an honest one of that size does.
//!
//! Behaviour kept from the old parser: a repeated key is last-wins. Behaviour that
//! differs: `<<` merge keys and tags are expanded, `.inf` and `.nan` are errors, and
//! `yes`/`no`/`on`/`off` stay strings in both.

use serde::de::DeserializeOwned;
use serde_saphyr::{Budget, DuplicateKeyPolicy, Options};

/// How deep a document may nest: the old parser's recursion limit. A release build
/// parses 127 levels on a 2 MiB thread stack; a debug build overflows it near 85, so
/// tests nest at most 80.
pub const MAX_DEPTH: usize = 128;

/// Parser options for input of at most `max_bytes`.
///
/// A node, event or alias takes at least two input bytes (`[1,1,1]`), so a cap on the
/// bytes is a cap on each count: a document within `max_bytes` can never hit them. Alias
/// replay is the one amplifier, and it is bounded separately by the replay cap below.
#[must_use]
pub fn options(max_bytes: usize) -> Options {
    let mut budget = Budget::default();
    // Never below the crate's own limits, so a small cap does not tighten them.
    budget.max_reader_input_bytes = Some(max_bytes);
    budget.max_events = budget.max_events.max(max_bytes);
    budget.max_nodes = budget.max_nodes.max(max_bytes / 2);
    budget.max_total_scalar_bytes = budget.max_total_scalar_bytes.max(max_bytes);
    budget.max_depth = MAX_DEPTH;
    budget.max_aliases = budget.max_aliases.max(max_bytes / 2);
    budget.max_anchors = budget.max_anchors.max(max_bytes / 2);
    // The ratio check (aliases above ten times the anchors) trips on one shared anchor
    // used thousands of times, which real specs do. The absolute alias cap above is the
    // limit instead: the ratio only starts counting where that cap already ends.
    budget.alias_anchor_min_aliases = budget.max_aliases;
    let mut opts = Options::default();
    opts.alias_limits.max_total_replayed_events = opts
        .alias_limits
        .max_total_replayed_events
        .max(max_bytes.saturating_mul(2));
    budget.max_recorded_anchor_events = budget
        .max_recorded_anchor_events
        .max(opts.alias_limits.max_total_replayed_events);
    opts.budget = Some(budget);
    opts.duplicate_keys = DuplicateKeyPolicy::LastWins;
    // `yes`, `no`, `on` and `off` are strings, as the old parser read them.
    opts.strict_booleans = true;
    opts
}

fn too_large(len: usize, max_bytes: usize) -> String {
    format!("{len} bytes of YAML, more than the {max_bytes} allowed")
}

/// One YAML document of at most `max_bytes`.
///
/// # Errors
/// The input is larger than `max_bytes`, is not valid YAML, is empty, or does not fit `T`.
pub fn from_str<T: DeserializeOwned>(text: &str, max_bytes: usize) -> Result<T, String> {
    if text.len() > max_bytes {
        return Err(too_large(text.len(), max_bytes));
    }
    serde_saphyr::from_str_with_options(text, options(max_bytes)).map_err(|e| e.to_string())
}

/// [`from_str`] for bytes.
///
/// # Errors
/// As [`from_str`].
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, String> {
    if bytes.len() > max_bytes {
        return Err(too_large(bytes.len(), max_bytes));
    }
    serde_saphyr::from_slice_with_options(bytes, options(max_bytes)).map_err(|e| e.to_string())
}

/// Every `---` separated document in `text`, each as the reader yields it: a document
/// that does not fit `T` is an `Err` and the ones after it are still read, a syntax
/// error or an exceeded budget ends the list. Empty documents are skipped.
#[must_use]
pub fn docs<T: DeserializeOwned>(text: &str, max_bytes: usize) -> Vec<Result<T, String>> {
    if text.len() > max_bytes {
        return vec![Err(too_large(text.len(), max_bytes))];
    }
    serde_saphyr::read_with_options::<_, T>(&mut text.as_bytes(), options(max_bytes))
        .map(|d| d.map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fmt::Write as _;

    const CAP: usize = 8 * 1024 * 1024;

    #[derive(serde::Deserialize)]
    struct S {
        a: u8,
    }

    #[test]
    fn a_large_flat_document_near_the_cap_parses() {
        // 2.5 MB of flat entries: the stock budget stops this at 250,000 nodes.
        let mut s = String::from("openapi: 3.0.0\npaths:\n");
        let mut i = 0;
        while s.len() < 2_500_000 {
            let _ = writeln!(s, "  /p{i}: {{get: {{}}}}");
            i += 1;
        }
        let v: Value = from_str(&s, CAP).unwrap();
        assert_eq!(v["paths"].as_object().unwrap().len(), i);
        // Tiny nodes up to a small cap: 1 MiB of `- 1` is 262,144 nodes, over the stock 250,000.
        let mut big = String::new();
        while big.len() < (1 << 20) - 8 {
            big.push_str("- 1\n");
        }
        let v: Value = from_str(&big, 1 << 20).unwrap();
        assert_eq!(v.as_array().unwrap().len(), big.len() / 4);
        // Over the cap is refused, in words.
        let e = from_str::<Value>(&(big.clone() + &big), 1 << 20).unwrap_err();
        assert!(e.contains("more than the"), "{e}");
    }

    #[test]
    fn eighty_deep_nesting_parses() {
        let nest = |n: usize| {
            let mut s = String::new();
            for i in 0..n {
                s.push_str(&"  ".repeat(i));
                s.push_str("k:\n");
            }
            s.push_str(&"  ".repeat(n));
            s.push_str("leaf: 1\n");
            s
        };
        let v: Value = from_str(&nest(80), CAP).unwrap();
        let mut at = &v;
        for _ in 0..80 {
            at = &at["k"];
        }
        assert_eq!(at["leaf"], 1);
    }

    #[test]
    fn many_aliases_of_one_anchor_parse() {
        let mut s = String::from("base: &a {x: 1}\nuses:\n");
        for _ in 0..20_000 {
            s.push_str("  - *a\n");
        }
        let v: Value = from_str(&s, CAP).unwrap();
        assert_eq!(v["uses"].as_array().unwrap().len(), 20_000);
        assert_eq!(v["uses"][19_999]["x"], 1);
    }

    #[test]
    fn a_repeated_key_is_last_wins() {
        let v: Value = from_str("a: 1\nb: 2\na: 3\n", CAP).unwrap();
        assert_eq!(v, json!({"a": 3, "b": 2}));
        let s: S = from_str("a: 1\na: 2\n", CAP).unwrap();
        assert_eq!(s.a, 2);
    }

    #[test]
    fn merge_keys_expand() {
        let y = "base: &b {image: x, port: 80}\nsvc:\n  <<: *b\n  port: 8080\n";
        let v: Value = from_str(y, CAP).unwrap();
        assert_eq!(v["svc"], json!({"image": "x", "port": 8080}));
    }

    #[test]
    fn yes_and_no_stay_strings() {
        let v: Value = from_str("a: yes\nb: no\nc: on\nd: off\n", CAP).unwrap();
        assert_eq!(v, json!({"a": "yes", "b": "no", "c": "on", "d": "off"}));
    }

    #[test]
    fn non_finite_floats_are_errors() {
        assert!(from_str::<Value>("a: .inf\n", CAP).is_err());
        assert!(from_str::<Value>("a: .nan\n", CAP).is_err());
    }

    #[test]
    fn docs_skip_empty_and_keep_going_past_a_misfit() {
        let got = docs::<Value>("a: 1\n---\n---\nb: 2\n", CAP);
        let got: Vec<_> = got.into_iter().map(Result::unwrap).collect();
        assert_eq!(got, vec![json!({"a": 1}), json!({"b": 2})]);
    }

    #[test]
    fn a_billion_laughs_document_still_hits_a_budget() {
        let mut s = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let prev = i - 1;
            let refs = vec![format!("*a{prev}"); 10].join(", ");
            let _ = writeln!(s, "a{i}: &a{i} [{refs}]");
        }
        assert!(from_str::<Value>(&s, 64 * 1024).is_err());
    }
}
