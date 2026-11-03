//! The one place the agent reads YAML (`serde-saphyr`, which replaced the unmaintained
//! `serde_yaml_ng`, RUSTSEC-2024-0449).
//!
//! Every reader names the largest input it accepts (`max_bytes`, its own existing cap on
//! the file or page it reads) and refuses anything longer. The parser's budgets are sized
//! from the length of the input actually read: the crate's stock budgets (250,000 nodes,
//! depth 64, an alias ratio) reject documents the old parser took, such as a 2.5 MB flat
//! `OpenAPI` spec, and budgets sized from the cap let a few hundred bytes of aliases expand
//! to hundreds of megabytes. They stay on as the denial-of-service control.
//!
//! Read as the old parser read them: a repeated key (last wins in a map, an error for a
//! struct), `yes`/`no`/`on`/`off` and `0644`/`08`/`1_000` as strings, `.inf` and `.nan`
//! as null in a `Value`. Different: `<<` merge keys and tags are expanded.

use serde::de::DeserializeOwned;
use serde_saphyr::options::NonFiniteFloatPolicy;
use serde_saphyr::{Budget, DuplicateKeyPolicy, Options};

/// How deep a document may nest: the old parser's recursion limit. A release build
/// parses 127 levels on a 2 MiB thread stack; a debug build overflows it near 85, so
/// tests nest at most 80.
pub const MAX_DEPTH: usize = 128;

/// Nodes any input may hold however short it is: well under the crate's stock 250,000 so
/// that a few hundred bytes of aliases cannot fill memory, well over what a small honest
/// document, or 20,000 aliases of one anchor, needs.
const NODE_FLOOR: usize = 100_000;

/// Parser options for an input of `len` bytes.
///
/// The limits are sized from the input actually read, never from the reader's cap: a
/// small hostile document must not be allowed what a cap-sized honest one is. A node, an
/// event or an alias takes at least two input bytes (`[1,1,1]`), so a document without
/// aliases never holds more than `len / 2` of any of them. Aliases are the one amplifier
/// (a 313 byte "billion laughs" document replays to hundreds of megabytes), so the nodes
/// and replayed events are held to what an honest document of this length could hold,
/// with [`NODE_FLOOR`] as the floor for small inputs.
///
/// Callers need a thread stack of at least 1 MiB: nesting up to [`MAX_DEPTH`] overflowed
/// a 256 KiB stack in a release build and fits in 512 KiB.
#[must_use]
pub fn options(len: usize) -> Options {
    let stock = Budget::default();
    let mut budget = Budget::default();
    budget.max_reader_input_bytes = Some(len);
    let honest = len / 2;
    budget.max_events = stock.max_events.max(len);
    budget.max_nodes = NODE_FLOOR.max(honest);
    budget.max_total_scalar_bytes = stock.max_total_scalar_bytes.max(len);
    budget.max_depth = MAX_DEPTH;
    budget.max_aliases = stock.max_aliases.max(honest);
    budget.max_anchors = stock.max_anchors.max(honest);
    // The ratio check (aliases above ten times the anchors) trips on one shared anchor
    // used thousands of times, which real specs do, so it starts counting only where the
    // absolute alias cap above already ends. What bounds amplification is the node and
    // replay limits, which follow the input length.
    budget.alias_anchor_min_aliases = budget.max_aliases;
    let mut opts = Options::default();
    opts.alias_limits.max_total_replayed_events = (5 * NODE_FLOOR).max(len);
    budget.max_recorded_anchor_events = (5 * NODE_FLOOR).max(len);
    opts.budget = Some(budget);
    // A repeated key is passed to the target type, as the old parser did: a map keeps the
    // last value and a derived struct refuses it ("duplicate field").
    opts.duplicate_keys = DuplicateKeyPolicy::PassThrough;
    // `yes`, `no`, `on` and `off` are strings, as the old parser read them.
    opts.strict_booleans = true;
    // `0644`, `08` and `1_000` are strings and `.inf` and `.nan` read as null, as before.
    opts.leading_zero_numbers_as_strings = true;
    opts.underscored_numbers_as_strings = true;
    opts.non_finite_float_policy = NonFiniteFloatPolicy::PassThrough;
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
    serde_saphyr::from_str_with_options(text, options(text.len())).map_err(|e| e.to_string())
}

/// [`from_str`] for bytes.
///
/// # Errors
/// As [`from_str`].
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, String> {
    if bytes.len() > max_bytes {
        return Err(too_large(bytes.len(), max_bytes));
    }
    serde_saphyr::from_slice_with_options(bytes, options(bytes.len())).map_err(|e| e.to_string())
}

/// Every `---` separated document in `text`, each as the reader yields it: a document
/// that does not fit `T` is an `Err` and the ones after it are still read, a syntax
/// error or an exceeded budget ends the list. Empty documents are skipped.
#[must_use]
pub fn docs<T: DeserializeOwned>(text: &str, max_bytes: usize) -> Vec<Result<T, String>> {
    if text.len() > max_bytes {
        return vec![Err(too_large(text.len(), max_bytes))];
    }
    serde_saphyr::read_with_options::<_, T>(&mut text.as_bytes(), options(text.len()))
        .map(|d| d.map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fmt::Write as _;

    const CAP: usize = 8 * 1024 * 1024;

    #[derive(Debug, serde::Deserialize)]
    struct S {
        a: u8,
    }

    #[derive(serde::Deserialize)]
    struct F {
        a: f64,
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
    fn a_repeated_key_is_last_wins_in_a_map_and_an_error_in_a_struct() {
        let v: Value = from_str("a: 1\nb: 2\na: 3\n", CAP).unwrap();
        assert_eq!(v, json!({"a": 3, "b": 2}));
        // As the old parser: a derived struct refuses a repeated field.
        let e = from_str::<S>("a: 1\na: 2\n", CAP).unwrap_err();
        assert!(e.contains("duplicate field"), "{e}");
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
    fn scalars_read_as_the_old_parser_read_them() {
        let v: Value = from_str("a: 0644\nb: 08\nc: 1_000\nd: 017\ne: 0o17\nf: 12\n", CAP).unwrap();
        assert_eq!(v["a"], "0644");
        assert_eq!(v["b"], "08");
        assert_eq!(v["c"], "1_000");
        assert_eq!(v["d"], "017");
        assert_eq!(v["e"], 15);
        assert_eq!(v["f"], 12);
        // `.inf` and `.nan` are null in a `Value`, not an error.
        let v: Value = from_str("a: .inf\nb: -.inf\nc: .nan\n", CAP).unwrap();
        assert_eq!(v, json!({"a": null, "b": null, "c": null}));
        let f: F = from_str("a: .inf\n", CAP).unwrap();
        assert!(f.a.is_infinite());
    }

    #[test]
    fn docs_skip_empty_and_keep_going_past_a_misfit() {
        let got = docs::<S>("a: 1\n---\n---\na: nope\n---\na: 3\n", CAP);
        assert_eq!(
            got.len(),
            3,
            "{got:?}",
            got = got
                .iter()
                .map(|r| r.as_ref().map(|s| s.a))
                .collect::<Vec<_>>()
        );
        assert_eq!(got[0].as_ref().unwrap().a, 1);
        assert!(got[1].is_err());
        assert_eq!(got[2].as_ref().unwrap().a, 3);
    }

    /// `levels` anchors of `fanout` references each: a few hundred bytes that replay to
    /// `fanout.pow(levels)` nodes.
    fn bomb(fanout: usize, levels: usize) -> String {
        let mut s = format!("a0: &a0 [{}]\n", vec!["x"; fanout].join(", "));
        for i in 1..levels {
            let refs = vec![format!("*a{}", i - 1); fanout].join(", ");
            let _ = writeln!(s, "a{i}: &a{i} [{refs}]");
        }
        s
    }

    #[test]
    fn small_alias_bombs_are_refused_at_the_real_caps() {
        // The readers' real caps: a crawled page (5 MiB, the default), a repository file
        // and a kubeconfig (8 MiB). The limits follow the input, so a few hundred bytes
        // is held to the floor (about 100,000 nodes, some 20 MiB), not to the cap's
        // millions of nodes (700 MiB measured before).
        for cap in [5 * 1024 * 1024, 8 * 1024 * 1024] {
            for (fanout, levels) in [(10, 7), (7, 8), (4, 12), (2, 24), (100, 4), (17, 6)] {
                let s = bomb(fanout, levels);
                assert!(s.len() < 2_000, "{} bytes", s.len());
                let e = from_str::<Value>(&s, cap).unwrap_err();
                assert!(e.contains("Nodes"), "{fanout}x{levels} at {cap}: {e}");
            }
        }
    }

    #[test]
    fn an_aliased_large_scalar_is_refused() {
        // One 200 KB string used 3,000 times is 600 MB if it is copied each time.
        let mut s = format!("big: &b \"{}\"\nuses:\n", "x".repeat(200_000));
        for _ in 0..3_000 {
            s.push_str("  - *b\n");
        }
        assert!(s.len() < 5 * 1024 * 1024);
        let e = from_str::<Value>(&s, 5 * 1024 * 1024).unwrap_err();
        assert!(e.contains("budget breached"), "{e}");
    }
}
