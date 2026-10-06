//! Bounded "heavy hitters" tables (the Space-Saving algorithm, Metwally et al. 2005).
//!
//! A table holds at most `capacity` keys. A new key when the table is full replaces the
//! key with the smallest count and inherits that count as its error bound, so memory is
//! fixed however many distinct names, paths or addresses pass, and every key whose true
//! count exceeds `total / capacity` is guaranteed to be in the table. Keys are truncated
//! to [`MAX_KEY`] bytes on a character boundary.

use std::collections::HashMap;

use serde::Serialize;

/// Longest key kept, in bytes.
pub(crate) const MAX_KEY: usize = 128;

/// One row of a table, as the snapshot shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Row {
    pub(crate) key: String,
    /// Upper bound of the true count.
    pub(crate) count: u64,
    /// How much of `count` may belong to keys this one replaced (0: exact).
    pub(crate) error: u64,
}

/// A Space-Saving table.
#[derive(Debug)]
pub(crate) struct TopK {
    capacity: usize,
    entries: HashMap<String, (u64, u64)>,
    total: u64,
    replaced: u64,
}

impl TopK {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::with_capacity(capacity.max(1)),
            total: 0,
            replaced: 0,
        }
    }

    /// Counts one occurrence of `key`.
    pub(crate) fn add(&mut self, key: &str) {
        self.total = self.total.saturating_add(1);
        let key = truncate(key);
        if let Some(e) = self.entries.get_mut(key) {
            e.0 = e.0.saturating_add(1);
            return;
        }
        if self.entries.len() < self.capacity {
            self.entries.insert(key.to_owned(), (1, 0));
            return;
        }
        // Replace the smallest; ties broken by key so the result is deterministic.
        let victim = self
            .entries
            .iter()
            .min_by(|a, b| a.1.0.cmp(&b.1.0).then_with(|| b.0.cmp(a.0)))
            .map(|(k, v)| (k.clone(), v.0));
        if let Some((k, min)) = victim {
            self.entries.remove(&k);
            self.entries
                .insert(key.to_owned(), (min.saturating_add(1), min));
            self.replaced = self.replaced.saturating_add(1);
        }
    }

    /// Keys currently held.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Occurrences counted.
    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    /// How many times a key was replaced because the table was full.
    pub(crate) fn replaced(&self) -> u64 {
        self.replaced
    }

    /// The `n` largest rows, largest first.
    pub(crate) fn top(&self, n: usize) -> Vec<Row> {
        let mut rows: Vec<Row> = self
            .entries
            .iter()
            .map(|(k, (c, e))| Row {
                key: k.clone(),
                count: *c,
                error: *e,
            })
            .collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        rows.truncate(n);
        rows
    }
}

/// `key` cut to at most [`MAX_KEY`] bytes on a character boundary.
pub(crate) fn truncate(key: &str) -> &str {
    if key.len() <= MAX_KEY {
        return key;
    }
    let mut end = MAX_KEY;
    while !key.is_char_boundary(end) {
        end -= 1;
    }
    &key[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_while_it_fits() {
        let mut t = TopK::new(4);
        for k in ["a", "b", "a", "c", "a", "b"] {
            t.add(k);
        }
        let top = t.top(10);
        assert_eq!(
            top[0],
            Row {
                key: "a".into(),
                count: 3,
                error: 0
            }
        );
        assert_eq!(top[1].key, "b");
        assert_eq!(t.total(), 6);
        assert_eq!(t.replaced(), 0);
    }

    #[test]
    fn stays_bounded_and_keeps_heavy_hitters() {
        let mut t = TopK::new(16);
        for i in 0..100_000u32 {
            t.add(&format!("noise-{i}"));
            if i % 10 == 0 {
                t.add("heavy");
            }
        }
        assert_eq!(t.len(), 16, "never more keys than the capacity");
        let top = t.top(1);
        assert_eq!(top[0].key, "heavy");
        assert!(top[0].count >= 10_000);
        assert!(t.replaced() > 0);
    }

    #[test]
    fn truncates_long_keys_on_char_boundaries() {
        let long = "é".repeat(200);
        let cut = truncate(&long);
        assert!(cut.len() <= MAX_KEY && cut.is_char_boundary(cut.len()));
        let mut t = TopK::new(2);
        t.add(&long);
        assert!(t.top(1)[0].key.len() <= MAX_KEY);
    }
}
