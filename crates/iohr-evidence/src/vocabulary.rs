//! The versioned predicate vocabulary (ADR 0015 in inorbithr/core).
//!
//! A claim's predicate is a name from a registry at a version: `depends_on@1`. Two
//! observers that both say "depends on" mean the same thing only when they cite the same
//! predicate version, so predicates are never free text.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::digest::ContentDigest;
use crate::ids::EntityId;

/// A predicate name: lower-case ASCII letters, digits and underscores, starting with a
/// letter, at most 64 bytes. Dots separate a namespace: `net.connects_to`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PredicateName(String);

/// A predicate name that breaks the naming rule.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a predicate name: {0:?}")]
pub struct BadPredicateName(pub String);

impl TryFrom<String> for PredicateName {
    type Error = BadPredicateName;

    fn try_from(s: String) -> Result<Self, BadPredicateName> {
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.split('.').all(|part| {
                part.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            });
        if ok {
            Ok(Self(s))
        } else {
            Err(BadPredicateName(s))
        }
    }
}

impl From<PredicateName> for String {
    fn from(p: PredicateName) -> Self {
        p.0
    }
}

impl PredicateName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A predicate at a vocabulary version: what a claim says about its subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PredicateRef {
    /// The predicate's name.
    pub name: PredicateName,
    /// The vocabulary version that defines it.
    pub version: u32,
}

impl fmt::Display for PredicateRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name.as_str(), self.version)
    }
}

/// The object of a claim. Closed set: a value Atlas cannot compare is not a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "v", rename_all = "snake_case")]
pub enum Value {
    /// A truth value.
    Bool(bool),
    /// A whole number.
    Int(i64),
    /// Text, compared exactly.
    Text(String),
    /// Another entity: the object of a relation such as `depends_on`.
    Entity(EntityId),
    /// A content digest.
    Digest(ContentDigest),
    /// A duration in milliseconds.
    Millis(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_names_follow_the_rule() {
        for good in ["depends_on", "net.connects_to", "k8s.v1.runs_as", "a"] {
            assert!(PredicateName::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in [
            "",
            "DependsOn",
            "depends on",
            "1st",
            ".x",
            "x.",
            "x..y",
            "dépend",
            &"a".repeat(65),
        ] {
            assert!(PredicateName::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn predicate_refs_print_with_their_version() {
        let p = PredicateRef {
            name: PredicateName::try_from("depends_on".to_owned()).unwrap(),
            version: 3,
        };
        assert_eq!(p.to_string(), "depends_on@3");
    }
}
