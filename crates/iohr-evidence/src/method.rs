//! Evidence methods: how a piece of evidence was obtained (ADR 0016 in inorbithr/core).
//!
//! There will be hundreds of connections and frontends: rust-analyzer, `go/types`, the
//! TypeScript compiler, kubectl, Grafana, Loki, an enterprise's own APM. The core never
//! learns their names. Each declares an open [`MethodName`] (data, not code) and one
//! [`MethodCategory`] from a small closed set. Proof contracts are written against
//! categories, so a new connector needs no change here: it declares what kind of
//! evidence it produces, and every predicate's contract applies to it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::observer::ObserverClass;

/// What kind of evidence a method produces. Closed on purpose: proof contracts depend
/// on this set, and adding to it is an architectural decision (an ADR), not a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodCategory {
    /// A compiler or language server resolved it: a call to a definition, a type.
    StaticResolution,
    /// Seen happening on a running system: a connection, a packet, a syscall, a process.
    RuntimeObservation,
    /// A control plane's statement of current state: a Kubernetes object, a service
    /// registry entry. What the system says is running, not what was seen happening.
    RuntimeState,
    /// Recorded by the application itself: a trace span, an SDK event.
    ApplicationTrace,
    /// A metric series.
    Metrics,
    /// A log line.
    Logs,
    /// A configuration value or manifest: an env var, a Kubernetes object, a route.
    Configuration,
    /// Source code constructs it (a client built with a URL) without resolving where it
    /// goes at runtime.
    SourceConstruction,
    /// Another system's record through its API: a CI result, a GitHub review.
    ExternalRecord,
    /// Prose: a README, a wiki page, a comment.
    Documentation,
    /// A textual match (grep).
    TextSearch,
    /// A model's interpretation.
    ModelInterpretation,
    /// A person's answer.
    HumanTestimony,
}

impl MethodCategory {
    /// Whether this category may ever be the method that verifies a claim. Prose, text
    /// matches, interpretation and testimony can support or suggest; they never prove.
    #[must_use]
    pub const fn may_prove(self) -> bool {
        !matches!(
            self,
            Self::Documentation
                | Self::TextSearch
                | Self::ModelInterpretation
                | Self::HumanTestimony
        )
    }

    /// Whether an observer of `class` can produce evidence of this category. A model
    /// only interprets; a person only testifies; no instrument interprets or testifies.
    #[must_use]
    pub const fn produced_by(self, class: ObserverClass) -> bool {
        match self {
            Self::ModelInterpretation => matches!(class, ObserverClass::ModelExtractor),
            Self::HumanTestimony => matches!(class, ObserverClass::HumanTestimony),
            _ => !matches!(
                class,
                ObserverClass::ModelExtractor | ObserverClass::HumanTestimony
            ),
        }
    }
}

/// A method's name, owned by its connector: `rust_analyzer.resolve`, `k8s.api.read`,
/// `grafana.query`, `acme_apm.span`. Same naming rule as predicates.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MethodName(String);

/// A method name that breaks the naming rule.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a method name: {0:?}")]
pub struct BadMethodName(pub String);

impl TryFrom<String> for MethodName {
    type Error = BadMethodName;

    fn try_from(s: String) -> Result<Self, BadMethodName> {
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
            Err(BadMethodName(s))
        }
    }
}

impl From<MethodName> for String {
    fn from(m: MethodName) -> Self {
        m.0
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How completely a method sees what it covers. Ordered: best effort < sampled < complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum CoverageModel {
    /// No completeness claim.
    BestEffort,
    /// A declared sample, in parts per thousand (1 to 999).
    Sampled {
        /// Parts per thousand kept.
        per_mille: u16,
    },
    /// Everything in scope, or the method reports what it missed.
    Complete,
}

/// How far a method's output can be trusted not to have been altered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Can be edited after the fact (an ordinary application log).
    Mutable,
    /// The system of record for it (a control plane, a compiler).
    Authoritative,
    /// Tamper-evident (an append-only, signed audit log).
    TamperEvident,
}

/// How sensitive the evidence is, which decides where it may go (a third-party model,
/// a public page).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// May be published.
    Public,
    /// Internal to the customer.
    Internal,
    /// Confidential: never to a third-party model without the customer's grant.
    Confidential,
    /// Restricted (secrets, personal or health data): stays where it was read.
    Restricted,
}

/// How a piece of evidence was obtained: a connector's method with strict, versioned
/// semantics. Two connectors that both produce logs are not equivalent if one keeps a
/// complete, tamper-evident audit log and the other samples 10% of application logs; the
/// method says which, and proof contracts can require it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceMethod {
    /// The connector's name for it, e.g. `grafana.promql.query`.
    pub name: MethodName,
    /// What kind of evidence it is.
    pub category: MethodCategory,
    /// The version of the method's semantics; a change of meaning is a new version.
    pub semantics_version: u32,
    /// How completely it sees.
    pub coverage: CoverageModel,
    /// How far its output can be trusted not to have changed.
    pub trust: Trust,
    /// How sensitive its output is.
    pub classification: DataClass,
    /// What else it can do, declared by the connector (e.g. `historical`, `streaming`).
    pub capabilities: std::collections::BTreeSet<String>,
}

/// A method's category cannot come from an observer of this class.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a {category:?} method cannot come from a {class:?} observer")]
pub struct MethodMismatch {
    /// The method's category.
    pub category: MethodCategory,
    /// The observer's class.
    pub class: ObserverClass,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [MethodCategory; 13] = [
        MethodCategory::StaticResolution,
        MethodCategory::RuntimeObservation,
        MethodCategory::RuntimeState,
        MethodCategory::ApplicationTrace,
        MethodCategory::Metrics,
        MethodCategory::Logs,
        MethodCategory::Configuration,
        MethodCategory::SourceConstruction,
        MethodCategory::ExternalRecord,
        MethodCategory::Documentation,
        MethodCategory::TextSearch,
        MethodCategory::ModelInterpretation,
        MethodCategory::HumanTestimony,
    ];

    #[test]
    fn interpretation_and_testimony_can_never_prove() {
        for c in ALL {
            let weak = matches!(
                c,
                MethodCategory::Documentation
                    | MethodCategory::TextSearch
                    | MethodCategory::ModelInterpretation
                    | MethodCategory::HumanTestimony
            );
            assert_eq!(c.may_prove(), !weak, "{c:?}");
        }
    }

    #[test]
    fn a_model_only_interprets_and_a_person_only_testifies() {
        for c in ALL {
            assert_eq!(
                c.produced_by(ObserverClass::ModelExtractor),
                c == MethodCategory::ModelInterpretation,
                "{c:?}"
            );
            assert_eq!(
                c.produced_by(ObserverClass::HumanTestimony),
                c == MethodCategory::HumanTestimony,
                "{c:?}"
            );
            let instrument = !matches!(
                c,
                MethodCategory::ModelInterpretation | MethodCategory::HumanTestimony
            );
            assert_eq!(
                c.produced_by(ObserverClass::DirectSensor),
                instrument,
                "{c:?}"
            );
        }
    }

    #[test]
    fn connector_method_names_are_open_but_well_formed() {
        for good in [
            "rust_analyzer.resolve",
            "k8s.api.read",
            "grafana.query",
            "acme_apm.span",
        ] {
            assert!(MethodName::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in ["", "Grafana", "k8s api", ".x"] {
            assert!(MethodName::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}
