//! Observers, their classes, coverage, health and calibration (ADR 0006, 0010 in inorbithr/core).
//!
//! Every source of evidence is an observer with a class. The class says what kind of
//! epistemic operation produced its output, and the proof rules treat classes
//! differently: a measurement is not an interpretation, and a person's answer is
//! neither.

use serde::{Deserialize, Serialize};

use crate::ids::ObserverId;
use crate::snapshot::SnapshotId;
use crate::time::{Interval, Timestamp};
use crate::vocabulary::PredicateRef;

/// What kind of operation an observer performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverClass {
    /// Measures the world directly: a process table, a socket, a packet, an eBPF probe,
    /// a Kubernetes API read.
    DirectSensor,
    /// Reads an artefact with a deterministic program: a manifest parser, a Cargo
    /// workspace reader, an Envoy route reader. Same input, same output.
    DeterministicExtractor,
    /// A model reading an artefact and stating what it means. Interprets; never measures.
    ModelExtractor,
    /// A person's answer.
    HumanTestimony,
    /// Another system's statement through its API: GitHub, a CI system, a monitoring
    /// vendor. Trusted as far as that system is calibrated.
    ExternalSystem,
}

impl ObserverClass {
    /// Whether this class can directly observe an artefact's bytes. Only measurement
    /// and deterministic reading can; a model's output is never the artefact.
    #[must_use]
    pub const fn can_observe_artifacts(self) -> bool {
        matches!(self, Self::DirectSensor | Self::DeterministicExtractor)
    }

    /// Whether this class measures or reads deterministically, as opposed to
    /// interpreting or testifying. Absence and security proofs accept only these.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        matches!(
            self,
            Self::DirectSensor | Self::DeterministicExtractor | Self::ExternalSystem
        )
    }
}

/// What an observer was allowed to see when it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityContext {
    /// The identity it ran as (a uid, a service account, an API token's subject).
    pub principal: String,
    /// The capabilities or scopes it held, sorted.
    pub capabilities: Vec<String>,
    /// Whether its authority covered everything in scope. False means "absent" and
    /// "not visible to me" cannot be told apart.
    pub sufficient: bool,
}

/// How completely an observer watched its scope during an interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// The interval it was meant to watch.
    pub expected: Interval,
    /// The interval it actually watched, if any.
    pub actual: Option<Interval>,
    /// Events received.
    pub received: u64,
    /// Events dropped (ring buffer overflow, map eviction, back-pressure).
    pub dropped: u64,
    /// Events it could not parse.
    pub parse_failures: u64,
}

impl Coverage {
    /// Complete: watched the whole expected interval, dropped nothing, parsed everything.
    /// Absence claims need this (ADR 0010).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.dropped == 0
            && self.parse_failures == 0
            && self.actual.as_ref().is_some_and(|a| {
                a.from() <= self.expected.from()
                    && match (a.to(), self.expected.to()) {
                        (None, _) => true,
                        (Some(_), None) => false,
                        (Some(at), Some(et)) => at >= et,
                    }
            })
    }
}

/// An observer's own health at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// Working as declared.
    Healthy,
    /// Working with losses (drops, a missing probe).
    Degraded,
    /// Not working.
    Down,
}

/// Measured performance of an observer kind for one predicate in one environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    /// The predicate it was measured on.
    pub predicate: PredicateRef,
    /// Known events seen / known events generated.
    pub recall: Ratio,
    /// Correct reports / all reports.
    pub precision: Ratio,
    /// The snapshot the measurement ran in (a new kernel or agent version stales it).
    pub measured_in: SnapshotId,
    /// When it was measured.
    pub measured_at: Timestamp,
}

/// A measured ratio, kept as counts so nothing is rounded away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ratio {
    /// Successes.
    pub num: u64,
    /// Trials. Never zero.
    pub den: u64,
}

/// A ratio with no trials.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a ratio needs at least one trial, and at most as many successes as trials")]
pub struct BadRatio;

impl Ratio {
    /// `num` out of `den`.
    ///
    /// # Errors
    /// `den` is zero or `num > den`.
    pub const fn new(num: u64, den: u64) -> Result<Self, BadRatio> {
        if den == 0 || num > den {
            return Err(BadRatio);
        }
        Ok(Self { num, den })
    }

    /// Whether this ratio is at least `other`, compared exactly (no floats).
    #[must_use]
    pub fn at_least(&self, other: &Self) -> bool {
        u128::from(self.num) * u128::from(other.den) >= u128::from(other.num) * u128::from(self.den)
    }
}

/// An observer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observer {
    /// Its identity, e.g. for `observer://account/host-17/ebpf`.
    pub id: ObserverId,
    /// Its class.
    pub class: ObserverClass,
    /// What it is, e.g. `k8s-reader`, `envoy-route-reader`, `ebpf-capture`.
    pub name: String,
    /// Its version: a new version stales its calibration.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Utc};
    use proptest::prelude::*;

    fn at(s: i64) -> Timestamp {
        Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    #[test]
    fn only_measurement_and_deterministic_reading_observe_artefacts() {
        assert!(ObserverClass::DirectSensor.can_observe_artifacts());
        assert!(ObserverClass::DeterministicExtractor.can_observe_artifacts());
        assert!(!ObserverClass::ModelExtractor.can_observe_artifacts());
        assert!(!ObserverClass::HumanTestimony.can_observe_artifacts());
        assert!(!ObserverClass::ExternalSystem.can_observe_artifacts());
    }

    #[test]
    fn coverage_with_any_drop_or_gap_is_incomplete() {
        let expected = Interval::closed(at(0), at(100)).unwrap();
        let full = Coverage {
            expected,
            actual: Some(expected),
            received: 10,
            dropped: 0,
            parse_failures: 0,
        };
        assert!(full.is_complete());
        assert!(
            !Coverage {
                dropped: 1,
                ..full.clone()
            }
            .is_complete()
        );
        assert!(
            !Coverage {
                parse_failures: 1,
                ..full.clone()
            }
            .is_complete()
        );
        assert!(
            !Coverage {
                actual: None,
                ..full.clone()
            }
            .is_complete()
        );
        let late_start = Interval::closed(at(1), at(100)).unwrap();
        assert!(
            !Coverage {
                actual: Some(late_start),
                ..full.clone()
            }
            .is_complete()
        );
        let early_end = Interval::closed(at(0), at(99)).unwrap();
        assert!(
            !Coverage {
                actual: Some(early_end),
                ..full
            }
            .is_complete()
        );
    }

    #[test]
    fn ratios_refuse_zero_trials_and_impossible_counts() {
        assert!(Ratio::new(1, 0).is_err());
        assert!(
            Ratio::new(0, 0).is_err(),
            "zero trials is not a ratio, even with zero successes"
        );
        assert!(Ratio::new(3, 2).is_err());
        assert!(Ratio::new(998, 1000).is_ok());
    }

    proptest! {
        // Exact comparison agrees with the mathematical order of the fractions.
        #[test]
        fn at_least_is_exact(a in 0u64..1000, b in 1u64..1000, c in 0u64..1000, d in 1u64..1000) {
            prop_assume!(a <= b && c <= d);
            let x = Ratio::new(a, b).unwrap();
            let y = Ratio::new(c, d).unwrap();
            prop_assert_eq!(x.at_least(&y), u128::from(a) * u128::from(d) >= u128::from(c) * u128::from(b));
        }
    }
}
