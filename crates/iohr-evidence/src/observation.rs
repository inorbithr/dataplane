//! What observers report (ADR 0006 in inorbithr/core).
//!
//! Four records, one per epistemic operation, never interchangeable:
//!
//! - [`Observation`]: a measured or deterministically read fact (direct sensors,
//!   deterministic extractors, external systems).
//! - [`ArtifactObservation`]: an artefact's bytes, named by their digest. Only a direct
//!   sensor or a deterministic extractor can make one.
//! - [`Extraction`]: a model's reading of one or more artefacts: what it says they mean.
//!   Only a model extractor makes one, always citing the artefacts it read.
//! - [`Testimony`]: what a person said, in which role.
//!
//! The chain is artefact → [`ArtifactObservation`] → [`Extraction`] → (proof rules) →
//! supported claim. A prompt injection in an artefact can corrupt an extraction, the
//! interpretation, but never the artefact observation: its digest is computed from the
//! bytes, not reported by a model.

use serde::{Deserialize, Serialize};

use crate::digest::ContentDigest;
use crate::ids::{
    ArtifactObservationId, EntityId, ExtractionId, ObservationId, ObserverId, ReasonerInstanceId,
    TestimonyId,
};
use crate::nonempty::NonEmpty;
use crate::observer::{AuthorityContext, ObserverClass};
use crate::time::{ObservedTime, Timestamp};
use crate::vocabulary::{PredicateRef, Value};

/// Whether a statement asserts that something holds, or that it is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    /// "A depends on B", "port 443 is open".
    Holds,
    /// "No egress from A in this window", "no port is open". Needs coverage (ADR 0010).
    Absent,
}

/// What a statement says: subject, predicate, value and polarity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// What it is about.
    pub subject: EntityId,
    /// What is said of it.
    pub predicate: PredicateRef,
    /// The object.
    pub value: Value,
    /// Holds or absent.
    pub polarity: Polarity,
}

/// A record was made by an observer of the wrong class for it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a {record} cannot come from a {class:?} observer")]
pub struct WrongObserverClass {
    /// The record being built.
    pub record: &'static str,
    /// The observer's class.
    pub class: ObserverClass,
}

/// A measured or deterministically read fact. Always positive: an observer reports what
/// it saw; absence is concluded from coverage, never reported as an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    id: ObservationId,
    observer: ObserverId,
    class: ObserverClass,
    subject: EntityId,
    predicate: PredicateRef,
    value: Value,
    observed: ObservedTime,
    authority: AuthorityContext,
}

impl Observation {
    /// A new observation.
    ///
    /// # Errors
    /// The observer is a model extractor (its output is an [`Extraction`]) or a person
    /// (their answer is [`Testimony`]).
    #[allow(clippy::too_many_arguments)] // every field is a required part of the record
    pub fn new(
        observer: ObserverId,
        class: ObserverClass,
        subject: EntityId,
        predicate: PredicateRef,
        value: Value,
        when: ObservedTime,
        authority: AuthorityContext,
    ) -> Result<Self, WrongObserverClass> {
        if !class.is_deterministic() {
            return Err(WrongObserverClass {
                record: "observation",
                class,
            });
        }
        Ok(Self {
            id: ObservationId::new(),
            observer,
            class,
            subject,
            predicate,
            value,
            observed: when,
            authority,
        })
    }

    /// Its identity.
    #[must_use]
    pub const fn id(&self) -> ObservationId {
        self.id
    }
    /// The observer.
    #[must_use]
    pub const fn observer(&self) -> ObserverId {
        self.observer
    }
    /// The observer's class.
    #[must_use]
    pub const fn class(&self) -> ObserverClass {
        self.class
    }
    /// The statement observed, always [`Polarity::Holds`].
    #[must_use]
    pub fn statement(&self) -> Statement {
        Statement {
            subject: self.subject,
            predicate: self.predicate.clone(),
            value: self.value.clone(),
            polarity: Polarity::Holds,
        }
    }
    /// When.
    #[must_use]
    pub const fn observed(&self) -> &ObservedTime {
        &self.observed
    }
    /// With what authority.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityContext {
        &self.authority
    }
}

/// Where an artefact lives and what its bytes were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Its location: a repository path at a commit, a URL, a document version.
    pub location: String,
    /// The digest of the bytes read.
    pub digest: ContentDigest,
}

/// An artefact's bytes, observed directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactObservation {
    id: ArtifactObservationId,
    observer: ObserverId,
    class: ObserverClass,
    artifact: ArtifactRef,
    observed: ObservedTime,
}

impl ArtifactObservation {
    /// Observe these bytes at this location. The digest is computed here, from the bytes,
    /// so no caller (and no model) can report a digest the bytes don't have.
    ///
    /// # Errors
    /// The observer is not a direct sensor or deterministic extractor.
    pub fn of_bytes(
        observer: ObserverId,
        class: ObserverClass,
        location: String,
        bytes: &[u8],
        when: ObservedTime,
    ) -> Result<Self, WrongObserverClass> {
        if !class.can_observe_artifacts() {
            return Err(WrongObserverClass {
                record: "artifact observation",
                class,
            });
        }
        Ok(Self {
            id: ArtifactObservationId::new(),
            observer,
            class,
            artifact: ArtifactRef {
                location,
                digest: ContentDigest::of_bytes(bytes),
            },
            observed: when,
        })
    }

    /// Its identity.
    #[must_use]
    pub const fn id(&self) -> ArtifactObservationId {
        self.id
    }
    /// The artefact.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
    /// The observer's class.
    #[must_use]
    pub const fn class(&self) -> ObserverClass {
        self.class
    }
    /// The observer.
    #[must_use]
    pub const fn observer(&self) -> ObserverId {
        self.observer
    }
}

/// A model's reading of artefacts: what it says they mean. Interpretation, never
/// measurement; weak until proof rules corroborate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extraction {
    id: ExtractionId,
    extractor: ObserverId,
    reasoner: ReasonerInstanceId,
    read: NonEmpty<ArtifactObservationId>,
    statement: Statement,
    span: Option<String>,
}

impl Extraction {
    /// A model extractor's statement about the artefacts it read.
    ///
    /// # Errors
    /// The extractor is not a model extractor.
    pub fn new(
        extractor: ObserverId,
        class: ObserverClass,
        reasoner: ReasonerInstanceId,
        read: NonEmpty<ArtifactObservationId>,
        statement: Statement,
        span: Option<String>,
    ) -> Result<Self, WrongObserverClass> {
        if class != ObserverClass::ModelExtractor {
            return Err(WrongObserverClass {
                record: "extraction",
                class,
            });
        }
        Ok(Self {
            id: ExtractionId::new(),
            extractor,
            reasoner,
            read,
            statement,
            span,
        })
    }

    /// Its identity.
    #[must_use]
    pub const fn id(&self) -> ExtractionId {
        self.id
    }
    /// The artefacts it read.
    #[must_use]
    pub fn read(&self) -> &[ArtifactObservationId] {
        self.read.as_slice()
    }
    /// What it says.
    #[must_use]
    pub const fn statement(&self) -> &Statement {
        &self.statement
    }
    /// The recorded model call that produced it.
    #[must_use]
    pub const fn reasoner(&self) -> ReasonerInstanceId {
        self.reasoner
    }
    /// The extractor.
    #[must_use]
    pub const fn extractor(&self) -> ObserverId {
        self.extractor
    }
}

/// A person's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Testimony {
    /// Its identity.
    pub id: TestimonyId,
    /// Who answered (their principal).
    pub person: String,
    /// In which role (owner of the service, tech lead, security).
    pub role: String,
    /// What they said.
    pub statement: Statement,
    /// When.
    pub given_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::ClockQuality;
    use chrono::{TimeDelta, Utc};

    fn now() -> ObservedTime {
        ObservedTime {
            wall: Utc::now(),
            boot_id: "b".into(),
            monotonic_ns: None,
            clock: ClockQuality {
                source: "ntp".into(),
                uncertainty: TimeDelta::milliseconds(5),
            },
        }
    }

    #[test]
    fn a_model_cannot_observe_an_artefact() {
        let r = ArtifactObservation::of_bytes(
            ObserverId::new(),
            ObserverClass::ModelExtractor,
            "foo.rs".into(),
            b"x",
            now(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn the_artefact_digest_comes_from_the_bytes() {
        let a = ArtifactObservation::of_bytes(
            ObserverId::new(),
            ObserverClass::DeterministicExtractor,
            "foo.rs".into(),
            b"fn main() {}",
            now(),
        )
        .unwrap();
        assert_eq!(
            a.artifact().digest,
            ContentDigest::of_bytes(b"fn main() {}")
        );
    }

    #[test]
    fn only_a_model_extractor_makes_an_extraction() {
        let s = Statement {
            subject: EntityId::new(),
            predicate: PredicateRef {
                name: "depends_on".to_owned().try_into().unwrap(),
                version: 1,
            },
            value: Value::Entity(EntityId::new()),
            polarity: Polarity::Holds,
        };
        let read = NonEmpty::one(ArtifactObservationId::new());
        for class in [
            ObserverClass::DirectSensor,
            ObserverClass::DeterministicExtractor,
            ObserverClass::HumanTestimony,
            ObserverClass::ExternalSystem,
        ] {
            assert!(
                Extraction::new(
                    ObserverId::new(),
                    class,
                    ReasonerInstanceId::new(),
                    read.clone(),
                    s.clone(),
                    None
                )
                .is_err()
            );
        }
        assert!(
            Extraction::new(
                ObserverId::new(),
                ObserverClass::ModelExtractor,
                ReasonerInstanceId::new(),
                read,
                s,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn a_model_or_a_person_cannot_make_an_observation() {
        let auth = AuthorityContext {
            principal: "p".into(),
            capabilities: vec![],
            sufficient: true,
        };
        let p = PredicateRef {
            name: "exists".to_owned().try_into().unwrap(),
            version: 1,
        };
        for class in [ObserverClass::ModelExtractor, ObserverClass::HumanTestimony] {
            assert!(
                Observation::new(
                    ObserverId::new(),
                    class,
                    EntityId::new(),
                    p.clone(),
                    Value::Bool(true),
                    now(),
                    auth.clone()
                )
                .is_err()
            );
        }
    }
}
