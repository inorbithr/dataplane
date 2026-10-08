//! Evidence references, lineage and failure modes (ADR 0009 in inorbithr/core).
//!
//! Corroboration counts only between independent sources. Two pieces of evidence are
//! dependent when they share an ancestor (four dashboards on one trace) or a failure
//! mode (the same host clock, the same kernel, the same extraction model). An item
//! records both; Atlas core groups items by them, and proof rules count groups, not
//! items.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::digest::ContentDigest;
use crate::ids::{
    ArtifactObservationId, ClaimId, ExtractionId, ObservationId, ObserverId, TestimonyId,
};
use crate::method::{EvidenceMethod, MethodCategory, MethodMismatch};
use crate::observer::ObserverClass;

/// A reference to one piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum EvidenceRef {
    /// A measured or deterministically read fact.
    Observation(ObservationId),
    /// An artefact's bytes.
    Artifact(ArtifactObservationId),
    /// A model's reading.
    Extraction(ExtractionId),
    /// A person's answer.
    Testimony(TestimonyId),
    /// Another claim (for derived claims).
    Claim(ClaimId),
}

/// A way two pieces of evidence can fail together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "v", rename_all = "snake_case")]
pub enum FailureMode {
    /// Read by the same observer.
    Observer(ObserverId),
    /// Timed by the same host clock.
    HostClock(String),
    /// Seen through the same kernel in the same boot.
    Kernel {
        /// The host.
        host: String,
        /// The boot.
        boot: String,
    },
    /// Derived from the same upstream source (one trace, one export).
    Upstream(String),
    /// Produced by the same model and prompt.
    Model(ContentDigest),
}

/// One piece of evidence with what it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// The evidence.
    pub reference: EvidenceRef,
    /// The class of the observer that produced it.
    pub class: ObserverClass,
    /// How it was obtained.
    pub method: EvidenceMethod,
    /// Everything it was derived from, recorded at derivation time. Its own reference is
    /// implied and need not be listed.
    pub ancestors: BTreeSet<EvidenceRef>,
    /// How it can fail together with other evidence. Its observer is always one.
    pub failure_modes: BTreeSet<FailureMode>,
}

impl EvidenceItem {
    /// An item produced by `observer` with `method`, with no other ancestry yet.
    ///
    /// # Errors
    /// The method's category cannot come from this observer class (a model's runtime
    /// observation, an instrument's testimony), or the reference's kind does not match
    /// it (an extraction must be a model interpretation, testimony must be testimony).
    pub fn new(
        reference: EvidenceRef,
        class: ObserverClass,
        observer: ObserverId,
        method: EvidenceMethod,
    ) -> Result<Self, MethodMismatch> {
        let category = method.category;
        let kind_matches = match reference {
            EvidenceRef::Extraction(_) => category == MethodCategory::ModelInterpretation,
            EvidenceRef::Testimony(_) => category == MethodCategory::HumanTestimony,
            EvidenceRef::Observation(_) | EvidenceRef::Artifact(_) => !matches!(
                category,
                MethodCategory::ModelInterpretation | MethodCategory::HumanTestimony
            ),
            EvidenceRef::Claim(_) => true,
        };
        if !category.produced_by(class) || !kind_matches {
            return Err(MethodMismatch { category, class });
        }
        Ok(Self {
            reference,
            class,
            method,
            ancestors: BTreeSet::new(),
            failure_modes: BTreeSet::from([FailureMode::Observer(observer)]),
        })
    }

    /// The same item, recorded as derived from `ancestor`.
    #[must_use]
    pub fn derived_from(mut self, ancestor: EvidenceRef) -> Self {
        self.ancestors.insert(ancestor);
        self
    }

    /// The same item, sharing `mode` with whatever else has it.
    #[must_use]
    pub fn with_failure_mode(mut self, mode: FailureMode) -> Self {
        self.failure_modes.insert(mode);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ExtractionId, ObservationId, TestimonyId};
    use crate::method::MethodCategory;
    use crate::testkit::{default_method, item, method};

    #[test]
    fn an_item_starts_with_its_observer_as_its_only_failure_mode() {
        let observer = ObserverId::new();
        let i = EvidenceItem::new(
            EvidenceRef::Observation(ObservationId::new()),
            ObserverClass::DirectSensor,
            observer,
            default_method(ObserverClass::DirectSensor),
        )
        .unwrap();
        assert_eq!(
            i.failure_modes,
            BTreeSet::from([FailureMode::Observer(observer)])
        );
        assert!(i.ancestors.is_empty());
        let trace = EvidenceRef::Observation(ObservationId::new());
        let derived = item(ObserverClass::ExternalSystem).derived_from(trace);
        assert!(derived.ancestors.contains(&trace));
    }

    #[test]
    fn evidence_refuses_a_method_its_observer_cannot_produce() {
        let obs_ref = EvidenceRef::Observation(ObservationId::new());
        // A model claiming a runtime observation.
        assert!(
            EvidenceItem::new(
                obs_ref,
                ObserverClass::ModelExtractor,
                ObserverId::new(),
                method("x.y", MethodCategory::RuntimeObservation)
            )
            .is_err()
        );
        // An instrument claiming an interpretation.
        assert!(
            EvidenceItem::new(
                obs_ref,
                ObserverClass::DirectSensor,
                ObserverId::new(),
                method("x.y", MethodCategory::ModelInterpretation)
            )
            .is_err()
        );
        // An extraction dressed up as configuration.
        let ext = EvidenceRef::Extraction(ExtractionId::new());
        assert!(
            EvidenceItem::new(
                ext,
                ObserverClass::ModelExtractor,
                ObserverId::new(),
                method("x.y", MethodCategory::Configuration)
            )
            .is_err()
        );
        // Testimony must be testimony.
        let tst = EvidenceRef::Testimony(TestimonyId::new());
        assert!(
            EvidenceItem::new(
                tst,
                ObserverClass::HumanTestimony,
                ObserverId::new(),
                method("x.y", MethodCategory::Documentation)
            )
            .is_err()
        );
    }
}
