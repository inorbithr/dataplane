//! Helpers for tests, in this crate and in Atlas core: evidence built through the same
//! validating constructors as production code, so no test can create evidence the core
//! would refuse. Compiled for this crate's tests and for the `testkit` feature.

use crate::evidence::{EvidenceItem, EvidenceRef};
use crate::ids::{ExtractionId, ObservationId, ObserverId, TestimonyId};
use crate::method::{CoverageModel, DataClass, EvidenceMethod, MethodCategory, Trust};
use crate::observer::ObserverClass;

/// A method of `category` named `name`: complete, authoritative, internal.
///
/// # Panics
/// `name` is not a well-formed method name.
#[must_use]
pub fn method(name: &str, category: MethodCategory) -> EvidenceMethod {
    method_with(name, category, CoverageModel::Complete)
}

/// A method of `category` named `name` with this coverage.
///
/// # Panics
/// `name` is not a well-formed method name.
#[must_use]
pub fn method_with(
    name: &str,
    category: MethodCategory,
    coverage: CoverageModel,
) -> EvidenceMethod {
    let name = match name.to_owned().try_into() {
        Ok(n) => n,
        Err(e) => panic!("test method name: {e}"),
    };
    EvidenceMethod {
        name,
        category,
        semantics_version: 1,
        coverage,
        trust: Trust::Authoritative,
        classification: DataClass::Internal,
        capabilities: std::collections::BTreeSet::new(),
    }
}

/// The usual method for an observer class.
#[must_use]
pub fn default_method(class: ObserverClass) -> EvidenceMethod {
    match class {
        ObserverClass::DirectSensor => method("probe.observe", MethodCategory::RuntimeObservation),
        ObserverClass::DeterministicExtractor => {
            method("parser.read", MethodCategory::Configuration)
        }
        ObserverClass::ExternalSystem => method("vendor.api", MethodCategory::ExternalRecord),
        ObserverClass::ModelExtractor => method("model.read", MethodCategory::ModelInterpretation),
        ObserverClass::HumanTestimony => method("person.answer", MethodCategory::HumanTestimony),
    }
}

/// A fresh evidence item from a new observer of `class`, with that class's usual method.
#[must_use]
pub fn item(class: ObserverClass) -> EvidenceItem {
    item_with(class, default_method(class))
}

/// A fresh evidence item from a new observer of `class` with `method`.
///
/// # Panics
/// `method` cannot come from `class` (the constructor refuses it).
#[must_use]
pub fn item_with(class: ObserverClass, method: EvidenceMethod) -> EvidenceItem {
    let reference = match class {
        ObserverClass::ModelExtractor => EvidenceRef::Extraction(ExtractionId::new()),
        ObserverClass::HumanTestimony => EvidenceRef::Testimony(TestimonyId::new()),
        _ => EvidenceRef::Observation(ObservationId::new()),
    };
    match EvidenceItem::new(reference, class, ObserverId::new(), method) {
        Ok(i) => i,
        Err(e) => panic!("test evidence: {e}"),
    }
}
