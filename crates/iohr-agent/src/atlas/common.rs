//! What every observer here shares: the clock reading, the predicate and method
//! vocabulary, and one way to write an observation with its evidence item.

use std::collections::BTreeSet;
use std::time::Instant;

use chrono::TimeDelta;
use iohr_evidence::evidence::{EvidenceItem, EvidenceRef};
use iohr_evidence::ids::{ArtifactObservationId, ObservationId, ObserverId};
use iohr_evidence::method::{CoverageModel, DataClass, EvidenceMethod, MethodCategory, Trust};
use iohr_evidence::observation::{ArtifactObservation, Observation};
use iohr_evidence::observer::{AuthorityContext, Observer, ObserverClass};
use iohr_evidence::time::{ClockQuality, ObservedTime};
use iohr_evidence::vocabulary::{PredicateRef, Value};

use super::record::{Record, Sink};
use crate::error::{Error, Result};

/// The vocabulary version every predicate here is at.
pub const VOCABULARY: u32 = 1;

/// The clock this run reads: the system clock, in one boot, at whole-second confidence.
#[derive(Debug, Clone)]
pub struct ObservedNow {
    boot_id: String,
    started: Instant,
}

impl ObservedNow {
    /// The clock, with the boot id from the kernel when it offers one.
    #[must_use]
    pub fn now() -> Self {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_owned())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        Self {
            boot_id,
            started: Instant::now(),
        }
    }

    /// A reading taken now.
    #[must_use]
    pub fn at(&self) -> ObservedTime {
        ObservedTime {
            wall: chrono::Utc::now(),
            boot_id: self.boot_id.clone(),
            monotonic_ns: u64::try_from(self.started.elapsed().as_nanos()).ok(),
            clock: ClockQuality {
                source: "system".into(),
                uncertainty: TimeDelta::seconds(1),
            },
        }
    }
}

/// A predicate at this run's vocabulary version.
///
/// # Errors
/// `name` is not a well-formed predicate name.
pub fn predicate(name: &str) -> Result<PredicateRef> {
    let name = name
        .to_owned()
        .try_into()
        .map_err(|e| Error::Atlas(format!("predicate: {e}")))?;
    Ok(PredicateRef {
        name,
        version: VOCABULARY,
    })
}

/// A method of this agent: complete over what it read, mutable at the source (a checkout
/// or a control plane can change after the reading), internal data.
///
/// # Errors
/// `name` is not a well-formed method name.
pub fn method(name: &str, category: MethodCategory) -> Result<EvidenceMethod> {
    let name = name
        .to_owned()
        .try_into()
        .map_err(|e| Error::Atlas(format!("method: {e}")))?;
    Ok(EvidenceMethod {
        name,
        category,
        semantics_version: 1,
        coverage: CoverageModel::Complete,
        trust: Trust::Mutable,
        classification: DataClass::Internal,
        capabilities: BTreeSet::new(),
    })
}

/// One observer of this run, writing through one method.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// The observer.
    pub observer: Observer,
    /// How it reads.
    pub method: EvidenceMethod,
    /// As whom.
    pub authority: AuthorityContext,
    /// The clock.
    pub clock: ObservedNow,
}

impl Ctx {
    /// An observer named `name` of `class`, reading through `method`, as `principal`.
    /// Records the observer in `sink`.
    ///
    /// # Errors
    /// The method cannot come from this class.
    pub fn new(
        sink: &mut Sink,
        name: &str,
        class: ObserverClass,
        method: EvidenceMethod,
        principal: &str,
        capabilities: &[&str],
        clock: &ObservedNow,
    ) -> Result<Self> {
        if !method.category.produced_by(class) {
            return Err(Error::Atlas(format!(
                "a {:?} method cannot come from a {class:?} observer",
                method.category
            )));
        }
        let observer = Observer {
            id: ObserverId::new(),
            class,
            name: name.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        sink.push(Record::Observer(observer.clone()));
        let mut capabilities: Vec<String> = capabilities.iter().map(|&c| c.to_owned()).collect();
        capabilities.sort();
        Ok(Self {
            observer,
            method,
            authority: AuthorityContext {
                principal: principal.to_owned(),
                capabilities,
                sufficient: true,
            },
            clock: clock.clone(),
        })
    }

    /// Observes `bytes` at `location` and records the artefact with its evidence item.
    ///
    /// # Errors
    /// This observer's class cannot observe artefacts.
    pub fn artifact(
        &self,
        sink: &mut Sink,
        location: &str,
        bytes: &[u8],
    ) -> Result<ArtifactObservationId> {
        let a = ArtifactObservation::of_bytes(
            self.observer.id,
            self.observer.class,
            location.to_owned(),
            bytes,
            self.clock.at(),
        )
        .map_err(|e| Error::Atlas(e.to_string()))?;
        let id = a.id();
        let item = EvidenceItem::new(
            EvidenceRef::Artifact(id),
            self.observer.class,
            self.observer.id,
            self.method.clone(),
        )
        .map_err(|e| Error::Atlas(e.to_string()))?;
        sink.push(Record::Artifact(a));
        sink.push(Record::Evidence(item));
        Ok(id)
    }

    /// Records that `subject` (an entity key) has `predicate` = `value`, derived from
    /// these artefacts, with its evidence item.
    ///
    /// # Errors
    /// The predicate name is malformed, or this observer's class cannot make observations.
    pub fn observe(
        &self,
        sink: &mut Sink,
        subject: &str,
        predicate_name: &str,
        value: Value,
        derived_from: &[ArtifactObservationId],
    ) -> Result<ObservationId> {
        let refs: Vec<EvidenceRef> = derived_from
            .iter()
            .map(|a| EvidenceRef::Artifact(*a))
            .collect();
        self.observe_from(sink, subject, predicate_name, value, &refs)
    }

    /// Like [`Self::observe`], derived from any evidence (artefacts or other
    /// observations): what a derived finding cites.
    ///
    /// # Errors
    /// The predicate name is malformed, or this observer's class cannot make observations.
    pub fn observe_from(
        &self,
        sink: &mut Sink,
        subject: &str,
        predicate_name: &str,
        value: Value,
        derived_from: &[EvidenceRef],
    ) -> Result<ObservationId> {
        let subject = sink.entity(subject);
        let o = Observation::new(
            self.observer.id,
            self.observer.class,
            subject,
            predicate(predicate_name)?,
            value,
            self.clock.at(),
            self.authority.clone(),
        )
        .map_err(|e| Error::Atlas(e.to_string()))?;
        let id = o.id();
        let mut item = EvidenceItem::new(
            EvidenceRef::Observation(id),
            self.observer.class,
            self.observer.id,
            self.method.clone(),
        )
        .map_err(|e| Error::Atlas(e.to_string()))?;
        for r in derived_from {
            item = item.derived_from(*r);
        }
        sink.push(Record::Observation(o));
        sink.push(Record::Evidence(item));
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_model_cannot_be_an_observer_here() {
        let mut sink = Sink::default();
        let m = method("k8s.api.read", MethodCategory::RuntimeState).unwrap();
        let e = Ctx::new(
            &mut sink,
            "x",
            ObserverClass::ModelExtractor,
            m,
            "me",
            &[],
            &ObservedNow::now(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("cannot come from"), "{e}");
        assert!(
            sink.records().is_empty(),
            "nothing is recorded for a refused observer"
        );
    }

    #[test]
    fn an_observation_carries_its_evidence_item_and_lineage() {
        let mut sink = Sink::default();
        let m = method("k8s.manifest", MethodCategory::Configuration).unwrap();
        let ctx = Ctx::new(
            &mut sink,
            "x",
            ObserverClass::DeterministicExtractor,
            m,
            "me",
            &["read"],
            &ObservedNow::now(),
        )
        .unwrap();
        let a = ctx
            .artifact(
                &mut sink,
                "repo@abc:devops/k8s/labs.yaml",
                b"kind: Deployment",
            )
            .unwrap();
        let o = ctx
            .observe(
                &mut sink,
                "deployment/tbd/labs",
                "runs_image",
                Value::Text("img".into()),
                &[a],
            )
            .unwrap();
        let items: Vec<&EvidenceItem> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Evidence(i) => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].reference, EvidenceRef::Observation(o));
        assert!(items[1].ancestors.contains(&EvidenceRef::Artifact(a)));
        assert!(predicate("Bad Name").is_err());
    }
}
