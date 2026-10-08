//! Typed identities (ADR 0013 in inorbithr/core).
//!
//! Every record has an identity that cannot be confused with another kind's: a claim's
//! id is not an observation id, even though both are `UUIDv7` underneath. The kind is a
//! zero-sized marker, so the type checker rejects `fn f(c: ClaimId)` called with an
//! `ObservationId`. `UUIDv7` sorts by creation time, which keeps bitemporal rows in order.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// A kind of record that has an [`Id`]. Implemented only by the markers in this module:
/// the supertrait is crate-private, so no other crate can add a kind.
#[allow(private_bounds)] // the seal is the point
pub trait Kind: sealed::Sealed {
    /// The prefix shown in text form, e.g. `clm` for claims.
    const PREFIX: &'static str;
}

mod sealed {
    pub(crate) trait Sealed {}
}

/// An identity of a record of kind `K`.
pub struct Id<K: Kind> {
    raw: Uuid,
    kind: PhantomData<fn() -> K>,
}

impl<K: Kind> Id<K> {
    /// A new identity, ordered by creation time (`UUIDv7`).
    #[must_use]
    pub fn new() -> Self {
        Self::from_uuid(Uuid::now_v7())
    }

    /// The identity with this UUID, for records read back from the store.
    #[must_use]
    pub const fn from_uuid(raw: Uuid) -> Self {
        Self {
            raw,
            kind: PhantomData,
        }
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn uuid(&self) -> Uuid {
        self.raw
    }
}

impl<K: Kind> Default for Id<K> {
    fn default() -> Self {
        Self::new()
    }
}

// Manual impls: derives would require `K: Clone` etc., which markers need not be.
impl<K: Kind> Clone for Id<K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K: Kind> Copy for Id<K> {}
impl<K: Kind> PartialEq for Id<K> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl<K: Kind> Eq for Id<K> {}
impl<K: Kind> PartialOrd for Id<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K: Kind> Ord for Id<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}
impl<K: Kind> Hash for Id<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}
impl<K: Kind> fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", K::PREFIX, self.raw)
    }
}
impl<K: Kind> fmt::Display for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", K::PREFIX, self.raw)
    }
}
impl<K: Kind> Serialize for Id<K> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(s)
    }
}
impl<'de, K: Kind> Deserialize<'de> for Id<K> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Uuid::deserialize(d).map(Self::from_uuid)
    }
}

macro_rules! kinds {
    ($($(#[$doc:meta])* $marker:ident, $alias:ident, $prefix:literal;)*) => {$(
        $(#[$doc])*
        #[derive(Debug)]
        pub enum $marker {}
        impl sealed::Sealed for $marker {}
        impl Kind for $marker {
            const PREFIX: &'static str = $prefix;
        }
        $(#[$doc])*
        pub type $alias = Id<$marker>;
    )*};
}

kinds! {
    /// Something in the world: a host, a service, a repository, a document.
    EntityKind, EntityId, "ent";
    /// A source of observations, with its class (ADR 0006).
    ObserverKind, ObserverId, "obs";
    /// A fact as an observer reported it.
    ObservationKind, ObservationId, "obv";
    /// A directly observed artefact: bytes at a content digest.
    ArtifactObservationKind, ArtifactObservationId, "art";
    /// A model's reading of an artefact, before any proof.
    ExtractionKind, ExtractionId, "ext";
    /// A person's answer, recorded as evidence.
    TestimonyKind, TestimonyId, "tst";
    /// A typed statement about the world.
    ClaimKind, ClaimId, "clm";
    /// A diff between snapshots or commits; what invalidates claims.
    ChangeKind, ChangeId, "chg";
    /// A premise a proof or hypothesis takes for granted.
    AssumptionKind, AssumptionId, "asm";
    /// A candidate explanation.
    HypothesisKind, HypothesisId, "hyp";
    /// A question with competing hypotheses.
    QuestionKind, QuestionId, "qst";
    /// One recorded reasoner call: model, prompt digest, context.
    ReasonerInstanceKind, ReasonerInstanceId, "rsn";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_of_one_kind_order_by_creation() {
        let a = ClaimId::new();
        let b = ClaimId::new();
        assert!(a < b, "UUIDv7 identities sort by creation time");
    }

    #[test]
    fn id_text_carries_its_kind() {
        let id = ClaimId::from_uuid(Uuid::nil());
        assert_eq!(id.to_string(), "clm_00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn id_round_trips_through_serde_as_a_plain_uuid() {
        let id = EvidenceLikeCheck::id();
        let text = serde_json::to_string(&id).unwrap();
        assert!(text.starts_with('"') && !text.contains('_'));
        let back: ObservationId = serde_json::from_str(&text).unwrap();
        assert_eq!(back, id);
    }

    struct EvidenceLikeCheck;
    impl EvidenceLikeCheck {
        fn id() -> ObservationId {
            ObservationId::new()
        }
    }
}
