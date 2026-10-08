//! World snapshots and environment manifests (ADR 0008 in inorbithr/core).
//!
//! A claim is never scoped to "the version". A [`WorldSnapshot`] records what is known
//! per component: one revision, several at once (mixed, mid-rollout), or explicitly
//! unknown. Its identity is the digest of its canonical content, so the same knowledge
//! is the same snapshot however it was assembled. A claim scopes itself to the parts it
//! depends on ([`WorldSnapshot::restrict`]), so a change to an unrelated component does
//! not touch it.
//!
//! The [`EnvironmentManifest`] says how each known part was learned: which observation
//! reported it. A known part without a source is refused at construction.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::ContentDigest;
use crate::ids::{ObservationId, ObserverId};
use crate::time::Timestamp;

/// A component of a system: `service/labs`, `config/envoy`, `cluster/tbd`.
/// `kind/name`, both parts non-empty, no whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ComponentKey(String);

/// A component key that is not `kind/name`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a component key (kind/name): {0:?}")]
pub struct BadComponentKey(pub String);

impl TryFrom<String> for ComponentKey {
    type Error = BadComponentKey;

    fn try_from(s: String) -> Result<Self, BadComponentKey> {
        let ok = match s.split_once('/') {
            Some((kind, name)) => {
                !kind.is_empty() && !name.is_empty() && !s.chars().any(char::is_whitespace)
            }
            None => false,
        };
        if ok {
            Ok(Self(s))
        } else {
            Err(BadComponentKey(s))
        }
    }
}

impl From<ComponentKey> for String {
    fn from(k: ComponentKey) -> Self {
        k.0
    }
}

impl ComponentKey {
    /// The key as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One way a component's state is pinned down.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "v", rename_all = "snake_case")]
pub enum Revision {
    /// A source commit.
    Commit(String),
    /// A container image digest.
    Image(ContentDigest),
    /// A configuration's content digest.
    Config(ContentDigest),
    /// A named release or roll record.
    Release(String),
}

/// What is known about one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ComponentState {
    /// Known at these revisions. More than one means mixed (a rollout in progress, two
    /// nodes on different builds). Never empty.
    Known {
        /// The revisions, sorted; at least one.
        revisions: BTreeSet<Revision>,
    },
    /// Not known, and why: said explicitly rather than left out.
    Unknown {
        /// Why it is not known, e.g. "not observed", "no authority".
        reason: String,
    },
}

impl ComponentState {
    /// Known at exactly one revision.
    #[must_use]
    pub fn known(revision: Revision) -> Self {
        Self::Known {
            revisions: BTreeSet::from([revision]),
        }
    }

    /// Whether more than one revision runs at once.
    #[must_use]
    pub fn is_mixed(&self) -> bool {
        matches!(self, Self::Known { revisions } if revisions.len() > 1)
    }
}

/// Why a snapshot could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapshotError {
    /// A component marked known with no revision.
    #[error("component {0:?} is known at no revision")]
    EmptyKnown(String),
    /// A known component with no recorded source in the manifest.
    #[error("component {0:?} is known but no observation reports it")]
    Unsourced(String),
    /// A manifest source names a component the snapshot does not have.
    #[error("the manifest names {0:?}, which is not in the snapshot")]
    Extraneous(String),
    /// The scope asks for a component the snapshot does not have.
    #[error("the snapshot has no component {0:?}")]
    NotInSnapshot(String),
}

/// What is known about a system, per component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldSnapshot {
    components: BTreeMap<ComponentKey, ComponentState>,
}

/// A snapshot's identity: the digest of its canonical content.
pub type SnapshotId = ContentDigest;

impl WorldSnapshot {
    /// A snapshot of these components.
    ///
    /// # Errors
    /// A component is marked known with no revision.
    pub fn new(components: BTreeMap<ComponentKey, ComponentState>) -> Result<Self, SnapshotError> {
        for (key, state) in &components {
            if let ComponentState::Known { revisions } = state
                && revisions.is_empty()
            {
                return Err(SnapshotError::EmptyKnown(key.as_str().to_owned()));
            }
        }
        Ok(Self { components })
    }

    /// The snapshot's identity. Equal content, equal identity, whatever the build order.
    #[must_use]
    pub fn id(&self) -> SnapshotId {
        // A BTreeMap of string keys always encodes; the error arm cannot happen, but a
        // library never panics, so it falls back to the digest of the debug form.
        ContentDigest::of_canonical(&self.components).unwrap_or_else(|_| {
            ContentDigest::of_bytes(format!("{:?}", self.components).as_bytes())
        })
    }

    /// The state of one component.
    #[must_use]
    pub fn get(&self, key: &ComponentKey) -> Option<&ComponentState> {
        self.components.get(key)
    }

    /// The components.
    pub fn components(&self) -> impl Iterator<Item = (&ComponentKey, &ComponentState)> {
        self.components.iter()
    }

    /// The part of this snapshot a claim depends on.
    ///
    /// # Errors
    /// A key is not in this snapshot: a claim cannot depend on something unrecorded.
    pub fn restrict(&self, keys: &BTreeSet<ComponentKey>) -> Result<Self, SnapshotError> {
        let mut out = BTreeMap::new();
        for key in keys {
            let state = self
                .components
                .get(key)
                .ok_or_else(|| SnapshotError::NotInSnapshot(key.as_str().to_owned()))?;
            out.insert(key.clone(), state.clone());
        }
        Ok(Self { components: out })
    }

    /// The components whose state differs between `self` and `next`, including ones
    /// added or removed. This is what a change touches.
    #[must_use]
    pub fn changed(&self, next: &Self) -> BTreeSet<ComponentKey> {
        let keys: BTreeSet<&ComponentKey> = self
            .components
            .keys()
            .chain(next.components.keys())
            .collect();
        keys.into_iter()
            .filter(|k| self.components.get(*k) != next.components.get(*k))
            .cloned()
            .collect()
    }
}

/// How one part of a snapshot was learned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSource {
    /// The observation that reported it.
    pub observation: ObservationId,
    /// The observer that made it.
    pub observer: ObserverId,
    /// When it was read.
    pub read_at: Timestamp,
}

/// A snapshot together with where each known part came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentManifest {
    snapshot: WorldSnapshot,
    sources: BTreeMap<ComponentKey, Vec<ManifestSource>>,
}

impl EnvironmentManifest {
    /// A manifest for `snapshot`.
    ///
    /// # Errors
    /// A known component has no source, or a source names a component the snapshot
    /// does not have. Unknown components need no source: their unknownness is the fact.
    pub fn new(
        snapshot: WorldSnapshot,
        sources: BTreeMap<ComponentKey, Vec<ManifestSource>>,
    ) -> Result<Self, SnapshotError> {
        for key in sources.keys() {
            if snapshot.get(key).is_none() {
                return Err(SnapshotError::Extraneous(key.as_str().to_owned()));
            }
        }
        for (key, state) in snapshot.components() {
            let has_source = sources.get(key).is_some_and(|s| !s.is_empty());
            if matches!(state, ComponentState::Known { .. }) && !has_source {
                return Err(SnapshotError::Unsourced(key.as_str().to_owned()));
            }
        }
        Ok(Self { snapshot, sources })
    }

    /// The snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &WorldSnapshot {
        &self.snapshot
    }

    /// Where a component's state came from.
    #[must_use]
    pub fn sources(&self, key: &ComponentKey) -> &[ManifestSource] {
        self.sources.get(key).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(s: &str) -> ComponentKey {
        ComponentKey::try_from(s.to_owned()).unwrap()
    }

    fn commit(c: &str) -> Revision {
        Revision::Commit(c.to_owned())
    }

    #[test]
    fn component_keys_need_kind_and_name() {
        assert!(ComponentKey::try_from("service/labs".to_owned()).is_ok());
        for bad in ["labs", "/labs", "service/", "service/la bs"] {
            assert!(ComponentKey::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn known_with_no_revision_is_refused() {
        let mut m = BTreeMap::new();
        m.insert(
            key("service/labs"),
            ComponentState::Known {
                revisions: BTreeSet::new(),
            },
        );
        assert!(matches!(
            WorldSnapshot::new(m),
            Err(SnapshotError::EmptyKnown(_))
        ));
    }

    #[test]
    fn a_snapshot_can_be_mixed_and_partly_unknown() {
        let mut m = BTreeMap::new();
        m.insert(
            key("service/labs"),
            ComponentState::Known {
                revisions: BTreeSet::from([commit("a1"), commit("b2")]),
            },
        );
        m.insert(
            key("node/pool-b"),
            ComponentState::Unknown {
                reason: "not observed".into(),
            },
        );
        let s = WorldSnapshot::new(m).unwrap();
        assert!(s.get(&key("service/labs")).unwrap().is_mixed());
        assert!(matches!(
            s.get(&key("node/pool-b")),
            Some(ComponentState::Unknown { .. })
        ));
    }

    #[test]
    fn restricting_drops_unrelated_parts_and_refuses_missing_ones() {
        let mut m = BTreeMap::new();
        m.insert(key("service/labs"), ComponentState::known(commit("a1")));
        m.insert(key("service/paging"), ComponentState::known(commit("c3")));
        let s = WorldSnapshot::new(m).unwrap();
        let scope = s.restrict(&BTreeSet::from([key("service/labs")])).unwrap();
        assert_eq!(scope.components().count(), 1);
        assert!(s.restrict(&BTreeSet::from([key("service/none")])).is_err());
    }

    #[test]
    fn an_unrelated_change_does_not_change_a_restricted_scope() {
        let mut m = BTreeMap::new();
        m.insert(key("service/labs"), ComponentState::known(commit("a1")));
        m.insert(key("service/paging"), ComponentState::known(commit("c3")));
        let before = WorldSnapshot::new(m.clone()).unwrap();
        m.insert(key("service/paging"), ComponentState::known(commit("c4")));
        let after = WorldSnapshot::new(m).unwrap();
        let labs = BTreeSet::from([key("service/labs")]);
        assert_eq!(
            before.restrict(&labs).unwrap().id(),
            after.restrict(&labs).unwrap().id()
        );
        assert_eq!(
            before.changed(&after),
            BTreeSet::from([key("service/paging")])
        );
    }

    #[test]
    fn a_manifest_needs_a_source_for_every_known_part_and_none_for_unknown_ones() {
        let mut m = BTreeMap::new();
        m.insert(key("service/labs"), ComponentState::known(commit("a1")));
        m.insert(
            key("node/pool-b"),
            ComponentState::Unknown {
                reason: "no authority".into(),
            },
        );
        let s = WorldSnapshot::new(m).unwrap();
        assert!(matches!(
            EnvironmentManifest::new(s.clone(), BTreeMap::new()),
            Err(SnapshotError::Unsourced(_))
        ));
        let src = ManifestSource {
            observation: ObservationId::new(),
            observer: ObserverId::new(),
            read_at: chrono::Utc::now(),
        };
        let ok = EnvironmentManifest::new(
            s.clone(),
            BTreeMap::from([(key("service/labs"), vec![src.clone()])]),
        );
        assert!(ok.is_ok());
        let extra = EnvironmentManifest::new(
            s,
            BTreeMap::from([
                (key("service/labs"), vec![src.clone()]),
                (key("service/ghost"), vec![src]),
            ]),
        );
        assert!(matches!(extra, Err(SnapshotError::Extraneous(_))));
    }

    proptest! {
        // The identity depends on content only, never on the order parts were added.
        #[test]
        fn identity_is_independent_of_insertion_order(parts in proptest::collection::btree_map("[a-z]{1,6}", "[a-f0-9]{1,8}", 1..12)) {
            let forward: BTreeMap<_, _> = parts.iter()
                .map(|(n, c)| (key(&format!("service/{n}")), ComponentState::known(commit(c)))).collect();
            let mut backward = BTreeMap::new();
            for (n, c) in parts.iter().rev() {
                backward.insert(key(&format!("service/{n}")), ComponentState::known(commit(c)));
            }
            prop_assert_eq!(WorldSnapshot::new(forward).unwrap().id(), WorldSnapshot::new(backward).unwrap().id());
        }

        // A snapshot changed in one component reports exactly that component.
        #[test]
        fn changed_reports_exactly_the_touched_component(parts in proptest::collection::btree_map("[a-z]{1,6}", "[a-f0-9]{1,8}", 1..12), pick in any::<prop::sample::Index>()) {
            let m: BTreeMap<_, _> = parts.iter()
                .map(|(n, c)| (key(&format!("service/{n}")), ComponentState::known(commit(c)))).collect();
            let before = WorldSnapshot::new(m.clone()).unwrap();
            let touched = pick.get(&m.keys().cloned().collect::<Vec<_>>()).clone();
            let mut m2 = m;
            m2.insert(touched.clone(), ComponentState::known(commit("zzz-new")));
            let after = WorldSnapshot::new(m2).unwrap();
            prop_assert_eq!(before.changed(&after), BTreeSet::from([touched]));
        }
    }
}
