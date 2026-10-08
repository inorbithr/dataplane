//! The environment manifest: what was running, per deployment, pinned by the commit it
//! was built from and the image digests its pods ran, each part citing the observation
//! that reported it. A deployment seen with neither is in the snapshot as unknown, with
//! the reason, rather than left out.

use std::collections::{BTreeMap, BTreeSet};

use iohr_evidence::ids::ObserverId;
use iohr_evidence::snapshot::{
    ComponentKey, ComponentState, EnvironmentManifest, ManifestSource, Revision, WorldSnapshot,
};
use iohr_evidence::time::Timestamp;

use super::kube::DeploymentFacts;
use crate::error::{Error, Result};

/// Builds the manifest from what the runtime reader found.
///
/// # Errors
/// A deployment key is not a component key, or the manifest is inconsistent (a known
/// component without a source), which the constructors refuse.
pub fn build(
    facts: &BTreeMap<String, DeploymentFacts>,
    observer: ObserverId,
    read_at: Timestamp,
) -> Result<EnvironmentManifest> {
    let mut components = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (key, f) in facts {
        let key = ComponentKey::try_from(key.clone())
            .map_err(|e| Error::Atlas(format!("component key: {e}")))?;
        let mut revisions = BTreeSet::new();
        if let Some(c) = &f.commit {
            revisions.insert(Revision::Commit(c.clone()));
        }
        for d in &f.digests {
            revisions.insert(Revision::Image(*d));
        }
        let state = if revisions.is_empty() {
            ComponentState::Unknown {
                reason: "no image digest or commit annotation observed".into(),
            }
        } else {
            ComponentState::Known { revisions }
        };
        let srcs: Vec<ManifestSource> = f
            .observations
            .iter()
            .map(|o| ManifestSource {
                observation: *o,
                observer,
                read_at,
            })
            .collect();
        if !srcs.is_empty() {
            sources.insert(key.clone(), srcs);
        }
        components.insert(key, state);
    }
    let snapshot =
        WorldSnapshot::new(components).map_err(|e| Error::Atlas(format!("snapshot: {e}")))?;
    EnvironmentManifest::new(snapshot, sources).map_err(|e| Error::Atlas(format!("manifest: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iohr_evidence::digest::ContentDigest;
    use iohr_evidence::ids::ObservationId;

    #[test]
    fn known_deployments_cite_their_observations_and_unknown_ones_say_why() {
        let mut facts = BTreeMap::new();
        facts.insert(
            "deployment/tbd/labs".to_owned(),
            DeploymentFacts {
                digests: vec![ContentDigest::of_bytes(b"image")],
                commit: Some("0b708ed1".into()),
                observations: vec![ObservationId::new(), ObservationId::new()],
            },
        );
        facts.insert(
            "deployment/tbd/ghost".to_owned(),
            DeploymentFacts {
                digests: vec![],
                commit: None,
                observations: vec![ObservationId::new()],
            },
        );
        let m = build(&facts, ObserverId::new(), chrono::Utc::now()).unwrap();
        let labs = ComponentKey::try_from("deployment/tbd/labs".to_owned()).unwrap();
        let ghost = ComponentKey::try_from("deployment/tbd/ghost".to_owned()).unwrap();
        assert!(
            matches!(m.snapshot().get(&labs), Some(ComponentState::Known { revisions }) if revisions.len() == 2)
        );
        assert!(matches!(
            m.snapshot().get(&ghost),
            Some(ComponentState::Unknown { .. })
        ));
        assert_eq!(m.sources(&labs).len(), 2);
        // The same facts give the same snapshot identity, whatever the ids.
        let again = build(&facts, ObserverId::new(), chrono::Utc::now()).unwrap();
        assert_eq!(m.snapshot().id(), again.snapshot().id());
    }
}
