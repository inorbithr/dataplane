//! What `atlas observe` writes: one JSON record per line, typed by `record`. Every record
//! is built through `iohr_evidence`'s validating constructors, so a consumer can trust its
//! shape; what the evidence proves is decided elsewhere (Atlas core, ADR 0023 there).

use std::collections::BTreeMap;
use std::io::Write;

use iohr_evidence::evidence::EvidenceItem;
use iohr_evidence::ids::EntityId;
use iohr_evidence::observation::{ArtifactObservation, Observation};
use iohr_evidence::observer::Observer;
use iohr_evidence::snapshot::EnvironmentManifest;
use iohr_evidence::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// One line of the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    /// The first record: what this run looked at.
    Run(RunRecord),
    /// An observer this run used; its id is cited by every observation it made.
    Observer(Observer),
    /// A thing the observations are about, named by the key a consumer resolves it by
    /// (`kind/name`, for example `deployment/tbd/labs`). The id is derived from the key,
    /// so the same key always gets the same id.
    Entity {
        /// The id used in observations.
        id: EntityId,
        /// The natural key.
        key: String,
    },
    /// An artefact's bytes, by digest.
    Artifact(ArtifactObservation),
    /// A fact an observer read.
    Observation(Observation),
    /// How a record above was obtained (its method) and what it was derived from. One
    /// per artefact and per observation, written right after it.
    Evidence(EvidenceItem),
    /// What was running, per component, and where each part was learned.
    Manifest(EnvironmentManifest),
}

/// The run itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    /// When it started.
    pub started_at: Timestamp,
    /// The agent's version.
    pub agent_version: String,
    /// The repository read, if any: its commit, never its path.
    pub repository: Option<RepositoryRef>,
    /// The cluster read, if any: the kubeconfig context's name and the namespaces.
    pub cluster: Option<ClusterRef>,
    /// The documentation sources read, if any: their ids and providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub docs: Vec<DocsSourceRef>,
}

/// A documentation source this run read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocsSourceRef {
    /// Its id in `agent.toml`.
    pub id: String,
    /// The provider.
    pub provider: String,
    /// The workspace or site, by name, as the provider reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

/// A repository this run read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryRef {
    /// A name for it (the directory's name).
    pub name: String,
    /// The commit checked out, when the directory is a git checkout.
    pub commit: Option<String>,
}

/// A cluster this run read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterRef {
    /// The kubeconfig context.
    pub context: String,
    /// The namespaces read.
    pub namespaces: Vec<String>,
}

/// Collects records and the entities they name; writes them as JSON lines.
#[derive(Debug, Default)]
pub struct Sink {
    records: Vec<Record>,
    entities: BTreeMap<String, EntityId>,
}

impl Sink {
    /// Adds a record.
    pub fn push(&mut self, r: Record) {
        self.records.push(r);
    }

    /// Puts a record first (the run record, written once the run knows what it read).
    pub fn prepend(&mut self, r: Record) {
        self.records.insert(0, r);
    }

    /// The entity for `key`, recorded on first use. Keys are `kind/name` and the id is a
    /// function of the key alone, so runs agree on ids without coordination.
    pub fn entity(&mut self, key: &str) -> EntityId {
        if let Some(id) = self.entities.get(key) {
            return *id;
        }
        let id = entity_id(key);
        self.entities.insert(key.to_owned(), id);
        self.records.push(Record::Entity {
            id,
            key: key.to_owned(),
        });
        id
    }

    /// The key of an entity recorded here, by id.
    #[must_use]
    pub fn key_of(&self, id: EntityId) -> Option<&str> {
        self.entities
            .iter()
            .find(|(_, v)| **v == id)
            .map(|(k, _)| k.as_str())
    }

    /// The records so far.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// How many evidence items each method produced: the counts a run reports.
    #[must_use]
    pub fn per_method(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for r in &self.records {
            if let Record::Evidence(item) = r {
                *out.entry(item.method.name.to_string()).or_insert(0) += 1;
            }
        }
        out
    }

    /// Writes every record as one JSON line.
    ///
    /// # Errors
    /// The writer failed, or a record could not be encoded.
    pub fn write_to(&self, mut w: impl Write) -> Result<()> {
        for r in &self.records {
            let line = serde_json::to_string(r)
                .map_err(|e| Error::Atlas(format!("cannot encode a record: {e}")))?;
            writeln!(w, "{line}").map_err(|e| Error::Atlas(format!("cannot write: {e}")))?;
        }
        Ok(())
    }
}

/// The id for an entity key: a UUID (version 8) made from the SHA-256 of a fixed prefix
/// and the key. Deterministic on purpose: Atlas resolves entities by key and id alike.
#[must_use]
pub fn entity_id(key: &str) -> EntityId {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(b"iohr-agent atlas entity\0");
    h.update(key.as_bytes());
    let out = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&out[..16]);
    EntityId::from_uuid(uuid::Builder::from_custom_bytes(bytes).into_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_ids_are_a_function_of_the_key() {
        assert_eq!(
            entity_id("deployment/tbd/labs"),
            entity_id("deployment/tbd/labs")
        );
        assert_ne!(
            entity_id("deployment/tbd/labs"),
            entity_id("deployment/tbd/paging")
        );
        let mut s = Sink::default();
        let a = s.entity("crate/tbd-labs");
        let b = s.entity("crate/tbd-labs");
        assert_eq!(a, b);
        assert_eq!(s.records().len(), 1, "an entity is recorded once");
        assert_eq!(s.key_of(a), Some("crate/tbd-labs"));
    }

    #[test]
    fn records_round_trip_as_json_lines() {
        let mut s = Sink::default();
        s.push(Record::Run(RunRecord {
            started_at: chrono::Utc::now(),
            agent_version: "test".into(),
            repository: Some(RepositoryRef {
                name: "core".into(),
                commit: Some("0b708ed1".into()),
            }),
            cluster: None,
            docs: Vec::new(),
        }));
        s.entity("deployment/tbd/labs");
        let mut out = Vec::new();
        s.write_to(&mut out).unwrap();
        let lines: Vec<Record> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(matches!(lines[0], Record::Run(_)));
        assert!(matches!(&lines[1], Record::Entity { key, .. } if key == "deployment/tbd/labs"));
        assert!(s.per_method().is_empty());
    }
}
