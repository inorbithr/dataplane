//! `iohr-evidence`: what Atlas evidence is (RFC 0086 and ADR 0023 in inorbithr/core).
//!
//! The agent, the capture companion and any connector produce evidence with these types;
//! Atlas core (private) decides what that evidence proves. This crate holds no claims,
//! no proof rules and no certificates on purpose: a connector can make well-formed
//! evidence, and nothing here can make truth.
//!
//! What the constructors enforce, by type or by test:
//!
//! 1. An id of one kind is not an id of another ([`ids`]).
//! 2. Equal content has an equal digest, whatever the build order ([`digest`], [`snapshot`]).
//! 3. A model never observes an artefact: an artefact's digest is computed from its bytes
//!    by a direct sensor or a deterministic extractor, and a model's reading is an
//!    [`observation::Extraction`] that cites the artefacts it read ([`observation`]).
//! 4. Observations come only from instruments and deterministic readers; people testify
//!    and models interpret ([`observer::ObserverClass`], [`method::MethodCategory`]).
//! 5. A method's category must be one its observer class can produce, and prose, text
//!    search, interpretation and testimony can never be the method that proves a claim
//!    ([`method`], [`evidence::EvidenceItem::new`]).
//! 6. Absence needs complete coverage: a drop, a parse failure or a gap makes coverage
//!    incomplete ([`observer::Coverage`]).
//! 7. Two readings whose uncertainty windows overlap are unordered, never guessed
//!    ([`time::ObservedTime`]).
//! 8. A snapshot says per component what is known, at one or several revisions, or that
//!    it is unknown and why; a known part needs a source ([`snapshot`]).
//!
//! The mutation suite in `mutants/` breaks each of these on purpose; the tests must catch
//! every one.
//!
//! ```compile_fail,E0308
//! // An id of one kind is not an id of another.
//! fn takes_observer(_: iohr_evidence::ids::ObserverId) {}
//! takes_observer(iohr_evidence::ids::ObservationId::new());
//! ```

pub mod digest;
pub mod evidence;
pub mod ids;
pub mod method;
pub mod nonempty;
pub mod observation;
pub mod observer;
pub mod snapshot;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod time;
pub mod vocabulary;
