# ADR 0003: The evidence types live here, the proof does not

- Status: accepted
- Date: 2026-10-08
- Context: RFC 0086 (Atlas core) and ADR 0023 in inorbithr/core, PRD 0001 (InOrbit Atlas)

## Context

Atlas (inorbithr/core, private) keeps claims about a system and decides what evidence
proves them. The evidence comes from here: the agent, the capture companion and any
connector a company writes. Those need the evidence types, and a company auditing what
leaves its network needs to read them.

## Decision

`crates/iohr-evidence` holds what evidence *is*: typed ids, content digests, observed time
with its uncertainty, the predicate vocabulary types, evidence methods in closed
categories, observer classes with authority, coverage, health and calibration,
observations, artefact observations, extractions, testimony, evidence references and
failure modes, world snapshots and environment manifests. Its constructors enforce the
rules that make evidence well-formed: an artefact's digest is computed from its bytes, a
model's reading is an extraction and never an observation, a method's category must be one
its observer class can produce, absence coverage fails closed. Atlas core depends on this
crate at a pinned revision.

Nothing here can make truth: no claims, no proof rules, no certificates. That is the
boundary ADR 0023 draws in core: connections supply evidence; Atlas decides what it
proves.

Two dependencies join the workspace for this crate, both already widely audited: `chrono`
(time with serde) and `uuid` (UUIDv7 identities). They define the wire contract shared
with core, which uses the same two, so the types mean the same on both sides.

## Consequences

- A connector can be written against this crate alone and produce evidence Atlas accepts.
- The invariants are proven here: the crate's tests, and `mutants/mutate.py`, which breaks
  each invariant on purpose and must see a test fail (ADR 0001 in core).
- A change to a type here is a contract change with core: change both in step, say so in
  the pull request, and pin the new revision in core.
