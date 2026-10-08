#!/usr/bin/env python3
"""Mutation testing for iohr-evidence's invariants (ADR 0001 in inorbithr/core).

Every invariant listed here is broken on purpose, one at a time, and the crate's tests
must fail. A mutation the tests do not catch means a test proves less than we think.
A mutation whose anchor no longer exists fails the run: when code moves, its mutation
moves with it. A mutation that does not compile proves nothing and fails the run too.

Run from anywhere: python3 crates/iohr-evidence/mutants/mutate.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# (invariant, file, original, mutated)
MUTATIONS = [
    ("a model may observe an artefact", "observer.rs",
     "        matches!(self, Self::DirectSensor | Self::DeterministicExtractor)\n",
     "        matches!(self, Self::DirectSensor | Self::DeterministicExtractor | Self::ModelExtractor)\n"),
    ("a model counts as a deterministic observer", "observer.rs",
     "            Self::DirectSensor | Self::DeterministicExtractor | Self::ExternalSystem\n",
     "            Self::DirectSensor | Self::DeterministicExtractor | Self::ExternalSystem | Self::ModelExtractor\n"),
    ("coverage with drops counts as complete", "observer.rs",
     "        self.dropped == 0\n", "        true\n"),
    ("a ratio may have no trials", "observer.rs",
     "        if den == 0 || num > den {", "        if num > den {"),
    ("an artefact digest is not computed from the bytes", "observation.rs",
     "                digest: ContentDigest::of_bytes(bytes),",
     "                digest: ContentDigest::of_bytes(b\"\"),"),
    ("an extraction may come from any observer", "observation.rs",
     "        if class != ObserverClass::ModelExtractor {\n            return Err(WrongObserverClass {\n                record: \"extraction\",",
     "        if false {\n            return Err(WrongObserverClass {\n                record: \"extraction\","),
    ("a model may produce a runtime observation", "method.rs",
     "            _ => !matches!(\n                class,\n                ObserverClass::ModelExtractor | ObserverClass::HumanTestimony\n            ),",
     "            _ => true,"),
    ("weak categories may prove", "method.rs",
     "    pub const fn may_prove(self) -> bool {\n        !matches!(",
     "    pub const fn may_prove(self) -> bool {\n        true || !matches!("),
    ("evidence accepts a method its observer cannot produce", "evidence.rs",
     "        if !category.produced_by(class) || !kind_matches {", "        if false {"),
    ("snapshot identity depends on more than content", "snapshot.rs",
     "        ContentDigest::of_canonical(&self.components)",
     "        ContentDigest::of_canonical(&crate::ids::ObserverId::new())"),
    ("a known component needs no source", "snapshot.rs",
     "            if matches!(state, ComponentState::Known { .. }) && !has_source {", "            if false && !has_source {"),
    ("uncertain times are guessed as ordered", "time.rs",
     "        TemporalOrder::Unresolved\n    }\n}",
     "        if self.wall <= other.wall { TemporalOrder::Before } else { TemporalOrder::After }\n    }\n}"),
    ("an empty interval is accepted", "time.rs",
     "        if to <= from {\n            return Err(EmptyInterval { from, to });\n        }", ""),
    ("a predicate name may be anything", "vocabulary.rs",
     "        } else {\n            Err(BadPredicateName(s))\n        }", "        } else {\n            Ok(Self(s))\n        }"),
]


def run_tests():
    r = subprocess.run(
        ["cargo", "nextest", "run", "-p", "iohr-evidence", "--no-fail-fast"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    out = r.stdout + r.stderr
    failed = [l.split()[-1] for l in out.splitlines() if l.strip().startswith("FAIL [")]
    return r.returncode, failed


def main():
    backup = tempfile.mkdtemp(prefix="iohr-evidence-mutants-")
    shutil.copytree(SRC, os.path.join(backup, "src"))
    caught = missing = invalid = 0
    try:
        for name, f, a, b in MUTATIONS:
            shutil.rmtree(SRC)
            shutil.copytree(os.path.join(backup, "src"), SRC)
            path = os.path.join(SRC, f)
            text = open(path).read()
            if a not in text:
                missing += 1
                print(f"ANCHOR MISSING  {name}")
                continue
            open(path, "w").write(text.replace(a, b, 1))
            code, failed = run_tests()
            if code != 0 and failed:
                caught += 1
                print(f"CAUGHT  {name}: {len(failed)} failing, e.g. {failed[0]}")
            elif code != 0:
                invalid += 1
                print(f"INVALID {name}: the mutated code does not compile, so it tests nothing")
            else:
                print(f"MISSED  {name}")
    finally:
        shutil.rmtree(SRC)
        shutil.copytree(os.path.join(backup, "src"), SRC)
        shutil.rmtree(backup)
    print(f"{caught}/{len(MUTATIONS)} mutations caught"
          + (f", {missing} anchors missing" if missing else "")
          + (f", {invalid} invalid" if invalid else ""))
    sys.exit(0 if caught == len(MUTATIONS) else 1)


if __name__ == "__main__":
    main()
