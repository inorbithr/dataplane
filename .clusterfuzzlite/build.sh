#!/bin/bash -eu
# Builds every fuzz target in fuzz/ and copies the binaries to $OUT for ClusterFuzzLite.
cd "$SRC/dataplane/fuzz"
cargo fuzz build -O --debug-assertions
for target in fuzz_targets/*.rs; do
  name=$(basename "$target" .rs)
  cp "target/x86_64-unknown-linux-gnu/release/$name" "$OUT/$name"
done
