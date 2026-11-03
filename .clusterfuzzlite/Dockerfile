# ClusterFuzzLite builder: libFuzzer + the nightly Rust toolchain cargo-fuzz needs.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
# The image's nightly is older than the workspace rust-version; use the nightly pinned in
# mise.toml (`mise run capture:toolchain-check` fails when the two differ).
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-05
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --component rust-src
COPY . $SRC/dataplane
WORKDIR $SRC/dataplane
COPY .clusterfuzzlite/build.sh $SRC/
