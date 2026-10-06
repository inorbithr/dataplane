#!/usr/bin/env bash
# Static Linux binaries (musl, static-pie) into dist/bin/<os>-<arch>/: iohr-agent and
# iohr-capture (whose build.rs compiles the eBPF programs with the pinned nightly).
# Builds the host architecture; set TARGETS to build others when a cross C compiler for
# ring is available (CI builds each architecture on its own runner instead).
set -euo pipefail
cd "$(dirname "$0")/.."
host="$(uname -m)"
default="x86_64-unknown-linux-musl"
[ "$host" = "aarch64" ] && default="aarch64-unknown-linux-musl"
TARGETS="${TARGETS:-$default}"
target_dir="${CARGO_TARGET_DIR:-target}"
for t in $TARGETS; do
  case "$t" in
    x86_64-unknown-linux-musl) arch=amd64 ;;
    aarch64-unknown-linux-musl) arch=arm64 ;;
    *) echo "unsupported target $t" >&2; exit 1 ;;
  esac
  # ring's C parts are self-contained; the host C compiler builds them for musl.
  cc_var="CC_${t//-/_}"
  if [ -z "${!cc_var:-}" ] && ! command -v "${t%%-*}-linux-musl-gcc" >/dev/null; then
    export "$cc_var"="${CC:-gcc}"
  fi
  cargo build --release --locked --target "$t" -p iohr-agent -p iohr-capture
  mkdir -p "dist/bin/linux-$arch"
  for b in iohr-agent iohr-capture; do
    cp "$target_dir/$t/release/$b" "dist/bin/linux-$arch/$b"
    echo "dist/bin/linux-$arch/$b"
  done
done
