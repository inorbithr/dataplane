#!/usr/bin/env bash
# .deb (cargo-deb) and .rpm (cargo-generate-rpm) with the systemd unit, from the static
# binaries in dist/bin. Output: dist/packages/.
set -euo pipefail
cd "$(dirname "$0")/.."
target_dir="${CARGO_TARGET_DIR:-target}"
mkdir -p dist/packages
# RPM versions may not contain '-': a pre-release is written with '~' (0.1.0~alpha.4), which
# RPM sorts before the release, as Debian does.
version=$(cargo pkgid -p iohr-agent | sed 's/.*[#@]//')
rpm_version="${version//-/\~}"
for dir in dist/bin/linux-*; do
  arch="${dir##*-}"
  case "$arch" in
    amd64) t=x86_64-unknown-linux-musl; rpm_arch=x86_64 ;;
    arm64) t=aarch64-unknown-linux-musl; rpm_arch=aarch64 ;;
    *) continue ;;
  esac
  # Both tools package the binary from the target directory: put the static one there.
  mkdir -p "$target_dir/$t/release"
  cp "$dir/iohr-agent" "$target_dir/$t/release/iohr-agent"
  cargo deb -p iohr-agent --no-build --no-strip --target "$t" --output dist/packages/
  cargo generate-rpm -p crates/iohr-agent --target "$t" --arch "$rpm_arch" -o dist/packages/ \
    -s "version = \"$rpm_version\""
done
ls -1 dist/packages
