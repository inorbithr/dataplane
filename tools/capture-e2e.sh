#!/usr/bin/env bash
# End-to-end test of iohr-capture inside throwaway VMs (virtme-ng + QEMU/KVM), one per
# kernel in KERNELS. eBPF is loaded only inside the VM, never on the machine running this
# script. The guest side is tools/capture_e2e_guest.py; results land in
# dist/capture-e2e/<kernel>.json. Kernels are Ubuntu mainline builds that virtme-ng
# downloads and caches in ~/.cache/virtme-ng (docs/capture/develop.md).
set -euo pipefail
cd "$(dirname "$0")/.."
KERNELS="${KERNELS:-v5.15.222 v6.6.158 v6.12.112}"
target_dir="${CARGO_TARGET_DIR:-target}"

for tool in vng qemu-system-x86_64 python3; do
  command -v "$tool" >/dev/null || { echo "missing $tool: see docs/capture/develop.md" >&2; exit 2; }
done
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "no access to /dev/kvm: the VMs would be very slow; see docs/capture/develop.md (kvm group)" >&2
  exit 2
fi

# A static binary, so the guest needs nothing from the build.
t="$(uname -m)-unknown-linux-musl"
cc_var="CC_${t//-/_}"
export "$cc_var"="${!cc_var:-${CC:-gcc}}"
cargo build --release --locked --target "$t" -p iohr-capture
bin="$(realpath "$target_dir/$t/release/iohr-capture")"
out="$(realpath -m dist/capture-e2e)"
mkdir -p "$out"

fail=0
for k in $KERNELS; do
  echo "== kernel $k"
  rm -f "$out/$k.json"
  # --user root inside the guest only; the guest sees this host's files read-only, with
  # $out writable (as /tmp/e2e) for the result.
  if ! vng --run "$k" --user root --cpus 2 --memory 2G --rwdir="/tmp/e2e=$out" \
      --exec "python3 $(pwd)/tools/capture_e2e_guest.py $bin /tmp/e2e/$k.json" \
      </dev/null >"$out/$k.log" 2>&1; then
    fail=1
  fi
  if [ -s "$out/$k.json" ]; then
    python3 - "$out/$k.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"kernel {r['kernel']}: {'PASS' if r['ok'] else 'FAIL'}")
for m in r["modes"]:
    c = m["capture"]
    bad = [k for k, v in m["checks"].items() if not v]
    print(f"  {m['mode']:8} ingress {c['ingress']['packets']} pkts / {c['ingress']['bytes']} B,"
          f" egress {c['egress']['packets']} pkts / {c['egress']['bytes']} B,"
          f" kept {c['capabilities_after_attach']['kept'] or 'nothing'}"
          + (f"  FAILED: {', '.join(bad)}" if bad else ""))
d = r["doctor"]
print(f"  doctor   root exit 0: {d['doctor_root_exit_0']}, unprivileged exit 1: {d['doctor_unprivileged_exit_1']}")
PY
  else
    echo "  no result; log: $out/$k.log"; tail -20 "$out/$k.log"; fail=1
  fi
done
exit "$fail"
