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
  # A guest that hangs must not hang the run: 20 minutes per kernel at most.
  if ! timeout 1200 vng --run "$k" --user root --cpus 2 --memory 2G --rwdir="/tmp/e2e=$out" \
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
    L = m["layers"]
    p = L["protocols"]
    print(f"  {m['mode']:8} ingress {c['ingress']['packets']} skb / {c['ingress']['bytes']} B,"
          f" egress {c['egress']['packets']} skb / {c['egress']['bytes']} B,"
          f" kept {c['capabilities_after_attach']['kept'] or 'nothing'}"
          + (f"  FAILED: {', '.join(bad)}" if bad else ""))
    print(f"           protocols: http1 {p['http1_requests']}/{p['http1_responses']} req/resp, tls {p['tls_client_hellos']} (sni {p['tls_with_sni']}),"
          f" dns {p['dns_queries']}/{p['dns_responses']}, h2c {p['http2_connections']}, grpc {p['grpc_calls']}")
    w = L["owners"]["web"]
    print(f"           owners: {L['owners']['summary']['sockets']} sockets, web owner {w.get('owner')} ({w.get('process')}) flows {w.get('flows')}")
    t = L["tcp"]
    print(f"           tcp: rtt samples {sum(t['rtt_ms'].values())}, resets out {t['resets_out']}, listen overflows {t['host']['listen_overflows']};"
          f" drops {L['drops']}")
f = r.get("flood")
if f:
    bad = [k for k, v in f["checks"].items() if not v]
    s, l = f["small_ring"], f["rate_limited"]
    print(f"  flood    4 KiB ring: ring full {s['drops']['ring_buffer_full']}, flows evicted {s['flows']['evicted']}, rss {s['memory']['rss_kib']} KiB;"
          f" 100/s: rate limited {l['drops']['rate_limited']}, rss {l['memory']['rss_kib']} KiB" + (f"  FAILED: {', '.join(bad)}" if bad else ""))
if f:
    u = f["unlimited"]
    print(f"           16 MiB ring, no limit: ring full {u['drops']['ring_buffer_full']}, read {u['copy']['records_read']} of {u['copy']['records_copied']} copied,"
          f" dns after flood {u['dns_after_flood']}, parent rss {u['parent_rss_kib']} KiB, parser rss {u['memory']['rss_kib']} KiB")
p2 = r.get("phase2")
if p2:
    bad = [k for k, v in p2["checks"].items() if not v]
    L = p2["lookups"]
    def b(name):
        c = L[name].get("latency_ms", {}).get("counts", [])
        return ",".join(str(x) for x in c)
    print(f"  phase 2  timing via lookup v2 (bucket counts, bounds 0.5 1 2.5 5 10 25 50 100 250 500 1000 2500 5000 10000 ms):")
    for name in ("fast", "mid", "slow", "slower", "h2slow", "grpc_ok", "grpc_fail"):
        print(f"           {name:9} requests {L[name].get('requests')}, status {L[name].get('status_classes', {})}, grpc {L[name].get('grpc_status', {})}, buckets [{b(name)}]")
    print(f"           pcap last {p2['pcap_last'].get('packets')} packets / {p2['pcap_last'].get('bytes')} B; tshark lines {len(p2['tshark_head'])}+;"
          f" packets {p2['packets']}" + (f"  FAILED: {', '.join(bad)}" if bad else ""))
un = r.get("unit")
if un:
    bad = [k for k, v in un["checks"].items() if not v]
    print(f"  unit     real systemd: dir {un['dir']}, socket {un['socket']}, http1 on lo {un['http1_requests_on_lo']},"
          f" companion kept {un['companion_kept']}, stopped cleanly {un['checks']['stopped_cleanly']}" + (f"  FAILED: {', '.join(bad)}" if bad else ""))
d = r["doctor"]
print(f"  doctor   root exit 0: {d['doctor_root_exit_0']}, unprivileged exit 1: {d['doctor_unprivileged_exit_1']}")
PY
  else
    echo "  no result; log: $out/$k.log"; tail -20 "$out/$k.log"; fail=1
  fi
done
exit "$fail"
