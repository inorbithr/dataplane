# Installing and running iohr-capture

`iohr-capture` is the capture companion of the InOrbit agent. It attaches small eBPF
programs to one network interface, counts what passes in each direction, and reports the
totals. It is a separate program with its own service because it needs three kernel
capabilities to start; the agent itself stays unprivileged
([ADR 0002](../adr/0002-capture-companion.md)).

Status: phase 0, a preview. It counts packets and bytes per direction on one interface.
Protocols, owners, TCP health and request timing come in later versions.

## What it never does

- **It never drops, delays or changes a packet.** The programs always hand the packet on
  unchanged (`TC_ACT_OK`).
- **It stores nothing and sends nothing.** In this version `iohr-capture run` prints its
  totals when it stops. It opens no network connection (its unit blocks all IP traffic).
- **It does not keep its privileges.** Right after attaching it gives up its capabilities
  and checks that they are gone. On kernels before 6.6 it keeps `CAP_NET_ADMIN` to remove
  its filters when it stops, and before 6.5 also `CAP_BPF` to read its own counters (the
  run report lists what was kept).
- **It is never `--privileged`** in a container and never runs as part of the agent.

## Requirements

| Requirement | Why | Check |
|---|---|---|
| Linux 5.8 or newer | `CAP_BPF`, `CAP_PERFMON`, BPF ring buffers | `uname -r` |
| BTF (`/sys/kernel/btf/vmlinux`) | the programs adapt to the running kernel (CO-RE) | `ls /sys/kernel/btf/vmlinux` |
| `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` at start, or root | load the programs, attach them to the interface | the unit or `--cap-add` grants them |
| x86_64 or arm64 | the release builds these | `uname -m` |

Linux 6.6 or newer is better: the programs attach as TCX links, which the kernel removes
by itself when the process ends. Older kernels use netlink filters, which iohr-capture
removes on exit and, after a crash, at its next start or with `iohr-capture cleanup`.

Kernels tested in VMs on every change (`mise run capture:e2e`): 5.15, 6.6 and 6.12
(Ubuntu mainline builds). Distribution kernels that meet the requirements by default:
Ubuntu 22.04 and newer, Debian 12 and newer, RHEL and Rocky 9, Fedora 38 and newer,
Amazon Linux 2023. These are expected to work but are not yet in the test matrix.

## Check the host first: `iohr-capture doctor`

```sh
sudo iohr-capture doctor --interface eth0
```

`doctor` only reads `/proc` and `/sys`. It prints one line per requirement, `PASS`,
`INFO`, `WARN` or `FAIL`, and the exact fix under anything that is not a pass. It exits 0
only when capture can run. `--json` prints the same as JSON. The unit runs it before every
start, so a failed start says why in `journalctl -u iohr-capture`.

```text
PASS  kernel                Linux 6.8.0 (5.8 or newer needed)
PASS  btf                   /sys/kernel/btf/vmlinux present
PASS  tc attach             TCX links (Linux 6.6+): removed by the kernel when the process exits
PASS  bpffs                 bpf filesystem mounted
PASS  capabilities          CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN present (dropped right after attaching)
PASS  memlock               not limiting: eBPF memory is charged to the memory cgroup (Linux 5.11+)
PASS  interface             eth0 exists
PASS  lockdown              kernel lockdown off
PASS  unprivileged_bpf      kernel.unprivileged_bpf_disabled=2 (fine: capture is privileged only while attaching)
PASS  cgroup v2             unified hierarchy at /sys/fs/cgroup
PASS  lsm                   no SELinux enforcement, no AppArmor
capture can run on this host
```

## Install

### Debian, Ubuntu, RHEL, Fedora (package and systemd)

Download the `.deb` or `.rpm` from the [release](https://github.com/inorbithr/dataplane/releases),
[verify it](#verify-what-you-downloaded), then:

```sh
sudo apt install ./iohr-capture_<version>_amd64.deb   # or: sudo dnf install ./iohr-capture-<version>.x86_64.rpm
sudo sed -i 's/^IOHR_CAPTURE_INTERFACE=.*/IOHR_CAPTURE_INTERFACE=eth0/' /etc/iohr-capture/capture.env
sudo systemctl enable --now iohr-capture
```

The package creates the system user `iohr-capture` and installs the binary, the settings
file `/etc/iohr-capture/capture.env` and the unit
([`iohr-capture.service`](../../packaging/systemd/iohr-capture.service)). It never enables
or starts the service by itself. `tshark` is only suggested, never required.

The unit runs as `iohr-capture` with exactly `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`,
`LimitMEMLOCK=infinity`, no IP access, a read-only system and a system call filter
(`systemd-analyze security iohr-capture` rates it 1.3, "OK").

| Task | Command |
|---|---|
| status | `systemctl status iohr-capture` |
| logs | `journalctl -u iohr-capture -f` |
| the totals | stop it (`sudo systemctl stop iohr-capture`); they are the last JSON in the log |
| one count without the service | `sudo iohr-capture run --interface eth0 --for 30` |
| stop for good | `sudo systemctl disable --now iohr-capture` |
| remove left-over filters (kernels before 6.6) | `sudo iohr-capture cleanup --interface eth0` |
| uninstall | `sudo systemctl disable --now iohr-capture`, then `sudo apt purge iohr-capture` or `sudo dnf remove iohr-capture` |

Stopping the service removes its filters (`ExecStopPost=iohr-capture cleanup`). To be
sure nothing is left after an uninstall on a kernel before 6.6, run
`tc filter show dev eth0 ingress` and `tc filter show dev eth0 egress`: no line should
mention `iohr_ingress` or `iohr_egress`. On 6.6 and newer, `bpftool net show dev eth0`
lists TCX programs; nothing of ours remains once the process is gone.

### Container

```sh
docker run --rm --network host \
  --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --ulimit memlock=-1 \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  ghcr.io/inorbithr/iohr-capture:<version> run --interface eth0 --for 30
```

- `--network host`: the container must see the host's interfaces.
- `--cap-drop ALL`, then the three capabilities and nothing else. Docker grants
  capabilities only to root, so the image starts as uid 0 inside the container; the
  program drops them right after attaching.
- `/sys/kernel/btf` read-only: BTF for the running kernel. Docker usually exposes it
  already; the mount makes sure.
- `--ulimit memlock=-1` is needed only on kernels before 5.11.
- `/sys/fs/bpf` is not needed in this version (nothing is pinned). Later versions will
  ask for `-v /sys/fs/bpf:/sys/fs/bpf`.
- Never `--privileged`.

With no command the image runs `doctor`.

The image is built on every change but not yet published to `ghcr.io`. Until it is,
build it from a release's binaries: put them in `dist/bin/linux-<arch>/` and run
`docker build -f Dockerfile.capture .`.

### Kubernetes

Not yet shipped (phase 3). The plan is a per-node DaemonSet with host networking and the
same three capabilities, whose counts reach the cluster's agent through an authenticated
in-cluster endpoint. A sketch, for orientation only:

```yaml
# Sketch, not a supported manifest.
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: iohr-capture
          image: ghcr.io/inorbithr/iohr-capture:<version>
          args: ["run", "--interface", "eth0"]
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"], add: ["BPF", "PERFMON", "NET_ADMIN"] }
          volumeMounts: [{ name: btf, mountPath: /sys/kernel/btf, readOnly: true }]
      volumes: [{ name: btf, hostPath: { path: /sys/kernel/btf } }]
```

### As an iohr extension

Coming: `iohr ext install capture` will install the user commands (`iohr capture status`,
`pcap`, `dissect`) and control the system service, and will show the three capabilities
before it installs anything. Until then, use the package.

## Verify what you downloaded

Archives, `.deb` and `.rpm` carry SLSA provenance and a CycloneDX SBOM attestation
(`iohr-capture.cdx.json`, which covers the user-space program and its embedded eBPF
programs), signed by this repository's release workflow. The commands are the same as for
the agent: [verifying releases](../security/verifying-releases.md).

## Run it by hand

```sh
sudo iohr-capture run --interface eth0 --for 30
```

```json
{
  "interface": "eth0",
  "kernel": { "major": 6, "minor": 8, "patch": 0 },
  "attach": "tcx",
  "seconds": 30.0,
  "stale_filters_removed": 0,
  "packet_unit": "skb",
  "ingress": { "packets": 18234, "bytes": 21877412 },
  "egress": { "packets": 9120, "bytes": 1203311 },
  "capabilities_after_attach": { "effective": "0000000000000000", "permitted": "0000000000000000", "kept": [], "bounding_set_cleared": true },
  "detached": true
}
```

Without `--for` it runs until `Ctrl-C` or `SIGTERM`. `--attach tcx|netlink` forces the
attach mode (TCX needs 6.6).

**Counts are socket buffers, not wire packets** (`packet_unit: "skb"`). With GRO
(receive) or TSO/GSO (send) one buffer can carry several packets as they were on the wire,
so on a busy NIC the packet count is lower than a switch would show. Bytes count from the
Ethernet header on, without the frame check sequence. The interface's own counters
(`ip -s link show eth0`) count the same buffers.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `doctor`: `FAIL kernel` | kernel older than 5.8 | upgrade the kernel |
| `doctor`: `FAIL btf` | kernel built without `CONFIG_DEBUG_INFO_BTF` | use a distribution kernel with BTF; in a container mount `/sys/kernel/btf` |
| `doctor`: `FAIL capabilities` | not root and no capabilities | run from the unit, with `sudo`, or with the three `--cap-add` |
| `doctor`: `FAIL memlock` | kernel before 5.11 and a low `ulimit -l` | `LimitMEMLOCK=infinity` (the unit has it), `ulimit -l unlimited`, `--ulimit memlock=-1` |
| `doctor`: `FAIL interface` | wrong name, or a container without `--network host` | `ip -br link`; add `--network host` |
| `doctor`: `WARN lockdown` (confidentiality) | Secure Boot lockdown | counting works; later layers that read kernel memory will not; integrity mode is enough |
| `doctor`: `INFO lsm`, and loading fails with `EACCES` | SELinux or AppArmor policy | allow the `bpf` class (SELinux) or the three capabilities (AppArmor) for the service |
| `run`: "TCX needs Linux 6.6" | `--attach tcx` on an older kernel | leave `--attach` at `auto` |
| filters left after a crash (before 6.6) | the process was killed before it could detach | `sudo iohr-capture cleanup --interface eth0`; the next start removes them too |
