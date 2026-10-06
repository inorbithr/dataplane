# Installing and running iohr-capture

`iohr-capture` is the capture companion of the InOrbit agent. It attaches small eBPF
programs to one network interface, counts what passes in each direction, recognises the
protocols of new connections from their first bytes, names the services that own the
sockets and samples TCP health. It keeps the results in memory as counts and bounded
"top" tables and answers the agent on a local socket. It is a separate program with its
own service because it needs three kernel capabilities to start; the agent itself stays
unprivileged ([ADR 0002](../adr/0002-capture-companion.md)).

Status: phase 1, a preview. Layers 1 (headers), 2 (protocols), 4 (owners) and 5 (TCP
health). Full packets and pcap on request (layer 3) and request timing (layer 7) come in
phase 2.

**Do not run iohr-capture on any host before a signed release of it exists.** Install it
only from a release whose signatures and provenance you verified
([below](#verify-what-you-downloaded)); never from a build of a branch, and never on a
development machine to try it out (`mise run capture:e2e` runs it in throwaway VMs).

## What capture never does

These are guarantees of this version, each backed by code and a test:

- **It never drops, delays or changes a packet.** The programs always hand the packet on
  unchanged (`TC_ACT_OK`).
- **It writes nothing to disk.** No capture file, no database, no cache: the aggregates
  live in the companion's memory and are gone when it stops. (Phase 2 adds pcap files,
  made only when a person on the host asks for one, 0600, capped and deleted.)
- **It sends nothing off the host.** The companion opens no network connection (its unit
  denies all IP traffic; it uses only netlink and Unix sockets). The agent sends the
  platform only four strings, `capture:headers`, `capture:protocols`, `capture:owners`,
  `capture:tcp`, saying what this host can show, never what it saw.
- **Names, paths and addresses stay bounded, in memory, on this host.** HTTP hosts and
  path templates (ids replaced, queries dropped), TLS server names, DNS names, gRPC
  methods, remote addresses and owners exist only as fixed-size top-K tables (64 rows each,
  128 bytes per key) in the companion's memory. Only a person on the host sees them
  (`--tables`, members of `iohr-capture-read`). They are never in a result frame, the
  hello, an admin page value, a log line or an OTLP export or label: the companion refuses
  the tables to the agent's user, the agent only ever asks for numbers and parses the
  answer into numeric fields, so nothing else reaches its memory.
- **Evidence (control DAT-10, "captured traffic stays on the host"):** the test
  `dat10_captured_traffic_stays_on_the_host` in
  [`crates/iohr-agent/tests/capture_privacy.rs`](../../crates/iohr-agent/tests/capture_privacy.rs)
  runs the agent against a companion that deliberately puts names, paths, SNI, DNS names,
  addresses and pod ids into every field it answers (and into its error code), with OTLP
  export on, and fails if any of them, or the counts themselves, appears in a frame sent
  to the platform or an OTLP export, or any name appears on the admin page or in
  `status.json`. The companion's refusal of tables to the agent's user is tested in
  `crates/iohr-capture/src/server.rs` and in the VM test. Both run in every `mise run ci`
  and `mise run capture:e2e`. Not covered: the agent's local stderr (the journal), which
  stays on the host and carries the same fixed strings as `status.json`.
- **Nothing is parsed with a capability.** Right after attaching the companion gives up
  its capabilities and checks that they are gone. On kernels before 6.6 it keeps
  `CAP_NET_ADMIN` to remove its filters when it stops, and before 6.5 also `CAP_BPF` to
  read its own maps; that process only copies bytes. All parsing, the tables, `sock_diag`
  and both sockets run in a second process (`iohr-capture worker`) with an empty
  capability set on every kernel, and never as root: run by hand with `sudo`, it runs as
  `iohr-capture` (or `nobody`) (`privileges` in the answer shows both processes).
- **It never decrypts anything.** TLS is seen up to the plaintext ClientHello (server name,
  offered protocols); HTTP/2 inside TLS is counted as TLS.
- **It is never `--privileged`** in a container and never runs as part of the agent.

## What each layer shows

| Layer | Where the numbers come from | What you see | Limits |
|---|---|---|---|
| 1 headers | the TC programs, per CPU, in the kernel | packets (socket buffers, `skb`) and bytes per direction and protocol class (TCP/UDP/ICMP, IPv4/IPv6, non-IP); SYN, SYN-ACK, FIN, RST per direction; per service port (the lower of the two ports) packets, bytes, SYN, RST | with GRO/TSO one skb can carry several wire packets; the per-port table keeps the 1024 most recently used ports |
| 2 protocols | the first 128 header bytes plus 512 payload bytes of each flow's first 8 payload packets, copied through a per-CPU token bucket (2000/s per CPU, burst 500) into a 4 MiB ring buffer, parsed in user space after the privilege drop | HTTP/1 requests (method, version, Host, path template) and response status classes; TLS ClientHellos (SNI, first ALPN, TLS 1.3 offered); DNS queries (name, type) and response codes; HTTP/2 cleartext connections and gRPC calls (method from `:path`); Redis command names; PostgreSQL connection openings | only the first request of a connection is seen (keep-alive and later HTTP/2 streams are counted, not named); a ClientHello cut before its server name counts as `tls_truncated` |
| 4 owners | `sock_diag` (what `ss` uses) every 2 s: each socket's cgroup id, mapped to `/sys/fs/cgroup` paths | per owner: systemd unit, Docker/containerd/Podman container (short id), Kubernetes pod (UID and container id), or user; listening ports, sockets, flows; process names where visible | pod and container *names* need the runtime's API and are not shown; sockets in other network namespaces (bridged containers) count as unowned; under the shipped unit other users' process names are hidden (see the unit) |
| 5 TCP | `tcp_info` from `sock_diag` every 2 s; `/proc/net/netstat` and `/proc/net/snmp` | established/listening sockets, smoothed RTT distribution, retransmits (sampled), resets in/out (from layer 1), listen queue overflows and drops; per port: RTT average and maximum, retransmits, accept queue and backlog, times the queue was full | a sample: a connection that opens and closes between two polls has no RTT; retransmit events between polls of a closed socket are missed (tracepoints come later) |

Drops are always counted, never queued: `drops.rate_limited` (over the token bucket),
`drops.ring_buffer_full` (the ring buffer had no room), `drops.flows_evicted` (the flow
table, 16384 flows by default, was full). Memory is bounded by those sizes; `memory.rss_kib`
reports what the process uses.

## Requirements

| Requirement | Why | Check |
|---|---|---|
| Linux 5.8 or newer | `CAP_BPF`, `CAP_PERFMON`, BPF ring buffers | `uname -r` |
| BTF (`/sys/kernel/btf/vmlinux`) | the programs adapt to the running kernel (CO-RE) | `ls /sys/kernel/btf/vmlinux` |
| `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` at start, or root | load the programs, attach them to the interface | the unit or `--cap-add` grants them |
| x86_64 or arm64 | the release builds these | `uname -m` |
| Linux 5.9+ and cgroup v2 (recommended) | owners by unit, container and pod (layer 4) | `iohr-capture doctor` (`owners`) |
| the group `iohr-capture-read` | owns the aggregates socket; the agent's user and people who may read the tables are members | `getent group iohr-capture-read` |

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

`doctor` only reads `/proc`, `/sys` and `/etc/group`. It prints one line per requirement,
`PASS`, `INFO`, `WARN` or `FAIL`, and the exact fix under anything that is not a pass. It
exits 0 only when capture can run (warnings are limits of a layer, not blockers).
`--json` prints the same as JSON. The unit runs it before every start, so a failed start
says why in `journalctl -u iohr-capture`.

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
PASS  owners                sockets carry their cgroup id: owners named by systemd unit, container or pod (layer 4)
PASS  socket group          iohr-capture-read exists: the aggregates socket is 0660 iohr-capture-read; the agent reads it as a member
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

The package creates the system user `iohr-capture` and the group `iohr-capture-read`, adds
the `iohr-agent` user to that group if the agent is installed (the agent's package does
the same when it comes second; a failure to create a user or group fails the
installation), tells you to restart a running agent so it sees the group, and installs
the binary, the settings file
`/etc/iohr-capture/capture.env` (every setting is listed there, commented, with its
default) and the unit ([`iohr-capture.service`](../../packaging/systemd/iohr-capture.service)).
It never enables or starts the service by itself. `tshark` is only suggested, never
required.

The unit runs as user `iohr-capture`, group `iohr-capture-read` (so its sockets belong
to that group without any `chown`), in the set-group-id runtime directory
`/run/iohr-capture` (2750), with exactly `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`,
`LimitMEMLOCK=infinity`, `MemoryMax=256M` for both processes, no IP access, a read-only
system, other users' processes hidden and a system call filter
(`systemd-analyze security iohr-capture` rates it 1.3, "OK"). The VM test starts this
unit under a real systemd on every kernel in the matrix.

| Task | Command |
|---|---|
| status | `systemctl status iohr-capture` |
| logs | `journalctl -u iohr-capture -f` (who asked the sockets and the outcome, never what they answered) |
| what it counted | `iohr-capture stats` (or `iohr agent capture status`); `--tables` for names, paths, addresses and owners; `--json` |
| one run without the service | `sudo iohr-capture run --interface eth0 --for 30` |
| stop for good | `sudo systemctl disable --now iohr-capture` |
| remove left-over filters (kernels before 6.6) | `sudo iohr-capture cleanup --interface eth0` |
| uninstall | `sudo systemctl disable --now iohr-capture`, then `sudo apt purge iohr-capture` or `sudo dnf remove iohr-capture` |

Stopping the service removes its filters (`ExecStopPost=iohr-capture cleanup`) and its
sockets. To be sure nothing is left after an uninstall on a kernel before 6.6, run
`tc filter show dev eth0 ingress` and `tc filter show dev eth0 egress`: no line should
mention `iohr_ingress` or `iohr_egress`. On 6.6 and newer, `bpftool net show dev eth0`
lists TCX programs; nothing of ours remains once the process is gone.

### The two sockets

| Socket | Mode | Who may use it | What it answers |
|---|---|---|---|
| `/run/iohr-capture/aggregates.sock` | 0660, group `iohr-capture-read` (directory 2750) | checked per connection with `SO_PEERCRED`: root, `iohr-capture`, the `iohr-agent` user, members of `iohr-capture-read`; anyone else gets `forbidden` | `counts` (numbers only; all the agent gets) and `tables` (plus the top-K tables; for a person, never for the agent's user) |
| `/run/iohr-capture/control.sock` | 0600 | root only | phase 1: `not_available` (pcap on request is phase 2; no platform job can ever start one) |

To read the tables as yourself, join the read group: `sudo usermod -aG iohr-capture-read
"$USER"`, then log in again. It is a group of its own on purpose: it grants the capture
tables and nothing else (the `iohr-agent` group can read the agent's configuration). The
socket serves 16 connections at once; a client has 2 s to ask and 5 s to read. The protocol (one JSON line in, one JSON document out, versioned,
bounded to 1 MiB) is in [design-phase1.md](design-phase1.md).

### Turn it on in the agent

The agent reads the aggregates only when its policy says so. In
`/etc/iohr-agent/policy.toml` ([policy reference](../policy.md#work)):

```toml
[work]
capture = true

[capture]                                   # optional; these are the defaults
socket = "/run/iohr-capture/aggregates.sock"
layers = ["headers", "protocols", "owners", "tcp"]
max_snapshot_age_secs = 30
```

Then `sudo systemctl restart iohr-agent`. **These keys need an agent newer than
0.1.0-alpha.4**: older agents reject unknown policy keys and refuse to start with them, so
upgrade the agent first, then the policy. Changing the policy changes its hash, which the
console shows next to the agent.

The agent's user must be in `iohr-capture-read` (the packages arrange it; by hand:
`sudo usermod -aG iohr-capture-read iohr-agent` and restart the agent). At every session
start the agent asks the socket for counts
(1 s timeout) and announces `capture:<layer>` for each layer that the policy allows, the
companion runs, and whose numbers are at most `max_snapshot_age_secs` old. If the
companion is not running, the agent announces nothing for capture and keeps working.

What the agent shows locally:

- `iohr agent capture status` (or `iohr-agent capture status`): the counts; `--tables`
  for the top-K tables; `--json`.
- The admin page's **Traffic** section (refreshed every 15 s): whether the companion
  answers and why not, what is announced, and the counts. No names, paths or addresses.

### Container

```sh
docker run --rm --network host \
  --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --ulimit memlock=-1 \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /run/iohr-capture:/run/iohr-capture \
  ghcr.io/inorbithr/iohr-capture:<version> run --interface eth0 --for 30 --socket-group root
```

- `--network host`: the container must see the host's interfaces and sockets (owners and
  TCP health read the host's `sock_diag`).
- `--cap-drop ALL`, then the three capabilities and nothing else. Docker grants
  capabilities only to root, so the image starts as uid 0 inside the container; the
  program drops them right after attaching.
- `/sys/kernel/btf` read-only: BTF for the running kernel.
- `/run/iohr-capture`: where the sockets are created, for the agent on the host. Inside the
  container the `iohr-capture-read` group does not exist: pass `--socket-group` with a
  group (name in the image or numeric id) that the host's agent belongs to, or read the
  counts with `docker exec <id> iohr-capture stats`.
- On kernels before 6.6 the filters outlive a killed container: run
  `iohr-capture cleanup --interface eth0` (same capabilities) after it, as the unit's
  `ExecStopPost` does.
- Owners need the host's cgroup tree, which a container sees only partly; on hosts that
  run containers, prefer the package.
- `--ulimit memlock=-1` is needed only on kernels before 5.11.
- Never `--privileged`.

With no command the image runs `doctor`.

Releases publish the image to `ghcr.io/inorbithr/iohr-capture` (amd64 and arm64), signed
by the release workflow with its build provenance and SBOM attached, from the first
release after this change; verify it as in
[verifying releases](../security/verifying-releases.md). To build one yourself, put a
release's binaries in `dist/bin/linux-<arch>/` and run `docker build -f Dockerfile.capture .`.

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

While it runs, `sudo iohr-capture stats` shows the counts and `sudo iohr-capture stats
--tables` the top-K tables. When it stops it prints its totals (counts only, as it goes to
the journal under the unit):

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
  "detached": true,
  "counts": { "version": 1, "layers": ["headers", "protocols", "owners", "tcp"], "protocols": { "http1_requests": 412, "tls_client_hellos": 3051, "dns_queries": 88, "...": "..." }, "...": "..." }
}
```

Without `--for` it runs until `Ctrl-C` or `SIGTERM`. `--attach tcx|netlink` forces the
attach mode (TCX needs 6.6). Every setting has a flag and an `IOHR_CAPTURE_*` variable
(`iohr-capture run --help`): `--layers`, `--samples-per-sec`, `--burst`,
`--ring-buffer-kib` (4 to 32768), `--first-packets`, `--max-flows` (at most 65536),
`--poll-ms`, the socket paths, `--socket-group`, `--agent-user`.

Run by hand as root, `run` keeps root only for the privileged process: the parser runs as
`iohr-capture` (or `nobody`), and `/run/iohr-capture` is made that user's, in the read
group. A later start of the unit takes the directory back (`RuntimeDirectory=`).

**Memory.** Both processes share the unit's `MemoryMax=256M`. The ring buffer (at most
32 MiB) and the flow table (about 2 KiB per flow while its protocol is undecided, at most
65536 flows, so about 140 MiB in the worst case) fit under it with room for the rest; the
defaults (4 MiB, 16384 flows) use a few tens of MiB. Raising `MemoryMax` in a drop-in is
the way to go beyond.

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
| `doctor`: `WARN owners` | Linux before 5.9 or no cgroup v2 | owners are named by user only; upgrade for units, containers and pods |
| `doctor`: `WARN socket group` | no `iohr-capture-read` group | reinstall the package, or `sudo groupadd --system iohr-capture-read && sudo usermod -aG iohr-capture-read iohr-agent` |
| `doctor`: `INFO lsm`, and loading fails with `EACCES` | SELinux or AppArmor policy | allow the `bpf` class (SELinux) or the three capabilities (AppArmor) for the service |
| `run`: "TCX needs Linux 6.6" | `--attach tcx` on an older kernel | leave `--attach` at `auto` |
| `run`: "is served by another process" | a second iohr-capture on the same socket | stop the other one (`systemctl status iohr-capture`) |
| filters left after a crash (before 6.6) | the process was killed before it could detach | `sudo iohr-capture cleanup --interface eth0`; the next start removes them too |
| `stats` / `capture status`: `forbidden` or permission denied | your user is not in `iohr-capture-read` | `sudo usermod -aG iohr-capture-read "$USER"`, log in again; or use `sudo` |
| `capture status --tables` as the agent's user: `forbidden` | by design: the agent's user gets counts only | run it as yourself (a member of `iohr-capture-read`) |
| `stats` / `capture status`: cannot reach the socket | the companion is not running, or a different socket path | `systemctl status iohr-capture`; `[capture] socket` in the policy must match |
| the agent's admin page: Traffic "not answering" | as above, for the agent user | the agent's user needs `iohr-capture-read` (the packages set it); restart the agent after adding it |
| `journalctl -u iohr-capture`: "the parser process exited" | the parser crashed or was killed (for example by `MemoryMax`) | the unit restarts it; report it with the log lines before |
| the service is killed for memory | `MemoryMax=256M` with a large ring or flow table | lower `IOHR_CAPTURE_RING_BUFFER_KIB` / `IOHR_CAPTURE_MAX_FLOWS`, or raise `MemoryMax` in a drop-in |
| log: "the agent's user does not exist" or "is root" | `IOHR_CAPTURE_AGENT_USER` names no user, or root | the guard that gives the agent counts only is off: set it to the agent's real user |
| log: "the socket directory keeps its mode" | a drop-in changed `RuntimeDirectoryMode=` | capture still starts; set it back to 2750 so only the read group reaches the socket |
| the package says "restart the agent" | the agent's user just joined `iohr-capture-read` | `sudo systemctl restart iohr-agent` (a running process does not see a new group) |
| the agent's admin page: Traffic "stale" | the companion's numbers are older than `max_snapshot_age_secs` | the companion is stuck or overloaded: `journalctl -u iohr-capture` |
| `drops.rate_limited` grows | more new flows than the token bucket allows | expected under load (counted, not queued); raise `IOHR_CAPTURE_SAMPLES_PER_SEC` if the CPU allows |
| `drops.ring_buffer_full` grows | user space cannot keep up | raise `IOHR_CAPTURE_RING_BUFFER_KIB`, or lower the sample rate |
| `drops.flows_evicted` grows | more concurrent flows than `--max-flows` | raise `IOHR_CAPTURE_MAX_FLOWS` (each flow costs at most about 2 KiB while undecided) |
| owners show `user:` rows only | Linux before 5.9, or no cgroup v2 | see `doctor` (`owners`) |
| owners have no process names | the unit hides other users' processes (`ProtectProc=invisible`) | a drop-in with `ProtectProc=default` if you want process names |
| many `flows_unowned` | sockets in other network namespaces (bridged containers), or connections shorter than the 2 s poll from local clients | expected in phase 1 |
