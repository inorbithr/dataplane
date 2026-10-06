# ADR 0002: Capture runs in a privileged companion; the agent stays unprivileged

- Status: proposed (phase 0, the toolchain spike); accepted when the spike's VM tests are
  green on every kernel in the matrix
- Date: 2026-10-05
- Context: ADR 0001 (the agent), the capture plan (traffic capture with eBPF, layers 1-5
  and 7; RFC in inorbithr/core to follow), RFC 0003 (eBPF at the edge)

## Context

The platform wants packet-level understanding of the traffic arriving at a customer's
server: headers, protocols, the owning process, TCP health, request timing. On Linux that
means eBPF programs in the kernel, which need privileges to load and attach. The agent
(ADR 0001) is deliberately unprivileged: an empty capability set, `@privileged` system
calls and `AF_PACKET` blocked in its unit and Helm chart. A security team reads that unit
and approves it. Giving the agent `CAP_BPF` would change what they approved, for every
customer, including the ones that never turn capture on.

## Decision

### A separate program with its own unit: `iohr-capture`

- `iohr-capture` is its own binary, package and systemd unit
  ([`packaging/systemd/iohr-capture.service`](../../packaging/systemd/iohr-capture.service)).
  The agent's unit does not change.
- It holds `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN` and nothing else
  (`AmbientCapabilities` and `CapabilityBoundingSet`), runs as its own system user, and
  uses them only to load and attach its programs. Right after attaching, while still
  single-threaded, it sets its capability sets to empty (`capset`), clears the ambient
  set, sets `no_new_privs`, reads the sets back and refuses to continue if anything is
  left. The map and link file descriptors it already holds stay valid.
- Two kernel limits narrow "empty", and the spike measures both:
  - Before Linux 6.6 TC programs are attached as netlink filters, which outlive the
    process. Removing them on exit needs `CAP_NET_ADMIN`, so on those kernels that one
    stays effective. A filter left by a killed process is removed at the next start and by
    `iohr-capture cleanup` (the unit's `ExecStopPost`). From 6.6, TCX links are file
    descriptors: the kernel removes them when the process exits, so all capabilities go.
  - Before Linux 6.5 every `bpf()` command, map reads included, needs `CAP_BPF` when
    `kernel.unprivileged_bpf_disabled` is set (the default on current distributions;
    `kernel/bpf/syscall.c`, `__sys_bpf`). On those kernels `CAP_BPF` stays effective so the
    counters can be read. From 6.5 the check moved to map creation and program loading.
  - So: Linux 6.6+ keeps nothing; 6.5 keeps `CAP_NET_ADMIN`; 5.8-6.4 keeps `CAP_BPF` and
    `CAP_NET_ADMIN`. `CAP_PERFMON` is always dropped. `iohr-capture doctor` and the `run`
    report say which applies.
- The unit allows `bpf` and `capset` on top of `@system-service`, `AF_NETLINK` and
  `AF_UNIX` only, no IP traffic (`IPAddressDeny=any`), `LimitMEMLOCK=infinity` (maps are
  charged to `RLIMIT_MEMLOCK` before 5.11), and the usual protections
  (`ProtectSystem=strict`, `PrivateDevices`, `MemoryDenyWriteExecute`, and so on).
  `systemd-analyze security` rates it 1.3 with phase 1's runtime directory,
  `Group=` and `MemoryMax=` (the agent's unit: 1.4); what it flags is what the companion exists
  for: BPF, network administration, netlink.

### Why the agent stays unprivileged

The agent talks to the platform; the companion touches the kernel. Keeping them apart
means a compromise of the agent's session code reaches no kernel privilege, a customer who
never turns capture on runs exactly the agent they approved, and the companion can be
reviewed on its own: it opens no network connection at all.

### Two local sockets (built in phase 1)

- **Aggregates** for the agent: a Unix socket, mode 0660, group `iohr-capture-read`. The
  companion checks the peer with `SO_PEERCRED` (root, itself, the `iohr-agent` user and
  that group's members) and answers with counts, or for a person the bounded top-K tables
  too; the agent's user never gets the tables. It is not a network listener, so ADR 0001's "no new listener" holds. The protocol:
  [design-phase1.md](../capture/design-phase1.md).
- The group comes from the unit's `Group=iohr-capture-read` and the set-group-id runtime
  directory, never from `chown` (the unit's system call filter forbids it).

### Privilege separation (phase 1)

Before Linux 6.6 the companion keeps `CAP_NET_ADMIN` after attaching, and before 6.5
also `CAP_BPF`. Parsing untrusted packet bytes with those would put a parser bug one step
from network administration. So `iohr-capture run` splits in two:

- the **privileged process** loads, attaches, drops to what the kernel requires, reads the
  maps and the ring buffer, and copies the records and map readings as framed bytes into a
  pipe. It never looks inside a record;
- the **parser process** (`iohr-capture worker`, started by `run` with the pipe as its
  standard input) sets its capabilities to empty before anything else, then parses, keeps
  the flow table and top-K tables, reads `sock_diag`, `/proc` and the cgroup tree, and
  serves both sockets. The parsing engine can only be built with the proof value the drop
  returns. The VM test checks its `CapEff` and `CapPrm` are zero on every kernel.
- the parser is never root. Under the unit it runs as `iohr-capture`. Run by hand as root
  (`sudo iohr-capture run`), the privileged process starts it as `iohr-capture` (or
  `nobody` when that user does not exist) with the read group and no supplementary groups,
  before it drops its own capabilities, and makes the sockets' directory the parser's; the
  parser refuses to run as root and refuses inherited files beyond standard input, output
  and error. The VM test checks its uid is not 0.
- the parser's blocking work (`sock_diag`, `/proc`, the cgroup walk) runs on a separate
  thread and locks the engine only to apply the result, so reading the pipe never waits on
  it; writes to the pipe time out after 3 s, so a stuck parser cannot keep the privileged
  process from stopping within the unit's `TimeoutStopSec`.

`counts` reports both: `privileges.parser_capabilities` (always empty) and
`privileges.companion_kept`.
- **Control**, root only (0600, and `SO_PEERCRED` uid 0: the companion's own user is
  refused too): pcap on request (phase 2, [design-phase2.md](../capture/design-phase2.md)).
  No platform job can ever start a pcap; root on the host can. The parser writes the file
  (0600, in a 0700 directory of its own user under `StateDirectory=`, size- and
  time-capped, deleted after a retention) and only returns its path; no socket of the
  companion can carry a file, and the unit allows no IP traffic.

### Whole packets (phase 2)

Layer 3 is the companion's own switch (`--packets`), off by default and out of the
agent's reach. A second ring buffer receives each packet up to the snap length after its
own per-CPU token bucket; reservations must be constant-sized, so a packet goes into the
smallest of four record sizes (256 B to 64 KiB). The privileged process relays those
records like the others, without looking inside, bounded per batch by bytes. The parser
keeps them in memory, bounded by bytes and 300 s, and writes a pcapng file only for a
root request on the control socket.

The agent never gets packets and has no `pcap` or `dissect` command: it is the process
that talks to the platform, and keeping payloads out of its reach keeps a session bug from
being one step away from them.

### Where `unsafe` is allowed

The workspace forbids `unsafe`. Two narrow exceptions:

1. `crates/iohr-capture-ebpf`, the eBPF programs. The `aya-ebpf` context and map API
   hands out raw pointers; there is no safe way to write a per-CPU counter. Every `unsafe`
   block carries a `SAFETY` comment, and the kernel verifier checks every program before
   it runs (bounds, pointer provenance, termination).
2. `crates/iohr-capture-common`: one `unsafe impl aya::Pod` per record type, behind the
   `user` feature, so user space can read those bytes from a map. The types are
   `#[repr(C)]`, `Copy`, padding-free and valid for every bit pattern; a test pins their
   size. The crate's lint level is `deny` (not `forbid`) so that only those impls can
   `#[allow(unsafe_code)]`.

The user-space daemon (`crates/iohr-capture`) keeps `unsafe` forbidden; capabilities and
rlimits go through `rustix`'s safe wrappers.

### The eBPF crate's licence: MIT OR GPL-2.0

The kernel lets a program call GPL-only helpers only if its `license` section names a
GPL-compatible licence. The eBPF crate is `MIT OR GPL-2.0` (the object says
`Dual MIT/GPL`); everything else stays Apache-2.0. `deny.toml` allows `GPL-2.0` for that
crate alone. The eBPF crate is not a workspace member: it builds for the BPF target with
its own pinned nightly (`rust-toolchain.toml`, also pinned in `mise.toml`) and
`bpf-linker`, through `aya-build` from `crates/iohr-capture/build.rs`, with its own
`Cargo.lock`.

### Kernel requirement

Linux 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux`): `CAP_BPF` and `CAP_PERFMON`,
BPF ring buffers and CO-RE all arrive by then. Older kernels are refused with a clear
message (`iohr-capture doctor` shows it before anything is loaded).

### Dissection: `tshark`, never ours

Phase 2 hands a pcap file to `tshark` for dissection. `tshark` is GPL and is never
bundled, linked or started by the companion: `iohr-capture dissect` (a separate command of
the same binary, run by a person, never by the companion or the agent) runs the host's own
`tshark`, as the person who asked, with a file that person opened as its standard input,
and refuses to run as root unless told `--as-root`. The deb only `Suggests` it; the rpm
suggests `wireshark-cli`. An earlier draft of this ADR named `iohr agent capture
dissect`; that was dropped so that the agent never touches packets.

### What capture never does

It never drops, redirects or changes a packet (the classifiers always return
`TC_ACT_OK`). It sends nothing anywhere. It stores nothing but the pcap files root asks for
(phase 2), which expire.

## Consequences

- Two units to install where capture is wanted; one where it is not.
- Building needs a nightly toolchain and `bpf-linker` next to stable (`mise install`).
- Privileged code is tested in throwaway VMs only (`mise run capture:e2e`, virtme-ng on
  QEMU/KVM across kernels 5.15, 6.6 and 6.12), never on a developer's or a production host.
- On kernels before 6.6 the companion keeps one or two capabilities while it runs; the
  report and `doctor` say so instead of claiming an empty set.
- Kubernetes (a DaemonSet with host networking) is a later design step.
