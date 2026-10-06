# Developing iohr-capture

How the capture crates are built and tested. Installing and running it:
[install.md](install.md). Why it is shaped this way: [ADR 0002](../adr/0002-capture-companion.md).

## The crates

| Crate | What | Toolchain |
|---|---|---|
| `crates/iohr-capture-ebpf` | the eBPF programs (`no_std`, `aya-ebpf`), `MIT OR GPL-2.0`, not a workspace member, its own `Cargo.lock` and `deny.toml` | the pinned nightly in its `rust-toolchain.toml`, `bpf-linker` |
| `crates/iohr-capture-common` | `no_std` types shared by kernel and user space; `unsafe impl aya::Pod` behind the `user` feature | stable |
| `crates/iohr-capture` | the program: `run`, `doctor`, `cleanup` | stable; its `build.rs` builds the eBPF crate |

`crates/iohr-capture/build.rs` calls `aya-build`, which runs
`cargo build --target bpfel-unknown-none -Z build-std=core` for the eBPF crate with the
nightly named in `crates/iohr-capture-ebpf/rust-toolchain.toml` and embeds the object in
the binary. Nothing else in the workspace uses nightly.

## Setup

```sh
mise install          # stable and the pinned nightly (rust-src, clippy, rustfmt), bpf-linker
mise run ci           # includes capture:ebpf-check (fmt, clippy for the BPF target, cargo-deny)
cargo build -p iohr-capture
```

`mise.toml` pins the nightly next to stable and `bpf-linker` (whose LLVM must be at
least as new as the nightly's). `mise run capture:toolchain-check` fails when
`mise.toml` and the eBPF crate's `rust-toolchain.toml` name different nightlies. To move
to a newer nightly, change both, run `mise install` and `mise run ci`, and check the
`bpf-linker` release notes for the LLVM version.

`cargo build` without `mise` needs `rustup`, the nightly with `rust-src`, and
`bpf-linker` on `PATH`.

## Tests

- `cargo nextest run -p iohr-capture -p iohr-capture-common`: unit tests, including every
  `doctor` probe against fixtures. No privileges, no eBPF.
- `mise run capture:e2e`: the real thing, in throwaway VMs.

**Never load the programs on your own machine or a server to try them out.** Loading and
attaching need root, change the interface's TC hooks and, on a shared or production host,
affect everyone. The VM test exists so nobody has to.

### The VM test (`mise run capture:e2e`)

[`tools/capture-e2e.sh`](../../tools/capture-e2e.sh) builds a static `iohr-capture` and
boots one VM per kernel with [virtme-ng](https://github.com/arighi/virtme-ng) (`vng`) on
QEMU with KVM. The VM sees this machine's files read-only; inside it,
[`tools/capture_e2e_guest.py`](../../tools/capture_e2e_guest.py) runs as root and refuses
to run anywhere but a virtme-ng guest. For each attach mode the kernel has (netlink
always, TCX from 6.6) it:

1. makes a veth pair, one end in a network namespace, IPv6 off and static neighbour
   entries so there is no background traffic;
2. starts `iohr-capture run` on the root namespace's end;
3. sends 1000 UDP datagrams and 100 TCP connections (64 bytes each) from the namespace;
4. stops capture and asserts.

How counts are compared: capture's ingress and egress packet counts must equal the
interface's own rx and tx packet counters over the same window, exactly. Both count
socket buffers, and with small payloads on veth (no GRO without XDP, nothing for TSO to
merge) one socket buffer is one packet; on real NICs GRO can merge packets, which is why
the report says `packet_unit: "skb"`. Bytes may differ from the interface counters only
by the Ethernet header (0 or 14 bytes per packet). It also checks that at least the sent
traffic was seen, that the capabilities left after attaching are the expected ones for
the kernel and mode, that nothing is left on the interface afterwards, that `cleanup` and
the next start remove the filters of a `SIGKILL`ed netlink run, and that `doctor` exits 0
as root and 1 without capabilities.

Results: `dist/capture-e2e/<kernel>.json` and `.log`.

#### What it needs

- `vng` (virtme-ng 1.32 or newer) and `qemu-system-x86_64`:
  `sudo apt install virtme-ng qemu-system-x86` (Ubuntu 24.04+), or `pipx install virtme-ng`
  plus your distribution's QEMU.
- Read and write access to `/dev/kvm`. Without it the VMs are too slow to be useful and
  the script stops. Join the `kvm` group (`sudo usermod -aG kvm "$USER"`, then log in
  again), or for the current login only: `sudo setfacl -m u:"$USER":rw /dev/kvm`.
- Network access the first time: `vng --run v<version>` downloads Ubuntu mainline kernel
  builds (image and modules) from kernel.ubuntu.com and caches them in
  `~/.cache/virtme-ng`.

#### The kernel matrix

`KERNELS` in `tools/capture-e2e.sh` (default `v5.15.222 v6.6.158 v6.12.112`): 5.15 is the
oldest LTS that most fleets still run and exercises netlink attach and the kept
`CAP_BPF`; 6.6 is the first with TCX; 6.12 is a current LTS. To add one, pick a version
from <https://kernel.ubuntu.com/mainline/>, check it boots with
`KERNELS=v6.x.y mise run capture:e2e`, and add it to the default list. One run:

```sh
KERNELS=v6.6.158 mise run capture:e2e
```
