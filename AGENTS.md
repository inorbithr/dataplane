# InOrbit data plane

`iohr-agent`, the program companies run in their own network for the InOrbit platform
(RFC 0029 in inorbithr/core). This file is the brief for coding agents and people.

## Layout

| Path | What it holds |
|---|---|
| `crates/iohr-agent/src/` | the agent: `cli` (commands), `config` (agent.toml), `policy` (policy.toml, target checks, DNS pinning), `enroll`/`keys`/`token` (identity), `session`/`protocol` (WebSocket), `executor` (admission, ceilings), `checks/` (http, tcp, tls, grpc_health), `checks_file` (checks.toml: declared checks, `checks lint`), `secrets` (env/file/k8s/vault), `admin`/`state` (local page), `capture` (the companion's counts, `capture:*` in the hello), `telemetry` (OTLP), `extsock`/`platform` (iohr token socket, init) |
| `crates/iohr-agent/tests/end_to_end.rs` | the agent against a fake control plane |
| `crates/iohr-capture*/` | the capture companion: `iohr-capture` (user space: `capture` load/attach/drop, `engine` aggregates, `proto/` recognisers, `flows`, `topk`, `sockdiag`/`owners`/`procnet` for layers 4-5, `server` sockets), `-common` (shared types), `-ebpf` (eBPF programs, nightly, not a workspace member); ADR 0002, `docs/capture/` |
| `charts/iohr-agent/` | Helm chart |
| `packaging/` | systemd unit, default config, deb/rpm scripts |
| `tools/` | release building blocks: static binaries, packages, extension artifact, VEX, local release |
| `docs/` | ADRs, policy reference, release and verification guides |

## The contract

The session frames, enrollment and token exchange follow the shared contract for RFC
0029 (the agents service in inorbithr/core). Changing a frame or field is a contract
change: change core in step, and say so in the PR.

## Rules

- Read `CONTRIBUTING.md`. The policy wins; only timings, codes, classes and counts leave
  the machine (plus the targets a company declares in `checks.toml` and the `capture:*` capability strings, sent in the hello); capture data never leaves the host (`crates/iohr-agent/tests/capture_privacy.rs`, control DAT-10); no new listener; small dependency set.
- Hydra (the platform's identity provider) accepts only RS/PS/ES algorithms for
  `private_key_jwt`; the default key is ES256 for that reason.
- Capture (ADR 0002): `unsafe` only in `crates/iohr-capture-ebpf` and the `aya::Pod` impls
  in `crates/iohr-capture-common`. Never load eBPF or run `iohr-capture run` on a
  development or production host; `mise run capture:e2e` runs it in throwaway VMs.
- `mise run ci` before saying a change is done. Use `CARGO_TARGET_DIR` inside the repo
  (`target/`) and `mise run clean` when finished: the disk is shared.
- Conventional Commits; every change through a pull request; never push to `main`.
- Never claim compliance with a standard; say "aligned with" or "designed for".
