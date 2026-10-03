# InOrbit data plane

`iohr-agent`, the program companies run in their own network for the InOrbit platform
(RFC 0029 in inorbithr/core). This file is the brief for coding agents and people.

## Layout

| Path | What it holds |
|---|---|
| `crates/iohr-agent/src/` | the agent: `cli` (commands), `config` (agent.toml), `policy` (policy.toml, target checks, DNS pinning), `enroll`/`keys`/`token` (identity), `session`/`protocol` (WebSocket), `executor` (admission, ceilings), `checks/` (http, tcp, tls, grpc_health), `secrets` (env/file/k8s/vault), `admin`/`state` (local page), `telemetry` (OTLP), `extsock`/`platform` (iohr token socket, init) |
| `crates/iohr-agent/tests/end_to_end.rs` | the agent against a fake control plane |
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
  the machine; no new listener; small dependency set.
- Hydra (the platform's identity provider) accepts only RS/PS/ES algorithms for
  `private_key_jwt`; the default key is ES256 for that reason.
- `mise run ci` before saying a change is done. Use `CARGO_TARGET_DIR` inside the repo
  (`target/`) and `mise run clean` when finished: the disk is shared.
- Conventional Commits; every change through a pull request; never push to `main`.
- Never claim compliance with a standard; say "aligned with" or "designed for".
