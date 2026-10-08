# InOrbit data plane

`iohr-agent`, the program companies run in their own network for the InOrbit platform
(RFC 0029 in inorbithr/core). This file is the brief for coding agents and people.

## Layout

| Path | What it holds |
|---|---|
| `crates/iohr-agent/src/` | the agent: `cli` (commands), `config` (agent.toml), `policy` (policy.toml, target checks, DNS pinning), `enroll`/`keys`/`token` (identity), `session`/`protocol` (WebSocket), `executor` (admission, ceilings), `checks/` (http, tcp, tls, grpc_health; the transport surfaces grpc, sse, ws, mqtt, mcp, graphql, off unless the policy lists them), `checks_file` (checks.toml: declared checks, `checks lint`), `secrets` (env/file/k8s/vault), `admin/` (the local agent page: server, security rules, `page` rendering; `docs/security/admin-page.md`), `state` (what the page shows), `ledger` (the egress ledger, `docs/ledger.md`), `redact` (secret redaction for the page and logs), `logbuf` (recent log lines in memory), `capture` (the companion's counts, `capture:*` in the hello), `telemetry` (OTLP), `extsock`/`platform` (iohr token socket, init), `atlas/` (`atlas observe`: evidence from a checkout and the Kubernetes API, `docs/atlas.md`; `atlas/docs/` the documentation connectors: the `DocsSource` trait, its mock, the sync engine, Notion, Confluence (`adf` renders Atlassian Document Format), `docs/docs-connectors.md`; `atlas/host.rs` host evidence), `host/` (host observers over `/sys` and `/proc`: `hwmon`, `pcie`, `storage`, `pressure`, `boot`, `derive` findings, `sampler` window, `check` for the `hwmon` surface, `report`; `docs/host.md`) |
| `crates/iohr-agent/tests/end_to_end.rs` | the agent against a fake control plane |
| `crates/iohr-agent/tests/atlas_observe.rs` | `atlas observe` against a checkout and a fake Kubernetes API, and the redacted InOrbit sample (`tests/fixtures/atlas-inorbit-sample.jsonl`) |
| `crates/iohr-agent/tests/host_observe.rs` | `atlas observe host` over the sysfs/procfs tree captured read-only from a real TRX40 host (`tests/fixtures/host/trx40/`), checked against the manual findings |
| `crates/iohr-agent/tests/docs_notion.rs`, `docs_confluence.rs` | `atlas docs sync` against Notion and Confluence played by wiremock from `tests/fixtures/<provider>/`; the real APIs are never called |
| `crates/iohr-agent/tests/transport_checks.rs` | the transport surfaces against poisoned local servers: verdicts, and nothing a target said in a frame, the admin page or OTLP |
| `crates/iohr-evidence/` | what Atlas evidence is (ADR 0003): typed ids, digests, observed time, evidence methods and categories, observers, observations, artefacts, extractions, testimony, world snapshots; the public half of Atlas core in inorbithr/core, pinned there by revision. `mutants/mutate.py` breaks each invariant on purpose; every one must be caught |
| `crates/iohr-capture*/` | the capture companion: `iohr-capture` (user space: `capture` load/attach/drop, `engine` aggregates, `proto/` recognisers, `flows`, `topk`, `sockdiag`/`owners`/`procnet` for layers 4-5, `timing` + `route` for layer 7 (route vectors in `tests/route_vectors.json`, checksummed), `pcap` for layer 3, `server` sockets (aggregates v1/v2, control), `worker` the unprivileged parser process), `-common` (shared types), `-ebpf` (eBPF programs, nightly, not a workspace member); ADR 0002, `docs/capture/` |
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
  the machine (plus the targets, categories and tags a company declares in `checks.toml` and the `capture:*` capability strings, sent in the hello; an `hwmon` check's result adds the sensor key, its numbers and level, only when the policy sets `[work] host` and lists `hwmon`; a transport check's request stays in `checks.toml`, the job names its key); capture data never leaves the host (`crates/iohr-agent/tests/capture_privacy.rs`, control DAT-10); no new listener; small dependency set.
- Hydra (the platform's identity provider) accepts only RS/PS/ES algorithms for
  `private_key_jwt`; the default key is ES256 for that reason.
- Capture (ADR 0002): `unsafe` only in `crates/iohr-capture-ebpf` and the `aya::Pod` impls
  in `crates/iohr-capture-common`. Never load eBPF or run `iohr-capture run` on a
  development or production host; `mise run capture:e2e` runs it in throwaway VMs.
- `mise run ci` before saying a change is done. Use `CARGO_TARGET_DIR` inside the repo
  (`target/`) and `mise run clean` when finished: the disk is shared.
- Conventional Commits; every change through a pull request; never push to `main`.
- Never claim compliance with a standard; say "aligned with" or "designed for".
