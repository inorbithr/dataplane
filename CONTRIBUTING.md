# Contributing

Thanks for helping. This page covers setup, the rules that keep the agent safe to run in
someone else's network, and how a change gets merged.

## Setup

1. Install [mise](https://mise.jdx.dev/getting-started.html).
2. `mise install` in the repository root: the pinned Rust toolchain, cargo tools, Helm,
   cosign, oras and the linters.
3. `mise run ci` runs every check CI runs. `mise tasks` lists the rest.

## The rules that matter

- **The local policy wins.** Every job passes `Executor::admit` and the policy's target
  check before anything connects. A new kind of work adds a `[work]` switch that defaults
  to off.
- **Nothing but timings, codes, classes and counts leaves the machine.** No bodies, no
  header values, no URL paths or queries, no secrets, in results, logs or errors. Tests
  assert it; keep them. The one exception is what a company writes in `checks.toml`: its
  declared targets go to the platform in the `hello` (`docs/checks.md`).
- **No new listener.** The agent dials out. The admin page stays read-only on loopback.
- **Small dependency set.** Every crate ships into a company's network. Justify each new
  one in the PR; `cargo deny check` must pass.
- **Rust 2024, `unsafe` forbidden, clippy pedantic with `-D warnings`.** No `unwrap`
  outside tests.
- **Integration tests use the fake control plane** in `crates/iohr-agent/tests/`, which
  speaks the shared contract: real servers on port 0, no mocks of the agent's own parts.

## Dependencies

Every crate, toolchain, tool, base image and action stays on its latest release, majors
included; a major update adapts the code in the same pull request rather than waiting.
The minimum supported Rust (`rust-version`, 1.94) is raised only on its own, as a
decision.

- Dependabot (`.github/dependabot.yml`) checks Cargo and the Docker base images weekly and
  the actions daily, with a 7-day cooldown, grouped into one pull request for patch and
  minor and one for majors per ecosystem.
- Patch and minor updates (minor only at 1.0 or later; a 0.x minor is breaking) merge
  themselves once `ci-ok` passes (`.github/workflows/dependabot-automerge.yml`, which runs
  only for pull requests Dependabot opened). Majors wait for a maintainer.
- `mise.toml` is outside Dependabot: `mise outdated --bump` lists what is behind, and the
  Rust image in `Dockerfile.source` follows the Rust in `mise.toml`.

## Commits and pull requests

- Titles follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat: grpc health over TLS`, `fix(policy): …`. Release notes and versions are
  generated from them.
- Breaking changes use `!` and explain the migration in the body.
- One change per PR. The required check is `ci-ok`.

## Using coding agents

`AGENTS.md` (most agents) and `CLAUDE.md` (Claude Code) hold the same rules. Whatever tool
you use, you are responsible for what you submit: run `mise run ci` and read the diff.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
