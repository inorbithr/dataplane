# Releasing

1. Merge pull requests with Conventional Commit titles. `release-please` keeps a release
   PR open with the next version and the changelog (`release-please.yml`).
2. Merging the release PR creates the tag `v<version>` (by the release GitHub App).
3. The tag starts `release.yml`: `build` (binaries per platform), `assemble` (image,
   chart, extension, packages, SBOM, VEX; pushed by digest), `sign` (keyless signatures,
   extension bundles as OCI referrers, provenance and SBOM attestations, GitHub release).
   The `release-agent` environment waits for a maintainer's approval.

A maintainer may also push a `v<version>` tag by hand (the version in `Cargo.toml`, the
chart and `.release-please-manifest.json` bumped first in a pull request); `sign` then
creates the GitHub release itself, a pre-release when the version has a suffix.
Release tags are immutable: a failed release is fixed forward with the next version.

## Before the first release (owner)

- Branch protection or a ruleset on `main`: pull requests only, required check `ci-ok`,
  no force push, no deletion; tag protection for `v*`.
- Environment `release-agent` with required reviewers.
- `RELEASE_APP_ID` (variable) and `RELEASE_APP_PRIVATE_KEY` (secret) for release-please.
- GitHub Packages: allow this repository to write `ghcr.io/inorbithr/iohr-agent`,
  `…/charts/iohr-agent` and `…/iohr-ext/agent`, and make them public when the agent is.
- Artifact attestations on a private repository need GitHub Enterprise Cloud; on a
  public repository they are free. Cosign keyless entries in the public Rekor log name
  this repository.

## Without GitHub Actions

`mise run ci` runs every check locally. `mise run dist:packages`, `dist:sbom` and
`dist:vex` build what a release carries. `mise run release:local` pushes image, chart and
extension to `$IOHR_DOGFOOD_REGISTRY`, signed with a local key outside the repository;
that is the internal dogfood channel, never a public release.
