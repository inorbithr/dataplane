# Changelog

## [0.1.0-alpha.6](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.5...v0.1.0-alpha.6) (2026-10-06)


### Bug fixes

* **release:** Cargo.lock carries the capture crates' version, so a release builds with --locked ([#18](https://github.com/inorbithr/dataplane/issues/18)) ([4fd2bbf](https://github.com/inorbithr/dataplane/commit/4fd2bbf0645707f8953b49a29b560534b8d0ae54))
* **release:** the eBPF crate's own Cargo.lock follows the capture-common version ([#19](https://github.com/inorbithr/dataplane/issues/19)) ([1a93b6b](https://github.com/inorbithr/dataplane/commit/1a93b6b534c57f67d66de1a3956a10640c18f94b))

## [0.1.0-alpha.5](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.4...v0.1.0-alpha.5) (2026-10-06)


### Features

* **capture:** iohr-capture phase 0, eBPF toolchain spike with VM tests ([#13](https://github.com/inorbithr/dataplane/issues/13)) ([09dd821](https://github.com/inorbithr/dataplane/commit/09dd821485e00e79e36f690fbeb7cb53ec85f84f))
* **capture:** phase 1, headers, protocols, owners and TCP health, with the agent's capture policy ([#14](https://github.com/inorbithr/dataplane/issues/14)) ([7fd5241](https://github.com/inorbithr/dataplane/commit/7fd52410a69182c2d14d5f7ec4fddffa9851eca2))
* **capture:** phase 2, whole packets with pcap on request, request timing per route, lookup v2 ([#17](https://github.com/inorbithr/dataplane/issues/17)) ([874321b](https://github.com/inorbithr/dataplane/commit/874321bcd6246bd562b30eb14641d3727421e6c2))


### Documentation

* the repository's logo and social preview ([#16](https://github.com/inorbithr/dataplane/issues/16)) ([5d327a8](https://github.com/inorbithr/dataplane/commit/5d327a8efb3fd392251f075eab92f5c37c3f3029))


### Dependencies

* **deps:** move every crate to its latest release, majors included ([#10](https://github.com/inorbithr/dataplane/issues/10)) ([7807768](https://github.com/inorbithr/dataplane/commit/780776855b4a5cfada0d17874756d5f82d5dbad9))

## [0.1.0-alpha.4](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.3...v0.1.0-alpha.4) (2026-10-03)


### Features

* declared checks, checks.toml in the hello and checks lint (RFC 0040.1) ([#9](https://github.com/inorbithr/dataplane/issues/9)) ([9c0c63a](https://github.com/inorbithr/dataplane/commit/9c0c63a9bba4ba6eec56f72980c44771c6943246))


### Documentation

* the PR template asks which platform RFCs a change implements (RFC 0041) ([#7](https://github.com/inorbithr/dataplane/issues/7)) ([27a9391](https://github.com/inorbithr/dataplane/commit/27a9391a5a8bd77718f51a5750b5a88e62e00154))

## [0.1.0-alpha.3](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.2...v0.1.0-alpha.3) (2026-10-03)


### Bug fixes

* **cli:** help and hints name the command as typed, iohr agent or iohr-agent ([#5](https://github.com/inorbithr/dataplane/issues/5)) ([85ffd60](https://github.com/inorbithr/dataplane/commit/85ffd60d751c3804c48dec760cb094e6d9ffeead))
* **release:** create the GitHub release when a hand-pushed tag has none ([#4](https://github.com/inorbithr/dataplane/issues/4)) ([b625e87](https://github.com/inorbithr/dataplane/commit/b625e87184fc62d7b4f8ccf78e2a9211408f68ca))
