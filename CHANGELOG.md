# Changelog

## [0.1.0-alpha.9](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.8...v0.1.0-alpha.9) (2026-10-09)


### Features

* **agent:** [share] in the policy decides what the hello tells the platform ([#35](https://github.com/inorbithr/dataplane/issues/35)) ([9507c6b](https://github.com/inorbithr/dataplane/commit/9507c6b9fa289af44663df6dfafd6f0354d06174))
* **agent:** Confluence Cloud documentation connector (REST v2, ADF) ([#31](https://github.com/inorbithr/dataplane/issues/31)) ([920ec2b](https://github.com/inorbithr/dataplane/commit/920ec2bf837107ee9cfad10ad8be2a5074616805))
* **agent:** static documentation sites through robots.txt and the sitemap ([#37](https://github.com/inorbithr/dataplane/issues/37)) ([b935ffb](https://github.com/inorbithr/dataplane/commit/b935ffb098b8a306a468326548c580d3f1fd840e))
* **agent:** the decided world, PRDs, ADRs and RFCs read as evidence (atlas observe --decided) ([#39](https://github.com/inorbithr/dataplane/issues/39)) ([378549d](https://github.com/inorbithr/dataplane/commit/378549d8c8bdd571e7caaafcc013e63de25a8575))
* **agent:** what InOrbit sees, set on the local page or with `iohr agent share` ([#36](https://github.com/inorbithr/dataplane/issues/36)) ([286d5ef](https://github.com/inorbithr/dataplane/commit/286d5ef2f8f67ea0add424f5780c44e1211840fa))


### Documentation

* **checks:** an authenticated socket heartbeat calls an RPC its key may call ([#38](https://github.com/inorbithr/dataplane/issues/38)) ([286b329](https://github.com/inorbithr/dataplane/commit/286b32974717f17cd925ecb7a22e4fdf4f449e7b))
* **readme:** the repository's banner in today's brand, dark and light ([61d7f30](https://github.com/inorbithr/dataplane/commit/61d7f307138cf1ded3c3562f59c271d4f6e3c22e))

## [0.1.0-alpha.8](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.7...v0.1.0-alpha.8) (2026-10-08)


### Features

* **agent:** atlas observe, the first Atlas observers ([#26](https://github.com/inorbithr/dataplane/issues/26)) ([91424fc](https://github.com/inorbithr/dataplane/commit/91424fcc63eef1b28ea56eff9a429978e75da072))
* **agent:** documentation connectors framework and Notion (atlas docs sync) ([#29](https://github.com/inorbithr/dataplane/issues/29)) ([f1e6e0d](https://github.com/inorbithr/dataplane/commit/f1e6e0df45a28df196c79aba1537825b8af453f0))
* **agent:** enterprise metadata in agent.toml, config validate/show/schema (RFC 0088) ([#27](https://github.com/inorbithr/dataplane/issues/27)) ([40e2098](https://github.com/inorbithr/dataplane/commit/40e20983bffdc0d7279369a7d2e03ea1d87ea68d))
* **agent:** host observers and the hwmon check (atlas observe host) ([#30](https://github.com/inorbithr/dataplane/issues/30)) ([7a4fbaf](https://github.com/inorbithr/dataplane/commit/7a4fbafb03e118131b41ec400a4b099f11b088c7))
* **agent:** the local agent page, the egress ledger and the page's threat model ([#32](https://github.com/inorbithr/dataplane/issues/32)) ([0947cce](https://github.com/inorbithr/dataplane/commit/0947cce514636c2f6d81834cb4d365679a65bc95))
* **evidence:** add iohr-evidence, the public half of Atlas core ([#25](https://github.com/inorbithr/dataplane/issues/25)) ([00a05ea](https://github.com/inorbithr/dataplane/commit/00a05eaaba67ffa4e5251ec1328cf26bb0d46147))
* **packaging:** run the agent on macOS as a LaunchAgent ([#24](https://github.com/inorbithr/dataplane/issues/24)) ([775ca35](https://github.com/inorbithr/dataplane/commit/775ca35304dcc7068b1a041ac1a901c312ff3cc1))

## [0.1.0-alpha.7](https://github.com/inorbithr/dataplane/compare/v0.1.0-alpha.6...v0.1.0-alpha.7) (2026-10-06)


### Features

* **agent:** transport check surfaces grpc, sse, ws, mqtt, mcp and graphql (RFC 0040.2) ([#22](https://github.com/inorbithr/dataplane/issues/22)) ([5ebc83b](https://github.com/inorbithr/dataplane/commit/5ebc83be00e56379e3c6bdfde52a3d2ae012ff81))


### Documentation

* **brand:** a social preview that shows what this repo builds ([#21](https://github.com/inorbithr/dataplane/issues/21)) ([6c7e25b](https://github.com/inorbithr/dataplane/commit/6c7e25b44d7a8b83b2a33ec80a83f072a0d3eaf2))

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
