# Support policy

## Versions

The agent follows [Semantic Versioning](https://semver.org); the image, chart, packages
and extension of one release share its version.

### Before 1.0

Only the latest release receives fixes, security fixes included. A 0.x minor release may
change the policy or configuration format; the changelog says how to migrate, and the
agent refuses a file it does not understand rather than guessing.

### From 1.0

| Major version | Features and bug fixes | Security fixes |
|---|---|---|
| Latest major | yes | yes |
| Earlier majors | no | yes, for at least 5 years from the major's first release |

The 5-year period follows the support period the EU Cyber Resilience Act expects
(Regulation (EU) 2024/2847, Article 13(8)). A major reaches end of life only after its
support period and never with less than 12 months' notice, announced in the release
notes and in this file.

## Platforms

| Form | Platforms |
|---|---|
| Container image, Helm chart | linux/amd64, linux/arm64; Kubernetes 1.30+ |
| `.deb`, `.rpm` | amd64, arm64; systemd |
| iohr extension | linux/amd64, linux/arm64, darwin/arm64, darwin/amd64 |

Rust MSRV is 1.94 for building from source.

## Updates

The agent never updates itself. A new version runs when you install it: `helm upgrade`,
your package manager, or `iohr ext upgrade agent`.

## Getting help

- Bugs and feature requests: [GitHub issues](https://github.com/inorbithr/dataplane/issues).
- Vulnerabilities: privately, as described in [SECURITY.md](SECURITY.md).
