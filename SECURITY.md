# Security policy

This policy covers `iohr-agent`: the binary, the container image, the Helm chart, the
`.deb`/`.rpm` packages and the iohr extension artifact built from this repository. How the
agent is built to be safe: [docs/adr/0001-architecture.md](docs/adr/0001-architecture.md)
and [docs/security/](docs/security/).

## Reporting a vulnerability

Report privately through GitHub:
[Security > Report a vulnerability](https://github.com/inorbithr/dataplane/security/advisories/new),
or by e-mail to security@inorbit.hr. Do not open a public issue, pull request or
discussion about a vulnerability.

Include, as far as you can: the version and how it runs (Helm, package, extension); what
an attacker can do and under which conditions; the smallest reproduction you have;
whether you know of it being exploited.

## What happens next

| Step | Target |
|---|---|
| Acknowledge your report | within 2 business days |
| Triage: confirm, rate severity (CVSS v4), agree a timeline with you | within 5 business days |
| Fix released, Critical | within 7 days of triage |
| Fix released, High | within 30 days |
| Fix released, Medium | within 90 days |
| Fix released, Low | in the next regular release |

## Coordinated disclosure

- We ask for up to 90 days from your report to publish a fix; sooner when a fix is out or
  the issue is being exploited.
- Every confirmed vulnerability gets a GitHub Security Advisory and a CVE (GitHub is a
  CVE Numbering Authority), a CSAF 2.0 document in [advisories/csaf/](advisories/csaf/), and an OpenVEX
  statement ([vex/](vex/)) saying which versions are affected.
- We credit you unless you ask us not to.

## Safe harbour

We will not pursue legal action against research that stays within this policy, reports
privately, avoids privacy violations, data destruction and service disruption, uses only
accounts you own, and stops as soon as it reaches data that is not yours.

## EU Cyber Resilience Act

InOrbit d.o.o. treats itself as the manufacturer of the agent under Regulation (EU)
2024/2847. For an actively exploited vulnerability or a severe incident affecting the
agent, InOrbit reports through ENISA's Single Reporting Platform within the Article 14
deadlines (early warning in 24 hours, notification in 72 hours, final report within 14
days of a fix, one month for a severe incident), and informs users through the advisory
and the release notes.

## What we do on our side

- Releases are built and signed only by the release workflow from a tag: cosign keyless
  signatures, SLSA v1 build provenance, a CycloneDX SBOM per artifact
  ([verifying releases](docs/security/verifying-releases.md)). No long-lived signing key
  exists for public releases.
- Every GitHub Action is pinned to a commit SHA; workflows are checked by actionlint and
  zizmor on every change; dependencies by cargo-deny.
- The agent sends no telemetry to InOrbit, never sends request or response bodies, and
  never logs a secret, a token or a key.

## Supported versions

See [SUPPORT.md](SUPPORT.md). Before 1.0, only the latest release receives fixes.
