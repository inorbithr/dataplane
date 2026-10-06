# Verifying a release

Every public release is built and signed by
`https://github.com/inorbithr/dataplane/.github/workflows/release.yml` at a tag
`refs/tags/v<version>`, with an identity from GitHub Actions
(`https://token.actions.githubusercontent.com`). No long-lived signing key exists.

| Artifact | Where | Signature | Provenance | SBOM |
|---|---|---|---|---|
| Image | `ghcr.io/inorbithr/iohr-agent:<version>` | cosign keyless | SLSA v1, OCI referrer | CycloneDX, OCI referrer |
| Helm chart | `oci://ghcr.io/inorbithr/charts/iohr-agent:<version>` | cosign keyless | SLSA v1, OCI referrer | — |
| iohr extension | `ghcr.io/inorbithr/iohr-ext/agent:<version>` | Sigstore bundle v0.3 (OCI referrer) | SLSA v1 bundle (OCI referrer) | — |
| Archives, `.deb`, `.rpm` | GitHub release | — | SLSA v1 (`gh attestation`) | CycloneDX attestation + `iohr-agent.cdx.json` |

Each release also carries `iohr-agent.openvex.json` (which known vulnerabilities affect
it) and `SHA256SUMS`. Advisories: [advisories/csaf/](../../advisories/csaf/).

## Image and chart

```sh
IDENTITY='^https://github.com/inorbithr/dataplane/.github/workflows/release.yml@refs/tags/v'
cosign verify ghcr.io/inorbithr/iohr-agent@sha256:<digest> \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/inorbithr/iohr-agent@sha256:<digest> \
  --repo inorbithr/dataplane --signer-workflow inorbithr/dataplane/.github/workflows/release.yml
```

The capture companion's image, `ghcr.io/inorbithr/iohr-capture`, is signed and attested
the same way: use the same commands with that image name.

The same `cosign verify` arguments work in a Kyverno or Sigstore policy-controller
admission policy, so a cluster runs only images this workflow signed.

## Extension

`iohr ext install agent` checks the signature bundle and the SLSA provenance against the
identity above before anything is written; there is no flag that skips it.

## Packages and archives

```sh
gh attestation verify iohr-agent_<version>_amd64.deb --repo inorbithr/dataplane
sha256sum -c SHA256SUMS
```

## Build level

Provenance is SLSA v1 from GitHub's `actions/attest-build-provenance`, signed with the
release workflow's identity. Builds run on GitHub-hosted, ephemeral runners; the signing
job runs no repository code and only receives the built artifacts and their digests,
and only it holds the OIDC token.

GitHub states SLSA Build L3 for attestations made inside a **reusable** workflow, whose
identity the caller cannot alter. We do not use one yet: its certificate would name the
reusable workflow, and `iohr ext` (and the identity printed above) accept only
`release.yml@refs/tags/*`. By GitHub's definition these releases are therefore **SLSA
Build L2**, with the signing step isolated from the build steps. Moving to L3 is one
change on both sides: build and attest in `.github/workflows/build.yml` called from
`release.yml`, and have `iohr` accept that workflow as the provenance signer.

## Internal dogfood channel

Builds pushed by `mise run release:local` are signed with a local key (no transparency
log) and are not releases. Trust them only by adding that public key to
`iohr config set ext.trusted_keys` or your admission policy.
