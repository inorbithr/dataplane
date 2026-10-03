#!/usr/bin/env bash
# The internal dogfood channel: builds the image, the Helm chart and the iohr extension
# artifact from dist/bin, pushes them to $IOHR_DOGFOOD_REGISTRY and signs each with a
# local cosign key. This is NOT a release: public releases come only from the release
# workflow (keyless signature + SLSA provenance). Consumers of the dogfood channel trust
# the public key with `iohr config set ext.trusted_keys` / their admission policy.
#
#   IOHR_DOGFOOD_REGISTRY   e.g. registry.internal:5000/inorbithr (required)
#   IOHR_DOGFOOD_COSIGN_KEY private key path, outside the repository
#                           (default ~/.config/inorbit/dogfood-cosign.key; made if missing)
#   COSIGN_PASSWORD         the key's password (required)
#   IOHR_DOGFOOD_INSECURE=1 plain-HTTP registry (a local test registry only)
#   IOHR_DOGFOOD_TAG        tag suffix, default -dogfood.<git short sha>
set -euo pipefail
cd "$(dirname "$0")/.."
repo_root="$(pwd)"
reg="${IOHR_DOGFOOD_REGISTRY:?set IOHR_DOGFOOD_REGISTRY, e.g. registry.internal:5000/inorbithr}"
key="${IOHR_DOGFOOD_COSIGN_KEY:-$HOME/.config/inorbit/dogfood-cosign.key}"
: "${COSIGN_PASSWORD:?set COSIGN_PASSWORD for the dogfood signing key}"
export COSIGN_PASSWORD
case "$(realpath -m "$key")" in
  "$repo_root"/*) echo "the signing key must live outside the repository" >&2; exit 1 ;;
esac
if [ ! -f "$key" ]; then
  mkdir -p "$(dirname "$key")" && chmod 700 "$(dirname "$key")"
  (cd "$(dirname "$key")" && cosign generate-key-pair --output-key-prefix "$(basename "${key%.key}")")
  echo "made $key and ${key%.key}.pub; distribute only the .pub" >&2
fi

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
tag="${version}${IOHR_DOGFOOD_TAG:--dogfood.$(git rev-parse --short HEAD)}"
plain=(); oras_plain=(); cosign_insecure=()
if [ "${IOHR_DOGFOOD_INSECURE:-}" = 1 ]; then
  plain=(--plain-http); oras_plain=(--to-plain-http); cosign_insecure=(--allow-http-registry --allow-insecure-registry)
fi
sign() { cosign sign --yes --key "$key" --tlog-upload=false "${cosign_insecure[@]}" "$@"; }

platforms=""
for d in dist/bin/linux-*; do platforms="${platforms:+$platforms,}linux/${d##*-}"; done
[ -n "$platforms" ] || { echo "no binaries: run mise run dist:bin" >&2; exit 1; }
mkdir -p dist/oci

echo "== image $reg/iohr-agent:$tag ($platforms)"
docker buildx build --platform "$platforms" --build-arg VERSION="$tag" \
  --tag "$reg/iohr-agent:$tag" --push --metadata-file dist/oci/image.json .
image_digest="$(python3 -c 'import json;print(json.load(open("dist/oci/image.json"))["containerimage.digest"])')"
sign "$reg/iohr-agent@$image_digest"
cosign attest --yes --key "$key" --tlog-upload=false "${cosign_insecure[@]}" --type cyclonedx \
  --predicate dist/sbom/iohr-agent.cdx.json "$reg/iohr-agent@$image_digest"

echo "== chart oci://$reg/charts/iohr-agent:$tag"
rm -rf dist/chart && mkdir -p dist/chart
helm package charts/iohr-agent --version "$tag" --app-version "$tag" -d dist/chart >/dev/null
chart_digest="$(helm push dist/chart/iohr-agent-"$tag".tgz "oci://$reg/charts" "${plain[@]}" 2>&1 | sed -n 's/^Digest: //p')"
sign "$reg/charts/iohr-agent@$chart_digest"

echo "== extension $reg/iohr-ext/agent:$tag"
# The layout iohr ext install verifies (sdk ADR 0012): an image index, and a Sigstore
# bundle v0.3 holding a DSSE in-toto statement whose subject is the index digest,
# attached as an OCI referrer of artifactType $bundle_type. cosign's own referrer
# fallback index mislabels the artifactType, so the bundle is made as a file over the
# index bytes and attached with oras.
bundle_type="application/vnd.dev.sigstore.bundle.v0.3+json"
ext_digest="$(python3 tools/ext_artifact.py --version "$tag" --out dist/oci/ext-agent)"
oras cp --from-oci-layout "dist/oci/ext-agent:$tag" "$reg/iohr-ext/agent:$tag" "${oras_plain[@]}" >/dev/null
[ "$(oras resolve "$reg/iohr-ext/agent:$tag" "${plain[@]}")" = "$ext_digest" ] || { echo "registry digest differs from the layout" >&2; exit 1; }
mkdir -p dist/oci/bundles
printf '{}' > dist/oci/bundles/empty.json
cosign attest-blob --yes --key "$key" --new-bundle-format --use-signing-config=false --tlog-upload=false \
  --type https://sigstore.dev/cosign/sign/v1 --predicate dist/oci/bundles/empty.json \
  --bundle dist/oci/bundles/ext-signature.sigstore.json "dist/oci/ext-agent/blobs/sha256/${ext_digest#sha256:}" >/dev/null
(cd dist/oci/bundles && oras attach "${plain[@]}" --artifact-type "$bundle_type" \
  "$reg/iohr-ext/agent@$ext_digest" "ext-signature.sigstore.json:$bundle_type" >/dev/null)

cat <<DONE
Pushed and signed with $key (public key ${key%.key}.pub):
  image      $reg/iohr-agent@$image_digest
  chart      $reg/charts/iohr-agent@$chart_digest
  extension  $reg/iohr-ext/agent@$ext_digest
Trust it:   iohr config set ext.trusted_keys ${key%.key}.pub
Install:    iohr config set ext.registry $reg/iohr-ext && iohr ext install agent@$tag
Verify:     cosign verify --key ${key%.key}.pub --insecure-ignore-tlog=true $reg/iohr-agent@$image_digest
DONE
