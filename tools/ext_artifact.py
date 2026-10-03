#!/usr/bin/env python3
"""Builds the iohr extension artifact (RFC 0028, shared contract v1) as an OCI image
layout: one image index per version, one manifest per platform, each with the config
`application/vnd.inorbit.iohr.extension.config.v1+json` and one layer
`application/vnd.inorbit.iohr.extension.layer.v1.tar+gzip` holding the binary.

    tools/ext_artifact.py --version 0.1.0 --out dist/oci/ext-agent

Binaries are read from dist/bin/<os>-<arch>/iohr-agent[.exe]. Output is deterministic:
the same binaries give the same digests. Push with
`oras cp --from-oci-layout dist/oci/ext-agent:<version> <registry>/iohr-ext/agent:<version>`.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile

CONFIG_TYPE = "application/vnd.inorbit.iohr.extension.config.v1+json"
LAYER_TYPE = "application/vnd.inorbit.iohr.extension.layer.v1.tar+gzip"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
PLATFORMS = ["linux/amd64", "linux/arm64", "darwin/arm64", "darwin/amd64", "windows/amd64", "windows/arm64"]
SCOPES = ["agents:write", "domains:read"]
SOURCE = "https://github.com/inorbithr/dataplane"


def blob(out: pathlib.Path, data: bytes, media_type: str, **extra) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    path = out / "blobs" / "sha256" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(data), **extra}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def layer(binary: pathlib.Path, name: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size = binary.stat().st_size
        info.mode = 0o755
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        with binary.open("rb") as f:
            tar.addfile(info, f)
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0, compresslevel=9) as g:
        g.write(raw.getvalue())
    return gz.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--bin-dir", default="dist/bin")
    ap.add_argument("--out", default="dist/oci/ext-agent")
    ap.add_argument("--revision", default=os.environ.get("GITHUB_SHA", ""))
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    if out.exists():
        for p in sorted(out.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
    out.mkdir(parents=True, exist_ok=True)

    manifests = []
    for platform in PLATFORMS:
        os_, arch = platform.split("/")
        exe = "iohr-agent.exe" if os_ == "windows" else "iohr-agent"
        binary = pathlib.Path(args.bin_dir) / f"{os_}-{arch}" / exe
        if not binary.exists():
            continue
        config = {
            "name": "agent",
            "version": args.version,
            "entrypoint": exe,
            "scopes": SCOPES,
            "description": "The InOrbit agent: dials out, obeys a local policy, runs checks in your network.",
        }
        cfg = blob(out, canonical(config), CONFIG_TYPE)
        lay = blob(out, layer(binary, exe), LAYER_TYPE,
                   annotations={"org.opencontainers.image.title": exe})
        manifest = {
            "schemaVersion": 2,
            "mediaType": MANIFEST_TYPE,
            "config": cfg,
            "layers": [lay],
            "annotations": {
                "org.opencontainers.image.version": args.version,
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.created": "1970-01-01T00:00:00Z",
                **({"org.opencontainers.image.revision": args.revision} if args.revision else {}),
            },
        }
        manifests.append(blob(out, canonical(manifest), MANIFEST_TYPE,
                              platform={"os": os_, "architecture": arch}))
        print(f"{platform}: {manifests[-1]['digest']}", file=sys.stderr)
    if not manifests:
        print(f"no binaries under {args.bin_dir}/<os>-<arch>/", file=sys.stderr)
        return 1
    index = {
        "schemaVersion": 2,
        "mediaType": INDEX_TYPE,
        "manifests": manifests,
        "annotations": {
            "org.opencontainers.image.version": args.version,
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.licenses": "Apache-2.0",
        },
    }
    idx = blob(out, canonical(index), INDEX_TYPE,
               annotations={"org.opencontainers.image.ref.name": args.version})
    (out / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    (out / "index.json").write_text(json.dumps({"schemaVersion": 2, "mediaType": INDEX_TYPE, "manifests": [idx]}, indent=2))
    print(idx["digest"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
