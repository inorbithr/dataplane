#!/usr/bin/env python3
"""Writes the OpenVEX document for the current version to stdout: vex/statements.json
(maintained by hand when a known vulnerability is assessed) wrapped for this release."""
import datetime
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
version = re.search(r'^version = "([^"]+)"', (root / "Cargo.toml").read_text(), re.M).group(1)
statements = json.loads((root / "vex" / "statements.json").read_text())
products = [
    f"pkg:oci/iohr-agent?repository_url=ghcr.io/inorbithr&tag={version}",
    f"pkg:oci/agent?repository_url=ghcr.io/inorbithr/iohr-ext&tag={version}",
    f"pkg:github/inorbithr/dataplane@v{version}",
]
for s in statements:
    s.setdefault("products", [{"@id": p} for p in products])
doc = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": f"https://github.com/inorbithr/dataplane/releases/v{version}/iohr-agent.openvex.json",
    "author": "InOrbit d.o.o. <security@inorbit.hr>",
    "role": "Manufacturer",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    "version": 1,
    "statements": statements,
}
json.dump(doc, sys.stdout, indent=2)
sys.stdout.write("\n")
