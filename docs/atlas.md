# Atlas observers (`atlas observe`)

Atlas (RFC 0086 in inorbithr/core) keeps claims about a system and decides what the
evidence for them proves. The agent's part is the evidence: it reads a checkout and a
cluster and writes what it read. It never writes a claim or a proof (ADR 0005 and ADR 0023
in inorbithr/core). The record types come from [`iohr-evidence`](adr/0003-evidence-types.md),
and every record is built through that crate's validating constructors.

```sh
iohr-agent atlas observe --repo ../core \
  --kube-context k3d-tbd -n tbd --policy policy.toml --out inorbit.jsonl
```

A company's documentation (Notion first) is read by `atlas docs sync` into the same
records; see [docs-connectors.md](docs-connectors.md). The machine the agent runs on
(sensors, PCI, storage, pressure, boots) is read by `atlas observe host`; see
[host.md](host.md).

Nothing is sent anywhere. The output is a local file (or standard output), and a summary
of counts goes to standard error.

## What it reads

| Observer | Class | Method (category) | Reads | Writes |
|---|---|---|---|---|
| `cargo-manifest-reader` | deterministic extractor | `cargo.metadata` (static resolution) | every `Cargo.toml` in the checkout | `crate/<name> defined_in`, `depends_on` (only crates in the checkout) |
| `k8s-manifest-reader` | deterministic extractor | `k8s.manifest` (configuration) | Deployments, StatefulSets, DaemonSets and Services in YAML files (the namespace comes from the object, else the nearest `kustomization.yaml`, else `default`) | `runs_image`, `labelled`, `reads_secret`, `reads_secret_key`, `selects`, `targets`, `exposes_port` |
| `k8s-networkpolicy-reader` | deterministic extractor | `k8s.networkpolicy` (configuration) | NetworkPolicies in the same files | `selects`, `applies_to`, `allows_egress` |
| `envoy-route-reader` | deterministic extractor | `envoy.route` (configuration) | `envoy.yaml` static listeners and clusters | `envoy.route/<vhost>/<match> matches_path`, `in_virtual_host`, `routes_to`; `envoy.cluster/<name> upstream_host`, `upstream_port`, `upstream_service` |
| `k8s-reader` | external system | `k8s.api.read` (runtime state) | the Kubernetes API: deployments, pods, services, network policies in the namespaces asked for | the same predicates as the manifests, plus `built_from_commit` (the `inorbit.hr/commit` annotation), `runs_image_digest` (from pod status) and `replicas_ready` |

Every file read becomes an artefact observation with the digest of its bytes, and every
fact from a file cites that artefact. The location is `<repo>@<commit>:<path>`; the
absolute path never appears. A YAML document that does not parse (a Helm template, say) is
skipped, not guessed at. A route's key includes its header matches, so routes that differ
only by a header stay separate.

From the cluster reading, the run also writes an environment manifest: one component per
deployment, pinned by its commit and its pods' image digests. Each part cites the
observation that reported it. A deployment with neither is listed as unknown, with the
reason.

## Output

One JSON object per line, tagged by `record`: `run` (first; agent version, the repository's
name and commit, the kubeconfig context and namespaces), `observer`, `entity` (a key such
as `deployment/tbd/labs` and an id derived from it, so runs agree on ids), `artifact`,
`observation`, `evidence` (method and lineage of the record before it), and `manifest`.

## What it may touch

- **Files**: only under `--repo`, read-only, at most 8 MiB per file, 12 directories deep.
  Hidden directories, `target`, `node_modules`, `dist`, `build`, `vendor` and `.cargo`
  are skipped. No program runs: `cargo metadata` is what the manifests say, read directly.
- **The Kubernetes API**: only after the API server's address passes the policy, like any
  check target (`networks.allow`, `networks.deny`, DNS pinning; [policy.md](policy.md)). A
  cluster is never read without a policy. The calls are `GET` lists only, with no proxy,
  a 30 s timeout and 32 MiB per answer. The kubeconfig user must authenticate with a
  client certificate or a token. An `exec` plugin is refused because the agent runs no
  other program, and so is `insecure-skip-tls-verify`. Errors name the path and status,
  never the token.

k3d writes `https://0.0.0.0:<port>` into the kubeconfig, and the default `networks.deny`
refuses `0.0.0.0/8`. Point a copy at `127.0.0.1` and allow `127.0.0.1/32`.

## A run on InOrbit

`crates/iohr-agent/tests/fixtures/atlas-inorbit-sample.jsonl` is a redacted cut from a run
against inorbithr/core and its local cluster. It holds the two RFC 0086 test chains, the
manifest, and every record they cite. The principal, boot id, upstream host names and CIDR
literals are redacted. `tests/atlas_observe.rs` reads it back through the public types
and checks both chains.
