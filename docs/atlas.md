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
| `decided-document-reader` | deterministic extractor | `docs.decided` (configuration) | PRDs, ADRs and RFCs: `docs/prds`, `docs/adrs`, `docs/rfcs` of `--repo` (READMEs excepted), or every markdown file under `--decided <dir>` | `document/<kind>/<n>` `doc.kind`, `doc.source`, `doc.status`, `doc.title`, `doc.date`, `doc.public`, `doc.parent`, `doc.decides`, `doc.states`; each fact of a `decided` block as `decided.<predicate>` on its subject and as `decision/<kind>/<n>#<i>` with `decision.document`, `decision.subject`, `decision.predicate`, `decision.value`, `decision.lines`; each constraint sentence as `statement/<kind>/<n>@<first>-<last>` with `statement.text`, `statement.lines` |
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

## The decided world

What a document decides about the running system, it states in a `decided` block: a fenced
block marked `decided`, TOML with one `[[decided]]` table per fact.

````markdown
```decided
[[decided]]
subject = "deployment/tbd/paging"      # an entity key, as the other observers name it
predicate = "egress_only"              # read as decided.egress_only
text = "api.push.apple.com:443"        # exactly one of text, entity, int, bool
note = "one line for people; not observed"
```
````

The block is refused as a whole when it does not parse or a fact has an unknown field, two
values or none; a refusal is listed in the run's summary and nothing of the block is read.
Facts use the `decided.` namespace so they never pass for something an observer measured:
setting a decided fact against an observed one (and telling a discovery from a
restatement: a fact is *stated* when a `decision` names the same subject, predicate and
value) is Atlas core's job, not the reader's.

Sentences of a `Decision` or `Decisions` section that say `must`, `only`, `never` or
`always` are kept as text with their lines, never typed. Classified spans
(`[[classified:…]]…[[/classified]]` and fenced `classified` blocks) are cut before anything
is read, keeping line numbers; nothing inside one is ever observed. The kind comes from the
front matter, else the file name (`adr-9001-….md`), else the directory; the number from the
file name.

## Rollouts and metrics (investigations)

An investigation ("why did latency rise after the last deploy?") needs what changed and
what was measured as evidence, not as memory.

- **Rollouts** (`rollout-reader`, method `k8s.api.replicasets`): with `--kubeconfig`, every
  `ReplicaSet` a `Deployment` owns becomes `rollout/<ns>/<deployment>/<replicaset>` with
  `rolls_out` (the deployment), `rolled_at` (the control plane's creation time), `revision`,
  `runs_image` and `serving`. Same client, same policy check, `list` only.
- **Metrics** (`metrics-reader`, method `prometheus.query`): `--metrics <file> --at <RFC 3339>`
  (repeat `--at`) evaluates the file's named queries against a Prometheus-compatible API
  (Prometheus, VictoriaMetrics, Thanos, Mimir) at each instant. Per series:
  `metric/<name>{kept labels}@<instant>` with `measured_ms` (or `measured`), `measured_at`
  and `query`, all derived from `query/<name>@<instant>`'s `answer_digest`.
  - **Ranges:** `--at START..END[/STEP]` names every instant from `START` to `END`, both
    included: hourly by default, or a step like `15m` or `2h`. All instants are written in
    UTC, and a run takes at most 169 (a week, hourly).
  - **Bucket bounds:** when a query reads a histogram, `metric/<name>@<instant>` also gets
    `histogram`, `bucket_bounds` (the `le` values ascending, `+Inf` last, comma-separated)
    and `bucket_count`, from `query/<name>.buckets@<instant>`'s `answer_digest`. A quantile
    read from a histogram can't be finer than its buckets, and these say how coarse they
    are.
    - **Which histogram:** the one `<histogram>_bucket` series the query names. When it
      names several, set `histogram` in the file.
    - **The query:** the agent runs `count by (le) (<histogram>_bucket)`, and the
      histogram must be a plain metric name. That is the only query text the agent writes
      itself.

```toml
endpoint = "http://victoria-metrics.observability:8428"

[[metric]]
name = "envoy.upstream.p95.1h"
query = "histogram_quantile(0.95, sum by (envoy_cluster_name, le) (rate(envoy_cluster_upstream_rq_time_bucket[1h])))"
unit = "ms"                       # ms, s (converted to ms) or count
keep_labels = ["envoy_cluster_name"]
# histogram = "envoy_cluster_upstream_rq_time"   # only when the query reads several
```

Why this is scoped, since read-only is not automatically safe:

- **Only the file's queries run, plus one bucket list per histogram the file reads.**
  Nothing the platform sends can make the agent run a query of its choosing, so a metrics
  API cannot be used to enumerate what you measure.
- **The endpoint passes the policy** like every target (host, port, networks).
- **Only numbers and the labels you keep are recorded.** Every other label (pods, paths,
  users, tenants) is dropped before anything is written; the answer is kept by digest.
- **A query answering more than 64 series is refused, not cut:** a silent cut would bias
  the evidence.
- As everywhere in `atlas observe`, the output is a local file; nothing is sent.

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
