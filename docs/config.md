# agent.toml

The agent reads one file: where the platform is, where its own files are, the local
services it runs, and, since RFC 0088, the metadata that says where it runs, who owns it
and what binds it. What the agent may *do* is in [`policy.toml`](policy.md); what it
watches is in [`checks.toml`](checks.md).

`iohr-agent init` writes a complete file with every metadata field present and commented
out. The JSON Schema of the whole file is generated from the agent's types:
`iohr-agent config schema` prints it, and the repository keeps the current one at
[`schema/agent.schema.json`](schema/agent.schema.json) (a test fails when it is stale).
Point an editor or a CI step at it.

| Command | |
|---|---|
| `iohr-agent config validate` | read the file, apply the environment overrides, check every rule; each problem names its line and column (`agent.toml:12:1: metadata.placement.residency_zone: a residency zone needs placement.country`), or the variable that set it. Exit 2 on any error, so a pipeline can gate on it. |
| `iohr-agent config show` | print the effective configuration (file plus overrides, paths made absolute) as TOML. The Vault token reference is reduced to its scheme. Metadata never holds secrets, so nothing else needs redacting; a value that looks like a key or a token is refused at validation. |
| `iohr-agent config schema` | print the JSON Schema. |

## Precedence

A value written in the file is the base. A CI step that rewrites the file wins over it
by writing the file. An environment variable wins over both, for the fields it names:
`IOHR_AGENT_META_<SECTION>_<FIELD>` sets one metadata field
(`IOHR_AGENT_META_PLACEMENT_COUNTRY=DE`, `IOHR_AGENT_META_COMPLIANCE_REGIMES=gdpr,dora`,
`IOHR_AGENT_META_ASSET_TAGS=owner-team=sre,tier=gold`, `IOHR_AGENT_META_REPORT=false`).
A list splits on commas, tags are `key=value` pairs, `clock_uncertainty_ms` is a number.
An override is checked exactly like a value in the file; a bad one names the variable.
Everything else in the file (`api`, `name`, paths, `[admin]`, `[ledger]`, `[telemetry]`, `[secrets]`,
`[tls]`, `[session]`) has no environment form; `IOHR_AGENT_CONFIG` names the file.

## The sections

Top level: `api` (the platform, `https`), `name` (1 to 64 characters, shown in the
console), `environment` (must equal the policy's), `policy`, `checks`, `key`,
`state_dir` (relative paths resolve against the file's directory), `key_alg` (`es256`
or `ed25519`).

`[admin]` the local agent page: loopback only unless `allow_non_loopback`, which then needs `tls_cert` and `tls_key` and always asks for the page's token; `require_token` asks for it on loopback too; `hosts` adds `Host` values it answers to ([security/admin-page.md](security/admin-page.md)); `[ledger]` the egress ledger, on by default, `retain_days` and `max_mb` ([ledger.md](ledger.md)); `[telemetry]` OTLP export, off by default;
`[secrets]` the Vault and Kubernetes stores references may resolve from; `[tls]` an extra
CA bundle; `[session]` reconnect backoff; `[docs]` the documentation sources
`atlas docs sync` reads, each credential a secret reference ([docs-connectors.md](docs-connectors.md)).

## Metadata

`[metadata]` is what devops knows and the agent cannot find out by itself: the
datacentre, the country, the team, the compliance regimes, the trust domain. The
platform uses it to place every observation the agent sends (RFC 0088 in inorbithr/core:
which failure mode a trust domain implies, which data class a check's target has, which
jurisdiction a result may leave). Every field is optional. **An unset field is unknown,
never a default**: the platform treats unknown as a weaker claim, not as "production" or
"public". Strings are at most 128 characters, lists at most 32 entries, tags at most 32
pairs; the enumerations are closed; a value that looks like a key or a token is refused.

| Section | Holds | Fill it from |
|---|---|---|
| `placement` | `provider` (`cloud`, `on_prem`, `colocation`, `edge`), `provider_name`, `site_id`, `site_name`, `region`, `zone`, `rack`, `row`, `country` (ISO 3166-1 alpha-2), `jurisdiction`, `residency_zone` (needs `country`), `latency_zone` | the inventory or the cloud account |
| `organisation` | `legal_entity`, `business_unit`, `department`, `team`, `cost_centre`, `project`, `owner_role`, `contact_channel`, `on_call_rota`, `escalation_policy`: references and roles, never a person's name or address | the org chart, the CMDB, the on-call tool |
| `environment` | `tier` (`production`, `staging`, `development`, `test`, `disaster_recovery`), `criticality` (`critical` … `low`), `change_freeze` (date intervals `2026-12-20/2027-01-05`), `maintenance_windows`, `sla_ref`, `slo_refs` | change management |
| `asset` | `cmdb_id`, `catalogue_refs`, `hardware_class` (`bare_metal`, `virtual_machine`, `container`, `serverless`), `commissioned`, `decommission_planned` (after `commissioned`), `tags` (free `key = "value"` pairs) | the CMDB, the service catalogue |
| `compliance` | `regimes` (`gdpr`, `hipaa`, `dora`, `soc2`, `iso27001`, `pci_dss`, `nis2`, `ccpa`, `other:<name>`), `data_classes_allowed`, `may_leave_jurisdiction` (a subset of allowed), `external_models_may_see` (a subset of what may leave; never `restricted`), `retention_policy`, `audit_destination` | the compliance programme |
| `security` | `trust_domain` (machines that fail together share one; one domain is one independent witness), `attestation` (`none`, `tpm`, `measured_boot`, `confidential_vm`), `isolation` (`shared`, `dedicated`, `air_gapped`), `certificate_authority`, `secrets_backend` | the security team |
| `network` | `zone`, `egress` (`direct`, `proxy`, `none`), `dns`, `ntp`, `clock_source` (`ntp`, `ptp`, `rtc`, `unknown`), `clock_uncertainty_ms` (at most 60000) | the network team |
| `operations` | `profile` (`minimal`, `standard`, `deep`, `incident`, `forensic`), `runbook` | the operators |
| `platform` | `group`: what the agent believes about its place; the platform's own labels decide targeting | the platform console |

### What leaves the machine

The hello carries the reported subset, when `report = true` (the default) and anything
at all is set. Rack and row, the DNS and NTP names, the certificate authority, the
secrets backend, the audit destination and the whole `operations` section **never**
leave the machine: they describe the inside of your network and the platform has no use
for them. `report = false` sends none of the table. The platform keeps the reported
subset per agent, replaces it on every hello, clears it when a hello comes without it,
and never writes it to logs or metrics (RFC 0088, "What leaves the machine"). The
contract test that fails if a local-only field ever reaches the wire is
`hello_reports_metadata_without_what_stays_local` in `crates/iohr-agent/tests`.

### Rules checked

- `may_leave_jurisdiction` ⊆ `data_classes_allowed`; `external_models_may_see` ⊆
  `may_leave_jurisdiction`; `restricted` is never in `external_models_may_see`.
- `residency_zone` needs `country`; `decommission_planned` is after `commissioned`; a
  `change_freeze` interval does not end before it starts.
- `clock_uncertainty_ms` is at most a minute: a clock more uncertain than that is not a
  clock, say `clock_source = "unknown"` instead.
- Unknown fields and unknown enumeration values are errors with a line and column; a
  wrong country code names the code.

### Examples

[`packaging/examples/agent.enterprise.toml`](../packaging/examples/agent.enterprise.toml)
is a Linux system install in a colocation datacentre with every field filled;
[`packaging/examples/agent.macos.toml`](../packaging/examples/agent.macos.toml) is a Mac
with relative paths. On Kubernetes the Helm chart renders the same table from
`.Values.metadata` (`charts/iohr-agent/values.yaml`). Both examples are loaded by the
test `the_packaged_examples_are_valid`.
