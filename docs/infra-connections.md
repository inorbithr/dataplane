# Infrastructure connections

Implements RFC 0150.1, slice C8. Module: `crates/iohr-agent/src/infra_conn/`.
Status: the connection kinds and the verb tables exist and are tested; they are not yet
registered in the policy or `agent.toml`, and the approval source is a test double (slice C4
brings the real one). Nothing here is live on a running agent yet. This page was updated on
2026-10-18 after the security review of the slice.

A connection runs one tool: `kubectl`, `helm`, `ansible`, `tofu` or `ssh`. Its kubeconfig,
inventory, keys and cloud credentials are in the connection's `prefix` and `env` on the agent
and are never sent upstream.

## What the real control is

The identity a connection runs as decides what it can do: Kubernetes RBAC for `kubectl` and
`helm`, the cloud role for `tofu`, the remote user and its sudo rules for `ssh` and
`ansible`. Give that identity only what the connection needs; for example, RBAC that denies
it `secrets`. Everything on this page (the verb tables, the allow-lists, the manifest checks)
is defence in depth on top of that, not a replacement for it.

## How a request runs

1. The caller sends an argv. `verbs::classify` parses it against the kind's table. An argv
   the table does not name is refused before any process starts.
2. The connection's allow-lists are checked (see below), then, for reads and plans, the
   trusted-tree check.
3. What runs is built from the parsed words, in the table's order, never from the caller's
   text. No shell is involved: the binary (an absolute path from configuration) is started
   with that argv, an empty environment plus the connection's `env`, no stdin, a deadline
   (`timeout_secs`, 1 to 900) and a cap per stream (`max_output`, 1 KiB to 8 MiB).
4. The process runs in its own process group. At the deadline the whole group gets TERM,
   then KILL 2 seconds later, so a child the tool started is stopped too. When the tool
   exits on its own, whatever is left in its group is killed at once, so nothing it started
   in the background outlives the command.
5. Output goes through the connection's own `redact::Redactor` before it is returned (JSON
   output through `redact_json`, which falls back to text for a cut stream).
6. Every request writes to the hash-chained audit log: who, `infra.<kind>.<class>` (or
   `infra.<kind>.refused`), connection and verb, outcome. Never the output.

## Classes

- read: runs at once.
- plan: copies each input file into a snapshot, runs the plan verb on the snapshot and saves
  the plan under `<plans_dir>/<hash>/`. The hash is the sha256 of the plan file for `tofu`,
  and of the plan record for the others.
- apply: needs an `Approval { id, plan_hash }`. Refused unless all of these hold:
  - the plan exists and is intact;
  - it was made on this connection;
  - it is younger than the connection's `plan_ttl_secs` (1 to 86400, default 1800);
  - the requested apply equals the apply form the plan recorded;
  - the connection's context hash is the one the plan recorded;
  - no other apply runs on this connection;
  - the `ApprovalCheck` spends the approval for exactly that hash.

  An approval is single use. The checks above run before the approval is spent, so a
  refused apply does not spend it. Without a checker every apply is denied. The apply runs
  from the snapshot, so an input edited after the plan changes nothing.

### The plan record

The record holds the apply form, the snapshot file hashes, the hash of the redacted output,
the connection name, a context hash, the helm chart and version, and `created_at` (Unix
seconds). The context hash is the sha256 of the prefix, `KUBECONFIG`, `KUBECONTEXT`,
`HELM_KUBECONTEXT` and the contents of each kubeconfig file, plus the contents of every
file the prefix names with `--kubeconfig`, `-i`, `--private-key`, `--key-file` or
`--client-key`, an ssh `-o IdentityFile=<file>` or attached `-i<file>`, and every absolute-path
environment value (`KUBE_CONFIG_PATH`, a `/a:/b` list). An apply against another cluster or identity, or after one of those files was
swapped, is denied.

For `tofu` the plan hash is the plan file's sha256, and the record carries its own hash
(`record_sha256`) as well, so its connection, context and time cannot be edited on their own.
For the other kinds the plan hash is the record's hash.

One apply runs per connection at a time. A plan that would produce the hash of the apply
running now is refused until that apply ends; the check and the saving of a plan happen under
the same lock the apply takes before it loads the plan, so neither can replace the other's
directory.

## The trusted tree

Plans and reads run tools that load content from the working directory: playbooks, roles,
plugins, kustomizations, providers. That tree must be content the agent cannot change.
Before a read, a plan or a `tofu` apply, every directory from the working directory up to the connection's
`root` (default: the working directory itself) is checked. The request is refused when any of
them is writable by the agent's user or by group or others. Every request is refused when the
agent runs as uid 0, since root can change any tree. Other applies are not checked, because they run
from the snapshot; a `tofu` apply runs in the working directory itself, so it is.

On a host that is not unix, reads and plans are refused.

## Per kind

### kubectl

A manifest given to a plan is refused if it holds `kind: Secret` in any spelling (YAML, JSON,
inside a `List`, `Secrets.v1` and so on). The refusal is audited with the file, the kind and
the namespace, never the values. `get secrets` is refused in every spelling kubectl accepts
(`Secret`, `secrets.v1`, `SECRETS.v1.core`, inside a comma list or `secrets/name`), and the
same check and the resource allow-list run on every positional of `get` and `describe`, so
`get pod/a secret/db` is refused too.

### helm

A chart is `repo/name` from a configured repository with an exact `--version` (`1.2.3`,
`v1.2.3-rc.1+build`; never a range), or an OCI reference pinned by digest
(`oci://<registry>/<path>@sha256:<64 hex>`, which takes no `--version`) from a registry the
connection lists in `oci_registries`. Local paths, `https://` archives and OCI tags are
refused, since helm would load whatever is there at plan time and again at apply time.
`diff upgrade` always runs with `--suppress-secrets`.
`template` output is checked like a manifest: a plan is refused, and nothing saved, when the
rendered chart holds `kind: Secret`, a type the connection does not allow, or is cut by the
output cap (a Secret could sit past the cap).

### ansible

Ansible always runs with an empty config file (`ANSIBLE_CONFIG` points at an empty file in the
plans directory), so no `ansible.cfg` from the tree is loaded. Only the `yaml` and `ini`
inventory plugins and the `host_group_vars` vars plugin are on, so the tree cannot bring its
own. `--list-hosts` and `--list-tasks` load the playbook, so they are plans: they pass the
trusted-tree check, but save nothing and lead to no apply.

### tofu

`show` runs without `-json`, and there is no `output` verb: both would print sensitive
values. A plan needs a remote backend: `.terraform/terraform.tfstate` (written by `tofu init`)
must exist and name a known remote backend type (`s3`, `gcs`, `azurerm`, `http`, `pg`,
`consul`, `kubernetes`, `remote`, `cloud`, `oss`, `cos`, `etcdv3`, `swift`). A missing,
unreadable or `local` backend (an implicit local backend leaves no file) is refused with
"run tofu init with a remote backend", since the plan runs on a snapshot and local state
would be lost or edited.

### ssh

Every ssh run starts with options the connection cannot override (ssh keeps the first value
it is given): `-F /dev/null`, `-o BatchMode=yes`, `-o StrictHostKeyChecking=yes`,
`-o ControlPath=none`, `-o IdentitiesOnly=yes` (only the identity the prefix names, never the
agent's keys), `-o ForwardAgent=no` and `-o ClearAllForwardings=yes`. A prefix that names a config file (`-F`) is refused when the connection
is checked. The remote command is a single word assembled from the table and validated
values.

## Allow-lists

Each connection can narrow what its verbs may name:

- `resources` (kubectl): the resource types it may name or apply, compared without case,
  API group or plural `s`. Short names (`deploy`, `po`) are compared as written, so list each
  spelling you accept. Unset means every type but secrets. Manifests are checked against it
  too.
- `oci_registries` (helm): the registries an OCI chart may come from. Empty refuses OCI
  charts.
- `units` (ssh): the systemd units `systemctl status` and `journalctl -u` may name, with or
  without `.service`. Unset means any.

## Redaction

Each connection has its own `Redactor` on top of the shape and key rules and the
process-wide values. When the runner is built it registers:

- every `env` value that is not an absolute path, whatever its name (the redactor ignores
  values under 8 characters, so `1` or `true` never garble output);
- values of `--token` and `--password` in the prefix;
- the contents of key files: the files named by `--private-key`, `--key-file`,
  `--client-key` (and `-i` for ssh) in the prefix, and `env` values that are absolute paths
  to files up to 64 KiB. The whole file, each line of 16 characters or more, and each such
  value after a `key:` or `key=` (a kubeconfig's token) are registered.

The rules live in the shared `iohr-redact` crate (also used by Atlas core's infra worker); the agent's `redact.rs` adds only the process-wide values. Every redaction also hides the userinfo of a URL that carries a password:
`postgres://admin:pw@db/x` becomes `postgres://[redacted]@db/x`. A bare user
(`ssh://git@host`) stays. A password with a raw `/`, `?` or `#` is covered: when the text
before it reads `user:word` (not a port), the userinfo runs to the last `@` of the token. A
password of digits only that holds a `/` is the one shape not caught.

A manifest whose `kind` is empty or not a plain name (`kind:` then a new line, `!!str`, `|`)
is refused as one that cannot be read. A path list in an environment value (`KUBECONFIG=/a:/b`)
has each file learned for redaction.

## Verbs

| Kind | read | plan | apply |
| --- | --- | --- | --- |
| kubectl | `get`, `describe`, `logs` (default `--tail 200`, 1 MiB), `top`, `api-resources`, `version`, `auth can-i` | `diff -f FILE` (server side) | `apply --server-side -f FILE` |
| helm | `list`, `status`, `history`, `get values` | `template REL CHART --version V`, `diff upgrade REL CHART --version V --suppress-secrets` | `upgrade --install REL CHART --version V` |
| ansible | `inventory --list` | `--check --diff PLAYBOOK`; `PLAYBOOK --list-hosts`, `PLAYBOOK --list-tasks` (no apply) | `PLAYBOOK` |
| tofu | `show`, `state list`, `validate`, `version` | `plan [-target ADDR]` (saves the plan file) | `apply` of the saved plan |
| ssh | `uptime`, `df`, `systemctl status UNIT`, `journalctl -u UNIT [-n N]` | none | none |

Flags per verb are a short allow-list (`-n`, `-o`, `-l`, `-f`, `--version`, `--limit`, `--tags`,
and so on); an unknown flag, `--`, `--kubeconfig`, `--raw`, `-e`, `-i`, `-auto-approve`, `-out`
or `-var` from the caller is refused. Plan input files must lie inside the connection's
working directory (a symlink that leaves it is refused).

## Tests and the `test-approvals` feature

`FedApprovals`, the approval double that the tests feed, is built only under `cfg(test)` or
the `test-approvals` cargo feature, which a release never turns on: an agent built with it
could be fed approvals in process. `tests/infra_connections.rs` requires the feature:

```
cargo nextest run -p iohr-agent --features test-approvals
```

## Known limits

- Anyone who can write the plans directory (mode 0700, owned by the agent) can recompute a
  tofu record's hash after editing it. The plan file's own hash still pins what applies.
- The writability check covers directories, not files. A file in the tree that the agent
  or others can write is not caught.
- The refusal of a re-plan while the same plan is applying, and the uid 0 refusal, have no
  test yet.
- `cli.rs`, the admin page and the MCP door still use the process-wide redact functions,
  not a `Redactor` of their own.

## Not done in this slice

Apply verbs for rollout, scale and delete, `helm rollback` and `uninstall`; registration in
policy and `agent.toml` and the connections model; the real approval check (C4); re-plan
comparison; local helm charts and playbooks that need roles beside them (only the named file
is snapshotted); monitors.
