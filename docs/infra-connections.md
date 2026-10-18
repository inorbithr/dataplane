# Infrastructure connections

Implements RFC 0150.1, slice C8. Module: `crates/iohr-agent/src/infra_conn/`.
Status: the connection kinds and the verb tables exist and are tested; they are not yet
registered in the policy or `agent.toml`, and the approval source is a test double (slice C4
brings the real one). Nothing here is live on a running agent yet.

A connection runs one tool: `kubectl`, `helm`, `ansible`, `tofu` or `ssh`. Its kubeconfig,
inventory, keys and cloud credentials are in the connection's `prefix` and `env` on the agent
and are never sent upstream.

## How a request runs

1. The caller sends an argv. `verbs::classify` parses it against the kind's table. An argv
   the table does not name is refused before any process starts.
2. What runs is built from the parsed words, in the table's order, never from the caller's
   text. No shell is involved: the binary (an absolute path from configuration) is started
   with that argv, an empty environment plus the connection's `env`, no stdin, a deadline
   (`timeout_secs`, 1 to 900) and a cap per stream (`max_output`, 1 KiB to 8 MiB).
3. Output goes through `redact::redact` (and `redact_json` for JSON) before it is returned.
4. Every request writes to the hash-chained audit log: who, `infra.<kind>.<class>`,
   connection and verb, outcome. Never the output.

## Classes

- read: runs at once.
- plan: copies each input file into a snapshot, runs the plan verb on the snapshot and saves
  the plan under `<plans_dir>/<hash>/`. The hash is the sha256 of the plan file for `tofu`,
  and of the plan record (apply form, snapshot hashes, redacted output hash) for the others.
- apply: needs an `Approval { id, plan_hash }`. Refused unless the plan exists and is intact,
  the requested apply equals the apply form the plan recorded, and the `ApprovalCheck` spends
  the approval for exactly that hash. An approval is single use, and a refused apply does not
  spend it. Without a checker every apply is denied. The apply runs from the snapshot, so an
  input edited after the plan changes nothing.

## Verbs

| Kind | read | plan | apply |
| --- | --- | --- | --- |
| kubectl | `get`, `describe`, `logs` (default `--tail 200`, 1 MiB), `top`, `api-resources`, `version`, `auth can-i` | `diff -f FILE` (server side) | `apply --server-side -f FILE` |
| helm | `list`, `status`, `history`, `get values` | `template REL CHART --version V`, `diff upgrade REL CHART --version V` | `upgrade --install REL CHART --version V` |
| ansible | `inventory --list`, `PLAYBOOK --list-hosts`, `PLAYBOOK --list-tasks` | `--check --diff PLAYBOOK` | `PLAYBOOK` |
| tofu | `show [-json]`, `state list`, `output [NAME]`, `validate`, `version` | `plan [-target ADDR]` (saves the plan file) | `apply` of the saved plan |
| ssh | `uptime`, `df`, `systemctl status UNIT`, `journalctl -u UNIT [-n N]` | none | none |

Flags per verb are a short allow-list (`-n`, `-o`, `-l`, `-f`, `--version`, `--limit`, `--tags`,
and so on); an unknown flag, `--`, `--kubeconfig`, `--raw`, `-e`, `-i`, `-auto-approve`, `-out`
or `-var` from the caller is refused. `kubectl get secrets` is refused (also inside a comma
list), and a manifest containing `kind: Secret` is never planned. Plan input files must lie
inside the connection's working directory (a symlink that leaves it is refused). The `ssh`
remote command is a single word assembled from the table and validated values.

## Not done in this slice

Apply verbs for rollout, scale and delete, `helm rollback` and `uninstall`; registration in
policy and `agent.toml` and the connections model; the real approval check (C4); re-plan
comparison; local helm charts and playbooks that need roles or an `ansible.cfg` beside them
(only the named file is snapshotted); monitors.
