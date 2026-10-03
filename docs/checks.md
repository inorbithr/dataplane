# Declared checks (`checks.toml`)

`checks.toml` lists what this agent watches. On every connection the agent sends the
list in its `hello`; the platform turns each entry into a monitor **managed by this
agent** and keeps it running, with the same scheduler, history and alerts as any other
monitor. The file is the one source of truth: managed monitors are read-only in the
console and the API, and changing the file (then restarting the agent) changes them.
Design: [RFC 0040.1](https://inorbit.hr/lab/rfc/0040.1-declared-checks-and-self-tests/).

The file is optional. Without it the agent declares nothing and the platform changes
nothing. An empty file (no entries) removes every monitor this agent declared.

The agent gets no new credential for this. Declaring is part of the session it already
has; the platform decides what to accept, inside the domains the account has verified and
at the account's ceilings. The local [policy](policy.md) still wins: a job for a declared
check is an ordinary job and passes the same admission as any other.

## Where it lives

Next to `agent.toml` by default (`checks.toml` in the same directory). Name another path
with `checks` in `agent.toml`:

```toml
checks = "/etc/iohr-agent/checks.toml"
```

With Helm, set `checks.checksToml` in your values (or `checks.existingConfigMap`, key
`checks.toml`); the chart mounts it beside the policy. Restart the agent to apply a change.

## Reference

```toml
[[check]]
name = "api"
surface = "http"
target = "https://api.example.com/healthz"
every = "60s"
expect = { status = 200, max_ms = 2000 }
fail_after = 2
rfc = "0029"

[[check]]
name = "api-tls"
surface = "tls"
target = "api.example.com"
every = "1h"
expect = { valid_for_days = 14 }

[[refuse]]
name = "private-is-refused"
target = "https://db.internal/"
by = "policy"
every = "5m"

[[refuse]]
name = "outside-domains-is-refused"
target = "https://example.com/"
by = "platform"
every = "5m"

[[refuse]]
name = "api-needs-a-token"
surface = "http"
target = "https://api.example.com/v1/me"
expect = { status = 401 }
every = "5m"
```

Unknown keys are errors, so a typo never silently changes what is checked.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | 1 to 64 of `a-z 0-9 -`, unique in the file. The monitor's key: renaming an entry replaces its monitor. |
| `surface` | no | `http`, `tcp`, `tls` or `grpc_health`. Default: `http` for a URL target, `tcp` for host and port. |
| `target` | yes | A URL (`"https://api.example.com/healthz"`), `"host:port"`, a bare host for `tls` (port 443), or a table: `{ url = "…" }` or `{ host = "…", port = 5432, tls = true }` (`tls` for `grpc_health`). No user or password in a URL; credentials go in `auth`. |
| `every` | yes | `"60s"`, `"5m"`, `"1h"`, `"1d"`: from one minute to 24 hours. |
| `expect` | no | `status` (100 to 599, `http`), `max_ms` (1 to 30000), `valid_for_days` (1 to 365, `tls` and `http`: the certificate must stay valid that long; judged by the platform from the expiry the agent reports). Without `status`, any status below 400 passes. |
| `fail_after` | no | Failed runs in a row before the monitor goes down, 1 to 5. Default 2 for `[[check]]`, 1 for `[[refuse]]`. |
| `service` | no | The gRPC health service name (`grpc_health` only); empty means the whole server. |
| `auth` | no | A secret reference (`env:NAME`, `file:/path`, `k8s:ns/name#key`, `vault:path#key`) sent as the `authorization` header of `http` and `grpc_health` checks. Never a value; the policy's `[secrets] allow` must permit it. |
| `rfc` | no | The platform RFC this check proves (`"0029"`, `"0040.1"`); the RFC's page then shows "proved since". |
| `by` | `[[refuse]]` | Who must refuse: `"policy"` or `"platform"`. Leave it out and give `expect` for a refusal the target answers. |

At most 50 entries, `[[check]]` and `[[refuse]]` together.

## Tests that must fail: `[[refuse]]`

A `[[refuse]]` entry passes when the target is refused. A guard that stops guarding then
turns its monitor `down` with the class `guard_open`, instead of every monitor staying
green.

| Written as | Passes when |
|---|---|
| `by = "policy"` | this agent's policy refuses the job (result `refused`, class `refused_by_policy`); nothing is sent to the target |
| `by = "platform"` | the platform refuses the job before it reaches the agent (the target is outside the account's verified domains) |
| `expect = { … }` | the target answers with the expected refusal, e.g. `status = 401`; an ordinary check whose expected answer is the refusal |

A refusal monitor is never paused for succeeding and is not folded into uptime figures.

## `checks lint`

```sh
iohr agent checks lint                       # the files agent.toml names
iohr-agent checks lint --file checks.toml --policy policy.toml
iohr-agent checks lint --resolve             # also resolve names, as a job would
```

Offline by default. One line per entry, `ok`, `warning` or `error` with the reason, then
the count and the `checks_hash`; exit 1 on any error. It checks that:

- every entry parses and respects the bounds above;
- a `[[check]]` (and a refusal expected from the target's answer) is allowed by the
  policy: surface enabled, a named host in `networks.allow` or inside a bound domain, an
  address in `networks.allow` and outside `networks.deny`, the `auth` reference in
  `[secrets] allow`;
- a `by = "policy"` refusal is refused by the policy. A host inside a bound domain is
  refused only when it resolves outside `networks.allow`; lint warns, and `--resolve`
  decides;
- a `by = "platform"` refusal lies outside the policy's bound domains (a warning if not:
  the platform refuses only hosts outside the account's verified domains);
- a URL with a query string is a warning: the query is sent to the platform with the check.

## What is sent

The `hello` carries three more fields (shared contract, RFC 0040.1):

| Field | Contents |
|---|---|
| `agent_time` | this machine's clock, RFC 3339 UTC; the platform measures the skew |
| `checks_hash` | `sha256:` and lowercase hex over the canonical JSON of `checks` (entries in file order, object keys sorted, no whitespace); absent without a file |
| `checks` | the entries, normalized; absent without a file |

The normalized form of the example above starts:

```json
[{"key":"api","kind":"check","surface":"http",
  "target":{"url":"https://api.example.com/healthz"},
  "every_secs":60,"fail_after":2,"expect":{"status":200,"max_ms":2000},"rfc":"0029"},
 {"key":"private-is-refused","kind":"refuse","refuse_by":"policy","surface":"http",
  "target":{"url":"https://db.internal/"},"every_secs":300,"fail_after":1}]
```

`kind` is `check` or `refuse`; `refuse_by` is `policy`, `platform` or `answer` (a refusal
given with `expect`).

So the targets and names you declare leave the machine: full URLs (path and query
included), host names and ports, secret *references* and RFC numbers. Secret values never
do; neither do results beyond what any job reports. The platform answers what it accepted
and why it rejected the rest; the agent's page in the console shows both.
