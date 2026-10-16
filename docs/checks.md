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
| `surface` | no | `http`, `tcp`, `tls`, `grpc_health`, or a transport surface: `grpc`, `sse`, `ws`, `mqtt`, `mcp`, `graphql` ([below](#transport-surfaces)). Default: `http` for a URL target, `tcp` for host and port. |
| `target` | yes | A URL (`"https://api.example.com/healthz"`), `"host:port"`, a bare host for `tls` (port 443), or a table: `{ url = "…" }` or `{ host = "…", port = 5432, tls = true }` (`tls` for `grpc_health`). No user or password in a URL; credentials go in `auth`. |
| `every` | yes | `"60s"`, `"5m"`, `"1h"`, `"1d"`: from one minute to 24 hours. |
| `expect` | no | `status` (100 to 599; `http`, `sse`, `mcp`, `graphql`), `max_ms` (1 to 30000), `valid_for_days` (1 to 365, `tls` and `http`: the certificate must stay valid that long; judged by the platform from the expiry the agent reports). Without `status`, any status below 400 passes. |
| `fail_after` | no | Failed runs in a row before the monitor goes down, 1 to 5. Default 2 for `[[check]]`, 1 for `[[refuse]]`. |
| `service` | no | The gRPC health service name (`grpc_health` only); empty means the whole server. |
| `auth` | no | A secret reference (`env:NAME`, `file:/path`, `k8s:ns/name#key`, `vault:path#key`) sent as the `authorization` header of every surface but `tcp` and `tls` (on `ws` and `mqtt`, of the WebSocket upgrade; on `grpc`, as metadata). Never a value; the policy's `[secrets] allow` must permit it. |
| `auth_scheme` | no | A word put before the secret's value, `"Bearer"`; without it the value is sent as it is. Stays on this machine. |
| `category` | no | One of `availability`, `transport`, `contract`, `security`, `performance`, `synthetic`; the monitor's category. |
| `label` | no | What the console calls the check when its target is not shared (`[share] targets` in the policy, the default); 1 to 128 characters. Default: the name. |
| `tags` | no | Up to 10 labels, `{ transport = "ws" }`: keys `^[a-z][a-z0-9_.-]{0,31}$`, values `^[A-Za-z0-9_.:/-]{1,64}$`. They leave the machine with the check; never put customer data in them. |
| `rfc` | no | The platform RFC this check proves (`"0029"`, `"0040.1"`); the RFC's page then shows "proved since". |
| `by` | `[[refuse]]` | Who must refuse: `"policy"` or `"platform"`. Leave it out and give `expect` for a refusal the target answers. |

At most 50 entries, `[[check]]` and `[[refuse]]` together.

## Transport surfaces

RFC 0040.2. Six surfaces test an API transport end to end. Each reads a bounded answer
(at most 1 MiB, at most 32 WebSocket or MQTT messages, at most 20 events), judges it in
memory and drops it. A result is still a verdict, the latency, an HTTP status and an
error class: never a body, a header value, an error message or a payload. The class
`answer` means the target answered in the wrong shape.

They are off until the policy lists them in `[work] surfaces`. What each sends beyond its
target is in the keys below and **stays on this machine**: the platform's job for the
check names only its `name`, the agent reads the rest from this file, and it refuses a job
whose surface or target differ from the entry. `ws`, `mqtt` and `grpc` run only as
declared checks.

| Surface | Target | Keys | Passes when |
|---|---|---|---|
| `sse` | URL | `events` (0 to 20, default 1) | `GET` with `Accept: text/event-stream` answers the expected status (any 2xx) as an event stream and delivers `events` events (a block with `data`; comments do not count) in time |
| `graphql` | URL | `query` (default `{ __typename }`, at most 8 KiB), `variables` | `POST` answers the expected status with `data` and no `errors` |
| `mcp` | URL | `min_tools` (default 1), `tool`, `args`, `allow_side_effects` | `initialize`, `notifications/initialized` and `tools/list` succeed with at least `min_tools` tools; with `tool`, its `tools/call` succeeds without `isError`. A tool is called only when `tools/list` annotates it `readOnlyHint: true`, or with `allow_side_effects = true`; otherwise the job is refused and nothing is called |
| `ws` | URL (`http` becomes `ws`, `https` `wss`) | `method` (`pkg.Service/Method`, required), `params`, `expect_error` | the `/v1/ws` frame `call` gets a `data` frame; with `expect_error`, an `error` frame with that `code` |
| `mqtt` | URL of the MQTT-over-WebSocket endpoint | `topic` (required, no wildcards), `params`, `expect_error` | MQTT 5 (subprotocol `mqtt`): CONNECT, SUBSCRIBE to `reply/<client id>/check`, PUBLISH at QoS 1 with that Response Topic and random Correlation Data; the answer carries no `error` user property (with `expect_error`, that value). A refusal in CONNACK, SUBACK or PUBACK is `status` |
| `grpc` | URL or `{ host, port, tls }` | `method` (required), `expect_code` (0 to 16, default 0) | a unary call with an empty request message ends with that `grpc-status` |

`http` gains `method` (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`), a JSON
`body` (at most 8 KiB, sent as `application/json`) and `headers` limited to `accept` and
`content-type`, so a health check can `POST`. Its answer is still never read.

```toml
[[check]]
name = "graphql-heartbeat"
surface = "graphql"
target = "https://api.example.com/graphql"
query = "{ __typename }"
every = "15m"
category = "transport"
tags = { transport = "graphql" }

[[check]]
name = "ws-heartbeat"
surface = "ws"
target = "https://api.example.com/v1/ws"
method = "iohr.events.v1.EventsService/ListEventTypes"
params = { page_size = 1 }
auth = "env:PROBE_KEY"
auth_scheme = "Bearer"
every = "15m"

[[check]]
name = "mqtt-heartbeat"
surface = "mqtt"
target = "https://api.example.com/v1/mqtt"
topic = "rpc/events/ListEventTypes"
params = { page_size = 1 }
auth = "env:PROBE_KEY"
auth_scheme = "Bearer"
every = "15m"
```

An authenticated heartbeat calls something its key may call. A key with catalogue scopes
(`events:read`, `mcp:read`, …; not `iohr.api`) gets past the socket upgrade on `/v1/ws` and
`/v1/mqtt`, and then the gateway checks every call against the same scope table as REST: a
method whose route no scope of the key names is refused (`forbidden`, which this agent reports
as `answer` on `ws` and `status` on `mqtt`). `EventsService/ListEventTypes` is the route of
`GET /v1/events/types`, which `events:read` admits, and it reads nothing of the account. The
earlier example, `LedgerService/Ping`, is named by no scope: it passes only with a full API
token, and a probe key never passes it (found live on 2026-10-08, the outside-in heartbeats).

`grpc` sends an empty request only: a method whose request needs fields is checked by the
status it refuses with. Requests built from server reflection are not in this version.

## Host sensors: `hwmon`

A sensor on the agent's own machine against thresholds. It needs `[work] host = true` and
`hwmon` in `[work] surfaces` ([policy](policy.md#host)). The agent samples every hwmon
sensor every `[host] sample_secs` (10 s) and judges a run on the window since the
previous run, so a spike between two runs is not missed.

```toml
[[check]]
name = "chipset-temp"
surface = "hwmon"
target = { sensor = "asusec/Chipset" }   # chip/label, or chip/kind/label
every = "60s"
warn = 100          # °C
crit = 108
rate_warn = 2       # °C per minute, rising
fail_after = 1
category = "availability"

[[check]]
name = "chipset-fan"
target = { sensor = "asusec/Chipset" }
kind = "fan"        # temp (default), fan, in, curr, power
below = true        # thresholds are lower bounds: a fan that slows or stops
warn = 3000         # RPM
crit = 1000
every = "60s"
```

| Field | Meaning |
|---|---|
| `target` | `{ sensor = "chip/label" }`. The chip is the hwmon name (`asusec`, `k10temp`), an NVMe controller (`nvme5`), or `name@<pci address>` when two chips share a name; `atlas observe host --report` and the evidence list every key. |
| `kind` | What the label measures; the same label can name a temperature and a fan (`asusec` has both for `Chipset`). |
| `warn`, `crit` | In °C, RPM, V, A or W. At or past `crit` the run fails (`error_class = "threshold"`); at or past `warn` it passes with `level = "warn"`. |
| `rate_warn`, `rate_crit` | Change per minute over the last two minutes (least squares), rising (falling with `below`). |
| `below` | Thresholds are lower bounds. |

The result carries `detail.reading`: `sensor` (the key), `unit` (`millicelsius`, `rpm`,
`millivolts`, `milliamps`, `microwatts`), `value` (newest), `peak` (worst since the last
run), `rate_per_min` (when known), `level` (`ok`, `warn`, `crit`) and `samples`. A sensor
that is not on the host, or has no sample yet, fails with `error_class = "sensor"`. The
thresholds stay in this file: a job names the check's key, and a job for `hwmon` that does
not name a declared check is refused. In the hello the entry carries
`"target": {"sensor": "asusec/temp/Chipset"}` and
`"thresholds": {"unit": "millicelsius", "warn": 100000, "crit": 108000, ...}` in the raw
unit, so the platform can show them.

A reading is a measurement of the agent's own machine, not of a target's answer: the
sensor key, the numbers and the level leave the machine; nothing else about the host does
(the topology, mounts and boots stay in local `atlas observe host` output).

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

Every entry also carries `label` and `target_shared`. That example is the policy's
`[share] targets = "full"`. By default (`"hash"`) an entry leaves without `target` and
`auth`, with `target_hash` (`hmac-sha256:…`, keyed on this machine) and, when it reads a
secret, `uses_secret: true`; with `"label"`, without the hash too
([policy.md](policy.md#share)). `checks_hash` is over the entries exactly as sent.

So at `"full"` the targets and names you declare leave the machine: full URLs (path and
query included), host names and ports, secret *references*, RFC numbers, categories and
tags. At the default only names, labels, keyed hashes, schedules, expectations, RFC
numbers, categories and tags do. A transport check's request (method, params, query, topic, tool, body, headers) and
`auth_scheme` do not. Secret values never
do; neither do results beyond what any job reports. The platform answers what it accepted
and why it rejected the rest; the agent's page in the console shows both.

## Running the checks once, from a pipeline

`iohr-agent run --once` runs these entries one time and exits 0, 1 or 2, for a CI step that
gates a deploy on real checks from inside the network. See [run-once.md](run-once.md).
