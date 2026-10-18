# Policy reference (`policy.toml`)

The policy says what this agent may reach and do. It belongs to whoever runs the agent
and wins over anything the platform asks for: a job outside it is refused, and the
refusal, with the reason, is sent to the platform and shown in the console. Unknown keys
are errors, so a typo never silently allows something. Restart the agent to apply a
change; `iohr-agent policy check` validates a file and prints its hash, which the console
shows next to the agent.

What the agent declares it watches lives in a separate file, [`checks.toml`](checks.md);
the policy still decides whether each of those checks may run, and
`iohr-agent checks lint` tells you before the platform does.

```toml
environment = "staging"

[domains]
bound = ["example.com"]

[networks]
allow = ["10.0.0.0/8", "db.internal", "*.svc.cluster.local"]
deny  = ["0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "::/128"]

[work]
checks = true
load = false
faults = false
surfaces = ["http", "tcp", "tls", "grpc_health"]
capture = false

[ceilings]
max_concurrent_jobs = 4
max_job_ms = 30000
max_jobs_per_minute = 120

[secrets]
allow = ["vault:kv/staging/*", "k8s:checks/*"]
```

## Sections a version does not know

From 0.1.0-alpha.9, a whole top-level section this agent version does not know (written for
a later one) is **ignored with a loud warning**: in the log at every start and reload, and
at the top of the local page's Overview and Policy sections. The agent starts, and the
section is left out of the policy hash. Everything else still refuses the file and stops
the agent, as before: an unknown key inside a known section (a typo in a deny rule fails
closed), and an unknown key at the top level that is not a section. Agents before
alpha.9 refuse any unknown section, `[share]` included: set it after upgrading.

## `environment` (required)

The one environment this agent serves: 1 to 32 of `a-z 0-9 -`, starting with a letter.
It must equal `environment` in `agent.toml` and the environment the enrollment token was
made for, or the agent does not start.

## `[domains]`

| Key | Default | Meaning |
|---|---|---|
| `bound` | `[]` | A target named by host may be checked when it is one of these or under one (`api.example.com` under `example.com`) **and** every address it resolves to is in `networks.allow`. Usually the domains the enrollment was bound to, which must be verified in your account (RFC 0030). |

## `[networks]`

| Key | Default | Meaning |
|---|---|---|
| `allow` | `[]` | CIDRs (`10.0.0.0/8`), single addresses, host names (`db.internal`) and host suffixes (`*.svc.cluster.local`, which matches names under it, not itself). |
| `deny` | link-local, cloud metadata, unspecified | CIDRs never connected to, even when allowed. Setting `deny` replaces the default list. |

How a target is decided:

- **An address** (`10.1.2.3`, `[::1]`): allowed when inside `allow` and outside `deny`.
  IPv4-mapped IPv6 addresses are treated as IPv4.
- **A host name**: refused before any DNS query unless it is named in `allow` or lies
  inside a bound domain. It is then resolved **once**; every address must be outside
  `deny`, and, for a bound-domain name, inside `allow`. The connection goes to the
  checked address only: no second lookup, so a DNS answer cannot change between the
  check and the connection. HTTP redirects are not followed.

## `[work]`

| Key | Default | Meaning |
|---|---|---|
| `checks` | `true` | Accept surface checks. |
| `load` | `false` | Load generation. Not in this version: always refused. |
| `faults` | `false` | Faults through the proxy. Not in this version: always refused. |
| `surfaces` | `http`, `tcp`, `tls`, `grpc_health` | Which check surfaces are accepted. The transport surfaces `grpc`, `sse`, `ws`, `mqtt`, `mcp` and `graphql` read a bounded answer (never reported) and are accepted only when listed ([checks](checks.md#transport-surfaces)). `examples` is accepted only when listed and a set exists ([`[examples]`](#examples)). |
| `capture` | `false` | Read the capture companion's counts ([`[capture]`](#capture)) and announce `capture:*`. Needs an agent newer than 0.1.0-alpha.4. |
| `host` | `false` | Observe this machine, read-only: `atlas observe host` and the `hwmon` check surface with its sampler ([`[host]`](#host), [host.md](host.md)). `hwmon` must also be listed in `surfaces` for checks. Needs an agent newer than 0.1.0-alpha.8. |

The agent announces what it accepts (`check:http`, …) in its `hello`, so the console only
offers what this policy allows.

## `[capture]`

Read only when `[work] capture = true`; without that switch the section is accepted and
does nothing. **Needs an agent newer than 0.1.0-alpha.4**: older agents reject the
unknown keys (`capture` in `[work]`, the `[capture]` section) and do not start, so upgrade
the agent before adding them. A policy without them keeps the hash it had before.

| Key | Default | Meaning |
|---|---|---|
| `socket` | `/run/iohr-capture/aggregates.sock` | The companion's aggregates socket (absolute path). |
| `layers` | `["headers", "protocols", "owners", "tcp", "packets", "timing"]` | Layers the agent may announce: `capture:<layer>` in the hello, for each one the companion also runs. `packets` also needs the companion's root-only control socket to exist; it says the host can make pcap files for root, never that the agent can (the agent never gets packets). `packets` and `timing` need an agent with capture phase 2: phase 1 agents reject a policy that names them and do not start, so upgrade the agents first, then the policies; a `[capture]` section without `layers` gets a new policy hash with that agent, because the default list grew. |
| `max_snapshot_age_secs` | `30` | 1–3600. An answer whose numbers are older counts as no answer: nothing is announced. |

At each session start the agent asks the socket for counts (1 s timeout). Only the
`capture:*` strings travel to the platform; the counts stay on the admin page and in
`iohr agent capture status`. `iohr agent capture lookup` asks for the numbers of one
route and owner the caller already knows (socket protocol version 2). Names, routes, paths,
addresses and packets never reach the agent at all
([install guide](capture/install.md#what-capture-never-does)).

## `[host]`

Read only when `[work] host = true`; without that switch the section is accepted and does
nothing. Older agents reject the unknown keys (`host` in `[work]`, the `[host]` section)
and do not start, so upgrade the agent first. A policy without them keeps its hash.

| Key | Default | Meaning |
|---|---|---|
| `journal` | `false` | Run `journalctl --list-boots` and read each earlier boot's last entries to tell which boots ended without a shutdown record. The only program the host observers run (fixed arguments, empty environment, 10 s timeout, 1 MiB bound). The agent's user needs to read the journal (group `adm` or `systemd-journal`). |
| `sample_secs` | `10` | 5–300. Seconds between sensor samples while the agent runs. |
| `window_secs` | `900` | 60–3600, at least two samples. History kept in memory for rates and peaks; nothing is written to disk. |

The host observers need no privilege. With `CAP_SYS_ADMIN` (and nothing else) they also
read PCI config space past 64 bytes, which gives the per-link ASPM state; without it that
state is reported as not observed. See [host.md](host.md#privileges).

## `[examples]`

SDK example sets the agent runs on a timer, one table per set key (RFC 0165). A set is
read by `examples` checks ([checks](checks.md#sdk-examples-examples)); the surface is
accepted only when `examples` is in `[work] surfaces` and at least one set exists. Older
agents ignore the table with a warning, so the check is refused there. A policy without it
keeps its hash.

```toml
[examples.sdk]
dir = "/srv/sdk"
command = ["mise", "run", "examples:run"]
every_secs = 3600
timeout_secs = 1800
```

| Key | Default | Meaning |
|---|---|---|
| `dir` | required | Absolute path of the checkout the command runs in. |
| `command` | required | Program and arguments, no shell. Stdio is discarded. |
| `results` | `examples-results.json` | Relative path under `dir` the command writes (schema 1); no `..`. It must be newer than the run's start. |
| `every_secs` | `3600` | 60 to 86400. Seconds between runs; a set never overlaps itself. |
| `timeout_secs` | `1800` | 10 to 7200. The run is killed past this. |
| `max_age_secs` | `2 x every_secs + timeout_secs` | At least `every_secs`. A newest run older than this reads `run/stale`. |

The set key is a lowercase slug. Nothing from the command's output leaves the machine.

## `[ceilings]`

| Key | Default | Range | Meaning |
|---|---|---|---|
| `max_concurrent_jobs` | 4 | 1–64 | More at once are refused. |
| `max_job_ms` | 30000 | 100–300000 | A longer deadline from the platform is cut to this. |
| `max_jobs_per_minute` | 120 | 1–6000 | More in a rolling minute are refused. |

## `[secrets]`

| Key | Default | Meaning |
|---|---|---|
| `allow` | `[]` | Secret references a job may name: exact, or a prefix ending in `*`. Empty means no job may use a secret. |

References are resolved on the agent at the moment of the call and dropped after:

| Reference | Read from |
|---|---|
| `env:NAME` | the agent's environment |
| `file:/abs/path` | a file (trailing newline removed) |
| `k8s:<namespace>/<name>#<key>` | a Kubernetes Secret, with the pod's service account (`[secrets.kubernetes]` in `agent.toml`) |
| `vault:<mount>/<path>#<key>` | HashiCorp Vault KV v2 (`[secrets.vault] addr`, token from `env:` or `file:`) |

A check uses a secret as one header (`auth: {header, scheme, secret}` in the job), marked
sensitive; the value is never logged, reported or written anywhere.

## `[share]`

What the hello tells the platform about this agent (RFC 0100 D11 and D13 in
inorbithr/core). Absent means the defaults, which keep targets and the host name on
this machine.

You rarely edit it by hand. Three ways set it, each rewriting only these two keys in place
(comments and every other line kept) and applying it without a restart:

- **The agent's local page**, Policy, "What InOrbit sees": Everything, Fingerprint or Label
  only, and a "Send host name" switch, with a preview of exactly what the next hello would
  carry. Only on the agent's own machine (the page and the browser both on loopback) and
  signed in (`iohr agent page --open`); the platform cannot change it.
- **`iohr agent share full|hash|label [--hostname on|off]`** for headless machines (run it
  as a user who can write the policy, `sudo` for a packaged `/etc/iohr-agent/policy.toml`).
  Without a level it prints what InOrbit sees now.
- **`iohr agent init`** asks once, with the defaults shown; `--share-targets` and
  `--share-hostname` answer it for unattended installs.

The running agent reloads its policy and checks when told to, opens a new session whose
hello says what the new policy shares, and records the choice in the ledger
(`share_set`, local, nothing sent). A change made by hand is recorded when the agent next
starts or reloads.

| Key | Default | Meaning |
|---|---|---|
| `targets` | `"hash"` | How each declared check's target leaves: `"hash"` sends its label and an HMAC-SHA256 of the target under a key that never leaves the machine (`<state_dir>/share.key`), so the platform can tell when a target changes but not what it is, nor test a guess; `"label"` sends the label only; `"full"` sends the URL, or host and port, as before. |
| `hostname` | `false` | Send this machine's host name (`hostname` in the hello). Off, the console shows the agent's name. |
| `inventory` | `true` | Send the agent's inventory in the hello (RFC 0088.1 in inorbithr/core): the surfaces and work kinds this policy admits, its `[ceilings]`, its observers (`host` with `[work] host`), the OS and CPU architecture, and the extensions installed beside it as `iohr-ext.lock` pins them (name, version, digest, signer, privileges). The platform uses it only to send *less*: no work this agent can't run or its policy refuses. No address, host name or location. `false` sends the older capability strings alone. Set it in the file; the page and `iohr agent share` keep it. |
| `host` | `false` | Send a coarse host summary on the heartbeat (RFC 0102 in inorbithr/core), on the first and every fourth: the 1-minute load, CPUs, memory in use, each filesystem's mount point, use and free space and whether it is read-only (the kernel's `emergency_ro` too), temperatures (`chip/label` and °C, the chipset, CPU and drives first), `md` arrays (name, level, state, members, failed members) and NVMe controllers' kernel states. Needs `[work] host`. No process, user, file, address, model or serial number. Set it in the file; the page and `iohr agent share` keep it as it is. |

Below `"full"`:

- a check's secret reference (`auth`) stays here too; the hello says `uses_secret: true`;
- the platform names a check in a job by its key (and may add the `target_hash` it was
  given, which must match); the agent takes the target from `checks.toml`;
- a refusal's reason leaves with the target replaced by `the target of "<label>"` and
  any address replaced too; the local page keeps the full reason;
- a `[[refuse]]` entry with `by = "platform"` still sends its target: the platform cannot
  refuse what it does not know. Such targets lie outside your domains by definition.

The local page's Policy section shows the levels and, check by check, what the platform
gets. Whatever the level, every message that leaves is in the [egress ledger](ledger.md).

## `[console]`

Who may sign in to the local console (RFC 0100.2). Left out, only the machine's token works.

```toml
[console]
users = ["machine", "oidc"]   # the ways in

[console.oidc]
issuer = "https://login.example.com"   # https; its discovery document names the rest
name = "Example SSO"                    # what the sign-in page calls it
client_id = "iohr-agent-console"        # this agent's (confidential) client at the issuer
client_secret = "env:IOHR_CONSOLE_OIDC_SECRET"   # a reference, never the value
groups_claim = "groups"
roles = { owner = ["sec-admins"], admin = ["sre-leads"], member = ["engineering"], viewer = ["auditors"] }
```

- `machine`: the token in `<state_dir>/admin.token`. Whoever can read that file is the
  machine's break-glass **owner**, always recorded as `machine`.
- `oidc`: the company's identity provider, authorization code with PKCE; the redirect URI is
  `http(s)://<the console's host>/auth/oidc/callback`. A person gets the highest role any of
  their groups names, and no session at all when none does. InOrbit is not involved.
- Roles: `viewer` reads; `member` also changes `checks.toml`; `admin` also changes this policy
  and the extensions; `owner` is everything. Every change is in the local audit log.

## `[extensions]`

Which extensions this machine allows (RFC 0073.1). Left out: `allow = ["inorbit/*"]`.

```toml
[extensions]
allow = ["inorbit/agent-core", "inorbit/console", "inorbit/monitors"]
```

An extension runs only when the licence entitles it, this list allows it (with the `[work]`
kinds its manifest needs), and the agent's lock (`<state_dir>/extensions.lock`) has it. The
local console's Extensions page shows all three for each one. The console cannot add to this
list: changing the policy is an admin's edit of this file, audited and noted in the egress
ledger (`policy_set`, hashes only).

## `[actions]`

Signed read-only HTTP actions (PRD 0117 in inorbithr/core): the platform asks this agent
to call an API only it can reach, a self-hosted Grafana first (`grafana-self-hosted`).
Off unless `enabled = true`; an agent before this version ignores the section (see above)
and runs no actions.

```toml
[secrets]
allow = ["k8s:observability/grafana-inorbit-sa#token"]

[actions]
enabled = true
platform_keys = ["ed25519:<the platform's job-signing public key, base64url>"]
account_id = "<your account id>"          # optional: must repeat the enrolled account
hosts = ["grafana.observability.svc.cluster.local"]
datasources = ["victoriametrics"]         # the only datasource uids a query may use; empty: none
max_bytes = 1048576                       # the largest answer read, 1 KiB to 8 MiB

[[actions.sensors]]
name = "api-error-rate"
template = "error-rate"                   # the connection's saved query template
base_url = "http://grafana.observability.svc.cluster.local:3000"
auth = "k8s:observability/grafana-inorbit-sa#token"
datasource_uid = "victoriametrics"
expr = "sum(rate(http_requests_total{code=~\"5..\"}[5m]))"
interval_secs = 60                        # 15 to 3600
range_secs = 300
step_secs = 60                            # at least 15; range / step at most 1000 points
labels = ["job"]
warn = 1.0
crit = 5.0
below = false                             # true: the thresholds are floors
```

Every action job is refused unless all of these hold, before anything is resolved or
connected:

- its envelope is signed with Ed25519 by a key in `platform_keys`, names this agent and
  this job and the account this agent enrolled in (always; `account_id`, when set, must be
  the same), was issued no more than 60 s ahead of this clock,
  lives at most 600 s and has not expired; a job id runs once;
- the method is `GET`, the base URL is `http(s)://host[:port]` (no trailing dot) with its host in `hosts`
  (and allowed by `[networks]`), and the path is one of the connector's fixed routes:
  `/api/search`, `/api/dashboards/uid/<uid>`, `/api/datasources`, and
  `/api/datasources/proxy/uid/<uid>/api/v1/query_range` with a range of at most 7 days,
  a step of at least 15 s and at most 1000 points, the datasource in `datasources` (an empty list allows no query);
- the token is a secret reference in `[secrets] allow`.

The address is resolved once and pinned (no second lookup), no proxy is used, redirects
are never followed (a 3xx is a failed job of class `status`), the answer is read up to
`max_bytes` and the job ends at its deadline (`[ceilings] max_job_ms`), and never after its envelope
expires. The token is
resolved here and sent only to that host, marked sensitive; it never reaches the platform.

### What leaves the machine

The result of an action carries an `output` the agent shapes in code, whatever the job
asks for, at most 48 KiB (so its result frame fits the platform's 64 KiB session frame;
a larger answer fails with class `answer`):

| Route | `output` |
|---|---|
| `/api/search` | dashboards: uid, title, folder, url, tags (at most 500) |
| `/api/dashboards/uid/<uid>` | uid, title, folder, url, and each panel's id, title, type, datasource uid and queries (ref id, expression, datasource uid); never panel data or snapshots (at most 200 panels) |
| `/api/datasources` | uid, name, type, whether it is the default (no URL, no credentials, no settings) |
| `query_range` | only `series`, `points` (counts) and the label names on the job's allowlist |

A query's series values leave only when the job names a template this policy made a
sensor (`[[actions.sensors]]` with the same template, base URL, token reference,
datasource and expression): then at most 50
series, 1000 points each, with only the labels on the job's allowlist.

A sensor runs here on its interval (kept across reconnects, and counted against
`[ceilings] max_jobs_per_minute`) and sends a `signal` frame (sensor, template, the worst
latest value, its level `ok`, `warn`, `crit` or `unknown`, the number of series, the time),
only when the platform's welcome says it accepts `signal`. Every result and signal is in
the [egress ledger](ledger.md), under the rule `actions.grafana-self-hosted` or
`actions.sensors`.
