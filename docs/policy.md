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

[ceilings]
max_concurrent_jobs = 4
max_job_ms = 30000
max_jobs_per_minute = 120

[secrets]
allow = ["vault:kv/staging/*", "k8s:checks/*"]
```

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
| `surfaces` | all | Which check surfaces are accepted: `http`, `tcp`, `tls`, `grpc_health`. |

The agent announces what it accepts (`check:http`, …) in its `hello`, so the console only
offers what this policy allows.

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
