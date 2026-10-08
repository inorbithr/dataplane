# The local agent page: threat model

The agent serves a page at `http://127.0.0.1:7790/` (`crates/iohr-agent/src/admin/`). It
is where the people who run the agent check what it is, what its policy allows, what it
did, and what left the machine, without trusting InOrbit. This file says what the page
defends against, how, and what it does not cover.

## What the page holds

| Section | Shows | JSON |
|---|---|---|
| Overview | connection, platform URL, agent id, name, environment, version, uptime, policy and checks hashes, ledger head, last heartbeat, jobs per minute against the ceilings, where each promise stands | `/api/v1/overview.json` |
| Checks | each declared check, its last runs (verdict, latency, status, certificate expiry), a 60-run history, refusals by policy or by platform, the local view of `fail_after` | `/api/v1/checks.json` |
| Policy | the effective policy, its hash, and what the agent can never do (fixed by this version or turned off by the policy) | `/api/v1/policy.json` |
| What left | the egress ledger ([docs/ledger.md](../ledger.md)) | `/api/v1/ledger.json`, `/ledger.jsonl` |
| Jobs | the last day's jobs and refusals, with reasons | `/api/v1/jobs.json` |
| Host | host observations and capture counts when the policy turns them on; "off by policy" otherwise | `/api/v1/host.json` |
| Logs | the agent's last 300 log lines, from memory, redacted | `/api/v1/logs.json` |

`/status.json` (what `iohr agent status` reads) and `/healthz` are unchanged.

What it never holds: the private key, the enrollment record or token, access tokens,
secret values, the secret references check headers are read from, check auth headers,
request or response bodies.

## Assets and adversaries

The asset is the page's content: it describes a company's network (targets, allowed
ranges) and its agent's behaviour. The page is not a control surface: nothing reached
through it changes the agent.

| Adversary | Can | Wants |
|---|---|---|
| A web page in the operator's browser | make the browser send requests to `127.0.0.1`, rebind its own DNS name to `127.0.0.1` | read the page (rebinding), make the agent do something (CSRF) |
| Another host on the network | connect to the port if the page listens beyond loopback | read the page |
| Another user on the same machine | connect to `127.0.0.1` | read the page |
| A compromised or careless platform | put strings into jobs (targets, ids, kinds) | script injection into the page, smuggle a secret onto it |
| A secret in the agent's memory | appear in a log line or an error | be shown |

## Controls

| Threat | Control | Test (`crates/iohr-agent/src/admin/tests.rs` unless named) |
|---|---|---|
| Reached from the network | Loopback only by default. Beyond loopback only with `admin.allow_non_loopback = true`, and then the agent refuses to start without `admin.tls_cert` and `admin.tls_key`, always asks for the token (`require_token = false` is refused), and prints a warning at startup | `config::tests::a_non_loopback_page_without_tls_and_token_is_refused_at_startup` |
| DNS rebinding | The `Host` header must be exactly `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` (plus `admin.hosts`); anything else gets 421; a missing or repeated `Host`, or an absolute-form target, gets 400 | `host_header_rebinding_attempts_are_refused` |
| CSRF, cross-site reads | Read-only: GET and HEAD only (405 otherwise), no request bodies (413). An `Origin` that is not this page gets 403. `Sec-Fetch-Site` other than `same-origin`/`none` gets 403, except a top-level navigation to an HTML page (a link followed from another site), which cannot read what it opens. No CORS header is ever sent, so a preflight never succeeds | `a_cross_origin_post_is_refused_and_nothing_writes` |
| Framing, script injection, leaks through referrers or caches | `Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; img-src 'self'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`; the page has no script at all; `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, COOP and CORP `same-origin`. Every value is HTML-escaped | `every_answer_carries_the_security_headers_and_no_cors` |
| Another local user | `admin.require_token = true` makes the page ask for its token on loopback too. The token (32 random bytes, new each start) is written to `<state_dir>/admin.token`, mode 0600; `iohr agent page --open` opens the browser with it; the page turns it into a session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over TLS, 12 h) and redirects so it leaves the address bar. Compared in constant time. `iohr agent status` sends it as a bearer header, which a browser cannot send cross-site without a preflight | `the_token_opens_the_page_once_required`, `constant_time_comparison` |
| Secrets on the page | Values are redacted when recorded (log lines, errors, job fields) and every response body is redacted again on its way out ([`redact.rs`](../../crates/iohr-agent/src/redact.rs)): PEM private keys, values after secret-looking keys, bearer tokens, JWTs, enrollment tokens, cloud and Git tokens, long high-entropy words, and the page's own token. Check auth is shown as "a header from a secret", never the reference | `no_secret_in_any_page_or_api_answer` (a property test planting secrets in logs, errors, job fields and the ledger), `redact::tests` |
| Path traversal | No file is served by path: the routes are a fixed list and the assets are compiled in | `every_answer_carries_the_security_headers_and_no_cors` |
| Resource exhaustion | 8 KiB of request head, 64 header lines, 5 s to send it, 10 s per write, 64 connections at once, a token bucket per client address (40 burst, 10 per second, 1024 addresses tracked), 16 sessions; history, logs and the in-memory ledger are capped (60 runs per check, 300 log lines kept of 500, 1000 ledger entries in memory, the ledger on disk by `[ledger] retain_days` and `max_mb`) | `bounded_requests_and_rate`, `a_slow_client_is_cut_off`, `ledger::tests::bounded_in_memory`, `logbuf::tests::bounded_and_redacted` |

## Not covered

- **Root, or the agent's own user.** Either can read the state directory, the token and
  the ledger, and rewrite the ledger's files. The page is for honest operators checking
  an agent, not a defence against the machine's administrator.
- **A browser extension or malware in the browser** sees whatever the operator sees.
- **Beyond loopback**, the page is as safe as its TLS certificate and the network policy
  in front of it. Prefer loopback and an SSH tunnel.
- **Redaction is pattern-based.** A secret with no recognisable shape and no
  secret-looking key next to it (a short password in prose) can get through. The agent
  never puts secret values into its state on purpose; redaction is the second line.
- **Plain HTTP on loopback.** Traffic on `127.0.0.1` does not leave the machine; a local
  user able to sniff loopback is root.

## Changing the page

Any new endpoint must be GET, read-only, listed in `page::route`, covered by
`render_all` (so the planted-secret property test reaches it) and by the headers test.
An endpoint that changes anything needs the token whatever `require_token` says, a
same-origin check, and its own entry in this file.
