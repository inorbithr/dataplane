# The egress ledger

Before the agent sends the platform anything, it appends one line to a file on this
machine: when, what kind of message, how many bytes, the SHA-256 of the exact bytes, the
policy and the rule that allowed it, and where it went. Each line carries the hash of the
line before it, so a removed, inserted or edited line breaks the chain. This is phase 1
of ADR 0049 (inorbithr/core, "a customer-visible egress ledger"): metadata only, never
the payload.

## What is recorded

| Kind | When | Rule |
|---|---|---|
| `token_request` | each access-token request to the identity provider (the form body: a signed client assertion) | `contract.token` |
| `session_open` | each WebSocket upgrade (no body; its headers are the access token and the user agent) | `contract.session` |
| `hello` | the first frame of every session | `contract.hello` |
| `heartbeat` | every heartbeat | `contract.heartbeat` |
| `result` | a job that ran, under the surface the policy turned on | `work.surfaces.<surface>` |
| `result` | a refusal (the contract answers every job) | `contract.refusal` |
| `share_set` | the agent starts with a `[share]` it did not run with before (set on the page, with `iohr agent share` or by hand); local, nothing is sent, the destination says so | `operator.policy.share` |

WebSocket pings and the closing frame carry no payload and are counted on the page, not
recorded. Enrollment happens once, before the agent has a ledger, and is not recorded.
Checks go to your own targets, not the platform; they are on the Jobs section.

## An entry

```json
{"seq":42,"at":"2026-10-08T17:07:26.512Z","kind":"heartbeat","bytes":30,
 "sha256":"sha256:…","policy":"sha256:…","rule":"contract.heartbeat",
 "destination":"wss://api.inorbit.hr/v1/agents/session","prev":"sha256:…","hash":"sha256:…"}
```

`hash` is the SHA-256 of the entry serialised with `hash` empty; `prev` is the previous
entry's `hash` (all zeros for the first). `job_id` is added for results.

## Where and how long

`<state_dir>/ledger/ledger-YYYY-MM-DD.jsonl`, one file per UTC day, mode 0600 in a 0700
directory.

```toml
[ledger]
enabled = true      # default; off is shown on the page
retain_days = 30    # 1 to 3650
max_mb = 256        # 1 to 10240; the oldest days go first
```

When a day is removed for retention, its last entry is kept in `anchor.json`, so the
chain that remains still verifies from where it starts. If an entry cannot be written
(disk full, permissions), the message is not sent: the ledger fails closed, the session
drops and reconnects, and the page shows the error.

## Checking it

```sh
iohr agent ledger verify            # exit 1 on any problem
iohr agent ledger export > out.jsonl   # every entry, oldest first, for your SIEM
```

The page shows the latest entries and serves the same export at `/ledger.jsonl`.

## What phase 1 does not do

- **Payloads.** `keep_payload_days` (keeping what left, for a few days) is not built.
- **Receipts.** The platform does not yet record its own receipt with the same hash, so
  nothing outside this machine confirms the chain; someone who can rewrite these files
  can rewrite the whole chain. Receipts, the chain head in the heartbeat and the daily
  reconciliation come with the core side of ADR 0049 (a contract change).
