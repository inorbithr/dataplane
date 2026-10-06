# Capture phase 1: the aggregates socket, the policy and the hello

A short design note, written before the code (the agent's rule: the session protocol and
the policy format are shared contracts). It covers what changes between `iohr-capture`
and `iohr-agent` in phase 1 (layers 1 headers, 2 protocols, 4 owners, 5 TCP health).
Why the companion exists at all: [ADR 0002](../adr/0002-capture-companion.md). Operating
it: [install.md](install.md).

## What leaves the machine

Only four capability strings in the session `hello`: `capture:headers`,
`capture:protocols`, `capture:owners`, `capture:tcp`. They say what this host *can* show,
never what it saw. No result frame, heartbeat, admin page value other than a count, OTLP
metric, label, span or log carries anything from capture. A test enforces it
(`crates/iohr-agent/tests/capture_privacy.rs`).

## The two sockets

| Socket | Path (fixed) | Mode | Who may connect | Answers |
|---|---|---|---|---|
| aggregates | `/run/iohr-capture/aggregates.sock` (directory 2750, set-group-id) | 0660, group `iohr-capture-read` | checked with `SO_PEERCRED`: root, the companion's own user, the `iohr-agent` user, members of `iohr-capture-read` | counts; the bounded top-K tables too, but never to the agent's user |
| control | `/run/iohr-capture/control.sock` | 0600 | root only (`SO_PEERCRED` uid 0) | phase 1: `not_available` for everything; phase 2: pcap on request |

Both are Unix sockets, not network listeners (ADR 0001's "no new listener" holds). The
parser process (`iohr-capture worker`, started by `run`, with no capability at all)
creates and serves them; the privileged process only prepares the directory. The sockets
get their group from the directory (set-group-id) or the unit's `Group=`, never by
`chown`. At most 16 connections are served at once; a client has 2 s to send its request
and 5 s to read the answer.

The companion enforces DAT-10 itself: a peer whose uid is the agent's user gets
`forbidden` for `tables`, whatever it asks.

### Protocol (version 1)

One request per connection, one answer, then the companion closes it.

- Request: one line of JSON, at most 1 KiB, within 2 s:
  `{"version": 1, "request": "counts"}` or `{"version": 1, "request": "tables"}`.
- Answer: one JSON document, at most 1 MiB (the top-K bounds keep it far below), then EOF.
  Every answer has `version` (1) and either the data or `error` (a code) and `message`.
- `counts`: numbers only, by construction. No name, path, address, SNI, DNS name, host,
  port number tied to a name, pod or container identifier. This is all the agent ever
  asks for.
- `tables`: `counts` plus the top-K tables (HTTP hosts and path templates, TLS SNI and
  ALPN, DNS names, gRPC methods, remote addresses, owners, per-port TCP health). Only
  `iohr agent capture status --tables` and `iohr-capture stats --tables` ask for it, for a
  person on the host.
- Error codes: `forbidden`, `unsupported_version`, `bad_request`, `unknown_request`,
  `too_large`, `not_available` (control socket). The agent repeats only these; any other
  code becomes `other` on its side.
- A request with another `version` gets `{"version": 1, "error": "unsupported_version"}`;
  the client decides. New fields may be added within version 1; clients ignore unknown
  fields. Removing or renaming a field is version 2.

The `counts` answer (abridged; the companion's `stats --json` prints the full form):

```json
{
  "version": 1,
  "companion_version": "0.1.0-alpha.5",
  "interface": "eth0",
  "started_unix_ms": 1759740000000,
  "updated_unix_ms": 1759740123000,
  "packet_unit": "skb",
  "layers": ["headers", "protocols", "owners", "tcp"],
  "headers": { "ingress": { "packets": 1, "bytes": 1 }, "egress": { "packets": 1, "bytes": 1 }, "...": "..." },
  "drops": { "rate_limited": 0, "ring_buffer_full": 0, "flows_evicted": 0 },
  "protocols": { "http1_requests": 0, "tls_client_hellos": 0, "dns_queries": 0, "http2_connections": 0, "grpc_calls": 0 },
  "owners": { "sockets": 0, "owners": 0, "flows_owned": 0, "flows_unowned": 0 },
  "tcp": { "established": 0, "listening": 0, "retransmits": 0, "resets": 0, "listen_overflows": 0 }
}
```

## The agent's policy

`[work] capture = false` by default, and a `[capture]` section:

```toml
[work]
capture = true

[capture]
socket = "/run/iohr-capture/aggregates.sock"   # the default
layers = ["headers", "protocols", "owners", "tcp"]   # the default: all of phase 1
max_snapshot_age_secs = 30   # 1-3600; an older answer counts as "not answering"
```

- Unknown keys stay errors. **An agent older than this version refuses a policy with
  `capture` in `[work]` or a `[capture]` section**: upgrade the agent first, then the
  policy. The policy docs say from which version the keys apply.
- The policy hash is unchanged for a policy that does not use capture: `work.capture` is
  left out of the hashed form while it is `false`, and `[capture]` while it is absent.
  Turning capture on changes the hash, as any policy change does.
- `[capture]` without `[work] capture = true` is accepted and does nothing.

## The hello

At the start of every session the agent, when `[work] capture = true`, asks the socket
for `counts` (1 s timeout). It adds `capture:<layer>` for every layer that is in
`[capture] layers` **and** in the companion's `layers` **and** only if the answer is
version 1 and no older than `max_snapshot_age_secs`. No answer: no `capture:*` strings,
and the admin page says why. Nothing else in the hello changes; the platform stores and
shows the strings (core's agents service learns them in the same change).

## The admin page and `iohr agent capture status`

- The admin page gets a **Traffic** section with counts only: packets and bytes per
  direction, drops, flows, requests per protocol, owners and TCP totals, the answer's age.
  The agent refreshes it every 15 s from `counts`.
- `iohr agent capture status` asks the socket and prints the counts; `--json` prints the
  answer; `--tables` asks for `tables` and prints them, for the person at the terminal.
