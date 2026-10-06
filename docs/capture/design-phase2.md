# Capture phase 2: packets and pcap on request, request timing, lookup v2

A short design note, written before the code, like [design-phase1.md](design-phase1.md).
Phase 2 adds layer 3 (full packets, kept in memory, a pcap file on request) and layer 7
(request timing per route template), and version 2 of the aggregates socket with a keyed
lookup for RFC 0070's join. Why the companion exists: [ADR 0002](../adr/0002-capture-companion.md).
Operating it: [install.md](install.md).

What does not change: nothing from capture leaves the host. The agent learns counts only,
the platform learns capability strings only (now also `capture:packets` and
`capture:timing`), and the privacy test (`crates/iohr-agent/tests/capture_privacy.rs`,
control DAT-10) covers the new answers.

## Layer 3: full packets, in memory, pcap on request

### Switch and bounds

Off unless the companion is started with `--packets` (`IOHR_CAPTURE_PACKETS=true` in
`/etc/iohr-capture/capture.env`). This is the companion's own switch, separate from the
agent's policy: an agent can never turn it on.

| Setting | Default | Range | What |
|---|---|---|---|
| `IOHR_CAPTURE_SNAPLEN` | 65535 | 64-65535 | bytes copied per packet, from the link-layer header |
| `IOHR_CAPTURE_PACKETS_PER_SEC` | 1000 | 0-1000000 (0 = no limit) | packet copies per second per CPU (kernel token bucket) |
| `IOHR_CAPTURE_PACKETS_BURST` | 200 | 1- | burst of that bucket |
| `IOHR_CAPTURE_PACKETS_RING_KIB` | 8192 | 256-32768 | the second ring buffer |
| `IOHR_CAPTURE_PACKETS_BUFFER_MIB` | 32 | 1-128 | packets kept in the parser's memory (oldest out first; nothing older than 300 s) |

The buffer is bounded by bytes first. With GRO and TSO one copy is up to 64 KiB, so on a
busy interface 32 MiB holds seconds of traffic, not 300; the copy rate cap
(`IOHR_CAPTURE_PACKETS_PER_SEC`) and `buffer_evicted` say how much was kept.

In the kernel a second ring buffer (`IOHR_PACKETS`) gets a copy of every packet on the
interface, ingress and egress, up to the snap length, after its own per-CPU token bucket.
A ring-buffer reservation has to be a constant size, so a packet goes into the smallest
of four record sizes that holds it (256, 1536, 9216 or 65536 bytes). A copy over the rate
or without room in the ring is counted (`packets.rate_limited`, `packets.ring_buffer_full`),
never queued. The privileged process relays the records to the parser over the same pipe
(a third frame kind) without looking inside them. The parser keeps them in a ring in
memory bounded by bytes and by age.

### The control socket (protocol version 1)

`/run/iohr-capture/control.sock`, mode 0600, and the parser accepts a peer only when
`SO_PEERCRED` says uid 0. The companion's own user is refused too. The agent never runs as
root, and has no code that speaks to this socket. **No platform job can ever start a
pcap**: only root on the host can. One JSON line in, one JSON answer out, as on the
aggregates socket.

```json
{"version": 1, "request": "pcap", "seconds": 30, "filter": "tcp and port 443", "max_bytes": 10485760, "mode": "last"}
```

- `seconds`: 1 to 300.
  - In mode `last` (the default) the file holds the packets of the last `seconds` from
    memory. The answer comes when the file is written.
  - In mode `next` the file collects the packets of the next `seconds`. The answer comes at
    once, with `until_unix_ms`, and the file grows until then. At most one `next` capture
    runs at a time; another is answered `busy`.
- `filter`: optional, a small subset of the tcpdump syntax, joined by `and`, each term
  optionally negated by `not`, at most 8 terms. The terms are:
  - `tcp`, `udp`, `icmp`, `ip`, `ip6`;
  - `[src|dst] port N`;
  - `[src|dst] host ADDR` (an IPv4 or IPv6 address, never a name).

  `or`, ranges, port names and byte offsets are refused (`bad_request`).
- `max_bytes`: optional, at most the configured cap (`IOHR_CAPTURE_PCAP_MAX_BYTES`, default
  64 MiB, at most 1 GiB). The file stops growing there and the answer says
  `truncated: true`.
- Answer: `path`, `packets`, `bytes`, `truncated`, `from_unix_ms`, `to_unix_ms` (or
  `until_unix_ms`), `expires_unix_ms`.
- `status` answers the packet buffer's numbers and the pcap directory's use (files, bytes).
- Error codes: `forbidden` (not root), `not_available` (packets are off), `bad_request`,
  `unknown_request`, `unsupported_version`, `busy`, `no_space` (the directory's cap,
  `IOHR_CAPTURE_PCAP_DIR_MAX_BYTES`, default 512 MiB), `io`.

### The files

- Directory: `IOHR_CAPTURE_PCAP_DIR`, default `/var/lib/iohr-capture/pcap`. The unit makes
  it with `StateDirectory=iohr-capture iohr-capture/pcap` and `StateDirectoryMode=0700`:
  it is on disk (not in `/run`, whose tmpfs pages would count against `MemoryMax=`) and
  belongs to the companion's user. Run by hand as root, the privileged process creates it
  0700 and gives it to the parser's user, as it does with the sockets' directory.
- Files: `iohr-<UTC time>-<n>.pcapng`, created with `O_EXCL`, mode 0600. They are pcapng
  with one section and one interface: Ethernet (or raw IP on L3 devices),
  nanosecond timestamps, and the direction of each packet in `epb_flags`.
- Retention: a file is deleted `IOHR_CAPTURE_PCAP_RETENTION_SECS` after it was written
  (default 3600, range 1-86400). The parser sweeps the directory at start and every poll,
  and deletes only files named like its own. When the companion stops, nothing would
  expire them, so `iohr-capture cleanup` (the unit's `ExecStopPost`) deletes them all;
  `/usr/lib/tmpfiles.d/iohr-capture.conf` (`e … 1h`) is the net for a host that went down
  hard.
- Room: a request gets at most what is left under `IOHR_CAPTURE_PCAP_DIR_MAX_BYTES`
  (clamped to one largest file and 64 GiB) after the files there and what a running
  `next` file may still grow to, and never more than the file system's free space less
  64 MiB (`statvfs`).
- The directories: an existing sockets or pcap directory is used only if it belongs to
  root or the parser's user and its parent is not writable by others (unless sticky).
- Writing: a `last` file is written off the lock and off the parser's event loop. A
  `next` file is appended in the loop that reads the pipe (buffered, to the page cache);
  moving it to its own writer thread is a follow-up.
- The pcap file is never sent anywhere: no socket of the companion can carry it, and the
  unit allows no IP traffic (`IPAddressDeny=any`).

### `iohr-capture pcap` and `iohr-capture dissect`

- `sudo iohr-capture pcap --seconds 30 --filter 'tcp and port 443' [--next] [--max-bytes N] [--out FILE]`
  talks to the control socket. With `--out`, root copies the file for the person who ran
  `sudo`, who can then dissect it without root. The copy is theirs to delete; the
  companion's own copy expires. The parser that names the file is the least trusted part
  of the companion, so the command trusts nothing in its answer:
  - the path must be `<pcap dir>/<name>`, for the directory the command resolves itself
    (`--pcap-dir`, `IOHR_CAPTURE_PCAP_DIR`), with a name of the companion's own form;
  - the directory is opened `O_DIRECTORY|O_NOFOLLOW` and the file with `openat`,
    `O_NOFOLLOW|O_NONBLOCK`, so a symbolic link fails and a FIFO cannot block;
  - `fstat` of the open file: a regular file, one link, owned by the directory's owner
    (never root), within the size cap;
  - only then root becomes the person (`setgroups`, `setresgid`, `setresuid` to
    `SUDO_UID`/`SUDO_GID`) and creates `FILE` as them, 0600, never over an existing file,
    so the copy can only land where that person could write; a partial copy is removed.
- `iohr-capture dissect FILE [-- tshark options]` runs the host's own `tshark -n -r -`
  as the invoking user, with the file it opened as tshark's standard input, and prints
  tshark's output. Only absolute `PATH` entries are searched. With `--as-root` the
  environment is cleared but for `PATH` and `LANG` (`HOME=/root`). It refuses
  to run as root unless `--as-root` is given (dissectors parse untrusted bytes; Wireshark's
  own advice is to never run them as root). With no `tshark` on `PATH` it says how to
  install it (`apt install tshark`, `dnf install wireshark-cli`). `tshark` is GPL. It is
  a separate program that iohr-capture never bundles, links or starts from the
  companion. The deb `Suggests:` it; the rpm only mentions it.
- **There is no `iohr agent capture pcap` or `dissect`.** The agent is the process that
  talks to the platform. If it could reach packets, one bug in the session code would be
  one step from payloads, and a job could ask for them. The agent cannot reach the
  control socket (root only), never asks for packets, and its policy has no key for them.
  A person on the host uses `iohr-capture` directly.

## Layer 7: request timing

On by default with layer 2 (`timing` in `IOHR_CAPTURE_LAYERS`, which needs `protocols`).

### What the kernel copies

With timing on, the kernel copies the first 512 payload bytes of **every** TCP packet
that carries payload, not only a flow's first 8 (phase 1). The same token bucket and
counters apply (`drops.rate_limited`), so a busy host loses timing samples, never more
memory. The parser tracks each direction's TCP sequence number. A gap (a copy that was
dropped or reordered) makes that flow stop timing (`timing.unsynced`). Requests still
waiting at that point are not paired, so a lost copy can never pair a request with the
wrong response.

### Pairing

- **HTTP/1.** A request starts with a segment from the client that begins with a method,
  and a response with a segment from the server that begins with `HTTP/1.x NNN`.
  Responses pair with the oldest waiting request (pipelining keeps order). At most 16
  requests wait per flow. Pipelined requests that share one TCP segment count as one (only a
  segment's start is read), so a pipelining client is under-counted; responses that share
  a segment the same way. A `1xx` response is not the answer: `100 Continue` is skipped,
  and `101` ends timing for the flow.
- **HTTP/2 (h2c, gRPC).** Frames are followed across segments using the frame lengths and
  the sequence numbers, from the client preface and the server's first SETTINGS. A
  HEADERS frame from the client on stream N is the request, and the first HEADERS frame
  from the server on stream N is the response (`:status`). Frames past the copied 512
  bytes of a segment are skipped by length. If a frame header itself falls there, the
  flow stops timing. At most 64 streams wait per flow.
- **The path rule from phase 1 stays.** The decoder keeps no HPACK dynamic table across
  header blocks, so a path is never guessed:
  - the connection's first request has its path;
  - a later request has its path only when its header block decodes on its own (static
    table and literals);
  - otherwise its route is `unknown`.
- **gRPC** status comes from the trailers (`grpc-status` in the HEADERS frame that ends the
  stream, or in a trailers-only response) when that block decodes on its own and falls
  within the copied bytes. Otherwise the call counts with its HTTP status only.
- **Latency** is the time from the first copied byte of the request to the first copied
  byte of the response, both taken by the kernel (`bpf_ktime_get_ns`) as the packets pass
  TC on this host. For a server that is its time to first byte plus the request's own
  upload time. On `lo` both ends are on this host, so every request is timed twice: once
  for the client's flow, once for the server's.

### Aggregates

Keyed by (method, route template, owner):

- requests, responses, unanswered;
- status classes `1xx` to `5xx`, and gRPC status codes 0 to 16;
- a latency histogram, cumulative like Prometheus, with upper bounds in milliseconds:
  0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf;
- the latency sum.

The owner is layer 4's owner key (`cgroup:/…`, `systemd:….service`, `container:…`,
`kubernetes:pod …`), or `unowned`. At most 2048 keys. A new key beyond that is counted
in `timing.keys_dropped`, and its requests in `timing.untracked`.

**Memory.** Every tracker together may hold at most 32768 waiting requests (HTTP/1
queues and HTTP/2 streams) and 8 MiB of header block bytes, charged after each segment;
header bytes are kept only as they arrive. With the budget spent, a new request is dropped
and counted (`timing.budget.refused`) and no header block is kept, so spoofed traffic on
many flows fills the budget, never the parser's memory. Per flow the bounds stay 16
waiting HTTP/1 requests, 64 HTTP/2 streams and 4 KiB per header block.

`counts` carries totals only (requests, responses, unanswered, unsynced, keys, the
histogram summed over keys). `tables` carries the 50 busiest keys, with their names, for
a person on the host.

### Route templates

One module, `crates/iohr-capture/src/route.rs`, implements the rules RFC 0070 sets for the
SDKs, the companion and the browser recorder. Test vectors live in
`crates/iohr-capture/tests/route_vectors.json`, with a SHA-256 in
`route_vectors.json.sha256` that a unit test checks. Today the companion owns the file.
When the SDK repository publishes its conformance vectors (RFC 0070's source), that file
replaces ours byte for byte, the checksum file follows it, and the same test keeps the
copy honest. The rules are also listed in a comment at the top of that module. In
order:

1. **Request target forms.**
   - `*` stays `*`.
   - An absolute form (`http://host/a`, `https://…`, scheme case-insensitive) keeps only
     its path, and `/` when it has none.
   - Any other target that does not start with `/` becomes `{other}`.
2. **Query and fragment.** Everything from the first `?` or `#` is dropped, before any
   decoding.
3. **Segments.** The path after its leading `/` is split on `/`. Empty segments (from `//`
   or a trailing slash) are kept as written: a trailing slash stays.
4. **Percent-decoding.** Each segment is percent-decoded once. `%HH` with two hex digits
   becomes that byte, and anything else stays as written. A segment whose decoded bytes
   are not valid UTF-8 becomes `{id}`. Comparison is case-sensitive.
5. **Identifiers.** A decoded segment becomes `{id}` when it is:
   - all ASCII digits (any length; RFC 0070's rule. A brief that said "two digits or more"
     was overruled so that `/page/1` and `/page/10` land on one route);
   - a UUID (8-4-4-4-12 hex digits, either case);
   - 16 or more hex digits;
   - a date `YYYY-MM-DD` (digits only, no range check);
   - 20 or more characters from the base64url alphabet `[A-Za-z0-9_-]` with at least one
     digit;
   - anything containing `@` (an e-mail address or `user@host`). This one is our addition,
     proposed to RFC 0070: an address in a path is personal data.
6. **Segment count.** After 8 segments the rest becomes one `{rest}` segment.
7. **Length.** The template is at most 256 bytes. If longer, segments are dropped from the
   end until `…/{rest}` fits.

The method stays as sent (HTTP/1: one of the nine standard methods; HTTP/2: `:method`, if
upper-case ASCII of at most 16 bytes, else `?`). A route key is `METHOD template`, for
example `GET /orders/{id}`.

## The aggregates socket, protocol version 2

- **Version 1 stays as it was.** `counts` and `tables` with `"version": 1` get the same
  answers, with the new fields `timing` and `packets` added (which version 1 allows).
  Phase 1 agents keep working without change.
- **Version 2** adds one request, and `counts` and `tables` answer it as well:

  ```json
  {"version": 2, "request": "lookup", "owner": "cgroup:/shop.slice/api.service", "route": "GET /orders/{id}"}
  ```

  - `owner` is at most 256 bytes and `route` at most 300.
  - The answer holds numbers for that one key and nothing else: `found`; `requests`,
    `responses`, `unanswered`; `status_classes`; `grpc_status`; `latency_ms` (the
    buckets and sum); and `owner_tcp` with that owner's `retransmits`, `resets` and an
    `rtt_ms` histogram. The owner and the route are not echoed back.
  - A key never seen answers `found: false` and zeros.
  - The agent's user may ask (counts only). It never gets a list: no request of either
    version returns keys to it.
  - A peer may make at most 50 lookups a second (beyond that, `rate_limited`). Guessing
    route names one by one stays slow, and RFC 0070's join needs a lookup per span batch,
    not per request.
  - **No allowlist of owners and routes for the agent (decided).** A lookup is an oracle:
    asked for a key, it says whether that key saw traffic. We considered answering the
    agent's user only for owners and routes its local policy lists, and chose not to:
    - the keys the agent asks for come from spans of the company's own programs on this
      host (RFC 0070), which already carry those routes, so the oracle tells the agent
      little it does not hold;
    - the answers are numbers and stay on the host: RFC 0070 keeps capture-joined
      attributes host-only, and the agent forwards none of them;
    - an allowlist would be a second, company-maintained list of routes in the companion's
      configuration that must track every deploy, and a stale list silently breaks the
      join;
    - guessing is bounded: 50 lookups a second, templates only (ids already replaced),
      never a list.

    Revisit if the agent ever forwards lookup results off the host, or if a deployment
    must keep route names from the agent's user: then the allowlist goes into the
    companion's own configuration, not the agent's policy.
- **Negotiation.**
  - A client sends the highest version it speaks.
  - The companion answers in the version it was asked, if it speaks it. Otherwise it
    answers `{"version": 2, "error": "unsupported_version", "supported": [1, 2]}`, and the
    client retries with the highest version both speak.
  - A phase 1 companion answers a version 2 request with
    `{"version": 1, "error": "unsupported_version"}`. A client then knows lookups are not
    there.
  - The agent asks `counts` in version 1, which every companion speaks, and `lookup` in
    version 2.
  - Removing or renaming a field remains a version change.
- New error codes: `rate_limited`, `busy`, `no_space`, `io`. As before, the agent repeats
  only the codes it knows and turns anything else into `other`.

## The agent

- `capture:timing` when `timing` is in the companion's layers and in the policy's
  `[capture] layers`.
- `capture:packets` when the companion reports `packets` in its layers (that is,
  `--packets` is on and its control socket is bound), the control socket exists next to
  the aggregates socket (`control.sock` in the same directory), and the policy lists the
  layer.
- `CaptureLayer` gains `packets` and `timing`; the default `layers` is now all six.
  - An agent older than this version refuses a policy that names them.
  - A policy with a `[capture]` section but no `layers` key gets a new hash, because the
    default list grew.
- `iohr agent capture status` shows the timing totals and the packet copy numbers. With
  `--tables` it also shows the timing rows with route names, for a person on the host
  (the companion refuses `tables` to the agent's user, as before).
- `iohr agent capture lookup --owner … --route …` asks the version 2 lookup and prints the
  numbers. The library function behind it (`capture::lookup`) parses the answer into a
  numbers-only type, so RFC 0070's receiver can join on it later without ever holding a
  name the companion might send.
