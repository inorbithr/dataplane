# ADR 0001: Dial out, an identity of its own, a local policy that wins

- Status: accepted
- Date: 2026-10-03
- Context: RFC 0029 (the agent), RFC 0028 (iohr extensions), RFC 0018 (connections)

## Context

The agent runs inside a company's network on the platform's behalf. A security team asks
what it is, what it can do, who decides, where secrets go and what leaves the network.
The design answers each with a mechanism, not a promise.

## Decision

### It dials out

One WebSocket to `wss://<api>/v1/agents/session`, opened by the agent with a bearer
token. JSON text frames: `hello`, `heartbeat`, `result` up; `welcome`, `job`, `cancel`,
`revoked` down. A WebSocket ping goes with each heartbeat so a half-open connection is
noticed within three heartbeats. Reconnects back off exponentially with full jitter
(1 s to 60 s). When the session ends, every running job is aborted; work exists only
inside a session. The only listener is the read-only admin page on loopback.

### An identity of its own

- Enrollment presents a one-time token (`ioe_…`, one hour) once. The agent makes its key
  pair locally (EC P-256 by default, Ed25519 optional), writes the private key 0600 before
  the platform sees the public half, and receives an OAuth2 client id.
- Access tokens come from `client_credentials` with a `private_key_jwt` client assertion
  (RFC 7523: `iss`=`sub`=client id, `aud`=token endpoint, two minutes, random `jti`).
  They last 15 minutes and live only in memory. No long-lived bearer secret sits on disk.
- ES256 is the default because Ory Hydra (the platform's identity provider) accepts RS*,
  PS* and ES* assertions only (fosite `client_authentication.go`).
- Revocation deletes the OAuth2 client: the next token request fails, and the platform's
  `revoked` frame stops the agent at once (exit code 3; systemd does not restart it).

### The local policy wins

`policy.toml` is owned by whoever runs the agent. Every job passes, in order:

1. kind of work enabled (`[work]`; load and faults refused in this version);
2. spec understood, surface enabled, secret reference allowed (`[secrets] allow`);
3. ceilings: jobs per rolling minute, concurrent jobs, deadline cut to `max_job_ms`;
4. target: an IP must be in `networks.allow` and outside `networks.deny`; a name must be
   named in `networks.allow` or lie inside a bound domain, checked before any DNS query;
   it is resolved once, every address checked, and the connection pinned to the checked
   address (no second lookup, so no DNS rebinding); HTTP redirects are not followed.

A refusal is sent as a `refused` result with its reason, so the console shows why.
Configuration and policy disagreeing on the environment stops the agent at start.

### Secrets stay where they are

A job names a reference (`vault:`, `k8s:`, `env:`, `file:`); the agent reads the value at
the call, holds it in zeroized memory, puts it in one sensitive header, and drops it.
Errors name the reference, never the value. Kubernetes access is a Role with `get` on
named Secrets only.

### What leaves the machine

Results carry latency, HTTP status, an error class, certificate expiry and refusal
reasons. Bodies are never read beyond the status line and headers (gRPC: the one health
message); URLs, header values and secrets are never reported. Telemetry goes only to the
company's own OpenTelemetry collector, off by default.

### Small and verifiable

tokio and rustls (ring), reqwest without default features, tokio-tungstenite, h2 for gRPC
health, RustCrypto for keys, OpenTelemetry. The admin page and the gRPC health codec are
hand-written to keep a server framework and a protobuf stack out. Releases are signed
keylessly by the release workflow at a tag with SLSA provenance and SBOMs
([verifying releases](../security/verifying-releases.md)).

## Consequences

- A company can audit everything the agent may do by reading one file.
- Load, faults and Kubernetes actions each arrive behind a `[work]` switch that defaults
  to off, through this ADR's admission path.
- No HTTP proxy support for the platform connection yet; a company with a mandatory
  egress proxy needs it (tracked for a later release).
