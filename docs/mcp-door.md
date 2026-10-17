# The MCP door

`iohr-agent mcp` is the one local endpoint a person's AI sessions use to reach InOrbit's
MCP, and the one holder of the OAuth sign-in behind it ([RFC 0129](https://inorbit.hr):
the agent is the access point). Sessions hold no platform credential. They send one local
secret to a loopback address; the agent holds the token chain and forwards the call.

Why one holder: the identity provider rotates refresh tokens with a 30 second reuse
window. Many sessions each refreshing their own copy of one credential looked like token
theft and the whole chain was revoked. One holder cannot race itself.

## Commands

| Command | |
|---|---|
| `iohr-agent mcp serve` | run the door (run it under launchd) |
| `iohr-agent mcp login` | open the sign-in in the browser once and wait for it |
| `iohr-agent mcp status` | signed in or not, token time left, upstream state |
| `iohr-agent mcp headers` | the JSON header sessions send (for Claude Code's `headersHelper`) |
| `iohr-agent mcp register [--file F]` | point Claude Code's `inorbit` server at the door; a `.bak-mcp-door` backup is kept |
| `iohr-agent mcp launchd` | print the launchd job that runs `mcp serve` |

Every option is a flag with an environment variable (`IOHR_MCP_LISTEN`, `IOHR_MCP_UPSTREAM`,
`IOHR_MCP_ISSUER`, `IOHR_MCP_CLIENT_ID`, `IOHR_MCP_REDIRECT_PORT`, `IOHR_MCP_STATE_DIR`,
`IOHR_MCP_NOTIFY`, `IOHR_MCP_TOKEN_ITEM`, `IOHR_MCP_SECRET_ITEM`). The defaults are the
production platform and `127.0.0.1:47821`.

## The local door

- `POST /mcp` and `POST /login` only. A request is refused with 403 unless it has no
  `Origin` header (a browser always sends one), a `Host` that is the door's own address,
  and `X-Iohr-Bridge` equal to the local secret (compared in constant time).
- `GET /status` needs no secret and carries no token: `auth`, `auth_why`, `token_left_s`,
  `upstream`, `cached_tools`. Other methods get 405.
- The local secret and the token chain are two keychain items (`iohr-mcp-bridge-local`,
  `iohr-mcp-bridge`). The token item is written through `security -i` on stdin, never argv.

## Staying up

`initialize` and `tools/list` are answered from a cache when the platform is unreachable,
and an empty tool list beats a failed start. A call that is safe to repeat is retried with
backoff; a `tools/call` whose reply was lost is never sent twice (it returns an error
result). The names of the platform fall back to the last good addresses and then to
DNS-over-HTTPS addressed by IP, when the router's DNS fails.

## What is logged

Methods, tool names, status codes and timings, on stderr (launchd redirects it to a file).
Never prompts, tool arguments or results. There is no in-process log rotation yet; rotate
the launchd output file externally.

## Limits today

- The keychain is macOS only. Other systems get a clear error from `mcp serve`.
- It runs as its own process (`mcp serve`), not inside `iohr-agent run`: that needs an
  enrollment, and the door must work before one. Hosting it in the daemon, the RFC's
  grants and principals, and recording the door's egress in the ledger are follow-ups.
- Nothing here claims compliance with any framework; the controls it keeps are the edge as
  the only authenticator, secrets only in the keychain, default deny locally, and no
  content in logs.

## Limits worth knowing

- The keychain items are written through `/usr/bin/security`; another process of the same
  user can read them the same way. The door does not isolate the sign-in from the user's own
  processes, it keeps it out of files, argv and logs.
- The local secret, Host and Origin checks run before a request body is read; bodies are
  capped at 2 MiB.
- A `tools/call` is never resent; when its reply is lost the door says the call may have run.
