@AGENTS.md

## Claude Code

- Plan mode first for anything that changes the session protocol, enrollment or the
  policy format: those are shared with inorbithr/core and with deployed agents.
- Verify with the narrowest command first (`cargo nextest run -E 'test(name)'`), then
  `mise run ci`, and show the output.
- Releases are never run from a session. `mise run release:local` feeds the internal
  dogfood channel only, with a key that lives outside the repository.
