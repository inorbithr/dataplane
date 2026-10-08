# Documentation connectors (`atlas docs sync`)

Atlas (RFC 0086 in inorbithr/core) reads a company's internal documentation as evidence.
The company's own agent does the reading, from inside the company's network. InOrbit never
crawls a customer's docs from its cloud and never holds the credential (PRD 0001, Q1).

```sh
iohr-agent atlas docs sync --out docs.jsonl          # what changed since the last run
iohr-agent atlas docs sync --full --out docs.jsonl   # everything; drops what is gone
iohr-agent atlas docs sources                        # what is configured and held
```

Nothing is sent anywhere. The documents go into a local content store. The evidence goes
to a local file (or standard output), and a summary of counts goes to standard error.

## Status

| Provider | State | Reads |
|---|---|---|
| Notion | in development (merged, in no release yet) | pages, database rows (properties as fields), data source schemas, page comments; attachments by reference |

Other providers (Confluence, Google Docs, GitBook, static docs sites, SharePoint, Slab,
Coda) use the same framework. Each one is added in its own pull request and listed here
once it is merged.

## What a run produces

Every item becomes an artefact observation. The artefact's bytes are its normalized
markdown, and its digest is computed from those bytes. The item's facts are observations
that cite that artefact.

| Record | Example |
|---|---|
| observer | `notion-reader`, class deterministic extractor, principal `notion-integration:<bot id>`, authority marked insufficient (it sees only what it was shared) |
| method | `notion.page.read`, `notion.row.read`, `notion.database.read`, `notion.comment.read`, `notion.space.read`: category `documentation`, coverage best effort, trust mutable, data class confidential |
| artefact | location `notion:<source>/page/<id>@<last edited>`, digest of the markdown |
| observations | `doc.title`, `doc.kind`, `doc.url`, `doc.created_at`, `doc.updated_at`, `doc.author` (a `person/<source>/<user id>` entity, never a name or mail), `doc.parent`, `doc.in_database`, `doc.in_space`, `doc.links_to`, `doc.mentions`, `doc.field.<name>` (a row's properties), `doc.has_attachment` with `attachment.name`/`media_type`/`size_bytes`/`url`, `doc.comment_count` |

Documentation never proves a claim (ADR 0016). A page can support a claim or suggest where
to look, and Atlas wants deterministic evidence (a manifest, a trace, a runtime reading)
before it calls anything verified. A model reading the stored markdown makes an extraction
that cites the artefact (ADR 0006). The extraction can be wrong, but the artefact's digest
cannot be.

## Incremental sync

- Each source keeps `state.json` in its store: the time of the last complete run, and per
  item its change time and digest. It holds no content.
- A run lists items changed since the last complete run, minus a five-minute overlap
  (provider clocks and search indexes lag). It reads an item only when its change time
  moved. An item touched without a change reads to the same digest.
- The cursor moves only when a run is complete: the listing finished and every read
  succeeded. A rate limit that outlasts the retries, an outage, a failed read or the
  per-run cap (`max_items`, default 5000) leaves the cursor in place, so the next run
  picks up the rest.
- Incremental listings cannot see deletions. `--full` lists everything (and still reads
  only what changed), then deletes the local copies of items that are no longer visible.
  Run it daily.

## Rate limits and failures

One client serves every provider. It spaces requests to the provider's published limit
(`requests_per_minute` lowers it). It retries 429 and 5xx answers and network failures up
to five times, with jittered exponential backoff from 0.5 s to 60 s, and honours
`Retry-After` (a longer wait ends the run as incomplete). It does not follow redirects,
never leaves the source's origin, caps an answer at 16 MiB and times a request out after
30 s.

| Answer | What happens |
|---|---|
| 401 | The credential is refused. The source's whole local store is deleted, and the run reports `revoked`. |
| 403, 404, archived | The item is gone for this credential, and its local copy is deleted. |
| 429, 5xx | Retried, then the run is incomplete and the next run continues. |

## Privacy

Customer documents are customer data.

- **The store.** One directory per source under `[docs] content_dir` (default
  `<state_dir>/docs`): mode 0700, files mode 0600, written atomically.
- **What stays local.** Document bodies and comments never reach a record, a log line, a
  metric or an error message. The records carry ids, digests, titles, links, times and
  structured fields. `src/atlas/docs/sync.rs` (`content_never_reaches_the_records_or_the_logs`)
  and `tests/docs_notion.rs` fail if that regresses.
- **Personal data.** Authors are provider user ids only. Notion `email` and `phone_number`
  properties are not read. A Notion-hosted file comes with a signed link that expires
  within an hour. That link is a credential, so it is never stored or recorded; the file is
  recorded by name.
- **Deletion.** A revoked credential deletes the source's store. An unshared or deleted
  item loses its local copy at the next run that notices (always at `--full`).
- **Errors.** Errors name the method, path and status, never a header, a query, a body or
  the token.

## Configuration

```toml
[docs]
# content_dir = "/var/lib/iohr-agent/docs"   # default: <state_dir>/docs

[[docs.sources]]
id = "acme-notion"                       # names entities (doc/acme-notion/...) and the store
provider = "notion"
token = "vault:kv/iohr/notion#token"     # a reference, never the value
comments = true                          # needs the integration's "Read comments"
# requests_per_minute = 180              # Notion's average of 3 per second
# max_items = 5000
```

The policy must allow both the credential reference and the provider's host. Nothing is
read before it agrees:

```toml
[networks]
allow = ["api.notion.com"]

[secrets]
allow = ["vault:kv/iohr/notion#token"]
```

`packaging/examples/agent.docs.toml` is a complete example. `iohr-agent config validate`
refuses a source whose `token` is not a reference, so a token pasted into the file fails
validation.

## Notion

**Auth: an internal integration, not a public OAuth integration.** A workspace owner
creates an internal integration (Settings, Connections, Develop or manage integrations),
gives it **Read content** (and **Read comments** if wanted), **no** insert or update
capabilities, and **No user information**. They then share the pages and databases Atlas
may read with it (the page's `...` menu, Connections). The token goes into the company's
secret store.

A public OAuth integration would need InOrbit's client secret and a redirect through
InOrbit's servers to exchange the code. The token would then pass through, or be held by,
InOrbit's cloud, and that is the hosted path the agent-only rule excludes. An internal
integration's token is created in the customer's workspace and read only by the
customer's agent, and the customer revokes it in Notion without asking us.

Notion does not report an integration's capabilities through the API. The agent records
the ones it uses (`read_content`, and `read_comments` when comments are on), and it only
ever sends reads: `GET`, plus `POST /v1/search` and data-source queries, which Notion
defines as reads.

| Notion | Becomes |
|---|---|
| page | `page` (`doc.parent` is the page or block above it) |
| page in a data source (a database row) | `row`: properties as `doc.field.*` and a table in the markdown, `doc.in_database` |
| data source | `database`: description as the body, schema as fields (`status: Planned, Done`) |
| workspace | the one space |
| blocks | markdown: headings, paragraphs, lists, to-dos, toggles, quotes, callouts, code, equations, tables, dividers, bookmarks and embeds as links, child pages as mentions (each is its own item), files and images as attachments; navigation blocks and unknown types are skipped |
| comments | page-level comments into a separate artefact (`#comments`); a 403 turns them off for the rest of the run |

API version `2025-09-03`. The limit is an average of three requests a second per
integration, so a first run over 1,000 pages takes several minutes. Nested blocks are
followed eight levels deep, and at most 20,000 blocks are read per page; the copy says when
it was cut.

The tests run against wiremock with fixtures shaped like the documented answers
(`tests/fixtures/notion/`). CI never calls the real API.
