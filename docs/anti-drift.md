---
layout: doc
---

# Swarm line-file capture (anti-drift)

> Issue [#3587](https://github.com/alphaonedev/ai-memory-mcp/issues/3587)
> unit U2 (shipped) plus the QUAL-10 scaffolding in U5a. This page is
> the operator-facing contract for capturing swarm inbox/outbox
> **line files** into ai-memory. It does **not** claim the later
> units (store supersession, curator stale-ruling digest, capture-turn
> hook) have shipped. U6 PREP templates live under
> [`docs/ops/watch-wiring.md`](ops/watch-wiring.html); activation stays
> with the Conductor.

A multi-model swarm stays coherent only while every ruling and status
line is captured as substrate truth. Host transcripts (`claude-code` /
`codex` / `gemini`) already flow through `ai-memory watch` / L2
`recover-previous-session`. Deputy and Conductor **line files**
(`DEPUTY-OUTBOX.md`, `MASTER-INBOX.md`, and the same arrow-prefixed
shape) are not transcripts: they are append-only status logs. `#3587`
U2 is the capture path for those files.

## What to run

```bash
ai-memory watch --daemon \
  --host file:/path/to/DEPUTY-OUTBOX.md \
  --host file:/path/to/MASTER-INBOX.md \
  --agent-id ai:grok
```

`--host file:<path>` is repeatable and mixes with transcript hosts.
Full flag table: [`CLI_REFERENCE.md`](CLI_REFERENCE.html) § `watch`.
The watcher-layer type is `WatchSource` (`src/recover/line_file.rs`);
`HostKind` is unchanged (four-arm, `Copy`, kebab-case `--json` wire).

## Path safety

`inspect_line_file` is fail-closed. A path is accepted only when every
check holds:

| Check | Disposition |
|---|---|
| Any symlink component in the path | refused (`refuses symlink component`) |
| Final path is a symlink | refused (`refuses symlink`); open uses `O_NOFOLLOW` + fstat `(dev, ino)` identity so a swap between inspect and open cannot sneak a link through |
| Directory / FIFO / non-regular | refused |
| Owner uid ≠ watch-process euid | refused (no "allowed roots" concept) |
| File larger than 1 GiB (`MAX_LINE_FILE_BYTES`) | refused |
| Missing file | **not** an error — `Ok(None)` so a daemon can start before the outbox exists |
| `--dry-run` | writes nothing and never arms retry state |

There is no operator allowlist of extra directories. Same-uid +
regular-file + no-symlink is the whole gate.

## Dedup (zero schema change)

Idempotency reuses `transcript_line_dedup`:

- `host_kind` = `file`
- `transcript_path` = the absolute path
- `normalized_sha256` and `raw_sha256` = `sha256(abs_path ‖ 0x00 ‖ line)` (R1)
- `metadata.line_sha256` = `sha256(line)` (unsalted; the line's own digest)

The same verbatim line in two files is **two** memories (two dedup
rows). Restart, rotation, and truncation are safe: the in-memory
`(dev, ino, len, offset)` tuple is only the change detector and
resets on inode change or shrink. A trailing line without a newline
is never consumed. Reads stream at O(max-line) (64 KiB
`MAX_LINE_BYTES`); an oversized line is refused and skipped without
loading the rest of the file, and the next complete line still
ingests. Whitespace-only lines are skipped. Quiet ticks (no growth)
return before opening the database.

Title is `<basename>:<first 8 hex of line sha256>`. Identical lines in
same-named files do share a title; that is harmless because
`recover_turn_idempotent` does a plain insert with a fresh id (no
`(title, namespace)` upsert) — identity is the per-file dedup row, not
the title.

## Authorship and `observed_actor`

`metadata.agent_id` is **always** the watch process's resolved
principal (`--agent-id` / `AI_MEMORY_AGENT_ID`). File bytes never
become the owner — a line that says `MASTER → …` is not a privilege
escalation.

The parsed actor prefix, when present, lands in
`metadata.observed_actor` (`field_names::OBSERVED_ACTOR`). It is
**untrusted** observation:

- Arrow form: text left of `→` after an optional RFC3339-ish
  timestamp (`2026-09-10T22:58Z MASTER → Grok …` → `MASTER`).
- Otherwise the first whitespace token, and only when it looks like
  an identity (`:` or `@`). `READY #3587 …` yields **no**
  `observed_actor` (a tag, not an actor).

Kind is `Observation`, tier `mid`, `source` = `watch`,
`capture_layer` = `L3`.

## Tags (`SWARM_LINE_TAGS`)

Every captured line is tagged `swarm-line` and `host:file`. Additional
tags are taken from the closed SSOT
`READY` / `STATUS` / `BLOCKER` / `ACK` / `NOTE` / `MASTER`, matched
**case-sensitively** as whole tokens (prose "the build is ready" does
not tag `ready`).

## Postgres and `fs-notify`

| Build | Write path |
|---|---|
| Default (no `sal`) | `refuse_pg_store` — loud fail-closed if the resolved store is postgres |
| `--features sal` | line-file **and** transcript rows go through `MemoryStore::recover_turn_idempotent` (sqlite or postgres) |
| `--features fs-notify` | each line-file source watches its **parent directory**; poll is the fallback only when that directory is unwatchable |

## Two stores, two truth sets

Capture is per database. Conductor rulings on f2 and deputy lines on
the f1 hive are **not** one corpus: a line captured here does not
supersede a ruling over there. Supersession, when it lands, is per
store. This page documents that boundary. U6 PREP copy-and-substitute
templates are [`docs/ops/watch-wiring.md`](ops/watch-wiring.html);
activation stays with the Conductor.

## Contradiction proposals (U1, `[autonomy]`)

With `[autonomy] supersede_on_contradiction = "propose"` (config file
only; default `off`), the SQLite curator turns a conserved same-author
contradiction into a PENDING `supersede` approval request instead of
leaving it only down-weighted. The old memory's hardened owner approves
it with `memory_pending_approve` / `ai-memory pending approve` /
`POST /api/v1/pending/{id}/approve` / `POST /api/v1/approvals/{pending_id}`; the approved replay archives the old
memory exactly as `ai-memory resolve` would. Nothing is archived without
that approval, and proposals never leave the node. Details:
[`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.html) §`[autonomy]`.

## QUAL-10 ceilings (U5a)

U5a bumped three test-gate module-size ceilings so later anti-drift
units do not fight QUAL-10. Those are **not** runtime config keys.
Table: [`ENGINEERING_STANDARDS.md`](ENGINEERING_STANDARDS.html) §2.7;
pointer: [`CONFIG_SCHEMA.md`](CONFIG_SCHEMA.html) §"Quality-gate
module-size ceilings".
