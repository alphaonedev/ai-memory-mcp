# Migration guide — sqlite → PostgreSQL on ai-memory v0.7.0

> **Audience.** Operators currently running ai-memory on sqlite who
> want to switch to PostgreSQL + Apache AGE on v0.7.0. The reverse
> direction (postgres → sqlite) is also supported and uses the same
> tool.
>
> See also: [`postgres-age-guide.md`](postgres-age-guide.md) for the
> postgres+AGE install and configuration prerequisites; this guide
> assumes those steps are already done.

## Why migrate

Stay on sqlite if all of these are true:

- Single-tenant single-daemon workstation deployment.
- Corpus comfortably fits in RAM (<1M memories typical).
- No multi-droplet A2A topology.
- AGE Cypher KG features are not in your hot path.

Migrate to postgres+AGE if any of these are true:

- Multi-tenant or multi-daemon (HTTP API behind a load balancer; or
  two `ai-memory serve` processes sharing a store).
- Corpus larger than RAM, or growing fast (10M+ memories).
- KG-heavy workloads — `find_paths` at depth ≥ 5 on a 1k+ entity
  graph; `kg_query` / `kg_timeline` in the recall hot path.
- Multi-droplet A2A federation where shared state is required (the
  v0.7.0 A2A campaign Wave 4 deployment shape).

The v0.7.0 SAL trait makes the backend choice an **operational**
decision, not a code one — every MCP / HTTP / CLI surface behaves
identically on either backend.

## Schema parity status (v0.7.0)

As of v0.7.0 release (post Wave 2 + ship-readiness cascade), both
backends sit at **schema_version=57**. The full v16 → v57 ladder
on the postgres side covers: governance inheritance, webhook
subscriptions, audit chain, transcripts, signed events with the
V-4 cross-row hash chain (#698), agent quotas, link `attest_level`,
A2A correlation, smart-load veto, KG temporal-index v2,
tier-promotion metadata, subscription DLQ, `consolidated_from_agents`
array, plus the v34 → v55 deltas (recursive-learning depth
columns, Batman Form-4/5 provenance + confidence-calibration
columns, optimistic-concurrency `version` column at v45,
`federation_push_dlq` table at v48, archive_memories +14
columns at v49, per-namespace K8 quota dimension at v50 #1156,
`federation_nonce_cache` persistence table at v51 #1255 / PR #1296,
`transcript_line_dedup` idempotency table at v52 #1389, the
`memories_au` FTS5 trigger scoping at v53 #1418, the tier-default
expiry backfill at v54 #1466, and the federation-catchup
`updated_at` index work at v55 #1476 (a sargable rewrite of
`list_memories_updated_since`; postgres adds NO new index because
`memories_updated_at_idx (updated_at DESC)` already serves the
range scan via Index Scan Backward, so `migrate_v55()` is a
version-stamp no-op on the postgres side).
The v34 → v55 deltas land via in-process
`migrate_v34() … migrate_v55()` async functions that run as a side
effect of `ai-memory schema-init --store-url <url>` opening the store
(there is no `--upgrade` flag); they are NOT separate `.sql` files.

If you migrated from sqlite to postgres on v0.7-alpha, your
postgres db is at v15. Run `ai-memory schema-init --store-url <url>`
with the v0.7.0 binary (see "In-place v15 → v55" below) before
pointing a v0.7.0 daemon at it.

## Pre-flight checklist

Before you start:

- **Backup the sqlite db.** Either copy the file (with the daemon
  stopped — sqlite WAL means a hot copy can be inconsistent) or
  use `sqlite3 memory.db ".backup memory.bak.db"`. Either way, write
  the backup somewhere that survives a failed migration.
- **Stop any running `ai-memory` processes** that have the sqlite
  file open — daemon, MCP server, sync daemon, curator daemon. The
  migration tool requires exclusive access to the source.
- **Provision the postgres database** per `postgres-age-guide.md`
  ("Prerequisites" + "Database setup"). The target db must exist;
  the tool does not create it.
- **Note your current sqlite schema version:**
  ```bash
  sqlite3 ~/.local/share/ai-memory/memory.db \
    "SELECT MAX(version) FROM schema_version;"
  ```
  If this is **less than 55**, upgrade first: start `ai-memory serve`
  briefly against the sqlite db (it auto-migrates on connect to v55),
  then stop it. The postgres side won't accept a partial migration.

## Step 1 — Bootstrap the postgres schema

```bash
ai-memory schema-init \
  --store-url postgres://aimemory:PASSWORD@HOST:5432/aimemory
```

Idempotent on rerun. Exit code 0 + the human summary reporting
`schema_version: 55` is the success signal (pass `--json` for the
machine-parseable report, which also carries `age_projection_created`
and `embedding_dim`):

```text
schema initialized at <url>
  tables: <count>
  indices: <count>
  views: <count>
  functions: <count>
  extensions: [<list>]
  schema_version: 55
```

## Step 2 — Dry-run the migration

```bash
ai-memory migrate \
  --from sqlite:///$HOME/.local/share/ai-memory/memory.db \
  --to   postgres://aimemory:PASSWORD@HOST:5432/aimemory \
  --dry-run
```

The dry-run emits the same `MigrationReport` the real run does, with
nothing written to the destination:

- `memories_read` / `memories_written` (0 on dry-run) — memory rows
  enumerated from the source.
- `links_read` / `links_written` / `links_skipped` — `memory_links`
  rows (F6 Gap 2: links migrate alongside memories).
- `batches`, `dry_run: true`, and an `errors` array.

Pass `--json` for the machine-parseable shape. Read the report and
investigate any `errors` entry before proceeding. Note the current
migrator reads one page capped at 1,000,000 rows (`MAX_ROWS` in
`src/migrate.rs`) and refuses loudly past it; `--batch` is an
API-compatibility hint only.

## Step 3 — Real migration

```bash
ai-memory migrate \
  --from sqlite:///$HOME/.local/share/ai-memory/memory.db \
  --to   postgres://aimemory:PASSWORD@HOST:5432/aimemory
```

What it does (see `src/migrate.rs`):

1. Opens both stores via the SAL trait (`open_store` on each URL —
   opening the destination runs its schema bootstrap as a side
   effect).
2. Walks the source's memories via a single admin-scope `list` call
   (capped at `MAX_ROWS` = 1,000,000 — it refuses loudly past the cap
   rather than truncating) and writes each row via the destination's
   `store`, preserving ids verbatim.
3. Walks the source's `memory_links` rows and replays each into the
   destination (v0.7.0 F6 Gap 2 — edge migration was missing in
   v0.7-alpha; v0.7.0 closes that gap). Duplicate
   `(source_id, target_id, relation)` triples count as
   `links_skipped`.
4. Emits the `MigrationReport` (memories/links read + written +
   skipped, batches, errors) — human-readable, or JSON with `--json`.

Idempotent on rerun: each write uses the source memory's id verbatim,
so the adapter's upsert-on-id semantics make a re-run a no-op when the
source hasn't changed (links land via `ON CONFLICT DO NOTHING` /
`INSERT OR IGNORE`).

## Step 4 — Verification

```bash
# Row-count parity.
sqlite3 ~/.local/share/ai-memory/memory.db \
  "SELECT 'memories', COUNT(*) FROM memories
   UNION ALL SELECT 'memory_links', COUNT(*) FROM memory_links
   UNION ALL SELECT 'namespaces', COUNT(*) FROM namespaces
   UNION ALL SELECT 'signed_events', COUNT(*) FROM signed_events
   UNION ALL SELECT 'memory_transcripts', COUNT(*) FROM memory_transcripts;"

psql 'postgres://aimemory:PASSWORD@HOST:5432/aimemory' -c "
  SELECT 'memories' AS tbl, COUNT(*) FROM memories
  UNION ALL SELECT 'memory_links', COUNT(*) FROM memory_links
  UNION ALL SELECT 'namespaces', COUNT(*) FROM namespaces
  UNION ALL SELECT 'signed_events', COUNT(*) FROM signed_events
  UNION ALL SELECT 'memory_transcripts', COUNT(*) FROM memory_transcripts;"
```

Counts must match for `memories` and `memory_links` (the migrate tool
copies those two tables; operational tables such as `signed_events` and
`memory_transcripts` start fresh on the postgres side). If
`memory_links` is short on the postgres side, you migrated against a
pre-Wave-1 binary — re-run with the v0.7.0 binary that has Stream A's
`migrate.rs` link-walk.

```bash
# Schema parity.
psql 'postgres://aimemory:PASSWORD@HOST:5432/aimemory' \
  -tAc "SELECT MAX(version) FROM schema_version;"
# → 55
```

```bash
# Idempotency probe — a second run against an unchanged source should
# report links_skipped == links_read and zero errors.
ai-memory migrate \
  --from sqlite:///$HOME/.local/share/ai-memory/memory.db \
  --to   postgres://aimemory:PASSWORD@HOST:5432/aimemory \
  --dry-run --json
```

(There is no separate `verify-migration` subcommand at v0.7.0 — the
row-count parity queries above plus the dry-run report are the
verification surface. Mismatched counts ⇒ stop the cutover and file an
issue with the per-table count delta.)

## Step 5 — Cutover

Once verification passes:

```bash
# (a) Stop the sqlite-backed daemon if it's still running.
sudo systemctl stop ai-memory   # or your service manager

# (b) Reconfigure for postgres. The daemon takes the URL via the
#     --store-url FLAG only (the AI_MEMORY_STORE_URL env fallback was
#     deliberately dropped — commit 1e8ad69b). Recommended: systemd
#     drop-in that overrides ExecStart:
sudo systemctl edit ai-memory <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/ai-memory serve --store-url postgres://aimemory:PASSWORD@HOST:5432/aimemory
EOF

# (c) Start the daemon.
sudo systemctl start ai-memory
journalctl -u ai-memory | grep "Postgres KG backend"
# → "Postgres KG backend: AGE" (or CTE without the AGE extension)
```

Verify the live HTTP path (the CLI `recall` subcommand reads the local
sqlite file, not the daemon's postgres store — use the HTTP API):

```bash
curl -s "http://localhost:9077/api/v1/recall?context=smoke%20test" | jq '.memories | length'
# Should return your existing memories. If you get 0, double-check
# the URL — you may have started the daemon against an empty postgres.
```

## Reverse migration (postgres → sqlite)

The migration tool is bidirectional. If you need to fall back:

```bash
ai-memory migrate \
  --from postgres://aimemory:PASSWORD@HOST:5432/aimemory \
  --to   sqlite:///$HOME/.local/share/ai-memory/memory.db
```

Same dry-run / verify dance. Useful for:

- Taking a sqlite snapshot of a postgres prod store for offline
  analysis or backup.
- Rolling back a postgres deployment if a postgres-only regression
  surfaces (the migration is lossless either direction at v0.7.0
  schema parity).

## In-place v15 → v55 (postgres → postgres on the same host)

If you're upgrading an existing v0.7-alpha postgres db (schema v15)
to v0.7.0's v55 parity:

```bash
ai-memory schema-init \
  --store-url postgres://aimemory:PASSWORD@HOST:5432/aimemory
```

Opening the store walks the v15 → v55 deltas idempotently (the
v34 → v55 layer lands via in-process `migrate_v34()…migrate_v55()`
async functions that run on connect; there is no `--upgrade` flag).
Existing data is preserved; only DDL changes.

## Rollback strategy

The cleanest rollback path:

1. **Keep the sqlite backup from the pre-flight checklist.** The
   migrate tool does not delete the source — your sqlite file is
   untouched after the migration, by design.
2. **Verify the sqlite file is still good** before disposing of it:
   ```bash
   sqlite3 memory.bak.db "PRAGMA integrity_check;"
   # → ok
   ```
3. **If you need to roll back** within the first 24-48h after cutover:
   - Stop the postgres-backed daemon.
   - Reverse-migrate the postgres store back onto the sqlite file
     (`ai-memory migrate --from postgres://… --to sqlite:///…`). The
     migrator has no time-window flag — it replays the full corpus,
     and upsert-on-id semantics make re-copying unchanged rows a
     no-op, so the effective result is the post-cutover delta.
   - Restart the daemon pointing at the sqlite file.

If the postgres deployment is stable for >1 week, the rollback
window has effectively closed — the postgres store has accumulated
material new state, and you'd want a fresh forward-migration to
sqlite (which the tool supports) rather than a rollback.

## Known gotchas

### Embeddings carry over verbatim

The migration tool transports the embedding bytes as-is. The model
and dimension are recorded on each memory; the postgres side's
pgvector HNSW gets the same vectors the sqlite side's HNSW had. No
re-embedding required.

### FTS5 → tsvector swap

sqlite uses FTS5 for keyword search; postgres uses native `tsvector`
+ GIN index. The migration tool builds the postgres tsvector index
during the import phase. The two FTS rankers are **not** byte-identical —
you may see top-K shuffles in keyword-only queries between sqlite and
postgres for ties. The recall parity test (`tests/recall_scoring_parity.rs`)
asserts the **score** stays equal within FP tolerance, but the
underlying rankers differ slightly.

### AGE projection rebuild on first daemon start

If you migrate into a postgres whose AGE `memory_graph` projection was
never created (e.g. you ran the v0.7-alpha migrate tool, or AGE was
installed after schema-init), the first time a v0.7.0 daemon connects
with AGE enabled it bootstraps the `memory_graph` projection at
connect time, and link writes `MERGE` nodes/edges into it lazily. The
first heavy `kg_query` on a large KG may take 10-60 seconds —
subsequent queries are fast. Pre-prime by running
`ai-memory schema-init --store-url <url>` once (it issues the
idempotent `SELECT create_graph('memory_graph')` when AGE is
installed).

### Auth secrets in URLs

If you put `aimemory:PASSWORD@…` directly in `--store-url`, the URL
appears in `ps` output and (on some shells) in `~/.bash_history`.
Note the daemon does NOT read an `AI_MEMORY_STORE_URL` env var (that
fallback was deliberately dropped in commit `1e8ad69b`) — `--store-url`
is a flag-only surface. To keep the password out of `ps` / history,
reference it indirectly inside the unit, e.g. a systemd
`EnvironmentFile=` (`chmod 0600`) defining `PGPASS_URL` and
`ExecStart=… serve --store-url ${PGPASS_URL}`, or use a `.pgpass`-style
credential and a password-less URL where your postgres setup allows it.

## References

- v0.7.0 release notes: [`v0.7.0/release-notes.md`](v0.7.0/release-notes.md)
- Postgres+AGE operator guide: [`postgres-age-guide.md`](postgres-age-guide.md)
- Adapter-selection design: [`RUNBOOK-adapter-selection.md`](RUNBOOK-adapter-selection.md)
- Schema parity gap (pre-Wave-2 reference): the table in
  `ai-memory-a2a-v0.7.0/docs/coverage.md` "Schema parity gap"
  section (now closed in v0.7.0).
- Migration tool source: `src/migrate.rs` + `tests/migrate_*` fixtures.
