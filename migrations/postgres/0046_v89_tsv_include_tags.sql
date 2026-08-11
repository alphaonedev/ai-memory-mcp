-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #2392 — schema v89: fold `tags` into the stored generated `tsv`
-- tsvector so the POSTGRES full-text-search surface indexes
-- title + content + tags, mirroring the SQLite `memories_fts(title,
-- content, tags)` scope.
--
-- ## The defect this closes
--
-- The v57 (#1579 B2) generated column was
--   to_tsvector('english', coalesce(title,'') || ' ' || coalesce(content,''))
-- which OMITS `tags`. SQLite's FTS5 virtual table `memories_fts` has
-- indexed `(title, content, tags)` since inception (the `SCHEMA` const in
-- `src/storage/migrations.rs` + the v53 `memories_au` trigger scope,
-- R5.F5.2 / #1418). So the SAME wire query — a `q` / `context` FTS search,
-- recall, or contradiction whose only match is a tag word — returned rows
-- on SQLite but ZERO on postgres, a silent cross-backend row-set
-- divergence on the enterprise (postgres) tier. Every postgres read path
-- already reads the `tsv` COLUMN for BOTH the `@@` match and `ts_rank(...)`
-- (v57), so redefining the column fixes recall / search / contradiction /
-- list uniformly with no query-shape change.
--
-- ## Why DROP + ADD (not ALTER)
--
-- PG16 has no `ALTER TABLE ... ALTER COLUMN ... SET EXPRESSION` (PG17+),
-- so a generated-column expression change is a DROP COLUMN + ADD COLUMN.
-- `DROP COLUMN IF EXISTS tsv` cascades away the dependent GIN index
-- `memories_tsv_gin` (no CASCADE keyword needed), so this file recreates
-- it with the SAME definition v57 used. `IF EXISTS` is load-bearing for
-- the ladder replay harness (`tests/postgres_ladder_replay.rs`), which
-- strips the v57 `tsv` column when synthesizing a legacy shape below v89 —
-- a bare `DROP COLUMN tsv` would then error `column "tsv" does not exist`.
--
-- ## The tags fold
--
-- `tags` is JSONB and a postgres GENERATED column bars set-returning
-- functions / subqueries / aggregates, so `jsonb_array_elements_text` is
-- unavailable there. The generated-column-LEGAL fold is
-- `coalesce(tags::text, '')`: the `jsonb -> text` cast is an immutable,
-- deterministic I/O coercion, and the JSON brackets / quotes / commas are
-- text-search separators (they yield no lexemes), so the array elements
-- tokenize into the tsvector exactly as the title / content words do —
-- under the SAME 'english' config already applied to title + content (the
-- tag stemming / stopword nuance is a pre-existing property of the
-- postgres FTS surface, not introduced here).
--
-- ## Operational note (fleet apply)
--
-- `ADD COLUMN ... GENERATED ALWAYS AS ... STORED` takes an ACCESS
-- EXCLUSIVE lock and rewrites the table to backfill the column (the same
-- posture as the original v57 add). At the fleet's ~8k rows this is
-- sub-second; plan a maintenance window before running it against
-- multi-million-row deployments. If the rewrite exceeds the pooled
-- connection's default 30s `statement_timeout` on such a table, raise or
-- disable the ceiling for the boot that runs the migration via
-- `postgres_statement_timeout_secs` (`AI_MEMORY_PG_STATEMENT_TIMEOUT_SECS`;
-- `0` lifts both the `statement_timeout` and `lock_timeout` bounds) so the
-- arm can complete instead of rolling back every boot. This DDL is executed by
-- `PostgresStore::migrate_v89()` (via `sqlx::raw_sql`) inside ONE
-- transaction on the POOLED connection, which RETAINS the pool's
-- `lock_timeout` / `statement_timeout` — deliberately, so under lock
-- contention the arm fails CLOSED (rolls back, stays at v88, retries next
-- boot) rather than waiting unbounded. A STORED-generated rewrite CANNOT
-- be built CONCURRENTLY, so the brief exclusive lock is the accepted
-- posture; the durable title/content/tags TEXT is never at risk (`tsv` is
-- derived data regenerated from it).
--
-- The SQLite twin is a version-stamp no-op (FTS5 already indexes tags) —
-- see `migrations/sqlite/0073_v89_tsv_tags_noop.sql`.
--
-- Executed by `src/store/postgres.rs::PostgresStore::migrate_v89`
-- (const `MIGRATION_V89_TSV_INCLUDE_TAGS`). Fresh installs get the same
-- final shape: `src/store/postgres_schema.sql` carries the tags-folded
-- generated column inline, migrate_v57 makes the GIN index, and this arm
-- (which fresh installs also run, entering the ladder at version 0)
-- DROP+ADDs the column so greenfield and upgrade converge byte-identically.

ALTER TABLE memories DROP COLUMN IF EXISTS tsv;

ALTER TABLE memories
    ADD COLUMN tsv tsvector GENERATED ALWAYS AS (
        to_tsvector(
            'english',
            coalesce(title, '') || ' ' || coalesce(content, '') || ' ' || coalesce(tags::text, '')
        )
    ) STORED;

CREATE INDEX IF NOT EXISTS memories_tsv_gin ON memories USING gin (tsv);
