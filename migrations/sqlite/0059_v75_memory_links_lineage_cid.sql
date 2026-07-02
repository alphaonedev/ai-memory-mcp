-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 G13-mem (#1859, schema v75) — memory-derivation lineage-DAG.
--
-- Additive content-id mirror columns on `memory_links`: `source_cid` /
-- `target_cid` carry the `b3:<hex>` content-address (schema v74
-- `memories.cid`) of each endpoint AT LINK-CREATION TIME, so a lineage
-- traversal can resolve stable node identity even after a source memory
-- is tombstoned + its live plaintext diverges. NULL when the endpoint
-- carried no cid (legacy / pre-v74 rows); the query layer falls back to a
-- LEFT JOIN on `memories.cid` for those. The lineage-DAG is a VIEW over
-- the provenance subset P = {derived_from, reflects_on, derives_from} of
-- the existing closed `relation` CHECK allowlist — this migration adds NO
-- new relation and NO relation-CHECK rebuild.
--
-- SQLite has no `ADD COLUMN IF NOT EXISTS` and adds one column per ALTER,
-- so the v75 ladder arm in `src/storage/migrations.rs` runs this file only
-- behind a `SELECT source_cid FROM memory_links LIMIT 0` column-existence
-- probe (the v73/v74 pattern). Fresh installs inherit the columns inline
-- from the `CREATE TABLE memory_links` in the bootstrap `SCHEMA` const, so
-- the probe skips the ALTER and this unguarded DDL never double-runs.
ALTER TABLE memory_links ADD COLUMN source_cid TEXT;
ALTER TABLE memory_links ADD COLUMN target_cid TEXT;

-- Descendant traversal (`target_id`-keyed reverse walk) and per-hop cid
-- resolution both scan by target; index it.
CREATE INDEX IF NOT EXISTS idx_memory_links_target_cid ON memory_links(target_cid);
