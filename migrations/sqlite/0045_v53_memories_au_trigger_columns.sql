-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.7.0 R5.F5.2 (#1418) — scope the `memories_au` FTS5 sync trigger
-- to (title, content, tags) instead of firing on every column UPDATE.
--
-- BEFORE this migration the trigger was:
--
--   CREATE TRIGGER memories_au AFTER UPDATE ON memories ...
--
-- which fires on UPDATE of ANY column. The substrate's hot-path
-- updates (`set_embeddings_batch` at `src/storage/mod.rs:6825`,
-- `touch_many` at `src/storage/mod.rs:1089-1098`) modify
-- non-FTS columns (`embedding`, `access_count`, `last_accessed_at`,
-- `confidence_decayed_at`, `version`) and were paying 2 unnecessary
-- FTS5 row ops (one DELETE + one INSERT) per UPDATE — at 100k rows
-- the embed-backfill loop alone churned 200k spurious FTS5 row ops.
--
-- The fix scopes the trigger to the three FTS5-mirrored columns
-- so non-FTS updates skip the FTS5 sync entirely. SQLite's
-- `CREATE TRIGGER ... AFTER UPDATE OF <columns>` is exactly
-- this primitive — the trigger only fires when one of the
-- listed columns is in the UPDATE's SET clause.
--
-- Idempotent — re-applying this migration against an already-v53
-- DB is a no-op: `DROP TRIGGER IF EXISTS` is null-safe and the
-- recreated trigger is byte-identical to the prior v53 run.

DROP TRIGGER IF EXISTS memories_au;

CREATE TRIGGER memories_au
    AFTER UPDATE OF title, content, tags ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
    VALUES ('delete', old.rowid, old.title, old.content, old.tags);
    INSERT INTO memories_fts(rowid, title, content, tags)
    VALUES (new.rowid, new.title, new.content, new.tags);
END;
