-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v96 (#3344, v1.0.0) — DURABLE EMBED SKIP LIST (SQLite).
--
-- Doc twin of `src/storage/embed_skip.rs` (`MIGRATION_V96_SQLITE`). Applied
-- by the additive `if version < CURRENT_SCHEMA_VERSION` arm in
-- `src/storage/migrations.rs`. The postgres twin is
-- `migrations/postgres/0053_v96_embed_skip.sql`.
--
-- Remember rows that cannot be embedded under the CURRENT key material
-- (undecryptable envelope, #1779/#2317) or that exceed the embed byte cap
-- (#1595 oversize) so boot and the live backfill worker do not re-read and
-- re-WARN them every pass. Keyed by memory_id + the agent's encryption-key
-- fingerprint: restoring or rotating the key changes the fingerprint, the
-- stale skip is dropped, and the row is retried (healing path).
--
-- This table holds NO durable memory truth — it is a derived skip cache,
-- regenerable by re-scanning. Additive `CREATE TABLE IF NOT EXISTS`,
-- `IF NOT EXISTS` triggers, no full-table rebuild (the v63/v65 hazard
-- does not arise). Revert is DROP TABLE / DROP TRIGGER.
--
-- The memories-clearing triggers MUST be created only by this v96 arm
-- (after `memories.embedding` exists). They must NOT be inlined in
-- bootstrap `SCHEMA`: `open()` replays SCHEMA against mid-ladder
-- databases before the ladder, and `embedding` is a v3 ALTER — a
-- SCHEMA-installed `WHEN NEW.embedding IS NOT NULL` trigger makes
-- later ALTER TABLE / the v50 agent_quotas rebuild fail with
-- `error in trigger memories_embed_skip_clear_on_embed: no such
-- column: NEW.embedding`. Rebuild arms DROP the pair first; this arm
-- recreates them only when the column exists.
--
-- Slots after #3419's settled v95 `attested_write_ledger` arm.

CREATE TABLE IF NOT EXISTS embed_skip (
    memory_id        TEXT NOT NULL PRIMARY KEY,
    agent_id         TEXT NOT NULL DEFAULT '',
    key_fingerprint  TEXT NOT NULL,
    reason           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    CHECK (reason IN ('undecryptable', 'oversize'))
);

CREATE INDEX IF NOT EXISTS idx_embed_skip_fp
    ON embed_skip(key_fingerprint);

-- Healing: a content / envelope rewrite means the row may now be
-- embeddable (smaller body, restored plaintext). Drop the skip so the
-- next scan retries.
CREATE TRIGGER IF NOT EXISTS memories_embed_skip_clear_on_content
AFTER UPDATE OF content, encrypted_envelope ON memories
BEGIN
    DELETE FROM embed_skip WHERE memory_id = NEW.id;
END;

-- Hygiene: a successful embedding write drops the skip (the row has
-- left the unembedded scan set anyway).
CREATE TRIGGER IF NOT EXISTS memories_embed_skip_clear_on_embed
AFTER UPDATE OF embedding ON memories
WHEN NEW.embedding IS NOT NULL
BEGIN
    DELETE FROM embed_skip WHERE memory_id = NEW.id;
END;
