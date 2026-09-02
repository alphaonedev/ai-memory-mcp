-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v96 (#3344, v1.0.0) — DURABLE EMBED SKIP LIST (Postgres).
--
-- Doc twin of `PostgresStore::migrate_v96` in `src/store/postgres.rs`.
-- The postgres parity of the sqlite v96 arm: a derived skip cache for
-- permanently unembeddable rows (undecryptable envelope / oversize) so
-- boot and the live backfill worker do not re-read and re-WARN them
-- every pass. Keyed by memory_id + encryption-key fingerprint; restoring
-- the key invalidates the skip (healing path).
--
-- Additive, `IF NOT EXISTS`-idempotent, no rewrite. Revert is DROP TABLE
-- / DROP TRIGGER / DROP FUNCTION. A fresh cluster also inherits this
-- table from `src/store/postgres_schema.sql`.
--
-- Slots after #3419's settled v95 `attested_write_ledger` arm.

CREATE TABLE IF NOT EXISTS embed_skip (
    memory_id        TEXT        NOT NULL PRIMARY KEY,
    agent_id         TEXT        NOT NULL DEFAULT '',
    key_fingerprint  TEXT        NOT NULL,
    reason           TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT embed_skip_reason_ck CHECK (reason IN ('undecryptable', 'oversize'))
);

CREATE INDEX IF NOT EXISTS idx_embed_skip_fp
    ON embed_skip(key_fingerprint);

CREATE OR REPLACE FUNCTION trg_embed_skip_clear()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM embed_skip WHERE memory_id = NEW.id;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS memories_embed_skip_clear ON memories;
CREATE TRIGGER memories_embed_skip_clear
AFTER UPDATE OF content, encrypted_envelope, embedding ON memories
FOR EACH ROW
EXECUTE FUNCTION trg_embed_skip_clear();
