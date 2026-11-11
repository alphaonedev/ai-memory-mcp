-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v102 (#9082): serving-assigned change sequence. Doc twin of
-- `PostgresStore::migrate_v102` in `src/store/postgres.rs`, parity twin of
-- `migrations/sqlite/0086_v102_sync_seq.sql` (the rationale lives there).
-- Shape ratified by the 5-agent vote (4d3ea1c5), memory c472a44b.
--
-- Assignment is one UPDATE ... RETURNING on the one-row counter inside a
-- BEFORE trigger: the counter row lock is held to COMMIT, so a second writer
-- waits for the first to commit or roll back before it takes the next value,
-- and seq order equals commit order. No CREATE SEQUENCE: `nextval` is handed
-- out at call time, not commit time, so a reader could see seq N+1 committed
-- while N is still in flight and step its cursor past N for ever.
--
-- `SET search_path FROM CURRENT` pins the counter lookup to the schema the
-- migration ran in, so an AGE `SET LOCAL search_path` (#7101) in the same
-- transaction cannot redirect it to another schema's counter.
ALTER TABLE memories ADD COLUMN IF NOT EXISTS sync_seq BIGINT NOT NULL DEFAULT 0;

WITH ranked AS (
    SELECT id, row_number() OVER (ORDER BY updated_at, id) AS rn FROM memories
)
UPDATE memories AS m SET sync_seq = ranked.rn FROM ranked WHERE ranked.id = m.id;

CREATE TABLE IF NOT EXISTS sync_seq_counter (
    id    SMALLINT PRIMARY KEY CHECK (id = 1),
    head  BIGINT   NOT NULL CHECK (head >= 0),
    epoch TEXT     NOT NULL
);

INSERT INTO sync_seq_counter (id, head, epoch)
-- The epoch is 32 lowercase hex characters on both backends (sqlite mints
-- lower(hex(randomblob(16)))); pullers accept only ASCII alphanumerics.
SELECT 1, COALESCE(MAX(sync_seq), 0), replace(gen_random_uuid()::text, '-', '') FROM memories
ON CONFLICT (id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_sync_seq ON memories (sync_seq);

CREATE OR REPLACE FUNCTION memories_sync_seq_assign() RETURNS trigger
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $fn$
BEGIN
    UPDATE sync_seq_counter SET head = head + 1 WHERE id = 1 RETURNING head INTO NEW.sync_seq;
    IF NEW.sync_seq IS NULL THEN
        RAISE EXCEPTION 'sync_seq_counter row 1 is missing (v102)';
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS memories_sync_seq_bi ON memories;
CREATE TRIGGER memories_sync_seq_bi BEFORE INSERT ON memories
    FOR EACH ROW EXECUTE FUNCTION memories_sync_seq_assign();

DROP TRIGGER IF EXISTS memories_sync_seq_bu ON memories;
CREATE TRIGGER memories_sync_seq_bu
    BEFORE UPDATE OF tier, namespace, title, content, tags, priority, confidence, source,
        created_at, updated_at, metadata, reflection_depth, memory_kind, entity_id,
        persona_version, citations, source_uri, source_span, confidence_source,
        confidence_signals, version, lifecycle_state, valid_from, valid_until,
        encrypted_envelope
    ON memories
    FOR EACH ROW
    WHEN ((OLD.tier, OLD.namespace, OLD.title, OLD.content, OLD.tags, OLD.priority,
           OLD.confidence, OLD.source, OLD.created_at, OLD.updated_at, OLD.metadata,
           OLD.reflection_depth, OLD.memory_kind, OLD.entity_id, OLD.persona_version,
           OLD.citations, OLD.source_uri, OLD.source_span, OLD.confidence_source,
           OLD.confidence_signals, OLD.version, OLD.lifecycle_state,
           OLD.valid_from, OLD.valid_until, OLD.encrypted_envelope)
          IS DISTINCT FROM
          (NEW.tier, NEW.namespace, NEW.title, NEW.content, NEW.tags, NEW.priority,
           NEW.confidence, NEW.source, NEW.created_at, NEW.updated_at, NEW.metadata,
           NEW.reflection_depth, NEW.memory_kind, NEW.entity_id, NEW.persona_version,
           NEW.citations, NEW.source_uri, NEW.source_span, NEW.confidence_source,
           NEW.confidence_signals, NEW.version, NEW.lifecycle_state,
           NEW.valid_from, NEW.valid_until, NEW.encrypted_envelope))
    EXECUTE FUNCTION memories_sync_seq_assign();

-- Puller-side mirror (the sync daemon keeps its cursors on the sqlite file;
-- this table holds no rows on a postgres deployment and keeps the ladders at
-- schema parity, precedent v99 `sync_peer_contact`).
CREATE TABLE IF NOT EXISTS sync_pull_seq (
    agent_id   TEXT   NOT NULL,
    peer_id    TEXT   NOT NULL,
    last_seq   BIGINT CHECK (last_seq IS NULL OR last_seq >= 0),
    seq_epoch  TEXT,
    updated_at TEXT   NOT NULL,
    PRIMARY KEY (agent_id, peer_id)
);
