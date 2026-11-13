-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v102 (#9082): serving-assigned change sequence. Doc twin of
-- `PostgresStore::migrate_v102` in `src/store/postgres.rs`, parity twin of
-- `migrations/sqlite/0086_v102_sync_seq.sql` (the rationale lives there).
-- Shape ratified by the 5-agent vote (4d3ea1c5), memory c472a44b.
--
-- Assignment happens at COMMIT, not at write time. A BEFORE INSERT trigger
-- gives a new row a unique NEGATIVE placeholder from a plain sequence (no
-- lock; readers walk `sync_seq > after_seq >= 0` and never see it), and two
-- DEFERRABLE INITIALLY DEFERRED constraint triggers (after insert, and after
-- a real change of a replicated column) take the next value with one
-- UPDATE ... RETURNING on the one-row counter when the transaction commits.
-- The counter row lock is therefore taken only after every row lock of the
-- transaction is already held and released by the COMMIT right after it, so
-- it can never be part of a lock cycle (#9176 F5: a lock taken inside a
-- per-row BEFORE trigger made new deadlocks between multi-row writers). A
-- second committer waits for the first to commit or roll back before it takes
-- the next value, so seq order still equals commit order. Positive values are
-- never handed out by a sequence: `nextval` is handed out at call time, not
-- commit time, so a reader could see seq N+1 committed while N is still in
-- flight and step its cursor past N for ever.
--
-- `SET search_path FROM CURRENT` pins the counter lookup to the schema the
-- migration ran in, so an AGE `SET LOCAL search_path` (#7101) in the same
-- transaction cannot redirect it to another schema's counter.
--
-- The part above the marker runs ONLY while `memories.sync_seq` is absent
-- (`PostgresStore::migrate_v102` probes information_schema.columns, the twin
-- of the sqlite pragma_table_info probe): a ladder re-run never re-numbers an
-- assigned value (#9176 F1). Everything below the marker is idempotent.
-- The bump column list is the SSOT `storage::sync_seq::SYNC_SEQ_BUMP_COLUMNS`
-- (pinned by tests/federation_sync_seq_9082.rs). A later migration that drops
-- or renames one of those columns must drop the two deferred triggers first
-- and recreate them after (`storage::sync_seq::SQL_DROP_SYNC_SEQ_TRIGGERS`).
ALTER TABLE memories ADD COLUMN sync_seq BIGINT NOT NULL DEFAULT 0;

WITH ranked AS (
    SELECT id, row_number() OVER (ORDER BY updated_at, id) AS rn FROM memories
)
UPDATE memories AS m SET sync_seq = ranked.rn FROM ranked WHERE ranked.id = m.id;
-- @@v102-once@@

-- `node_identity` binds the epoch to this database instance
-- (`system_identifier:timeline_id:database oid`); `PostgresStore::connect`
-- mints a new epoch when it differs, so a pg_restore, a PITR or a clone that
-- comes back with a lower head is rewalked by every puller (#9176 F6).
CREATE TABLE IF NOT EXISTS sync_seq_counter (
    id            SMALLINT PRIMARY KEY CHECK (id = 1),
    head          BIGINT   NOT NULL CHECK (head >= 0),
    epoch         TEXT     NOT NULL,
    node_identity TEXT
);
-- A database migrated by an earlier cut of this migration has the table
-- without the column; the add is a no-op everywhere else.
ALTER TABLE sync_seq_counter ADD COLUMN IF NOT EXISTS node_identity TEXT;

INSERT INTO sync_seq_counter (id, head, epoch)
-- The epoch is 32 lowercase hex characters on both backends (sqlite mints
-- lower(hex(randomblob(16)))); pullers accept only ASCII alphanumerics.
SELECT 1, GREATEST(COALESCE(MAX(sync_seq), 0), 0), replace(gen_random_uuid()::text, '-', '')
FROM memories
ON CONFLICT (id) DO NOTHING;

-- A row written while the deferred triggers were dropped (a ladder re-run
-- that drops a bump column, `SQL_DROP_SYNC_SEQ_TRIGGERS_PG`) keeps its
-- negative placeholder, and a walk (`sync_seq > after_seq >= 0`) would never
-- serve it. Give each such row the next value under the counter row lock, in
-- insertion order (the placeholder is `-nextval`), and move the head past
-- them. An assigned (positive) value is never touched (#9176 F1).
WITH base AS (
    SELECT head FROM sync_seq_counter WHERE id = 1 FOR UPDATE
), pending AS (
    SELECT id, row_number() OVER (ORDER BY sync_seq DESC, id) AS rn
    FROM memories WHERE sync_seq <= 0
)
UPDATE memories AS m SET sync_seq = base.head + pending.rn
FROM pending, base WHERE m.id = pending.id;

UPDATE sync_seq_counter
SET head = GREATEST(head, (SELECT COALESCE(MAX(sync_seq), 0) FROM memories))
WHERE id = 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_sync_seq ON memories (sync_seq);

CREATE SEQUENCE IF NOT EXISTS memories_sync_seq_pending AS BIGINT;

CREATE OR REPLACE FUNCTION memories_sync_seq_placeholder() RETURNS trigger
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $fn$
BEGIN
    NEW.sync_seq := -nextval('memories_sync_seq_pending');
    RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION memories_sync_seq_assign() RETURNS trigger
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $fn$
DECLARE
    v BIGINT;
BEGIN
    UPDATE sync_seq_counter SET head = head + 1 WHERE id = 1 RETURNING head INTO v;
    IF v IS NULL THEN
        RAISE EXCEPTION 'sync_seq_counter row 1 is missing (v102)';
    END IF;
    UPDATE memories SET sync_seq = v WHERE id = NEW.id;
    RETURN NULL;
END
$fn$;

DROP TRIGGER IF EXISTS memories_sync_seq_bu ON memories;
DROP TRIGGER IF EXISTS memories_sync_seq_bi ON memories;
CREATE TRIGGER memories_sync_seq_bi BEFORE INSERT ON memories
    FOR EACH ROW EXECUTE FUNCTION memories_sync_seq_placeholder();

DROP TRIGGER IF EXISTS memories_sync_seq_ai ON memories;
CREATE CONSTRAINT TRIGGER memories_sync_seq_ai AFTER INSERT ON memories
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION memories_sync_seq_assign();

DROP TRIGGER IF EXISTS memories_sync_seq_au ON memories;
CREATE CONSTRAINT TRIGGER memories_sync_seq_au
    AFTER UPDATE OF tier, namespace, title, content, tags, priority, confidence, source,
        created_at, updated_at, metadata, reflection_depth, memory_kind, entity_id,
        persona_version, citations, source_uri, source_span, confidence_source,
        confidence_signals, version, lifecycle_state, valid_from, valid_until,
        encrypted_envelope
    ON memories
    DEFERRABLE INITIALLY DEFERRED
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
