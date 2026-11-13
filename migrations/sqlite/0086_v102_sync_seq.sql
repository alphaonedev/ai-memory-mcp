-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v102 (#9082, v1.0.0) — SERVING-ASSIGNED CHANGE SEQUENCE (SQLite).
--
-- Doc twin of `crate::storage::sync_seq::migrate_v102`, parity twin of
-- `migrations/postgres/0059_v102_sync_seq.sql`. Shape ratified by the
-- 5-agent vote (4d3ea1c5), memory c472a44b.
--
-- `/sync/since` filtered by the row's OWN `updated_at`, a value the WRITER
-- chose. A row that reached this node with an `updated_at` below a puller's
-- cursor (a relayed row, a backward clock step on the origin) was never
-- served again. `sync_seq` is assigned by THIS node, in commit order, on
-- every insert and every real change of a replicated column, so a puller
-- walking `sync_seq > after_seq` sees every row this node holds.
--
-- Order (binding): add the column, backfill in (updated_at, id) order, seed
-- the one-row counter at the backfilled head, THEN the UNIQUE index, THEN
-- the assignment triggers (so the backfill itself is never re-numbered).
--
-- Assignment: SQLite serialises writers on the database write lock, so the
-- counter bump inside the trigger is in commit order. The value is never
-- read from push / import / restore input: `Memory` carries no `sync_seq`
-- field and every insert is re-numbered by the AFTER INSERT trigger.
--
-- Bump set: every replicated column EXCEPT the access-touch columns
-- (`access_count`, `last_accessed_at`, the `expires_at` TTL floor that
-- `touch` extends) and the decay stamp `confidence_decayed_at`; a no-op
-- upsert changes nothing in the set and does not bump. `cid` is derived from
-- the content columns already in the set, so it is left out: a re-derived
-- `cid` (v74 backfill) is not a replicated change. `sync_seq` itself is
-- not in the set, so the trigger's own write never re-fires it.
ALTER TABLE memories ADD COLUMN sync_seq INTEGER NOT NULL DEFAULT 0;

WITH ranked AS (
    SELECT id, row_number() OVER (ORDER BY updated_at, id) AS rn FROM memories
)
UPDATE memories SET sync_seq = ranked.rn FROM ranked WHERE ranked.id = memories.id;

-- @@v102-once@@
-- Everything above runs only when `sync_seq` is absent
-- (`migrate_v102` checks `pragma_table_info`), so a ladder re-run never
-- adds the column twice nor re-numbers live rows. Everything below is
-- idempotent on its own.

-- `node_identity` binds the epoch to this database file (its inode); the
-- open re-mints the epoch when a copied-back file carries another one, so a
-- file restored without `ai-memory restore` is rewalked by every puller
-- (#9176 F6). An in-place overwrite of the live file keeps the inode: a
-- restore must go through `ai-memory restore`, which arms the sidecar.
CREATE TABLE IF NOT EXISTS sync_seq_counter (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    head          INTEGER NOT NULL CHECK (head >= 0),
    epoch         TEXT    NOT NULL,
    node_identity TEXT
);

INSERT OR IGNORE INTO sync_seq_counter (id, head, epoch)
SELECT 1, MAX(COALESCE(MAX(sync_seq), 0), 0), lower(hex(randomblob(16))) FROM memories;

-- A row written while the triggers were dropped (a ladder re-run that drops
-- a bump column, `SQL_DROP_SYNC_SEQ_TRIGGERS`) keeps the column default 0, and
-- a walk (`sync_seq > after_seq >= 0`) would never serve it. Give each such
-- row the next value and move the head past them; an assigned (positive)
-- value is never touched (#9176 F1). Parity twin of the postgres heal.
WITH pending AS (
    SELECT id, row_number() OVER (ORDER BY sync_seq DESC, id) AS rn
    FROM memories WHERE sync_seq <= 0
)
UPDATE memories
SET sync_seq = (SELECT head FROM sync_seq_counter WHERE id = 1) + pending.rn
FROM pending WHERE pending.id = memories.id;

UPDATE sync_seq_counter
SET head = MAX(head, (SELECT COALESCE(MAX(sync_seq), 0) FROM memories))
WHERE id = 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_sync_seq ON memories (sync_seq);

CREATE TRIGGER IF NOT EXISTS memories_sync_seq_ai AFTER INSERT ON memories
BEGIN
    UPDATE sync_seq_counter SET head = head + 1 WHERE id = 1;
    UPDATE memories SET sync_seq = (SELECT head FROM sync_seq_counter WHERE id = 1)
     WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS memories_sync_seq_au
AFTER UPDATE OF tier, namespace, title, content, tags, priority, confidence, source,
    created_at, updated_at, metadata, reflection_depth, memory_kind, entity_id,
    persona_version, citations, source_uri, source_span, confidence_source,
    confidence_signals, version, lifecycle_state, valid_from, valid_until,
    encrypted_envelope
ON memories
WHEN OLD.tier IS NOT NEW.tier OR OLD.namespace IS NOT NEW.namespace
  OR OLD.title IS NOT NEW.title OR OLD.content IS NOT NEW.content
  OR OLD.tags IS NOT NEW.tags OR OLD.priority IS NOT NEW.priority
  OR OLD.confidence IS NOT NEW.confidence OR OLD.source IS NOT NEW.source
  OR OLD.created_at IS NOT NEW.created_at OR OLD.updated_at IS NOT NEW.updated_at
  OR OLD.metadata IS NOT NEW.metadata OR OLD.reflection_depth IS NOT NEW.reflection_depth
  OR OLD.memory_kind IS NOT NEW.memory_kind OR OLD.entity_id IS NOT NEW.entity_id
  OR OLD.persona_version IS NOT NEW.persona_version OR OLD.citations IS NOT NEW.citations
  OR OLD.source_uri IS NOT NEW.source_uri OR OLD.source_span IS NOT NEW.source_span
  OR OLD.confidence_source IS NOT NEW.confidence_source
  OR OLD.confidence_signals IS NOT NEW.confidence_signals
  OR OLD.version IS NOT NEW.version OR OLD.lifecycle_state IS NOT NEW.lifecycle_state
  OR OLD.valid_from IS NOT NEW.valid_from
  OR OLD.valid_until IS NOT NEW.valid_until
  OR OLD.encrypted_envelope IS NOT NEW.encrypted_envelope
BEGIN
    UPDATE sync_seq_counter SET head = head + 1 WHERE id = 1;
    UPDATE memories SET sync_seq = (SELECT head FROM sync_seq_counter WHERE id = 1)
     WHERE id = NEW.id;
END;

-- Puller side: the per-(agent, peer) seq cursor, a sibling of `sync_state`
-- (precedent v99 `sync_peer_contact`), never a `sync_state` column. NULL
-- `last_seq` means "walk from after_seq=0"; it is never seeded from the
-- timestamp cursor. `seq_epoch` is the serving node's epoch the cursor was
-- taken under; a mismatch resets the walk to 0.
CREATE TABLE IF NOT EXISTS sync_pull_seq (
    agent_id   TEXT NOT NULL,
    peer_id    TEXT NOT NULL,
    last_seq   INTEGER CHECK (last_seq IS NULL OR last_seq >= 0),
    seq_epoch  TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, peer_id)
);
