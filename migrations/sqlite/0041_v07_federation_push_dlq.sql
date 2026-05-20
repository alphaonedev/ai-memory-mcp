-- v0.7.0 Track D #933 closeout — `federation_push_dlq` dead-letter
-- queue for the quorum-broadcast fanout.
--
-- See the Postgres counterpart (`migrations/postgres/0030_v07_federation_push_dlq.sql`)
-- for the full design rationale (why-a-DLQ, why-mutable, replay
-- worker contract). This file ships the SQLite-native column types
-- (TEXT for JSON blobs, INTEGER PK AUTOINCREMENT for the surrogate
-- key, TEXT for timestamps — matches `signed_events_dlq` from
-- migration v40).
--
-- # Mechanics
--
-- * `id`             — INTEGER PRIMARY KEY AUTOINCREMENT, surrogate
--                      key.
-- * `memory_id`      — TEXT, the `Memory.id` whose fanout failed. NOT
--                      a FK to `memories(id)` so the DLQ survives
--                      memory-row deletion upstream.
-- * `peer_id`        — TEXT, the `PeerEndpoint.id`.
-- * `payload_json`   — TEXT (JSON-shaped), the exact body that was
--                      POSTed. Captured at DLQ-write time.
-- * `attempt_count`  — INTEGER, bumped on each replay attempt.
-- * `last_error`     — TEXT, most recent failure reason.
-- * `failed_at`      — TEXT, RFC3339 UTC instant the row was first
--                      written.
-- * `replayed_at`    — TEXT NULL, set when the replay worker observes
--                      an Ack.
--
-- Partial unique index on `(memory_id, peer_id) WHERE replayed_at IS
-- NULL` prevents a flapping peer from stacking duplicate pending rows
-- — the INSERT path uses `ON CONFLICT(memory_id, peer_id) DO UPDATE`
-- to bump attempt_count instead.

CREATE TABLE IF NOT EXISTS federation_push_dlq (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id      TEXT NOT NULL,
    peer_id        TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    attempt_count  INTEGER NOT NULL DEFAULT 1,
    last_error     TEXT NOT NULL,
    failed_at      TEXT NOT NULL,
    replayed_at    TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_federation_push_dlq_pending_failed_at
    ON federation_push_dlq(failed_at)
    WHERE replayed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_federation_push_dlq_peer_pending
    ON federation_push_dlq(peer_id)
    WHERE replayed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_push_dlq_pending_uniq
    ON federation_push_dlq(memory_id, peer_id)
    WHERE replayed_at IS NULL;
