-- v0.7.0 Track D #933 closeout — `federation_push_dlq` dead-letter
-- queue for the quorum-broadcast fanout (Postgres counterpart to the
-- SQLite v48 migration at `migrations/sqlite/0041_v07_federation_push_dlq.sql`).
--
-- # Why a DLQ at all
--
-- `broadcast_store_quorum` fans a just-committed write out to every
-- configured peer. Pre-#933, when a peer was down or slow:
--
--   * If the leader's local commit succeeded but quorum was NOT met
--     (timeout / unreachable), the HTTP write returned `503
--     quorum_not_met` and NOTHING captured the per-peer push that
--     failed. On the peer's recovery, the catchup loop (`spawn_catchup_
--     loop`) pulls rows the peer is BEHIND on but the leader never
--     re-attempts the original push. Cross-recall consistency after
--     restart only worked when both daemons shared a postgres store
--     (Track B finding #925 masked the gap).
--
--   * If quorum WAS met (e.g. W=1 and the leader counts) but one or
--     more peers in the fanout silently 5xx'd or hung past the
--     deadline, those peers also stayed permanently behind.
--
-- The Track D finding (verdict memory `2f0151a3-...` in
-- `ai-memory/v0.7.0-nhi-testing`) called this an unbounded silent-data-
-- loss surface. This DLQ closes it: every per-peer fanout failure (Ack
-- != Ack OR no-response-before-deadline) lands a row, and the
-- `replay_federation_push_dlq` worker (spawned alongside the catchup
-- loop in `daemon_runtime::spawn_catchup_loop_with_store`) polls every
-- N seconds and re-attempts `post_once` against each peer, clearing
-- rows on Ack.
--
-- # Columns
--
-- * `id`             — BIGSERIAL surrogate primary key. Two failed
--                      attempts to push the SAME `(memory_id, peer_id)`
--                      both land their own rows; the replay worker
--                      DELETEs by `id` on success and the partial
--                      unique constraint `(memory_id, peer_id) WHERE
--                      replayed_at IS NULL` prevents unbounded growth
--                      from a wedged-peer flapping case.
-- * `memory_id`      — TEXT, the `Memory.id` whose fanout failed.
--                      NOT a FK to `memories(id)` so a DLQ row survives
--                      the row being deleted upstream (the audit
--                      property the DLQ provides is "every fanout
--                      failure is observable", independent of
--                      memory-row lifecycle).
-- * `peer_id`        — TEXT, the `PeerEndpoint.id` (typically the
--                      peer's sync_push URL or mTLS fingerprint).
-- * `payload_json`   — JSONB, the exact body that was POSTed. Captured
--                      at DLQ-write time so a replay always re-POSTs
--                      the same shape even if `Memory` row evolves on
--                      the leader between the original push and the
--                      replay window.
-- * `attempt_count`  — INTEGER, incremented by the replay worker on
--                      each failed replay. Operators alert on
--                      attempt_count high-water (a peer permanently
--                      down keeps stacking rows; a transient gap
--                      converges to attempt_count <= 1).
-- * `last_error`     — TEXT, the most recent failure reason
--                      (rusqlite-style operator string; not parsed).
-- * `failed_at`      — TIMESTAMPTZ, when the row was first inserted
--                      (original fanout failure time).
-- * `replayed_at`    — TIMESTAMPTZ NULL, set by the replay worker to
--                      the moment the push finally Acked. Rows with
--                      `replayed_at IS NULL` are pending; with it set
--                      the row is a historical receipt the operator
--                      can prune at will.
--
-- # Append-only invariant — NOT enforced for the DLQ
--
-- Unlike `signed_events`, this DLQ is mutable: the replay worker
-- UPDATEs attempt_count + last_error on each retry and DELETEs (or
-- stamps `replayed_at`) on Ack. The integrity property the DLQ
-- provides is "no fanout failure is silent", not "DLQ rows are tamper-
-- evident".

CREATE TABLE IF NOT EXISTS federation_push_dlq (
    id             BIGSERIAL PRIMARY KEY,
    memory_id      TEXT NOT NULL,
    peer_id        TEXT NOT NULL,
    payload_json   JSONB NOT NULL,
    attempt_count  INTEGER NOT NULL DEFAULT 1,
    last_error     TEXT NOT NULL,
    failed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    replayed_at    TIMESTAMPTZ NULL
);

-- Index supporting the replay worker's "pending rows" scan
-- (`SELECT ... WHERE replayed_at IS NULL ORDER BY failed_at LIMIT N`).
CREATE INDEX IF NOT EXISTS idx_federation_push_dlq_pending_failed_at
    ON federation_push_dlq(failed_at)
    WHERE replayed_at IS NULL;

-- Index supporting the per-peer scan operators use to drive
-- `federation_push_dlq_depth{peer="…"}` alerts.
CREATE INDEX IF NOT EXISTS idx_federation_push_dlq_peer_pending
    ON federation_push_dlq(peer_id)
    WHERE replayed_at IS NULL;

-- Partial uniqueness on `(memory_id, peer_id)` for pending rows so a
-- flapping peer (10 failed pushes for the same memory in 30s) doesn't
-- accumulate 10 rows. The INSERT path uses ON CONFLICT to bump
-- attempt_count + refresh last_error instead.
CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_push_dlq_pending_uniq
    ON federation_push_dlq(memory_id, peer_id)
    WHERE replayed_at IS NULL;
