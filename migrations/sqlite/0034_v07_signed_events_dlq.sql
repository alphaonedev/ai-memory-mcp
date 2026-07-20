-- v0.7.0 Cluster-C SEC-3 closeout (issue #767) — `signed_events_dlq`
-- dead-letter queue for the deferred-audit drainer.
--
-- # Why a DLQ at all
--
-- The deferred-audit drainer (`src/governance/deferred_audit.rs`) is
-- the only path that promotes storage-hook `governance.refusal`
-- events into the `signed_events` cryptographic chain. Pre-Cluster-C
-- the drainer dropped failed appends silently: a SQLITE_BUSY,
-- SQLITE_CONSTRAINT_UNIQUE (chain-head race), or any other rusqlite
-- error logged at `tracing::error!`, incremented the metric counter,
-- and proceeded to the next event. The audit chain ROW for that
-- refusal was permanently lost — the exact failure mode the
-- chain-log primitive exists to prevent.
--
-- The current sink handles failures in two stages:
--
--   * `SQLITE_CONSTRAINT_UNIQUE` on the `idx_signed_events_sequence`
--     UNIQUE index: retry within the same append call, up to the
--     bounded retry budget. BEGIN IMMEDIATE serialises each fresh
--     residence check + append attempt against the WAL write lock.
--
--   * On retry exhaustion or a non-race chain error, attempt to land
--     in `signed_events_dlq` for chain-aware operator disposition.
--     If that INSERT also fails, append returns an error; on the
--     journal-backed production path the already-admitted spool
--     record remains for recovery. A successful DLQ row carries the
--     failure reason observed at landing time.
--
-- # Why a SQL table (not a JSONL file)
--
-- - The DLQ is queryable through the capabilities live-depth signal
--   and direct operator inspection.
-- - The drainer already owns a SQLite Connection; landing a row in
--   the same DB is one INSERT, no extra I/O surface.
-- - JSONL would couple the DLQ to the audit-log path's append-only
--   chflags semantics — which is the wrong primitive (the DLQ is
--   recoverable / mutable; the audit log is not).
-- - v1.0.0 ships no replay CLI or automatic replay sweep. Operators
--   preserve these rows and escalate for chain-aware disposition;
--   ad hoc copy/delete SQL is not a supported recovery procedure.
--
-- # Columns
--
-- Mirrors `signed_events` 1:1 for the would-be-chain-log fields
-- (`id` / `agent_id` / `event_type` / `payload_hash` / `signature` /
-- `attest_level` / `timestamp`) so the failed `SignedEvent` inputs remain
-- inspectable for possible chain-aware disposition. The original refusal
-- payload is not stored here, and v1.0.0 exposes no supported replay
-- procedure. Adds:
--
-- * `dlq_id`         — INTEGER PRIMARY KEY AUTOINCREMENT. Distinct
--                      from `id` because two failed attempts to
--                      append the SAME logical event (rare but
--                      possible if the supervisor restarts mid-DLQ)
--                      must not collide on the UUIDv4.
-- * `failure_reason` — TEXT, rusqlite error string at time of DLQ
--                      landing. Operator-readable; not parsed.
-- * `failed_at`      — TEXT, RFC3339 UTC instant the DLQ row was
--                      written. Distinct from `timestamp` (which is
--                      the original event time) so the auditor can
--                      tell "event was at T0, failed to chain-log at
--                      T1".
--
-- # Append-only invariant — NOT enforced for the DLQ
--
-- Unlike `signed_events`, the schema does not enforce append-only
-- storage or chain-hash DLQ rows. v1.0.0 provides no supported replay
-- or deletion command, so operators preserve rows until an explicit
-- chain-aware disposition. The property is "a successful DLQ landing
-- is observable", not "DLQ rows are tamper-evident".

CREATE TABLE IF NOT EXISTS signed_events_dlq (
    dlq_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    id              TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload_hash    BLOB NOT NULL,
    signature       BLOB,
    attest_level    TEXT NOT NULL DEFAULT 'unsigned',
    timestamp       TEXT NOT NULL,
    failure_reason  TEXT NOT NULL,
    failed_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signed_events_dlq_failed_at
    ON signed_events_dlq(failed_at);
CREATE INDEX IF NOT EXISTS idx_signed_events_dlq_agent
    ON signed_events_dlq(agent_id);
