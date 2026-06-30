-- v72 (#1823, v0.9.0 G6) — append-only spine: the `memory_revisions`
-- signed identity-only revision ledger (postgres mirror of the sqlite
-- v72 arm). One signed leaf per supersede / tombstone / forget /
-- archive / expire / evict / consolidate transition. IDENTITY-ONLY and
-- NEVER content (a content fingerprint would re-leak an erased row —
-- the `forget_tombstones` posture). `prev_hash` + `sequence` mirror
-- `signed_events` so the ledger is a verifiable hash chain.
--
-- PURE ADDITIVE `CREATE TABLE IF NOT EXISTS`.
CREATE TABLE IF NOT EXISTS memory_revisions (
    id            TEXT PRIMARY KEY,
    memory_id     TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN (
                      'SUPERSEDE', 'TOMBSTONE', 'FORGET', 'ARCHIVE',
                      'EXPIRE', 'EVICT', 'CONSOLIDATE'
                  )),
    prior_version BIGINT,
    namespace     TEXT NOT NULL,
    agent_id      TEXT,
    created_at    TEXT NOT NULL,
    signature     BYTEA,
    prev_hash     BYTEA NOT NULL,
    sequence      BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS memory_revisions_memory_id_idx
    ON memory_revisions(memory_id);
CREATE UNIQUE INDEX IF NOT EXISTS memory_revisions_sequence_idx
    ON memory_revisions(sequence);
