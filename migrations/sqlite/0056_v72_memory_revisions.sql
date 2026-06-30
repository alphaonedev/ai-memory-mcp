-- v72 (#1823, v0.9.0 G6) — append-only spine: the `memory_revisions`
-- signed identity-only revision ledger.
--
-- One signed leaf is appended here for every supersede / tombstone /
-- forget / archive / expire / evict / consolidate transition that the
-- (step 2+) append-only write paths will route through
-- `append_revision_leaf`. The table is IDENTITY-ONLY and NEVER carries
-- memory content (a content fingerprint would re-leak an erased row —
-- the same posture as `forget_tombstones`). The `prev_hash` + `sequence`
-- columns mirror `signed_events` so the ledger is a verifiable hash
-- chain an auditor can replay from the stored columns alone.
--
-- PURE ADDITIVE `CREATE TABLE IF NOT EXISTS` — NO full-table rebuild (a
-- rebuild silently drops every trigger; the v63 -> v65 lesson). Also
-- inline in the bootstrap `SCHEMA` const so fresh DBs have it.
CREATE TABLE IF NOT EXISTS memory_revisions (
    id            TEXT PRIMARY KEY,
    memory_id     TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN (
                      'SUPERSEDE', 'TOMBSTONE', 'FORGET', 'ARCHIVE',
                      'EXPIRE', 'EVICT', 'CONSOLIDATE'
                  )),
    prior_version INTEGER,
    namespace     TEXT NOT NULL,
    agent_id      TEXT,
    created_at    TEXT NOT NULL,
    signature     BLOB,
    prev_hash     BLOB NOT NULL,
    sequence      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_revisions_memory_id
    ON memory_revisions(memory_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_revisions_sequence
    ON memory_revisions(sequence);
