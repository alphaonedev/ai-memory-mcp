-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 Pillar-2 (Typed Cognition, #1709) — schema v63. Extend the
-- closed `memory_links.relation` CHECK taxonomy with the three
-- typed-cognition wiring relations that bind the Goal/Plan/Step
-- MemoryKind vocabulary (landed in commit 466a7c96) into a typed
-- plan graph:
--
--   * decomposes_into — a parent breaks down into children (a Goal
--     decomposes_into Plans; a Plan decomposes_into Steps). Parent ->
--     child structural edge.
--   * depends_on       — an ordering / prerequisite edge between
--     siblings (a Step depends_on another Step). Dependent ->
--     prerequisite. The memory-link-vocab analogue of the action-DAG
--     EdgeType::Requires concept; it does NOT touch or duplicate that
--     executable-graph enum.
--   * advances          — a child contributes progress toward an
--     ancestor (a Step advances a Plan/Goal). Child -> ancestor.
--
-- Result: the closed taxonomy grows 6 -> 9 relations. The set MUST
-- stay byte-identical to `crate::validate::VALID_RELATIONS`,
-- `crate::models::MemoryLinkRelation::as_str`, the bootstrap SCHEMA
-- const in `src/storage/migrations.rs`, and the postgres CHECK in
-- `src/store/postgres_schema.sql` / `migrate_v63` — any drift between
-- them surfaces as migration / validation breakage.
--
-- SQLite has no `ALTER TABLE ADD CONSTRAINT CHECK` for an existing
-- column-level CHECK clause, so we full-table-rebuild — the identical
-- dance the v33 rebuild (0027) and the v36 `derives_from` extension
-- (0030 / MIGRATION_V36_REBUILD_LINKS_SQL) performed before us:
--   1. CREATE TABLE memory_links_v63 with the CURRENT column set + the
--      EXTENDED 9-relation CHECK.
--   2. INSERT ... SELECT the explicit column list (NOT `SELECT *`).
--   3. DROP the triggers + indexes the rebuild would otherwise orphan.
--   4. DROP TABLE memory_links.
--   5. ALTER TABLE memory_links_v63 RENAME TO memory_links.
--   6. Recreate every index the rebuild dropped.
--   7. Recreate the attest_level enforcement triggers (the column-level
--      CHECK only covers `relation`, so attest_level still rides on the
--      BEFORE INSERT/UPDATE RAISE triggers — same as v33/v36).
--
-- The rebuild names the new table memory_links_v63 only for the
-- duration of the batch, so this migration is replay-safe. Pre-existing
-- rows are preserved verbatim — the INSERT ... SELECT only widens the
-- accepted set, so no legacy row can violate the new CHECK.

-- Step 1: new table — column set verbatim from the bootstrap SCHEMA
-- `memory_links` block (source_id, target_id, relation, created_at,
-- valid_from, valid_until, observed_by, signature, attest_level +
-- PRIMARY KEY) with the EXTENDED 9-relation CHECK.
CREATE TABLE memory_links_v63 (
    source_id    TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    target_id    TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    relation     TEXT NOT NULL DEFAULT 'related_to',
    created_at   TEXT NOT NULL,
    valid_from   TEXT,
    valid_until  TEXT,
    observed_by  TEXT,
    signature    BLOB,
    attest_level TEXT,
    PRIMARY KEY (source_id, target_id, relation),
    CHECK (relation IN ('related_to', 'supersedes', 'contradicts',
                        'derived_from', 'reflects_on', 'derives_from',
                        'decomposes_into', 'depends_on', 'advances'))
);

-- Step 2: copy rows with an EXPLICIT column list (not `SELECT *`) so a
-- future column add cannot silently mis-map the INSERT.
INSERT INTO memory_links_v63 (
    source_id, target_id, relation, created_at,
    valid_from, valid_until, observed_by, signature, attest_level
)
SELECT
    source_id, target_id, relation, created_at,
    valid_from, valid_until, observed_by, signature, attest_level
FROM memory_links;

-- Step 3: drop the triggers + indexes the rebuild would orphan. SQLite
-- drops table-attached triggers when the table is dropped, but the
-- explicit DROP IF EXISTS keeps the intent visible and the migration
-- replayable.
--
-- The legacy v23 RAISE triggers `memory_links_ck_relation_ins` /
-- `_upd` (migration 0023) enforce the OLD six-relation set with a
-- `RAISE(ABORT, ...)`. The v33 rebuild (0027) was meant to retire them
-- in favour of the column-level CHECK, but on the fresh-install ladder
-- they can survive (re-created by the v23 arm, table-rename leaves them
-- detached). If they survive into v63 they would refuse the three new
-- typed-cognition relations even though the column CHECK now admits
-- them — so drop them here. The column-level CHECK is the sole
-- relation gate post-v63.
DROP TRIGGER IF EXISTS memory_links_ck_relation_ins;
DROP TRIGGER IF EXISTS memory_links_ck_relation_upd;
DROP TRIGGER IF EXISTS memory_links_ck_attest_level_ins;
DROP TRIGGER IF EXISTS memory_links_ck_attest_level_upd;

DROP INDEX IF EXISTS idx_links_temporal_src;
DROP INDEX IF EXISTS idx_links_temporal_tgt;
DROP INDEX IF EXISTS idx_links_relation;
DROP INDEX IF EXISTS idx_memory_links_attest_level;

-- Step 4: drop the old table.
DROP TABLE memory_links;

-- Step 5: rename the new table into place.
ALTER TABLE memory_links_v63 RENAME TO memory_links;

-- Step 6: recreate every index the rebuild dropped (idempotent guard
-- preserves replay safety).
CREATE INDEX IF NOT EXISTS idx_links_temporal_src
    ON memory_links (source_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_links_temporal_tgt
    ON memory_links (target_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_links_relation
    ON memory_links (relation, valid_from);
CREATE INDEX IF NOT EXISTS idx_memory_links_attest_level
    ON memory_links (attest_level, created_at);

-- Step 7: recreate the attest_level enforcement triggers (the
-- column-level CHECK only covers `relation`).
CREATE TRIGGER IF NOT EXISTS memory_links_ck_attest_level_ins
BEFORE INSERT ON memory_links
FOR EACH ROW
WHEN NEW.attest_level IS NOT NULL
  AND NEW.attest_level NOT IN ('unsigned', 'self_signed', 'peer_attested')
BEGIN
    SELECT RAISE(ABORT, 'CHECK constraint failed: memory_links.attest_level must be one of unsigned/self_signed/peer_attested (or NULL for legacy rows)');
END;

CREATE TRIGGER IF NOT EXISTS memory_links_ck_attest_level_upd
BEFORE UPDATE OF attest_level ON memory_links
FOR EACH ROW
WHEN NEW.attest_level IS NOT NULL
  AND NEW.attest_level NOT IN ('unsigned', 'self_signed', 'peer_attested')
BEGIN
    SELECT RAISE(ABORT, 'CHECK constraint failed: memory_links.attest_level must be one of unsigned/self_signed/peer_attested (or NULL for legacy rows)');
END;
