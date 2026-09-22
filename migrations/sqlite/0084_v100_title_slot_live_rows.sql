-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v100 (#3690 / #3695 / #3699, v1.0.0, data-integrity): the (title, namespace)
-- slot belongs to LIVE rows only.
--
-- Consolidation keeps each source as `lifecycle_state = 'tombstoned'` and,
-- under the FULL unique index, the hidden row kept its (title, namespace)
-- slot: a later `store` of the same title upserted INTO the tombstone — the
-- CLI printed an id, and get/list/recall never showed the text (#3690). The
-- index is now PARTIAL, excluding tombstoned rows (the #3690 5-agent vote,
-- Q1 5/5; Q4: `tombstoned` ONLY — quarantined / contaminated rows keep their
-- slot and the write funnels refuse them with a typed conflict, #3695).
-- The predicate is `models::TITLE_SLOT_INDEX_PREDICATE`; every
-- `ON CONFLICT(title, namespace)` target spells it so the statement keeps
-- matching this index. `lifecycle_state` is NOT NULL DEFAULT 'open', so the
-- predicate is NULL-safe. Rebuilt under the same name; idempotent (DROP IF
-- EXISTS + CREATE); reversible by recreating the full index once no live row
-- shares a title with a tombstone (NoLoss: no row is touched).
DROP INDEX IF EXISTS idx_memories_title_ns;
CREATE UNIQUE INDEX idx_memories_title_ns
    ON memories(title, namespace)
    WHERE lifecycle_state <> 'tombstoned';
