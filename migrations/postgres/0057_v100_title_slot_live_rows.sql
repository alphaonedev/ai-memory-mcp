-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v100 (#3690 / #3695 / #3699, v1.0.0, data-integrity): the (title, namespace)
-- slot belongs to LIVE rows only — the postgres twin of
-- migrations/sqlite/0084_v100_title_slot_live_rows.sql. See that file for the
-- defect and the ruling; the predicate is `models::TITLE_SLOT_INDEX_PREDICATE`
-- and every `ON CONFLICT (title, namespace)` target spells it. Rebuilt under
-- the same name inside the migration transaction; idempotent; NoLoss.
DROP INDEX IF EXISTS memories_title_ns_uidx;
CREATE UNIQUE INDEX memories_title_ns_uidx
    ON memories (title, namespace)
    WHERE lifecycle_state <> 'tombstoned';
