-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v94 (#3324, #3266 MVG, v1.0.0) — LIFECYCLE_STATE INDEX (Postgres).
--
-- Doc twin of `PostgresStore::migrate_v94` in `src/store/postgres.rs`. The
-- postgres parity of the sqlite v94 arm: an additive supporting index for the
-- system-only (hidden) lifecycle-state listings that filter
-- `WHERE lifecycle_state = ?` (`list_quarantined`, operator/curator review of
-- contaminated / tombstoned / quarantined rows).
--
-- The new `contaminated` lifecycle vocabulary is migration-free at the column
-- level (no CHECK constraint enumerates the states on either backend); the
-- fail-closed recall-visibility gate `lifecycle_visible_clause` — a literal
-- allow-list bound to nothing — is shared verbatim by both backends, so
-- `contaminated` is hidden identically on SQLite and Postgres with no schema
-- change. Additive, `IF NOT EXISTS`-idempotent, reversible.
CREATE INDEX IF NOT EXISTS idx_memories_lifecycle_state
    ON memories(lifecycle_state);
