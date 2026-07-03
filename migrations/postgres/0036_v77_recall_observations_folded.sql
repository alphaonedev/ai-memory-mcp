-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 P0-1 (#1869, schema v77) — recall purity: `folded` fold-state
-- column on `recall_observations` (postgres mirror of
-- migrations/sqlite/0061_v77_recall_observations_folded.sql; see that
-- file for the full design rationale).
--
-- BOOLEAN (not INTEGER) to match this backend's `consumed` column
-- convention. The BACKFILL (`UPDATE recall_observations SET folded =
-- TRUE`) lives in the probe-guarded Rust arm (`migrate_v77`), NOT in
-- this replay-safe DDL file: pre-existing rows were recorded in the
-- sync-touch era and already applied at recall time — folding them
-- would double-count — but re-running the UPDATE after the column
-- exists would wrongly re-mark rows the fold has not yet consumed, so
-- it fires only when the probe says the column was just added.
--
-- Fresh installs carry the column + partial index inline from
-- src/store/postgres_schema.sql; existing schemas pick them up here
-- via migrate_v77().
ALTER TABLE recall_observations
    ADD COLUMN IF NOT EXISTS folded BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_recall_observations_unfolded
    ON recall_observations(memory_id) WHERE NOT folded;
