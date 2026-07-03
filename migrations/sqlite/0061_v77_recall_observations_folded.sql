-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 P0-1 (#1869, schema v77) — recall purity: `folded` fold-state
-- column on the `recall_observations` ledger.
--
-- With recall PURE by default (zero writes to `memories` on any recall
-- path), the append-only ledger becomes the carrier of the access
-- signal and the periodic FOLD job (`db::fold_recall_accesses`)
-- batch-applies the legacy touch ladders (access_count bump,
-- last_accessed_at, per-tier TTL floor-extend, mid→long promotion,
-- priority decade ladder) from rows still `folded = 0`, marking them
-- `folded = 1` once applied. Rows written while the deprecated
-- `AI_MEMORY_RECALL_TOUCH_SYNC=1` legacy flag is ON are inserted
-- PRE-MARKED `folded = 1` (the recall already touched synchronously)
-- so the fold never double-counts.
--
-- BACKFILL: every pre-existing row is stamped `folded = 1` — those
-- rows were recorded in the sync-touch era, so their accesses were
-- already applied at recall time; folding them would double-count.
--
-- The partial index covers the fold's hot aggregate
-- (`... WHERE folded = 0 GROUP BY memory_id`) and stays near-empty in
-- steady state (folds every 60 s by default).
--
-- SQLite has no `ADD COLUMN IF NOT EXISTS`; the ladder arm probes the
-- column before executing this file (the v75 precedent), so replays
-- are safe.
ALTER TABLE recall_observations ADD COLUMN folded INTEGER NOT NULL DEFAULT 0;
UPDATE recall_observations SET folded = 1;
CREATE INDEX IF NOT EXISTS idx_recall_observations_unfolded
    ON recall_observations(memory_id) WHERE folded = 0;
