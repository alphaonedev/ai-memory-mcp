-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3250 — schema v91 (POSTGRES twin): ARCHIVE-LINK CID PARITY.
--
-- See migrations/sqlite/0075_v91_archived_memory_links_cid.sql for the
-- full rationale. In short: `archived_memory_links` never gained the v75
-- (#1859) lineage-DAG `source_cid` / `target_cid` mirrors, so every
-- archive snapshot DROPPED them and restore re-inserted edges with NULL
-- CIDs. Additive and idempotent (`IF NOT EXISTS`); no rewrite, no
-- reindex. Column types mirror `memory_links.source_cid` / `target_cid`
-- on this backend (TEXT). Pre-v91 snapshot rows keep NULL and keep the
-- legacy restore fallback.

ALTER TABLE archived_memory_links ADD COLUMN IF NOT EXISTS source_cid TEXT;
ALTER TABLE archived_memory_links ADD COLUMN IF NOT EXISTS target_cid TEXT;
