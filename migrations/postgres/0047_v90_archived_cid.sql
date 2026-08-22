-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #2385 — schema v90 (POSTGRES twin): ARCHIVE CID PARITY.
--
-- See migrations/sqlite/0074_v90_archived_cid.sql for the full rationale.
-- In short: `archived_memories` never gained the v74 (#1825) genesis
-- content-id pair, so archive→restore RE-MINTED the BLAKE3 address from six
-- reconstructed inputs instead of carrying it. When any input drifted the
-- restored row silently changed identity and every `memory_links.source_cid`
-- / `target_cid` mirror dangled — identity corruption of the durable tier
-- with no write intent and no error.
--
-- Additive and idempotent (`IF NOT EXISTS`); no rewrite, no reindex, no
-- table lock beyond the catalogue update. Column types mirror
-- `memories.cid` / `memories.cid_genesis` on this backend (TEXT / BYTEA).
-- Pre-v90 archive rows keep NULL and keep the legacy re-mint fallback.

ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS cid TEXT;
ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS cid_genesis BYTEA;
