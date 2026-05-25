-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.7.0 #1255 (MED) — federation nonce LRU persistence.
--
-- Pre-#1255 the `FederationNonceCache` lived purely in-process. A
-- daemon restart (operator-triggered upgrade, panic, SIGTERM by
-- supervisor, etc.) wiped the cache and re-opened a fresh
-- replay window: an attacker who captured a `(body, sig, nonce)`
-- tuple before the restart could re-submit it after the restart and
-- the freshly-empty cache would treat the nonce as never-seen.
--
-- This migration adds the `federation_nonce_cache` table so the
-- daemon can persist every `(peer_id, fingerprint)` pair to disk
-- and re-load it on the next boot. `fingerprint` is the 32-byte
-- SHA-256 over `(length-prefixed peer_id, length-prefixed nonce)`
-- produced by `FederationNonceCache::fingerprint`. `last_touch` is
-- a monotonic counter advanced on every `record_and_check`; the
-- outer-LRU peer-slot eviction picks the slot with the smallest
-- value, matching the in-memory shape verbatim.
--
-- The PRIMARY KEY is `(peer_id, fingerprint)` so a second observation
-- of the same `(peer_id, nonce)` pair is a no-op (the in-memory
-- check already returns Replay before we'd reach the INSERT).
-- `last_touch` is updated on every per-peer touch so the LRU
-- bookkeeping survives the restart too.
--
-- The supporting indexes serve the load-on-boot read path
-- (`SELECT peer_id, fingerprint FROM federation_nonce_cache ORDER
-- BY last_touch ASC`) and the eviction lookups (`SELECT peer_id
-- FROM federation_nonce_cache ORDER BY last_touch ASC LIMIT 1`).
--
-- Idempotent — re-applying this migration against an already-v51
-- DB is a no-op via the `IF NOT EXISTS` guards.

CREATE TABLE IF NOT EXISTS federation_nonce_cache (
    peer_id     TEXT NOT NULL,
    fingerprint BLOB NOT NULL,
    last_touch  INTEGER NOT NULL,
    inserted_at TEXT NOT NULL,
    PRIMARY KEY (peer_id, fingerprint)
) WITHOUT ROWID;

-- Per-peer ordered scans for FIFO eviction on per-peer-slot overflow.
CREATE INDEX IF NOT EXISTS idx_federation_nonce_cache_peer_touch
    ON federation_nonce_cache(peer_id, last_touch);

-- Outer LRU lookup across all peers (eviction picks the smallest
-- last_touch across the whole table when peer count exceeds the cap).
CREATE INDEX IF NOT EXISTS idx_federation_nonce_cache_touch
    ON federation_nonce_cache(last_touch);
