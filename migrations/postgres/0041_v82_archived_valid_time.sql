-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #1834 / #2035 (schema v82) — mirror the claim-bitemporal
-- VALID-time columns onto archived_memories so archive → restore
-- round-trips valid_from / valid_until losslessly (the #1025 v49
-- archived-mirror precedent, here for the #1834 v79 `memories` columns).
--
-- Purely additive; idempotent `ADD COLUMN IF NOT EXISTS` (postgres has
-- the guard natively, unlike the sqlite twin which probes). RFC3339 TEXT,
-- matching the `memories.valid_from` / `valid_until` column type + the
-- sqlite archived_memories mirror. Nullable; NULL on legacy archived rows.
ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS valid_from TEXT;
ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS valid_until TEXT;
