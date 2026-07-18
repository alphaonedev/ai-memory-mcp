-- v1.0.0 #2035 — archive→restore lossless round-trip for the #1834
-- claim-bitemporal VALID-time (postgres twin of the sqlite v85 arm).
--
-- The v79/#1834 columns `memories.valid_from` / `memories.valid_until`
-- (RFC3339 TEXT; the half-open `[valid_from, valid_until)` interval a claim
-- is asserted to hold) were never mirrored onto `archived_memories`, so a
-- memory archived via GC eviction (archive_on_gc), explicit `forget`, or the
-- in_place_edit supersede snapshot — and later restored — came back with both
-- columns NULL, silently DROPPING the claim's validity interval. This is the
-- exact class of loss #1025 (schema v49) closed for the other 14 v0.7.0
-- Memory columns and #228/#1728 (v68) closed for `encrypted_envelope`.
--
-- Replay-safe (`ADD COLUMN IF NOT EXISTS` x2). Purely additive, no rewrite.
-- The archive INSERT...SELECT sites carry the two columns directly (memories
-- → archived_memories) and the restore INSERT...SELECT re-inserts them
-- (archived_memories → memories), so the interval survives the round-trip.

ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS valid_from TEXT;
ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS valid_until TEXT;
