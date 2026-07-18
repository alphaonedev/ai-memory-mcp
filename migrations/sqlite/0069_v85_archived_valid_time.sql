-- v1.0.0 #2035 — archive→restore lossless round-trip for the #1834
-- claim-bitemporal VALID-time.
--
-- The v79/#1834 columns `memories.valid_from` / `memories.valid_until`
-- (RFC3339 TEXT; the half-open `[valid_from, valid_until)` interval a claim
-- is asserted to hold) were never mirrored onto `archived_memories`, so a
-- memory archived via GC eviction (archive_on_gc), explicit `forget`, or the
-- in_place_edit supersede snapshot — and later restored — came back with both
-- columns NULL, silently DROPPING the claim's validity interval. This is the
-- exact class of loss #1025 (schema v49) closed for the other 14 v0.7.0
-- Memory columns and #228/#1728 (v68) closed for `encrypted_envelope`:
-- archived_memories must mirror the full Memory shape for a lossless
-- archive→restore round-trip on both backends. The memory TEXT + all its
-- fields are the durable source of truth (North Star).
--
-- Additive only (`ALTER TABLE ... ADD COLUMN`), no table rebuild — so the
-- v63/v65 trigger-drop hazard does not arise (mirrors the v49/#1025 +
-- v84/#2167 archive-column-parity precedent). SQLite has no `ADD COLUMN IF
-- NOT EXISTS`, so `migrate()` applies these behind per-column existence
-- probes (the v18 `embedding_dim` / v84 `embedding_space` precedent); this
-- file is the canonical DDL. The archive INSERT...SELECT sites carry the two
-- columns directly (memories → archived_memories) and `restore_archived*`
-- re-insert them (archived_memories → memories), so the interval survives the
-- round-trip.

ALTER TABLE archived_memories ADD COLUMN valid_from TEXT;
ALTER TABLE archived_memories ADD COLUMN valid_until TEXT;
