-- v74 (#1825, v0.9.0 G8) — additive, content-addressed BLAKE3
-- content-id (CID) for a memory's GENESIS identity (postgres mirror of
-- SQLite schema v74, `migrations/sqlite/0058_v74_memories_cid.sql`).
--
-- Adds two additive, nullable columns to `memories`:
--   * `cid`         TEXT  — the `b3:<hex>` content-address minted from
--                   the genesis identity. Sits ALONGSIDE the UUID `id`
--                   (still the PK / every FK / the federation LWW
--                   tiebreak) — a second, content-derived name.
--   * `cid_genesis` BYTEA — the canonical cid PRE-IMAGE bytes, read on
--                   demand by the verify path; NULLed on erasure
--                   (RecordKind::Forget) while `cid` is retained, so the
--                   stored content digest can't be a confirmation-oracle.
--
-- BLAKE3 is the OUTER address hash only; the inner content digest stays
-- SHA-256. Title + content are secret-screened MODE-INDEPENDENTLY before
-- hashing so federated nodes on different `AI_MEMORY_SECRET_SCREEN_MODE`
-- settings converge on the same cid. Postgres supports
-- `ADD COLUMN IF NOT EXISTS`, so this is a single idempotent DDL batch —
-- fresh installs inherit the columns inline from `postgres_schema.sql`;
-- pre-v74 deployments pick them up here via `PostgresStore::migrate_v74`.

ALTER TABLE memories ADD COLUMN IF NOT EXISTS cid TEXT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS cid_genesis BYTEA;
CREATE INDEX IF NOT EXISTS idx_memories_cid ON memories(cid);
