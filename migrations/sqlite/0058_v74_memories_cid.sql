-- v74 (#1825, v0.9.0 G8) — additive, content-addressed BLAKE3
-- content-id (CID) for a memory's GENESIS identity.
--
-- Adds two additive, nullable columns to `memories`:
--   * `cid`         TEXT — the `b3:<hex>` content-address minted from
--                   the genesis identity (`agent_id + namespace +
--                   screen(title) + memory_kind + created_at +
--                   SHA256(screen(content))`). Sits ALONGSIDE the UUID
--                   `id`, which stays the PK / every FK / the federation
--                   last-writer-wins tiebreak — the cid is a SECOND,
--                   content-derived name, never a replacement.
--   * `cid_genesis` BLOB — the canonical cid PRE-IMAGE bytes
--                   (`identity::cid::canonical_cid_preimage`), so the
--                   verify path can recompute the BLAKE3 address without
--                   re-reading (and re-screening) the row's plaintext.
--                   NULLed on erasure (RecordKind::Forget) — retaining
--                   `cid` but dropping the pre-image so the stored content
--                   digest can't become a confirmation-oracle for erased
--                   content.
--
-- BLAKE3 is the OUTER address hash only; the inner content term inside
-- the pre-image is SHA-256, as is the whole audit spine. `title` and
-- `content` are folded through `secret_screen::screen`
-- MODE-INDEPENDENTLY before hashing, so two federated nodes on different
-- `AI_MEMORY_SECRET_SCREEN_MODE` settings mint the SAME cid for the same
-- genesis (receive-time equivalence) and no recoverable credential ever
-- reaches the stored digest.
--
-- SQLite has no `ADD COLUMN IF NOT EXISTS` and can add only one column
-- per ALTER, so the migration ladder (`storage::migrations`) runs this
-- file only after a column-existence probe (the v73 pattern); fresh
-- installs inherit the columns inline from the bootstrap `SCHEMA` const.
-- Legacy rows keep `cid`/`cid_genesis` NULL until the v74 backfill
-- stamps the ones it can decrypt.

ALTER TABLE memories ADD COLUMN cid TEXT;
ALTER TABLE memories ADD COLUMN cid_genesis BLOB;
CREATE INDEX IF NOT EXISTS idx_memories_cid ON memories(cid);
