-- v1.0.0 #2167 — embedding vector-space provenance.
--
-- Per-row identity token of the embedding space a stored vector lives in:
-- `<canonical_model_id>#<prefix_scheme>` (see `EmbeddingSpace::mint`). NULL =
-- legacy / unverified (no provenance was recorded when the row was written).
-- The token is compared only as a WHOLE value at recall time so a vector from
-- a different embedding space (a same-dim model swap) can never be scored
-- against the live query — worst case is DEGRADED recall (excluded until
-- `reembed` regenerates the vector from the durable text), never WRONG recall.
--
-- Additive only (`ALTER TABLE ... ADD COLUMN`), no table rebuild — so the
-- v63/v65 trigger-drop hazard does not arise. The G13 BLOB embedding header is
-- untouched (a variable-length string would break `decode_embedding_blob`'s
-- `len % 4` legacy discrimination). SQLite has no `ADD COLUMN IF NOT EXISTS`,
-- so `migrate()` applies these behind a column-existence probe (the v18
-- `embedding_dim` precedent); the partial index is ladder-owned (created
-- unconditionally with `IF NOT EXISTS` so both the fresh-install and
-- legacy-upgrade paths converge — the #1861 lesson).

ALTER TABLE memories ADD COLUMN embedding_space TEXT;            -- NULL = legacy/unverified
ALTER TABLE archived_memories ADD COLUMN embedding_space TEXT;

CREATE INDEX IF NOT EXISTS idx_memories_embedding_space
    ON memories(embedding_space) WHERE embedding_space IS NOT NULL;
