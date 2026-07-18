-- v1.0.0 #2167 — embedding vector-space provenance (postgres twin of the
-- sqlite v84 arm). Per-row identity token of the embedding space a stored
-- vector lives in: `<canonical_model_id>#<prefix_scheme>` (see
-- `EmbeddingSpace::mint`). NULL = legacy / unverified. Compared only as a
-- WHOLE value at recall time (the `AND embedding_space = $fp` predicate on
-- every `<=>` site) so a vector from a different embedding space can never be
-- scored against the live query — worst case is DEGRADED recall (excluded
-- until `reembed` regenerates from the durable text), never WRONG recall.
--
-- Replay-safe (`ADD COLUMN IF NOT EXISTS` x2, `CREATE INDEX IF NOT EXISTS`).
-- Ladder-owned index (#1861). Purely additive, no rewrite.

ALTER TABLE memories ADD COLUMN IF NOT EXISTS embedding_space TEXT;
ALTER TABLE archived_memories ADD COLUMN IF NOT EXISTS embedding_space TEXT;

CREATE INDEX IF NOT EXISTS idx_memories_embedding_space
    ON memories(embedding_space) WHERE embedding_space IS NOT NULL;
