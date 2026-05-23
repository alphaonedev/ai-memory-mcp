-- v0.7.0 #1156 — per-namespace K8 quota dimension extension (schema v50).
--
-- v28 (file 0022_v07_agent_quotas.sql) shipped K8 with `agent_quotas
-- (agent_id PRIMARY KEY)`. That single-row-per-agent shape conflates
-- every namespace the agent writes into one accounting bucket: an
-- agent that is generous in their personal `alice/scratch` namespace
-- can starve their writes against a shared `team/policies` namespace
-- because the same daily counter caps both surfaces. The substrate
-- already routes namespace through every K8 call site (the field is
-- on the request DTO), so the only missing piece is the storage
-- dimension itself.
--
-- v50 extends the PK to `(agent_id, namespace)` so per-namespace
-- allotments hold even when a single agent operates across many
-- namespaces. The sentinel namespace string `_global` (a leading
-- underscore visibly separates it from user-supplied namespaces by
-- convention, even though `validate_namespace` does not strictly
-- reject `_`-prefixed identifiers) carries forward every
-- pre-v50 row's accounting verbatim, preserving the historical
-- accounting for every existing deployment. Callers that do not
-- supply a `namespace` argument continue to land on `_global`, so
-- the pre-#1156 behaviour is byte-for-byte preserved at the public
-- API boundary; per-namespace accounting is opt-in via the new
-- argument.
--
-- NSA CSI MCP mapping: this file backs NSA recommendation (c)
-- "Implement strict input validation and authorization checks" by
-- letting operators carve per-namespace blast-radius limits on a
-- compromised or misbehaving agent. Defense-in-depth on top of the
-- seven-layer DoS substrate already documented in
-- `docs/compliance/nsa-csi-mcp-security-mapping.md` (control
-- "recommendation-c" row).
--
-- Idempotency: SQLite does NOT allow altering an existing PRIMARY
-- KEY in place, so the migration runs through the canonical
-- shadow-table swap idiom: build the new table, copy rows over with
-- `namespace = '_global'`, drop the old, rename. The Rust arm
-- (`src/storage/migrations.rs::if version < 50`) probes for the
-- presence of the `namespace` column via `PRAGMA table_info` and
-- only sources this file when the migration is needed — re-applying
-- after a partial failure or a replay is a no-op via that
-- column-presence guard. The arm itself runs inside the BEGIN
-- EXCLUSIVE transaction that wraps the whole migrate() body.

-- 1. Build the v50-shape shadow table.
CREATE TABLE agent_quotas_v50_shadow (
    agent_id                TEXT NOT NULL,
    namespace               TEXT NOT NULL DEFAULT '_global',
    max_memories_per_day    INTEGER NOT NULL DEFAULT 1000,
    max_storage_bytes       INTEGER NOT NULL DEFAULT 104857600,
    max_links_per_day       INTEGER NOT NULL DEFAULT 5000,
    current_memories_today  INTEGER NOT NULL DEFAULT 0,
    current_storage_bytes   INTEGER NOT NULL DEFAULT 0,
    current_links_today     INTEGER NOT NULL DEFAULT 0,
    day_started_at          TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (agent_id, namespace)
);

-- 2. Copy every existing row to the '_global' namespace sentinel.
--    Preserves the historical accounting verbatim so no operator
--    loses their counters across the upgrade.
INSERT INTO agent_quotas_v50_shadow (
    agent_id,
    namespace,
    max_memories_per_day,
    max_storage_bytes,
    max_links_per_day,
    current_memories_today,
    current_storage_bytes,
    current_links_today,
    day_started_at,
    created_at,
    updated_at
)
SELECT
    agent_id,
    '_global',
    max_memories_per_day,
    max_storage_bytes,
    max_links_per_day,
    current_memories_today,
    current_storage_bytes,
    current_links_today,
    day_started_at,
    created_at,
    updated_at
FROM agent_quotas;

-- 3. Drop the old single-PK table.
DROP TABLE agent_quotas;

-- 4. Rename the shadow table into place.
ALTER TABLE agent_quotas_v50_shadow RENAME TO agent_quotas;

-- 5. Indexes.
--
--    * idx_agent_quotas_agent_id is preserved (point-lookup by
--      agent_id remains the hot path for list_status without a
--      namespace filter — used by the legacy aggregate view).
--
--    * idx_agent_quotas_namespace lights up per-namespace queries
--      that drive the new namespace-scoped status calls (the MCP
--      tool's optional `namespace` arg and the HTTP route's
--      `?namespace=` query parameter).
CREATE INDEX IF NOT EXISTS idx_agent_quotas_agent_id
    ON agent_quotas (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_quotas_namespace
    ON agent_quotas (namespace, agent_id);
