-- v1.0.0 #2044 (#2032-A / H1 IDOR + M1 admin spoof) — per-agent api-key
-- principal binding.
--
-- The HTTP surface's `X-Agent-Id` header is a SELF-ASSERTED principal while the
-- `api_key` is only a SHARED transport credential, so any api-key-bearing caller
-- could act as / read another agent's data (H1) or assert admin (M1). This table
-- is the server-held secret that binds an asserted `X-Agent-Id: X` to proven
-- possession of agent X's enrolled per-agent api-key.
--
-- * `token_sha256` — lowercase hex SHA-256 of the per-agent api-key token. The
--                    RAW token is NEVER stored (only its digest), so a DB read
--                    cannot recover the bearer secret. PRIMARY KEY: one row per
--                    distinct token (a token maps to exactly one agent).
-- * `agent_id`     — the principal the presenting caller is bound to.
-- * `bound_at`     — RFC3339 enrollment timestamp (forensics).
--
-- Purely additive `CREATE TABLE IF NOT EXISTS` (replay-safe on both a fresh
-- install via the bootstrap SCHEMA and an upgrade via the v83 migration arm);
-- no full-table rebuild, so the v63/v65 trigger-drop hazard does not arise.

CREATE TABLE IF NOT EXISTS agent_api_keys (
    token_sha256 TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    bound_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_api_keys_agent ON agent_api_keys(agent_id);
