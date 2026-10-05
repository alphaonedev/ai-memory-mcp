-- ai-memory — PgBouncer role-default timeouts (v0.8.0 Pillar-4 4.B, #1736).
--
-- ai-memory sets statement_timeout / lock_timeout per session in its sqlx
-- `after_connect` hook (src/store/postgres.rs). In `session` pool mode (the only
-- supported mode, #4667) each client keeps its own backend and that hook is
-- enough. Setting the same values as role defaults means a backend the client
-- did not itself configure starts with them too; it is the narrowing step in
-- docs/enterprise-deployment.md section 5.6.7 for deployments that ran
-- transaction mode, where those per-session SETs can land on another client's
-- backend.
--
-- search_path mirrors the path the adapter itself sets per session
-- (normalize_app_search_path in src/store/postgres.rs); docs/enterprise-deployment.md
-- section 5.6.7 step 3 prescribes the same three role defaults.
--
-- Values quote the binary's compiled defaults:
--   DEFAULT_STATEMENT_TIMEOUT_SECS = 30  (src/store/postgres.rs)
--   DEFAULT_LOCK_TIMEOUT_SECS      = 5   (src/store/postgres.rs)
-- If you tune AI_MEMORY_PG_* / postgres_statement_timeout_secs, mirror it here.
--
-- Run once against the REAL postgres backend (port 5432), as a superuser:
--   psql "postgres://postgres@postgres:5432/ai_memory" -f role-defaults.sql

ALTER ROLE ai_memory SET search_path = public, ag_catalog;
ALTER ROLE ai_memory SET statement_timeout = '30s';
ALTER ROLE ai_memory SET lock_timeout = '5s';
