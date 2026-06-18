-- ai-memory — PgBouncer role-default timeouts (v0.8.0 Pillar-4 4.B, #1736).
--
-- The per-session statement_timeout / lock_timeout that ai-memory sets in its
-- sqlx `after_connect` hook (src/store/postgres.rs) do NOT survive PgBouncer's
-- inter-transaction `DISCARD ALL` under transaction-mode pooling — a pooled
-- backend is reset between transactions, dropping the session GUCs. The robust
-- path is server-side role defaults: set them on the role so every backend the
-- pooler hands out already carries them.
--
-- Values quote the binary's compiled defaults:
--   DEFAULT_STATEMENT_TIMEOUT_SECS = 30  (src/store/postgres.rs)
--   DEFAULT_LOCK_TIMEOUT_SECS      = 5   (src/store/postgres.rs)
-- If you tune AI_MEMORY_PG_* / postgres_statement_timeout_secs, mirror it here.
--
-- Run once against the REAL postgres backend (port 5432), as a superuser:
--   psql "postgres://postgres@postgres:5432/ai_memory" -f role-defaults.sql

ALTER ROLE ai_memory SET statement_timeout = '30s';
ALTER ROLE ai_memory SET lock_timeout = '5s';
