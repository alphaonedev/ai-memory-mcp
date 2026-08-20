-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- enterprise-federation-repro — first-boot extension bootstrap.
--
-- Runs ONCE via the stock postgres image's /docker-entrypoint-initdb.d hook,
-- as the superuser, against the audit database (POSTGRES_DB). It creates ONLY
-- the two server extensions the ai-memory sal-postgres adapter needs:
--
--   * age    — Apache AGE 1.8.0 (property-graph over PostgreSQL).
--   * vector — pgvector 0.8.6 (the server-side `vector` column type the
--              sal-postgres adapter maps Rust embedding vectors to).
--
-- Both are IF NOT EXISTS so a re-run (or a warm data volume) is a no-op.
--
-- The AGE graph itself (create_graph('memory_graph')) is NOT created here:
-- `ai-memory schema-init` creates the app schema AND runs
-- `SELECT create_graph('memory_graph')` when the target store is Postgres +
-- AGE (repro.sh step 6). Splitting it keeps this bootstrap purely about the
-- extension binaries.
--
-- SCHEMA-PLACEMENT NOTE (audit finding #3055). An UNQUALIFIED `CREATE TABLE`
-- lands in whichever schema the connection's search_path resolves FIRST. If
-- ag_catalog precedes the app schema, ai-memory's own tables would be created
-- inside ag_catalog. This kit pins `public,ag_catalog` (public first) in the
-- store DSN's search_path, so ai-memory's tables live in `public` and AGE's
-- catalog objects remain reachable — the honest, load-bearing ordering.

CREATE EXTENSION IF NOT EXISTS age;
CREATE EXTENSION IF NOT EXISTS vector;
