-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- One-shot init for the scoped LAN-parity test PG+AGE container.
-- Runs ONCE on first start (when /var/lib/postgresql/data is empty)
-- via the postgres image's /docker-entrypoint-initdb.d hook.
--
-- Provisions: AGE extension, pgvector extension, the `memory_graph`
-- AGE graph the SAL postgres adapter expects, and per-IronClaw
-- schemas so alice + bob can share the same database without their
-- row sets colliding.

-- AGE is auto-created by the upstream apache/age image's own
-- 00-create-extension-age.sql before this file runs; no need
-- to re-create it. pgvector comes from the local Dockerfile
-- layer (postgresql-16-pgvector).
CREATE EXTENSION IF NOT EXISTS vector;

LOAD 'age';
SET search_path = ag_catalog, "$user", public;
SELECT create_graph('memory_graph');

-- Per-IronClaw search-path schemas so alice + bob coexist cleanly.
CREATE SCHEMA IF NOT EXISTS ic_alice;
CREATE SCHEMA IF NOT EXISTS ic_bob;

-- Grant the test user full access to everything it just provisioned.
GRANT ALL PRIVILEGES ON DATABASE ai_memory_test TO ai_memory;
GRANT ALL PRIVILEGES ON SCHEMA public, ic_alice, ic_bob, ag_catalog TO ai_memory;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ag_catalog TO ai_memory;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ag_catalog TO ai_memory;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA ag_catalog TO ai_memory;
