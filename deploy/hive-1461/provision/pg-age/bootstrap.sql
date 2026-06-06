-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- Idempotent peer-DB bootstrap. Run as the postgres superuser with the
-- aimemory role password supplied out-of-band as the psql variable :pw
-- (NEVER hard-coded here):  psql -v pw="$AIMEMORY_PG_PASSWORD" -f bootstrap.sql
--
-- Creates the aimemory role + database, installs age + vector, and pins the
-- AGE-aware search_path. The ai-memory `schema-init` step (run separately)
-- then lays down the v55 application schema + the ai_memory_kg graph.

SELECT format('CREATE ROLE aimemory LOGIN PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimemory')
\gexec

SELECT 'CREATE DATABASE aimemory OWNER aimemory'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'aimemory')
\gexec

\connect aimemory

CREATE EXTENSION IF NOT EXISTS age;
CREATE EXTENSION IF NOT EXISTS vector;

GRANT USAGE ON SCHEMA ag_catalog TO aimemory;
GRANT ALL ON ALL TABLES IN SCHEMA ag_catalog TO aimemory;
ALTER DATABASE aimemory SET search_path = ag_catalog, "$user", public;
