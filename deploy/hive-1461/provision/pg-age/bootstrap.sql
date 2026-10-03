-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- Idempotent peer-DB bootstrap. Run as the postgres superuser with the
-- aimemory role password supplied out-of-band in the AIMEMORY_PW environment
-- variable (NEVER hard-coded here, and never a `-v pw=...` argv word, which any
-- local user can read from the process list, #4617):
--   AIMEMORY_PW="$AIMEMORY_PG_PASSWORD" psql -f bootstrap.sql   (psql >= 15)
--
-- Creates the aimemory role + database, installs age + vector, and pins the
-- AGE-aware search_path. The ai-memory `schema-init` step (run separately)
-- then lays down the v55 application schema + the ai_memory_kg graph.

\getenv pw AIMEMORY_PW

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

-- ai-memory's schema-init issues UNqualified `CREATE TABLE memories ...` etc.,
-- which land in the FIRST writable schema on search_path. public must therefore
-- come before ag_catalog, and aimemory needs CREATE on public (PG16 strips the
-- implicit public-CREATE grant from non-owners). ag_catalog stays LAST so AGE
-- agtype/cypher function + type resolution still scans it -- function/type
-- lookup walks the whole search_path, so trailing placement is sufficient.
GRANT USAGE, CREATE ON SCHEMA public TO aimemory;
ALTER DATABASE aimemory SET search_path = "$user", public, ag_catalog;
