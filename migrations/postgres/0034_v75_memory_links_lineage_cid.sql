-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 G13-mem (#1859, schema v75) — memory-derivation lineage-DAG
-- (postgres mirror of the sqlite v75 arm). Additive content-id mirror
-- columns on `memory_links`: `source_cid` / `target_cid` carry the
-- `b3:<hex>` content-address (schema v74 `memories.cid`) of each endpoint
-- at link-creation time so a lineage traversal resolves stable node
-- identity even after a source memory is tombstoned. NULL when the endpoint
-- carried no cid (legacy rows); the query layer LEFT JOINs `memories.cid`.
-- The lineage-DAG is a VIEW over the provenance subset P = {derived_from,
-- reflects_on, derives_from} of the existing closed `relation` set — this
-- migration adds NO new relation. Postgres supports `ADD COLUMN IF NOT
-- EXISTS`, so the DDL is a single idempotent batch.
ALTER TABLE memory_links ADD COLUMN IF NOT EXISTS source_cid TEXT;
ALTER TABLE memory_links ADD COLUMN IF NOT EXISTS target_cid TEXT;

CREATE INDEX IF NOT EXISTS memory_links_target_cid_idx ON memory_links (target_cid);

-- v0.9.0 G13-mem (#1859) repair: drop the STALE narrow v32 relation CHECK
-- if this database carries it ALONGSIDE the extended
-- `memory_links_relation_check_wt1a`. Fresh installs bootstrapped from
-- postgres_schema.sql and then replayed the ladder from version 0, where
-- the pre-#1859 v32 arm re-added the narrow 5-relation constraint the 0017
-- upgrade then skipped (its probe found wt1a already present) — leaving
-- BOTH constraints and refusing every post-v32 relation. Every database
-- reaching v75 carries the wt1a(9) form (v63 guarantees it), so dropping
-- the narrow name is always safe and idempotent.
ALTER TABLE memory_links DROP CONSTRAINT IF EXISTS memory_links_relation_check;
