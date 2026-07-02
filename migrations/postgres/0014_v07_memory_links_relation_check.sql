-- v0.7.0 v0.7.1-fold (#687/#688) — promote `memory_links.relation`
-- validation to a SQL-side CHECK constraint on the Postgres backend.
--
-- Mirrors migrations/sqlite/0027_v07_memory_links_relation_check.sql
-- (schema v33). Postgres supports `ALTER TABLE ADD CONSTRAINT` for
-- CHECK clauses directly, so the rebuild dance the SQLite migration
-- performs is not required here.
--
-- Closed taxonomy mirrors `crate::validate::VALID_RELATIONS` exactly:
--   related_to / supersedes / contradicts / derived_from / reflects_on
--
-- Idempotent: the `DO $$ ... $$` block checks pg_constraint before
-- adding the constraint so re-running the migration is a no-op.

-- v0.9.0 G13-mem (#1859) hardening: ALSO skip when the EXTENDED
-- `memory_links_relation_check_wt1a` constraint is already present. A
-- fresh install bootstraps the wt1a form inline from postgres_schema.sql
-- and then replays this ladder from version 0; pre-#1859 this arm re-added
-- the narrow 5-relation constraint ALONGSIDE wt1a, silently refusing every
-- post-v32 relation (`derives_from` / `decomposes_into` / `depends_on` /
-- `advances`) on fresh Postgres deployments. The v75 migration drops the
-- stale narrow constraint on already-affected databases.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'memory_links_relation_check'
          AND conrelid = 'memory_links'::regclass
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'memory_links_relation_check_wt1a'
          AND conrelid = 'memory_links'::regclass
    ) THEN
        ALTER TABLE memory_links
            ADD CONSTRAINT memory_links_relation_check
            CHECK (relation IN ('related_to', 'supersedes', 'contradicts', 'derived_from', 'reflects_on'));
    END IF;
END $$;
