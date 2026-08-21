-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3055 — AGE schema-placement repair (installed-base relocation half).
--
-- Runs PRE-BOOTSTRAP (before postgres_schema.sql / INIT_SCHEMA), under the
-- bootstrap MIGRATION_ADVISORY_LOCK_KEY, from PostgresStore::connect via
-- `relocate_app_tables_to_public`. It moves the ai-memory APPLICATION tables
-- out of the Apache AGE `ag_catalog` schema and back into `public`.
--
-- WHY. The recommended AGE setup puts `ag_catalog` FIRST on the
-- role/database search_path (so `LOAD 'age'` resolves `agtype` + `cypher()`
-- unqualified). Under that search_path an UNQUALIFIED `CREATE TABLE memories
-- ...` landed the table in `ag_catalog`, entangling durable application data
-- with the AGE extension catalog: a `DROP EXTENSION age CASCADE` would then
-- take the app tables with it (silent data loss), and placement was
-- non-deterministic. The companion fix qualifies every bootstrap CREATE as
-- `public.<t>`; this file repairs an ALREADY-affected installed base.
--
-- SAFETY / crash-resume. Each table is moved only when it IS in `ag_catalog`
-- AND is NOT yet in `public` (`to_regclass(...) IS NOT NULL / IS NULL`). That
-- per-object guard is the idempotency + crash-resume mechanism: a re-run
-- skips already-moved tables, so a crash mid-relocation self-heals on the
-- next boot. The caller wraps this whole file in ONE transaction, so a crash
-- rolls back cleanly (no split schema). `ALTER TABLE ... SET SCHEMA` is
-- non-destructive (re-points the namespace, touching no rows) and reversible
-- (`ALTER TABLE public.<t> SET SCHEMA ag_catalog`).
--
-- ALLOWLIST DISCIPLINE. The 37 tables + 6 sequences below are enumerated BY
-- NAME. This is NEVER a schema wildcard, so an AGE-owned catalog object
-- (`ag_graph`, `ag_label`, `agtype`, `_ag_label_vertex`, `_ag_label_edge`, or
-- any per-graph label table) can NEVER be moved. Do not replace the explicit
-- list with a `pg_class` sweep.
DO $relocate_3055$
BEGIN
    IF to_regclass('ag_catalog.memories') IS NOT NULL AND to_regclass('public.memories') IS NULL THEN
        ALTER TABLE ag_catalog.memories SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.memory_links') IS NOT NULL AND to_regclass('public.memory_links') IS NULL THEN
        ALTER TABLE ag_catalog.memory_links SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.archived_memories') IS NOT NULL AND to_regclass('public.archived_memories') IS NULL THEN
        ALTER TABLE ag_catalog.archived_memories SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.archived_memory_links') IS NOT NULL AND to_regclass('public.archived_memory_links') IS NULL THEN
        ALTER TABLE ag_catalog.archived_memory_links SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.memory_revisions') IS NOT NULL AND to_regclass('public.memory_revisions') IS NULL THEN
        ALTER TABLE ag_catalog.memory_revisions SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.memory_transcripts') IS NOT NULL AND to_regclass('public.memory_transcripts') IS NULL THEN
        ALTER TABLE ag_catalog.memory_transcripts SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.memory_transcript_links') IS NOT NULL AND to_regclass('public.memory_transcript_links') IS NULL THEN
        ALTER TABLE ag_catalog.memory_transcript_links SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.transcript_line_dedup') IS NOT NULL AND to_regclass('public.transcript_line_dedup') IS NULL THEN
        ALTER TABLE ag_catalog.transcript_line_dedup SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.entity_aliases') IS NOT NULL AND to_regclass('public.entity_aliases') IS NULL THEN
        ALTER TABLE ag_catalog.entity_aliases SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.forget_tombstones') IS NOT NULL AND to_regclass('public.forget_tombstones') IS NULL THEN
        ALTER TABLE ag_catalog.forget_tombstones SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.namespace_meta') IS NOT NULL AND to_regclass('public.namespace_meta') IS NULL THEN
        ALTER TABLE ag_catalog.namespace_meta SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.pending_actions') IS NOT NULL AND to_regclass('public.pending_actions') IS NULL THEN
        ALTER TABLE ag_catalog.pending_actions SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.sync_state') IS NOT NULL AND to_regclass('public.sync_state') IS NULL THEN
        ALTER TABLE ag_catalog.sync_state SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.subscriptions') IS NOT NULL AND to_regclass('public.subscriptions') IS NULL THEN
        ALTER TABLE ag_catalog.subscriptions SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.subscription_events') IS NOT NULL AND to_regclass('public.subscription_events') IS NULL THEN
        ALTER TABLE ag_catalog.subscription_events SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.subscription_dlq') IS NOT NULL AND to_regclass('public.subscription_dlq') IS NULL THEN
        ALTER TABLE ag_catalog.subscription_dlq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.audit_log') IS NOT NULL AND to_regclass('public.audit_log') IS NULL THEN
        ALTER TABLE ag_catalog.audit_log SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.signed_events') IS NOT NULL AND to_regclass('public.signed_events') IS NULL THEN
        ALTER TABLE ag_catalog.signed_events SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.signed_events_dlq') IS NOT NULL AND to_regclass('public.signed_events_dlq') IS NULL THEN
        ALTER TABLE ag_catalog.signed_events_dlq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.federation_push_dlq') IS NOT NULL AND to_regclass('public.federation_push_dlq') IS NULL THEN
        ALTER TABLE ag_catalog.federation_push_dlq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.kg_projection_outbox') IS NOT NULL AND to_regclass('public.kg_projection_outbox') IS NULL THEN
        ALTER TABLE ag_catalog.kg_projection_outbox SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.agent_lineage') IS NOT NULL AND to_regclass('public.agent_lineage') IS NULL THEN
        ALTER TABLE ag_catalog.agent_lineage SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.agent_subkey_certs') IS NOT NULL AND to_regclass('public.agent_subkey_certs') IS NULL THEN
        ALTER TABLE ag_catalog.agent_subkey_certs SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.agent_api_keys') IS NOT NULL AND to_regclass('public.agent_api_keys') IS NULL THEN
        ALTER TABLE ag_catalog.agent_api_keys SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.agent_quotas') IS NOT NULL AND to_regclass('public.agent_quotas') IS NULL THEN
        ALTER TABLE ag_catalog.agent_quotas SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.model_attestations') IS NOT NULL AND to_regclass('public.model_attestations') IS NULL THEN
        ALTER TABLE ag_catalog.model_attestations SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.confidence_shadow_observations') IS NOT NULL AND to_regclass('public.confidence_shadow_observations') IS NULL THEN
        ALTER TABLE ag_catalog.confidence_shadow_observations SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.recall_observations') IS NOT NULL AND to_regclass('public.recall_observations') IS NULL THEN
        ALTER TABLE ag_catalog.recall_observations SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.offloaded_blobs') IS NOT NULL AND to_regclass('public.offloaded_blobs') IS NULL THEN
        ALTER TABLE ag_catalog.offloaded_blobs SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.actions') IS NOT NULL AND to_regclass('public.actions') IS NULL THEN
        ALTER TABLE ag_catalog.actions SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.action_edges') IS NOT NULL AND to_regclass('public.action_edges') IS NULL THEN
        ALTER TABLE ag_catalog.action_edges SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.leases') IS NOT NULL AND to_regclass('public.leases') IS NULL THEN
        ALTER TABLE ag_catalog.leases SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.signals') IS NOT NULL AND to_regclass('public.signals') IS NULL THEN
        ALTER TABLE ag_catalog.signals SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.checkpoints') IS NOT NULL AND to_regclass('public.checkpoints') IS NULL THEN
        ALTER TABLE ag_catalog.checkpoints SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.routines') IS NOT NULL AND to_regclass('public.routines') IS NULL THEN
        ALTER TABLE ag_catalog.routines SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.routine_runs') IS NOT NULL AND to_regclass('public.routine_runs') IS NULL THEN
        ALTER TABLE ag_catalog.routine_runs SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.schema_version') IS NOT NULL AND to_regclass('public.schema_version') IS NULL THEN
        ALTER TABLE ag_catalog.schema_version SET SCHEMA public;
    END IF;
    -- Owned BIGSERIAL sequences move WITH their table under ALTER TABLE ... SET
    -- SCHEMA (PostgreSQL moves indexes, constraints, and column-owned sequences
    -- together); these guarded ALTERs are defense-in-depth for any sequence
    -- somehow orphaned in ag_catalog without its table. The guard makes each a
    -- no-op once the owning table has already carried it into public.
    IF to_regclass('ag_catalog.confidence_shadow_observations_id_seq') IS NOT NULL AND to_regclass('public.confidence_shadow_observations_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.confidence_shadow_observations_id_seq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.signed_events_dlq_dlq_id_seq') IS NOT NULL AND to_regclass('public.signed_events_dlq_dlq_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.signed_events_dlq_dlq_id_seq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.federation_push_dlq_id_seq') IS NOT NULL AND to_regclass('public.federation_push_dlq_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.federation_push_dlq_id_seq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.kg_projection_outbox_id_seq') IS NOT NULL AND to_regclass('public.kg_projection_outbox_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.kg_projection_outbox_id_seq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.subscription_events_id_seq') IS NOT NULL AND to_regclass('public.subscription_events_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.subscription_events_id_seq SET SCHEMA public;
    END IF;
    IF to_regclass('ag_catalog.subscription_dlq_id_seq') IS NOT NULL AND to_regclass('public.subscription_dlq_id_seq') IS NULL THEN
        ALTER SEQUENCE ag_catalog.subscription_dlq_id_seq SET SCHEMA public;
    END IF;
END
$relocate_3055$;
