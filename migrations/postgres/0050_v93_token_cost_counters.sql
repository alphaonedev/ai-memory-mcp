-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3323 — schema v93 (POSTGRES twin): PER-LINEAGE + PER-NAMESPACE
-- TOKEN/COST ACCOUNTING.
--
-- See migrations/sqlite/0077_v93_token_cost_counters.sql for the full
-- rationale. In short: one advisory append-and-increment counter relation
-- keyed by (scope_kind, scope_key) — 'namespace' rows carry per-namespace
-- token spend, 'lineage' rows carry each memory node's own tokens so a
-- per-lineage-root rollup can sum a root plus its `derives_from`
-- descendants at report time. Advisory, disposable, best-effort: a
-- metering failure never fails a memory write or recall. Additive and
-- idempotent (`IF NOT EXISTS`); no rewrite, no reindex. Counter columns
-- are BIGINT (i64) to mirror the SQLite INTEGER twin; `updated_at` is
-- TIMESTAMPTZ per this backend's convention (the SQLite twin stores TEXT).
-- The CHECKs mirror the SQLite twin so a co-tenant with DML on this SHARED
-- cluster cannot plant a negative counter or an unknown scope kind.
--
-- Applied on a FRESH database inline from src/store/postgres_schema.sql,
-- and on an EXISTING database by the probe-guarded `migrate_v93` arm in
-- src/store/postgres.rs (which sources this same DDL).

CREATE TABLE IF NOT EXISTS token_cost_counters (
    scope_kind      TEXT        NOT NULL,
    scope_key       TEXT        NOT NULL,
    tokens_written  BIGINT      NOT NULL DEFAULT 0,
    tokens_recalled BIGINT      NOT NULL DEFAULT 0,
    write_events    BIGINT      NOT NULL DEFAULT 0,
    recall_events   BIGINT      NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, scope_key),
    CONSTRAINT token_cost_counters_scope_kind_ck
        CHECK (scope_kind IN ('namespace', 'lineage')),
    CONSTRAINT token_cost_counters_tokens_written_ck  CHECK (tokens_written  >= 0),
    CONSTRAINT token_cost_counters_tokens_recalled_ck CHECK (tokens_recalled >= 0),
    CONSTRAINT token_cost_counters_write_events_ck    CHECK (write_events    >= 0),
    CONSTRAINT token_cost_counters_recall_events_ck   CHECK (recall_events   >= 0)
);
