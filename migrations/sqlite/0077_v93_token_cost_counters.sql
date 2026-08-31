-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3323 — schema v93: PER-LINEAGE + PER-NAMESPACE TOKEN/COST
-- ACCOUNTING. Additive, instant, NO table rebuild (a fresh standalone
-- table, so the v63/v65 "a full-table rebuild silently drops every
-- trigger" hazard does not arise).
--
-- What this is
-- ------------
-- A single append-and-increment counter relation that gives a runaway
-- atomisation/reflection cascade a DOLLAR FIGURE instead of a discovery
-- (the "$50k on the screen"). Two scope kinds share one table:
--
--   * 'namespace' — scope_key is the namespace. Every LOCAL-authorship
--     write adds the stored content's cl100k_base token count here, and
--     every SAL-funnel recall adds the served token count. The direct
--     "how much has this namespace cost" figure.
--   * 'lineage'   — scope_key is a memory id (a node in the
--     `derives_from` lineage DAG). Each node accrues ITS OWN tokens at
--     O(1) on the write path (no DAG walk on the hot path); the
--     per-lineage-ROOT rollup is computed at REPORT time by summing a
--     root plus its descendants (`storage::lineage_descendants`).
--
-- Integrity posture (North Star)
-- ------------------------------
-- This table is ADVISORY, disposable, derived data — it is NOT the
-- durable memory truth. Every increment is best-effort: a metering
-- failure NEVER fails or rolls back a memory write or recall (degrade,
-- never corrupt). Counters are exact integers (never floats — a float
-- key/aggregate would corrupt ordering, cl100k tokens are whole units);
-- the tokens->cost model is applied only at rollup time so the durable
-- rows hold no float and re-pricing needs no rewrite. The CHECKs keep an
-- out-of-band writer from planting a negative counter or an unknown
-- scope kind.
--
-- The DDL below is applied by the additive `if version < CURRENT_SCHEMA_VERSION`
-- arm in src/storage/migrations.rs via `execute_batch(MIGRATION_V93_SQLITE)`
-- (this file, `include_str!`-embedded) — CREATE TABLE IF NOT EXISTS, so it is
-- idempotent and a no-op on a database already carrying the table. The
-- postgres twin is migrations/postgres/0050_v93_token_cost_counters.sql.

CREATE TABLE IF NOT EXISTS token_cost_counters (
    scope_kind      TEXT    NOT NULL,
    scope_key       TEXT    NOT NULL,
    tokens_written  INTEGER NOT NULL DEFAULT 0,
    tokens_recalled INTEGER NOT NULL DEFAULT 0,
    write_events    INTEGER NOT NULL DEFAULT 0,
    recall_events   INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT    NOT NULL,
    PRIMARY KEY (scope_kind, scope_key),
    CHECK (scope_kind IN ('namespace', 'lineage')),
    CHECK (tokens_written  >= 0),
    CHECK (tokens_recalled >= 0),
    CHECK (write_events    >= 0),
    CHECK (recall_events   >= 0)
);
