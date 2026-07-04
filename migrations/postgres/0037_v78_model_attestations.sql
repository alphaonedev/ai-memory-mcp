-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 §25.3 S1 (D3-012, #1870, schema v78) — model attestation
-- substrate (postgres mirror of
-- migrations/sqlite/0062_v78_model_attestations.sql; see that file for
-- the full design rationale + honest coverage note).
--
-- BYTEA for the operator signature (this backend's blob convention);
-- `agent_id TEXT NOT NULL DEFAULT ''` mirrors the sqlite twin so the
-- UNIQUE(provider, model_ref, model_family, agent_id) TOFU constraint is
-- backend-identical (NULLs would be pairwise-distinct, breaking
-- write-once). All DDL is IF NOT EXISTS / replay-safe; fresh installs
-- carry the table + index inline from src/store/postgres_schema.sql,
-- existing schemas pick them up here via migrate_v78().
CREATE TABLE IF NOT EXISTS model_attestations (
    id            TEXT NOT NULL PRIMARY KEY,
    provider      TEXT NOT NULL,
    model_ref     TEXT NOT NULL,
    model_digest  TEXT,
    model_family  TEXT NOT NULL,
    attest_level  TEXT NOT NULL
        CHECK (attest_level IN ('loader_observed','operator_signed')),
    agent_id      TEXT NOT NULL DEFAULT '',
    signature     BYTEA,
    created_at    TEXT NOT NULL,
    UNIQUE (provider, model_ref, model_family, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_model_attestations_family
    ON model_attestations(model_family, agent_id);
