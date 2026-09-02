-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #3419 — schema v95: the ATTESTED-WRITE REPLAY LEDGER (postgres twin).
--
-- Byte-for-byte the same contract as
-- migrations/sqlite/0079_v95_attested_write_ledger.sql — see that file for the
-- defect, the fingerprint definition, and the bounded-retention argument.
-- Deliberately NOT a sqlite-only sidecar (the v51 `federation_nonce_cache`
-- shape): the direct attested-write surfaces run on the SAL trait when the
-- daemon is postgres-backed, so a sqlite-only ledger would leave every
-- postgres deployment with no replay guard at all.
--
-- `fingerprint` is the PRIMARY KEY, so the uniqueness constraint IS the
-- decision: `INSERT ... ON CONFLICT (fingerprint) DO NOTHING` admits an
-- envelope exactly once even under concurrent submission.
--
-- PURE ADDITIVE `CREATE TABLE IF NOT EXISTS`; no backfill, no rewrite of any
-- existing row. Reversible (DROP TABLE + lower the stamp); NoLoss.

CREATE TABLE IF NOT EXISTS attested_write_ledger (
    fingerprint BYTEA  NOT NULL PRIMARY KEY,
    agent_id    TEXT   NOT NULL,
    created_at  TEXT   NOT NULL,
    seen_at     BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attested_write_ledger_seen_at
    ON attested_write_ledger(seen_at);
