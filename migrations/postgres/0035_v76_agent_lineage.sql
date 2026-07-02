-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 G13 (#1828, schema v76) — identity-lineage succession chain
-- (postgres mirror of the sqlite v76 arm; see
-- migrations/sqlite/0060_v76_agent_lineage.sql for the full design
-- rationale).
--
-- The composite PRIMARY KEY (agent_id, epoch) is the DB-enforced
-- anti-equivocation defense (C5). `not_before` stays TEXT (the exact
-- RFC3339 string inside the signed bytes) so re-canonicalisation is
-- byte-stable across backends; `epoch` is BIGINT to carry the u64
-- record epoch. Every INSERT co-transacts with the flat
-- `metadata.agent_pubkey` sync and a `signed_events` witness row
-- (C4/C1) — see `PostgresStore::append_lineage_record`.
--
-- Idempotent single-batch DDL; fresh schemas also carry the table
-- inline from src/store/postgres_schema.sql.
CREATE TABLE IF NOT EXISTS agent_lineage (
    agent_id            TEXT    NOT NULL,
    epoch               BIGINT  NOT NULL,
    reason              TEXT    NOT NULL CHECK (reason IN ('genesis', 'rotation', 'recovery')),
    predecessor_pubkey  TEXT    NOT NULL,
    successor_pubkey    TEXT    NOT NULL,
    recovery_pubkey     TEXT,
    not_before          TEXT    NOT NULL,
    prev_record_hash    BYTEA   NOT NULL,
    signature           BYTEA   NOT NULL,
    record_bytes        BYTEA   NOT NULL,
    created_at          TEXT    NOT NULL,
    PRIMARY KEY (agent_id, epoch)
);
