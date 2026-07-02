-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 G13 (#1828, schema v76) — identity-lineage succession chain
-- (single-node ROTATION-survival core).
--
-- Dedicated `agent_lineage` table holding the authoritative signed
-- succession-record bodies: one row per (agent_id, epoch), genesis at
-- epoch 0. The composite PRIMARY KEY (agent_id, epoch) IS the
-- anti-equivocation defense (C5): the database refuses a second record
-- at the same epoch, so no two competing successors can ever coexist —
-- a JSON metadata array could not enforce this. The row's `signature`
-- is the predecessor key's Ed25519 signature over the LINEAGE_DOMAIN-
-- tagged canonical CBOR (`record_bytes` keeps the exact canonical body
-- as the audit copy; verification re-derives it from the typed columns
-- so a divergence is detectable).
--
-- `not_before` is stored as the exact RFC3339 TEXT that entered the
-- signed bytes (NOT a native timestamp) on BOTH backends, so
-- re-canonicalisation is byte-stable across sqlite/postgres.
--
-- Every INSERT co-transacts with the flat `metadata.agent_pubkey` sync
-- and an append-only `signed_events` witness row (C4/C1) — see
-- `crate::storage::append_lineage_record`. The table alone is mutable
-- storage; the witness rows are what make substitution detectable.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS); also mirrored inline in the
-- bootstrap `SCHEMA` const for fresh installs. The composite PK covers
-- the (agent_id, epoch)-ordered `read_lineage` scan, so no secondary
-- index is needed.
CREATE TABLE IF NOT EXISTS agent_lineage (
    agent_id            TEXT    NOT NULL,
    epoch               INTEGER NOT NULL,
    reason              TEXT    NOT NULL CHECK (reason IN ('genesis', 'rotation', 'recovery')),
    predecessor_pubkey  TEXT    NOT NULL,
    successor_pubkey    TEXT    NOT NULL,
    recovery_pubkey     TEXT,
    not_before          TEXT    NOT NULL,
    prev_record_hash    BLOB    NOT NULL,
    signature           BLOB    NOT NULL,
    record_bytes        BLOB    NOT NULL,
    created_at          TEXT    NOT NULL,
    PRIMARY KEY (agent_id, epoch)
);
