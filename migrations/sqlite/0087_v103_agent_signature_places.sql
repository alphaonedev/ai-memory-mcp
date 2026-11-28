-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v103 (#10108, v1.0.0, signed writes): the persisted places of two agent
-- signatures that had none, and the agent-attribution cutover marker.
-- 3-agent vote (71472661) V1-AGENT-SIG-SCHEMA, decision A.
--
-- 1. `transcript_line_dedup.host_signature` (64 bytes) and `host_pubkey`
--    (32 bytes): the L4 host's Ed25519 signature over the captured turn and
--    the allowlisted key it verified under. Both set or both NULL. Added by the
--    Rust arm (`src/storage/agent_cutover_v103.rs`) behind a `pragma
--    table_info` probe, because SQLite `ALTER TABLE ADD COLUMN` has no
--    `IF NOT EXISTS` form.
-- 2. `atomisation_receipts`: the stored record an `atomisation_complete`
--    chain row is recomputed from (created below).
-- 3. The cutover marker: one `signed_events.agent_cutover` row appended at the
--    chain head in the SAME transaction as the version stamp, committing to its
--    sequence, the preceding head hash and the count of agent-labelled rows
--    before it. Written only when the chain is non-empty.
--
-- Strictly additive: no existing row is rewritten, relabelled or deleted.
-- Idempotent: every statement is guarded, so a crash before COMMIT rolls the
-- whole step back and the next open re-runs it. There is no down migration; a
-- downgrade is a restore of the pre-v103 backup (docs/MIGRATION.md).
-- The postgres twin is `PostgresStore::migrate_v103`
-- (`migrations/postgres/0060_v103_agent_signature_places.sql`).

CREATE TABLE IF NOT EXISTS atomisation_receipts (
    source_id TEXT NOT NULL,
    atomised_at TEXT NOT NULL,
    atom_ids TEXT NOT NULL CHECK (json_valid(atom_ids) AND json_type(atom_ids) = 'array'),
    atom_count INTEGER NOT NULL CHECK (atom_count >= 0),
    calling_agent_id TEXT NOT NULL,
    curator_model TEXT,
    signer_agent_id TEXT,
    signature BLOB CHECK (signature IS NULL OR (typeof(signature) = 'blob' AND length(signature) = 64)),
    CHECK ((signer_agent_id IS NULL) = (signature IS NULL)),
    PRIMARY KEY (source_id, atomised_at)
);
