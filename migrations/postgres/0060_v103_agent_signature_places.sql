-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v103 (#10108, v1.0.0, signed writes): the persisted places of two agent
-- signatures that had none. 3-agent vote (71472661) V1-AGENT-SIG-SCHEMA,
-- decision A. The SQLite twin is
-- `migrations/sqlite/0087_v103_agent_signature_places.sql`.
--
-- Strictly additive and idempotent (`IF NOT EXISTS` on every column, table and
-- constraint). `PostgresStore::migrate_v103` runs this file, then appends the
-- `signed_events.agent_cutover` marker under `LOCK TABLE signed_events IN
-- EXCLUSIVE MODE`, then stamps 103, in ONE transaction.

ALTER TABLE transcript_line_dedup ADD COLUMN IF NOT EXISTS host_signature BYTEA NULL;
ALTER TABLE transcript_line_dedup ADD COLUMN IF NOT EXISTS host_pubkey BYTEA NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'transcript_line_dedup_host_sig_v103'
          AND conrelid = 'transcript_line_dedup'::regclass
    ) THEN
        ALTER TABLE transcript_line_dedup ADD CONSTRAINT transcript_line_dedup_host_sig_v103
            CHECK (
                (host_signature IS NULL) = (host_pubkey IS NULL)
                AND (host_signature IS NULL OR octet_length(host_signature) = 64)
                AND (host_pubkey IS NULL OR octet_length(host_pubkey) = 32)
            );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS atomisation_receipts (
    source_id TEXT NOT NULL,
    atomised_at TEXT NOT NULL,
    atom_ids TEXT NOT NULL CHECK (jsonb_typeof(atom_ids::jsonb) = 'array'),
    atom_count BIGINT NOT NULL CHECK (atom_count >= 0),
    calling_agent_id TEXT NOT NULL,
    curator_model TEXT,
    signer_agent_id TEXT,
    signature BYTEA CHECK (signature IS NULL OR octet_length(signature) = 64),
    CHECK ((signer_agent_id IS NULL) = (signature IS NULL)),
    PRIMARY KEY (source_id, atomised_at)
);
