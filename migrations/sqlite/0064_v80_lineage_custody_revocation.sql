-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #1949 (R13, epic #1940, decision `da9eeb26`, schema v80) —
-- custody-class + signed revocation on the v76 identity-lineage chain.
-- See the R24 spec §3
-- docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md.
--
-- Two additive columns on `agent_lineage`:
--   * custody_class  TEXT — the OSS-refusal-attested custody environment
--     of the successor key (CLOSED set: 'software-file' + RESERVED
--     {tpm2,pkcs11-hsm,secure-enclave,kms}). NULL on legacy rows = the
--     'software-file' default. Committed INSIDE the predecessor-signed
--     bytes (software-file is OMITTED from the CBOR for legacy
--     byte-compat), so this column is the read-side copy; verification
--     re-derives it.
--   * suspected_compromise_from_seq INTEGER — for a 'revocation' record
--     ONLY, the signed_events witness SEQUENCE high-water the compromise
--     is dated from (the ordering authority; never wall-clock). NULL for
--     genesis/rotation.
--
-- AND a widened `reason` CHECK to admit the 4th LineageReason
-- 'revocation'. SQLite cannot ALTER a CHECK constraint in place, so this
-- is a guarded FULL-TABLE REBUILD. The v63/v65 trigger-drop hazard does
-- NOT arise here: `agent_lineage` carries NO triggers and NO secondary
-- indexes — only the composite PRIMARY KEY (agent_id, epoch), which the
-- new table definition recreates identically (it is both the C5
-- anti-equivocation constraint and the covering index for the
-- epoch-ordered read_lineage scan). There is nothing to recreate beyond
-- the table itself.
--
-- Guarded by the `custody_class` column-existence probe in the v80
-- ladder arm: a fresh install (new bootstrap SCHEMA already carries the
-- widened table) skips this file; a legacy upgrade DB (column absent)
-- runs it exactly once. Idempotent by that probe.

CREATE TABLE agent_lineage_v80 (
    agent_id            TEXT    NOT NULL,
    epoch               INTEGER NOT NULL,
    reason              TEXT    NOT NULL
        CHECK (reason IN ('genesis', 'rotation', 'recovery', 'revocation')),
    predecessor_pubkey  TEXT    NOT NULL,
    successor_pubkey    TEXT    NOT NULL,
    recovery_pubkey     TEXT,
    not_before          TEXT    NOT NULL,
    prev_record_hash    BLOB    NOT NULL,
    signature           BLOB    NOT NULL,
    record_bytes        BLOB    NOT NULL,
    created_at          TEXT    NOT NULL,
    custody_class       TEXT,
    suspected_compromise_from_seq INTEGER,
    PRIMARY KEY (agent_id, epoch)
);

-- Copy every existing row verbatim; custody_class + the sequence default
-- to NULL (legacy software-file / no-revocation on read).
INSERT INTO agent_lineage_v80
    (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey,
     recovery_pubkey, not_before, prev_record_hash, signature,
     record_bytes, created_at)
SELECT
     agent_id, epoch, reason, predecessor_pubkey, successor_pubkey,
     recovery_pubkey, not_before, prev_record_hash, signature,
     record_bytes, created_at
FROM agent_lineage;

DROP TABLE agent_lineage;
ALTER TABLE agent_lineage_v80 RENAME TO agent_lineage;
