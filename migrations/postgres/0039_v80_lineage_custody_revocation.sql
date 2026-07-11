-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #1949 (R13, epic #1940, decision `da9eeb26`, schema v80) —
-- custody-class + signed revocation on the v76 identity-lineage chain
-- (postgres twin of migrations/sqlite/0064_v80_lineage_custody_revocation.sql).
-- See the R24 spec §3
-- docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md.
--
-- Purely additive, NO table rewrite (unlike the SQLite twin, postgres
-- can widen a CHECK constraint in place). Idempotent:
--   * ADD COLUMN IF NOT EXISTS for the two new columns;
--   * DROP CONSTRAINT IF EXISTS + ADD CONSTRAINT to widen the `reason`
--     CHECK to admit the 4th LineageReason 'revocation'. The inline CHECK
--     from the bootstrap schema is auto-named `agent_lineage_reason_check`.

ALTER TABLE agent_lineage
    ADD COLUMN IF NOT EXISTS custody_class TEXT;

ALTER TABLE agent_lineage
    ADD COLUMN IF NOT EXISTS suspected_compromise_from_seq BIGINT;

ALTER TABLE agent_lineage
    DROP CONSTRAINT IF EXISTS agent_lineage_reason_check;

ALTER TABLE agent_lineage
    ADD CONSTRAINT agent_lineage_reason_check
    CHECK (reason IN ('genesis', 'rotation', 'recovery', 'revocation'));
