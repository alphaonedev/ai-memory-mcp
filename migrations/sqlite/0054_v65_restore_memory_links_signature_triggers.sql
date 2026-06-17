-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 #1709 — schema v65 sqlite: RESTORE the memory_links
-- (attest_level, signature) atomicity triggers that the v63 (0053)
-- memory_links full-table-rebuild silently dropped.
--
-- # Why
--
-- The v63 typed-cognition relation-taxonomy migration rebuilt
-- `memory_links` (CREATE _v63 + INSERT..SELECT + DROP TABLE + RENAME)
-- to widen the relation CHECK with decomposes_into / depends_on /
-- advances. A SQLite `DROP TABLE` silently drops EVERY trigger
-- attached to the table — including the `(attest_level, signature)`
-- atomicity pair that migration 0037 (#810 / #813) installed to refuse
-- "phantom-signed" rows (attest_level = self_signed / peer_attested
-- with a NULL or non-64-byte signature). The v63 recreation block
-- restored the relation + attest_level-vocabulary triggers but MISSED
-- this signature pair, so self_signed / peer_attested links without a
-- valid 64-byte Ed25519 signature were silently accepted again — a
-- regression of the #810 / #813 security invariant surfaced by the
-- `ck_trigger_refuses_*_self_signed_*` storage tests.
--
-- Postgres is unaffected: its #902 / migrate_v47 invariant is a real
-- column CHECK constraint, and the v63 postgres migration swapped only
-- the relation CHECK in place (`ALTER TABLE ... DROP/ADD CONSTRAINT
-- memory_links_relation_check_wt1a`) — it never touched the signature
-- constraint. So the postgres v65 arm is a version-stamp no-op.
--
-- # The fix
--
-- Reinstall the pair, idempotently. `DROP TRIGGER IF EXISTS` guards
-- against a partially-present state; the trigger bodies are
-- byte-identical to migration 0037.

DROP TRIGGER IF EXISTS memory_links_ck_attest_signature_ins;
CREATE TRIGGER memory_links_ck_attest_signature_ins
BEFORE INSERT ON memory_links
FOR EACH ROW
WHEN NEW.attest_level IN ('self_signed', 'peer_attested')
  AND (NEW.signature IS NULL OR length(NEW.signature) != 64)
BEGIN
    SELECT RAISE(ABORT, 'CHECK constraint failed: attest_level=self_signed/peer_attested requires 64-byte signature');
END;

DROP TRIGGER IF EXISTS memory_links_ck_attest_signature_upd;
CREATE TRIGGER memory_links_ck_attest_signature_upd
BEFORE UPDATE ON memory_links
FOR EACH ROW
WHEN NEW.attest_level IN ('self_signed', 'peer_attested')
  AND (NEW.signature IS NULL OR length(NEW.signature) != 64)
BEGIN
    SELECT RAISE(ABORT, 'CHECK constraint failed: attest_level=self_signed/peer_attested requires 64-byte signature');
END;
