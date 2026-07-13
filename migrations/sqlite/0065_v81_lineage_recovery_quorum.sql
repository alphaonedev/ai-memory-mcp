-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #1831 (G17, epic #1940, schema v81) — M-of-N threshold key
-- recovery. Two additive recovery-only columns on `agent_lineage`:
--   * guardian_set_id  BLOB — the SHA-256 digest over the SORTED enrolled
--     recovery-guardian public keys the recovery quorum was minted against.
--     Committed INSIDE the predecessor-position signed CBOR body so a
--     persisted recovery is re-verified against the guardian set AT MINT
--     time (never the verifier's later env); this column is the read-side
--     copy verification re-derives. NULL on every non-recovery record.
--   * recovery_threshold INTEGER — the committed M-of-N threshold the
--     quorum was minted against, also committed inside the signed body so a
--     later-lowered env threshold can never retroactively re-judge a
--     persisted recovery. NULL on every non-recovery record.
--
-- Pure ADDITIVE ALTER ADD COLUMN — NO reason-CHECK change (the v80 CHECK
-- already admits 'recovery') and therefore NO SQLite full-table rebuild, so
-- the v63/v65 trigger-drop hazard does NOT arise. Guarded by the
-- `guardian_set_id` column-existence probe in the v81 ladder arm: a fresh
-- install (whose bootstrap SCHEMA already carries the widened table) skips
-- this file; a legacy upgrade DB (column absent) runs it exactly once.

ALTER TABLE agent_lineage ADD COLUMN guardian_set_id BLOB;
ALTER TABLE agent_lineage ADD COLUMN recovery_threshold INTEGER;
