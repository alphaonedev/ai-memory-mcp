-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 #1831 (G17, epic #1940, schema v81) — M-of-N threshold key
-- recovery (postgres twin of the sqlite v81 arm). Two additive
-- recovery-only columns on `agent_lineage`:
--   * guardian_set_id  BYTEA — the SHA-256 digest over the SORTED enrolled
--     recovery-guardian public keys the recovery quorum was minted against.
--     Committed inside the signed CBOR body so a persisted recovery is
--     re-verified against the guardian set AT MINT time (never the
--     verifier's later env); this column is the read-side copy. NULL on
--     every non-recovery record.
--   * recovery_threshold BIGINT — the committed M-of-N threshold, also
--     committed inside the signed body so a later-lowered env threshold can
--     never retroactively re-judge a persisted recovery. NULL on every
--     non-recovery record.
--
-- Purely additive `ADD COLUMN IF NOT EXISTS` — NO reason-CHECK change (the
-- v80 CHECK already admits 'recovery') and no table rewrite. Idempotent.

ALTER TABLE agent_lineage ADD COLUMN IF NOT EXISTS guardian_set_id BYTEA;
ALTER TABLE agent_lineage ADD COLUMN IF NOT EXISTS recovery_threshold BIGINT;
