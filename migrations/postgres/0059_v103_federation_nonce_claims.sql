-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v103 (#9187, v1.0.0): postgres twin of
-- `migrations/sqlite/0086_v103_federation_nonce_claims.sql`; see it for the
-- contract. The PRIMARY KEY (key_fp, nonce_fp) is the atomic arbiter and the
-- only index; rows are never pruned (the replay window is the signing-key
-- lifetime: the signed nonce carries no time, see #9234). Additive,
-- idempotent, no backfill, NoLoss.
CREATE TABLE IF NOT EXISTS federation_nonce_claims (
    key_fp      BYTEA       NOT NULL,
    nonce_fp    BYTEA       NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (key_fp, nonce_fp)
);
