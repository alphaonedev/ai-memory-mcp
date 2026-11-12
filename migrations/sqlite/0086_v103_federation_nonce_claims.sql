-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v103 (#9187, v1.0.0): `federation_nonce_claims`, the federation nonce claim
-- table. One row per accepted (signing key, nonce) pair: `key_fp` is the
-- fingerprint of the push's signing key, `nonce_fp` the fingerprint of its
-- nonce. The PRIMARY KEY (key_fp, nonce_fp) is the atomic arbiter: the first
-- INSERT of a pair wins, any later one conflicts and is a replay, on every
-- daemon over the same store. It is the only index. Rows are never pruned:
-- the replay window is the signing-key lifetime, because the signed nonce
-- carries no time (see #9234). Additive `CREATE TABLE IF NOT EXISTS`, no
-- backfill, idempotent, reversible (NoLoss: the table is new and no existing
-- row is touched). The legacy v51 `federation_nonce_cache` table is left as it
-- is. The file numbers differ per backend; the logical schema version is one.
-- `accepted_at` is unix seconds. The postgres twin is
-- `PostgresStore::migrate_v103`
-- (`migrations/postgres/0059_v103_federation_nonce_claims.sql`).
CREATE TABLE IF NOT EXISTS federation_nonce_claims (
    key_fp      BLOB    NOT NULL,
    nonce_fp    BLOB    NOT NULL,
    accepted_at INTEGER NOT NULL,
    PRIMARY KEY (key_fp, nonce_fp)
);
