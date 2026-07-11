-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 crypto-core stage 2 (#1942/#1941/#1945/#1834, epic #1940,
-- schema v79) — the coordinated ADDITIVE migration (postgres mirror of
-- SQLite schema v79, migrations/sqlite/0063_v79_crypto_core.sql). See
-- the R24 spec docs/v1.0.0/format-decisions/
-- SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md (§2.3, §4, §8).
--
-- Purely additive on BOTH backends, NO full-table rebuild — so the
-- v63/v65 trigger-drop lesson does not arise (no trigger is recreated).
-- Postgres supports `ADD COLUMN IF NOT EXISTS`, so this is one
-- idempotent, replay-safe DDL batch — fresh installs inherit the columns
-- + table + index inline from postgres_schema.sql; pre-v79 deployments
-- pick them up here via `PostgresStore::migrate_v79`.
--
-- (a) memories.kind_provenance (#1945, spec §4) — epistemic-typing
--     provenance: HOW the `memory_kind` was assigned. Closed vocab
--     {declared, channel_derived, regex, llm}; UNSIGNED metadata (NOT
--     part of the SignableWrite v2 envelope). Nullable.
-- (b) memories.valid_from / valid_until (#1834) — claim-bitemporal
--     validity window (RFC3339 TEXT, mirroring the memory_links temporal
--     columns). Nullable; NULL = unbounded.
-- (c) agent_subkey_certs (#1942, spec §2.3) — instance sub-key
--     certificate store (SubkeyCert). `instance_key_id` = the sub-key's
--     raw Ed25519 verifying-key bytes; `cert_bytes` is the exact
--     canonical signed CBOR; `signature` is the principal root's Ed25519
--     over those bytes; `revoked` is the additive revocation flag.

ALTER TABLE memories ADD COLUMN IF NOT EXISTS kind_provenance TEXT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS valid_from TEXT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS valid_until TEXT;

CREATE TABLE IF NOT EXISTS agent_subkey_certs (
    id                 TEXT NOT NULL PRIMARY KEY,
    principal          TEXT NOT NULL,
    instance_key_id    BYTEA NOT NULL,
    model_version_ref  BYTEA NOT NULL,
    not_before         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    signature          BYTEA NOT NULL,
    cert_bytes         BYTEA NOT NULL,
    revoked            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_subkey_certs_instance
    ON agent_subkey_certs(instance_key_id);
