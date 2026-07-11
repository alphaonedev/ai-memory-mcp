-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v1.0.0 crypto-core stage 2 (#1942/#1941/#1945/#1834, epic #1940,
-- schema v79) — the coordinated ADDITIVE migration. See the R24 spec
-- docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md
-- (§2.3, §4, §8).
--
-- Purely additive on BOTH backends, NO full-table rebuild — so the
-- v63/v65 trigger-drop lesson does not arise (no trigger is recreated).
--
-- (a) memories.kind_provenance (#1945, spec §4) — epistemic-typing
--     provenance: HOW the `memory_kind` was assigned. Closed vocab
--     {declared, channel_derived, regex, llm}; UNSIGNED metadata (NOT
--     part of the SignableWrite v2 envelope). Nullable; NULL on legacy
--     rows.
-- (b) memories.valid_from / valid_until (#1834) — claim-bitemporal
--     validity window (RFC3339 TEXT, mirroring the memory_links temporal
--     columns). Nullable; NULL = unbounded.
-- (c) agent_subkey_certs (#1942, spec §2.3) — instance sub-key
--     certificate store (SubkeyCert). CREATE TABLE IF NOT EXISTS is
--     idempotent; the lookup index is LADDER-OWNED (created in the v79
--     arm, NOT here / NOT bootstrap-inline — the #1861 lesson).
--
-- SQLite lacks `ADD COLUMN IF NOT EXISTS`, so the whole file runs only
-- behind the `kind_provenance` column-existence probe in the v79 ladder
-- arm: a fresh install (columns present inline from the bootstrap
-- SCHEMA) skips it; a legacy upgrade DB (columns absent) runs it once.
ALTER TABLE memories ADD COLUMN kind_provenance TEXT;
ALTER TABLE memories ADD COLUMN valid_from TEXT;
ALTER TABLE memories ADD COLUMN valid_until TEXT;

CREATE TABLE IF NOT EXISTS agent_subkey_certs (
    id                 TEXT NOT NULL PRIMARY KEY,
    principal          TEXT NOT NULL,
    instance_key_id    BLOB NOT NULL,
    model_version_ref  BLOB NOT NULL,
    not_before         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    signature          BLOB NOT NULL,
    cert_bytes         BLOB NOT NULL,
    revoked            INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL
);
