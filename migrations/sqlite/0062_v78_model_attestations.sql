-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.9.0 §25.3 S1 (D3-012, #1870, schema v78) — model attestation
-- substrate. The append-only, write-once (TOFU) record of WHICH model
-- family produced a given generation, captured at the LLM-client
-- construction boundary (`loader_observed`) or enrolled out-of-band by
-- an operator (`operator_signed`).
--
-- Honest coverage: only substrate-invoked generation is attestable, so
-- loader coverage hard-caps at ~40% (ROADMAP.md:1229). Externally
-- authored reflections remain CLAIMED forever on this architecture —
-- see src/identity/model_family.rs + docs/honest-limitations.md.
--
-- `agent_id` is `TEXT NOT NULL DEFAULT ''` (NOT nullable): a NULL
-- agent_id would make the UNIQUE(provider, model_ref, model_family,
-- agent_id) constraint pairwise-distinct on NULLs, destroying the TOFU
-- write-once (`INSERT ... ON CONFLICT DO NOTHING`) guarantee.
--
-- The family index is LADDER-OWNED (created below and in the v78 arm),
-- NOT inline in the bootstrap SCHEMA — the #1861 / v74-v75 lesson that a
-- bootstrap-inline index crashes legacy opens.
CREATE TABLE IF NOT EXISTS model_attestations (
    id            TEXT NOT NULL PRIMARY KEY,      -- uuid
    provider      TEXT NOT NULL,                  -- resolved backend selector
    model_ref     TEXT NOT NULL,                  -- verbatim resolved model string
    model_digest  TEXT,                           -- nullable; provider digest (TOFU)
    model_family  TEXT NOT NULL,                  -- normalized family token
    attest_level  TEXT NOT NULL
        CHECK (attest_level IN ('loader_observed','operator_signed')),
    agent_id      TEXT NOT NULL DEFAULT '',       -- operator enrollment binding ('' = none)
    signature     BLOB,                           -- operator Ed25519 (operator_signed rows)
    created_at    TEXT NOT NULL,
    UNIQUE (provider, model_ref, model_family, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_model_attestations_family
    ON model_attestations(model_family, agent_id);
