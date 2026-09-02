-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v97 (#3464, v1.0.0, security-high) — APPEND-ONLY AGENT PUBKEY HISTORY
-- (SQLite).
--
-- Doc twin of the inline `MIGRATION_V97_SQLITE` arm in
-- `src/storage/migrations.rs`.
--
-- Before #3464 an agent's Ed25519 attestation key lived ONLY in the flat
-- `metadata.agent_pubkey` field of its `_agents` registration row, and every
-- rebind (`bind_agent_pubkey`) OVERWROTE it. That silently destroyed the
-- anchor for every `agent_attested` row the previous key had signed: those
-- rows can no longer be re-verified by `row_is_agent_attested`, by federation
-- under `AI_MEMORY_FED_REQUIRE_WRITE_SIG=1`, or by any attestation audit.
-- Destroying a durable provenance anchor to record a rotation is exactly the
-- data-loss class the substrate must never have.
--
-- This table is the append-only ledger of that anchor. One row per (agent,
-- key version): `version` is dense and 1-based per agent, the composite
-- PRIMARY KEY `(agent_id, version)` is the anti-equivocation constraint (a
-- duplicate version is refused by the DATABASE, not merely by code — the
-- `agent_lineage` (agent_id, epoch) precedent), `bound_at` opens the key's
-- validity window and `superseded_at` closes it when the next key is bound or
-- the key is revoked. A row is NEVER deleted and its `pubkey_b64` is NEVER
-- rewritten; the only mutation is stamping `superseded_at` exactly once, on
-- the row whose window is still open.
--
-- `bind_authority` records WHY the binding was admitted:
--   * 'possession_proof'   — the candidate key signed a server-issued,
--                            single-use, domain-separated challenge
--                            (`crate::identity::pubkey_bind`), the only
--                            authority reachable from an external surface;
--   * 'lineage_succession' — a verified succession record: the agent's
--                            CURRENT key-holder signed the rotation;
--   * 'legacy_unproven'    — backfilled below from a PRE-#3464 binding, for
--                            which no proof of possession was ever required.
--                            Deliberately labelled so an operator can
--                            enumerate every binding that predates the gate.
--
-- The backfill copies each `_agents` row's live `agent_pubkey` in as version
-- 1 so no existing anchor is lost by the upgrade itself; `bound_at` prefers
-- the recorded `pubkey_bound_at` and falls back to the row's `created_at`.
--
-- Additive, `IF NOT EXISTS`-idempotent (`INSERT OR IGNORE` on the composite
-- PK makes the backfill re-runnable), reversible (revert is DROP TABLE — the
-- flat `metadata.agent_pubkey` binding this ladder does not touch remains the
-- live key), no data loss, no full-table rebuild.
CREATE TABLE IF NOT EXISTS agent_pubkey_history (
    agent_id       TEXT    NOT NULL,
    version        INTEGER NOT NULL,
    pubkey_b64     TEXT    NOT NULL,
    bind_authority TEXT    NOT NULL,
    proof_nonce    TEXT,
    bound_at       TEXT    NOT NULL,
    superseded_at  TEXT,
    PRIMARY KEY (agent_id, version)
);

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_history_agent_bound
    ON agent_pubkey_history(agent_id, bound_at);

INSERT OR IGNORE INTO agent_pubkey_history
    (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
SELECT
    json_extract(metadata, '$.agent_id'),
    1,
    json_extract(metadata, '$.agent_pubkey'),
    'legacy_unproven',
    NULL,
    COALESCE(json_extract(metadata, '$.pubkey_bound_at'), created_at),
    NULL
FROM memories
WHERE namespace = '_agents'
  AND json_extract(metadata, '$.agent_pubkey') IS NOT NULL
  AND json_extract(metadata, '$.agent_id') IS NOT NULL;

-- ---------------------------------------------------------------------------
-- agent_pubkey_challenges — DURABLE proof-of-possession bind challenges.
--
-- The challenge a candidate key must sign before `bind_agent_pubkey` will
-- accept it. Durable, NOT in-process, because the certified Postgres tier
-- explicitly supports SEVERAL DAEMONS ON ONE SHARED STORE (the #2445 guard
-- calls the schema "SHARED by every daemon on the cluster"): issuing the
-- challenge on replica A and answering it on replica B is a SUPPORTED shape,
-- not an edge case, so an in-process cache would fail those binds closed with
-- an opaque 403 and no in-product remedy. It also survives a restart, so a
-- rolling deploy does not silently void every outstanding enrolment.
--
-- `pubkey_b64` is stored server-side ON PURPOSE: it is part of the signed
-- transcript, so the candidate key is pinned by the ISSUER and the bind
-- re-checks the caller's key against this row. A caller-supplied key at bind
-- time could otherwise retarget a live challenge at a different key.
--
-- Single use is the `consumed_at IS NULL` predicate of the consuming UPDATE,
-- so the storage engine's own row-level decision is what admits exactly one
-- bind per challenge — never a check-then-act read (the v95
-- `attested_write_ledger` discipline, where the constraint IS the decision).
-- Expired rows are reaped by `gc`; retention is bounded by the challenge TTL,
-- never by history.
--
-- Additive, `IF NOT EXISTS`-idempotent, reversible (DROP TABLE), NoLoss — the
-- table holds only short-lived, regenerable enrolment state, never durable
-- memory truth.
CREATE TABLE IF NOT EXISTS agent_pubkey_challenges (
    challenge_id     TEXT NOT NULL PRIMARY KEY,
    agent_id         TEXT NOT NULL,
    pubkey_b64       TEXT NOT NULL,
    nonce            TEXT NOT NULL UNIQUE,
    issued_at        TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT,
    issuer_daemon_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_challenges_expires
    ON agent_pubkey_challenges(expires_at);
