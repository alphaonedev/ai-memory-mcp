-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v97 (#3464, v1.0.0, security-high) — APPEND-ONLY AGENT PUBKEY HISTORY
-- (Postgres).
--
-- Doc twin of `PostgresStore::migrate_v97` in `src/store/postgres.rs`, and the
-- parity twin of `migrations/sqlite/0081_v97_agent_pubkey_history.sql`.
--
-- Pre-#3464 an agent's Ed25519 attestation key lived ONLY in the flat
-- `metadata.agent_pubkey` field of its `_agents` registration row, and every
-- rebind OVERWROTE it — silently destroying the anchor for every
-- `agent_attested` row the previous key signed, so none of them could be
-- re-verified again (`row_is_agent_attested`, the federation
-- `AI_MEMORY_FED_REQUIRE_WRITE_SIG` lane, any attestation audit).
--
-- `agent_pubkey_history` is that anchor's append-only ledger: one row per
-- (agent, dense 1-based key version); the composite PRIMARY KEY
-- `(agent_id, version)` is the anti-equivocation constraint (a duplicate
-- version is refused by the DATABASE — the `agent_lineage (agent_id, epoch)`
-- precedent); `bound_at`/`superseded_at` are the key's half-open
-- `[bound_at, superseded_at)` validity window. Rows are never deleted and
-- `pubkey_b64` is never rewritten; the sole mutation is stamping
-- `superseded_at` once on the row whose window is still open.
--
-- `bind_authority` records WHY a binding was admitted: 'possession_proof'
-- (the candidate key signed a server-issued, single-use, domain-separated
-- challenge — the only authority reachable from an external surface),
-- 'lineage_succession' (a verified succession record signed by the agent's
-- CURRENT key-holder), or 'legacy_unproven' (backfilled below from a
-- PRE-#3464 binding, which was never required to prove possession —
-- deliberately labelled so an operator can enumerate every such binding).
--
-- The backfill copies each `_agents` row's live `agent_pubkey` in as version 1
-- so the upgrade itself loses no anchor.
--
-- Additive, `IF NOT EXISTS` + `ON CONFLICT DO NOTHING` idempotent, reversible
-- (revert is DROP TABLE — the flat binding this arm does not touch remains the
-- live key), no data loss, no table rewrite, no blocking DDL on `memories`.
CREATE TABLE IF NOT EXISTS agent_pubkey_history (
    agent_id       TEXT   NOT NULL,
    version        BIGINT NOT NULL,
    pubkey_b64     TEXT   NOT NULL,
    bind_authority TEXT   NOT NULL,
    proof_nonce    TEXT,
    bound_at       TEXT   NOT NULL,
    superseded_at  TEXT,
    PRIMARY KEY (agent_id, version)
);

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_history_agent_bound
    ON agent_pubkey_history(agent_id, bound_at);

INSERT INTO agent_pubkey_history
    (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
SELECT
    metadata->>'agent_id',
    1,
    metadata->>'agent_pubkey',
    'legacy_unproven',
    NULL,
    COALESCE(metadata->>'pubkey_bound_at', created_at::text),
    NULL
FROM memories
WHERE namespace = '_agents'
  AND metadata->>'agent_pubkey' IS NOT NULL
  AND metadata->>'agent_id' IS NOT NULL
ON CONFLICT (agent_id, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- agent_pubkey_challenges — DURABLE proof-of-possession bind challenges.
--
-- The parity twin of the sqlite table. Durable rather than in-process because
-- THIS tier is precisely the one that supports several daemons on one shared
-- store (the #2445 guard calls the schema "SHARED by every daemon on the
-- cluster"), so challenge-on-replica-A / bind-on-replica-B is a supported
-- deployment shape. An in-process cache would fail those binds closed with an
-- opaque 403 and no in-product remedy, and would void every outstanding
-- enrolment on a rolling deploy.
--
-- `pubkey_b64` is stored server-side ON PURPOSE: it rides inside the signed
-- transcript, so the candidate key is pinned by the ISSUER and the bind
-- re-checks the caller's key against this row.
--
-- Single use is the `consumed_at IS NULL` predicate of the consuming
-- `UPDATE ... RETURNING`, so exactly one bind is admitted per challenge even
-- under concurrent submission — the decision is the row-level write, never a
-- check-then-act read. Expired rows are reaped by `gc`.
--
-- Additive, `IF NOT EXISTS`-idempotent, reversible (DROP TABLE), NoLoss.
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
