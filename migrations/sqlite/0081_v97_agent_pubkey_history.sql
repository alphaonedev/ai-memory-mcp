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
--   * 'guardian_recovery'  — an independently verified M-of-N guardian
--                            quorum; the only authority that may advance a
--                            closed/revoked latest history row;
--   * 'legacy_unproven'    — backfilled below from a PRE-#3464 binding, for
--                            which no proof of possession was ever required.
--                            Deliberately labelled so an operator can
--                            enumerate every binding that predates the gate.
--
-- The backfill copies each CANONICAL `_agents` row's live `agent_pubkey` in as
-- version 1 so no existing anchor is lost by the upgrade itself; `bound_at`
-- prefers the recorded `pubkey_bound_at` and falls back to `created_at`.
-- Pre-v97 generic writes could create registration-shaped rows, so matching
-- metadata.agent_id alone is unsafe: a noncanonical title could otherwise win
-- the backfill conflict for a victim's `(agent_id, 1)` and anchor an attacker key.
--
-- Additive, `IF NOT EXISTS`-idempotent (targeted PK conflict handling on the
-- PK makes the backfill re-runnable), reversible (drop both authoritative
-- triggers before dropping the two v97 tables; the flat binding remains the
-- live-key compatibility mirror), no data loss, no full-table rebuild.
CREATE TABLE IF NOT EXISTS agent_pubkey_history (
    agent_id       TEXT    NOT NULL,
    version        INTEGER NOT NULL,
    pubkey_b64     TEXT    NOT NULL CHECK (
        length(pubkey_b64) = 43 AND pubkey_b64 NOT GLOB '*[^A-Za-z0-9_-]*'
        AND substr(pubkey_b64, 43, 1) IN
            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8')
    ),
    bind_authority TEXT    NOT NULL,
    proof_nonce    TEXT,
    bound_at       TEXT    NOT NULL,
    superseded_at  TEXT,
    PRIMARY KEY (agent_id, version)
);

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_history_agent_bound
    ON agent_pubkey_history(agent_id, bound_at);

-- The storage engine, not a check-then-act read, enforces that an identity has
-- at most one CURRENT key. Closed windows remain append-only history.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_pubkey_history_one_open
    ON agent_pubkey_history(agent_id) WHERE superseded_at IS NULL;

-- A retired key can never become live again, including through guardian
-- recovery. This also makes a same-key multi-version history structurally
-- unrepresentable; an open same-key reassert remains an application no-op.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_pubkey_history_key_once
    ON agent_pubkey_history(agent_id, pubkey_b64);

INSERT INTO agent_pubkey_history
    (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
SELECT
    json_extract(metadata, '$.agent_id'),
    1,
    CASE
      WHEN (length(trim(json_extract(metadata, '$.agent_pubkey'))) = 43
            AND trim(json_extract(metadata, '$.agent_pubkey')) NOT GLOB '*[^A-Za-z0-9_-]*'
            AND substr(trim(json_extract(metadata, '$.agent_pubkey')), 43, 1)
                IN ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8'))
        OR (length(trim(json_extract(metadata, '$.agent_pubkey'))) = 44
            AND substr(trim(json_extract(metadata, '$.agent_pubkey')), 1, 43)
                NOT GLOB '*[^A-Za-z0-9+/]*'
            AND substr(trim(json_extract(metadata, '$.agent_pubkey')), 43, 1)
                IN ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8')
            AND substr(trim(json_extract(metadata, '$.agent_pubkey')), 44, 1) = '=')
      THEN rtrim(replace(replace(trim(json_extract(metadata, '$.agent_pubkey')),
                                 '+', '-'), '/', '_'), '=')
      ELSE trim(json_extract(metadata, '$.agent_pubkey'))
    END,
    'legacy_unproven',
    NULL,
    COALESCE(json_extract(metadata, '$.pubkey_bound_at'), created_at),
    NULL
FROM memories
WHERE namespace = '_agents'
  AND json_extract(metadata, '$.agent_pubkey') IS NOT NULL
  AND json_extract(metadata, '$.agent_id') IS NOT NULL
  AND title = 'agent:' || (json_extract(metadata, '$.agent_id'))
ON CONFLICT(agent_id, version) DO NOTHING;

-- Project a legacy padded/standard spelling back from canonical history.
-- Changing signed bytes requires removing the old signature and downgrading
-- both mirrors to `claimed` before the authoritative trigger is installed.
UPDATE memories
SET metadata = json_set(
        json_remove(metadata, '$.write_signature'),
        '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history
                           WHERE agent_id = json_extract(memories.metadata, '$.agent_id')
                             AND superseded_at IS NULL),
        '$.attest_level', 'claimed'),
    content = json_set(
        json_remove(metadata, '$.write_signature'),
        '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history
                           WHERE agent_id = json_extract(memories.metadata, '$.agent_id')
                             AND superseded_at IS NULL),
        '$.attest_level', 'claimed'),
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE namespace = '_agents'
  AND title = 'agent:' || (json_extract(metadata, '$.agent_id'))
  AND EXISTS (SELECT 1 FROM agent_pubkey_history
               WHERE agent_id = json_extract(memories.metadata, '$.agent_id')
                 AND superseded_at IS NULL
                 AND (pubkey_b64 IS NOT json_extract(memories.metadata, '$.agent_pubkey')
                      OR pubkey_b64 IS NOT json_extract(
                          CASE WHEN json_valid(memories.content) THEN memories.content ELSE '{}' END,
                          '$.agent_pubkey')));

-- The history ledger is the trust authority.  A generic memory/import/
-- federation write may carry an `_agents.metadata.agent_pubkey`, but it has
-- no possession or lineage witness and therefore may not create or replace a
-- binding.  Reconcile both JSON mirrors to the one CURRENT history row (or
-- remove the pair when there is no current row).  The explicit bind/lineage
-- funnels append/rotate history BEFORE updating `memories`, so their writes
-- already equal the authoritative pair and this trigger is an idempotent
-- no-op.  This is the backend-blind backstop for every present and future
-- generic write surface, including `--trust-source` restores.
-- Any projection correction also clears the now-stale `write_signature` and
-- forces `attest_level=claimed` in both mirrors: trusted bytes must be exactly
-- the bytes the application verified, never bytes this trigger changed later.
CREATE TRIGGER IF NOT EXISTS agent_pubkey_history_authoritative_insert_v97
AFTER INSERT ON memories
WHEN NEW.namespace = '_agents' AND (
    json_extract(NEW.metadata, '$.agent_pubkey') IS NOT (
        SELECT pubkey_b64 FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(NEW.metadata, '$.pubkey_bound_at') IS NOT (
        SELECT bound_at FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END,
                 '$.agent_pubkey') IS NOT (
        SELECT pubkey_b64 FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END,
                 '$.pubkey_bound_at') IS NOT (
        SELECT bound_at FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    )
)
BEGIN
    UPDATE memories
       SET metadata = json_set(json_remove(CASE
             WHEN EXISTS (
                 SELECT 1 FROM agent_pubkey_history
                  WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                    AND superseded_at IS NULL
             ) THEN json_set(
                 json_remove(metadata, '$.agent_pubkey', '$.pubkey_bound_at'),
                 '$.agent_pubkey', (
                     SELECT pubkey_b64 FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 ),
                 '$.pubkey_bound_at', (
                     SELECT bound_at FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 )
             )
             ELSE json_remove(metadata, '$.agent_pubkey', '$.pubkey_bound_at')
           END, '$.write_signature'), '$.attest_level', 'claimed'),
           content = CASE WHEN json_valid(content) THEN
             json_set(json_remove(CASE WHEN EXISTS (
                 SELECT 1 FROM agent_pubkey_history
                  WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                    AND superseded_at IS NULL
             ) THEN json_set(
                 json_remove(content, '$.agent_pubkey', '$.pubkey_bound_at'),
                 '$.agent_pubkey', (
                     SELECT pubkey_b64 FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 ),
                 '$.pubkey_bound_at', (
                     SELECT bound_at FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 )
             )
             ELSE json_remove(content, '$.agent_pubkey', '$.pubkey_bound_at') END,
             '$.write_signature'), '$.attest_level', 'claimed')
             ELSE content END
     WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS agent_pubkey_history_authoritative_update_v97
AFTER UPDATE OF metadata, content, title, namespace ON memories
WHEN NEW.namespace = '_agents' AND (
    json_extract(NEW.metadata, '$.agent_pubkey') IS NOT (
        SELECT pubkey_b64 FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(NEW.metadata, '$.pubkey_bound_at') IS NOT (
        SELECT bound_at FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END,
                 '$.agent_pubkey') IS NOT (
        SELECT pubkey_b64 FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    ) OR
    json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END,
                 '$.pubkey_bound_at') IS NOT (
        SELECT bound_at FROM agent_pubkey_history
         WHERE agent_id = substr(NEW.title, length('agent:') + 1)
           AND superseded_at IS NULL
    )
)
BEGIN
    UPDATE memories
       SET metadata = json_set(json_remove(CASE
             WHEN EXISTS (
                 SELECT 1 FROM agent_pubkey_history
                  WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                    AND superseded_at IS NULL
             ) THEN json_set(
                 json_remove(metadata, '$.agent_pubkey', '$.pubkey_bound_at'),
                 '$.agent_pubkey', (
                     SELECT pubkey_b64 FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 ),
                 '$.pubkey_bound_at', (
                     SELECT bound_at FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 )
             )
             ELSE json_remove(metadata, '$.agent_pubkey', '$.pubkey_bound_at')
           END, '$.write_signature'), '$.attest_level', 'claimed'),
           content = CASE WHEN json_valid(content) THEN
             json_set(json_remove(CASE WHEN EXISTS (
                 SELECT 1 FROM agent_pubkey_history
                  WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                    AND superseded_at IS NULL
             ) THEN json_set(
                 json_remove(content, '$.agent_pubkey', '$.pubkey_bound_at'),
                 '$.agent_pubkey', (
                     SELECT pubkey_b64 FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 ),
                 '$.pubkey_bound_at', (
                     SELECT bound_at FROM agent_pubkey_history
                      WHERE agent_id = substr(NEW.title, length('agent:') + 1)
                        AND superseded_at IS NULL
                 )
             )
             ELSE json_remove(content, '$.agent_pubkey', '$.pubkey_bound_at') END,
             '$.write_signature'), '$.attest_level', 'claimed')
             ELSE content END
     WHERE id = NEW.id;
END;

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
-- so the storage engine's own row-level decision is what admits at most one
-- proof-verification attempt per challenge — never a check-then-act read (the v95
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
    pubkey_b64       TEXT NOT NULL CHECK (
        length(pubkey_b64) = 43 AND pubkey_b64 NOT GLOB '*[^A-Za-z0-9_-]*'
        AND substr(pubkey_b64, 43, 1) IN
            ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8')
    ),
    nonce            TEXT NOT NULL UNIQUE,
    issued_at        TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT,
    issuer_daemon_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_challenges_expires
    ON agent_pubkey_challenges(expires_at);
