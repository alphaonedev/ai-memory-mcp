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
-- CURRENT key-holder), 'guardian_recovery' (an independently verified M-of-N
-- guardian quorum, the only authority that may advance a closed head), or
-- 'legacy_unproven' (backfilled below from a
-- PRE-#3464 binding, which was never required to prove possession —
-- deliberately labelled so an operator can enumerate every such binding).
--
-- The backfill copies each CANONICAL `_agents` row's live `agent_pubkey` in as
-- version 1 so the upgrade itself loses no anchor. Pre-v97 generic writes
-- could create registration-shaped rows, so metadata.agent_id alone is not an
-- identity authority: a noncanonical title must never win ON CONFLICT for a
-- victim's `(agent_id, 1)` and anchor an attacker key.
--
-- Additive, `IF NOT EXISTS` + `ON CONFLICT DO NOTHING` idempotent, reversible
-- (drop the authoritative trigger/function before the two v97 tables; the flat
-- binding remains the live-key compatibility mirror), no data loss and no
-- table rewrite.
CREATE TABLE IF NOT EXISTS agent_pubkey_history (
    agent_id       TEXT   NOT NULL,
    version        BIGINT NOT NULL,
    pubkey_b64     TEXT   NOT NULL CONSTRAINT agent_pubkey_history_pubkey_canonical
        CHECK (length(pubkey_b64) = 43 AND pubkey_b64 ~ '^[A-Za-z0-9_-]{43}$'
               AND right(pubkey_b64, 1) IN
                   ('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8')),
    bind_authority TEXT   NOT NULL,
    proof_nonce    TEXT,
    bound_at       TEXT   NOT NULL,
    superseded_at  TEXT,
    PRIMARY KEY (agent_id, version)
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM agent_pubkey_history
         GROUP BY agent_id, pubkey_b64 HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'v97 pubkey history corruption: a retired key appears in multiple versions; refusing migration rather than deduplicating trust history';
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_agent_pubkey_history_agent_bound
    ON agent_pubkey_history(agent_id, bound_at);

-- The storage engine, not a check-then-act read, enforces that an identity has
-- at most one CURRENT key. Closed windows remain append-only history.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_pubkey_history_one_open
    ON agent_pubkey_history(agent_id) WHERE superseded_at IS NULL;

-- A superseded/revoked key is permanently retired. Guardian recovery may
-- advance a closed head, but may not resurrect any prior key material.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_pubkey_history_key_once
    ON agent_pubkey_history(agent_id, pubkey_b64);

-- Close the upgrade cutover race. Without this transaction-scoped write lock,
-- a generic `_agents` write could commit after the backfill SELECT but before
-- CREATE TRIGGER, leaving a flat key with no v97 history row forever. Reads
-- remain available; writers resume after the ladder transaction commits with
-- the authoritative trigger installed.
LOCK TABLE memories IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO agent_pubkey_history
    (agent_id, version, pubkey_b64, bind_authority, proof_nonce, bound_at, superseded_at)
SELECT
    metadata->>'agent_id',
    1,
    CASE
      WHEN btrim(metadata->>'agent_pubkey') ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
        OR btrim(metadata->>'agent_pubkey') ~ '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'
      THEN translate(rtrim(btrim(metadata->>'agent_pubkey'), '='), '+/', '-_')
      ELSE btrim(metadata->>'agent_pubkey')
    END,
    'legacy_unproven',
    NULL,
    COALESCE(metadata->>'pubkey_bound_at', created_at::text),
    NULL
FROM memories
WHERE namespace = '_agents'
  AND metadata->>'agent_pubkey' IS NOT NULL
  AND metadata->>'agent_id' IS NOT NULL
  AND title = 'agent:' || (metadata->>'agent_id')
ON CONFLICT (agent_id, version) DO NOTHING;

-- Reconcile a pre-v97 padded/standard flat spelling to canonical history.
-- The spelling change mutates signed bytes, so both mirrors are rebuilt from
-- one projection and truthfully downgraded before the trigger is installed.
WITH canonicalized AS (
    SELECT m.id,
           (m.metadata - 'write_signature') ||
             jsonb_build_object('agent_pubkey', h.pubkey_b64,
                                'attest_level', 'claimed') AS projection
      FROM memories AS m
      JOIN agent_pubkey_history AS h
        ON h.agent_id = m.metadata->>'agent_id' AND h.superseded_at IS NULL
     WHERE m.namespace = '_agents'
       AND m.title = 'agent:' || (m.metadata->>'agent_id')
       AND (m.metadata->>'agent_pubkey' IS DISTINCT FROM h.pubkey_b64
            OR (m.content::jsonb)->>'agent_pubkey' IS DISTINCT FROM h.pubkey_b64)
)
UPDATE memories AS m
   SET metadata = canonicalized.projection,
       content = canonicalized.projection::text,
       updated_at = CURRENT_TIMESTAMP
  FROM canonicalized
 WHERE m.id = canonicalized.id;

-- The history ledger, not caller-provided registration JSON, is the trust
-- authority. This ladder-owned function/trigger MUST remain out of the
-- replayed postgres_schema.sql: INIT_SCHEMA runs before migrations, and early
-- installation would expose empty history before this transaction's lock and
-- backfill preserve legacy flat keys. Generic memory/import/federation writes
-- are reconciled to the
-- one CURRENT history row, or have the binding pair removed when no current
-- row exists.  Explicit PoP/lineage bind writes append history first, inside
-- the same transaction, so this trigger preserves their exact pair.  This
-- closes post-v97 flat-key planting through every current and future generic
-- write surface, including an operator-selected `--trust-source` restore.
-- Any correction also removes the now-stale `write_signature` and forces
-- `attest_level=claimed` in both JSON representations, so a trusted stamp can
-- never describe bytes this trigger changed after application verification.
CREATE OR REPLACE FUNCTION reconcile_agent_pubkey_from_history_v97()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    canonical_agent_id TEXT;
    current_pubkey TEXT;
    current_bound_at TEXT;
    content_json JSONB;
    reconciled_metadata JSONB;
    reconciled_content JSONB;
    projection_changed BOOLEAN := FALSE;
BEGIN
    IF NEW.namespace <> '_agents' THEN
        RETURN NEW;
    END IF;

    canonical_agent_id := substring(NEW.title FROM length('agent:') + 1);
    SELECT pubkey_b64, bound_at
      INTO current_pubkey, current_bound_at
      FROM agent_pubkey_history
     WHERE agent_id = canonical_agent_id
       AND superseded_at IS NULL;

    reconciled_metadata := NEW.metadata - 'agent_pubkey' - 'pubkey_bound_at';
    IF current_pubkey IS NOT NULL THEN
        reconciled_metadata := reconciled_metadata || jsonb_build_object(
            'agent_pubkey', current_pubkey,
            'pubkey_bound_at', current_bound_at
        );
    END IF;
    IF reconciled_metadata IS DISTINCT FROM NEW.metadata THEN
        NEW.metadata := reconciled_metadata;
        projection_changed := TRUE;
    END IF;

    BEGIN
        content_json := NEW.content::jsonb;
        IF jsonb_typeof(content_json) = 'object' THEN
            reconciled_content := content_json - 'agent_pubkey' - 'pubkey_bound_at';
            IF current_pubkey IS NOT NULL THEN
                reconciled_content := reconciled_content || jsonb_build_object(
                    'agent_pubkey', current_pubkey,
                    'pubkey_bound_at', current_bound_at
                );
            END IF;
            IF reconciled_content IS DISTINCT FROM content_json THEN
                NEW.content := reconciled_content::text;
                projection_changed := TRUE;
            END IF;
        END IF;
    EXCEPTION WHEN invalid_text_representation THEN
        -- A malformed legacy registration body is not a trust input; metadata
        -- remains reconciled and the opaque body crosses unchanged.
        NULL;
    END;

    IF projection_changed THEN
        NEW.metadata := (NEW.metadata - 'write_signature')
            || jsonb_build_object('attest_level', 'claimed');
        IF jsonb_typeof(content_json) = 'object' THEN
            reconciled_content := (reconciled_content - 'write_signature')
                || jsonb_build_object('attest_level', 'claimed');
            NEW.content := reconciled_content::text;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_v97 ON memories;
CREATE TRIGGER agent_pubkey_history_authoritative_v97
BEFORE INSERT OR UPDATE OF metadata, content, title, namespace ON memories
FOR EACH ROW EXECUTE FUNCTION reconcile_agent_pubkey_from_history_v97();

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
-- `UPDATE ... RETURNING`, so at most one proof-verification attempt is admitted
-- per challenge even under concurrent submission — a bad answer burns the
-- nonce and the decision is the row-level write, never a
-- check-then-act read. Expired rows are reaped by `gc`.
--
-- Additive, `IF NOT EXISTS`-idempotent, reversible (DROP TABLE), NoLoss.
CREATE TABLE IF NOT EXISTS agent_pubkey_challenges (
    challenge_id     TEXT NOT NULL PRIMARY KEY,
    agent_id         TEXT NOT NULL,
    pubkey_b64       TEXT NOT NULL CHECK (
        length(pubkey_b64) = 43 AND pubkey_b64 ~ '^[A-Za-z0-9_-]{43}$'
        AND right(pubkey_b64, 1) IN
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
