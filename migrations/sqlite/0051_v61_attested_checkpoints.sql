-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 Pillar 1 (#1709) — attested-checkpoints storage foundation schema
-- (v61, sqlite). One additive table backing the agent-coordination
-- checkpoint substrate (conditional gates whose resolution is Ed25519-
-- attested). The SAL methods + `memory_checkpoint_*` MCP tools + the
-- signing/verification logic land on top of this in subsequent units;
-- this migration is schema-only.
--
-- All TEXT ids + INTEGER epoch-second timestamps + BLOB Ed25519 material,
-- mirroring the ROADMAP §11.4 Pillar-1 DDL convention and the v60
-- signed-signals migration (`0050_v60_signed_signals.sql`). `namespace`
-- is a bare TEXT column (no FK — there is no `namespaces` table; consistent
-- with `memories.namespace`, `actions.namespace`, and `signals.namespace`;
-- the ROADMAP DDL's `FOREIGN KEY (namespace) REFERENCES namespaces(name)`
-- is intentionally OMITTED because no such PK table exists). Idempotent via
-- `IF NOT EXISTS`.

-- checkpoints — conditional coordination gates. `condition_type` is one of
-- approval | external_signal | condition_predicate | deadline (enforced by
-- the SAL layer, not a CHECK, so a future type can be added without a
-- migration). `condition` is a JSON condition spec; `state` is one of
-- pending | resolved | rejected | expired. `signature` / `resolver_pubkey`
-- are the Ed25519 attestation over the canonical resolution (populated only
-- once a checkpoint resolves, hence nullable).
CREATE TABLE IF NOT EXISTS checkpoints (
    id              TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    title           TEXT NOT NULL,
    condition_type  TEXT NOT NULL,                 -- approval|external_signal|condition_predicate|deadline
    condition       TEXT NOT NULL DEFAULT '{}',    -- JSON condition spec
    state           TEXT NOT NULL,                 -- pending|resolved|rejected|expired
    created_by      TEXT NOT NULL,
    resolved_by     TEXT,
    resolution      TEXT,
    resolution_note TEXT,
    signature       BLOB,                           -- Ed25519 over the canonical resolution (attested)
    resolver_pubkey BLOB,
    created_at      INTEGER NOT NULL,
    deadline_at     INTEGER,
    resolved_at     INTEGER,
    metadata        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_ns_state ON checkpoints(namespace, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_checkpoints_condition_type ON checkpoints(condition_type);
CREATE INDEX IF NOT EXISTS idx_checkpoints_deadline ON checkpoints(deadline_at);
