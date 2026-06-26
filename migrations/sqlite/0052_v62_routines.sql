-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 Pillar 1 (#1709) — routines storage foundation schema (v62,
-- sqlite). Two additive tables backing the agent-coordination routine
-- substrate: `routines` (parameterised action+edge templates that can be
-- frozen into an immutable, regulatory-hold form) and `routine_runs` (one
-- materialisation of a routine under a concrete argument binding). The SAL
-- methods + `memory_routine_*` MCP tools + the freeze-attestation
-- signing/verification logic land on top of this in subsequent units; this
-- migration is schema-only.
--
-- All TEXT ids + INTEGER epoch-second timestamps + BLOB Ed25519 material,
-- mirroring the ROADMAP §11.4 Pillar-1 DDL convention and the v61
-- attested-checkpoints migration (`0051_v61_attested_checkpoints.sql`).
-- `namespace` is a bare TEXT column (no FK — there is no `namespaces`
-- table; consistent with `memories.namespace`, `actions.namespace`,
-- `signals.namespace`, and `checkpoints.namespace`; the ROADMAP DDL's
-- `FOREIGN KEY (namespace) REFERENCES namespaces(name)` is intentionally
-- OMITTED because no such PK table exists). The `routine_runs.routine_id`
-- self/parent FK to `routines(id)` IS documented + present. Idempotent via
-- `IF NOT EXISTS`.

-- routines — parameterised action+edge templates. `template` is a JSON
-- spec of action + edge declarations carrying `{{parameter}}` placeholders;
-- `parameters` is the JSON array of declared parameter names. `state` is
-- one of draft | frozen (frozen = immutable, regulatory hold; enforced by
-- the SAL layer, not a CHECK, so a future state can be added without a
-- migration). `signature` / `signer_pubkey` are the future
-- freeze-attestation Ed25519 material (caller-provided / empty for now,
-- hence nullable).
CREATE TABLE IF NOT EXISTS routines (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    template    TEXT NOT NULL,                 -- JSON: action + edge declarations w/ {{parameter}} placeholders
    parameters  TEXT NOT NULL DEFAULT '[]',    -- JSON array of declared parameter names
    state       TEXT NOT NULL,                 -- draft | frozen (frozen = immutable, regulatory hold)
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    frozen_at   INTEGER,
    signature   BLOB,                          -- future freeze-attestation (caller-provided/empty for now)
    signer_pubkey BLOB,
    metadata    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_routines_ns_state ON routines(namespace, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_routines_name ON routines(name);

-- routine_runs — one materialisation of a routine under a concrete
-- argument binding. `arguments` is the JSON `{{parameter}} -> value`
-- binding for this run; `state` is one of pending | running | completed |
-- failed (enforced by the SAL layer, not a CHECK). `created_action_ids` is
-- the JSON array of action ids this run materialised. `error` carries the
-- failure detail when `state = failed`.
CREATE TABLE IF NOT EXISTS routine_runs (
    id                 TEXT PRIMARY KEY,
    routine_id         TEXT NOT NULL,
    namespace          TEXT NOT NULL,
    arguments          TEXT NOT NULL DEFAULT '{}',  -- JSON: {{parameter}} -> value bindings for this run
    state              TEXT NOT NULL,               -- pending | running | completed | failed
    created_action_ids TEXT NOT NULL DEFAULT '[]',  -- JSON array of action ids this run materialized
    started_at         INTEGER NOT NULL,
    finished_at        INTEGER,
    error              TEXT,
    metadata           TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (routine_id) REFERENCES routines(id)
);
CREATE INDEX IF NOT EXISTS idx_routine_runs_routine ON routine_runs(routine_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_routine_runs_ns_state ON routine_runs(namespace, state);
