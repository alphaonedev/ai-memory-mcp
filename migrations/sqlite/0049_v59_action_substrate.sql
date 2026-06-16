-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 Pillar 1 (#1709) — distributed coordination substrate, foundation
-- schema (v59, sqlite). Three additive tables backing the action state
-- machine, its typed dependency DAG, and the lease+heartbeat resilience
-- layer. The SAL methods + `memory_action_*` / `memory_lease_*` MCP tools
-- land on top of these in subsequent units; this migration is schema-only.
--
-- All TEXT ids + BIGINT/INTEGER epoch-second timestamps, mirroring the
-- ROADMAP §11.4 Pillar-1 signals DDL convention. `namespace` is a bare TEXT
-- column (no FK — there is no `namespaces` table; consistent with
-- `memories.namespace`). Idempotent via `IF NOT EXISTS`.

-- actions — the coordination-action state machine. State transitions
-- (pending → claimed → in_progress → done | failed | abandoned) are enforced
-- by the SAL layer, not a CHECK, so a future state can be added without a
-- migration. `vector_clock` (JSON) carries the per-action causal clock for
-- federation merge (ROADMAP §11.4 Pillar-1).
CREATE TABLE IF NOT EXISTS actions (
    id           TEXT    NOT NULL PRIMARY KEY,
    namespace    TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    state        TEXT    NOT NULL DEFAULT 'pending',
    title        TEXT    NOT NULL DEFAULT '',
    payload      TEXT    NOT NULL DEFAULT '{}',
    priority     INTEGER NOT NULL DEFAULT 5,
    agent_id     TEXT,
    claimed_by   TEXT,
    vector_clock TEXT    NOT NULL DEFAULT '{}',
    metadata     TEXT    NOT NULL DEFAULT '{}',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_ns_state ON actions(namespace, state);
CREATE INDEX IF NOT EXISTS idx_actions_state_priority ON actions(state, priority DESC);

-- action_edges — typed dependency DAG. Edge types: requires | unlocks |
-- blocks | gated_by | sibling. The composite PK keeps the substrate
-- idempotent under duplicate edge declarations.
CREATE TABLE IF NOT EXISTS action_edges (
    from_action TEXT    NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    to_action   TEXT    NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    edge_type   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (from_action, to_action, edge_type)
);
-- Inbound-edge probe for blocked-frontier computation.
CREATE INDEX IF NOT EXISTS idx_action_edges_to ON action_edges(to_action);

-- leases — lease + heartbeat resilience (one lease per action). The sweeper
-- scans `expires_at` to release stale leases (and emit a `signed_events`
-- audit row). PK on `action_id` enforces single-holder.
CREATE TABLE IF NOT EXISTS leases (
    action_id    TEXT    NOT NULL PRIMARY KEY REFERENCES actions(id) ON DELETE CASCADE,
    holder       TEXT    NOT NULL,
    acquired_at  INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    heartbeat_at INTEGER NOT NULL
);
-- Outer scan for the expired-lease sweeper.
CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at);
