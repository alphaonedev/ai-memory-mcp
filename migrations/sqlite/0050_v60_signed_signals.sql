-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 Pillar 1 (#1709) — signed-signals storage foundation schema
-- (v60, sqlite). One additive table backing the agent-to-agent signed
-- signal substrate (typed, Ed25519-signed inter-agent messages). The SAL
-- methods + `memory_signal_*` MCP tools + the signing/verification logic
-- land on top of this in subsequent units; this migration is schema-only.
--
-- All TEXT ids + INTEGER epoch-second timestamps + BLOB Ed25519 material,
-- mirroring the ROADMAP §11.4 Pillar-1 signals DDL convention and the v59
-- action-substrate migration (`0049_v59_action_substrate.sql`). `namespace`
-- is a bare TEXT column (no FK — there is no `namespaces` table; consistent
-- with `memories.namespace` and `actions.namespace`; the ROADMAP DDL's
-- `FOREIGN KEY (namespace) REFERENCES namespaces(name)` is intentionally
-- OMITTED because no such PK table exists). Idempotent via `IF NOT EXISTS`.

-- signals — typed, signed inter-agent messages. `signal_type` is one of
-- authorize | notify | request | response | broadcast (enforced by the SAL
-- layer, not a CHECK, so a future type can be added without a migration).
-- `body` is a JSON-typed payload; `reference_ids` is a JSON array. The
-- `in_reply_to` self-FK threads responses back onto their request. NB: the
-- `reference_ids` column is renamed from the ROADMAP's `references` —
-- `references` is a SQL reserved word in both sqlite and postgres, so using
-- it bare invites breakage; the rename is carried through model + postgres.
CREATE TABLE IF NOT EXISTS signals (
    id              TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    from_agent      TEXT NOT NULL,
    to_agent        TEXT,                          -- NULL = broadcast within namespace
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,                 -- JSON-typed payload
    signal_type     TEXT NOT NULL,                 -- authorize|notify|request|response|broadcast
    in_reply_to     TEXT,
    correlation_id  TEXT,
    reference_ids   TEXT NOT NULL DEFAULT '[]',    -- JSON array; renamed from ROADMAP `references` (SQL reserved word)
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    delivered_at    INTEGER,
    read_at         INTEGER,
    acknowledged_at INTEGER,
    signature       BLOB NOT NULL,                 -- Ed25519 over canonical content
    sender_pubkey   BLOB NOT NULL,
    FOREIGN KEY (in_reply_to) REFERENCES signals(id)
);
CREATE INDEX IF NOT EXISTS idx_signals_namespace ON signals(namespace, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_signals_to_agent ON signals(to_agent, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_signals_correlation ON signals(correlation_id);
