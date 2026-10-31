-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v101 (#8444, v1.0.0): durable task table for the Google Agent2Agent (A2A 1.0)
-- standard binding (`POST /api/v1/a2a`). One row per A2A Task, owned by the
-- AUTHENTICATED agent that created it (`agent_id` is taken from the
-- credential, never from a request header or body). `state` is the A2A
-- TaskState wire string; transitions are compare-and-set UPDATEs so a
-- concurrent CancelTask and completion leave exactly one terminal state.
-- Additive `CREATE TABLE IF NOT EXISTS`, idempotent, reversible (NoLoss: the
-- table is new and no existing row is touched). The postgres twin is
-- `PostgresStore::migrate_v101` (`migrations/postgres/0058_v101_a2a_tasks.sql`;
-- the file numbers differ per backend, the logical schema version is one).
CREATE TABLE IF NOT EXISTS a2a_tasks (
    id               TEXT PRIMARY KEY,
    context_id       TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    state            TEXT NOT NULL,
    status_timestamp TEXT NOT NULL,
    history_json     TEXT NOT NULL DEFAULT '[]',
    artifacts_json   TEXT NOT NULL DEFAULT '[]',
    metadata_json    TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_agent_updated
    ON a2a_tasks (agent_id, updated_at);
