-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v101 (#8444, v1.0.0): durable task table for the Google Agent2Agent (A2A 1.0)
-- standard binding. Postgres twin of
-- `migrations/sqlite/0085_v101_a2a_tasks.sql`; see it for the contract.
-- Additive, idempotent, NoLoss.
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

-- Content-free task history (#8444 r2); see the sqlite twin for the contract.
CREATE TABLE IF NOT EXISTS a2a_task_memories (
    task_id   TEXT NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, memory_id)
);
CREATE INDEX IF NOT EXISTS idx_a2a_task_memories_memory
    ON a2a_task_memories (memory_id);
