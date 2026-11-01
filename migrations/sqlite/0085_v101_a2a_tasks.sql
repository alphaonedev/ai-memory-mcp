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

-- Content-free task history (#8444 r2): a task NEVER stores message content.
-- `history_json` holds only ids; the content stays in the inbox memory (the
-- memory funnel is the sole content store: erase, at-rest sealing and the
-- secret screen all apply). This link table ties a task to the inbox
-- memories its history names, so every path that deletes a memory (erase,
-- delete, gc, archive) removes the link in the SAME statement via ON DELETE
-- CASCADE, and GetTask renders only entries whose memory is still linked.
CREATE TABLE IF NOT EXISTS a2a_task_memories (
    task_id   TEXT NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, memory_id)
);
CREATE INDEX IF NOT EXISTS idx_a2a_task_memories_memory
    ON a2a_task_memories (memory_id);
