-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v101 (#8487, v1.0.0): the optional sender idempotency key on memory_notify —
-- the postgres twin of migrations/sqlite/0085_v101_notify_dedup.sql. See that
-- file for the shape. The row is written in the SAME transaction as the inbox
-- row. Additive, idempotent, reversible (DROP TABLE notify_dedup; no inbox row
-- is touched).
CREATE TABLE IF NOT EXISTS notify_dedup (
    sender         TEXT NOT NULL,
    target         TEXT NOT NULL,
    key            TEXT NOT NULL,
    memory_id      TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (sender, target, key)
);
CREATE INDEX IF NOT EXISTS idx_notify_dedup_memory_id ON notify_dedup(memory_id);
