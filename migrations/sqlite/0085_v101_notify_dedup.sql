-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v101 (#8487, v1.0.0): the optional sender idempotency key on memory_notify.
--
-- One row per (sender, target, key): the id of the inbox row the first
-- delivery created and the sha256 fingerprint of what was delivered. A retry
-- with the same fingerprint is answered with `memory_id`; a different
-- fingerprint is a typed conflict. The row is written in the SAME transaction
-- as the inbox row, so a crash leaves both or neither. `sender` is the
-- server-resolved caller, never a request field. Additive and idempotent
-- (CREATE TABLE IF NOT EXISTS); reversible by dropping the table (a dropped
-- table only re-enables a duplicate delivery on retry; no inbox row is touched).
CREATE TABLE IF NOT EXISTS notify_dedup (
    sender         TEXT NOT NULL,
    target         TEXT NOT NULL,
    key            TEXT NOT NULL,
    memory_id      TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    PRIMARY KEY (sender, target, key)
);
-- The erase path (#3192 / #3286) purges by memory_id.
CREATE INDEX IF NOT EXISTS idx_notify_dedup_memory_id ON notify_dedup(memory_id);
