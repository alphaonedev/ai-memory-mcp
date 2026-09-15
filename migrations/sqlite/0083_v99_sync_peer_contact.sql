-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v99 (#3655, v1.0.0, observability-high) — DURABLE PER-PEER CONTACT (SQLite).
--
-- Doc twin of the inline `MIGRATION_V99_SQLITE` arm in
-- `src/storage/migrations.rs`.
--
-- `sync_state.last_pulled_at` is stamped by `sync_state_observe`, which only
-- runs when a pull ADVANCED the data watermark. A peer that answers every
-- pull with an empty window (nothing new to replicate — the normal state of
-- a quiet mesh) therefore never moves `last_pulled_at`, and any reader that
-- treats that column as "when did we last reach this peer" calls a healthy,
-- reachable, quiet peer stale. `last_pulled_at` is a DATA watermark stamp,
-- not a contact time.
--
-- This table records CONTACT separately: one row per (local agent, peer),
-- `last_contact_at` = this node's clock at the last pull the peer ANSWERED
-- (2xx, parseable envelope), stamped whether or not the window carried rows;
-- `catchup_interval_secs` = the cadence of the loop that made that pull, so
-- an offline reader (`ai-memory doctor`) can apply the SAME reachability
-- window the live daemon uses (#3654: a pull observation older than
-- REACHABILITY_STALE_AFTER_CATCHUP_INTERVALS × the cadence says nothing).
-- NULL cadence means the writer did not know its loop's cadence — reported
-- as unknown, never as a default.
--
-- Additive, idempotent, reversible (DROP TABLE sync_peer_contact; no other
-- relation references it). No stored data changes.
CREATE TABLE IF NOT EXISTS sync_peer_contact (
    agent_id              TEXT NOT NULL,
    peer_id               TEXT NOT NULL,
    last_contact_at       TEXT NOT NULL,
    catchup_interval_secs INTEGER,
    PRIMARY KEY (agent_id, peer_id)
);
