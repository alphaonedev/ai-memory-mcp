-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.7.0 #1389 — `transcript_line_dedup` for the layered-capture
-- architecture (L2 recover-on-boot + L3 substrate watcher + L4
-- `memory_capture_turn` MCP tool).
--
-- Closes the #1388 substrate failure mode at the storage layer:
-- when an AI agent session terminates ungracefully (SIGKILL, tmux
-- lockup, host crash) between turns, the L2 / L3 / L4 recovery
-- surfaces atomise transcript turns into `observation` memories.
-- This table provides sha256-keyed idempotency so re-running
-- recovery (or a concurrent L3 watcher invocation overlapping with
-- an L2 fast-path scan) is a no-op for already-atomised turns.
--
-- Schema choices:
--
-- - PRIMARY KEY (sha256) — the canonical dedup key, computed over
--   the verbatim transcript-line bytes (for L2/L3) or the
--   serialized `memory_capture_turn` payload (for L4). sha256 is
--   collision-resistant at the relevant volumes (a single agent
--   would generate < 2^32 turns over its operational lifetime;
--   sha256's birthday bound at 2^128 leaves ample margin).
-- - `memory_id` — the memory created from this transcript line.
--   FOREIGN KEY is intentionally NOT enforced because the recovery
--   paths can write to either sqlite or postgres adapters and the
--   archive sweep may move the memory out from under us; the
--   row's purpose is dedup, not referential integrity.
-- - `host_kind` — one of `claude-code` / `codex` / `gemini` /
--   `auto` so an operator can audit which surface captured each
--   row. The L4 path stores its own `host_kind` from the
--   `memory_capture_turn` request envelope.
-- - `transcript_path` — full filesystem path the line came from
--   (L2/L3 case) or NULL (L4 case — L4 doesn't read transcripts).
-- - `host_session_id` + `host_turn_index` — populated by the L4
--   path from the `memory_capture_turn` request envelope; NULL on
--   L2/L3 rows.
-- - `recovered_at` — unix epoch ms when this dedup row was
--   inserted. Allows operators to query "what did the substrate
--   capture in the last hour" without joining `memories`.
-- - The supporting index serves the L4 idempotency lookup:
--   `SELECT memory_id FROM transcript_line_dedup WHERE host_session_id = ? AND host_turn_index = ?`
--   is the L4 fast-path before computing sha256 + writing.
--
-- Idempotent — re-applying this migration against an already-v52
-- DB is a no-op via the `IF NOT EXISTS` guards.

CREATE TABLE IF NOT EXISTS transcript_line_dedup (
    sha256           BLOB NOT NULL,
    memory_id        TEXT NOT NULL,
    host_kind        TEXT NOT NULL,
    transcript_path  TEXT,
    host_session_id  TEXT,
    host_turn_index  INTEGER,
    recovered_at     INTEGER NOT NULL,
    PRIMARY KEY (sha256)
) WITHOUT ROWID;

-- L4 fast-path index: substrate dedup by (host_session_id,
-- host_turn_index) before computing sha256 + writing the memory.
-- Partial index because L2/L3 rows have these columns NULL and
-- shouldn't pay for the index space.
CREATE INDEX IF NOT EXISTS idx_transcript_line_dedup_host_turn
    ON transcript_line_dedup(host_session_id, host_turn_index)
    WHERE host_session_id IS NOT NULL;

-- Operator audit-by-time path: "what did we capture in the last N
-- hours via which layer."
CREATE INDEX IF NOT EXISTS idx_transcript_line_dedup_recovered_at
    ON transcript_line_dedup(recovered_at, host_kind);
