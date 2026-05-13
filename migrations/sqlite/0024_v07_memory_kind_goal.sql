-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.7.0 L1-6 — Goal MemoryKind variant (schema v31).
--
-- L1-1 (migration v30) added `memories.memory_kind TEXT NOT NULL DEFAULT
-- 'observation'` with no validity constraint. L1-6 extends the closed
-- set to {observation, reflection, goal} and pins the constraint at the
-- DB layer so a wire-level shim (HTTP body, postgres replication peer
-- on an older binary) cannot smuggle in an unrecognised value.
--
-- A CHECK constraint cannot be added to an existing column in SQLite
-- without rebuilding the table — that operation is destructive enough
-- (FTS triggers + FK targets + indexes) to be unsafe in an additive
-- migration.  The Rust-side `MemoryKind::from_str` enforcement is the
-- canonical typed gate; this SQL file holds the supporting index plus
-- a trigger-based check that rejects unrecognised wire-level values
-- on INSERT and UPDATE without rebuilding the table.
--
-- Idempotent: CREATE INDEX IF NOT EXISTS / CREATE TRIGGER IF NOT EXISTS
-- both no-op on a partially-stamped database.

-- Trigger guard — reject any non-canonical value on INSERT.  Replaces
-- a CHECK constraint without rebuilding the table.  When L1-6 lands
-- v0.8.0 Plan/Step/Decision variants the trigger body is the one place
-- to update (alongside `MemoryKind::from_str`).
CREATE TRIGGER IF NOT EXISTS memory_kind_check_insert
  BEFORE INSERT ON memories
  FOR EACH ROW
  WHEN NEW.memory_kind NOT IN ('observation', 'reflection', 'goal')
  BEGIN
    SELECT RAISE(ABORT, 'memory_kind must be observation|reflection|goal');
  END;

CREATE TRIGGER IF NOT EXISTS memory_kind_check_update
  BEFORE UPDATE OF memory_kind ON memories
  FOR EACH ROW
  WHEN NEW.memory_kind NOT IN ('observation', 'reflection', 'goal')
  BEGIN
    SELECT RAISE(ABORT, 'memory_kind must be observation|reflection|goal');
  END;

-- The L1-1 index on memory_kind is created by migration v30; L1-6 does
-- not need a second one — `goal` rows are stored in the same column and
-- the existing index already serves `WHERE memory_kind = 'goal'` filters.
