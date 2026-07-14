-- v1.0.0 #2024 — operator-authorized skill retire/unretire lifecycle.
--
-- Adds three additive nullable columns to the `skills` table so a skill
-- lineage (namespace, name) — or a single version by id — can be RETIRED
-- (hidden from discovery + blocked from re-registration) and later
-- UNRETIRED, fully reversibly. This is the reversible half of the
-- lifecycle; hard-delete / purge is deliberately out of scope for #2024.
--
-- * `retired_at`    — INTEGER, Unix epoch seconds (UTC) when the row was
--                     retired. NULL means the row is ACTIVE (not retired).
--                     This is the single source of truth for the retired
--                     predicate: `retired_at IS NULL` = active.
-- * `retired_by`    — TEXT, the operator/agent id that performed the
--                     retire. NULL when active.
-- * `retire_reason` — TEXT, optional free-form reason. NULL when active
--                     or when no reason was supplied.
--
-- The ALTER statements below are emitted from Rust only AFTER a
-- `PRAGMA table_info(skills)` probe confirms the columns are absent —
-- SQLite has no `ADD COLUMN IF NOT EXISTS`, so replay-safety is the
-- probe's responsibility (the v79 probe-guarded-ALTER precedent). Purely
-- additive: no full-table rebuild, so the v63/v65 trigger-drop hazard
-- does not arise (`skills` carries no triggers).

ALTER TABLE skills ADD COLUMN retired_at INTEGER;
ALTER TABLE skills ADD COLUMN retired_by TEXT;
ALTER TABLE skills ADD COLUMN retire_reason TEXT;
