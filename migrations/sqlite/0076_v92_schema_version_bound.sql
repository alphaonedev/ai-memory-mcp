-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v92 (#2555, v1.0.0) — BOUND schema_version with an upper CHECK ceiling.
--
-- `schema_version` shipped as `CREATE TABLE ... (version INTEGER NOT NULL)`
-- with no PK/UNIQUE/CHECK, so `INSERT INTO schema_version VALUES (2147483647)`
-- was a permanent, fleet-wide kill-switch: it reads back through
-- `COALESCE(MAX(version), 0)` and trips the #2445 schema-ahead DENY on every
-- daemon, with no in-product recovery. This migration retrofits the
-- `version <= 100000` upper bound (== `MAX_SCHEMA_VERSION`) so an out-of-band
-- write is refused at the boundary.
--
-- SQLite cannot ADD a column CHECK to an existing table, so this is a
-- full-table rebuild. `schema_version` is a standalone one-column table with
-- NO indexes, triggers, views, or foreign keys referencing it, so the rebuild
-- is trivial and lossless (contrast the v63/v65 memory_links rebuilds that had
-- to re-create triggers). The rebuild is applied by the `if version < 92` arm
-- of `migrate()` ONLY when the live table lacks the CHECK, so it is idempotent
-- and a no-op on a fresh database (whose bootstrap SCHEMA already ships it).
--
-- UPPER-BOUND ONLY on purpose: the low end (0 / negative / deleted stamp) is
-- #2564's read-time domain (the ZEROED guard), and a `version >= 0` bound here
-- would reject #2564's own negative-stamp recovery fixtures.
CREATE TABLE schema_version_new (
    version INTEGER NOT NULL CHECK (version <= 100000)
);
INSERT INTO schema_version_new (version) SELECT version FROM schema_version;
DROP TABLE schema_version;
ALTER TABLE schema_version_new RENAME TO schema_version;
