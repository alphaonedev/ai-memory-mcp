-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v92 (#2555, v1.0.0) — BOUND schema_version with an upper CHECK ceiling.
--
-- `schema_version` shipped as `(version INTEGER PRIMARY KEY, ...)` with no
-- upper bound, so on a SHARED postgres cluster any co-tenant with DML could
-- `INSERT INTO schema_version VALUES (2147483647)` — a permanent, fleet-wide
-- kill-switch that trips the #2445 schema-ahead DENY on every daemon reading
-- the shared ledger, with no in-product recovery. This retrofits the
-- `version <= 100000` upper bound (== MAX_SCHEMA_VERSION) so an out-of-band
-- write is refused at the boundary.
--
-- Applied by `PostgresStore::migrate_v92`, which probes `pg_constraint` first
-- (a fresh schema inherits the constraint inline from postgres_schema.sql) and
-- pre-flights for out-of-band rows so a poisoned cluster gets a clear error
-- rather than a half-applied migration. UPPER-BOUND ONLY on purpose: the low
-- end (0 / negative / deleted) is #2564's read-time domain.
ALTER TABLE schema_version
    ADD CONSTRAINT schema_version_bounded CHECK (version <= 100000);
