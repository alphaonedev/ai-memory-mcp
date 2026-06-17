-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v0.8.0 §22 Policy-Engine PE-5 (epic #697) — schema v66 sqlite:
-- extend the `governance_rules.severity` CHECK constraint to admit the
-- new `escalate` severity that produces the `Decision::Escalate`
-- governance verdict (severity-based human escalation).
--
-- # Why a full-table rebuild
--
-- `governance_rules.severity` (migration 0024, v30) is a column-level
-- CHECK: `severity TEXT NOT NULL CHECK (severity IN ('refuse', 'warn',
-- 'log'))`. SQLite has no `ALTER TABLE ... ALTER CONSTRAINT`, so
-- widening a CHECK requires the canonical
-- create-new + copy + drop + rename dance.
--
-- # Safety — this table holds OPERATOR-SIGNED rules
--
-- `governance_rules` carries the L1-6 substrate hard rules, including
-- the `signature` BLOB and `attest_level` columns that the rule-load
-- path (`list_enabled_by_kind`) Ed25519-verifies before a rule is
-- allowed to fire. The rebuild MUST preserve EVERY row and EVERY
-- column byte-for-byte (a dropped signed-rule row or a dropped
-- signature column is a security regression). The INSERT..SELECT below
-- names all 11 columns explicitly so column order / count can never
-- drift, and copies `signature` + `attest_level` verbatim.
--
-- `governance_rules` has NO triggers (confirmed: no `... ON
-- governance_rules` trigger exists in any migration). It has exactly
-- TWO indexes — `idx_governance_rules_kind_enabled (kind, enabled)` and
-- `idx_governance_rules_namespace (namespace)` (migration 0024). A
-- SQLite `DROP TABLE` drops every attached index, so BOTH are recreated
-- below (the #1709 v65 lesson: a rebuild that forgets an index/trigger
-- silently degrades the table).
--
-- Postgres is unaffected: its bootstrap schema (`postgres_schema.sql`)
-- does NOT ship a `governance_rules` table at all (governance is
-- sqlite-only), so the postgres v66 arm is a version-stamp no-op.

CREATE TABLE governance_rules_new (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    matcher       TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('refuse', 'warn', 'log', 'escalate')),
    reason        TEXT NOT NULL,
    namespace     TEXT NOT NULL DEFAULT '_global',
    created_by    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    signature     BLOB,
    attest_level  TEXT NOT NULL DEFAULT 'unsigned'
);

INSERT INTO governance_rules_new
    (id, kind, matcher, severity, reason, namespace, created_by, created_at, enabled, signature, attest_level)
SELECT
    id, kind, matcher, severity, reason, namespace, created_by, created_at, enabled, signature, attest_level
FROM governance_rules;

DROP TABLE governance_rules;

ALTER TABLE governance_rules_new RENAME TO governance_rules;

CREATE INDEX IF NOT EXISTS idx_governance_rules_kind_enabled
    ON governance_rules (kind, enabled);
CREATE INDEX IF NOT EXISTS idx_governance_rules_namespace
    ON governance_rules (namespace);
