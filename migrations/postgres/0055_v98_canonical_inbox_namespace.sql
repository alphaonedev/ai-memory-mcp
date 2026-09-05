-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v98 (#3401): lossless canonical inbox aliases.
-- Namespace is signed: NEVER rewrite stored rows, including archived rows.
-- A view also covers imported legacy rows and archive restores after upgrade.
-- Idempotent. Reversible: DROP VIEW inbox_namespace_aliases, then restore the
-- prior binary/schema stamp while writers are quiesced. No stored data changes.
CREATE OR REPLACE VIEW inbox_namespace_aliases AS
SELECT '_messages/' AS legacy_prefix, '_inbox/' AS canonical_prefix;
-- Applies to memories and archived_memories without depending on either
-- relation, so historical table-rebuild migrations remain replayable.
