-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v96 (#3401, v1.0.0) — canonical inbox namespace (PostgreSQL).
--
-- Keep upgrades and imported SQLite corpora backend-blind by moving legacy
-- `_messages/<agent>` rows into the canonical `_inbox/<agent>` namespace.
-- The prefix predicate makes this idempotent.
UPDATE memories
SET namespace = '_inbox/' || substr(namespace, 11)
WHERE left(namespace, 10) = '_messages/';

UPDATE archived_memories
SET namespace = '_inbox/' || substr(namespace, 11)
WHERE left(namespace, 10) = '_messages/';
