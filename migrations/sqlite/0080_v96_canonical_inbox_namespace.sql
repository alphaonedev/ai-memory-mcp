-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v96 (#3401, v1.0.0) — canonical inbox namespace (SQLite).
--
-- Early MCP notify writes used `_messages/<agent>` while SAL and PostgreSQL
-- used `_inbox/<agent>`. Move every live and archived legacy message into the
-- canonical namespace. The prefix predicate makes this idempotent.
UPDATE memories
SET namespace = '_inbox/' || substr(namespace, 11)
WHERE substr(namespace, 1, 10) = '_messages/';

UPDATE archived_memories
SET namespace = '_inbox/' || substr(namespace, 11)
WHERE substr(namespace, 1, 10) = '_messages/';
