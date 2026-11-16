-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v102 (#8341, #9259, #9260) - the v97 agent public-key projection becomes an
-- abort guard instead of a rewriting trigger.
--
-- Root cause. `memories_fts` is an external-content FTS5 index kept in step by
-- the `memories_ai` / `memories_au` triggers. The two v97 AFTER triggers ran a
-- nested `UPDATE memories SET content = ...` that rewrote the row after the
-- FTS sync had indexed the pre-rewrite text, so the index no longer matched
-- the table and `INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')`
-- failed with SQLITE_CORRUPT_VTAB (267).
--
-- Design A (3-agent vote 71472661, tally 3-0 A). Every Rust write funnel now
-- writes the authoritative projection itself (`storage::agent_projection`)
-- BEFORE its statement, and no trigger on `memories` changes title, content or
-- tags. The guards below only RAISE(ABORT): a funnel that forgets the
-- projection fails loudly instead of being silently rewritten.
--
-- Order (one ladder transaction): drop the rewriting triggers, rebuild the FTS
-- index from the table (so the reconcile's `memories_au` deletes remove exactly
-- the indexed text), reconcile rows that are already out of step with the
-- ledger, install the guards, then rebuild the FTS index again so it equals the
-- reconciled table. Every step is idempotent.
--
-- The predicate is the full v97 WHEN clause (key and bound_at, metadata and
-- content mirrors), scoped to `_agents`. A sealed row (#228 at-rest
-- encryption: content '' plus an envelope) cannot have its content mirror read
-- by SQL; Rust projects the plaintext before sealing, so a sealed row passes
-- when its metadata pair equals the open history row.
--
-- The update guard's `UPDATE OF` list names every column its WHEN clause and
-- body read (#9406): metadata, content, title, namespace AND
-- encrypted_envelope, so an envelope-only unseal of a bound row is re-checked.

DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_insert_v97;
DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_update_v97;

INSERT INTO memories_fts(memories_fts) VALUES('rebuild');

UPDATE memories
   SET metadata = json_set(json_remove(CASE WHEN EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL)
         THEN json_set(json_remove(memories.metadata, '$.agent_pubkey', '$.pubkey_bound_at'),
              '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL),
              '$.pubkey_bound_at', (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL))
         ELSE json_remove(memories.metadata, '$.agent_pubkey', '$.pubkey_bound_at') END,
         '$.write_signature'), '$.attest_level', 'claimed'),
       content = CASE WHEN json_valid(memories.content) THEN json_set(json_remove(CASE WHEN EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL)
         THEN json_set(json_remove(memories.content, '$.agent_pubkey', '$.pubkey_bound_at'),
              '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL),
              '$.pubkey_bound_at', (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL))
         ELSE json_remove(memories.content, '$.agent_pubkey', '$.pubkey_bound_at') END,
         '$.write_signature'), '$.attest_level', 'claimed') ELSE memories.content END
 WHERE (memories.namespace = '_agents' AND (
         json_extract(memories.metadata, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(memories.metadata, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(memories.content) THEN memories.content ELSE '{}' END, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(memories.content) THEN memories.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL)))
   AND NOT (memories.encrypted_envelope IS NOT NULL AND memories.content = ''
         AND json_extract(memories.metadata, '$.agent_pubkey') IS (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL)
         AND json_extract(memories.metadata, '$.pubkey_bound_at') IS (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(memories.title, length('agent:') + 1) AND superseded_at IS NULL));

CREATE TRIGGER IF NOT EXISTS agent_pubkey_history_projection_guard_insert
AFTER INSERT ON memories
WHEN (NEW.namespace = '_agents' AND (
         json_extract(NEW.metadata, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(NEW.metadata, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)))
 AND NOT (NEW.encrypted_envelope IS NOT NULL AND NEW.content = ''
         AND json_extract(NEW.metadata, '$.agent_pubkey') IS (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)
         AND json_extract(NEW.metadata, '$.pubkey_bound_at') IS (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it')
     WHERE NEW.encrypted_envelope IS NULL
       AND EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)
       AND json_type(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE 'null' END) IS NOT 'object';
    SELECT RAISE(ABORT, 'agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)');
END;

CREATE TRIGGER IF NOT EXISTS agent_pubkey_history_projection_guard_update
AFTER UPDATE OF metadata, content, title, namespace, encrypted_envelope ON memories
WHEN (NEW.namespace = '_agents' AND (
         json_extract(NEW.metadata, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(NEW.metadata, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL) OR
         json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)))
 AND NOT (NEW.encrypted_envelope IS NOT NULL AND NEW.content = ''
         AND json_extract(NEW.metadata, '$.agent_pubkey') IS (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)
         AND json_extract(NEW.metadata, '$.pubkey_bound_at') IS (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL))
BEGIN
    SELECT RAISE(ABORT, 'agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it')
     WHERE NEW.encrypted_envelope IS NULL
       AND EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL)
       AND json_type(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE 'null' END) IS NOT 'object';
    SELECT RAISE(ABORT, 'agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)');
END;

INSERT INTO memories_fts(memories_fts) VALUES('rebuild');
