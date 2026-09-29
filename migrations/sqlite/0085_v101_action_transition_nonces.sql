-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
--
-- v101 (#4024, v1.0.0, security / data-integrity): durable OPERATION IDENTITY
-- for federated action transitions, recorded in the SAME transaction as the
-- compare-and-swap that applies the transition.
--
-- Pre-#4024 both receive funnels recorded a transition's signed `nonce` in the
-- in-memory federation replay cache BEFORE the CAS and counted a CAS miss as a
-- `noop`. A transition delivered ahead of its causal predecessor (or one whose
-- CAS hit a transient error) was therefore acknowledged without being applied
-- AND had its identity consumed, so the sender's retry was refused as a replay
-- and the op was never applied anywhere. The cache was also bounded, evicting
-- and process-local, so the #1805 cyclic-edge replay defence it provided was
-- neither durable nor exact.
--
-- A row here means exactly one thing: the transition `(action_id, nonce)`
-- WAS applied on this node. It is written by
-- `actions::transition_cas_once` inside the transaction that performs the
-- CAS, so "applied" and "recorded" commit or roll back together: a CAS miss or
-- error records nothing (the retry stays applicable) and an applied op is
-- recorded durably (its replay stays refused across a cyclic edge and across
-- restarts). The key is `(action_id, nonce)` — both are bound by the op's
-- signature, so the identity holds regardless of which peer relays it.
--
-- `ON DELETE CASCADE` ties the identity rows to their action's lifetime (the
-- same discipline as `action_edges` / `leases`). Additive, idempotent
-- (IF NOT EXISTS), reversible (DROP TABLE action_transition_nonces; NoLoss —
-- the table holds no memory text). Postgres twin:
-- migrations/postgres/0058_v101_action_transition_nonces.sql.
CREATE TABLE IF NOT EXISTS action_transition_nonces (
    action_id  TEXT    NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    nonce      BLOB    NOT NULL,
    from_state TEXT    NOT NULL,
    to_state   TEXT    NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (action_id, nonce)
) WITHOUT ROWID;
