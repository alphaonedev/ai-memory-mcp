-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v101 (#4024, v1.0.0, security / data-integrity): durable operation identity
-- for federated action transitions, recorded in the SAME transaction as the
-- compare-and-swap that applies the transition. Doc twin of
-- `PostgresStore::migrate_v101` in `src/store/postgres.rs` and the parity twin
-- of migrations/sqlite/0085_v101_action_transition_nonces.sql — see that file
-- for the defect and the invariant (a row means "this op WAS applied here").
-- Additive, idempotent, reversible (DROP TABLE action_transition_nonces).
CREATE TABLE IF NOT EXISTS action_transition_nonces (
    action_id  TEXT   NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
    nonce      BYTEA  NOT NULL,
    from_state TEXT   NOT NULL,
    to_state   TEXT   NOT NULL,
    recorded_at BIGINT NOT NULL,
    PRIMARY KEY (action_id, nonce)
);
