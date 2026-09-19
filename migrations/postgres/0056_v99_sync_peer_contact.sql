-- Copyright 2026 AlphaOne LLC
-- SPDX-License-Identifier: Apache-2.0
-- v99 (#3655): durable per-peer CONTACT, stored apart from the data watermark.
-- Doc twin of `PostgresStore::migrate_v99` in `src/store/postgres.rs`, and the
-- parity twin of `migrations/sqlite/0083_v99_sync_peer_contact.sql`.
-- The sync daemon and its `sync_state` live on the sqlite file; this mirror
-- keeps the two ladders at schema parity and holds no rows on a postgres
-- deployment. Additive, idempotent, reversible (DROP TABLE sync_peer_contact).
CREATE TABLE IF NOT EXISTS sync_peer_contact (
    agent_id              TEXT   NOT NULL,
    peer_id               TEXT   NOT NULL,
    last_contact_at       TEXT   NOT NULL,
    catchup_interval_secs BIGINT,
    PRIMARY KEY (agent_id, peer_id)
);
