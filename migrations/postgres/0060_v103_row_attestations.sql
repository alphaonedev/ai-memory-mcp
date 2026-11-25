-- v103 (#10040, 3-agent vote (71472661) V1-10040): the additive
-- `row_attestations` side table, column-for-column parity with the SQLite
-- 0087 migration. No existing table or row is altered.
CREATE TABLE IF NOT EXISTS row_attestations (
    id BIGSERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    row_key BYTEA NOT NULL,
    seq BIGINT NOT NULL,
    op TEXT NOT NULL,
    row_digest BYTEA,
    prior_digest BYTEA NOT NULL,
    agent_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    attested_at TEXT NOT NULL,
    format_version BIGINT NOT NULL,
    covered_columns TEXT NOT NULL,
    store_id TEXT NOT NULL,
    table_seq BIGINT NOT NULL,
    table_acc BYTEA NOT NULL,
    signature BYTEA,
    attestation_digest BYTEA NOT NULL,
    UNIQUE (table_name, row_key, seq)
);
CREATE INDEX IF NOT EXISTS idx_row_attestations_table_seq
    ON row_attestations (table_name, table_seq);
-- PR 10083 L-3: the Supersede tombstone prune and the cutover probes filter
-- on `op` (and `op` plus `table_name`); `op` leads so both are searches.
-- Parity with the sqlite 0087 twin.
CREATE INDEX IF NOT EXISTS idx_row_attestations_op_table
    ON row_attestations (op, table_name);
