-- v103 (#10040, 3-agent vote (71472661) V1-10040): the additive
-- `row_attestations` side table. One signed attestation per affected row
-- key of every attested table, written in the transaction that changed
-- the row. No existing table or row is altered.
CREATE TABLE IF NOT EXISTS row_attestations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    row_key BLOB NOT NULL,
    seq INTEGER NOT NULL,
    op TEXT NOT NULL,
    row_digest BLOB,
    prior_digest BLOB NOT NULL,
    agent_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    attested_at TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    covered_columns TEXT NOT NULL,
    store_id TEXT NOT NULL,
    table_seq INTEGER NOT NULL,
    table_acc BLOB NOT NULL,
    signature BLOB,
    attestation_digest BLOB NOT NULL,
    UNIQUE (table_name, row_key, seq)
);
CREATE INDEX IF NOT EXISTS idx_row_attestations_table_seq
    ON row_attestations (table_name, table_seq);
-- PR 10083 L-3: the Supersede tombstone prune and the cutover probes filter
-- on `op` (and `op` plus `table_name`); `op` leads so both are searches.
CREATE INDEX IF NOT EXISTS idx_row_attestations_op_table
    ON row_attestations (op, table_name);
