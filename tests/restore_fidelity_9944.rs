// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Prose-heavy regression docs name SQLite as a product, matching the
// `tests/` precedent (`tests/export_import_roundtrip_3405.rs`).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #9944 (GA standard 4, proven restore) — every SQLite restore path
//! must reproduce its source store EXACTLY, or name what it does not carry.
//!
//! Before this file no test compared a restored store with its source: the
//! #3405 round-trip compares links only, with no embeddings, no
//! `namespace_meta`, no archived rows and no signed rows.
//!
//! # The comparison
//!
//! [`snapshot`] reads EVERY table of a database (from `sqlite_master`) and
//! EVERY column of every row into a typed [`StoreSnapshot`]: values keep their
//! SQLite storage class, REAL values compare by bit pattern and BLOBs byte by
//! byte, so an embedding that loses one byte, its dimension or its space tag
//! is a difference. [`assert_restored`] is the one shared comparison every
//! path below uses.
//!
//! # The ratchet
//!
//! Every live table must appear in each path's [`Classification`]
//! ([`BACKUP_RESTORE`], [`EXPORT_FULL_IMPORT`], [`EXPORT_IMPORT`]) with a
//! disposition, and every column a path does not carry must appear in that
//! path's `lossy` list with its reason. A new table fails
//! [`every_live_table_is_classified_for_every_path_9944`] until it is
//! classified; a new column is compared by default (the snapshot reads the
//! live column list), so it can only escape the comparison by being named in
//! a `lossy` list. A lossy entry is executable: the test asserts the
//! source holds a value there and the destination does not, so a path that
//! starts carrying the field fails until the entry is removed.
//!
//! # Why the binary
//!
//! The paths are the shipped CLI verbs (`backup`/`restore`,
//! `export --full`/`import`, `export`/`import`, `archive restore`). Every
//! child runs with `AI_MEMORY_NO_CONFIG=1`, its own audit sink and the shared
//! sandboxed key directory, so no host state reaches the outcome.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ai_memory::models::{Memory, Tier};
use assert_cmd::Command;
use rusqlite::types::ValueRef;
use tempfile::TempDir;

// #7232 - the shared keystore sandbox: every CLI child below is pinned to it.
#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

// #9944 - the one shared snapshot comparison (also used by the PG twin).
#[path = "common/restore_seed.rs"]
mod restore_seed;
#[path = "common/restore_snapshot.rs"]
mod restore_snapshot;

use restore_snapshot::{
    Carry, Classification, Expect, Rederived, Row, SchemaBaseline, SchemaObject, SourceStore,
    SqlValue, StoreSnapshot, TableSnapshot, assert_restored, source_store,
};

// ── corpus constants ────────────────────────────────────────────────────────

/// The embedding dimension of the production embedder the issue names.
const EMBEDDING_DIM: usize = 768;
/// The embedding-space tag stamped on every corpus embedding.
const EMBEDDING_SPACE: &str = "fidelity-9944/model#768";
/// Two namespaces, so a path that keys on namespace cannot pass by accident.
const NAMESPACE_A: &str = "fidelity-9944-alpha";
const NAMESPACE_B: &str = "fidelity-9944-beta/child";
/// The agent every corpus row is attributed to.
const CORPUS_AGENT: &str = "ai:fidelity-9944";
/// Unicode text covering multi-byte, combining, right-to-left and emoji forms.
const UNICODE_TITLE: &str = "réstore — 復元 — استعادة — 🧠🔁";
const UNICODE_CONTENT: &str = "e\u{301} ﬁ ß 𝔘 \u{200d} 👩‍💻 — byte-exact or bust";
/// A row whose optional fields are empty (no tags), not NULL.
const EMPTY_TAGS_TITLE: &str = "empty-fields row";
/// The shortest content the write path accepts (blank content is refused by
/// input validation on every write path, import included).
const MINIMAL_CONTENT: &str = "·";
/// The link relation the corpus edges carry.
const LINK_RELATION: &str = "related_to";
/// The archive reason of the archived corpus row.
const ARCHIVE_REASON: &str = "fidelity-9944";
/// Audit sink directory each test pins under its own tempdir.
const SINK_DIR: &str = "audit-sink";
/// Key directory holding the operator keypair the backup manifest is signed with.
const OPERATOR_KEY_DIR: &str = "operator-keys";
/// The isolated HOME every CLI child runs with (#10013).
const CHILD_HOME_DIR: &str = "child-home";
/// Seconds-precision timestamps the corpus rows carry (fixed, so a path that
/// rewrites a timestamp shows up as a difference rather than noise).
const CREATED_AT: &str = "2031-04-01T10:00:00.000000+00:00";
const UPDATED_AT: &str = "2031-04-02T11:30:00.123456+00:00";

// ── disposition reasons ─────────────────────────────────────────────────────

/// The FTS5 shadow tables are index pages derived from `memories`; the
/// `memories_fts` view over them is compared instead.
const FTS_DERIVED: &str =
    "by design: FTS5 shadow pages derived from memories; memories_fts is compared";
/// Tables outside the Portability v2 record classes (docs/spec/PORTABILITY-V2.md).
const NOT_V2_CLASS: &str =
    "by design: not a Portability v2 record class; node-local or operational state";
/// The one `memories` column an archive restore rewrites.
const RESTAMPED_COLUMN: &str = "updated_at";
/// The columns an archive restore may change, exactly.
const ARCHIVE_RESTORE_RESTAMPED: &[&str] = &[RESTAMPED_COLUMN];
/// Why: the restore is itself a write (`restore_archived` binds `now`), so a
/// federation peer's last-writer-wins merge adopts the un-forget instead of
/// keeping its own archived copy.
const ARCHIVE_RESTORE_RESTAMP_REASON: &str =
    "restore_archived stamps updated_at = now so last-writer-wins peers adopt the restore";
/// Tables the convenience export (memories + links only) does not carry.
const NOT_CONVENIENCE_CLASS: &str =
    "by design: the convenience export carries memories and links only";
/// Why both export paths drop the memory vectors: the vector is a derived,
/// regenerable artifact the destination re-embeds from the durable text
/// (`src/portability/import.rs` module doc, `embedding_space`).
const VECTOR_NOT_EXPORTED: &str =
    "by design: memory vectors are regenerable artifacts the destination re-embeds from the text";
/// Why `export --full` drops an archived row's content address: a bundle's cid
/// is remote-asserted, and admitting it would launder it onto a live row via
/// archive then restore (`src/portability/import.rs`, #2385 comment).
const ARCHIVED_CID_NOT_TRUSTED: &str = "a bundle cid is remote-asserted; the archived lane leaves it NULL so restore re-mints it (#2385)";
/// Why the convenience import loses the signed link spine: it is the
/// memories+links convenience view (`src/export_scope.rs` EXPORT_SCOPE_WARN)
/// and lands every edge through `create_link`, which signs nothing.
const CONVENIENCE_LINK_UNSIGNED: &str = "by design: the convenience import re-creates each edge through create_link, which carries no signature";
/// Why the convenience import rewrites a link's timestamps and attestation:
/// `create_link` stamps `created_at` / `valid_from` with now and derives
/// `attest_level` from the signature it does not carry.
const CONVENIENCE_LINK_RESTAMPED: &str =
    "by design: create_link stamps created_at and valid_from with now and attest_level as unsigned";
/// The attestation class `create_link` writes for an edge it lands unsigned
/// (written out here, never read from the code under test).
const UNSIGNED_ATTEST_LEVEL: &str = "unsigned";
/// The convenience export writes `a2a_tasks` (`src/cli/io.rs` export), but
/// `import` never reads the key, so every task is lost with exit 0 (#10024).
const A2A_NOT_IMPORTED: &str =
    "the convenience export emits a2a_tasks but import never reads them (#10024)";
/// The v2 export drops every link's `attest_level`: `export_link_from_row`
/// leaves it `None` for the federation wire, so `export --full` never emits
/// it and the import lands NULL. Defect #9948.
const LINK_ATTEST_LEVEL_DROPPED: &str = "export_link_from_row leaves attest_level None, so export --full never carries it (defect #9948)";
/// The main `export --full` cell seeds no identity lineage: `import` strips
/// the `_agents` key binding before its lineage gate and then refuses every
/// enrolled lineage as forged (#10027). The dedicated red cell
/// `export_full_keeps_an_enrolled_identity_lineage_10027` seeds one.
const LINEAGE_IMPORT_REFUSED: &str = "import strips the agent_pubkey binding before its lineage gate and refuses every enrolled lineage as forged (#10027)";
/// The main convenience cell seeds no sealed live row: the convenience
/// export/import writes it back as plaintext with no envelope (#10028). The
/// dedicated red cell `convenience_export_keeps_a_sealed_row_sealed_10028`
/// seeds one.
const SEALED_ROW_UNSEALED: &str =
    "the convenience export/import writes a sealed row back as plaintext with no envelope (#10028)";
/// The convenience wire row (`models::Memory`) has no field for the
/// atomisation, kind-provenance and entity-mention columns (#10029).
const ATOM_COLUMNS_DROPPED: &str =
    "the convenience wire row has no field for this memories column, so import lands NULL (#10029)";
/// The convenience import lands every edge through `create_link`, which
/// takes no validity window (#10030).
const LINK_VALID_UNTIL_DROPPED: &str = "the convenience import re-creates each edge through create_link, which drops valid_until (#10030)";

/// The v2 envelope carries live rows as `Memory`, which has no field for
/// the atomisation, kind-provenance and entity-mention columns (#10031).
const FULL_ATOM_COLUMNS_DROPPED: &str = "export --full emits live rows as Memory, which drops atomised_into, atom_of, kind_provenance and mentioned_entity_id (#10031)";

/// `export --full` emits plaintext and the import re-seals against the
/// destination policy, so a sealed row lands in plaintext on a node with
/// at-rest encryption off; the main cell seeds no sealed row (#10032).
const FULL_SEALED_ROW_UNSEALED: &str = "export --full then import unseals a sealed row on a destination with at-rest encryption off (#10032)";

/// One live corpus row: `(title, namespace, tier, content, tags, with_embedding)`.
type CorpusRow = (
    &'static str,
    &'static str,
    Tier,
    &'static str,
    &'static [&'static str],
    bool,
);

/// The live rows of the corpus: `(title, namespace, tier, content, tags,
/// with_embedding)`.
const LIVE_ROWS: &[CorpusRow] = &[
    (
        UNICODE_TITLE,
        NAMESPACE_A,
        Tier::Long,
        UNICODE_CONTENT,
        &["unicode", "ü"],
        true,
    ),
    (
        "mid tier row",
        NAMESPACE_A,
        Tier::Mid,
        "plain ascii content",
        &["mid"],
        true,
    ),
    (
        "short tier row",
        NAMESPACE_B,
        Tier::Short,
        "short-lived content",
        &[],
        false,
    ),
    (
        EMPTY_TAGS_TITLE,
        NAMESPACE_B,
        Tier::Long,
        MINIMAL_CONTENT,
        &[],
        true,
    ),
];

/// The row that is archived (with its embedding) before the copy is taken.
const ARCHIVED_ROW: (&str, &str, Tier, &str) = (
    "archived row",
    NAMESPACE_A,
    Tier::Long,
    "archived content ✓",
);

// ── typed full-store snapshot ───────────────────────────────────────────────

/// One SQLite value, keeping its storage class.
fn value_from_ref(v: ValueRef<'_>) -> SqlValue {
    match v {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(i) => SqlValue::Integer(i),
        ValueRef::Real(f) => SqlValue::Real(f.to_bits()),
        ValueRef::Text(t) => SqlValue::Text(t.to_vec()),
        ValueRef::Blob(b) => SqlValue::Blob(b.to_vec()),
    }
}

/// Read every table and every column of `db` into a [`StoreSnapshot`].
fn snapshot(db: &Path) -> StoreSnapshot {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open snapshot read-only");
    let names: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("list tables");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("query tables")
            .collect::<Result<_, _>>()
            .expect("table names")
    };
    let mut tables = BTreeMap::new();
    for name in names {
        let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
        let mut stmt = conn
            .prepare(&sql)
            .unwrap_or_else(|e| panic!("table {name} is unreadable in the snapshot: {e}"));
        let columns: Vec<String> = stmt
            .column_names()
            .iter()
            .map(|c| (*c).to_string())
            .collect();
        let mut rows: Vec<Row> = stmt
            .query_map([], |r| {
                let mut row = Row::new();
                for (i, c) in columns.iter().enumerate() {
                    row.insert(c.clone(), value_from_ref(r.get_ref(i)?));
                }
                Ok(row)
            })
            .expect("query rows")
            .collect::<Result<_, _>>()
            .expect("rows");
        rows.sort();
        tables.insert(name, TableSnapshot { columns, rows });
    }
    let mut schema: Vec<SchemaObject> = {
        let mut stmt = conn
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")
            .expect("list schema");
        stmt.query_map([], |r| {
            Ok(SchemaObject {
                kind: r.get(0)?,
                name: r.get(1)?,
                table: r.get(2)?,
                sql: value_from_ref(r.get_ref(3)?),
            })
        })
        .expect("query schema")
        .collect::<Result<_, _>>()
        .expect("schema rows")
    };
    schema.sort();
    StoreSnapshot { tables, schema }
}

// ── per-path classification (the ratchet) ───────────────────────────────────

/// A restore path under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestorePath {
    /// `backup --to` then `restore --from --latest` into a new database file.
    BackupRestore,
    /// `export --full` (Portability v2 envelope) then `import --trust-source`.
    ExportFullImport,
    /// The convenience `export` (memories + links) then `import --trust-source`.
    ExportImport,
}

impl RestorePath {
    const ALL: [Self; 3] = [
        Self::BackupRestore,
        Self::ExportFullImport,
        Self::ExportImport,
    ];

    fn class(self) -> &'static Classification {
        match self {
            Self::BackupRestore => &BACKUP_RESTORE,
            Self::ExportFullImport => &EXPORT_FULL_IMPORT,
            Self::ExportImport => &EXPORT_IMPORT,
        }
    }

    /// The corpus this path's main cell is proven on. Each `Absent` names
    /// the tracked defect that makes the path lose that class; its dedicated
    /// red cell seeds the class and stays red until the fix lands.
    fn seed_shape(self) -> SeedShape {
        match self {
            Self::BackupRestore => SeedShape::FULL,
            // ExportFullImport: #10027 (import refuses an enrolled lineage as
            // forged) and #10032 (the full pair unseals a sealed row).
            // ExportImport: #10028 (the convenience pair unseals a sealed
            // row); the convenience format carries no lineage, and an
            // imported `_agents` key binding is stripped by design (#3464).
            Self::ExportFullImport | Self::ExportImport => SeedShape {
                lineage: Lineage::Absent,
                sealed: Sealed::Absent,
            },
        }
    }
}

/// Whether the corpus enrols an identity lineage (enrol, succession and a
/// guardian recovery) for `LINEAGE_AGENT` (CBC-02: an enum, not a bool).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lineage {
    Enrolled,
    Absent,
}

/// Whether the corpus holds a sealed live row (#10015).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sealed {
    Present,
    Absent,
}

/// The classes a corpus seeds beyond the fixed rows.
#[derive(Clone, Copy, Debug)]
struct SeedShape {
    lineage: Lineage,
    sealed: Sealed,
}

impl SeedShape {
    /// Every class seeded.
    const FULL: Self = Self {
        lineage: Lineage::Enrolled,
        sealed: Sealed::Present,
    };
}

static BACKUP_RESTORE: Classification = Classification {
    path: "sqlite backup/restore",
    tables: &[
        ("a2a_task_memories", Carry::Exact),
        ("a2a_tasks", Carry::Exact),
        ("action_edges", Carry::Exact),
        ("actions", Carry::Exact),
        ("agent_api_keys", Carry::Exact),
        ("agent_lineage", Carry::Exact),
        ("agent_pubkey_challenges", Carry::Exact),
        ("agent_pubkey_history", Carry::Exact),
        ("agent_quotas", Carry::Exact),
        ("agent_subkey_certs", Carry::Exact),
        ("archived_memories", Carry::Exact),
        ("archived_memory_links", Carry::Exact),
        ("attested_write_ledger", Carry::Exact),
        ("audit_log", Carry::Exact),
        ("checkpoints", Carry::Exact),
        ("confidence_shadow_observations", Carry::Exact),
        ("embed_skip", Carry::Exact),
        ("entity_aliases", Carry::Exact),
        ("federation_nonce_cache", Carry::Exact),
        ("federation_push_dlq", Carry::Exact),
        ("forget_tombstones", Carry::Exact),
        ("governance_rules", Carry::Exact),
        ("leases", Carry::Exact),
        ("lineage_integrity_watermark", Carry::Exact),
        ("memories", Carry::Exact),
        ("memories_fts", Carry::Exact),
        ("memories_fts_config", Carry::Exact),
        ("memories_fts_data", Carry::Exact),
        ("memories_fts_docsize", Carry::Exact),
        ("memories_fts_idx", Carry::Exact),
        ("memory_links", Carry::Exact),
        ("memory_revisions", Carry::Exact),
        ("memory_transcript_links", Carry::Exact),
        ("memory_transcripts", Carry::Exact),
        ("model_attestations", Carry::Exact),
        ("namespace_meta", Carry::Exact),
        ("offloaded_blobs", Carry::Exact),
        ("pending_actions", Carry::Exact),
        ("recall_observations", Carry::Exact),
        ("routine_runs", Carry::Exact),
        ("routines", Carry::Exact),
        ("schema_version", Carry::Exact),
        ("signals", Carry::Exact),
        ("signed_events", Carry::Exact),
        ("signed_events_dlq", Carry::Exact),
        ("skill_resources", Carry::Exact),
        ("skills", Carry::Exact),
        ("subscription_dlq", Carry::Exact),
        ("subscription_events", Carry::Exact),
        ("subscriptions", Carry::Exact),
        ("sync_peer_contact", Carry::Exact),
        ("sync_state", Carry::Exact),
        ("token_cost_counters", Carry::Exact),
        ("transcript_line_dedup", Carry::Exact),
    ],
    lossy: &[],
    rederived: &[],
    sparse: &[
        (
            "schema_version",
            "by design: one row, the store's schema version; a second row is an invalid store",
        ),
        (
            "memories_fts_config",
            "by design: FTS5 writes one config row (the version key) per index",
        ),
    ],
    null_columns: &[],
    schema: SchemaBaseline::Source,
};

static EXPORT_FULL_IMPORT: Classification = Classification {
    path: "sqlite export --full/import",
    tables: &[
        ("a2a_task_memories", Carry::NotCarried(NOT_V2_CLASS)),
        ("a2a_tasks", Carry::NotCarried(NOT_V2_CLASS)),
        ("action_edges", Carry::NotCarried(NOT_V2_CLASS)),
        ("actions", Carry::NotCarried(NOT_V2_CLASS)),
        ("agent_api_keys", Carry::NotCarried(NOT_V2_CLASS)),
        ("agent_lineage", Carry::Exact),
        ("agent_pubkey_challenges", Carry::NotCarried(NOT_V2_CLASS)),
        ("agent_pubkey_history", Carry::NotCarried(NOT_V2_CLASS)),
        ("agent_quotas", Carry::NotCarried(NOT_V2_CLASS)),
        ("agent_subkey_certs", Carry::NotCarried(NOT_V2_CLASS)),
        ("archived_memories", Carry::Exact),
        ("archived_memory_links", Carry::Exact),
        ("attested_write_ledger", Carry::NotCarried(NOT_V2_CLASS)),
        ("audit_log", Carry::NotCarried(NOT_V2_CLASS)),
        ("checkpoints", Carry::NotCarried(NOT_V2_CLASS)),
        (
            "confidence_shadow_observations",
            Carry::NotCarried(NOT_V2_CLASS),
        ),
        ("embed_skip", Carry::NotCarried(NOT_V2_CLASS)),
        ("entity_aliases", Carry::NotCarried(NOT_V2_CLASS)),
        ("federation_nonce_cache", Carry::NotCarried(NOT_V2_CLASS)),
        ("federation_push_dlq", Carry::NotCarried(NOT_V2_CLASS)),
        ("forget_tombstones", Carry::Exact),
        ("governance_rules", Carry::Exact),
        ("leases", Carry::NotCarried(NOT_V2_CLASS)),
        (
            "lineage_integrity_watermark",
            Carry::NotCarried(NOT_V2_CLASS),
        ),
        ("memories", Carry::Exact),
        ("memories_fts", Carry::Exact),
        ("memories_fts_config", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_data", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_docsize", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_idx", Carry::NotCarried(FTS_DERIVED)),
        ("memory_links", Carry::Exact),
        ("memory_revisions", Carry::Exact),
        ("memory_transcript_links", Carry::NotCarried(NOT_V2_CLASS)),
        ("memory_transcripts", Carry::NotCarried(NOT_V2_CLASS)),
        ("model_attestations", Carry::Exact),
        ("namespace_meta", Carry::Exact),
        ("offloaded_blobs", Carry::NotCarried(NOT_V2_CLASS)),
        ("pending_actions", Carry::NotCarried(NOT_V2_CLASS)),
        ("recall_observations", Carry::NotCarried(NOT_V2_CLASS)),
        ("routine_runs", Carry::NotCarried(NOT_V2_CLASS)),
        ("routines", Carry::NotCarried(NOT_V2_CLASS)),
        ("schema_version", Carry::NotCarried(NOT_V2_CLASS)),
        ("signals", Carry::NotCarried(NOT_V2_CLASS)),
        ("signed_events", Carry::Exact),
        ("signed_events_dlq", Carry::NotCarried(NOT_V2_CLASS)),
        ("skill_resources", Carry::NotCarried(NOT_V2_CLASS)),
        ("skills", Carry::NotCarried(NOT_V2_CLASS)),
        ("subscription_dlq", Carry::NotCarried(NOT_V2_CLASS)),
        ("subscription_events", Carry::NotCarried(NOT_V2_CLASS)),
        ("subscriptions", Carry::NotCarried(NOT_V2_CLASS)),
        ("sync_peer_contact", Carry::NotCarried(NOT_V2_CLASS)),
        ("sync_state", Carry::NotCarried(NOT_V2_CLASS)),
        ("token_cost_counters", Carry::NotCarried(NOT_V2_CLASS)),
        ("transcript_line_dedup", Carry::NotCarried(NOT_V2_CLASS)),
    ],
    lossy: &[
        ("memories", "embedding", VECTOR_NOT_EXPORTED),
        ("memories", "embedding_dim", VECTOR_NOT_EXPORTED),
        ("memories", "embedding_space", VECTOR_NOT_EXPORTED),
        ("archived_memories", "cid", ARCHIVED_CID_NOT_TRUSTED),
        ("archived_memories", "cid_genesis", ARCHIVED_CID_NOT_TRUSTED),
        ("memory_links", "attest_level", LINK_ATTEST_LEVEL_DROPPED),
        ("memories", "atomised_into", FULL_ATOM_COLUMNS_DROPPED),
        ("memories", "atom_of", FULL_ATOM_COLUMNS_DROPPED),
        ("memories", "kind_provenance", FULL_ATOM_COLUMNS_DROPPED),
        ("memories", "mentioned_entity_id", FULL_ATOM_COLUMNS_DROPPED),
    ],
    rederived: &[],
    sparse: &[("agent_lineage", LINEAGE_IMPORT_REFUSED)],
    null_columns: &[
        ("memories", "encrypted_envelope", FULL_SEALED_ROW_UNSEALED),
        (
            "archived_memories",
            "encrypted_envelope",
            FULL_SEALED_ROW_UNSEALED,
        ),
    ],
    schema: SchemaBaseline::Destination,
};

static EXPORT_IMPORT: Classification = Classification {
    path: "sqlite export/import",
    tables: &[
        (
            "a2a_task_memories",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("a2a_tasks", Carry::NotCarried(A2A_NOT_IMPORTED)),
        ("action_edges", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("actions", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("agent_api_keys", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("agent_lineage", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "agent_pubkey_challenges",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "agent_pubkey_history",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("agent_quotas", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "agent_subkey_certs",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "archived_memories",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "archived_memory_links",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "attested_write_ledger",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("audit_log", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("checkpoints", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "confidence_shadow_observations",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("embed_skip", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("entity_aliases", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "federation_nonce_cache",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "federation_push_dlq",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "forget_tombstones",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("governance_rules", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("leases", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "lineage_integrity_watermark",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("memories", Carry::Exact),
        ("memories_fts", Carry::Exact),
        ("memories_fts_config", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_data", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_docsize", Carry::NotCarried(FTS_DERIVED)),
        ("memories_fts_idx", Carry::NotCarried(FTS_DERIVED)),
        ("memory_links", Carry::Exact),
        ("memory_revisions", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "memory_transcript_links",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "memory_transcripts",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "model_attestations",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("namespace_meta", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("offloaded_blobs", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("pending_actions", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "recall_observations",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("routine_runs", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("routines", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("schema_version", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("signals", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("signed_events", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "signed_events_dlq",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("skill_resources", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("skills", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        ("subscription_dlq", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "subscription_events",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("subscriptions", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "sync_peer_contact",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        ("sync_state", Carry::NotCarried(NOT_CONVENIENCE_CLASS)),
        (
            "token_cost_counters",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
        (
            "transcript_line_dedup",
            Carry::NotCarried(NOT_CONVENIENCE_CLASS),
        ),
    ],
    lossy: &[
        ("memories", "embedding", VECTOR_NOT_EXPORTED),
        ("memories", "embedding_dim", VECTOR_NOT_EXPORTED),
        ("memories", "embedding_space", VECTOR_NOT_EXPORTED),
        ("memory_links", "signature", CONVENIENCE_LINK_UNSIGNED),
        ("memory_links", "observed_by", CONVENIENCE_LINK_UNSIGNED),
        ("memories", "atomised_into", ATOM_COLUMNS_DROPPED),
        ("memories", "atom_of", ATOM_COLUMNS_DROPPED),
        ("memories", "kind_provenance", ATOM_COLUMNS_DROPPED),
        ("memories", "mentioned_entity_id", ATOM_COLUMNS_DROPPED),
        ("memory_links", "valid_until", LINK_VALID_UNTIL_DROPPED),
    ],
    rederived: &[
        Rederived {
            table: "memory_links",
            column: "created_at",
            reason: CONVENIENCE_LINK_RESTAMPED,
            expect: Expect::Restamped,
        },
        Rederived {
            table: "memory_links",
            column: "valid_from",
            reason: CONVENIENCE_LINK_RESTAMPED,
            expect: Expect::Restamped,
        },
        Rederived {
            table: "memory_links",
            column: "attest_level",
            reason: CONVENIENCE_LINK_RESTAMPED,
            expect: Expect::Text(UNSIGNED_ATTEST_LEVEL),
        },
    ],
    sparse: &[],
    null_columns: &[("memories", "encrypted_envelope", SEALED_ROW_UNSEALED)],
    schema: SchemaBaseline::Destination,
};

// ── corpus and CLI plumbing ─────────────────────────────────────────────────

fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").expect("ai-memory binary");
    let parent = db.parent().expect("db has a parent");
    let sink = parent.join(SINK_DIR);
    // #10013 - every child gets its own HOME, so no host config, key or
    // cache directory can reach the outcome.
    let home = parent.join(CHILD_HOME_DIR);
    std::fs::create_dir_all(&home).expect("child HOME");
    cmd.env("HOME", &home)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("AI_MEMORY_AUDIT_DIR", sink)
        .env("AI_MEMORY_KEY_DIR", key_dir_sandbox::pin())
        .env("AI_MEMORY_AGENT_ID", CORPUS_AGENT)
        .args(["--db", db.to_str().expect("utf-8 db path")]);
    cmd
}

/// A deterministic 768-dimension embedding, distinct per `seed`.
fn embedding(seed: usize) -> Vec<f32> {
    (0..EMBEDDING_DIM)
        .map(|i| {
            let x = u32::try_from((i * 31 + seed * 7919) % 10_007).expect("small");
            f32::from_bits(0x3c00_0000 | (x << 4)) - 0.5
        })
        .collect()
}

fn corpus_memory(title: &str, ns: &str, tier: Tier, content: &str, tags: &[&str]) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        priority: 7,
        confidence: 0.875,
        source: "import".to_string(),
        created_at: CREATED_AT.to_string(),
        updated_at: UPDATED_AT.to_string(),
        metadata: serde_json::json!({ "agent_id": CORPUS_AGENT, "note": "ünïcode ✓" }),
        ..Memory::default()
    }
}

/// The seeded corpus: ids of the live rows, the archived id.
struct Corpus {
    live: Vec<String>,
    archived: String,
    /// The sealed row's id, when the shape seeds one.
    encrypted: Option<String>,
}

/// Build the corpus in `db` through the storage funnels the product writes
/// with: insert, set_embedding, create_link (one unsigned, one signed),
/// set_namespace_standard, archive_memory.
fn seed(db: &Path, shape: SeedShape) -> Corpus {
    // Initialise the schema through the binary, exactly as a deployment does.
    ai_memory(db).args(["stats"]).assert().success();
    // The binary boots with the lineage DAG on (compiled default, config.rs
    // `ResolvedStorage::lineage_dag`); the in-process seed must write links
    // the way the binary does, with their source_cid / target_cid mirror.
    ai_memory::config::set_lineage_dag(true);
    let conn = ai_memory::db::open(db).expect("open corpus db");
    let mut live = Vec::new();
    for (i, (title, ns, tier, content, tags, with_emb)) in LIVE_ROWS.iter().enumerate() {
        let mut mem = corpus_memory(title, ns, tier.clone(), content, tags);
        if i == EDGE_ROW {
            set_edge_fields(&mut mem);
        }
        let id = ai_memory::db::insert(&conn, &mem).expect("insert corpus row");
        if *with_emb {
            ai_memory::db::set_embedding(&conn, &id, &embedding(i), EMBEDDING_SPACE)
                .expect("set embedding");
        }
        live.push(id);
    }
    let (t, ns, tier, content) = ARCHIVED_ROW;
    let archived_mem = corpus_memory(t, ns, tier, content, &["archived"]);
    let archived = ai_memory::db::insert(&conn, &archived_mem).expect("insert archived row");
    ai_memory::db::set_embedding(&conn, &archived, &embedding(99), EMBEDDING_SPACE)
        .expect("archived embedding");
    ai_memory::db::create_link(&conn, &live[0], &live[1], LINK_RELATION).expect("link 0-1");
    let keypair = ai_memory::identity::keypair::generate(CORPUS_AGENT).expect("generate keypair");
    ai_memory::db::create_link_signed(&conn, &live[1], &live[3], LINK_RELATION, Some(&keypair))
        .expect("signed link 1-3");
    ai_memory::db::create_link(&conn, &live[0], &archived, LINK_RELATION)
        .expect("link to archived");
    ai_memory::db::set_namespace_standard(&conn, NAMESPACE_A, &live[0], None)
        .expect("namespace standard A");
    ai_memory::db::set_namespace_standard(&conn, NAMESPACE_B, &live[3], Some(NAMESPACE_A))
        .expect("namespace standard B");
    // #10014 - a second archived row with links on both sides, so the
    // archive tables hold two rows each.
    let mut second = corpus_memory(
        ARCHIVED_SECOND_TITLE,
        NAMESPACE_B,
        Tier::Mid,
        ARCHIVED_SECOND_CONTENT,
        &["archived", "second"],
    );
    set_edge_fields(&mut second);
    let archived_second = ai_memory::db::insert(&conn, &second).expect("insert archived row 2");
    ai_memory::db::create_link(&conn, &live[1], &archived_second, LINK_RELATION)
        .expect("link to archived 2");
    ai_memory::db::create_link(&conn, &archived_second, &live[2], LINK_RELATION)
        .expect("link from archived 2");
    set_raw_edge_columns(&conn, &live, &archived_second, shape.sealed);
    for id in [&archived, &archived_second] {
        assert!(
            ai_memory::db::archive_memory(&conn, id, Some(ARCHIVE_REASON)).expect("archive"),
            "the archived corpus row must move to the archive"
        );
    }
    let encrypted = match shape.sealed {
        Sealed::Present => Some(seed_encrypted_row(&conn)),
        Sealed::Absent => None,
    };
    seed_signed_spine(&conn, db, &live, shape.lineage);
    restore_seed::seed_node_local(&conn, &live);
    // A store at rest has been opened by the binary since its last write:
    // boot records the lineage high-water marks (`schema_integrity::
    // enforce_lineage_watermarks`), so the export path's own open cannot
    // be mistaken for a change to the source.
    ai_memory(db).args(["stats"]).assert().success();
    Corpus {
        live,
        archived,
        encrypted,
    }
}

/// The live row that carries every optional column (#10015).
const EDGE_ROW: usize = 2;
const ARCHIVED_SECOND_TITLE: &str = "fidelity 9944 archived second";
const ARCHIVED_SECOND_CONTENT: &str = "the second archived row, linked both ways";
/// The plaintext the encrypted corpus row seals (#10015).
const SEALED_PLAINTEXT: &str = "sealed fidelity 9944 plaintext ✓";
const SEALED_TITLE: &str = "fidelity 9944 encrypted";
const LINEAGE_AGENT: &str = "ai:fidelity-9944-lineage";
const SPINE_TS: [&str; 2] = [
    "2031-04-05T08:00:00.000000+00:00",
    "2031-04-06T09:15:00.250000+00:00",
];

/// Set every optional `Memory` field the struct carries (#10015).
fn set_edge_fields(mem: &mut Memory) {
    use ai_memory::models::{Citation, ConfidenceSignals, SourceSpan};
    mem.last_accessed_at = Some("2031-04-03T09:00:00.000000+00:00".to_string());
    mem.expires_at = Some("2099-01-01T00:00:00.000000+00:00".to_string());
    mem.entity_id = Some("entity-fidelity-9944".to_string());
    mem.persona_version = Some(3);
    mem.citations = vec![Citation {
        uri: "uri:https://example.invalid/fidelity-9944".to_string(),
        accessed_at: "2031-04-01T00:00:00.000000+00:00".to_string(),
        hash: Some("ab".repeat(32)),
        span: Some(SourceSpan { start: 1, end: 4 }),
    }];
    mem.source_uri = Some("uri:https://example.invalid/fidelity-9944/source".to_string());
    mem.source_span = Some(SourceSpan { start: 2, end: 9 });
    mem.confidence_signals = Some(ConfidenceSignals {
        source_age_days: 1.5,
        atom_derivation: true,
        prior_corroboration_count: 2,
        freshness_factor: 0.75,
        baseline_per_source: 0.625,
    });
    mem.confidence_decayed_at = Some("2031-04-04T00:00:00.000000+00:00".to_string());
    mem.valid_from = Some("2031-01-01T00:00:00.000000+00:00".to_string());
    mem.valid_until = Some("2098-12-31T23:59:59.000000+00:00".to_string());
    if let Some(obj) = mem.metadata.as_object_mut() {
        obj.insert("target_agent_id".into(), serde_json::json!(LINEAGE_AGENT));
    }
}

/// The edge columns no `Memory` field writes (atom lineage, the mentioned
/// entity, kind provenance), set with the product's own column values.
///
/// Runs before the archive step, so the second archived row and its links
/// carry every column into the archive tables.
fn set_raw_edge_columns(
    conn: &rusqlite::Connection,
    live: &[String],
    archived_second: &str,
    sealed: Sealed,
) {
    conn.execute(
        "UPDATE memories SET atomised_into = 1 WHERE id = ?1",
        rusqlite::params![&live[0]],
    )
    .expect("atomised_into");
    for (id, atomised) in [
        (&live[EDGE_ROW], None),
        (&archived_second.to_string(), Some(2_i64)),
    ] {
        conn.execute(
            "UPDATE memories SET atom_of = ?1, mentioned_entity_id = ?2, \
             kind_provenance = 'declared', atomised_into = COALESCE(?3, atomised_into) \
             WHERE id = ?4",
            rusqlite::params![&live[0], "entity-fidelity-9944", atomised, id],
        )
        .expect("atom_of");
    }
    if sealed == Sealed::Present {
        let kp =
            ai_memory::encryption::get_or_create_keypair(CORPUS_AGENT).expect("x25519 keypair");
        let envelope = ai_memory::encryption::encrypt(ARCHIVED_SECOND_CONTENT, &kp.public)
            .expect("seal archived row");
        conn.execute(
            "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
            rusqlite::params![envelope.to_bytes(), archived_second],
        )
        .expect("archived envelope");
    }
    // Every optional link column, on a live link and on an archived one. The
    // live link stays unsigned (the signed corpus link carries a real
    // signature); the archived link's signature bytes are copied verbatim.
    let archived_target = archived_second.to_string();
    for (source, target, signature) in [
        (&live[0], &live[1], None),
        (&live[1], &archived_target, Some(vec![0x55_u8; 64])),
    ] {
        let changed = conn
            .execute(
                "UPDATE memory_links SET valid_from = ?1, valid_until = ?2, observed_by = ?3, \
                 signature = COALESCE(?4, signature) WHERE source_id = ?5 AND target_id = ?6",
                rusqlite::params![
                    "2031-02-01T00:00:00.000000+00:00",
                    "2097-02-01T00:00:00.000000+00:00",
                    LINEAGE_AGENT,
                    signature,
                    source,
                    target
                ],
            )
            .expect("link edge columns");
        assert_eq!(changed, 1, "one link {source} -> {target}");
    }
}

/// One row whose content is sealed (#10015): empty content, the envelope in
/// `encrypted_envelope`.
fn seed_encrypted_row(conn: &rusqlite::Connection) -> String {
    let kp = ai_memory::encryption::get_or_create_keypair(CORPUS_AGENT).expect("x25519 keypair");
    let envelope =
        ai_memory::encryption::encrypt(SEALED_PLAINTEXT, &kp.public).expect("seal plaintext");
    let mem = corpus_memory(SEALED_TITLE, NAMESPACE_A, Tier::Long, "", &["sealed"]);
    let id = ai_memory::db::insert(conn, &mem).expect("insert sealed row");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        rusqlite::params![envelope.to_bytes(), &id],
    )
    .expect("store envelope");
    id
}

/// Assert the restored sealed row holds an envelope that decrypts to the
/// written plaintext (#10015).
fn assert_sealed_row_decrypts(s: &StoreSnapshot, id: &str) {
    let rows = s.rows_where("memories", "id", id);
    assert_eq!(rows.len(), 1, "the sealed row is restored");
    let Some(SqlValue::Blob(bytes)) = rows[0].get("encrypted_envelope") else {
        panic!("the restored sealed row holds no envelope BLOB");
    };
    let kp = ai_memory::encryption::get_or_create_keypair(CORPUS_AGENT).expect("x25519 keypair");
    let parsed = ai_memory::encryption::Envelope::from_bytes(bytes).expect("parse envelope");
    let plain = ai_memory::encryption::decrypt(&parsed, &kp.secret).expect("decrypt envelope");
    assert_eq!(plain, SEALED_PLAINTEXT, "the restored envelope decrypts");
}

/// The Portability v2 record classes, two rows each, through the product
/// funnels (#10014).
fn seed_signed_spine(conn: &rusqlite::Connection, db: &Path, live: &[String], lineage: Lineage) {
    use ai_memory::governance::rules_store::{self, Rule};
    use ai_memory::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
    use ai_memory::signed_events::{SignedEvent, append_signed_event, payload_hash};
    use ai_memory::storage::model_attest;
    for (k, ts) in SPINE_TS.iter().enumerate() {
        conn.execute(
            "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                format!("fidelity-9944-forgotten-{k}"),
                NAMESPACE_A,
                ts,
                CORPUS_AGENT,
                vec![0x11_u8.wrapping_add(u8::try_from(k).expect("small")); 64]
            ],
        )
        .expect("tombstone");
        let leaf = RevisionLeaf::new(
            format!("fidelity-9944-rev-{k}"),
            &live[k],
            RecordKind::Supersede,
            Some(i64::try_from(k).expect("small").saturating_add(1)),
            NAMESPACE_A,
            Some(CORPUS_AGENT.to_string()),
            *ts,
        );
        append_revision_leaf(conn, &leaf).expect("revision leaf");
        conn.execute(
            "INSERT INTO model_attestations (id, provider, model_ref, model_digest, model_family, \
             attest_level, agent_id, signature, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                format!("fidelity-9944-ma-{k}"),
                "openrouter",
                format!("google/gemma-4-31b-{k}"),
                format!("sha256:{}", "cd".repeat(32)),
                "gemma",
                model_attest::ATTEST_LEVEL_LOADER_OBSERVED,
                CORPUS_AGENT,
                vec![0x22_u8; 64],
                ts
            ],
        )
        .expect("model attestation");
        rules_store::insert(
            conn,
            &Rule {
                id: format!("FID-9944-{k}"),
                kind: "namespace_deny".into(),
                matcher: format!("secret-{k}/*"),
                severity: "warn".into(),
                reason: format!("fidelity 9944 rule {k}"),
                namespace: NAMESPACE_A.into(),
                created_by: CORPUS_AGENT.into(),
                created_at: 1_700_000_000_i64.saturating_add(i64::try_from(k).expect("small")),
                enabled: k == 0,
                signature: Some(vec![0x33_u8; 64]),
                attest_level: "unsigned".into(),
            },
        )
        .expect("governance rule");
        let ev = SignedEvent {
            id: format!("fidelity-9944-ev-{k}"),
            agent_id: CORPUS_AGENT.into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(format!("payload-{k}").as_bytes()),
            signature: Some(vec![0x44_u8; 64]),
            attest_level: "unsigned".into(),
            timestamp: (*ts).into(),
            cause_hash: Some(payload_hash(format!("cause-{k}").as_bytes())),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("signed event");
    }
    ai_memory::db::register_agent(conn, LINEAGE_AGENT, "ai:test", &[]).expect("register agent");
    if lineage == Lineage::Enrolled {
        let k0 = ai_memory::identity::keypair::generate(LINEAGE_AGENT).expect("k0");
        let recovery = ai_memory::identity::keypair::generate(LINEAGE_AGENT).expect("recovery");
        ai_memory::db::enroll_lineage(conn, LINEAGE_AGENT, &k0, Some(&recovery.public_base64()))
            .expect("enroll lineage");
        let k1 = ai_memory::identity::keypair::generate(LINEAGE_AGENT).expect("k1");
        ai_memory::db::append_succession(conn, LINEAGE_AGENT, &k0, &k1.public_base64(), None)
            .expect("append succession");
        seed_recovery_record(conn, db);
    }
    conn.execute(
        "UPDATE memory_revisions SET signature = ?1 WHERE id = 'fidelity-9944-rev-1'",
        rusqlite::params![vec![0x77_u8; 64]],
    )
    .expect("revision signature");
}

/// A genuine 2-of-2 guardian-quorum recovery record at epoch 2, so the
/// recovery-only lineage columns (`suspected_compromise_from_seq`,
/// `guardian_set_id`, `recovery_threshold`) hold values. The guardians sign
/// the product's own `LineageRecord::recovery` signing input, and the record
/// is persisted by the shipped `identity recover` verb (`append_recovery`),
/// which verifies the quorum and writes the append-only witness in the same
/// transaction. The guardian env goes to that child process only.
fn seed_recovery_record(conn: &rusqlite::Connection, db: &Path) {
    use ai_memory::identity::lineage::{LineageRecord, guardian_set_id_digest};
    use base64::Engine as _;
    use ed25519_dalek::Signer;
    let (head, _) = ai_memory::db::lineage_head(conn, LINEAGE_AGENT)
        .expect("lineage head")
        .expect("enrolled lineage");
    let guardians = guardian_keys();
    let set_id = guardian_set_id_digest(
        &guardians
            .iter()
            .map(ed25519_dalek::SigningKey::verifying_key)
            .collect::<Vec<_>>(),
    );
    let k2 = ai_memory::identity::keypair::generate(LINEAGE_AGENT).expect("k2");
    let successor = k2.public_base64();
    let record = LineageRecord::recovery(
        &head,
        &successor,
        Some(RECOVERY_COMPROMISE_SEQ),
        head.recovery_pubkey_b64.clone(),
        set_id,
        RECOVERY_THRESHOLD,
        RECOVERY_NOT_BEFORE,
    )
    .expect("recovery record");
    let input = record.signing_input().expect("recovery signing input");
    let mut cmd = ai_memory(db);
    cmd.env(
        ai_memory::identity::lineage::RECOVERY_GUARDIAN_PUBKEYS_ENV,
        guardian_pubkeys_env(),
    )
    .env(
        ai_memory::identity::lineage::RECOVERY_THRESHOLD_ENV,
        RECOVERY_THRESHOLD.to_string(),
    )
    .args([
        "identity",
        "recover",
        "--agent-id",
        LINEAGE_AGENT,
        "--successor-pubkey",
        &successor,
        "--not-before",
        RECOVERY_NOT_BEFORE,
        "--from-seq",
        &RECOVERY_COMPROMISE_SEQ.to_string(),
    ]);
    for g in &guardians {
        let attestation = format!(
            "{}:{}",
            ai_memory::identity::keypair::encode_public_base64(&g.verifying_key()),
            base64::engine::general_purpose::STANDARD.encode(g.sign(&input).to_bytes())
        );
        cmd.args(["--attestation", &attestation]);
    }
    cmd.assert().success();
}

/// The two recovery guardians, from fixed seeds so the importing process can
/// enrol the same set through the guardian env.
fn guardian_keys() -> [ed25519_dalek::SigningKey; 2] {
    [
        ed25519_dalek::SigningKey::from_bytes(&[0xA1_u8; 32]),
        ed25519_dalek::SigningKey::from_bytes(&[0xA2_u8; 32]),
    ]
}

/// The guardian env value (comma-joined public keys) for an importer.
fn guardian_pubkeys_env() -> String {
    guardian_keys()
        .iter()
        .map(|g| ai_memory::identity::keypair::encode_public_base64(&g.verifying_key()))
        .collect::<Vec<_>>()
        .join(",")
}

/// The compromise window a recovery record commits (#10015).
const RECOVERY_COMPROMISE_SEQ: u64 = 7;
/// The M of the 2-of-2 guardian quorum (#10015).
const RECOVERY_THRESHOLD: u64 = 2;
/// An enrolled corpus writes at least the enrol, succession and recovery
/// lineage rows.
const MIN_LINEAGE_ROWS: usize = 3;
/// The recovery record's `not_before`, after the succession's.
const RECOVERY_NOT_BEFORE: &str = "2099-01-01T00:00:00Z";

/// Assert the corpus really holds every field class the paths must carry, so
/// a green comparison is never vacuous.
fn assert_corpus_is_rich(s: &StoreSnapshot, shape: SeedShape) {
    let rows = |t: &str| s.tables.get(t).map_or(0, |t| t.rows.len());
    // The live rows, the `_agents` registration row and, when seeded, the
    // sealed row.
    let sealed_rows = match shape.sealed {
        Sealed::Present => 1,
        Sealed::Absent => 0,
    };
    assert_eq!(
        rows("memories"),
        LIVE_ROWS.len() + 1 + sealed_rows,
        "live rows"
    );
    let lineage_rows = rows("agent_lineage");
    match shape.lineage {
        Lineage::Enrolled => assert!(
            lineage_rows >= MIN_LINEAGE_ROWS,
            "an enrolled lineage holds enrol, succession and recovery rows, got {lineage_rows}"
        ),
        Lineage::Absent => assert_eq!(lineage_rows, 0, "no lineage seeded"),
    }
    assert_eq!(rows("archived_memories"), 2, "archived rows");
    assert!(rows("namespace_meta") >= 2, "namespace_meta rows");
    assert!(rows("memory_links") >= 2, "live links");
    let mem = &s.tables["memories"];
    let emb_rows = mem
        .rows
        .iter()
        .filter(|r| matches!(r.get("embedding"), Some(SqlValue::Blob(b)) if ai_memory::embeddings::decoded_dim(b) == EMBEDDING_DIM))
        .count();
    assert_eq!(emb_rows, 3, "three live rows carry a 768-dim embedding");
    let signed = s.tables["memory_links"]
        .rows
        .iter()
        .filter(|r| matches!(r.get("signature"), Some(SqlValue::Blob(_))))
        .count();
    assert_eq!(signed, 1, "one link is signed");
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn backup_restore(src: &Path, dir: &Path) -> PathBuf {
    let backups = dir.join("backups");
    // The shipped path: `backup` signs its manifest with the operator key and
    // `restore --latest` only takes a manifest that verifies (#3199), so the
    // pair runs against a key directory holding an operator keypair.
    let operator_keys = dir.join(OPERATOR_KEY_DIR);
    key_dir_sandbox::mkdir_0700(&operator_keys);
    let operator = ai_memory::identity::keypair::generate(ai_memory::cli::rules::OPERATOR_KEY_ID)
        .expect("generate operator key");
    ai_memory::identity::keypair::save(&operator, &operator_keys).expect("save operator key");
    ai_memory(src)
        .env("AI_MEMORY_KEY_DIR", &operator_keys)
        .args(["backup", "--to", path_str(&backups)])
        .assert()
        .success();
    let restored = dir.join("restored.db");
    ai_memory(&restored)
        .env("AI_MEMORY_KEY_DIR", &operator_keys)
        .args(["restore", "--from", path_str(&backups), "--latest", "--yes"])
        .assert()
        .success();
    restored
}

/// Export `src`, import into a fresh store; returns the destination and the
/// schema it held before the import (the [`SchemaBaseline::Destination`]).
fn export_import(src: &Path, dir: &Path, full: bool) -> (PathBuf, Vec<SchemaObject>) {
    let mut exp = ai_memory(src);
    exp.arg("export");
    if full {
        exp.arg("--full");
    }
    let out = exp.output().expect("export runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "export must be complete; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dest = dir.join(if full {
        "imported-full.db"
    } else {
        "imported.db"
    });
    ai_memory(&dest).args(["stats"]).assert().success();
    let fresh_schema = snapshot(&dest).schema;
    let imp = ai_memory(&dest)
        .env(
            ai_memory::identity::lineage::RECOVERY_GUARDIAN_PUBKEYS_ENV,
            guardian_pubkeys_env(),
        )
        .env(
            ai_memory::identity::lineage::RECOVERY_THRESHOLD_ENV,
            RECOVERY_THRESHOLD.to_string(),
        )
        .args(["import", "--trust-source"])
        .write_stdin(out.stdout)
        .output()
        .expect("import runs");
    assert_eq!(
        imp.status.code(),
        Some(0),
        "import must be complete; stdout: {} stderr: {}",
        String::from_utf8_lossy(&imp.stdout),
        String::from_utf8_lossy(&imp.stderr)
    );
    (dest, fresh_schema)
}

/// One cell's inputs: the refused-unless-rich source, the restored store and
/// the destination's pre-import schema.
struct Cell {
    source: SourceStore,
    restored: StoreSnapshot,
    destination_schema: Vec<SchemaObject>,
    /// The id of the sealed row (#10015), when the shape seeds one.
    encrypted: Option<String>,
}

/// One run of `path` over a corpus of `shape`, with no classification: the
/// source and restored snapshots, the destination's pre-import schema and
/// the corpus ids. The red cells read it directly.
struct RawRun {
    before: StoreSnapshot,
    restored: StoreSnapshot,
    destination_schema: Vec<SchemaObject>,
    corpus: Corpus,
}

/// Seed a corpus of `shape`, run `path`, and check the source is unchanged.
/// `refuse` runs on the source snapshot before the path does, so a corpus
/// that cannot prove the path is refused before paying for the run.
fn run_raw_checked(
    path: RestorePath,
    shape: SeedShape,
    refuse: impl FnOnce(&StoreSnapshot),
) -> RawRun {
    let tmp = TempDir::new().expect("tempdir");
    let src = tmp.path().join("source.db");
    let corpus = seed(&src, shape);
    let before = snapshot(&src);
    assert_corpus_is_rich(&before, shape);
    refuse(&before);
    let (restored, destination_schema) = match path {
        RestorePath::BackupRestore => (backup_restore(&src, tmp.path()), Vec::new()),
        RestorePath::ExportFullImport => export_import(&src, tmp.path(), true),
        RestorePath::ExportImport => export_import(&src, tmp.path(), false),
    };
    // The source is never changed by taking the copy.
    assert_eq!(before, snapshot(&src), "{path:?} changed its SOURCE store");
    RawRun {
        before,
        restored: snapshot(&restored),
        destination_schema,
        corpus,
    }
}

fn run_raw(path: RestorePath, shape: SeedShape) -> RawRun {
    run_raw_checked(path, shape, |_| {})
}

/// The main cell of `path`: its own seed shape, and a source that
/// [`source_store`] accepts for the path's classification.
fn run_path(path: RestorePath) -> Cell {
    let run = run_raw_checked(path, path.seed_shape(), |before| {
        drop(source_store(path.class(), before.clone()));
    });
    Cell {
        source: source_store(path.class(), run.before),
        restored: run.restored,
        destination_schema: run.destination_schema,
        encrypted: run.corpus.encrypted,
    }
}

fn assert_cell(path: RestorePath) {
    let cell = run_path(path);
    assert_restored(
        path.class(),
        &cell.source,
        &cell.restored,
        &cell.destination_schema,
    );
    match (path.seed_shape().sealed, &cell.encrypted) {
        (Sealed::Present, Some(id)) => assert_sealed_row_decrypts(&cell.restored, id),
        (Sealed::Absent, None) => {}
        (sealed, id) => panic!("seed shape {sealed:?} disagrees with the sealed id {id:?}"),
    }
}

/// The key and value columns a red cell compares, per row.
type KeyedColumns = BTreeMap<Vec<Option<SqlValue>>, Vec<Option<SqlValue>>>;

/// The rows of `table` keyed by `key`, each projected to `columns`.
fn keyed_columns(s: &StoreSnapshot, table: &str, key: &[&str], columns: &[&str]) -> KeyedColumns {
    let pick = |r: &Row, cols: &[&str]| cols.iter().map(|c| r.get(*c).cloned()).collect();
    s.tables[table]
        .rows
        .iter()
        .map(|r| (pick(r, key), pick(r, columns)))
        .collect()
}

/// Some source row of `table` sets each of `columns` (the red cell is not
/// vacuous), and the restore keeps them row for row.
fn assert_columns_kept(run: &RawRun, table: &str, key: &[&str], columns: &[&str], defect: &str) {
    let want = keyed_columns(&run.before, table, key, columns);
    for (idx, col) in columns.iter().enumerate() {
        assert!(
            want.values()
                .any(|v| v[idx].as_ref().is_some_and(|v| !v.is_null())),
            "{table}.{col}: the corpus never sets it, so the cell would be vacuous"
        );
    }
    let got = keyed_columns(&run.restored, table, key, columns);
    assert_eq!(got, want, "{table} {columns:?} not kept ({defect})");
}

// ── the round-trip tests ────────────────────────────────────────────────────

#[test]
fn backup_then_restore_reproduces_every_table_exactly_9944() {
    assert_cell(RestorePath::BackupRestore);
}

#[test]
fn export_full_then_import_reproduces_the_store_9944() {
    assert_cell(RestorePath::ExportFullImport);
}

#[test]
fn convenience_export_then_import_reproduces_memories_and_links_9944() {
    assert_cell(RestorePath::ExportImport);
}

/// Defect #9948, red until it lands: `export --full` then `import` must keep
/// every link's attestation class. Today the v2 envelope never carries
/// `attest_level` (`export_link_from_row` leaves it `None`), so every restored
/// edge lands NULL while its signature is kept. The fix removes the
/// `LINK_ATTEST_LEVEL_DROPPED` lossy entry above in the same commit.
#[test]
fn export_full_keeps_every_link_attestation_9944() {
    let path = RestorePath::ExportFullImport;
    let run = run_raw(path, path.seed_shape());
    let (src, restored) = (&run.before, &run.restored);
    let key = |r: &Row| (r.get("source_id").cloned(), r.get("target_id").cloned());
    let attest = |s: &StoreSnapshot| -> BTreeMap<_, Option<SqlValue>> {
        s.tables["memory_links"]
            .rows
            .iter()
            .map(|r| (key(r), r.get("attest_level").cloned()))
            .collect()
    };
    let (want, got) = (attest(src), attest(restored));
    assert!(
        want.values()
            .all(|v| v.as_ref().is_some_and(|v| !v.is_null())),
        "every source link carries an attestation class: {want:?}"
    );
    assert_eq!(
        got, want,
        "export --full lost link attestation (defect #9948)"
    );
}

/// Defect #10027, red until it lands: `export --full` then `import` of a store
/// with an enrolled identity lineage (enrol, succession, guardian recovery)
/// must land every lineage row. Today `import` strips the `_agents` key
/// binding before its lineage gate, the gate reads the stripped head as a
/// forgery, and the import exits non-zero. The fix removes the
/// `LINEAGE_IMPORT_REFUSED` sparse entry above in the same commit.
#[test]
fn export_full_keeps_an_enrolled_identity_lineage_10027() {
    let run = run_raw(RestorePath::ExportFullImport, SeedShape::FULL);
    let src = &run.before.tables["agent_lineage"];
    assert!(
        src.rows.len() >= MIN_LINEAGE_ROWS,
        "the corpus enrols a lineage"
    );
    assert_eq!(
        run.restored.tables["agent_lineage"].rows, src.rows,
        "export --full lost the identity lineage (defect #10027)"
    );
}

/// Defect #10028, red until it lands: the convenience export then import must
/// keep a sealed row sealed (empty content, the envelope byte for byte). The
/// fix removes the `SEALED_ROW_UNSEALED` null-column entry above.
#[test]
fn convenience_export_keeps_a_sealed_row_sealed_10028() {
    let shape = SeedShape {
        lineage: Lineage::Absent,
        sealed: Sealed::Present,
    };
    let run = run_raw(RestorePath::ExportImport, shape);
    let id = run
        .corpus
        .encrypted
        .clone()
        .expect("the shape seeds a sealed row");
    assert_columns_kept(
        &run,
        "memories",
        &["id"],
        &["encrypted_envelope"],
        "defect #10028",
    );
    let content = |s: &StoreSnapshot| {
        s.tables["memories"]
            .rows
            .iter()
            .find(|r| r.get("id") == Some(&SqlValue::Text(id.as_bytes().to_vec())))
            .and_then(|r| r.get("content").cloned())
    };
    assert_eq!(
        content(&run.restored),
        content(&run.before),
        "the convenience export unsealed a sealed row's content (defect #10028)"
    );
}

/// Defect #10029, red until it lands: the convenience export then import must
/// keep every atomisation, kind-provenance and entity-mention column. The fix
/// removes the `ATOM_COLUMNS_DROPPED` lossy entries above.
#[test]
fn convenience_export_keeps_every_atomisation_column_10029() {
    let path = RestorePath::ExportImport;
    let run = run_raw(path, path.seed_shape());
    assert_columns_kept(
        &run,
        "memories",
        &["id"],
        &[
            "atomised_into",
            "atom_of",
            "kind_provenance",
            "mentioned_entity_id",
        ],
        "defect #10029",
    );
}

/// Defect #10030, red until it lands: the convenience export then import must
/// keep every link's validity window. The fix removes the
/// `LINK_VALID_UNTIL_DROPPED` lossy entry above.
#[test]
fn convenience_export_keeps_every_link_validity_window_10030() {
    let path = RestorePath::ExportImport;
    let run = run_raw(path, path.seed_shape());
    assert_columns_kept(
        &run,
        "memory_links",
        &["source_id", "target_id", "relation"],
        &["valid_until"],
        "defect #10030",
    );
}

/// Defect #10031, red until it lands: `export --full` then `import` must keep
/// every live row's atomisation, kind-provenance and entity-mention column.
/// The fix removes the `FULL_ATOM_COLUMNS_DROPPED` lossy entries above.
#[test]
fn export_full_keeps_every_atomisation_column_10031() {
    let path = RestorePath::ExportFullImport;
    let run = run_raw(path, path.seed_shape());
    assert_columns_kept(
        &run,
        "memories",
        &["id"],
        &[
            "atomised_into",
            "atom_of",
            "kind_provenance",
            "mentioned_entity_id",
        ],
        "defect #10031",
    );
}

/// Defect #10032, red until it lands: `export --full` then `import` must keep
/// a sealed live row and a sealed archived row sealed (empty live content,
/// each envelope present). The fix removes the `FULL_SEALED_ROW_UNSEALED`
/// null-column entries above.
#[test]
fn export_full_keeps_a_sealed_row_sealed_10032() {
    let shape = SeedShape {
        lineage: Lineage::Absent,
        sealed: Sealed::Present,
    };
    let run = run_raw(RestorePath::ExportFullImport, shape);
    let id = run
        .corpus
        .encrypted
        .clone()
        .expect("the shape seeds a sealed row");
    let content = |s: &StoreSnapshot| {
        s.rows_where("memories", "id", &id)
            .first()
            .and_then(|r| r.get("content").cloned())
    };
    assert_eq!(
        content(&run.restored),
        content(&run.before),
        "export --full unsealed a sealed row's content (defect #10032)"
    );
    for table in ["memories", "archived_memories"] {
        let sealed_rows = |s: &StoreSnapshot| {
            s.tables[table]
                .rows
                .iter()
                .filter(|r| matches!(r.get("encrypted_envelope"), Some(SqlValue::Blob(_))))
                .count()
        };
        assert!(
            sealed_rows(&run.before) > 0,
            "{table}: the corpus seals a row"
        );
        assert_eq!(
            sealed_rows(&run.restored),
            sealed_rows(&run.before),
            "{table}: export --full dropped an envelope (defect #10032)"
        );
    }
    assert_sealed_row_decrypts(&run.restored, &id);
}

/// Archive then restore: the memory row, its embedding and its edges come
/// back exactly as they were before the archive.
#[test]
fn archive_then_restore_reproduces_the_row_its_embedding_and_its_links_9944() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("source.db");
    let corpus = seed(&db, SeedShape::FULL);
    // Restore the archived row first so the pre-image below is a LIVE row.
    ai_memory(&db)
        .args(["archive", "restore", &corpus.archived])
        .assert()
        .success();
    let target = corpus.live[1].clone();
    let before = row_image(&db, &target);
    {
        let conn = ai_memory::db::open(&db).expect("open");
        assert!(
            ai_memory::db::archive_memory(&conn, &target, Some(ARCHIVE_REASON)).expect("archive"),
            "target archived"
        );
    }
    assert!(
        row_image(&db, &target).0.is_empty(),
        "archived row left memories"
    );
    ai_memory(&db)
        .args(["archive", "restore", &target])
        .assert()
        .success();
    let after = row_image(&db, &target);
    assert_eq!(
        before.0.len(),
        after.0.len(),
        "the restored memories row is missing"
    );
    let differing: Vec<&str> = before
        .0
        .iter()
        .zip(&after.0)
        .flat_map(|(a, b)| a.keys().filter(|c| a.get(*c) != b.get(*c)))
        .map(String::as_str)
        .collect();
    assert_eq!(
        differing, ARCHIVE_RESTORE_RESTAMPED,
        "the restored memories row differs from its pre-archive image in columns {differing:?}; \
         only {ARCHIVE_RESTORE_RESTAMPED:?} may change ({ARCHIVE_RESTORE_RESTAMP_REASON})"
    );
    let stamp = |rows: &[Row]| match rows[0].get(RESTAMPED_COLUMN) {
        Some(v) if v.as_str().is_some() => v.as_str().unwrap_or_default().to_string(),
        other => panic!("{RESTAMPED_COLUMN} is not UTF-8 text: {other:?}"),
    };
    // The corpus stamps are fixed in the future (UPDATED_AT), so the restore
    // stamp (now) differs from them; it must be a valid RFC 3339 instant.
    let restamped = stamp(&after.0);
    assert_ne!(
        restamped,
        stamp(&before.0),
        "the restore rewrites {RESTAMPED_COLUMN}"
    );
    chrono::DateTime::parse_from_rfc3339(&restamped)
        .unwrap_or_else(|e| panic!("{RESTAMPED_COLUMN} {restamped:?} is not RFC 3339: {e}"));
    assert_eq!(
        before.1, after.1,
        "the restored row's links differ from their pre-archive image"
    );
}

/// The `memories` row and the `memory_links` rows touching `id`.
fn row_image(db: &Path, id: &str) -> (Vec<Row>, Vec<Row>) {
    let s = snapshot(db);
    let mem = s.tables["memories"]
        .rows
        .iter()
        .filter(|r| r.get("id") == Some(&SqlValue::text(id)))
        .cloned()
        .collect();
    let want = SqlValue::text(id);
    let links = s.tables["memory_links"]
        .rows
        .iter()
        .filter(|r| r.get("source_id") == Some(&want) || r.get("target_id") == Some(&want))
        .cloned()
        .collect();
    (mem, links)
}

// ── the ratchet ─────────────────────────────────────────────────────────────

/// Every live table is classified for every path, and every lossy entry names
/// a live column of a carried table (no stale entry can hide a regression).
#[test]
fn every_live_table_is_classified_for_every_path_9944() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("schema.db");
    seed(&db, SeedShape::FULL);
    let s = snapshot(&db);
    let problems: Vec<String> = RestorePath::ALL
        .iter()
        .flat_map(|p| p.class().ratchet(&s))
        .collect();
    assert!(
        problems.is_empty(),
        "classification out of step with the live schema:\n  {}",
        problems.join("\n  ")
    );
}

// ── mutation probes: the comparison itself catches each field class ────────

/// The four mutation classes the issue names, applied to a copy of the
/// seeded store: each must turn the comparison red with the exact difference.
#[test]
fn the_comparison_catches_every_mutation_class_9944() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("probe.db");
    seed(&db, SeedShape::FULL);
    let snap = snapshot(&db);
    let class = RestorePath::BackupRestore.class();
    let src = source_store(class, snap.clone());
    assert_eq!(
        restore_snapshot::compare(class, &src, &snap, &[]),
        Vec::<String>::new(),
        "a store compared with itself is exact"
    );
    let mutate = |name: &str, f: &dyn Fn(&mut StoreSnapshot)| {
        let mut m = snap.clone();
        f(&mut m);
        let diffs = restore_snapshot::compare(class, &src, &m, &[]);
        for d in &diffs {
            eprintln!("probe {name}: {}", d.lines().next().unwrap_or_default());
        }
        diffs
    };
    // 1. drop embeddings
    let diffs = mutate("drop-embeddings", &|s| {
        for r in rows_mut(s, "memories") {
            r.insert("embedding".to_string(), SqlValue::Null);
        }
    });
    assert!(
        diffs
            .iter()
            .any(|d| d.starts_with("memories: ") && d.contains("\n      embedding: source ")),
        "dropped embeddings: {diffs:?}"
    );
    // 2. drop namespace_meta
    let diffs = mutate("drop-namespace_meta", &|s| {
        rows_mut(s, "namespace_meta").clear();
    });
    assert!(
        diffs.iter().any(|d| d.starts_with("namespace_meta: ")),
        "dropped namespace_meta: {diffs:?}"
    );
    // 3. alter one byte of one embedding
    let diffs = mutate("alter-one-byte", &|s| {
        let row = rows_mut(s, "memories")
            .iter_mut()
            .find(|r| matches!(r.get("embedding"), Some(SqlValue::Blob(_))))
            .expect("an embedded row");
        if let Some(SqlValue::Blob(b)) = row.get_mut("embedding") {
            let last = b.last_mut().expect("non-empty blob");
            *last ^= 0x01;
        }
    });
    // Exactly one diff, naming exactly one source row and exactly one column.
    assert_eq!(diffs.len(), 1, "one altered byte: {diffs:?}");
    let report = &diffs[0];
    let n = snap.row_count("memories");
    let head =
        format!("memories: {n} source rows, {n} restored rows, 1 source rows not reproduced");
    assert!(report.starts_with(&head), "one altered byte: {report}");
    let named: Vec<&str> = report
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| *l != "--")
        .collect();
    assert_eq!(
        named.len(),
        1,
        "one altered byte names one column: {report}"
    );
    assert!(
        named[0].starts_with("embedding: source "),
        "one altered byte: {report}"
    );
    // 4. drop one link
    let diffs = mutate("drop-one-link", &|s| {
        rows_mut(s, "memory_links").remove(0);
    });
    assert!(
        diffs.iter().any(|d| d.starts_with("memory_links: ")),
        "dropped link: {diffs:?}"
    );
}

fn rows_mut<'a>(s: &'a mut StoreSnapshot, table: &str) -> &'a mut Vec<Row> {
    &mut s.tables.get_mut(table).expect("table").rows
}
