// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #10021 (GA standard 4): PostgreSQL-native backup and restore behind the existing
//! `backup` / `restore` verbs.
//!
//! Invariant under test: a backup of a PostgreSQL store, restored into a freshly migrated
//! PostgreSQL store, reproduces every row of every dumped table byte-exactly (canonical
//! `row::text` under `TimeZone=UTC`), the sequences continue past the restored maximum, and a
//! tampered, truncated, unsigned, re-signed, foreign or mismatched artifact is refused with
//! its exact error while the target stays empty.
//!
//! Expected values are hand-written literals (the corpus in `corpus.rs`, the table, sequence,
//! exclusion and type lists below); none is computed by the code under test.
//!
//! Every cell needs a live PostgreSQL (+ AGE + pgvector): `AI_MEMORY_TEST_POSTGRES_URL`. The
//! cells do not self-skip: an unset URL fails the cell.
#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::similar_names
)]

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

#[path = "pg_native_backup_restore_10021/corpus.rs"]
mod corpus;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ai_memory::identity::keypair;
use ai_memory::models::{MemoryLink, MemoryLinkRelation};
use ai_memory::store::native_backup::{
    self as nb, Exclusion, NativeBackupError, NativeDumpBody, NativeRestoreReport, SequenceValue,
    SignedPgManifest, VerifiedPgBackup,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, VerifyFilter};
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// The agent every signed write in these cells is attributed to.
const AGENT: &str = "ai:pgnb";

/// The operator trust anchor's secret seed (test-only). Not a repeated byte: the corpus
/// holds a `\x07` x 32 bytea value, and the C-8 secret scan must not match table content.
const ANCHOR_SEED: [u8; 32] = *b"anchor-seed/pgnb-10021/v1-------";

/// A key embedded by an attacker in a re-signed artifact (test-only).
const EMBEDDED_SEED: [u8; 32] = [9u8; 32];

/// Plaintext API key whose hash is bound in the C-8 cell; it must never reach the artifact.
const API_KEY_CANARY: &str = "pgnb-canary-10021-plaintext-api-key";

/// The 45 dumped public tables, hand-written (the catalog of a migrated store minus
/// `schema_version`).
const EXPECTED_TABLES: [&str; 45] = [
    "a2a_task_memories",
    "a2a_tasks",
    "action_edges",
    "actions",
    "agent_api_keys",
    "agent_lineage",
    "agent_pubkey_challenges",
    "agent_pubkey_history",
    "agent_quotas",
    "agent_subkey_certs",
    "archived_memories",
    "archived_memory_links",
    "attested_write_ledger",
    "audit_log",
    "checkpoints",
    "confidence_shadow_observations",
    "embed_skip",
    "entity_aliases",
    "federation_push_dlq",
    "forget_tombstones",
    "kg_projection_outbox",
    "leases",
    "lineage_integrity_watermark",
    "memories",
    "memory_links",
    "memory_revisions",
    "memory_transcript_links",
    "memory_transcripts",
    "model_attestations",
    "namespace_meta",
    "offloaded_blobs",
    "pending_actions",
    "recall_observations",
    "routine_runs",
    "routines",
    "signals",
    "signed_events",
    "signed_events_dlq",
    "subscription_dlq",
    "subscription_events",
    "subscriptions",
    "sync_peer_contact",
    "sync_state",
    "token_cost_counters",
    "transcript_line_dedup",
];

/// The 6 dumped public sequences, hand-written.
const EXPECTED_SEQUENCES: [&str; 6] = [
    "confidence_shadow_observations_id_seq",
    "federation_push_dlq_id_seq",
    "kg_projection_outbox_id_seq",
    "signed_events_dlq_dlq_id_seq",
    "subscription_dlq_id_seq",
    "subscription_events_id_seq",
];

const R_VIEW: &str = "view: holds no rows";
const R_EXT: &str = "owned by extension; created by CREATE EXTENSION / target migration";
const R_AGE: &str =
    "AGE projection of public.memory_links; restore re-projects every memory_links row";
const R_LEDGER: &str = "target's own migration ledger; restore requires equal MAX(version)";
const R_GEN: &str = "generated; recomputed";

/// Every relation (and generated column) deliberately not dumped, with its reason,
/// hand-written, sorted by relation.
const EXPECTED_EXCLUSIONS: [(&str, &str); 15] = [
    ("ag_catalog.ag_graph", R_EXT),
    ("ag_catalog.ag_label", R_EXT),
    ("memory_graph._ag_label_edge", R_AGE),
    ("memory_graph._ag_label_edge_id_seq", R_AGE),
    ("memory_graph._ag_label_vertex", R_AGE),
    ("memory_graph._ag_label_vertex_id_seq", R_AGE),
    ("memory_graph._label_id_seq", R_AGE),
    ("public.inbox_namespace_aliases", R_VIEW),
    ("public.kg_query_view", R_VIEW),
    ("public.kg_timeline_view", R_VIEW),
    ("public.memories.agent_id_idx", R_GEN),
    ("public.memories.scope_idx", R_GEN),
    ("public.memories.target_agent_id_idx", R_GEN),
    ("public.memories.tsv", R_GEN),
    ("public.schema_version", R_LEDGER),
];

/// Column types with a backup handler, hand-written. Every non-generated column of a
/// migrated store has exactly these types.
const EXPECTED_TYPES: [&str; 9] = [
    "bool",
    "bytea",
    "float8",
    "int4",
    "int8",
    "jsonb",
    "text",
    "timestamptz",
    "vector",
];

/// The first table of the restore order (FK topological, ties by name), hand-written.
const FIRST_RESTORE_TABLE: &str = "public.a2a_tasks";

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

fn admin_url() -> String {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("#10021: AI_MEMORY_TEST_POSTGRES_URL must name a live PostgreSQL (no self-skip)")
}

fn anchor() -> SigningKey {
    SigningKey::from_bytes(&ANCHOR_SEED)
}

fn anchor_pub() -> VerifyingKey {
    anchor().verifying_key()
}

/// A freshly migrated store in its own scratch database, plus a raw pool on it.
struct Db {
    pool: PgPool,
    store: PostgresStore,
    scratch: pg_barrier::ScratchDb,
}

async fn fresh(prefix: &str) -> Db {
    let scratch = pg_barrier::ScratchDb::create(&admin_url(), prefix)
        .await
        .expect("scratch db");
    {
        let p0 = PgPoolOptions::new()
            .max_connections(1)
            .connect(&scratch.url())
            .await
            .expect("p0");
        sqlx::query("CREATE EXTENSION IF NOT EXISTS age")
            .execute(&p0)
            .await
            .expect("age");
        p0.close().await;
    }
    let store = PostgresStore::connect(&scratch.url())
        .await
        .expect("connect + migrate");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET TIME ZONE 'UTC'")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&scratch.url())
        .await
        .expect("raw pool");
    Db {
        pool,
        store,
        scratch,
    }
}

fn sql_lit(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

async fn insert_rows(conn: &mut sqlx::PgConnection, table: &str, rows: &[&[corpus::Cell]]) {
    for row in rows {
        let cols: Vec<&str> = row.iter().filter(|c| c.1.is_some()).map(|c| c.0).collect();
        let vals: Vec<String> = row.iter().filter_map(|c| c.1).map(sql_lit).collect();
        let sql = format!(
            "INSERT INTO public.{table} ({}) VALUES ({})",
            cols.join(", "),
            vals.join(", ")
        );
        sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("seed {table}: {e}"));
    }
}

/// Seed the whole corpus in one transaction (FKs and user triggers off for the seed only).
async fn seed_corpus(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("seed tx");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica role");
    for (table, rows) in corpus::CORPUS {
        insert_rows(&mut tx, table, rows).await;
    }
    tx.commit().await.expect("seed commit");
}

fn corpus_rows(table: &str) -> &'static [&'static [corpus::Cell]] {
    corpus::CORPUS
        .iter()
        .find(|(t, _)| *t == table)
        .map_or_else(|| panic!("corpus has no table {table}"), |(_, r)| *r)
}

fn corpus_row_total() -> u64 {
    corpus::CORPUS
        .iter()
        .map(|(_, r)| u64::try_from(r.len()).expect("len"))
        .sum()
}

/// (row count, md5 of the canonical row text in a stable order) of one table.
async fn table_digest(pool: &PgPool, qualified: &str) -> (i64, Option<String>) {
    sqlx::query_as(&format!(
        "SELECT count(1), md5(string_agg(x::text, E'\\n' ORDER BY x::text COLLATE \"C\")) \
         FROM {qualified} x"
    ))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("digest {qualified}: {e}"))
}

async fn count_rows(pool: &PgPool, qualified: &str) -> i64 {
    table_digest(pool, qualified).await.0
}

/// Every dumped table of `tables` holds zero rows on `pool`.
async fn assert_empty(pool: &PgPool, why: &str) {
    for t in EXPECTED_TABLES {
        let n = count_rows(pool, &format!("public.{t}")).await;
        assert_eq!(
            n, 0,
            "#10021 {why}: public.{t} holds {n} rows; target must stay empty"
        );
    }
}

/// Assert every corpus cell reads back as its hand-written expected text.
async fn assert_corpus_cells(pool: &PgPool) {
    for (table, rows) in corpus::CORPUS {
        for row in *rows {
            let (key_col, _, key_val) = row[0];
            for (col, _, expected) in *row {
                let got: Option<String> = sqlx::query_scalar(&format!(
                    "SELECT {col}::text FROM public.{table} WHERE {key_col}::text = $1"
                ))
                .bind(key_val)
                .fetch_optional(pool)
                .await
                .unwrap_or_else(|e| panic!("cell {table}.{col}: {e}"));
                assert_eq!(
                    got.as_deref(),
                    Some(*expected),
                    "#10021 cell public.{table}.{col} (key {key_val}) not restored exactly"
                );
            }
        }
    }
}

/// A unique scratch directory under `<repo>/.local-runs/` (never /tmp).
fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("pgnb-10021")
        .join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

/// A dumped artifact on disk.
struct Artifact {
    dir: PathBuf,
    data: PathBuf,
    manifest: PathBuf,
    body: NativeDumpBody,
}

fn write_signed(dir: &Path, name: &str, body: &NativeDumpBody, key: &SigningKey) -> PathBuf {
    let m = nb::sign_pg_manifest(body, key).expect("sign");
    write_manifest(dir, name, &m)
}

fn write_manifest(dir: &Path, name: &str, m: &SignedPgManifest) -> PathBuf {
    let path = dir.join(format!("{name}.{}", nb::PG_BACKUP_MANIFEST_SUFFIX));
    let mut f = nb::create_private_file(&path).expect("manifest file");
    f.write_all(&m.to_json_bytes().expect("manifest json"))
        .expect("write manifest");
    f.sync_all().expect("sync manifest");
    path
}

async fn dump(db: &Db, tag: &str) -> Artifact {
    let dir = unique_dir(tag);
    let data = dir.join(format!("backup.{}", nb::PG_BACKUP_DATA_SUFFIX));
    let file = nb::create_private_file(&data).expect("data file");
    let body = db.store.native_backup(file).await.expect("native_backup");
    let manifest = write_signed(&dir, "backup", &body, &anchor());
    Artifact {
        dir,
        data,
        manifest,
        body,
    }
}

fn verify(manifest: &Path, data: &Path) -> Result<VerifiedPgBackup, NativeBackupError> {
    let bytes = nb::read_manifest_capped(manifest)?;
    let file = std::fs::File::open(data).expect("open data");
    nb::verify_pg_backup(&bytes, file, &anchor_pub())
}

async fn restore(db: &Db, manifest: &Path, data: &Path) -> Result<NativeRestoreReport, StoreError> {
    let verified = verify(manifest, data).expect("artifact must verify");
    db.store.native_restore(verified).await
}

fn integrity_detail(e: StoreError) -> String {
    match e {
        StoreError::IntegrityFailed { detail } => detail,
        other => panic!("#10021 expected StoreError::IntegrityFailed, got {other:?}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn copy_data(a: &Artifact, name: &str) -> PathBuf {
    let p = a.dir.join(format!("{name}.{}", nb::PG_BACKUP_DATA_SUFFIX));
    let bytes = std::fs::read(&a.data).expect("read data");
    let mut f = nb::create_private_file(&p).expect("copy data");
    f.write_all(&bytes).expect("write copy");
    p
}

fn segment<'a>(body: &'a NativeDumpBody, qualified: &str) -> &'a nb::TableSegment {
    body.tables
        .iter()
        .find(|s| s.qualified() == qualified)
        .unwrap_or_else(|| panic!("artifact has no segment {qualified}"))
}

/// Compare every dumped table of `src` and `tgt` by canonical bytes; returns the count.
async fn assert_tables_equal(src: &PgPool, tgt: &PgPool, skip: &[&str]) -> usize {
    let mut compared = 0usize;
    for t in EXPECTED_TABLES {
        if skip.contains(&t) {
            continue;
        }
        let q = format!("public.{t}");
        let a = table_digest(src, &q).await;
        let b = table_digest(tgt, &q).await;
        assert_eq!(a, b, "#10021 {q}: restored rows differ from the source");
        compared += 1;
    }
    compared
}

async fn now_epoch(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
        .fetch_one(pool)
        .await
        .expect("now")
}

// ---------------------------------------------------------------------------------------
// C-5 + standard 4: exact round trip
// ---------------------------------------------------------------------------------------

/// Backup then restore into a freshly migrated store reproduces every row of every table
/// byte-exactly, every corpus cell as its hand-written text, and the sequences continue past
/// the restored maximum. Mutants: skip a table on backup / on restore, drop the sequence reset.
#[tokio::test(flavor = "multi_thread")]
async fn round_trip_is_byte_exact_10021() {
    let src = fresh("pgnb10021rts").await;
    seed_corpus(&src.pool).await;
    // #10049: a distinct (last_value, is_called) per sequence, both is_called states, so a
    // restore that resets or drops either half is red.
    for (k, s) in EXPECTED_SEQUENCES.iter().enumerate() {
        let (last, called) = seq_value(k);
        sqlx::query(&format!("SELECT setval('public.{s}', $1, $2)"))
            .bind(last)
            .bind(called)
            .execute(&src.pool)
            .await
            .expect("setval");
    }
    let art = dump(&src, "rt").await;

    let names: Vec<String> = art
        .body
        .tables
        .iter()
        .map(nb::TableSegment::qualified)
        .collect();
    let got: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let want: BTreeSet<String> = EXPECTED_TABLES
        .iter()
        .map(|t| format!("public.{t}"))
        .collect();
    let want: BTreeSet<&str> = want.iter().map(String::as_str).collect();
    assert_eq!(
        got, want,
        "#10021 backup must dump exactly the 45 public tables"
    );
    assert_eq!(art.body.tables.len(), 45, "#10021 catalog table count");
    assert_eq!(art.body.tables[0].qualified(), FIRST_RESTORE_TABLE);
    for t in EXPECTED_TABLES {
        let rows = u64::try_from(corpus_rows(t).len()).expect("len");
        assert_eq!(
            segment(&art.body, &format!("public.{t}")).rows,
            rows,
            "rows of {t}"
        );
    }
    let seqs: Vec<SequenceValue> = EXPECTED_SEQUENCES
        .iter()
        .enumerate()
        .map(|(k, s)| SequenceValue {
            schema: "public".to_string(),
            name: (*s).to_string(),
            last_value: seq_value(k).0,
            is_called: seq_value(k).1,
        })
        .collect();
    assert_eq!(
        art.body.sequences, seqs,
        "#10021 sequence values in the artifact"
    );
    assert_eq!(art.body.backend, nb::PG_BACKUP_BACKEND);
    assert_eq!(art.body.layout_version, nb::PG_BACKUP_LAYOUT_VERSION);

    let tgt = fresh("pgnb10021rtt").await;
    let report = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("restore into a fresh store");
    assert_eq!(
        report,
        NativeRestoreReport {
            tables: 45,
            rows: corpus_row_total(),
            sequences: 6,
            leases_clamped: 0,
            age_edges_projected: 1,
        }
    );

    assert_corpus_cells(&tgt.pool).await;
    let compared = assert_tables_equal(&src.pool, &tgt.pool, &[]).await;
    assert_eq!(compared, 45, "#10021 compared table count");

    // Generated columns are recomputed on the target, equal to the hand-written values.
    let generated: (String, String, String) = sqlx::query_as(
        "SELECT agent_id_idx, scope_idx, target_agent_id_idx FROM public.memories \
         WHERE id = 'm1-10021'",
    )
    .fetch_one(&tgt.pool)
    .await
    .expect("generated cols");
    assert_eq!(
        generated,
        (
            "ai:pgnb".to_string(),
            "private".to_string(),
            "ai:pgnb-peer".to_string()
        )
    );

    // Every sequence carries the source's exact (last_value, is_called) and continues from
    // it (#10049; mutants: drop the sequence reset, bind a constant last_value).
    for (k, s) in EXPECTED_SEQUENCES.iter().enumerate() {
        let (last, called) = seq_value(k);
        let state: (i64, bool) =
            sqlx::query_as(&format!("SELECT last_value, is_called FROM public.{s}"))
                .fetch_one(&tgt.pool)
                .await
                .expect("sequence state");
        assert_eq!(
            state,
            (last, called),
            "#10049 sequence public.{s} state on the target"
        );
        let next: i64 = sqlx::query_scalar(&format!("SELECT nextval('public.{s}')"))
            .fetch_one(&tgt.pool)
            .await
            .expect("nextval");
        let want = if called { last + 1 } else { last };
        assert_eq!(
            next, want,
            "#10049 sequence public.{s} must continue from the restored state"
        );
    }
}

/// The `(last_value, is_called)` the round trip sets on sequence `k` (#10049).
fn seq_value(k: usize) -> (i64, bool) {
    (100 + i64::try_from(k).expect("k"), k.is_multiple_of(2))
}

// ---------------------------------------------------------------------------------------
// C-4: catalog completeness ratchet
// ---------------------------------------------------------------------------------------

/// Every relation over all non-system schemas (AGE included) plus every sequence is either
/// dumped and compared or on the one named exclusion list with its reason; every column type
/// has a handler; the corpus fills every non-generated column.
#[tokio::test(flavor = "multi_thread")]
async fn catalog_ratchet_every_relation_dumped_or_excluded_10021() {
    let src = fresh("pgnb10021cat").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "cat").await;

    let mut excl: Vec<Exclusion> = art.body.exclusions.clone();
    excl.sort_by(|a, b| a.relation.cmp(&b.relation));
    let want: Vec<Exclusion> = EXPECTED_EXCLUSIONS
        .iter()
        .map(|(r, why)| Exclusion {
            relation: (*r).to_string(),
            reason: (*why).to_string(),
        })
        .collect();
    assert_eq!(excl, want, "#10021 the named exclusion list");

    let dumped: BTreeSet<String> = art
        .body
        .tables
        .iter()
        .map(nb::TableSegment::qualified)
        .collect();
    let seqs: BTreeSet<String> = art
        .body
        .sequences
        .iter()
        .map(|s| format!("{}.{}", s.schema, s.name))
        .collect();
    let excluded: BTreeSet<&str> = EXPECTED_EXCLUSIONS.iter().map(|(r, _)| *r).collect();

    let rels: Vec<(String, String)> = sqlx::query_as(
        "SELECT format('%s.%s', n.nspname, c.relname), c.relkind::text \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r','p','S','v','m','f') \
           AND n.nspname NOT IN ('pg_catalog','information_schema') \
           AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1",
    )
    .fetch_all(&src.pool)
    .await
    .expect("catalog");
    let mut accounted = 0usize;
    for (rel, kind) in &rels {
        let ok = dumped.contains(rel) || seqs.contains(rel) || excluded.contains(rel.as_str());
        assert!(
            ok,
            "#10021 relation {rel} (relkind {kind}) is neither dumped nor excluded"
        );
        accounted += 1;
    }
    assert_eq!(
        accounted, 62,
        "#10021 catalog relation count (45 + 6 + 11 excluded)"
    );
    assert_eq!(dumped.len() + seqs.len(), 51);

    let gens: Vec<String> = sqlx::query_scalar(
        "SELECT format('%s.%s.%s', n.nspname, c.relname, a.attname) FROM pg_attribute a \
         JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> '' \
           AND c.relkind IN ('r','p') ORDER BY 1",
    )
    .fetch_all(&src.pool)
    .await
    .expect("generated");
    for g in &gens {
        assert!(
            excluded.contains(g.as_str()),
            "#10021 generated column {g} not excluded"
        );
    }

    let cols: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text, t.typname::text FROM pg_attribute a \
         JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_type t ON t.oid = a.atttypid \
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum > 0 \
           AND NOT a.attisdropped AND a.attgenerated = '' AND c.relname <> 'schema_version' \
         ORDER BY c.relname, a.attnum",
    )
    .fetch_all(&src.pool)
    .await
    .expect("columns");
    let types: BTreeSet<&str> = cols.iter().map(|c| c.2.as_str()).collect();
    let want_types: BTreeSet<&str> = EXPECTED_TYPES.iter().copied().collect();
    assert_eq!(
        types, want_types,
        "#10021 every column type has a backup handler"
    );
    for seg in &art.body.tables {
        let catalog: Vec<(String, String)> = cols
            .iter()
            .filter(|c| c.0 == seg.name)
            .map(|c| (c.1.clone(), c.2.clone()))
            .collect();
        let spec: Vec<(String, String)> = seg
            .columns
            .iter()
            .map(|c| (c.name.clone(), c.type_name.clone()))
            .collect();
        assert_eq!(spec, catalog, "#10021 column specs of {}", seg.qualified());
        for row in corpus_rows(&seg.name) {
            let have: BTreeSet<&str> = row.iter().map(|c| c.0).collect();
            for (c, _) in &catalog {
                assert!(
                    have.contains(c.as_str()),
                    "corpus misses {}.{c}",
                    seg.qualified()
                );
            }
        }
    }
}

/// A column type with no backup handler refuses the backup with its exact error.
#[tokio::test(flavor = "multi_thread")]
async fn backup_refuses_a_column_type_with_no_handler_10021() {
    let src = fresh("pgnb10021typ").await;
    sqlx::query("ALTER TABLE public.namespace_meta ADD COLUMN x10021 inet")
        .execute(&src.pool)
        .await
        .expect("add inet column");
    let dir = unique_dir("typ");
    let file = nb::create_private_file(&dir.join("t.pgdata")).expect("file");
    let err = src
        .store
        .native_backup(file)
        .await
        .expect_err("must refuse");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::CatalogMismatch {
            detail: "column public.namespace_meta.x10021 has type inet with no backup handler"
                .to_string(),
        }
        .to_string()
    );
}

/// A table on the source that the target does not have refuses the restore before any write.
#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_a_table_missing_on_the_target_10021() {
    let src = fresh("pgnb10021xts").await;
    seed_corpus(&src.pool).await;
    sqlx::query("CREATE TABLE public.extra_10021 (x int4 PRIMARY KEY)")
        .execute(&src.pool)
        .await
        .expect("extra table");
    let art = dump(&src, "xt").await;
    let tgt = fresh("pgnb10021xtt").await;
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("must refuse");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::CatalogMismatch {
            detail: "table public.extra_10021 does not exist on the target".to_string(),
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "missing table").await;
}

/// A sequence on the target that the artifact does not carry refuses the restore before
/// any write (#10044, the reverse direction of the sequence check).
/// Mutant: drop the target-to-artifact sequence loop in `check_catalog`.
#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_a_sequence_only_on_the_target_10044() {
    let src = fresh("pgnb10044xss").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "xs").await;
    let tgt = fresh("pgnb10044xst").await;
    sqlx::query("CREATE SEQUENCE public.extra_seq_10021")
        .execute(&tgt.pool)
        .await
        .expect("extra sequence");
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("must refuse");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::CatalogMismatch {
            detail: "sequence public.extra_seq_10021 exists on the target but not in the artifact"
                .to_string(),
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "extra target sequence").await;
}

/// A data file changed in place after verification (same inode, same length, one byte
/// flipped inside `public.memories`) is caught by the per-segment re-hash during the load:
/// the exact digest refusal, nothing written, and a retry after the byte is restored
/// succeeds (#10043). Mutant: drop the digest check in `feed_segment`.
#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_a_data_file_changed_after_verification_10021() {
    use std::io::{Seek as _, SeekFrom};
    let src = fresh("pgnb10043tcs").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "tc").await;
    let tgt = fresh("pgnb10043tct").await;

    let seg = segment(&art.body, "public.memories").clone();
    let at = seg.offset + seg.len / 2;
    let flip = |path: &Path| {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open data in place");
        let mut b = [0u8; 1];
        f.seek(SeekFrom::Start(at)).expect("seek");
        std::io::Read::read_exact(&mut f, &mut b).expect("read byte");
        b[0] ^= 0x01;
        f.seek(SeekFrom::Start(at)).expect("seek back");
        f.write_all(&b).expect("write byte");
        f.sync_all().expect("sync");
    };
    let len_before = std::fs::metadata(&art.data).expect("meta").len();

    let verified = verify(&art.manifest, &art.data).expect("the good artifact verifies");
    flip(&art.data);
    assert_eq!(
        std::fs::metadata(&art.data).expect("meta").len(),
        len_before
    );
    let err = tgt
        .store
        .native_restore(verified)
        .await
        .expect_err("a file changed after verification must be refused");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::DigestMismatch {
            table: "public.memories".to_string()
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "changed after verification").await;

    flip(&art.data);
    restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("a retry with the original bytes succeeds");
    assert_tables_equal(&src.pool, &tgt.pool, &[]).await;
}

// ---------------------------------------------------------------------------------------
// C-6 + C-3: verification refusals before any write
// ---------------------------------------------------------------------------------------

/// Tampered, truncated, unsigned, re-signed-with-an-embedded-key, unknown-layout,
/// cross-backend and foreign (SQLite) artifacts are each refused with the exact error by the
/// verifier, so no `VerifiedPgBackup` exists and the target writes zero rows.
/// Mutants: drop a digest check, drop the signature check.
#[tokio::test(flavor = "multi_thread")]
async fn verifier_refuses_every_bad_artifact_exactly_10021() {
    let src = fresh("pgnb10021vfs").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "vf").await;
    verify(&art.manifest, &art.data).expect("the good artifact verifies");

    // Tampered row byte, whole-file digest recomputed and re-signed by the anchor: the
    // per-table digest catches it.
    let tampered = copy_data(&art, "tampered");
    let seg = segment(&art.body, "public.memories").clone();
    let mut bytes = std::fs::read(&tampered).expect("read");
    let at = usize::try_from(seg.offset + seg.len / 2).expect("offset");
    bytes[at] ^= 0x01;
    std::fs::write(&tampered, &bytes).expect("write tampered");
    let mut body = art.body.clone();
    body.data_sha256 = sha256_hex(&bytes);
    let m = write_signed(&art.dir, "tampered", &body, &anchor());
    assert_eq!(
        verify(&m, &tampered).expect_err("tampered"),
        NativeBackupError::DigestMismatch {
            table: "public.memories".to_string()
        }
    );

    // Whole-file digest wrong in a correctly signed manifest.
    let mut body = art.body.clone();
    body.data_sha256 = "00".repeat(32);
    let m = write_signed(&art.dir, "datasha", &body, &anchor());
    assert_eq!(
        verify(&m, &art.data).expect_err("data digest"),
        NativeBackupError::DataDigestMismatch
    );

    // Truncated data file.
    let truncated = copy_data(&art, "truncated");
    let full = std::fs::read(&truncated).expect("read");
    let cut = full.len() - 1;
    std::fs::write(&truncated, &full[..cut]).expect("truncate");
    assert_eq!(
        verify(&art.manifest, &truncated).expect_err("truncated"),
        NativeBackupError::Truncated {
            expected: art.body.data_len,
            actual: u64::try_from(cut).expect("cut"),
        }
    );

    // Unsigned.
    let mut m = nb::sign_pg_manifest(&art.body, &anchor()).expect("sign");
    m.signature_b64 = String::new();
    let p = write_manifest(&art.dir, "unsigned", &m);
    assert_eq!(
        verify(&p, &art.data).expect_err("unsigned"),
        NativeBackupError::Unsigned
    );

    // Re-signed with a key embedded in the artifact (signer field names it).
    let embedded = SigningKey::from_bytes(&EMBEDDED_SEED);
    let p = write_signed(&art.dir, "embedded", &art.body, &embedded);
    let parsed: SignedPgManifest =
        serde_json::from_slice(&std::fs::read(&p).expect("read")).expect("json");
    assert_eq!(
        parsed.signer,
        hex::encode(embedded.verifying_key().to_bytes())
    );
    assert_eq!(
        verify(&p, &art.data).expect_err("embedded key"),
        NativeBackupError::BadSignature
    );

    // Payload edited after signing (signature from the anchor over the old payload).
    let mut m = nb::sign_pg_manifest(&art.body, &anchor()).expect("sign");
    let mut edited = art.body.clone();
    edited.schema_version += 1;
    m.payload_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&edited).expect("json"));
    let p = write_manifest(&art.dir, "edited", &m);
    assert_eq!(
        verify(&p, &art.data).expect_err("edited payload"),
        NativeBackupError::BadSignature
    );

    // Unknown layout version (correctly signed).
    let mut body = art.body.clone();
    body.layout_version = 2;
    let p = write_signed(&art.dir, "layout", &body, &anchor());
    assert_eq!(
        verify(&p, &art.data).expect_err("layout"),
        NativeBackupError::UnknownLayout { version: 2 }
    );

    // Cross-backend artifact (correctly signed).
    let mut body = art.body.clone();
    body.backend = "sqlite".to_string();
    let p = write_signed(&art.dir, "crossbackend", &body, &anchor());
    assert_eq!(
        verify(&p, &art.data).expect_err("cross backend"),
        NativeBackupError::CrossBackend {
            backend: "sqlite".to_string()
        }
    );

    // A foreign SQLite backup manifest (the existing layout) is not a PostgreSQL manifest.
    let sqlite_manifest = serde_json::json!({
        "snapshot": "ai-memory-20260102T030405Z.db",
        "sha256": "ab".repeat(32),
        "bytes": 4096,
        "source_db": "ai-memory.db",
        "version": "1.0.0",
        "created_at": "2026-01-02T03:04:05Z",
        "backend": "sqlite",
    });
    let raw = serde_json::to_vec(&sqlite_manifest).expect("json");
    let p = art.dir.join("foreign.json");
    std::fs::write(&p, &raw).expect("write foreign");
    let expected_detail = serde_json::from_slice::<SignedPgManifest>(&raw)
        .expect_err("serde refuses")
        .to_string();
    assert_eq!(
        verify(&p, &art.data).expect_err("foreign"),
        NativeBackupError::ManifestMalformed {
            detail: expected_detail
        }
    );

    // Over the manifest cap.
    let big = art.dir.join("big.json");
    let f = std::fs::File::create(&big).expect("big");
    f.set_len(nb::PG_BACKUP_MAX_MANIFEST_BYTES + 1)
        .expect("set_len");
    assert_eq!(
        nb::read_manifest_capped(&big).expect_err("cap"),
        NativeBackupError::ManifestTooLarge {
            len: nb::PG_BACKUP_MAX_MANIFEST_BYTES + 1
        }
    );

    // No verified artifact exists for any of these, so the target is untouched.
    let tgt = fresh("pgnb10021vft").await;
    assert_empty(&tgt.pool, "after verifier refusals").await;
}

/// A correctly signed artifact whose schema version differs from the target is refused
/// inside the restore transaction, before any write.
#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_a_schema_version_mismatch_10021() {
    let src = fresh("pgnb10021svs").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "sv").await;
    let mut body = art.body.clone();
    body.schema_version += 1;
    let m = write_signed(&art.dir, "schema", &body, &anchor());
    let tgt = fresh("pgnb10021svt").await;
    let err = restore(&tgt, &m, &art.data).await.expect_err("must refuse");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::SchemaMismatch {
            artifact: art.body.schema_version + 1,
            target: art.body.schema_version,
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "schema mismatch").await;
}

// ---------------------------------------------------------------------------------------
// C-2: "empty" means a freshly migrated store with its seeded rows
// ---------------------------------------------------------------------------------------

/// A freshly migrated store (with only its seeded `schema_version` and AGE catalog rows) is
/// empty and accepts a restore; one row in ANY dumped table makes it non-empty and the
/// restore is refused with the exact error naming that table, writing nothing.
/// Mutant: drop the non-empty refusal.
#[tokio::test(flavor = "multi_thread")]
async fn non_empty_target_is_refused_for_every_table_10021() {
    let src = fresh("pgnb10021nes").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "ne").await;

    let tgt = fresh("pgnb10021net").await;
    assert_empty(&tgt.pool, "fresh store").await;
    let ledger = count_rows(&tgt.pool, "public.schema_version").await;
    assert!(ledger > 0, "a fresh store carries its migration ledger");
    assert_eq!(count_rows(&tgt.pool, "ag_catalog.ag_graph").await, 1);
    assert_eq!(count_rows(&tgt.pool, "ag_catalog.ag_label").await, 2);

    for (table, rows) in corpus::CORPUS {
        {
            let mut tx = tgt.pool.begin().await.expect("tx");
            sqlx::query("SET LOCAL session_replication_role = replica")
                .execute(&mut *tx)
                .await
                .expect("replica");
            insert_rows(&mut tx, table, &rows[..1]).await;
            tx.commit().await.expect("commit");
        }
        let err = restore(&tgt, &art.manifest, &art.data)
            .await
            .expect_err("a non-empty target must be refused");
        assert_eq!(
            integrity_detail(err),
            NativeBackupError::TargetNotEmpty {
                table: format!("public.{table}")
            }
            .to_string(),
            "#10021 one row in public.{table}"
        );
        let mut tx = tgt.pool.begin().await.expect("tx");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("replica");
        sqlx::query(&format!("DELETE FROM public.{table}"))
            .execute(&mut *tx)
            .await
            .expect("delete");
        tx.commit().await.expect("commit");
        assert_eq!(count_rows(&tgt.pool, &format!("public.{table}")).await, 0);
    }
    assert_empty(&tgt.pool, "after every refusal").await;

    // #10045: the AGE graph schema is not dumped, so one vertex under any label of
    // memory_graph makes the target non-empty too (mutant: drop check_age_graph_empty).
    {
        let mut tx = tgt.pool.begin().await.expect("tx");
        sqlx::query("LOAD 'age'")
            .execute(&mut *tx)
            .await
            .expect("load age");
        sqlx::query("SET LOCAL search_path = ag_catalog, \"$user\", public")
            .execute(&mut *tx)
            .await
            .expect("search_path");
        sqlx::query(
            "SELECT * FROM cypher('memory_graph', $$ CREATE (:probe_10045 {id: 'x'}) $$) \
             AS (v agtype)",
        )
        .execute(&mut *tx)
        .await
        .expect("probe vertex");
        tx.commit().await.expect("commit");
    }
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("a non-empty graph must be refused");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::TargetNotEmpty {
            table: "memory_graph.probe_10045".to_string()
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "after the graph refusal").await;
    sqlx::query("DELETE FROM memory_graph.probe_10045")
        .execute(&tgt.pool)
        .await
        .expect("delete probe vertex");

    // The freshly migrated store (seeded rows only) accepts the restore ...
    restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("fresh store accepts");
    // ... and a second restore into it is refused, naming the first table of the order.
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("restored store is not empty");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::TargetNotEmpty {
            table: FIRST_RESTORE_TABLE.to_string()
        }
        .to_string()
    );
    assert_tables_equal(&src.pool, &tgt.pool, &[]).await;
}

// ---------------------------------------------------------------------------------------
// C-1: one transaction each side
// ---------------------------------------------------------------------------------------

/// An injected mid-restore failure (the last table's recorded row count is one more than the
/// data holds, correctly signed) rolls the whole restore back: the target stays empty and a
/// retry with the good artifact succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn mid_restore_failure_leaves_target_empty_and_retryable_10021() {
    let src = fresh("pgnb10021mrs").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "mr").await;
    let mut body = art.body.clone();
    let last = body.tables.last_mut().expect("tables");
    let (table, rows) = (last.qualified(), last.rows);
    last.rows += 1;
    let m = write_signed(&art.dir, "rows", &body, &anchor());

    let tgt = fresh("pgnb10021mrt").await;
    let err = restore(&tgt, &m, &art.data)
        .await
        .expect_err("injected failure");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::RowCountMismatch {
            table,
            expected: rows + 1,
            actual: rows,
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "mid-restore failure").await;

    restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("retry succeeds");
    assert_eq!(assert_tables_equal(&src.pool, &tgt.pool, &[]).await, 45);
}

/// A dump taken while writers commit linked rows is one snapshot: it restores (FKs hold)
/// and every link's memory is present.
#[tokio::test(flavor = "multi_thread")]
async fn dump_beside_concurrent_writers_restores_consistent_10021() {
    let src = fresh("pgnb10021cws").await;
    seed_corpus(&src.pool).await;
    let stop = Arc::new(AtomicBool::new(false));
    let written = Arc::new(AtomicU64::new(0));
    let writer = {
        let (pool, stop, written) = (src.pool.clone(), stop.clone(), written.clone());
        tokio::spawn(async move {
            let mut i = 0u64;
            while !stop.load(Ordering::Acquire) {
                let id = format!("cw-{i}");
                let mut tx = pool.begin().await.expect("writer tx");
                sqlx::query(
                    "INSERT INTO public.memories (id, tier, namespace, title, content, source) \
                     VALUES ($1, 'short', 'ns-cw-10021', $1, 'cw', 'test')",
                )
                .bind(&id)
                .execute(&mut *tx)
                .await
                .expect("writer memory");
                sqlx::query(
                    "INSERT INTO public.memory_links (source_id, target_id) VALUES ($1, 'm1-10021')",
                )
                .bind(&id)
                .execute(&mut *tx)
                .await
                .expect("writer link");
                tx.commit().await.expect("writer commit");
                i += 1;
                written.store(i, Ordering::Release);
            }
        })
    };
    while written.load(Ordering::Acquire) < 5 {
        assert!(
            !writer.is_finished(),
            "#10021 the writer stopped before 5 commits"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let art = dump(&src, "cw").await;
    stop.store(true, Ordering::Release);
    writer.await.expect("writer joined");

    let tgt = fresh("pgnb10021cwt").await;
    restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("a snapshot dump restores with every FK satisfied");
    let mems: i64 =
        sqlx::query_scalar("SELECT count(1) FROM public.memories WHERE namespace = 'ns-cw-10021'")
            .fetch_one(&tgt.pool)
            .await
            .expect("mems");
    let links: i64 =
        sqlx::query_scalar("SELECT count(1) FROM public.memory_links WHERE source_id LIKE 'cw-%'")
            .fetch_one(&tgt.pool)
            .await
            .expect("links");
    let orphans: i64 = sqlx::query_scalar(
        "SELECT count(1) FROM public.memory_links l WHERE NOT EXISTS \
         (SELECT 1 FROM public.memories m WHERE m.id = l.source_id) OR NOT EXISTS \
         (SELECT 1 FROM public.memories m WHERE m.id = l.target_id)",
    )
    .fetch_one(&tgt.pool)
    .await
    .expect("orphans");
    assert!(mems >= 5, "the dump saw the committed writers ({mems})");
    assert_eq!(
        mems, links,
        "#10021 every snapshot memory has its link and vice versa"
    );
    assert_eq!(orphans, 0, "#10021 no link without its memory");
    let seg = segment(&art.body, "public.memories");
    assert_eq!(seg.rows, u64::try_from(mems + 2).expect("rows"));
}

// ---------------------------------------------------------------------------------------
// C-7: restored state has no side effect and every chain still verifies
// ---------------------------------------------------------------------------------------

/// After restore: triggers did not alter restored rows, a stored link signature still
/// verifies, the `audit_log` / `attested_write_ledger` chains are byte-identical, delivered
/// outbox / DLQ rows stay delivered, and no restored lease is live.
#[tokio::test(flavor = "multi_thread")]
async fn restored_state_has_no_side_effect_and_signatures_verify_10021() {
    let _keys = key_dir_sandbox::pin();
    let src = fresh("pgnb10021c7s").await;
    seed_corpus(&src.pool).await;
    let kp = keypair::generate(AGENT).expect("keypair");
    keypair::save(&kp, key_dir_sandbox::pin()).expect("save keypair");
    let ctx = CallerContext::for_agent(AGENT);
    let link = MemoryLink {
        source_id: "m2-10021".to_string(),
        target_id: "m1-10021".to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: "2026-01-02T03:04:05Z".to_string(),
        signature: None,
        observed_by: Some(AGENT.to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    src.store
        .link_signed(&ctx, &link, Some(&kp))
        .await
        .expect("signed link");
    let filter = VerifyFilter {
        source_id: Some("m2-10021".to_string()),
        target_id: Some("m1-10021".to_string()),
        link_id: None,
    };
    assert!(
        src.store
            .verify_link(filter.clone())
            .await
            .expect("verify src")
            .verified
    );

    // One live lease on the source.
    let live_until = now_epoch(&src.pool).await + 86_400;
    sqlx::query("UPDATE public.leases SET expires_at = $1")
        .bind(live_until)
        .execute(&src.pool)
        .await
        .expect("live lease");

    let art = dump(&src, "c7").await;
    let tgt = fresh("pgnb10021c7t").await;
    let before = now_epoch(&tgt.pool).await;
    let report = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("restore");
    let after = now_epoch(&tgt.pool).await;
    assert_eq!(report.leases_clamped, 1, "#10021 the live lease is clamped");
    assert_eq!(report.age_edges_projected, 2);

    // The stored signature verifies on the restored store.
    let v = tgt.store.verify_link(filter).await.expect("verify tgt");
    assert!(v.verified, "#10021 restored signed link must verify");

    // Triggers did not rewrite the restored _agents row.
    for col in ["content", "metadata", "title", "namespace"] {
        let q = format!("SELECT {col}::text FROM public.memories WHERE id = 'm2-10021'");
        let a: String = sqlx::query_scalar(&q)
            .fetch_one(&src.pool)
            .await
            .expect("src");
        let b: String = sqlx::query_scalar(&q)
            .fetch_one(&tgt.pool)
            .await
            .expect("tgt");
        assert_eq!(
            a, b,
            "#10021 memories.{col} of m2-10021 changed by a trigger"
        );
    }
    let m2 = corpus_rows("memories")[1];
    for (col, _, expected) in m2 {
        let got: String = sqlx::query_scalar(&format!(
            "SELECT {col}::text FROM public.memories WHERE id = 'm2-10021'"
        ))
        .fetch_one(&tgt.pool)
        .await
        .expect("m2 cell");
        assert_eq!(&got, expected, "#10021 memories.{col} of m2-10021");
    }

    // Chains and every other table are byte-identical; leases differ only by the clamp.
    assert_eq!(
        assert_tables_equal(&src.pool, &tgt.pool, &["leases"]).await,
        44
    );
    for t in ["audit_log", "attested_write_ledger", "memory_links"] {
        let q = format!("public.{t}");
        assert_eq!(
            table_digest(&src.pool, &q).await,
            table_digest(&tgt.pool, &q).await
        );
    }

    // Delivered outbox / DLQ rows stay delivered (no redelivery).
    let probes = [
        (
            "SELECT projected_at::text FROM public.kg_projection_outbox WHERE id = 1",
            "2026-02-03 04:05:06.654321+00",
        ),
        (
            "SELECT delivery_status FROM public.subscription_events WHERE id = 1",
            "delivered",
        ),
        (
            "SELECT replayed_at::text FROM public.federation_push_dlq WHERE id = 1",
            "2026-02-03 04:05:06.654321+00",
        ),
    ];
    for (q, want) in probes {
        let got: String = sqlx::query_scalar(q)
            .fetch_one(&tgt.pool)
            .await
            .expect("probe");
        assert_eq!(got, want, "#10021 {q}");
    }

    // No live stale lease: the restored lease expires no later than the restore.
    let (holder, acquired, expires, heartbeat): (String, i64, i64, i64) = sqlx::query_as(
        "SELECT holder, acquired_at, expires_at, heartbeat_at FROM public.leases \
         WHERE action_id = 'act-10021'",
    )
    .fetch_one(&tgt.pool)
    .await
    .expect("lease");
    assert_eq!(
        (holder.as_str(), acquired, heartbeat),
        ("ai:pgnb-worker", 1_700_000_000, 1_700_000_100)
    );
    assert!(
        expires >= before && expires <= after,
        "#10021 lease expires_at {expires} must be clamped into [{before}, {after}]"
    );
    let live: i64 = sqlx::query_scalar("SELECT count(1) FROM public.leases WHERE expires_at > $1")
        .bind(after)
        .fetch_one(&tgt.pool)
        .await
        .expect("live");
    assert_eq!(live, 0, "#10021 no live lease after restore");
}

// ---------------------------------------------------------------------------------------
// C-8: artifact protection
// ---------------------------------------------------------------------------------------

/// Both artifact files are mode 0600; neither holds a private signing key nor a plaintext
/// API key (the bound key's SHA-256 hash, which the table holds, is present).
#[tokio::test(flavor = "multi_thread")]
async fn artifact_is_0600_and_holds_no_secret_10021() {
    let _keys = key_dir_sandbox::pin();
    let src = fresh("pgnb10021c8s").await;
    seed_corpus(&src.pool).await;
    let kp = keypair::generate("ai:pgnb-c8").expect("keypair");
    keypair::save(&kp, key_dir_sandbox::pin()).expect("save");
    let token_hash = sha256_hex(API_KEY_CANARY.as_bytes());
    let ctx = CallerContext::for_agent(AGENT);
    let bound = src
        .store
        .bind_agent_api_key(&ctx, "ai:pgnb-c8", &token_hash)
        .await
        .expect("bind api key");
    assert_eq!(bound, ai_memory::storage::BindApiKeyOutcome::Bound);
    let art = dump(&src, "c8").await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for p in [&art.data, &art.manifest] {
            let mode = std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "#10021 {} must be 0600", p.display());
        }
    }

    let data = std::fs::read(&art.data).expect("data");
    let manifest = std::fs::read(&art.manifest).expect("manifest");
    let agent_secret = kp.private.as_ref().expect("private key").to_bytes();
    let anchor_secret = anchor().to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut needles: Vec<Vec<u8>> = vec![API_KEY_CANARY.as_bytes().to_vec()];
    for secret in [agent_secret, anchor_secret] {
        needles.push(secret.to_vec());
        needles.push(hex::encode(secret).into_bytes());
        needles.push(b64.encode(secret).into_bytes());
        needles.push(b64url.encode(secret).into_bytes());
    }
    for (file, hay) in [("data", &data), ("manifest", &manifest)] {
        for (idx, n) in needles.iter().enumerate() {
            let hit = hay.windows(n.len()).position(|w| w == n.as_slice());
            let table = hit.and_then(|at| {
                let at = u64::try_from(at).ok()?;
                art.body
                    .tables
                    .iter()
                    .find(|t| at >= t.offset && at < t.offset + t.len)
                    .map(|t| format!("{}.{}", t.schema, t.name))
            });
            assert!(
                hit.is_none(),
                "#10021 the {file} file holds secret form #{idx} (segment {table:?})"
            );
        }
    }
    assert!(
        data.windows(token_hash.len())
            .any(|w| w == token_hash.as_bytes()),
        "the bound key hash (table content) is in the artifact"
    );
}

// ---------------------------------------------------------------------------------------
// #10048, #10047, #10046, #10049: refusals before user code runs, paging, AGE equality
// ---------------------------------------------------------------------------------------

/// A dumped table with a trigger that replica mode leaves on (`ENABLE ALWAYS`) or with a
/// rewrite rule refuses the restore with the exact error naming it, writing nothing; once
/// it is gone the restore succeeds (#10048). Mutant: drop `check_no_active_triggers_or_rules`.
#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_an_always_trigger_or_a_rule_10048() {
    let src = fresh("pgnb10048trs").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "tr").await;
    let tgt = fresh("pgnb10048trt").await;

    for sql in [
        "CREATE FUNCTION public.t_10048_fn() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RETURN NEW; END $$",
        "CREATE TRIGGER t_10048 BEFORE INSERT ON public.memories \
         FOR EACH ROW EXECUTE FUNCTION public.t_10048_fn()",
        "ALTER TABLE public.memories ENABLE ALWAYS TRIGGER t_10048",
    ] {
        sqlx::query(sql).execute(&tgt.pool).await.expect("trigger");
    }
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("an ALWAYS trigger must be refused");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::ActiveTriggerOrRule {
            table: "public.memories".to_string(),
            kind: "trigger".to_string(),
            name: "t_10048".to_string(),
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "always trigger").await;
    sqlx::query("DROP TRIGGER t_10048 ON public.memories")
        .execute(&tgt.pool)
        .await
        .expect("drop trigger");

    sqlx::query("CREATE RULE r_10048 AS ON INSERT TO public.memory_links DO ALSO NOTHING")
        .execute(&tgt.pool)
        .await
        .expect("rule");
    let err = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect_err("a rule must be refused");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::ActiveTriggerOrRule {
            table: "public.memory_links".to_string(),
            kind: "rule".to_string(),
            name: "r_10048".to_string(),
        }
        .to_string()
    );
    assert_empty(&tgt.pool, "rule").await;
    sqlx::query("DROP RULE r_10048 ON public.memory_links")
        .execute(&tgt.pool)
        .await
        .expect("drop rule");

    restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("restore succeeds once the trigger and rule are gone");
    assert_tables_equal(&src.pool, &tgt.pool, &[]).await;
}

/// A restoring role that holds every table privilege but may not SET
/// `session_replication_role` gets the exact `InsufficientPrivilege` refusal, nothing written
/// (#10047). Mutant: map the SET failure through the generic error path.
#[tokio::test(flavor = "multi_thread")]
async fn restore_as_a_non_superuser_is_refused_exactly_10047() {
    let src = fresh("pgnb10047lps").await;
    seed_corpus(&src.pool).await;
    let art = dump(&src, "lp").await;
    let tgt = fresh("pgnb10047lpt").await;
    let role = format!("restore_lowpriv_10047_{}", std::process::id());
    // The managed-PostgreSQL shape: the restoring role inherits the privileges of the
    // role that owns every object (the store's connect-time bootstrap re-runs owner
    // DDL), but holds no SUPERUSER attribute of its own.
    let owner: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&tgt.pool)
        .await
        .expect("owner");
    for sql in [
        format!("CREATE ROLE {role} NOLOGIN NOSUPERUSER"),
        format!("GRANT \"{owner}\" TO {role}"),
    ] {
        sqlx::query(&sql)
            .execute(&tgt.pool)
            .await
            .expect("role setup");
    }
    let base = tgt.scratch.url();
    let sep = if base.contains('?') { '&' } else { '?' };
    let low_url = format!("{base}{sep}options=-c%20role%3D{role}");

    let outcome = match PostgresStore::connect(&low_url).await {
        Ok(low) => {
            let verified = verify(&art.manifest, &art.data).expect("verifies");
            let r = low.native_restore(verified).await;
            drop(low);
            Ok(r)
        }
        Err(e) => Err(format!("{e:?}")),
    };
    for sql in [format!("DROP OWNED BY {role}"), format!("DROP ROLE {role}")] {
        sqlx::query(&sql)
            .execute(&tgt.pool)
            .await
            .expect("role cleanup");
    }
    let err = outcome
        .expect("the low-privilege role connects")
        .expect_err("a non-superuser restore must be refused");
    assert_eq!(
        integrity_detail(err),
        NativeBackupError::InsufficientPrivilege.to_string()
    );
    assert_empty(&tgt.pool, "non-superuser").await;
}

/// More links than one keyset page (2001 = two full pages and one row) are all re-projected
/// into AGE (#10046). Mutant: stop after the first page.
#[tokio::test(flavor = "multi_thread")]
async fn restore_projects_every_link_across_pages_10046() {
    const EXTRA: i64 = 2000;
    let src = fresh("pgnb10046pgs").await;
    seed_corpus(&src.pool).await;
    {
        let cols: String = sqlx::query_scalar(
            "SELECT string_agg(column_name::text, ', ' ORDER BY ordinal_position) \
             FROM information_schema.columns WHERE table_schema = 'public' \
             AND table_name = 'memory_links' AND is_generated = 'NEVER' \
             AND column_name <> 'source_id'",
        )
        .fetch_one(&src.pool)
        .await
        .expect("link columns");
        let mut tx = src.pool.begin().await.expect("tx");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("replica");
        sqlx::query(&format!(
            "INSERT INTO public.memory_links (source_id, {cols}) \
             SELECT 'pg10046-' || lpad(g::text, 5, '0'), {cols} \
             FROM public.memory_links CROSS JOIN generate_series(1, $1::int8) g"
        ))
        .bind(EXTRA)
        .execute(&mut *tx)
        .await
        .expect("many links");
        tx.commit().await.expect("commit");
    }
    let links = count_rows(&src.pool, "public.memory_links").await;
    assert_eq!(links, EXTRA + 1);
    let art = dump(&src, "pg").await;
    let tgt = fresh("pgnb10046pgt").await;
    let report = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("restore");
    assert_eq!(
        report.age_edges_projected,
        u64::try_from(links).expect("links")
    );
    let edges: i64 = sqlx::query_scalar("SELECT count(1) FROM memory_graph._ag_label_edge")
        .fetch_one(&tgt.pool)
        .await
        .expect("edge count");
    assert_eq!(
        edges, links,
        "#10046 every link is an AGE edge on the target"
    );
}

/// Every AGE edge as `(label, start vertex props, end vertex props, edge props)`, all text.
async fn age_edge_set(pool: &PgPool) -> BTreeSet<(String, String, String, String)> {
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("LOAD 'age'")
        .execute(&mut *tx)
        .await
        .expect("load age");
    sqlx::query("SET LOCAL search_path = ag_catalog, \"$user\", public")
        .execute(&mut *tx)
        .await
        .expect("search_path");
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT e.tableoid::regclass::text, s.properties::text, t.properties::text, \
                e.properties::text \
         FROM memory_graph._ag_label_edge e \
         JOIN memory_graph._ag_label_vertex s ON s.id = e.start_id \
         JOIN memory_graph._ag_label_vertex t ON t.id = e.end_id",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("age edges");
    tx.rollback().await.expect("rollback");
    rows.into_iter().collect()
}

/// Links written through the store API (plain, bounded by `valid_from` / `valid_until`, and
/// kg-invalidated) restore into an AGE edge set equal to the source's in every endpoint,
/// label and property (#10049). Mutant: re-project with no validity stamps.
#[tokio::test(flavor = "multi_thread")]
async fn restored_age_edges_equal_the_source_10049() {
    let _keys = key_dir_sandbox::pin();
    let src = fresh("pgnb10049ags").await;
    seed_corpus(&src.pool).await;
    // The corpus link is raw SQL with no AGE edge; drop it so every source link is one
    // the live writers projected.
    {
        let mut tx = src.pool.begin().await.expect("tx");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("replica");
        sqlx::query("DELETE FROM public.memory_links")
            .execute(&mut *tx)
            .await
            .expect("drop corpus link");
        tx.commit().await.expect("commit");
    }
    let kp = keypair::generate(AGENT).expect("keypair");
    keypair::save(&kp, key_dir_sandbox::pin()).expect("save keypair");
    let ctx = CallerContext::for_agent(AGENT);
    let mk = |s: &str, t: &str, rel, vf: Option<&str>, vu: Option<&str>| MemoryLink {
        source_id: s.to_string(),
        target_id: t.to_string(),
        relation: rel,
        created_at: "2026-01-02T03:04:05Z".to_string(),
        signature: None,
        observed_by: Some(AGENT.to_string()),
        valid_from: vf.map(str::to_string),
        valid_until: vu.map(str::to_string),
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    let links = [
        mk(
            "m1-10021",
            "m2-10021",
            MemoryLinkRelation::RelatedTo,
            None,
            None,
        ),
        mk(
            "m2-10021",
            "m1-10021",
            MemoryLinkRelation::Supersedes,
            Some("2026-02-03T04:05:06.123456Z"),
            Some("2027-02-03T04:05:06Z"),
        ),
        mk(
            "m1-10021",
            "m2-10021",
            MemoryLinkRelation::Contradicts,
            None,
            None,
        ),
    ];
    for l in &links {
        src.store
            .link_signed(&ctx, l, Some(&kp))
            .await
            .expect("link");
    }
    src.store
        .invalidate_link(
            "m1-10021",
            "m2-10021",
            "contradicts",
            Some("2026-06-07T08:09:10Z"),
            Some(AGENT),
        )
        .await
        .expect("kg_invalidate");

    let want = age_edge_set(&src.pool).await;
    assert_eq!(
        want.len(),
        3,
        "#10049 the source graph holds the three links"
    );
    let art = dump(&src, "ag").await;
    let tgt = fresh("pgnb10049agt").await;
    let report = restore(&tgt, &art.manifest, &art.data)
        .await
        .expect("restore");
    assert_eq!(report.age_edges_projected, 3);
    let got = age_edge_set(&tgt.pool).await;
    assert_eq!(
        got, want,
        "#10049 restored AGE edges must equal the source's"
    );
}
