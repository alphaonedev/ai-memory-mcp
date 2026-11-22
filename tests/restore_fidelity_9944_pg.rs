// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #9944 — the PostgreSQL half of the restore-fidelity matrix (GA
//! standard 4, proven restore).
//!
//! The SQLite cells live in `tests/restore_fidelity_9944.rs`; both use the one
//! shared comparison in `tests/common/restore_snapshot.rs`. A PostgreSQL store
//! has no CLI backup/restore or `export --full`: its restore paths are the
//! admin export/import (`GET /api/v1/export` walks `export_memories_page` +
//! `export_links_page`; `POST /api/v1/import` lands each row through
//! `MemoryStore::store` and each edge through `MemoryStore::link`) and the
//! archive (`archive_by_ids` then `archive_restore`). These cells drive those
//! trait calls on two scratch databases and compare EVERY table and EVERY
//! column of every non-system schema (`public` and the AGE graph schema)
//! under a per-path classification, plus the ratchet that keeps the
//! classification in step with the live schema.
//!
//! Each cell mints its own scratch databases (`common::pg_barrier::ScratchDb`,
//! dropped on unwind) and creates `age` before `vector` in each (#9930). The
//! admin URL comes from `common::pg_isolate::isolated_url()`; with
//! `AI_MEMORY_TEST_PG_ISOLATE=1` a missing URL is a failure, never a skip.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeMap, HashSet};

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::Row as _;

mod common;
use common::pg_barrier;

#[path = "common/restore_snapshot.rs"]
mod restore_snapshot;

use restore_snapshot::{
    Carry, Classification, Row, SqlValue, StoreSnapshot, TableSnapshot, assert_restored,
};

// ── corpus constants (the same corpus as the SQLite cells) ─────────────────

/// The embedding dimension of the production embedder the issue names.
const EMBEDDING_DIM: usize = 768;
/// The same dimension as the schema bootstrap takes it.
const EMBEDDING_DIM_U32: u32 = 768;
/// The embedding space every corpus vector is stamped with.
const EMBEDDING_SPACE: &str = "fidelity-9944/model#768";
const NAMESPACE_A: &str = "fidelity-9944-alpha";
const NAMESPACE_B: &str = "fidelity-9944-beta/child";
/// The owner of every corpus row.
const CORPUS_AGENT: &str = "ai:fidelity-9944";
const UNICODE_TITLE: &str = "réstore — 復元 — استعادة — 🧠🔁";
const UNICODE_CONTENT: &str = "e\u{301} ﬁ ß 𝔘 \u{200d} 👩‍💻 — byte-exact or bust";
const EMPTY_TAGS_TITLE: &str = "empty-fields row";
/// The shortest content the validator accepts.
const MINIMAL_CONTENT: &str = "·";
const ARCHIVE_REASON: &str = "fidelity-9944";
/// Fixed future stamps, so a restamp by the restore is always visible.
const CREATED_AT: &str = "2031-04-01T10:00:00.000000+00:00";
const UPDATED_AT: &str = "2031-04-02T11:30:00.123456+00:00";
/// Scratch database prefix (`<prefix>_<unix>_<hex>`, swept by age).
const SCRATCH_PREFIX: &str = "fid9944";
/// Rows per export page: smaller than the corpus, so the walk pages.
const EXPORT_PAGE_LIMIT: usize = 2;
/// The upper bound on export pages; a walk that needs more is a defect.
const EXPORT_PAGE_CAP: usize = 64;
/// Extensions every scratch database creates, `age` first (#9930).
const EXTENSIONS: &[&str] = &["age", "vector"];
/// Schemas that hold no store data.
const SYSTEM_SCHEMAS: &[&str] = &["pg_catalog", "information_schema", "ag_catalog"];
/// The env flag under which a missing URL is a failure.
const ISOLATE_FLAG: &str = "AI_MEMORY_TEST_PG_ISOLATE";

/// One live corpus row: `(title, namespace, tier, content, tags, with_embedding)`.
type CorpusRow = (
    &'static str,
    &'static str,
    Tier,
    &'static str,
    &'static [&'static str],
    bool,
);

/// `(title, namespace, tier, content, tags, with_embedding)`.
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
const ARCHIVED_ROW: (&str, &str, Tier, &str) = (
    "archived row",
    NAMESPACE_A,
    Tier::Long,
    "archived content ✓",
);
/// The embedding seed of the archived row.
const ARCHIVED_SEED: usize = 99;

// ── classification of the admin export → import path ───────────────────────

const NOT_EXPORT_CLASS: &str = "the admin export carries memories and links only";
/// The AGE graph (`memory_graph.*`) is a regenerable projection of
/// `memory_links`: the destination's `link()` funnel re-projects every edge
/// with graph ids of its own sequence, so the source's ids are not carried.
const GRAPH_PROJECTION: &str = "the AGE graph is re-projected from memory_links by the destination link() with its own graph ids";
const ARCHIVE_NOT_EXPORTED: &str =
    "the admin export walks live memories; the archive is node-local";
const VECTOR_NOT_EXPORTED: &str =
    "memory vectors are regenerable artifacts the destination re-embeds from the text";
/// The admin import lands every edge through the unsigned `link()` funnel
/// (`src/handlers/admin.rs` postgres branch), so the signed spine is not carried.
const CONVENIENCE_LINK_UNSIGNED: &str =
    "the admin import re-creates each edge through link(), which carries no signature";
/// `link()` derives `attest_level` from the signature it does not carry.
const CONVENIENCE_LINK_ATTEST: &str =
    "link() stamps attest_level as unsigned on every imported edge";

static EXPORT_IMPORT: Classification = Classification {
    path: "postgres admin export/import",
    tables: &[
        ("memories", Carry::Exact),
        ("memory_links", Carry::Exact),
        ("a2a_task_memories", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("a2a_tasks", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("action_edges", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("actions", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("agent_api_keys", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("agent_lineage", Carry::NotCarried(NOT_EXPORT_CLASS)),
        (
            "agent_pubkey_challenges",
            Carry::NotCarried(NOT_EXPORT_CLASS),
        ),
        ("agent_pubkey_history", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("agent_quotas", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("agent_subkey_certs", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("archived_memories", Carry::NotCarried(ARCHIVE_NOT_EXPORTED)),
        (
            "archived_memory_links",
            Carry::NotCarried(ARCHIVE_NOT_EXPORTED),
        ),
        ("attested_write_ledger", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("audit_log", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("checkpoints", Carry::NotCarried(NOT_EXPORT_CLASS)),
        (
            "confidence_shadow_observations",
            Carry::NotCarried(NOT_EXPORT_CLASS),
        ),
        ("embed_skip", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("entity_aliases", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("federation_push_dlq", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("forget_tombstones", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("kg_projection_outbox", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("leases", Carry::NotCarried(NOT_EXPORT_CLASS)),
        (
            "lineage_integrity_watermark",
            Carry::NotCarried(NOT_EXPORT_CLASS),
        ),
        ("memory_graph.Memory", Carry::NotCarried(GRAPH_PROJECTION)),
        (
            "memory_graph._ag_label_edge",
            Carry::NotCarried(GRAPH_PROJECTION),
        ),
        (
            "memory_graph._ag_label_vertex",
            Carry::NotCarried(GRAPH_PROJECTION),
        ),
        (
            "memory_graph.related_to",
            Carry::NotCarried(GRAPH_PROJECTION),
        ),
        ("memory_revisions", Carry::NotCarried(NOT_EXPORT_CLASS)),
        (
            "memory_transcript_links",
            Carry::NotCarried(NOT_EXPORT_CLASS),
        ),
        ("memory_transcripts", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("model_attestations", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("namespace_meta", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("offloaded_blobs", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("pending_actions", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("recall_observations", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("routine_runs", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("routines", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("schema_version", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("signals", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("signed_events", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("signed_events_dlq", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("subscription_dlq", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("subscription_events", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("subscriptions", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("sync_peer_contact", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("sync_state", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("token_cost_counters", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("transcript_line_dedup", Carry::NotCarried(NOT_EXPORT_CLASS)),
    ],
    lossy: &[
        ("memories", "embedding", VECTOR_NOT_EXPORTED),
        ("memories", "embedding_space", VECTOR_NOT_EXPORTED),
        ("memory_links", "signature", CONVENIENCE_LINK_UNSIGNED),
        ("memory_links", "observed_by", CONVENIENCE_LINK_UNSIGNED),
    ],
    rederived: &[("memory_links", "attest_level", CONVENIENCE_LINK_ATTEST)],
};

// ── scratch stores ──────────────────────────────────────────────────────────

/// The admin URL, or `None` to skip (only when isolation is not requested).
fn admin_url() -> Option<String> {
    let url = common::pg_isolate::isolated_url();
    if url.is_none() {
        assert_ne!(
            std::env::var(ISOLATE_FLAG).ok().as_deref(),
            Some("1"),
            "{ISOLATE_FLAG}=1 but no Postgres URL resolved: the PG cell must run, not skip"
        );
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
    }
    url
}

/// A scratch database with `age` then `vector`, and a store on it.
async fn scratch_store(admin: &str) -> (pg_barrier::ScratchDb, PostgresStore) {
    let db = pg_barrier::ScratchDb::create(admin, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db.url())
        .await
        .expect("connect scratch database");
    for ext in EXTENSIONS {
        sqlx::raw_sql(&format!("CREATE EXTENSION IF NOT EXISTS {ext}"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("CREATE EXTENSION {ext}: {e}"));
    }
    pool.close().await;
    let store = PostgresStore::connect_with_dim(&db.url(), EMBEDDING_DIM_U32)
        .await
        .expect("connect store");
    (db, store)
}

fn ctx() -> CallerContext {
    CallerContext::for_agent(CORPUS_AGENT)
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

fn edge(source_id: &str, target_id: &str) -> MemoryLink {
    MemoryLink {
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: CREATED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

struct Corpus {
    live: Vec<String>,
    archived: String,
}

/// Seed the corpus through the trait funnels a postgres daemon writes with.
async fn seed(store: &PostgresStore) -> Corpus {
    let ctx = ctx();
    let mut live = Vec::new();
    for (i, (title, ns, tier, content, tags, with_emb)) in LIVE_ROWS.iter().enumerate() {
        let mem = corpus_memory(title, ns, tier.clone(), content, tags);
        let id = if *with_emb {
            store
                .store_with_embedding(&ctx, &mem, Some(&embedding(i)), Some(EMBEDDING_SPACE))
                .await
        } else {
            store.store(&ctx, &mem).await
        }
        .expect("store corpus row");
        live.push(id);
    }
    let (t, ns, tier, content) = ARCHIVED_ROW;
    let archived_mem = corpus_memory(t, ns, tier, content, &["archived"]);
    let archived = store
        .store_with_embedding(
            &ctx,
            &archived_mem,
            Some(&embedding(ARCHIVED_SEED)),
            Some(EMBEDDING_SPACE),
        )
        .await
        .expect("store archived row");
    store
        .link(&ctx, &edge(&live[0], &live[1]))
        .await
        .expect("link 0-1");
    let keypair = ai_memory::identity::keypair::generate(CORPUS_AGENT).expect("generate keypair");
    store
        .link_signed(&ctx, &edge(&live[1], &live[3]), Some(&keypair))
        .await
        .expect("signed link 1-3");
    store
        .link(&ctx, &edge(&live[0], &archived))
        .await
        .expect("link to archived");
    store
        .set_namespace_standard(&ctx, NAMESPACE_A, &live[0], None)
        .await
        .expect("namespace standard A");
    store
        .set_namespace_standard(&ctx, NAMESPACE_B, &live[3], Some(NAMESPACE_A))
        .await
        .expect("namespace standard B");
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&archived), Some(ARCHIVE_REASON))
        .await
        .expect("archive");
    assert_eq!(moved, 1, "the archived corpus row must move to the archive");
    Corpus { live, archived }
}

// ── typed full-store snapshot (sqlx) ────────────────────────────────────────

/// One JSON value of `to_jsonb(row)`: text exactly as the server renders it.
fn value_from_json(v: &serde_json::Value) -> SqlValue {
    match v {
        serde_json::Value::Null => SqlValue::Null,
        serde_json::Value::String(s) => SqlValue::Text(s.clone()),
        other => SqlValue::Text(other.to_string()),
    }
}

/// Every base table of every non-system schema, every column. A `public`
/// table keeps its bare name; any other schema's table is `schema.table`.
async fn snapshot(store: &PostgresStore) -> StoreSnapshot {
    let pool = store.pool();
    let current: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(pool)
        .await
        .expect("current_schema");
    let names = sqlx::query(
        "SELECT table_schema::text AS s, table_name::text AS t FROM information_schema.tables \
         WHERE table_type = 'BASE TABLE' AND table_schema <> ALL($1) \
         AND table_schema NOT LIKE 'pg_toast%' AND table_schema NOT LIKE 'pg_temp%' \
         ORDER BY 1, 2",
    )
    .bind(SYSTEM_SCHEMAS)
    .fetch_all(pool)
    .await
    .expect("list tables");
    let mut tables = BTreeMap::new();
    for r in names {
        let (schema, table): (String, String) = (r.get("s"), r.get("t"));
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
        )
        .bind(&schema)
        .bind(&table)
        .fetch_all(pool)
        .await
        .expect("list columns");
        let quoted = format!(
            "{}.{}",
            pg_barrier::quote_ident(&schema),
            pg_barrier::quote_ident(&table)
        );
        let raw: Vec<String> =
            sqlx::query_scalar(&format!("SELECT to_jsonb(t)::text FROM {quoted} t"))
                .fetch_all(pool)
                .await
                .unwrap_or_else(|e| panic!("table {quoted} is unreadable in the snapshot: {e}"));
        let mut rows: Vec<Row> = raw
            .iter()
            .map(|j| {
                let obj: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(j).expect("row json");
                obj.iter()
                    .map(|(k, v)| (k.clone(), value_from_json(v)))
                    .collect()
            })
            .collect();
        rows.sort();
        let key = if schema == current {
            table
        } else {
            format!("{schema}.{table}")
        };
        tables.insert(key, TableSnapshot { columns, rows });
    }
    StoreSnapshot { tables }
}

/// The corpus really holds every field class, so a green compare is never vacuous.
fn assert_corpus_is_rich(s: &StoreSnapshot) {
    for (table, min) in [
        ("memories", LIVE_ROWS.len()),
        ("memory_links", 2),
        ("namespace_meta", 2),
        ("archived_memories", 1),
    ] {
        assert!(
            s.row_count(table) >= min,
            "corpus {table} holds {} rows, want >= {min}",
            s.row_count(table)
        );
    }
}

// ── the export → import path ────────────────────────────────────────────────

/// Walk the admin export exactly as the handler does, then land every row and
/// edge through the import lane's trait calls.
async fn export_import(src: &PostgresStore, dst: &PostgresStore) {
    let as_of = chrono::Utc::now();
    let mut cursor = None;
    let (mut memories, mut links) = (Vec::new(), Vec::new());
    for _ in 0..EXPORT_PAGE_CAP {
        let page = src
            .export_memories_page(cursor.as_ref(), EXPORT_PAGE_LIMIT, as_of, None)
            .await
            .expect("export page");
        assert_eq!(page.undecryptable, 0, "the corpus has no undecryptable row");
        let survivors: HashSet<String> = page.memories.iter().map(|m| m.id.clone()).collect();
        let page_links = src
            .export_links_page(&page.scope, &survivors)
            .await
            .expect("export links page");
        links.extend(page_links.links);
        memories.extend(page.memories);
        cursor.clone_from(&page.next_cursor);
        if cursor.is_none() {
            break;
        }
    }
    assert!(
        cursor.is_none(),
        "the export walk did not finish in {EXPORT_PAGE_CAP} pages"
    );
    let ctx = ctx();
    for mem in &memories {
        dst.store(&ctx, mem).await.expect("import row");
    }
    for link in &links {
        dst.link(&ctx, link).await.expect("import link");
    }
}

/// Red until defect #9949 lands: `store_with_embedding` writes no local
/// `metadata.version_vector`, the import's `store()` does, so every vector
/// row comes back with a clock its source never had. No column entry hides it.
#[tokio::test(flavor = "multi_thread")]
async fn pg_export_then_import_reproduces_memories_and_links_9944() {
    let Some(admin) = admin_url() else { return };
    let (_src_db, src) = scratch_store(&admin).await;
    let (_dst_db, dst) = scratch_store(&admin).await;
    seed(&src).await;
    let before = snapshot(&src).await;
    assert_corpus_is_rich(&before);
    export_import(&src, &dst).await;
    assert_eq!(
        before,
        snapshot(&src).await,
        "the export changed its SOURCE store"
    );
    assert_restored(&EXPORT_IMPORT, &before, &snapshot(&dst).await);
}

// ── the archive → restore path ──────────────────────────────────────────────

/// Columns `archive_restore` rewrites on the restored row, and why.
const ARCHIVE_RESTORE_RESTAMPED: &[&str] = &["updated_at"];

/// The `memories` row and the `memory_links` rows touching `id`.
fn row_image(s: &StoreSnapshot, id: &str) -> (Vec<Row>, Vec<Row>) {
    let want = SqlValue::Text(id.to_string());
    let mem = s.rows_where("memories", "id", id);
    let links = s.tables["memory_links"]
        .rows
        .iter()
        .filter(|r| r.get("source_id") == Some(&want) || r.get("target_id") == Some(&want))
        .cloned()
        .collect();
    (mem, links)
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_archive_then_restore_reproduces_the_row_its_embedding_and_its_links_9944() {
    let Some(admin) = admin_url() else { return };
    let (_db, store) = scratch_store(&admin).await;
    let corpus = seed(&store).await;
    let ctx = ctx();
    assert!(
        store
            .archive_restore(&ctx, &corpus.archived)
            .await
            .expect("restore archived")
    );
    let target = corpus.live[1].clone();
    let before = row_image(&snapshot(&store).await, &target);
    assert_eq!(
        before.0.len(),
        1,
        "the target row is live before the archive"
    );
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&target), Some(ARCHIVE_REASON))
        .await
        .expect("archive target");
    assert_eq!(moved, 1, "target archived");
    assert!(
        row_image(&snapshot(&store).await, &target).0.is_empty(),
        "archived row left memories"
    );
    assert!(
        store
            .archive_restore(&ctx, &target)
            .await
            .expect("restore target")
    );
    let after = row_image(&snapshot(&store).await, &target);
    assert_eq!(after.0.len(), 1, "the restored memories row is missing");
    let differing: Vec<&str> = before.0[0]
        .keys()
        .filter(|c| before.0[0].get(*c) != after.0[0].get(*c))
        .map(String::as_str)
        .collect();
    assert_eq!(
        differing, ARCHIVE_RESTORE_RESTAMPED,
        "the restored row differs from its pre-archive image in {differing:?}\n before {:?}\n after  {:?}",
        before.0[0], after.0[0]
    );
    assert_eq!(
        before.1, after.1,
        "the restored row's links differ from their pre-archive image"
    );
}

// ── the ratchet and the mutation probes ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn pg_every_live_table_is_classified_9944() {
    let Some(admin) = admin_url() else { return };
    let (_db, store) = scratch_store(&admin).await;
    seed(&store).await;
    let problems = EXPORT_IMPORT.ratchet(&snapshot(&store).await);
    assert!(
        problems.is_empty(),
        "classification out of step with the live postgres schema:\n  {}",
        problems.join("\n  ")
    );
}

/// Every classified table as `Exact`: the probe compares a store with a
/// mutated copy of itself, so nothing may be excused.
fn exact_probe_class() -> &'static Classification {
    let tables: Vec<(&'static str, Carry)> = EXPORT_IMPORT
        .tables
        .iter()
        .map(|(t, _)| (*t, Carry::Exact))
        .collect();
    Box::leak(Box::new(Classification {
        path: "postgres mutation probe",
        tables: Box::leak(tables.into_boxed_slice()),
        lossy: &[],
        rederived: &[],
    }))
}

fn rows_mut<'a>(s: &'a mut StoreSnapshot, table: &str) -> &'a mut Vec<Row> {
    &mut s.tables.get_mut(table).expect("table").rows
}

/// The four mutation classes the issue names, applied to a copy of the seeded
/// postgres store: each must turn the comparison red with the exact difference.
#[tokio::test(flavor = "multi_thread")]
async fn pg_the_comparison_catches_every_mutation_class_9944() {
    let Some(admin) = admin_url() else { return };
    let (_db, store) = scratch_store(&admin).await;
    seed(&store).await;
    let src = snapshot(&store).await;
    assert_corpus_is_rich(&src);
    let class = exact_probe_class();
    assert_eq!(
        restore_snapshot::compare(class, &src, &src),
        Vec::<String>::new(),
        "a store compared with itself is exact"
    );
    let mutate = |name: &str, f: &dyn Fn(&mut StoreSnapshot)| {
        let mut m = src.clone();
        f(&mut m);
        let diffs = restore_snapshot::compare(class, &src, &m);
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
    // 3. alter one byte of one embedding (one digit of the server's rendering)
    let diffs = mutate("alter-one-byte", &|s| {
        let row = rows_mut(s, "memories")
            .iter_mut()
            .find(|r| matches!(r.get("embedding"), Some(SqlValue::Text(_))))
            .expect("an embedded row");
        if let Some(SqlValue::Text(t)) = row.get_mut("embedding") {
            let mut bytes = std::mem::take(t).into_bytes();
            let at = bytes.iter().rposition(u8::is_ascii_digit).expect("a digit");
            bytes[at] = if bytes[at] == b'9' {
                b'0'
            } else {
                bytes[at] + 1
            };
            *t = String::from_utf8(bytes).expect("ascii edit keeps utf-8");
        }
    });
    assert_eq!(diffs.len(), 1, "one altered byte: {diffs:?}");
    let report = &diffs[0];
    let n = src.row_count("memories");
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
