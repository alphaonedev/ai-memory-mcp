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
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use sqlx::Row as _;

mod common;
use common::pg_barrier;

#[path = "common/restore_snapshot.rs"]
mod restore_snapshot;

use restore_snapshot::{
    Carry, Classification, ColumnEntry, Expect, MIN_SOURCE_ROWS, Rederived, Row, SchemaBaseline,
    SchemaObject, SqlValue, StoreSnapshot, TableEntry, TableSnapshot, assert_restored,
    source_store,
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

// ── raw column values the trait funnels do not write (#10014, #10015) ──────
// Every value is written out here; none is read from the code under test.

/// The title of the sealed corpus row (#10015).
const SEALED_TITLE: &str = "sealed row";
/// The plaintext the sealed row's envelope opens to.
const SEALED_PLAINTEXT: &str = "sealed plaintext — 封印 ✓";
const LAST_ACCESSED_AT: &str = "2031-04-03T08:15:00.250000+00:00";
/// The claim window in the canonical micros-`Z` rendering every write funnel
/// stores (`validate::canonical_valid_time_opt`).
const CLAIM_VALID_FROM: &str = "2031-01-01T00:00:00.000000Z";
const CLAIM_VALID_UNTIL: &str = "2099-12-31T23:59:59.000000Z";
const LINK_VALID_UNTIL: &str = "2097-02-01T00:00:00.000000+00:00";
/// A `ConfidenceSignals` envelope in its serialised field order.
const CONFIDENCE_SIGNALS: &str = r#"{"source_age_days":12.5,"atom_derivation":false,"prior_corroboration_count":2,"freshness_factor":0.75,"baseline_per_source":0.5}"#;
const CONFIDENCE_DECAYED_AT: &str = "2031-04-04T00:00:00.000000+00:00";
const PERSONA_VERSION: i32 = 4;
const ENTITY_ID: &str = "entity-fidelity-9944";
const SOURCE_URI: &str = "file:///fidelity-9944/source.md";
const SOURCE_SPAN: &str = r#"{"start":0,"end":17}"#;
const KIND_PROVENANCE: &str = "declared";
const ATOMISED_INTO: i32 = 2;
const TARGET_AGENT: &str = "ai:fidelity-9944-peer";

// ── classification of the admin export → import path ───────────────────────

const NOT_EXPORT_CLASS: &str = "by design: the admin export carries memories and links only";
/// The AGE graph (`memory_graph.*`) is a regenerable projection of
/// `memory_links`: the destination's `link()` funnel re-projects every edge
/// with graph ids of its own sequence, so the source's ids are not carried.
const GRAPH_PROJECTION: &str = "by design: the AGE graph is re-projected from memory_links by the destination link() with its own graph ids";
const ARCHIVE_NOT_EXPORTED: &str =
    "by design: the admin export walks live memories; the archive is node-local";
const VECTOR_NOT_EXPORTED: &str =
    "by design: memory vectors are regenerable artifacts the destination re-embeds from the text";
/// The admin import lands every edge through the unsigned `link()` funnel
/// (`src/handlers/admin.rs` postgres branch), so the signed spine is not carried.
const CONVENIENCE_LINK_UNSIGNED: &str =
    "by design: the admin import re-creates each edge through link(), which carries no signature";
/// `link()` derives `attest_level` from the signature it does not carry.
const CONVENIENCE_LINK_ATTEST: &str =
    "by design: link() stamps attest_level as unsigned on every imported edge";
/// The attestation class `link()` writes for an edge it lands unsigned
/// (written out here, never read from the code under test).
const UNSIGNED_ATTEST_LEVEL: &str = "unsigned";
/// The admin export carries the A2A task records on its final page, but the
/// import lands memories and links only, so the tasks are dropped (#10024).
const A2A_NOT_IMPORTED: &str = "the admin import drops the a2a_tasks the export carries (#10024)";

/// The admin export opens a sealed row and the import writes the plaintext
/// back with no envelope (#10033).
const SEALED_ROW_UNSEALED: &str = "the postgres admin export/import writes a sealed row back as plaintext with no envelope (#10033)";
/// The main export cells seed no sealed row (#10033); the dedicated red
/// cell seeds one and stays red until the fix lands.
const MAIN_CELL_SEALED: Sealed = Sealed::Absent;
/// `models::Memory` has no field for the atomisation and entity-mention
/// columns, so the admin page never carries them (#10034). The dedicated red
/// cell `pg_router_export_keeps_every_atomisation_column_10034` checks them.
const ATOM_COLUMNS_DROPPED: &str = "the admin export page has no field for this memories column, so the import lands NULL (#10034)";
/// The admin import re-creates each edge through `link()`, which does not write
/// the carried endpoint cid mirrors (#10035). The dedicated red cell
/// `pg_router_export_keeps_every_link_cid_mirror_10035` checks them.
const LINK_CID_DROPPED: &str =
    "the admin import re-creates each edge through link(), which drops the cid mirrors (#10035)";
/// The declared vector dimension describes the vector the export does not
/// carry, so it goes with it.
const VECTOR_DIM_NOT_EXPORTED: &str = "by design: embedding_dim declares the vector the export does not carry; the destination re-embeds";
/// The atomisation and entity-mention columns the admin pair drops (#10034).
const ATOM_COLUMNS: &[&str] = &["atomised_into", "atom_of", "mentioned_entity_id"];
/// The edge cid mirrors the admin pair drops (#10035).
const LINK_CID_COLUMNS: &[&str] = &["source_cid", "target_cid"];

static EXPORT_IMPORT: Classification = Classification {
    path: "postgres admin export/import",
    tables: &[
        ("memories", Carry::Exact),
        ("memory_links", Carry::Exact),
        ("a2a_task_memories", Carry::NotCarried(NOT_EXPORT_CLASS)),
        ("a2a_tasks", Carry::NotCarried(A2A_NOT_IMPORTED)),
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
        ("memories", "embedding_dim", VECTOR_DIM_NOT_EXPORTED),
        ("memories", "atomised_into", ATOM_COLUMNS_DROPPED),
        ("memories", "atom_of", ATOM_COLUMNS_DROPPED),
        ("memories", "mentioned_entity_id", ATOM_COLUMNS_DROPPED),
        ("memory_links", "signature", CONVENIENCE_LINK_UNSIGNED),
        ("memory_links", "observed_by", CONVENIENCE_LINK_UNSIGNED),
        ("memory_links", "source_cid", LINK_CID_DROPPED),
        ("memory_links", "target_cid", LINK_CID_DROPPED),
    ],
    rederived: &[Rederived {
        table: "memory_links",
        column: "attest_level",
        reason: CONVENIENCE_LINK_ATTEST,
        expect: Expect::Text(UNSIGNED_ATTEST_LEVEL),
    }],
    sparse: &[],
    null_columns: &[("memories", "encrypted_envelope", SEALED_ROW_UNSEALED)],
    schema: SchemaBaseline::Destination,
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
    /// The sealed live row, when the shape seeds one.
    sealed: Option<String>,
}

/// Seed the corpus through the trait funnels a postgres daemon writes with.
async fn seed(store: &PostgresStore, sealed: Sealed) -> Corpus {
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
    set_raw_columns(store, &live).await;
    let sealed = match sealed {
        Sealed::Present => Some(seed_sealed_row(store).await),
        Sealed::Absent => None,
    };
    Corpus {
        live,
        archived,
        sealed,
    }
}

/// Whether the corpus holds a sealed live row (#10015; CBC-02: an enum, not
/// a bool). A path that loses the class seeds `Absent` in its main cell and
/// names the tracked defect; its dedicated red cell seeds `Present`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sealed {
    Present,
    Absent,
}

/// Execute one raw UPDATE on the source and require exactly `want` rows changed.
async fn raw_update(
    pool: &sqlx::PgPool,
    q: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
    what: &str,
    want: u64,
) {
    let done = q
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(done.rows_affected(), want, "{what}: rows changed");
}

/// One live row whose content is sealed (#10015): empty content and the
/// envelope in `encrypted_envelope`, as the at-rest seal funnel leaves it.
async fn seed_sealed_row(store: &PostgresStore) -> String {
    let mem = corpus_memory(SEALED_TITLE, NAMESPACE_A, Tier::Long, "", &["sealed"]);
    let id = store.store(&ctx(), &mem).await.expect("store sealed row");
    let kp = ai_memory::encryption::get_or_create_keypair(CORPUS_AGENT).expect("x25519 keypair");
    let envelope =
        ai_memory::encryption::encrypt(SEALED_PLAINTEXT, &kp.public).expect("seal plaintext");
    raw_update(
        store.pool(),
        sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
            .bind(envelope.to_bytes())
            .bind(&id),
        "sealed envelope",
        1,
    )
    .await;
    id
}

/// Set every optional `memories` / `memory_links` column the trait funnels
/// leave NULL, so no compared column passes vacuously (#10014).
async fn set_raw_columns(store: &PostgresStore, live: &[String]) {
    let pool = store.pool();
    raw_update(
        pool,
        sqlx::query(
            "UPDATE memories SET last_accessed_at = $1::timestamptz, valid_from = $2, \
             valid_until = $3, confidence_signals = $4, confidence_decayed_at = $5, \
             persona_version = $6, entity_id = $7, source_uri = $8, source_span = $9, \
             kind_provenance = $10, atomised_into = $11, embedding_dim = $12, \
             metadata = metadata || jsonb_build_object('target_agent_id', $13::text, \
             'kind_provenance', $10::text) \
             WHERE id = $14",
        )
        .bind(LAST_ACCESSED_AT)
        .bind(CLAIM_VALID_FROM)
        .bind(CLAIM_VALID_UNTIL)
        .bind(CONFIDENCE_SIGNALS)
        .bind(CONFIDENCE_DECAYED_AT)
        .bind(PERSONA_VERSION)
        .bind(ENTITY_ID)
        .bind(SOURCE_URI)
        .bind(SOURCE_SPAN)
        .bind(KIND_PROVENANCE)
        .bind(ATOMISED_INTO)
        .bind(i32::try_from(EMBEDDING_DIM).expect("small"))
        .bind(TARGET_AGENT)
        .bind(&live[0]),
        "memories optional columns",
        1,
    )
    .await;
    raw_update(
        pool,
        sqlx::query(
            "UPDATE memories SET atom_of = $1, mentioned_entity_id = $2, kind_provenance = $3, \
             metadata = metadata || jsonb_build_object('entity_id', $2::text, \
             'kind_provenance', $3::text) WHERE id = $4",
        )
        .bind(&live[0])
        .bind(ENTITY_ID)
        .bind(KIND_PROVENANCE)
        .bind(&live[1]),
        "memories atom columns",
        1,
    )
    .await;
    raw_update(
        pool,
        sqlx::query(
            // The cid mirrors hold each endpoint's `memories.cid`, as the
            // lineage-DAG link funnel writes them (`models::link` source_cid).
            "UPDATE memory_links SET valid_until = $1::timestamptz, \
             source_cid = (SELECT cid FROM memories WHERE id = $2), \
             target_cid = (SELECT cid FROM memories WHERE id = $3) \
             WHERE source_id = $2 AND target_id = $3",
        )
        .bind(LINK_VALID_UNTIL)
        .bind(&live[0])
        .bind(&live[1]),
        "memory_links optional columns",
        1,
    )
    .await;
}

// ── typed full-store snapshot (sqlx) ────────────────────────────────────────

/// One JSON value of `to_jsonb(row)`, typed: NULL, bool, integer, real and
/// text keep their JSON kind; a nested array or object is its JSON text.
fn value_from_json(v: &serde_json::Value) -> SqlValue {
    match v {
        serde_json::Value::Null => SqlValue::Null,
        serde_json::Value::String(s) => SqlValue::text(s),
        serde_json::Value::Bool(b) => SqlValue::Bool(*b),
        // Integer, Real and Text stay distinct (#10019): `1`, `1.0` and `"1"`
        // are three different cells.
        serde_json::Value::Number(n) => n.as_i64().map_or_else(
            || SqlValue::real(n.as_f64().unwrap_or(f64::NAN)),
            SqlValue::Integer,
        ),
        other @ (serde_json::Value::Array(_) | serde_json::Value::Object(_)) => {
            SqlValue::text(&other.to_string())
        }
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
    StoreSnapshot {
        tables,
        schema: schema_objects(pool, &current).await,
    }
}

/// The schema of the current schema (#10017): every column with its type,
/// default and nullability, and every index with its definition.
async fn schema_objects(pool: &sqlx::PgPool, current: &str) -> Vec<SchemaObject> {
    let mut schema = Vec::new();
    let columns = sqlx::query(
        "SELECT table_name::text AS t, column_name::text AS c, data_type::text AS d, \
         coalesce(column_default::text, '') AS f, is_nullable::text AS n \
         FROM information_schema.columns WHERE table_schema = $1",
    )
    .bind(current)
    .fetch_all(pool)
    .await
    .expect("schema columns");
    for r in columns {
        let (table, column): (String, String) = (r.get("t"), r.get("c"));
        let (ty, default, nullable): (String, String, String) =
            (r.get("d"), r.get("f"), r.get("n"));
        schema.push(SchemaObject {
            kind: "column".to_string(),
            name: format!("{table}.{column}"),
            table,
            sql: SqlValue::text(&format!("{ty}|{default}|{nullable}")),
        });
    }
    let indexes = sqlx::query(
        "SELECT tablename::text AS t, indexname::text AS i, indexdef::text AS d \
         FROM pg_indexes WHERE schemaname = $1",
    )
    .bind(current)
    .fetch_all(pool)
    .await
    .expect("schema indexes");
    for r in indexes {
        let (table, name, def): (String, String, String) = (r.get("t"), r.get("i"), r.get("d"));
        schema.push(SchemaObject {
            kind: "index".to_string(),
            name,
            table,
            sql: SqlValue::text(&def),
        });
    }
    schema.sort();
    schema
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

/// The SAL-adapter cell: page through the `PostgresStore` export methods the
/// admin handler calls (`export_memories_page`, `export_links_page`), then
/// land every row and edge through the adapter's `store()` / `link()`. It
/// proves the postgres adapter pair; the shipped handlers themselves are
/// proven by `pg_router_export_then_import_reproduces_memories_and_links_9944`
/// (S3 / C3, #10016), which a handler mutant turns red.
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
    seed(&src, MAIN_CELL_SEALED).await;
    let before = snapshot(&src).await;
    assert_corpus_is_rich(&before);
    let dst_schema = snapshot(&dst).await.schema;
    export_import(&src, &dst).await;
    assert_eq!(
        before,
        snapshot(&src).await,
        "the export changed its SOURCE store"
    );
    assert_restored(
        &EXPORT_IMPORT,
        &source_store(&EXPORT_IMPORT, before),
        &snapshot(&dst).await,
        &dst_schema,
    );
}

// ── the production router over a postgres store (the HTTP export → import) ──

/// The admin the router cells present: the corpus owner, so the import's
/// caller restamp of `metadata.agent_id` is the identity the rows already hold.
const ROUTER_ADMIN: &str = CORPUS_AGENT;
/// The admin's enrolled per-agent key, sent as `X-API-Key` (#8494).
const ROUTER_ADMIN_TOKEN: &str = "fidelity-9944-admin-token-0123456789abcdef";
const EXPORT_ROUTE: &str = "/api/v1/export";
const IMPORT_ROUTE: &str = "/api/v1/import";
/// The largest response body a corpus page may take.
const BODY_LIMIT: usize = 8 * 1024 * 1024;

fn admin_enrolled_registry() -> Arc<ai_memory::handlers::identity_binding::EnrolledAgentKeys> {
    let registry = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
    registry.mutate(|m| {
        *m = std::collections::HashMap::from([(
            ai_memory::handlers::identity_binding::api_key_sha256_hex(ROUTER_ADMIN_TOKEN),
            ROUTER_ADMIN.to_string(),
        )]);
    });
    registry
}

/// The #1570 header-trust posture, so the allowlisted admin header resolves
/// to admin on this keyless router. Set once; it only loosens admin gating.
fn enable_admin_header_trust() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once before any reader, never cleared for the life of
        // the test binary.
        unsafe {
            std::env::set_var(ai_memory::handlers::admin_role::ENV_ADMIN_HEADER_TRUST, "1");
        }
    });
}

/// The production router (`ai_memory::build_router`) over `store` with
/// `storage_backend = Postgres`, so the handler's postgres branch runs.
fn router_for(store: PostgresStore) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(store);
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ROUTER_ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: admin_enrolled_registry(),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(&app_state.enrolled_agent_keys),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("router call");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT)
        .await
        .expect("response body");
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn admin_request(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", ROUTER_ADMIN)
        .header("x-api-key", ROUTER_ADMIN_TOKEN)
}

/// Page through `GET /api/v1/export` on the source router, then post every
/// memory and link to `POST /api/v1/import` on the destination router: the
/// shipped handlers end to end, not a copy of their bodies.
async fn router_export_import(src: &PostgresStore, dst: &PostgresStore) {
    enable_admin_header_trust();
    let (src_router, dst_router) = (router_for(src.clone()), router_for(dst.clone()));
    let first = format!("{EXPORT_ROUTE}?limit={EXPORT_PAGE_LIMIT}");
    let mut uri = first.clone();
    let (mut memories, mut links) = (Vec::new(), Vec::new());
    let mut finished = false;
    for _ in 0..EXPORT_PAGE_CAP {
        let (status, page) = send(
            &src_router,
            admin_request("GET", &uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export {uri}: {page}");
        for (key, sink) in [("memories", &mut memories), ("links", &mut links)] {
            let rows = page[key]
                .as_array()
                .unwrap_or_else(|| panic!("export {uri}: no {key} array: {page}"));
            sink.extend(rows.iter().cloned());
        }
        let Some(c) = page["next_cursor"].as_str() else {
            finished = true;
            break;
        };
        uri = format!("{first}&cursor={c}");
    }
    assert!(
        finished,
        "the router export walk did not finish in {EXPORT_PAGE_CAP} pages"
    );
    let body = json!({ "memories": memories, "links": links });
    let (status, receipt) = send(
        &dst_router,
        admin_request("POST", IMPORT_ROUTE)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("import body")))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import: {receipt}");
}

/// S3 / C3 (#10016): the shipped `/api/v1/export` and `/api/v1/import`
/// handlers on a postgres `AppState` reproduce every carried row exactly.
#[tokio::test(flavor = "multi_thread")]
async fn pg_router_export_then_import_reproduces_memories_and_links_9944() {
    let Some(admin) = admin_url() else { return };
    let (_src_db, src) = scratch_store(&admin).await;
    let (_dst_db, dst) = scratch_store(&admin).await;
    seed(&src, MAIN_CELL_SEALED).await;
    let before = snapshot(&src).await;
    assert_corpus_is_rich(&before);
    let dst_schema = snapshot(&dst).await.schema;
    router_export_import(&src, &dst).await;
    assert_eq!(
        before,
        snapshot(&src).await,
        "the router export changed its SOURCE store"
    );
    assert_restored(
        &EXPORT_IMPORT,
        &source_store(&EXPORT_IMPORT, before),
        &snapshot(&dst).await,
        &dst_schema,
    );
}

// ── dedicated red cells for the tracked admin-path defects ─────────────────

/// One router export → import of a corpus with the given shape: the corpus,
/// the source image and the restored image.
async fn router_run(sealed: Sealed) -> Option<(Corpus, StoreSnapshot, StoreSnapshot)> {
    let admin = admin_url()?;
    let (_src_db, src) = scratch_store(&admin).await;
    let (_dst_db, dst) = scratch_store(&admin).await;
    let corpus = seed(&src, sealed).await;
    let before = snapshot(&src).await;
    assert_corpus_is_rich(&before);
    router_export_import(&src, &dst).await;
    let restored = snapshot(&dst).await;
    Some((corpus, before, restored))
}

/// `table` rows keyed by `key`, projected onto `columns`.
fn keyed_columns(
    s: &StoreSnapshot,
    table: &str,
    key: &[&str],
    columns: &[&str],
) -> BTreeMap<Vec<Option<SqlValue>>, Vec<Option<SqlValue>>> {
    let pick = |r: &Row, cols: &[&str]| cols.iter().map(|c| r.get(*c).cloned()).collect();
    s.tables[table]
        .rows
        .iter()
        .map(|r| (pick(r, key), pick(r, columns)))
        .collect()
}

/// Some source row of `table` sets each of `columns` (the red cell is not
/// vacuous), and the restore keeps them row for row.
fn assert_columns_kept(
    before: &StoreSnapshot,
    restored: &StoreSnapshot,
    table: &str,
    key: &[&str],
    columns: &[&str],
    defect: &str,
) {
    let want = keyed_columns(before, table, key, columns);
    for (idx, col) in columns.iter().enumerate() {
        assert!(
            want.values()
                .any(|v| v[idx].as_ref().is_some_and(|v| !v.is_null())),
            "{table}.{col}: the corpus never sets it, so the cell would be vacuous"
        );
    }
    let got = keyed_columns(restored, table, key, columns);
    assert_eq!(got, want, "{table} {columns:?} not kept ({defect})");
}

/// Defect #10033, red until it lands: the admin export then import must keep
/// a sealed row sealed (empty content, the envelope byte for byte, and it
/// still opens to the written plaintext). The fix removes the
/// `SEALED_ROW_UNSEALED` null-column entry and sets `MAIN_CELL_SEALED` Present.
#[tokio::test(flavor = "multi_thread")]
async fn pg_router_export_keeps_a_sealed_row_sealed_10033() {
    let Some((corpus, before, restored)) = router_run(Sealed::Present).await else {
        return;
    };
    let id = corpus.sealed.expect("the shape seeds a sealed row");
    let image = |s: &StoreSnapshot| {
        s.rows_where("memories", "id", &id).first().map(|r| {
            (
                r.get("content").cloned(),
                r.get("encrypted_envelope").cloned(),
            )
        })
    };
    let want = image(&before);
    assert!(
        matches!(&want, Some((_, Some(v))) if !v.is_null()),
        "the corpus sealed row holds no envelope"
    );
    assert_eq!(
        image(&restored),
        want,
        "the admin export/import unsealed a sealed row (defect #10033)"
    );
    let Some((_, Some(SqlValue::Text(hex)))) = image(&restored) else {
        panic!("the restored sealed row holds no envelope (defect #10033)");
    };
    let hex = std::str::from_utf8(&hex).expect("bytea text");
    let hex = hex.strip_prefix("\\x").expect("bytea hex rendering");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
        .collect();
    let kp = ai_memory::encryption::get_or_create_keypair(CORPUS_AGENT).expect("x25519 keypair");
    let parsed = ai_memory::encryption::Envelope::from_bytes(&bytes).expect("parse envelope");
    let plain = ai_memory::encryption::decrypt(&parsed, &kp.secret).expect("decrypt envelope");
    assert_eq!(plain, SEALED_PLAINTEXT, "the restored envelope decrypts");
}

/// Defect #10034, red until it lands: the admin export then import must keep
/// every atomisation and entity-mention column. The fix removes the
/// `ATOM_COLUMNS_DROPPED` lossy entries above.
#[tokio::test(flavor = "multi_thread")]
async fn pg_router_export_keeps_every_atomisation_column_10034() {
    let Some((_, before, restored)) = router_run(MAIN_CELL_SEALED).await else {
        return;
    };
    assert_columns_kept(
        &before,
        &restored,
        "memories",
        &["id"],
        ATOM_COLUMNS,
        "defect #10034",
    );
}

/// Defect #10035, red until it lands: the admin export then import must keep
/// every edge's endpoint cid mirrors. The fix removes the `LINK_CID_DROPPED`
/// lossy entries above.
#[tokio::test(flavor = "multi_thread")]
async fn pg_router_export_keeps_every_link_cid_mirror_10035() {
    let Some((_, before, restored)) = router_run(MAIN_CELL_SEALED).await else {
        return;
    };
    assert_columns_kept(
        &before,
        &restored,
        "memory_links",
        &["source_id", "target_id", "relation"],
        LINK_CID_COLUMNS,
        "defect #10035",
    );
}

// ── the archive → restore path ──────────────────────────────────────────────

/// Columns `archive_restore` rewrites on the restored row, and why.
const ARCHIVE_RESTORE_RESTAMPED: &[&str] = &["updated_at"];

/// The `memories` row and the `memory_links` rows touching `id`.
fn row_image(s: &StoreSnapshot, id: &str) -> (Vec<Row>, Vec<Row>) {
    let want = SqlValue::text(id);
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
    let corpus = seed(&store, Sealed::Present).await;
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
    seed(&store, Sealed::Present).await;
    let problems = EXPORT_IMPORT.ratchet(&snapshot(&store).await);
    assert!(
        problems.is_empty(),
        "classification out of step with the live postgres schema:\n  {}",
        problems.join("\n  ")
    );
}

/// Why the probe may hold sparse tables and unset columns: it tests the
/// comparison itself, so no restore path is under test.
const PROBE_REASON: &str = "by design: the mutation probe compares a store with a mutated copy of itself; no restore path is under test";

/// Every classified table as `Exact`: the probe compares a store with a
/// mutated copy of itself, so nothing may be excused. The tables and columns
/// `snap` leaves sparse or unset are listed with [`PROBE_REASON`].
fn exact_probe_class(snap: &StoreSnapshot) -> &'static Classification {
    let tables: Vec<(&'static str, Carry)> = EXPORT_IMPORT
        .tables
        .iter()
        .map(|(t, _)| (*t, Carry::Exact))
        .collect();
    let mut sparse: Vec<TableEntry> = Vec::new();
    let mut null_columns: Vec<ColumnEntry> = Vec::new();
    for (table, _) in EXPORT_IMPORT.tables {
        let Some(t) = snap.tables.get(*table) else {
            continue;
        };
        if t.rows.len() < MIN_SOURCE_ROWS {
            sparse.push((*table, PROBE_REASON));
        }
        if t.rows.is_empty() {
            continue;
        }
        for col in &t.columns {
            if t.rows
                .iter()
                .all(|r| r.get(col).is_none_or(SqlValue::is_null))
            {
                let col: &'static str = Box::leak(col.clone().into_boxed_str());
                null_columns.push((*table, col, PROBE_REASON));
            }
        }
    }
    Box::leak(Box::new(Classification {
        path: "postgres mutation probe",
        tables: Box::leak(tables.into_boxed_slice()),
        lossy: &[],
        rederived: &[],
        sparse: Box::leak(sparse.into_boxed_slice()),
        null_columns: Box::leak(null_columns.into_boxed_slice()),
        schema: SchemaBaseline::Source,
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
    seed(&store, Sealed::Present).await;
    let snap = snapshot(&store).await;
    assert_corpus_is_rich(&snap);
    let class = exact_probe_class(&snap);
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
    // 3. alter one byte of one embedding (one digit of the server's rendering)
    let diffs = mutate("alter-one-byte", &|s| {
        let row = rows_mut(s, "memories")
            .iter_mut()
            .find(|r| matches!(r.get("embedding"), Some(SqlValue::Text(_))))
            .expect("an embedded row");
        if let Some(SqlValue::Text(t)) = row.get_mut("embedding") {
            let at = t.iter().rposition(u8::is_ascii_digit).expect("a digit");
            t[at] = if t[at] == b'9' { b'0' } else { t[at] + 1 };
        }
    });
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
