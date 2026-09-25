// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! Boids item 3 parts 1-4, f1-review follow-up (ruling `ITEM3-P1P4-f1`): the
//! three live counterexamples from f1's adversarial probe, turned into pins.
//!
//! * **F1 (authz)** — a supersedes link stamps under the CALLER's authority:
//!   an attested non-admin cannot contaminate another owner's private
//!   descendant (HTTP, `HttpIdentityMode::Enforce`); a non-admin who owns the
//!   target stamps only its own descendants; an admin stamps across owners.
//! * **F2 (lost update)** — a stamp blocked behind a concurrent writer's row
//!   lock must not overwrite the metadata that writer committed (descendant
//!   stamp AND the rewind root-marker upgrade).
//! * **F3 (duplicate event)** — two concurrent rewinds of an already-
//!   contaminated root yield exactly ONE new `swarm.rewind` event.
//!
//! Live-PG cells: `#[ignore]`-gated (the postgres-ignored tier) and skipped
//! when `AI_MEMORY_TEST_POSTGRES_URL` is unset. Every interleaving is
//! deterministic: a held row lock plus a `pg_blocking_pids` barrier.
#![cfg(all(feature = "sal", feature = "sal-postgres"))]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::{Body, to_bytes};
use axum::http::Request;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const DEPTH: usize = ai_memory::storage::LINEAGE_MAX_DEPTH;
const VICTIM: &str = "ai:f1fix-victim";
const BOB: &str = "ai:f1fix-bob";
const ADMIN: &str = "ai:f1fix-admin";
const SHARED_KEY: &str = "f1fix-shared-key";
const BOB_KEY: &str = "f1fix-bob-per-agent-key";

fn mem(ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

fn reflection(ns: &str, title: &str, owner: &str) -> Memory {
    let mut m = mem(ns, title, owner);
    m.memory_kind = MemoryKind::Reflection;
    m.reflection_depth = 1;
    m
}

fn private(mut m: Memory) -> Memory {
    m.metadata["scope"] = json!("private");
    m
}

fn edge(src: &Memory, tgt: &Memory, relation: MemoryLinkRelation) -> MemoryLink {
    MemoryLink {
        source_id: src.id.clone(),
        target_id: tgt.id.clone(),
        relation,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

async fn connect() -> Option<Arc<PostgresStore>> {
    static WARMED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    let pg = Arc::new(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    );
    // On a FRESH database, parallel first-touch AGE label creation can defer
    // one edge's graph projection to the outbox, and the (sync-mode AGE)
    // lineage walk then misses that edge — a pre-existing AGE-projection
    // window, not what these pins measure. Create each edge label once,
    // serially, before any cell seeds its own lineage.
    WARMED
        .get_or_init(|| async {
            let n = ns("warm");
            let (a, b) = (reflection(&n, "warm a", BOB), reflection(&n, "warm b", BOB));
            seed(&pg, &[&a, &b]).await;
            derive(&pg, &b, &a).await;
            pg.link(
                &CallerContext::for_agent(BOB),
                &edge(&b, &a, MemoryLinkRelation::Supersedes),
            )
            .await
            .expect("warm supersedes");
        })
        .await;
    Some(pg)
}

fn ns(tag: &str) -> String {
    format!("f1fix-{tag}-{}", uuid::Uuid::new_v4().simple())
}

/// Store each memory as its owner.
async fn seed(pg: &PostgresStore, rows: &[&Memory]) {
    for m in rows {
        let owner = m.metadata["agent_id"].as_str().expect("owner").to_string();
        pg.store(&CallerContext::for_agent(owner), m)
            .await
            .expect("seed");
    }
}

/// `child derives_from parent`, written by the child's owner.
async fn derive(pg: &PostgresStore, child: &Memory, parent: &Memory) {
    let owner = child.metadata["agent_id"].as_str().expect("owner");
    pg.link(
        &CallerContext::for_agent(owner),
        &edge(child, parent, MemoryLinkRelation::DerivesFrom),
    )
    .await
    .expect("lineage");
}

async fn state(pg: &PostgresStore, id: &str) -> String {
    sqlx::query_scalar("SELECT lifecycle_state FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(pg.pool())
        .await
        .expect("state")
}

async fn metadata(pg: &PostgresStore, id: &str) -> Value {
    sqlx::query_scalar("SELECT metadata FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(pg.pool())
        .await
        .expect("metadata")
}

/// Wait until `n` backends are blocked behind `holder_pid`'s locks — directly,
/// or queued behind a waiter that is (a second `FOR UPDATE` waiter on the same
/// row blocks on the first waiter's tuple lock, not on the holder).
async fn wait_blocked_behind(pg: &PostgresStore, holder_pid: i32, n: i64) {
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "WITH w AS (SELECT pid, pg_blocking_pids(pid) AS b FROM pg_stat_activity) \
             SELECT count(*) FROM w WHERE $1 = ANY(w.b) OR EXISTS \
             (SELECT 1 FROM w AS v WHERE v.pid = ANY(w.b) AND $1 = ANY(v.b))",
        )
        .bind(holder_pid)
        .fetch_one(pg.pool())
        .await
        .expect("barrier probe");
        if blocked >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "barrier not reached: {blocked}/{n} blocked"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Open a transaction holding `FOR UPDATE` on `id`; returns it + its pid.
async fn hold_row_lock(
    pg: &PostgresStore,
    id: &str,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = pg.pool().begin().await.expect("lock tx");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .expect("pid");
    sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock row");
    (tx, pid)
}

/// The concurrent writer: commit a new metadata key under the held lock.
async fn commit_concurrent_key(mut tx: sqlx::Transaction<'static, sqlx::Postgres>, id: &str) {
    sqlx::query(
        "UPDATE memories SET metadata = jsonb_set(metadata, '{concurrent_committed}', \
         'true'::jsonb), version = version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("concurrent writer");
    tx.commit().await.expect("commit concurrent metadata");
}

// ---------------------------------------------------------------- F1 ----

fn app_state(pg: Arc<PostgresStore>) -> AppState {
    let scratch = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        scratch,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let mut keys = std::collections::HashMap::new();
    keys.insert(api_key_sha256_hex(BOB_KEY), BOB.to_string());
    let store: Arc<dyn MemoryStore> = pg;
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
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
        admin_agent_ids: Arc::new(vec![ADMIN.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(EnrolledAgentKeys::from_map(keys)),
        http_identity_mode: HttpIdentityMode::Enforce,
    }
}

fn router(pg: Arc<PostgresStore>) -> axum::Router {
    let state = app_state(pg);
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(&state.enrolled_agent_keys),
        identity_mode: state.http_identity_mode,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, state)
}

/// f1's PROBE_AUTHZ: an ATTESTED non-admin (enrolled per-agent key under
/// `enforce`) supersedes a victim's private reflection from its own
/// reflection. The link still commits (201) — containment is best-effort
/// after commit — but the victim's private descendant stays OPEN.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_attested_nonadmin_cross_owner_supersedes_leaves_victim_descendant_open_f1() {
    let Some(pg) = connect().await else { return };
    let (vns, bns) = (ns("victim"), ns("bob"));
    let target = private(reflection(&vns, "old reflection", VICTIM));
    let child = private(mem(&vns, "private descendant", VICTIM));
    let source = reflection(&bns, "new reflection", BOB);
    seed(&pg, &[&target, &child, &source]).await;
    derive(&pg, &child, &target).await;
    assert!(
        pg.get(&CallerContext::for_agent(BOB), &child.id)
            .await
            .is_err(),
        "precondition: the caller cannot see the victim's private descendant"
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/links")
        .header(ai_memory::HEADER_API_KEY, BOB_KEY)
        .header("x-agent-id", BOB)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "source_id": source.id,
                "target_id": target.id,
                "relation": "supersedes",
            }))
            .expect("serialise"),
        ))
        .expect("request");
    let resp = router(Arc::clone(&pg)).oneshot(req).await.expect("route");
    let status = resp.status().as_u16();
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    assert_eq!(status, 201, "the link itself commits: {body:?}");
    assert_eq!(
        state(&pg, &child.id).await,
        "open",
        "a non-admin must not contaminate another owner's private descendant"
    );
}

/// A non-admin who OWNS the superseded target stamps its own descendants
/// and leaves another owner's private descendant untouched.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_nonadmin_target_owner_stamps_only_its_own_descendants_f1() {
    let Some(pg) = connect().await else { return };
    let (bns, vns) = (ns("own"), ns("victim"));
    let source = reflection(&bns, "new", BOB);
    let target = reflection(&bns, "old", BOB);
    let own = mem(&bns, "own descendant", BOB);
    let victim = private(mem(&vns, "victim descendant", VICTIM));
    seed(&pg, &[&source, &target, &own, &victim]).await;
    derive(&pg, &own, &target).await;
    derive(&pg, &victim, &target).await;
    pg.link_signed(
        &CallerContext::for_agent(BOB),
        &edge(&source, &target, MemoryLinkRelation::Supersedes),
        None,
    )
    .await
    .expect("supersedes");
    assert_eq!(
        state(&pg, &own.id).await,
        "contaminated",
        "own descendant stamped"
    );
    assert_eq!(
        state(&pg, &victim.id).await,
        "open",
        "another owner's descendant is outside a non-admin's authority"
    );
}

/// An admin (`bypass_visibility`) stamps across owners.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_admin_supersedes_stamps_across_owners_f1() {
    let Some(pg) = connect().await else { return };
    let (bns, vns) = (ns("admin-src"), ns("admin-victim"));
    let source = reflection(&bns, "new", BOB);
    let target = private(reflection(&vns, "old", VICTIM));
    let child = private(mem(&vns, "descendant", VICTIM));
    seed(&pg, &[&source, &target, &child]).await;
    derive(&pg, &child, &target).await;
    pg.link_signed(
        &CallerContext::for_admin(ADMIN),
        &edge(&source, &target, MemoryLinkRelation::Supersedes),
        None,
    )
    .await
    .expect("supersedes");
    assert_eq!(
        state(&pg, &child.id).await,
        "contaminated",
        "an admin's supersede stamps across owners"
    );
}

// ---------------------------------------------------------------- F2 ----

/// f1's PROBE_LOST_UPDATE: the stamp blocks behind a concurrent writer's row
/// lock; that writer commits a new metadata key; the stamp must keep it.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_stamp_preserves_concurrently_committed_metadata_f2() {
    let Some(pg) = connect().await else { return };
    let n = ns("race");
    let root = mem(&n, "metadata root", VICTIM);
    let leaf = mem(&n, "metadata leaf", VICTIM);
    seed(&pg, &[&root, &leaf]).await;
    derive(&pg, &leaf, &root).await;
    let (lock, holder) = hold_row_lock(&pg, &leaf.id).await;
    let handle = Arc::clone(&pg);
    let rid = root.id.clone();
    let stamp =
        tokio::spawn(async move { handle.stamp_contaminated_descendants_pg(&rid, DEPTH).await });
    wait_blocked_behind(&pg, holder, 1).await;
    commit_concurrent_key(lock, &leaf.id).await;
    let outcome = stamp.await.expect("join").expect("stamp");
    assert_eq!(outcome.stamped, 1, "{outcome:?}");
    let meta = metadata(&pg, &leaf.id).await;
    assert_eq!(
        meta.get("concurrent_committed"),
        Some(&json!(true)),
        "the concurrently committed key must survive the stamp: {meta}"
    );
    assert!(
        meta.get("contamination").is_some(),
        "marker written: {meta}"
    );
    assert_eq!(state(&pg, &leaf.id).await, "contaminated");
}

/// Seed a root already contaminated (no `rewind` marker) — f1's fixture.
async fn contaminated_root(pg: &PostgresStore, tag: &str) -> Memory {
    let mut root = mem(&ns(tag), "already tainted root", VICTIM);
    root.metadata = json!({
        "agent_id": VICTIM,
        "contamination": {"prior_lifecycle_state": "open", "contaminated_from": "fixture"},
    });
    seed(pg, &[&root]).await;
    sqlx::query("UPDATE memories SET lifecycle_state = 'contaminated' WHERE id = $1")
        .bind(&root.id)
        .execute(pg.pool())
        .await
        .expect("initial taint");
    root
}

/// The same lost update on the rewind's ROOT-marker upgrade.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_rewind_root_marker_preserves_concurrently_committed_metadata_f2() {
    let Some(pg) = connect().await else { return };
    let root = contaminated_root(&pg, "root-race").await;
    let (lock, holder) = hold_row_lock(&pg, &root.id).await;
    let handle = Arc::clone(&pg);
    let id = root.id.clone();
    let rewind = tokio::spawn(async move {
        handle
            .swarm_rewind(
                &CallerContext::for_admin_checked(ADMIN, true),
                &id,
                DEPTH,
                "memory",
                &[],
                false,
            )
            .await
    });
    wait_blocked_behind(&pg, holder, 1).await;
    commit_concurrent_key(lock, &root.id).await;
    let report = rewind.await.expect("join").expect("rewind");
    assert!(!report.already_rewound, "{report:?}");
    let meta = metadata(&pg, &root.id).await;
    assert_eq!(
        meta.get("concurrent_committed"),
        Some(&json!(true)),
        "the concurrently committed key must survive the root marker: {meta}"
    );
    assert_eq!(meta["contamination"]["rewind"], json!(true), "{meta}");
    assert_eq!(
        meta["contamination"]["prior_lifecycle_state"],
        json!("open"),
        "the reversibility anchor is kept: {meta}"
    );
}

// ---------------------------------------------------------------- F3 ----

/// f1's PROBE_CONCURRENT_REWIND: two rewinds of an already-contaminated root,
/// both parked behind a held root lock, then released together.
#[tokio::test]
#[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
async fn pg_concurrent_rewinds_append_exactly_one_signed_event_f3() {
    let Some(pg) = connect().await else { return };
    let root = contaminated_root(&pg, "idempotency").await;
    // A per-test issuer so a sibling cell's events cannot skew the count.
    let issuer = format!("ai:f1fix-f3-{}", uuid::Uuid::new_v4().simple());
    let count = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM signed_events WHERE event_type = 'swarm.rewind' \
             AND agent_id = $1",
        )
        .bind(&issuer)
        .fetch_one(pg.pool())
        .await
        .expect("count")
    };
    let before = count().await;
    let (lock, holder) = hold_row_lock(&pg, &root.id).await;
    let mut calls = Vec::new();
    for _ in 0..2 {
        let (handle, id, who) = (Arc::clone(&pg), root.id.clone(), issuer.clone());
        calls.push(tokio::spawn(async move {
            handle
                .swarm_rewind(
                    &CallerContext::for_admin_checked(who, true),
                    &id,
                    DEPTH,
                    "memory",
                    &[],
                    false,
                )
                .await
        }));
    }
    wait_blocked_behind(&pg, holder, 2).await;
    lock.commit().await.expect("release root");
    let mut already = 0;
    for c in calls {
        let r = c.await.expect("join").expect("rewind succeeds");
        already += usize::from(r.already_rewound);
    }
    assert_eq!(
        count().await - before,
        1,
        "exactly ONE new swarm.rewind event"
    );
    assert_eq!(already, 1, "exactly one call reports already_rewound");
}
