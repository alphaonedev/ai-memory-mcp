// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! #2725 (CB-23) — `POST /api/v1/memories/bulk` must HONOR `on_conflict`.
//!
//! The CONFIRMED data-integrity defect: `bulk_create` never resolved
//! `body.on_conflict`, so every row whose `(title, namespace)` collided with a
//! PRE-EXISTING stored row went straight to `db::insert`'s upsert arm and
//! silently, unrecoverably OVERWROTE the stored content (no pre-overwrite
//! snapshot — `ai-memory undo-edit` had nothing to restore). sqlite
//! single-create defaults `on_conflict=error` (409 + `existing_id`); bulk had
//! no such default.
//!
//! **R-203.** At the parent commit these cells fail for the right reason:
//! `default_collision_is_rejected_not_overwritten` observes the pre-existing
//! content REPLACED (bulk reported `updated: 1` and the row silently changed);
//! `explicit_merge_updates_and_discloses_superseded_id` observes NO
//! `updated_rows[]` in the envelope. The in-batch and reconciliation cells are
//! CONTROLS proving the fix did not regress the existing dedup path.
//!
//! Counter assertions are ALWAYS paired with an out-of-band `SELECT` — a
//! counter-only assertion is precisely how the class of #2551/#2725 defects
//! hides (the envelope is self-consistent and wrong).

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

/// #1751 — pin this binary to the explicit permissive agent-attestation
/// opt-out; the v1.0 HTTP-direct default is REQUIRED and would reject these
/// unsigned store fixtures before the accounting under test runs.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn build_test_router() -> (axum::Router, std::path::PathBuf, NamedTempFile) {
    permissive_attestation_for_tests();
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db_path, f)
}

const AGENT: &str = "bulk-on-conflict-agent";

async fn post(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

fn row(namespace: &str, title: &str, content: &str) -> Value {
    json!({
        "tier": "long", "namespace": namespace, "title": title, "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "api", "metadata": {},
    })
}

/// Out-of-band ground truth — never the response's own counters.
fn db_content(db_path: &Path, namespace: &str, title: &str) -> String {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT content FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| r.get(0),
        )
        .expect("content")
}

fn db_id(db_path: &Path, namespace: &str, title: &str) -> String {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| r.get(0),
        )
        .expect("id")
}

fn db_row_count(db_path: &Path, namespace: &str) -> i64 {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            params![namespace],
            |r| r.get(0),
        )
        .expect("count")
}

/// The reconciliation identity a fleet loader asserts on (#2551): a
/// conflict-rejected row now counts in `rejected`, never in `updated`.
fn assert_reconciles(v: &Value) {
    let n = |k: &str| v[k].as_u64().unwrap_or_else(|| panic!("missing {k}: {v}"));
    let pending = v["pending"].as_array().expect("pending[]").len() as u64;
    assert_eq!(
        n("created") + n("updated") + n("deduped") + n("rejected") + pending,
        n("sent"),
        "#2551/#2725: created+updated+deduped+rejected+pending must equal sent: {v}"
    );
}

/// Seed one durable pre-existing row via bulk (default `on_conflict=error`,
/// no collision) and return its stored id.
async fn seed(
    router: &axum::Router,
    db_path: &Path,
    ns: &str,
    title: &str,
    content: &str,
) -> String {
    let (status, v) = post(
        router,
        "/api/v1/memories/bulk",
        &json!([row(ns, title, content)]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed should land cleanly: {v}");
    assert_eq!(v["created"], json!(1), "{v}");
    db_id(db_path, ns, title)
}

// ---------------------------------------------------------------------------
// (a) — default: a collision with a PRE-EXISTING row is REJECTED, not overwritten.
// ---------------------------------------------------------------------------

/// PARENT: bulk had no `on_conflict` default, so this row's `db::insert`
/// upserted onto the seeded row and its content silently became "attempted
/// overwrite" — the envelope reported `updated: 1`. There was no snapshot, so
/// the original content was unrecoverable.
#[tokio::test]
async fn default_collision_is_rejected_not_overwritten_2725() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "cb23-default";
    let existing_id = seed(&router, &db_path, ns, "dup", "original").await;

    // Same (title, namespace), no on_conflict → default `error`.
    let (status, v) = post(
        &router,
        "/api/v1/memories/bulk",
        &json!([row(ns, "dup", "attempted overwrite")]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "all-rejected → dominant 409: {v}"
    );
    assert_eq!(v["created"], json!(0), "{v}");
    assert_eq!(v["updated"], json!(0), "{v}");
    assert_eq!(v["rejected"], json!(1), "{v}");
    let err = &v["errors"][0];
    assert_eq!(err["code"], json!("CONFLICT"), "{v}");
    assert_eq!(err["index"], json!(0), "{v}");
    assert_eq!(
        err["existing_id"],
        json!(existing_id),
        "the conflict must carry the stored id so a loader can reconcile: {v}"
    );
    assert!(
        v.get("updated_rows").is_none(),
        "a rejected row is NOT an updated row: {v}"
    );

    // The DATA-INTEGRITY assertion — out of band, never the envelope.
    assert_eq!(
        db_content(&db_path, ns, "dup"),
        "original",
        "#2725: the default MUST NOT overwrite pre-existing content"
    );
    assert_eq!(db_row_count(&db_path, ns), 1, "no new row was minted: {v}");
    assert_reconciles(&v);
}

// ---------------------------------------------------------------------------
// (b) — explicit merge overwrites AND discloses the superseded id.
// ---------------------------------------------------------------------------

/// PARENT: `updated_rows[]` did not exist, so a loader could not tell WHICH of
/// its records replaced existing content — only the scalar `updated: N`.
#[tokio::test]
async fn explicit_merge_updates_and_discloses_superseded_id_2725() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "cb23-merge";
    let existing_id = seed(&router, &db_path, ns, "dup", "original").await;

    let mut body = row(ns, "dup", "new content");
    body["on_conflict"] = json!("merge");
    let (status, v) = post(&router, "/api/v1/memories/bulk", &json!([body])).await;

    assert_eq!(status, StatusCode::OK, "a clean merge-update is 200: {v}");
    assert_eq!(v["created"], json!(0), "{v}");
    assert_eq!(v["updated"], json!(1), "{v}");
    assert_eq!(v["rejected"], json!(0), "{v}");
    let updated = v["updated_rows"].as_array().expect("updated_rows[]");
    assert_eq!(updated.len(), 1, "{v}");
    assert_eq!(updated[0]["index"], json!(0), "{v}");
    assert_eq!(
        updated[0]["superseded_by"],
        json!(existing_id),
        "the id whose content was overwritten: {v}"
    );

    assert_eq!(
        db_content(&db_path, ns, "dup"),
        "new content",
        "#2725: an explicit merge DOES overwrite"
    );
    assert_eq!(
        db_row_count(&db_path, ns),
        1,
        "still one row (id preserved): {v}"
    );
    assert_eq!(
        db_id(&db_path, ns, "dup"),
        existing_id,
        "id is never rewritten on upsert"
    );
    assert_reconciles(&v);
}

// ---------------------------------------------------------------------------
// (c) — in-batch dedup is UNCHANGED (control: the fix did not regress it).
// ---------------------------------------------------------------------------

/// Two rows sharing `(title, namespace)` in the SAME batch, no pre-existing
/// row. That is an in-batch collapse (`deduped_rows[]`), NOT an on_conflict
/// collision — the default `error` must not reject the later sibling.
#[tokio::test]
async fn in_batch_dedup_is_unchanged_2725() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "cb23-dedup";
    let (status, v) = post(
        &router,
        "/api/v1/memories/bulk",
        &json!([row(ns, "same", "first"), row(ns, "same", "second")]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::MULTI_STATUS,
        "a partial-fill dedup is 207: {v}"
    );
    assert_eq!(v["created"], json!(1), "{v}");
    assert_eq!(
        v["updated"],
        json!(0),
        "an in-batch collapse is NOT an update: {v}"
    );
    assert_eq!(
        v["rejected"],
        json!(0),
        "no conflict rejection for an in-batch dup: {v}"
    );
    let deduped = v["deduped_rows"].as_array().expect("deduped_rows[]");
    assert_eq!(deduped.len(), 1, "{v}");
    assert_eq!(deduped[0]["index"], json!(0), "{v}");
    assert_eq!(
        deduped[0]["superseded_by"],
        json!(1),
        "LAST input position survives: {v}"
    );
    assert!(
        v.get("updated_rows").is_none(),
        "in-batch dedup emits no updated_rows: {v}"
    );

    assert_eq!(
        db_content(&db_path, ns, "same"),
        "second",
        "the LAST row's content is durable"
    );
    assert_eq!(db_row_count(&db_path, ns), 1, "{v}");
    assert_reconciles(&v);
}

// ---------------------------------------------------------------------------
// (d) — reconciliation holds across a mixed batch (every bucket exercised).
// ---------------------------------------------------------------------------

/// A single batch that touches every disposition: a default-error collision
/// (rejected), a fresh insert (created), an explicit-merge overwrite
/// (updated + updated_rows), and an in-batch dup pair (created + deduped). The
/// identity `created+updated+deduped+rejected+pending == sent` must hold and
/// each bucket must be counted exactly once.
#[tokio::test]
async fn mixed_batch_reconciles_2725() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "cb23-mixed";
    let err_id = seed(&router, &db_path, ns, "err-target", "err-original").await;
    let merge_id = seed(&router, &db_path, ns, "merge-target", "merge-original").await;

    let mut merge_body = row(ns, "merge-target", "merge-new");
    merge_body["on_conflict"] = json!("merge");

    let (status, v) = post(
        &router,
        "/api/v1/memories/bulk",
        &json!([
            row(ns, "err-target", "should-be-refused"), // 0: default error → rejected
            row(ns, "fresh", "brand-new"),              // 1: created
            merge_body,                                 // 2: merge → updated
            row(ns, "twin", "twin-a"),                  // 3: in-batch dup → deduped
            row(ns, "twin", "twin-b"),                  // 4: in-batch dup survivor → created
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::MULTI_STATUS, "partial fill: {v}");
    assert_eq!(v["created"], json!(2), "fresh + twin survivor: {v}");
    assert_eq!(v["updated"], json!(1), "the merge: {v}");
    assert_eq!(v["deduped"], json!(1), "the in-batch dup: {v}");
    assert_eq!(v["rejected"], json!(1), "the default-error collision: {v}");
    assert_reconciles(&v);

    // The rejected row carries the right id and did NOT overwrite.
    assert_eq!(v["errors"][0]["code"], json!("CONFLICT"), "{v}");
    assert_eq!(v["errors"][0]["existing_id"], json!(err_id), "{v}");
    assert_eq!(
        db_content(&db_path, ns, "err-target"),
        "err-original",
        "the error-mode collision left the row untouched"
    );

    // The merge row overwrote and disclosed the superseded id.
    let updated = v["updated_rows"].as_array().expect("updated_rows[]");
    assert_eq!(updated.len(), 1, "{v}");
    assert_eq!(updated[0]["index"], json!(2), "{v}");
    assert_eq!(updated[0]["superseded_by"], json!(merge_id), "{v}");
    assert_eq!(db_content(&db_path, ns, "merge-target"), "merge-new");

    // The in-batch twin collapsed last-wins.
    assert_eq!(db_content(&db_path, ns, "twin"), "twin-b");
}
