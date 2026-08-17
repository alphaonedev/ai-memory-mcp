// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! #2550 / #2551 / #2552 / #2588 / #2594 — `POST /api/v1/memories/bulk` must
//! tell the truth about what it did.
//!
//! All five issues were symptoms of ONE root cause: `bulk_create`
//! re-implemented the single-create funnel instead of calling it, and each
//! issue is a different stage the re-implementation omitted. These cells pin
//! the OUTCOME of each omitted stage, not the refactor that closed it.
//!
//! **R-203.** Every cell below fails at the parent commit, for the right
//! reason — the observed pre-fix values are recorded per cell:
//!
//! | cell | parent behaviour |
//! |---|---|
//! | `bulk_honours_caller_scope_2550` | `metadata.scope` ABSENT (row lands `scope_idx='private'`) |
//! | `bulk_stamps_kind_provenance_2550` | `kind_provenance` NULL |
//! | `bulk_matches_single_create_field_resolution_2550` | the two surfaces disagree on both fields |
//! | `bulk_created_counts_persisted_not_sent_2551` | `created: 3` for 2 rows in the table |
//! | `bulk_updated_is_distinct_from_created_2551` | a cross-call upsert reports `created: 1` |
//! | `bulk_row_errors_carry_index_and_code_2552` | `errors: ["validation failed"]` (bare strings) |
//! | `bulk_total_rejection_is_not_200_2588` | `200 {"created":0,"errors":["internal error"]}` |
//! | `bulk_partial_fill_is_207_2588` | `200` |
//! | `bulk_write_funnel_embeds_2594` | zero `app.embedder` references in the bulk funnel |
//!
//! Two CONTROL cells (`bulk_all_success_is_still_200`,
//! `bulk_empty_batch_is_200`) pin that the new refusals are not passing for a
//! trivial reason — the #2449 harness lesson that a cell which never reaches
//! the assertion also "fails".
//!
//! Counter assertions are ALWAYS paired with an out-of-band `SELECT` against
//! the database. A counter-only assertion is precisely how #2551 hid: the
//! envelope was self-consistent and wrong.

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
/// opt-out; the v0.9 HTTP-direct default is REQUIRED and would reject these
/// unsigned store fixtures before any of the accounting under test runs.
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
        auto_tag_queue: None,
        atomise_queue: None,
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

const AGENT: &str = "bulk-truth-agent";

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

fn db_metadata(db_path: &Path, namespace: &str, title: &str) -> Value {
    let raw: String = Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT metadata FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| r.get(0),
        )
        .expect("metadata");
    serde_json::from_str(&raw).expect("metadata json")
}

fn db_kind_provenance(db_path: &Path, namespace: &str, title: &str) -> Option<String> {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT kind_provenance FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| r.get::<_, Option<String>>(0),
        )
        .expect("kind_provenance")
}

/// The reconciliation identity a fleet loader asserts on (#2551).
fn assert_reconciles(v: &Value) {
    let n = |k: &str| v[k].as_u64().unwrap_or_else(|| panic!("missing {k}: {v}"));
    let pending = v["pending"].as_array().expect("pending[]").len() as u64;
    assert_eq!(
        n("created") + n("updated") + n("deduped") + n("rejected") + pending,
        n("sent"),
        "#2551: created+updated+deduped+rejected+pending must equal sent: {v}"
    );
}

// ---------------------------------------------------------------------------
// #2550 — field resolution.
// ---------------------------------------------------------------------------

/// PARENT: `metadata.scope` is ABSENT — `body.scope` is accepted by the DTO,
/// never read, and the row lands on the `scope_idx` generated column's
/// `'private'` default. Every OTHER agent then sees zero rows, and the caller
/// was told `{"created":N,"errors":[]}`.
#[tokio::test]
async fn bulk_honours_caller_scope_2550() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "scope-2550";
    let mut body = row(ns, "collective-row", "x");
    body["scope"] = json!("collective");
    let (status, v) = post(&router, "/api/v1/memories/bulk", &json!([body])).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let meta = db_metadata(&db_path, ns, "collective-row");
    assert_eq!(
        meta["scope"],
        json!("collective"),
        "#2550: the caller's top-level `scope` must reach the row — a dropped \
         `collective` silently becomes owner-only `private`: {meta}"
    );
}

/// PARENT: `kind_provenance` is NULL on a bulk row while the byte-identical
/// body posted to `/memories` lands `declared`.
#[tokio::test]
async fn bulk_stamps_kind_provenance_2550() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "kindprov-2550";
    let mut body = row(ns, "declared-row", "x");
    body["kind"] = json!("concept");
    let (status, v) = post(&router, "/api/v1/memories/bulk", &json!([body])).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    assert_eq!(
        db_kind_provenance(&db_path, ns, "declared-row").as_deref(),
        Some("declared"),
        "#2550: a caller-supplied `kind` is `declared` provenance on EVERY \
         create funnel"
    );
}

/// The surface-parity cell #2550 asks for: the SAME `CreateMemory` body must
/// resolve identically on `/memories` and `/memories/bulk`. This shape had no
/// coverage at all, which is why the divergence survived.
#[tokio::test]
async fn bulk_matches_single_create_field_resolution_2550() {
    let (router, db_path, _keep) = build_test_router();
    let mut single = row("parity-single", "parity-row", "x");
    single["scope"] = json!("collective");
    single["kind"] = json!("concept");
    let mut bulk = single.clone();
    bulk["namespace"] = json!("parity-bulk");

    let (s1, v1) = post(&router, "/api/v1/memories", &single).await;
    assert_eq!(s1, StatusCode::CREATED, "{v1}");
    let (s2, v2) = post(&router, "/api/v1/memories/bulk", &json!([bulk])).await;
    assert_eq!(s2, StatusCode::OK, "{v2}");

    assert_eq!(
        db_metadata(&db_path, "parity-single", "parity-row")["scope"],
        db_metadata(&db_path, "parity-bulk", "parity-row")["scope"],
        "#2550: single-create and bulk must agree on resolved `scope`"
    );
    assert_eq!(
        db_kind_provenance(&db_path, "parity-single", "parity-row"),
        db_kind_provenance(&db_path, "parity-bulk", "parity-row"),
        "#2550: single-create and bulk must agree on `kind_provenance`"
    );
}

// ---------------------------------------------------------------------------
// #2551 — accounting.
// ---------------------------------------------------------------------------

/// PARENT: `{"created":3}` for a batch that persists 2 rows. Measured at
/// corpus scale as 7,912 sent / 7,912 reported / 7,855 landed, `errors: []`.
///
/// The in-batch collapse is CORRECT — the upsert is last-wins by design. What
/// was wrong is reporting it as three creations and giving the caller no way
/// to learn that row 0's content was discarded.
#[tokio::test]
async fn bulk_created_counts_persisted_not_sent_2551() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "dedup-2551";
    let batch = json!([
        row(ns, "dup-title", "first version"),
        row(ns, "unique-a", "a"),
        row(ns, "dup-title", "second version wins"),
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;

    // Ground truth FIRST, from the database, never the envelope.
    assert_eq!(db_row_count(&db_path, ns), 2, "2 rows are persisted: {v}");
    assert_eq!(
        db_content(&db_path, ns, "dup-title"),
        "second version wins",
        "last-wins is the upsert contract"
    );

    assert_eq!(v["sent"], 3, "{v}");
    assert_eq!(
        v["created"], 2,
        "#2551: `created` is rows PERSISTED, not rows SENT: {v}"
    );
    assert_eq!(v["deduped"], 1, "#2551: the collapsed row is counted: {v}");
    assert_reconciles(&v);

    // The collapse must be ADDRESSABLE — a scalar count cannot tell a loader
    // WHICH of its 1000 source records was discarded.
    let d = v["deduped_rows"].as_array().expect("deduped_rows[]");
    assert_eq!(d.len(), 1, "{v}");
    assert_eq!(d[0]["index"], 0, "#2551: input index 0 was superseded: {v}");
    assert_eq!(d[0]["superseded_by"], 2, "#2551: by input index 2: {v}");

    // A partial application is not an unqualified success.
    assert_eq!(status, StatusCode::MULTI_STATUS, "{v}");
}

/// PARENT: a second bulk call that UPSERTS an already-existing row reports
/// `created: 1`. Summing `created` across batches then over-counts the table,
/// which is the cross-batch half of the 7,912/7,855 discrepancy.
///
/// #2725 (CB-23) — the cross-call upsert is now an EXPLICIT `on_conflict=merge`;
/// the default (`error`) rejects a pre-existing collision rather than silently
/// overwriting (that data-integrity change is pinned by
/// `tests/bulk_on_conflict_2725.rs`). This cell keeps pinning the surviving
/// #2551 concern: an upsert reports `updated`, never `created`.
#[tokio::test]
async fn bulk_updated_is_distinct_from_created_2551() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "upsert-2551";
    let (_, first) = post(
        &router,
        "/api/v1/memories/bulk",
        &json!([row(ns, "t", "v1")]),
    )
    .await;
    assert_eq!(first["created"], 1, "{first}");
    assert_eq!(first["updated"], 0, "{first}");

    let mut merge_row = row(ns, "t", "v2");
    merge_row["on_conflict"] = json!("merge");
    let (status, second) = post(&router, "/api/v1/memories/bulk", &json!([merge_row])).await;
    assert_eq!(db_row_count(&db_path, ns), 1, "still one row: {second}");
    assert_eq!(
        second["created"], 0,
        "#2551: an upsert of a pre-existing row is not a creation: {second}"
    );
    assert_eq!(second["updated"], 1, "#2551: it is an update: {second}");
    assert_reconciles(&second);
    // Nothing was rejected or discarded, so this is still a clean success.
    assert_eq!(status, StatusCode::OK, "{second}");
}

// ---------------------------------------------------------------------------
// #2552 — error mapping.
// ---------------------------------------------------------------------------

/// PARENT: `{"errors":["validation failed"]}` — a bare string, no field, no
/// row index. A 1000-row batch yielded 1000 identical, information-free
/// strings and diagnosing a corpus load required bisecting field-by-field
/// through the single-create endpoint instead.
#[tokio::test]
async fn bulk_row_errors_carry_index_and_code_2552() {
    let (router, _db, _keep) = build_test_router();
    let ns = "errshape-2552";
    let batch = json!([
        row(ns, "ok-row", "x"),
        row(ns, "", "y"), // empty title -> validation failure
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;

    let errors = v["errors"].as_array().expect("errors[]");
    assert_eq!(errors.len(), 1, "{v}");
    assert_eq!(
        errors[0]["index"], 1,
        "#2552: the caller must learn WHICH row failed: {v}"
    );
    assert_eq!(
        errors[0]["code"], "VALIDATION_FAILED",
        "#2552: and a machine-readable cause it can switch on: {v}"
    );
    // #851 is PRESERVED: the human label stays inside the sanitized allowlist.
    assert_eq!(errors[0]["error"], "validation failed", "{v}");
    assert_eq!(v["rejected"], 1, "{v}");
    assert_reconciles(&v);
    assert_eq!(status, StatusCode::MULTI_STATUS, "{v}");
}

// ---------------------------------------------------------------------------
// #2588 — exit discipline.
// ---------------------------------------------------------------------------

/// PARENT: `200 OK` with `{"created":0,"errors":["internal error"]}` and ZERO
/// log lines. 31,000 rows were dropped behind exactly this shape while the
/// single-row surface on the same daemon returned a typed `429`.
#[tokio::test]
async fn bulk_total_rejection_is_not_200_2588() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "quota-2588";
    // Seed the (agent, namespace) quota row, then close the cap entirely.
    {
        let conn = Connection::open(&db_path).expect("open");
        ai_memory::quotas::get_status(&conn, AGENT, ns).expect("seed row");
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 0 \
             WHERE agent_id = ?1 AND namespace = ?2",
            params![AGENT, ns],
        )
        .expect("close cap");
    }
    let batch = json!([row(ns, "q1", "x"), row(ns, "q2", "y")]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;

    assert_eq!(db_row_count(&db_path, ns), 0, "nothing landed: {v}");
    assert_ne!(
        status,
        StatusCode::OK,
        "#2588: a request in which NOTHING was created is not a success: {v}"
    );
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "#2588: a quota rejection reports the same typed 429 the single-row \
         surface reports: {v}"
    );
    assert_eq!(v["created"], 0, "{v}");
    assert_eq!(v["rejected"], 2, "{v}");
    for e in v["errors"].as_array().expect("errors[]") {
        assert_eq!(
            e["code"], "QUOTA_EXCEEDED",
            "#2588: a retryable quota breach must NOT be flattened to \
             `internal error` — that is what left the loader with no signal \
             to back off: {v}"
        );
        assert_eq!(e["error"], "quota exceeded", "{v}");
    }
    assert_reconciles(&v);
}

/// PARENT: `200`. A batch where 1 of 3 rows landed reported unqualified
/// success; a client checking only the status could not tell.
#[tokio::test]
async fn bulk_partial_fill_is_207_2588() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "partial-2588";
    {
        let conn = Connection::open(&db_path).expect("open");
        ai_memory::quotas::get_status(&conn, AGENT, ns).expect("seed row");
        conn.execute(
            "UPDATE agent_quotas SET max_memories_per_day = 1 \
             WHERE agent_id = ?1 AND namespace = ?2",
            params![AGENT, ns],
        )
        .expect("cap 1");
    }
    let batch = json!([row(ns, "p1", "x"), row(ns, "p2", "y"), row(ns, "p3", "z")]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;

    assert_eq!(db_row_count(&db_path, ns), 1, "exactly one fit: {v}");
    assert_eq!(
        status,
        StatusCode::MULTI_STATUS,
        "#2588: a PARTIAL application is 207, never 200: {v}"
    );
    assert_eq!(v["created"], 1, "{v}");
    assert_eq!(v["rejected"], 2, "{v}");
    assert_reconciles(&v);
}

// ---------------------------------------------------------------------------
// CONTROL cells — the refusals above must not be passing for a trivial reason.
// ---------------------------------------------------------------------------

/// A batch in which every row landed as its own distinct row is STILL a plain
/// `200`. Without this, the three status cells above would also pass against a
/// handler that simply never returns 200.
#[tokio::test]
async fn bulk_all_success_is_still_200() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "control-ok";
    let batch = json!([row(ns, "c1", "x"), row(ns, "c2", "y"), row(ns, "c3", "z")]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;
    assert_eq!(status, StatusCode::OK, "control: clean batch is 200: {v}");
    assert_eq!(db_row_count(&db_path, ns), 3, "{v}");
    assert_eq!(v["created"], 3, "{v}");
    assert_eq!(v["deduped"], 0, "{v}");
    assert_eq!(v["rejected"], 0, "{v}");
    assert!(
        v["errors"].as_array().expect("errors[]").is_empty(),
        "control: a clean batch carries no errors: {v}"
    );
    assert_reconciles(&v);
}

/// An empty batch is a no-op success, not a degenerate 4xx.
#[tokio::test]
async fn bulk_empty_batch_is_200() {
    let (router, _db, _keep) = build_test_router();
    let (status, v) = post(&router, "/api/v1/memories/bulk", &json!([])).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["sent"], 0, "{v}");
    assert_reconciles(&v);
}

// ---------------------------------------------------------------------------
// #2594 — embedding.
// ---------------------------------------------------------------------------

/// PARENT: `grep -n "embedder" src/handlers/memories_query.rs` returned ONE
/// hit — a comment — so bulk rows carried no vector on either backend while
/// single-create embedded inline. This is a STRUCTURAL pin (the same evidence
/// shape the issue used): a hermetic test cannot construct a real `Embedder`,
/// which needs a model on disk, so the wiring is asserted at the source level
/// and its behaviour is covered by the live-postgres cell below plus the
/// `handlers::bulk` unit tests.
#[test]
fn bulk_write_funnel_embeds_2594() {
    // Locate the funnel by the HANDLER IT DEFINES, never by a fixed path: a
    // path-keyed assertion would silently start reading the post-fix file the
    // moment one exists, which is exactly how this cell first passed against
    // the parent tree.
    let handlers = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/handlers"));
    let mut funnel: Option<(String, String)> = None;
    for entry in std::fs::read_dir(handlers).expect("src/handlers") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read");
        if src.contains("pub async fn bulk_create(") {
            assert!(
                funnel.is_none(),
                "exactly one module may define the bulk write funnel"
            );
            funnel = Some((path.display().to_string(), src));
        }
    }
    let (path, src) = funnel.expect("`pub async fn bulk_create` must be defined somewhere");
    for needle in [
        // #2594 — the funnel must consult the embedder at all. At the parent
        // commit `grep -n embedder src/handlers/memories_query.rs` returned a
        // single hit, and it was a COMMENT.
        "app.embedder",
        // ...batch the vendor round trips rather than issue N single calls.
        "embed_batch",
        // ...and persist the vector on BOTH backends.
        "db::set_embedding",
        "set_embeddings_batch",
    ] {
        assert!(
            src.contains(needle),
            "#2594: the bulk write funnel ({path}) must reference `{needle}` — \
             bulk-ingested rows are otherwise invisible to semantic recall \
             until the paced backfill sweep reaches them, and in an MCP-stdio \
             or CLI-only topology that sweep never runs"
        );
    }
}

// ---------------------------------------------------------------------------
// #2550 (security half) — the #907 caller-claim refusal reaches bulk.
// ---------------------------------------------------------------------------

/// PARENT: the bulk branches built `metadata_stamped` by inserting the
/// resolved caller over whatever the row claimed, so a disagreeing
/// `agent_id` / `metadata.agent_id` was silently OVERWRITTEN. Single-create
/// has refused that with a 403 since #907. Silently discarding a caller's
/// stated identity is the same class as silently discarding their stated
/// `scope`, on the funnel's most security-relevant field.
///
/// Also pins the typed classification: the refusal is PERMANENT, so it must
/// not surface as the retryable `internal error` the substring classifier
/// would otherwise infer from `AGENT_ID_BODY_MISMATCH` prose.
#[tokio::test]
async fn bulk_refuses_disagreeing_agent_id_claim_2550() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "claim-2550";
    let mut body = row(ns, "claimed", "x");
    body["agent_id"] = json!("someone-else");
    let (status, v) = post(&router, "/api/v1/memories/bulk", &json!([body])).await;

    assert_eq!(db_row_count(&db_path, ns), 0, "the row must not land: {v}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#2550: a claim that disagrees with the authenticated caller is \
         refused, not silently rewritten: {v}"
    );
    let errors = v["errors"].as_array().expect("errors[]");
    assert_eq!(errors[0]["code"], "AGENT_ID_MISMATCH", "{v}");
    assert_eq!(
        errors[0]["error"], "forbidden",
        "#851: the wire label stays inside the sanitized allowlist: {v}"
    );
    assert_reconciles(&v);
}

/// #2588 — the total-rejection status tracks the CAUSE, it is not merely
/// "something that isn't 200".
///
/// Twin of `bulk_total_rejection_is_not_200_2588`, which drives the same
/// nothing-persisted path to a **429** via the quota. Here the only cause is
/// `validate_create`, so the dominant cause is `VALIDATION_FAILED` and the
/// status is **400** — byte-identical to what the SAME body gets from
/// single-create `POST /api/v1/memories`.
///
/// Pinned as its own cell because a single not-200 assertion would pass
/// against a handler that returned one blanket error status for every cause,
/// which is exactly the behaviour the retryable-first precedence exists to
/// prevent: a quota-throttled batch must be distinguishable from an
/// unfixable one, or a fleet loader cannot tell "back off" from "never retry".
#[tokio::test]
async fn bulk_total_rejection_status_tracks_the_cause_2588() {
    let (router, db_path, _keep) = build_test_router();
    let ns = "cause-2588";
    let batch = json!([row(ns, "", "x"), row(ns, "", "y")]); // empty titles
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;

    assert_eq!(db_row_count(&db_path, ns), 0, "nothing landed: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#2588: a batch rejected solely by validation reports 400, not the \
         429 its quota-rejected twin reports: {v}"
    );
    for e in v["errors"].as_array().expect("errors[]") {
        assert_eq!(e["code"], "VALIDATION_FAILED", "{v}");
    }
    assert_reconciles(&v);
}
