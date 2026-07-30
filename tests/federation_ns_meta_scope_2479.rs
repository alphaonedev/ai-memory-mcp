// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2479 (CWE-284) — namespace confinement for the federated GOVERNANCE-STANDARD
//! lanes (`/sync/push` `namespace_meta[]` + `namespace_meta_clears[]`) on the
//! sqlite receive funnel (`handlers::federation_receive::sync_push`).
//!
//! ## The hole
//!
//! Both loops validated `validate_namespace` / `validate_id` and NOTHING else,
//! then called `db::set_namespace_standard` / `db::clear_namespace_standard`.
//! Neither consulted the peer's `allowed_namespaces`. That is an authz-CONFIG
//! takeover, not a data write: the row selects the standard memory whose
//! `metadata.governance` `resolve_governance_policy` returns, so it rewrites the
//! rules every subsequent LOCAL write to that namespace is judged against — and
//! the `parent_namespace` field re-points which OTHER namespace's policy governs
//! by reference.
//!
//! ## Three traps these cells are shaped to avoid
//!
//! 1. **The tautology.** `set_namespace_standard` REFUSES when the `standard_id`
//!    memory does not exist locally (`MemoryNotFound`), and the loop counts that
//!    as `skipped` with `namespace_meta_applied == 0` — the exact observable a
//!    scope refusal produces. No single cell can tell them apart. The killer is
//!    a PAIRED pair of cells with an identical seed and a BYTE-IDENTICAL push
//!    body where only the allowlist differs
//!    (`exploit_set_rebinds_out_of_scope_victim_standard_2479` /
//!    `control_same_body_in_scope_applies_2479`); every exploit cell also
//!    positively asserts the standard memory EXISTS.
//! 2. **The declared-namespace-only fix.** A fix that gates only
//!    `entry.namespace` leaves `parent_namespace` — a persisted, chain-altering
//!    field — ungated.
//!    `exploit_parent_reparents_root_under_out_of_scope_namespace_2479` reds
//!    under that fix, and it asserts the RESOLVED POLICY, not just the stored
//!    column. It uses a SINGLE-SEGMENT namespace deliberately:
//!    `build_namespace_chain` consults the explicit parent only on the ROOT `/`
//!    segment of a queried namespace, so the same cell written against
//!    `public/x` would be VACUOUS — the column would be dead config. Do not
//!    "simplify" it to a nested namespace. Names are hyphen-free because
//!    `auto_detect_parent` splits on `-`.
//! 3. **The global standard.** `validate_namespace("*")` PASSES and
//!    `build_namespace_chain` prepends `*` to EVERY namespace's chain, while
//!    `glob_match("*", "*")` is `true` (a bare `*` pattern matches any
//!    single-segment target, and `"*"` has no `/`). So a peer scoped `["*"]` —
//!    documented as "any top-level namespace" — would reach the substrate-wide
//!    default policy for every DEEP namespace it may not write.
//!    `exploit_global_standard_refused_under_single_segment_scope_2479` pins the
//!    Amendment-E refusal; its `**` control pins that the deliberate allow-all
//!    still works.
//!
//! ## Why this file builds its OWN router (R-203, load-bearing)
//!
//! `build_router_fixture` in the shared HTTP-surface suite pre-sets
//! `AI_MEMORY_FED_SYNC_TRUST_PEER=1`, which flips `sync_trust_peer_bypass()` and
//! papers over exactly the refusals under test — that is how
//! `tests/l07_3_chunk_d_http_surface.rs` stayed green over the broken delete
//! lane until #2488. This file builds a router with that var explicitly REMOVED,
//! mirroring `tests/federation_delete_ns_scope_2488.rs` and
//! `tests/federation_pending_ns_scope_2478.rs`.
//!
//! Primary assertion is always DB ROW STATE (or the RESOLVED POLICY, which is
//! the thing an operator actually cares about), with response counters
//! secondary: `skipped` increments for several unrelated reasons.
//!
//! Design decided by the 5-agent adversarial vote (`4d3ea1c5`): B_UNION on
//! Borda + plurality, Amendment E unanimous 5/5.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:evil";
const VICTIM_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";

/// `ai:evil` may act inside `public/*` only.
const SCOPED_ALLOWLIST: &str =
    r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The CONTROL posture: the same peer, scoped to reach the victim namespace too.
const SCOPED_ALLOWLIST_WITH_VICTIM: &str = r#"{"ai:evil":{"allowed_namespaces":["public/*","secure/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// Root-namespace posture for the parent cell: the peer owns `alpha` but NOT the
/// namespace it tries to attach as `alpha`'s inheritance parent.
const SCOPED_ALLOWLIST_ROOT: &str =
    r#"{"ai:evil":{"allowed_namespaces":["alpha"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The control for the parent cell: both ends of the link are in scope.
const SCOPED_ALLOWLIST_ROOT_AND_PARENT: &str = r#"{"ai:evil":{"allowed_namespaces":["alpha","victim"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// Amendment E: `["*"]` reads as "any top-level namespace" but glob-matches the
/// literal global-standard key `*`.
const SCOPED_ALLOWLIST_SINGLE_STAR: &str =
    r#"{"ai:evil":{"allowed_namespaces":["*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The deliberate per-peer allow-all — the ONLY scope Amendment E admits for the
/// global standard.
const SCOPED_ALLOWLIST_DOUBLE_STAR: &str =
    r#"{"ai:evil":{"allowed_namespaces":["**"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// An ENROLLED peer that declares NO namespace scope at all — the ONE shape
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` (env row 147) governs.
const ENROLLED_UNSCOPED_ALLOWLIST: &str = r#"{"ai:evil":{"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// RAII posture guard — `Drop` runs on unwind, so a failing assertion cannot
/// leak an enrolled allowlist into the next test in this binary (#2482 shape).
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let path = std::path::PathBuf::from(":memory:");
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path,
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile for SqliteStore");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), db)
}

/// Seed the peer-attestation posture. `allowlist == None` = ZERO-CONFIG.
/// `AI_MEMORY_FED_SYNC_TRUST_PEER` is deliberately NEVER set and actively
/// removed — setting it is what makes federation coverage vacuous.
///
/// `require_scope` is pinned EXPLICITLY in every cell rather than left ambient:
/// otherwise a CI-wide value would silently decide the Layer-2 cells.
fn set_posture(allowlist: Option<&str>, require_scope: Option<&str>) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        match allowlist {
            Some(json) => std::env::set_var(
                ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
                json,
            ),
            None => {
                std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
            }
        }
        match require_scope {
            Some(v) => std::env::set_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                v,
            ),
            None => std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            ),
        }
        std::env::remove_var("AI_MEMORY_FED_SYNC_TRUST_PEER");
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
    }
}

/// Create a row through the normal HTTP write path and return its id. When
/// `governance` is `Some` the row is usable as a namespace STANDARD whose policy
/// `resolve_governance_policy` will return.
async fn seed_standard_memory(
    router: &axum::Router,
    namespace: &str,
    title: &str,
    governance: Option<Value>,
) -> String {
    let mut metadata = json!({});
    if let Some(gov) = governance {
        metadata[ai_memory::META_KEY_GOVERNANCE] = gov;
    }
    let create = json!({
        "title": title,
        "content": "namespace standard the federated governance lane will target",
        "tier": "long",
        "namespace": namespace,
        "tags": [],
        "priority": 5,
        "source": "api",
        "metadata": metadata,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", "ai:victim")
        .body(Body::from(create.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "seed write must succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    created["id"].as_str().expect("created id").to_string()
}

/// Bind a namespace standard LOCALLY (not over the wire), so the exploit cells
/// act against operator-authored state this node minted itself.
async fn bind_standard_locally(
    db: &ai_memory::handlers::Db,
    namespace: &str,
    standard_id: &str,
    parent: Option<&str>,
) {
    let guard = db.lock().await;
    ai_memory::db::set_namespace_standard(&guard.0, namespace, standard_id, parent)
        .expect("local bind must succeed");
}

async fn stored_standard(db: &ai_memory::handlers::Db, namespace: &str) -> Option<String> {
    let guard = db.lock().await;
    ai_memory::db::get_namespace_standard(&guard.0, namespace).expect("read standard")
}

async fn stored_parent(db: &ai_memory::handlers::Db, namespace: &str) -> Option<String> {
    let guard = db.lock().await;
    ai_memory::db::get_namespace_meta_entry(&guard.0, namespace)
        .expect("read meta row")
        .and_then(|row| row.parent_namespace)
}

/// The observable an operator actually cares about: which policy now governs.
async fn resolved_write_level(
    db: &ai_memory::handlers::Db,
    namespace: &str,
) -> Option<ai_memory::models::GovernanceLevel> {
    let guard = db.lock().await;
    ai_memory::db::resolve_governance_policy(&guard.0, namespace).map(|p| p.core.write)
}

async fn memory_exists(db: &ai_memory::handlers::Db, id: &str) -> bool {
    let guard = db.lock().await;
    ai_memory::db::get(&guard.0, id)
        .expect("get memory")
        .is_some()
}

/// One `namespace_meta[]` wire entry.
fn meta_entry(namespace: &str, standard_id: &str, parent: Option<&str>) -> Value {
    json!({
        "namespace": namespace,
        "standard_id": standard_id,
        "parent_namespace": parent,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    })
}

/// POST a `/sync/push` carrying the governance-standard subcollections.
async fn push_namespace_meta(
    router: &axum::Router,
    namespace_meta: Vec<Value>,
    clears: Vec<&str>,
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "namespace_meta": namespace_meta,
        "namespace_meta_clears": clears,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

/// The `/sync/push` counters are TOP-LEVEL keys of the 200 envelope (the sibling
/// `"applied"` key is the memories counter, not a nested object).
fn counter(report: &Value, key: &str) -> u64 {
    report[key]
        .as_u64()
        .unwrap_or_else(|| panic!("counter {key} missing from response: {report}"))
}

// ---------------------------------------------------------------------------
// EXPLOIT — the `namespace_meta[]` bind against a FOREIGN namespace.
// ---------------------------------------------------------------------------

/// A `public/*`-scoped peer must not rebind `secure/ops`'s governance standard.
///
/// REDS at the parent: the pre-fix loop consults no scope at all, so the victim
/// namespace's standard is silently re-pointed at the peer's own memory and
/// every subsequent local write to `secure/ops` is judged by the peer's policy.
#[tokio::test]
async fn exploit_set_rebinds_out_of_scope_victim_standard_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), Some("1"));
    let (router, db) = build_router_with_db();

    let victim_standard = seed_standard_memory(&router, VICTIM_NS, "victim standard", None).await;
    let evil_standard = seed_standard_memory(&router, IN_SCOPE_NS, "evil standard", None).await;
    bind_standard_locally(&db, VICTIM_NS, &victim_standard, None).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry(VICTIM_NS, &evil_standard, None)],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "per-entry skip, batch survives");

    // Excludes the tautology: the refusal cannot be `MemoryNotFound`.
    assert!(
        memory_exists(&db, &evil_standard).await,
        "the standard memory MUST exist locally, else this cell proves nothing"
    );
    // PRIMARY — DB row state.
    assert_eq!(
        stored_standard(&db, VICTIM_NS).await.as_deref(),
        Some(victim_standard.as_str()),
        "the victim namespace's standard must be UNCHANGED: {report}"
    );
    // Secondary — counters.
    assert_eq!(counter(&report, "namespace_meta_applied"), 0, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 1, "{report}");
}

/// CONTROL, byte-identical body + seed — only the allowlist differs. This is
/// what makes the exploit cell non-tautological: a `MemoryNotFound` refusal
/// would red HERE too.
#[tokio::test]
async fn control_same_body_in_scope_applies_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_WITH_VICTIM), Some("1"));
    let (router, db) = build_router_with_db();

    let victim_standard = seed_standard_memory(&router, VICTIM_NS, "victim standard", None).await;
    let evil_standard = seed_standard_memory(&router, IN_SCOPE_NS, "evil standard", None).await;
    bind_standard_locally(&db, VICTIM_NS, &victim_standard, None).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry(VICTIM_NS, &evil_standard, None)],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        stored_standard(&db, VICTIM_NS).await.as_deref(),
        Some(evil_standard.as_str()),
        "an IN-SCOPE bind must still apply: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 1, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 0, "{report}");
}

// ---------------------------------------------------------------------------
// EXPLOIT — the DESTRUCTIVE `namespace_meta_clears[]` twin.
// ---------------------------------------------------------------------------

/// Clearing DISARMS a namespace (absent policy resolves permissive), and the
/// lane carries no `standard_id` at all — so it has zero tautology surface and
/// is the purest cell in this file.
#[tokio::test]
async fn exploit_clear_disarms_out_of_scope_victim_standard_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), Some("1"));
    let (router, db) = build_router_with_db();

    let victim_standard = seed_standard_memory(
        &router,
        VICTIM_NS,
        "victim standard",
        Some(json!({"write": "owner"})),
    )
    .await;
    bind_standard_locally(&db, VICTIM_NS, &victim_standard, None).await;
    assert_eq!(
        resolved_write_level(&db, VICTIM_NS).await,
        Some(ai_memory::models::GovernanceLevel::Owner),
        "precondition: the victim namespace IS governed before the push"
    );

    let (status, report) = push_namespace_meta(&router, vec![], vec![VICTIM_NS]).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        stored_standard(&db, VICTIM_NS).await.as_deref(),
        Some(victim_standard.as_str()),
        "the victim namespace's standard must SURVIVE: {report}"
    );
    assert_eq!(
        resolved_write_level(&db, VICTIM_NS).await,
        Some(ai_memory::models::GovernanceLevel::Owner),
        "governance must not have been disarmed: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_cleared"), 0, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 1, "{report}");
}

/// CONTROL — the same clear from a peer scoped to reach the namespace.
#[tokio::test]
async fn control_clear_in_scope_still_clears_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_WITH_VICTIM), Some("1"));
    let (router, db) = build_router_with_db();

    let victim_standard = seed_standard_memory(&router, VICTIM_NS, "victim standard", None).await;
    bind_standard_locally(&db, VICTIM_NS, &victim_standard, None).await;

    let (status, report) = push_namespace_meta(&router, vec![], vec![VICTIM_NS]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        stored_standard(&db, VICTIM_NS).await.is_none(),
        "an IN-SCOPE clear must still apply: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_cleared"), 1, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 0, "{report}");
}

// ---------------------------------------------------------------------------
// EXPLOIT — the `parent_namespace` field (the option-A killer).
// ---------------------------------------------------------------------------

/// A peer that owns the ROOT namespace `alpha` must not splice an out-of-scope
/// namespace into `alpha`'s inheritance chain.
///
/// This is the cell a declared-namespace-only fix FAILS: `alpha` itself is in
/// scope, so such a fix applies the row, and the assertion below then observes
/// `victim`'s permissive policy displacing the restrictive global standard for
/// every `alpha/**` write. It asserts the RESOLVED POLICY, not merely the stored
/// column, so it cannot be satisfied by writing the row and calling it confined.
#[tokio::test]
async fn exploit_parent_reparents_root_under_out_of_scope_namespace_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_ROOT), Some("1"));
    let (router, db) = build_router_with_db();

    // The restrictive substrate-wide default the peer wants out of its way.
    let global_standard = seed_standard_memory(
        &router,
        "alpha",
        "global standard",
        Some(json!({"write": "owner"})),
    )
    .await;
    bind_standard_locally(&db, "*", &global_standard, None).await;
    // A permissive policy living in a namespace the peer may NOT act in.
    let victim_standard = seed_standard_memory(
        &router,
        "victim",
        "permissive standard",
        Some(json!({"write": "any"})),
    )
    .await;
    bind_standard_locally(&db, "victim", &victim_standard, None).await;
    // The peer's own standard carries NO governance blob, so the chain walk
    // falls THROUGH it — which is what makes the parent link load-bearing.
    let plain_standard = seed_standard_memory(&router, "alpha", "plain standard", None).await;

    assert_eq!(
        resolved_write_level(&db, "alpha/sub").await,
        Some(ai_memory::models::GovernanceLevel::Owner),
        "precondition: the global standard governs alpha/sub"
    );

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry("alpha", &plain_standard, Some("victim"))],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        memory_exists(&db, &plain_standard).await,
        "the standard memory MUST exist locally, else this cell proves nothing"
    );
    // PRIMARY — the resolved policy is unchanged.
    assert_eq!(
        resolved_write_level(&db, "alpha/sub").await,
        Some(ai_memory::models::GovernanceLevel::Owner),
        "the out-of-scope parent must NOT have displaced the global standard: {report}"
    );
    assert!(
        stored_standard(&db, "alpha").await.is_none(),
        "the whole entry is refused — never partially applied with the parent stripped: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_refused"), 1, "{report}");
}

/// CONTROL — both ends of the link in scope: the parent applies AND takes effect.
/// This also proves the exploit cell is not vacuous, i.e. that the parent field
/// really does move the resolved policy on a ROOT namespace.
#[tokio::test]
async fn control_parent_in_scope_applies_and_takes_effect_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_ROOT_AND_PARENT), Some("1"));
    let (router, db) = build_router_with_db();

    let global_standard = seed_standard_memory(
        &router,
        "alpha",
        "global standard",
        Some(json!({"write": "owner"})),
    )
    .await;
    bind_standard_locally(&db, "*", &global_standard, None).await;
    let victim_standard = seed_standard_memory(
        &router,
        "victim",
        "permissive standard",
        Some(json!({"write": "any"})),
    )
    .await;
    bind_standard_locally(&db, "victim", &victim_standard, None).await;
    let plain_standard = seed_standard_memory(&router, "alpha", "plain standard", None).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry("alpha", &plain_standard, Some("victim"))],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        stored_parent(&db, "alpha").await.as_deref(),
        Some("victim"),
        "an IN-SCOPE parent must be persisted: {report}"
    );
    assert_eq!(
        resolved_write_level(&db, "alpha/sub").await,
        Some(ai_memory::models::GovernanceLevel::Any),
        "and must actually move the resolved policy — otherwise the exploit cell \
         above is vacuous: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 1, "{report}");
}

// ---------------------------------------------------------------------------
// AMENDMENT E — the global `*` standard.
// ---------------------------------------------------------------------------

/// `allowed_namespaces: ["*"]` reads as "any top-level namespace", and
/// `glob_match("*", "*")` is `true` — so without Amendment E that scope also
/// grants the substrate-wide default policy for every DEEP namespace the peer
/// may not write. Both lanes must refuse, UNCONDITIONALLY (knob 147 pinned OFF
/// here to prove the refusal does not ride the rollout hatch).
#[tokio::test]
async fn exploit_global_standard_refused_under_single_segment_scope_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_SINGLE_STAR), Some("0"));
    let (router, db) = build_router_with_db();

    let global_standard = seed_standard_memory(
        &router,
        "alpha",
        "global standard",
        Some(json!({"write": "owner"})),
    )
    .await;
    bind_standard_locally(&db, "*", &global_standard, None).await;
    let evil_standard = seed_standard_memory(
        &router,
        "alpha",
        "evil standard",
        Some(json!({"write": "any"})),
    )
    .await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![meta_entry("*", &evil_standard, None)],
        vec!["*"],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(memory_exists(&db, &evil_standard).await);
    assert_eq!(
        stored_standard(&db, "*").await.as_deref(),
        Some(global_standard.as_str()),
        "the global standard must be neither rebound nor cleared: {report}"
    );
    assert_eq!(
        resolved_write_level(&db, "deep/unrelated/ns").await,
        Some(ai_memory::models::GovernanceLevel::Owner),
        "the substrate-wide default must still govern a namespace the peer \
         cannot write: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 0, "{report}");
    assert_eq!(counter(&report, "namespace_meta_cleared"), 0, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 2, "{report}");
}

/// CONTROL — the DELIBERATE per-peer allow-all `**` still reaches the global
/// standard. Amendment E must narrow one scope string, not brick the feature.
#[tokio::test]
async fn control_global_standard_allowed_under_double_star_scope_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST_DOUBLE_STAR), Some("1"));
    let (router, db) = build_router_with_db();

    let evil_standard = seed_standard_memory(&router, "alpha", "evil standard", None).await;

    let (status, report) =
        push_namespace_meta(&router, vec![meta_entry("*", &evil_standard, None)], vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        stored_standard(&db, "*").await.as_deref(),
        Some(evil_standard.as_str()),
        "an allow-all peer must still be able to set the global standard: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 1, "{report}");
}

// ---------------------------------------------------------------------------
// CONTROLS — zero-config, Layer 2, batch survival.
// ---------------------------------------------------------------------------

/// ZERO-CONFIG must stay BYTE-IDENTICAL: with no `AI_MEMORY_FED_PEER_ATTESTATION`
/// the whole gate short-circuits, and every body the cells above refuse applies.
/// This is the #2491 silent-outage control — the delete lane went dark because a
/// gate ran unconditionally.
#[tokio::test]
async fn zero_config_replication_is_byte_identical_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(None, Some("1"));
    let (router, db) = build_router_with_db();

    let victim_standard = seed_standard_memory(&router, VICTIM_NS, "victim standard", None).await;
    let evil_standard = seed_standard_memory(&router, IN_SCOPE_NS, "evil standard", None).await;
    let global_standard = seed_standard_memory(&router, "alpha", "global standard", None).await;
    bind_standard_locally(&db, VICTIM_NS, &victim_standard, None).await;
    let doomed = seed_standard_memory(&router, "alpha", "doomed standard", None).await;
    bind_standard_locally(&db, "beta", &doomed, None).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![
            meta_entry(VICTIM_NS, &evil_standard, None),
            meta_entry("*", &global_standard, None),
            meta_entry("alpha", &evil_standard, Some("victim")),
        ],
        vec!["beta"],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        stored_standard(&db, VICTIM_NS).await.as_deref(),
        Some(evil_standard.as_str()),
        "zero-config must keep applying: {report}"
    );
    assert_eq!(
        stored_standard(&db, "*").await.as_deref(),
        Some(global_standard.as_str()),
        "zero-config must keep applying to the global standard: {report}"
    );
    assert_eq!(stored_parent(&db, "alpha").await.as_deref(), Some("victim"));
    assert!(
        stored_standard(&db, "beta").await.is_none(),
        "clear applied"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 3, "{report}");
    assert_eq!(counter(&report, "namespace_meta_cleared"), 1, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 0, "{report}");
}

/// LAYER 2 — an ENROLLED peer that declares NO scope is the ONE shape env row
/// 147 governs, and this lane must honour it exactly like every sibling lane
/// rather than hard-coding a verdict.
#[tokio::test]
async fn enrolled_unscoped_peer_honours_knob_147_2479() {
    for (knob, expect_applied) in [("1", 0u64), ("0", 1u64)] {
        let _lock = ENV_LOCK.lock().await;
        let _guard = PostureGuard;
        set_posture(Some(ENROLLED_UNSCOPED_ALLOWLIST), Some(knob));
        let (router, db) = build_router_with_db();

        let evil_standard = seed_standard_memory(&router, IN_SCOPE_NS, "evil standard", None).await;
        let (status, report) = push_namespace_meta(
            &router,
            vec![meta_entry(VICTIM_NS, &evil_standard, None)],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            counter(&report, "namespace_meta_applied"),
            expect_applied,
            "knob={knob}: {report}"
        );
        assert_eq!(
            stored_standard(&db, VICTIM_NS).await.is_some(),
            expect_applied == 1,
            "knob={knob}: row state must match the counter: {report}"
        );
    }
}

/// BATCH SURVIVAL — a refusal is a PER-ENTRY skip. An in-scope entry sharing the
/// request with a refused one must still apply, so no cell above can be green
/// merely because the whole push 4xx'd.
#[tokio::test]
async fn refusal_is_per_entry_and_batch_survives_2479() {
    let _lock = ENV_LOCK.lock().await;
    let _guard = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), Some("1"));
    let (router, db) = build_router_with_db();

    let evil_standard = seed_standard_memory(&router, IN_SCOPE_NS, "evil standard", None).await;

    let (status, report) = push_namespace_meta(
        &router,
        vec![
            meta_entry(VICTIM_NS, &evil_standard, None),
            meta_entry(IN_SCOPE_NS, &evil_standard, None),
        ],
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "never a whole-request refusal");
    assert!(
        stored_standard(&db, VICTIM_NS).await.is_none(),
        "out-of-scope entry refused: {report}"
    );
    assert_eq!(
        stored_standard(&db, IN_SCOPE_NS).await.as_deref(),
        Some(evil_standard.as_str()),
        "in-scope sibling entry in the SAME request must still apply: {report}"
    );
    assert_eq!(counter(&report, "namespace_meta_applied"), 1, "{report}");
    assert_eq!(counter(&report, "namespace_meta_refused"), 1, "{report}");
}
