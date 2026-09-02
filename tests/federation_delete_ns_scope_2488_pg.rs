// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2488 (CWE-284, GA blocker) — POSTGRES twin of
//! `tests/federation_delete_ns_scope_2488.rs`.
//!
//! ## The exploit this file pins
//!
//! The #2447 postgres delete gate wrapped itself in
//! `receive_auth::inbound_write_needs_existing_namespace`, which is
//! `has_allowlist() && peer_declares_namespace_scope(...)`. That predicate is
//! documented in `receive_auth.rs` as a hot-path READ-ELISION optimisation, and
//! it returns FALSE for an enrolled peer whose `allowed_namespaces` is
//! empty/absent — which is a legal shape, because `PeerScope::allowed_namespaces`
//! is `#[serde(default)]`, so an operator who enrols a peer purely for
//! `allowed_sender_agent_ids` silently gets `[]`. In the WRITE lane a `false`
//! verdict still falls through to Layer 2 inside
//! `inbound_write_namespace_authorized`; in the DELETE lane it skipped ALL
//! checking, so `apply_remote_deletion` ran unguarded. Net: the peer that may
//! not write anywhere could still destroy anything, by id, on any
//! postgres-backed node.
//!
//! **The empty-scope shape is the whole point.** `set_scoped_posture` in
//! `tests/federation_write_ns_scope_2447_pg.rs` always writes a NON-EMPTY
//! `allowed_namespaces`, which arms Layer 1 and makes the elision predicate
//! true — which is exactly why the existing pg suite was green over this hole.
//! Every enrolled-unscoped test here therefore builds the allowlist by hand with
//! `allowed_namespaces` OMITTED.
//!
//! Row-state assertions go through a RAW `SELECT COUNT(*)` rather than
//! `MemoryStore::get`, for two reasons: `PostgresStore::get` folds a #910
//! visibility denial into `NotFound`, and — load-bearing for the last test here
//! — it fails CLOSED on a row whose at-rest envelope will not open, which is the
//! very condition under test.
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip (the house pattern). Deliberately NOT `#[ignore]`: the PR postgres
//! job does not pass `--include-ignored`, so an ignored test silently never runs.
//!
//! Design decided by the Fable 5 1×7 adversarial vote (`4d3ea1c5`), 7/7.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serialises every test in this binary — they all mutate the process-global
/// federation env vars, and cargo runs `#[tokio::test]`s concurrently.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";

/// RAII posture guard — an assertion panic must not leak an enrolled allowlist
/// into the next test in this binary (`clear_posture()` at the end of a test
/// body does not run on unwind).
struct PostureGuard;

impl Drop for PostureGuard {
    fn drop(&mut self) {
        clear_posture();
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

async fn pg_router(url: &str) -> (axum::Router, Arc<dyn MemoryStore>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        store: store.clone(),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Enrol `peer` with `allowed_sender_agent_ids` ONLY — `allowed_namespaces` is
/// OMITTED, so it silently becomes `[]`. THE #2488 shape. Never use a helper
/// that writes a non-empty scope here: that arms Layer 1 and is precisely how
/// this defect shipped with a green pg suite.
fn set_unscoped_posture(peer: &str, require_scope: Option<&str>) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(r#"{{"{peer}":{{"allowed_sender_agent_ids":["{peer}"]}}}}"#),
        );
        match require_scope {
            Some(v) => std::env::set_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                v,
            ),
            None => std::env::remove_var(
                ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            ),
        }
    }
}

/// Enrol `peer` scoped to `<public_ns_root>/*` ONLY — arms Layer 1.
fn set_scoped_posture(peer: &str, public_ns_root: &str) {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            format!(
                r#"{{"{peer}":{{"allowed_namespaces":["{public_ns_root}/*"],"allowed_sender_agent_ids":["{peer}"]}}}}"#
            ),
        );
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

/// The ZERO-CONFIG posture: no allowlist, and — critically — no
/// `AI_MEMORY_FED_SYNC_TRUST_PEER` (which `install_federation_legacy_bypass_pg`
/// sets, masking the refusal this guards against).
fn set_zero_config_posture() {
    unsafe {
        std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(SYNC_TRUST_PEER_ENV);
        std::env::remove_var(TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
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

/// Admin ctx — the TEST's own write, so seeding is not visibility-filtered.
fn admin_ctx() -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent("ai:test-2488-pg");
    ctx.bypass_visibility = true;
    ctx
}

async fn raw_pool(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("raw pool for row-state assertions")
}

/// PRIMARY assertion surface. Raw SQL on purpose: `MemoryStore::get` folds a
/// visibility denial into `NotFound` AND fails closed on an unopenable at-rest
/// envelope, so it cannot answer "does the row still exist" honestly for the
/// shapes under test here.
async fn row_exists(pool: &sqlx::PgPool, id: &str) -> bool {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM memories WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count row");
    n == 1
}

async fn seed_row(store: &Arc<dyn MemoryStore>, id: &str, namespace: &str, title: &str) {
    let victim = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "row the federated delete lane will target".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: json!({"agent_id": "ai:victim-2488"}),
        ..Default::default()
    };
    store
        .store(&admin_ctx(), &victim)
        .await
        .expect("seed victim row");
}

async fn push_deletions(
    router: &axum::Router,
    peer: &str,
    sender: &str,
    ids: &[&str],
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": ids,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            peer,
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

fn counter(report: &Value, key: &str) -> i64 {
    report.get(key).and_then(Value::as_i64).unwrap_or(-1)
}

/// #2497 — a deletions push carrying NO `X-Peer-Id` header at all.
async fn push_deletions_no_peer_header(router: &axum::Router, ids: &[&str]) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": "ai:anonymous-2497",
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": ids,
        "dry_run": false,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
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

// ---------------------------------------------------------------------
// R-203 #1 — THE #2488 EXPLOIT. pg x enrolled-unscoped x deletions.
// ---------------------------------------------------------------------

#[tokio::test]
async fn enrolled_unscoped_federated_deletion_refused_2488_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP enrolled_unscoped_federated_deletion_refused_2488_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let peer = uniq("ai:evil");
    let victim_ns = uniq("secure/ops");
    set_unscoped_posture(&peer, None);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let victim_id = uuid::Uuid::new_v4().to_string();
    seed_row(&store, &victim_id, &victim_ns, &uniq("delete-victim")).await;
    assert!(row_exists(&pool, &victim_id).await, "seed row must exist");

    // EXPLOIT: this peer's WRITES are refused by #2447 Layer 2 on both backends.
    // Pre-#2488 its DELETIONS were applied for any id, in any namespace, because
    // the gate was wrapped in the read-elision predicate that returns false for
    // exactly this shape.
    let (status, _report) = push_deletions(&router, &peer, &peer, &[&victim_id]).await;
    assert!(
        status.is_success(),
        "sync_push must not hard-error (per-item skip, batch survives); got {status}"
    );
    assert!(
        row_exists(&pool, &victim_id).await,
        "#2488: an ENROLLED peer that declares NO allowed_namespaces must NOT be \
         able to hard-delete a row by id on a postgres-backed node. A peer refused \
         every write must not retain unbounded destruction."
    );
}

// ---------------------------------------------------------------------
// R-203 #2 — the knob must be REACHABLE on this lane (pg).
// ---------------------------------------------------------------------

#[tokio::test]
async fn enrolled_unscoped_federated_deletion_applies_under_knob_off_2488_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP enrolled_unscoped_federated_deletion_applies_under_knob_off_2488_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let peer = uniq("ai:evil");
    let victim_ns = uniq("secure/ops");
    set_unscoped_posture(&peer, Some("0"));
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let victim_id = uuid::Uuid::new_v4().to_string();
    seed_row(&store, &victim_id, &victim_ns, &uniq("knob-off-victim")).await;

    let (status, report) = push_deletions(&router, &peer, &peer, &[&victim_id]).await;
    assert!(status.is_success());
    assert!(
        !row_exists(&pool, &victim_id).await,
        "#2488: AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0 must restore the \
         permissive posture for an unscoped enrolled peer on the DELETE lane too — \
         the fix honours env row 147 instead of hard-coding a disposition"
    );
    assert_eq!(counter(&report, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #3 — availability guard: the fix must not become an outage.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_federated_deletion_still_applies_2488_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP zero_config_federated_deletion_still_applies_2488_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let peer = uniq("ai:zeroconf");
    let ns = uniq("secure/ops");
    set_zero_config_posture();
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let id = uuid::Uuid::new_v4().to_string();
    seed_row(&store, &id, &ns, &uniq("zero-config-victim")).await;

    let (status, report) = push_deletions(&router, &peer, &peer, &[&id]).await;
    assert!(status.is_success());
    assert!(
        !row_exists(&pool, &id).await,
        "#2488: widening the gate to the ENROLLED posture must NOT black-hole \
         zero-config deletions — that would trade the #2488 confidentiality hole \
         for the #2491 permanent-divergence outage on the other backend"
    );
    assert_eq!(counter(&report, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #4 — enrolled-SCOPED controls (Layer 1), both directions.
// ---------------------------------------------------------------------

#[tokio::test]
async fn enrolled_scoped_federated_deletion_confinement_controls_2488_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP enrolled_scoped_federated_deletion_confinement_controls_2488_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    let victim_ns = uniq("secure/ops");
    set_scoped_posture(&peer, &public_root);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let victim_id = uuid::Uuid::new_v4().to_string();
    seed_row(&store, &victim_id, &victim_ns, &uniq("out-of-scope-victim")).await;
    let in_scope_id = uuid::Uuid::new_v4().to_string();
    let in_scope_ns = format!("{public_root}/ok");
    seed_row(&store, &in_scope_id, &in_scope_ns, &uniq("in-scope-target")).await;

    // OUT OF SCOPE — refused (the #1934 confinement, unchanged by #2488).
    let (status, _r) = push_deletions(&router, &peer, &peer, &[&victim_id]).await;
    assert!(status.is_success());
    assert!(
        row_exists(&pool, &victim_id).await,
        "#1934/#2488 (pg): a peer scoped to {public_root}/* must NOT hard-delete a \
         row in {victim_ns}"
    );

    // IN SCOPE — applied. The fix confines; it must not brick the peer.
    let (status2, report2) = push_deletions(&router, &peer, &peer, &[&in_scope_id]).await;
    assert!(status2.is_success());
    assert!(
        !row_exists(&pool, &in_scope_id).await,
        "#2488 (pg): an IN-SCOPE federated deletion must still be applied"
    );
    assert_eq!(counter(&report2, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #5 — the undecryptable-envelope row (pg). The cell that proves
// the scalar probe removed the permanent-erasure-denial trap.
// ---------------------------------------------------------------------

#[tokio::test]
async fn undecryptable_envelope_row_is_still_federated_deleted_2488_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP undecryptable_envelope_row_is_still_federated_deleted_2488_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let peer = uniq("ai:evil");
    let public_root = uniq("public");
    // Enrolled + SCOPED so Layer 1 is armed and the probe actually RUNS, with
    // the target IN SCOPE — so the ONLY thing that can refuse this deletion is
    // the probe itself.
    set_scoped_posture(&peer, &public_root);
    let (router, store) = pg_router(&url).await;
    let pool = raw_pool(&url).await;

    let id = uuid::Uuid::new_v4().to_string();
    let ns = format!("{public_root}/ok");
    seed_row(&store, &id, &ns, &uniq("undecryptable-target")).await;

    // Plant an envelope that cannot open under ANY key on this node (leading
    // scheme byte 0x00 is not a known envelope version), so the full-row mapper
    // returns Err under DecryptFailurePolicy::FailClosed — the exact shape a
    // rotated/lost keypair leaves behind in production.
    sqlx::query("UPDATE memories SET encrypted_envelope = $1 WHERE id = $2")
        .bind(vec![0_u8; 96])
        .bind(&id)
        .execute(&pool)
        .await
        .expect("plant an undecryptable envelope");

    let (status, report) = push_deletions(&router, &peer, &peer, &[&id]).await;
    assert!(status.is_success());
    assert!(
        !row_exists(&pool, &id).await,
        "#2488 (pg): a row whose at-rest envelope will not open on this node MUST \
         still be federated-deletable. Routing the namespace gate through \
         `MemoryStore::get` (SELECT * + row_to_memory pinned to FailClosed) turned \
         the gate's fail-closed arm into a PERMANENT erasure-denial primitive with \
         no operator escape hatch (AI_MEMORY_STRICT_DECRYPT_READS only hardens, \
         never relaxes) — behind an HTTP 200. The scalar `SELECT namespace` probe \
         cannot fail for the decrypt reason at all."
    );
    assert_eq!(
        counter(&report, "deleted"),
        1,
        "#2488 (pg): the undecryptable row must be COUNTED deleted, not skipped"
    );
}

// ---------------------------------------------------------------------
// R-203 #6 (#2497) — the shapes the KNOB MUST NEVER GOVERN (postgres).
//
// Postgres twin of the sqlite cells. On this backend the parent
// (`4f28f1d8`) ALSO allowed both shapes — `peer_declares_namespace_scope`
// is false for an unknown/absent peer, so the read-elision predicate
// skipped the whole gate — which makes these the #2488 fail-open for two
// MORE peer shapes, not only a #2497 regression. They must be refused
// UNCONDITIONALLY: the rollout knob governs only an ENROLLED peer that
// declared no allowed_namespaces.
// ---------------------------------------------------------------------

/// A peer id that is never enrolled by any posture helper in this file.
const UNKNOWN_PEER_ID: &str = "ai:unknown-2497";

#[tokio::test]
async fn unknown_peer_federated_deletion_refused_under_enrolled_posture_2497_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP unknown_peer_federated_deletion_refused_under_enrolled_posture_2497_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let enrolled = uniq("ai:enrolled");
    let public_root = uniq("public");
    let pool = raw_pool(&url).await;

    // PROBED (see the sqlite twin for the full note): the #1056 TOFU guard
    // lives in the SHARED outer `sync_push` entry, ahead of the postgres
    // dispatch, so a PRESENT-but-unlisted `x-peer-id` is refused with a typed
    // `401 x_peer_id_not_in_allowlist` on this backend too — it never reaches
    // the namespace gate. The gate's own refusal of this shape is
    // defence-in-depth, pinned purely by
    // `receive_auth::tests::inbound_by_id_verdict_option_contract_2488`.
    for knob in [None, Some("0")] {
        for scoped in [false, true] {
            if scoped {
                set_scoped_posture(&enrolled, &public_root);
                if let Some(v) = knob {
                    unsafe {
                        std::env::set_var(
                            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                            v,
                        );
                    }
                }
            } else {
                set_unscoped_posture(&enrolled, knob);
            }
            let (router, store) = pg_router(&url).await;
            let victim_ns = uniq("secure/ops");
            let victim_id = uuid::Uuid::new_v4().to_string();
            seed_row(&store, &victim_id, &victim_ns, &uniq("unknown-peer-victim")).await;

            let (status, _report) =
                push_deletions(&router, UNKNOWN_PEER_ID, UNKNOWN_PEER_ID, &[&victim_id]).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "#2497/#1056 (pg): a peer NOT in a non-empty allowlist must be refused \
                 LOUDLY at the shared envelope layer, independent of the \
                 namespace-scope rollout knob. scoped={scoped}, knob={knob:?}"
            );
            assert!(
                row_exists(&pool, &victim_id).await,
                "#2497 (pg): nothing is deleted when the envelope gate refuses the \
                 push. scoped={scoped}, knob={knob:?}"
            );
        }
    }
}

#[tokio::test]
async fn header_absent_federated_deletion_refused_under_enrolled_posture_2497_pg() {
    let Some(url) = pg_url() else {
        eprintln!(
            "SKIP header_absent_federated_deletion_refused_under_enrolled_posture_2497_pg: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let _g = FED_ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    let enrolled = uniq("ai:enrolled");
    let pool = raw_pool(&url).await;

    // Reachability needs both documented rollout hatches (see the sqlite twin).
    // AI_MEMORY_FED_SYNC_TRUST_PEER stays REMOVED (the posture helpers clear
    // it), so this is not the legacy bypass.
    for knob in [None, Some("0")] {
        set_unscoped_posture(&enrolled, knob);
        unsafe {
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
        }
        let (router, store) = pg_router(&url).await;
        let victim_ns = uniq("secure/ops");
        let victim_id = uuid::Uuid::new_v4().to_string();
        seed_row(&store, &victim_id, &victim_ns, &uniq("anonymous-victim")).await;

        let (status, report) = push_deletions_no_peer_header(&router, &[&victim_id]).await;
        assert!(
            status.is_success(),
            "the legacy header-absent opt-out lets the push reach the loops; \
             got {status} {report}"
        );
        assert!(
            row_exists(&pool, &victim_id).await,
            "#2497 (pg): an ANONYMOUS push (no x-peer-id) must NOT be able to \
             hard-delete by id on a node that declares a peer allowlist — \
             UNCONDITIONALLY, never widened by the rollout knob. \
             AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE={knob:?}"
        );
    }
}
