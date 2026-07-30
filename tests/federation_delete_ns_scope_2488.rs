// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2488 + #2491 — the federated DELETE lane's namespace confinement, on the
//! sqlite receive funnel (`handlers::federation_receive::sync_push`).
//!
//! Two defects, opposite directions, same two lines on the two backends:
//!
//! * **#2491 (sqlite, data-integrity):** the #1934 delete gate called
//!   `peer_attestation::namespace_allowed` UNCONDITIONALLY. Its
//!   `scope_for(peer) == None` arm falls through to `sync_trust_peer_bypass()`
//!   (default FALSE), so in the ZERO-CONFIG posture — and on any header-absent
//!   push — EVERY federated deletion was refused and counted `skipped` inside an
//!   HTTP 200. No DLQ, no retry: replicas diverged permanently while the origin
//!   believed the erasure had propagated.
//! * **#2488 (postgres, CWE-284):** the twin wrapped the whole gate in the
//!   read-ELISION predicate, making it unreachable for the enrolled-unscoped
//!   peer Layer 2 exists to refuse. Pinned in
//!   `tests/federation_delete_ns_scope_2488_pg.rs`.
//!
//! ## Why these tests build their OWN router (R-203, load-bearing)
//!
//! `tests/l07_3_chunk_d_http_surface.rs:2811 http_sync_push_with_deletions`
//! already asserts `deleted >= 1` on a zero-config sqlite push, and it is GREEN
//! over the broken lane — because `build_router_fixture` sets
//! `AI_MEMORY_FED_SYNC_TRUST_PEER=1`, which flips `sync_trust_peer_bypass()` and
//! papers over the refusal. `install_federation_legacy_bypass_pg` does the same
//! on the postgres side. A new zero-config test written against either fixture
//! passes BEFORE the fix and proves nothing. So this file builds a router with
//! NO `AI_MEMORY_FED_SYNC_TRUST_PEER` (mirroring
//! `tests/federation_write_ns_scope_2447.rs`), and every test here was confirmed
//! RED at the parent commit.
//!
//! Primary assertion is always DB ROW STATE (`SELECT ... FROM memories`), with
//! the response counter as a secondary: `skipped` increments for several
//! unrelated reasons (`validate_id` failure, `dry_run`, a pre-resolve error), so
//! `skipped >= 1` alone would not distinguish a scope refusal from a typo.
//!
//! Design decided by the Fable 5 1×7 adversarial vote (`4d3ea1c5`), 7/7.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars, so
/// they must not race each other. Mirrors `federation_write_ns_scope_2447.rs`.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";
const PEER_ID: &str = "ai:evil";
const VICTIM_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";

/// `ai:evil` may delete inside `public/*` only.
const SCOPED_ALLOWLIST: &str =
    r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The legal-but-unscoped shape: enrolled for the #238 sender attestation with
/// `allowed_namespaces` OMITTED (it is `#[serde(default)]`, so this silently
/// yields `[]`). Layer 2 governs this peer. NEVER use a scoped-posture helper
/// for the #2488 cell — a non-empty scope arms Layer 1 and is exactly how the
/// defect shipped untested.
const UNSCOPED_ALLOWLIST: &str = r#"{"ai:evil":{"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// RAII posture guard (#2482 analogue). The pre-existing federation tests clear
/// the process-global `AI_MEMORY_FED_*` env at the END of the test body — which
/// does NOT run when an assertion panics, leaking an enrolled allowlist into
/// whichever test in this binary runs next. `Drop` runs on unwind.
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

/// Seed the peer-attestation posture. `allowlist == None` = the ZERO-CONFIG
/// posture (env removed entirely). `AI_MEMORY_FED_SYNC_TRUST_PEER` is
/// deliberately NEVER set here — setting it is what made the pre-existing
/// zero-config coverage vacuous.
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
        // Belt-and-braces: if any earlier test in the process set either legacy
        // bypass, unset it — otherwise it would mask the very refusal under test.
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

/// Create a row through the normal HTTP write path and return its id.
async fn seed_row(router: &axum::Router, namespace: &str, title: &str) -> String {
    let create = json!({
        "title": title,
        "content": "row the federated delete lane will target",
        "tier": "long",
        "namespace": namespace,
        "tags": [],
        "priority": 5,
        "source": "api",
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

/// POST a deletions-only `/sync/push`. `peer` = `None` sends NO `X-Peer-Id`
/// header (the header-absent shape).
async fn push_deletions(
    router: &axum::Router,
    peer: Option<&str>,
    ids: &[&str],
) -> (StatusCode, Value) {
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "deletions": ids,
        "dry_run": false,
    });
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json");
    if let Some(p) = peer {
        builder = builder.header(ai_memory::federation::peer_attestation::PEER_ID_HEADER, p);
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, report)
}

/// The PRIMARY assertion surface: does the row still exist in `memories`?
async fn row_exists(db: &ai_memory::handlers::Db, id: &str) -> bool {
    let guard = db.lock().await;
    let n: i64 = guard
        .0
        .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap();
    n == 1
}

fn counter(report: &Value, key: &str) -> i64 {
    report.get(key).and_then(Value::as_i64).unwrap_or(-1)
}

// ---------------------------------------------------------------------
// R-203 #1 (#2491) — the live zero-config delete-replication outage.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_federated_deletion_applies_2491() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    // ZERO-CONFIG: no AI_MEMORY_FED_PEER_ATTESTATION and no
    // AI_MEMORY_FED_SYNC_TRUST_PEER. Pre-fix `namespace_allowed`'s
    // `scope_for == None` arm returned false here, so the deletion was refused
    // and the row survived forever on this replica.
    set_posture(None, None);
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, VICTIM_NS, "zero-config-delete-target").await;
    assert!(row_exists(&db, &id).await, "seed row must exist");

    let (status, report) = push_deletions(&router, Some(PEER_ID), &[&id]).await;
    assert!(
        status.is_success(),
        "#2491: sync_push must not hard-error; got {status}"
    );
    assert!(
        !row_exists(&db, &id).await,
        "#2491: a zero-config federated deletion MUST be applied — the row \
         surviving here is the live delete-replication outage (replicas diverge \
         permanently while the origin is told the erasure propagated)"
    );
    assert_eq!(
        counter(&report, "deleted"),
        1,
        "#2491: the receiver report must count the deletion (secondary to row state)"
    );
}

// ---------------------------------------------------------------------
// R-203 #2 (#2491) — header-absent disposition, asserted not incidental.
// ---------------------------------------------------------------------

#[tokio::test]
async fn header_absent_federated_deletion_disposition_2491() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(None, None);
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, VICTIM_NS, "header-absent-delete-target").await;

    // PART 1 — the disposition, asserted rather than assumed. #2491's body
    // treated the header-absent shape as an additional silently-lossy arm of
    // the namespace gate. It is not reachable there on this surface: the #238
    // envelope gate refuses a push with no `X-Peer-Id` *before* any
    // subcollection loop runs, with a typed 403 the SENDER can see and retry —
    // a loud refusal, not a 200-with-skipped. Pinning it so a future change
    // that moves the peer-id requirement cannot silently re-open a lossy arm.
    let (status, report) = push_deletions(&router, None, &[&id]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#2491: a header-absent /sync/push must be refused LOUDLY by the #238 \
         envelope gate, not silently discarded per-item; got {status} {report}"
    );
    assert!(
        row_exists(&db, &id).await,
        "#2491: nothing is applied when the envelope gate refuses the whole push"
    );

    // PART 2 — the one posture in which a header-absent push DOES reach the
    // subcollection loops: the documented legacy-peer opt-out. Zero-config +
    // no peer header is precisely the shape whose deletions were all silently
    // refused pre-fix (`namespace_allowed`'s header-absent arm falls through to
    // `sync_trust_peer_bypass()`, false by default).
    unsafe {
        std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
    }
    let (status2, report2) = push_deletions(&router, None, &[&id]).await;
    assert!(
        status2.is_success(),
        "the legacy opt-out must let the push through; got {status2} {report2}"
    );
    assert!(
        !row_exists(&db, &id).await,
        "#2491: under the legacy header-absent opt-out, a ZERO-CONFIG federated \
         deletion must be APPLIED — the ENROLLED posture is what arms the \
         namespace gate, never the presence of a header"
    );
    assert_eq!(counter(&report2, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #3 (#2488 Layer 2) — enrolled-unscoped, both dispositions.
// ---------------------------------------------------------------------

#[tokio::test]
async fn enrolled_unscoped_federated_deletion_refused_by_default_2488() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    // Layer 2, default ON: the operator enrolled this peer purely for
    // `allowed_sender_agent_ids`, so `allowed_namespaces` silently became `[]`.
    // Its read + write scopes are empty; its delete scope must be too.
    set_posture(Some(UNSCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, VICTIM_NS, "unscoped-refused-target").await;

    let (status, _report) = push_deletions(&router, Some(PEER_ID), &[&id]).await;
    assert!(status.is_success());
    assert!(
        row_exists(&db, &id).await,
        "#2488 Layer 2: an enrolled peer that declares no allowed_namespaces must \
         NOT be able to hard-delete by id"
    );
}

#[tokio::test]
async fn enrolled_unscoped_federated_deletion_applies_under_knob_off_2488() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    // The documented staged-rollout opt-out must be REACHABLE on this lane.
    // Pre-fix sqlite hard-coded deny-on-empty, so the knob was structurally
    // unreachable here and an operator had no rollout window at all.
    set_posture(Some(UNSCOPED_ALLOWLIST), Some("0"));
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, VICTIM_NS, "unscoped-knob-off-target").await;

    let (status, report) = push_deletions(&router, Some(PEER_ID), &[&id]).await;
    assert!(status.is_success());
    assert!(
        !row_exists(&db, &id).await,
        "#2488: AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0 must restore the \
         permissive posture on the DELETE lane, proving the knob is reachable here"
    );
    assert_eq!(counter(&report, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #4 — the enrolled-SCOPED controls (Layer 1) must stay green.
// ---------------------------------------------------------------------

#[tokio::test]
async fn enrolled_scoped_federated_deletion_confinement_controls_2488() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();

    let victim_id = seed_row(&router, VICTIM_NS, "scoped-out-of-scope-target").await;
    let in_scope_id = seed_row(&router, IN_SCOPE_NS, "scoped-in-scope-target").await;

    // OUT OF SCOPE — refused (the #1934 confinement, unchanged).
    let (status, _r) = push_deletions(&router, Some(PEER_ID), &[&victim_id]).await;
    assert!(status.is_success());
    assert!(
        row_exists(&db, &victim_id).await,
        "#1934/#2488: a peer scoped to public/* must NOT hard-delete a secure/ops row"
    );

    // IN SCOPE — applied. The fix confines; it must not brick the peer.
    let (status2, report2) = push_deletions(&router, Some(PEER_ID), &[&in_scope_id]).await;
    assert!(status2.is_success());
    assert!(
        !row_exists(&db, &in_scope_id).await,
        "#2488: an IN-SCOPE federated deletion must still be applied"
    );
    assert_eq!(counter(&report2, "deleted"), 1);
}

// ---------------------------------------------------------------------
// R-203 #5 — the undecryptable-envelope row. The cell that proves the
// scalar probe actually removed the permanent-erasure-denial trap.
// ---------------------------------------------------------------------

#[tokio::test]
async fn undecryptable_envelope_row_is_still_federated_deleted_2488() {
    let _g = ENV_LOCK.lock().await;
    let _posture = PostureGuard;
    // Enrolled + SCOPED so Layer 1 is armed and the probe actually RUNS — the
    // only posture in which the probe's failure mode is observable. The target
    // is IN SCOPE, so the only thing that can refuse it is the probe itself.
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();
    let id = seed_row(&router, IN_SCOPE_NS, "undecryptable-delete-target").await;

    // Plant an envelope that cannot open under ANY key on this node (leading
    // scheme byte 0x00 is not a known envelope version), so the full-row
    // `row_to_memory` decode returns Err under DecryptFailurePolicy::FailClosed
    // — the exact shape a rotated/lost keypair leaves behind in production.
    {
        let guard = db.lock().await;
        guard
            .0
            .execute(
                "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
                rusqlite::params![vec![0_u8; 96], &id],
            )
            .expect("plant an undecryptable envelope");
    }

    let (status, report) = push_deletions(&router, Some(PEER_ID), &[&id]).await;
    assert!(status.is_success());
    assert!(
        !row_exists(&db, &id).await,
        "#2488: a row whose at-rest envelope will not open on this node MUST still \
         be federated-deletable. Routing the namespace gate through `get` made the \
         gate's fail-closed arm a PERMANENT erasure-denial primitive with no \
         operator escape hatch (AI_MEMORY_STRICT_DECRYPT_READS only hardens) — the \
         row an operator most urgently wants gone was the one row made immortal, \
         behind an HTTP 200. The scalar `SELECT namespace` probe cannot fail for \
         the decrypt reason at all."
    );
    assert_eq!(
        counter(&report, "deleted"),
        1,
        "#2488: the undecryptable row must be COUNTED deleted, not skipped"
    );
}
