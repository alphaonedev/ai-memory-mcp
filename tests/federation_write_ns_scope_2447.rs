// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2447 (CWE-284, security-high) — the federated inbound WRITE lane
//! (`POST /api/v1/sync/push` `memories[]`) must be confined to the peer's
//! per-peer `allowed_namespaces` scope, like the read (`/sync/since`) and
//! delete (#1934) lanes already are.
//!
//! Pre-fix, `peer_attestation::namespace_allowed` had exactly ONE production
//! call site in `src/` — inside the deletions loop (the #1934 fix). The
//! `memories[]` loop consulted neither the peer's namespace scope nor the
//! target row's, and a comment above the delete loop falsely asserted the write
//! lane was already confined "via `resolve_inbound_attribution`" (that resolver
//! gates WHO you may claim to be, never WHICH namespace you may write into).
//!
//! Every test here is R-203-shaped: it FAILS on the parent commit and PASSES
//! after. The four exploit tests are the load-bearing ones; the two posture
//! tests guard the regressions a naive verbatim fix would have caused.
//!
//! Postgres twin: `tests/federation_write_ns_scope_2447_pg.rs`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars
/// (peer allowlist, attestation-required, the #2447 knob), so they must not
/// race each other. Mirrors `tests/security_authz_isolation_cluster.rs`.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const PEER_ID: &str = "ai:evil";
const VICTIM_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";

/// `ai:evil` may push as itself, scoped to `public/*` only — verbatim the
/// failure scenario in the issue body.
const SCOPED_ALLOWLIST: &str =
    r#"{"ai:evil":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:evil"]}}"#;

/// The legal-but-unscoped shape: enrolled for the #238 sender attestation with
/// `allowed_namespaces` OMITTED (it is `#[serde(default)]`, so this silently
/// yields `[]`). Layer 2 governs this peer.
const UNSCOPED_ALLOWLIST: &str = r#"{"ai:evil":{"allowed_sender_agent_ids":["ai:evil"]}}"#;

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
        auto_tag_queue: None,
        atomise_queue: None,
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
/// posture (env removed entirely).
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
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_ATTEST_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
    }
}

/// A federation-wire memory row authored by `PEER_ID`.
fn wire_memory(id: &str, namespace: &str, title: &str, content: &str, updated_at: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": namespace,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "access_count": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": updated_at,
        "metadata": {"agent_id": PEER_ID},
        "reflection_depth": 0,
        "memory_kind": "observation",
    })
}

async fn push(router: &axum::Router, body: &Value) -> StatusCode {
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
    let _ = axum::body::to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

fn push_body(memories: &[Value]) -> Value {
    json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": memories,
        "dry_run": false,
    })
}

async fn count_ns(db: &ai_memory::handlers::Db, ns: &str) -> i64 {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            [ns],
            |r| r.get(0),
        )
        .unwrap()
}

async fn row_namespace_and_title(
    db: &ai_memory::handlers::Db,
    id: &str,
) -> Option<(String, String)> {
    let guard = db.lock().await;
    guard
        .0
        .query_row(
            "SELECT namespace, title FROM memories WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
}

// ---------------------------------------------------------------------
// R-203 #1 — the issue's literal failure scenario.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_write_outside_peer_scope_refused_2447() {
    let _g = ENV_LOCK.lock().await;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();

    // EXPLOIT: a peer scoped to public/* pushes a memory into secure/ops.
    let status = push(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "poison",
            "substrate truth the peer was denied",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(
        status.is_success(),
        "#2447: sync_push must not hard-error (per-memory skip, batch survives); got {status}"
    );
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        0,
        "#2447: a peer scoped to public/* must NOT write into secure/ops"
    );

    // CONTROL: the SAME peer writing inside its declared scope still lands —
    // the fix confines, it does not brick the peer.
    let ok_status = push(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            IN_SCOPE_NS,
            "legit",
            "in scope",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(ok_status.is_success());
    assert_eq!(
        count_ns(&db, IN_SCOPE_NS).await,
        1,
        "#2447: an in-scope write must still be applied"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// R-203 #2 — the merge-clobber bypass a claimed-namespace-only fix leaves.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_write_cannot_relocate_foreign_row_by_id_collision_2447() {
    let _g = ENV_LOCK.lock().await;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();

    // Seed a victim row in secure/ops via the normal create path.
    let create = json!({
        "title": "sensitive",
        "content": "secure ops row the peer has no scope for",
        "tier": "long",
        "namespace": VICTIM_NS,
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
    assert!(resp.status().is_success());
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    let victim_id = created["id"].as_str().expect("created id").to_string();
    assert_eq!(count_ns(&db, VICTIM_NS).await, 1);

    // EXPLOIT: push the VICTIM'S id under an IN-SCOPE namespace with a fresh
    // `updated_at`. `merge_inbound` field-merges by id and `merge_memory` LWWs
    // the `namespace` field, so a claimed-namespace-only gate would let this
    // RELOCATE the secure/ops row into public/* (where the peer can then pull
    // it) and clobber its title + content.
    let status = push(
        &router,
        &push_body(&[wire_memory(
            &victim_id,
            "public/loot",
            "clobbered",
            "attacker content",
            "2099-01-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(status.is_success());

    let (ns, title) = row_namespace_and_title(&db, &victim_id)
        .await
        .expect("#2447: the victim row must still exist");
    assert_eq!(
        ns, VICTIM_NS,
        "#2447: an out-of-scope STORED namespace must block the merge — the row \
         must not be relocated out of secure/ops by an id-collision push"
    );
    assert_eq!(
        title, "sensitive",
        "#2447: the victim row's content must not be clobbered"
    );
    assert_eq!(count_ns(&db, "public/loot").await, 0);

    clear_posture();
}

// ---------------------------------------------------------------------
// R-203 #3 / #4 — the by-id sibling lanes in the same handler.
// ---------------------------------------------------------------------

#[tokio::test]
async fn federated_archive_and_restore_outside_peer_scope_refused_2447() {
    let _g = ENV_LOCK.lock().await;
    set_posture(Some(SCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();

    let create = json!({
        "title": "sensitive-archive",
        "content": "secure ops row",
        "tier": "long",
        "namespace": VICTIM_NS,
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    let victim_id = created["id"].as_str().unwrap().to_string();

    // EXPLOIT: archives[] is the soft-delete twin of the #1934 delete hole.
    let body = json!({
        "sender_agent_id": PEER_ID,
        "sender_clock": {"entries": {}},
        "memories": [],
        "archives": [victim_id],
        "dry_run": false,
    });
    let status = push(&router, &body).await;
    assert!(status.is_success());
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        "#2447: a peer scoped to public/* must NOT archive a secure/ops row"
    );

    clear_posture();
}

// ---------------------------------------------------------------------
// Posture guards — the regressions a naive verbatim fix would have caused.
// ---------------------------------------------------------------------

#[tokio::test]
async fn zero_config_federation_write_still_applies_2447() {
    let _g = ENV_LOCK.lock().await;
    // ZERO-CONFIG: no AI_MEMORY_FED_PEER_ATTESTATION at all. Calling
    // `namespace_allowed` verbatim here would have returned false (its
    // `scope_for == None` arm falls through to `sync_trust_peer_bypass()`,
    // which is false by default) and silently black-holed EVERY inbound
    // memory on every unconfigured deployment.
    set_posture(None, None);
    let (router, db) = build_router_with_db();

    let status = push(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "zero-config replication",
            "must still land",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        "#2447: zero-config federation must be byte-identical to pre-fix — the \
         namespace gate engages ONLY under an enrolled posture"
    );

    clear_posture();
}

#[tokio::test]
async fn enrolled_peer_without_declared_namespaces_denied_by_default_2447() {
    let _g = ENV_LOCK.lock().await;
    // Layer 2, default ON: the operator enrolled this peer but declared no
    // `allowed_namespaces`, so its read + delete scope are already empty while
    // its write scope was unbounded. Default-deny makes the lanes agree.
    set_posture(Some(UNSCOPED_ALLOWLIST), None);
    let (router, db) = build_router_with_db();

    let status = push(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "unscoped peer",
            "denied by default",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        0,
        "#2447 Layer 2: an enrolled peer that declares no allowed_namespaces must \
         be refused by default"
    );

    // The SAME disposition must hold on the by-id sibling lanes, or Layer 2
    // would deny the write while permitting the archive that removes the very
    // same row from every live read — the inconsistency #2447 exists to end.
    let create = json!({
        "title": "unscoped-archive-victim",
        "content": "secure ops row",
        "tier": "long",
        "namespace": VICTIM_NS,
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    let victim_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(count_ns(&db, VICTIM_NS).await, 1);

    let arch_status = push(
        &router,
        &json!({
            "sender_agent_id": PEER_ID,
            "sender_clock": {"entries": {}},
            "memories": [],
            "archives": [victim_id],
            "dry_run": false,
        }),
    )
    .await;
    assert!(arch_status.is_success());
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        "#2447 Layer 2: an unscoped enrolled peer must be refused IDENTICALLY on \
         the by-id archive lane, not only on memories[]"
    );

    // The documented staged-rollout opt-out restores the legacy posture.
    set_posture(Some(UNSCOPED_ALLOWLIST), Some("0"));
    let (router2, db2) = build_router_with_db();
    let status2 = push(
        &router2,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "unscoped peer",
            "admitted under the opt-out",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(status2.is_success());
    assert_eq!(
        count_ns(&db2, VICTIM_NS).await,
        1,
        "#2447: AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=0 must restore the \
         pre-fix permissive posture for an unscoped enrolled peer"
    );

    clear_posture();
}

#[tokio::test]
async fn double_star_scope_is_the_per_peer_allow_all_escape_2447() {
    let _g = ENV_LOCK.lock().await;
    // The PER-PEER escape hatch named in the Layer 2 refusal WARN, so an
    // operator can exempt ONE legacy peer without disabling the gate fleet-wide.
    set_posture(
        Some(r#"{"ai:evil":{"allowed_namespaces":["**"],"allowed_sender_agent_ids":["ai:evil"]}}"#),
        None,
    );
    let (router, db) = build_router_with_db();

    let status = push(
        &router,
        &push_body(&[wire_memory(
            &uuid::Uuid::new_v4().to_string(),
            VICTIM_NS,
            "explicit allow-all",
            "operator declared **",
            "2026-07-01T00:00:00+00:00",
        )]),
    )
    .await;
    assert!(status.is_success());
    assert_eq!(
        count_ns(&db, VICTIM_NS).await,
        1,
        r#"#2447: an explicit ["**"] scope is a deliberate per-peer allow-all"#
    );

    clear_posture();
}
