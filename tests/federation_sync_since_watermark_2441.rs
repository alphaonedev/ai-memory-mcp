// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

//! #2441 (federation liveness / data-integrity) — the `/sync/since`
//! anti-entropy cursor must advance on rows the server EXAMINED, never on
//! rows it PROJECTED.
//!
//! ## The defect
//!
//! `src/handlers/federation_sync_since.rs` sends the page `LIMIT` to SQL,
//! then runs the per-peer namespace allowlist and the `scope=private`
//! visibility filter IN MEMORY, AFTER it. Pre-#2441 the response's only
//! cursor-shaped field (`latest_updated_at`) — and the server's own durable
//! `sync_state_observe` clock entry — were derived from the POST-filter
//! vector. A window composed entirely of out-of-scope rows therefore
//! answered `count: 0`, `latest_updated_at: null`, HTTP 200. The puller
//! (`daemon_runtime::sync_cycle_once`, which derived its next `since` from
//! `pulled.memories.last()`) got no new cursor, re-requested the identical
//! window forever, and never converged — permanent, silent, unbounded
//! replica divergence that reads as healthy on every observable signal.
//!
//! ## R-203
//!
//! Parent commit: `03bbd556`. Every test tagged `R-203` below FAILS there —
//! `v["next_since"]` is `Value::Null` (the field does not exist), so the
//! cursor cannot move and `drive_pull_to_convergence` exhausts its
//! iteration budget without reaching the newest row. Observed failure at
//! the parent:
//!
//! ```text
//! thread 'cursor_advances_when_every_row_is_out_of_scope_2441' panicked:
//!   #2441: a fully-filtered window MUST still publish a cursor; got null
//!   (count=0, excluded_for_scope=3) — the puller re-requests this window
//!   forever
//! ```
//!
//! ## Why this file builds its OWN router
//!
//! The shared `build_router_fixture` sets `AI_MEMORY_FED_SYNC_TRUST_PEER=1`,
//! which resolves `allow_all_legacy` and makes the namespace + visibility
//! filters no-ops — over which the broken cursor is invisible. Mirrors the
//! same reasoning in `tests/federation_write_ns_scope_2447.rs` and
//! `tests/federation_delete_ns_scope_2488.rs`.
//!
//! Tie-group guard (`cursor_holds_rather_than_skipping_a_cut_tie_group_2441`)
//! is NOT R-203-shaped — it passes at the parent for the wrong reason (a
//! null cursor never skips anything). It exists to block the naive fix
//! (`examined.last()`), which WOULD silently drop rows sharing the boundary
//! timestamp under the strict `updated_at > since` predicate.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

/// Process-global async mutex — these tests mutate process-wide env vars,
/// so they must not race each other.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const REQUIRE_SIG_ENV: &str = "AI_MEMORY_FED_REQUIRE_SIG";
const REQUIRE_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";
const TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";

const PEER_ID: &str = "ai:puller";
/// Namespace the peer is NOT scoped for — the rows that get filtered out
/// AFTER the SQL `LIMIT` has already been spent on them.
const OUT_OF_SCOPE_NS: &str = "secure/ops";
const IN_SCOPE_NS: &str = "public/ok";

/// `ai:puller` may pull `public/*` only.
const SCOPED_ALLOWLIST: &str =
    r#"{"ai:puller":{"allowed_namespaces":["public/*"],"allowed_sender_agent_ids":["ai:puller"]}}"#;

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

/// Scoped-peer posture with NO trust bypass (the bypass would resolve
/// `allow_all_legacy` and mask the entire defect).
fn set_posture() {
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            SCOPED_ALLOWLIST,
        );
    }
}

fn clear_posture() {
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(REQUIRE_ENROLLMENT_ENV);
        std::env::remove_var(REQUIRE_SIG_ENV);
        std::env::remove_var(TRUST_PEER_ENV);
    }
}

/// Insert a row directly through the storage primitive so the test does not
/// depend on any write-path posture (attestation, quotas, governance).
async fn seed(db: &ai_memory::handlers::Db, id: &str, ns: &str, updated_at: &str) {
    let guard = db.lock().await;
    guard
        .0
        .execute(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, tags, priority, confidence, source, \
                  metadata, access_count, created_at, updated_at) \
             VALUES (?1, 'long', ?2, ?3, 'body', '[]', 5, 1.0, 'api', \
                     json('{\"agent_id\":\"ai:puller\",\"scope\":\"collective\"}'), \
                     0, ?4, ?4)",
            rusqlite::params![id, ns, format!("t-{id}"), updated_at],
        )
        .expect("seed row");
}

/// One `/sync/since` pull as `PEER_ID`. Returns the decoded envelope.
async fn pull(router: &axum::Router, since: Option<&str>, limit: usize) -> Value {
    let mut uri = format!("/api/v1/sync/since?limit={limit}&peer={PEER_ID}");
    if let Some(s) = since {
        uri.push_str("&since=");
        uri.push_str(&urlencode(s));
    }
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(
            ai_memory::federation::peer_attestation::PEER_ID_HEADER,
            PEER_ID,
        )
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "pull must answer 200");
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("json envelope")
}

/// Minimal percent-encoder for the RFC3339 `+` in a timestamp.
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '+' => "%2B".to_string(),
            ':' => "%3A".to_string(),
            other => other.to_string(),
        })
        .collect()
}

fn next_since(v: &Value) -> Option<String> {
    v["next_since"].as_str().map(str::to_string)
}

/// Drive the real puller loop shape (`daemon_runtime::sync_cycle_once`:
/// pull → adopt cursor → pull again) until it stops moving. Returns the
/// final cursor and the number of round trips it took.
async fn drive_pull_to_convergence(
    router: &axum::Router,
    limit: usize,
    budget: usize,
) -> (Option<String>, usize) {
    let mut cursor: Option<String> = None;
    for i in 0..budget {
        let v = pull(router, cursor.as_deref(), limit).await;
        match next_since(&v) {
            // A cursor that does not move is a stall, not convergence.
            Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
            _ => return (cursor, i + 1),
        }
    }
    (cursor, budget)
}

// ---------------------------------------------------------------------------
// R-203 — the stall itself
// ---------------------------------------------------------------------------

/// R-203. THE defect: a window whose every row is out of the peer's
/// namespace scope answers `count: 0` behind an HTTP 200, and pre-#2441
/// published NO cursor at all — so the puller re-requested it forever.
#[tokio::test]
async fn cursor_advances_when_every_row_is_out_of_scope_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    seed(&db, "a", OUT_OF_SCOPE_NS, "2026-01-01T00:00:01+00:00").await;
    seed(&db, "b", OUT_OF_SCOPE_NS, "2026-01-01T00:00:02+00:00").await;
    seed(&db, "c", OUT_OF_SCOPE_NS, "2026-01-01T00:00:03+00:00").await;

    // limit far above the row count ⇒ the page is provably not truncated,
    // so the cursor may land on the newest examined row.
    let v = pull(&router, None, 500).await;
    clear_posture();

    assert_eq!(v["count"], 0, "every row is out of scope");
    assert_eq!(v["excluded_for_scope"], 3, "all three filtered post-LIMIT");
    assert!(
        v["latest_updated_at"].is_null(),
        "latest_updated_at still describes the PROJECTED page (unchanged wire meaning)"
    );
    assert_eq!(
        next_since(&v).as_deref(),
        Some("2026-01-01T00:00:03+00:00"),
        "#2441: a fully-filtered window MUST still publish a cursor; got {:?} \
         (count={}, excluded_for_scope={}) — the puller re-requests this \
         window forever",
        v["next_since"],
        v["count"],
        v["excluded_for_scope"],
    );
}

/// R-203. The liveness property the issue is really about: the pull loop
/// must TERMINATE. Pre-#2441 it never did — the same window came back on
/// every cycle. Uses a small `limit` so the loop must page through.
#[tokio::test]
async fn pull_loop_converges_instead_of_stalling_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    for i in 1..=6 {
        seed(
            &db,
            &format!("m{i}"),
            OUT_OF_SCOPE_NS,
            &format!("2026-01-01T00:00:0{i}+00:00"),
        )
        .await;
    }

    let (cursor, trips) = drive_pull_to_convergence(&router, 2, 12).await;
    clear_posture();

    assert_eq!(
        cursor.as_deref(),
        Some("2026-01-01T00:00:06+00:00"),
        "#2441: the cursor must reach the newest examined row; a stalled \
         cursor stops at {cursor:?} after {trips} round trip(s)"
    );
    assert!(
        trips < 12,
        "#2441: the pull loop must terminate, not burn its budget ({trips} trips)"
    );
}

/// R-203. The `scope=private` visibility filter is the SECOND post-LIMIT
/// filter and stalls the cursor identically — a row inside an ALLOWED
/// namespace but owned privately by another agent.
#[tokio::test]
async fn cursor_advances_when_every_row_is_visibility_filtered_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    {
        let guard = db.lock().await;
        for (id, ts) in [
            ("p1", "2026-02-01T00:00:01+00:00"),
            ("p2", "2026-02-01T00:00:02+00:00"),
        ] {
            guard
                .0
                .execute(
                    "INSERT INTO memories \
                         (id, tier, namespace, title, content, tags, priority, confidence, \
                          source, metadata, access_count, created_at, updated_at) \
                     VALUES (?1, 'long', ?2, ?3, 'body', '[]', 5, 1.0, 'api', \
                             json('{\"agent_id\":\"ai:someone-else\",\"scope\":\"private\"}'), \
                             0, ?4, ?4)",
                    rusqlite::params![id, IN_SCOPE_NS, format!("t-{id}"), ts],
                )
                .expect("seed private row");
        }
    }

    let v = pull(&router, None, 500).await;
    clear_posture();

    assert_eq!(v["count"], 0, "both rows are another agent's private rows");
    assert_eq!(v["excluded_for_scope_private"], 2);
    assert_eq!(
        next_since(&v).as_deref(),
        Some("2026-02-01T00:00:02+00:00"),
        "#2441: the visibility filter also runs post-LIMIT and must not pin \
         the cursor; got {:?}",
        v["next_since"],
    );
}

// ---------------------------------------------------------------------------
// Guards against a NAIVE fix (these pass at the parent, for the wrong reason)
// ---------------------------------------------------------------------------

/// GUARD (not R-203). The cursor predicate is strict `updated_at > since`,
/// so advancing onto a timestamp that several rows share SKIPS every sharer
/// that fell beyond the `LIMIT` — silent, permanent row loss on the
/// replica. A naive `examined.last()` fix does exactly that. When the page
/// came back FULL and is one single tie group, the honest answer is to HOLD
/// the cursor (a loud stall) rather than lose rows.
#[tokio::test]
async fn cursor_holds_rather_than_skipping_a_cut_tie_group_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    // Four rows, ONE timestamp. limit=2 cuts the tie group in half.
    for i in 1..=4 {
        seed(
            &db,
            &format!("tie{i}"),
            OUT_OF_SCOPE_NS,
            "2026-03-01T00:00:00+00:00",
        )
        .await;
    }

    let v = pull(&router, None, 2).await;
    clear_posture();

    assert_eq!(v["count"], 0);
    assert!(
        next_since(&v).is_none(),
        "#2441: a FULL page that is one tie group must NOT advance the cursor \
         (advancing past 2026-03-01T00:00:00+00:00 would silently drop the two \
         rows beyond the LIMIT); got {:?}",
        v["next_since"],
    );
}

/// GUARD (not R-203). A page that is FULL but spans several timestamps
/// advances only to the newest STRICTLY-OLDER timestamp, so the trailing
/// tie group is re-examined next round rather than skipped. Re-examination
/// is a free no-op on the receiver (`insert_if_newer`).
#[tokio::test]
async fn full_page_drops_the_trailing_tie_group_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    seed(&db, "x1", OUT_OF_SCOPE_NS, "2026-04-01T00:00:01+00:00").await;
    seed(&db, "x2", OUT_OF_SCOPE_NS, "2026-04-01T00:00:02+00:00").await;
    seed(&db, "x3", OUT_OF_SCOPE_NS, "2026-04-01T00:00:02+00:00").await;
    seed(&db, "x4", OUT_OF_SCOPE_NS, "2026-04-01T00:00:03+00:00").await;

    // limit=3 ⇒ examined = [x1, x2, x3]; the :02 group may be cut.
    let v = pull(&router, None, 3).await;
    clear_posture();

    assert_eq!(
        next_since(&v).as_deref(),
        Some("2026-04-01T00:00:01+00:00"),
        "#2441: a cut page must land on the newest strictly-older timestamp"
    );
}

// ---------------------------------------------------------------------------
// Wire back-compat
// ---------------------------------------------------------------------------

/// The existing `latest_updated_at` / `earliest_updated_at` S39 diagnostic
/// fields keep describing the PROJECTED page — `next_since` is additive and
/// does not redefine them. Guards the mixed-version mesh, where a pre-#2441
/// puller still reads `memories.last()`.
#[tokio::test]
async fn projected_page_diagnostics_are_unchanged_2441() {
    let _g = ENV_LOCK.lock().await;
    set_posture();
    let (router, db) = build_router_with_db();

    seed(&db, "in1", IN_SCOPE_NS, "2026-05-01T00:00:01+00:00").await;
    seed(&db, "out1", OUT_OF_SCOPE_NS, "2026-05-01T00:00:02+00:00").await;

    let v = pull(&router, None, 500).await;
    clear_posture();

    assert_eq!(v["count"], 1, "only the in-scope row projects");
    assert_eq!(v["latest_updated_at"], json!("2026-05-01T00:00:01+00:00"));
    assert_eq!(v["earliest_updated_at"], json!("2026-05-01T00:00:01+00:00"));
    assert_eq!(
        next_since(&v).as_deref(),
        Some("2026-05-01T00:00:02+00:00"),
        "the cursor is ahead of the projected page — that is the whole point"
    );
}

/// The default-deny arm (no allowlist entry, no trust bypass) never reads
/// the DB, so it has no examined set. `null` there is an honest refusal,
/// not a stall — `scope_status` already names it.
#[tokio::test]
async fn default_deny_arm_publishes_a_null_cursor_2441() {
    let _g = ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var(REQUIRE_SIG_ENV, "0");
        std::env::set_var(REQUIRE_ENROLLMENT_ENV, "0");
        std::env::remove_var(TRUST_PEER_ENV);
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            r#"{"ai:other":{"allowed_namespaces":["public/*"]}}"#,
        );
    }
    let (router, db) = build_router_with_db();
    seed(&db, "d1", IN_SCOPE_NS, "2026-06-01T00:00:01+00:00").await;

    let v = pull(&router, None, 500).await;
    clear_posture();

    assert_eq!(v["scope_status"], "no_allowlist_default_deny");
    assert!(
        next_since(&v).is_none(),
        "default-deny publishes no cursor: nothing was examined"
    );
}
