// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 (option 1, GOD ruling: landing-blocking for the approval-gate unit) —
//! a namespace-standard bind that would push an ENTITLED explicit
//! `parent_namespace` chain past `MAX_NAMESPACE_DEPTH` is refused AT BIND TIME
//! with a typed 400 and no row, identically on sqlite and postgres and through
//! HTTP, MCP and the SAL trait.
//!
//! Without it, #4477's fail-closed refusal of an over-depth chain is a
//! cross-principal lever: B binds the unbound root above A's governed
//! `v/proj`, hangs a 9-link same-owner chain above it, and every governed
//! operation in A's subtree returns 500.
//!
//! Cells, sqlite and PG 18.6, outcome compared across backends:
//! - (a) the cross-principal shape, chain built bottom-up: B's root link that
//!   crosses the bound is refused, no row, A's writes under `v/proj` stay 201;
//! - (b) the same chain built top-down (a link added at the TOP) is refused at
//!   the crossing link; the refusal text is identical on HTTP, MCP and SAL;
//! - (c) a chain exactly AT the bound is accepted and governed writes under it
//!   still succeed;
//! - (e) the federated `namespace_meta[]` apply (both receive loops, the
//!   postgres admin apply context included) applies the 8 legal links of a
//!   pushed chain and refuses the one that crosses the bound;
//! - (d) two binds, each legal alone, that together exceed the bound, racing
//!   (deterministic: the first held open under the bind's own serialisation):
//!   exactly one is refused.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(
    clippy::many_single_char_names,
    reason = "u/v/s/b are the run id, the root and a (status, body) pair, as in the sibling cells"
)]

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt as _;

mod common;

const KEY: &str = "issue-4492-key";
const ALICE: &str = "ai:alice-4492";
const BOB: &str = "ai:bob-4492";
const TEXT: &str = ai_memory::governance::bind_chain_depth::BIND_CHAIN_OVER_DEPTH;

const PEER: &str = "ai:peer-4492";

const POSTURE_VARS: [&str; 6] = [
    ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
    "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT",
    "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
    ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
    "AI_MEMORY_FED_SYNC_TRUST_PEER",
    "AI_MEMORY_FED_TRUST_BODY_AGENT_ID",
];

/// Restores the PREVIOUS value of every posture var on every exit path (the
/// cells around it rely on `common::permissive_attestation_for_tests`).
struct PostureGuard(Vec<(&'static str, Option<String>)>);

impl Drop for PostureGuard {
    fn drop(&mut self) {
        for (k, v) in &self.0 {
            // SAFETY: serialised by SERIAL; test-only env mutation.
            unsafe {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
}

fn set_peer_posture() -> PostureGuard {
    let saved = POSTURE_VARS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    let allow = json!({PEER: {"allowed_namespaces": ["**"], "allowed_sender_agent_ids": [PEER]}});
    // SAFETY: serialised by SERIAL; test-only env mutation.
    unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::remove_var("AI_MEMORY_FED_SYNC_TRUST_PEER");
        std::env::remove_var("AI_MEMORY_FED_TRUST_BODY_AGENT_ID");
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            allow.to_string(),
        );
        std::env::set_var(
            ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            "1",
        );
    }
    PostureGuard(saved)
}

/// The cells share process-global test state; one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn router(
    backend: StorageBackend,
    store: Arc<dyn MemoryStore>,
    db_path: &std::path::Path,
) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let conn = ai_memory::db::open(db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    let enrolled = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
    let app = AppState {
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
        storage_backend: backend,
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    ai_memory::build_router(
        ApiKeyState {
            key: Some(KEY.to_string()),
            mtls_enforced: false,
            enrolled_agent_keys: enrolled,
            identity_mode: HttpIdentityMode::Advisory,
            ..Default::default()
        },
        app,
    )
}

async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    agent: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", KEY)
        .header("x-agent-id", agent)
        .header("content-type", "application/json");
    let req = req
        .body(match body {
            Some(b) => Body::from(serde_json::to_vec(b).expect("body")),
            None => Body::empty(),
        })
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("bytes");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn standard(router: &axum::Router, agent: &str, ns: &str) -> String {
    let (s, b) = call(
        router,
        "POST",
        "/api/v1/memories",
        agent,
        Some(&json!({
            "namespace": ns, "title": format!("std4492 {}", uuid::Uuid::new_v4()),
            "content": "standard", "tier": "long", "tags": [], "priority": 5,
            "confidence": 1.0, "source": "api", "metadata": {},
        })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    b["id"].as_str().expect("id").to_string()
}

async fn bind(
    router: &axum::Router,
    agent: &str,
    ns: &str,
    id: &str,
    parent: Option<&str>,
    governance: Option<Value>,
) -> (StatusCode, Value) {
    let mut body = json!({"namespace": ns, "id": id});
    if let Some(p) = parent {
        body["parent"] = json!(p);
    }
    if let Some(g) = governance {
        body["governance"] = g;
    }
    call(router, "POST", "/api/v1/namespaces", agent, Some(&body)).await
}

async fn write(router: &axum::Router, agent: &str, ns: &str) -> u16 {
    let (s, _) = call(
        router,
        "POST",
        "/api/v1/memories",
        agent,
        Some(&json!({
            "namespace": ns, "title": format!("w4492 {}", uuid::Uuid::new_v4()),
            "content": "governed write", "tier": "long", "tags": [], "priority": 5,
            "confidence": 1.0, "source": "api", "metadata": {},
        })),
    )
    .await;
    s.as_u16()
}

async fn bound(store: &Arc<dyn MemoryStore>, ns: &str) -> bool {
    store
        .get_namespace_standard(&CallerContext::for_admin("ai:admin-4492"), ns)
        .await
        .expect("read binding")
        .is_some()
}

fn is_refusal(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::BAD_REQUEST && body["error"] == TEXT
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// (a) B's crossing root link: (status, typed text, row absent)
    a_root_link: (u16, bool, bool),
    /// (a) A's governed write under v/proj after B's attempt
    a_alice_write: u16,
    /// (b) top-down crossing link over HTTP: (status, typed text, row absent)
    b_top_link: (u16, bool, bool),
    /// (b) the same link through the SAL trait is the typed `InvalidInput`
    b_sal_typed: bool,
    /// (b) the same link through MCP (sqlite only; `true` on postgres)
    b_mcp_typed: bool,
    /// (c) every link up to exactly the bound accepted
    c_at_bound_accepted: bool,
    /// (c) A's governed write under the at-bound root
    c_alice_write: u16,
    /// (e) federated: a batch building the same 9-hop chain applies the 8
    /// legal links and refuses the crossing one: (applied, crossing root bound)
    fed: (u64, bool),
}

async fn run(
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    db_path: &std::path::Path,
) -> Outcome {
    let u = uuid::Uuid::new_v4().simple().to_string();
    let std_ns = format!("std4492{u}");
    let sqlite = matches!(backend, StorageBackend::Sqlite);
    let router = router(backend, Arc::clone(&store), db_path);

    // (a) A governs v/proj; B builds c1 -> ... -> c9 bottom-up (8 hops from
    // c1), then tries to hang v under it: 9 hops from v.
    let v = format!("va{u}");
    let proj = format!("{v}/proj");
    let a_std = standard(&router, ALICE, &std_ns).await;
    let (s, b) = bind(
        &router,
        ALICE,
        &proj,
        &a_std,
        None,
        Some(json!({"write": "owner"})),
    )
    .await;
    assert!(s.is_success(), "alice governs v/proj: {s} {b}");
    for i in (1..=8).rev() {
        let sid = standard(&router, BOB, &std_ns).await;
        let (s, b) = bind(
            &router,
            BOB,
            &format!("ca{i}x{u}"),
            &sid,
            Some(&format!("ca{}x{u}", i + 1)),
            None,
        )
        .await;
        assert!(
            s.is_success(),
            "chain link c{i} (<= the bound from c1): {s} {b}"
        );
    }
    let b_std = standard(&router, BOB, &std_ns).await;
    let (s, b) = bind(&router, BOB, &v, &b_std, Some(&format!("ca1x{u}")), None).await;
    let a_root_link = (s.as_u16(), is_refusal(s, &b), !bound(&store, &v).await);
    let a_alice_write = write(&router, ALICE, &proj).await;

    // (b)+(c) top-down: v2 -> d1 -> ... -> d8 is exactly the bound (8 hops),
    // then d8 -> d9 crosses it.
    let v2 = format!("vb{u}");
    let proj2 = format!("{v2}/proj");
    let (s, b) = bind(
        &router,
        ALICE,
        &proj2,
        &a_std,
        None,
        Some(json!({"write": "owner"})),
    )
    .await;
    assert!(s.is_success(), "alice governs v2/proj: {s} {b}");
    let mut c_at_bound_accepted = true;
    let mut prev = v2.clone();
    for i in 1..=8 {
        let sid = standard(&router, BOB, &std_ns).await;
        let next = format!("db{i}x{u}");
        let (s, _) = bind(&router, BOB, &prev, &sid, Some(&next), None).await;
        c_at_bound_accepted &= s.is_success();
        prev = next;
    }
    let c_alice_write = write(&router, ALICE, &proj2).await;
    // prev = d8 (unbound); binding it with parent d9 is the 9th hop from v2.
    let d9 = format!("db9x{u}");
    let top_sid = standard(&router, BOB, &std_ns).await;
    let (s, b) = bind(&router, BOB, &prev, &top_sid, Some(&d9), None).await;
    let b_top_link = (s.as_u16(), is_refusal(s, &b), !bound(&store, &prev).await);
    let sal = store
        .set_namespace_standard(&CallerContext::for_agent(BOB), &prev, &top_sid, Some(&d9))
        .await;
    let b_sal_typed = matches!(&sal, Err(StoreError::InvalidInput { detail }) if detail == TEXT);
    let b_mcp_typed = if sqlite {
        let conn = ai_memory::db::open(db_path).expect("mcp conn");
        ai_memory::mcp::handle_namespace_set_standard(
            &conn,
            &json!({"namespace": prev, "id": top_sid, "parent": d9, "agent_id": BOB}),
        )
        .err()
        .as_deref()
            == Some(TEXT)
    } else {
        true
    };

    // (e) the federated `namespace_meta[]` apply runs the same refusal (sqlite
    // receive loop and the postgres SET arm alike, admin apply context too).
    let fed = {
        let _posture = set_peer_posture();
        let admin = CallerContext::for_admin("ai:admin-4492");
        let mut entries = Vec::new();
        for i in (1..=8).rev() {
            let m = ai_memory::models::Memory {
                id: uuid::Uuid::new_v4().to_string(),
                title: format!("fed std {i} {u}"),
                tier: ai_memory::models::Tier::Long,
                namespace: std_ns.clone(),
                content: "standard".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
                updated_at: chrono::Utc::now().to_rfc3339(),
                metadata: json!({"agent_id": PEER, "scope": "shared"}),
                ..ai_memory::models::Memory::default()
            };
            store.store(&admin, &m).await.expect("peer standard");
            entries.push(json!({
                "namespace": format!("fc{i}x{u}"), "standard_id": m.id,
                "parent_namespace": format!("fc{}x{u}", i + 1),
                "updated_at": chrono::Utc::now().to_rfc3339(),
            }));
        }
        let root_std = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("fed root std {u}"),
            tier: ai_memory::models::Tier::Long,
            namespace: std_ns.clone(),
            content: "standard".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: json!({"agent_id": PEER, "scope": "shared"}),
            ..ai_memory::models::Memory::default()
        };
        store
            .store(&admin, &root_std)
            .await
            .expect("peer root standard");
        let fed_root = format!("fv{u}");
        entries.push(json!({
            "namespace": fed_root, "standard_id": root_std.id,
            "parent_namespace": format!("fc1x{u}"),
            "updated_at": chrono::Utc::now().to_rfc3339(),
        }));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync/push")
            .header("x-api-key", KEY)
            .header(
                ai_memory::federation::peer_attestation::PEER_ID_HEADER,
                PEER,
            )
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "sender_agent_id": PEER, "sender_clock": {"entries": {}}, "memories": [],
                    "namespace_meta": entries, "namespace_meta_clears": [], "dry_run": false,
                }))
                .expect("push body"),
            ))
            .expect("push request");
        let resp = router.clone().oneshot(req).await.expect("route");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("bytes");
        let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(
            status,
            StatusCode::OK,
            "per-entry skip, batch survives: {report}"
        );
        (
            report["namespace_meta_applied"]
                .as_u64()
                .unwrap_or(u64::MAX),
            bound(&store, &fed_root).await,
        )
    };

    Outcome {
        a_root_link,
        a_alice_write,
        b_top_link,
        b_sal_typed,
        b_mcp_typed,
        c_at_bound_accepted,
        c_alice_write,
        fed,
    }
}

const WANT: Outcome = Outcome {
    a_root_link: (400, true, true),
    a_alice_write: 201,
    b_top_link: (400, true, true),
    b_sal_typed: true,
    b_mcp_typed: true,
    c_at_bound_accepted: true,
    c_alice_write: 201,
    fed: (8, false),
};

async fn sqlite_outcome() -> Outcome {
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    run(store, StorageBackend::Sqlite, &path).await
}

#[tokio::test]
async fn sqlite_over_depth_link_is_refused_at_bind_4492() {
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    assert_eq!(sqlite_outcome().await, WANT);
}

/// The postgres twin and the cross-backend identity. A set-but-unreachable
/// URL FAILS (never skips); only an UNSET URL skips.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_over_depth_link_is_refused_at_bind_4492() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let pg = run(
        store,
        StorageBackend::Postgres,
        &dir.path().join("scratch.db"),
    )
    .await;
    let sq = sqlite_outcome().await;
    assert_eq!(pg, sq, "both backends must produce the identical outcome");
    assert_eq!(pg, WANT);
}

// ---------------------------------------------------------------------------
// (d) the race: A = bind r4 -> r5 (r0 .. r8 becomes exactly 8 hops), B = bind
// r8 -> r9 (alone 4 hops from r5). Together 9 hops from r0. A is held open
// under the bind's own serialisation (sqlite BEGIN IMMEDIATE, postgres the
// bind advisory lock) while B runs; B must wait, re-read, and be refused.
// ---------------------------------------------------------------------------

/// Seed r0->r1->r2->r3->r4 and r5->r6->r7->r8 (all BOB) through the SAL trait
/// as an operator (the fixture must not depend on the gate under test).
async fn race_fixture(store: &Arc<dyn MemoryStore>, u: &str) -> (String, String) {
    let admin = CallerContext::for_admin("ai:admin-4492");
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: format!("race std {u}"),
        tier: ai_memory::models::Tier::Long,
        namespace: format!("std4492r{u}"),
        content: "standard".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: json!({"agent_id": BOB, "scope": "shared"}),
        ..ai_memory::models::Memory::default()
    };
    store.store(&admin, &mem).await.expect("bob standard");
    let sid = mem.id.clone();
    for (from, to) in [(0, 1), (1, 2), (2, 3), (3, 4), (5, 6), (6, 7), (7, 8)] {
        store
            .set_namespace_standard(
                &admin,
                &format!("r{from}x{u}"),
                &sid,
                Some(&format!("r{to}x{u}")),
            )
            .await
            .expect("fixture link");
    }
    (sid, format!("r4x{u}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_racing_binds_that_jointly_exceed_the_bound_one_refused_4492() {
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").expect("local-runs");
    let dir = tempfile::tempdir_in(".local-runs").expect("tempdir");
    let path = dir.path().join("memories.db");
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.clone()).expect("open SqliteStore"),
    );
    let u = uuid::Uuid::new_v4().simple().to_string();
    let (sid, r4) = race_fixture(&store, &u).await;
    // A, held open: the single sqlite writer lock + the uncommitted row.
    let holder = ai_memory::db::open(&path).expect("holder conn");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("hold the write lock");
    holder
        .execute(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
             VALUES (?1, ?2, '2026-10-02T00:00:00Z', ?3)",
            rusqlite::params![r4, sid, format!("r5x{u}")],
        )
        .expect("A: r4 -> r5, uncommitted");
    let b = {
        let (store, r8, r9, sid) = (
            Arc::clone(&store),
            format!("r8x{u}"),
            format!("r9x{u}"),
            sid.clone(),
        );
        tokio::spawn(async move {
            store
                .set_namespace_standard(&CallerContext::for_agent(BOB), &r8, &sid, Some(&r9))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    holder.execute_batch("COMMIT").expect("commit A");
    let b = b.await.expect("B task");
    assert!(
        matches!(&b, Err(StoreError::InvalidInput { detail }) if detail == TEXT),
        "B must be refused once A is committed: {b:?}"
    );
    let n: i64 = holder
        .query_row(
            "SELECT COUNT(*) FROM namespace_meta WHERE namespace = ?1",
            rusqlite::params![format!("r8x{u}")],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "the refused bind wrote no row");
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_racing_binds_that_jointly_exceed_the_bound_one_refused_4492() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    let _serial = SERIAL.lock().await;
    common::permissive_attestation_for_tests();
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    );
    let u = uuid::Uuid::new_v4().simple().to_string();
    let (sid, r4) = race_fixture(&store, &u).await;
    let pool = sqlx::PgPool::connect(&url).await.expect("raw pool");
    let mut holder = pool.begin().await.expect("holder tx");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(ai_memory::ns_standard_ancestor::PG_STANDARD_BIND_LOCK_KEY)
        .execute(&mut *holder)
        .await
        .expect("take the bind lock");
    sqlx::query(
        "INSERT INTO namespace_meta (namespace, standard_id, parent_namespace) VALUES ($1, $2, $3)",
    )
    .bind(&r4)
    .bind(&sid)
    .bind(format!("r5x{u}"))
    .execute(&mut *holder)
    .await
    .expect("A: r4 -> r5, uncommitted");
    let b = {
        let (store, r8, r9, sid) = (
            Arc::clone(&store),
            format!("r8x{u}"),
            format!("r9x{u}"),
            sid.clone(),
        );
        tokio::spawn(async move {
            store
                .set_namespace_standard(&CallerContext::for_agent(BOB), &r8, &sid, Some(&r9))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!b.is_finished(), "B must wait for A's bind lock");
    holder.commit().await.expect("commit A");
    let b = b.await.expect("B task");
    let refused = matches!(&b, Err(StoreError::InvalidInput { detail }) if detail == TEXT);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM namespace_meta WHERE namespace = $1")
        .bind(format!("r8x{u}"))
        .fetch_one(&pool)
        .await
        .expect("count");
    for p in [format!("r%x{u}"), format!("std4492r{u}")] {
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace LIKE $1")
            .bind(&p)
            .execute(&pool)
            .await;
    }
    assert!(refused, "B must be refused once A is committed: {b:?}");
    assert_eq!(n, 0, "the refused bind wrote no row");
}
