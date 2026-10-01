// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4030 / #4031 / #4032 — the CRDT-lite federation merge
//! (`models::merge_memory`, persisted by BOTH adapters' `merge_inbound`) is a
//! real join, and its output is always relayable.
//!
//! * **#4030** — content LWW compared parsed instants while the merged
//!   `updated_at` compared raw strings, so `10:00+02:00` (08:00Z) was stamped
//!   over a kept `09:00Z` content and a later `08:30Z` edit then overwrote the
//!   newer content.
//! * **#4031** — a value retained from an operand that lacked the key on the
//!   other side inherited the merged row's newer clock, so
//!   `merge(merge(A,C),B) != merge(A,merge(C,B))` and replicas that saw the
//!   same versions in different orders diverged (`metadata.k`, `source_uri`).
//! * **#4032** — the tag / metadata unions of two individually valid rows
//!   exceeded the authored-input caps the receivers validated full rows
//!   against, so the merged row could no longer be relayed to a third node.
//!
//! Every cell drives the PRODUCTION `/sync/push` route on a real router
//! (sqlite here; the postgres twins are `#[ignore]` + `sal-postgres` against
//! `AI_MEMORY_TEST_POSTGRES_URL`) and reads the persisted row back between
//! merges; the pure algebra is pinned too.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::Memory;
#[cfg(feature = "sal-postgres")]
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;

static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());
const PEER_HEADER: &str = "x-peer-id";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Posture for the memories[] lane (sig gate off, body sender trusted, the
/// peer scoped to its namespace). Restored on Drop.
struct Posture([(&'static str, Option<std::ffi::OsString>); 5]);

impl Posture {
    fn new(peer: &str, namespace: &str) -> Self {
        use ai_memory::federation::peer_attestation::{
            PEER_ATTESTATION_ENV, TRUST_BODY_AGENT_ID_ENV,
        };
        use ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV;
        use ai_memory::federation::signing::REQUIRE_SIG_ENV;
        const REQUIRE_ATTEST_ENV: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
        let keys = [
            PEER_ATTESTATION_ENV,
            REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
            REQUIRE_SIG_ENV,
            TRUST_BODY_AGENT_ID_ENV,
            REQUIRE_ATTEST_ENV,
        ];
        let guard = Self(keys.map(|k| (k, std::env::var_os(k))));
        let allowlist = json!({peer: {
            "allowed_sender_agent_ids": [peer],
            "allowed_namespaces": [namespace],
        }});
        // SAFETY: every caller holds FED_ENV_LOCK; Drop restores before release.
        unsafe {
            std::env::set_var(PEER_ATTESTATION_ENV, allowlist.to_string());
            std::env::remove_var(REQUIRE_PUSH_NAMESPACE_SCOPE_ENV);
            std::env::set_var(REQUIRE_SIG_ENV, "0");
            std::env::set_var(TRUST_BODY_AGENT_ID_ENV, "1");
            std::env::set_var(REQUIRE_ATTEST_ENV, "0");
        }
        guard
    }
}

impl Drop for Posture {
    fn drop(&mut self) {
        // SAFETY: the enclosing test still holds FED_ENV_LOCK.
        for (key, previous) in &self.0 {
            unsafe {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[derive(Clone)]
enum Backend {
    Sqlite,
    #[cfg(feature = "sal-postgres")]
    Postgres(String),
}

/// One receiving node: a production router plus its read handles.
struct Node {
    router: axum::Router,
    // Read only by the postgres arm of `Node::read`.
    #[cfg_attr(not(feature = "sal-postgres"), allow(dead_code))]
    store: Arc<dyn MemoryStore>,
    db: Db,
    backend: Backend,
}

#[allow(clippy::unused_async)] // the pg arm awaits; the sqlite arm does not
async fn node(backend: &Backend) -> Node {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let (store, storage_backend): (Arc<dyn MemoryStore>, StorageBackend) = match backend {
        Backend::Sqlite => {
            let tmp = tempfile::NamedTempFile::new().expect("tempfile");
            let p = tmp.path().to_path_buf();
            std::mem::forget(tmp);
            (
                Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store")),
                StorageBackend::Sqlite,
            )
        }
        #[cfg(feature = "sal-postgres")]
        Backend::Postgres(url) => (
            Arc::new(
                ai_memory::store::postgres::PostgresStore::connect(url)
                    .await
                    .expect("connect postgres"),
            ),
            StorageBackend::Postgres,
        ),
    };
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend,
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
        ..Default::default()
    };
    Node {
        router: ai_memory::build_router(api_key_state, app_state),
        store,
        db,
        backend: backend.clone(),
    }
}

impl Node {
    /// Push one row through the production `/sync/push` route; returns the
    /// receiver's report.
    async fn push(&self, peer: &str, mem: &Value) -> Value {
        let body = json!({
            "sender_agent_id": peer,
            "sender_clock": {"entries": {}},
            "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
            "memories": [mem],
            "dry_run": false,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync/push")
            .header("content-type", "application/json")
            .header(PEER_HEADER, peer)
            .body(Body::from(body.to_string()))
            .expect("request");
        let resp = self.router.clone().oneshot(req).await.expect("route");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        let report: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::OK, "push refused: {report}");
        report
    }

    /// The persisted row, read back from the backend the route wrote to.
    async fn read(&self, id: &str) -> Memory {
        match &self.backend {
            Backend::Sqlite => {
                let guard = self.db.lock().await;
                ai_memory::db::get_any(&guard.0, id)
                    .expect("read")
                    .expect("row present")
            }
            #[cfg(feature = "sal-postgres")]
            Backend::Postgres(_) => {
                let mut ctx = CallerContext::for_agent("ai:reader-4031");
                ctx.bypass_visibility = true;
                self.store.get(&ctx, id).await.expect("row present")
            }
        }
    }
}

fn instant(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .expect("rfc3339")
        .with_timezone(&chrono::Utc)
}

fn row(id: &str, ns: &str, peer: &str, updated_at: &str, content: &str) -> Value {
    json!({
        "id": id,
        "tier": "long",
        "namespace": ns,
        // Unique per id: on postgres every "node" shares one database, so a
        // shared title would fold distinct ids together by (title, namespace).
        "title": format!("merge convergence probe {id}"),
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": "2026-09-20T00:00:00Z",
        "updated_at": updated_at,
        "metadata": {"agent_id": peer}
    })
}

// ------------------------------------------------------------ #4030 ------

async fn clock_never_regresses(backend: &Backend) {
    let peer = uniq("ai:peer-4030");
    let ns = uniq("fit-4030");
    let _posture = Posture::new(&peer, &ns);
    let n = node(backend).await;
    for (variant, b_ts) in [
        ("offset", "2026-09-26T10:00:00+02:00"),
        ("offset-fraction", "2026-09-26T10:00:00.000000+02:00"),
        ("negative-offset", "2026-09-26T03:00:00-05:00"),
    ] {
        let id = uniq("m4030");
        n.push(
            &peer,
            &row(
                &id,
                &ns,
                &peer,
                "2026-09-26T09:00:00Z",
                "A — newest content",
            ),
        )
        .await;
        // B is 08:00Z (older) but its raw string sorts AFTER 09:00Z.
        n.push(&peer, &row(&id, &ns, &peer, b_ts, "B — older content"))
            .await;
        let after_b = n.read(&id).await;
        assert_eq!(
            after_b.content, "A — newest content",
            "{variant}: A is newer"
        );
        assert_eq!(
            instant(&after_b.updated_at),
            instant("2026-09-26T09:00:00Z"),
            "#4030 {variant}: the merged row's clock regressed to B's older instant ({})",
            after_b.updated_at
        );
        // C (08:30Z) is older than A and must not overwrite it.
        n.push(
            &peer,
            &row(&id, &ns, &peer, "2026-09-26T08:30:00Z", "C — stale edit"),
        )
        .await;
        let after_c = n.read(&id).await;
        assert_eq!(
            after_c.content, "A — newest content",
            "#4030 {variant}: a stale edit overwrote newer content through the regressed clock"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_merged_clock_never_regresses_4030() {
    let _g = FED_ENV_LOCK.lock().await;
    clock_never_regresses(&Backend::Sqlite).await;
}

#[test]
fn pure_merge_takes_the_temporal_max_4030() {
    let base: Memory =
        serde_json::from_value(row("x", "n", "ai:p", "2026-09-26T09:00:00Z", "A")).expect("memory");
    let mut b = base.clone();
    b.updated_at = "2026-09-26T10:00:00+02:00".to_string();
    b.content = "B".to_string();
    for (l, r) in [(&base, &b), (&b, &base)] {
        let m = ai_memory::models::merge_memory(l, r);
        assert_eq!(m.content, "A");
        assert_eq!(instant(&m.updated_at), instant("2026-09-26T09:00:00Z"));
    }
}

// ------------------------------------------------------------ #4031 ------

/// `A{k=old, source_uri=old}@t1`, `B{k=new, source_uri=new}@t2`, `C{}@t3` (C
/// edits an unrelated field and omits both).
fn abc(id: &str, ns: &str, peer: &str) -> [Value; 3] {
    let mut a = row(id, ns, peer, "2026-09-26T01:00:00Z", "same text");
    a["metadata"]["k"] = json!("old");
    a["source_uri"] = json!("doc:provenance-old");
    let mut b = row(id, ns, peer, "2026-09-26T02:00:00Z", "same text");
    b["metadata"]["k"] = json!("new");
    b["source_uri"] = json!("doc:provenance-new");
    let mut c = row(id, ns, peer, "2026-09-26T03:00:00Z", "same text");
    c["priority"] = json!(7);
    [a, b, c]
}

/// The converged, order-independent projection of a row (node-local and
/// representation-only fields excluded).
fn projection(m: &Memory) -> Value {
    json!({
        "content": m.content,
        "k": m.metadata.get("k"),
        "source_uri": m.source_uri,
        "priority": m.priority,
        "updated_at": instant(&m.updated_at).to_rfc3339(),
    })
}

async fn every_delivery_order_converges(backend: &Backend) {
    let peer = uniq("ai:peer-4031");
    let ns = uniq("fit-4031");
    let _posture = Posture::new(&peer, &ns);
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut results = Vec::new();
    for order in orders {
        // One fresh node per order (distinct ids keep pg cells independent).
        let n = node(backend).await;
        let id = uniq("m4031");
        let rows = abc(&id, &ns, &peer);
        for i in order {
            let report = n.push(&peer, &rows[i]).await;
            assert_eq!(
                report.get("skipped").and_then(Value::as_u64).unwrap_or(0),
                0,
                "row {i} of order {order:?} was refused: {report}"
            );
        }
        results.push((order, projection(&n.read(&id).await)));
    }
    let (first_order, first) = &results[0];
    for (order, got) in &results[1..] {
        assert_eq!(
            got, first,
            "#4031: delivery order {order:?} diverged from {first_order:?}"
        );
    }
    assert_eq!(first["k"], json!("new"), "the newest value of k wins");
    assert_eq!(first["source_uri"], json!("doc:provenance-new"));
    assert_eq!(first["priority"], json!(7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_every_delivery_order_converges_4031() {
    let _g = FED_ENV_LOCK.lock().await;
    every_delivery_order_converges(&Backend::Sqlite).await;
}

#[test]
fn pure_merge_is_associative_on_distinct_clocks_4031() {
    use ai_memory::models::merge_memory;
    let rows: Vec<Memory> = abc("x", "n", "ai:p")
        .into_iter()
        .map(|v| serde_json::from_value(v).expect("memory"))
        .collect();
    let (a, b, c) = (&rows[0], &rows[1], &rows[2]);
    let left = merge_memory(&merge_memory(a, c), b);
    let right = merge_memory(a, &merge_memory(c, b));
    assert_eq!(projection(&left), projection(&right), "(A∘C)∘B vs A∘(C∘B)");
    assert_eq!(left.metadata.get("k"), Some(&json!("new")));
    // Nested + type-flip: A{o:{x}}@t1, B{o:5}@t2, C{o:{y}}@t3.
    let mut a2 = a.clone();
    a2.metadata["o"] = json!({"x": 1});
    let mut b2 = b.clone();
    b2.metadata["o"] = json!(5);
    let mut c2 = c.clone();
    c2.metadata["o"] = json!({"y": 2});
    let orders = [
        merge_memory(&merge_memory(&a2, &b2), &c2),
        merge_memory(&merge_memory(&a2, &c2), &b2),
        merge_memory(&merge_memory(&b2, &c2), &a2),
        merge_memory(&a2, &merge_memory(&c2, &b2)),
    ];
    for m in &orders {
        assert_eq!(
            m.metadata.get("o"),
            Some(&json!({"y": 2})),
            "the object written after the scalar wins, without the object the scalar replaced"
        );
    }
    // Idempotent on its own output.
    let once = merge_memory(a, b);
    assert_eq!(projection(&merge_memory(&once, &once)), projection(&once));
}

// ------------------------------------------- #4031 (visibility: scope) ---

/// An absent or explicit `private` scope: owner-only visibility.
fn owner_private(metadata: &Value) -> bool {
    metadata.get("scope").is_none_or(|s| s == "private")
}

/// `metadata.scope` is authorization-bearing (an absent / `private` scope is
/// owner-only, `collective` is broad). `A{scope=collective}@t1`,
/// `B{scope=private}@t2`, `C{no scope}@t3`: every delivery order must converge
/// on an OWNER-PRIVATE row — pre-#4031 the order A, C, B kept `collective`.
/// (Since the f2r review the newest row's ABSENCE of `scope` is itself a
/// versioned value, so the converged row carries no scope: owner-private.)
fn scope_rows(id: &str, ns: &str, peer: &str) -> [Value; 3] {
    let mut a = row(id, ns, peer, "2026-09-26T01:00:00Z", "same text");
    a["metadata"]["scope"] = json!("collective");
    let mut b = row(id, ns, peer, "2026-09-26T02:00:00Z", "same text");
    b["metadata"]["scope"] = json!("private");
    let c = row(id, ns, peer, "2026-09-26T03:00:00Z", "same text");
    [a, b, c]
}

async fn scope_never_widens_by_delivery_order(backend: &Backend) {
    let peer = uniq("ai:peer-4031s");
    let ns = uniq("fit-4031s");
    let _posture = Posture::new(&peer, &ns);
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let n = node(backend).await;
        let id = uniq("m4031s");
        let rows = scope_rows(&id, &ns, &peer);
        for i in order {
            n.push(&peer, &rows[i]).await;
        }
        let got = n.read(&id).await;
        assert!(
            owner_private(&got.metadata),
            "#4031: delivery order {order:?} let an older `collective` scope override the \
             newer owner-private state: {}",
            got.metadata
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_scope_never_widens_by_delivery_order_4031() {
    let _g = FED_ENV_LOCK.lock().await;
    scope_never_widens_by_delivery_order(&Backend::Sqlite).await;
}

/// The per-field clock map is bound to the row clock it was minted at. A row
/// whose retained `k=v1` carries a recorded (older) version, then is edited
/// locally to `v2` (t4) and back to `v1` (t5) by a read-modify-write client
/// that round-trips the map verbatim, must keep `v1` when the stale t4 `v2`
/// row is replayed later. Without the binding the t5 `v1` matched its old
/// fingerprint and resurrected the t1 version, so the replay won. (First
/// found on `scope`; since the f2r review the visibility keys are
/// absence-versioned, so the retained-old-version precondition is exercised
/// on an ordinary key.)
fn aba_rows() -> (Memory, Memory) {
    use ai_memory::models::merge_memory;
    let mut x: Memory =
        serde_json::from_value(row("x", "n", "ai:p", "2026-09-26T01:00:00Z", "t")).expect("m");
    x.metadata["k"] = json!("v1");
    let y: Memory =
        serde_json::from_value(row("x", "n", "ai:p", "2026-09-26T03:00:00Z", "t")).expect("m");
    // M@t3 retains k=v1 with its t1 version recorded in the map.
    let merged = merge_memory(&x, &y);
    assert!(
        merged.metadata.get("crdt_field_clocks").is_some(),
        "precondition: the merge recorded the retained value's own version"
    );
    let mut edit_v2 = merged.clone();
    edit_v2.metadata["k"] = json!("v2");
    edit_v2.updated_at = "2026-09-26T04:00:00Z".to_string();
    let mut edit_back = edit_v2.clone();
    edit_back.metadata["k"] = json!("v1");
    edit_back.updated_at = "2026-09-26T05:00:00Z".to_string();
    (edit_back, edit_v2)
}

#[test]
fn pure_edited_back_value_never_resurrects_an_old_version_4031() {
    use ai_memory::models::merge_memory;
    let (newest, stale) = aba_rows();
    for m in [merge_memory(&newest, &stale), merge_memory(&stale, &newest)] {
        assert_eq!(
            m.metadata.get("k"),
            Some(&json!("v1")),
            "a stale replay of the intermediate edit beat the owner's newest value"
        );
    }
}

async fn edited_back_value_survives_a_stale_replay(backend: &Backend) {
    let peer = uniq("ai:peer-4031a");
    let ns = uniq("fit-4031a");
    let _posture = Posture::new(&peer, &ns);
    let n = node(backend).await;
    let id = uniq("m4031a");
    let (newest, stale) = aba_rows();
    let wire = |m: &Memory| -> Value {
        let mut v = serde_json::to_value(m).expect("serialize");
        v["id"] = json!(id);
        v["namespace"] = json!(ns);
        v["title"] = json!(format!("merge convergence probe {id}"));
        v["metadata"]["agent_id"] = json!(peer);
        v
    };
    n.push(&peer, &wire(&newest)).await;
    n.push(&peer, &wire(&stale)).await;
    assert_eq!(
        n.read(&id).await.metadata.get("k"),
        Some(&json!("v1")),
        "the replayed stale row beat the owner's newest edit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_edited_back_value_survives_a_stale_replay_4031() {
    let _g = FED_ENV_LOCK.lock().await;
    edited_back_value_survives_a_stale_replay(&Backend::Sqlite).await;
}

/// The #4032 bounded metadata fallback keeps only the row-LWW winner's
/// ordinary keys; the visibility keys must still resolve by their own
/// versions, so the fallback can never widen a row.
#[test]
fn pure_bounded_metadata_fallback_never_widens_scope_4032() {
    use ai_memory::models::merge_memory;
    let big = "x".repeat(300 * 1024);
    // The winner W@t3 carries `collective` whose OWN version (per its clock
    // map) is t1: the row-LWW winner holding an older visibility value.
    let collective_fp = blake3::hash(b"\"collective\"").to_hex().as_str()[..16].to_string();
    let winner = mem_at(
        "2026-09-26T03:00:00Z",
        json!({"scope": "collective", "big_a": big, "crdt_field_clocks": {
            "v": 1,
            "row": "2026-09-26T03:00:00.000000Z",
            "leaf": {"/scope": ["2026-09-26T01:00:00.000000Z", collective_fp]}
        }}),
    );
    let mut loser: Memory =
        serde_json::from_value(row("x", "n", "ai:p", "2026-09-26T02:00:00Z", "t")).expect("m");
    loser.metadata["scope"] = json!("private");
    loser.metadata["big_b"] = json!(big);
    for m in [merge_memory(&winner, &loser), merge_memory(&loser, &winner)] {
        assert!(
            m.metadata.get("big_b").is_none(),
            "precondition: the join crossed the replicated cap and took the bounded fallback"
        );
        assert_eq!(
            m.metadata.get("scope"),
            Some(&json!("private")),
            "the bounded fallback dropped the loser's NEWER `private` scope"
        );
    }
}

// ------------------------------------------------------------ #4032 ------

fn tags(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}-{i:03}")).collect()
}

async fn merged_row_stays_relayable(backend: &Backend) {
    let peer = uniq("ai:peer-4032");
    let ns = uniq("fit-4032");
    let _posture = Posture::new(&peer, &ns);
    let n2 = node(backend).await;
    let n3 = node(backend).await;

    // Tags: two valid 26-tag rows, disjoint.
    let id = uniq("m4032");
    let mut a = row(&id, &ns, &peer, "2026-09-26T01:00:00Z", "tags");
    a["tags"] = json!(tags("left", 26));
    let mut b = row(&id, &ns, &peer, "2026-09-26T02:00:00Z", "tags");
    b["tags"] = json!(tags("right", 26));
    for v in [&a, &b] {
        let m: Memory = serde_json::from_value(v.clone()).expect("memory");
        ai_memory::validate::validate_memory(&m).expect("each operand is individually valid");
    }
    n2.push(&peer, &a).await;
    n2.push(&peer, &b).await;
    let merged = n2.read(&id).await;
    assert_eq!(
        merged.tags.len(),
        52,
        "both writers' tags survive the merge"
    );

    // Relay the persisted merged row to a third node through /sync/push. On
    // postgres the "third node" shares the database, so the relayed copy
    // travels under a fresh id + title (its validation is what is under test).
    let relay = |m: &Memory| {
        let mut v = serde_json::to_value(m).expect("json");
        let rid = uniq("relay");
        v["title"] = json!(format!("relayed {rid}"));
        v["id"] = json!(rid);
        v
    };
    let relay_row = relay(&merged);
    let relay_id = relay_row["id"].as_str().expect("id").to_string();
    let report = n3.push(&peer, &relay_row).await;
    assert_eq!(
        report.get("skipped").and_then(Value::as_u64).unwrap_or(0),
        0,
        "#4032: the third node refused to relay the merged row: {report}"
    );
    let relayed = n3.read(&relay_id).await;
    let mut want = merged.tags.clone();
    want.sort();
    let mut got = relayed.tags.clone();
    got.sort();
    assert_eq!(got, want, "#4032: every merged tag reached the third node");

    // Metadata: two valid ~40 KB disjoint entries.
    let mid = uniq("m4032-meta");
    let mut ma = row(&mid, &ns, &peer, "2026-09-26T01:00:00Z", "meta");
    ma["metadata"]["left_blob"] = json!("l".repeat(40_000));
    let mut mb = row(&mid, &ns, &peer, "2026-09-26T02:00:00Z", "meta");
    mb["metadata"]["right_blob"] = json!("r".repeat(40_000));
    n2.push(&peer, &ma).await;
    n2.push(&peer, &mb).await;
    let merged_meta = n2.read(&mid).await;
    assert!(merged_meta.metadata.get("left_blob").is_some());
    assert!(merged_meta.metadata.get("right_blob").is_some());
    let relay_meta = relay(&merged_meta);
    let relay_meta_id = relay_meta["id"].as_str().expect("id").to_string();
    let report = n3.push(&peer, &relay_meta).await;
    assert_eq!(
        report.get("skipped").and_then(Value::as_u64).unwrap_or(0),
        0,
        "#4032: the third node refused the merged-metadata row: {report}"
    );
    let relayed_meta = n3.read(&relay_meta_id).await;
    assert!(relayed_meta.metadata.get("left_blob").is_some());
    assert!(relayed_meta.metadata.get("right_blob").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_merged_row_stays_relayable_4032() {
    let _g = FED_ENV_LOCK.lock().await;
    merged_row_stays_relayable(&Backend::Sqlite).await;
}

/// Repeated joins: 12 disjoint 50-tag authored versions (600 distinct tags)
/// stay bounded, valid, and order-independent.
#[test]
fn pure_repeated_joins_stay_bounded_and_convergent_4032() {
    use ai_memory::models::merge_memory;
    let versions: Vec<Memory> = (0..12)
        .map(|i| {
            let mut v = row(
                "x",
                "n",
                "ai:p",
                &format!("2026-09-26T{:02}:00:00Z", i + 1),
                "t",
            );
            v["tags"] = json!(tags(&format!("v{i:02}"), 50));
            serde_json::from_value(v).expect("memory")
        })
        .collect();
    let forward = versions[1..]
        .iter()
        .fold(versions[0].clone(), |acc, v| merge_memory(&acc, v));
    let backward = versions[..11]
        .iter()
        .rev()
        .fold(versions[11].clone(), |acc, v| merge_memory(&acc, v));
    ai_memory::validate::validate_memory(&forward).expect("the joined row is relayable");
    let mut f = forward.tags.clone();
    f.sort();
    let mut b = backward.tags.clone();
    b.sort();
    assert_eq!(f, b, "the bounded tag join is order-independent");
    assert_eq!(f.len(), ai_memory::validate::MAX_REPLICATED_TAGS);
}

// ------------------------- f2r review: visibility absence + forged floors ---

/// A pure `Memory` from [`row`] with the given metadata.
fn mem_at(updated_at: &str, metadata: Value) -> Memory {
    let mut m: Memory =
        serde_json::from_value(row("x", "n", "ai:alice", updated_at, "t")).expect("memory");
    m.metadata = metadata;
    m
}

/// The two visibility-absence cases: `(newer, stale, dropped key)`. The owner
/// made the row private by DROPPING `scope` (absent = owner-private), and
/// revoked a share by dropping `target_agent_id`; a stale peer row still
/// carries the broad value.
fn absence_cases() -> [(Value, Value, &'static str); 2] {
    [
        (
            json!({"agent_id": "ai:alice"}),
            json!({"agent_id": "ai:alice", "scope": "collective"}),
            "scope",
        ),
        (
            json!({"agent_id": "ai:alice", "scope": "private"}),
            json!({"agent_id": "ai:alice", "scope": "private", "target_agent_id": "ai:bob"}),
            "target_agent_id",
        ),
    ]
}

#[test]
fn pure_newer_absence_of_a_visibility_key_beats_a_stale_presence() {
    use ai_memory::models::merge_memory;
    for (newer, stale, key) in absence_cases() {
        let newer = mem_at("2026-09-26T02:00:00Z", newer);
        let stale = mem_at("2026-09-26T01:00:00Z", stale);
        for m in [merge_memory(&newer, &stale), merge_memory(&stale, &newer)] {
            assert!(
                m.metadata.get(key).is_none(),
                "a stale `{key}` resurrected over the owner's newer removal: {}",
                m.metadata
            );
        }
        // A genuinely NEWER presence still wins over an older absence.
        let mut later = stale.clone();
        later.updated_at = "2026-09-26T03:00:00Z".to_string();
        assert!(merge_memory(&newer, &later).metadata.get(key).is_some());
    }
}

#[test]
fn pure_visibility_absence_joins_associatively() {
    use ai_memory::models::merge_memory;
    // A{scope=collective}@t1, B{}@t2 (owner dropped scope), C{scope=team}@t3
    // omitted from half the groupings: every grouping ends with B's absence
    // until C's newer value arrives.
    let a = mem_at("2026-09-26T01:00:00Z", json!({"scope": "collective"}));
    let b = mem_at("2026-09-26T02:00:00Z", json!({}));
    let c = mem_at("2026-09-26T03:00:00Z", json!({"note": "unrelated"}));
    let groupings = [
        merge_memory(&merge_memory(&a, &b), &c),
        merge_memory(&merge_memory(&a, &c), &b),
        merge_memory(&a, &merge_memory(&c, &b)),
        merge_memory(&merge_memory(&c, &a), &b),
    ];
    for m in &groupings {
        assert!(
            m.metadata.get("scope").is_none(),
            "grouping kept the stale collective scope: {}",
            m.metadata
        );
        assert_eq!(m.metadata.get("note"), Some(&json!("unrelated")));
    }
}

/// A forged floor: H@t3 carries no `prefs` at all, only a clock map claiming a
/// scalar superseded `/prefs` at t3. It must not erase L's nested object.
fn forged_floor_rows() -> (Memory, Memory) {
    let local = mem_at("2026-09-26T02:00:00Z", json!({"prefs": {"x": 1, "y": 2}}));
    let forged = mem_at(
        "2026-09-26T03:00:00Z",
        json!({"crdt_field_clocks": {
            "v": 1,
            "row": "2026-09-26T03:00:00.000000Z",
            "floor": {"/prefs": "2026-09-26T03:00:00.000000Z"}
        }}),
    );
    (local, forged)
}

#[test]
fn pure_forged_floor_cannot_erase_a_nested_object() {
    use ai_memory::models::merge_memory;
    let (local, forged) = forged_floor_rows();
    for m in [merge_memory(&local, &forged), merge_memory(&forged, &local)] {
        assert_eq!(
            m.metadata.get("prefs"),
            Some(&json!({"x": 1, "y": 2})),
            "a peer-forged floor erased a nested object the peer never held"
        );
    }
}

#[test]
fn pure_inconsistent_clock_map_keeps_the_join_idempotent() {
    use ai_memory::models::merge_memory;
    // H@9 {a:{b:"x"}} with floor /a=9 and leaf /a/b=3: the floor contradicts a
    // descendant H itself carries (an honest merge would have pruned it).
    // The leaf carries the value's real fingerprint (16 hex of blake3 over
    // the canonical JSON), so it is honoured.
    let x_fp = blake3::hash(b"\"x\"").to_hex().as_str()[..16].to_string();
    let h = mem_at(
        "2026-09-26T09:00:00Z",
        json!({"a": {"b": "x"}, "crdt_field_clocks": {
            "v": 1,
            "row": "2026-09-26T09:00:00.000000Z",
            "floor": {"/a": "2026-09-26T09:00:00.000000Z"},
            "leaf": {"/a/b": ["2026-09-26T03:00:00.000000Z", x_fp]}
        }}),
    );
    let hh = merge_memory(&h, &h);
    assert_eq!(hh.metadata.get("a"), Some(&json!({"b": "x"})), "H v H != H");
    // Honest outputs are byte-idempotent, clock map included.
    let honest = merge_memory(
        &mem_at("2026-09-26T01:00:00Z", json!({"o": {"x": 1}, "k": "old"})),
        &mem_at("2026-09-26T02:00:00Z", json!({"o": 5})),
    );
    let honest = merge_memory(
        &honest,
        &mem_at("2026-09-26T03:00:00Z", json!({"o": {"y": 2}})),
    );
    assert_eq!(merge_memory(&honest, &honest).metadata, honest.metadata);
}

async fn visibility_absence_survives_a_stale_replay(backend: &Backend) {
    let peer = uniq("ai:peer-f2r");
    let ns = uniq("fit-f2r");
    let _posture = Posture::new(&peer, &ns);
    for (newer, stale, key) in absence_cases() {
        for stale_first in [false, true] {
            let n = node(backend).await;
            let id = uniq("mvis");
            let wire = |meta: &Value, ts: &str| -> Value {
                let mut v = row(&id, &ns, &peer, ts, "same text");
                let mut meta = meta.clone();
                meta["agent_id"] = json!(peer);
                v["metadata"] = meta;
                v
            };
            let newer_row = wire(&newer, "2026-09-26T02:00:00Z");
            let stale_row = wire(&stale, "2026-09-26T01:00:00Z");
            let order = if stale_first {
                [&stale_row, &newer_row]
            } else {
                [&newer_row, &stale_row]
            };
            for r in order {
                n.push(&peer, r).await;
            }
            let got = n.read(&id).await;
            assert!(
                got.metadata.get(key).is_none(),
                "stale `{key}` widened the row (stale_first={stale_first}): {}",
                got.metadata
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_visibility_absence_survives_a_stale_replay_f2r() {
    let _g = FED_ENV_LOCK.lock().await;
    visibility_absence_survives_a_stale_replay(&Backend::Sqlite).await;
}

async fn forged_floor_is_refused(backend: &Backend) {
    let peer = uniq("ai:peer-f2rf");
    let ns = uniq("fit-f2rf");
    let _posture = Posture::new(&peer, &ns);
    let n = node(backend).await;
    let id = uniq("mfloor");
    let (local, forged) = forged_floor_rows();
    for m in [&local, &forged] {
        let mut v = serde_json::to_value(m).expect("serialize");
        v["id"] = json!(id);
        v["namespace"] = json!(ns);
        v["title"] = json!(format!("merge convergence probe {id}"));
        v["metadata"]["agent_id"] = json!(peer);
        n.push(&peer, &v).await;
    }
    assert_eq!(
        n.read(&id).await.metadata.get("prefs"),
        Some(&json!({"x": 1, "y": 2})),
        "a forged clock-map floor erased the stored nested object"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_forged_floor_is_refused_f2r() {
    let _g = FED_ENV_LOCK.lock().await;
    forged_floor_is_refused(&Backend::Sqlite).await;
}

// ------------------- f2r round 2: rank laundering on the visibility register ---

/// `2026-09-26T00:00:<sec>.000000Z`.
fn t(sec: u32) -> String {
    format!("2026-09-26T00:00:{sec:02}.000000Z")
}

/// A clock map binding `row` with `leaf` entries `(path, at, fingerprint)`.
fn clock_map(row: u32, leaves: &[(&str, u32, &str)]) -> Value {
    let leaf: serde_json::Map<String, Value> = leaves
        .iter()
        .map(|(p, at, fp)| ((*p).to_string(), json!([t(*at), fp])))
        .collect();
    json!({"v": 1, "row": t(row), "leaf": leaf})
}

/// f2r's counterexample: a={u:20, scope:collective}; b={u:22, ATTESTED, leaf
/// /scope ABSENT@19}; c={u:21, leaf /scope ABSENT@20}. The merged row's
/// `attest_level` used to supply the register rank, so a value that landed in an
/// attested row inherited rank 1 and the verdict depended on the grouping:
/// (a|b)|c stayed collective while a|(b|c) was private.
fn laundering_rows() -> [Memory; 3] {
    let a = mem_at(&t(20), json!({"scope": "collective"}));
    let b = mem_at(
        &t(22),
        json!({
            "attest_level": "agent_attested",
            "crdt_field_clocks": clock_map(22, &[("/scope", 19, "absent")]),
        }),
    );
    let c = mem_at(
        &t(21),
        json!({"crdt_field_clocks": clock_map(21, &[("/scope", 20, "absent")])}),
    );
    [a, b, c]
}

#[test]
fn pure_visibility_register_never_fails_open_by_grouping_rank_laundering() {
    use ai_memory::models::merge_memory as j;
    let [a, b, c] = laundering_rows();
    let groupings = [
        ("(a|b)|c", j(&j(&a, &b), &c)),
        ("c|(a|b)", j(&c, &j(&a, &b))),
        ("a|(b|c)", j(&a, &j(&b, &c))),
        ("(a|c)|b", j(&j(&a, &c), &b)),
        ("b|(a|c)", j(&b, &j(&a, &c))),
        ("(b|c)|a", j(&j(&b, &c), &a)),
    ];
    for (name, m) in &groupings {
        assert!(
            m.metadata.get("scope").is_none(),
            "{name} kept `scope` (fails OPEN): {}",
            m.metadata
        );
    }
}

#[test]
fn pure_equal_version_present_vs_absent_absence_wins_regardless_of_rank() {
    use ai_memory::models::merge_memory as j;
    // Equal version, and the PRESENT side carries the higher attestation rank.
    let present = mem_at(
        &t(20),
        json!({"attest_level": "agent_attested", "scope": "collective"}),
    );
    let absent = mem_at(&t(20), json!({}));
    for m in [j(&present, &absent), j(&absent, &present)] {
        assert!(m.metadata.get("scope").is_none(), "{}", m.metadata);
    }
}

async fn rank_laundering_converges_private_in_every_order(backend: &Backend) {
    let peer = uniq("ai:peer-f2r2");
    let ns = uniq("fit-f2r2");
    let _posture = Posture::new(&peer, &ns);
    let rows = laundering_rows();
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let node_under_test = node(backend).await;
        let id = uniq("mrank");
        for idx in order {
            let mut wire = serde_json::to_value(&rows[idx]).expect("serialize");
            wire["id"] = json!(id);
            wire["namespace"] = json!(ns);
            wire["title"] = json!(format!("merge convergence probe {id}"));
            wire["metadata"]["agent_id"] = json!(peer);
            node_under_test.push(&peer, &wire).await;
        }
        let got = node_under_test.read(&id).await;
        assert!(
            got.metadata.get("scope").is_none(),
            "order {order:?} left `scope` set (fails OPEN): {}",
            got.metadata
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_rank_laundering_converges_private_in_every_order_f2r() {
    let _g = FED_ENV_LOCK.lock().await;
    rank_laundering_converges_private_in_every_order(&Backend::Sqlite).await;
}

// ---------------------------------------------------------- postgres -----

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;

    fn pg_backend() -> Option<Backend> {
        match std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
            Ok(url) if !url.is_empty() => Some(Backend::Postgres(url)),
            _ => {
                eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
                None
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_merged_clock_never_regresses_4030() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        clock_never_regresses(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_every_delivery_order_converges_4031() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        every_delivery_order_converges(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_scope_never_widens_by_delivery_order_4031() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        scope_never_widens_by_delivery_order(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_edited_back_value_survives_a_stale_replay_4031() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        edited_back_value_survives_a_stale_replay(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_visibility_absence_survives_a_stale_replay_f2r() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        visibility_absence_survives_a_stale_replay(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_rank_laundering_converges_private_in_every_order_f2r() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        rank_laundering_converges_private_in_every_order(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_forged_floor_is_refused_f2r() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        forged_floor_is_refused(&backend).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_merged_row_stays_relayable_4032() {
        let _g = FED_ENV_LOCK.lock().await;
        let Some(backend) = pg_backend() else { return };
        merged_row_stays_relayable(&backend).await;
    }
}
