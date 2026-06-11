// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! v0.7.0 K8 — quota enforcement on the store + link write paths.
//!
//! K8 ships the per-agent quota substrate. The substrate-level checks
//! against [`crate::quotas::check_quota`] / [`crate::quotas::record_op`]
//! live in `src/quotas.rs::tests` and exercise the inline-roll +
//! daily-reset semantics directly. This integration test pins the
//! enforcement seam — store under limit succeeds, store at limit
//! returns a `QUOTA_EXCEEDED` diagnostic naming the limit hit.

use ai_memory::quotas::{
    self, DEFAULT_MAX_LINKS_PER_DAY, DEFAULT_MAX_MEMORIES_PER_DAY, DEFAULT_MAX_STORAGE_BYTES,
    GLOBAL_NAMESPACE, QuotaCheckError, QuotaLimit, QuotaOp,
};
use rusqlite::{Connection, params};

mod common;
use common::fresh_db_tempfile_path as fresh_db;

/// Tighten a row's caps so the test can hit the wall in O(1) calls.
///
/// v0.7.0 #1156 — quota rows are now keyed by `(agent_id, namespace)`.
/// These legacy tests exercise the `_global` sentinel namespace so the
/// pre-#1156 behaviour is preserved byte-for-byte; per-namespace
/// isolation regression coverage lives in
/// `tests/per_namespace_quota.rs` and `src/quotas.rs::tests`.
fn tighten_caps(
    conn: &Connection,
    agent_id: &str,
    max_memories_per_day: i64,
    max_storage_bytes: i64,
    max_links_per_day: i64,
) {
    conn.execute(
        "UPDATE agent_quotas SET
           max_memories_per_day = ?1,
           max_storage_bytes    = ?2,
           max_links_per_day    = ?3
         WHERE agent_id = ?4 AND namespace = ?5",
        params![
            max_memories_per_day,
            max_storage_bytes,
            max_links_per_day,
            agent_id,
            GLOBAL_NAMESPACE,
        ],
    )
    .expect("tighten caps");
}

#[test]
fn k8_store_under_limit_returns_ok() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    // First call inserts the default row with the generous compiled
    // defaults; under those defaults a single 100-byte store passes.
    quotas::check_quota(
        &conn,
        "agent-under-limit",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 100 },
    )
    .expect("under limit must succeed");

    let status = quotas::get_status(&conn, "agent-under-limit", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(status.max_memories_per_day, DEFAULT_MAX_MEMORIES_PER_DAY);
    assert_eq!(status.max_storage_bytes, DEFAULT_MAX_STORAGE_BYTES);
    assert_eq!(status.max_links_per_day, DEFAULT_MAX_LINKS_PER_DAY);
}

#[test]
fn k8_store_at_memories_per_day_limit_returns_quota_exceeded() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    // Seed the row by passing a check, then tighten the cap to 1 and
    // record one op so the next check trips memories_per_day.
    quotas::check_quota(
        &conn,
        "agent-mem",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();
    tighten_caps(&conn, "agent-mem", 1, DEFAULT_MAX_STORAGE_BYTES, 1000);
    quotas::record_op(
        &conn,
        "agent-mem",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();

    let err = quotas::check_quota(
        &conn,
        "agent-mem",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 1 },
    )
    .expect_err("expected QUOTA_EXCEEDED");

    match err {
        QuotaCheckError::Quota(q) => {
            assert_eq!(q.limit, QuotaLimit::MemoriesPerDay);
            assert_eq!(q.max, 1);
            assert_eq!(q.current, 1);
            assert_eq!(q.agent_id, "agent-mem");
            // The Display impl includes the literal "QUOTA_EXCEEDED"
            // marker the MCP layer uses to surface the diagnostic name
            // to callers without parsing the message.
            let s = q.to_string();
            assert!(s.contains("QUOTA_EXCEEDED"), "expected marker in {s}");
            assert!(s.contains("memories_per_day"), "expected limit name in {s}");
        }
        QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL error: {e}"),
    }
}

#[test]
fn k8_store_at_storage_bytes_limit_returns_quota_exceeded() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    // Seed the row, tighten the storage cap, then attempt a write that
    // would push current_storage_bytes past the cap.
    quotas::check_quota(
        &conn,
        "agent-bytes",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 1 },
    )
    .unwrap();
    tighten_caps(&conn, "agent-bytes", 1000, 50, 1000);

    let err = quotas::check_quota(
        &conn,
        "agent-bytes",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 200 },
    )
    .expect_err("expected QUOTA_EXCEEDED");
    match err {
        QuotaCheckError::Quota(q) => {
            assert_eq!(q.limit, QuotaLimit::StorageBytes);
            assert_eq!(q.max, 50);
        }
        QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL error: {e}"),
    }
}

#[test]
fn k8_link_at_links_per_day_limit_returns_quota_exceeded() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    quotas::check_quota(&conn, "agent-links", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
    tighten_caps(&conn, "agent-links", 1000, DEFAULT_MAX_STORAGE_BYTES, 1);
    quotas::record_op(&conn, "agent-links", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();

    let err = quotas::check_quota(&conn, "agent-links", GLOBAL_NAMESPACE, QuotaOp::Link)
        .expect_err("expected QUOTA_EXCEEDED");
    match err {
        QuotaCheckError::Quota(q) => {
            assert_eq!(q.limit, QuotaLimit::LinksPerDay);
            assert_eq!(q.max, 1);
        }
        QuotaCheckError::Sql(e) => panic!("expected QuotaError, got SQL error: {e}"),
    }
}

/// H12 (#628 blocker) — concurrent writers must not each pass the
/// quota check and then both record_op past the cap. The
/// `check_and_record` API combines both operations into a single
/// `BEGIN IMMEDIATE` SQLite transaction so SQLite serialises every
/// other would-be writer behind the row lock. Spawn 10 threads each
/// trying to store one memory at a quota cap of 1; exactly 1 must
/// succeed and 9 must see `QUOTA_EXCEEDED`.
#[test]
fn k8_check_and_record_serialises_concurrent_writers_h12() {
    let (_keep, db_path) = fresh_db();

    // Seed the row with the default caps, then tighten memories cap
    // to 1. The first thread that wins the BEGIN IMMEDIATE lock will
    // commit a count of 1; every other thread must see QUOTA_EXCEEDED.
    {
        let conn = Connection::open(&db_path).unwrap();
        ai_memory::quotas::check_and_record(
            &conn,
            "race-agent",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 1 },
        )
        .expect("seed insert");
        // Reset the counter back to zero so the cap-1 race below can
        // play out from a clean slate.
        conn.execute(
            "UPDATE agent_quotas SET
               max_memories_per_day = 1,
               current_memories_today = 0
             WHERE agent_id = ?1 AND namespace = ?2",
            params!["race-agent", GLOBAL_NAMESPACE],
        )
        .unwrap();
    }

    // Spawn 10 threads. Each opens its own connection to the shared
    // on-disk database, then races to call `check_and_record`. SQLite
    // WAL mode permits concurrent readers, but writers serialise on
    // the RESERVED lock acquired by `BEGIN IMMEDIATE` — exactly the
    // shape `check_and_record` relies on.
    let path = std::sync::Arc::new(db_path.clone());
    let mut handles = Vec::new();
    for _ in 0..10 {
        let p = path.clone();
        handles.push(std::thread::spawn(move || -> bool {
            // Each thread retries on `SQLITE_BUSY` (the lock-waiter
            // signal) so the race is decided by quota state, not by
            // the OS scheduler dropping a busy retry. Cap retries to
            // avoid an infinite loop if something unexpected fails.
            let conn = {
                let c = Connection::open(&*p).expect("open");
                c.busy_timeout(std::time::Duration::from_secs(5))
                    .expect("set busy timeout");
                c
            };
            matches!(
                ai_memory::quotas::check_and_record(
                    &conn,
                    "race-agent",
                    GLOBAL_NAMESPACE,
                    QuotaOp::Memory { bytes: 1 },
                ),
                Ok(()),
            )
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for h in handles {
        if h.join().expect("thread join") {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one thread must commit past the cap-1 quota; got {successes} successes / {failures} failures"
    );
    assert_eq!(
        failures, 9,
        "the other nine threads must see QUOTA_EXCEEDED; got {successes} successes / {failures} failures"
    );

    // The persisted counter must read exactly 1 — no double-increment
    // could have slipped past the BEGIN IMMEDIATE lock.
    let conn = Connection::open(&db_path).unwrap();
    let s = ai_memory::quotas::get_status(&conn, "race-agent", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(
        s.current_memories_today, 1,
        "counter should be exactly 1 after the race"
    );
}

/// H12 — `refund_op` rolls back a successfully-recorded op when the
/// downstream insert fails. Callers use this to keep the quota
/// counter coherent with the actual successful-write count.
#[test]
fn k8_refund_op_decrements_counters_h12() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    ai_memory::quotas::check_and_record(
        &conn,
        "refund-agent",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 100 },
    )
    .unwrap();
    let pre = ai_memory::quotas::get_status(&conn, "refund-agent", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(pre.current_memories_today, 1);
    assert_eq!(pre.current_storage_bytes, 100);

    ai_memory::quotas::refund_op(
        &conn,
        "refund-agent",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 100 },
    )
    .unwrap();
    let post = ai_memory::quotas::get_status(&conn, "refund-agent", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(post.current_memories_today, 0);
    assert_eq!(post.current_storage_bytes, 0);

    // Saturating: extra refunds must not push counters below zero.
    ai_memory::quotas::refund_op(
        &conn,
        "refund-agent",
        GLOBAL_NAMESPACE,
        QuotaOp::Memory { bytes: 100 },
    )
    .unwrap();
    let saturated = ai_memory::quotas::get_status(&conn, "refund-agent", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(saturated.current_memories_today, 0);
    assert_eq!(saturated.current_storage_bytes, 0);
}

#[test]
fn k8_record_op_after_check_increments_counters() {
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).unwrap();

    // Three memory writes + two link writes against the same agent.
    for _ in 0..3 {
        quotas::check_quota(
            &conn,
            "agent-record",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 10 },
        )
        .unwrap();
        quotas::record_op(
            &conn,
            "agent-record",
            GLOBAL_NAMESPACE,
            QuotaOp::Memory { bytes: 10 },
        )
        .unwrap();
    }
    for _ in 0..2 {
        quotas::check_quota(&conn, "agent-record", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
        quotas::record_op(&conn, "agent-record", GLOBAL_NAMESPACE, QuotaOp::Link).unwrap();
    }
    let status = quotas::get_status(&conn, "agent-record", GLOBAL_NAMESPACE).unwrap();
    assert_eq!(status.current_memories_today, 3);
    assert_eq!(status.current_storage_bytes, 30);
    assert_eq!(status.current_links_today, 2);
}

// ---------------------------------------------------------------------------
// #1621 — K8 link-quota parity on the HTTP surface. Pre-#1621 only the
// MCP `memory_link` path charged `QuotaOp::Link`; `POST /api/v1/links`
// bypassed the quota entirely, so a throttled agent with HTTP access
// sidestepped K8 limits.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal")]
#[tokio::test]
#[allow(clippy::items_after_statements, clippy::too_many_lines)]
async fn k8_http_link_at_links_per_day_limit_returns_429_1621() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    const AID: &str = "ai:k8-http-1621";

    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let router = ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
        },
        app_state,
    );

    let post = |uri: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-agent-id", AID)
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let store_mem = |title: &str| {
        serde_json::json!({
            "title": title,
            "content": "body long enough to be a real memory for the 1621 quota test",
            "namespace": "k8-1621",
            "agent_id": AID,
        })
    };

    // Two owned memories to link.
    let r1 = router
        .clone()
        .oneshot(post("/api/v1/memories", store_mem("k8-1621-a")))
        .await
        .unwrap();
    assert!(r1.status().is_success(), "store a: {:?}", r1.status());
    let b1 = axum::body::to_bytes(r1.into_body(), usize::MAX)
        .await
        .unwrap();
    let id_a = serde_json::from_slice::<serde_json::Value>(&b1).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r2 = router
        .clone()
        .oneshot(post("/api/v1/memories", store_mem("k8-1621-b")))
        .await
        .unwrap();
    assert!(r2.status().is_success(), "store b: {:?}", r2.status());
    let b2 = axum::body::to_bytes(r2.into_body(), usize::MAX)
        .await
        .unwrap();
    let id_b = serde_json::from_slice::<serde_json::Value>(&b2).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Zero the link allowance on every accounting row for this agent.
    {
        // The two memory stores above already charged QuotaOp::Memory,
        // so the (agent, namespace) accounting row exists.
        let conn = Connection::open(&db_path).expect("open for cap tighten");
        conn.execute(
            "UPDATE agent_quotas SET max_links_per_day = 0 WHERE agent_id = ?1",
            params![AID],
        )
        .expect("tighten link cap");
    }

    // The link write must now 429 with the canonical envelope.
    let r3 = router
        .clone()
        .oneshot(post(
            "/api/v1/links",
            serde_json::json!({"source_id": id_a, "target_id": id_b, "relation": "related_to"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        r3.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "#1621: HTTP link at zero allowance must 429"
    );
    let b3 = axum::body::to_bytes(r3.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b3).unwrap();
    assert_eq!(v["code"].as_str(), Some("QUOTA_EXCEEDED"), "envelope: {v}");
    assert_eq!(v["limit"].as_str(), Some("links_per_day"), "envelope: {v}");

    // No row landed.
    {
        let conn = Connection::open(&db_path).expect("open for assert");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_links WHERE source_id = ?1",
                params![id_a],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "#1621: refused link must not persist");
    }
}
