// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4071 — the inbox SSE stream must not expose the PROCESS-WIDE wake
//! sequence.
//!
//! Every inbox wake draws its `seq` from one counter shared by all
//! recipients. The stream filtered frames by recipient correctly but
//! serialised the allowed event unchanged, so the gap between two of a
//! subscriber's OWN frames equalled the number of wakes published for OTHER
//! agents in between — the cross-tenant notify-rate signal the handler
//! already refuses to leak through a skipped-frame tick or a lag count.
//!
//! The pin consumes the REAL SSE response body for recipient A, publishes
//! wakes for A, B, B, A sequentially through the production notify funnel,
//! and asserts that no B frame appears and that A's wire frames carry exactly
//! the recipient-safe field set: the only counter on the wire is A's own
//! `recipient_seq` (#4125), and the two B publishes in between leave NO gap
//! in it. Once with sqlite publishers and once with the postgres adapter.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal")]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::{CallerContext, MemoryStore};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn sqlite_router(dir: &tempfile::TempDir) -> (axum::Router, Arc<dyn MemoryStore>) {
    let db_path = dir.path().join("m.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
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
        storage_backend: StorageBackend::Sqlite,
        store: Arc::clone(&store),
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
    (ai_memory::build_router(api_key_state, app_state), store)
}

/// Exactly what a recipient may learn from one of its own wakes.
const WIRE_FIELDS: [&str; 9] = [
    "event",
    "recipient_agent_id",
    "correlation_id",
    "inbox_row_id",
    "namespace",
    "sender_agent_id",
    "content_digest",
    "notified_at",
    "recipient_seq",
];

/// Parse the `data:` payloads of every complete SSE event in `text`.
fn frames(text: &str) -> Vec<(String, Value)> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut event = None;
            let mut data = String::new();
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    event = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push_str(v.trim_start());
                }
            }
            let event = event?;
            serde_json::from_str(&data).ok().map(|v| (event, v))
        })
        .collect()
}

/// Publish A, B, B, A through `store.notify` while A holds the real stream;
/// assert on every frame A's connection carried.
async fn run(router: &axum::Router, publisher: &Arc<dyn MemoryStore>) {
    use http_body_util::BodyExt as _;

    let a = uid("ai:rcpt-a-4071");
    let b = uid("ai:rcpt-b-4071");
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/inbox/stream")
                .header(ai_memory::HEADER_AGENT_ID, &a)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    // The handler subscribed before returning, so nothing below is missed.
    let ctx = CallerContext::for_agent("ai:sender-4071");
    let mut a_rows = Vec::new();
    for recipient in [&a, &b, &b, &a] {
        let id = publisher
            .notify(&ctx, recipient, "ping", "4071 body", Some(5), None, None)
            .await
            .expect("notify");
        if recipient == &a {
            a_rows.push(id);
        }
    }

    let mut buf = Vec::new();
    let read = async {
        loop {
            let text = String::from_utf8_lossy(&buf).into_owned();
            let mine = frames(&text)
                .into_iter()
                .filter(|(e, _)| e == "agent_notified")
                .count();
            if mine >= 2 {
                return text;
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(bytes) = frame.data_ref() {
                        buf.extend_from_slice(bytes);
                    }
                }
                Some(Err(e)) => panic!("body error: {e}"),
                None => panic!("stream ended early"),
            }
        }
    };
    let text = tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("A's two wakes within 10s");

    assert!(
        !text.contains(&b),
        "a B frame (or B's id) reached A's stream: {text}"
    );
    let notified: Vec<Value> = frames(&text)
        .into_iter()
        .filter(|(e, _)| e == "agent_notified")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(notified.len(), 2, "exactly A's two wakes: {text}");
    let expected: BTreeSet<&str> = WIRE_FIELDS.into_iter().collect();
    let mut recipient_seqs = Vec::new();
    for (frame, row) in notified.iter().zip(&a_rows) {
        let obj = frame.as_object().expect("frame is an object");
        let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys, expected,
            "the wire frame must carry exactly the recipient-safe fields — no \
             process-wide sequence: {frame}"
        );
        for (key, value) in obj {
            assert!(
                key == "recipient_seq" || !value.is_number(),
                "the only counter on the wire is the recipient's own: {key} in {frame}"
            );
        }
        assert_eq!(frame["recipient_agent_id"], Value::String(a.clone()));
        assert_eq!(frame["inbox_row_id"], Value::String(row.clone()));
        assert_eq!(frame["event"], "agent_notified");
        recipient_seqs.push(
            frame["recipient_seq"]
                .as_u64()
                .expect("recipient_seq is an unsigned integer"),
        );
    }
    // Two B wakes were published between A's two wakes. A's OWN sequence
    // must not reflect them: consecutive, no gap, nothing to count.
    assert_eq!(
        recipient_seqs[1],
        recipient_seqs[0] + 1,
        "A's recipient_seq must not skip over B's publishes: {recipient_seqs:?}"
    );
}

#[tokio::test]
async fn sqlite_inbox_stream_frames_carry_no_global_sequence_4071() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (router, store) = sqlite_router(&dir);
    run(&router, &store).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_published_wakes_carry_no_global_sequence_4071() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
    else {
        eprintln!("skip postgres_published_wakes_carry_no_global_sequence_4071: no PG url");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let (router, _) = sqlite_router(&dir);
    let pg: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("PostgresStore::connect"),
    );
    run(&router, &pg).await;
}
