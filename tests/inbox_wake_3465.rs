// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3465 — `agent_notified` write event + the agent-facing wake
//! stream.
//!
//! Pre-#3465 `memory_notify` wrote a durable inbox row and dispatched
//! NOTHING: no subscription event, no push. A recipient could only
//! discover mail by polling. These tests pin the control on BOTH
//! halves of the fix and on BOTH the allowed and the denied path:
//!
//! * every notify funnel emits `agent_notified` (MCP `handle_notify`,
//!   which the CLI and the HTTP sqlite branch route through, and the
//!   `SqliteStore` SAL adapter; the postgres adapter twin lives in
//!   `tests/inbox_wake_postgres_3465.rs`, which needs a live cluster);
//! * the frame carries a `sha256:` digest and NEVER the body;
//! * `GET /api/v1/inbox/stream` delivers a recipient its OWN wake
//!   (ALLOWED) and delivers a non-recipient NOTHING (DENIED), rather
//!   than becoming a push-shaped way to observe an inbox the pull
//!   surface would refuse;
//! * `agent_notified` is a real, subscribable webhook event type, so
//!   adding it to `WEBHOOK_EVENT_TYPES` is not a claim the substrate
//!   cannot honour.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE
// the `#![cfg]` so they still apply on a leg where the cfg empties the
// crate but the `//!` module docs above are still linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]
#![cfg(feature = "sal")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend, inbox_wake_visible_to};
use ai_memory::inbox_wake::{InboxEvent, subscribe};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt as _;

/// A per-test recipient id. The wake bus is process-wide, so every test
/// filters the frames it receives to its own recipient rather than
/// assuming it is the only publisher.
fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn temp_db() -> std::path::PathBuf {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    db_path
}

fn build_sqlite_router(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("SqliteStore"));
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
        store,
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
    ai_memory::build_router(api_key_state, app_state)
}

/// Drain the bus until a wake for `recipient` shows up, or the deadline
/// passes. Frames for other tests' recipients are skipped.
async fn wake_for(
    rx: &mut tokio::sync::broadcast::Receiver<InboxEvent>,
    recipient: &str,
) -> Option<InboxEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => return Some(ev),
            // Another test's recipient, or a ring overrun caused by a
            // concurrent test: keep looking until the deadline.
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// The emitter: every notify funnel wakes the recipient
// ---------------------------------------------------------------------------

/// ALLOWED path, MCP funnel: a committed `memory_notify` publishes one
/// wake naming the recipient, the sender, the durable row and a digest.
#[tokio::test]
async fn mcp_notify_publishes_a_wake_3465() {
    let recipient = uid("bob");
    let payload = "the body nobody may put on the bus";
    let db_path = temp_db();
    let conn = ai_memory::db::open(&db_path).expect("open");
    let mut rx = subscribe();

    let envelope = ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": recipient,
            "title": "ping",
            "payload": payload,
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");
    let row_id = envelope["id"].as_str().expect("id").to_string();
    // The sender on the wake must be the RESOLVED principal the
    // envelope reports, not the raw `mcp_client` hint: `handle_notify`
    // runs it through `identity::resolve_agent_id`, which host-qualifies
    // it. Pinning them to each other catches a future divergence between
    // what the caller is told and what the wake attributes the write to.
    let expected_sender = envelope["from"].as_str().expect("from").to_string();

    let ev = wake_for(&mut rx, &recipient).await.expect("wake published");
    let InboxEvent::AgentNotified {
        recipient_agent_id,
        inbox_row_id,
        namespace,
        sender_agent_id,
        content_digest,
        correlation_id,
        seq,
        ..
    } = ev;
    assert_eq!(recipient_agent_id, recipient);
    assert_eq!(inbox_row_id, row_id, "the wake must name the durable row");
    // #3401 unified BOTH notify lanes on the canonical
    // `_inbox/<agent>` namespace (`_messages/<agent>` survives only as
    // a lossless legacy read alias), so the wake reports the namespace
    // the row ACTUALLY landed in via the same SSOT helper the SAL twin
    // asserts against — never a lane-specific literal.
    assert_eq!(namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(sender_agent_id, expected_sender);
    assert!(seq > 0, "wake seq starts at 1");
    assert_eq!(
        correlation_id,
        ai_memory::write_events::correlation_id_for(&row_id),
        "every lane must derive the same correlation handle"
    );
    assert!(
        content_digest.starts_with("sha256:"),
        "digest must be a labelled sha256; got {content_digest}"
    );
    assert_ne!(
        content_digest,
        format!("sha256:{payload}"),
        "the digest must be a hash, not the body wearing a prefix"
    );
}

/// DENIED path: the BODY never reaches the bus. This is the property
/// the whole design turns on — the bus is process-wide and holds every
/// tenant's frames next to each other.
#[tokio::test]
async fn wake_frame_never_carries_the_body_3465() {
    let recipient = uid("carol");
    let secret = "SUPER-SECRET-NOTIFY-BODY-3465";
    let db_path = temp_db();
    let conn = ai_memory::db::open(&db_path).expect("open");
    let mut rx = subscribe();

    ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": recipient,
            "title": "subject line",
            "payload": secret,
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");

    let ev = wake_for(&mut rx, &recipient).await.expect("wake published");
    let wire = serde_json::to_string(&ev).expect("serialise");
    assert!(
        !wire.contains(secret),
        "the notification body must never appear on the wake bus: {wire}"
    );
    // The title is caller content too, and is equally absent.
    assert!(!wire.contains("subject line"), "{wire}");
}

/// ALLOWED path, SAL funnel (sqlite adapter): a direct
/// `MemoryStore::notify` caller also wakes its recipient, so the wake
/// does not depend on which surface the write arrived through.
#[tokio::test]
async fn sqlite_sal_notify_publishes_a_wake_3465() {
    let recipient = uid("dave");
    let db_path = temp_db();
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore");
    let ctx = ai_memory::store::CallerContext::for_agent("ai:alice");
    let mut rx = subscribe();

    let new_id = {
        use ai_memory::store::MemoryStore as _;
        store
            .notify(&ctx, &recipient, "ping", "body", Some(5), None, None)
            .await
            .expect("sal notify")
    };

    let ev = wake_for(&mut rx, &recipient).await.expect("wake published");
    assert_eq!(ev.recipient_agent_id(), recipient);
    let InboxEvent::AgentNotified {
        inbox_row_id,
        namespace,
        ..
    } = ev;
    assert_eq!(inbox_row_id, new_id);
    // Both lanes write the canonical `_inbox/<agent>` since #3401; the
    // wake reports the namespace the row ACTUALLY landed in rather than
    // a lane-blind guess, so a future divergence fails here.
    assert_eq!(namespace, ai_memory::inbox_namespace(&recipient));
}

// ---------------------------------------------------------------------------
// Visibility predicate — allowed vs denied
// ---------------------------------------------------------------------------

#[test]
fn only_the_recipient_may_see_a_wake_3465() {
    let ev = InboxEvent::AgentNotified {
        seq: 1,
        recipient_agent_id: "bob".into(),
        correlation_id: "sha256:c".into(),
        inbox_row_id: "row".into(),
        namespace: "_messages/bob".into(),
        sender_agent_id: "alice".into(),
        content_digest: "sha256:d".into(),
        notified_at: "2026-09-02T00:00:00Z".into(),
    };
    // ALLOWED
    assert!(inbox_wake_visible_to("bob", &ev));
    // DENIED — no delegation, unlike the approvals stream.
    assert!(!inbox_wake_visible_to("alice", &ev));
    assert!(!inbox_wake_visible_to("", &ev));
    assert!(!inbox_wake_visible_to("host:node-1", &ev));
}

// ---------------------------------------------------------------------------
// GET /api/v1/inbox/stream
// ---------------------------------------------------------------------------

/// ALLOWED path, end to end: the recipient holds the stream, a notify
/// commits, and the recipient's connection carries the frame.
#[tokio::test]
async fn inbox_stream_delivers_the_recipients_own_wake_3465() {
    use http_body_util::BodyExt as _;

    let recipient = uid("erin");
    let db_path = temp_db();
    let router = build_sqlite_router(&db_path);

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/inbox/stream")
                .header("x-agent-id", &recipient)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(ct.contains("text/event-stream"), "got {ct}");
    let mut body = resp.into_body();

    // The handler subscribed before returning the response, so a notify
    // issued now cannot be missed.
    let conn = ai_memory::db::open(&db_path).expect("open");
    ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": recipient,
            "title": "ping",
            "payload": "body",
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");

    let mut buf = Vec::new();
    let read = async {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(bytes) = frame.data_ref() {
                        buf.extend_from_slice(bytes);
                        if String::from_utf8_lossy(&buf).contains("agent_notified") {
                            return Ok::<(), String>(());
                        }
                    }
                }
                Some(Err(e)) => return Err(format!("body error: {e}")),
                None => return Err("body ended before the wake".into()),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("SSE timeout - no agent_notified frame in 10s")
        .expect("SSE read failed");
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("event: agent_notified"), "{text}");
    assert!(text.contains("content_digest"), "{text}");
    assert!(
        !text.contains("\"body\""),
        "the notification body must not ride the SSE frame: {text}"
    );
}

/// DENIED path, end to end: a DIFFERENT agent holding the stream
/// receives nothing at all when someone else is notified — not the
/// frame, not a redacted stand-in, not a tick that would leak the
/// other tenant's notify rate.
#[tokio::test]
async fn inbox_stream_never_delivers_another_agents_wake_3465() {
    use http_body_util::BodyExt as _;

    let recipient = uid("frank");
    let eavesdropper = uid("mallory");
    let db_path = temp_db();
    let router = build_sqlite_router(&db_path);

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/inbox/stream")
                .header("x-agent-id", &eavesdropper)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    let conn = ai_memory::db::open(&db_path).expect("open");
    ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": recipient,
            "title": "private",
            "payload": "not for mallory",
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");

    // Nothing may arrive. The keepalive interval is 15 s, so a 3 s
    // window is quiet by construction on a stream with no visible
    // frames.
    match tokio::time::timeout(Duration::from_secs(3), body.frame()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(Ok(frame))) => {
            let text = frame
                .data_ref()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default();
            assert!(
                !text.contains("agent_notified") && !text.contains(&recipient),
                "a non-recipient received another agent's wake: {text}"
            );
        }
        Ok(Some(Err(e))) => panic!("stream error: {e}"),
    }
}

/// DENIED path: an unresolved identity is fail-closed. The stream still
/// OPENS (200, matching `approvals_sse`), it simply never emits.
#[tokio::test]
async fn inbox_stream_anonymous_subscriber_opens_but_is_fail_closed_3465() {
    for header in [None, Some("host:laptop:pid-1")] {
        let db_path = temp_db();
        let router = build_sqlite_router(&db_path);
        let mut req = Request::builder().method("GET").uri("/api/v1/inbox/stream");
        if let Some(h) = header {
            req = req.header("x-agent-id", h);
        }
        let resp = router
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "header={header:?}");
    }
    // The visibility half of "fail closed" is pinned by
    // `only_the_recipient_may_see_a_wake_3465`.
}

// ---------------------------------------------------------------------------
// The webhook lane half of the same event
// ---------------------------------------------------------------------------

/// ALLOWED + DENIED on the subscription surface: `agent_notified` is a
/// real canonical event type an operator can subscribe to, and a
/// near-miss is still refused — so adding it to `WEBHOOK_EVENT_TYPES`
/// is a claim the substrate honours rather than a decorative entry.
#[test]
fn agent_notified_is_a_subscribable_webhook_event_3465() {
    let db_path = temp_db();
    let conn = ai_memory::db::open(&db_path).expect("open");

    let allowed = ai_memory::subscriptions::insert(
        &conn,
        &ai_memory::subscriptions::NewSubscription {
            url: "https://example.invalid/hook",
            events: "agent_notified",
            secret: Some("s3cret"),
            namespace_filter: None,
            agent_filter: None,
            created_by: Some("ai:operator"),
            event_types: Some(&["agent_notified".to_string()]),
        },
    )
    .expect("agent_notified must be subscribable");
    assert!(!allowed.is_empty());

    let denied = ai_memory::subscriptions::insert(
        &conn,
        &ai_memory::subscriptions::NewSubscription {
            url: "https://example.invalid/hook",
            events: "agent_notifiedd",
            secret: None,
            namespace_filter: None,
            agent_filter: None,
            created_by: Some("ai:operator"),
            event_types: Some(&["agent_notifiedd".to_string()]),
        },
    );
    assert!(
        denied.is_err(),
        "an unknown event type must still be refused"
    );
}
