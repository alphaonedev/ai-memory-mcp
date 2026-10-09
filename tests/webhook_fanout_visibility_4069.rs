// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4069 — webhook fan-out must check that the SUBSCRIPTION OWNER may read
//! the source memory before it delivers an event about it.
//!
//! Pre-fix the fan-out selected recipients by event / namespace / agent
//! STRING filters over the global subscription set and never consulted the
//! read predicate, so a non-admin subscriber with no filters was sent events
//! for another principal's PRIVATE memories — and on SQLite the delete event
//! carried the pre-delete TITLE, so private title text reached a subscriber
//! the read path denies (`GET /memories/{id}` → not found). The wire-surface
//! gate the dispatcher's comment relied on only establishes subscription
//! OWNERSHIP, not per-event read authorization.
//!
//! Each cell registers two wildcard subscriptions — one owned by the row's
//! owner, one by a stranger — fires the dispatcher, and reads what the
//! recording TLS receiver saw. The stranger must receive NOTHING about a
//! private row (store and delete), while the owner still does; the
//! collective-scope control proves the stranger is not simply cut off.

#![allow(clippy::too_many_lines)]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::subscriptions::{
    DeleteEventDetails, NewSubscription, dispatch_event, dispatch_event_with_details, insert,
    wait_dispatch_idle,
};
use serde_json::json;
use std::path::{Path, PathBuf};

mod common;
use common::tls_receiver::{TlsReceiver, ack_echo, dispatch_tls};

/// The two webhook event names under test (the MCP tool names).
const MEMORY_STORE: &str = "memory_store";
const MEMORY_DELETE: &str = "memory_delete";
const ALICE: &str = "ai:alice-4069";
const BOB: &str = "ai:bob-4069";
const NS: &str = "fanout-visibility-4069";
const PRIVATE_TITLE: &str = "alice private title 4069";

fn scratch(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("tempdir under .local-runs")
}

fn local_runs() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
}

fn open_db(dir: &Path) -> (PathBuf, rusqlite::Connection) {
    let path = dir.join("fanout.db");
    let conn = ai_memory::db::open(&path).expect("open sqlite db");
    (path, conn)
}

fn memory(owner: &str, scope: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = match scope {
        Some(s) => json!({ "agent_id": owner, "scope": s }),
        None => json!({ "agent_id": owner }),
    };
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: PRIVATE_TITLE.to_string(),
        content: "private body".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// A wildcard subscription owned by `created_by` whose hook path carries
/// `tag`, so the receiver's log tells the two subscribers apart.
fn subscribe(conn: &rusqlite::Connection, receiver: &TlsReceiver, created_by: &str, tag: &str) -> String {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let path = format!("/{tag}/{unique}");
    let url = format!("{}{path}", receiver.uri());
    insert(
        conn,
        &NewSubscription {
            url: &url,
            events: "*",
            secret: Some("fanout-secret-4069"),
            namespace_filter: None,
            agent_filter: None,
            created_by: Some(created_by),
            event_types: None,
        },
    )
    .expect("insert subscription");
    path
}

async fn receiver() -> TlsReceiver {
    ai_memory::config::set_allow_loopback_webhooks(true);
    let tls = dispatch_tls(&local_runs());
    TlsReceiver::start_with(tls, ack_echo()).await
}

/// Did the receiver see a delivery on `path`?
async fn delivered(receiver: &TlsReceiver, path: &str) -> bool {
    receiver
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .any(|r| r.url.path() == path)
}

/// Bodies delivered on `path`, as UTF-8.
async fn bodies_on(receiver: &TlsReceiver, path: &str) -> Vec<String> {
    receiver
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == path)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// A `memory_store` event about alice's PRIVATE row reaches alice's
/// subscription and NOT bob's.
#[tokio::test(flavor = "multi_thread")]
async fn private_store_event_reaches_only_subscribers_who_can_read_it_4069() {
    let receiver = receiver().await;
    let dir = scratch("fanout-4069-store-");
    let (db_path, conn) = open_db(dir.path());
    let bob_path = subscribe(&conn, &receiver, BOB, "bob");
    let alice_path = subscribe(&conn, &receiver, ALICE, "alice");
    let id = ai_memory::db::insert(&conn, &memory(ALICE, None)).expect("insert alice's row");

    dispatch_event(&conn, MEMORY_STORE, &id, NS, Some(ALICE), &db_path);
    wait_dispatch_idle().await;

    assert!(
        delivered(&receiver, &alice_path).await,
        "the owner's own subscription receives the event"
    );
    assert!(
        !delivered(&receiver, &bob_path).await,
        "#4069: bob cannot read alice's private row, so bob's subscription must not \
         receive an event about it"
    );
}

/// A `memory_delete` event (which carries the pre-delete TITLE on SQLite)
/// about alice's private row must not reach bob.
#[tokio::test(flavor = "multi_thread")]
async fn private_delete_title_does_not_reach_a_non_reader_4069() {
    let receiver = receiver().await;
    let dir = scratch("fanout-4069-delete-");
    let (db_path, conn) = open_db(dir.path());
    let bob_path = subscribe(&conn, &receiver, BOB, "bob");
    let alice_path = subscribe(&conn, &receiver, ALICE, "alice");
    let row = memory(ALICE, None);
    let id = ai_memory::db::insert(&conn, &row).expect("insert alice's row");
    assert!(ai_memory::db::delete(&conn, &id).expect("delete"), "row deleted");

    let details = serde_json::to_value(DeleteEventDetails {
        title: row.title.clone(),
        tier: row.tier.to_string(),
    })
    .ok();
    dispatch_event_with_details(
        &conn,
        MEMORY_DELETE,
        &id,
        NS,
        Some(ALICE),
        &db_path,
        details,
    );
    wait_dispatch_idle().await;

    let alice_bodies = bodies_on(&receiver, &alice_path).await;
    assert!(
        alice_bodies.iter().any(|b| b.contains(PRIVATE_TITLE)),
        "the owner's subscription receives the delete event with its title: {alice_bodies:?}"
    );
    let bob_bodies = bodies_on(&receiver, &bob_path).await;
    assert!(
        bob_bodies.is_empty(),
        "#4069: bob is denied a direct read of the row, so the delete event (and its \
         title) must not reach bob: {bob_bodies:?}"
    );
}

/// CONTROL — a `scope=collective` row is readable by everyone, so both
/// subscriptions receive the event: the stranger is filtered by READ
/// permission, not cut off.
#[tokio::test(flavor = "multi_thread")]
async fn collective_store_event_reaches_every_subscriber_4069_control() {
    let receiver = receiver().await;
    let dir = scratch("fanout-4069-collective-");
    let (db_path, conn) = open_db(dir.path());
    let bob_path = subscribe(&conn, &receiver, BOB, "bob");
    let alice_path = subscribe(&conn, &receiver, ALICE, "alice");
    let id = ai_memory::db::insert(&conn, &memory(ALICE, Some("collective")))
        .expect("insert alice's collective row");

    dispatch_event(&conn, MEMORY_STORE, &id, NS, Some(ALICE), &db_path);
    wait_dispatch_idle().await;

    assert!(delivered(&receiver, &alice_path).await, "owner receives");
    assert!(
        delivered(&receiver, &bob_path).await,
        "control: a collective row is readable by bob, so bob's subscription receives it"
    );
}

/// The POSTGRES dispatch arm (`dispatch_event_postgres`, SAL-backed
/// `_subscriptions/<agent>` rows) applies the same read gate.
#[cfg(feature = "sal")]
mod postgres_arm {
    use super::*;
    use ai_memory::handlers::{AppState, StorageBackend, dispatch_event_postgres};
    use ai_memory::store::{CallerContext, MemoryStore, sqlite::SqliteStore};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Mutex, RwLock};

    /// SHA-256 hex of the per-subscription secret, as the postgres
    /// `subscribe` arm persists it (unsigned dispatch is disabled, so a
    /// subscription without a resolvable secret is never delivered).
    fn secret_hash(secret: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(secret.as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    fn subscription_memory(owner: &str, url: &str) -> Memory {
        let sub_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: sub_id.clone(),
            tier: Tier::Long,
            namespace: format!("_subscriptions/{owner}"),
            title: format!("subscription:{sub_id}"),
            content: format!("subscription for {owner}"),
            tags: vec!["subscription".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "subscribe".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({
                "kind": "subscription",
                "agent_id": owner,
                "subscription_id": sub_id,
                "url": url,
                "events": "*",
                "secret_hash": secret_hash("fanout-secret-4069"),
                "created_by": owner,
                "created_at": chrono::Utc::now().to_rfc3339(),
            }),
            memory_kind: MemoryKind::Observation,
            confidence_source: ConfidenceSource::CallerProvided,
            version: 1,
            ..Memory::default()
        }
    }

    fn state(dir: &Path) -> AppState {
        let sqlite_path = dir.join("audit.db");
        let conn = ai_memory::db::open(&sqlite_path).expect("open sqlite audit db");
        let db: ai_memory::handlers::Db = Arc::new(Mutex::new((
            conn,
            sqlite_path,
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        let store: Arc<dyn MemoryStore> =
            Arc::new(SqliteStore::open(dir.join("store.db")).expect("open SAL SqliteStore"));
        AppState {
            db,
            embedder: Arc::new(None),
            vector_index: Arc::new(Mutex::new(None)),
            federation: Arc::new(None),
            tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: Arc::new(None),
            active_keypair: Arc::new(None),
            family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
            store,
            llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: Duration::from_secs(30),
            replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::new()),
            verify_require_nonce: false,
            federation_nonce_cache: Arc::new(
                ai_memory::identity::replay::FederationNonceCache::new(),
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
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_store_event_reaches_only_readers_on_the_postgres_arm_4069() {
        let receiver = receiver().await;
        let dir = scratch("fanout-4069-pg-");
        let state = state(dir.path());
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let bob_path = format!("/pg-bob/{unique}");
        let alice_path = format!("/pg-alice/{unique}");
        let admin = CallerContext::for_admin("test-setup-4069");
        for (owner, path) in [(BOB, &bob_path), (ALICE, &alice_path)] {
            state
                .store
                .store(
                    &admin,
                    &subscription_memory(owner, &format!("{}{path}", receiver.uri())),
                )
                .await
                .expect("seed subscription memory");
        }
        let id = state
            .store
            .store(&CallerContext::for_agent(ALICE), &memory(ALICE, None))
            .await
            .expect("store alice's private row");

        dispatch_event_postgres(&state, MEMORY_STORE, &id, NS, Some(ALICE), None)
            .await;
        wait_dispatch_idle().await;

        assert!(
            delivered(&receiver, &alice_path).await,
            "the owner's own subscription receives the event (postgres arm)"
        );
        assert!(
            !delivered(&receiver, &bob_path).await,
            "#4069: bob cannot read alice's private row, so bob's subscription must not \
             receive an event about it (postgres arm)"
        );
        // Keep the scratch dir alive past the worker's audit writes.
        std::mem::forget(dir);
    }
}
