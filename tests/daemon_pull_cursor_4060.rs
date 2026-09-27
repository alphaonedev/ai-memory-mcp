// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4060: explicit null holds the pull cursor; missing fields remain legacy-compatible.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::handlers::Db;
use ai_memory::models::Memory;
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use tokio::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());
const PEER: &str = "ai:catchup-peer-3582";
const LOCAL: &str = "ai:catchup-local-3582";
const BEFORE: &str = "2026-01-01T00:00:00Z";
const AFTER: &str = "2026-01-02T00:00:00Z";
const ENV_KEYS: [&str; 3] = [
    ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
    ai_memory::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
    "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
];

struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl EnvGuard {
    fn new() -> Self {
        Self(
            ENV_KEYS
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        )
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            // SAFETY: every test holds ENV_LOCK through all spawned tasks' termination.
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }
}

fn posture(require: Option<&str>, scoped: bool, namespace: &str) {
    // SAFETY: every caller holds ENV_LOCK through every catchup task's termination.
    unsafe {
        for key in ENV_KEYS {
            std::env::remove_var(key);
        }
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
        if let Some(value) = require {
            std::env::set_var(ENV_KEYS[1], value);
        }
        if scoped {
            std::env::set_var(
                ENV_KEYS[0],
                json!({PEER: {
                    "allowed_namespaces": [namespace], "allowed_sender_agent_ids": [PEER]
                }})
                .to_string(),
            );
        }
    }
}

fn db() -> Db {
    Arc::new(Mutex::new((
        ai_memory::db::open(std::path::Path::new(":memory:")).expect("sqlite"),
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

fn memory(namespace: &str) -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    Memory {
        id: id.clone(),
        title: format!("catchup-{id}"),
        namespace: namespace.to_string(),
        content: "original content".to_string(),
        source: "system".to_string(),
        created_at: BEFORE.to_string(),
        updated_at: BEFORE.to_string(),
        metadata: json!({"agent_id": PEER, "scope": "collective"}),
        ..Memory::default()
    }
}

/// Abort on unwind as well; normal completion additionally joins every task.
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Task {
    async fn stop(&mut self) {
        self.0.abort();
        let result = (&mut self.0).await;
        assert!(
            result.is_ok() || result.is_err_and(|e| e.is_cancelled()),
            "task panicked"
        );
    }
}

type Envelope = Arc<std::sync::Mutex<Value>>;

async fn peer(envelope: Value) -> (FederationConfig, Envelope, Task) {
    let payload = Arc::new(std::sync::Mutex::new(envelope));
    let response = payload.clone();
    let router = Router::new()
        .route(
            "/api/v1/sync/since",
            get(
                move |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let mut body = response.lock().unwrap().clone();
                    if let Some(since) = query.get("since") {
                        let rows = body["memories"].as_array_mut().unwrap();
                        rows.retain(|row| row["updated_at"].as_str().unwrap() > since.as_str());
                        let count = rows.len();
                        body["count"] = json!(count);
                    }
                    async move { Json(body) }
                },
            ),
        )
        .route(
            "/api/v1/sync/push",
            axum::routing::post(|| async { Json(json!({"applied":0})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    (
        FederationConfig {
            policy: ai_memory::replication::QuorumPolicy::new(
                2,
                1,
                Duration::from_secs(10),
                Duration::from_secs(30),
            )
            .unwrap(),
            peers: vec![PeerEndpoint {
                id: PEER.into(),
                sync_push_url: format!("http://{addr}/api/v1/sync/push"),
            }],
            client: reqwest::Client::new(),
            sender_agent_id: LOCAL.into(),
            api_key: None,
            signing_key: None,
            dlq_sink: None,
        },
        payload,
        task,
    )
}

#[tokio::test]
async fn explicit_null_holds_serve_puller_4060() {
    check_puller(false).await;
}

#[tokio::test]
async fn explicit_null_holds_sync_daemon_puller_4060() {
    check_puller(true).await;
}

async fn check_puller(sync_daemon: bool) {
    let _lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::new();
    posture(Some("0"), false, "cursor4060");
    for cursor in [Some(Value::Null), None, Some(json!(AFTER))] {
        let rows: Vec<_> = (0..2)
            .map(|_| {
                let mut row = memory("cursor4060");
                row.updated_at = AFTER.into();
                row
            })
            .collect();
        let mut body = json!({"memories": rows, "count":2, "limit":2});
        if let Some(value) = &cursor {
            body["next_since"] = value.clone();
        }
        let (config, payload, mut server) = peer(body).await;
        let expected = if cursor == Some(Value::Null) {
            BEFORE
        } else {
            AFTER
        };
        if !sync_daemon {
            let db = db();
            ai_memory::db::sync_state_observe(&db.lock().await.0, LOCAL, PEER, BEFORE).unwrap();
            catchup(&config, &db).await;
            let actual = ai_memory::db::sync_state_load(&db.lock().await.0, LOCAL).unwrap();
            assert_eq!(
                actual.entries[PEER], expected,
                "serve cursor for {cursor:?}"
            );
            assert!(
                ai_memory::db::get(&db.lock().await.0, &rows[0].id)
                    .unwrap()
                    .is_some()
            );
            if cursor == Some(Value::Null) {
                let third = enlarge_page(&payload, &rows);
                catchup(&config, &db).await;
                assert!(
                    ai_memory::db::get(&db.lock().await.0, &third.id)
                        .unwrap()
                        .is_some(),
                    "the formerly omitted tie row must arrive"
                );
                assert_eq!(
                    ai_memory::db::sync_state_load(&db.lock().await.0, LOCAL)
                        .unwrap()
                        .entries[PEER],
                    AFTER
                );
            }
        } else {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sync.db");
            let url = config.peers[0]
                .sync_push_url
                .trim_end_matches("/api/v1/sync/push");
            let conn = ai_memory::db::open(&path).unwrap();
            ai_memory::db::sync_state_observe(&conn, LOCAL, url, BEFORE).unwrap();
            ai_memory::daemon_runtime::sync_cycle_once(&config.client, &path, LOCAL, url, None, 2)
                .await
                .unwrap();
            let actual = ai_memory::db::sync_state_load(&conn, LOCAL).unwrap();
            assert_eq!(
                actual.entries[url], expected,
                "sync-daemon cursor for {cursor:?}"
            );
            if cursor == Some(Value::Null) {
                let third = enlarge_page(&payload, &rows);
                ai_memory::daemon_runtime::sync_cycle_once(
                    &config.client,
                    &path,
                    LOCAL,
                    url,
                    None,
                    4,
                )
                .await
                .unwrap();
                assert!(
                    ai_memory::db::get(&conn, &third.id).unwrap().is_some(),
                    "the formerly omitted tie row must arrive"
                );
                assert_eq!(
                    ai_memory::db::sync_state_load(&conn, LOCAL)
                        .unwrap()
                        .entries[url],
                    AFTER
                );
            }
        }
        server.stop().await;
    }
}

async fn catchup(config: &FederationConfig, db: &Db) {
    ai_memory::federation::catchup_apply_once_for_tests(
        config,
        db,
        #[cfg(feature = "sal")]
        None,
    )
    .await;
}

fn enlarge_page(payload: &Envelope, rows: &[Memory]) -> Memory {
    let mut third = memory("cursor4060");
    third.updated_at = AFTER.into();
    let mut all = rows.to_vec();
    all.push(third.clone());
    *payload.lock().unwrap() = json!({"memories": all, "count":3, "limit":4, "next_since": AFTER});
    third
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires dedicated AI_MEMORY_TEST_POSTGRES_URL"]
async fn postgres_explicit_null_holds_then_recovers_tie_tail_4060() {
    let _lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::new();
    posture(Some("0"), false, "cursor4060");
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("dedicated database");
    let pg = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .unwrap(),
    );
    let store: Arc<dyn ai_memory::store::MemoryStore> = pg.clone();
    let rows: Vec<_> = (0..2)
        .map(|_| {
            let mut row = memory("cursor4060");
            row.updated_at = AFTER.into();
            row
        })
        .collect();
    let (config, payload, mut server) =
        peer(json!({"memories": rows, "count":2, "limit":2, "next_since":null})).await;
    let db = db();
    ai_memory::db::sync_state_observe(&db.lock().await.0, LOCAL, PEER, BEFORE).unwrap();
    ai_memory::federation::catchup_apply_once_for_tests(&config, &db, Some(&store)).await;
    assert_eq!(
        ai_memory::db::sync_state_load(&db.lock().await.0, LOCAL)
            .unwrap()
            .entries[PEER],
        BEFORE
    );
    let third = enlarge_page(&payload, &rows);
    ai_memory::federation::catchup_apply_once_for_tests(&config, &db, Some(&store)).await;
    let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
        .bind(&third.id)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert!(
        found,
        "PostgreSQL receiver must recover the omitted tie row"
    );
    assert_eq!(
        ai_memory::db::sync_state_load(&db.lock().await.0, LOCAL)
            .unwrap()
            .entries[PEER],
        AFTER
    );
    assert!(
        ai_memory::db::get(&db.lock().await.0, &third.id)
            .unwrap()
            .is_none(),
        "the corpus must not fall through to the SQLite sidecar"
    );
    server.stop().await;
}
