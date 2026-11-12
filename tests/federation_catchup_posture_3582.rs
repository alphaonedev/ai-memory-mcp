// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3582: production catchup loops must never apply a row the peer may not
//! write, on SQLite and the live PostgreSQL SAL dispatch.
//!
//! #9198: under the #8788 settled-row contract a namespace refusal is
//! recorded (one `RefusedRow` with reason `namespace_scope`, the refused-rows
//! counter +1) and the since cursor passes the refused row; the receiver keeps
//! every column of its own copy and the sender keeps the row.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::federation::{
    FederationConfig, PeerEndpoint, PullOutcome, RefusalReason, RefusedRow,
};
use ai_memory::handlers::Db;
use ai_memory::models::Memory;
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify};

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

/// The label of the refused-rows counter series a namespace refusal bumps.
const NAMESPACE_SCOPE: &str = "namespace_scope";

fn refused_namespace_scope_total() -> u64 {
    ai_memory::metrics::registry()
        .federation_pull_rows_refused_total
        .with_label_values(&[NAMESPACE_SCOPE])
        .get()
}

/// The mock peer. `hold_second` parks every GET after the first, so a
/// spawned loop completes exactly one tick; without it every GET is
/// answered, so the sender can be read back after a single pass.
async fn peer(rows: Vec<Memory>, hold_second: bool) -> (FederationConfig, Arc<Notify>, Task) {
    let second = Arc::new(Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let notice = second.clone();
    let router = Router::new().route(
        "/api/v1/sync/since",
        get(move || {
            let rows = rows.clone();
            let calls = calls.clone();
            let notice = notice.clone();
            async move {
                if hold_second && calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0 {
                    // The sequential loop finished its first apply + cursor update.
                    // Hold this response so no second apply can begin.
                    notice.notify_one();
                    std::future::pending::<()>().await;
                }
                Json(json!({"memories": rows, "next_since": AFTER}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock peer");
    let address = listener.local_addr().expect("peer address");
    let task = Task(tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve peer");
    }));
    let config = FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            1,
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .expect("quorum"),
        peers: vec![PeerEndpoint {
            id: PEER.to_string(),
            sync_push_url: format!("http://{address}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client"),
        sender_agent_id: LOCAL.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    };
    (config, second, task)
}

/// The rows the sender still serves.
async fn sender_rows(config: &FederationConfig) -> Vec<Memory> {
    let base = config.peers[0]
        .sync_push_url
        .trim_end_matches("/api/v1/sync/push")
        .to_string();
    let body: Value = config
        .client
        .get(format!("{base}/api/v1/sync/since"))
        .send()
        .await
        .expect("GET sender")
        .json()
        .await
        .expect("sender JSON");
    serde_json::from_value(body["memories"].clone()).expect("sender rows")
}

fn single(mut outcomes: Vec<(String, PullOutcome)>) -> PullOutcome {
    assert_eq!(outcomes.len(), 1, "one configured peer, one outcome");
    let (peer_id, outcome) = outcomes.remove(0);
    assert_eq!(peer_id, PEER, "the outcome names the configured peer");
    outcome
}

/// #9198 — the exact values of one refused window: the outcome records one
/// `namespace_scope` refusal for `refused_id`, the counter moved by exactly
/// one, and the cursor equals `prior` with this peer's entry at `AFTER`.
async fn assert_refused_window(
    label: &str,
    db: &Db,
    outcome: &PullOutcome,
    refused_id: &str,
    counter_before: u64,
    prior: &Value,
) {
    assert_eq!(
        outcome.refused,
        vec![RefusedRow {
            memory_id: refused_id.to_string(),
            reason: RefusalReason::NamespaceScope,
        }],
        "{label}: a refused delivery is recorded as one namespace_scope RefusedRow"
    );
    assert_eq!(outcome.applied, 0, "{label}: nothing applied");
    assert_eq!(
        refused_namespace_scope_total() - counter_before,
        1,
        "{label}: the refused-rows counter moves by exactly one"
    );
    let mut expected = prior.clone();
    expected["entries"][PEER] = json!(AFTER);
    assert_eq!(
        cursor(db).await,
        expected,
        "{label}: a refused delivery is settled, the cursor passes it to AFTER (#8788)"
    );
}

async fn cursor(db: &Db) -> Value {
    let lock = db.lock().await;
    serde_json::to_value(
        ai_memory::db::sync_state_load(&lock.0, LOCAL).expect("read persisted cursor"),
    )
    .expect("clock JSON")
}

async fn seed_cursor(db: &Db) {
    let lock = db.lock().await;
    ai_memory::db::sync_state_observe(&lock.0, LOCAL, PEER, BEFORE).expect("seed prior cursor");
}

async fn complete_tick(mut task: Task, second: &Notify, server: &mut Task) {
    let completed = tokio::time::timeout(Duration::from_secs(30), second.notified()).await;
    task.stop().await;
    server.stop().await;
    completed.expect("second GET proves first catchup tick completed");
}

async fn sqlite_snapshot(db: &Db) -> Vec<Vec<rusqlite::types::Value>> {
    let lock = db.lock().await;
    let mut stmt = lock
        .0
        .prepare("SELECT * FROM memories ORDER BY id")
        .expect("snapshot query");
    let columns = stmt.column_count();
    stmt.query_map([], |r| {
        (0..columns)
            .map(|i| r.get(i))
            .collect::<rusqlite::Result<Vec<_>>>()
    })
    .expect("snapshot rows")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("snapshot values")
}

#[tokio::test]
async fn sqlite_catchup_posture_preserves_rows_and_cursor_3582() {
    let _lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::new();
    for (label, require, scoped, allowed) in [
        ("default-required", None, false, false),
        ("explicit-required", Some("1"), false, false),
        ("standard-opt-out", Some("0"), false, true),
        ("scoped", None, true, true),
    ] {
        let namespace = "catchup3582/ok";
        posture(require, scoped, namespace);
        let db = db();
        seed_cursor(&db).await;
        let original = memory(namespace);
        ai_memory::db::insert_if_newer(&db.lock().await.0, &original).expect("seed old row");
        let before = sqlite_snapshot(&db).await;
        let prior_cursor = cursor(&db).await;
        let mut update = original.clone();
        update.content = "received update".to_string();
        update.updated_at = AFTER.to_string();
        let mut new = memory(namespace);
        new.updated_at = AFTER.to_string();
        if !allowed {
            // #9198: one delivered row, refused, through one pass of the
            // production loop body (the outcome is the observable).
            let (config, _second, mut server) = peer(vec![update.clone()], false).await;
            let counter_before = refused_namespace_scope_total();
            let outcome = single(ai_memory::federation::catchup_pass_for_tests(&config, &db).await);
            assert_eq!(
                sqlite_snapshot(&db).await,
                before,
                "{label}: the refused row is not applied, every column preserved"
            );
            assert_refused_window(
                label,
                &db,
                &outcome,
                &update.id,
                counter_before,
                &prior_cursor,
            )
            .await;
            assert_eq!(
                sender_rows(&config)
                    .await
                    .into_iter()
                    .map(|m| (m.id, m.content, m.updated_at))
                    .collect::<Vec<_>>(),
                vec![(
                    update.id.clone(),
                    update.content.clone(),
                    update.updated_at.clone()
                )],
                "{label}: the sender still holds the refused row"
            );
            server.stop().await;
            continue;
        }
        let (config, second, mut server) = peer(vec![update.clone(), new.clone()], true).await;
        let task = Task(ai_memory::federation::spawn_catchup_loop(
            config,
            db.clone(),
            Duration::from_millis(1),
        ));
        complete_tick(task, &second, &mut server).await;
        {
            let lock = db.lock().await;
            let stored = ai_memory::db::get(&lock.0, &original.id)
                .expect("get old row")
                .expect("old row exists");
            assert_eq!(stored.content, update.content, "{label}");
            assert!(
                ai_memory::db::get(&lock.0, &new.id)
                    .expect("get new row")
                    .is_some(),
                "{label}"
            );
            drop(lock);
            assert_eq!(cursor(&db).await["entries"][PEER], json!(AFTER), "{label}");
        }
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_catchup_posture_preserves_rows_and_cursor_3582() {
    use ai_memory::store::{CallerContext, MemoryStore, postgres::PostgresStore};
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _lock = ENV_LOCK.lock().await;
    let _env = EnvGuard::new();
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(&url).await.expect("live PG store"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("raw snapshots");
    let ctx = CallerContext::for_agent(PEER);
    for (label, require, scoped, allowed) in [
        ("default-required", None, false, false),
        ("explicit-required", Some("1"), false, false),
        ("standard-opt-out", Some("0"), false, true),
        ("scoped", None, true, true),
    ] {
        let namespace = format!("catchup3582/{}", uuid::Uuid::new_v4());
        posture(require, scoped, &namespace);
        let db = db();
        seed_cursor(&db).await;
        let original = memory(&namespace);
        store.store(&ctx, &original).await.expect("seed old PG row");
        let snapshot_sql = "SELECT to_jsonb(m) FROM memories m WHERE namespace = $1 ORDER BY id";
        let before: Vec<Value> = sqlx::query_scalar(snapshot_sql)
            .bind(&namespace)
            .fetch_all(&pool)
            .await
            .expect("snapshot before");
        let prior_cursor = cursor(&db).await;
        let mut update = original.clone();
        update.content = "received update".to_string();
        update.updated_at = AFTER.to_string();
        let mut new = memory(&namespace);
        new.updated_at = AFTER.to_string();
        if !allowed {
            // #9198: one delivered row, refused, through one pass of the
            // production SAL loop body.
            let (config, _second, mut server) = peer(vec![update.clone()], false).await;
            let counter_before = refused_namespace_scope_total();
            let outcome = single(
                ai_memory::federation::catchup_pass_with_store_for_tests(&config, &db, &store)
                    .await,
            );
            let after: Vec<Value> = sqlx::query_scalar(snapshot_sql)
                .bind(&namespace)
                .fetch_all(&pool)
                .await
                .expect("snapshot after");
            assert_eq!(
                after, before,
                "{label}: the refused row is not applied, every PG column preserved"
            );
            assert_refused_window(
                label,
                &db,
                &outcome,
                &update.id,
                counter_before,
                &prior_cursor,
            )
            .await;
            assert_eq!(
                sender_rows(&config)
                    .await
                    .into_iter()
                    .map(|m| (m.id, m.content, m.updated_at))
                    .collect::<Vec<_>>(),
                vec![(
                    update.id.clone(),
                    update.content.clone(),
                    update.updated_at.clone()
                )],
                "{label}: the sender still holds the refused row"
            );
            assert!(
                sqlite_snapshot(&db).await.is_empty(),
                "PG writes must never land in the SQLite cursor DB"
            );
            server.stop().await;
            continue;
        }
        let (config, second, mut server) = peer(vec![update.clone(), new.clone()], true).await;
        let task = Task(ai_memory::federation::spawn_catchup_loop_with_store(
            config,
            db.clone(),
            Some(store.clone()),
            Duration::from_millis(1),
        ));
        complete_tick(task, &second, &mut server).await;
        let after: Vec<Value> = sqlx::query_scalar(snapshot_sql)
            .bind(&namespace)
            .fetch_all(&pool)
            .await
            .expect("snapshot after");
        {
            assert_eq!(
                store
                    .get(&ctx, &original.id)
                    .await
                    .expect("updated row")
                    .content,
                update.content,
                "{label}"
            );
            assert_eq!(
                store.get(&ctx, &new.id).await.expect("new row").id,
                new.id,
                "{label}"
            );
            assert_eq!(cursor(&db).await["entries"][PEER], json!(AFTER), "{label}");
            assert_ne!(after, before, "{label}: the authorised update is applied");
        }
        assert!(
            sqlite_snapshot(&db).await.is_empty(),
            "PG writes must never land in the SQLite cursor DB"
        );
    }
    pool.close().await;
}
