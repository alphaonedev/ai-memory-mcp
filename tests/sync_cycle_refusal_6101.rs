// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6101 (PR #9173 round 1, code F3 / F4) — every refusal branch of
//! `daemon_runtime::sync_cycle_once` is pinned by its EXACT error text.
//!
//! * A peer URL whose rendering is not a unique durable key (an ambiguous
//!   authority, or a URL that does not parse) is refused BEFORE any database
//!   open, so no cursor is ever shared between two peers and the database
//!   file is never created by the refused cycle.
//! * The refusal hint matches the cause: `%40` advice only for an ambiguous
//!   authority, never for a URL that does not parse (F4).
//! * The sibling refusal branches of the same cycle (pull status, push
//!   status) are pinned too, against an in-process axum peer.
//!
//! Backend parity: `sync_cycle_once` takes a sqlite database path and has no
//! Postgres form, so there is one sqlite cell per branch.

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use tempfile::TempDir;
use tokio::net::TcpListener;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};

const LOCAL_AGENT: &str = "ai:node-6101";
const BATCH: usize = 10;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// A canary that must never appear in any refusal text.
const CANARY: &str = "SECRETX6101pw";
/// The durable cursor seeded before a refused cycle; it must survive.
const SEEDED_PEER: &str = "https://peer.example:9077/mesh";
const SEEDED_AT: &str = "2026-11-01T00:00:00+00:00";

const AMBIGUOUS_REFUSAL: &str = "peer http://<redacted-authority> refused: no unique sync key; \
     its authority is ambiguous; percent-encode each '/', '?', '#' or '@' inside the \
     userinfo, path or query (a literal '@' as %40)";
const UNPARSEABLE_REFUSAL: &str = "peer http://<unparseable> refused: no unique sync key; \
     the peer URL does not parse; write it as scheme://host[:port][/path]";
const PULL_REFUSAL: &str = "sync-daemon: pull status 503 Service Unavailable";
const PUSH_REFUSAL: &str = "sync-daemon: push status 503 Service Unavailable";

fn scratch() -> TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sync-cycle-refusal-6101");
    std::fs::create_dir_all(&root).expect("create .local-runs root");
    tempfile::Builder::new()
        .prefix("cell-")
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(CLIENT_TIMEOUT)
        .build()
        .expect("client")
}

async fn run_cycle(db_path: &std::path::Path, peer: &str) -> String {
    let err = ai_memory::daemon_runtime::sync_cycle_once(
        &client(),
        db_path,
        LOCAL_AGENT,
        peer,
        None,
        BATCH,
    )
    .await
    .expect_err("the cycle must refuse");
    format!("{err:#}")
}

fn seeded_cursors(db_path: &std::path::Path) -> Vec<(String, String)> {
    let conn = rusqlite::Connection::open(db_path).expect("open");
    let mut stmt = conn
        .prepare("SELECT peer_id, last_seen_at FROM sync_state ORDER BY peer_id")
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

#[tokio::test(flavor = "current_thread")]
async fn ambiguous_authority_peer_is_refused_with_the_exact_reason_before_any_open_6101() {
    key_dir_sandbox::pin();
    let dir = scratch();
    let fresh = dir.path().join("never-created.db");
    let peer = format!("http://svc:/{CANARY}@127.0.0.1:9/mesh");

    let text = run_cycle(&fresh, &peer).await;
    assert_eq!(text, AMBIGUOUS_REFUSAL);
    assert!(!text.contains(CANARY), "the refusal must not echo userinfo");
    assert!(
        !fresh.exists(),
        "the refusal precedes every database open, so no file is created"
    );

    // A database that already holds a durable cursor keeps it unchanged.
    let seeded = dir.path().join("seeded.db");
    {
        let conn = db::open(&seeded).expect("open + migrate");
        db::sync_state_observe(&conn, LOCAL_AGENT, SEEDED_PEER, SEEDED_AT).expect("seed cursor");
    }
    let before = seeded_cursors(&seeded);
    assert_eq!(run_cycle(&seeded, &peer).await, AMBIGUOUS_REFUSAL);
    assert_eq!(
        seeded_cursors(&seeded),
        before,
        "a refused cycle writes no cursor"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn unparseable_peer_gets_the_parse_hint_not_the_percent_encoding_hint_6101() {
    key_dir_sandbox::pin();
    let dir = scratch();
    let fresh = dir.path().join("never-created.db");

    let text = run_cycle(&fresh, "http://[::1").await;
    assert_eq!(text, UNPARSEABLE_REFUSAL);
    assert!(
        !text.contains("%40"),
        "a URL that does not parse gets no percent-encoding advice"
    );
    assert!(!fresh.exists(), "the refusal precedes every database open");
}

async fn unavailable() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({"error": "down-6101"})),
    )
}

async fn empty_since() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"count": 0, "limit": BATCH, "memories": []})),
    )
}

async fn spawn_peer(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "current_thread")]
async fn pull_status_refusal_names_the_status_exactly_6101() {
    key_dir_sandbox::pin();
    let dir = scratch();
    let db_path = dir.path().join("pull.db");
    drop(db::open(&db_path).expect("open + migrate"));
    let peer = spawn_peer(
        Router::new()
            .route("/api/v1/sync/since", get(unavailable))
            .route("/api/v1/sync/push", post(unavailable)),
    )
    .await;

    assert_eq!(run_cycle(&db_path, &peer).await, PULL_REFUSAL);
}

#[tokio::test(flavor = "current_thread")]
async fn push_status_refusal_names_the_status_exactly_6101() {
    key_dir_sandbox::pin();
    let dir = scratch();
    let db_path = dir.path().join("push.db");
    {
        let conn = db::open(&db_path).expect("open + migrate");
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: "00000000-0000-0000-0000-000000006101".to_string(),
            title: "push-refusal-6101".to_string(),
            content: "an outgoing row so the push branch runs".to_string(),
            namespace: "ns-6101".to_string(),
            tier: Tier::Mid,
            created_at: now.clone(),
            updated_at: now,
            ..Default::default()
        };
        db::insert(&conn, &mem).expect("insert outgoing memory");
    }
    let peer = spawn_peer(
        Router::new()
            .route("/api/v1/sync/since", get(empty_since))
            .route("/api/v1/sync/push", post(unavailable)),
    )
    .await;

    assert_eq!(run_cycle(&db_path, &peer).await, PUSH_REFUSAL);
}
