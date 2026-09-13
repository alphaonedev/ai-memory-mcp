// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3655 (review rework) — contact is recorded SEPARATELY from the data
//! watermark, and it is stamped even when the pull window is EMPTY.
//!
//! `sync_state.last_pulled_at` only moves when a pull advances the data
//! watermark, so a quiet peer that answers every pull with an empty window
//! never touches it. Pre-rework the doctor aged that column as "last
//! observed" and called such a peer stale. The real `sync_cycle_once` is
//! driven against an in-process axum peer whose `/sync/since` always returns
//! `count: 0`; afterwards `sync_peer_contact` must carry a fresh row for the
//! peer while `sync_state` carries nothing — the two claims are different
//! and are stored apart.

use std::net::SocketAddr;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use tokio::net::TcpListener;

use ai_memory::db;

async fn empty_since() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"count": 0, "limit": 10, "memories": []})),
    )
}

async fn accept_push() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"applied": 0})),
    )
}

async fn failing_since() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({"error": "boom-3655"})),
    )
}

async fn spawn_failing_peer() -> String {
    let app = Router::new()
        .route("/api/v1/sync/since", get(failing_since))
        .route("/api/v1/sync/push", post(accept_push));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

async fn spawn_quiet_peer() -> String {
    let app = Router::new()
        .route("/api/v1/sync/since", get(empty_since))
        .route("/api/v1/sync/push", post(accept_push));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "current_thread")]
async fn empty_window_stamps_contact_but_not_the_data_watermark_3655() {
    // A tempdir-scoped database, never a `NamedTempFile` path (#3669).
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sync-3655.db");
    drop(db::open(&db_path).expect("open + migrate"));

    let peer_url = spawn_quiet_peer().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client");
    let before = chrono::Utc::now();
    ai_memory::daemon_runtime::sync_cycle_once(
        &client,
        &db_path,
        "ai:node-3655",
        &peer_url,
        None,
        10,
    )
    .await
    .expect("an empty window is a successful cycle");

    let conn = rusqlite::Connection::open(&db_path).expect("open");
    // CONTACT: recorded, and stamped by THIS node's clock at the pull.
    let (contact_at, cadence): (String, Option<i64>) = conn
        .query_row(
            "SELECT last_contact_at, catchup_interval_secs FROM sync_peer_contact \
             WHERE agent_id = 'ai:node-3655' AND peer_id = ?1",
            [&peer_url],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("#3655: an answered pull must record contact even on an empty window");
    let contact = chrono::DateTime::parse_from_rfc3339(&contact_at).expect("rfc3339");
    assert!(
        contact.with_timezone(&chrono::Utc) >= before - chrono::Duration::seconds(1),
        "contact {contact_at} must be stamped at the pull, not copied from data"
    );
    // No catch-up loop published a cadence in this process: the column says
    // so (NULL), it does not invent one.
    assert_eq!(
        cadence, None,
        "no cadence was published, so none may be claimed"
    );

    // DATA WATERMARK: untouched — nothing was replicated.
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_state WHERE agent_id = 'ai:node-3655'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        rows, 0,
        "an empty window must not fabricate a data watermark; contact and data are separate"
    );

    // A second cycle only moves the contact stamp forward, never backwards.
    ai_memory::daemon_runtime::sync_cycle_once(
        &client,
        &db_path,
        "ai:node-3655",
        &peer_url,
        None,
        10,
    )
    .await
    .expect("second cycle");
    let later: String = conn
        .query_row(
            "SELECT last_contact_at FROM sync_peer_contact WHERE peer_id = ?1",
            [&peer_url],
            |r| r.get(0),
        )
        .expect("row");
    assert!(
        later >= contact_at,
        "contact must be monotonic: {later} < {contact_at}"
    );
}

/// v3 review — a peer that answers every pull with a non-2xx is NOT
/// contacted: no row may be stamped, or "reachable" would be a lie told by
/// a 500.
#[tokio::test(flavor = "current_thread")]
async fn non_2xx_pull_never_stamps_contact_3655() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sync-3655-500.db");
    drop(db::open(&db_path).expect("open + migrate"));
    let peer_url = spawn_failing_peer().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client");
    for _ in 0..3 {
        let res = ai_memory::daemon_runtime::sync_cycle_once(
            &client,
            &db_path,
            "ai:node-3655",
            &peer_url,
            None,
            10,
        )
        .await;
        assert!(res.is_err(), "a 500 pull is a failed cycle: {res:?}");
    }
    let conn = rusqlite::Connection::open(&db_path).expect("open");
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_peer_contact", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        rows, 0,
        "#3655: a non-2xx answer must never be recorded as contact"
    );
    let state: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_state", [], |r| r.get(0))
        .expect("count");
    assert_eq!(state, 0);
}
