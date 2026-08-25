// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2672 — a peer must NOT be able to defeat the push-DLQ quarantine
//! ceiling by returning a count containing `429`.
//!
//! ## The chain (verbatim from the issue)
//!
//! `sync::success_report_non_ack_reason` built the failure reason from a count
//! read VERBATIM out of the peer's own JSON body:
//! `"peer 2xx but {skipped} item(s) skipped …"`. That string became the DLQ
//! row's `last_error`, and `reset_throttled_quarantine` matched it with a bare
//! `last_error LIKE '%429%'` on BOTH backends, setting `attempt_count = 0`.
//!
//! A peer answering **HTTP 200** with `{"skipped": 429}` therefore had its rows
//! un-quarantined on every sweep — they could never reach
//! `MAX_REPLAY_ATTEMPTS`, which is exactly the unbounded no-op POST
//! amplification #1544 introduced quarantine to stop. `classify_quarantine_
//! cause`'s first arm (`contains("429") => "quota"`) also mislabelled the row,
//! misdirecting the operator to "raise the daily quota".
//!
//! ## What this pins
//!
//! - a peer-chosen `429` count does NOT reset the attempt budget,
//! - a REAL HTTP 429 still does (the #1544 behaviour is preserved),
//! - pre-#2672 UNTAGGED rows still heal on the legacy rule (no in-flight
//!   upgrade backlog is stranded),
//! - the diagnostic count survives in `last_error` (the fix removes the
//!   control signal, not the forensics).

#![cfg(feature = "sal")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::federation::push_dlq::{
    FederationDlqSink, MAX_REPLAY_ATTEMPTS, SqliteDlqSink, replay_once,
};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::replication::QuorumPolicy;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::net::TcpListener;

/// Mock peer response mode.
#[derive(Clone)]
struct PeerState {
    /// 0 = HTTP 200 with `{"skipped": 429}` (the laundering attempt);
    /// 1 = a REAL HTTP 429.
    mode: Arc<AtomicUsize>,
}

const MODE_LAUNDERED_200: usize = 0;
const MODE_REAL_429: usize = 1;

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(_body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    match state.mode.load(Ordering::Relaxed) {
        MODE_REAL_429 => (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({"error": "quota"})),
        ),
        // A 2xx whose body claims 429 items were skipped: the peer never has
        // to send a real 429 to reach the classifier.
        _ => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"applied": 0, "noop": 0, "skipped": 429})),
        ),
    }
}

async fn spawn_mock_peer(state: PeerState) -> String {
    let app = Router::new()
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// On-disk sqlite `Db` migrated past v48 so `federation_push_dlq` exists.
/// Scratch under `.local-runs/` per the project no-`/tmp` HARD RULE.
fn fresh_dlq_db() -> (
    tempfile::TempDir,
    ai_memory::handlers::Db,
    std::path::PathBuf,
) {
    let tmp = tempfile::Builder::new()
        .prefix("v100-2672-dlq-class-")
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create local-runs tempdir");
    let db_path = tmp.path().join("dlq.db");
    let conn = ai_memory::storage::open(&db_path).expect("open sqlite");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle = Arc::new(tokio::sync::Mutex::new((conn, db_path.clone(), ttl, true)));
    (tmp, handle, db_path)
}

fn build_cfg(peer_url: &str, sink: Arc<dyn FederationDlqSink>) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(1, 1, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-dlq-2672".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:dlq-class-2672".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

/// Force a pending row into the QUARANTINED band (`attempt_count >=
/// MAX_REPLAY_ATTEMPTS`), which is the state `reset_throttled_quarantine`
/// operates on.
fn quarantine_all(db_path: &std::path::Path) {
    let conn = rusqlite::Connection::open(db_path).expect("raw open dlq db");
    conn.execute(
        "UPDATE federation_push_dlq SET attempt_count = ?1 WHERE replayed_at IS NULL",
        rusqlite::params![MAX_REPLAY_ATTEMPTS],
    )
    .expect("quarantine rows");
}

fn last_errors(db_path: &std::path::Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(db_path).expect("raw open dlq db");
    let mut stmt = conn
        .prepare("SELECT last_error FROM federation_push_dlq WHERE replayed_at IS NULL")
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

async fn drive_one_replay(
    mode: usize,
) -> (
    tempfile::TempDir,
    Arc<dyn FederationDlqSink>,
    std::path::PathBuf,
) {
    // `build_governed_peer_post` uses `check_governed`, which fail-closes
    // when `GOVERNANCE_PRE_ACTION` is unset. This binary is not a daemon
    // bootstrap — install the same allow-all hook the other in-process
    // federation tests use (`federation_bulk_catchup_identity_headers_3148`).
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let state = PeerState {
        mode: Arc::new(AtomicUsize::new(mode)),
    };
    let peer_url = spawn_mock_peer(state).await;
    let (tmp, db, db_path) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db).await.unwrap());
    sink.enqueue_push_failure(
        "mem-2672",
        "peer-dlq-2672",
        &serde_json::json!({"memories": []}),
        "initial local failure",
    )
    .await
    .expect("enqueue");
    let cfg = build_cfg(&peer_url, sink.clone());
    // One replay tick: the row is re-POSTed and its `last_error` is refreshed
    // by the REAL production classifier (not a hand-written fixture string).
    replay_once(&cfg, sink.as_ref()).await;
    (tmp, sink, db_path)
}

/// The issue's attack: HTTP 200 + `{"skipped": 429}` must NOT reset the
/// attempt budget.
#[tokio::test(flavor = "multi_thread")]
async fn peer_supplied_429_count_cannot_reset_the_quarantine_2672() {
    let (_tmp, sink, db_path) = drive_one_replay(MODE_LAUNDERED_200).await;

    let errors = last_errors(&db_path);
    assert_eq!(errors.len(), 1, "one pending row expected: {errors:?}");
    assert!(
        errors[0].contains("429"),
        "the diagnostic count must be PRESERVED (the fix removes the control signal, not \
         the forensics); got {}",
        errors[0]
    );

    quarantine_all(&db_path);
    let reset = sink
        .reset_throttled_quarantine()
        .await
        .expect("reset_throttled_quarantine");
    assert_eq!(
        reset, 0,
        "#2672: a peer-chosen `skipped` count containing 429 must NOT un-quarantine the \
         row. Pre-fix `LIKE '%429%'` matched it on every sweep, so attempt_count was reset \
         to 0 forever and the #1544 quarantine ceiling could never be reached — unbounded \
         no-op POST amplification steered entirely by the peer. last_error={}",
        errors[0]
    );
}

/// The #1544 behaviour must survive: a REAL HTTP 429 still un-quarantines.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_http_429_still_resets_the_quarantine_2672() {
    let (_tmp, sink, db_path) = drive_one_replay(MODE_REAL_429).await;

    quarantine_all(&db_path);
    let reset = sink
        .reset_throttled_quarantine()
        .await
        .expect("reset_throttled_quarantine");
    assert_eq!(
        reset,
        1,
        "a genuine 429 throttle must still un-quarantine (#1544); last_error={:?}",
        last_errors(&db_path)
    );
}

/// A row written by a PRE-#2672 binary carries no class tag and must keep
/// healing on the historical substring rule, so an in-flight upgrade backlog
/// is not stranded in quarantine.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_untagged_429_rows_still_heal_2672() {
    let (_tmp, db, db_path) = fresh_dlq_db();
    let sink: Arc<dyn FederationDlqSink> = Arc::new(SqliteDlqSink::new(db).await.unwrap());
    // Exactly what an older binary persisted for a real 429.
    sink.enqueue_push_failure(
        "mem-legacy",
        "peer-legacy-2672",
        &serde_json::json!({"memories": []}),
        "http 429 Too Many Requests",
    )
    .await
    .expect("enqueue legacy row");
    quarantine_all(&db_path);

    let reset = sink
        .reset_throttled_quarantine()
        .await
        .expect("reset_throttled_quarantine");
    assert_eq!(
        reset, 1,
        "a pre-#2672 untagged 429 row must still un-quarantine on the legacy arm"
    );
}
