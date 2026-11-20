// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #9596, vote condition A-2 (3-agent vote 71472661) — every
//! production `/sync/since` puller of this build sends ONE identity in all
//! three clock fields: `X-Peer-Id`, `?peer=` and `X-Agent-Id`.
//!
//! The #9596 fix refuses an authenticated pull whose `?peer=` or
//! `X-Agent-Id` names a principal other than the authenticated `X-Peer-Id`
//! (403 `sync_since_peer_mismatch`). That refusal must never hit a puller
//! this repository ships, so this binary pins the client side: a capturing
//! loopback `/sync/since` decodes each request exactly as the server does
//! (`Query<SyncSinceQuery>` for `?peer=`, the same header names) and
//! asserts the three values are equal to the local id, for every puller
//! form and every id in a corpus that covers each character class an agent
//! id may hold (`validate_agent_id`: ASCII alphanumerics plus `_ - : @ . /`,
//! up to 128 bytes).
//!
//! Puller forms (one table row each):
//! - the sync daemon, `daemon_runtime::sync_cycle_once` (percent-encodes
//!   `?peer=`);
//! - the catch-up loop, `federation::spawn_catchup_loop`: under
//!   `--features sal` it runs `catchup_once_with_store`, without it
//!   `catchup_once_legacy`, so running this binary in both feature sets
//!   covers both catch-up bodies;
//! - the catch-up test harness, `federation::catchup_once_for_tests`.
//!
//! No environment variable is set or removed here.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};

use ai_memory::config::ResolvedTtl;
use ai_memory::federation::peer_attestation::PEER_ID_HEADER;
use ai_memory::federation::{
    FederationConfig, PeerEndpoint, catchup_once_for_tests, spawn_catchup_loop,
};
use ai_memory::handlers::Db;
use ai_memory::handlers::federation_receive::SyncSinceQuery;
use ai_memory::replication::QuorumPolicy;

const SYNC_SINCE_PATH: &str = "/api/v1/sync/since";
const SYNC_PUSH_PATH: &str = "/api/v1/sync/push";
/// The agent-id length cap `validate_agent_id` enforces (src/validate.rs).
const MAX_AGENT_ID_LEN: usize = 128;
const MAX_ID_PREFIX: &str = "ai:";
const MAX_ID_FILL: char = 'm';
/// Valid agent ids, one per character class the validator admits.
const ID_CORPUS: &[&str] = &[
    "ai:peer-alice",
    "node_1.example",
    "agent@node-7",
    "spiffe://example.org/ns/prod",
    "a/b:c@d.e_f-g",
    "UPPER-lower-0123456789",
];
/// The catch-up loop sleeps 5 s before its first pull; one day keeps it
/// from pulling twice inside the test.
const LOOP_INTERVAL: Duration = Duration::from_hours(24);
/// Upper bound for one captured pull (the loop's 5 s start delay included).
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_BATCH: usize = 10;

/// The three clock fields as the server decodes them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Captured {
    peer_id_header: Option<String>,
    peer_param: Option<String>,
    agent_id_header: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum PullerForm {
    SyncDaemon,
    CatchupLoop,
    CatchupHarness,
}

const PULLER_FORMS: &[(PullerForm, &str)] = &[
    (PullerForm::SyncDaemon, "sync-daemon sync_cycle_once"),
    (
        PullerForm::CatchupLoop,
        if cfg!(feature = "sal") {
            "catch-up loop (catchup_once_with_store)"
        } else {
            "catch-up loop (catchup_once_legacy)"
        },
    ),
    (
        PullerForm::CatchupHarness,
        "catch-up catchup_once_for_tests",
    ),
];

async fn capture(
    State(tx): State<mpsc::UnboundedSender<Captured>>,
    headers: HeaderMap,
    Query(q): Query<SyncSinceQuery>,
) -> axum::Json<serde_json::Value> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let _ = tx.send(Captured {
        peer_id_header: header(PEER_ID_HEADER),
        peer_param: q.peer,
        agent_id_header: header(ai_memory::HEADER_AGENT_ID),
    });
    axum::Json(serde_json::json!({ "memories": [], "count": 0 }))
}

/// A loopback `/sync/since` that forwards every decoded request.
async fn spawn_capture() -> (String, mpsc::UnboundedReceiver<Captured>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new()
        .route(SYNC_SINCE_PATH, get(capture))
        .with_state(tx);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), rx)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(CLIENT_TIMEOUT)
        .build()
        .expect("reqwest client")
}

fn fed_config(peer_url: &str, local_id: &str) -> FederationConfig {
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30))
            .expect("quorum policy"),
        peers: vec![PeerEndpoint {
            id: "peer-0".to_string(),
            sync_push_url: format!("{peer_url}{SYNC_PUSH_PATH}"),
        }],
        client: client(),
        sender_agent_id: local_id.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// Drive one puller form against a fresh capture server and return the
/// first pull it sent.
async fn first_pull(form: PullerForm, local_id: String) -> Captured {
    let (url, mut rx) = spawn_capture().await;
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    match form {
        PullerForm::SyncDaemon => {
            drop(conn);
            // The cycle pushes after the pull; the capture server has no push
            // route, so the cycle's result is not the subject here.
            let _ = tokio::time::timeout(
                CAPTURE_TIMEOUT,
                ai_memory::daemon_runtime::sync_cycle_once(
                    &client(),
                    &db_path,
                    &local_id,
                    &url,
                    None,
                    DAEMON_BATCH,
                ),
            )
            .await;
        }
        PullerForm::CatchupLoop => {
            let db: Db = Arc::new(Mutex::new((
                conn,
                db_path.clone(),
                ResolvedTtl::default(),
                true,
            )));
            let handle = spawn_catchup_loop(fed_config(&url, &local_id), db, LOOP_INTERVAL);
            let got = tokio::time::timeout(CAPTURE_TIMEOUT, rx.recv()).await;
            handle.abort();
            return got
                .expect("catch-up loop pulled within the bound")
                .expect("capture channel open");
        }
        PullerForm::CatchupHarness => {
            drop(conn);
            catchup_once_for_tests(&fed_config(&url, &local_id)).await;
        }
    }
    tokio::time::timeout(CAPTURE_TIMEOUT, rx.recv())
        .await
        .expect("puller pulled within the bound")
        .expect("capture channel open")
}

fn id_corpus() -> Vec<String> {
    let mut ids: Vec<String> = ID_CORPUS.iter().map(|s| (*s).to_string()).collect();
    let fill = MAX_AGENT_ID_LEN - MAX_ID_PREFIX.len();
    ids.push(format!(
        "{MAX_ID_PREFIX}{}",
        MAX_ID_FILL.to_string().repeat(fill)
    ));
    ids
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_puller_form_sends_one_identity_in_all_clock_fields_9596() {
    let ids = id_corpus();
    for id in &ids {
        assert!(
            ai_memory::validate::validate_agent_id(id).is_ok(),
            "corpus id {id:?} must be a valid agent id"
        );
    }
    let mut cases = tokio::task::JoinSet::new();
    for &(form, label) in PULLER_FORMS {
        for id in &ids {
            let id = id.clone();
            cases.spawn(async move { (label, id.clone(), first_pull(form, id).await) });
        }
    }
    let mut rows = 0_usize;
    while let Some(done) = cases.join_next().await {
        let (label, id, got) = done.expect("case task");
        let want = Captured {
            peer_id_header: Some(id.clone()),
            peer_param: Some(id.clone()),
            agent_id_header: Some(id.clone()),
        };
        assert_eq!(
            got, want,
            "#9596 A-2: puller form `{label}` with local id {id:?} must send X-Peer-Id, \
             ?peer= and X-Agent-Id all equal to its local id"
        );
        rows += 1;
    }
    assert_eq!(rows, PULLER_FORMS.len() * ids.len(), "every table row ran");
}
