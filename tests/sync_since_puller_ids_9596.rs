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
//!
//! Scheduling (#9596 r1, M1): the verdict must not depend on host load.
//! Each case runs on its own OS thread with its own current-thread runtime,
//! so a puller that opens its database synchronously (`sync_cycle_once`
//! does, CONCURRENCY-22) blocks only its own case, never another case's
//! capture server. The fixture database is opened before the case's
//! runtime starts, at most [`CASES_IN_FLIGHT`] cases run at once, and the
//! one hang guard wraps the pull alone. A puller that sent nothing is a
//! row failure naming the form, the id and what the puller returned.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
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
/// One day keeps the catch-up loop from pulling twice inside the test.
const LOOP_INTERVAL: Duration = Duration::from_hours(24);
/// The catch-up loop's fixed delay before its first pull
/// (`src/federation/receive.rs`, both loop bodies).
const LOOP_START_DELAY: Duration = Duration::from_secs(5);
/// Hang guard for one pull: the puller's HTTP client timeout and the bound
/// on the pull call itself. It detects a hung puller; it is not a speed
/// claim, and no database open or runtime start runs inside it.
const PULL_HANG_GUARD: Duration = Duration::from_secs(30);
/// Cases running at once, one OS thread each.
const CASES_IN_FLIGHT: usize = 4;
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
        .timeout(PULL_HANG_GUARD)
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

/// Drive one puller form against a fresh capture server on the case's own
/// runtime and return the first pull it sent, or why there was none.
async fn first_pull(
    form: PullerForm,
    local_id: &str,
    db_path: PathBuf,
    conn: rusqlite::Connection,
) -> Result<Captured, String> {
    let (url, mut rx) = spawn_capture().await;
    let puller_outcome = match form {
        PullerForm::SyncDaemon => {
            drop(conn);
            // The cycle pushes after the pull; the capture server has no push
            // route, so an `Err` after the pull is expected and only reported.
            match tokio::time::timeout(
                PULL_HANG_GUARD,
                ai_memory::daemon_runtime::sync_cycle_once(
                    &client(),
                    &db_path,
                    local_id,
                    &url,
                    None,
                    DAEMON_BATCH,
                ),
            )
            .await
            {
                Ok(Ok(())) => "returned Ok".to_string(),
                Ok(Err(e)) => format!("returned Err({e})"),
                Err(_) => format!("hung past {PULL_HANG_GUARD:?}"),
            }
        }
        PullerForm::CatchupLoop => {
            let db: Db = Arc::new(Mutex::new((
                conn,
                db_path.clone(),
                ResolvedTtl::default(),
                true,
            )));
            let handle = spawn_catchup_loop(fed_config(&url, local_id), db, LOOP_INTERVAL);
            let wait = LOOP_START_DELAY + PULL_HANG_GUARD;
            let got = tokio::time::timeout(wait, rx.recv()).await;
            handle.abort();
            return match got {
                Ok(Some(captured)) => Ok(captured),
                Ok(None) => Err("capture channel closed before a pull".to_string()),
                Err(_) => Err(format!("loop sent no pull within {wait:?}")),
            };
        }
        PullerForm::CatchupHarness => {
            drop(conn);
            match tokio::time::timeout(
                PULL_HANG_GUARD,
                catchup_once_for_tests(&fed_config(&url, local_id)),
            )
            .await
            {
                Ok(()) => "returned".to_string(),
                Err(_) => format!("hung past {PULL_HANG_GUARD:?}"),
            }
        }
    };
    // The capture handler forwards the request before it answers, so a
    // puller that got any answer has already been captured: no wait here.
    rx.try_recv()
        .map_err(|e| format!("no pull captured (puller {puller_outcome}; channel {e})"))
}

/// One table row, run on the calling OS thread: the fixture database is
/// opened before the case's runtime starts, then the pull runs on a
/// current-thread runtime nobody else shares.
fn run_case(form: PullerForm, local_id: &str) -> Result<Captured, String> {
    let db_tmp = tempfile::NamedTempFile::new().map_err(|e| format!("db tempfile: {e}"))?;
    let db_path = db_tmp.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).map_err(|e| format!("db::open: {e}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("case runtime: {e}"))?;
    runtime.block_on(first_pull(form, local_id, db_path, conn))
}

/// One finished row: `(puller label, local id, what it sent or why not)`.
type CaseResult<'a> = (&'a str, &'a str, Result<Captured, String>);

fn id_corpus() -> Vec<String> {
    let mut ids: Vec<String> = ID_CORPUS.iter().map(|s| (*s).to_string()).collect();
    let fill = MAX_AGENT_ID_LEN - MAX_ID_PREFIX.len();
    ids.push(format!(
        "{MAX_ID_PREFIX}{}",
        MAX_ID_FILL.to_string().repeat(fill)
    ));
    ids
}

#[test]
fn every_puller_form_sends_one_identity_in_all_clock_fields_9596() {
    let ids = id_corpus();
    for id in &ids {
        assert!(
            ai_memory::validate::validate_agent_id(id).is_ok(),
            "corpus id {id:?} must be a valid agent id"
        );
    }
    let cases: Vec<(PullerForm, &str, &str)> = PULLER_FORMS
        .iter()
        .flat_map(|&(form, label)| ids.iter().map(move |id| (form, label, id.as_str())))
        .collect();
    let next_case = AtomicUsize::new(0);
    let results: StdMutex<Vec<CaseResult<'_>>> = StdMutex::new(Vec::with_capacity(cases.len()));
    std::thread::scope(|scope| {
        for _ in 0..CASES_IN_FLIGHT {
            scope.spawn(|| {
                while let Some(&(form, label, id)) =
                    cases.get(next_case.fetch_add(1, Ordering::Relaxed))
                {
                    let got = run_case(form, id);
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((label, id, got));
                }
            });
        }
    });
    let results = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(results.len(), cases.len(), "every table row ran");
    let failures: Vec<String> = results
        .iter()
        .filter_map(|(label, id, got)| {
            let want = Captured {
                peer_id_header: Some((*id).to_string()),
                peer_param: Some((*id).to_string()),
                agent_id_header: Some((*id).to_string()),
            };
            match got {
                Ok(captured) if *captured == want => None,
                Ok(captured) => Some(format!(
                    "form `{label}` id {id:?}: sent {captured:?}, want {want:?}"
                )),
                Err(why) => Some(format!("form `{label}` id {id:?}: {why}")),
            }
        })
        .collect();
    assert!(
        failures.is_empty(),
        "#9596 A-2: every puller form must send X-Peer-Id, ?peer= and X-Agent-Id all \
         equal to its local id; {} of {} rows failed:\n{}",
        failures.len(),
        results.len(),
        failures.join("\n")
    );
}
