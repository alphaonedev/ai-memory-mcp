// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8741 round 1 — the bounds and receipt rules of the fan-out funnel
//! (F4 / sec-F1 size and time bound, F5 empty batch, F6 minimum ack,
//! F3 read-back classification, sec-F4 stable task-failure code).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::{Json, Router, routing::post};
use serde_json::{Value, json};

use super::*;
use crate::federation::PeerEndpoint;
use crate::replication::QuorumPolicy;

/// Ids in the size-and-time bound batch (the class invariant: a bulk
/// erasure of any size ships `ceil(N / MAX_BULK_SIZE)` bodies per peer).
const BIG_BATCH_IDS: usize = 100_000;
/// Wall-clock ceiling for delivering [`BIG_BATCH_IDS`] to two loopback
/// peers. Pre-fix (one POST per id) the same batch is 100 000 POSTs per
/// peer and does not finish inside it.
const BIG_BATCH_CEILING: Duration = Duration::from_secs(60);
/// Ack timeout of the deadline cell; the batch deadline is
/// [`FANOUT_BATCH_DEADLINE_ACK_TIMEOUTS`] of these.
const SLOW_ACK_TIMEOUT: Duration = Duration::from_millis(200);
/// How long the slow peer holds every request (longer than any deadline).
const SLOW_PEER_HOLD: Duration = Duration::from_secs(5);
/// Ids of the deadline cell: 50 chunks, 7 waves of 8 at one ack timeout
/// each, well past the 4-ack-timeout batch deadline.
const SLOW_BATCH_IDS: usize = 50 * MAX_BULK_SIZE;

#[derive(Default)]
struct PeerCounters {
    posts: AtomicUsize,
    deletions: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

async fn spawn_counting_peer(hold: Duration) -> (String, Arc<PeerCounters>) {
    let counters = Arc::new(PeerCounters::default());
    let c = Arc::clone(&counters);
    let app = Router::new().route(
        "/api/v1/sync/push",
        post(move |Json(body): Json<Value>| {
            let c = Arc::clone(&c);
            async move {
                let live = c.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                c.max_in_flight.fetch_max(live, Ordering::SeqCst);
                c.posts.fetch_add(1, Ordering::SeqCst);
                let n = body["deletions"].as_array().map_or(0, Vec::len);
                c.deletions.fetch_add(n, Ordering::SeqCst);
                tokio::time::sleep(hold).await;
                c.in_flight.fetch_sub(1, Ordering::SeqCst);
                Json(json!({"applied": n, "noop": 0, "skipped": 0}))
            }
        }),
    );
    (crate::test_support::spawn_tls_mock(app).await, counters)
}

fn config(peers: &[String], ack_timeout: Duration) -> FederationConfig {
    crate::governance::wire_check::ensure_installed_for_test();
    let n = 1 + peers.len();
    FederationConfig {
        policy: QuorumPolicy::new(n, n, ack_timeout, Duration::from_secs(30))
            .expect("valid quorum policy"),
        peers: peers
            .iter()
            .enumerate()
            .map(|(i, url)| PeerEndpoint {
                id: format!("peer-{i}:{url}"),
                sync_push_url: format!("{url}/api/v1/sync/push"),
            })
            .collect(),
        client: crate::test_support::tls_test_client(ack_timeout),
        sender_agent_id: "ai:fed-fanout-8741".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("erase-{i:06}")).collect()
}

/// F4 / sec-F1 — 100 000 erased ids reach each peer as exactly
/// `ceil(N / MAX_BULK_SIZE)` bodies carrying every id once, with at most
/// `BULK_FANOUT_CONCURRENCY` requests in flight, inside the time ceiling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_delete_100k_ids_is_chunked_bounded_and_timed_8741() {
    let (a, ca) = spawn_counting_peer(Duration::ZERO).await;
    let (b, cb) = spawn_counting_peer(Duration::ZERO).await;
    let fed = config(&[a, b], Duration::from_secs(10));
    let started = Instant::now();
    let out = deliver_batch(&fed, bulk_effects(BulkEffect::Delete, &ids(BIG_BATCH_IDS))).await;
    let elapsed = started.elapsed();
    assert_eq!(out, Ok(Some(3)), "every chunk must reach quorum 3-of-3");
    let chunks = BIG_BATCH_IDS.div_ceil(MAX_BULK_SIZE);
    for c in [&ca, &cb] {
        assert_eq!(c.posts.load(Ordering::SeqCst), chunks, "POSTs per peer");
        assert_eq!(
            c.deletions.load(Ordering::SeqCst),
            BIG_BATCH_IDS,
            "ids per peer"
        );
        assert!(
            c.max_in_flight.load(Ordering::SeqCst) <= BULK_FANOUT_CONCURRENCY,
            "in-flight requests per peer exceeded the bulk concurrency"
        );
    }
    assert!(
        elapsed < BIG_BATCH_CEILING,
        "100K-id delivery took {elapsed:?}"
    );
}

/// F4 / sec-F1 — a batch that cannot settle inside its overall deadline
/// returns the exact `FANOUT_DEADLINE_EXCEEDED` 202 detail at the deadline,
/// not after every effect timed out in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_delete_past_the_batch_deadline_is_the_exact_202_8741() {
    let (slow, _c) = spawn_counting_peer(SLOW_PEER_HOLD).await;
    let fed = config(&[slow], SLOW_ACK_TIMEOUT);
    let started = Instant::now();
    let out = deliver_batch(&fed, bulk_effects(BulkEffect::Delete, &ids(SLOW_BATCH_IDS))).await;
    let elapsed = started.elapsed();
    assert_eq!(
        out,
        Err(QuorumError::LocalWriteFailed {
            detail: FANOUT_DEADLINE_EXCEEDED.to_string()
        })
    );
    let deadline = SLOW_ACK_TIMEOUT.saturating_mul(FANOUT_BATCH_DEADLINE_ACK_TIMEOUTS);
    assert!(
        elapsed < deadline + Duration::from_secs(1),
        "the response waited {elapsed:?}, past the {deadline:?} batch deadline"
    );
}

/// F4 / sec-F1 — a chunk one id past `MAX_BULK_SIZE` is refused on the
/// origin with the exact `DELETE_BATCH_TOO_LARGE` code and nothing is sent;
/// a chunk of exactly `MAX_BULK_SIZE` ids is one body per peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_delete_chunk_is_refused_unsent_8741() {
    let (peer, counters) = spawn_counting_peer(Duration::ZERO).await;
    let fed = config(&[peer], Duration::from_secs(10));
    let out = crate::federation::broadcast_delete_batch_quorum(&fed, &ids(MAX_BULK_SIZE + 1)).await;
    assert_eq!(
        out.err(),
        Some(QuorumError::LocalWriteFailed {
            detail: crate::federation::DELETE_BATCH_TOO_LARGE.to_string()
        })
    );
    assert_eq!(
        counters.posts.load(Ordering::SeqCst),
        0,
        "nothing may be sent"
    );
    let full = crate::federation::broadcast_delete_batch_quorum(&fed, &ids(MAX_BULK_SIZE)).await;
    assert_eq!(
        full.map(|t| t.finalise(Instant::now())),
        Ok(Ok(2)),
        "a full chunk reaches 2-of-2"
    );
    assert_eq!(
        counters.posts.load(Ordering::SeqCst),
        1,
        "one body per peer"
    );
    assert_eq!(counters.deletions.load(Ordering::SeqCst), MAX_BULK_SIZE);
}

/// F5 — an empty batch delivered nothing, so it reports no ack count.
#[tokio::test]
async fn empty_batch_reports_no_ack_count_8741() {
    let fed = config(&[], Duration::from_millis(100));
    assert_eq!(deliver_batch(&fed, Vec::new()).await, Ok(None));
    assert!(bulk_effects(BulkEffect::Delete, &[]).is_empty());
}

/// F4 — erasures chunk at `MAX_BULK_SIZE`, archives stay one per id.
#[test]
fn bulk_effects_chunk_deletes_only_8741() {
    let sizes: Vec<usize> = bulk_effects(BulkEffect::Delete, &ids(2 * MAX_BULK_SIZE + 7))
        .iter()
        .map(|e| match e {
            OwnedEffect::DeleteChunk(c) => c.len(),
            _ => usize::MAX,
        })
        .collect();
    assert_eq!(sizes, vec![MAX_BULK_SIZE, MAX_BULK_SIZE, 7]);
    let archives = bulk_effects(BulkEffect::Archive, &ids(3));
    assert_eq!(archives.len(), 3);
    assert!(
        archives
            .iter()
            .all(|e| matches!(e, OwnedEffect::Archive(_)))
    );
}

/// F6 — a request that delivered several effects reports the MINIMUM ack
/// count, whatever order the effects settled in.
#[test]
fn stamp_quorum_keeps_the_minimum_ack_count_8741() {
    let fed = config(
        &["https://127.0.0.1:9".to_string()],
        Duration::from_millis(100),
    );
    for order in [[2_usize, 1, 2], [1, 2, 2], [2, 2, 1]] {
        let mut receipt = json!({"id": "x"});
        for acks in order {
            stamp_quorum(&mut receipt, &fed, acks);
        }
        assert_eq!(
            receipt[crate::write_receipt::QUORUM_ACKS_FIELD],
            json!(1),
            "order {order:?}"
        );
        assert_eq!(receipt[crate::write_receipt::QUORUM_N_FIELD], json!(2));
        assert_eq!(
            receipt[crate::write_receipt::QUORUM_REQUIRED_FIELD],
            json!(2)
        );
    }
}

/// F3 — a produced row that is absent or unreadable is `Unread(id)`,
/// never "nothing produced".
#[test]
fn produced_read_back_failure_is_unread_8741() {
    let absent: Result<Option<Memory>, String> = Ok(None);
    assert!(matches!(Produced::from_read("m-1", absent), Produced::Unread(id) if id == "m-1"));
    let failed: Result<Option<Memory>, String> = Err("backend down".to_string());
    assert!(matches!(Produced::from_read("m-2", failed), Produced::Unread(id) if id == "m-2"));
}

/// sec-F4 — a panicked delivery task is the stable `FANOUT_TASK_FAILED`
/// code; the panic text never reaches the response detail.
#[tokio::test]
async fn panicked_task_is_the_stable_task_failed_code_8741() {
    let task = tokio::spawn(async {
        let fail = true;
        assert!(!fail, "secret-bearing panic text");
        Ok::<usize, QuorumError>(1)
    });
    let mut out = BatchOutcome {
        min_acks: None,
        first_err: None,
    };
    out.fold(task.await);
    assert_eq!(
        out.first_err,
        Some(QuorumError::LocalWriteFailed {
            detail: FANOUT_TASK_FAILED.to_string()
        })
    );
}

/// F3 — an approved `delete` returns the id it erased; it leaves no row to
/// read back, so its absence is not a read-back failure. Every other action
/// (and an unknown snapshot, fail closed) is read back.
#[test]
fn only_a_delete_leaves_no_row_to_read_back_8741() {
    let pending = |action: GovernedAction| PendingAction {
        id: "p-1".to_string(),
        action_type: action.as_str().to_string(),
        memory_id: Some("m-1".to_string()),
        namespace: "ns".to_string(),
        payload: json!({}),
        requested_by: "ai:requester".to_string(),
        requested_at: "2026-11-11T00:00:00Z".to_string(),
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        approvals: Vec::new(),
    };
    assert!(!Produced::leaves_row(Some(&pending(
        GovernedAction::Delete
    ))));
    for action in [
        GovernedAction::Store,
        GovernedAction::Promote,
        GovernedAction::Reflect,
    ] {
        assert!(Produced::leaves_row(Some(&pending(action))), "{action:?}");
    }
    assert!(Produced::leaves_row(None));
}

/// F3 / T1 — the read-back-failure cell: a decision whose produced row could
/// not be read back delivers the decision, then answers the exact
/// `202 local_write_failed:fanout_readback_failed: <id>`, never a 200 ack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decision_with_an_unread_row_is_the_exact_readback_202_8741() {
    let (peer, counters) = spawn_counting_peer(Duration::ZERO).await;
    let conn = crate::db::open(std::path::Path::new(":memory:")).expect("scratch db");
    let db: crate::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        crate::config::ResolvedTtl::default(),
        true,
    )));
    let mut app = crate::handlers::tests::test_app_state(db);
    app.federation = Arc::new(Some(config(&[peer], Duration::from_secs(5))));
    let decision = PendingDecision {
        id: "pending-8741".to_string(),
        approved: true,
        decider: "ai:approver-8741".to_string(),
    };
    let mut receipt = json!({"approved": true});
    let out = fanout_decision(
        &app,
        &decision,
        &Produced::Unread("produced-8741".to_string()),
        &mut receipt,
    )
    .await;
    let resp = out.expect_err("an unread produced row is never a delivered ack");
    assert_eq!(resp.status(), axum::http::StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("202 body");
    let body: Value = serde_json::from_slice(&bytes).expect("202 JSON");
    assert_eq!(
        body["reason"],
        json!(format!(
            "local_write_failed:{FANOUT_READBACK_FAILED}: produced-8741"
        ))
    );
    assert_eq!(body["quorum_met"], json!(false));
    assert_eq!(
        counters.posts.load(Ordering::SeqCst),
        1,
        "the decision itself is delivered before the read-back verdict"
    );
}
