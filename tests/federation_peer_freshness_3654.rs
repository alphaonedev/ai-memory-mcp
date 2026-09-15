// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3654 — per-peer federation freshness.
//!
//! Before #3654 an unreachable or rejecting peer produced only DEBUG lines and
//! no per-peer series: a quiet peer, an unreachable one, one that 401s or 500s
//! every catch-up, and one that silently stopped accepting our pushes all
//! looked identical to an operator. These tests drive real HTTP peers and pin
//! that each case is now distinguishable in `federation::freshness` and in the
//! Prometheus exposition, that sustained failure escalates to a WARN exactly
//! at the documented streak points, that recovery is logged, that a skewed
//! peer clock is measured but never used as a freshness timestamp, and that
//! the catch-up cadence is published so a stalled worker is alertable.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ai_memory::federation::freshness::{self, ESCALATE_AFTER_CONSECUTIVE_FAILURES};
use ai_memory::federation::{FederationConfig, PeerEndpoint, catchup_once_for_tests};
use ai_memory::models::Memory;
use ai_memory::replication::QuorumPolicy;
use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use tokio::net::TcpListener;

/// How a mock peer answers.
#[derive(Clone, Copy)]
enum Answer {
    /// 200 with an empty window / an applied push.
    Ok,
    /// This HTTP status with an empty JSON body.
    Status(u16),
    /// 200 for `/sync/since` but with the given `Date` offset from real time.
    SkewedOk(i64),
    /// 200 on `/sync/push` whose own report says the item was skipped.
    PushSkipped,
    /// Fail this many requests with 500, then answer 200.
    FailThenOk(usize),
}

#[derive(Clone)]
struct PeerState {
    answer: Answer,
    calls: Arc<AtomicUsize>,
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

fn respond(state: &PeerState, ok_body: serde_json::Value) -> Response {
    let n = state.calls.fetch_add(1, Ordering::Relaxed);
    match state.answer {
        Answer::Ok => (StatusCode::OK, axum::Json(ok_body)).into_response(),
        Answer::Status(code) => (
            StatusCode::from_u16(code).expect("valid status"),
            axum::Json(json!({})),
        )
            .into_response(),
        Answer::SkewedOk(offset) => {
            let mut resp = (StatusCode::OK, axum::Json(ok_body)).into_response();
            let date = chrono::DateTime::from_timestamp(now_unix() + offset, 0)
                .expect("valid timestamp")
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string();
            resp.headers_mut().insert(
                header::DATE,
                HeaderValue::from_str(&date).expect("date header"),
            );
            resp
        }
        Answer::PushSkipped => (
            StatusCode::OK,
            axum::Json(json!({"applied": 0, "skipped": 1})),
        )
            .into_response(),
        Answer::FailThenOk(failures) => {
            if n < failures {
                (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({}))).into_response()
            } else {
                (StatusCode::OK, axum::Json(ok_body)).into_response()
            }
        }
    }
}

async fn spawn_peer(answer: Answer) -> String {
    let state = PeerState {
        answer,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route(
            "/api/v1/sync/since",
            get(
                |axum::extract::State(s): axum::extract::State<PeerState>| async move {
                    respond(&s, json!({"memories": [], "count": 0}))
                },
            ),
        )
        .route(
            "/api/v1/sync/push",
            post(
                |axum::extract::State(s): axum::extract::State<PeerState>| async move {
                    respond(&s, json!({"applied": 1, "skipped": 0}))
                },
            ),
        )
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// A URL nothing listens on: bind an ephemeral port, then release it.
async fn dead_peer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

fn config(peer_url: &str, peer_id: &str) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: peer_id.to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        sender_agent_id: "ai:freshness-3654".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// A minted-shape id, unique per test so the process-global registry never
/// mixes two tests' peers.
fn peer_id() -> String {
    format!("peer-h1{}", uuid::Uuid::new_v4().simple())
}

fn memory() -> Memory {
    let id = uuid::Uuid::new_v4().to_string();
    Memory {
        id: id.clone(),
        title: format!("freshness-{id}"),
        namespace: "freshness3654".to_string(),
        content: "content".to_string(),
        source: "system".to_string(),
        created_at: "2026-09-12T00:00:00Z".to_string(),
        updated_at: "2026-09-12T00:00:00Z".to_string(),
        metadata: json!({"agent_id": "ai:freshness-3654", "scope": "collective"}),
        ..Memory::default()
    }
}

/// The value of one exposition sample, by metric name and label pairs. Every
/// freshness series is an integer gauge or counter.
fn sample(metric: &str, labels: &[(&str, &str)]) -> Option<i64> {
    ai_memory::metrics::render().lines().find_map(|line| {
        let rest = line.strip_prefix(metric)?.strip_prefix('{')?;
        let (label_part, value) = rest.split_once("} ")?;
        if !labels
            .iter()
            .all(|(k, v)| label_part.contains(&format!("{k}=\"{v}\"")))
        {
            return None;
        }
        value.trim().parse::<i64>().ok()
    })
}

#[derive(Clone, Default)]
struct LogSink(Arc<StdMutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("sink")).into_owned()
    }
}

fn capture_logs() -> (LogSink, tracing::subscriber::DefaultGuard) {
    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (sink, guard)
}

#[tokio::test]
async fn idle_healthy_peer_is_fresh_on_pull_and_has_no_push_numbers() {
    let id = peer_id();
    let cfg = config(&spawn_peer(Answer::Ok).await, &id);
    let before = now_unix();
    catchup_once_for_tests(&cfg).await;

    let fresh = freshness::snapshot_for(&id).expect("pull recorded");
    assert_eq!(fresh.pull.consecutive_failures, 0);
    let success = fresh.pull.last_success_unix.expect("pull succeeded");
    assert!(
        success >= before && success <= now_unix(),
        "local-clock timestamp"
    );
    assert_eq!(fresh.pull.last_attempt_unix, Some(success));
    // A quiet peer we never pushed to has NO push numbers, never a zero.
    assert_eq!(fresh.push.last_attempt_unix, None);
    assert_eq!(fresh.push.last_success_unix, None);
    let labels = [("peer", id.as_str()), ("direction", "push")];
    assert_eq!(
        sample(
            "ai_memory_federation_peer_last_success_timestamp_seconds",
            &labels
        ),
        None,
        "no push series before the first push"
    );
    assert_eq!(
        sample(
            "ai_memory_federation_peer_last_success_timestamp_seconds",
            &[("peer", id.as_str()), ("direction", "pull")]
        ),
        Some(success)
    );
}

#[tokio::test]
async fn unreachable_peer_escalates_at_the_threshold_and_not_before() {
    let (logs, _guard) = capture_logs();
    let id = peer_id();
    let cfg = config(&dead_peer().await, &id);
    for _ in 1..ESCALATE_AFTER_CONSECUTIVE_FAILURES {
        catchup_once_for_tests(&cfg).await;
    }
    assert!(
        !logs.text().contains("consecutive attempts"),
        "a transient below the threshold must not WARN: {}",
        logs.text()
    );
    catchup_once_for_tests(&cfg).await;
    let text = logs.text();
    assert!(text.contains("WARN"), "{text}");
    assert!(
        text.contains(&format!(
            "peer {id} pull has failed {ESCALATE_AFTER_CONSECUTIVE_FAILURES} consecutive attempts"
        )),
        "{text}"
    );
    assert!(text.contains("last: unreachable"), "{text}");
    // One more failure is not an escalation point: no second WARN.
    catchup_once_for_tests(&cfg).await;
    assert_eq!(logs.text().matches("consecutive attempts").count(), 1);

    let fresh = freshness::snapshot_for(&id).expect("recorded");
    assert_eq!(
        fresh.pull.consecutive_failures,
        ESCALATE_AFTER_CONSECUTIVE_FAILURES + 1
    );
    assert_eq!(fresh.pull.last_failure_class, Some("unreachable"));
    assert_eq!(fresh.pull.last_success_unix, None);
    let pull = [("peer", id.as_str()), ("direction", "pull")];
    assert_eq!(
        sample("ai_memory_federation_peer_consecutive_failures", &pull),
        Some(i64::try_from(ESCALATE_AFTER_CONSECUTIVE_FAILURES + 1).expect("fits"))
    );
    assert_eq!(
        sample(
            "ai_memory_federation_peer_failures_total",
            &[
                ("peer", id.as_str()),
                ("direction", "pull"),
                ("class", "unreachable")
            ]
        ),
        Some(i64::try_from(ESCALATE_AFTER_CONSECUTIVE_FAILURES + 1).expect("fits"))
    );
}

#[tokio::test]
async fn unauthorized_and_server_error_peers_are_told_apart() {
    for (status, class) in [
        (401, "unauthorized"),
        (403, "unauthorized"),
        (500, "server_error"),
    ] {
        let id = peer_id();
        let cfg = config(&spawn_peer(Answer::Status(status)).await, &id);
        catchup_once_for_tests(&cfg).await;
        let fresh = freshness::snapshot_for(&id).expect("recorded");
        assert_eq!(fresh.pull.consecutive_failures, 1, "status {status}");
        assert_eq!(
            fresh.pull.last_failure_class,
            Some(class),
            "status {status}"
        );
        assert!(fresh.pull.last_attempt_unix.is_some());
        assert_eq!(fresh.pull.last_success_unix, None);
    }
}

#[tokio::test]
async fn recovery_after_an_escalated_streak_is_logged_once() {
    let (logs, _guard) = capture_logs();
    let id = peer_id();
    let streak = usize::try_from(ESCALATE_AFTER_CONSECUTIVE_FAILURES).expect("fits");
    let cfg = config(&spawn_peer(Answer::FailThenOk(streak)).await, &id);
    for _ in 0..streak {
        catchup_once_for_tests(&cfg).await;
    }
    catchup_once_for_tests(&cfg).await;
    let text = logs.text();
    assert!(
        text.contains(&format!(
            "peer {id} pull recovered after {ESCALATE_AFTER_CONSECUTIVE_FAILURES} consecutive"
        )),
        "{text}"
    );
    let fresh = freshness::snapshot_for(&id).expect("recorded");
    assert_eq!(fresh.pull.consecutive_failures, 0);
    assert_eq!(fresh.pull.failing_since_unix, None);
    assert!(fresh.pull.last_success_unix.is_some());
    // A further success is not a recovery.
    catchup_once_for_tests(&cfg).await;
    assert_eq!(logs.text().matches("recovered after").count(), 1);
}

#[tokio::test]
async fn skewed_peer_clock_is_measured_but_never_used_as_freshness() {
    let id = peer_id();
    let skew = 7_200; // two hours ahead
    let cfg = config(&spawn_peer(Answer::SkewedOk(skew)).await, &id);
    let before = now_unix();
    catchup_once_for_tests(&cfg).await;
    let after = now_unix();
    let fresh = freshness::snapshot_for(&id).expect("recorded");
    let measured = fresh.clock_skew_seconds.expect("Date header measured");
    assert!(
        (skew - 2..=skew + 2).contains(&measured),
        "measured skew {measured}, expected ~{skew}"
    );
    let success = fresh.pull.last_success_unix.expect("pull ok");
    assert!(
        success >= before && success <= after,
        "freshness must come from the LOCAL clock, not the peer's Date ({success} not in {before}..={after})"
    );
    assert_eq!(
        sample(
            "ai_memory_federation_peer_clock_skew_seconds",
            &[("peer", id.as_str())]
        ),
        Some(measured)
    );
}

#[tokio::test]
async fn pushes_distinguish_accepting_rejecting_and_not_applying_peers() {
    let accepting = peer_id();
    let cfg = config(&spawn_peer(Answer::Ok).await, &accepting);
    let _ = ai_memory::federation::broadcast_store_quorum(&cfg, &memory()).await;
    let fresh = freshness::snapshot_for(&accepting).expect("push recorded");
    assert_eq!(fresh.push.consecutive_failures, 0);
    assert!(fresh.push.last_success_unix.is_some());
    assert_eq!(fresh.push.last_attempt_unix, fresh.push.last_success_unix);

    // A peer that has stopped accepting pushes: every attempt is newer than
    // the last success (here: there never was one), and the streak climbs.
    let rejecting = peer_id();
    let cfg = config(&spawn_peer(Answer::Status(500)).await, &rejecting);
    let _ = ai_memory::federation::broadcast_store_quorum(&cfg, &memory()).await;
    let fresh = freshness::snapshot_for(&rejecting).expect("push recorded");
    assert!(fresh.push.last_attempt_unix.is_some());
    assert_eq!(fresh.push.last_success_unix, None);
    assert!(fresh.push.consecutive_failures >= 1);
    assert_eq!(fresh.push.last_failure_class, Some("server_error"));

    // A 2xx whose own report says the item was skipped is NOT a success
    // (#2341), so a peer that answers 200 and drops everything is visible.
    let dropping = peer_id();
    let cfg = config(&spawn_peer(Answer::PushSkipped).await, &dropping);
    let _ = ai_memory::federation::broadcast_store_quorum(&cfg, &memory()).await;
    let fresh = freshness::snapshot_for(&dropping).expect("push recorded");
    assert_eq!(fresh.push.last_success_unix, None);
    assert_eq!(fresh.push.last_failure_class, Some("not_applied"));
}

#[tokio::test]
async fn bulk_catchup_push_records_the_peer_and_its_report() {
    let ok = peer_id();
    let cfg = config(&spawn_peer(Answer::Ok).await, &ok);
    assert!(
        ai_memory::federation::bulk_catchup_push(&cfg, &[memory()])
            .await
            .is_empty()
    );
    assert!(
        freshness::snapshot_for(&ok)
            .expect("recorded")
            .push
            .last_success_unix
            .is_some()
    );

    let skipped = peer_id();
    let cfg = config(&spawn_peer(Answer::PushSkipped).await, &skipped);
    let _ = ai_memory::federation::bulk_catchup_push(&cfg, &[memory()]).await;
    let fresh = freshness::snapshot_for(&skipped).expect("recorded");
    assert_eq!(fresh.push.last_success_unix, None);
    assert_eq!(fresh.push.last_failure_class, Some("not_applied"));
}

#[tokio::test]
async fn url_shaped_peer_ids_never_reach_the_exposition() {
    let secret_id = "peer-0:https://operator:hunter2@peer.example:9077";
    let cfg = config(&dead_peer().await, secret_id);
    catchup_once_for_tests(&cfg).await;
    let exposition = ai_memory::metrics::render();
    assert!(
        !exposition.contains("hunter2"),
        "credential leaked into /metrics"
    );
    assert!(
        !exposition.contains("peer.example"),
        "peer URL leaked into /metrics"
    );
    let label = freshness::peer_label(secret_id);
    assert_eq!(
        sample(
            "ai_memory_federation_peer_consecutive_failures",
            &[("peer", label.as_str()), ("direction", "pull")]
        ),
        Some(1)
    );
}

#[tokio::test]
async fn catchup_worker_publishes_its_cadence_so_a_stall_is_alertable() {
    let id = peer_id();
    let cfg = config(&spawn_peer(Answer::Ok).await, &id);
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        ai_memory::db::open(std::path::Path::new(":memory:")).expect("sqlite"),
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let interval = Duration::from_secs(47);
    let handle = ai_memory::federation::spawn_catchup_loop(cfg, db, interval);
    handle.abort();
    let _ = handle.await;
    let published = ai_memory::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix("ai_memory_federation_catchup_interval_seconds "))
        .map(|v| v.trim().to_string());
    assert_eq!(published.as_deref(), Some("47"));
    // The worker never got to run: the peer has NO attempt series, which is
    // exactly what `time() - last_attempt > k * interval` alerts on — never a
    // zero that would read as "attempted in 1970".
    assert_eq!(freshness::snapshot_for(&id), None);
}

/// Unix seconds of an RFC3339 instant, for the DLQ backlog expectations.
fn unix_of(rfc3339: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid rfc3339")
        .timestamp()
}

/// The per-peer DLQ backlog the replay tick publishes, on the sqlite sink:
/// grouped by peer, PENDING rows only, and the oldest row chosen by parsed
/// instant. `failed_at` offset spellings have varied across releases, so
/// `…T05:00:01+05:00` (00:00:01Z) is older than `…T01:00:00Z` although it
/// sorts after it as text; and the `:01` second pins exact integer seconds
/// (float `julianday` arithmetic truncated it to `:00`). A row whose
/// timestamp does not parse still counts toward depth, and its peer gets no
/// oldest series at all (absent, never a fake 0).
#[tokio::test]
async fn sqlite_dlq_backlog_is_per_peer_pending_only_and_oldest_by_instant() {
    use ai_memory::federation::push_dlq::{FederationDlqSink, SqliteDlqSink};

    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("dlq-backlog-3654.db");
    let (a, b) = (peer_id(), peer_id());
    {
        let conn = ai_memory::storage::open(&path).expect("open db");
        let rows = [
            ("m1", a.as_str(), "2026-01-01T01:00:00Z", None),
            ("m2", a.as_str(), "2026-01-01T05:00:01+05:00", None),
            (
                "m3",
                a.as_str(),
                "2025-01-01T00:00:00Z",
                Some("2025-01-02T00:00:00Z"),
            ),
            ("m4", b.as_str(), "not-a-timestamp", None),
        ];
        for (mem, peer, failed_at, replayed_at) in rows {
            conn.execute(
                "INSERT INTO federation_push_dlq (memory_id, peer_id, payload_json, \
                 attempt_count, last_error, failed_at, replayed_at) \
                 VALUES (?1, ?2, '{}', 1, 'e', ?3, ?4)",
                rusqlite::params![mem, peer, failed_at, replayed_at],
            )
            .expect("insert dlq row");
        }
    }
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        ai_memory::storage::open(&path).expect("handle conn"),
        path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let sink = SqliteDlqSink::new(db).await.expect("sqlite dlq sink");

    let mut backlog = sink
        .pending_dlq_backlog_by_peer()
        .await
        .expect("backlog by peer");
    backlog.sort_by(|x, y| x.peer_id.cmp(&y.peer_id));
    let find = |id: &str| backlog.iter().find(|r| r.peer_id == id).expect("peer row");
    assert_eq!(backlog.len(), 2, "one row per peer: {backlog:?}");
    assert_eq!(find(&a).pending, 2, "the replayed row is not pending");
    assert_eq!(
        find(&a).oldest_failed_unix,
        Some(unix_of("2026-01-01T00:00:01Z")),
        "oldest by instant, to the exact second"
    );
    assert_eq!(find(&b).pending, 1, "an unparseable row still counts");
    assert_eq!(find(&b).oldest_failed_unix, None);

    freshness::record_push_dlq_backlog(&backlog);
    let (la, lb) = (freshness::peer_label(&a), freshness::peer_label(&b));
    let depth = "ai_memory_federation_peer_push_dlq_depth";
    let oldest = "ai_memory_federation_peer_push_dlq_oldest_failed_timestamp_seconds";
    assert_eq!(sample(depth, &[("peer", la.as_str())]), Some(2));
    assert_eq!(
        sample(oldest, &[("peer", la.as_str())]),
        Some(unix_of("2026-01-01T00:00:01Z"))
    );
    assert_eq!(sample(depth, &[("peer", lb.as_str())]), Some(1));
    assert_eq!(sample(oldest, &[("peer", lb.as_str())]), None);
}

/// The postgres sink's per-peer backlog (`failed_at` is TIMESTAMPTZ there):
/// same grouping, pending-only and oldest-instant contract as the sqlite
/// sink. Runs only against a live PG named by `AI_MEMORY_TEST_POSTGRES_URL`;
/// every row it writes carries this test's unique peer ids and is deleted
/// before the assertions run, so a failure leaves no residue.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL)"]
async fn pg_dlq_backlog_is_per_peer_pending_only_and_oldest_by_instant() {
    use ai_memory::federation::push_dlq::{FederationDlqSink, PostgresDlqSink};

    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("AI_MEMORY_TEST_POSTGRES_URL must name a live scratch postgres");
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect live PG");
    let pool = store.pool().clone();
    let (a, b) = (peer_id(), peer_id());
    let rows = [
        ("m1", a.as_str(), "2026-01-01T01:00:00Z", None),
        ("m2", a.as_str(), "2026-01-01T05:00:01+05:00", None),
        (
            "m3",
            a.as_str(),
            "2025-01-01T00:00:00Z",
            Some("2025-01-02T00:00:00Z"),
        ),
        ("m4", b.as_str(), "2026-02-01T00:00:00Z", None),
    ];
    for (mem, peer, failed_at, replayed_at) in rows {
        sqlx::query(
            "INSERT INTO federation_push_dlq (memory_id, peer_id, payload_json, \
             attempt_count, last_error, failed_at, replayed_at) \
             VALUES ($1, $2, '{}'::jsonb, 1, 'e', $3::timestamptz, $4::timestamptz)",
        )
        .bind(mem)
        .bind(peer)
        .bind(failed_at)
        .bind(replayed_at)
        .execute(&pool)
        .await
        .expect("insert dlq row");
    }

    let sink = PostgresDlqSink::new(Arc::new(store));
    let backlog = sink.pending_dlq_backlog_by_peer().await;
    sqlx::query("DELETE FROM federation_push_dlq WHERE peer_id = $1 OR peer_id = $2")
        .bind(&a)
        .bind(&b)
        .execute(&pool)
        .await
        .expect("clean up dlq rows");

    let backlog = backlog.expect("backlog by peer");
    let find = |id: &str| backlog.iter().find(|r| r.peer_id == id).expect("peer row");
    assert_eq!(find(&a).pending, 2, "the replayed row is not pending");
    assert_eq!(
        find(&a).oldest_failed_unix,
        Some(unix_of("2026-01-01T00:00:01Z"))
    );
    assert_eq!(find(&b).pending, 1);
    assert_eq!(
        find(&b).oldest_failed_unix,
        Some(unix_of("2026-02-01T00:00:00Z"))
    );
}
