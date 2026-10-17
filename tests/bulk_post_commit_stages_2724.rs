// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #2724 (CB-22) — `POST /api/v1/memories/bulk` must run the post-commit
//! stages single-create runs.
//!
//! `bulk_create` re-implemented the single-create funnel and omitted three
//! post-commit stages (the same re-implementation-omits-a-stage root cause as
//! #2550/#2551/#2552/#2588/#2594):
//!
//! - **F1 audit** — the funnel emitted ZERO `AuditAction::Store` rows, so a
//!   fleet corpus load left an invisible gap in the tamper-evident chain.
//! - **F2 dispatch** — the funnel fired ZERO `subscriptions::dispatch_event`,
//!   so a registered `memory_store` subscriber received nothing.
//! - **F3 postgres federation fanout** — covered by the `sal-postgres` twin in
//!   `tests/federation_postgres_fanout.rs::bulk_create_postgres_fans_out_to_peers_2724`.
//!
//! These sqlite cells pin the F1 + F2 OUTCOMES and, critically, that the
//! stages fire ONCE per DISTINCT persisted row and NEVER for a rejected /
//! collapsed input row — the partial-failure honesty the North Star requires.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl, set_allow_loopback_webhooks};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::subscriptions::{self, NewSubscription};

mod common;

/// #1751 — the v0.9 HTTP-direct default is REQUIRED; opt out so the unsigned
/// store fixtures below exercise the post-commit stages, not a 403.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

const AGENT: &str = "bulk-postcommit-agent";

fn build_router(db_path: &Path) -> axum::Router {
    permissive_attestation_for_tests();
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn fresh_db() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("bulk-2724.db");
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    (dir, db_path)
}

async fn post(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

fn row(namespace: &str, title: &str, content: &str) -> Value {
    json!({
        "tier": "long", "namespace": namespace, "title": title, "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "api", "metadata": {},
    })
}

fn db_row_count(db_path: &Path, namespace: &str) -> i64 {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
            params![namespace],
            |r| r.get(0),
        )
        .expect("count")
}

/// The ids of the rows committed to `namespace` (#7395): the delivered ids
/// must equal this set, not merely have the same count.
fn db_committed_ids(db_path: &Path, namespace: &str) -> BTreeSet<String> {
    let conn = Connection::open(db_path).expect("open");
    let mut stmt = conn
        .prepare("SELECT id FROM memories WHERE namespace = ?1")
        .expect("prepare");
    stmt.query_map(params![namespace], |r| r.get::<_, String>(0))
        .expect("query ids")
        .collect::<Result<BTreeSet<String>, _>>()
        .expect("collect ids")
}

/// Count `AuditAction::Store` NDJSON rows in the audit log whose target
/// namespace matches `namespace`. Filtering by namespace makes the count
/// robust against any other rows that share the process-global audit sink.
fn store_audit_rows_for_ns(audit_file: &Path, namespace: &str) -> usize {
    let raw = std::fs::read_to_string(audit_file).unwrap_or_default();
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|ev| {
            ev["action"] == json!("store") && ev["target"]["namespace"] == json!(namespace)
        })
        .count()
}

// ---------------------------------------------------------------------------
// F1 — audit emit.
// ---------------------------------------------------------------------------

/// PARENT: `grep -n "crate::audit::emit" src/handlers/bulk.rs` returned ZERO
/// hits — a bulk load left NO `Store` rows in the tamper-evident chain while
/// single-create wrote one per memory. Post-#2724 the funnel emits one `Store`
/// row per DISTINCT persisted row: a clean batch of N draws N; an in-batch
/// collapse draws one per surviving row (never one per input index); a
/// rejected row draws none.
#[tokio::test]
async fn bulk_emits_one_store_audit_row_per_persisted_row_2724() {
    let (_dir, db_path) = fresh_db();
    let audit_dir = TempDir::new().expect("audit dir");
    let audit_file = audit_dir.path().join("audit.ndjson");
    // Enable the (process-global) audit sink; the namespace filter below keeps
    // the counts correct even if a concurrent test shares this sink.
    ai_memory::audit::init(&audit_file, false, false).expect("audit init");
    assert!(ai_memory::audit::is_enabled(), "audit sink must be enabled");

    let router = build_router(&db_path);

    // (1) A clean batch of 3 distinct rows draws exactly 3 Store rows.
    let ns_clean = "audit-clean-2724";
    let clean = json!([
        row(ns_clean, "c1", "x"),
        row(ns_clean, "c2", "y"),
        row(ns_clean, "c3", "z"),
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &clean).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(db_row_count(&db_path, ns_clean), 3, "3 rows persisted: {v}");
    assert_eq!(
        store_audit_rows_for_ns(&audit_file, ns_clean),
        3,
        "#2724 F1: one Store audit row per persisted memory (found for ns {ns_clean})"
    );

    // (2) A batch with an in-batch collapse (two rows share a title, last-wins)
    // plus a validation-rejected empty-title row persists 2 distinct rows, so
    // it draws 2 Store rows — NOT 3 (per input index) and NOT for the reject.
    let ns_mixed = "audit-mixed-2724";
    let mixed = json!([
        row(ns_mixed, "dup", "first"),
        row(ns_mixed, "uniq", "u"),
        row(ns_mixed, "dup", "second wins"),
        row(ns_mixed, "", "rejected-empty-title"),
    ]);
    let (status2, v2) = post(&router, "/api/v1/memories/bulk", &mixed).await;
    assert_eq!(status2, StatusCode::MULTI_STATUS, "{v2}");
    assert_eq!(db_row_count(&db_path, ns_mixed), 2, "2 distinct rows: {v2}");
    assert_eq!(v2["created"], 2, "{v2}");
    assert_eq!(v2["deduped"], 1, "{v2}");
    assert_eq!(v2["rejected"], 1, "{v2}");
    assert_eq!(
        store_audit_rows_for_ns(&audit_file, ns_mixed),
        2,
        "#2724 F1: the audit fires per DISTINCT persisted row, never for a \
         collapsed or rejected input index"
    );
}

// ---------------------------------------------------------------------------
// F2 — subscription dispatch.
// ---------------------------------------------------------------------------

/// PARENT: `grep -n "dispatch_event" src/handlers/bulk.rs` returned ZERO hits
/// — a `memory_store` subscriber received NOTHING from a bulk write while
/// single-create fired the event on every store. Post-#2724 a bulk write fires
/// one `memory_store` dispatch per persisted row, so a registered subscriber's
/// webhook is invoked once per committed row and never for a rejected one.
#[tokio::test]
async fn bulk_dispatches_memory_store_event_per_persisted_row_2724() {
    pin_serial_dispatch();
    let _cell = DISPATCH_CELL_LOCK.lock().await;
    // The receiver binds loopback; the SSRF guard rejects loopback by
    // default. #3705 — it serves TLS (every `http://` target is refused,
    // loopback included) and the dispatcher trusts the fixture leaf. The
    // dispatcher counts a delivery successful ONLY on a 2xx whose body echoes
    // `{"status":"ack","correlation_id":<the sent id>}`; anything else is
    // retried on the [200ms, 1s, 5s] ladder (which would double the observed
    // request count), so the receiver echoes the id and each delivery lands
    // once.
    set_allow_loopback_webhooks(true);
    let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
    let server =
        common::tls_receiver::TlsReceiver::start_with(tls, common::tls_receiver::ack_echo()).await;

    let (_dir, db_path) = fresh_db();
    let hook_url = format!("{}/hook", server.uri());
    // ONE wildcard subscriber registered in the SAME db the router reads.
    {
        let conn = Connection::open(&db_path).expect("open");
        subscriptions::insert(
            &conn,
            &NewSubscription {
                url: &hook_url,
                events: "*",
                // HMAC-signed dispatch is mandatory at v0.7.0 (unsigned
                // delivery DISABLED), so a secret-less subscription would be
                // skipped and never deliver.
                secret: Some("bulk-2724-secret"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .expect("insert subscription");
    }

    let router = build_router(&db_path);
    let ns = "dispatch-2724";
    // 3 distinct rows commit; the empty-title row is rejected and must NOT
    // fire a dispatch.
    let batch = json!([
        row(ns, "d1", "x"),
        row(ns, "d2", "y"),
        row(ns, "d3", "z"),
        row(ns, "", "rejected"),
    ]);
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;
    assert_eq!(status, StatusCode::MULTI_STATUS, "{v}");
    assert_eq!(db_row_count(&db_path, ns), 3, "3 committed rows: {v}");

    // #7320 - bounded wait on the DISTINCT dispatched-row count (never a
    // single sample): exactly 3, one per committed row, zero for the rejected
    // row (the settle inside the helper surfaces a spurious extra).
    let seen = wait_for_dispatches(&server, 3).await;
    let total_requests = server.received_count().await;
    assert_eq!(
        (seen.rows, seen.correlations),
        (3, 3),
        "#2724 F2: the subscriber must receive exactly one memory_store \
         dispatch (one correlation id) per committed row (3), never for the \
         rejected row ({seen:?}, {total_requests} requests): {v}"
    );
    // #7396 - no request was silently dropped from the summary.
    assert!(
        seen.malformed.is_empty(),
        "#7396: every received request must be a well-formed dispatch; \
         malformed (request index, body length): {:?}",
        seen.malformed
    );
    // #7395 - the delivered ids ARE the committed ids, not just as many.
    assert_eq!(
        id_mismatch(&seen, &db_committed_ids(&db_path, ns)),
        None,
        "#7395: delivered memory_ids must equal the committed set"
    );
}

// ---------------------------------------------------------------------------
// #7320 - the dispatch wait must cover the asynchronous delivery budget.
// ---------------------------------------------------------------------------

/// #7320 - webhook delivery is asynchronous relative to the committed rows
/// (`dispatch_event_to_subs` spawns one bounded worker per subscriber). The
/// wait on the receiver therefore cannot be a short fixed window: it is the
/// product's worst-case budget for one delivery (every attempt timing out plus
/// the retry backoffs) plus a margin for queueing behind other deliveries.
const DISPATCH_WAIT_MARGIN: Duration = Duration::from_secs(10);

/// Deliveries that can hold the single dispatch permit ahead of a cell's own
/// rows: the previous cell's last delivery may still hold it after
/// `DISPATCH_CELL_LOCK` is released (#7369).
const LEFTOVER_DELIVERIES: usize = 1;

/// Worst-case time for ONE delivery: every attempt times out plus the retry
/// backoffs, `ACK_TIMEOUT * (RETRY_BACKOFFS.len() + 1) + sum(RETRY_BACKOFFS)`
/// = 5 s * 4 + (0.2 + 1 + 5) s = 26.2 s.
fn delivery_budget() -> Duration {
    use ai_memory::subscriptions::{ACK_TIMEOUT, RETRY_BACKOFFS};
    let attempts = u32::try_from(RETRY_BACKOFFS.len() + 1).expect("small attempt count");
    ACK_TIMEOUT * attempts + RETRY_BACKOFFS.iter().sum::<Duration>()
}

/// Upper bound the wait loop honours (it returns as soon as the count is met).
/// With `SERIAL_DISPATCH_PERMITS` = 1 the deliveries run one at a time, so the
/// worst case is every one of `rows` plus `LEFTOVER_DELIVERIES` burning its
/// whole budget in turn: `(rows + 1) * 26.2 s + DISPATCH_WAIT_MARGIN` (#7369),
/// e.g. 4 rows = 5 * 26.2 + 10 = 141 s.
fn dispatch_wait_window(rows: usize) -> Duration {
    let serialised = u32::try_from(rows + LEFTOVER_DELIVERIES).expect("small row count");
    delivery_budget() * serialised + DISPATCH_WAIT_MARGIN
}

/// Poll interval while waiting for deliveries to land.
const DISPATCH_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Settle time so a spurious extra delivery would surface after the count is met.
const DISPATCH_SETTLE: Duration = Duration::from_millis(300);

/// Serialised dispatch (one worker permit) used by the slow-receiver cell.
const SERIAL_DISPATCH_PERMITS: usize = 1;

/// Per-delivery ack delay for the slow-receiver cell: under one permit the
/// k-th delivery reaches the receiver k * delay after the first, which pushes
/// the later deliveries beyond the old fixed window while every one of them
/// is still inside the product's own per-attempt ack budget.
const SLOW_ACK_MARGIN: Duration = Duration::from_secs(1);

/// Ack delay: `ACK_TIMEOUT` (which also covers the TLS handshake) minus
/// `SLOW_ACK_MARGIN`, so the ack stays inside the attempt budget (#7370).
const SLOW_ACK_DELAY: Duration =
    ai_memory::subscriptions::ACK_TIMEOUT.saturating_sub(SLOW_ACK_MARGIN);

/// Rows in the slow-receiver batch (the fourth arrives at ~3 * 4 s = 12 s).
const SLOW_BATCH_ROWS: usize = 4;

/// The dispatch semaphore is process-wide: with one permit a slow cell would
/// starve a concurrent cell's deliveries, so the dispatch cells run one at a
/// time. The lock does not drain the previous cell's last delivery, which can
/// still hold the permit; `LEFTOVER_DELIVERIES` in the wait window covers it.
static DISPATCH_CELL_LOCK: Mutex<()> = Mutex::const_new(());

/// Pin the process-wide dispatch concurrency before any dispatch runs; the
/// first caller wins, so every dispatch cell in this binary calls it.
fn pin_serial_dispatch() {
    let _ =
        ai_memory::subscriptions::override_dispatch_concurrency_for_tests(SERIAL_DISPATCH_PERMITS);
}

/// What the receiver saw, reduced to the exactly-once invariant (#7367).
#[derive(Debug, PartialEq, Eq)]
struct DispatchSummary {
    /// Distinct `memory_id`s delivered.
    rows: usize,
    /// Distinct `correlation_id`s delivered (a retry shares its id).
    correlations: usize,
    /// The distinct `memory_id`s themselves (#7395).
    memory_ids: BTreeSet<String>,
    /// Requests that lacked `memory_id` or `correlation_id`, or whose body was
    /// not JSON (#7396), as (request index, body length). Must be empty: such
    /// a request is never silently dropped.
    malformed: Vec<(usize, usize)>,
}

/// One request the receiver saw, after classification (#7396).
#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    /// A well-formed dispatch: `(memory_id, correlation_id)`.
    Valid(String, String),
    /// A request that is not a well-formed dispatch. Carries the request index
    /// and body length only, never the body (it may hold row content).
    Malformed { index: usize, body_len: usize },
}

/// Classify one received request body (#7396).
fn classify_delivery(index: usize, body: &[u8]) -> Delivery {
    let malformed = Delivery::Malformed {
        index,
        body_len: body.len(),
    };
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return malformed;
    };
    let field = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    match (field("memory_id"), field("correlation_id")) {
        (Some(m), Some(c)) => Delivery::Valid(m, c),
        _ => malformed,
    }
}

/// Describe how the delivered ids differ from the committed ids (#7395), or
/// `None` when the two sets are equal. Never prints a body, only ids.
fn id_mismatch(seen: &DispatchSummary, committed: &BTreeSet<String>) -> Option<String> {
    if &seen.memory_ids == committed {
        return None;
    }
    let missing: Vec<&String> = committed.difference(&seen.memory_ids).collect();
    let foreign: Vec<&String> = seen.memory_ids.difference(committed).collect();
    Some(format!(
        "delivered ids differ from committed ids: committed but never delivered \
         {missing:?}, delivered but not committed {foreign:?}"
    ))
}

/// Reduce `(memory_id, correlation_id)` pairs to a [`DispatchSummary`].
fn summarise_dispatches(deliveries: &[Delivery]) -> DispatchSummary {
    let mut rows: BTreeSet<String> = BTreeSet::new();
    let mut correlations: BTreeSet<&str> = BTreeSet::new();
    let mut malformed: Vec<(usize, usize)> = Vec::new();
    for d in deliveries {
        match d {
            Delivery::Valid(m, c) => {
                rows.insert(m.clone());
                correlations.insert(c.as_str());
            }
            Delivery::Malformed { index, body_len } => malformed.push((*index, *body_len)),
        }
    }
    DispatchSummary {
        rows: rows.len(),
        correlations: correlations.len(),
        memory_ids: rows,
        malformed,
    }
}

/// Classify every request the receiver saw; none is dropped (#7396).
async fn received_deliveries(server: &common::tls_receiver::TlsReceiver) -> Vec<Delivery> {
    let reqs = server.received_requests().await.unwrap_or_default();
    reqs.iter()
        .enumerate()
        .map(|(i, r)| classify_delivery(i, &r.body))
        .collect()
}

/// Wait (bounded) until `expected` distinct rows were dispatched, then settle
/// and return the final summary.
async fn wait_for_dispatches(
    server: &common::tls_receiver::TlsReceiver,
    expected: usize,
) -> DispatchSummary {
    let deadline = std::time::Instant::now() + dispatch_wait_window(expected);
    while std::time::Instant::now() < deadline {
        if summarise_dispatches(&received_deliveries(server).await).rows >= expected {
            break;
        }
        tokio::time::sleep(DISPATCH_POLL_INTERVAL).await;
    }
    tokio::time::sleep(DISPATCH_SETTLE).await;
    summarise_dispatches(&received_deliveries(server).await)
}

/// #7367 - a second dispatch of one row (new correlation id) must be visible.
#[test]
fn duplicate_dispatch_of_one_row_is_detected_7367() {
    let pair = |m: &str, c: &str| Delivery::Valid(m.to_owned(), c.to_owned());
    let dup = [pair("m1", "c1"), pair("m2", "c2"), pair("m2", "c3")];
    let dup_seen = summarise_dispatches(&dup);
    assert_eq!(
        (dup_seen.rows, dup_seen.correlations),
        (2, 3),
        "a duplicate dispatch of m2 must add a correlation id"
    );
    // A retry of one delivery shares its correlation id: not a duplicate.
    let retry = [pair("m1", "c1"), pair("m1", "c1")];
    let retry_seen = summarise_dispatches(&retry);
    assert_eq!((retry_seen.rows, retry_seen.correlations), (1, 1));
}

/// #7396 - a request without `memory_id`/`correlation_id`, or with an
/// unparsable or empty body, is counted as malformed, never dropped.
#[test]
fn malformed_requests_are_counted_not_dropped_7396() {
    const GOOD: &[u8] = br#"{"memory_id":"m1","correlation_id":"c1"}"#;
    const NO_MEMORY_ID: &[u8] = br#"{"correlation_id":"c1"}"#;
    const NO_CORRELATION_ID: &[u8] = br#"{"memory_id":"m1"}"#;
    const NOT_JSON: &[u8] = b"not json";
    const EMPTY: &[u8] = b"";
    let bodies = [GOOD, NO_MEMORY_ID, NO_CORRELATION_ID, NOT_JSON, EMPTY];
    let classified: Vec<Delivery> = bodies
        .iter()
        .enumerate()
        .map(|(i, b)| classify_delivery(i, b))
        .collect();
    let seen = summarise_dispatches(&classified);
    assert_eq!(
        seen.malformed,
        vec![(1, 23), (2, 18), (3, 8), (4, 0)],
        "{seen:?}"
    );
    assert_eq!((seen.rows, seen.correlations), (1, 1));
    assert_eq!(
        classified[4],
        Delivery::Malformed {
            index: 4,
            body_len: 0
        }
    );
}

/// #7395 - same counts, wrong ids: a foreign id plus a missing committed row
/// keeps both counts at N and must still be reported.
#[test]
fn delivered_ids_must_equal_committed_ids_7395() {
    let pair = |m: &str, c: &str| Delivery::Valid(m.to_owned(), c.to_owned());
    let committed: BTreeSet<String> = ["m1", "m2"].iter().map(|m| (*m).to_owned()).collect();
    let good = summarise_dispatches(&[pair("m1", "c1"), pair("m2", "c2")]);
    assert_eq!(id_mismatch(&good, &committed), None);
    let foreign = summarise_dispatches(&[pair("m1", "c1"), pair("m9", "c2")]);
    assert_eq!((foreign.rows, foreign.correlations), (2, 2));
    let why = id_mismatch(&foreign, &committed).expect("a foreign id must be reported");
    assert!(why.contains("m9") && why.contains("m2"), "{why}");
}

/// #7320 - a slow (but within-budget) receiver delays later deliveries past
/// the old fixed window; every committed row must still be dispatched.
#[tokio::test]
async fn bulk_dispatch_waits_for_slow_receiver_deliveries_7320() {
    pin_serial_dispatch();
    let _cell = DISPATCH_CELL_LOCK.lock().await;
    set_allow_loopback_webhooks(true);
    let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
    let server = common::tls_receiver::TlsReceiver::start_with(
        tls,
        common::tls_receiver::ack_echo_slow(SLOW_ACK_DELAY),
    )
    .await;

    let (_dir, db_path) = fresh_db();
    let hook_url = format!("{}/hook", server.uri());
    {
        let conn = Connection::open(&db_path).expect("open");
        subscriptions::insert(
            &conn,
            &NewSubscription {
                url: &hook_url,
                events: "*",
                secret: Some("bulk-7320-secret"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        )
        .expect("insert subscription");
    }

    let router = build_router(&db_path);
    let ns = "dispatch-7320";
    let batch = Value::Array(
        (0..SLOW_BATCH_ROWS)
            .map(|i| row(ns, &format!("s{i}"), "slow"))
            .collect(),
    );
    let (status, v) = post(&router, "/api/v1/memories/bulk", &batch).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        db_row_count(&db_path, ns),
        i64::try_from(SLOW_BATCH_ROWS).unwrap(),
        "all rows committed: {v}"
    );

    let seen = wait_for_dispatches(&server, SLOW_BATCH_ROWS).await;
    assert_eq!(
        (seen.rows, seen.correlations),
        (SLOW_BATCH_ROWS, SLOW_BATCH_ROWS),
        "#7320/#7367: every committed row must be dispatched exactly once to \
         a slow receiver ({seen:?}, expected {SLOW_BATCH_ROWS}): {v}"
    );
    // #7396 - no request was silently dropped from the summary.
    assert!(
        seen.malformed.is_empty(),
        "#7396: every received request must be a well-formed dispatch; \
         malformed (request index, body length): {:?}",
        seen.malformed
    );
    // #7395 - the delivered ids ARE the committed ids, not just as many.
    assert_eq!(
        id_mismatch(&seen, &db_committed_ids(&db_path, ns)),
        None,
        "#7395: delivered memory_ids must equal the committed set"
    );
}
