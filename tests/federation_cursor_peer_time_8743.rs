// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8743 — a federation receiver's pull cursor is never derived from a value
//! the peer controls.
//!
//! The defect: a peer row (or a peer `next_since`) stamped ahead of the
//! receiver's clock was written into the monotonic `sync_state` cursor, so
//! every row the peer wrote later (with an honest, earlier timestamp) fell
//! below the cursor and was never pulled, while every pull logged `ok`.
//!
//! The invariant, checked over a named corpus of timestamp sequences on
//! every pull loop (serve catch-up on the sqlite connection, the SAL store
//! on sqlite and on postgres, and the sync-daemon `sync_cycle_once`):
//!
//! - every row the peer holds with a timestamp inside the skew bound ends up
//!   in the receiver's store exactly once;
//! - a row beyond `now + PULL_CURSOR_FUTURE_SKEW_SECS` is not applied and is
//!   counted as `future_skew`; neither it nor a malformed timestamp is
//!   silently used;
//! - the persisted cursor never passes the receiver's clock nor any delivered
//!   row that was neither applied nor refused;
//! - #8788 / #8789 — a delivered row the receiver refuses (malformed
//!   timestamp, failed field validation, forged attestation, out-of-scope
//!   namespace) is recorded with its exact reason exactly once (a row with a
//!   parseable timestamp is never re-delivered) and never stops the rows
//!   after it, wherever it sits in the window;
//! - a window that left a delivered row behind is not complete (no `ok`).
//!
//! The peer is an in-process axum server on 127.0.0.1 with the production
//! `/sync/since` semantics (`updated_at > since`, ascending, `LIMIT`,
//! `next_since` = newest examined row) and per-case overrides for the hostile
//! shapes (reordering, duplicates, an advertised future `next_since`).

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ai_memory::federation::{
    FederationConfig, OUTCOME_DEFERRED_FUTURE_SKEW, PeerEndpoint, PullOutcome, RefusalReason,
};
use ai_memory::replication::QuorumPolicy;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use chrono::{DateTime, SecondsFormat, Utc};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// The receiver's skew bound (mirrors `PULL_CURSOR_FUTURE_SKEW_SECS`).
const SKEW_SECS: i64 = 300;
/// The audit's exact case: a peer row stamped one day ahead.
const AUDIT_FUTURE_SECS: i64 = ai_memory::SECS_PER_DAY;
/// A peer-advertised `next_since` inside the old 300 s skew window.
const WITHIN_SKEW_NEXT_SINCE_SECS: i64 = 200;
/// A row the peer writes after the first pass (inside the skew bound).
const LATER_WRITE_SECS: i64 = 30;
/// Far-past timestamps that must still be pulled.
const FAR_PAST_EPOCH: &str = "1970-01-01T00:00:01Z";
const FAR_PAST_Y2K: &str = "2000-01-01T00:00:00Z";
/// A timestamp the receiver cannot parse.
const MALFORMED_TS: &str = "not-a-timestamp";
/// The page size the production peer applies when none is configured.
const DEFAULT_PAGE: usize = 500;
/// The receiver's agent id and the catch-up peer id.
const LOCAL_ID: &str = "ai:receiver-8743";
const PEER_ID: &str = "peer-8743";
const NAMESPACE: &str = "fed-8743";
/// Passes run per phase: enough for every multi-page case to drain.
const PASSES_PER_PHASE: usize = 4;
/// #8789 — corpus row-name prefix: the row fails `validate_memory`.
const KIND_INVALID: &str = "invalid_";
/// #8788 — corpus row-name prefix: the row carries a `write_signature` that
/// is not base64, which the pull attestation gate refuses for every author
/// whether or not the receiver has a key enrolled for it.
const KIND_FORGED: &str = "forged_";
/// #8788 — corpus row-name prefix: the row is in a namespace outside the
/// catch-up peer's allowlist (catch-up loops only; the sync daemon has no
/// per-peer namespace scope).
const KIND_OUT_OF_SCOPE: &str = "oos_";
/// A priority outside `1..=10`, refused by `validate_memory`.
const INVALID_PRIORITY: i64 = 11;
/// The namespace a [`KIND_OUT_OF_SCOPE`] row lands in.
const OUT_OF_SCOPE_NAMESPACE: &str = "fed-8743-out";
/// The forged author's claimed agent id.
const FORGED_AUTHOR: &str = "ai:forger-8788";
/// A presented signature that is not base64 (`!` is outside the alphabet).
const FORGED_SIGNATURE_B64: &str = "!forged-8788!";

/// #8788 — the most times one refused row (parseable timestamp) is recorded:
/// once when first delivered, plus once more when it was the newest row of a
/// full page, because the tie-safe cursor stays strictly below that row and
/// the next window re-delivers it. Never more: the second window settles it
/// below a newer row and the cursor passes it.
const MAX_RECORDS_PER_REFUSED_ROW: usize = 2;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// How the hostile peer shapes a page beyond the production semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageShape {
    /// Production order: ascending `updated_at`.
    Ascending,
    /// The page in descending order.
    Reversed,
    /// Every row of the page delivered twice.
    Duplicated,
}

#[derive(Clone, Debug)]
struct PeerRow {
    id: String,
    /// The corpus name (its prefix selects a refused-row kind).
    name: &'static str,
    updated_at: String,
}

#[derive(Default)]
struct PeerData {
    rows: Vec<PeerRow>,
    page: usize,
    shape: Option<PageShape>,
    next_since_override: Option<String>,
}

type PeerState = Arc<Mutex<PeerData>>;

fn memory_json(row: &PeerRow) -> serde_json::Value {
    let namespace = if row.name.starts_with(KIND_OUT_OF_SCOPE) {
        OUT_OF_SCOPE_NAMESPACE
    } else {
        NAMESPACE
    };
    let priority = if row.name.starts_with(KIND_INVALID) {
        INVALID_PRIORITY
    } else {
        5
    };
    let metadata = if row.name.starts_with(KIND_FORGED) {
        serde_json::json!({
            (ai_memory::META_KEY_AGENT_ID): FORGED_AUTHOR,
            (ai_memory::models::field_names::WRITE_SIGNATURE): FORGED_SIGNATURE_B64,
        })
    } else {
        serde_json::json!({})
    };
    serde_json::json!({
        "id": row.id,
        "tier": "long",
        "namespace": namespace,
        "title": format!("row {}", row.id),
        "content": "peer-time corpus row (#8743)",
        "tags": [],
        "priority": priority,
        "confidence": 1.0,
        "source": "api",
        "metadata": metadata,
        "access_count": 0,
        "created_at": FAR_PAST_EPOCH,
        "updated_at": row.updated_at,
    })
}

async fn since_handler(
    State(state): State<PeerState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    let data = state.lock().await;
    let limit = q
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(data.page)
        .min(data.page);
    let since = q.get("since").cloned();
    let mut page: Vec<PeerRow> = data
        .rows
        .iter()
        .filter(|r| since.as_deref().is_none_or(|s| r.updated_at.as_str() > s))
        .cloned()
        .collect();
    // Stable sort on `updated_at` alone: a tie group keeps the peer's
    // insertion order, as the production `ORDER BY updated_at` may.
    page.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
    page.truncate(limit);
    let next_since = data
        .next_since_override
        .clone()
        .or_else(|| page.last().map(|r| r.updated_at.clone()));
    let mut delivered: Vec<serde_json::Value> = page.iter().map(memory_json).collect();
    match data.shape.unwrap_or(PageShape::Ascending) {
        PageShape::Ascending => {}
        PageShape::Reversed => delivered.reverse(),
        PageShape::Duplicated => {
            delivered = delivered
                .iter()
                .flat_map(|m| [m.clone(), m.clone()])
                .collect();
        }
    }
    axum::Json(serde_json::json!({
        "count": delivered.len(),
        "limit": limit,
        "memories": delivered,
        "next_since": next_since,
    }))
}

async fn push_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"applied": 0}))
}

async fn spawn_peer(state: PeerState) -> String {
    let app = Router::new()
        .route("/api/v1/sync/since", get(since_handler))
        .route("/api/v1/sync/push", post(push_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// One corpus case: rows by phase (the peer gains each phase's rows before
/// that phase's passes) and the exact expected result.
struct Case {
    name: &'static str,
    page: usize,
    shape: PageShape,
    next_since_secs: Option<i64>,
    phases: Vec<Vec<(&'static str, Ts)>>,
    /// Ids that must end up in the store, exactly once each.
    expect_ids: &'static [&'static str],
    /// Rows counted `future_skew` on the LAST pass.
    expect_future_skew_last: usize,
    /// #8788 / #8789 — every row refused over the whole case, with its
    /// reason (each exactly once, except an unparseable timestamp, which the
    /// peer re-delivers every pass).
    expect_refused: &'static [(&'static str, RefusalReason)],
    /// Rows refused on the LAST pass.
    expect_refused_last: usize,
    /// The case needs the per-peer namespace scope (catch-up loops only).
    catchup_only: bool,
    /// The LAST pass was held on a full single-tie-group page.
    expect_held_last: bool,
}

#[derive(Clone, Copy)]
enum Ts {
    /// Seconds relative to the case start (receiver clock).
    Rel(i64),
    /// A fixed literal timestamp.
    Lit(&'static str),
}

fn render(start: DateTime<Utc>, ts: Ts) -> String {
    match ts {
        Ts::Rel(secs) => {
            (start + chrono::Duration::seconds(secs)).to_rfc3339_opts(SecondsFormat::Secs, true)
        }
        Ts::Lit(s) => s.to_string(),
    }
}

/// Stable UUID-shaped id for a corpus row name.
fn row_id(name: &str) -> String {
    let digest = name.bytes().fold(0u64, |h, b| {
        h.wrapping_mul(1_099_511_628_211) ^ u64::from(b)
    });
    format!(
        "8743{:04x}-0000-4000-8000-{:012x}",
        digest & 0xffff,
        digest & 0xffff_ffff_ffff
    )
}

fn corpus() -> Vec<Case> {
    vec![
        Case {
            name: "audit_24h_future_row_then_later_write",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![
                vec![("a", Ts::Rel(-120)), ("future", Ts::Rel(AUDIT_FUTURE_SECS))],
                vec![("later", Ts::Rel(LATER_WRITE_SECS))],
            ],
            expect_ids: &["a", "later"],
            expect_future_skew_last: 1,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "peer_next_since_inside_old_skew_window",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: Some(WITHIN_SKEW_NEXT_SINCE_SECS),
            phases: vec![
                vec![("a", Ts::Rel(-60))],
                vec![("later", Ts::Rel(LATER_WRITE_SECS))],
            ],
            expect_ids: &["a", "later"],
            expect_future_skew_last: 0,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "far_past_rows",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![vec![
                ("epoch", Ts::Lit(FAR_PAST_EPOCH)),
                ("y2k", Ts::Lit(FAR_PAST_Y2K)),
                ("recent", Ts::Rel(-60)),
            ]],
            expect_ids: &["epoch", "y2k", "recent"],
            expect_future_skew_last: 0,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "equal_timestamps_across_page_boundary",
            page: 3,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![vec![
                ("t1", Ts::Rel(-50)),
                ("t1b", Ts::Rel(-45)),
                ("t2a", Ts::Rel(-40)),
                ("t2b", Ts::Rel(-40)),
                ("t3", Ts::Rel(-30)),
            ]],
            expect_ids: &["t1", "t1b", "t2a", "t2b", "t3"],
            expect_future_skew_last: 0,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "tie_group_larger_than_page_is_held_not_skipped",
            page: 2,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![vec![
                ("tie1", Ts::Rel(-40)),
                ("tie2", Ts::Rel(-40)),
                ("tie3", Ts::Rel(-40)),
                ("after", Ts::Rel(-30)),
            ]],
            // The page cannot reach `tie3` / `after` without a compound
            // cursor (wire change, filed under #8741): the receiver must hold
            // and say so, never advance past them.
            expect_ids: &["tie1", "tie2"],
            expect_future_skew_last: 0,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: true,
        },
        Case {
            name: "reordered_page_with_future_row_first",
            page: DEFAULT_PAGE,
            shape: PageShape::Reversed,
            next_since_secs: None,
            phases: vec![vec![
                ("r1", Ts::Rel(-30)),
                ("r2", Ts::Rel(-20)),
                ("r3", Ts::Rel(-10)),
                ("future", Ts::Rel(AUDIT_FUTURE_SECS)),
            ]],
            expect_ids: &["r1", "r2", "r3"],
            expect_future_skew_last: 1,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "duplicated_rows",
            page: DEFAULT_PAGE,
            shape: PageShape::Duplicated,
            next_since_secs: None,
            phases: vec![vec![("d1", Ts::Rel(-20)), ("d2", Ts::Rel(-10))]],
            expect_ids: &["d1", "d2"],
            expect_future_skew_last: 0,
            expect_refused: &[],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        Case {
            name: "malformed_timestamp_rejected_not_used",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![vec![
                ("m1", Ts::Rel(-20)),
                ("bad", Ts::Lit(MALFORMED_TS)),
                ("m3", Ts::Rel(-10)),
            ]],
            expect_ids: &["m1", "m3"],
            expect_future_skew_last: 0,
            expect_refused: &[("bad", RefusalReason::UnparseableTs)],
            expect_refused_last: 1,
            catchup_only: false,
            expect_held_last: false,
        },
        // #8789 — a row failing validation, FIRST in the window.
        Case {
            name: "invalid_row_first_does_not_halt_8789",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![
                vec![
                    ("invalid_a", Ts::Rel(-50)),
                    ("b", Ts::Rel(-40)),
                    ("c", Ts::Rel(-30)),
                ],
                vec![("later", Ts::Rel(LATER_WRITE_SECS))],
            ],
            expect_ids: &["b", "c", "later"],
            expect_future_skew_last: 0,
            expect_refused: &[("invalid_a", RefusalReason::InvalidMemory)],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        // #8788 — a forged attestation in the MIDDLE of the window.
        Case {
            name: "forged_attestation_middle_does_not_halt_8788",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![
                vec![
                    ("a", Ts::Rel(-50)),
                    ("forged_b", Ts::Rel(-40)),
                    ("c", Ts::Rel(-30)),
                ],
                vec![("later", Ts::Rel(LATER_WRITE_SECS))],
            ],
            expect_ids: &["a", "c", "later"],
            expect_future_skew_last: 0,
            expect_refused: &[("forged_b", RefusalReason::Attestation)],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
        // #8788 — an out-of-scope namespace LAST in the window, then a later
        // write the peer adds after the refusal.
        Case {
            name: "out_of_scope_row_last_does_not_halt_8788",
            page: DEFAULT_PAGE,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![
                vec![("a", Ts::Rel(-50)), ("oos_c", Ts::Rel(-30))],
                vec![("later", Ts::Rel(LATER_WRITE_SECS))],
            ],
            expect_ids: &["a", "later"],
            expect_future_skew_last: 0,
            expect_refused: &[("oos_c", RefusalReason::NamespaceScope)],
            expect_refused_last: 0,
            catchup_only: true,
            expect_held_last: false,
        },
        // #8788 / #8789 — a whole full page of refused rows: the cursor must
        // still reach the rows on the next pages.
        Case {
            name: "refused_rows_fill_a_full_page_8788",
            page: 2,
            shape: PageShape::Ascending,
            next_since_secs: None,
            phases: vec![vec![
                ("invalid_1", Ts::Rel(-50)),
                ("forged_2", Ts::Rel(-45)),
                ("r3", Ts::Rel(-40)),
                ("r4", Ts::Rel(-35)),
                ("r5", Ts::Rel(-30)),
            ]],
            expect_ids: &["r3", "r4", "r5"],
            expect_future_skew_last: 0,
            expect_refused: &[
                ("invalid_1", RefusalReason::InvalidMemory),
                ("forged_2", RefusalReason::Attestation),
            ],
            expect_refused_last: 0,
            catchup_only: false,
            expect_held_last: false,
        },
    ]
}

/// The pull loop under test.
#[derive(Clone, Copy, Debug)]
enum Loop {
    /// Serve catch-up on the daemon's sqlite connection (no SAL store).
    CatchupSqlite,
    /// Serve catch-up through the SAL store on sqlite.
    #[cfg(feature = "sal")]
    CatchupStoreSqlite,
    /// Serve catch-up through the SAL store on postgres.
    #[cfg(feature = "sal-postgres")]
    CatchupStorePostgres,
    /// The sync-daemon `sync_cycle_once` pull half.
    SyncCycle,
}

struct Receiver {
    db: ai_memory::handlers::Db,
    db_path: PathBuf,
    #[cfg(feature = "sal")]
    store: Option<Arc<dyn ai_memory::store::MemoryStore>>,
    _dir: tempfile::TempDir,
    #[cfg(feature = "sal-postgres")]
    _scratch: Option<common::pg_barrier::ScratchDb>,
}

fn open_db(path: &Path) -> ai_memory::handlers::Db {
    let conn = ai_memory::db::open(path).expect("open receiver db");
    Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )))
}

// Awaits only in the postgres cell.
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn receiver(lp: Loop) -> Option<Receiver> {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir");
    let db_path = dir.path().join("receiver-8743.db");
    let db = open_db(&db_path);
    #[cfg(feature = "sal-postgres")]
    let mut scratch = None;
    #[cfg(feature = "sal")]
    let store: Option<Arc<dyn ai_memory::store::MemoryStore>> = match lp {
        Loop::CatchupSqlite | Loop::SyncCycle => None,
        Loop::CatchupStoreSqlite => Some(Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(dir.path().join("store-8743.db"))
                .expect("open sqlite store"),
        )),
        #[cfg(feature = "sal-postgres")]
        Loop::CatchupStorePostgres => {
            let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
                eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (postgres cell)");
                return None;
            };
            let db = common::pg_barrier::ScratchDb::create(&url, "hc8743_cursor")
                .await
                .expect("create scratch database");
            let pg = ai_memory::store::postgres::PostgresStore::connect(&db.url())
                .await
                .expect("connect scratch database");
            scratch = Some(db);
            Some(Arc::new(pg))
        }
    };
    #[cfg(not(feature = "sal"))]
    let _ = lp;
    Some(Receiver {
        db,
        db_path,
        #[cfg(feature = "sal")]
        store,
        _dir: dir,
        #[cfg(feature = "sal-postgres")]
        _scratch: scratch,
    })
}

/// Test scratch lives under the worktree's `.local-runs/`, never a tmpfs.
fn scratch_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/test-8743");
    std::fs::create_dir_all(&root).expect("create scratch root");
    root
}

fn fed_config(peer_url: &str) -> FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 1, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: PEER_ID.to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: LOCAL_ID.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

async fn one_pass(lp: Loop, rx: &Receiver, peer_url: &str) -> PullOutcome {
    match lp {
        Loop::CatchupSqlite => single(
            ai_memory::federation::catchup_pass_for_tests(&fed_config(peer_url), &rx.db).await,
        ),
        #[cfg(feature = "sal")]
        Loop::CatchupStoreSqlite => single(
            ai_memory::federation::catchup_pass_with_store_for_tests(
                &fed_config(peer_url),
                &rx.db,
                rx.store.as_ref().expect("store"),
            )
            .await,
        ),
        #[cfg(feature = "sal-postgres")]
        Loop::CatchupStorePostgres => single(
            ai_memory::federation::catchup_pass_with_store_for_tests(
                &fed_config(peer_url),
                &rx.db,
                rx.store.as_ref().expect("store"),
            )
            .await,
        ),
        Loop::SyncCycle => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("client");
            ai_memory::daemon_runtime::sync_cycle_once_reporting(
                &client,
                &rx.db_path,
                LOCAL_ID,
                peer_url,
                None,
                DEFAULT_PAGE,
            )
            .await
            .expect("sync cycle")
        }
    }
}

fn single(mut outcomes: Vec<(String, PullOutcome)>) -> PullOutcome {
    assert_eq!(outcomes.len(), 1, "one configured peer, one outcome");
    outcomes.remove(0).1
}

/// Every id in the receiver's store for the corpus namespace.
async fn stored_ids(lp: Loop, rx: &Receiver) -> Vec<String> {
    #[cfg(feature = "sal")]
    if let Some(store) = rx.store.as_ref() {
        let mut ctx = ai_memory::store::CallerContext::for_agent(LOCAL_ID);
        // The corpus checks every row the catch-up wrote, whatever its scope.
        ctx.bypass_visibility = true;
        let mut filter = ai_memory::store::Filter::default();
        filter.namespace = Some(NAMESPACE.to_string());
        filter.limit = DEFAULT_PAGE;
        let _ = lp;
        return store
            .list(&ctx, &filter)
            .await
            .expect("list store")
            .into_iter()
            .map(|m| m.id)
            .collect();
    }
    let _ = lp;
    let lock = rx.db.lock().await;
    let mut stmt = lock
        .0
        .prepare("SELECT id FROM memories WHERE namespace = ?1")
        .expect("prepare");
    stmt.query_map([NAMESPACE], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// The single persisted cursor entry for this receiver, if any.
fn cursor(rx: &Receiver) -> Option<String> {
    let conn = rusqlite::Connection::open(&rx.db_path).expect("open db for cursor");
    let clock = ai_memory::db::sync_state_load(&conn, LOCAL_ID).expect("sync_state_load");
    assert!(
        clock.entries.len() <= 1,
        "one peer, at most one cursor: {clock:?}"
    );
    clock.entries.into_values().next()
}

fn parse(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

async fn run_case(lp: Loop, case: &Case) {
    if case.catchup_only && matches!(lp, Loop::SyncCycle) {
        return;
    }
    let Some(rx) = receiver(lp).await else {
        return;
    };
    let start = Utc::now();
    let state: PeerState = Arc::new(Mutex::new(PeerData {
        rows: Vec::new(),
        page: case.page,
        shape: Some(case.shape),
        next_since_override: case.next_since_secs.map(|s| render(start, Ts::Rel(s))),
    }));
    let peer_url = spawn_peer(state.clone()).await;
    let label = format!("{lp:?}/{}", case.name);
    let mut last = PullOutcome::default();
    let mut blocked: Vec<String> = Vec::new();
    let mut refused: Vec<(String, RefusalReason)> = Vec::new();
    for phase in &case.phases {
        {
            let mut data = state.lock().await;
            for (name, ts) in phase {
                let updated_at = render(start, *ts);
                let out_of_bound = match parse(&updated_at) {
                    None => false,
                    Some(dt) => dt > start + chrono::Duration::seconds(SKEW_SECS),
                };
                if out_of_bound {
                    blocked.push(updated_at.clone());
                }
                data.rows.push(PeerRow {
                    id: row_id(name),
                    name,
                    updated_at,
                });
            }
        }
        for _ in 0..PASSES_PER_PHASE {
            last = one_pass(lp, &rx, &peer_url).await;
            refused.extend(last.refused.iter().map(|r| (r.memory_id.clone(), r.reason)));
            if let Some(c) = cursor(&rx) {
                let cdt = parse(&c).unwrap_or_else(|| panic!("{label}: cursor {c} not RFC3339"));
                assert!(
                    cdt <= Utc::now(),
                    "{label}: cursor {c} passed the receiver's clock"
                );
                for b in &blocked {
                    assert!(
                        c.as_str() < b.as_str(),
                        "{label}: cursor {c} reached the out-of-bound row {b}"
                    );
                }
            }
        }
    }

    let got: Vec<String> = stored_ids(lp, &rx).await;
    let got_set: BTreeSet<String> = got.iter().cloned().collect();
    assert_eq!(
        got.len(),
        got_set.len(),
        "{label}: a row was stored twice: {got:?}"
    );
    let want: BTreeSet<String> = case.expect_ids.iter().map(|n| row_id(n)).collect();
    assert_eq!(
        got_set, want,
        "{label}: the eligible set was not pulled exactly"
    );

    assert_eq!(
        last.future_skew, case.expect_future_skew_last,
        "{label}: rows counted {OUTCOME_DEFERRED_FUTURE_SKEW} on the last pass ({last:?})"
    );
    // #8788 / #8789 — every refusal recorded with its exact reason; a row
    // with a parseable timestamp is recorded at least once and at most
    // MAX_RECORDS_PER_REFUSED_ROW times (the cursor passed
    // it), never silently dropped and never re-refused forever.
    let want_refused: BTreeSet<(String, RefusalReason)> = case
        .expect_refused
        .iter()
        .map(|(n, r)| (row_id(n), *r))
        .collect();
    let got_refused: BTreeSet<(String, RefusalReason)> = refused.iter().cloned().collect();
    assert_eq!(
        got_refused, want_refused,
        "{label}: refused rows and reasons ({refused:?})"
    );
    for (id, reason) in &got_refused {
        let times = refused.iter().filter(|(i, _)| i == id).count();
        if *reason != RefusalReason::UnparseableTs {
            assert!(
                (1..=MAX_RECORDS_PER_REFUSED_ROW).contains(&times),
                "{label}: {id} refused {times} times, want 1..={MAX_RECORDS_PER_REFUSED_ROW}"
            );
        }
    }
    assert_eq!(
        last.refused.len(),
        case.expect_refused_last,
        "{label}: rows refused on the last pass ({last:?})"
    );
    assert_eq!(last.held, case.expect_held_last, "{label}: held ({last:?})");
    let expect_complete = case.expect_future_skew_last == 0
        && case.expect_refused_last == 0
        && !case.expect_held_last;
    assert_eq!(
        last.is_complete(),
        expect_complete,
        "{label}: only a window that left nothing behind is complete ({last:?})"
    );
}

/// Receiver-side posture shared by every cell: no inbound signature or
/// enrollment requirement interferes with the cursor under test.
async fn run_loop(lp: Loop) {
    let _g = ENV_LOCK.lock().await;
    set_peer_scope();
    for case in corpus() {
        run_case(lp, &case).await;
    }
    clear_peer_scope();
}

/// The catch-up peer's inbound namespace scope: `NAMESPACE` only. The
/// default-on `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` refuses every row
/// from a peer with no configured scope (#3582).
const PEER_SCOPE_JSON: &str = r#"{"peer-8743":{"allowed_namespaces":["fed-8743"]}}"#;

fn set_peer_scope() {
    // SAFETY: every env mutation in this binary runs under `ENV_LOCK`, and no
    // other thread reads the environment while the guard is held (precedent
    // tests/g_issue_239_sync_scope.rs `reset_env`).
    unsafe {
        std::env::set_var(
            ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV,
            PEER_SCOPE_JSON,
        );
    }
}

fn clear_peer_scope() {
    // SAFETY: as `set_peer_scope`.
    unsafe {
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catchup_sqlite_cursor_never_passes_receiver_clock_8743() {
    run_loop(Loop::CatchupSqlite).await;
}

#[cfg(feature = "sal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catchup_store_sqlite_cursor_never_passes_receiver_clock_8743() {
    run_loop(Loop::CatchupStoreSqlite).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catchup_store_postgres_cursor_never_passes_receiver_clock_8743() {
    run_loop(Loop::CatchupStorePostgres).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_cycle_cursor_never_passes_receiver_clock_8743() {
    run_loop(Loop::SyncCycle).await;
}
