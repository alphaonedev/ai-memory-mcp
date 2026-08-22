// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2446 regression test — GDPR Article 17: an MCP / CLI erasure
//! MUST propagate to federated replicas.
//!
//! ## Why this test exists
//!
//! `sync::broadcast_delete_quorum` had exactly ONE production caller: the
//! HTTP `DELETE /api/v1/memories/{id}` handler. Every other erasure funnel
//! — MCP `memory_delete`, MCP `memory_forget`, CLI `delete`, CLI `forget`
//! — was purely local. An agent calling `memory_forget` over MCP deleted
//! locally and got `success`, while every federated replica kept the row,
//! re-served it, and could later LWW-resurrect it. Meanwhile the STORE
//! path fanned out. That is a GDPR Article 17 erasure failure AND a
//! permanent replica divergence.
//!
//! Anti-entropy catch-up cannot cover this: it propagates WRITES by
//! pulling rows, and an erased row is exactly the thing it can no longer
//! see. Only an explicit tombstone push can carry an erasure.
//!
//! ## Coverage
//!
//! - `mcp_memory_delete_queues_an_erasure_outbox_row_2446` /
//!   `mcp_memory_forget_queues_erasure_outbox_rows_2446` — drive the REAL
//!   `ai-memory mcp` stdio binary (`CARGO_BIN_EXE_ai-memory`, the pm-v3.3
//!   fresh-subprocess discipline) and assert the erasure left a pending
//!   sentinel row. At the parent commit these leave NOTHING.
//! - `cli_delete_queues_an_erasure_outbox_row_2446` /
//!   `cli_forget_queues_erasure_outbox_rows_2446` — same for the two CLI
//!   funnels, driven in-process.
//! - `drain_expands_sentinel_and_delivers_deletion_to_peer_2446` — one
//!   `replay_once` tick expands the sentinel into a per-peer row and the
//!   next delivers `deletions:[id]` to a mock peer, clearing it.
//! - `peer_down_leaves_the_expanded_row_pending_2446` — a DOWN peer leaves
//!   the row pending for the next tick (the erasure is never lost).
//! - `unconfigured_deployment_erasure_succeeds_and_queues_nothing_2446` —
//!   the bound: no drainability marker ⇒ zero rows, and the erasure still
//!   succeeds.
//! - `restore_after_delete_supersedes_the_queued_erasure_2446` — the
//!   data-integrity guard: a queued erasure whose id is LIVE again locally
//!   is NOT fanned out (it would destroy a replica of a row this node
//!   currently holds).
//! - `sentinel_and_real_peer_row_coexist_for_the_same_memory_2446` — the
//!   partial-unique index is keyed on the PAIR, so the sentinel cannot
//!   collide with a real per-peer row for the same memory.

#![cfg(feature = "sal")]
#![allow(clippy::needless_update)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ai_memory::federation::push_dlq::{SqliteDlqSink, replay_once};
use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;

const NS: &str = "erasure-2446";

// The two reserved tokens are mirrored here as LITERALS rather than
// imported from `ai_memory::federation::erasure_outbox`, deliberately:
// this suite must COMPILE at the parent commit `03bbd556` so its
// assertions fail BEHAVIOURALLY (zero rows) instead of failing to build
// (R-203 — a compile error proves an API is absent, not that a behaviour
// is). Their values are pinned against the module consts by the unit
// tests in `src/federation/erasure_outbox.rs`.
const SENTINEL_PEER_ID: &str = "__ai_memory_all_peers__";
const MARKER_SUFFIX: &str = ".federation-outbox";

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

fn scratch_dir(prefix: &str) -> tempfile::TempDir {
    // Project HARD RULE: no agent-created files under /tmp.
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(concat!(env!("CARGO_MANIFEST_DIR"), "/.local-runs"))
        .expect("create .local-runs tempdir")
}

fn sample_memory(id: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "v1.0.0 #2446 erasure-replication probe payload".to_string(),
        tags: vec!["erasure".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Open a fresh sqlite DB, seed `ids`, and (unless `drainable` is false)
/// stamp the #2446 drainability marker the way a federated sqlite-backed
/// `serve` boot does.
fn seed_db(path: &std::path::Path, ids: &[&str], drainable: bool) {
    let conn = ai_memory::storage::open(path).expect("open sqlite");
    for (i, id) in ids.iter().enumerate() {
        ai_memory::db::insert(&conn, &sample_memory(id, &format!("probe-{i}"))).expect("seed");
    }
    drop(conn);
    // Stamp the drainability marker exactly the way a federated,
    // sqlite-backed `serve` boot does — by writing the sidecar directly,
    // so this suite compiles at the parent commit (see the const block
    // above). The marker is deliberately NOT a row in
    // `federation_push_dlq`: all three indexes on that table are partial
    // `WHERE replayed_at IS NULL`, so an in-table marker would be
    // invisible to every one of them and each probe would be a full scan.
    let marker = marker_path(path);
    let _ = std::fs::remove_file(&marker);
    if drainable {
        std::fs::write(&marker, r#"{"peer_count":1}"#).expect("stamp drainability marker");
    }
}

/// The sidecar drainability-marker path for a database file.
fn marker_path(db: &std::path::Path) -> std::path::PathBuf {
    let mut name = db.file_name().expect("db file name").to_os_string();
    name.push(MARKER_SUFFIX);
    db.with_file_name(name)
}

/// Every PENDING erasure-outbox sentinel row: `(memory_id, payload_json)`.
fn pending_sentinels(path: &std::path::Path) -> Vec<(String, serde_json::Value)> {
    let conn = ai_memory::storage::open(path).expect("reopen sqlite");
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, payload_json FROM federation_push_dlq \
             WHERE peer_id = ?1 AND replayed_at IS NULL ORDER BY memory_id",
        )
        .expect("prepare sentinel query");
    let rows = stmt
        .query_map(rusqlite::params![SENTINEL_PEER_ID], |r| {
            let id: String = r.get(0)?;
            let payload: String = r.get(1)?;
            Ok((id, payload))
        })
        .expect("query sentinels")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect sentinels");
    rows.into_iter()
        .map(|(id, payload)| {
            (
                id,
                serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

/// Every PENDING row that is NOT a sentinel: `(memory_id, peer_id, payload)`.
fn pending_peer_rows(path: &std::path::Path) -> Vec<(String, String, serde_json::Value)> {
    let conn = ai_memory::storage::open(path).expect("reopen sqlite");
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, peer_id, payload_json FROM federation_push_dlq \
             WHERE peer_id <> ?1 AND replayed_at IS NULL ORDER BY memory_id, peer_id",
        )
        .expect("prepare peer-row query");
    // The drainability marker rides in this table with `replayed_at`
    // pre-set, so it can never appear here — nothing is filtered out and
    // the count assertions speak for themselves.
    stmt.query_map(rusqlite::params![SENTINEL_PEER_ID], |r| {
        let id: String = r.get(0)?;
        let peer: String = r.get(1)?;
        let payload: String = r.get(2)?;
        Ok((id, peer, payload))
    })
    .expect("query peer rows")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect peer rows")
    .into_iter()
    .map(|(id, peer, payload)| {
        (
            id,
            peer,
            serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
        )
    })
    .collect()
}

fn memory_exists(path: &std::path::Path, id: &str) -> bool {
    let conn = ai_memory::storage::open(path).expect("reopen sqlite");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, i64>(0),
    )
    .expect("count memories")
        > 0
}

// ---------------------------------------------------------------------
// MCP stdio driver (pm-v3.3 fresh-subprocess discipline)
// ---------------------------------------------------------------------

/// Drive the REAL `ai-memory mcp` stdio binary through one `tools/call`
/// and return the JSON-RPC response for it.
fn mcp_tool_call(db_path: &std::path::Path, tool: &str, arguments: &serde_json::Value) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("mcp")
        .arg("--profile")
        .arg("full")
        .arg("--db")
        .arg(db_path)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_DB", db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ai-memory mcp");
    {
        let stdin = child.stdin.as_mut().expect("mcp stdin");
        let init = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "erasure-2446", "version": "1"}
            }
        });
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        });
        writeln!(stdin, "{init}").expect("write initialize");
        writeln!(stdin, "{call}").expect("write tools/call");
        stdin.flush().expect("flush mcp stdin");
    }
    // Close stdin so the stdio loop terminates after answering.
    drop(child.stdin.take());
    let stdout = child.stdout.take().expect("mcp stdout");
    let mut last = String::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read mcp stdout line");
        if line.contains("\"id\":2") {
            last = line;
        }
    }
    let _ = child.wait();
    assert!(
        !last.is_empty(),
        "#2446: the MCP stdio server produced no response for {tool}"
    );
    last
}

// ---------------------------------------------------------------------
// Mock federation peer (shape borrowed from tests/federation_dlq_replay.rs)
// ---------------------------------------------------------------------

#[derive(Clone, Default)]
struct PeerState {
    fail_mode: Arc<AtomicBool>,
    hit_count: Arc<AtomicUsize>,
    last_body: Arc<Mutex<Option<serde_json::Value>>>,
}

async fn push_handler(
    State(state): State<PeerState>,
    axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    state.hit_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().await = Some(body);
    if state.fail_mode.load(Ordering::Relaxed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "peer down"})),
        );
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"applied": 1, "noop": 0, "skipped": 0})),
    )
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

fn build_cfg(
    peer_url: &str,
    sink: Arc<dyn ai_memory::federation::FederationDlqSink>,
) -> FederationConfig {
    let _ =
        ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION.set(Box::new(|_action| Ok(())));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    FederationConfig {
        policy: QuorumPolicy::new(2, 2, Duration::from_secs(2), Duration::from_secs(30)).unwrap(),
        peers: vec![PeerEndpoint {
            id: "peer-0".to_string(),
            sync_push_url: format!("{peer_url}/api/v1/sync/push"),
        }],
        client,
        sender_agent_id: "ai:erasure-2446".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: Some(sink),
    }
}

// ---------------------------------------------------------------------
// (1) MCP funnels
// ---------------------------------------------------------------------

/// #2446 — MCP `memory_delete` must queue the erasure for federated
/// fan-out. At the parent commit it queues NOTHING and every replica keeps
/// the row forever.
#[test]
fn mcp_memory_delete_queues_an_erasure_outbox_row_2446() {
    let tmp = scratch_dir("erasure-2446-mcp-delete-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["mcp-del-1"], true);

    let resp = mcp_tool_call(
        &db,
        "memory_delete",
        &serde_json::json!({"id": "mcp-del-1"}),
    );
    assert!(
        !resp.contains("\"error\""),
        "#2446: memory_delete must succeed; got {resp}"
    );
    assert!(
        !memory_exists(&db, "mcp-del-1"),
        "#2446: the local erasure must still happen"
    );

    let sentinels = pending_sentinels(&db);
    assert_eq!(
        sentinels.len(),
        1,
        "#2446: MCP memory_delete must leave exactly ONE pending erasure-outbox \
         row (pre-fix it left NOTHING and the erasure never reached any peer); got {sentinels:?}"
    );
    assert_eq!(sentinels[0].0, "mcp-del-1");
    assert_eq!(
        sentinels[0].1["deletions"],
        serde_json::json!(["mcp-del-1"]),
        "#2446: the queued payload must be a real federated deletion body"
    );
}

/// #2446 — MCP `memory_forget` must queue EVERY erased id, not just the
/// first `DRY_RUN_PREVIEW_CAP` of them.
#[test]
fn mcp_memory_forget_queues_erasure_outbox_rows_2446() {
    let tmp = scratch_dir("erasure-2446-mcp-forget-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["mcp-fgt-1", "mcp-fgt-2", "mcp-fgt-3"], true);

    let resp = mcp_tool_call(&db, "memory_forget", &serde_json::json!({"namespace": NS}));
    assert!(
        !resp.contains("\"error\""),
        "#2446: memory_forget must succeed; got {resp}"
    );

    let mut ids: Vec<String> = pending_sentinels(&db)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "mcp-fgt-1".to_string(),
            "mcp-fgt-2".to_string(),
            "mcp-fgt-3".to_string()
        ],
        "#2446: MCP memory_forget must queue an erasure-outbox row for EVERY \
         forgotten id (pre-fix it queued NOTHING)"
    );
}

// ---------------------------------------------------------------------
// (2) CLI funnels
// ---------------------------------------------------------------------

/// #2446 — CLI `ai-memory delete` must queue the erasure.
#[test]
fn cli_delete_queues_an_erasure_outbox_row_2446() {
    let tmp = scratch_dir("erasure-2446-cli-delete-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["cli-del-1"], true);

    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
    ai_memory::cli::crud::cmd_delete(
        &db,
        &ai_memory::cli::crud::DeleteArgs {
            id: "cli-del-1".to_string(),
            capability: None,
            capability_file: None,
        },
        true,
        None,
        &mut cli_out,
    )
    .expect("#2446: a local CLI delete must never start failing");

    let sentinels = pending_sentinels(&db);
    assert_eq!(
        sentinels.len(),
        1,
        "#2446: CLI delete must leave exactly ONE pending erasure-outbox row \
         (pre-fix it left NOTHING); got {sentinels:?}"
    );
    assert_eq!(sentinels[0].0, "cli-del-1");
}

/// #2446 — CLI `ai-memory forget` must queue every erased id.
#[test]
fn cli_forget_queues_erasure_outbox_rows_2446() {
    let tmp = scratch_dir("erasure-2446-cli-forget-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["cli-fgt-1", "cli-fgt-2"], true);

    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
    ai_memory::cli::forget::cmd_forget(
        &db,
        &ai_memory::cli::forget::ForgetArgs {
            namespace: Some(NS.to_string()),
            pattern: None,
            tier: None,
            confirm_global: false,
            show_receipt: None,
            verify_receipt: None,
        },
        true,
        &mut cli_out,
    )
    .expect("#2446: a local CLI forget must never start failing");

    let mut ids: Vec<String> = pending_sentinels(&db)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec!["cli-fgt-1".to_string(), "cli-fgt-2".to_string()],
        "#2446: CLI forget must queue an erasure-outbox row for EVERY forgotten \
         id (pre-fix it queued NOTHING)"
    );
}

// ---------------------------------------------------------------------
// (3) The bound — an unconfigured deployment
// ---------------------------------------------------------------------

/// #2446 — the accumulation bound: with NO drainability marker (the
/// overwhelmingly common single-node MCP deployment), an erasure writes
/// ZERO outbox rows AND still succeeds. Nothing can accumulate forever.
#[test]
fn unconfigured_deployment_erasure_succeeds_and_queues_nothing_2446() {
    let tmp = scratch_dir("erasure-2446-unconfigured-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["solo-1"], false);

    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
    ai_memory::cli::crud::cmd_delete(
        &db,
        &ai_memory::cli::crud::DeleteArgs {
            id: "solo-1".to_string(),
            capability: None,
            capability_file: None,
        },
        true,
        None,
        &mut cli_out,
    )
    .expect("#2446: erasure must NOT start failing on an unfederated deployment");

    assert!(!memory_exists(&db, "solo-1"), "the local erasure happened");
    assert!(
        pending_sentinels(&db).is_empty(),
        "#2446: an unfederated deployment must accumulate ZERO outbox rows"
    );
    assert!(
        pending_peer_rows(&db).is_empty(),
        "#2446: and no per-peer rows either"
    );

    // Deliberately NOT a bare "nothing is queued" assertion — that is
    // vacuously green at the parent commit, where nothing is EVER queued.
    // The paired DRAINABLE database proves the marker is the actual
    // discriminator, so this test can only pass when the bound is real
    // AND the mechanism works.
    let drainable = tmp.path().join("drainable.db");
    seed_db(&drainable, &["paired-1"], true);
    let mut out2 = Vec::new();
    let mut err2 = Vec::new();
    let mut cli_out2 = ai_memory::cli::io_writer::CliOutput::from_std(&mut out2, &mut err2);
    ai_memory::cli::crud::cmd_delete(
        &drainable,
        &ai_memory::cli::crud::DeleteArgs {
            id: "paired-1".to_string(),
            capability: None,
            capability_file: None,
        },
        true,
        None,
        &mut cli_out2,
    )
    .expect("erasure on the drainable twin");
    assert_eq!(
        pending_sentinels(&drainable).len(),
        1,
        "#2446: the SAME erasure on a DRAINABLE database must queue exactly one \
         row — the drainability marker is the discriminator, not a blanket \
         never-queue"
    );
}

// ---------------------------------------------------------------------
// (4) Drain
// ---------------------------------------------------------------------

/// #2446 — the daemon's existing push-DLQ replay worker expands the
/// sentinel into a per-peer row and then delivers `deletions:[id]` to the
/// peer, clearing the row. This is the half that actually closes the
/// GDPR gap: without it the queued erasure never reaches a replica.
#[tokio::test]
async fn drain_expands_sentinel_and_delivers_deletion_to_peer_2446() {
    let tmp = scratch_dir("erasure-2446-drain-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["drain-1"], true);

    // Erase locally through the CLI funnel (the real production path).
    {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
        ai_memory::cli::crud::cmd_delete(
            &db,
            &ai_memory::cli::crud::DeleteArgs {
                id: "drain-1".to_string(),
                capability: None,
                capability_file: None,
            },
            true,
            None,
            &mut cli_out,
        )
        .expect("local delete");
    }
    assert_eq!(pending_sentinels(&db).len(), 1, "queued before the drain");

    let peer = PeerState::default();
    let peer_url = spawn_mock_peer(peer.clone()).await;

    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle: ai_memory::handlers::Db = Arc::new(Mutex::new((
        ai_memory::storage::open(&db).expect("sink conn"),
        db.clone(),
        ttl,
        true,
    )));
    let sink = Arc::new(SqliteDlqSink::new(handle).await.expect("sqlite dlq sink"));
    let cfg = build_cfg(&peer_url, sink.clone());

    // Tick 1: expand the sentinel into a per-peer row.
    replay_once(&cfg, sink.as_ref()).await;
    assert!(
        pending_sentinels(&db).is_empty(),
        "#2446: the sentinel must be cleared once expanded"
    );
    let peer_rows = pending_peer_rows(&db);
    assert_eq!(
        peer_rows.len(),
        1,
        "#2446: expansion must mint exactly one per-peer delete row; got {peer_rows:?}"
    );
    assert_eq!(peer_rows[0].1, "peer-0");
    assert_eq!(peer_rows[0].2["deletions"], serde_json::json!(["drain-1"]));

    // Tick 2: deliver it.
    replay_once(&cfg, sink.as_ref()).await;
    assert_eq!(
        peer.hit_count.load(Ordering::Relaxed),
        1,
        "#2446: the peer must receive exactly one deletion POST"
    );
    let body = peer.last_body.lock().await.clone().expect("peer body");
    assert_eq!(
        body["deletions"],
        serde_json::json!(["drain-1"]),
        "#2446: the delivered body must be a federated deletion for the erased id"
    );
    assert!(
        pending_peer_rows(&db).is_empty(),
        "#2446: an acked deletion must clear the row"
    );
}

/// #2446 — a peer that is DOWN leaves the expanded row PENDING for the
/// next tick. An erasure is never dropped because a peer was unreachable.
#[tokio::test]
async fn peer_down_leaves_the_expanded_row_pending_2446() {
    let tmp = scratch_dir("erasure-2446-peerdown-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["down-1"], true);
    {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
        ai_memory::cli::crud::cmd_delete(
            &db,
            &ai_memory::cli::crud::DeleteArgs {
                id: "down-1".to_string(),
                capability: None,
                capability_file: None,
            },
            true,
            None,
            &mut cli_out,
        )
        .expect("local delete");
    }

    let peer = PeerState {
        fail_mode: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    };
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle: ai_memory::handlers::Db = Arc::new(Mutex::new((
        ai_memory::storage::open(&db).expect("sink conn"),
        db.clone(),
        ttl,
        true,
    )));
    let sink = Arc::new(SqliteDlqSink::new(handle).await.expect("sqlite dlq sink"));
    let cfg = build_cfg(&peer_url, sink.clone());

    replay_once(&cfg, sink.as_ref()).await; // expand
    replay_once(&cfg, sink.as_ref()).await; // attempt against a DOWN peer

    let peer_rows = pending_peer_rows(&db);
    assert_eq!(
        peer_rows.len(),
        1,
        "#2446: a DOWN peer must leave the erasure PENDING for the next tick, \
         never drop it; got {peer_rows:?}"
    );
    assert_eq!(peer_rows[0].0, "down-1");
}

// ---------------------------------------------------------------------
// (5) Data-integrity guards
// ---------------------------------------------------------------------

/// #2446 — the restore-after-delete race. A queued erasure that replays
/// AFTER the id was legitimately restored locally would DESTROY the
/// peer's copy of a row this node currently holds — unintentional data
/// loss, the highest-order harm under the repo's North Star. The
/// expansion re-checks liveness and refuses to fan out.
#[tokio::test]
async fn restore_after_delete_supersedes_the_queued_erasure_2446() {
    let tmp = scratch_dir("erasure-2446-restore-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["restore-1"], true);
    {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
        ai_memory::cli::crud::cmd_delete(
            &db,
            &ai_memory::cli::crud::DeleteArgs {
                id: "restore-1".to_string(),
                capability: None,
                capability_file: None,
            },
            true,
            None,
            &mut cli_out,
        )
        .expect("local delete");
    }
    assert_eq!(pending_sentinels(&db).len(), 1);

    // The id is LIVE again (an archive restore reuses the SAME id —
    // `db::restore_archived` restores by the archived row's id verbatim).
    {
        let conn = ai_memory::storage::open(&db).expect("reopen");
        ai_memory::db::insert(&conn, &sample_memory("restore-1", "restored")).expect("restore");
    }

    let peer = PeerState::default();
    let peer_url = spawn_mock_peer(peer.clone()).await;
    let ttl = ai_memory::config::ResolvedTtl::default();
    let handle: ai_memory::handlers::Db = Arc::new(Mutex::new((
        ai_memory::storage::open(&db).expect("sink conn"),
        db.clone(),
        ttl,
        true,
    )));
    let sink = Arc::new(SqliteDlqSink::new(handle).await.expect("sqlite dlq sink"));
    let cfg = build_cfg(&peer_url, sink.clone());

    replay_once(&cfg, sink.as_ref()).await;
    replay_once(&cfg, sink.as_ref()).await;

    assert!(
        pending_sentinels(&db).is_empty(),
        "#2446: the superseded sentinel must be cleared, not left to retry forever"
    );
    assert!(
        pending_peer_rows(&db).is_empty(),
        "#2446: a superseded erasure must mint NO per-peer delete row"
    );
    assert_eq!(
        peer.hit_count.load(Ordering::Relaxed),
        0,
        "#2446: a restored row must NEVER be deleted on the peer — that would \
         destroy a replica of a row this node currently holds"
    );
    assert!(
        memory_exists(&db, "restore-1"),
        "the restored row is still live locally"
    );
}

/// #2446 mechanism check — the reserved sentinel `peer_id` round-trips
/// through the v48 partial-unique index WITHOUT colliding with a real
/// per-peer row for the same `memory_id` (the index is keyed on the PAIR).
#[test]
fn sentinel_and_real_peer_row_coexist_for_the_same_memory_2446() {
    let tmp = scratch_dir("erasure-2446-coexist-");
    let db = tmp.path().join("m.db");
    seed_db(&db, &["coexist-1"], true);
    {
        // A real per-peer row for the SAME memory (the shape PR #2662's
        // delete-lane DLQ landing pass writes).
        let conn = ai_memory::storage::open(&db).expect("reopen");
        conn.execute(
            "INSERT INTO federation_push_dlq \
                 (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
             VALUES ('coexist-1', 'peer-0', '{}', 1, 'deadline_exceeded', \
                     '2026-07-30T00:00:00Z')",
            [],
        )
        .expect("seed real peer row");
    }

    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut cli_out = ai_memory::cli::io_writer::CliOutput::from_std(&mut out, &mut err);
    ai_memory::cli::crud::cmd_delete(
        &db,
        &ai_memory::cli::crud::DeleteArgs {
            id: "coexist-1".to_string(),
            capability: None,
            capability_file: None,
        },
        true,
        None,
        &mut cli_out,
    )
    .expect("local delete");

    assert_eq!(
        pending_sentinels(&db).len(),
        1,
        "#2446: the sentinel row must land despite a real per-peer row for the \
         same memory_id"
    );
    assert_eq!(
        pending_peer_rows(&db).len(),
        1,
        "#2446: and the pre-existing per-peer row must be untouched"
    );
}

// ---------------------------------------------------------------------
// (6) Postgres drain-side parity (live PG, opt-in)
// ---------------------------------------------------------------------

/// #2446 — the DRAIN side must be backend-blind. Nothing writes an
/// erasure sentinel into the POSTGRES `federation_push_dlq` today (MCP
/// stdio is sqlite-only by construction, CLAUDE.md #1675/n24, and the CLI
/// erasure verbs open a local rusqlite connection), so this arm is not
/// production-reachable — which is exactly why it needs a test: an
/// invalid SQL string on an unreachable path ships undetected until the
/// day it becomes reachable.
///
/// Runs only against a live PG named by `AI_MEMORY_TEST_POSTGRES_URL`;
/// leaves ZERO residue (every row it writes carries the `pg-2446-` id
/// prefix and is deleted at the end).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires a live postgres (AI_MEMORY_TEST_POSTGRES_URL)"]
async fn pg_expand_erasure_sentinel_parity_2446() {
    use ai_memory::federation::SentinelExpansion;
    use ai_memory::federation::push_dlq::{FederationDlqSink, PostgresDlqSink};

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("pg parity skipped: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect live PG");
    let pool = store.pool().clone();
    let mem_id = format!("pg-2446-{}", chrono::Utc::now().timestamp_millis());

    // Clean slate, then queue a sentinel exactly as a postgres-side writer
    // would.
    sqlx::query("DELETE FROM federation_push_dlq WHERE memory_id LIKE 'pg-2446-%'")
        .execute(&pool)
        .await
        .expect("pre-clean");
    let row_id: (i64,) = sqlx::query_as(
        "INSERT INTO federation_push_dlq \
             (memory_id, peer_id, payload_json, attempt_count, last_error) \
         VALUES ($1, $2, $3::jsonb, 1, 'queued') RETURNING id",
    )
    .bind(&mem_id)
    .bind(SENTINEL_PEER_ID)
    .bind(serde_json::json!({"memories": [], "deletions": [mem_id.clone()]}).to_string())
    .fetch_one(&pool)
    .await
    .expect("queue pg sentinel");

    let sink = PostgresDlqSink::new(std::sync::Arc::new(store.clone()));
    let body = serde_json::json!({
        "sender_agent_id": "ai:erasure-2446",
        "memories": [],
        "deletions": [mem_id.clone()],
        "dry_run": false,
    });
    let outcome = sink
        .expand_erasure_sentinel(
            row_id.0,
            1,
            &mem_id,
            &["peer-0".to_string(), "peer-1".to_string()],
            &body,
            "expanded",
        )
        .await
        .expect("pg expansion must succeed");
    assert_eq!(
        outcome,
        SentinelExpansion::Expanded(2),
        "#2446: the postgres arm must expand the sentinel into one row per peer"
    );

    let pending: Vec<(String,)> = sqlx::query_as(
        "SELECT peer_id FROM federation_push_dlq \
         WHERE memory_id = $1 AND replayed_at IS NULL ORDER BY peer_id",
    )
    .bind(&mem_id)
    .fetch_all(&pool)
    .await
    .expect("read back");
    assert_eq!(
        pending.iter().map(|r| r.0.clone()).collect::<Vec<_>>(),
        vec!["peer-0".to_string(), "peer-1".to_string()],
        "#2446: the sentinel must be cleared and exactly the per-peer rows left"
    );

    // ZERO residue.
    sqlx::query("DELETE FROM federation_push_dlq WHERE memory_id LIKE 'pg-2446-%'")
        .execute(&pool)
        .await
        .expect("post-clean");
    let residue: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM federation_push_dlq WHERE memory_id LIKE 'pg-2446-%'")
            .fetch_one(&pool)
            .await
            .expect("residue check");
    assert_eq!(
        residue.0, 0,
        "#2446: the pg parity test must leave no residue"
    );
}
