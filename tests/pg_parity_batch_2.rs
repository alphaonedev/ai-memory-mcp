// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 cross-backend PARITY regression harness — batch 2.
//!
//! Every test here pins ONE invariant that the sqlite SSOT already held and
//! the postgres adapter did NOT, in the #3110 defect class: a gate/check/cap
//! present on one backend and missing (or divergently implemented) on its
//! twin, producing a LEAK, WRONG RESULTS, or unbounded/unreconciled state.
//!
//! Each invariant is asserted against BOTH adapters through the SAME SAL
//! surface so the pair cannot silently drift again:
//!
//! * sqlite — always runs (`SqliteStore` over a `.local-runs/` temp DB);
//! * postgres — gated on `AI_MEMORY_TEST_POSTGRES_URL`, skipped cleanly when
//!   unset (the established skip-if-unset pattern from
//!   `tests/cov_ga2_postgres.rs`).
//!
//! Covered invariants:
//! 1. `signal_inbox` EXCLUDES acknowledged signals (#3011) — pg had no
//!    `acknowledged_at IS NULL` predicate while `signal_ack` stamps-and-keeps,
//!    so a pg inbox re-served finished work forever.
//! 2. `run_gc` REAPS expired signals (#3011) — pg persisted `expires_at` but
//!    never reaped, so ephemeral signals accumulated unbounded.
//! 3. `action_add_edge` refuses a cycle ATOMICALLY (#3008) — pg ran the cycle
//!    probe and the INSERT as two independent pool statements, so concurrent
//!    opposing arcs could co-close a cycle and wedge the frontier.
//! 4. `search_with_source_uri` honours `tags_any` / `agent_id` — pg silently
//!    dropped both filters BEFORE `LIMIT`, so the page was wrong, not just wide.
//! 5. `kg_query` is ROW-CAPPED — pg returned every simple path up to depth 5
//!    with no `LIMIT` while sqlite clamps to 200/1000.
//! 6. `list_by_namespace_prefix` saturates a huge `limit` instead of relying on
//!    a `usize as i64` cast (PERF-07).

// The sqlite half drives `SqliteStore`, which lives behind the `sal` feature,
// so the WHOLE suite is `sal`-gated (the postgres half adds its own
// `sal-postgres` guards on top).
#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use std::path::PathBuf;

use ai_memory::models::{
    ConfidenceSource, EdgeType, LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation,
    Signal, SignalType, Tier,
};
use ai_memory::store::{CallerContext, MemoryStore};
// `Filter` is only used by the postgres-only `search_with_source_uri` case.
#[cfg(feature = "sal-postgres")]
use ai_memory::store::Filter;

// ─────────────────────────────────────────────────────────────────────
// fixtures
// ─────────────────────────────────────────────────────────────────────

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("pg-parity-batch-2");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn sqlite_store(dir: &tempfile::TempDir) -> ai_memory::store::sqlite::SqliteStore {
    ai_memory::store::sqlite::SqliteStore::open(dir.path().join("parity.db"))
        .expect("open SqliteStore")
}

fn signal(ns: &str, to: Option<&str>, subject: &str, expires_at: Option<i64>) -> Signal {
    Signal {
        id: uid("sig"),
        namespace: ns.to_string(),
        from_agent: "ai:sender".to_string(),
        to_agent: to.map(str::to_string),
        subject: subject.to_string(),
        body: serde_json::json!({"k": "v"}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: Some(uid("corr")),
        reference_ids: serde_json::json!([]),
        created_at: chrono::Utc::now().timestamp(),
        expires_at,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

fn action(ns: &str, id: &str) -> ai_memory::models::Action {
    let now = chrono::Utc::now().timestamp();
    ai_memory::models::Action {
        id: id.to_string(),
        namespace: ns.to_string(),
        kind: "parity-batch-2".to_string(),
        state: ai_memory::models::ActionState::Pending,
        title: id.to_string(),
        payload: serde_json::json!({}),
        priority: 5,
        agent_id: Some("ai:parity".to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: now,
        updated_at: now,
    }
}

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "parity-batch-2".to_string(),
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
        lifecycle_state: LifecycleState::Open,
    }
}

fn chain_link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: Some(chrono::Utc::now().to_rfc3339()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

#[cfg(feature = "sal-postgres")]
async fn live_pg() -> Option<ai_memory::store::postgres::PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match ai_memory::store::postgres::PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: postgres connect failed: {e}");
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// (1) #3011 — signal_inbox EXCLUDES acknowledged signals, on BOTH backends.
// ─────────────────────────────────────────────────────────────────────

/// Shared assertion body, driven against whichever adapter is handed in.
async fn verify_inbox_excludes_acked(store: &dyn MemoryStore, backend: &str) {
    let ctx = CallerContext::for_agent("ai:parity-inbox");
    let ns = uid("parity-inbox");
    let to = uid("ai:recipient");
    let sig = signal(&ns, Some(&to), "please-do-work", None);
    let sig_id = sig.id.clone();
    store
        .signal_send(&ctx, &sig, None)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] signal_send: {e}"));

    let before = store
        .signal_inbox(&ctx, &ns, Some(&to), 50)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] signal_inbox before ack: {e}"));
    assert!(
        before.iter().any(|s| s.id == sig_id),
        "[{backend}] an UNACKED signal must be in the inbox; got {before:?}"
    );

    let acked = store
        .signal_ack(&ctx, &sig_id, chrono::Utc::now().timestamp())
        .await
        .unwrap_or_else(|e| panic!("[{backend}] signal_ack: {e}"));
    assert!(acked, "[{backend}] first ack must stamp the row");

    let after = store
        .signal_inbox(&ctx, &ns, Some(&to), 50)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] signal_inbox after ack: {e}"));
    assert!(
        !after.iter().any(|s| s.id == sig_id),
        "[{backend}] #3011: an ACKED signal must NOT be re-served by the inbox — \
         an inbox that keeps returning acked signals re-serves the same work forever; \
         got {after:?}"
    );

    // The acked signal is still READABLE by id and by thread on both backends —
    // the exclusion is an inbox-dispatch rule, never data loss.
    let got = store
        .signal_get(&ctx, &sig_id)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] signal_get: {e}"));
    assert!(
        got.is_some_and(|s| s.acknowledged_at.is_some()),
        "[{backend}] the acked signal must still be readable by id with acknowledged_at set"
    );
}

#[tokio::test]
async fn sqlite_signal_inbox_excludes_acked_3011() {
    let dir = fresh_dir("inbox-acked");
    let store = sqlite_store(&dir);
    verify_inbox_excludes_acked(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_signal_inbox_excludes_acked_3011() {
    let Some(store) = live_pg().await else { return };
    verify_inbox_excludes_acked(&store, "postgres").await;
}

// ─────────────────────────────────────────────────────────────────────
// (2) #3011 — run_gc REAPS expired signals, on BOTH backends.
// ─────────────────────────────────────────────────────────────────────

async fn verify_gc_reaps_expired_signals(store: &dyn MemoryStore, backend: &str) {
    let ctx = CallerContext::for_agent("ai:parity-gc");
    let ns = uid("parity-gc");
    let to = uid("ai:recipient");
    let now = chrono::Utc::now().timestamp();

    // One EXPIRED ephemeral + one DURABLE (no expires_at) signal.
    let expired = signal(&ns, Some(&to), "ephemeral", Some(now - 3600));
    let durable = signal(&ns, Some(&to), "durable", None);
    let expired_id = expired.id.clone();
    let durable_id = durable.id.clone();
    store
        .signal_send(&ctx, &expired, None)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] send expired: {e}"));
    store
        .signal_send(&ctx, &durable, None)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] send durable: {e}"));

    store
        .run_gc(false)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] run_gc: {e}"));

    assert!(
        store
            .signal_get(&ctx, &expired_id)
            .await
            .unwrap_or_else(|e| panic!("[{backend}] get expired: {e}"))
            .is_none(),
        "[{backend}] #3011: gc must reap a caller-declared-ephemeral signal whose \
         expires_at has passed — otherwise the documented TTL contract is false and \
         signals accumulate unbounded"
    );
    assert!(
        store
            .signal_get(&ctx, &durable_id)
            .await
            .unwrap_or_else(|e| panic!("[{backend}] get durable: {e}"))
            .is_some(),
        "[{backend}] a signal with NO expires_at is a durable coordination record and \
         must SURVIVE gc — the reap is intended TTL expiry, never unintentional loss"
    );
}

#[tokio::test]
async fn sqlite_gc_reaps_expired_signals_3011() {
    let dir = fresh_dir("gc-signals");
    let store = sqlite_store(&dir);
    verify_gc_reaps_expired_signals(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_gc_reaps_expired_signals_3011() {
    let Some(store) = live_pg().await else { return };
    verify_gc_reaps_expired_signals(&store, "postgres").await;
}

// ─────────────────────────────────────────────────────────────────────
// (3) #3008 — action_add_edge refuses a cycle ATOMICALLY.
// ─────────────────────────────────────────────────────────────────────

async fn verify_add_edge_refuses_self_and_cycle(store: &dyn MemoryStore, backend: &str) {
    let ctx = CallerContext::for_agent("ai:parity-edge");
    let ns = uid("parity-edge");
    let a = uid("act-a");
    let b = uid("act-b");
    let now = chrono::Utc::now().timestamp();
    for id in [&a, &b] {
        store
            .action_create(&ctx, &action(&ns, id))
            .await
            .unwrap_or_else(|e| panic!("[{backend}] action_create: {e}"));
    }

    assert!(
        store
            .action_add_edge(&ctx, &a, &a, EdgeType::Requires, now)
            .await
            .is_err(),
        "[{backend}] a self-edge must be REFUSED (it wedges the frontier)"
    );
    store
        .action_add_edge(&ctx, &a, &b, EdgeType::Requires, now)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] first ordering edge must be accepted: {e}"));
    assert!(
        store
            .action_add_edge(&ctx, &b, &a, EdgeType::Requires, now)
            .await
            .is_err(),
        "[{backend}] the opposing arc closes an ordering cycle and must be REFUSED"
    );
    // Sibling edges impose no ordering, so the reverse sibling arc is fine.
    store
        .action_add_edge(&ctx, &b, &a, EdgeType::Sibling, now)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] a sibling edge imposes no ordering: {e}"));
}

#[tokio::test]
async fn sqlite_action_add_edge_refuses_self_and_cycle_3008() {
    let dir = fresh_dir("edge-gate");
    let store = sqlite_store(&dir);
    verify_add_edge_refuses_self_and_cycle(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_action_add_edge_refuses_self_and_cycle_3008() {
    let Some(store) = live_pg().await else { return };
    verify_add_edge_refuses_self_and_cycle(&store, "postgres").await;
}

/// The RACE this batch closes: `A -> B` and `B -> A` submitted CONCURRENTLY.
/// Pre-fix the postgres adapter ran the cycle probe and the INSERT as two
/// independent pool statements, so under READ COMMITTED both probes could see a
/// cycle-free graph and both inserts commit — a 2-cycle in the ordering DAG,
/// which wedges `action_frontier` permanently (a CORRUPTED coordination graph,
/// not merely a wrong answer). The advisory-lock + single-tx fix serializes
/// gate+write exactly as the sqlite connection mutex already did.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_action_add_edge_concurrent_opposing_arcs_cannot_both_land_3008() {
    let Some(store) = live_pg().await else { return };
    let store = std::sync::Arc::new(store);
    let ctx = CallerContext::for_agent("ai:parity-edge-race");
    let now = chrono::Utc::now().timestamp();

    // Repeat the race so a single lucky serialization cannot mask a regression.
    for round in 0..12 {
        let ns = uid("parity-edge-race");
        let a = uid("race-a");
        let b = uid("race-b");
        for id in [&a, &b] {
            store
                .action_create(&ctx, &action(&ns, id))
                .await
                .expect("action_create");
        }
        let (s1, s2) = (store.clone(), store.clone());
        let (c1, c2) = (ctx.clone(), ctx.clone());
        let (a1, b1) = (a.clone(), b.clone());
        let (a2, b2) = (a.clone(), b.clone());
        let f1 = tokio::spawn(async move {
            s1.action_add_edge(&c1, &a1, &b1, EdgeType::Requires, now)
                .await
        });
        let f2 = tokio::spawn(async move {
            s2.action_add_edge(&c2, &b2, &a2, EdgeType::Requires, now)
                .await
        });
        let (r1, r2) = (f1.await.expect("join 1"), f2.await.expect("join 2"));

        let landed = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
        assert_eq!(
            landed, 1,
            "round {round}: EXACTLY ONE orientation may survive two concurrent opposing \
             ordering-edge adds (#3008). Both landing means the cycle gate was raced and \
             the ordering DAG is corrupted; neither landing means a live-lock. \
             r1={r1:?} r2={r2:?}"
        );

        // Belt-and-suspenders: read the edges back and prove only one direction
        // is actually stored, so a future refactor cannot make the API refuse
        // while still writing the row.
        let edges = store.action_edges_for(&ctx, &a).await.expect("edges_for");
        let ordering: Vec<_> = edges
            .iter()
            .filter(|e| e.edge_type != EdgeType::Sibling)
            .collect();
        assert_eq!(
            ordering.len(),
            1,
            "round {round}: exactly one ordering edge must be PERSISTED between the pair; \
             got {ordering:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// (4) search_with_source_uri honours tags_any / agent_id.
// ─────────────────────────────────────────────────────────────────────

/// Both adapters must NARROW on `tags_any` and `agent_id`. Pre-fix the pg
/// inherent method bound neither, so the filter was dropped BEFORE `LIMIT` and
/// the caller got a page of rows that do not carry the requested tag/owner —
/// wrong results, not merely extra ones.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_search_with_source_uri_honours_tags_any_and_agent_id() {
    let Some(store) = live_pg().await else { return };
    let ctx = CallerContext::for_agent("ai:parity-uri");
    let ns = uid("parity-uri");
    let token = format!("prtytok{}", uuid::Uuid::new_v4().simple());
    let uri = format!("doc:parity/{}", uuid::Uuid::new_v4().simple());

    // Two rows on the SAME source_uri matching the SAME FTS token, differing
    // ONLY in tags + metadata.agent_id.
    let keep_id = uid("uri-keep");
    let mut keep = mem(&keep_id, &ns, &uid("keep-title"), &format!("{token} keep"));
    keep.tags = vec!["parity-keep".to_string()];
    keep.metadata = serde_json::json!({"agent_id": "ai:owner-keep"});
    keep.source_uri = Some(uri.clone());

    let drop_id = uid("uri-drop");
    let mut dropped = mem(&drop_id, &ns, &uid("drop-title"), &format!("{token} drop"));
    dropped.tags = vec!["parity-drop".to_string()];
    dropped.metadata = serde_json::json!({"agent_id": "ai:owner-drop"});
    dropped.source_uri = Some(uri.clone());

    for m in [&keep, &dropped] {
        store.store(&ctx, m).await.expect("store fixture");
    }

    let base = Filter {
        namespace: Some(ns.clone()),
        limit: 50,
        ..Default::default()
    };

    // No narrowing: BOTH rows surface (proves the fixture is sound).
    let all = store
        .search_with_source_uri(&token, &base, Some(&uri))
        .await
        .expect("search unfiltered");
    assert_eq!(
        all.len(),
        2,
        "fixture sanity: both rows share the source_uri and the FTS token; got {all:?}"
    );

    // tags_any narrows.
    let by_tag = store
        .search_with_source_uri(
            &token,
            &Filter {
                tags_any: vec!["parity-keep".to_string()],
                ..base.clone()
            },
            Some(&uri),
        )
        .await
        .expect("search by tag");
    assert_eq!(
        by_tag.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![keep_id.clone()],
        "`tags_any` MUST narrow the reciprocal-provenance search exactly as the sqlite \
         twin and the pg `search` trait method do — pre-fix it was silently ignored"
    );

    // agent_id narrows.
    let by_agent = store
        .search_with_source_uri(
            &token,
            &Filter {
                agent_id: Some("ai:owner-keep".to_string()),
                ..base.clone()
            },
            Some(&uri),
        )
        .await
        .expect("search by agent");
    assert_eq!(
        by_agent.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![keep_id.clone()],
        "`agent_id` MUST narrow the reciprocal-provenance search — pre-fix it was \
         silently ignored"
    );

    // A tag nobody carries returns NOTHING (fail-closed, not fail-open).
    let none = store
        .search_with_source_uri(
            &token,
            &Filter {
                tags_any: vec![uid("no-such-tag")],
                ..base.clone()
            },
            Some(&uri),
        )
        .await
        .expect("search by absent tag");
    assert!(
        none.is_empty(),
        "an unmatched `tags_any` must return NO rows, never the unfiltered page; got {none:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// (5) kg_query is ROW-CAPPED on postgres, matching the sqlite SSOT.
// ─────────────────────────────────────────────────────────────────────

/// The sqlite SAL adapter always passes `limit = None`, so `db::kg_query`
/// clamps to `KG_QUERY_DEFAULT_LIMIT` (200). Postgres had NO `LIMIT` at all on
/// either traversal branch, so an identical call returned a different (and
/// unbounded) result set. Seeds a fan-out wider than the cap at depth 1 and
/// asserts the exact sqlite page size on both backends.
const KG_QUERY_SAL_DEFAULT_CAP: usize = 200;

async fn verify_kg_query_row_cap(store: &dyn MemoryStore, backend: &str) {
    let ctx = CallerContext::for_agent("ai:parity-kg");
    let ns = uid("parity-kg");
    let root = uid("kg-root");
    store
        .store(&ctx, &mem(&root, &ns, &uid("kg-root-title"), "root"))
        .await
        .unwrap_or_else(|e| panic!("[{backend}] store root: {e}"));

    let fanout = KG_QUERY_SAL_DEFAULT_CAP + 25;
    for i in 0..fanout {
        let leaf = uid(&format!("kg-leaf-{i}"));
        store
            .store(&ctx, &mem(&leaf, &ns, &uid("kg-leaf-title"), "leaf"))
            .await
            .unwrap_or_else(|e| panic!("[{backend}] store leaf {i}: {e}"));
        store
            .link(&ctx, &chain_link(&root, &leaf))
            .await
            .unwrap_or_else(|e| panic!("[{backend}] link leaf {i}: {e}"));
    }

    let rows = store
        .kg_query(&root, 1, false)
        .await
        .unwrap_or_else(|e| panic!("[{backend}] kg_query: {e}"));
    assert_eq!(
        rows.len(),
        KG_QUERY_SAL_DEFAULT_CAP,
        "[{backend}] kg_query MUST cap at the sqlite SSOT default page size ({}) — an \
         uncapped traversal materializes every simple path up to depth 5 (combinatorial \
         in a dense graph) and returns a different result set than its twin. \
         DEGRADE (fewer rows), never unbounded.",
        KG_QUERY_SAL_DEFAULT_CAP
    );
}

#[tokio::test]
async fn sqlite_kg_query_is_row_capped() {
    let dir = fresh_dir("kg-cap");
    let store = sqlite_store(&dir);
    verify_kg_query_row_cap(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_kg_query_is_row_capped() {
    let Some(store) = live_pg().await else { return };
    verify_kg_query_row_cap(&store, "postgres").await;
}

// ─────────────────────────────────────────────────────────────────────
// (6) PERF-07 — a saturating `limit` must not ride a `usize as i64` cast.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
async fn pg_list_by_namespace_prefix_saturates_a_huge_limit() {
    let Some(store) = live_pg().await else { return };
    let ctx = CallerContext::for_agent("ai:parity-prefix");
    let ns_root = uid("parity-prefix");
    let child = format!("{ns_root}/child");
    store
        .store(&ctx, &mem(&uid("pfx"), &child, &uid("pfx-title"), "row"))
        .await
        .expect("store prefixed row");

    let rows = store
        .list_by_namespace_prefix(&ctx, &ns_root, usize::MAX)
        .await
        .expect("a usize::MAX limit must saturate to the SAL page cap, never wrap or error");
    assert!(
        rows.iter().any(|m| m.namespace == child),
        "the prefix scan must still return the child-namespace row; got {} rows",
        rows.len()
    );
    assert!(
        rows.len() <= 10_000,
        "the page must stay bounded by STORE_LIST_MAX_LIMIT_SAL; got {}",
        rows.len()
    );
}

// ─────────────────────────────────────────────────────────────────────
// (7) AGE fail-open closure — the unprojection MARKER lane, end to end.
//
// This is the fail-open closure itself, so it gets live-tier evidence rather
// than only the `from_str` unforgeability unit assertion.
//
// In production the recording path fires when an AGE runtime failure prevents
// the post-hard-delete detach. A test cannot induce that on a SHARED live tier
// without revoking the role's AGE access (which would break every concurrent
// test on it), so these tests reproduce the exact resulting STATE — relational
// row deleted, ghost `:Memory` node still attached — by deleting the row with
// raw SQL, then drive the REAL `record_unreconciled_unprojections` through the
// `#[doc(hidden)]` seam and the REAL drainer arm.
// ─────────────────────────────────────────────────────────────────────

/// Count AGE `:Memory` vertices carrying `id`. The id is test-minted
/// (`prefix-<uuid>`), so embedding it in the cypher body is injection-safe;
/// this keeps the helper free of an `agtype` encode/decode shim.
#[cfg(feature = "sal-postgres")]
async fn age_vertex_count(pool: &sqlx::PgPool, id: &str) -> usize {
    let mut tx = pool.begin().await.expect("begin age tx");
    // A non-superuser role may be refused LOAD; shared_preload_libraries then
    // provides the library. Tolerate it exactly as the adapter does.
    let _ = sqlx::query("LOAD 'age'").execute(&mut *tx).await;
    sqlx::query("SET LOCAL search_path = ag_catalog, \"$user\", public")
        .execute(&mut *tx)
        .await
        .expect("set search_path");
    let sql = format!(
        "SELECT v FROM cypher('memory_graph', $$ MATCH (m:Memory {{id: '{id}'}}) RETURN m $$) \
         AS (v agtype)"
    );
    let rows = sqlx::query(&sql)
        .persistent(false)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("cypher vertex count failed: {e}"));
    tx.commit().await.expect("commit age probe tx");
    rows.len()
}

/// Pending (unreconciled) outbox rows carrying the unprojection marker for `id`.
#[cfg(feature = "sal-postgres")]
async fn pending_marker_rows(pool: &sqlx::PgPool, id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM kg_projection_outbox \
          WHERE source_id = $1 AND relation = '__ai_memory_unproject__' \
            AND projected_at IS NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("count pending marker rows");
    n
}

#[cfg(feature = "sal-postgres")]
async fn reconciled_marker_rows(pool: &sqlx::PgPool, id: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM kg_projection_outbox \
          WHERE source_id = $1 AND relation = '__ai_memory_unproject__' \
            AND projected_at IS NOT NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("count reconciled marker rows");
    n
}

/// Seed `root -> leaf` so AGE holds a projected `:Memory` vertex for `root`,
/// then hard-delete `root`'s RELATIONAL row with raw SQL — reproducing the
/// ghost state a swallowed unprojection leaves behind. Returns `root`'s id.
#[cfg(feature = "sal-postgres")]
async fn seed_ghost_age_node(
    store: &ai_memory::store::postgres::PostgresStore,
    pool: &sqlx::PgPool,
    ns: &str,
) -> String {
    let ctx = CallerContext::for_agent("ai:parity-unproject");
    let root = uid("ghost-root");
    let leaf = uid("ghost-leaf");
    store
        .store(&ctx, &mem(&root, ns, &uid("ghost-root-title"), "root"))
        .await
        .expect("store root");
    store
        .store(&ctx, &mem(&leaf, ns, &uid("ghost-leaf-title"), "leaf"))
        .await
        .expect("store leaf");
    store
        .link(&ctx, &chain_link(&root, &leaf))
        .await
        .expect("link root->leaf (projects into AGE)");
    assert_eq!(
        age_vertex_count(pool, &root).await,
        1,
        "fixture sanity: the link write must project a :Memory vertex for the root"
    );

    // Raw-SQL delete: the relational row goes, the AGE projection stays — the
    // exact divergence a swallowed unprojection used to leave PERMANENTLY.
    sqlx::query("DELETE FROM memories WHERE id = $1")
        .bind(&root)
        .execute(pool)
        .await
        .expect("raw relational delete");
    assert_eq!(
        age_vertex_count(pool, &root).await,
        1,
        "fixture sanity: the ghost :Memory vertex must SURVIVE the relational delete"
    );
    root
}

/// The fail-open closure end to end: RECORD an unreconcilable unprojection,
/// prove it is durable and deduped, then prove the drainer actually detaches
/// the ghost vertex and stamps the row reconciled.
///
/// Pre-fix every failure arm swallowed the error, so this drift was invisible
/// and PERMANENT in sync mode: `kg_query` / `kg_timeline` would serve an edge to
/// a memory that no longer exists once AGE recovered, with no retry, no
/// reconcile and no operator-visible signal.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL + a live AGE backend"]
async fn pg_age_unprojection_marker_records_dedupes_and_reconciles() {
    let Some(store) = live_pg().await else { return };
    if store.kg_backend() != ai_memory::store::KgBackend::Age {
        eprintln!("skip: postgres backend is not AGE (no graph projection to reconcile)");
        return;
    }
    let pool = store.pool().clone();
    let ns = uid("parity-unproject");
    let root = seed_ghost_age_node(&store, &pool, &ns).await;

    // (1) RECORD — the real production recording path.
    store
        .record_unreconciled_unprojections_for_test(&[root.as_str()])
        .await;
    assert_eq!(
        pending_marker_rows(&pool, &root).await,
        1,
        "a failed unprojection MUST leave exactly one durable, pending marker row — \
         a log line that scrolls away is not a reconcilable record"
    );

    // (2) DEDUPE — a second failure for the same id while one is still pending
    // is a no-op, not a duplicate row (the `WHERE NOT EXISTS` arm).
    store
        .record_unreconciled_unprojections_for_test(&[root.as_str()])
        .await;
    assert_eq!(
        pending_marker_rows(&pool, &root).await,
        1,
        "re-recording an id that already has a PENDING marker must be idempotent — \
         a retry loop must not pile up outbox rows"
    );

    // (3) RECONCILE — the drainer's marker arm detaches the ghost and stamps it.
    store
        .drain_kg_projection_outbox(256)
        .await
        .expect("drain outbox");
    assert_eq!(
        pending_marker_rows(&pool, &root).await,
        0,
        "the drainer must consume the pending marker"
    );
    assert_eq!(
        reconciled_marker_rows(&pool, &root).await,
        1,
        "the consumed marker must be STAMPED reconciled, not deleted — the record of \
         what was repaired survives for the operator"
    );
    assert_eq!(
        age_vertex_count(&pool, &root).await,
        0,
        "the ghost :Memory vertex MUST be gone: this is the whole point of the marker — \
         kg_query must stop serving an edge to a memory the relational store deleted"
    );

    // Cleanup: leave the shared tier as we found it.
    let _ = sqlx::query("DELETE FROM kg_projection_outbox WHERE source_id = $1")
        .bind(&root)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(&pool)
        .await;
}

/// The SAFETY property that makes the marker sound: the drainer must NEVER
/// detach a vertex whose relational row EXISTS again.
///
/// A marker says "no `memories` row with this id should have a graph node". If
/// the id was re-created after the delete, acting on the stale marker would
/// destroy a LIVE projection — turning a repair tool into a data-loss tool. The
/// mirror-image liveness guard drops the marker instead.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL + a live AGE backend"]
async fn pg_age_unprojection_marker_never_detaches_a_recreated_id() {
    let Some(store) = live_pg().await else { return };
    if store.kg_backend() != ai_memory::store::KgBackend::Age {
        eprintln!("skip: postgres backend is not AGE");
        return;
    }
    let pool = store.pool().clone();
    let ctx = CallerContext::for_agent("ai:parity-unproject");
    let ns = uid("parity-unproject-recreate");
    let root = seed_ghost_age_node(&store, &pool, &ns).await;

    store
        .record_unreconciled_unprojections_for_test(&[root.as_str()])
        .await;
    assert_eq!(pending_marker_rows(&pool, &root).await, 1);

    // The id comes BACK before the drainer runs.
    store
        .store(&ctx, &mem(&root, &ns, &uid("recreated-title"), "recreated"))
        .await
        .expect("re-create the memory under the same id");

    store
        .drain_kg_projection_outbox(256)
        .await
        .expect("drain outbox");

    assert_eq!(
        reconciled_marker_rows(&pool, &root).await,
        1,
        "the stale marker must be CONSUMED (dropped), not left to fire later"
    );
    assert_eq!(
        age_vertex_count(&pool, &root).await,
        1,
        "the LIVE projection of the re-created id MUST survive — a reconciler that \
         detaches a vertex whose relational row exists again is a data-loss tool, not \
         a repair tool"
    );

    let _ = sqlx::query("DELETE FROM kg_projection_outbox WHERE source_id = $1")
        .bind(&root)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(&pool)
        .await;
}

/// QUARANTINE semantics for the marker lane: a row at the attempt ceiling is
/// EXCLUDED from the take-query, so a poison marker cannot head-of-line-block
/// the drain — a healthy marker enqueued behind it still reconciles in the SAME
/// pass. Driven by seeding `attempt_count = MAX_AGE_PROJECTION_ATTEMPTS`
/// directly (exhausting 100 real attempts against a live tier is not cheap).
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL + a live AGE backend"]
async fn pg_age_quarantined_marker_does_not_block_the_drain() {
    let Some(store) = live_pg().await else { return };
    if store.kg_backend() != ai_memory::store::KgBackend::Age {
        eprintln!("skip: postgres backend is not AGE");
        return;
    }
    let pool = store.pool().clone();
    let ns = uid("parity-unproject-quarantine");

    // Poison marker: at the ceiling, so the take-query must skip it.
    let poison = uid("quarantined-ghost");
    sqlx::query(
        "INSERT INTO kg_projection_outbox (source_id, target_id, relation, attempt_count) \
         VALUES ($1, $1, '__ai_memory_unproject__', $2)",
    )
    .bind(&poison)
    .bind(ai_memory::store::postgres::PostgresStore::MAX_AGE_PROJECTION_ATTEMPTS)
    .execute(&pool)
    .await
    .expect("seed quarantined marker");

    // Healthy marker enqueued BEHIND it, with a real ghost vertex to detach.
    let healthy = seed_ghost_age_node(&store, &pool, &ns).await;
    store
        .record_unreconciled_unprojections_for_test(&[healthy.as_str()])
        .await;

    store
        .drain_kg_projection_outbox(256)
        .await
        .expect("drain outbox");

    assert_eq!(
        pending_marker_rows(&pool, &poison).await,
        1,
        "a marker at the attempt ceiling stays PENDING (quarantined) — it is never \
         silently stamped reconciled, so the unrepaired drift remains visible in the \
         pending-depth gauge and to the operator"
    );
    assert_eq!(
        pending_marker_rows(&pool, &healthy).await,
        0,
        "the quarantined row must NOT head-of-line-block the drain: the healthy marker \
         behind it reconciles in the same pass"
    );
    assert_eq!(
        age_vertex_count(&pool, &healthy).await,
        0,
        "the healthy marker's ghost vertex is detached despite the poison row"
    );

    for id in [&poison, &healthy] {
        let _ = sqlx::query("DELETE FROM kg_projection_outbox WHERE source_id = $1")
            .bind(id)
            .execute(&pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1")
        .bind(&ns)
        .execute(&pool)
        .await;
}
