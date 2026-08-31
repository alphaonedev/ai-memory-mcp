// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3322 (#3266 MVG piece 1/3) — `memory_swarm_rewind`: ONE atomic,
//! resumable operation that intercepts and unwinds a memory cascade without
//! data loss, and reports the lineage token/cost.
//!
//! Proves the rock-solid data-integrity bar (North Star):
//!
//! * **Atomic** — a successful rewind lands the root taint, every descendant
//!   taint, the routine freezes, and the signed audit event TOGETHER.
//! * **Resumable / idempotent** — a re-run of an already-rewound root is a
//!   no-op that appends NO duplicate `swarm.rewind` audit row.
//! * **Reversible** — every stamped row records its pre-taint
//!   `lifecycle_state` so a future restore is exact; the durable memory TEXT is
//!   never touched.
//! * **Fail-closed / non-destructive** — a missing root, or a root already in a
//!   stronger system-only state, is refused; a stronger descendant state is
//!   never downgraded.
//! * **Cross-backend parity** — the `contaminated` state the rewind produces is
//!   hidden by the SHARED `lifecycle_visible_clause` (used verbatim by SQLite
//!   AND Postgres), and the `swarm.rewind` event kind is a backend-agnostic
//!   dotted slug appended through the one signing funnel.
//! * **Cost report** — the #3323 lineage rollup for the rewound subtree is
//!   returned alongside the effect counts.
//! * **Manageable** — `dry_run` projects the effect with zero writes.

use ai_memory::db;
use ai_memory::models::{LifecycleState, Memory, MemoryKind, Tier, lifecycle_visible_clause};
use ai_memory::signed_events::{self, event_types};
use rusqlite::Connection;
use serde_json::json;

fn fresh_conn() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "team/alpha".to_string(),
        title: title.to_string(),
        content: format!("body {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:tester"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// Wire `child` --`derives_from`--> `parent` so `child` is a DESCENDANT of
/// `parent` in the downstream provenance walk.
fn derives_from(conn: &Connection, child: &str, parent: &str) {
    db::create_link(conn, child, parent, "derives_from").expect("derives_from edge");
}

fn raw_state(conn: &Connection, id: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT lifecycle_state FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .expect("query")
}

fn raw_metadata(conn: &Connection, id: &str) -> serde_json::Value {
    let s: String = conn
        .query_row("SELECT metadata FROM memories WHERE id = ?1", [id], |r| {
            r.get::<_, String>(0)
        })
        .expect("query metadata");
    serde_json::from_str(&s).expect("metadata is JSON")
}

fn rewind_event_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [event_types::SWARM_REWIND],
        |r| r.get(0),
    )
    .expect("count rewind events")
}

/// Seed a `lineage`-scope token-cost counter row so the #3323 rollup has
/// something to report.
fn seed_lineage_cost(conn: &Connection, id: &str, written: i64, recalled: i64) {
    // `db::insert` already accrues a lineage counter row for a freshly-stored
    // memory, so UPSERT to pin the exact figures this test asserts on.
    conn.execute(
        "INSERT INTO token_cost_counters \
            (scope_kind, scope_key, tokens_written, tokens_recalled, write_events, recall_events, updated_at) \
         VALUES ('lineage', ?1, ?2, ?3, 1, 1, ?4) \
         ON CONFLICT(scope_kind, scope_key) DO UPDATE SET \
            tokens_written = excluded.tokens_written, \
            tokens_recalled = excluded.tokens_recalled",
        rusqlite::params![id, written, recalled, chrono::Utc::now().to_rfc3339()],
    )
    .expect("seed cost counter");
}

/// A chain: root <- child <- grandchild (`derives_from`), plus an off-DAG row.
fn seed_cascade(conn: &Connection) -> (Memory, Memory, Memory, Memory) {
    let root = make_mem("root");
    let child = make_mem("child");
    let grandchild = make_mem("grandchild");
    let unrelated = make_mem("unrelated");
    for m in [&root, &child, &grandchild, &unrelated] {
        db::insert(conn, m).expect("insert");
    }
    derives_from(conn, &child.id, &root.id);
    derives_from(conn, &grandchild.id, &child.id);
    (root, child, grandchild, unrelated)
}

// ---------------------------------------------------------------------------
// Atomic: all effects land together, cost is reported.
// ---------------------------------------------------------------------------

#[test]
fn swarm_rewind_contaminates_root_and_cascade_and_reports_cost() {
    let conn = fresh_conn();
    let (root, child, grandchild, unrelated) = seed_cascade(&conn);
    seed_lineage_cost(&conn, &root.id, 1000, 200);

    let report = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect("swarm_rewind");

    // Effect counts.
    assert!(
        report.root_contaminated,
        "root is invalidated (contaminated)"
    );
    assert_eq!(report.descendants_stamped, 2, "child + grandchild tainted");
    assert_eq!(report.descendants_total, 2);
    assert!(!report.already_rewound);
    assert!(!report.dry_run);
    assert!(
        report.signed_event_id.is_some(),
        "a signed event was emitted"
    );

    // Root + descendants are contaminated (hidden); off-DAG row untouched.
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("contaminated"));
    assert_eq!(raw_state(&conn, &child.id).as_deref(), Some("contaminated"));
    assert_eq!(
        raw_state(&conn, &grandchild.id).as_deref(),
        Some("contaminated")
    );
    assert_eq!(raw_state(&conn, &unrelated.id).as_deref(), Some("open"));

    // The root carries the idempotency marker; descendants record `via`.
    let root_meta = raw_metadata(&conn, &root.id);
    assert_eq!(
        root_meta["contamination"]["rewind"].as_bool(),
        Some(true),
        "root carries the rewind idempotency marker"
    );
    assert_eq!(
        root_meta["contamination"]["prior_lifecycle_state"].as_str(),
        Some("open"),
        "root pre-taint state recorded (reversibility)"
    );
    let child_meta = raw_metadata(&conn, &child.id);
    assert_eq!(
        child_meta["contamination"]["prior_lifecycle_state"].as_str(),
        Some("open")
    );
    assert_eq!(
        child_meta["contamination"]["via"].as_str(),
        Some("swarm_rewind")
    );
    // Pre-existing metadata preserved (additive, never destructive).
    assert_eq!(child_meta["agent_id"].as_str(), Some("ai:tester"));

    // End-to-end: contaminated rows are hidden from the ordinary get lane.
    assert!(db::get(&conn, &root.id).expect("get").is_none());
    assert!(db::get(&conn, &child.id).expect("get").is_none());
    assert!(db::get(&conn, &unrelated.id).expect("get").is_some());

    // Exactly ONE signed rewind event landed atomically with the taint.
    assert_eq!(rewind_event_count(&conn), 1);

    // Cost report (#3323) rolls up the WHOLE rewound subtree (root +
    // descendants), so it is at least the seeded root figures, and the derived
    // fields are self-consistent.
    assert!(
        report.cost.tokens_written >= 1000,
        "subtree rollup includes the seeded root write cost: {}",
        report.cost.tokens_written
    );
    assert!(report.cost.tokens_recalled >= 200);
    assert_eq!(
        report.cost.tokens_total,
        report.cost.tokens_written + report.cost.tokens_recalled
    );
    assert!(report.cost.micro_usd > 0, "non-zero cost for the subtree");
    assert!(
        report.cost.usd.starts_with('$'),
        "usd rendered: {}",
        report.cost.usd
    );
    assert_eq!(report.cost.scope_key, root.id);
}

// ---------------------------------------------------------------------------
// Resumable / idempotent: re-run is a no-op, no duplicate audit row.
// ---------------------------------------------------------------------------

#[test]
fn swarm_rewind_is_idempotent_no_duplicate_audit() {
    let conn = fresh_conn();
    let (root, child, _gc, _u) = seed_cascade(&conn);

    let first = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect("first rewind");
    assert!(first.root_contaminated);
    assert_eq!(first.descendants_stamped, 2);
    assert_eq!(rewind_event_count(&conn), 1);
    let child_meta_before = raw_metadata(&conn, &child.id);

    // Re-run: no-op. `already_rewound`, zero new stamps, NO new audit row.
    let second = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect("second rewind");
    assert!(second.already_rewound, "re-run must be a no-op");
    assert!(!second.root_contaminated);
    assert_eq!(second.descendants_stamped, 0);
    assert!(second.signed_event_id.is_none(), "no duplicate audit row");
    assert_eq!(
        rewind_event_count(&conn),
        1,
        "the append-only chain did not grow on the idempotent re-run"
    );
    // The recorded prior state is not clobbered.
    assert_eq!(
        raw_metadata(&conn, &child.id),
        child_meta_before,
        "re-run leaves the descendant metadata byte-identical"
    );
}

// ---------------------------------------------------------------------------
// #3327 (Sec-F4) — the already-Contaminated root branch's in-place marker CAS
// must FAIL CLOSED when it matches no row, mirroring the non-contaminated
// sibling's `Vanished` handling.
// ---------------------------------------------------------------------------

/// A root that is ALREADY `contaminated` (e.g. tainted earlier as some other
/// root's #3324 descendant) but NOT yet rewound routes `swarm_rewind` into the
/// in-place marker-UPGRADE branch. Its CAS is `WHERE id = root AND
/// lifecycle_state = 'contaminated'`. If a concurrent writer moves the root OFF
/// `contaminated` between the pre-tx autocommit read and the IMMEDIATE-tx CAS,
/// the CAS matches 0 rows. Before #3327 that silently no-op'd YET still froze
/// routines and committed the signed `swarm.rewind` event, while the
/// `rewind:true` idempotency marker never persisted — so a re-run appended a
/// DUPLICATE audit event. The fix checks the row count and rolls back.
///
/// The race is made deterministic with a TEMP TRIGGER: the moment step-1a's
/// cascade contamination stamps the child, the trigger flips the
/// already-contaminated root OFF `contaminated`, so step-1b's root CAS matches
/// no row. The op must return an error and commit NO `swarm.rewind` event.
#[test]
fn swarm_rewind_already_contaminated_root_vanished_mid_op_fails_closed_3327() {
    let conn = fresh_conn();
    let (root, child, _gc, _u) = seed_cascade(&conn);

    // Put the root into the already-Contaminated (but NOT yet rewound) state so
    // swarm_rewind takes the in-place marker-UPGRADE branch (1b).
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'contaminated' WHERE id = ?1",
        [&root.id],
    )
    .expect("pre-contaminate root");

    // The concurrent-writer race, made deterministic: when step-1a contaminates
    // the child, flip the root OFF `contaminated` so the step-1b CAS
    // (`WHERE lifecycle_state = 'contaminated'`) matches 0 rows. The flip runs
    // inside swarm_rewind's own transaction, so a correct fail-closed rollback
    // undoes it too.
    conn.execute(
        &format!(
            "CREATE TEMP TRIGGER flip_root_off_contaminated \
               AFTER UPDATE OF lifecycle_state ON memories \
               WHEN NEW.id = '{child}' AND NEW.lifecycle_state = 'contaminated' \
             BEGIN \
               UPDATE memories SET lifecycle_state = 'open' WHERE id = '{root}'; \
             END",
            child = child.id,
            root = root.id,
        ),
        [],
    )
    .expect("install the concurrent-writer race trigger");

    assert_eq!(
        rewind_event_count(&conn),
        0,
        "precondition: no rewind event yet"
    );

    let err = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect_err("a root that vanished off `contaminated` mid-op must FAIL CLOSED");
    let msg = err.to_string();
    assert!(
        msg.contains("changed during rewind"),
        "#3327 Sec-F4: the CAS-0 rollback must report the root changed during \
         rewind; got: {msg}"
    );

    // FAIL CLOSED: the whole transaction rolled back, so NO `swarm.rewind` audit
    // event was committed — a re-run therefore cannot double-count the chain.
    assert_eq!(
        rewind_event_count(&conn),
        0,
        "#3327 Sec-F4: a rolled-back rewind must commit NO signed event (else a \
         re-run appends a DUPLICATE audit row)"
    );
    // The rollback also undid the trigger's flip and the child's taint.
    assert_eq!(
        raw_state(&conn, &root.id).as_deref(),
        Some("contaminated"),
        "the root's pre-op state is restored by the rollback"
    );
    assert_eq!(
        raw_state(&conn, &child.id).as_deref(),
        Some("open"),
        "the child's cascade taint is rolled back with the failed rewind"
    );
}

// ---------------------------------------------------------------------------
// dry_run: zero writes, projected effect + cost.
// ---------------------------------------------------------------------------

#[test]
fn swarm_rewind_dry_run_writes_nothing() {
    let conn = fresh_conn();
    let (root, child, grandchild, _u) = seed_cascade(&conn);
    seed_lineage_cost(&conn, &root.id, 500, 0);

    let report = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        true,
    )
    .expect("dry run");

    assert!(report.dry_run);
    assert_eq!(report.descendants_stamped, 2, "projected taint count");
    assert!(report.root_contaminated, "projected root taint");
    assert!(report.signed_event_id.is_none(), "dry run emits no event");
    assert!(
        report.cost.tokens_written >= 500,
        "cost still reported on a dry run: {}",
        report.cost.tokens_written
    );

    // Nothing was written.
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("open"));
    assert_eq!(raw_state(&conn, &child.id).as_deref(), Some("open"));
    assert_eq!(raw_state(&conn, &grandchild.id).as_deref(), Some("open"));
    assert_eq!(rewind_event_count(&conn), 0);
}

// ---------------------------------------------------------------------------
// Fail-closed.
// ---------------------------------------------------------------------------

#[test]
fn swarm_rewind_missing_root_is_refused() {
    let conn = fresh_conn();
    let err = db::swarm_rewind(
        &conn,
        "nope-id",
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect_err("missing root must fail");
    assert!(err.to_string().contains("not found"), "got: {err}");
}

#[test]
fn swarm_rewind_refuses_already_contained_tombstoned_root() {
    let conn = fresh_conn();
    let root = make_mem("root");
    db::insert(&conn, &root).expect("insert");
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        [&root.id],
    )
    .expect("tombstone");

    let err = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect_err("tombstoned root refused");
    assert!(err.to_string().contains("system-only"), "got: {err}");
    // Untouched.
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("tombstoned"));
    assert_eq!(rewind_event_count(&conn), 0);
}

#[test]
fn swarm_rewind_never_downgrades_stronger_descendant_state() {
    let conn = fresh_conn();
    let (root, child, grandchild, _u) = seed_cascade(&conn);
    // A descendant already tombstoned must be left as-is (fail-closed).
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        [&child.id],
    )
    .expect("tombstone child");

    let report = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect("rewind");
    assert_eq!(report.descendants_skipped_system_only, 1);
    assert_eq!(raw_state(&conn, &child.id).as_deref(), Some("tombstoned"));
    // grandchild is still reachable downstream through the tombstoned child
    // (lineage traversal does not filter lifecycle_state) and is tainted.
    assert_eq!(
        raw_state(&conn, &grandchild.id).as_deref(),
        Some("contaminated")
    );
}

// ---------------------------------------------------------------------------
// Freeze affected routines.
// ---------------------------------------------------------------------------

#[test]
fn swarm_rewind_freezes_operator_supplied_routines() {
    let conn = fresh_conn();
    let (root, _c, _gc, _u) = seed_cascade(&conn);
    let routine_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO routines (id, namespace, name, template, parameters, state, created_by, created_at) \
         VALUES (?1, 'team/alpha', 'nightly', '{}', '[]', 'draft', 'ai:tester', 0)",
        [&routine_id],
    )
    .expect("insert draft routine");

    let report = db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        std::slice::from_ref(&routine_id),
        false,
    )
    .expect("rewind");

    assert_eq!(report.routines_requested, 1);
    assert_eq!(report.routines_frozen, 1);
    let state: String = conn
        .query_row(
            "SELECT state FROM routines WHERE id = ?1",
            [&routine_id],
            |r| r.get(0),
        )
        .expect("routine state");
    assert_eq!(state, "frozen", "the affected routine was frozen");
}

// ---------------------------------------------------------------------------
// Cross-backend parity + audit-chain integrity.
// ---------------------------------------------------------------------------

#[test]
fn contaminated_state_is_hidden_by_shared_clause_both_backends() {
    // The rewind produces `Contaminated`, which the SHARED clause (bound-free,
    // used verbatim by SQLite AND Postgres) must exclude — the parity guarantee.
    let clause = lifecycle_visible_clause("m");
    assert!(
        !clause.contains("'contaminated'"),
        "shared clause must hide contaminated on both backends: {clause}"
    );
    assert!(!LifecycleState::Contaminated.is_recall_visible());
}

#[test]
fn swarm_rewind_event_kind_is_gate_clean_and_chain_verifies() {
    // Dotted slug keeps the value clear of the underscore-joined L3 lexical gate.
    assert_eq!(event_types::SWARM_REWIND, "swarm.rewind");
    assert!(
        event_types::SWARM_REWIND.contains('.'),
        "event kind must be a dotted slug"
    );

    let conn = fresh_conn();
    let (root, _c, _gc, _u) = seed_cascade(&conn);
    db::swarm_rewind(
        &conn,
        &root.id,
        db::LINEAGE_MAX_DEPTH,
        "ai:operator",
        "memory",
        &[],
        false,
    )
    .expect("rewind");

    // The append-only signed_events chain still verifies after the rewind
    // event was appended inside the rewind transaction (no daemon key in the
    // test harness → the row is honestly `unsigned`; chain integrity holds).
    let report = signed_events::verify_audit_trail(&conn, None, None).expect("verify");
    assert!(
        report.chain_intact,
        "audit hash-chain must stay intact after the rewind append"
    );
}

// ---------------------------------------------------------------------------
// MCP surface: `--to <claim-id>` resolution + gated funnel.
// ---------------------------------------------------------------------------

#[test]
fn handle_swarm_rewind_resolves_claim_id_and_reports() {
    let conn = fresh_conn();
    let (root, _c, _gc, _u) = seed_cascade(&conn);

    let envelope = ai_memory::mcp::handle_swarm_rewind(&conn, &json!({ "to": root.id }))
        .expect("handle_swarm_rewind");

    assert_eq!(envelope["root_id"].as_str(), Some(root.id.as_str()));
    assert_eq!(envelope["target_kind"].as_str(), Some("memory"));
    assert_eq!(envelope["descendants_stamped"].as_u64(), Some(2));
    assert_eq!(envelope["root_contaminated"].as_bool(), Some(true));
    assert!(envelope["cost"]["usd"].as_str().is_some());
    assert!(envelope["signed_event_id"].as_str().is_some());
}

#[test]
fn handle_swarm_rewind_dry_run_previews_via_mcp() {
    let conn = fresh_conn();
    let (root, _c, _gc, _u) = seed_cascade(&conn);

    let envelope =
        ai_memory::mcp::handle_swarm_rewind(&conn, &json!({ "to": root.id, "dry_run": true }))
            .expect("handle_swarm_rewind dry run");
    assert_eq!(envelope["dry_run"].as_bool(), Some(true));
    assert_eq!(envelope["descendants_stamped"].as_u64(), Some(2));
    // No writes.
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("open"));
}
