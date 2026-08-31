// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3324 (#3266 MVG) — auto-propagating `contaminated` lifecycle along
//! the provenance DAG on invalidate.
//!
//! Proves the rock-solid bar for the new [`LifecycleState::Contaminated`]
//! state and its transactional auto-stamp
//! [`db::stamp_contaminated_descendants`]:
//!
//! * `Contaminated` is NOT recall-visible, and the Rust twin
//!   ([`LifecycleState::is_recall_visible`]) AGREES with the SQL twin
//!   ([`lifecycle_visible_clause`]) — fail-CLOSED (allow-list, never a
//!   deny-list) and cross-backend (the clause binds nothing, so it is used
//!   verbatim by SQLite and Postgres).
//! * The auto-stamp is idempotent (re-run = no-op), cycle-safe, depth-bounded,
//!   atomic, and reversible (the pre-taint state is recorded for a future
//!   `swarm_rewind`).
//! * A caller can never set `contaminated`, and the state hides a row from the
//!   ordinary `get` read lane end-to-end.

use ai_memory::db;
use ai_memory::models::{
    LifecycleState, Memory, MemoryKind, RECALL_VISIBLE_LIFECYCLE_STATES, Tier,
    lifecycle_visible_clause,
};
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

/// Raw read of `lifecycle_state` (bypassing the visibility filter that
/// `db::get` applies) so the test can observe a hidden row's true state.
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

/// Raw read of the `metadata` JSON blob.
fn raw_metadata(conn: &Connection, id: &str) -> serde_json::Value {
    let s: String = conn
        .query_row("SELECT metadata FROM memories WHERE id = ?1", [id], |r| {
            r.get::<_, String>(0)
        })
        .expect("query metadata");
    serde_json::from_str(&s).expect("metadata is JSON")
}

// ---------------------------------------------------------------------------
// State-model touchpoints (fail-closed).
// ---------------------------------------------------------------------------

#[test]
fn contaminated_is_not_recall_visible_rust_and_sql_twins_agree() {
    // Rust twin: fail-closed, NOT recall-visible.
    assert!(
        !LifecycleState::Contaminated.is_recall_visible(),
        "Contaminated must never be recall-visible"
    );
    assert!(
        !RECALL_VISIBLE_LIFECYCLE_STATES.contains(&LifecycleState::Contaminated),
        "Contaminated must be ABSENT from the allow-list (fail-closed)"
    );

    // SQL twin: the shared clause (used verbatim by BOTH backends — it binds
    // nothing) must NOT admit 'contaminated', and MUST admit every
    // recall-visible state. This IS the SQLite<->Postgres parity guarantee.
    for alias in ["", "m", "memories"] {
        let clause = lifecycle_visible_clause(alias);
        assert!(
            !clause.contains("'contaminated'"),
            "SQL twin must not list 'contaminated' (alias={alias:?}): {clause}"
        );
        for visible in RECALL_VISIBLE_LIFECYCLE_STATES {
            assert!(
                clause.contains(&format!("'{}'", visible.as_str())),
                "SQL twin must admit {} (alias={alias:?}): {clause}",
                visible.as_str()
            );
        }
    }

    // Twins agree for EVERY state: is_recall_visible <=> the state appears in
    // the SQL allow-list clause.
    let clause = lifecycle_visible_clause("");
    for st in LifecycleState::all() {
        let in_clause = clause.contains(&format!("'{}'", st.as_str()));
        assert_eq!(
            st.is_recall_visible(),
            in_clause,
            "Rust twin and SQL twin disagree for {}",
            st.as_str()
        );
    }
}

#[test]
fn contaminated_is_system_only_terminal_and_unreachable_by_caller() {
    assert!(LifecycleState::Contaminated.is_system_only());
    assert!(LifecycleState::Contaminated.is_terminal());

    // No caller transition may REACH Contaminated (absent from the graph).
    for from in LifecycleState::all() {
        assert!(
            !from.can_transition_to(LifecycleState::Contaminated),
            "{} must not transition to Contaminated",
            from.as_str()
        );
    }
    // ...and Contaminated is a dead end.
    for to in LifecycleState::all() {
        assert!(!LifecycleState::Contaminated.can_transition_to(*to));
    }

    // The write-boundary validator rejects it as caller input (system-only).
    let err = ai_memory::validate::validate_lifecycle_state(Some("contaminated"))
        .expect_err("caller may not set contaminated")
        .to_string();
    assert!(err.contains("system-only"), "{err}");
}

#[test]
fn contaminated_roundtrips_wire_string() {
    assert_eq!(LifecycleState::Contaminated.as_str(), "contaminated");
    assert_eq!(
        LifecycleState::from_str("contaminated"),
        Some(LifecycleState::Contaminated)
    );
    assert!(LifecycleState::all().contains(&LifecycleState::Contaminated));
}

// ---------------------------------------------------------------------------
// Transactional auto-stamp.
// ---------------------------------------------------------------------------

/// Wire `child` --`derives_from`--> `parent` so `child` is a DESCENDANT of
/// `parent` in the downstream provenance walk.
fn derives_from(conn: &Connection, child: &str, parent: &str) {
    db::create_link(conn, child, parent, "derives_from").expect("derives_from edge");
}

#[test]
fn auto_stamp_contaminates_derives_from_descendants_and_records_prior_state() {
    let conn = fresh_conn();
    let root = make_mem("root");
    let child = make_mem("child");
    let grandchild = make_mem("grandchild");
    let unrelated = make_mem("unrelated");
    for m in [&root, &child, &grandchild, &unrelated] {
        db::insert(&conn, m).expect("insert");
    }
    // root <- child <- grandchild (derives_from chain); `unrelated` is off-DAG.
    derives_from(&conn, &child.id, &root.id);
    derives_from(&conn, &grandchild.id, &child.id);

    let report =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("stamp");
    assert_eq!(report.stamped, 2, "child + grandchild are tainted");
    assert_eq!(report.already_contaminated, 0);
    assert_eq!(report.skipped_system_only, 0);

    // Descendants are Contaminated; the root itself is NOT (it is invalidated
    // by its own path, not by this cascade); the off-DAG row is untouched.
    assert_eq!(raw_state(&conn, &child.id).as_deref(), Some("contaminated"));
    assert_eq!(
        raw_state(&conn, &grandchild.id).as_deref(),
        Some("contaminated")
    );
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("open"));
    assert_eq!(raw_state(&conn, &unrelated.id).as_deref(), Some("open"));

    // Reversibility: the pre-taint state is recorded so a future swarm_rewind
    // can restore the exact prior state.
    let meta = raw_metadata(&conn, &child.id);
    assert_eq!(
        meta["contamination"]["prior_lifecycle_state"].as_str(),
        Some("open")
    );
    assert_eq!(
        meta["contamination"]["contaminated_from"].as_str(),
        Some(root.id.as_str())
    );
    // The pre-existing metadata is preserved (additive, never destructive).
    assert_eq!(meta["agent_id"].as_str(), Some("ai:tester"));

    // End-to-end fail-closed: the ordinary `get` read lane hides the row.
    assert!(
        db::get(&conn, &child.id).expect("get").is_none(),
        "contaminated row must be hidden from the ordinary get lane"
    );
    // ...while the untainted root stays visible.
    assert!(db::get(&conn, &root.id).expect("get").is_some());
}

#[test]
fn auto_stamp_is_idempotent() {
    let conn = fresh_conn();
    let root = make_mem("root");
    let child = make_mem("child");
    for m in [&root, &child] {
        db::insert(&conn, m).expect("insert");
    }
    derives_from(&conn, &child.id, &root.id);

    let first =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("first");
    assert_eq!(first.stamped, 1);

    // Re-run over the SAME subtree stamps NOTHING (idempotent no-op).
    let second =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("second");
    assert_eq!(second.stamped, 0, "re-run must be a no-op");
    assert_eq!(second.already_contaminated, 1);

    // The recorded prior state is not overwritten to 'contaminated' on re-run.
    let meta = raw_metadata(&conn, &child.id);
    assert_eq!(
        meta["contamination"]["prior_lifecycle_state"].as_str(),
        Some("open"),
        "re-run must not clobber the recorded prior state"
    );
}

#[test]
fn auto_stamp_is_cycle_safe() {
    let conn = fresh_conn();
    let root = make_mem("root");
    let a = make_mem("a");
    let b = make_mem("b");
    for m in [&root, &a, &b] {
        db::insert(&conn, m).expect("insert");
    }
    // A cycle downstream of root: root <- a <- b <- a (b derives_from a AND a
    // derives_from b). The bounded, visited-set walk must terminate.
    derives_from(&conn, &a.id, &root.id);
    derives_from(&conn, &b.id, &a.id);
    derives_from(&conn, &a.id, &b.id); // closes the cycle a<->b

    let report = db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH)
        .expect("stamp terminates on a cycle");
    // Both reachable nodes are stamped exactly once; no infinite loop.
    assert_eq!(report.stamped, 2);
    assert_eq!(raw_state(&conn, &a.id).as_deref(), Some("contaminated"));
    assert_eq!(raw_state(&conn, &b.id).as_deref(), Some("contaminated"));
}

#[test]
fn auto_stamp_is_depth_bounded() {
    let conn = fresh_conn();
    // Build a chain longer than the depth ceiling and stamp with max_depth = 2.
    // Only descendants within 2 hops may be tainted.
    let nodes: Vec<Memory> = (0..6).map(|i| make_mem(&format!("n{i}"))).collect();
    for m in &nodes {
        db::insert(&conn, m).expect("insert");
    }
    for i in 1..nodes.len() {
        derives_from(&conn, &nodes[i].id, &nodes[i - 1].id);
    }

    let report = db::stamp_contaminated_descendants(&conn, &nodes[0].id, 2).expect("stamp bounded");
    assert_eq!(report.stamped, 2, "only depth-1 and depth-2 descendants");
    assert_eq!(
        raw_state(&conn, &nodes[1].id).as_deref(),
        Some("contaminated")
    );
    assert_eq!(
        raw_state(&conn, &nodes[2].id).as_deref(),
        Some("contaminated")
    );
    // Beyond the depth bound: untouched.
    assert_eq!(raw_state(&conn, &nodes[3].id).as_deref(), Some("open"));
    assert_eq!(raw_state(&conn, &nodes[5].id).as_deref(), Some("open"));
}

#[test]
fn auto_stamp_does_not_clobber_stronger_system_only_states() {
    let conn = fresh_conn();
    let root = make_mem("root");
    let child_tomb = make_mem("child_tombstoned");
    let child_open = make_mem("child_open");
    for m in [&root, &child_tomb, &child_open] {
        db::insert(&conn, m).expect("insert");
    }
    derives_from(&conn, &child_tomb.id, &root.id);
    derives_from(&conn, &child_open.id, &root.id);

    // Put one descendant into a stronger, already-hidden system state.
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        [&child_tomb.id],
    )
    .expect("tombstone");

    let report =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("stamp");
    assert_eq!(report.stamped, 1, "only the open descendant is tainted");
    assert_eq!(report.skipped_system_only, 1);
    // The tombstone is preserved (non-destructive, fail-closed).
    assert_eq!(
        raw_state(&conn, &child_tomb.id).as_deref(),
        Some("tombstoned")
    );
    assert_eq!(
        raw_state(&conn, &child_open.id).as_deref(),
        Some("contaminated")
    );
}

#[test]
fn supersedes_edge_auto_stamps_reflection_dependents_end_to_end() {
    // The wire path the curator/operator use: a Reflection->Reflection
    // `supersedes` edge invalidates the target and auto-taints its
    // `reflects_on` dependents in the SAME call.
    let conn = fresh_conn();
    let db_path = std::path::Path::new(":memory:");

    let mut r1 = make_mem("R1");
    r1.memory_kind = MemoryKind::Reflection;
    r1.reflection_depth = 1;
    let mut r2 = make_mem("R2");
    r2.memory_kind = MemoryKind::Reflection;
    r2.reflection_depth = 1;
    let m1 = make_mem("M1");
    let m2 = make_mem("M2");
    for m in [&r1, &r2, &m1, &m2] {
        db::insert(&conn, m).expect("insert");
    }
    db::create_link(&conn, &m1.id, &r1.id, "reflects_on").expect("m1 reflects_on r1");
    db::create_link(&conn, &m2.id, &r1.id, "reflects_on").expect("m2 reflects_on r1");

    let resp = ai_memory::mcp::dispatch_handle_link_for_test(
        &conn,
        db_path,
        &json!({
            "source_id": r2.id,
            "target_id": r1.id,
            "relation": "supersedes",
            "agent_id": "ai:tester",
        }),
        None,
    )
    .expect("handle_link supersedes");

    // The wire response surfaces the taint cascade size.
    assert_eq!(resp["linked"].as_bool(), Some(true));
    assert_eq!(
        resp["contaminated_stamped"].as_u64(),
        Some(2),
        "both reflects_on dependents were auto-tainted"
    );

    // The dependents are Contaminated + hidden from the ordinary read lane;
    // the invalidated root and the winner are NOT contaminated by the cascade.
    for dep in [&m1.id, &m2.id] {
        assert_eq!(raw_state(&conn, dep).as_deref(), Some("contaminated"));
        assert!(
            db::get(&conn, dep).expect("get").is_none(),
            "contaminated dependent must be hidden from get"
        );
    }
    assert_ne!(raw_state(&conn, &r2.id).as_deref(), Some("contaminated"));
}

#[test]
fn auto_stamp_on_leaf_root_is_a_no_op() {
    let conn = fresh_conn();
    let root = make_mem("lonely");
    db::insert(&conn, &root).expect("insert");
    let report =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("stamp");
    assert_eq!(report.stamped, 0);
    assert_eq!(raw_state(&conn, &root.id).as_deref(), Some("open"));
}

#[test]
fn auto_stamp_tolerates_non_object_metadata_without_losing_the_taint() {
    // A descendant whose metadata is not a JSON object (a legacy/corrupt blob)
    // must still be tainted — the contamination marker is added over a fresh
    // object rather than failing the sweep (additive, never destructive).
    let conn = fresh_conn();
    let root = make_mem("root");
    let child = make_mem("child");
    for m in [&root, &child] {
        db::insert(&conn, m).expect("insert");
    }
    derives_from(&conn, &child.id, &root.id);
    // Overwrite the child's metadata with a non-object JSON scalar.
    conn.execute(
        "UPDATE memories SET metadata = '\"not-an-object\"' WHERE id = ?1",
        [&child.id],
    )
    .expect("corrupt metadata");

    let report =
        db::stamp_contaminated_descendants(&conn, &root.id, db::LINEAGE_MAX_DEPTH).expect("stamp");
    assert_eq!(report.stamped, 1);
    assert_eq!(raw_state(&conn, &child.id).as_deref(), Some("contaminated"));
    // The taint provenance is recorded on a fresh object.
    let meta = raw_metadata(&conn, &child.id);
    assert_eq!(
        meta["contamination"]["prior_lifecycle_state"].as_str(),
        Some("open")
    );
}
