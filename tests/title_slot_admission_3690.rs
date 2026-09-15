// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 (#3690 / #3695 / #3626 — sqlite half).
//!
//! The `(title, namespace)` slot belongs to LIVE rows only (schema v100: the
//! unique index is PARTIAL, `WHERE lifecycle_state <> 'tombstoned'`), and
//! every write funnel derives what it may do with an occupant from the ONE
//! predicate `LifecycleState::title_slot_admission`:
//!
//!  * a consolidation TOMBSTONE holds no slot — a later store of the same
//!    title is a FRESH, VISIBLE row beside it, never a write into the hidden
//!    one (#3690: the CLI printed an id and nothing ever showed the text);
//!  * a `quarantined` / `contaminated` occupant KEEPS its slot and every arm
//!    (merge / no-overwrite / same-id restore) is refused with a typed
//!    `ConflictError` whose `existing_id` is EMPTY — the hidden row is never
//!    named (#3695), and the local author's text is never written into a
//!    peer-attributed row (#3626);
//!  * the #2887 idempotent same-id restore of a tombstone still merges in
//!    place (vote Q3) and still leaves the row tombstoned.
//!
//! Every cell here drives a HIDDEN-ROW case and is RED on the pre-fix tree
//! (1ec64196b): there the full unique index let the store MERGE into the
//! tombstone / quarantined row and hand back its id.

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::storage::{ConflictError, ConflictMode};

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
        tags: vec!["slot-3690".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-3690".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:tester-3690" }),
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

fn open() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");
    (dir, conn)
}

fn set_state(conn: &rusqlite::Connection, id: &str, state: &str) {
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?2 WHERE id = ?1",
        rusqlite::params![id, state],
    )
    .expect("set lifecycle_state");
}

fn count_key(conn: &rusqlite::Connection, title: &str, ns: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
        rusqlite::params![title, ns],
        |r| r.get(0),
    )
    .expect("count")
}

fn raw(conn: &rusqlite::Connection, id: &str) -> (String, String, i64) {
    conn.query_row(
        "SELECT content, lifecycle_state, version FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .expect("row resident")
}

fn conflict(err: &anyhow::Error) -> &ConflictError {
    err.downcast_ref::<ConflictError>()
        .unwrap_or_else(|| panic!("expected a typed ConflictError, got: {err:#}"))
}

/// #3690 — the schema claim, on both halves the sqlite side owns: the ladder
/// tip is 100 and the SHIPPED index is the partial one.
#[test]
fn sqlite_schema_v100_carries_the_partial_title_slot_index_3690() {
    let (_dir, conn) = open();
    assert_eq!(ai_memory::storage::current_schema_version_for_tests(), 100);
    let ddl: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_memories_title_ns'",
            [],
            |r| r.get(0),
        )
        .expect("the title-slot index exists");
    assert!(
        ddl.contains(ai_memory::models::TITLE_SLOT_INDEX_PREDICATE),
        "idx_memories_title_ns must be PARTIAL on the ONE predicate; got: {ddl}"
    );
    assert!(
        ddl.to_ascii_uppercase().contains("UNIQUE"),
        "still unique: {ddl}"
    );
}

/// #3690 — the defect: a store beside a consolidation tombstone used to MERGE
/// into it (returning the tombstone's id) and the caller's text was never
/// visible again. Now the tombstone gives up its slot: the store lands as a
/// fresh, visible row; the tombstone is byte-identical.
#[test]
fn store_beside_a_tombstone_lands_as_a_fresh_visible_row_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "consolidated away"))
        .expect("seed");
    set_state(&conn, "id-a", "tombstoned");

    let id = ai_memory::db::insert(&conn, &mem("id-b", "team/ops", "slot", "the new text"))
        .expect("a tombstone holds no slot: the store must succeed");
    assert_eq!(
        id, "id-b",
        "the store must land as ITS OWN row, not the tombstone's"
    );
    let visible = ai_memory::db::get(&conn, "id-b")
        .expect("get")
        .expect("the new row is visible");
    assert_eq!(visible.content, "the new text");
    assert_eq!(
        raw(&conn, "id-a"),
        ("consolidated away".to_string(), "tombstoned".to_string(), 1)
    );
    let both: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'slot' AND namespace = 'team/ops'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(both, 2, "tombstone and live row coexist under one key");
}

/// #3690 — the LIVE slot is still unique: a second live store of the same
/// title merges into the live row (the legacy upsert), never forks a third.
#[test]
fn a_live_holder_still_merges_beside_a_tombstone_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "old")).expect("seed");
    set_state(&conn, "id-a", "tombstoned");
    ai_memory::db::insert(&conn, &mem("id-b", "team/ops", "slot", "live v1")).expect("fresh");
    let id = ai_memory::db::insert(&conn, &mem("id-c", "team/ops", "slot", "live v2"))
        .expect("merge into the live holder");
    assert_eq!(id, "id-b", "the live holder absorbs the re-store");
    assert_eq!(raw(&conn, "id-b").0, "live v2");
    assert_eq!(
        raw(&conn, "id-a").0,
        "old",
        "the tombstone is never the merge target"
    );
}

/// #3695 / #3626 — a QUARANTINED occupant keeps its slot and the merge arm is
/// refused with a typed conflict that names NO row; the quarantined row's
/// text, state and version are untouched, and nothing landed for the caller.
#[test]
fn store_onto_a_quarantined_holder_is_a_typed_unnamed_conflict_3695() {
    for hidden in ["quarantined", "contaminated"] {
        let (_dir, conn) = open();
        ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "peer text")).expect("seed");
        set_state(&conn, "id-a", hidden);

        let err = ai_memory::db::insert(&conn, &mem("id-b", "team/ops", "slot", "local text"))
            .expect_err("a hidden-for-security occupant refuses the merge");
        let c = conflict(&err);
        assert_eq!(c.existing_id, "", "{hidden}: the hidden row is never named");
        assert_eq!(
            (c.title.as_str(), c.namespace.as_str()),
            ("slot", "team/ops")
        );
        assert_eq!(
            raw(&conn, "id-a"),
            ("peer text".to_string(), hidden.to_string(), 1),
            "{hidden}: the occupant is byte-identical (no merge, no version bump)"
        );
        assert!(
            ai_memory::db::get(&conn, "id-b").expect("get").is_none(),
            "{hidden}: nothing landed"
        );
    }
}

/// #3695 — the no-overwrite arm (#2771) on a hidden occupant: still a typed
/// conflict, still unnamed (the pre-fix `DO NOTHING` re-probe handed the
/// quarantined id back).
#[test]
fn insert_no_overwrite_onto_a_quarantined_holder_names_no_row_3695() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "peer text")).expect("seed");
    set_state(&conn, "id-a", "quarantined");
    let err = ai_memory::db::insert_no_overwrite(&conn, &mem("id-b", "team/ops", "slot", "x"))
        .expect_err("refused");
    assert_eq!(conflict(&err).existing_id, "");
    assert_eq!(raw(&conn, "id-a").0, "peer text");
}

/// #3690 — the `on_conflict` pre-check the MCP / HTTP / CLI stores read
/// answers only with the VISIBLE occupant: a tombstone is a free slot, a
/// quarantined row is not something the caller may learn the id of.
#[test]
fn find_by_title_namespace_reports_only_the_visible_occupant_3690_3695() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "x")).expect("seed");
    let probe =
        || ai_memory::db::find_by_title_namespace(&conn, "slot", "team/ops", None).expect("probe");
    assert_eq!(probe().as_deref(), Some("id-a"));
    for state in ["tombstoned", "quarantined", "contaminated"] {
        set_state(&conn, "id-a", state);
        assert_eq!(probe(), None, "{state}: not a visible occupant");
    }
    set_state(&conn, "id-a", "done");
    assert_eq!(
        probe().as_deref(),
        Some("id-a"),
        "every recall-visible state occupies"
    );
}

/// #3690 — `on_conflict='error'` and `'version'` see the tombstone's slot as
/// FREE: `Error` inserts the fresh row, `Version` does not waste a `(2)`.
#[test]
fn conflict_modes_treat_a_tombstone_slot_as_free_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "x")).expect("seed");
    set_state(&conn, "id-a", "tombstoned");
    let id = ai_memory::db::insert_with_conflict(
        &conn,
        &mem("id-b", "team/ops", "slot", "fresh"),
        ConflictMode::Error,
    )
    .expect("error-mode store beside a tombstone is not a conflict");
    assert_eq!(id, "id-b");
    let err = ai_memory::db::insert_with_conflict(
        &conn,
        &mem("id-c", "team/ops", "slot", "again"),
        ConflictMode::Error,
    )
    .expect_err("the live row IS a conflict");
    assert_eq!(
        conflict(&err).existing_id,
        "id-b",
        "a visible holder is named"
    );
}

/// #2887 / #3690 (vote Q3) / #2894 — CHARACTERISATION: the same-id restore of
/// a TOMBSTONE behaves EXACTLY as it did before Unit 1.
///
/// Before v100 the full unique index covered tombstoned rows, so the restore
/// hit the `(title, namespace)` conflict and the CAS `DO UPDATE … WHERE
/// memories.id = excluded.id` merged IN PLACE, leaving the row tombstoned.
/// After v100 the tombstone is not in the partial index, no title conflict
/// fires, and the funnel re-targets the SAME `DO UPDATE` arm at the PRIMARY
/// KEY (`visibility::TitleSlotDisposition::ProceedByPrimaryKey`) to the SAME
/// outcome — behaviour preservation across an index change, which is what
/// an index change must be. So this cell asserts the old contract, field by
/// field, rather than only the outcome: ONE row under the key before and
/// after (never a second live row beside the tombstone); the columns the
/// arm rewrites (content, version) moved; every identity column (id,
/// `created_at`, `cid`, `lifecycle_state`) is byte-identical.
///
/// #2894 is NOT fixed by Unit 1 and must not be closed by association: the
/// restored original is still HIDDEN afterwards (the row stays tombstoned
/// and `get` returns nothing) — exactly as broken as before, no better and
/// no worse. The last assertion pins that as the CURRENT, still-open state.
#[test]
fn restore_same_id_onto_a_tombstone_preserves_the_pre_v100_in_place_merge_2887_2894_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "pre-tombstone")).expect("seed");
    set_state(&conn, "id-a", "tombstoned");
    let before: (String, String, String, Option<String>, i64, String) = conn
        .query_row(
            "SELECT id, created_at, lifecycle_state, cid, version, content FROM memories WHERE id = 'id-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .expect("row");
    assert_eq!(count_key(&conn, "slot", "team/ops"), 1);

    let id =
        ai_memory::db::insert_restore_same_id(&conn, &mem("id-a", "team/ops", "slot", "restored"))
            .expect("same-id restore against a tombstone must succeed (it did before v100)");
    assert_eq!(
        id, "id-a",
        "the restore lands on the SAME row (CAS semantics)"
    );

    let after: (String, String, String, Option<String>, i64, String) = conn
        .query_row(
            "SELECT id, created_at, lifecycle_state, cid, version, content FROM memories WHERE id = 'id-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .expect("row");
    // identity columns byte-identical (the pre-v100 in-place CAS contract)
    assert_eq!(
        (&after.0, &after.1, &after.2, &after.3),
        (&before.0, &before.1, &before.2, &before.3)
    );
    assert_eq!(
        after.2, "tombstoned",
        "restore never un-tombstones (pre-v100 kept memories.lifecycle_state)"
    );
    // the arm's rewrites moved
    assert_eq!(after.5, "restored");
    assert_eq!(
        after.4,
        before.4 + 1,
        "the same DO UPDATE arm ran (version bumped exactly once)"
    );
    // ONE row under the key — the second-live-row hazard of the partial index does not occur
    assert_eq!(
        count_key(&conn, "slot", "team/ops"),
        1,
        "never a second row beside the tombstone"
    );
    // #2894 — STILL OPEN: the restored original remains hidden from get.
    assert!(
        ai_memory::db::get(&conn, "id-a").expect("get").is_none(),
        "#2894 is not fixed here: the restored row is still hidden (pre- and post-Unit-1 alike)"
    );
}

/// #3690 (vote Q3) — a restore whose key is now held by a DIFFERENT live row
/// (possible only since v100: a store landed beside the tombstone) is refused
/// NAMING the visible holder; the tombstone and the holder are untouched.
#[test]
fn restore_same_id_refuses_when_a_different_live_row_holds_the_key_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "original")).expect("seed");
    set_state(&conn, "id-a", "tombstoned");
    ai_memory::db::insert(&conn, &mem("id-b", "team/ops", "slot", "newer owner")).expect("beside");
    let err =
        ai_memory::db::insert_restore_same_id(&conn, &mem("id-a", "team/ops", "slot", "restored"))
            .expect_err("the live holder wins");
    assert_eq!(conflict(&err).existing_id, "id-b");
    assert_eq!(
        raw(&conn, "id-a"),
        ("original".to_string(), "tombstoned".to_string(), 1)
    );
    assert_eq!(
        raw(&conn, "id-b"),
        ("newer owner".to_string(), "open".to_string(), 1)
    );
}

/// #3695 — a same-id restore onto a QUARANTINED row is refused unnamed: a
/// rollback must not launder a quarantine by rewriting the row's text.
#[test]
fn restore_same_id_onto_a_quarantined_row_is_refused_unnamed_3695() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "peer text")).expect("seed");
    set_state(&conn, "id-a", "quarantined");
    let err = ai_memory::db::insert_restore_same_id(&conn, &mem("id-a", "team/ops", "slot", "x"))
        .expect_err("refused");
    assert_eq!(conflict(&err).existing_id, "");
    assert_eq!(
        raw(&conn, "id-a"),
        ("peer text".to_string(), "quarantined".to_string(), 1)
    );
}

/// #3690 — a plain MERGE store that reuses a tombstone's OWN id under the
/// same key is the defect shape again (a write that lands in a hidden row):
/// refused typed and unnamed, never absorbed. Only a RESTORE may do that.
#[test]
fn merge_store_reusing_a_tombstones_id_is_refused_not_absorbed_3690() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "old")).expect("seed");
    set_state(&conn, "id-a", "tombstoned");
    let err = ai_memory::db::insert(&conn, &mem("id-a", "team/ops", "slot", "new"))
        .expect_err("a merge into a tombstone is refused");
    assert_eq!(conflict(&err).existing_id, "");
    assert_eq!(raw(&conn, "id-a").0, "old");
}

// ───────────────────────────────────────────────────────────────────
// #3696 / #3712 — the SECOND axis: an occupant the viewer cannot READ
// ───────────────────────────────────────────────────────────────────

fn private_row_of(owner: &str, id: &str, title: &str, content: &str) -> Memory {
    let mut m = mem(id, "team/ops", title, content);
    m.metadata = serde_json::json!({ "agent_id": owner, "scope": "private" });
    m
}

/// #3696 — a LIVE occupant that is another agent's `scope=private` row:
/// the merge arm refuses typed and UNNAMED for a viewer who cannot read it;
/// the owner and the trust-all posture still merge as before.
#[test]
fn store_onto_another_agents_private_row_is_a_typed_unnamed_conflict_3696() {
    let (_dir, conn) = open();
    ai_memory::db::insert(
        &conn,
        &private_row_of("ai:alice", "id-a", "slot", "alice's text"),
    )
    .expect("seed");
    // bob (Some viewer, not the owner): refused, unnamed, row untouched
    let err = ai_memory::db::insert_as(
        &conn,
        &private_row_of("ai:bob", "id-b", "slot", "bob's text"),
        Some("ai:bob"),
    )
    .expect_err("bob cannot read alice's private row, so the merge is refused");
    assert_eq!(
        conflict(&err).existing_id,
        "",
        "the private row is never named"
    );
    assert_eq!(
        raw(&conn, "id-a"),
        ("alice's text".to_string(), "open".to_string(), 1)
    );
    let err = ai_memory::db::insert_no_overwrite_as(
        &conn,
        &private_row_of("ai:bob", "id-c", "slot", "x"),
        Some("ai:bob"),
    )
    .expect_err("the no-overwrite arm is refused too");
    assert_eq!(conflict(&err).existing_id, "");
    // the OWNER merges (legacy dedup), and so does the trust-all posture
    let id = ai_memory::db::insert_as(
        &conn,
        &private_row_of("ai:alice", "id-d", "slot", "alice v2"),
        Some("ai:alice"),
    )
    .expect("the owner's re-store merges");
    assert_eq!(id, "id-a");
    assert_eq!(raw(&conn, "id-a").0, "alice v2");
    let id = ai_memory::db::insert(
        &conn,
        &private_row_of("ai:bob", "id-e", "slot", "trust-all"),
    )
    .expect("viewer None is the single-tenant trust-all posture");
    assert_eq!(id, "id-a");
}

/// #3696 — the `on_conflict` pre-check never hands another agent's private
/// row's id to the viewer; the owner and trust-all still see it.
#[test]
fn find_by_title_namespace_never_names_another_agents_private_row_3696() {
    let (_dir, conn) = open();
    ai_memory::db::insert(&conn, &private_row_of("ai:alice", "id-a", "slot", "x")).expect("seed");
    let probe = |viewer: Option<&str>| {
        ai_memory::db::find_by_title_namespace(&conn, "slot", "team/ops", viewer).expect("probe")
    };
    assert_eq!(probe(Some("ai:bob")), None, "bob learns nothing");
    assert_eq!(
        probe(Some("ai:alice")).as_deref(),
        Some("id-a"),
        "the owner sees it"
    );
    assert_eq!(probe(None).as_deref(), Some("id-a"), "trust-all sees it");
}

/// #3712 — the near-duplicate refusal on store is neither triggered by nor
/// names another agent's private memory; the same row still refuses its
/// owner (and trust-all).
#[test]
fn proactive_conflict_never_refuses_on_another_agents_private_row_3712() {
    let (_dir, conn) = open();
    let claim = "the deploy uses canary health checks before traffic shifts to the new replica set";
    let mut alice = private_row_of("ai:alice", "id-a", "alice-private", claim);
    alice.metadata["scope"] = serde_json::Value::String("private".into());
    ai_memory::db::insert(&conn, &alice).expect("seed");
    let emb: Vec<f32> = vec![1.0, 0.0, 0.0, 0.0];
    ai_memory::db::set_embedding(&conn, "id-a", &emb, "test#none").expect("embed");
    let probe = mem(
        "probe",
        "team/ops",
        "bob-store",
        &format!("{claim} and rolls back on failure"),
    );
    let ids = ["id-a".to_string()];
    assert!(
        ai_memory::db::proactive_conflict_check(&conn, &probe, &emb, Some("ai:bob"))
            .expect("scan")
            .is_none(),
        "bob's store is never refused on alice's private row"
    );
    assert!(
        ai_memory::db::proactive_conflict_check_candidates(
            &conn,
            &probe,
            &emb,
            &ids,
            Some("ai:bob")
        )
        .expect("ann")
        .is_none(),
        "the ANN-routed lane never names alice's private row to bob"
    );
    for viewer in [Some("ai:alice"), None] {
        let hit = ai_memory::db::proactive_conflict_check(&conn, &probe, &emb, viewer)
            .expect("scan")
            .expect("the owner / trust-all still get the advisory");
        assert_eq!(hit.existing_id, "id-a");
    }
}
