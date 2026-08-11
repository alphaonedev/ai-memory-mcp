// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2887 — the reversible-rollback restore paths (autonomy
//! `reverse_rollback_entry`/`reverse_rollback_entry_store`, curator
//! `rollback_consolidation`) must re-store a snapshot ATOMICALLY: a concurrent
//! writer that took the `(title, namespace)` slot after the target was
//! forgotten/consolidated must be REFUSED (typed conflict), never silently
//! overwritten by the restore's upsert.
//!
//! Pre-#2887 those paths were probe-then-`store()`: `find_by_title_namespace` /
//! `check_no_collision` → `store.store()` (an `ON CONFLICT DO UPDATE SET
//! content=excluded` upsert). A writer that slipped in between the probe and
//! the write had its content clobbered with no conflict and no snapshot — a
//! North-Star lost-update.
//!
//! The fix is the restore-safe CAS `db::insert_restore_same_id` /
//! `MemoryStore::restore_or_conflict`
//! (`INSERT … ON CONFLICT(title,namespace) DO UPDATE … WHERE memories.id =
//! excluded.id`): a SAME-id restore merges (incl. against a tombstoned row); a
//! DIFFERENT-id owner is refused with a typed conflict WITHOUT clobber.
//!
//! Coverage: the primitive directly (never vacuous — one atomic statement, no
//! probe), a genuine two-connection shared-file WAL race, the SAL trait wiring,
//! a mechanical SOURCE-PIN that the callers route their sole restore write
//! through the atomic primitive (the witness that FAILS against probe-then-
//! write), and a live-PG twin gated on `AI_MEMORY_TEST_POSTGRES_URL`.

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

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
        tags: vec!["restore-2887".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-2887".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:tester" }),
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

fn version_of(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT version FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("version row present")
}

// ───────────────────────────────────────────────────────────────────
// primitive — db::insert_restore_same_id (single-connection, deterministic)
// ───────────────────────────────────────────────────────────────────

/// No row holds the slot → a fresh INSERT (restore into an empty slot).
#[test]
fn restore_inserts_when_slot_free_2887() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");

    let m = mem("id-orig", "team/ops", "snap-title", "restored content");
    let id = ai_memory::db::insert_restore_same_id(&conn, &m).expect("restore into free slot");
    assert_eq!(id, "id-orig");
    let row = ai_memory::db::get(&conn, "id-orig")
        .expect("get")
        .expect("row present");
    assert_eq!(row.content, "restored content");
}

/// The SAME id already holds the slot → the DO UPDATE CAS fires (idempotent
/// restore), byte-identical to what `db::insert` (the pre-fix `store.store()`)
/// would do for a same-id re-store.
#[test]
fn restore_same_id_merges_2887() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");

    let first = mem("id-orig", "team/ops", "snap-title", "v1 content");
    ai_memory::db::insert(&conn, &first).expect("seed row");
    // Restore the SAME id with fresh content → DO UPDATE fires.
    let restore = mem("id-orig", "team/ops", "snap-title", "v2 restored content");
    let id = ai_memory::db::insert_restore_same_id(&conn, &restore).expect("same-id restore ok");
    assert_eq!(id, "id-orig");
    let row = ai_memory::db::get(&conn, "id-orig")
        .expect("get")
        .expect("row present");
    assert_eq!(row.content, "v2 restored content", "same-id restore merged");
    assert_eq!(row.version, 2, "same-id DO UPDATE bumped the version");
}

/// The SAME id holds the slot but the row is TOMBSTONED (the lineage-DAG #1859
/// consolidate-tombstone disposition that retains the id + key). The restore
/// must still SUCCEED (the CAS `WHERE memories.id = excluded.id` is true) — the
/// case that `store_with_embedding_no_overwrite` (#2771 DO NOTHING) would
/// wrongly refuse, which is exactly why this new primitive exists.
#[test]
fn restore_same_id_against_tombstoned_row_merges_2887() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");

    let orig = mem("id-orig", "team/ops", "snap-title", "pre-tombstone content");
    ai_memory::db::insert(&conn, &orig).expect("seed row");
    // Tombstone the row in place (retains id + (title, namespace) key).
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'tombstoned' WHERE id = ?1",
        rusqlite::params!["id-orig"],
    )
    .expect("tombstone");

    let restore = mem("id-orig", "team/ops", "snap-title", "restored content");
    let id = ai_memory::db::insert_restore_same_id(&conn, &restore)
        .expect("same-id restore against a tombstoned row must succeed, not refuse");
    assert_eq!(id, "id-orig");
    let row = ai_memory::db::get(&conn, "id-orig")
        .expect("get")
        .expect("row present");
    assert_eq!(
        row.content, "restored content",
        "tombstoned same-id restored"
    );
}

/// A DIFFERENT id owns the `(title, namespace)` slot → the CAS refuses with a
/// typed `ConflictError` carrying the occupant's id, and the foreign row is
/// left BYTE-IDENTICAL (its `version` never bumps — a clobbering DO UPDATE
/// would have advanced it to 2). This is the core lost-update fix.
#[test]
fn restore_refuses_foreign_id_without_clobber_2887() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("open");

    // A NEW memory (foreign id) squats the slot the original once held.
    let foreign = mem(
        "id-foreign",
        "team/ops",
        "snap-title",
        "FOREIGN durable content",
    );
    ai_memory::db::insert(&conn, &foreign).expect("foreign occupies slot");
    assert_eq!(version_of(&conn, "id-foreign"), 1);

    // Restore the ORIGINAL snapshot into the now-foreign-owned slot.
    let orig = mem(
        "id-orig",
        "team/ops",
        "snap-title",
        "ORIG content MUST NOT land",
    );
    let err = ai_memory::db::insert_restore_same_id(&conn, &orig)
        .expect_err("a different-id owner MUST be refused, never clobbered");
    let conflict = err
        .downcast_ref::<ai_memory::storage::ConflictError>()
        .expect("typed ConflictError");
    assert_eq!(conflict.existing_id, "id-foreign");
    assert_eq!(conflict.title, "snap-title");
    assert_eq!(conflict.namespace, "team/ops");

    // Foreign row is untouched — content AND version unchanged (no DO UPDATE).
    let row = ai_memory::db::get(&conn, "id-foreign")
        .expect("get")
        .expect("foreign row present");
    assert_eq!(
        row.content, "FOREIGN durable content",
        "foreign content preserved"
    );
    assert_eq!(
        version_of(&conn, "id-foreign"),
        1,
        "the refused restore must NOT have run a DO UPDATE on the foreign row"
    );
    // The original id was never created.
    assert!(
        ai_memory::db::get(&conn, "id-orig").expect("get").is_none(),
        "the refused original must not exist"
    );
}

// ───────────────────────────────────────────────────────────────────
// genuine two-connection race (shared FILE + WAL, never :memory:)
// ───────────────────────────────────────────────────────────────────

/// The exact #2887 window as a real race: one connection restores the ORIGINAL
/// snapshot (`insert_restore_same_id`) while another connection creates a
/// FOREIGN memory (`insert_no_overwrite`) into the SAME `(title, namespace)`
/// slot. The `(title, namespace)` UNIQUE index serialises them: exactly one
/// wins the slot and the other gets a typed `ConflictError`. NEITHER path is an
/// overwrite (both are CAS / no-overwrite), so the race can never clobber —
/// exactly one row survives and it is byte-identical to whichever writer won.
#[test]
fn concurrent_restore_vs_foreign_write_never_clobbers_2887() {
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("m.db");
    drop(ai_memory::db::open(&path).expect("seed schema"));

    let barrier = Arc::new(Barrier::new(2));

    let restore_path = path.clone();
    let restore_barrier = Arc::clone(&barrier);
    let restore = std::thread::spawn(move || {
        let conn = ai_memory::db::open(&restore_path).expect("open");
        conn.busy_timeout(Duration::from_secs(10)).expect("busy");
        let m = mem("id-orig", "race/ns", "raced-title", "content-ORIG");
        restore_barrier.wait();
        ai_memory::db::insert_restore_same_id(&conn, &m).map(|id| (id, "content-ORIG"))
    });

    let foreign_path = path.clone();
    let foreign_barrier = Arc::clone(&barrier);
    let foreign = std::thread::spawn(move || {
        let conn = ai_memory::db::open(&foreign_path).expect("open");
        conn.busy_timeout(Duration::from_secs(10)).expect("busy");
        let m = mem("id-foreign", "race/ns", "raced-title", "content-FOREIGN");
        foreign_barrier.wait();
        ai_memory::db::insert_no_overwrite(&conn, &m).map(|id| (id, "content-FOREIGN"))
    });

    let r_restore = restore.join().expect("join restore");
    let r_foreign = foreign.join().expect("join foreign");

    let winners: Vec<&(String, &str)> = [&r_restore, &r_foreign]
        .into_iter()
        .filter_map(|r| r.as_ref().ok())
        .collect();
    assert_eq!(winners.len(), 1, "exactly one writer must win the slot");
    for r in [&r_restore, &r_foreign] {
        if let Err(e) = r {
            e.downcast_ref::<ai_memory::storage::ConflictError>()
                .expect("loser must get the typed ConflictError, not a lock/other error");
        }
    }

    // Exactly one row, byte-identical to the winner (never a clobber).
    let conn = ai_memory::db::open(&path).expect("reopen");
    let (winner_id, winner_content) = winners[0].clone();
    let row = ai_memory::db::get(&conn, &winner_id)
        .expect("get")
        .expect("winner row present");
    assert_eq!(row.content, winner_content, "winner content is durable");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["raced-title", "race/ns"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(count, 1, "the race must leave exactly one row");
}

// ───────────────────────────────────────────────────────────────────
// SAL trait wiring — SqliteStore::restore_or_conflict
// ───────────────────────────────────────────────────────────────────

/// The SAL `restore_or_conflict` maps a same-id restore to `Ok` and a foreign
/// owner to `StoreError::Conflict` (the `ConflictError` → SAL conflict mapping),
/// leaving the foreign row untouched.
#[cfg(feature = "sal")]
#[test]
fn sal_restore_or_conflict_sqlite_2887() {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};

    let dir = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(dir.path().join("m.db")).expect("open store");
    let ctx = CallerContext::for_admin("ai:curator");

    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        // Same-id restore into a free slot → Ok.
        let orig = mem("id-orig", "team/ops", "snap-title", "restored");
        let id = store
            .restore_or_conflict(&ctx, &orig)
            .await
            .expect("restore ok");
        assert_eq!(id, "id-orig");

        // A DIFFERENT id squats the slot; a subsequent restore of a DIFFERENT
        // original at the same key is refused.
        let foreign = mem("id-foreign", "team/two", "shared", "FOREIGN");
        store.store(&ctx, &foreign).await.expect("foreign stored");
        let orig2 = mem("id-orig2", "team/two", "shared", "loser");
        let err = store
            .restore_or_conflict(&ctx, &orig2)
            .await
            .expect_err("foreign owner must refuse");
        assert!(
            matches!(err, StoreError::Conflict { id } if id == "id-foreign"),
            "expected Conflict carrying the occupant id"
        );
        // Foreign row unharmed.
        let row = store.get(&ctx, "id-foreign").await.expect("get foreign");
        assert_eq!(row.content, "FOREIGN");
    });
}

// ───────────────────────────────────────────────────────────────────
// SOURCE-PIN — the callers route their SOLE restore write through the
// atomic primitive (the witness that FAILS against probe-then-write)
// ───────────────────────────────────────────────────────────────────

/// The pre-#2887 collision tests pre-insert the squatter, so the OLD probe
/// caught it too — they pass against unfixed code. This mechanical pin closes
/// that gap: it proves the callers no longer carry a `find_by_title_namespace`
/// / `guard_no_collision` probe + `store.store()` write for the restore, and
/// route through the atomic `restore_or_conflict` / `insert_restore_same_id`
/// instead. It FAILS against the probe-then-write shape.
#[test]
fn callers_route_restore_through_atomic_cas_2887() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let compaction =
        std::fs::read_to_string(root.join("src/curator/compaction.rs")).expect("read compaction");
    assert!(
        compaction.contains("restore_or_conflict(&self.ctx, m)"),
        "curator rollback must write via the atomic restore_or_conflict"
    );
    assert!(
        !compaction.contains("find_by_title_namespace"),
        "curator rollback must NOT retain the racy probe-then-store shape"
    );

    let autonomy = std::fs::read_to_string(root.join("src/autonomy.rs")).expect("read autonomy");
    // The SAL rollback (`reverse_rollback_entry_store`) routes restores through
    // the atomic CAS and dropped the racy `guard_no_collision` probe helper.
    assert!(
        autonomy.contains("restore_or_conflict(ctx, m)"),
        "SAL rollback must write via the atomic restore_or_conflict"
    );
    assert!(
        !autonomy.contains("guard_no_collision"),
        "SAL rollback must NOT retain the racy guard_no_collision probe"
    );
    // The conn-based CLI rollback (`reverse_rollback_entry`) writes via the
    // atomic sqlite CAS SSOT rather than a bare `db::insert` upsert.
    assert!(
        autonomy.contains("insert_restore_same_id(conn, &m)")
            && autonomy.contains("insert_restore_same_id(conn, &snapshot)"),
        "CLI rollback must write via db::insert_restore_same_id"
    );
}

// ───────────────────────────────────────────────────────────────────
// postgres — SAL restore_or_conflict, live-PG (gated on a real database)
// ───────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::mem;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};
    use std::sync::Arc;

    async fn connect() -> Option<Arc<PostgresStore>> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        Some(Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        ))
    }

    fn uid(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    /// A same-id restore succeeds and a DIFFERENT-id owner of the
    /// `(title, namespace)` slot is refused with `StoreError::Conflict`, leaving
    /// the foreign row's content byte-identical — the postgres twin of the
    /// sqlite contract (pg dialect divergence — RETURNING on a skipped
    /// `DO UPDATE … WHERE false` — is exactly where this class could reappear).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_or_conflict_same_id_ok_foreign_refused_pg_2887() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_admin("ai:curator");

        // Same-id restore into a free slot → Ok.
        let ns = uid("restore-ns");
        let orig_id = uid("orig");
        let orig = mem(&orig_id, &ns, "snap-title", "restored");
        let got = store
            .restore_or_conflict(&ctx, &orig)
            .await
            .expect("same-id restore ok");
        assert_eq!(got, orig_id);
        let row = store.get(&ctx, &orig_id).await.expect("get restored");
        assert_eq!(row.content, "restored");

        // A DIFFERENT id owns another slot; restoring a different original there
        // is refused and the foreign row is untouched.
        let ns2 = uid("foreign-ns");
        let foreign_id = uid("foreign");
        let foreign = mem(&foreign_id, &ns2, "shared", "FOREIGN durable content");
        store.store(&ctx, &foreign).await.expect("foreign stored");
        let orig2 = mem(&uid("orig2"), &ns2, "shared", "loser MUST NOT land");
        let err = store
            .restore_or_conflict(&ctx, &orig2)
            .await
            .expect_err("foreign owner must be refused");
        assert!(
            matches!(&err, StoreError::Conflict { id } if id == &foreign_id),
            "expected Conflict carrying the occupant id, got {err:?}"
        );
        let row = store.get(&ctx, &foreign_id).await.expect("get foreign");
        assert_eq!(
            row.content, "FOREIGN durable content",
            "the refused restore must not clobber the foreign pg row"
        );
    }
}
