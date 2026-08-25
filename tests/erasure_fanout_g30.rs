// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W2 / gap G30 — erasure fanout: `forget` purges the non-cascaded
//! derived-store leaks (`federation_push_dlq` cleartext payload,
//! `transcript_line_dedup` content-hash oracle) in the same transaction.
//!
//! These channels survive a plain cascade DELETE because the DLQ keys its
//! row by a deliberately NON-FK `memory_id` and the dedup table has no FK /
//! cascade at all — so pre-W2 a forgotten secret lingered in both. (The
//! HNSW-eviction + federated-tombstone halves of W2 are covered separately.)

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};

fn seed_memory(conn: &rusqlite::Connection, namespace: &str, title: &str, content: &str) -> String {
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:test:g30" }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn seed_dlq_row(conn: &rusqlite::Connection, memory_id: &str, payload: &str) {
    conn.execute(
        "INSERT INTO federation_push_dlq \
         (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
         VALUES (?1, ?2, ?3, 1, 'simulated', '2026-06-28T00:00:00Z')",
        rusqlite::params![memory_id, "peer-1", payload],
    )
    .expect("insert dlq row");
}

fn seed_dedup_row(conn: &rusqlite::Connection, memory_id: &str, sha: &[u8]) {
    conn.execute(
        "INSERT INTO transcript_line_dedup (sha256, memory_id, host_kind, recovered_at) \
         VALUES (?1, ?2, 'claude-code', 0)",
        rusqlite::params![sha, memory_id],
    )
    .expect("insert dedup row");
}

fn dlq_count(conn: &rusqlite::Connection, memory_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM federation_push_dlq WHERE memory_id = ?1",
        rusqlite::params![memory_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn dedup_count(conn: &rusqlite::Connection, memory_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM transcript_line_dedup WHERE memory_id = ?1",
        rusqlite::params![memory_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn mem_count(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .unwrap()
}

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("g30.db");
    (dir, path)
}

/// Bulk `db::forget` purges the DLQ + dedup leaks for the forgotten rows.
#[test]
fn forget_purges_dlq_and_transcript_dedup_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(
        &conn,
        "g30-erase",
        "secret-note",
        "AKIAIOSFODNN7EXAMPLE leaked",
    );
    seed_dlq_row(&conn, &id, "{\"content\":\"AKIAIOSFODNN7EXAMPLE leaked\"}");
    seed_dedup_row(&conn, &id, &[1u8, 2, 3, 4]);

    assert_eq!(dlq_count(&conn, &id), 1, "precondition: DLQ row present");
    assert_eq!(
        dedup_count(&conn, &id),
        1,
        "precondition: dedup row present"
    );

    let deleted = db::forget(&conn, Some("g30-erase"), None, None, false).expect("forget");
    assert_eq!(deleted, 1, "the memory must be forgotten");

    assert_eq!(mem_count(&conn, &id), 0, "G30: the row must be gone");
    assert_eq!(
        dlq_count(&conn, &id),
        0,
        "G30.1: the federation_push_dlq cleartext payload must be purged on forget"
    );
    assert_eq!(
        dedup_count(&conn, &id),
        0,
        "G30: the transcript_line_dedup content-hash oracle must be purged on forget"
    );
}

/// The purge is SCOPED to the forgotten set — a DLQ / dedup row for an
/// UNRELATED memory (different namespace) survives.
#[test]
fn forget_does_not_over_purge_other_namespaces_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let keep_id = seed_memory(&conn, "g30-keep", "keep-note", "benign content here");
    seed_dlq_row(&conn, &keep_id, "{\"content\":\"benign\"}");
    seed_dedup_row(&conn, &keep_id, &[9u8, 9, 9, 9]);

    let gone_id = seed_memory(&conn, "g30-drop", "drop-note", "drop me");
    seed_dlq_row(&conn, &gone_id, "{\"content\":\"drop\"}");

    // Forget ONLY the g30-drop namespace.
    db::forget(&conn, Some("g30-drop"), None, None, false).expect("forget");

    assert_eq!(dlq_count(&conn, &gone_id), 0, "forgotten row's DLQ purged");
    assert_eq!(
        dlq_count(&conn, &keep_id),
        1,
        "G30: another namespace's pending DLQ row must NOT be over-purged"
    );
    assert_eq!(
        dedup_count(&conn, &keep_id),
        1,
        "G30: another namespace's dedup row must NOT be over-purged"
    );
    assert_eq!(mem_count(&conn, &keep_id), 1, "the kept memory survives");
}

fn tombstone_count(conn: &rusqlite::Connection, memory_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM forget_tombstones WHERE memory_id = ?1",
        rusqlite::params![memory_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// W2.3 — forget records a tombstone, and a simulated peer re-push of the
/// forgotten row via `insert_if_newer` (newer `updated_at`) is REJECTED, not
/// resurrected (tombstone-wins).
#[test]
fn forget_tombstone_blocks_resurrection_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(&conn, "g30-resurrect", "rnote", "original secret content");
    db::forget(&conn, Some("g30-resurrect"), None, None, false).expect("forget");

    assert_eq!(
        tombstone_count(&conn, &id),
        1,
        "G30 W2.3: forget must record a FORGET tombstone for the id"
    );
    assert_eq!(mem_count(&conn, &id), 0, "the row is gone");

    // A peer that still holds the row re-pushes it with a far-future
    // updated_at (so LWW would normally win) via the federation receive funnel.
    let revived = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: "g30-resurrect".to_string(),
        title: "rnote".to_string(),
        content: "original secret content".to_string(),
        updated_at: "2999-01-01T00:00:00Z".to_string(),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    };
    let returned = db::insert_if_newer(&conn, &revived).expect("insert_if_newer");
    assert_eq!(
        returned, id,
        "tombstone-wins: the id is returned without an insert"
    );
    assert_eq!(
        mem_count(&conn, &id),
        0,
        "G30 W2.3: a forgotten row must NOT be resurrected by a peer re-push"
    );
}

/// W2 acceptance remanence-probe: after a hard forget (archive=false) the
/// cleartext content appears in NO queryable store (memories, DLQ payload,
/// archive).
#[test]
fn forget_leaves_no_cleartext_remanence_g30() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");
    let secret = "REMANENCE-PROBE-AKIAIOSFODNN7EXAMPLE-xyz";

    let id = seed_memory(&conn, "g30-remanence", "rnote", secret);
    seed_dlq_row(&conn, &id, &format!("{{\"content\":\"{secret}\"}}"));

    db::forget(&conn, Some("g30-remanence"), None, None, false).expect("forget");

    let like = format!("%{secret}%");
    let in_memories: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE content LIKE ?1",
            rusqlite::params![like],
            |r| r.get(0),
        )
        .unwrap();
    let in_dlq: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM federation_push_dlq WHERE payload_json LIKE ?1",
            rusqlite::params![like],
            |r| r.get(0),
        )
        .unwrap();
    let in_archive: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE content LIKE ?1",
            rusqlite::params![like],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(in_memories, 0, "G30: cleartext gone from memories");
    assert_eq!(in_dlq, 0, "G30: cleartext gone from the DLQ payload");
    assert_eq!(
        in_archive, 0,
        "G30: a hard forget (archive=false) must not leave the content in the archive"
    );
}

/// #1848 reconciled to #1771 (5-agent vote 4d3ea1c5, option B) — an
/// OPERATOR-initiated restore of a forgotten (tombstoned) memory is an
/// AUTHORIZED un-forget and MUST round-trip (the #1771 recoverable-delete
/// contract). The G30 tombstone gates only AUTOMATIC peer-triggered
/// resurrection (the federation `/sync/push` restores[] chokepoint + the LWW
/// re-push gate), NOT the operator's own restore. This pins the revert of the
/// over-broad original #1848 storage-layer guard against silent reintroduction.
#[test]
fn operator_restore_unblocked_after_forget_tombstone_1848() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(&conn, "g30-restore", "rnote", "original secret content");
    // archive=true: the archived copy survives the forget (+ a tombstone).
    db::forget(&conn, Some("g30-restore"), None, None, true).expect("forget");
    assert_eq!(
        tombstone_count(&conn, &id),
        1,
        "#1848: forget still records a tombstone (gates the federation path)"
    );
    assert_eq!(
        mem_count(&conn, &id),
        0,
        "the live row is gone after forget"
    );

    // Operator un-forget via the unscoped restore path SUCCEEDS.
    let restored = db::restore_archived(&conn, &id).expect("restore_archived");
    assert!(
        restored,
        "#1848/#1771: operator restore of a forgotten memory must SUCCEED (authorized un-forget)"
    );
    assert_eq!(
        mem_count(&conn, &id),
        1,
        "#1771: the memory is live again after the operator restore"
    );

    // Owner-scoped operator restore path likewise succeeds (re-forget first to
    // exercise it on a fresh tombstoned id).
    db::forget(&conn, Some("g30-restore"), None, None, true).expect("re-forget");
    assert_eq!(mem_count(&conn, &id), 0, "gone again after re-forget");
    let restored_caller =
        db::restore_archived_for_caller(&conn, &id, "ai:test:g30").expect("restore_for_caller");
    assert!(
        restored_caller,
        "#1848/#1771: owner-scoped operator restore must also succeed"
    );
    assert_eq!(
        mem_count(&conn, &id),
        1,
        "live again after owner-scoped restore"
    );
}

/// #1848 (option B) — the federation `/sync/push` restores[] chokepoint
/// (`src/handlers/federation_receive.rs`) consults `db::memory_is_tombstoned`
/// BEFORE `db::restore_archived` and skips (noop) when true, so a PEER cannot
/// undo a local forget by pushing a restore. This pins the gate primitive: a
/// forgotten id reports tombstoned (→ the federation loop no-ops) EVEN THOUGH
/// its archived copy exists (so it is the tombstone, not a missing archive,
/// that gates the peer path) — while the operator path stays open (above).
#[test]
fn federation_restore_gate_primitive_blocks_tombstoned_1848() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(&conn, "g30-fedrestore", "rnote", "peer-resurrect attempt");
    db::forget(&conn, Some("g30-fedrestore"), None, None, true).expect("forget");

    // The archived copy is present (forget archived it)...
    let archived: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        archived, 1,
        "the archived copy exists after forget(archive=true)"
    );

    // ...yet the federation guard primitive reports it tombstoned, so the
    // restores[] loop takes its `noop += 1; continue;` branch and never reaches
    // restore_archived — a peer-pushed restore cannot resurrect it.
    assert!(
        db::memory_is_tombstoned(&conn, &id).expect("tombstone check"),
        "#1848: the federation restore gate must see the forgotten id as tombstoned"
    );
    assert_eq!(mem_count(&conn, &id), 0, "the row stays forgotten");
}

/// #3192 — single-row `db::delete` records a forget tombstone, and a
/// simulated peer re-push via `insert_if_newer` with a *fresher*
/// `updated_at` is REJECTED (tombstone-wins). Pre-fix the G30
/// resurrection guard found no tombstone and the row came back.
///
/// This is the production funnel for MCP `memory_delete`, HTTP DELETE,
/// CLI `delete`, `SqliteStore::delete`, `SqliteStore::apply_remote_deletion`,
/// and the inbound federation `deletions[]` lane
/// (`src/handlers/federation_receive.rs` → `db::delete`).
#[test]
fn delete_tombstone_blocks_insert_if_newer_3192() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(&conn, "g30-delete", "dnote", "original secret content");
    assert!(
        db::delete(&conn, &id).expect("delete"),
        "#3192: delete of a live row must report true"
    );

    assert_eq!(
        tombstone_count(&conn, &id),
        1,
        "#3192: db::delete must record a forget_tombstones row"
    );
    assert!(
        db::memory_is_tombstoned(&conn, &id).expect("tombstone check"),
        "#3192: memory_is_tombstoned must see the deleted id"
    );
    assert_eq!(mem_count(&conn, &id), 0, "the row is gone");

    let revived = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: "g30-delete".to_string(),
        title: "dnote".to_string(),
        content: "original secret content".to_string(),
        updated_at: "2999-01-01T00:00:00Z".to_string(),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    };
    let returned = db::insert_if_newer(&conn, &revived).expect("insert_if_newer");
    assert_eq!(
        returned, id,
        "tombstone-wins: the id is returned without an insert"
    );
    assert_eq!(
        mem_count(&conn, &id),
        0,
        "#3192: a deleted row must NOT be resurrected by a fresher peer re-push"
    );
}

/// #3192 — inbound federation `deletions[]` is `db::delete` on sqlite
/// (`federation_receive.rs` + `SqliteStore::apply_remote_deletion`). Pin
/// that the same primitive leaves a tombstone the G30 restore-gate
/// consults, so a peer-pushed restore cannot undo a federated deletion.
#[test]
fn federation_inbound_deletion_leaves_tombstone_3192() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");

    let id = seed_memory(&conn, "g30-feddel", "dnote", "peer-delete target");
    // The inbound lane calls db::delete with the id from deletions[].
    assert!(
        db::delete(&conn, &id).expect("inbound deletions[] apply"),
        "existing row is removed"
    );
    assert!(
        db::memory_is_tombstoned(&conn, &id).expect("tombstone check"),
        "#3192: inbound deletions[] of a locally-held id must leave a tombstone"
    );
    assert_eq!(mem_count(&conn, &id), 0, "the row stays deleted");
}

/// #3192 — a delete of a never-seen id stays a no-op and does NOT mint
/// a tombstone (no namespace to bind). First-arrival of that id later
/// is a fresh write, not a resurrection.
#[test]
fn delete_missing_does_not_tombstone_3192() {
    let (_dir, path) = fresh_db();
    let conn = db::open(&path).expect("open");
    let missing = uuid::Uuid::new_v4().to_string();
    assert!(
        !db::delete(&conn, &missing).expect("delete missing"),
        "missing id returns false"
    );
    assert!(
        !db::memory_is_tombstoned(&conn, &missing).expect("tombstone check"),
        "#3192: a never-seen id must not grow a forget_tombstones row"
    );
}

/// The FORGET tombstone signable bytes are deterministic + domain-separated.
#[test]
fn forget_tombstone_signable_bytes_deterministic_g30() {
    let first = db::forget_tombstone_signable_bytes("id-1", "ns-a", "2026-06-28T00:00:00Z");
    let again = db::forget_tombstone_signable_bytes("id-1", "ns-a", "2026-06-28T00:00:00Z");
    assert_eq!(first, again, "same inputs → same bytes");
    let other_id = db::forget_tombstone_signable_bytes("id-2", "ns-a", "2026-06-28T00:00:00Z");
    assert_ne!(first, other_id, "different memory_id → different bytes");
    assert!(
        first.starts_with(b"forget-tombstone-v1\x00"),
        "domain-separation prefix present"
    );
    // No field-boundary ambiguity: ("ab","c") must not equal ("a","bc").
    let split_ab_c = db::forget_tombstone_signable_bytes("ab", "c", "t");
    let split_a_bc = db::forget_tombstone_signable_bytes("a", "bc", "t");
    assert_ne!(
        split_ab_c, split_a_bc,
        "null-delimited fields are unambiguous"
    );
}
