// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

//! v1.0.0 #2948 — the create-funnel upsert append-only bypass fix.
//!
//! `db::insert` (the primary create funnel) resolves a `(title, namespace)`
//! collision with `ON CONFLICT(title, namespace) DO UPDATE SET content =
//! excluded.content`, which rewrites an existing memory's durable authored
//! `content` IN PLACE. Before #2948, with the append-only spine (#1823/#2947)
//! ARMED, that overwrite emitted NO signed `memory_revisions` leaf — the
//! hottest write path bypassed the tamper-evident ledger while every explicit
//! supersede/erase path recorded one. #2948 routes the overwrite through the
//! ledger: an armed conflict-merge appends EXACTLY ONE identity-only SUPERSEDE
//! leaf in the same transaction (5-agent vote `4d3ea1c5`, UNANIMOUS A1).
//!
//! This suite pins:
//!  * STEP 1 (empirical): the ON CONFLICT arm DOES overwrite `content` in place
//!    on an existing row (and preserves the existing row's id) — the finding
//!    the whole fix rests on, proven with a probe rather than asserted.
//!  * ARMED: an upsert-merge emits exactly one SUPERSEDE leaf (same id,
//!    `prior_version` = the pre-merge version, identity-only, signature valid);
//!    a FRESH insert emits none.
//!  * OFF (default): the same operations emit ZERO leaves (byte-identical).
//!  * The `Refuse` (`insert_no_overwrite`) and different-id `RestoreSameId`
//!    arms — which return a typed conflict WITHOUT overwriting — emit no leaf,
//!    while a same-id restore (a real content overwrite) does.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ed25519_dalek::{Signature, SigningKey};
use rand_core::OsRng;

/// `append_only` is a process-wide `AtomicBool`; serialize the tests that
/// toggle it so one test's expectation cannot race another's.
static FLAG_LOCK: Mutex<()> = Mutex::new(());
static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ensure_audit_key() {
    AUDIT_DIR.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("ai-memory-2948-")
            .tempdir()
            .expect("tempdir for audit sink");
        let signing = SigningKey::generate(&mut OsRng);
        ai_memory::governance::audit::init(dir.path(), Some(signing))
            .expect("install daemon audit key");
        dir
    });
}

#[derive(Debug, Clone)]
struct Leaf {
    memory_id: String,
    kind: String,
    prior_version: Option<i64>,
    namespace: String,
    agent_id: Option<String>,
    created_at: String,
    signature: Option<Vec<u8>>,
    prev_hash: Vec<u8>,
}

fn read_leaves(conn: &rusqlite::Connection) -> Vec<Leaf> {
    let mut stmt = conn
        .prepare(
            "SELECT memory_id, kind, prior_version, namespace, agent_id, \
                    created_at, signature, prev_hash \
             FROM memory_revisions ORDER BY sequence",
        )
        .expect("prepare leaf read");
    let rows = stmt
        .query_map([], |r| {
            Ok(Leaf {
                memory_id: r.get(0)?,
                kind: r.get(1)?,
                prior_version: r.get(2)?,
                namespace: r.get(3)?,
                agent_id: r.get(4)?,
                created_at: r.get(5)?,
                signature: r.get(6)?,
                prev_hash: r.get(7)?,
            })
        })
        .expect("query leaves");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect leaves")
}

fn leaf_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
        .expect("count leaves")
}

fn leaf_all_bytes(leaf: &Leaf) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(leaf.memory_id.as_bytes());
    buf.extend_from_slice(leaf.kind.as_bytes());
    if let Some(v) = leaf.prior_version {
        buf.extend_from_slice(v.to_string().as_bytes());
    }
    buf.extend_from_slice(leaf.namespace.as_bytes());
    if let Some(a) = &leaf.agent_id {
        buf.extend_from_slice(a.as_bytes());
    }
    buf.extend_from_slice(leaf.created_at.as_bytes());
    if let Some(s) = &leaf.signature {
        buf.extend_from_slice(s);
    }
    buf.extend_from_slice(&leaf.prev_hash);
    buf
}

fn leaf_bytes_contain(leaf: &Leaf, needle: &str) -> bool {
    let hay = leaf_all_bytes(leaf);
    let n = needle.as_bytes();
    !n.is_empty() && hay.windows(n.len()).any(|w| w == n)
}

fn verify_leaf_signature(leaf: &Leaf) {
    let vk = ai_memory::governance::audit::resolve_daemon_verifying_key()
        .expect("daemon verifying key must be installed");
    let sig_bytes = leaf
        .signature
        .as_ref()
        .expect("an armed leaf must carry a signature when the audit key is installed");
    let arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 signature must be 64 bytes");
    let sig = Signature::from_bytes(&arr);
    let kind =
        ai_memory::revisions::RecordKind::from_str_opt(&leaf.kind).expect("leaf kind is known");
    let msg = ai_memory::revisions::revision_leaf_signable_bytes(
        &leaf.memory_id,
        kind,
        leaf.prior_version,
        &leaf.namespace,
        leaf.agent_id.as_deref(),
        &leaf.created_at,
    );
    vk.verify_strict(&msg, &sig)
        .expect("revision leaf Ed25519 signature must verify under the daemon key");
}

fn open_mem_db() -> rusqlite::Connection {
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

fn make_memory(id: &str, title: &str, namespace: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: namespace.to_string(),
        tier: Tier::Mid,
        // Stamp an explicit agent_id so the SUPERSEDE leaf records a concrete
        // author (the incoming writer, matching `db::update`).
        metadata: serde_json::json!({ "agent_id": "ai:writer-2948" }),
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// STEP 1 — the empirical probe: prove the ON CONFLICT arm overwrites content
// in place (and keeps the EXISTING row's id). Flag-independent (SQL behavior).
// ---------------------------------------------------------------------------

#[test]
fn step1_on_conflict_overwrites_content_in_place_keeps_existing_id() {
    let _g = flag_guard();
    ai_memory::config::set_append_only(false);
    let conn = open_mem_db();

    let first = make_memory(
        "00000000-0000-0000-0000-00000000c001",
        "collide",
        "ns-2948-step1",
        "ORIGINAL-DURABLE-CONTENT",
    );
    let first_id = db::insert(&conn, &first).expect("first insert");

    // A SECOND store at the SAME (title, namespace) with a DIFFERENT id and
    // DIFFERENT content lands on the ON CONFLICT arm.
    let second = make_memory(
        "00000000-0000-0000-0000-00000000c002",
        "collide",
        "ns-2948-step1",
        "OVERWRITTEN-DURABLE-CONTENT",
    );
    let second_id = db::insert(&conn, &second).expect("second insert (upsert-merge)");

    // The surviving row keeps the EXISTING id (not the incoming one) ...
    assert_eq!(
        second_id, first_id,
        "the upsert-merge returns the EXISTING row id, not the incoming id"
    );
    // ... exactly one row exists for (title, namespace) ...
    let row_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["collide", "ns-2948-step1"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(row_count, 1, "the collision merged into one row, not two");
    // ... and its durable content was REWRITTEN IN PLACE.
    let head = db::get(&conn, &first_id)
        .expect("get")
        .expect("surviving row");
    assert_eq!(
        head.content, "OVERWRITTEN-DURABLE-CONTENT",
        "STEP 1 FINDING: the ON CONFLICT arm overwrote durable authored content in place"
    );
    assert_eq!(head.version, 2, "the upsert-merge bumped the version");
}

// ---------------------------------------------------------------------------
// ARMED — an upsert-merge emits exactly one identity-only SUPERSEDE leaf.
// ---------------------------------------------------------------------------

#[test]
fn armed_upsert_merge_emits_one_identity_only_supersede_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();

    const PRIOR: &str = "PRIOR-CONTENT-must-not-leak-into-the-leaf";
    let first = make_memory(
        "00000000-0000-0000-0000-00000000c101",
        "armed-collide",
        "ns-2948-armed",
        PRIOR,
    );
    let id = db::insert(&conn, &first).expect("first insert");
    assert_eq!(
        leaf_count(&conn),
        0,
        "a FRESH insert (no prior row) destroys nothing → no leaf"
    );

    // Re-store at the same (title, namespace) → conflict-merge overwrites.
    let second = make_memory(
        "00000000-0000-0000-0000-00000000c102",
        "armed-collide",
        "ns-2948-armed",
        "NEW-CONTENT-v2",
    );
    let merged_id = db::insert(&conn, &second).expect("upsert-merge");
    assert_eq!(merged_id, id, "same surviving id");

    let leaves = read_leaves(&conn);
    assert_eq!(
        leaves.len(),
        1,
        "the armed upsert-merge appends EXACTLY ONE SUPERSEDE leaf"
    );
    let leaf = &leaves[0];
    assert_eq!(leaf.kind, "SUPERSEDE");
    assert_eq!(
        leaf.memory_id, id,
        "the leaf is for the surviving memory id"
    );
    assert_eq!(leaf.namespace, "ns-2948-armed");
    assert_eq!(
        leaf.prior_version,
        Some(1),
        "the leaf records the pre-merge version"
    );
    assert_eq!(
        leaf.agent_id.as_deref(),
        Some("ai:writer-2948"),
        "the leaf records the incoming writer's agent id"
    );
    assert!(
        !leaf_bytes_contain(leaf, PRIOR),
        "the SUPERSEDE leaf must be identity-only — never carry prior content"
    );
    assert!(
        !leaf_bytes_contain(leaf, "NEW-CONTENT-v2"),
        "the leaf must not carry the new content either"
    );
    verify_leaf_signature(leaf);

    // The head carries the new content; the durable overwrite happened.
    let head = db::get(&conn, &id).expect("get").expect("head");
    assert_eq!(head.content, "NEW-CONTENT-v2");
    assert_eq!(head.version, 2);
}

#[test]
fn armed_repeated_restore_emits_one_leaf_per_merge() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();

    let base = make_memory(
        "00000000-0000-0000-0000-00000000c201",
        "reput",
        "ns-2948-repeat",
        "v1",
    );
    let id = db::insert(&conn, &base).expect("insert");
    for (i, body) in ["v2", "v3", "v4"].iter().enumerate() {
        let m = make_memory(
            &format!("00000000-0000-0000-0000-00000000c2{i:02}"),
            "reput",
            "ns-2948-repeat",
            body,
        );
        db::insert(&conn, &m).expect("re-store");
    }
    let leaves = read_leaves(&conn);
    assert_eq!(
        leaves.len(),
        3,
        "three conflict-merges → three SUPERSEDE leaves"
    );
    assert!(
        leaves
            .iter()
            .all(|l| l.kind == "SUPERSEDE" && l.memory_id == id)
    );
    // The prior_version advances 1 → 2 → 3 across the three merges.
    assert_eq!(
        leaves
            .iter()
            .filter_map(|l| l.prior_version)
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "each leaf records the version it superseded"
    );
}

// ---------------------------------------------------------------------------
// OFF (default) — ZERO leaves (byte-identical claim at the leaf layer).
// ---------------------------------------------------------------------------

#[test]
fn off_default_upsert_merge_emits_no_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(false);
    let conn = open_mem_db();

    let first = make_memory(
        "00000000-0000-0000-0000-00000000c301",
        "off-collide",
        "ns-2948-off",
        "off-v1",
    );
    db::insert(&conn, &first).expect("insert");
    let second = make_memory(
        "00000000-0000-0000-0000-00000000c302",
        "off-collide",
        "ns-2948-off",
        "off-v2",
    );
    db::insert(&conn, &second).expect("upsert-merge");

    assert_eq!(
        leaf_count(&conn),
        0,
        "with append_only OFF, an upsert-merge writes NO memory_revisions row"
    );
}

// ---------------------------------------------------------------------------
// The non-overwriting conflict arms emit no leaf; a same-id restore does.
// ---------------------------------------------------------------------------

#[test]
fn armed_refuse_arm_conflict_emits_no_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();

    let first = make_memory(
        "00000000-0000-0000-0000-00000000c401",
        "refuse-collide",
        "ns-2948-refuse",
        "kept",
    );
    db::insert(&conn, &first).expect("insert");
    assert_eq!(leaf_count(&conn), 0);

    // `insert_no_overwrite` (the #2771 fail-closed create) refuses a collision
    // WITHOUT overwriting → no content destroyed → no leaf.
    let clash = make_memory(
        "00000000-0000-0000-0000-00000000c402",
        "refuse-collide",
        "ns-2948-refuse",
        "would-clobber",
    );
    let err = db::insert_no_overwrite(&conn, &clash).expect_err("must refuse the collision");
    assert!(
        err.to_string().contains("CONFLICT"),
        "the refuse arm returns a typed conflict: {err}"
    );
    assert_eq!(
        leaf_count(&conn),
        0,
        "a refused (non-overwriting) collision must emit NO leaf"
    );
    // The existing content is byte-identical.
    let head = db::get(&conn, &first.id).expect("get").expect("row");
    assert_eq!(head.content, "kept");
}

#[test]
fn armed_restore_same_id_emits_leaf_foreign_id_does_not() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);
    let conn = open_mem_db();

    let id = "00000000-0000-0000-0000-00000000c501";
    let first = make_memory(id, "restore-collide", "ns-2948-restore", "v1");
    db::insert(&conn, &first).expect("insert");
    assert_eq!(leaf_count(&conn), 0);

    // Same-id restore → real in-place content overwrite → ONE SUPERSEDE leaf.
    let same = make_memory(id, "restore-collide", "ns-2948-restore", "v2");
    db::insert_restore_same_id(&conn, &same).expect("same-id restore");
    let after_same = read_leaves(&conn);
    assert_eq!(
        after_same.len(),
        1,
        "same-id restore overwrote content → one leaf"
    );
    assert_eq!(after_same[0].kind, "SUPERSEDE");
    assert_eq!(after_same[0].memory_id, id);

    // A DIFFERENT id claiming the same (title, namespace) is refused by the CAS
    // WITHOUT overwriting → no additional leaf.
    let foreign = make_memory(
        "00000000-0000-0000-0000-00000000c502",
        "restore-collide",
        "ns-2948-restore",
        "foreign-clobber",
    );
    let err = db::insert_restore_same_id(&conn, &foreign).expect_err("foreign id must be refused");
    assert!(
        err.to_string().contains("CONFLICT"),
        "typed conflict: {err}"
    );
    assert_eq!(
        read_leaves(&conn).len(),
        1,
        "the refused foreign-id restore adds NO leaf"
    );
    let head = db::get(&conn, id).expect("get").expect("row");
    assert_eq!(
        head.content, "v2",
        "the foreign restore left content untouched"
    );
}
