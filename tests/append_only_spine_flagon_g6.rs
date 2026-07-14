// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_update,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! v0.9.0 G6 (#1823) STEP 3 — the FLAG-ON regression suite.
//!
//! Step 2 routed every memory-mutation primitive through the signed
//! `memory_revisions` ledger, gated so `append_only` OFF is byte-identical
//! to the legacy path. The static guard proved every site is *routed*; it
//! does NOT prove the routing *fires*. These tests close that gap with the
//! flag turned ON (`config::set_append_only(true)`), asserting that each
//! sanctioned primitive writes the EXACT leaf the design promises — the
//! claims-discipline §26.5 "no `works` without a test" bar.
//!
//! What each test pins:
//!
//!  1. `update_with_expected_version` (the PUT / content-supersede path)
//!     writes EXACTLY ONE `SUPERSEDE` leaf for the SAME memory id; the head
//!     row keeps its id; the leaf is IDENTITY-ONLY (the prior content
//!     string is absent from the leaf row bytes); the Ed25519 signature
//!     verifies under the daemon audit key.
//!  2. `bind_agent_pubkey` + `revoke_agent_pubkey` each write one
//!     `SUPERSEDE` leaf.
//!  3. `forget` writes a `FORGET` leaf AND the `forget_tombstone`
//!     (`memory_is_tombstoned` stays true) AND scrubs the row (content gone)
//!     — right-to-be-forgotten preserved; no content in the leaf.
//!  4. `delete` (the sqlite `apply_remote_deletion` delegate) writes a
//!     `TOMBSTONE` leaf, identity-only. The postgres twin pins the headline
//!     #12962 atomic remote-erase audit-leaf fix.
//!  5. CONVERGENCE: a same-id supersede followed by a federation merge of a
//!     concurrent head converges to the IDENTICAL (title, namespace) winner
//!     with the flag ON vs OFF — the leaf emission never perturbs which head
//!     the `EXCLUDED.id > memories.id` tiebreak picks (the path-a property).
//!  6. `gc` / `size_gc` / `archive_memory` each emit their
//!     `EXPIRE` / `EVICT` / `ARCHIVE` leaf.
//!
//! NEGATIVE: with the flag OFF the same operations write ZERO
//! `memory_revisions` rows — re-confirming the step-2 byte-identical claim
//! at the leaf layer.
//!
//! ## Concurrency
//!
//! `append_only` and the daemon audit key are process-wide. The sqlite
//! tests serialize on a file-local `Mutex` and set the flag per test; the
//! audit key is installed once via a `OnceLock`. The postgres twins are
//! `#[cfg(feature = "sal-postgres")]` + `#[ignore]` (a live instance is
//! required), mirroring `tests/secret_screen_postgres_parity_g29.rs`.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ed25519_dalek::{Signature, SigningKey};
use rand_core::OsRng;

// ---------------------------------------------------------------------------
// Process-wide test fixtures (flag + audit key are global singletons)
// ---------------------------------------------------------------------------

/// Serializes the sqlite tests so one test's `set_append_only` cannot race
/// another's expectation (the flag is a process-wide `AtomicBool`).
static FLAG_LOCK: Mutex<()> = Mutex::new(());

/// Keeps the audit sink's temp dir alive for the whole process so the
/// installed `DAEMON_AUDIT_KEY` (an `OnceLock`, first-install-wins) stays
/// valid for signature verification across every test.
static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    // Recover from a poisoned lock so one failing test does not cascade-mask
    // every later test behind a PoisonError.
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install a process-wide daemon audit signing key exactly once, so the
/// signed leaves carry a real Ed25519 signature `resolve_daemon_verifying_key`
/// can check. Idempotent (the `OnceLock` swallows later installs).
fn ensure_audit_key() {
    AUDIT_DIR.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("ai-memory-g6-flagon-")
            .tempdir()
            .expect("tempdir for audit sink");
        let signing = SigningKey::generate(&mut OsRng);
        ai_memory::governance::audit::init(dir.path(), Some(signing))
            .expect("install daemon audit key");
        dir
    });
}

// ---------------------------------------------------------------------------
// Leaf helpers (read the `memory_revisions` ledger directly)
// ---------------------------------------------------------------------------

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

/// Every stored byte of one leaf row, for the identity-only assertion: a
/// content fingerprint would re-leak an erased row, so the prior content
/// must be absent from EVERY column (including the signature + chain hash).
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

/// True when `needle`'s bytes appear anywhere in the leaf row's stored bytes.
fn leaf_bytes_contain(leaf: &Leaf, needle: &str) -> bool {
    let hay = leaf_all_bytes(leaf);
    let n = needle.as_bytes();
    !n.is_empty() && hay.windows(n.len()).any(|w| w == n)
}

/// Verify the leaf's Ed25519 signature under the daemon audit key, rebuilding
/// the canonical identity-only signable bytes from the stored columns alone
/// (the same path an auditor / federation receiver uses).
fn verify_leaf_signature(leaf: &Leaf) {
    let vk = ai_memory::governance::audit::resolve_daemon_verifying_key()
        .expect("daemon verifying key must be installed");
    let sig_bytes = leaf
        .signature
        .as_ref()
        .expect("a flag-ON leaf must carry a signature when the audit key is installed");
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

// ---------------------------------------------------------------------------
// Memory builders
// ---------------------------------------------------------------------------

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
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Content update (PUT) → exactly one SUPERSEDE leaf, same id, identity-only
// ---------------------------------------------------------------------------

#[test]
fn content_update_writes_one_identity_only_supersede_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    const PRIOR_CONTENT: &str = "PRIOR-SECRET-CONTENT-v1-do-not-leak";
    let mem = make_memory(
        "00000000-0000-0000-0000-0000000000a1",
        "put-target",
        "ns-flagon-put",
        PRIOR_CONTENT,
    );
    let id = db::insert(&conn, &mem).expect("insert");
    assert_eq!(
        leaf_count(&conn),
        0,
        "a plain insert is not a revision leaf"
    );

    let (found, content_changed) = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("brand-new-body-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None, // #1834 valid_until
    )
    .expect("content update");
    assert!(found && content_changed, "the content update must land");

    let leaves = read_leaves(&conn);
    assert_eq!(
        leaves.len(),
        1,
        "a content supersede writes EXACTLY ONE leaf (the in_place_edit \
         archive snapshot is NOT a leaf)"
    );
    let leaf = &leaves[0];
    assert_eq!(leaf.kind, "SUPERSEDE");
    assert_eq!(leaf.memory_id, id, "the leaf is for the same memory id");
    assert_eq!(leaf.namespace, "ns-flagon-put");
    assert_eq!(
        leaf.prior_version,
        Some(1),
        "the leaf records the pre-supersede version"
    );

    // The head row keeps the SAME id and carries the new content.
    let head = db::get(&conn, &id).expect("get").expect("head present");
    assert_eq!(head.id, id, "supersede is SAME-id in-place (path-a)");
    assert_eq!(head.content, "brand-new-body-v2");
    assert_eq!(head.version, 2, "the version was bumped in place");

    // IDENTITY-ONLY: the prior content must be absent from the leaf bytes.
    assert!(
        !leaf_bytes_contain(leaf, PRIOR_CONTENT),
        "the leaf must NEVER carry (a fingerprint of) the prior content"
    );

    // The signature verifies under the daemon audit key.
    verify_leaf_signature(leaf);
}

// ---------------------------------------------------------------------------
// 2. bind / revoke agent pubkey → one SUPERSEDE leaf each
// ---------------------------------------------------------------------------

#[test]
fn bind_and_revoke_pubkey_each_write_one_supersede_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    let agent = "ai:flagon-bob";
    db::register_agent(&conn, agent, "llm", &[]).expect("register agent");
    assert_eq!(
        leaf_count(&conn),
        0,
        "registering an agent is an insert, not a revision leaf"
    );

    db::bind_agent_pubkey(&conn, agent, "dummy-base64-pubkey-AAAA").expect("bind pubkey");
    let after_bind = read_leaves(&conn);
    assert_eq!(after_bind.len(), 1, "bind writes one leaf");
    assert_eq!(after_bind[0].kind, "SUPERSEDE");
    verify_leaf_signature(&after_bind[0]);

    db::revoke_agent_pubkey(&conn, agent).expect("revoke pubkey");
    let after_revoke = read_leaves(&conn);
    assert_eq!(after_revoke.len(), 2, "revoke writes a second leaf");
    assert_eq!(after_revoke[1].kind, "SUPERSEDE");
    assert_eq!(
        after_revoke[0].memory_id, after_revoke[1].memory_id,
        "both leaves concern the same registration row"
    );
    verify_leaf_signature(&after_revoke[1]);
}

// ---------------------------------------------------------------------------
// 3. forget → FORGET leaf + tombstone + content scrub
// ---------------------------------------------------------------------------

#[test]
fn forget_writes_forget_leaf_keeps_tombstone_and_scrubs_content() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    const SECRET: &str = "ERASE-ME-RIGHT-TO-BE-FORGOTTEN-SECRET";
    let mem = make_memory(
        "00000000-0000-0000-0000-0000000000f3",
        "forgettable",
        "ns-flagon-forget",
        SECRET,
    );
    let id = db::insert(&conn, &mem).expect("insert");

    let removed = db::forget(&conn, Some("ns-flagon-forget"), None, None, false).expect("forget");
    assert_eq!(removed, 1, "the one matching row is forgotten");

    let leaves = read_leaves(&conn);
    assert_eq!(leaves.len(), 1, "forget writes exactly one FORGET leaf");
    let leaf = &leaves[0];
    assert_eq!(leaf.kind, "FORGET");
    assert_eq!(leaf.memory_id, id);
    assert_eq!(leaf.namespace, "ns-flagon-forget");
    verify_leaf_signature(leaf);

    // Right-to-be-forgotten preserved: the tombstone stays, the row is gone.
    assert!(
        db::memory_is_tombstoned(&conn, &id).expect("tombstone check"),
        "the forget_tombstone must remain so the id cannot be resurrected"
    );
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "the live row (and its content) must be scrubbed"
    );

    // No content fingerprint in the leaf.
    assert!(
        !leaf_bytes_contain(leaf, SECRET),
        "the FORGET leaf must not carry the erased content"
    );
}

// ---------------------------------------------------------------------------
// 4. remote deletion (the sqlite apply_remote_deletion delegate) → TOMBSTONE
// ---------------------------------------------------------------------------

#[test]
fn remote_deletion_writes_identity_only_tombstone_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    let conn = open_mem_db();
    const REMOTE_CONTENT: &str = "REMOTE-ROW-CONTENT-must-not-leak";
    let mem = make_memory(
        "00000000-0000-0000-0000-0000000000d4",
        "remote-doomed",
        "ns-flagon-remote",
        REMOTE_CONTENT,
    );
    let id = db::insert(&conn, &mem).expect("insert");

    // `SqliteStore::apply_remote_deletion` delegates to this free fn; the
    // capture-then-compact TOMBSTONE leaf is the audit trail a federation
    // erase must leave (no silent destroy).
    let deleted = db::delete(&conn, &id).expect("delete");
    assert!(deleted, "the row was deleted");

    let leaves = read_leaves(&conn);
    assert_eq!(
        leaves.len(),
        1,
        "the remote delete leaves one TOMBSTONE leaf"
    );
    let leaf = &leaves[0];
    assert_eq!(leaf.kind, "TOMBSTONE");
    assert_eq!(leaf.memory_id, id);
    assert!(
        !leaf_bytes_contain(leaf, REMOTE_CONTENT),
        "a TOMBSTONE leaf is identity-only"
    );
    verify_leaf_signature(leaf);
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "the row is compacted away after the leaf is captured"
    );
}

// ---------------------------------------------------------------------------
// 5. Convergence: same-id supersede does not perturb the federation winner
// ---------------------------------------------------------------------------

/// Run the minimal both-heads case under one flag state and return
/// `(winner_id, winner_content, leaf_count)`.
///
/// A local head is inserted, superseded in place (path-a: SAME id), then a
/// concurrent inbound head that ties on `updated_at` but sorts HIGHER by id
/// is merged. The `ON CONFLICT(title, namespace)` tiebreak
/// (`excluded.id > memories.id`) must therefore pick the inbound content —
/// and because the supersede kept the local id stable, that decision is
/// deterministic and independent of the flag.
fn run_convergence_case(flag: bool) -> (String, String, i64) {
    ai_memory::config::set_append_only(flag);
    let conn = open_mem_db();

    let local_id = "aaaa-local-head";
    let mut local = make_memory(local_id, "conv-title", "ns-conv", "local-v1");
    // Anchor the pre-supersede timestamp in the past so the in-place
    // supersede strictly bumps updated_at to "now".
    local.created_at = "2020-01-01T00:00:00Z".to_string();
    local.updated_at = "2020-01-01T00:00:00Z".to_string();
    db::insert(&conn, &local).expect("insert local head");

    // Same-id in-place supersede (the path-a property under test).
    let (found, changed) = db::update_with_expected_version(
        &conn,
        local_id,
        None,
        Some("local-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None, // #1834 valid_until
    )
    .expect("supersede local head");
    assert!(found && changed);

    // Read back the superseded head's updated_at and construct a concurrent
    // inbound head that TIES on it, with a strictly higher id.
    let head = db::get(&conn, local_id)
        .expect("get")
        .expect("head present");
    assert_eq!(head.id, local_id, "supersede kept the id stable");
    let head_updated_at = head.updated_at;
    let mut inbound = make_memory("zzzz-remote-head", "conv-title", "ns-conv", "remote-v2");
    inbound.updated_at.clone_from(&head_updated_at);
    inbound.created_at = head_updated_at;
    db::insert_if_newer(&conn, &inbound).expect("federation merge");

    let (winner_id, winner_content): (String, String) = conn
        .query_row(
            "SELECT id, content FROM memories WHERE title = ?1 AND namespace = ?2",
            rusqlite::params!["conv-title", "ns-conv"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read the single surviving head");
    (winner_id, winner_content, leaf_count(&conn))
}

#[test]
fn same_id_supersede_converges_identically_flag_on_vs_off() {
    let _g = flag_guard();
    ensure_audit_key();

    let on = run_convergence_case(true);
    let off = run_convergence_case(false);

    // The merge picks the IDENTICAL winner regardless of the flag.
    assert_eq!(on.0, off.0, "same (title, namespace) winner id");
    assert_eq!(on.1, off.1, "same winner content");

    // The winner is well-defined and the id tiebreak actually fired (the
    // assertion is not vacuous): the inbound content won on excluded.id >
    // memories.id, and the surviving row kept the stable local id.
    assert_eq!(on.0, "aaaa-local-head", "the in-place head id is stable");
    assert_eq!(
        on.1, "remote-v2",
        "the higher-id concurrent head wins the updated_at tie"
    );

    // The ONLY divergence between the two runs is the audit leaf: ON emits a
    // supersede leaf, OFF emits nothing.
    assert_eq!(on.2, 1, "flag ON emits the supersede leaf");
    assert_eq!(off.2, 0, "flag OFF stays byte-identical at the leaf layer");
}

// ---------------------------------------------------------------------------
// 6. gc / size_gc / archive each emit their EXPIRE / EVICT / ARCHIVE leaf
// ---------------------------------------------------------------------------

#[test]
fn gc_size_gc_and_archive_each_emit_their_leaf() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(true);

    // ARCHIVE — explicit archive_memory.
    {
        let conn = open_mem_db();
        let mem = make_memory(
            "00000000-0000-0000-0000-00000000a601",
            "archive-target",
            "ns-archive",
            "archive-body",
        );
        let id = db::insert(&conn, &mem).expect("insert");
        let moved = db::archive_memory(&conn, &id, Some("archive")).expect("archive");
        assert!(moved);
        let leaves = read_leaves(&conn);
        assert_eq!(leaves.len(), 1, "archive writes one leaf");
        assert_eq!(leaves[0].kind, "ARCHIVE");
        assert_eq!(leaves[0].memory_id, id);
        verify_leaf_signature(&leaves[0]);
    }

    // EXPIRE — TTL gc over a past-expiry row.
    {
        let conn = open_mem_db();
        let mut mem = make_memory(
            "00000000-0000-0000-0000-00000000a602",
            "expire-target",
            "ns-expire",
            "expire-body",
        );
        mem.expires_at = Some("2000-01-01T00:00:00Z".to_string());
        let id = db::insert(&conn, &mem).expect("insert");
        let reaped = db::gc(&conn, false).expect("gc");
        assert_eq!(reaped, 1, "the expired row is reaped");
        let leaves = read_leaves(&conn);
        assert_eq!(leaves.len(), 1, "gc writes one EXPIRE leaf");
        assert_eq!(leaves[0].kind, "EXPIRE");
        assert_eq!(leaves[0].memory_id, id);
        verify_leaf_signature(&leaves[0]);
    }

    // EVICT — byte-cap size_gc with archive=false (the hard-delete branch).
    {
        let conn = open_mem_db();
        let mem = make_memory(
            "00000000-0000-0000-0000-00000000a603",
            "evict-target",
            "ns-evict",
            "evict-body-large-enough-to-exceed-the-one-byte-cap",
        );
        let id = db::insert(&conn, &mem).expect("insert");
        let evicted = db::size_gc(&conn, "ns-evict", 1, false).expect("size_gc");
        assert_eq!(evicted, 1, "the over-cap row is evicted");
        let leaves = read_leaves(&conn);
        assert_eq!(leaves.len(), 1, "size_gc writes one EVICT leaf");
        assert_eq!(leaves[0].kind, "EVICT");
        assert_eq!(leaves[0].memory_id, id);
        verify_leaf_signature(&leaves[0]);
    }
}

// ---------------------------------------------------------------------------
// NEGATIVE: flag OFF writes ZERO revision leaves (byte-identical claim)
// ---------------------------------------------------------------------------

#[test]
fn flag_off_writes_no_revision_leaves() {
    let _g = flag_guard();
    ensure_audit_key();
    ai_memory::config::set_append_only(false);

    let conn = open_mem_db();

    // Content supersede.
    let put = make_memory(
        "00000000-0000-0000-0000-0000000000b1",
        "off-put",
        "ns-off",
        "off-v1",
    );
    let put_id = db::insert(&conn, &put).expect("insert");
    db::update_with_expected_version(
        &conn,
        &put_id,
        None,
        Some("off-v2"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(1),
        None, // #1834 valid_until
    )
    .expect("update");

    // bind / revoke.
    db::register_agent(&conn, "ai:off-agent", "llm", &[]).expect("register");
    db::bind_agent_pubkey(&conn, "ai:off-agent", "off-pubkey-AAAA").expect("bind");
    db::revoke_agent_pubkey(&conn, "ai:off-agent").expect("revoke");

    // tombstone (delete) + forget.
    let del = make_memory(
        "00000000-0000-0000-0000-0000000000b2",
        "off-del",
        "ns-off-del",
        "off-del-body",
    );
    let del_id = db::insert(&conn, &del).expect("insert");
    db::delete(&conn, &del_id).expect("delete");

    let forget_mem = make_memory(
        "00000000-0000-0000-0000-0000000000b3",
        "off-forget",
        "ns-off-forget",
        "off-forget-body",
    );
    db::insert(&conn, &forget_mem).expect("insert");
    db::forget(&conn, Some("ns-off-forget"), None, None, false).expect("forget");

    // archive + gc + size_gc.
    let arch = make_memory(
        "00000000-0000-0000-0000-0000000000b4",
        "off-arch",
        "ns-off-arch",
        "off-arch-body",
    );
    let arch_id = db::insert(&conn, &arch).expect("insert");
    db::archive_memory(&conn, &arch_id, Some("archive")).expect("archive");

    let mut exp = make_memory(
        "00000000-0000-0000-0000-0000000000b5",
        "off-exp",
        "ns-off-exp",
        "off-exp-body",
    );
    exp.expires_at = Some("2000-01-01T00:00:00Z".to_string());
    db::insert(&conn, &exp).expect("insert");
    db::gc(&conn, false).expect("gc");

    let evi = make_memory(
        "00000000-0000-0000-0000-0000000000b6",
        "off-evi",
        "ns-off-evi",
        "off-evi-body-large-enough-to-exceed-the-cap",
    );
    db::insert(&conn, &evi).expect("insert");
    db::size_gc(&conn, "ns-off-evi", 1, false).expect("size_gc");

    assert_eq!(
        leaf_count(&conn),
        0,
        "with append_only OFF, NOT ONE memory_revisions row may be written"
    );
}

// ---------------------------------------------------------------------------
// Postgres twins — #[ignore] + sal-postgres gated (need a live instance),
// mirroring tests/secret_screen_postgres_parity_g29.rs.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres_twins {
    use ai_memory::models::{Memory, MemoryKind, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skipping postgres flag-ON twin: connect failed: {e}");
                None
            }
        }
    }

    fn sample(id: &str, namespace: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: namespace.to_string(),
            title: format!("flagon-{id}"),
            content: content.to_string(),
            source: "g6-flagon".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ "agent_id": "ai:g6-flagon" }),
            memory_kind: MemoryKind::Observation,
            version: 1,
            ..Default::default()
        }
    }

    async fn count_leaves(pg: &PostgresStore, memory_id: &str, kind: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM memory_revisions WHERE memory_id = $1 AND kind = $2",
        )
        .bind(memory_id)
        .bind(kind)
        .fetch_one(pg.pool())
        .await
        .expect("count pg leaves")
    }

    /// The headline #12962 fix: a federation remote-erase appends an
    /// identity-only TOMBSTONE leaf in ONE tx (audited), not a silent
    /// pool-direct hard delete.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_apply_remote_deletion_writes_remote_tombstone_leaf() {
        let Some(pg) = live_pg().await else {
            return;
        };
        ai_memory::config::set_append_only(true);
        let ctx = CallerContext::for_agent("g6-flagon");
        let id = uuid::Uuid::new_v4().to_string();
        let mem = sample(&id, "ns-pg-remote", "PG-REMOTE-CONTENT");
        MemoryStore::store(&pg, &ctx, &mem)
            .await
            .expect("seed pg row");

        let deleted = MemoryStore::apply_remote_deletion(&pg, &ctx, &id)
            .await
            .expect("apply_remote_deletion");
        assert!(deleted, "the remote row was erased");

        assert_eq!(
            count_leaves(&pg, &id, "TOMBSTONE").await,
            1,
            "the atomic remote erase must leave one audited TOMBSTONE leaf"
        );
        assert!(
            MemoryStore::get(&pg, &ctx, &id).await.is_err(),
            "the row is compacted away after the leaf is captured"
        );
    }

    /// The production postgres content supersede (Store::update →
    /// update_with_expected_version_once) is path-a same-id in-place and
    /// appends one SUPERSEDE leaf for the SAME id.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_content_update_writes_one_supersede_leaf() {
        let Some(pg) = live_pg().await else {
            return;
        };
        ai_memory::config::set_append_only(true);
        let ctx = CallerContext::for_agent("g6-flagon");
        let id = uuid::Uuid::new_v4().to_string();
        let mem = sample(&id, "ns-pg-put", "pg-v1");
        MemoryStore::store(&pg, &ctx, &mem)
            .await
            .expect("seed pg row");

        let before = count_leaves(&pg, &id, "SUPERSEDE").await;
        let patch = UpdatePatch {
            content: Some("pg-v2".to_string()),
            ..UpdatePatch::default()
        };
        MemoryStore::update(&pg, &ctx, &id, patch)
            .await
            .expect("pg content update");

        assert_eq!(
            count_leaves(&pg, &id, "SUPERSEDE").await - before,
            1,
            "the in-place pg supersede appends exactly one SUPERSEDE leaf"
        );
        let head = MemoryStore::get(&pg, &ctx, &id)
            .await
            .expect("head present after supersede");
        assert_eq!(head.id, id, "supersede is SAME-id in-place (path-a)");
        assert_eq!(head.content, "pg-v2");
    }
}
