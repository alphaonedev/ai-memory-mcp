// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2064 (TRACT-gap G16, #1830) — end-to-end pins for the opt-in
//! erasure-coded archive cold tier.
//!
//! Covers, against a real file-backed sqlite DB:
//! - the paced sweep bundling committed archived rows (idempotent + paced);
//! - reconstruct-on-read: `restore_archived` re-materializing an archived
//!   row whose DB copy is GONE, from verified shards — including after
//!   shard loss up to the parity budget;
//! - loss BEYOND the budget failing LOUD (typed error, zero partial state);
//! - purge (destruction intent) removing bundles so purged content cannot
//!   be resurrected from the redundancy layer;
//! - the owner-scoped restore twin refusing un-owned bundles;
//! - default-OFF: no bundles, byte-identical behavior.
//!
//! Env-var toggles are process-global, so every test serializes on one
//! mutex (the `recover::durability` test-lock precedent).

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::db;
use ai_memory::erasure::ENV_ERASURE_COLD_TIER;
use ai_memory::erasure::ENV_ERASURE_RECOVER_QUARANTINE;
use ai_memory::erasure::archive_sync;
use ai_memory::models::Tier;
use rusqlite::{Connection, params};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct Fixture {
    _tmp: tempfile::TempDir,
    conn: Connection,
    db_path: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("cold.db");
    let conn = db::open(&db_path).expect("open file-backed sqlite");
    Fixture {
        _tmp: tmp,
        conn,
        db_path,
    }
}

fn erasure_dir(db_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.erasure", db_path.display()))
}

fn seed_archived(conn: &Connection, id: &str, content: &str, agent_id: Option<&str>) {
    let mem = ai_memory::models::Memory {
        id: id.to_string(),
        namespace: "erasure-2064".to_string(),
        title: format!("title-{id}"),
        content: content.to_string(),
        tier: Tier::Long,
        metadata: agent_id.map_or_else(
            || serde_json::json!({}),
            |a| serde_json::json!({ "agent_id": a }),
        ),
        ..ai_memory::models::Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory");
    assert!(
        db::archive_memory(conn, id, Some("erasure-2064-test")).expect("archive"),
        "archive_memory must succeed for {id}"
    );
}

/// Simulate partial DB loss: the archived row vanishes while the erasure
/// bundle survives.
fn drop_archived_row(conn: &Connection, id: &str) {
    conn.execute("DELETE FROM archived_memories WHERE id = ?1", params![id])
        .expect("simulate archived-row loss");
}

/// Pin an archived row's `archived_at` so the sweep's `(archived_at, id)`
/// keyset frontier ordering is deterministic in a test.
fn set_archived_at(conn: &Connection, id: &str, at: &str) {
    conn.execute(
        "UPDATE archived_memories SET archived_at = ?1 WHERE id = ?2",
        params![at, id],
    )
    .expect("set archived_at");
}

/// Make an archived row PERMANENTLY un-bundleable (#2225): stamp a non-UTF-8
/// TEXT `title` (`CAST(x'ff' AS TEXT)` stores the raw 0xFF byte) so
/// `archived_row_payload` bails loud on every bundling attempt — exactly the
/// poison-row failure mode (non-UTF-8 TEXT / non-finite REAL) the frontier
/// used to pin on.
fn poison_row(conn: &Connection, id: &str) {
    conn.execute(
        "UPDATE archived_memories SET title = CAST(x'ff' AS TEXT) WHERE id = ?1",
        params![id],
    )
    .expect("poison archived row title with non-UTF-8 bytes");
}

fn enable(on: bool) {
    if on {
        unsafe { std::env::set_var(ENV_ERASURE_COLD_TIER, "1") };
    } else {
        unsafe { std::env::remove_var(ENV_ERASURE_COLD_TIER) };
    }
}

#[test]
fn sweep_bundles_and_restore_reconstructs_lost_row() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-alpha", "the durable truth alpha", None);
    seed_archived(&f.conn, "row-beta", "the durable truth beta", None);

    let report = archive_sync::gc_tick(&f.conn).expect("sweep");
    assert_eq!(report.bundled, 2, "both archived rows bundle");
    let dir = erasure_dir(&f.db_path);
    assert!(dir.join("row-alpha").join("manifest.json").is_file());
    assert!(dir.join("row-beta").join("manifest.json").is_file());

    // Idempotent second pass: nothing re-bundles. With the F2 keyset frontier
    // the already-bundled prefix is SKIPPED (not re-probed), so a steady-state
    // tick does zero filesystem work — `already_current` is 0, not 2.
    let again = archive_sync::gc_tick(&f.conn).expect("sweep 2");
    assert_eq!(again.bundled, 0);
    assert_eq!(
        again.already_current, 0,
        "F2: the keyset frontier skips the already-bundled prefix — no re-probe"
    );

    // Partial DB loss, then reconstruct-on-read via the NORMAL restore verb.
    drop_archived_row(&f.conn, "row-alpha");
    assert!(
        db::restore_archived(&f.conn, "row-alpha").expect("restore from shards"),
        "restore must re-materialize the archived row from the bundle"
    );
    let content: String = f
        .conn
        .query_row(
            "SELECT content FROM memories WHERE id = 'row-alpha'",
            [],
            |r| r.get(0),
        )
        .expect("restored live row");
    assert_eq!(
        content, "the durable truth alpha",
        "byte-exact reconstruction"
    );
    enable(false);
}

#[test]
fn restore_survives_shard_loss_up_to_parity_budget() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-loss", "survives m shard losses", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");

    // Default geometry is (k=4, m=2): destroy exactly m shards — one
    // deleted, one bit-flipped in place (corruption must be DETECTED and
    // demoted to an erasure, never trusted).
    let bundle = erasure_dir(&f.db_path).join("row-loss");
    std::fs::remove_file(bundle.join("shard-001.bin")).expect("delete shard");
    let corrupt = bundle.join("shard-004.bin");
    let mut bytes = std::fs::read(&corrupt).expect("read shard");
    bytes[0] ^= 0xff;
    std::fs::write(&corrupt, bytes).expect("corrupt shard");

    drop_archived_row(&f.conn, "row-loss");
    assert!(
        db::restore_archived(&f.conn, "row-loss").expect("restore within budget"),
        "k of n verifiable shards must reconstruct"
    );
    let content: String = f
        .conn
        .query_row(
            "SELECT content FROM memories WHERE id = 'row-loss'",
            [],
            |r| r.get(0),
        )
        .expect("restored live row");
    assert_eq!(content, "survives m shard losses");
    enable(false);
}

#[test]
fn hostile_manifest_geometry_is_rejected_before_allocation() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-hostile-geometry", "must fail closed", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");

    let manifest_path = erasure_dir(&f.db_path)
        .join("row-hostile-geometry")
        .join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["data_shards"] = serde_json::json!(usize::MAX);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize hostile manifest"),
    )
    .expect("write hostile manifest");
    drop_archived_row(&f.conn, "row-hostile-geometry");

    let err = db::restore_archived(&f.conn, "row-hostile-geometry")
        .expect_err("hostile geometry must be a typed refusal, never an allocation panic");
    let detail = format!("{err:#}");
    assert!(
        detail.contains("manifest malformed") && detail.contains("invalid erasure params"),
        "unexpected refusal: {detail}"
    );
    enable(false);
}

#[test]
fn loss_beyond_budget_fails_loud_with_zero_partial_state() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-toast", "cannot be reconstructed", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");

    // Destroy m + 1 = 3 of the 6 shards: beyond the parity budget.
    let bundle = erasure_dir(&f.db_path).join("row-toast");
    for shard in ["shard-000.bin", "shard-002.bin", "shard-005.bin"] {
        std::fs::remove_file(bundle.join(shard)).expect("delete shard");
    }
    drop_archived_row(&f.conn, "row-toast");

    // FAIL LOUD: a typed error, NOT Ok(false) (which would read as
    // "nothing to restore") and NOT wrong data.
    let err = db::restore_archived(&f.conn, "row-toast")
        .expect_err("beyond-budget loss must be a loud error");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("parity budget"),
        "error must name the budget breach: {msg}"
    );
    // Zero partial state: the failed reconstruct rolled back — no archived
    // row, no live row.
    let archived: i64 = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = 'row-toast'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let live: i64 = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = 'row-toast'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        (archived, live),
        (0, 0),
        "no partial state after loud failure"
    );
    enable(false);
}

#[test]
fn purge_destruction_intent_removes_bundles() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-purged", "must not be resurrectable", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let bundle = erasure_dir(&f.db_path).join("row-purged");
    assert!(bundle.join("manifest.json").is_file());

    // Purge = explicit destruction intent; the bundle must go with the row
    // so the redundancy layer cannot resurrect purged content.
    let purged = db::purge_archive(&f.conn, None).expect("purge");
    assert_eq!(purged, 1);
    assert!(!bundle.exists(), "purge must remove the row's bundle");
    assert!(
        !db::restore_archived(&f.conn, "row-purged").expect("restore after purge"),
        "purged content must NOT be resurrectable from the cold tier"
    );
    enable(false);
}

#[test]
fn owner_scoped_restore_refuses_unowned_bundles() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(
        &f.conn,
        "row-owned",
        "alice's private cold data",
        Some("alice"),
    );
    archive_sync::gc_tick(&f.conn).expect("sweep");
    drop_archived_row(&f.conn, "row-owned");

    // A different caller: the bundle is invisible — no restore, no
    // side-effects, no existence oracle.
    assert!(
        !db::restore_archived_for_caller(&f.conn, "row-owned", "bob").expect("bob restore"),
        "an un-owned bundle must stay invisible to a non-owner caller"
    );
    let resurrected: i64 = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = 'row-owned'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        resurrected, 0,
        "no archived row may be materialized for a non-owner"
    );

    // The owner reconstructs fine.
    assert!(
        db::restore_archived_for_caller(&f.conn, "row-owned", "alice").expect("alice restore"),
        "the owner reconstructs from shards"
    );
    enable(false);
}

#[test]
fn sweep_is_paced_by_the_limit() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    for i in 0..3 {
        seed_archived(&f.conn, &format!("row-pace-{i}"), "paced", None);
    }
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let first = archive_sync::sweep_archive_bundles(&f.conn, &store, 1).expect("pass 1");
    assert_eq!(
        (first.bundled, first.failed),
        (1, 0),
        "limit bounds one pass"
    );
    let second = archive_sync::sweep_archive_bundles(&f.conn, &store, 10).expect("pass 2");
    assert_eq!(second.bundled, 2, "the frontier resumes where it left off");
    assert_eq!(
        second.already_current, 0,
        "F2: the keyset frontier skips the row bundled in pass 1 — it is not re-probed"
    );
    enable(false);
}

#[test]
fn sweep_frontier_survives_fresh_cli_process_2247() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    for (id, at) in [
        ("row-cli-1", "2020-01-01T00:00:01Z"),
        ("row-cli-2", "2020-01-01T00:00:02Z"),
        ("row-cli-3", "2020-01-01T00:00:03Z"),
    ] {
        seed_archived(&f.conn, id, "cli cadence", None);
        set_archived_at(&f.conn, id, at);
    }
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let first = archive_sync::sweep_archive_bundles(&f.conn, &store, 1).expect("first CLI gc");
    assert_eq!(first.bundled, 1);
    assert!(store.dir().join(".sweep-frontier.json").is_file());

    archive_sync::clear_process_caches_for_tests(store.dir());
    let next = archive_sync::sweep_archive_bundles(&f.conn, &store, 16).expect("fresh CLI gc");
    assert_eq!(next.bundled, 2, "fresh process resumes behind row 1");
    assert_eq!(
        next.already_current, 0,
        "fresh process loads the durable frontier instead of re-probing the prefix"
    );
    enable(false);
}

#[test]
fn reconcile_inventory_caches_root_walk_and_folds_temp_reap_2248() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-indexed", "inventory", None);
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    archive_sync::sweep_archive_bundles(&f.conn, &store, 16).expect("sweep");

    let (first, reaped) = store.reconcile_inventory(0, 0);
    assert_eq!(first, vec!["row-indexed"]);
    assert_eq!(reaped, 0);

    // A valid-looking directory added behind the cache is not discovered by
    // the ordinary fast path, proving that path does no root enumeration.
    let shadow = store.dir().join("row-shadow");
    std::fs::create_dir(&shadow).expect("shadow dir");
    std::fs::copy(
        store.dir().join("row-indexed").join("manifest.json"),
        shadow.join("manifest.json"),
    )
    .expect("shadow manifest");
    let temp = store.dir().join(".tmp-crashed-writer");
    std::fs::create_dir(&temp).expect("temp dir");
    let (cached, cached_reaped) = store.reconcile_inventory(u64::MAX, 0);
    assert_eq!(cached, vec!["row-indexed"]);
    assert_eq!(cached_reaped, 0);
    assert!(temp.exists(), "fast path performs no second temp-dir walk");

    let (refreshed, refreshed_reaped) = store.reconcile_inventory(0, 0);
    assert_eq!(refreshed, vec!["row-indexed", "row-shadow"]);
    assert_eq!(
        refreshed_reaped, 1,
        "refresh folds temp reap into its one walk"
    );
    assert!(!temp.exists());
    enable(false);
}

#[test]
fn reconcile_cursor_is_durable_and_keyed_per_store_2247() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f1 = fixture();
    let f2 = fixture();
    for f in [&f1, &f2] {
        for id in ["row-cursor-a", "row-cursor-b"] {
            seed_archived(&f.conn, id, "cursor", None);
        }
        archive_sync::gc_tick(&f.conn).expect("bundle cursor fixture");
        for id in ["row-cursor-a", "row-cursor-b"] {
            drop_archived_row(&f.conn, id);
        }
    }
    let s1 = archive_sync::store_for_conn(&f1.conn)
        .expect("store 1")
        .expect("enabled");
    let s2 = archive_sync::store_for_conn(&f2.conn)
        .expect("store 2")
        .expect("enabled");

    let first = archive_sync::reconcile_and_scrub(&f1.conn, &s1, 1, 0, 0);
    assert_eq!(first.quarantined, 1);
    assert!(
        s1.dir()
            .join(".quarantine/row-cursor-a/manifest.json")
            .is_file(),
        "store 1 begins at its own cursor zero"
    );
    archive_sync::clear_process_caches_for_tests(s1.dir());
    let resumed = archive_sync::reconcile_and_scrub(&f1.conn, &s1, 1, 0, 0);
    assert_eq!(resumed.quarantined, 1);
    assert!(
        s1.dir()
            .join(".quarantine/row-cursor-b/manifest.json")
            .is_file(),
        "fresh process resumes store 1 from its durable cursor"
    );

    let independent = archive_sync::reconcile_and_scrub(&f2.conn, &s2, 1, 0, 0);
    assert_eq!(independent.quarantined, 1);
    assert!(
        s2.dir()
            .join(".quarantine/row-cursor-a/manifest.json")
            .is_file(),
        "store 2 has an independent cursor instead of inheriting store 1's"
    );
    enable(false);
}

#[test]
fn journaled_purge_orphan_is_reaped_and_not_resurrectable() {
    // R1 (SAFE half of F1) — a bundle whose id carries a RECORDED purge intent
    // (journaled BEFORE the DELETE) is confirmed destruction. A crash between
    // the DELETE and the best-effort removal orphans the bundle; the
    // reconciler HARD-reaps it, and restore refuses to resurrect it even
    // while it lingers.
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-purged-crash", "destroyed on purpose", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let bundle = erasure_dir(&f.db_path).join("row-purged-crash");
    assert!(bundle.join("manifest.json").is_file(), "bundle minted");

    // A purge that journaled intent + deleted the row, then CRASHED before
    // removing the bundle.
    archive_sync::journal_purge_intent(&f.conn, &["row-purged-crash".to_string()])
        .expect("journal purge intent");
    drop_archived_row(&f.conn, "row-purged-crash");

    // Restore refuses a journaled id immediately (before any reconciliation).
    assert!(
        !db::restore_archived(&f.conn, "row-purged-crash").expect("restore"),
        "a journaled-purge id must NOT resurrect, even while its bundle lingers"
    );

    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(rr.orphans_reaped, 1, "the journaled orphan is hard-reaped");
    assert_eq!(rr.quarantined, 0, "a journaled orphan is never quarantined");
    assert!(
        !bundle.exists(),
        "journaled orphan bundle gone after reconciliation"
    );
    enable(false);
}

#[test]
fn purge_marker_blocks_cross_process_remint_until_row_and_bundle_are_gone() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-purge-race", "must not be re-minted", None);
    archive_sync::gc_tick(&f.conn).expect("initial sweep");
    let dir = erasure_dir(&f.db_path);
    let bundle = dir.join("row-purge-race");
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");

    archive_sync::journal_purge_intent(&f.conn, &["row-purge-race".to_string()])
        .expect("journal purge intent");
    archive_sync::remove_bundles_best_effort(&f.conn, &["row-purge-race".to_string()]);
    assert!(!bundle.exists(), "purge removed the old bundle");
    assert!(
        store.is_purge_intended("row-purge-race"),
        "intent survives removal while a racing sweep may still see the row"
    );

    // Model the second process: its sweep starts from an empty in-process
    // frontier while the durable archived row remains visible.
    archive_sync::reset_process_static_sweep_state_for_dir(&dir);
    let raced = archive_sync::sweep_archive_bundles(&f.conn, &store, 16).expect("racing sweep");
    assert_eq!(raced.skipped_purge_intent, 1);
    assert!(!bundle.exists(), "durable intent forbids re-minting");
    assert!(store.is_purge_intended("row-purge-race"));

    // Only after the row and bundle are both absent may compaction retire the
    // marker. This keeps the journal bounded without reopening the race.
    drop_archived_row(&f.conn, "row-purge-race");
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 16, 0, 0);
    assert_eq!(rr.journal_compacted, 1);
    assert!(!store.is_purge_intended("row-purge-race"));
    enable(false);
}

#[test]
fn unjournaled_dbloss_bundle_is_quarantined_not_destroyed_and_recoverable() {
    // R1 (BLOCKING inversion) — a rowless bundle with NO recorded purge intent
    // is byte-INDISTINGUISHABLE from the partial-DB-loss disaster the tier
    // EXISTS to survive (the bundle is the last surviving copy). It MUST NOT be
    // destroyed: quarantine (preserve + hide) instead. `restore` refuses to
    // auto-materialize a quarantined bundle (resurrection lane stays closed),
    // yet the operator can recover it via the DR path. "Never cause
    // unintentional data loss" outranks "purged content must not resurrect".
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-dbloss", "the last surviving copy", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let active = erasure_dir(&f.db_path).join("row-dbloss");
    let quarantined = erasure_dir(&f.db_path)
        .join(".quarantine")
        .join("row-dbloss");
    assert!(active.join("manifest.json").is_file(), "bundle minted");

    // Partial DB loss: the archived row vanishes, NO purge intent journaled.
    drop_archived_row(&f.conn, "row-dbloss");

    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(
        rr.quarantined, 1,
        "possible DB loss → QUARANTINE, never destroy"
    );
    assert_eq!(
        rr.orphans_reaped, 0,
        "no destruction without a recorded purge intent"
    );
    assert!(!active.exists(), "bundle moved OUT of the active store");
    assert!(
        quarantined.join("manifest.json").is_file(),
        "bundle PRESERVED in quarantine (not destroyed)"
    );
    assert!(
        !db::restore_archived(&f.conn, "row-dbloss").expect("restore"),
        "a quarantined bundle is invisible to restore (resurrection lane closed)"
    );

    // DR recovery: the operator asserts DB loss, engages recovery, reconciles →
    // the bundle returns to active; restore then reconstructs the lost row.
    unsafe { std::env::set_var(ENV_ERASURE_RECOVER_QUARANTINE, "1") };
    let rr2 = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(
        rr2.quarantine_recovered, 1,
        "DR mode recovers the quarantined bundle to active"
    );
    assert!(
        active.join("manifest.json").is_file(),
        "bundle is back in the active store"
    );
    assert!(
        db::restore_archived(&f.conn, "row-dbloss").expect("DR restore"),
        "after recovery the DB-lost row reconstructs from its preserved shards"
    );
    let content: String = f
        .conn
        .query_row(
            "SELECT content FROM memories WHERE id = 'row-dbloss'",
            [],
            |r| r.get(0),
        )
        .expect("restored live row");
    assert_eq!(content, "the last surviving copy", "byte-exact recovery");
    unsafe { std::env::remove_var(ENV_ERASURE_RECOVER_QUARANTINE) };
    enable(false);
}

#[test]
fn row_probe_error_skips_bundle_instead_of_classifying_it_as_rowless() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-probe-error", "must remain untouched", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let active = erasure_dir(&f.db_path).join("row-probe-error");

    f.conn
        .execute("DROP TABLE archived_memories", [])
        .expect("inject archived-row probe failure");
    let report = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);

    assert_eq!(report.scanned, 1);
    assert_eq!(report.orphans_reaped, 0);
    assert_eq!(report.quarantined, 0);
    assert!(
        active.join("manifest.json").is_file(),
        "a DB probe error must leave the bundle untouched for a later tick"
    );
    enable(false);
}

#[test]
fn dr_recovery_error_is_reported_for_retry() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let malformed = erasure_dir(&f.db_path)
        .join(".quarantine")
        .join("invalid id");
    std::fs::create_dir_all(&malformed).expect("create malformed quarantine entry");
    std::fs::write(malformed.join("manifest.json"), b"{}").expect("write manifest sentinel");

    unsafe { std::env::set_var(ENV_ERASURE_RECOVER_QUARANTINE, "1") };
    let report = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(report.quarantine_recovered, 0);
    assert_eq!(
        report.quarantine_recovery_failed, 1,
        "a failed DR recovery must be visible and retried later"
    );
    assert!(malformed.join("manifest.json").is_file());
    unsafe { std::env::remove_var(ENV_ERASURE_RECOVER_QUARANTINE) };
    enable(false);
}

#[test]
fn purge_marker_creation_failure_is_fail_closed() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(
        &f.conn,
        "row-marker-failure",
        "must survive failed journaling",
        None,
    );
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let marker_path = erasure_dir(&f.db_path)
        .join(".purge-intent")
        .join("row-marker-failure");
    std::fs::create_dir_all(&marker_path).expect("occupy marker path with a directory");

    let error = db::purge_archive(&f.conn, None)
        .expect_err("purge must not proceed when its intent cannot be journaled");
    assert!(
        format!("{error:#}").contains("create purge-intent marker"),
        "unexpected error chain: {error:#}"
    );
    let surviving: i64 = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memories WHERE id = 'row-marker-failure'",
            [],
            |row| row.get(0),
        )
        .expect("count surviving archived row");
    assert_eq!(surviving, 1, "the archived row must remain intact");
    assert!(
        store.contains("row-marker-failure"),
        "the cold-tier bundle must remain intact"
    );
    enable(false);
}

#[test]
fn aborted_purge_stale_marker_is_cleared_so_later_dbloss_quarantines() {
    // R5 — a purge that JOURNALED intent then had its `DELETE` abort
    // (SQLITE_BUSY / IO) leaves a stale marker while the row + bundle survive.
    // compact_purge_journal can't clear it (the bundle still exists). Left in
    // place, a LATER genuine DB loss of that id would be hard-reaped (the
    // forbidden direction, on a delayed fuse). The reconciler must clear a
    // stale marker (row present + journaled + past grace); a subsequent DB
    // loss then QUARANTINES (safe), not reaps.
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-aborted", "survives an aborted purge", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");

    // Aborted purge: intent journaled, but the DELETE failed so the archived
    // row + its bundle both still exist.
    archive_sync::journal_purge_intent(&f.conn, &["row-aborted".to_string()])
        .expect("journal purge intent");
    assert!(
        store.is_purge_intended("row-aborted"),
        "intent marker present"
    );

    // Reconcile (grace 0): the row still exists → the stale marker is cleared.
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(
        rr.stale_intent_cleared, 1,
        "stale marker on a surviving row is cleared"
    );
    assert!(
        !store.is_purge_intended("row-aborted"),
        "the stale intent marker is gone"
    );

    // A GENUINE later DB loss of the same id must QUARANTINE (preserve), not
    // hard-reap — the delayed-fuse direction is closed.
    drop_archived_row(&f.conn, "row-aborted");
    let rr2 = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(
        rr2.quarantined, 1,
        "a later DB loss quarantines (not hard-reaped) once the stale marker is gone"
    );
    assert_eq!(
        rr2.orphans_reaped, 0,
        "no destruction — the marker was cleared"
    );
    enable(false);
}

#[test]
fn re_archived_row_rebundles_on_stamp_change() {
    // F5 — the `bundle_is_current` mismatch path: a row whose `archived_at`
    // differs from its bundle's recorded stamp (a re-archive) is re-bundled.
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-restamp", "v1", None);
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    archive_sync::sweep_archive_bundles(&f.conn, &store, 256).expect("sweep 1");
    let stamp1 = store.get_manifest_meta("row-restamp").expect("manifest 1")["archived_at"]
        .as_str()
        .expect("stamp")
        .to_string();

    // A re-archive of the same id lands a strictly-later `archived_at`.
    let later = "2999-01-01T00:00:00+00:00";
    f.conn
        .execute(
            "UPDATE archived_memories SET archived_at = ?1 WHERE id = 'row-restamp'",
            params![later],
        )
        .expect("re-stamp");
    let report = archive_sync::sweep_archive_bundles(&f.conn, &store, 256).expect("sweep 2");
    assert_eq!(
        report.bundled, 1,
        "the re-stamped row re-bundles (bundle_is_current mismatch path)"
    );
    let stamp2 = store.get_manifest_meta("row-restamp").expect("manifest 2")["archived_at"]
        .as_str()
        .expect("stamp")
        .to_string();
    assert_eq!(stamp2, later, "the manifest currency stamp is refreshed");
    assert_ne!(
        stamp1, later,
        "the pre-restamp bundle carried the old stamp"
    );
    enable(false);
}

#[test]
fn torn_bundle_detected_and_reminted_by_scrub() {
    // F3 — a power loss can leave the manifest (the commit marker) behind
    // TORN shards. `bundle_is_current` trusts the manifest stamp, so the sweep
    // never re-mints it and the redundancy is silently gone until a
    // reconstruct needs it. The scrub lane hash-verifies current bundles and
    // re-mints a torn one from the DURABLE archived row BEFORE it is needed.
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-torn", "torn shards after power loss", None);
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    archive_sync::sweep_archive_bundles(&f.conn, &store, 256).expect("sweep");

    // Truncate beyond the parity budget: delete m + 1 = 3 of the 6 shards.
    let bundle = erasure_dir(&f.db_path).join("row-torn");
    for shard in ["shard-000.bin", "shard-001.bin", "shard-002.bin"] {
        std::fs::remove_file(bundle.join(shard)).expect("delete shard");
    }
    assert!(
        store.get("row-torn").is_err(),
        "a torn-beyond-budget bundle fails loud pre-scrub"
    );

    // The archived row still exists (the durable source of truth), so scrub
    // re-mints the whole bundle from it.
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(
        rr.scrub_reminted, 1,
        "the torn current bundle is re-minted from the durable archived row"
    );
    let recovered = store
        .get("row-torn")
        .expect("get")
        .expect("bundle present after re-mint");
    assert!(
        !recovered.was_degraded,
        "the re-mint restored the full loss budget"
    );
    enable(false);
}

#[test]
fn disabled_by_default_no_bundles_and_no_resurrection() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(false);
    let f = fixture();
    seed_archived(&f.conn, "row-off", "no redundancy when off", None);
    let report = archive_sync::gc_tick(&f.conn).expect("no-op tick");
    assert_eq!((report.bundled, report.already_current), (0, 0));
    assert!(
        !erasure_dir(&f.db_path).exists(),
        "OFF is byte-identical: no bundle directory is created"
    );
    drop_archived_row(&f.conn, "row-off");
    assert!(
        !db::restore_archived(&f.conn, "row-off").expect("restore"),
        "with the tier off a lost archived row stays lost (Ok(false))"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2225 — a poison row must not STARVE bundling of newer rows.
//
// The #2064 sweep's keyset frontier never advances past a failed row, so a
// permanently-failing (poison) row plus more than SWEEP_PROBE_BUDGET_PER_TICK
// successors pins the frontier forever and starves the tail. The bounded
// process-static poison skip-set unpins the frontier after a few ticks: these
// tests drive that behavior with a small, fast corpus (the frontier-advance is
// the mechanism that prevents the large-corpus starvation).
// ─────────────────────────────────────────────────────────────────────

/// Seed one poison row (earliest `archived_at`) plus three successors, then
/// drive enough ticks for the poison row to enter the skip-set.
fn poison_plus_successors_fixture() -> (Fixture, PathBuf) {
    let f = fixture();
    seed_archived(&f.conn, "aaa-poison", "will be corrupted", None);
    seed_archived(&f.conn, "bbb-succ-1", "successor one", None);
    seed_archived(&f.conn, "ccc-succ-2", "successor two", None);
    seed_archived(&f.conn, "ddd-succ-3", "successor three", None);
    // Deterministic frontier ordering: the poison row sorts strictly first.
    set_archived_at(&f.conn, "aaa-poison", "2020-01-01T00:00:00Z");
    set_archived_at(&f.conn, "bbb-succ-1", "2020-01-01T00:00:01Z");
    set_archived_at(&f.conn, "ccc-succ-2", "2020-01-01T00:00:02Z");
    set_archived_at(&f.conn, "ddd-succ-3", "2020-01-01T00:00:03Z");
    poison_row(&f.conn, "aaa-poison");
    // NOTE: the store dir is a fresh tempdir, so its process-static frontier /
    // poison skip-set start empty — no reset needed here. A reset that DID
    // matter (the restart test) must key on the store's OWN `dir()` (the exact
    // PathBuf the sweep uses as its registry key), NOT a recomputed
    // `erasure_dir(db_path)`: on macOS the tempdir path is a `/tmp`→`/private/tmp`
    // symlink, so `is_file()` resolves it but a raw-string PathBuf HashMap-key
    // comparison does not — the two strings differ and the wrong key is cleared.
    let dir = erasure_dir(&f.db_path);
    (f, dir)
}

#[test]
fn poison_row_does_not_starve_successor_bundling_2225() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let (f, dir) = poison_plus_successors_fixture();
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");

    // Drive enough ticks for the poison row to fail POISON_FAILURE_THRESHOLD
    // times and enter the skip-set (after which the frontier passes it).
    for _ in 0..(archive_sync::POISON_FAILURE_THRESHOLD + 2) {
        archive_sync::sweep_archive_bundles(&f.conn, &store, archive_sync::SWEEP_LIMIT_PER_TICK)
            .expect("sweep pass");
    }

    // Every successor is bundled despite the poison row that precedes them.
    for id in ["bbb-succ-1", "ccc-succ-2", "ddd-succ-3"] {
        assert!(
            dir.join(id).join("manifest.json").is_file(),
            "successor {id} must bundle despite the poison predecessor (#2225)"
        );
    }
    // The poison row itself never bundles — its archived DB row is the durable
    // source of truth (a redundancy gap, never corruption / data loss).
    assert!(
        !dir.join("aaa-poison").join("manifest.json").is_file(),
        "the poison row must NOT bundle (it fails encode); the archived row is the durable truth"
    );

    // The fix's signature: once the poison row is skipped, the keyset frontier
    // has advanced PAST it, so a settled tick re-probes NOTHING (failed == 0).
    // Without the skip-set the frontier stays pinned before the poison row and
    // every tick re-fails it (failed == 1) forever — the starvation the issue
    // describes.
    let settled =
        archive_sync::sweep_archive_bundles(&f.conn, &store, archive_sync::SWEEP_LIMIT_PER_TICK)
            .expect("settled sweep");
    assert_eq!(
        settled.failed, 0,
        "the frontier has advanced past the poison row — it is no longer re-probed each tick"
    );
    assert_eq!(settled.bundled, 0, "nothing new to bundle at steady state");
    enable(false);
}

#[test]
fn poison_skip_set_clears_on_restart_2225() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let (f, _dir) = poison_plus_successors_fixture();
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");

    // Drive the poison row into the skip-set + settle the frontier past it.
    for _ in 0..(archive_sync::POISON_FAILURE_THRESHOLD + 2) {
        archive_sync::sweep_archive_bundles(&f.conn, &store, archive_sync::SWEEP_LIMIT_PER_TICK)
            .expect("sweep pass");
    }
    let settled =
        archive_sync::sweep_archive_bundles(&f.conn, &store, archive_sync::SWEEP_LIMIT_PER_TICK)
            .expect("settled sweep");
    assert_eq!(
        settled.failed, 0,
        "poison row skipped; frontier advanced past it"
    );

    // Simulate a process RESTART: the skip-set + keyset frontier are
    // process-static and reset on restart, so the poison row is RETRIED (the
    // self-healing path once its underlying cause is repaired). Reset via the
    // store's OWN `dir()` — the exact PathBuf the sweep uses as its registry
    // key — so this matches on macOS too, where a recomputed erasure_dir string
    // would differ by the /tmp -> /private/tmp symlink (see the fixture note).
    archive_sync::reset_process_static_sweep_state_for_dir(store.dir());

    let after_restart =
        archive_sync::sweep_archive_bundles(&f.conn, &store, archive_sync::SWEEP_LIMIT_PER_TICK)
            .expect("post-restart sweep");
    assert_eq!(
        after_restart.failed, 1,
        "a restart clears the skip-set — the poison row is re-attempted (fails again, still poison)"
    );
    assert_eq!(
        after_restart.skipped_poison, 0,
        "the skip-set was cleared by the restart, so nothing is skipped on the first fresh tick"
    );
    enable(false);
}

// =====================================================================
// Pre-ship 3x7 concurrency fix — the sweep runs OFF the handler mutex
// =====================================================================

/// The detached sweep completes its full encode+fsync pass WHILE the
/// daemon's handler mutex (the `handlers::Db` lock every HTTP request
/// serializes on) is HELD by someone else — proving structurally that the
/// sweep never acquires it: it runs on its OWN dedicated connection, and
/// the shared connection is unreachable behind the held guard. Under the
/// pre-fix topology this call graph was impossible (the sweep only ran
/// INSIDE the lock), and an enabled cold tier draining a backlog stalled
/// every API request for the duration of the sweep.
#[test]
fn detached_sweep_completes_while_handler_mutex_is_held() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let Fixture {
        _tmp,
        conn,
        db_path,
    } = fixture();
    seed_archived(
        &conn,
        "row-offlock",
        "sweeps without the handler mutex",
        None,
    );

    // The daemon's shared state shape (`handlers::Db`).
    let state: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    // HOLD the handler mutex for the entire sweep. If the detached sweep
    // needed it (or the shared connection behind it), this would deadlock.
    let guard = state.blocking_lock();
    let report = archive_sync::gc_tick_detached(&db_path).expect("detached sweep");
    assert_eq!(
        report.bundled, 1,
        "detached sweep bundles on its own connection with the handler mutex held"
    );
    assert!(
        erasure_dir(&db_path)
            .join("row-offlock")
            .join("manifest.json")
            .is_file(),
        "bundle written while the handler mutex was held"
    );
    drop(guard);

    // The sweep is DB-read-only: the archived row is untouched, observed
    // through the SHARED connection after the lock is released.
    let lock = state.blocking_lock();
    let n: i64 = lock
        .0
        .query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count archived");
    assert_eq!(n, 1, "sweep wrote nothing to the database");
    drop(lock);
    enable(false);
}

/// The detached sweep FAILS CLOSED on any non-file-backed path: a dedicated
/// connection to `:memory:` (or a `mode=memory` URI) opens a DIFFERENT,
/// empty database whose reconciler would mis-classify every live bundle as
/// rowless. Callers gate on `is_in_memory_db_path` and keep such databases
/// on the legacy under-lock tick — a false-positive classification only
/// re-serializes the sweep, never yields a wrong result.
#[test]
fn detached_sweep_refuses_non_file_backed_paths() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    for p in [":memory:", "file:cold?mode=memory&cache=shared", ""] {
        assert!(
            archive_sync::is_in_memory_db_path(Path::new(p)),
            "{p:?} must classify as non-file-backed"
        );
        assert!(
            archive_sync::gc_tick_detached(Path::new(p)).is_err(),
            "{p:?} must be refused LOUD by the detached sweep"
        );
    }
    assert!(
        !archive_sync::is_in_memory_db_path(Path::new("/var/lib/ai-memory/cold.db")),
        "a plain file path is file-backed"
    );
    // Disabled tier short-circuits to an empty report before any path or
    // connection work — nothing to run off-lock.
    enable(false);
    let r = archive_sync::gc_tick_detached(Path::new(":memory:")).expect("disabled = no-op");
    assert_eq!(
        r.bundled + r.failed + r.already_current + r.skipped_poison,
        0,
        "disabled cold tier is a strict no-op"
    );
}

/// End-to-end daemon wiring: the production gc loop
/// (`spawn_gc_loop_with_shadow_retention`) drives the DETACHED erasure arm
/// for a file-backed database — the bundle lands on disk while the loop
/// holds the handler mutex only for the short in-lock section of each tick.
#[test]
fn gc_loop_runs_detached_erasure_arm_for_file_backed_db() {
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let Fixture {
        _tmp,
        conn,
        db_path,
    } = fixture();
    seed_archived(&conn, "row-loop", "bundled by the daemon gc loop", None);
    let state: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let handle = ai_memory::daemon_runtime::spawn_gc_loop_with_shadow_retention(
            state.clone(),
            None,
            30,
            std::time::Duration::from_millis(5),
        );
        let manifest = erasure_dir(&db_path).join("row-loop").join("manifest.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !manifest.is_file() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        handle.abort();
        let _ = handle.await;
        assert!(
            manifest.is_file(),
            "gc loop's detached erasure arm bundled the archived row"
        );
    });
    enable(false);
}
