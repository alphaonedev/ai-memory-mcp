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
fn orphan_bundle_reaped_and_not_resurrectable() {
    // F1 (HIGH) — a bundle whose archived row was purged (or lost between the
    // DELETE and the best-effort bundle removal) is an ORPHAN. Pre-fix it
    // survived FOREVER (no future purge revisits a purged id) and
    // `archive restore` could resurrect purged / forgotten-then-purged
    // content. The gc-tick orphan reconciliation must reap it.
    let _g = env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    enable(true);
    let f = fixture();
    seed_archived(&f.conn, "row-orphan", "purged, must not resurrect", None);
    archive_sync::gc_tick(&f.conn).expect("sweep");
    let bundle = erasure_dir(&f.db_path).join("row-orphan");
    assert!(bundle.join("manifest.json").is_file(), "bundle minted");

    // Simulate the purge-crash orphan: the archived row vanishes but the
    // bundle survives (remove_bundles_best_effort never ran).
    drop_archived_row(&f.conn, "row-orphan");
    assert!(bundle.exists(), "orphan bundle present pre-reconciliation");

    // Reconcile with a zero grace window (the const grace is 1h — not
    // waitable in a test). The orphan is reaped; the id no longer resurrects.
    let store = archive_sync::store_for_conn(&f.conn)
        .expect("store")
        .expect("enabled");
    let rr = archive_sync::reconcile_and_scrub(&f.conn, &store, 512, 16, 0);
    assert_eq!(rr.orphans_reaped, 1, "the orphan bundle is reaped");
    assert!(!bundle.exists(), "orphan bundle gone after reconciliation");
    assert!(
        !db::restore_archived(&f.conn, "row-orphan").expect("restore after reap"),
        "a purge-crash orphan must NOT be resurrectable from the cold tier"
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
