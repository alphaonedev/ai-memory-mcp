// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2955 — the forensic audit-trail watermark high-water read
//! ([`ai_memory::governance::audit::last_audit_watermark`], via
//! `scan_file_last_watermark`) must be scoped to the resolving database's
//! `genesis_db_id`, EXACTLY as its two sibling controls already are — the
//! WITNESS anchor (`witness_resolution_json`) and the ROLLBACK head-anchor
//! (`scan_head_anchor_log`), both #2370.
//!
//! The defect: the watermark file sink is process/host-global, so a watermark
//! written by a DIFFERENT database instance sharing the same on-host sink (a
//! restored / rotated / re-genesis'd DB, or a co-located test/prod mixup) was
//! read back as THIS db's high-water — a cross-DB watermark bleed that can
//! forge a wrong truncation/rollback verdict in `verify_audit_trail`.
//!
//! Pins (broken → wrong verdict, fixed → correct):
//! - a SIBLING-db watermark (foreign `db_id`) is NOT honored as this db's
//!   high-water (the removal-proof lane — mutating the scope filter off makes
//!   the foreign row honored → this test RED);
//! - THIS db's own watermark IS still honored (the fix does not over-block);
//! - a legacy id-less watermark is counted CONSERVATIVELY for every opener;
//! - v1.0.0 #3006/#3068 — an IDENTITY-LESS opener (`db_id = None`, no genesis /
//!   empty chain) counts only db_id-LESS legacy watermarks and SKIPS every
//!   IDENTIFIED one (WITHHOLD, never match-all), so two stores sharing one host
//!   never bleed a sibling's head (the pre-#3068 "None reads every watermark"
//!   posture false-convicted a freshly-migrated empty chain of truncation on a
//!   live sibling's climbing watermark);
//! - END-TO-END: a foreign watermark can no longer forge a `Detected`
//!   truncation verdict against a chain that was never truncated.
//!
//! The forensic sink is process-global, so these tests serialise via a
//! module-local lock (the `tests/audit_truncation_anchor_1850.rs` discipline).

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::governance::audit as forensic;
use ai_memory::signed_events::{
    SignedEvent, TruncationCheck, append_signed_event, genesis_db_id, payload_hash,
    verify_audit_trail,
};
use rusqlite::Connection;

/// Process-global serialisation for the shared forensic SINK.
fn forensic_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2955-watermark-db-id-scope");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn open_db(dir: &Path) -> Connection {
    let path = dir.join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    ai_memory::db::open(&path).expect("open db")
}

fn append_row(conn: &Connection, payload: &[u8]) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(payload),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append");
}

// ---------------------------------------------------------------------------
// Removal-proof lane (scripts/check-cert-removal-proof.sh row
// `scan_file_last_watermark_db_id_scope_2955`): a foreign-db watermark must
// NOT be honored as this db's high-water. Mutating the scope filter off makes
// it honored → this test RED.
// ---------------------------------------------------------------------------

#[test]
fn foreign_db_watermark_not_honored_as_this_db_high_water() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("a-forensic");
    forensic::init(fdir.path(), None).expect("forensic init");

    // A SIBLING database (a different genesis identity) stamped its head=100
    // into the SHARED on-host sink. `db-alpha`/`db-beta` stand in for two
    // genesis-derived `db_id`s sharing one watermark file.
    forensic::record_audit_watermark(100, "sibling-head-hash", Some("db-alpha"));
    forensic::flush_blocking();

    // FIX: an opener whose db_id is `db-beta` must NOT read the `db-alpha`
    // sibling's watermark as its own high-water.
    assert_eq!(
        forensic::last_audit_watermark(Some("db-beta")),
        None,
        "a foreign-db_id watermark bled into this db's high-water (cross-DB bleed #2955)"
    );

    // The OWNING database still reads its own watermark (no over-block).
    assert_eq!(
        forensic::last_audit_watermark(Some("db-alpha")),
        Some((100, "sibling-head-hash".to_string())),
        "own-db watermark must still be honored"
    );

    // v1.0.0 #3006/#3068 — an IDENTITY-LESS opener (`db_id = None`, no genesis /
    // empty chain) can NOT own an IDENTIFIED (db_id-bearing) watermark: the
    // `db-alpha` row is skipped, so a freshly-migrated empty chain co-located
    // with a live sibling is never convicted of truncation on the sibling's
    // watermark. (Pre-#3068 this returned `Some((100, …))` — the cross-store
    // bleed.) Wipe-to-empty of a formerly-identified chain is owned by the
    // SIGNED head-anchor-log lane, not this raw unsigned lane.
    assert_eq!(
        forensic::last_audit_watermark(None),
        None,
        "None (no genesis) must NOT read an identified sibling's watermark (#3068)"
    );
}

// ---------------------------------------------------------------------------
// Legacy id-less watermark: counted conservatively for every opener (the
// one-release compat window, mirroring scan_head_anchor_log's legacy arm).
// ---------------------------------------------------------------------------

#[test]
fn legacy_id_less_watermark_counted_for_every_scoped_reader() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("b-forensic");
    forensic::init(fdir.path(), None).expect("forensic init");

    // A pre-#2955 (id-less) watermark — no `db_id` in its payload.
    forensic::record_audit_watermark(42, "legacy-head-hash", None);
    forensic::flush_blocking();

    // A scoped opener still counts the legacy row (conservative: over-detect
    // toward truncation, never suppress).
    assert_eq!(
        forensic::last_audit_watermark(Some("db-gamma")),
        Some((42, "legacy-head-hash".to_string())),
        "a legacy id-less watermark must be counted for every scoped opener"
    );
}

// ---------------------------------------------------------------------------
// END-TO-END: a foreign-db watermark can no longer forge a `Detected`
// truncation verdict against a chain that was never truncated.
// ---------------------------------------------------------------------------

#[test]
fn foreign_watermark_does_not_forge_truncation_verdict() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("c-forensic");
    let ddir = fresh_dir("c-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let conn = open_db(ddir.path());
    for i in 0..3 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    // This db's real genesis-derived identity (64-hex) can never equal the
    // literal sibling label below, so the anchor is unambiguously foreign.
    let this_db_id = genesis_db_id(&conn)
        .expect("genesis db_id")
        .expect("chain has a genesis row");
    assert_ne!(this_db_id, "sibling-db-not-this-one");

    // A SIBLING DB (sharing this on-host sink) anchored head=100 — far above
    // this db's real head of 3. Pre-#2955 the unscoped read honored it and
    // forged `Detected { anchored_head: 100, db_head: 3 }`.
    forensic::record_audit_watermark(100, "sibling-head-hash", Some("sibling-db-not-this-one"));
    forensic::flush_blocking();

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.head_sequence, 3,
        "in-DB head is 3; report={report:?}"
    );
    assert_eq!(
        report.truncation,
        TruncationCheck::Unknown,
        "a SIBLING db's watermark must not forge a truncation verdict for THIS db; report={report:?}"
    );
    assert!(
        report.is_clean(),
        "an untruncated chain with only a foreign watermark stays clean; report={report:?}"
    );
}

// ---------------------------------------------------------------------------
// Own-db watermark still convicts a real truncation (the fix does not blind
// the CONVICTING lane for the resolving database).
// ---------------------------------------------------------------------------

#[test]
fn own_db_watermark_still_detects_truncation() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("d-forensic");
    let ddir = fresh_dir("d-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    let conn = open_db(ddir.path());
    for i in 0..5 {
        append_row(&conn, format!("payload-{i}").as_bytes());
    }
    let this_db_id = genesis_db_id(&conn)
        .expect("genesis db_id")
        .expect("chain has a genesis row");

    // Anchor head=5 under THIS db's own identity, then truncate the tail.
    forensic::record_audit_watermark(5, "own-head-hash", Some(&this_db_id));
    forensic::flush_blocking();
    conn.execute("DELETE FROM signed_events WHERE sequence IN (4, 5)", [])
        .expect("truncate tail");

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(
        report.truncation,
        TruncationCheck::Detected {
            anchored_head: 5,
            db_head: 3,
        },
        "own-db watermark must still convict a real tail truncation; report={report:?}"
    );
}

// ---------------------------------------------------------------------------
// v1.0.0 #3006 / #3068 — TWO STORES, ONE HOST: an IDENTITY-LESS (empty-chain /
// no-genesis) opener sharing the on-host forensic sink with an IDENTIFIED
// sibling must NOT read the sibling's watermark as its own high-water, but a
// LEGACY id-less watermark is still counted (conservative compat window).
// ---------------------------------------------------------------------------

#[test]
fn idless_opener_skips_identified_sibling_but_counts_legacy() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("e-forensic");
    forensic::init(fdir.path(), None).expect("forensic init");

    // A live IDENTIFIED sibling (its own genesis-derived db_id) stamped a high
    // head=78_000 into the SHARED sink.
    forensic::record_audit_watermark(78_000, "sibling-head", Some("sibling-db-id"));
    forensic::flush_blocking();

    // An IDENTITY-LESS opener (None = no genesis / empty chain) must NOT read
    // the identified sibling's watermark — cross-store bleed closed (#3068).
    assert_eq!(
        forensic::last_audit_watermark(None),
        None,
        "an identity-less opener must not read an identified sibling's watermark (#3068)"
    );

    // But a LEGACY id-less watermark on the same sink IS still counted for the
    // identity-less opener (over-detect toward Evidence, never suppression).
    forensic::record_audit_watermark(42, "legacy-head", None);
    forensic::flush_blocking();
    assert_eq!(
        forensic::last_audit_watermark(None),
        Some((42, "legacy-head".to_string())),
        "a legacy id-less watermark must still be counted for an identity-less opener"
    );
}

// ---------------------------------------------------------------------------
// v1.0.0 #3068 — a freshly-migrated store (memories migrated, but the
// signed_events audit chain is genuinely EMPTY: 0 rows, no genesis) must NOT be
// convicted of truncation on a co-located live sibling's climbing watermark.
// This is the exact shape #3068 reported against the pg-186 hive store — a
// TWO-DBs-on-one-host non-interference proof end to end through verify.
// ---------------------------------------------------------------------------

#[test]
fn empty_migrated_store_not_convicted_on_sibling_watermark() {
    let _g = forensic_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fdir = fresh_dir("f-forensic");
    let ddir = fresh_dir("f-db");
    forensic::init(fdir.path(), None).expect("forensic init");

    // A live IDENTIFIED sibling anchored a high head into the SHARED sink.
    forensic::record_audit_watermark(9_000, "sibling-head", Some("live-sibling-db-id"));
    forensic::flush_blocking();

    // A freshly-migrated store: opened, but its signed_events chain is genuinely
    // EMPTY (no rows appended → no genesis → genesis_db_id is None).
    let conn = open_db(ddir.path());
    assert!(
        genesis_db_id(&conn).expect("genesis db_id read").is_none(),
        "an empty-chain migrated store has no genesis identity"
    );

    // The empty store must NOT be convicted of truncation on the sibling's
    // climbing watermark — the raw forensic-watermark lane WITHHOLDS. (Pre-#3068
    // the identity-less read matched the sibling's head=9_000 vs db_head=0 and
    // forged `Detected { anchored_head: 9_000, db_head: 0 }`.)
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_eq!(report.head_sequence, 0, "empty chain; report={report:?}");
    assert_eq!(
        report.truncation,
        TruncationCheck::Unknown,
        "a co-located sibling's watermark must not convict a freshly-migrated empty chain; \
         report={report:?}"
    );
    assert!(
        report.is_clean(),
        "an empty migrated store with only a foreign watermark stays clean; report={report:?}"
    );
}

// ---------------------------------------------------------------------------
// v1.0.0 #3006 / #3068 — POSTGRES TWIN (live-pg, #[ignore]). The pg
// `verify_audit_trail` reads the SAME db_id-scoped shared forensic reader
// ([`last_audit_watermark`]) with the pg-resolved `watermark_db_id`, so a
// co-located FOREIGN sibling watermark must NOT forge a `Detected` truncation
// verdict on the pg store — TWO DBs on one host do not false-convict each other
// (K3 parity). Deterministic on the shared suite pg regardless of whether the
// pg chain is empty (`db_id = None` ⇒ #3068 identity-less WITHHOLD) or populated
// (`db_id = Some` ⇒ #2955 foreign-id skip): either way the foreign sibling is
// scoped out and the fresh forensic sink holds only that sibling row ⇒ Unknown.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres_twin {
    use super::{forensic, fresh_dir};
    use ai_memory::signed_events::TruncationCheck;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_foreign_sibling_watermark_does_not_convict_this_store() {
        // No module lock: #[ignore] + live-pg, run explicitly (never races the
        // sync tests), and a MutexGuard must not be held across an await.
        let Some(pg) = live_pg().await else {
            return;
        };

        // A FRESH forensic sink holding ONLY a FOREIGN identified sibling's
        // watermark, anchored far ABOVE any possible pg head (so a pre-fix
        // match-all / unscoped read would forge `Detected`).
        let fdir = fresh_dir("pg-forensic");
        forensic::init(fdir.path(), None).expect("forensic init");
        forensic::record_audit_watermark(
            9_000_000,
            "pg-foreign-sibling-head",
            Some("pg-foreign-sibling-db-id"),
        );
        forensic::flush_blocking();

        // The pg twin reads the db_id-scoped shared reader: the foreign sibling
        // is scoped out on BOTH the empty-chain (#3068) and populated-chain
        // (#2955) paths, so the sibling never becomes this store's high-water.
        let report = pg.verify_audit_trail(None, None).await.expect("pg verify");
        assert_eq!(
            report.truncation,
            TruncationCheck::Unknown,
            "a foreign sibling's watermark must not forge a truncation verdict on the pg \
             store (K3 cross-store isolation); report={report:?}"
        );
    }
}
