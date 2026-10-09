// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2554 — the bootstrap DDL must be atomic with the migration ladder.
//!
//! `db::open` ran `execute_batch(SCHEMA)` — this binary's FULL current
//! bootstrap — outside any transaction and before `migrate`, whose ladder is
//! all-or-nothing under `BEGIN EXCLUSIVE` with the stamp written at the tail.
//! A ladder that failed (crash, ENOSPC, a refusing arm) therefore left the
//! newer bootstrap objects COMMITTED with the stamp still at the old version,
//! and an older binary then saw `observed == its tip`, passed the #2445
//! downgrade guard, and operated a structurally newer database.
//!
//! Fix (5-agent vote (4d3ea1c5), 5/5 option A): when an upgrade is pending the
//! bootstrap runs as the first statement inside the ladder's transaction, so a
//! failed ladder rolls the bootstrap back with it. These cells make the ladder
//! fail deterministically AFTER the bootstrap (the v97 arm refuses ambiguous
//! retired-key history) and assert the database is left exactly as found.

use std::path::{Path, PathBuf};

/// A bootstrap-only object: created by `SCHEMA` (and by the v20 arm, which a
/// stamp of 96 never replays) and by nothing at or above v97.
const BOOTSTRAP_ONLY_INDEX: &str = "idx_audit_log_event_type";
const PRE_V97: i64 = 96;
/// A shape-valid, obviously fake 43-char base64url Ed25519 public key.
const PLACEHOLDER_PUBKEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// A fully migrated database, then rewound to v96 with the bootstrap-only
/// index removed and corrupt key history that makes the v97 arm refuse.
fn rewound_db_whose_v97_arm_refuses(dir: &Path) -> PathBuf {
    let path = dir.join("ai-memory.db");
    drop(ai_memory::db::open(&path).expect("fresh open"));
    let conn = ai_memory::db::open_unmigrated(&path).expect("raw open");
    conn.execute_batch(&format!(
        "DROP INDEX {BOOTSTRAP_ONLY_INDEX};
         DROP INDEX idx_agent_pubkey_history_key_once;
         DELETE FROM agent_pubkey_history;
         INSERT INTO agent_pubkey_history
           (agent_id, version, pubkey_b64, bind_authority, bound_at, superseded_at)
           VALUES ('ai:corrupt-2554', 1, '{PLACEHOLDER_PUBKEY}', 'legacy_unproven',
                   '2026-01-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00');
         INSERT INTO agent_pubkey_history
           (agent_id, version, pubkey_b64, bind_authority, bound_at)
           VALUES ('ai:corrupt-2554', 2, '{PLACEHOLDER_PUBKEY}', 'guardian_recovery',
                   '2026-03-01T00:00:00+00:00');
         DELETE FROM schema_version;
         INSERT INTO schema_version (version) VALUES ({PRE_V97});"
    ))
    .expect("rewind fixture");
    path
}

fn index_present(path: &Path, name: &str) -> bool {
    let conn = ai_memory::db::open_unmigrated(path).expect("probe open");
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .expect("sqlite_master probe")
        > 0
}

fn stamp(path: &Path) -> i64 {
    let conn = ai_memory::db::open_unmigrated(path).expect("probe open");
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .expect("stamp probe")
}

#[test]
fn a_failed_ladder_rolls_back_the_bootstrap_ddl_2554() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = rewound_db_whose_v97_arm_refuses(dir.path());
    assert!(
        !index_present(&path, BOOTSTRAP_ONLY_INDEX),
        "fixture precondition"
    );

    let err = ai_memory::db::open(&path).expect_err("the v97 arm must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("retired key appears in multiple versions"),
        "the failure must come from inside the ladder: {msg}"
    );
    assert_eq!(stamp(&path), PRE_V97, "a refused ladder must not stamp");
    assert!(
        !index_present(&path, BOOTSTRAP_ONLY_INDEX),
        "bootstrap DDL committed although the ladder failed: the database is \
         now structurally newer than its stamp"
    );
}

#[test]
fn a_successful_upgrade_still_lands_the_bootstrap_objects_2554() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    drop(ai_memory::db::open(&path).expect("fresh open"));
    {
        let conn = ai_memory::db::open_unmigrated(&path).expect("raw open");
        conn.execute_batch(&format!(
            "DROP INDEX {BOOTSTRAP_ONLY_INDEX};
             DELETE FROM schema_version;
             INSERT INTO schema_version (version) VALUES ({PRE_V97});"
        ))
        .expect("rewind");
    }
    drop(ai_memory::db::open(&path).expect("upgrade open"));
    assert_eq!(
        stamp(&path),
        ai_memory::storage::migrations::current_schema_version()
    );
    assert!(index_present(&path, BOOTSTRAP_ONLY_INDEX), "bootstrap ran");
}
