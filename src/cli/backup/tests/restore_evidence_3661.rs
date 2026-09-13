// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! v1.0.0 #3661 — evidence for a restore no verified manifest vouched for.
//!
//! Pre-fix the only record was a stderr `WARNING` plus a fire-and-forget
//! forensic row whose writer failures were swallowed; the `--json`
//! `audit_sink` flag said the sink was ENABLED, not that anything landed;
//! and the restored database's own `signed_events` spine never learned its
//! bytes had been accepted unverified. These tests pin the three properties
//! the fix adds: acknowledged sinks reported apart, a fsynced journal beside
//! the database written BEFORE any byte is staged, and the import of that
//! journal into the spine of whichever database is live at the next open —
//! the restored one, the rolled-back one, or the one an aborted publish left.
// File-level `cfg(test)` so the repo's source gates classify this file as
// test code (it is only ever compiled inside `backup::tests`).
#![cfg(test)]

use super::*;
use crate::restore_evidence::{self, PHASE_INTENT, PHASE_OUTCOME, SINK_DISABLED, SINK_PERSISTED};
use crate::signed_events::event_types::BACKUP_RESTORE_UNVERIFIED;

/// Review rework (#3661): import state lives in the sidecar cursor keyed by
/// entry digest, never in the journal. `true` when every journal entry's
/// digest is recorded there.
fn all_imported(db: &std::path::Path) -> bool {
    let cursor = restore_evidence::read_cursor(db).expect("cursor");
    let entries = journal_entries(db);
    !entries.is_empty() && entries.iter().all(|e| cursor.contains(&e.entry_hash()))
}

type Guards = (
    std::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
);

/// The forensic sink and the store-url resolution are process-global.
fn locks() -> Guards {
    let env = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sink = crate::governance::audit::forensic_sink_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (env, sink)
}

/// A live database with one row and a consistent `VACUUM INTO` snapshot.
fn fixture(env: &TestEnv) -> (PathBuf, PathBuf) {
    let db = env.db_path.clone();
    seed_memory(&db, "ns-3661", "live", "row in the live database");
    let snapshot = db.with_file_name("snapshot-3661.db");
    let conn = crate::db::open(&db).expect("open live db");
    conn.execute("VACUUM INTO ?1", [snapshot.to_string_lossy().as_ref()])
        .expect("vacuum into");
    (db, snapshot)
}

fn skip_verify_args(snapshot: PathBuf) -> RestoreArgs {
    RestoreArgs {
        from: snapshot,
        snapshot: None,
        latest: false,
        skip_verify: true,
        allow_unsigned_manifest: false,
        store_url: None,
        yes: true,
    }
}

fn restore_with(
    env: &mut TestEnv,
    db: &Path,
    args: &RestoreArgs,
    io: &mut dyn PublishIo,
) -> Result<()> {
    env.stdout.clear();
    env.stderr.clear();
    let mut out = env.output();
    run_restore_with(db, args, true, &mut out, test_restore_policy(false), io)
}

fn restore_json(env: &mut TestEnv, db: &Path, args: &RestoreArgs) -> serde_json::Value {
    restore_with(env, db, args, &mut RealPublishIo).expect("unverified restore completes");
    serde_json::from_str(env.stdout_str().trim()).expect("--json envelope")
}

/// Opening IMPORTS the journal; the returned events are the imported ones.
fn spine_events(db: &Path) -> Vec<crate::signed_events::SignedEvent> {
    let conn = crate::db::open(db).expect("open db");
    crate::signed_events::list_signed_events(&conn, None, 1_000, 0)
        .expect("list signed events")
        .into_iter()
        .filter(|e| e.event_type == BACKUP_RESTORE_UNVERIFIED)
        .collect()
}

fn journal_entries(db: &Path) -> Vec<restore_evidence::RestoreEvidenceEntry> {
    restore_evidence::read_journal(&restore_evidence::journal_path(db))
        .expect("journal readable")
        .0
}

fn forensic_kinds(dir: &Path) -> Vec<String> {
    crate::governance::audit::flush_blocking();
    let mut kinds = Vec::new();
    for entry in std::fs::read_dir(dir).expect("forensic dir").flatten() {
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in text.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                && let Some(kind) = v["kind"].as_str()
            {
                kinds.push(kind.to_string());
            }
        }
    }
    kinds
}

fn sink(e: &serde_json::Value, path: &[&str]) -> String {
    let mut v = &e["audit_sink"];
    for key in path {
        v = &v[*key];
    }
    v.as_str().unwrap_or_default().to_string()
}

#[test]
fn unverified_restore_persists_acknowledged_evidence_and_imports_at_next_open_3661() {
    let _g = locks();
    let mut env = TestEnv::fresh();
    let (db, snapshot) = fixture(&env);
    let forensic_dir = db.with_file_name("forensic-3661");
    crate::governance::audit::init(&forensic_dir, None).expect("forensic sink");

    let e = restore_json(&mut env, &db, &skip_verify_args(snapshot));
    assert_eq!(sink(&e, &["forensic", "intent"]), SINK_PERSISTED, "{e}");
    assert_eq!(sink(&e, &["forensic", "outcome"]), SINK_PERSISTED, "{e}");
    assert_eq!(sink(&e, &["journal", "intent"]), SINK_PERSISTED, "{e}");
    assert_eq!(sink(&e, &["journal", "outcome"]), SINK_PERSISTED, "{e}");
    assert!(sink(&e, &["journal", "path"]).ends_with(restore_evidence::JOURNAL_SUFFIX));
    assert_eq!(sink(&e, &["spine"]), restore_evidence::SPINE_PENDING_IMPORT);

    // The journal: intent BEFORE outcome, outcome linked to the intent, each
    // naming the acknowledged forensic row it pairs with.
    let entries = journal_entries(&db);
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0].phase, PHASE_INTENT);
    assert_eq!(entries[1].phase, PHASE_OUTCOME);
    assert_eq!(
        entries[1].intent_ref.as_deref(),
        Some(entries[0].entry_hash().as_str())
    );
    assert!(
        entries.iter().all(|x| x.forensic_row.is_some()),
        "{entries:?}"
    );
    assert!(entries.iter().all(|x| x.forensic_sink == SINK_PERSISTED));
    assert!(entries[1].durable_publish.is_some());
    assert!(
        restore_evidence::read_cursor(&db)
            .expect("cursor")
            .is_empty(),
        "not yet opened: nothing is in the import cursor"
    );

    // The forensic chain carries both rows (flushed, then read back).
    let kinds = forensic_kinds(&forensic_dir);
    assert!(
        kinds.contains(&RESTORE_UNVERIFIED_INTENT_KIND.to_string()),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&RESTORE_UNVERIFIED_AUDIT_KIND.to_string()),
        "{kinds:?}"
    );

    // The next open imports both entries into the spine, once.
    assert_eq!(spine_events(&db).len(), 2);
    assert!(all_imported(&db), "every journal entry is in the cursor");
    assert_eq!(spine_events(&db).len(), 2, "a second open imports nothing");
    crate::governance::audit::shutdown();
}

#[test]
fn forensic_sink_failure_is_reported_and_the_journal_still_lands_3661() {
    let _g = locks();
    let mut env = TestEnv::fresh();
    let (db, snapshot) = fixture(&env);
    let forensic_dir = db.with_file_name("forensic-3661-ro");
    crate::governance::audit::init(&forensic_dir, None).expect("forensic sink");
    // The sink is configured but its directory refuses new files: the daily
    // file cannot be created, so the acknowledged append must FAIL — and say so.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&forensic_dir, std::fs::Permissions::from_mode(0o500))
            .expect("chmod forensic dir");
    }
    let e = restore_json(&mut env, &db, &skip_verify_args(snapshot));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&forensic_dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore forensic dir mode");
    }
    assert!(
        sink(&e, &["forensic", "intent"]).starts_with(restore_evidence::SINK_FAILED_PREFIX),
        "{e}"
    );
    assert!(
        env.stderr_str().contains("could not be persisted"),
        "{}",
        env.stderr_str()
    );
    // The journal is independent of the forensic sink and records its failure.
    assert_eq!(sink(&e, &["journal", "intent"]), SINK_PERSISTED, "{e}");
    let entries = journal_entries(&db);
    assert_eq!(entries.len(), 2);
    assert!(
        entries[0]
            .forensic_sink
            .starts_with(restore_evidence::SINK_FAILED_PREFIX)
    );
    assert!(entries[0].forensic_row.is_none());
    assert_eq!(
        spine_events(&db).len(),
        2,
        "the spine import does not depend on the sink"
    );
    crate::governance::audit::shutdown();
}

#[test]
fn sink_disabled_still_journals_and_imports_3661() {
    let _g = locks();
    crate::governance::audit::shutdown();
    let mut env = TestEnv::fresh();
    let (db, snapshot) = fixture(&env);
    let e = restore_json(&mut env, &db, &skip_verify_args(snapshot));
    assert_eq!(sink(&e, &["forensic", "intent"]), SINK_DISABLED, "{e}");
    assert_eq!(sink(&e, &["forensic", "outcome"]), SINK_DISABLED, "{e}");
    assert_eq!(sink(&e, &["journal", "outcome"]), SINK_PERSISTED, "{e}");
    let entries = journal_entries(&db);
    assert!(
        entries
            .iter()
            .all(|x| x.forensic_sink == SINK_DISABLED && x.forensic_row.is_none())
    );
    // Evidence never lives only in the terminal: the spine still gets both.
    assert_eq!(spine_events(&db).len(), 2);
}

#[test]
fn rollback_copy_back_keeps_the_evidence_for_the_next_open_3661() {
    let _g = locks();
    crate::governance::audit::shutdown();
    let mut env = TestEnv::fresh();
    let (db, snapshot) = fixture(&env);
    let e = restore_json(&mut env, &db, &skip_verify_args(snapshot));
    let rollback = PathBuf::from(e["rollback"].as_str().expect("rollback path"));
    // The operator puts the previous database back. The journal is a sibling
    // FILE of the path, so it is untouched by the copy.
    std::fs::copy(&rollback, &db).expect("copy the rollback back");
    assert!(
        restore_evidence::read_cursor(&db)
            .expect("cursor")
            .is_empty()
    );
    // The next open — of the ROLLED-BACK database — imports the evidence.
    assert_eq!(spine_events(&db).len(), 2);
    assert!(all_imported(&db));
}

/// A publish that aborts after the intent (here: the pre-copy checkpoint
/// refuses) leaves the intent entry alone in the journal, and the next open
/// still imports it — an aborted unverified restore is evidenced too.
#[test]
fn intent_is_journaled_even_when_the_publish_aborts_3661() {
    struct FailCheckpoint;
    impl PublishIo for FailCheckpoint {
        fn checkpoint(&mut self, _conn: &rusqlite::Connection, _target: &Path) -> Result<()> {
            anyhow::bail!("injected checkpoint failure (#3661)")
        }
    }
    let _g = locks();
    crate::governance::audit::shutdown();
    let mut env = TestEnv::fresh();
    let (db, snapshot) = fixture(&env);
    let err = restore_with(
        &mut env,
        &db,
        &skip_verify_args(snapshot),
        &mut FailCheckpoint,
    )
    .expect_err("the injected checkpoint failure aborts the restore");
    assert!(err.to_string().contains("injected"), "{err:#}");
    let entries = journal_entries(&db);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].phase, PHASE_INTENT);
    assert_eq!(spine_events(&db).len(), 1, "the intent alone is imported");
}
