// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3152 — a SAL `update` carrying a content patch AND a lifecycle
//! transition is ONE commit on both backends.
//!
//! Before #3152 the patch committed first and the transition ran as a second,
//! separately committed statement, so a crash, an illegal edge or any error
//! between them persisted the patch, dropped the transition and returned
//! `Err`. Three kinds of proof, per backend:
//!
//! * **Refusal** — an illegal edge rolls the patch back: the row reads back
//!   with its original title, content, lifecycle state and `version`, and no
//!   `in_place_edit` snapshot is left behind. Before #3152 this failed on
//!   both backends (the patch had already committed).
//! * **Visibility** (sqlite) — at the fault point between the two
//!   statements, a second connection still reads the ORIGINAL row: the patch
//!   has executed but nothing has committed.
//! * **Crash** — the test binary is re-executed as a child that arms the
//!   fault point and `abort()`s there (the #3550 pattern). The parent then
//!   reads the row directly from the store and finds it fully unchanged.
//!
//! The fault point itself is test-only
//! ([`crate::recover::durability::in_tx_fault`]); it does not exist in a
//! shipped binary.

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::models::{LifecycleState, Memory, Tier};
use crate::recover::durability::in_tx_fault;
use crate::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

/// The owner every fixture row is stamped with (and the caller that edits it).
const OWNER: &str = "ai:atomicity-3152";
const ORIGINAL_TITLE: &str = "atomicity-3152 original title";
const ORIGINAL_CONTENT: &str = "atomicity-3152 original content body";
const PATCHED_TITLE: &str = "atomicity-3152 patched title";
const PATCHED_CONTENT: &str = "atomicity-3152 patched content body";

/// Env var naming the role a re-executed test plays. Read, never set, in
/// this process: the parent passes it only to the child's `Command`.
const CHILD_ROLE_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_ROLE";
/// Env var carrying the sqlite database path the child acts on.
const CHILD_DB_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_DB";
/// Env var carrying the memory id the child updates.
const CHILD_ID_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_ID";
/// Env var carrying the file the child writes just before aborting.
const CHILD_MARKER_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_MARKER";

const ROLE_SQLITE_SAL: &str = "sqlite-sal";

/// POSIX `SIGABRT`: what `std::process::abort()` raises.
#[cfg(unix)]
const SIGABRT: i32 = 6;

fn fixture(namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: ORIGINAL_TITLE.to_string(),
        content: ORIGINAL_CONTENT.to_string(),
        source: "atomicity-3152".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": OWNER }),
        ..Memory::default()
    }
}

/// A patch that rewrites the content AND asks for `target`.
fn content_and_lifecycle(target: LifecycleState) -> UpdatePatch {
    UpdatePatch {
        title: Some(PATCHED_TITLE.to_string()),
        content: Some(PATCHED_CONTENT.to_string()),
        lifecycle_state: Some(target),
        ..UpdatePatch::default()
    }
}

fn owner_ctx() -> CallerContext {
    CallerContext::for_agent(OWNER)
}

/// The row is exactly as `fixture` stored it.
fn assert_unchanged(mem: &Memory, why: &str) {
    assert_eq!(mem.title, ORIGINAL_TITLE, "{why}: title");
    assert_eq!(mem.content, ORIGINAL_CONTENT, "{why}: content");
    assert_eq!(
        mem.lifecycle_state,
        LifecycleState::Open,
        "{why}: lifecycle"
    );
    assert_eq!(mem.version, 1, "{why}: version");
}

/// Is this process a child re-executed to play `role`?
fn child_role_is(role: &str) -> bool {
    std::env::var(CHILD_ROLE_ENV).is_ok_and(|r| r == role)
}

fn child_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set in a #3152 child"))
}

/// Run THIS test binary again as a child executing exactly `test` (a name
/// in this module) with `env` set, from a clean environment.
#[cfg(unix)]
fn spawn_child(test: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("lib test binary"));
    cmd.args([
        "--exact",
        &format!("store::update_atomicity_3152_tests::{test}"),
        "--test-threads=1",
        "--nocapture",
    ])
    .env_clear()
    .env("TMPDIR", std::env::temp_dir())
    .env("AI_MEMORY_NO_CONFIG", "1");
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn the #3152 child")
}

/// The child died AT the fault point: by `SIGABRT`, after writing `marker`
/// with the id it was updating.
#[cfg(unix)]
fn assert_aborted_at_fault_point(out: &std::process::Output, marker: &Path, id: &str) {
    use std::os::unix::process::ExitStatusExt;
    let detail = format!(
        "status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.signal(),
        Some(SIGABRT),
        "the child must die by abort() at the fault point: {detail}"
    );
    let reached = std::fs::read_to_string(marker)
        .unwrap_or_else(|e| panic!("fault-point marker {marker:?} missing ({e}): {detail}"));
    assert_eq!(reached, id, "the abort must happen while updating {id}");
}

// ------------------------------------------------------------------
// sqlite SAL
// ------------------------------------------------------------------

fn sqlite_store(dir: &Path) -> (crate::store::sqlite::SqliteStore, PathBuf) {
    let path = dir.join("atomicity-3152.db");
    let store = crate::store::sqlite::SqliteStore::open(path.clone()).expect("open sqlite store");
    (store, path)
}

/// Read the row back through a FRESH connection: what is committed.
fn sqlite_committed_row(path: &Path, id: &str) -> Memory {
    let conn = crate::storage::open_read_only(path).expect("open read-only");
    crate::storage::get(&conn, id)
        .expect("read row")
        .expect("row present")
}

fn sqlite_in_place_snapshots(path: &Path, id: &str) -> i64 {
    let conn = crate::storage::open_read_only(path).expect("open read-only");
    conn.query_row(
        "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .expect("count archive snapshots")
}

#[tokio::test]
async fn sqlite_sal_illegal_edge_rolls_the_patch_back_3152() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, path) = sqlite_store(dir.path());
    let mem = fixture("atomicity-3152-sqlite-refuse");
    store.store(&owner_ctx(), &mem).await.expect("seed");

    // open -> done skips `active`: illegal.
    let err = store
        .update(
            &owner_ctx(),
            &mem.id,
            content_and_lifecycle(LifecycleState::Done),
        )
        .await
        .expect_err("an illegal edge must refuse the whole update");
    assert!(
        matches!(err, StoreError::InvalidTransition { .. }),
        "expected InvalidTransition, got {err:?}"
    );
    assert_unchanged(
        &sqlite_committed_row(&path, &mem.id),
        "a refused transition must roll the patch back",
    );
    assert_eq!(
        sqlite_in_place_snapshots(&path, &mem.id),
        0,
        "the in_place_edit snapshot must roll back with the patch"
    );
}

#[tokio::test]
async fn sqlite_sal_legal_edge_commits_patch_and_transition_together_3152() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, path) = sqlite_store(dir.path());
    let mem = fixture("atomicity-3152-sqlite-legal");
    store.store(&owner_ctx(), &mem).await.expect("seed");

    store
        .update(
            &owner_ctx(),
            &mem.id,
            content_and_lifecycle(LifecycleState::Active),
        )
        .await
        .expect("open -> active is legal");
    let row = sqlite_committed_row(&path, &mem.id);
    assert_eq!(row.content, PATCHED_CONTENT);
    assert_eq!(row.lifecycle_state, LifecycleState::Active);
    // One bump for the patch, one for the transition — the pre-#3152
    // version arithmetic is unchanged; only the commit count is.
    assert_eq!(row.version, 3);
}

/// At the fault point the patch has EXECUTED on the writer's transaction
/// but a second connection still reads the original row.
#[tokio::test]
async fn sqlite_sal_patch_is_uncommitted_at_the_fault_point_3152() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, path) = sqlite_store(dir.path());
    let mem = fixture("atomicity-3152-sqlite-observe");
    store.store(&owner_ctx(), &mem).await.expect("seed");

    let seen: Arc<Mutex<Option<Memory>>> = Arc::new(Mutex::new(None));
    let (seen_in, path_in, id_in) = (Arc::clone(&seen), path.clone(), mem.id.clone());
    in_tx_fault::arm(
        &mem.id,
        in_tx_fault::Action::Observe(Box::new(move || {
            let row = sqlite_committed_row(&path_in, &id_in);
            *seen_in.lock().unwrap_or_else(PoisonError::into_inner) = Some(row);
        })),
    );
    let res = store
        .update(
            &owner_ctx(),
            &mem.id,
            content_and_lifecycle(LifecycleState::Active),
        )
        .await;
    in_tx_fault::disarm(&mem.id);
    res.expect("open -> active is legal");

    let observed = seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("the fault point must be reached between patch and transition");
    assert_unchanged(
        &observed,
        "between the patch and the transition nothing may be committed",
    );
    let row = sqlite_committed_row(&path, &mem.id);
    assert_eq!(row.content, PATCHED_CONTENT);
    assert_eq!(row.lifecycle_state, LifecycleState::Active);
}

/// Child half of the sqlite crash test: a no-op unless re-executed.
#[tokio::test]
async fn sqlite_sal_crash_child_3152() {
    if !child_role_is(ROLE_SQLITE_SAL) {
        return;
    }
    let path = PathBuf::from(child_var(CHILD_DB_ENV));
    let id = child_var(CHILD_ID_ENV);
    let store = crate::store::sqlite::SqliteStore::open(path).expect("child open");
    in_tx_fault::arm(
        &id,
        in_tx_fault::Action::Abort {
            marker: PathBuf::from(child_var(CHILD_MARKER_ENV)),
        },
    );
    let res = store
        .update(
            &owner_ctx(),
            &id,
            content_and_lifecycle(LifecycleState::Active),
        )
        .await;
    panic!("the #3152 fault point was never reached; update returned {res:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn sqlite_sal_crash_between_patch_and_transition_leaves_row_unchanged_3152() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (store, path) = sqlite_store(dir.path());
    let mem = fixture("atomicity-3152-sqlite-crash");
    store.store(&owner_ctx(), &mem).await.expect("seed");
    drop(store);
    let marker = dir.path().join("reached-3152");

    let out = tokio::task::spawn_blocking({
        let (path, id, marker) = (path.clone(), mem.id.clone(), marker.clone());
        move || {
            spawn_child(
                "sqlite_sal_crash_child_3152",
                &[
                    (CHILD_ROLE_ENV, ROLE_SQLITE_SAL),
                    (CHILD_DB_ENV, &path.to_string_lossy()),
                    (CHILD_ID_ENV, &id),
                    (CHILD_MARKER_ENV, &marker.to_string_lossy()),
                ],
            )
        }
    })
    .await
    .expect("join the child spawn");
    assert_aborted_at_fault_point(&out, &marker, &mem.id);

    // Direct store read after the crash: the row is fully unchanged.
    let reopened = crate::store::sqlite::SqliteStore::open(path.clone()).expect("reopen");
    assert_unchanged(
        &reopened
            .get(&owner_ctx(), &mem.id)
            .await
            .expect("store read"),
        "a crash between the patch and the transition",
    );
    assert_eq!(sqlite_in_place_snapshots(&path, &mem.id), 0);
    let conn = crate::storage::open_read_only(&path).expect("open read-only");
    assert!(
        crate::recover::durability::integrity_ok(&conn).expect("integrity check"),
        "the database must be sound after the crash"
    );
}

// ------------------------------------------------------------------
// postgres: trait `update` and If-Match `update_with_expected_version`
// ------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use crate::store::postgres::PostgresStore;

    /// The live-postgres URL the pg children connect with (the house var).
    const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
    const ROLE_PG_TRAIT: &str = "pg-trait";
    const ROLE_PG_IF_MATCH: &str = "pg-if-match";

    fn pg_url(test: &str) -> Option<String> {
        let url = std::env::var(PG_URL_ENV).ok();
        if url.is_none() {
            eprintln!("SKIP {test}: {PG_URL_ENV} unset");
        }
        url
    }

    async fn seeded(url: &str, namespace: &str) -> (PostgresStore, Memory) {
        let store = PostgresStore::connect(url).await.expect("connect");
        let mem = fixture(namespace);
        store.store(&owner_ctx(), &mem).await.expect("seed");
        (store, mem)
    }

    async fn pg_in_place_snapshots(store: &PostgresStore, id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .expect("count archive snapshots")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pg_trait_update_illegal_edge_rolls_the_patch_back_3152() {
        let Some(url) = pg_url("pg_trait_update_illegal_edge_rolls_the_patch_back_3152") else {
            return;
        };
        let (store, mem) = seeded(&url, "atomicity-3152-pg-trait-refuse").await;
        let err = store
            .update(
                &owner_ctx(),
                &mem.id,
                content_and_lifecycle(LifecycleState::Done),
            )
            .await
            .expect_err("an illegal edge must refuse the whole update");
        assert!(
            matches!(err, StoreError::InvalidTransition { .. }),
            "expected InvalidTransition, got {err:?}"
        );
        assert_unchanged(
            &store.get(&owner_ctx(), &mem.id).await.expect("read"),
            "pg trait update: a refused transition must roll the patch back",
        );
        assert_eq!(pg_in_place_snapshots(&store, &mem.id).await, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pg_if_match_illegal_edge_rolls_the_patch_back_3152() {
        let Some(url) = pg_url("pg_if_match_illegal_edge_rolls_the_patch_back_3152") else {
            return;
        };
        let (store, mem) = seeded(&url, "atomicity-3152-pg-if-match-refuse").await;
        let err = store
            .update_with_expected_version(
                &owner_ctx(),
                &mem.id,
                content_and_lifecycle(LifecycleState::Done),
                Some(1),
            )
            .await
            .expect_err("an illegal edge must refuse the whole update");
        assert!(
            matches!(err, StoreError::InvalidTransition { .. }),
            "expected InvalidTransition, got {err:?}"
        );
        assert_unchanged(
            &store.get(&owner_ctx(), &mem.id).await.expect("read"),
            "pg If-Match update: a refused transition must roll the patch back",
        );
        assert_eq!(pg_in_place_snapshots(&store, &mem.id).await, 0);
    }

    /// The legal case commits both, and the If-Match path now reports the
    /// version the row actually carries (the transition's bump included).
    #[tokio::test(flavor = "multi_thread")]
    async fn pg_if_match_legal_edge_commits_both_and_reports_the_stored_version_3152() {
        let Some(url) =
            pg_url("pg_if_match_legal_edge_commits_both_and_reports_the_stored_version_3152")
        else {
            return;
        };
        let (store, mem) = seeded(&url, "atomicity-3152-pg-if-match-legal").await;
        let reported = store
            .update_with_expected_version(
                &owner_ctx(),
                &mem.id,
                content_and_lifecycle(LifecycleState::Active),
                Some(1),
            )
            .await
            .expect("open -> active is legal");
        let row = store.get(&owner_ctx(), &mem.id).await.expect("read");
        assert_eq!(row.content, PATCHED_CONTENT);
        assert_eq!(row.lifecycle_state, LifecycleState::Active);
        assert_eq!(row.version, 3, "one bump for the patch, one for the edge");
        assert_eq!(
            reported, row.version,
            "the returned version is the stored one"
        );
    }

    /// Child half of both pg crash tests: a no-op unless re-executed.
    #[test]
    fn pg_crash_child_3152() {
        let if_match = child_role_is(ROLE_PG_IF_MATCH);
        if !if_match && !child_role_is(ROLE_PG_TRAIT) {
            return;
        }
        let url = child_var(PG_URL_ENV);
        let id = child_var(CHILD_ID_ENV);
        let marker = PathBuf::from(child_var(CHILD_MARKER_ENV));
        let rt = tokio::runtime::Runtime::new().expect("child runtime");
        let res = rt.block_on(async {
            let store = PostgresStore::connect(&url).await.expect("child connect");
            in_tx_fault::arm(&id, in_tx_fault::Action::Abort { marker });
            let patch = content_and_lifecycle(LifecycleState::Active);
            if if_match {
                store
                    .update_with_expected_version(&owner_ctx(), &id, patch, Some(1))
                    .await
                    .map(|_| ())
            } else {
                store.update(&owner_ctx(), &id, patch).await
            }
        });
        panic!("the #3152 fault point was never reached; update returned {res:?}");
    }

    #[cfg(unix)]
    fn pg_crash_between_patch_and_transition(role: &str, namespace: &str) {
        let Some(url) = pg_url(namespace) else {
            return;
        };
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let (store, mem) = rt.block_on(seeded(&url, namespace));
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("reached-3152");
        let out = spawn_child(
            "pg::pg_crash_child_3152",
            &[
                (CHILD_ROLE_ENV, role),
                (PG_URL_ENV, &url),
                (CHILD_ID_ENV, &mem.id),
                (CHILD_MARKER_ENV, &marker.to_string_lossy()),
            ],
        );
        assert_aborted_at_fault_point(&out, &marker, &mem.id);
        // Direct store read after the crash: the child's transaction died
        // with its connection, so the row is fully unchanged.
        let row = rt
            .block_on(store.get(&owner_ctx(), &mem.id))
            .expect("store read");
        assert_unchanged(&row, &format!("pg {role}: a crash between the statements"));
        assert_eq!(rt.block_on(pg_in_place_snapshots(&store, &mem.id)), 0);
    }

    #[cfg(unix)]
    #[test]
    fn pg_trait_update_crash_between_patch_and_transition_leaves_row_unchanged_3152() {
        pg_crash_between_patch_and_transition(ROLE_PG_TRAIT, "atomicity-3152-pg-trait-crash");
    }

    #[cfg(unix)]
    #[test]
    fn pg_if_match_crash_between_patch_and_transition_leaves_row_unchanged_3152() {
        pg_crash_between_patch_and_transition(ROLE_PG_IF_MATCH, "atomicity-3152-pg-if-match-crash");
    }
}
