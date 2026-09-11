// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3550 — `restore` publish-ordering tests: sidecars before the
//! publish (fail closed), durable publish reported, `--snapshot` selection,
//! locks held through the publish, and the degraded arms (refusals) the
//! #3550 follow-up vote (memory 64694e75) settled. A child of
//! `cli::backup::tests`, so the
//! shared fixtures there (`take_backup`, `find_pre_restore_copy`, …) are in
//! scope through `super::*`.

#![cfg(test)]

use super::*;

// ==================================================================
// v1.0.0 #3550 — sidecars before the publish (fail closed), durable
// publish reported, `--snapshot` selection, lock held through publish.
// ==================================================================

/// v1.0.0 #3550 — REPLACES the #3131 pin
/// `remove_stale_sidecars_warns_when_unlink_fails_and_does_not_err_3131`,
/// which asserted that an unlink failure only WARNED. A sidecar that
/// cannot be removed now refuses the publish.
#[test]
fn clear_live_sidecars_refuses_when_a_sidecar_cannot_be_removed_3550() {
    let env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    let wal = sidecar_path(&db, "-wal");
    std::fs::create_dir(&wal).expect("plant a directory as the -wal sidecar");
    let err = clear_live_sidecars(&db, &mut RealPublishIo)
        .expect_err("an unremovable sidecar must refuse the publish");
    let msg = format!("{err:#}");
    assert!(msg.contains("refusing to publish"), "got: {msg}");
    assert!(msg.contains("#3550"), "got: {msg}");
    assert!(wal.is_dir(), "the planted directory must still be there");
    let _ = std::fs::remove_dir(&wal);
}

/// Every sidecar kind goes, including a DANGLING symlink (which
/// `Path::exists` reports as absent).
#[test]
fn clear_live_sidecars_removes_every_sidecar_kind_3550() {
    let env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "t", "c");
    for suffix in ["-wal", "-shm"] {
        std::fs::write(sidecar_path(&db, suffix), b"stale").expect("plant sidecar");
    }
    let journal = sidecar_path(&db, "-journal");
    #[cfg(unix)]
    std::os::unix::fs::symlink(db.with_extension("gone"), &journal)
        .expect("plant a dangling -journal symlink");
    #[cfg(not(unix))]
    std::fs::write(&journal, b"stale").expect("plant sidecar");
    clear_live_sidecars(&db, &mut RealPublishIo).expect("regular sidecars must unlink");
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        assert!(
            !path_present(&sidecar_path(&db, suffix)),
            "{suffix} must be gone"
        );
    }
}

/// Injectable publish I/O: fail the sidecar unlink, either directory
/// fsync, the checkpoint, the staged lock or the no-replace link; run an
/// observer at every step; unwind (panic) at one of them, or — in a child
/// process — really abort there.
#[derive(Default)]
struct FaultIo {
    fail_remove: bool,
    fail_sync_before_publish: bool,
    fail_sync_after_publish: bool,
    fail_checkpoint: bool,
    fail_lock_staged: bool,
    link_error: Option<std::io::ErrorKind>,
    crash_at: Option<PublishStep>,
    /// `(step, marker)`: write `marker` then `std::process::abort()` at
    /// `step` — no destructor, no unwinding, no SQLite close.
    abort_at: Option<(PublishStep, PathBuf)>,
    remove_calls: usize,
    sync_calls: usize,
    steps: Vec<PublishStep>,
    observe: Option<Box<dyn FnMut(PublishStep, &Path)>>,
}

impl PublishIo for FaultIo {
    fn checkpoint(&mut self, conn: &rusqlite::Connection, target: &Path) -> Result<()> {
        if self.fail_checkpoint {
            anyhow::bail!("injected checkpoint failure on {}", target.display());
        }
        checkpoint_before_sidecar_removal(conn, target)
    }
    fn lock_staged(
        &mut self,
        staged: &Path,
    ) -> std::result::Result<rusqlite::Connection, LockError> {
        if self.fail_lock_staged {
            return Err(LockError::Probe("injected staged-lock failure".to_string()));
        }
        lock_exclusive(staged)
    }
    fn hard_link(&mut self, staged: &Path, target: &Path) -> std::io::Result<()> {
        if let Some(kind) = self.link_error {
            return Err(std::io::Error::new(kind, "injected hard-link failure"));
        }
        std::fs::hard_link(staged, target)
    }
    fn remove_sidecar(&mut self, path: &Path) -> std::io::Result<()> {
        self.remove_calls += 1;
        if self.fail_remove {
            return Err(std::io::Error::other("injected unlink failure"));
        }
        std::fs::remove_file(path)
    }
    fn sync_dir(&mut self, dir: &Path) -> std::io::Result<()> {
        self.sync_calls += 1;
        let fail = if self.sync_calls == 1 {
            self.fail_sync_before_publish
        } else {
            self.fail_sync_after_publish
        };
        if fail {
            return Err(std::io::Error::other("injected directory fsync failure"));
        }
        sync_dir(dir)
    }
    fn at(&mut self, step: PublishStep, target: &Path) {
        self.steps.push(step);
        if let Some(observe) = self.observe.as_mut() {
            observe(step, target);
        }
        if let Some((abort_step, marker)) = self.abort_at.as_ref()
            && *abort_step == step
        {
            std::fs::write(marker, format!("{step:?}")).expect("write the abort marker");
            std::process::abort();
        }
        assert!(self.crash_at != Some(step), "injected crash at {step:?}");
    }
}

/// Standard posture, verifying against the module's test operator key
/// (#3199: a policy now carries a key, so these are no longer `const`s).
fn standard() -> RestorePolicy {
    test_restore_policy(false)
}

/// The asi-hard posture, verifying against the module's test operator key.
fn asi_hard() -> RestorePolicy {
    test_restore_policy(true)
}

const ALL_STEPS: [PublishStep; 7] = [
    PublishStep::Staged,
    PublishStep::Locked,
    PublishStep::AsideCopied,
    PublishStep::SidecarsCleared,
    PublishStep::PrePublishSynced,
    PublishStep::Published,
    PublishStep::PostPublishSynced,
];

fn restore_args_3550(from: PathBuf) -> RestoreArgs {
    RestoreArgs {
        from,
        snapshot: None,
        skip_verify: false,
        latest: false,
        allow_unsigned_manifest: false,
        store_url: None,
        yes: true,
    }
}

fn memory_rows(path: &Path) -> i64 {
    let conn = db::open_read_only(path).expect("database must open");
    conn.query_row(
        crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
        [],
        |r| r.get(0),
    )
    .expect("count memories")
}

fn restore_tmp_leftovers(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(RESTORE_TMP_INFIX))
        .count()
}

/// Write one memory whose commit stays in `<db>-wal`: the writer never
/// checkpoints, and its close neither checkpoints nor deletes the WAL. The
/// row then exists ONLY as WAL frames — what a daemon killed mid-run
/// leaves behind, and exactly what a publish that orders its unlink wrong
/// replays into the restored file. (A `seed_memory` connection folds its WAL
/// and deletes it on close, which is why the earlier fixture could not see
/// that class at all.)
fn seed_row_left_in_the_wal(db: &Path, title: &str) {
    let conn = db::open(db).expect("db::open");
    conn.pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable the autocheckpoint");
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .expect("keep the frames in the WAL on close");
    crate::cli::test_utils::seed_memory_on(&conn, "ns", title, "b");
    drop(conn);
    let wal_len = std::fs::metadata(sidecar_path(db, "-wal")).map_or(0, |m| m.len());
    assert!(wal_len > 0, "the fixture row must live in {db:?}-wal");
}

/// A live database holding 2 rows — the second ONLY in its `-wal` — and a
/// snapshot holding 1, so which one sits at the target is observable and a
/// lost or misplaced WAL changes the answer. Returns `(db, snapshot path)`.
fn two_row_live_one_row_snapshot(env: &mut TestEnv, tag: &str) -> (PathBuf, PathBuf) {
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "in-the-snapshot", "a");
    let backup_dir = db.parent().unwrap().join(format!("backups-3550-{tag}"));
    let manifest = take_backup(env, &db, &backup_dir);
    seed_row_left_in_the_wal(&db, "added-after-the-backup");
    assert_eq!(memory_rows(&db), 2, "the WAL row must be visible");
    (db, backup_dir.join(&manifest.snapshot))
}

/// v1.0.0 #3550 — run THIS test binary again as a child that executes one
/// test (`test`, a `publish_3550::` name) with `env` set, the shape
/// `federation::tests` and `governance::deferred_audit::tests` use. The
/// child starts from a clean environment so no parallel test's posture
/// leaks in.
#[cfg(unix)]
fn spawn_child_test(test: &str, env: &[(&str, &Path)]) -> std::process::Output {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("lib test binary"));
    cmd.args([
        "--exact",
        &format!("cli::backup::tests::publish_3550::{test}"),
        "--test-threads=1",
        "--nocapture",
    ])
    .env_clear()
    .env("TMPDIR", std::env::temp_dir())
    .env("AI_MEMORY_NO_CONFIG", "1");
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn the child test")
}

/// Env var naming the role a re-executed test plays. Read, never set, in
/// this process: the parent passes it only to the child's `Command`.
#[cfg(unix)]
const CHILD_ROLE_ENV: &str = "AI_MEMORY_TEST_3550_CHILD_ROLE";
/// Env var carrying the database path a child acts on.
#[cfg(unix)]
const CHILD_DB_ENV: &str = "AI_MEMORY_TEST_3550_CHILD_DB";
/// Env var carrying the snapshot path a restore child restores.
#[cfg(unix)]
const CHILD_SNAPSHOT_ENV: &str = "AI_MEMORY_TEST_3550_CHILD_SNAPSHOT";
/// Env var carrying the step a crash child aborts at (its `Debug` name).
#[cfg(unix)]
const CHILD_STEP_ENV: &str = "AI_MEMORY_TEST_3550_CHILD_STEP";
/// Env var carrying the file a crash child writes just before aborting.
#[cfg(unix)]
const CHILD_MARKER_ENV: &str = "AI_MEMORY_TEST_3550_CHILD_MARKER";
/// The writer child's role value.
#[cfg(unix)]
const ROLE_WRITER: &str = "writer";
/// The crash child's role value.
#[cfg(unix)]
const ROLE_CRASH: &str = "crash";

/// Is this process a child re-executed to play `role`?
#[cfg(unix)]
fn child_role_is(role: &str) -> bool {
    std::env::var(CHILD_ROLE_ENV).is_ok_and(|r| r == role)
}

/// A child path argument (present whenever the role is).
#[cfg(unix)]
fn child_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(key).unwrap_or_else(|| panic!("{key} must be set")))
}

/// Acceptance: an unlink failure is a NON-ZERO exit (an `Err` out of the
/// handler), nothing is published, and the live corpus is still the old
/// one.
#[test]
fn restore_refuses_to_publish_when_a_sidecar_unlink_fails_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "unlink");
    // Guarantee a sidecar exists at unlink time whatever the journal mode.
    std::fs::write(sidecar_path(&db, "-journal"), b"").expect("plant -journal");
    let mut io = FaultIo {
        fail_remove: true,
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect_err("an unlink failure must refuse the restore")
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("refusing to publish"), "got: {msg}");
    assert!(
        io.remove_calls >= 1,
        "the unlink must actually have been attempted"
    );
    assert!(
        !io.steps.contains(&PublishStep::Published),
        "nothing may be published after a failed unlink: {:?}",
        io.steps
    );
    assert_eq!(memory_rows(&db), 2, "the live corpus must be the old one");
    assert_eq!(restore_tmp_leftovers(db.parent().unwrap()), 0);
}

/// Acceptance: at the instant the replacement is at `target_db`, no
/// `-wal` / `-shm` / `-journal` exists beside it — and the unlink
/// happened while the OLD database was still the target.
#[test]
fn no_sidecar_exists_at_the_instant_the_restore_is_published_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ordering");
    std::fs::write(sidecar_path(&db, "-journal"), b"").expect("plant -journal");
    let snapshot_len = std::fs::metadata(&snap).expect("snapshot").len();
    let old_len = std::fs::metadata(&db).expect("live db").len();
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen_in = std::rc::Rc::clone(&seen);
    let mut io = FaultIo {
        observe: Some(Box::new(move |step, target| {
            let present: Vec<&str> = SQLITE_SIDECAR_SUFFIXES
                .into_iter()
                .filter(|s| path_present(&sidecar_path(target, s)))
                .collect();
            // `metadata` is a stat: it opens no descriptor, so it cannot
            // drop the restore's POSIX locks.
            let len = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0);
            seen_in.borrow_mut().push((step, present.join(","), len));
        })),
        ..FaultIo::default()
    };
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap.clone()),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect("restore must succeed");
    }
    let seen = seen.borrow();
    let at = |step: PublishStep| {
        seen.iter()
            .find(|(s, _, _)| *s == step)
            .cloned()
            .unwrap_or_else(|| panic!("step {step:?} never reached: {seen:?}"))
    };
    let (_, cleared_sidecars, cleared_len) = at(PublishStep::SidecarsCleared);
    assert_eq!(
        cleared_sidecars, "",
        "sidecars must be gone before the rename"
    );
    assert_eq!(
        cleared_len, old_len,
        "the OLD database must still be the target then"
    );
    let (_, published_sidecars, published_len) = at(PublishStep::Published);
    assert_eq!(
        published_sidecars, "",
        "no sidecar may exist at the instant the new file is at target_db"
    );
    assert_eq!(
        published_len, snapshot_len,
        "the replacement must be the target"
    );
    assert_eq!(
        std::fs::read(&db).expect("read restored db"),
        std::fs::read(&snap).expect("read snapshot"),
        "the published database must be byte-identical to the snapshot"
    );
}

/// One writer attempt on `target`: open read-write (never create), no busy
/// wait, `BEGIN IMMEDIATE`. `true` when SQLite answered BUSY/LOCKED.
fn writer_is_refused(target: &Path) -> bool {
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let writer = raw_connection(target, flags);
    writer
        .busy_timeout(std::time::Duration::ZERO)
        .expect("busy_timeout");
    let outcome = writer.execute_batch("BEGIN IMMEDIATE; ROLLBACK;");
    outcome.as_ref().is_err_and(is_busy)
}

/// Cert battery: "writer during restore". From the moment the old
/// database is locked until the locks are released, another connection —
/// in this process AND in another one — can neither write the old file nor
/// open the new one.
///
/// The in-process attempt alone is not proof: SQLite answers it from its
/// own per-process lock bookkeeping without asking the kernel, so it would
/// still pass if the restore had dropped its POSIX locks (by closing a
/// descriptor on the file). The child process can only be refused by the
/// kernel's byte-range locks.
#[cfg(unix)]
#[test]
fn a_writer_starting_mid_restore_is_refused_at_every_locked_step_3550() {
    if child_role_is(ROLE_WRITER) {
        let target = child_path(CHILD_DB_ENV);
        assert!(
            writer_is_refused(&target),
            "a writer in another process must get SQLITE_BUSY on {target:?}"
        );
        return;
    }
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "writer");
    let refused = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let refused_in = std::rc::Rc::clone(&refused);
    let mut io = FaultIo {
        observe: Some(Box::new(move |step, target| {
            if step == PublishStep::Staged {
                return; // the old database is not locked yet
            }
            let in_process = writer_is_refused(target);
            let child = spawn_child_test(
                "a_writer_starting_mid_restore_is_refused_at_every_locked_step_3550",
                &[
                    (CHILD_ROLE_ENV, Path::new(ROLE_WRITER)),
                    (CHILD_DB_ENV, target),
                ],
            );
            let cross_process = child.status.success()
                && String::from_utf8_lossy(&child.stdout).contains("1 passed");
            refused_in
                .borrow_mut()
                .push((step, in_process, cross_process));
        })),
        ..FaultIo::default()
    };
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect("restore must succeed");
    }
    let refused = refused.borrow();
    assert_eq!(
        refused.len(),
        ALL_STEPS.len() - 1,
        "every locked step observed"
    );
    for (step, in_process, cross_process) in refused.iter() {
        assert!(
            in_process,
            "a writer in this process must get SQLITE_BUSY at {step:?}: {refused:?}"
        );
        assert!(
            cross_process,
            "a writer in another process must get SQLITE_BUSY at {step:?}: {refused:?}"
        );
    }
    assert_eq!(memory_rows(&db), 1, "the restore must have landed intact");
}

/// A process that opened the target DURING the restore (held off by the
/// lock) must not carry on against the replaced, orphaned inode — where
/// it would create `<target>-wal` by name beside the restored database
/// and have SQLite replay it into the restore. It fails loudly instead.
#[cfg(unix)]
#[test]
fn a_connection_opened_mid_restore_cannot_use_the_replaced_file_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ghost");
    let ghost = std::rc::Rc::new(std::cell::RefCell::new(None));
    let ghost_in = std::rc::Rc::clone(&ghost);
    let mut io = FaultIo {
        observe: Some(Box::new(move |step, target| {
            if step == PublishStep::PrePublishSynced {
                *ghost_in.borrow_mut() =
                    Some(raw_connection(target, rusqlite::OpenFlags::default()));
            }
        })),
        ..FaultIo::default()
    };
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect("restore must succeed");
    }
    assert_ghost_is_refused(&ghost, &db);
}

/// The write a connection that opened the target mid-restore attempts must
/// fail with "file is not a database" (the orphan's header was
/// invalidated), leave no sidecar beside the restored file, and not change
/// the restored corpus.
#[cfg(unix)]
fn assert_ghost_is_refused(
    ghost: &std::rc::Rc<std::cell::RefCell<Option<rusqlite::Connection>>>,
    db: &Path,
) {
    let ghost = ghost.borrow_mut().take().expect("ghost opened");
    let write = ghost.execute_batch(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
         VALUES ('ghost', 'long', 'ns', 'ghost', 'ghost', 'x', 'x')",
    );
    assert!(
        matches!(
            &write,
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::NotADatabase
        ),
        "the orphaned inode must refuse the write as not-a-database, got {write:?}"
    );
    drop(ghost);
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        assert!(
            !path_present(&sidecar_path(db, suffix)),
            "no {suffix} may appear beside the restored database"
        );
    }
    assert_eq!(memory_rows(db), 1, "the restored corpus must be untouched");
}

/// v1.0.0 #3550 (vote Q5) — the orphan is invalidated even when the
/// directory fsync AFTER the rename fails, because the one before it made
/// the rollback copy durable. Before, a failed post-rename fsync skipped the
/// invalidation silently, and a connection queued on the old inode then
/// wrote on — the path that creates `<target>-wal` beside the restore.
#[cfg(unix)]
#[test]
fn a_ghost_cannot_write_when_the_post_publish_fsync_fails_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ghost-fsync");
    let ghost = std::rc::Rc::new(std::cell::RefCell::new(None));
    let ghost_in = std::rc::Rc::clone(&ghost);
    let mut io = FaultIo {
        fail_sync_after_publish: true,
        observe: Some(Box::new(move |step, target| {
            if step == PublishStep::PrePublishSynced {
                *ghost_in.borrow_mut() =
                    Some(raw_connection(target, rusqlite::OpenFlags::default()));
            }
        })),
        ..FaultIo::default()
    };
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            true,
            &mut out,
            standard(),
            &mut io,
        )
        .expect("Standard publishes and reports the missing fsync");
    }
    assert_eq!(json_envelope(&env)["durable_publish"], false);
    assert_ghost_is_refused(&ghost, &db);
}

/// When BOTH directory fsyncs fail the orphan is left alone (it may be the
/// only copy a power cut brings back) and the operator is told what that
/// leaves open.
#[cfg(unix)]
#[test]
fn both_fsyncs_failing_leaves_the_orphan_and_says_so_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "both-fsync");
    let mut io = FaultIo {
        fail_sync_before_publish: true,
        fail_sync_after_publish: true,
        ..FaultIo::default()
    };
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            true,
            &mut out,
            standard(),
            &mut io,
        )
        .expect("Standard publishes and reports the missing fsyncs");
    }
    assert_eq!(json_envelope(&env)["durable_publish"], false);
    assert!(
        env.stderr_str().contains("neither directory fsync"),
        "the operator must be told the orphan was kept; stderr: {}",
        env.stderr_str()
    );
    assert_eq!(memory_rows(&db), 1, "the restore landed");
}

/// Crash injection at EVERY publish step: whatever the step, the target
/// is a whole, verified database — the old one before the rename, the
/// snapshot after it — with no sidecar that could replay foreign frames
/// into it, and the rollback copy is intact once it has been taken.
/// (Restore is SQLite-only; there is no Postgres leg.)
#[test]
fn a_crash_at_any_publish_step_leaves_old_or_new_never_a_mix_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for crash_at in ALL_STEPS {
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "crash");
        let snapshot_bytes = std::fs::read(&snap).expect("read snapshot");
        let mut io = FaultIo {
            crash_at: Some(crash_at),
            ..FaultIo::default()
        };
        let unwound = {
            let mut out = env.output();
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_restore_with(
                    &db,
                    &restore_args_3550(snap.clone()),
                    false,
                    &mut out,
                    standard(),
                    &mut io,
                )
            }))
        };
        assert!(
            unwound.is_err(),
            "the injected crash at {crash_at:?} must fire"
        );
        let published = matches!(
            crash_at,
            PublishStep::Published | PublishStep::PostPublishSynced
        );
        if published {
            assert_eq!(
                std::fs::read(&db).expect("read target"),
                snapshot_bytes,
                "after the rename the target is exactly the snapshot ({crash_at:?})"
            );
            assert_eq!(memory_rows(&db), 1, "{crash_at:?}");
        } else {
            assert_eq!(
                memory_rows(&db),
                2,
                "before the rename the old DB stays ({crash_at:?})"
            );
        }
        let probe = db::open_read_only(&db).expect("target opens");
        assert!(
            matches!(
                crate::storage::sqlite_integrity::check(&probe).expect("integrity runs"),
                crate::storage::sqlite_integrity::Soundness::Sound(_)
            ),
            "the target must be sound after a crash at {crash_at:?}"
        );
        drop(probe);
        if !matches!(crash_at, PublishStep::Staged | PublishStep::Locked) {
            let aside = find_pre_restore_copy(db.parent().unwrap());
            assert_eq!(
                memory_rows(&aside),
                2,
                "rollback copy intact ({crash_at:?})"
            );
        }
    }
}

/// A REAL crash at every publish step. The test above unwinds, and an
/// unwind runs the destructors a crash never gets to run — the staged
/// file's removal, the lock release, SQLite's close. Here a child process
/// runs the restore and `abort()`s at the step, then this process inspects
/// what the kernel left on disk. The fixture's second row lives only in the
/// old database's `-wal`, so a WAL lost before the checkpoint, or replayed
/// into the restore after the publish, changes the row count.
#[cfg(unix)]
#[test]
fn an_abort_at_any_publish_step_leaves_old_or_new_never_a_mix_3550() {
    const TEST: &str = "an_abort_at_any_publish_step_leaves_old_or_new_never_a_mix_3550";
    if child_role_is(ROLE_CRASH) {
        let step_name = std::env::var(CHILD_STEP_ENV).expect("step");
        let step = ALL_STEPS
            .into_iter()
            .find(|s| format!("{s:?}") == step_name)
            .expect("a known publish step");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let mut io = FaultIo {
            abort_at: Some((step, child_path(CHILD_MARKER_ENV))),
            ..FaultIo::default()
        };
        let outcome = run_restore_with(
            &child_path(CHILD_DB_ENV),
            &restore_args_3550(child_path(CHILD_SNAPSHOT_ENV)),
            false,
            &mut out,
            standard(),
            &mut io,
        );
        panic!("the restore must have aborted at {step:?}; it returned {outcome:?}");
    }
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for step in ALL_STEPS {
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "abort");
        let snapshot_bytes = std::fs::read(&snap).expect("read snapshot");
        let dir = db.parent().unwrap().to_path_buf();
        let marker = dir.join("abort-marker");
        let step_name = format!("{step:?}");
        let child = spawn_child_test(
            TEST,
            &[
                (CHILD_ROLE_ENV, Path::new(ROLE_CRASH)),
                (CHILD_DB_ENV, &db),
                (CHILD_SNAPSHOT_ENV, &snap),
                (CHILD_STEP_ENV, Path::new(&step_name)),
                (CHILD_MARKER_ENV, &marker),
            ],
        );
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                child.status.signal(),
                Some(libc::SIGABRT),
                "the child must die by abort at {step:?}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
        }
        assert_eq!(
            std::fs::read_to_string(&marker).expect("abort marker"),
            step_name,
            "the child must have reached {step:?} before it died"
        );
        let published = matches!(
            step,
            PublishStep::Published | PublishStep::PostPublishSynced
        );
        if published {
            assert_eq!(
                std::fs::read(&db).expect("read target"),
                snapshot_bytes,
                "after the rename the target is exactly the snapshot ({step:?})"
            );
            for suffix in SQLITE_SIDECAR_SUFFIXES {
                assert!(
                    !path_present(&sidecar_path(&db, suffix)),
                    "no {suffix} of the old database may sit beside the restore ({step:?})"
                );
            }
            assert_eq!(memory_rows(&db), 1, "{step:?}");
        } else {
            assert_eq!(
                memory_rows(&db),
                2,
                "before the rename the old database — WAL row included — stays ({step:?})"
            );
        }
        let probe = db::open_read_only(&db).expect("target opens");
        assert!(
            matches!(
                crate::storage::sqlite_integrity::check(&probe).expect("integrity runs"),
                crate::storage::sqlite_integrity::Soundness::Sound(_)
            ),
            "the target must be sound after an abort at {step:?}"
        );
        drop(probe);
        if !matches!(step, PublishStep::Staged | PublishStep::Locked) {
            let aside = find_pre_restore_copy(&dir);
            assert_eq!(
                memory_rows(&aside),
                2,
                "the rollback copy holds the WAL row too ({step:?})"
            );
        }
    }
}

fn json_envelope(env: &TestEnv) -> serde_json::Value {
    serde_json::from_str(env.stdout_str().trim()).expect("one JSON document on stdout")
}

/// Standard posture: a failed directory fsync (before or after the
/// rename) still publishes, and `durable_publish: false` says so.
#[test]
fn standard_reports_a_failed_directory_fsync_as_not_durable_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (before, after) in [(true, false), (false, true)] {
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-std");
        let mut io = FaultIo {
            fail_sync_before_publish: before,
            fail_sync_after_publish: after,
            ..FaultIo::default()
        };
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                true,
                &mut out,
                standard(),
                &mut io,
            )
            .expect("Standard publishes despite a failed directory fsync");
        }
        let v = json_envelope(&env);
        assert_eq!(
            v["durable_publish"],
            serde_json::json!(false),
            "{before}/{after}"
        );
        assert!(
            env.stderr_str().contains("fsync"),
            "must warn: {}",
            env.stderr_str()
        );
        assert_eq!(memory_rows(&db), 1, "published ({before}/{after})");
    }
}

/// A clean run reports `durable_publish: true` and `selected_by`. (Unix
/// only: a directory cannot be fsynced on Windows, so no publish there is
/// ever reported durable.)
#[cfg(unix)]
#[test]
fn restore_json_reports_a_durable_explicit_publish_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "durable");
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            true,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore must succeed");
    }
    let v = json_envelope(&env);
    assert_eq!(v["durable_publish"], serde_json::json!(true));
    assert_eq!(v["selected_by"], serde_json::json!("explicit"));
}

/// asi-hard: a directory fsync that fails BEFORE the rename refuses with
/// nothing published; one that fails AFTER it is a non-zero exit with the
/// envelope still saying `durable_publish: false`.
#[test]
fn asi_hard_enforces_a_durable_publish_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Before the rename: refused, the old corpus stays.
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-hard-pre");
    let mut io = FaultIo {
        fail_sync_before_publish: true,
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            true,
            &mut out,
            asi_hard(),
            &mut io,
        )
        .expect_err("asi-hard must refuse a publish it cannot make durable")
    };
    assert!(format!("{err:#}").contains("asi-hard"), "got: {err:#}");
    assert!(!io.steps.contains(&PublishStep::Published));
    assert_eq!(memory_rows(&db), 2, "nothing published");
    assert_eq!(restore_tmp_leftovers(db.parent().unwrap()), 0);

    // After the rename: published, reported, non-zero.
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-hard-post");
    let mut io = FaultIo {
        fail_sync_after_publish: true,
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            true,
            &mut out,
            asi_hard(),
            &mut io,
        )
        .expect_err("asi-hard must exit non-zero on a non-durable publish")
    };
    assert!(format!("{err:#}").contains("durable"), "got: {err:#}");
    assert_eq!(
        json_envelope(&env)["durable_publish"],
        serde_json::json!(false)
    );
    assert_eq!(memory_rows(&db), 1, "the restore itself was published");
}

/// Move a second, DIFFERENT snapshot into `dir` under the id `id`
/// (so two snapshots share one directory without waiting a second for a
/// distinct `backup` timestamp).
///
/// v1.0.0 #3199 — a signed manifest names its snapshot, so the moved pair is
/// RE-SIGNED under its new name with the test operator key, and its signed
/// `created_at` is the timestamp in `id` (what `--latest` orders by).
pub(super) fn plant_snapshot(env: &mut TestEnv, dir: &Path, id: &str, rows: usize) -> PathBuf {
    let scratch = TestEnv::fresh();
    let db = scratch.db_path.clone();
    for i in 0..rows {
        seed_memory(&db, "ns", &format!("planted-{i}"), "p");
    }
    let staging = dir.with_extension(format!("plant-{id}"));
    let taken = take_backup(env, &db, &staging);
    let name = format!("{id}.{SNAPSHOT_FILE_EXT}");
    let snap = dir.join(&name);
    std::fs::rename(staging.join(&taken.snapshot), &snap).expect("move snapshot");
    let created_at = chrono::NaiveDateTime::parse_from_str(
        id.strip_prefix(SNAPSHOT_FILE_PREFIX)
            .expect("planted ids carry the snapshot prefix"),
        BACKUP_TS_FMT,
    )
    .expect("planted ids carry a backup timestamp")
    .and_utc()
    .to_rfc3339();
    let payload = manifest::SignedPayload {
        dst: manifest::MANIFEST_DOMAIN.to_owned(),
        v: manifest::PAYLOAD_VERSION,
        snapshot: name.clone(),
        sha256: taken.sha256.clone(),
        bytes: taken.bytes,
        source_db: taken.source_db.clone(),
        version: taken.version.clone(),
        created_at: created_at.clone(),
        backend: BACKEND_SQLITE.to_owned(),
        schema_version: taken.schema_version.expect("backup records the schema"),
        memory_count: taken.memory_count.expect("backup records the count"),
    };
    let mut m = BackupManifest {
        snapshot: name,
        created_at,
        manifest_version: None,
        signed_payload: None,
        signature: None,
        signer: None,
        ..taken
    };
    manifest::sign_into(&mut m, &payload, &test_operator_key()).expect("sign manifest");
    std::fs::write(
        dir.join(manifest_file_name(id)),
        serde_json::to_string(&m).expect("manifest json"),
    )
    .expect("write manifest");
    snap
}

/// Cert battery: "misleading mtimes". The older snapshot is given the
/// newest mtime. With `--snapshot` the named one is restored whatever the
/// mtimes say.
///
/// v1.0.0 #3199 (rule (e), old-contract pin changed): the #3550 half that
/// asserted the mtime FALLBACK picked the older snapshot is replaced. A bare
/// directory is now refused, and `--latest` follows the SIGNED `created_at`
/// (the newer snapshot) — the misleading mtime is ignored.
#[test]
fn snapshot_flag_beats_a_misleading_mtime_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "live", "l");
    let dir = db.parent().unwrap().join("backups-3550-mtime");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let old = plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 3);
    let newer = plant_snapshot(&mut env, &dir, "ai-memory-2026-06-01T000000Z", 1);
    let future = std::time::SystemTime::now()
        + std::time::Duration::from_secs(
            u64::try_from(crate::SECS_PER_HOUR).expect("positive const"),
        );
    std::fs::File::options()
        .write(true)
        .open(&old)
        .and_then(|f| f.set_modified(future))
        .expect("give the OLD snapshot the newest mtime");

    // #3199 — a bare directory is refused; nothing is chosen by mtime.
    let live_before = file_sha256(&db);
    let mut args = restore_args_3550(dir.clone());
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &args,
            true,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect_err("a bare --from directory is refused (#3199)")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("--snapshot") && msg.contains("--latest"),
        "got: {msg}"
    );
    assert_eq!(file_sha256(&db), live_before, "the live database is untouched");

    // #3199 — `--latest` follows the SIGNED created_at: the June snapshot,
    // although the January one carries the newest mtime.
    args.latest = true;
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &args,
            true,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("--latest restore");
    }
    assert_eq!(
        json_envelope(&env)["selected_by"],
        serde_json::json!("latest")
    );
    assert_eq!(
        json_envelope(&env)["manifest_verification"],
        serde_json::json!("signed")
    );
    assert_eq!(
        file_sha256(&db),
        file_sha256(&newer),
        "--latest restores the newest SIGNED backup, not the newest mtime"
    );
    args.latest = false;

    // Every accepted spelling of the id restores the named snapshot.
    for name in [
        "ai-memory-2026-06-01T000000Z",
        "ai-memory-2026-06-01T000000Z.db",
        "ai-memory-2026-06-01T000000Z.manifest.json",
    ] {
        env.stdout.clear();
        env.stderr.clear();
        // Each restore leaves a rollback copy; distinct timestamps are not
        // guaranteed within one second, so clear the previous one.
        for e in std::fs::read_dir(db.parent().unwrap())
            .expect("dir")
            .flatten()
        {
            if e.file_name().to_string_lossy().contains(PRE_RESTORE_INFIX) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        args.snapshot = Some(name.to_owned());
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &args,
                true,
                &mut out,
                standard(),
                &mut FaultIo::default(),
            )
            .unwrap_or_else(|e| panic!("--snapshot {name}: {e:#}"));
        }
        assert_eq!(
            json_envelope(&env)["selected_by"],
            serde_json::json!("explicit")
        );
        assert!(!env.stderr_str().contains("MODIFICATION TIME"), "{name}");
        assert_eq!(
            memory_rows(&db),
            1,
            "--snapshot {name} restores the named snapshot"
        );
    }
}

/// asi-hard refuses the mtime pick outright and lists the candidates.
/// (v1.0.0 #3199: the bare-directory refusal now holds under EVERY posture;
/// this stays as the asi-hard witness.)
#[test]
fn asi_hard_refuses_the_mtime_pick_and_lists_candidates_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "live", "l");
    let dir = db.parent().unwrap().join("backups-3550-hard-mtime");
    std::fs::create_dir_all(&dir).expect("mkdir");
    plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 1);
    let before = std::fs::read(&db).expect("read live db");
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(dir),
            false,
            &mut out,
            asi_hard(),
            &mut FaultIo::default(),
        )
        .expect_err("asi-hard must refuse the mtime pick")
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("--snapshot"), "got: {msg}");
    assert!(
        msg.contains("ai-memory-2026-01-01T000000Z"),
        "candidates listed: {msg}"
    );
    assert_eq!(
        std::fs::read(&db).expect("read live db"),
        before,
        "untouched"
    );
}

#[test]
fn snapshot_id_accepts_names_and_refuses_paths_3550() {
    for (name, want) in [
        ("ai-memory-x", Some("ai-memory-x")),
        ("ai-memory-x.db", Some("ai-memory-x")),
        ("ai-memory-x.DB", Some("ai-memory-x")),
        ("ai-memory-x.manifest.json", Some("ai-memory-x")),
        ("", None),
        (".", None),
        ("..", None),
        ("../ai-memory-x", None),
        ("dir/ai-memory-x", None),
        ("/abs/ai-memory-x", None),
        ("..\\ai-memory-x", None),
        (".manifest.json", None),
    ] {
        assert_eq!(snapshot_id(name), want, "{name:?}");
    }
}

/// `--snapshot` refuses a path, a `--from` that is a file, and a
/// snapshot that is a symlink.
#[test]
fn snapshot_flag_refusals_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let db = env.db_path.clone();
    seed_memory(&db, "ns", "live", "l");
    let dir = db.parent().unwrap().join("backups-3550-refusals");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let snap = plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 1);
    let before = std::fs::read(&db).expect("read live db");
    let mut cases: Vec<(PathBuf, String, &str)> = vec![
        (dir.clone(), "../escape".into(), "not a snapshot name"),
        (
            snap.clone(),
            "ai-memory-2026-01-01T000000Z".into(),
            "not a directory",
        ),
        (dir.clone(), "ai-memory-missing".into(), "no snapshot"),
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&snap, dir.join("ai-memory-link.db")).expect("symlink");
        cases.push((dir.clone(), "ai-memory-link".into(), "not a regular file"));
    }
    for (from, name, want) in cases {
        let mut args = restore_args_3550(from);
        args.snapshot = Some(name.clone());
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &args,
                false,
                &mut out,
                standard(),
                &mut FaultIo::default(),
            )
            .expect_err("must refuse")
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(want),
            "--snapshot {name}: want {want:?}, got: {msg}"
        );
    }
    assert_eq!(
        std::fs::read(&db).expect("read live db"),
        before,
        "untouched"
    );
}

/// The restored database keeps the permissions of the one it replaced,
/// never the snapshot's — a world-writable snapshot used to publish a
/// world-writable corpus.
#[cfg(unix)]
#[test]
fn restore_keeps_the_replaced_databases_permissions_3550() {
    use std::os::unix::fs::PermissionsExt;
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "mode");
    std::fs::set_permissions(&snap, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore must succeed");
    }
    let mode = std::fs::metadata(&db).expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o640, "the replaced database's mode is kept");
}

/// A hard link keeps the old database alive under another name: it must
/// NOT be invalidated, and the operator is told it is still the old one.
#[cfg(unix)]
#[test]
fn a_hard_linked_old_database_is_left_intact_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "hardlink");
    let link = db.with_extension("hardlink.db");
    std::fs::hard_link(&db, &link).expect("hard link");
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore must succeed");
    }
    assert_eq!(
        memory_rows(&link),
        2,
        "the linked old database must still open"
    );
    assert!(
        env.stderr_str().contains("hard"),
        "must warn: {}",
        env.stderr_str()
    );
    assert_eq!(memory_rows(&db), 1);
}

/// Defence in depth: a sidecar that appears beside the restored database
/// during the publish is reported as a failure, not handed to a daemon.
#[test]
fn a_sidecar_appearing_during_the_publish_is_reported_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "reappear");
    let mut io = FaultIo {
        observe: Some(Box::new(|step, target| {
            if step == PublishStep::Published {
                std::fs::write(sidecar_path(target, "-journal"), b"x").expect("plant");
            }
        })),
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect_err("a sidecar that appeared must fail the restore")
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("appeared"), "got: {msg}");
    assert!(
        msg.contains("do NOT delete") && msg.contains(PRE_RESTORE_INFIX),
        "the refusal must not tell the operator to delete what may be a live WAL, and \
         must name the rollback copy; got: {msg}"
    );
    let _ = std::fs::remove_file(sidecar_path(&db, "-journal"));
}

// ======================================================================
// v1.0.0 #3550 follow-up — the degraded arms (5-agent vote 4d3ea1c5,
// memory 64694e75): Q1 checkpoint failure, Q2 empty target, Q3 an
// unlockable target, Q4 an unlockable staged file.
// ======================================================================

/// SHA-256 of the file at `path` (a test-side identity check).
fn file_sha256(path: &Path) -> String {
    sha256_hex(&std::fs::File::open(path).expect("open")).expect("hash")
}

/// Every name in `dir` containing `needle`.
fn names_containing(dir: &Path, needle: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(needle))
        .collect();
    names.sort();
    names
}

/// Move the live database and every sidecar beside it into `dest` — the
/// disaster-recovery step the Q1/Q3 refusals name.
fn move_database_set_aside(db: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).expect("mkdir");
    let name = db.file_name().expect("file name").to_owned();
    std::fs::rename(db, dest.join(&name)).expect("move the database");
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        let sidecar = sidecar_path(db, suffix);
        if path_present(&sidecar) {
            std::fs::rename(&sidecar, sidecar_path(&dest.join(&name), suffix))
                .expect("move a sidecar");
        }
    }
}

/// Q1 — a WAL restore cannot fully fold into the main file under its lock
/// is a refusal in BOTH postures, before anything destructive: the live
/// database and its `-wal` (which holds the only copy of a committed row)
/// are byte-for-byte untouched and no rollback copy or staged file is left.
/// The named way through — move the set aside, restore into an empty
/// target — then works.
#[test]
fn restore_refuses_a_wal_it_cannot_checkpoint_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for policy in [standard(), asi_hard()] {
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ckpt");
        let dir = db.parent().unwrap().to_path_buf();
        let wal = sidecar_path(&db, "-wal");
        let (db_sha, wal_sha) = (file_sha256(&db), file_sha256(&wal));
        let mut io = FaultIo {
            fail_checkpoint: true,
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap.clone()),
                false,
                &mut out,
                policy,
                &mut io,
            )
            .expect_err("an uncheckpointable WAL must refuse the restore")
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("out of the way"),
            "must name the way through: {msg}"
        );
        assert_eq!(
            io.steps,
            vec![PublishStep::Staged],
            "nothing past the lock ran"
        );
        assert_eq!(file_sha256(&db), db_sha, "the live database is untouched");
        assert_eq!(file_sha256(&wal), wal_sha, "its -wal is untouched");
        assert!(
            names_containing(&dir, PRE_RESTORE_INFIX).is_empty(),
            "no rollback copy"
        );
        assert_eq!(restore_tmp_leftovers(&dir), 0);
        assert_eq!(memory_rows(&db), 2, "the WAL row is still readable");

        // The way through the refusal.
        move_database_set_aside(&db, &dir.join("damaged"));
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                policy,
                &mut FaultIo::default(),
            )
            .expect("a restore into the emptied target succeeds");
        }
        assert_eq!(memory_rows(&db), 1);
        assert_eq!(
            memory_rows(&dir.join("damaged").join(db.file_name().unwrap())),
            2
        );
    }
}

/// Q4 — a staged file that cannot be locked refuses before the rename and
/// before any sidecar is removed.
#[cfg(unix)]
#[test]
fn restore_refuses_when_the_staged_file_cannot_be_locked_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for policy in [standard(), asi_hard()] {
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "staged-lock");
        let mut io = FaultIo {
            fail_lock_staged: true,
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                policy,
                &mut io,
            )
            .expect_err("an unlockable staged file must refuse the restore")
        };
        assert!(
            format!("{err:#}").contains("could not lock the staged restore"),
            "{err:#}"
        );
        assert!(
            !io.steps.contains(&PublishStep::SidecarsCleared),
            "no sidecar may be removed: {:?}",
            io.steps
        );
        assert_eq!(io.remove_calls, 0);
        assert_eq!(memory_rows(&db), 2, "the live corpus is the old one");
        assert_eq!(restore_tmp_leftovers(db.parent().unwrap()), 0);
    }
}

/// Q3 — a target restore cannot lock (here: not a database at all, the
/// shape a damaged or wrong-key file takes) is refused end to end and left
/// byte-for-byte as it was; the named way through works.
#[test]
fn restore_over_an_unlockable_target_refuses_and_the_escape_works_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "unlockable");
    let dir = db.parent().unwrap().to_path_buf();
    move_database_set_aside(&db, &dir.join("good-old"));
    let garbage = b"not a database, and not something to restore over blindly\n";
    std::fs::write(&db, garbage).expect("plant");
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap.clone()),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect_err("an unlockable target must refuse the restore")
    };
    assert!(format!("{err:#}").contains("out of the way"), "{err:#}");
    assert_eq!(std::fs::read(&db).expect("read"), garbage, "left as it was");
    assert_eq!(restore_tmp_leftovers(&dir), 0);

    move_database_set_aside(&db, &dir.join("garbage"));
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore into the emptied target");
    }
    assert_eq!(memory_rows(&db), 1);
}

/// Q2 — with no database at the target the restore is published without
/// replacing anything: the target is the snapshot, the staging name is
/// gone, and there is no rollback copy to report.
#[test]
fn restore_into_an_empty_target_publishes_without_replacing_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "empty");
    let dir = db.parent().unwrap().to_path_buf();
    move_database_set_aside(&db, &dir.join("old"));
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap.clone()),
            true,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore into an empty target");
    }
    let v = json_envelope(&env);
    assert!(v["rollback"].is_null(), "no rollback copy: {v}");
    assert_eq!(std::fs::read(&db).unwrap(), std::fs::read(&snap).unwrap());
    assert_eq!(
        restore_tmp_leftovers(&dir),
        0,
        "the staging name is removed"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(&db).unwrap().nlink(),
            1,
            "one name, not two"
        );
    }
}

/// Q2 — a database that appears at the empty target while the restore
/// publishes (an MCP server auto-started on it) is never replaced: the
/// publish is refused and the new database keeps its row.
#[test]
fn a_database_appearing_at_an_empty_target_is_never_replaced_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "appears");
    let dir = db.parent().unwrap().to_path_buf();
    move_database_set_aside(&db, &dir.join("old"));
    let mut io = FaultIo {
        observe: Some(Box::new(|step, target| {
            if step == PublishStep::PrePublishSynced {
                seed_memory(target, "ns", "written-by-a-daemon", "keep me");
            }
        })),
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect_err("a database that appeared must not be replaced")
    };
    assert!(format!("{err:#}").contains("appeared"), "{err:#}");
    assert!(!io.steps.contains(&PublishStep::Published));
    assert_eq!(
        memory_rows(&db),
        1,
        "the database that appeared keeps its row"
    );
    let conn = db::open_read_only(&db).expect("open");
    let title: String = conn
        .query_row("SELECT title FROM memories", [], |r| r.get(0))
        .expect("row");
    assert_eq!(title, "written-by-a-daemon");
    drop(conn);
    assert_eq!(restore_tmp_leftovers(&dir), 0);
}

/// Q2 — a `-wal` beside a MISSING database may be the only copy of
/// committed frames: it is moved into the rollback set, byte-for-byte,
/// never deleted, and nothing is left beside the restore.
#[test]
fn orphan_sidecars_beside_a_missing_database_are_kept_not_deleted_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "orphans");
    let dir = db.parent().unwrap().to_path_buf();
    // Lose the main file only: the -wal (holding a committed row) and the
    // -shm stay behind.
    let wal_bytes = std::fs::read(sidecar_path(&db, "-wal")).expect("wal");
    std::fs::rename(&db, dir.join("lost-main-file.db")).expect("lose the main file");
    {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap.clone()),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore beside orphans");
    }
    assert_eq!(std::fs::read(&db).unwrap(), std::fs::read(&snap).unwrap());
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        assert!(
            !path_present(&sidecar_path(&db, suffix)),
            "no {suffix} may stay beside the restore"
        );
    }
    let kept: Vec<String> = names_containing(&dir, PRE_RESTORE_INFIX)
        .into_iter()
        .filter(|n| n.ends_with("-wal"))
        .collect();
    assert_eq!(kept.len(), 1, "the orphaned -wal is kept: {kept:?}");
    assert_eq!(
        std::fs::read(dir.join(&kept[0])).unwrap(),
        wal_bytes,
        "byte-for-byte"
    );
    assert!(
        env.stdout_str().contains("orphaned SQLite sidecar"),
        "{}",
        env.stdout_str()
    );
    assert_eq!(memory_rows(&db), 1);
}

/// Q2 — on a filesystem that cannot hard-link, the empty-target publish
/// refuses (never a replacing rename) and says how to finish by hand.
#[test]
fn an_empty_target_publish_that_cannot_link_refuses_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "no-link");
    let dir = db.parent().unwrap().to_path_buf();
    move_database_set_aside(&db, &dir.join("old"));
    let mut io = FaultIo {
        link_error: Some(std::io::ErrorKind::Unsupported),
        ..FaultIo::default()
    };
    let err = {
        let mut out = env.output();
        run_restore_with(
            &db,
            &restore_args_3550(snap),
            false,
            &mut out,
            standard(),
            &mut io,
        )
        .expect_err("no hard links: refuse")
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("without replacing anything") && msg.contains("cp "),
        "{msg}"
    );
    assert!(!path_present(&db), "nothing was published");
    assert_eq!(restore_tmp_leftovers(&dir), 0);
}

/// A symlinked `--db` restores the database it points at, which is where
/// SQLite (and so every daemon) reads it — not the link.
#[cfg(unix)]
#[test]
fn a_symlinked_target_restores_the_real_database_3550() {
    let _g = crate::store_url::store_url_env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::fresh();
    let (db, snap) = two_row_live_one_row_snapshot(&mut env, "symlink");
    let link = db.parent().unwrap().join("link-to-the-db.db");
    std::os::unix::fs::symlink(&db, &link).expect("symlink");
    {
        let mut out = env.output();
        run_restore_with(
            &link,
            &restore_args_3550(snap.clone()),
            false,
            &mut out,
            standard(),
            &mut FaultIo::default(),
        )
        .expect("restore through the link");
    }
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link is still a link"
    );
    assert_eq!(std::fs::read(&db).unwrap(), std::fs::read(&snap).unwrap());
    assert_eq!(memory_rows(&link), 1);
}

/// A `-wal` or `-journal` planted beside the staging name is refused before
/// anything opens the staged file: SQLite would read it into the
/// verification (or roll it into the file) without it being published.
#[test]
fn stage_snapshot_refuses_a_planted_sidecar_3550() {
    let mut env = TestEnv::fresh();
    let (_db, snap) = two_row_live_one_row_snapshot(&mut env, "planted");
    let staged = snap.parent().unwrap().join("staged-here.db");
    std::fs::write(sidecar_path(&staged, "-wal"), b"planted").expect("plant");
    let err = stage_snapshot(&snap, &staged).expect_err("a planted sidecar must refuse");
    assert!(format!("{err:#}").contains("already exists beside the staged restore"));
    assert!(!path_present(&staged), "the staged file is removed");
}

/// The staged NAME must still be the file that was hashed and verified.
#[cfg(unix)]
#[test]
fn a_swapped_staged_file_is_refused_3550() {
    let env = TestEnv::fresh();
    let dir = env.db_path.parent().unwrap().to_path_buf();
    let path = dir.join("staged-swap.db");
    let file = copy_into_new_file(&mut &b"verified"[..], &path, None).expect("stage");
    let staged = StagedFile::new(path.clone(), file);
    staged.ensure_unswapped().expect("unswapped at first");
    let other = dir.join("swapped-in.db");
    std::fs::write(&other, b"not what was verified").expect("write");
    std::fs::rename(&other, &path).expect("swap");
    let err = staged
        .ensure_unswapped()
        .expect_err("a swapped file must refuse");
    assert!(format!("{err:#}").contains("no longer the file"), "{err:#}");
}
