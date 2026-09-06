// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — `ai-memory backup` store-URL resolution: ambiguity is REFUSED.
//!
//! `backup` produces the artifact a disaster recovery is restored from, so
//! "which store did I actually snapshot?" must never be a guess. The
//! resolver consults `--store-url`, `AI_MEMORY_STORE_URL` and
//! `AI_MEMORY_STORE_URL_FILE`; when the flag and the environment name
//! DIFFERENT stores it refuses rather than silently preferring either — a
//! snapshot of the wrong database carries a perfectly valid checksum and the
//! restore from it returns the wrong corpus.
//!
//! These cases mutate the process-global store-URL environment, so per
//! `scripts/check-test-env-lock.sh` arm (d) (#3475) they live in their own
//! test binary rather than in the shared lib test binary whose cases run on
//! parallel threads. Within THIS binary they are the only writers and
//! readers of those variables, and they serialise behind the file-local
//! lock below (the crate-canonical `store_url_env_lock` is `pub(crate)` and
//! therefore not reachable from an integration test).

use std::sync::{Mutex, PoisonError};

static STORE_URL_ENV_LOCK: Mutex<()> = Mutex::new(());

use ai_memory::cli::CliOutput;
use ai_memory::cli::backup::{BackupArgs, run_backup};

/// Clear both environment channels. SAFETY: the caller holds
/// `STORE_URL_ENV_LOCK` for the duration.
unsafe fn clear_store_url_env() {
    unsafe {
        std::env::remove_var("AI_MEMORY_STORE_URL");
        std::env::remove_var("AI_MEMORY_STORE_URL_FILE");
    }
}

fn seeded_db(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let _conn = ai_memory::db::open(&path).expect("db::open");
    path
}

/// `--store-url` naming one store while `AI_MEMORY_STORE_URL` names another
/// is REFUSED, and the refusal names BOTH candidates so the operator can see
/// which channel to unset.
#[test]
fn store_url_flag_disagreeing_with_the_environment_is_refused() {
    let _g = STORE_URL_ENV_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = seeded_db(tmp.path(), "local-3521.db");
    let env_db = tmp.path().join("env-named-3521.db");
    let argv_db = tmp.path().join("argv-named-3521.db");

    // SAFETY: serialised by the store-URL env lock held above.
    unsafe {
        clear_store_url_env();
        std::env::set_var(
            "AI_MEMORY_STORE_URL",
            format!("sqlite://{}", env_db.display()),
        );
    }
    let args = BackupArgs {
        to: tmp.path().join("snapshots"),
        keep: 2,
        store_url: Some(format!("sqlite://{}", argv_db.display())),
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let err = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run_backup(&db, &args, false, &mut out)
            .expect_err("an ambiguous store must be refused, never resolved")
            .to_string()
    };
    // SAFETY: same lock scope.
    unsafe { clear_store_url_env() };

    assert!(
        err.contains("ambiguous store"),
        "the refusal must say the store is ambiguous; got: {err}"
    );
    assert!(
        err.contains("argv-named-3521.db") && err.contains("env-named-3521.db"),
        "the refusal must name BOTH candidates; got: {err}"
    );
    assert!(
        !args.to.exists(),
        "a refused backup must not have created the snapshot directory"
    );
}

/// A `sqlite://` URL that names no path is refused rather than silently
/// falling back to `--db`.
#[test]
fn pathless_sqlite_store_url_is_refused() {
    let _g = STORE_URL_ENV_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = seeded_db(tmp.path(), "local-pathless-3521.db");
    // SAFETY: serialised by the store-URL env lock held above.
    unsafe { clear_store_url_env() };

    let args = BackupArgs {
        to: tmp.path().join("snapshots-pathless"),
        keep: 2,
        store_url: Some("sqlite://".to_string()),
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let err = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run_backup(&db, &args, false, &mut out)
            .expect_err("a pathless sqlite store URL must be refused")
            .to_string()
    };
    assert!(
        err.contains("names no path"),
        "the refusal must say the URL names no path; got: {err}"
    );
}

/// When the configured store and `--db` disagree, the STORE wins on this
/// read verb — but the redirect is announced on stderr. An operator must
/// never learn later that the snapshot came from a different file than the
/// one they typed.
#[test]
fn a_store_url_that_disagrees_with_db_is_announced_and_wins() {
    let _g = STORE_URL_ENV_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = seeded_db(tmp.path(), "db-flag-3521.db");
    let store_db = seeded_db(tmp.path(), "configured-store-3521.db");
    // SAFETY: serialised by the store-URL env lock held above.
    unsafe { clear_store_url_env() };

    let args = BackupArgs {
        to: tmp.path().join("snapshots-redirect"),
        keep: 2,
        store_url: Some(format!("sqlite://{}", store_db.display())),
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        run_backup(&db, &args, false, &mut out).expect("the configured store backs up");
    }
    let text = String::from_utf8(stderr).expect("utf8 stderr");
    assert!(
        text.contains("acting on the configured store")
            && text.contains("configured-store-3521.db")
            && text.contains("db-flag-3521.db"),
        "the redirect must be announced with BOTH paths; stderr was: {text}"
    );
}
