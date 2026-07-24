// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2386 — the `asi-hard` pin enforcement (`std::env::set_var` over the
//! pinned-knob set) must run in the SYNCHRONOUS pre-runtime phase of the
//! binary's `fn main()`, never on the live multi-threaded tokio runtime.
//! Pre-fix, `daemon_runtime::run` (async, executing on the runtime's worker
//! pool) called `security_profile::enforce_at_boot()` directly, so every
//! `asi-hard` boot performed up to 14 `std::env::set_var` writes while the
//! tracing appender worker + tokio workers were live — re-introducing the
//! closed-#1889 `set_var`-on-a-threaded-process data-race class (glibc UB).
//!
//! Two pins here:
//! 1. A STRUCTURAL invariant over the shipped sources: `fn main()` invokes
//!    `enforce_at_boot_pre_runtime` BEFORE the tracing appender worker is
//!    spawned and BEFORE the tokio runtime is built, and the async
//!    `daemon_runtime::run` body no longer invokes the env-mutating
//!    `enforce_at_boot` (it consumes the READ-ONLY `runtime_boot_report`).
//! 2. A BEHAVIORAL subprocess check that the fail-closed below-floor abort
//!    still fires end-to-end after the relocation (the "no-disable"
//!    contract survives the move).
//!
//! The positive pins-take-effect half (asi-hard pinning
//! `AI_MEMORY_REQUIRE_ROLLBACK_CHECK=1` and having it honoured downstream)
//! is already pinned end-to-end by
//! `tests/security_profile_dispatch_1961.rs::asi_hard_engaged_pins_rollback_check_and_refuses_open_on_fresh_db`,
//! which now runs against the relocated pre-runtime enforcement.

use std::path::PathBuf;

const MAIN_SRC: &str = include_str!("../src/main.rs");
const DAEMON_SRC: &str = include_str!("../src/daemon_runtime.rs");

/// Structural pin: the env-mutating enforcement call sits in the sync
/// pre-runtime phase of `fn main()` — before the tracing appender worker
/// (`init_file_logging`) and before the tokio runtime builder — and the
/// async dispatch body never calls it.
#[test]
fn enforcement_is_pre_runtime_and_absent_from_the_async_body_2386() {
    let call = MAIN_SRC
        .find("enforce_at_boot_pre_runtime(")
        .expect("fn main() must invoke security_profile::enforce_at_boot_pre_runtime (#2386)");
    let logging_init = MAIN_SRC
        .find("logging::init_file_logging(")
        .expect("main.rs spawns the tracing appender worker via init_file_logging");
    let runtime_build = MAIN_SRC
        .find("tokio::runtime::Builder")
        .expect("main.rs builds the tokio runtime manually (#1889)");
    assert!(
        call < logging_init,
        "#2386: the posture enforcement (env set_var) must run BEFORE the \
         tracing appender worker thread is spawned (call at byte {call}, \
         init_file_logging at byte {logging_init})"
    );
    assert!(
        call < runtime_build,
        "#2386: the posture enforcement (env set_var) must run BEFORE the \
         tokio runtime is built (call at byte {call}, runtime builder at \
         byte {runtime_build})"
    );
    assert!(
        !DAEMON_SRC.contains("enforce_at_boot()"),
        "#2386: the async daemon_runtime::run body must NOT invoke the \
         env-mutating security_profile::enforce_at_boot — it runs on the \
         live multi-threaded runtime where std::env::set_var is a data race \
         (the closed-#1889 class)"
    );
    assert!(
        DAEMON_SRC.contains("runtime_boot_report"),
        "#2386: daemon_runtime::run must consume the READ-ONLY \
         security_profile::runtime_boot_report so the fail-closed posture \
         check still covers direct library callers of run()"
    );
}

/// Behavioral pin: the fail-closed "no-disable" refusal (a pinned knob set
/// below its hard floor under `asi-hard`) still aborts the boot after the
/// relocation — now from the pre-runtime phase of `fn main()`.
#[test]
fn below_floor_abort_still_fires_after_relocation_2386() {
    // Scratch under the repo's gitignored .local-runs/ (project no-/tmp
    // HARD RULE), mirroring tests/security_profile_dispatch_1961.rs.
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2386-prerun");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db = dir.path().join("ai-memory.db");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("--db")
        .arg(&db)
        .args(["stats", "--json"])
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_SECURITY_PROFILE", "asi-hard")
        .env("AI_MEMORY_SECRET_SCREEN_MODE", "off")
        .output()
        .expect("spawn ai-memory");
    assert!(
        !out.status.success(),
        "asi-hard + a below-floor knob must still refuse the boot after the \
         #2386 pre-runtime relocation; exit={:?} stdout={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("AI_MEMORY_SECRET_SCREEN_MODE") && stderr.contains("refuses to disable"),
        "expected the fail-closed loosening refusal naming the knob; stderr={stderr}"
    );
    // The refusal must fire BEFORE the DB is ever created (pre-runtime =
    // before any subcommand work).
    assert!(
        !db.exists(),
        "the pre-runtime refusal must abort before the subcommand opens/creates the DB"
    );
}
