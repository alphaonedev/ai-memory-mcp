// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3152 — the IN-TRANSACTION fault point of the single-commit update
//! contract, and the re-exec helpers the crash tests share. TEST BUILDS
//! ONLY: nothing here exists in a shipped binary, so unlike
//! [`crate::recover::durability::ENV_ABORT_AFTER_COMMIT`] it cannot be armed
//! in production.
//!
//! Every update funnel that applies a content patch AND a lifecycle
//! transition calls [`patched_before_lifecycle`] after the patch statement
//! has executed and before the transition runs, while both sit in one
//! uncommitted transaction. A test arms the point for ONE memory id (so a
//! parallel test on another row can never trip it) and either observes the
//! database from outside the transaction or hard-aborts the process there.
//! After an abort the row must read back exactly as it was before the
//! update: there is no COMMIT between the two statements.
//!
//! The crash tests re-execute the test binary as a child
//! ([`crate::test_support::spawn_test_child`]) that arms [`Action::Abort`]
//! and runs one update; the parent then asserts the child died AT the point
//! ([`assert_aborted_at_fault_point`]) and reads the row back.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

/// What reaching the armed point does.
pub(crate) enum Action {
    /// Write `marker`, then `std::process::abort()`: no destructor, no
    /// rollback, no connection close. A SIGKILL between the statements.
    Abort { marker: PathBuf },
    /// Run an observer — e.g. read the row through a second connection.
    Observe(Box<dyn Fn() + Send>),
}

/// Armed ids with their actions. Several tests may arm concurrently in one
/// test binary; each only ever matches its own row.
static ARMED: Mutex<Vec<(String, Action)>> = Mutex::new(Vec::new());

/// Arm the point for memory `id` only.
pub(crate) fn arm(id: &str, action: Action) {
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((id.to_string(), action));
}

/// Disarm the point for memory `id`.
pub(crate) fn disarm(id: &str) {
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|(armed, _)| armed != id);
}

/// Called by the update funnels between the patch and the transition. A
/// no-op unless the point is armed for `id`. An observer runs with the
/// registry locked, so it must not itself reach the point.
pub(crate) fn patched_before_lifecycle(id: &str) {
    let armed = ARMED.lock().unwrap_or_else(PoisonError::into_inner);
    let Some((_, action)) = armed.iter().find(|(armed, _)| armed == id) else {
        return;
    };
    match action {
        Action::Abort { marker } => {
            std::fs::write(marker, id).expect("write the #3152 abort marker");
            std::process::abort();
        }
        Action::Observe(observe) => observe(),
    }
}

/// Env var naming the role a re-executed test plays. Read, never set, in
/// the test process: the parent passes it only to the child's `Command`.
pub(crate) const CHILD_ROLE_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_ROLE";
/// Env var carrying the sqlite database path the child acts on.
pub(crate) const CHILD_DB_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_DB";
/// Env var carrying the memory id the child updates.
pub(crate) const CHILD_ID_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_ID";
/// Env var carrying the file the child writes just before aborting.
pub(crate) const CHILD_MARKER_ENV: &str = "AI_MEMORY_TEST_3152_CHILD_MARKER";

/// Is this process a child re-executed to play `role`?
pub(crate) fn child_role_is(role: &str) -> bool {
    std::env::var(CHILD_ROLE_ENV).is_ok_and(|r| r == role)
}

/// A variable the parent must have passed to a #3152 child.
pub(crate) fn child_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set in a #3152 child"))
}

/// POSIX `SIGABRT`: what `std::process::abort()` raises.
#[cfg(unix)]
const SIGABRT: i32 = 6;

/// The child died AT the fault point: by `SIGABRT`, after writing `marker`
/// with the id it was updating.
#[cfg(unix)]
pub(crate) fn assert_aborted_at_fault_point(
    out: &std::process::Output,
    marker: &std::path::Path,
    id: &str,
) {
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
