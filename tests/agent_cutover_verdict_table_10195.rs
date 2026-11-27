// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! #10195 — the agent cut-over marker verdict in a process WITH the
//! in-process daemon key (`audit::init` installs it before any open).
//!
//! The verifier states covered here are "in-process key" (no key passed;
//! the installed key verifies) and "pinned key" (the installed key passed
//! as `audit_pubkey`). The "no verifier" state is in
//! `agent_cutover_no_verifier_10195.rs`, which never installs a key.

use std::sync::OnceLock;

use ed25519_dalek::{SigningKey, VerifyingKey};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[path = "common/cutover_table_10195.rs"]
mod cutover_table;

use cutover_table::{Scenario, VerifierState};

/// The test daemon key (one per process).
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// Scratch database name prefix for the PostgreSQL cells of this file.
#[cfg(feature = "sal-postgres")]
const SCRATCH_PREFIX: &str = "ai_memory_10195vt";

/// Install the in-process daemon key once and return its public half.
fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-10195-");
        ai_memory::governance::audit::init(
            dir.path(),
            Some(SigningKey::from_bytes(&TEST_DAEMON_SEED)),
        )
        .expect("init sink");
        dir
    });
    ai_memory::governance::daemon_signer::verifying_key().expect("daemon key installed")
}

/// The key the walk is given for a verifier state this binary covers.
fn key_for(state: VerifierState, installed: &VerifyingKey) -> Option<&VerifyingKey> {
    match state {
        VerifierState::InProcess => None,
        VerifierState::Pinned => Some(installed),
        VerifierState::None => {
            panic!("this binary installs a daemon key; see the no-verifier binary")
        }
    }
}

/// The verifier states this binary covers.
const STATES: [VerifierState; 2] = [VerifierState::InProcess, VerifierState::Pinned];

/// #10007 — the process resolves no path under the real home.
#[test]
fn test_process_resolves_no_path_under_the_real_home_10195() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
    let child = home_sandbox::per_test_dir("child-env-10195-vt-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

fn sqlite_row(scenario: Scenario) {
    let installed = sink();
    for state in STATES {
        let dir = home_sandbox::per_test_dir("cutover-10195-vt-");
        let cell = cutover_table::sqlite_cell(dir.path(), scenario, key_for(state, &installed));
        cutover_table::assert_sqlite_cell(scenario, state, &cell);
    }
}

#[test]
fn test_valid_marker_verdict_per_verifier_sqlite_10195() {
    sqlite_row(Scenario::Valid);
}

#[test]
fn test_edited_marker_verdict_per_verifier_sqlite_10195() {
    sqlite_row(Scenario::Edited);
}

#[test]
fn test_bad_signature_marker_verdict_per_verifier_sqlite_10195() {
    sqlite_row(Scenario::BadSignature);
}

#[test]
fn test_duplicate_marker_verdict_per_verifier_sqlite_10195() {
    sqlite_row(Scenario::Duplicate);
}

#[test]
fn test_removed_marker_verdict_per_verifier_sqlite_10195() {
    sqlite_row(Scenario::Removed);
}

#[cfg(feature = "sal-postgres")]
mod pg_cells {
    use super::{SCRATCH_PREFIX, STATES, Scenario, cutover_table, home_sandbox, key_for, sink};

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// The PostgreSQL row of `scenario` and, per verifier state, the sqlite
    /// row it must equal (backend parity).
    async fn pg_row(scenario: Scenario) {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let installed = sink();
        for state in STATES {
            let key = key_for(state, &installed);
            let pg = cutover_table::pg::cell(&url, SCRATCH_PREFIX, scenario, key).await;
            cutover_table::assert_trail_cell(scenario, state, &pg, "postgres");
            let dir = home_sandbox::per_test_dir("cutover-10195-vt-parity-");
            let (_, sqlite) = cutover_table::sqlite_cell(dir.path(), scenario, key);
            assert_eq!(
                sqlite, pg,
                "sqlite and postgres disagree, {scenario:?} x {state:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_valid_marker_verdict_per_verifier_pg_10195() {
        pg_row(Scenario::Valid).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_edited_marker_verdict_per_verifier_pg_10195() {
        pg_row(Scenario::Edited).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_signature_marker_verdict_per_verifier_pg_10195() {
        pg_row(Scenario::BadSignature).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_duplicate_marker_verdict_per_verifier_pg_10195() {
        pg_row(Scenario::Duplicate).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_removed_marker_verdict_per_verifier_pg_10195() {
        pg_row(Scenario::Removed).await;
    }
}
