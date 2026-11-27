// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! #10195 — the agent cut-over marker verdict in a process with NO
//! in-process daemon key (this binary never calls `audit::init`).
//!
//! The marker is signed by the daemon key the sandbox key directory holds
//! (`DaemonChainSigner::provision_default`). The verifier states covered here
//! are "no verifier" (no key passed, none in process) and "pinned key" (that
//! disk key passed as `audit_pubkey`). The in-process state is in
//! `agent_cutover_verdict_table_10195.rs`, which installs the key.
//!
//! The table ([`cutover_table::expected`]) is written by hand: a correctly
//! signed marker with no verifier is unchecked (no failure, not verified);
//! an edited, duplicated or removed marker fails with or without a key; a
//! bad signature fails once a key is present.

use std::sync::OnceLock;

use ai_memory::governance::daemon_signer::DaemonChainSigner;
use ed25519_dalek::VerifyingKey;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[path = "common/cutover_table_10195.rs"]
mod cutover_table;

use cutover_table::{Scenario, VerifierState};

/// Scratch database name prefix for the PostgreSQL cells of this file.
#[cfg(feature = "sal-postgres")]
const SCRATCH_PREFIX: &str = "ai_memory_10195nv";

/// The daemon key in the sandbox key directory, resolved once before any
/// database is opened so every open signs with the same key.
fn disk_key() -> VerifyingKey {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    *KEY.get_or_init(|| {
        let _ = home_sandbox::install();
        DaemonChainSigner::provision_default()
            .expect("the sandbox daemon key resolves")
            .verifying_key()
    })
}

/// The key the walk is given for a verifier state this binary covers.
fn key_for(state: VerifierState, disk: &VerifyingKey) -> Option<&VerifyingKey> {
    match state {
        VerifierState::None => None,
        VerifierState::Pinned => Some(disk),
        VerifierState::InProcess => {
            panic!("this binary has no in-process daemon key; see the verdict-table binary")
        }
    }
}

/// The verifier states this binary covers.
const STATES: [VerifierState; 2] = [VerifierState::None, VerifierState::Pinned];

/// #10007 — the process resolves no path under the real home.
#[test]
fn test_process_resolves_no_path_under_the_real_home_10195() {
    let _ = home_sandbox::real_home();
    let _ = disk_key();
    home_sandbox::assert_process_isolated();
    let child = home_sandbox::per_test_dir("child-env-10195-nv-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

/// This binary has no in-process daemon key, so the "no verifier" cells
/// really have none.
#[test]
fn test_this_process_has_no_in_process_daemon_key_10195() {
    let _ = disk_key();
    assert!(
        ai_memory::governance::daemon_signer::verifying_key().is_none(),
        "the no-verifier binary must not install a daemon key"
    );
}

fn sqlite_row(scenario: Scenario) {
    let disk = disk_key();
    for state in STATES {
        let dir = home_sandbox::per_test_dir("cutover-10195-nv-");
        let cell = cutover_table::sqlite_cell(dir.path(), scenario, key_for(state, &disk));
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
    use super::{SCRATCH_PREFIX, STATES, Scenario, cutover_table, disk_key, home_sandbox, key_for};

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
        let disk = disk_key();
        for state in STATES {
            let key = key_for(state, &disk);
            let pg = cutover_table::pg::cell(&url, SCRATCH_PREFIX, scenario, key).await;
            cutover_table::assert_trail_cell(scenario, state, &pg, "postgres");
            let dir = home_sandbox::per_test_dir("cutover-10195-nv-parity-");
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
