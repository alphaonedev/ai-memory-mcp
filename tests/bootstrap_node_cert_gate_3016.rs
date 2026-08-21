// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3016/#3067 — `ai-memory audit bootstrap-node` cert-gate proof.
//!
//! Cluster-A (cert-posture armability) born-dirty regression + mechanical
//! bring-up gate:
//!
//! - A bare store-only migration (agent registry copied, `signed_events`
//!   audit spine EMPTY) is NON-certifiable / born DIRTY: under a certified
//!   armed require-mode (here `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`, one of
//!   the four `asi-hard`-pinned audit require-modes) an empty spine convicts
//!   on the identity-LINEAGE verdict, so `verify_audit_trail` is NOT clean.
//!   That is the #3067 "must stay dirty until a mechanical bring-up runs"
//!   property.
//! - The single idempotent `audit bootstrap-node` command runs the EXISTING
//!   lineage-genesis ceremony over the resolved store and REFUSES to report
//!   certified (exit 1) until `verify-audit-trail` exits 0 — turning the
//!   born-dirty node clean (exit 0), and re-running is an idempotent no-op.
//! - When a require-mode the command CANNOT satisfy is armed
//!   (`AI_MEMORY_REQUIRE_ROLE_SEPARATION`, whose distinct recorder/judge/
//!   stopper custody keys are an operator ceremony bring-up VERIFIES but
//!   never mints), bring-up FAIL-CLOSES (exit 1) and NAMES the remaining
//!   ceremony rather than false-certifying.
//!
//! Every `#[test]` here mutates the PROCESS-GLOBAL require-mode env that
//! `verify_audit_trail` reads, so each holds the shared `ENV_LOCK` via
//! `common::EnvVarGuard` for its whole body (the same discipline as
//! `tests/identity_lineage_succession.rs`).
//!
//! The postgres BORN-DIRTY verdict has a shipped twin
//! (`verify_audit_trail_postgres`) exercised by the `postgres_parity`
//! module below (gated on `AI_MEMORY_TEST_POSTGRES_URL`); the pg
//! spine-WRITE bring-up twin is deferred (like the pg re-anchor twin
//! #2217), so the write path is proven on sqlite here.

#![allow(clippy::too_many_lines, clippy::doc_markdown, clippy::similar_names)]

mod common;

use ai_memory::cli::audit::{self, AuditAction, AuditArgs, BootstrapNodeArgs};
use ai_memory::config::AppConfig;
use ai_memory::db;
use ai_memory::identity::keypair;
use ai_memory::identity::lineage::{LineageCheck, REQUIRE_IDENTITY_LINEAGE_ENV};
use ai_memory::signed_events::verify_audit_trail;
use common::EnvVarGuard;
use std::path::{Path, PathBuf};

const AGENT: &str = "bootstrap-node-3016";

/// A store-only-migrated node shape: the agent registry is populated (a
/// migration copies it) but the `signed_events` audit spine is EMPTY.
/// Returns (tempdir, db_path, key_dir, recovery_pubkey_b64).
fn store_only_migrated_node() -> (tempfile::TempDir, PathBuf, PathBuf, String) {
    let dir = tempfile::Builder::new()
        .prefix("bootstrap-3016-")
        .tempdir()
        .expect("tempdir");
    let db_path = dir.path().join("memories.db");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(&key_dir).expect("mk key_dir");

    let conn = db::open(&db_path).expect("open + migrate");
    // Registry row copied by a store-only migration; register_agent does NOT
    // write signed_events, so the audit spine stays empty (born-dirty).
    db::register_agent(&conn, AGENT, "ai:test", &[]).expect("register agent");

    // The agent's own keypair (self-signs the lineage genesis at bring-up).
    let kp = keypair::generate(AGENT).expect("gen keypair");
    keypair::save(&kp, &key_dir).expect("save keypair");
    // A cold RECOVERY pubkey the operator holds (#1949, required at genesis).
    let recovery = keypair::generate("bootstrap-node-3016-recovery")
        .expect("gen recovery")
        .public_base64();

    // Sanity: the spine really is empty (this is what makes the node dirty).
    let spine_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
        .expect("count signed_events");
    assert_eq!(spine_rows, 0, "fixture precondition: empty audit spine");
    drop(conn);

    (dir, db_path, key_dir, recovery)
}

fn cfg_for(db_path: &Path) -> AppConfig {
    AppConfig {
        db: Some(db_path.to_string_lossy().into_owned()),
        ..AppConfig::default()
    }
}

fn bootstrap_args(key_dir: &Path, recovery_pubkey: Option<String>) -> AuditArgs {
    AuditArgs {
        action: AuditAction::BootstrapNode(BootstrapNodeArgs {
            agent_id: Some(AGENT.to_string()),
            key_dir: Some(key_dir.to_path_buf()),
            recovery_pubkey,
            json: false,
        }),
        audit_dir: None,
    }
}

/// #3067 — a store-only-migrated node (empty spine) MUST stay DIRTY under an
/// armed require-mode until the mechanical bring-up runs.
#[test]
fn born_dirty_empty_spine_stays_dirty_under_armed_require_mode() {
    let (_dir, db_path, _key_dir, _recovery) = store_only_migrated_node();
    // Open BEFORE arming (require-modes are verify-time, not open-time here).
    let conn = db::open(&db_path).expect("open");
    let _g = EnvVarGuard::set(REQUIRE_IDENTITY_LINEAGE_ENV, "1".to_string());

    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(
        !report.is_clean(),
        "empty spine under armed require-lineage must be BORN DIRTY (#3067)"
    );
    assert!(
        matches!(report.lineage, LineageCheck::Missing),
        "the born-dirty discriminator is the Missing lineage verdict: {:?}",
        report.lineage
    );
}

/// #3016 — the single idempotent bring-up command turns a born-dirty node
/// clean, and REFUSES to report certified until verify exits 0.
#[test]
fn bootstrap_node_brings_up_born_dirty_node_and_is_idempotent() {
    let (_dir, db_path, key_dir, recovery) = store_only_migrated_node();
    let cfg = cfg_for(&db_path);
    let _g = EnvVarGuard::set(REQUIRE_IDENTITY_LINEAGE_ENV, "1".to_string());

    // Precondition: born dirty.
    {
        let conn = db::open(&db_path).expect("open");
        assert!(
            !verify_audit_trail(&conn, None, None).unwrap().is_clean(),
            "precondition: the node is born-dirty before bring-up"
        );
    }

    // First bring-up: enrolls the lineage genesis, then the verify GATE passes.
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    {
        let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
        let code = audit::run(bootstrap_args(&key_dir, Some(recovery)), &cfg, &mut out)
            .expect("bootstrap-node run");
        assert_eq!(
            code,
            0,
            "bring-up must certify the born-dirty node (exit 0). stderr: {}",
            String::from_utf8_lossy(&se)
        );
    }
    assert!(String::from_utf8_lossy(&so).contains("CERTIFIED-READY"));

    // The spine now verifies CLEAN directly.
    {
        let conn = db::open(&db_path).expect("open");
        assert!(
            verify_audit_trail(&conn, None, None).unwrap().is_clean(),
            "after bring-up the audit spine must verify clean"
        );
    }

    // Idempotent re-run WITHOUT a recovery pubkey (genesis already exists).
    let mut so2 = Vec::<u8>::new();
    let mut se2 = Vec::<u8>::new();
    {
        let mut out = ai_memory::cli::CliOutput::from_std(&mut so2, &mut se2);
        let code =
            audit::run(bootstrap_args(&key_dir, None), &cfg, &mut out).expect("idempotent re-run");
        assert_eq!(
            code,
            0,
            "idempotent re-run must stay certified (exit 0). stderr: {}",
            String::from_utf8_lossy(&se2)
        );
    }
    assert!(String::from_utf8_lossy(&so2).contains("already-enrolled"));
}

/// #3016 — bring-up FAIL-CLOSES (never false-certifies) when a require-mode
/// it cannot satisfy is armed, and NAMES the remaining operator ceremony.
#[test]
fn bootstrap_node_refuses_certified_when_role_separation_unsatisfied() {
    let (_dir, db_path, key_dir, recovery) = store_only_migrated_node();
    let cfg = cfg_for(&db_path);
    // Role separation needs DISTINCT recorder/judge/stopper custody keys —
    // bring-up verifies but never mints them, so this stays dirty.
    let _g = EnvVarGuard::set(
        ai_memory::governance::audit::REQUIRE_ROLE_SEPARATION_ENV,
        "1".to_string(),
    );

    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let code = audit::run(bootstrap_args(&key_dir, Some(recovery)), &cfg, &mut out)
        .expect("bootstrap-node run");
    assert_eq!(
        code, 1,
        "bring-up must REFUSE certified while role separation is unmet"
    );
    let err = String::from_utf8_lossy(&se);
    assert!(
        err.contains("NOT CERTIFIED"),
        "refusal must be explicit: {err}"
    );
    assert!(
        err.contains("ROLE SEPARATION"),
        "refusal must NAME the remaining operator ceremony: {err}"
    );
}

// ---------------------------------------------------------------------------
// K3 parity — the BORN-DIRTY verdict on a postgres store, via the shipped pg
// verify twin (`PostgresStore::verify_audit_trail`). Gated on a live pg tier
// (`AI_MEMORY_TEST_POSTGRES_URL`); the pg spine-WRITE bring-up twin is
// deferred (#2217-class), so this asserts the empty-spine born-dirty half.
// ---------------------------------------------------------------------------
#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
    }

    #[tokio::test]
    #[ignore = "requires a live postgres tier (AI_MEMORY_TEST_POSTGRES_URL); run with --include-ignored --test-threads=1"]
    async fn pg_empty_spine_is_born_dirty_under_armed_require_mode() {
        let Some(url) = pg_url() else {
            eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let _g = EnvVarGuard::set(REQUIRE_IDENTITY_LINEAGE_ENV, "1".to_string());
        let store = ai_memory::store::postgres::PostgresStore::connect_with_dim_and_timeout(
            &url,
            ai_memory::store::postgres::DEFAULT_EMBEDDING_DIM,
            ai_memory::store::postgres::DEFAULT_STATEMENT_TIMEOUT_SECS,
            AppConfig::default().resolve_pg_pool(),
        )
        .await
        .expect("connect pg tier (per-test schema isolated)");
        // A fresh isolated schema has an EMPTY signed_events spine.
        let report = store
            .verify_audit_trail(None, None)
            .await
            .expect("pg verify_audit_trail");
        assert!(
            !report.is_clean(),
            "pg empty spine under armed require-lineage must be born-dirty (K3 parity)"
        );
        assert!(
            matches!(report.lineage, LineageCheck::Missing),
            "pg born-dirty discriminator is Missing lineage: {:?}",
            report.lineage
        );
    }
}
