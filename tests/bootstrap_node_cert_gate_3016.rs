// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3016/#3067 — `ai-memory audit bootstrap-node` cert-gate proof.
//!
//! Cluster-A (cert-posture armability) born-dirty regression + mechanical
//! bring-up gate:
//!
//! - A bare store-only migration (agent registry copied, `signed_events`
//!   audit spine EMPTY) is NON-certifiable / born DIRTY: under an armed
//!   audit require-mode an empty spine convicts, so `verify_audit_trail` is
//!   NOT clean (the #3067 "must stay dirty until a mechanical bring-up runs"
//!   property).
//! - MB1 — the certified verdict is FAIL-CLOSED against the ambient env.
//!   `bootstrap-node` reports CERTIFIED-READY only when ALL THREE certified
//!   `asi-hard` audit require-modes (`AI_MEMORY_REQUIRE_WITNESS` /
//!   `_ROLE_SEPARATION` / `_IDENTITY_LINEAGE`) are armed in-process AND the
//!   verify is clean under them, with the operator custody keys enrolled
//!   (witness + recorder — a judge pubkey with no verdict checkpoint is
//!   permanently `Missing`, an out-of-band prerequisite bring-up VERIFIES).
//!   The tests prove the certified transition WITH keys, the fail-closed
//!   refusal under asi-hard WITHOUT keys, and the refusal when the certified
//!   modes are not armed at all (the false-green MB1 closes).
//!
//! Every `#[test]` here mutates PROCESS-GLOBAL require-mode / custody-dir env
//! that `verify_audit_trail` reads, so each holds the shared `ENV_LOCK` via
//! `common::{EnvVarGuard, MultiEnvVarGuard}` for its whole body (the same
//! discipline as `tests/identity_lineage_succession.rs`).
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
use ai_memory::governance::audit as roles;
use ai_memory::identity::keypair;
use ai_memory::identity::lineage::{LineageCheck, REQUIRE_IDENTITY_LINEAGE_ENV};
use ai_memory::signed_events::verify_audit_trail;
use common::{EnvVarGuard, MultiEnvVarGuard};
use std::path::{Path, PathBuf};

const AGENT: &str = "bootstrap-node-3016";

/// Enroll a custody key (witness / recorder / …) by generating an ed25519
/// keypair under the reserved `label` and saving it (0600) into `dir` — the
/// operator ceremony bring-up VERIFIES but never mints. The `<label>.pub`
/// file there satisfies the verdict's K1 pin automatically.
fn enroll_custody_key(dir: &Path, label: &str) {
    let kp = keypair::generate(label).expect("gen custody key");
    keypair::save(&kp, dir).expect("save custody key");
}

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
            store_url: None,
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

/// The three certified `asi-hard` AUDIT require-modes bootstrap-node's verdict
/// is gated on (MB1). `[(env, Some("1"))]` armed; the store-URL channels are
/// cleared so `resolve_store_url` is deterministic (F2/F3).
fn base_mutations() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        (roles::REQUIRE_WITNESS_ENV, Some("1")),
        (roles::REQUIRE_ROLE_SEPARATION_ENV, Some("1")),
        (REQUIRE_IDENTITY_LINEAGE_ENV, Some("1")),
        ("AI_MEMORY_STORE_URL", None),
        ("AI_MEMORY_STORE_URL_FILE", None),
        (roles::WITNESS_PUBKEY_ENV, None),
        (roles::RECORDER_PUBKEY_ENV, None),
    ]
}

fn run_bootstrap(
    cfg: &AppConfig,
    key_dir: &Path,
    recovery: Option<String>,
) -> (i32, String, String) {
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let code = {
        let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
        audit::run(bootstrap_args(key_dir, recovery), cfg, &mut out).expect("bootstrap-node run")
    };
    (
        code,
        String::from_utf8_lossy(&so).into_owned(),
        String::from_utf8_lossy(&se).into_owned(),
    )
}

/// MB1 — the CERTIFIED transition under the FULL certified `asi-hard` audit
/// require-mode set, with the operator custody keys (witness + recorder)
/// enrolled. This is the only path on which bootstrap-node may print
/// CERTIFIED-READY: all three modes armed AND a clean verify under them.
/// (Recorder-only role separation is the correct fresh-node posture — a judge
/// pubkey with no verdict checkpoint is permanently `Missing`, and no CLI mints
/// that checkpoint; that is a verify-only operator prerequisite.)
#[test]
fn bootstrap_node_certifies_under_full_asi_hard_modes_with_custody_keys() {
    let (_dir, db_path, key_dir, recovery) = store_only_migrated_node();
    let cfg = cfg_for(&db_path);
    let wdir = tempfile::tempdir().expect("witness dir");
    let rdir = tempfile::tempdir().expect("recorder dir");
    enroll_custody_key(wdir.path(), roles::WITNESS_KEY_LABEL);
    enroll_custody_key(rdir.path(), roles::RECORDER_KEY_LABEL);

    let mut muts = base_mutations();
    muts.push((roles::WITNESS_KEY_DIR_ENV, wdir.path().to_str()));
    muts.push((roles::RECORDER_KEY_DIR_ENV, rdir.path().to_str()));
    let _g = MultiEnvVarGuard::apply(&muts);

    let (code, so, se) = run_bootstrap(&cfg, &key_dir, Some(recovery));
    assert_eq!(
        code, 0,
        "certified under full asi-hard modes with witness+recorder keys. stderr: {se}"
    );
    assert!(so.contains("CERTIFIED-READY"), "stdout: {so}");
    // The success label names EXACTLY which modes were armed for the verdict.
    assert!(
        so.contains("witness") && so.contains("role_separation") && so.contains("identity_lineage"),
        "CERTIFIED-READY must name the armed modes for the auditor: {so}"
    );

    // The spine now verifies CLEAN under the same armed modes.
    {
        let conn = db::open(&db_path).expect("open");
        assert!(
            verify_audit_trail(&conn, None, None).unwrap().is_clean(),
            "after bring-up the audit spine must verify clean under the armed modes"
        );
    }

    // Idempotent re-run WITHOUT a recovery pubkey stays certified (exit 0).
    let (code2, so2, se2) = run_bootstrap(&cfg, &key_dir, None);
    assert_eq!(
        code2, 0,
        "idempotent re-run must stay certified. stderr: {se2}"
    );
    assert!(so2.contains("already-enrolled"), "stdout: {so2}");
}

/// MB1 — under the FULL asi-hard modes but WITHOUT the witness/recorder custody
/// keys, bring-up FAIL-CLOSES (never false-certifies): the verify convicts on
/// the witness + role-separation lanes, so bootstrap-node exits 1 and NAMES the
/// remaining operator ceremony. (This is the failure DIRECTION the pre-fix gate
/// got backwards — it would have printed CERTIFIED-READY here.)
#[test]
fn bootstrap_node_refuses_under_asi_hard_modes_without_custody_keys() {
    let (_dir, db_path, key_dir, recovery) = store_only_migrated_node();
    let cfg = cfg_for(&db_path);
    // Point the custody dirs at EMPTY dirs so no key resolves (hermetic —
    // never the operator's real custody dir).
    let empty_w = tempfile::tempdir().expect("empty witness dir");
    let empty_r = tempfile::tempdir().expect("empty recorder dir");
    let mut muts = base_mutations();
    muts.push((roles::WITNESS_KEY_DIR_ENV, empty_w.path().to_str()));
    muts.push((roles::RECORDER_KEY_DIR_ENV, empty_r.path().to_str()));
    let _g = MultiEnvVarGuard::apply(&muts);

    let (code, _so, se) = run_bootstrap(&cfg, &key_dir, Some(recovery));
    assert_eq!(
        code, 1,
        "asi-hard modes armed but no custody keys must REFUSE (fail-closed). stderr: {se}"
    );
    assert!(
        se.contains("NOT CERTIFIED"),
        "refusal must be explicit: {se}"
    );
    assert!(
        se.contains("WITNESS"),
        "refusal must name the unmet witness ceremony: {se}"
    );
    assert!(
        se.contains("ROLE SEPARATION"),
        "refusal must name the unmet role-separation ceremony: {se}"
    );
}

/// MB1 (the core false-certify) — when the certified require-modes are NOT all
/// armed in-process, bring-up CANNOT claim certified even though the verify
/// would be `is_clean()` under zero armed modes. This is the exact false-green
/// the pre-fix gate produced in a bare provisioning shell.
#[test]
fn bootstrap_node_refuses_when_certified_modes_not_armed() {
    let (_dir, db_path, key_dir, recovery) = store_only_migrated_node();
    let cfg = cfg_for(&db_path);
    // No certified require-modes armed (all explicitly cleared).
    let _g = MultiEnvVarGuard::apply(&[
        (roles::REQUIRE_WITNESS_ENV, None),
        (roles::REQUIRE_ROLE_SEPARATION_ENV, None),
        (REQUIRE_IDENTITY_LINEAGE_ENV, None),
        ("AI_MEMORY_STORE_URL", None),
        ("AI_MEMORY_STORE_URL_FILE", None),
    ]);

    let (code, _so, se) = run_bootstrap(&cfg, &key_dir, Some(recovery));
    assert_eq!(
        code, 1,
        "unarmed certified modes must REFUSE the certified claim (fail-closed). stderr: {se}"
    );
    assert!(
        se.contains("certified audit require-modes are NOT all armed"),
        "refusal must explain the modes are not armed: {se}"
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
