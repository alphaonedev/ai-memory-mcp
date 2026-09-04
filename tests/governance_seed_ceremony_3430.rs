// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3430 — the documented seed-rule ceremony must produce rules
//! that actually ENFORCE.
//!
//! `ai-memory rules sign-seed` signs `enabled` into the canonical
//! payload (`canonical_bytes_for_signing`). Before this fix
//! `ai-memory governance install-defaults --yes` then issued a raw
//! `UPDATE governance_rules SET enabled = 1` that did not touch the
//! signature column, so every seed signature stopped verifying and the
//! #1042 L1-6 load gate silently DROPPED all four rules — while the CLI
//! reported `activated` / `enabled: true` / `operator_signed` /
//! `inert: false` and `rules check` answered `allow`.
//!
//! This suite pins the control end-to-end:
//!
//! * DENIED path — after `sign-seed` → `install-defaults`, a `/tmp`
//!   write is REFUSED (the seeded R001 rule fires).
//! * ALLOWED path — a write outside every seed glob still passes, so
//!   the fix did not turn the gate into a blanket refusal.
//! * REFUSAL path — with signed seed rows and no loadable operator key,
//!   `install-defaults` refuses BEFORE any write and the rows stay
//!   disabled (it must never neuter a signature to make progress).
//! * SELF-HEAL path — a store already poisoned by the pre-#3430
//!   raw-UPDATE is repaired: the row is re-signed over the post-state
//!   and starts firing.
//! * SURFACE HONESTY — `rules list` reports `enforced` /
//!   `enforcement_state` derived from signature validity, never from the
//!   raw `enabled` column.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::cli::CliOutput;
use ai_memory::cli::governance_install_defaults::{self, InstallDefaultsArgs};
use ai_memory::cli::rules::{RulesAction, RulesArgs};
use ai_memory::governance::agent_action::{AgentAction, Decision, check_agent_action};
use ai_memory::governance::rules_store;

/// `AI_MEMORY_KEY_DIR` is process-global; serialise every test in this
/// binary that mutates it.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Point the operator-key resolution ladder (signer AND verifier) at a
/// scratch directory for the duration of the test. Restores the prior
/// value on drop, including on panic-unwind.
struct KeyDirGuard {
    prior: Option<std::ffi::OsString>,
    prior_pubkey: Option<std::ffi::OsString>,
}

impl KeyDirGuard {
    fn set(dir: &Path) -> Self {
        let prior = std::env::var_os("AI_MEMORY_KEY_DIR");
        let prior_pubkey = std::env::var_os("AI_MEMORY_OPERATOR_PUBKEY");
        // SAFETY: the caller holds `env_lock()` for the whole test body,
        // so no sibling test in this binary reads or writes the env
        // concurrently.
        unsafe {
            std::env::set_var("AI_MEMORY_KEY_DIR", dir);
            // The env var would shadow the on-disk key dir; clear it so
            // the ladder resolves `<key_dir>/operator.key.pub`.
            std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY");
        }
        Self {
            prior,
            prior_pubkey,
        }
    }
}

impl Drop for KeyDirGuard {
    fn drop(&mut self) {
        // SAFETY: same env_lock scope as `set`.
        unsafe {
            match self.prior.take() {
                Some(v) => std::env::set_var("AI_MEMORY_KEY_DIR", v),
                None => std::env::remove_var("AI_MEMORY_KEY_DIR"),
            }
            match self.prior_pubkey.take() {
                Some(v) => std::env::set_var("AI_MEMORY_OPERATOR_PUBKEY", v),
                None => std::env::remove_var("AI_MEMORY_OPERATOR_PUBKEY"),
            }
        }
    }
}

/// Fresh fully-migrated store (seeds R001-R004 at `enabled = 0`) plus a
/// 0700 scratch key directory.
fn fresh_env() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("ceremony.db");
    drop(ai_memory::db::open(&db_path).expect("open db"));
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(&key_dir).expect("mkdir keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key dir");
    }
    (dir, db_path, key_dir)
}

fn run_rules(db_path: &Path, key_dir: &Path, action: RulesAction) -> anyhow::Result<String> {
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let args = RulesArgs {
        key_dir: Some(key_dir.to_path_buf()),
        action,
    };
    // Scope the `CliOutput` so its borrow of `so` ends before we read it.
    let res = {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::rules::run(db_path, args, true, &mut out)
    };
    res?;
    Ok(String::from_utf8(so).expect("utf8 stdout"))
}

fn keygen(db_path: &Path, key_dir: &Path) {
    run_rules(
        db_path,
        key_dir,
        RulesAction::Keygen {
            out: Some(key_dir.join("operator.key")),
            force: false,
        },
    )
    .expect("keygen");
}

fn sign_seed(db_path: &Path, key_dir: &Path) {
    run_rules(
        db_path,
        key_dir,
        RulesAction::SignSeed {
            key: Some(key_dir.join("operator.key")),
            db: None,
        },
    )
    .expect("sign-seed");
}

fn install_defaults(db_path: &Path, key_dir: Option<&Path>) -> anyhow::Result<String> {
    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    // Scope the `CliOutput` so its borrow of `so` ends before we read it.
    let res = {
        let mut out = CliOutput::from_std(&mut so, &mut se);
        governance_install_defaults::run(
            db_path,
            InstallDefaultsArgs {
                yes: true,
                json: true,
                key_dir: key_dir.map(Path::to_path_buf),
            },
            &mut out,
        )
    };
    res?;
    Ok(String::from_utf8(so).expect("utf8 stdout"))
}

fn probe_tmp_write(db_path: &Path, path: &str) -> Decision {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    let action = AgentAction::FilesystemWrite {
        path: path.into(),
        byte_estimate: None,
    };
    check_agent_action(&conn, "agent:3430", &action).expect("check_agent_action")
}

fn enabled_flags(db_path: &Path) -> Vec<(String, bool, String)> {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    rules_store::list(&conn)
        .expect("list")
        .into_iter()
        .map(|r| (r.id, r.enabled, r.attest_level))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. The documented ceremony now DENIES the seeded actions.
// ---------------------------------------------------------------------------

#[test]
fn seed_ceremony_produces_enforcing_rules_3430() {
    let _g = env_lock();
    let (_dir, db_path, key_dir) = fresh_env();
    let _env = KeyDirGuard::set(&key_dir);

    keygen(&db_path, &key_dir);
    sign_seed(&db_path, &key_dir);

    // Pre-condition: the operator pubkey now resolves, so L1-6 is live.
    assert!(
        rules_store::resolve_operator_pubkey().is_some(),
        "keygen must leave a resolvable operator pubkey"
    );

    let stdout = install_defaults(&db_path, Some(&key_dir)).expect("install-defaults must succeed");
    let envelope: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("install-defaults JSON envelope");
    let result = &envelope["result"];
    assert_eq!(result["activated"].as_array().unwrap().len(), 4);
    assert_eq!(
        result["enforced"].as_array().unwrap().len(),
        4,
        "#3430: all four seed rules must be REALLY enforced, envelope was {envelope}"
    );
    assert!(
        result["not_enforced"].as_array().unwrap().is_empty(),
        "#3430: no seed rule may be left inert, envelope was {envelope}"
    );
    assert_eq!(
        result["resigned"].as_array().unwrap().len(),
        4,
        "#3430: activation of signed rows must re-commit the signature"
    );

    // DENIED path — this is the regression. Pre-#3430 this returned
    // Decision::Allow because every signature had been invalidated by
    // the raw `UPDATE ... SET enabled = 1`.
    match probe_tmp_write(&db_path, "/tmp/leak.txt") {
        Decision::Refuse { rule_id, .. } => assert_eq!(rule_id, "R001"),
        other => panic!("#3430: /tmp write must be REFUSED after the ceremony, got {other:?}"),
    }

    // ALLOWED path — the fix must not turn the gate into a blanket
    // refusal: a path outside every seed glob still passes.
    assert_eq!(
        probe_tmp_write(&db_path, "/home/operator/project/notes.txt"),
        Decision::Allow,
        "#3430: a path outside the seed globs must still be allowed"
    );

    // Every row is enabled AND operator_signed on disk.
    for (id, enabled, attest) in enabled_flags(&db_path) {
        assert!(enabled, "{id} must be enabled");
        assert_eq!(attest, "operator_signed", "{id} attest level");
    }
}

// ---------------------------------------------------------------------------
// 2. REFUSAL — signed rows + no loadable operator key => no write at all.
// ---------------------------------------------------------------------------

#[test]
fn install_defaults_refuses_signed_rows_without_operator_key_3430() {
    let _g = env_lock();
    let (dir, db_path, key_dir) = fresh_env();
    let _env = KeyDirGuard::set(&key_dir);

    keygen(&db_path, &key_dir);
    sign_seed(&db_path, &key_dir);

    // An empty (but well-permissioned) key directory: the operator key
    // is not reachable from here.
    let empty_key_dir = dir.path().join("no-keys");
    std::fs::create_dir_all(&empty_key_dir).expect("mkdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&empty_key_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
    }

    let err = install_defaults(&db_path, Some(&empty_key_dir))
        .expect_err("#3430: must refuse rather than neuter the signatures");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("#3430") && msg.contains("operator_signed"),
        "refusal must name the control and the cause; got: {msg}"
    );

    // Fail closed: the refusal fires BEFORE any write.
    for (id, enabled, _) in enabled_flags(&db_path) {
        assert!(
            !enabled,
            "#3430: {id} must stay disabled when the signed path is unavailable"
        );
    }
    assert_eq!(
        probe_tmp_write(&db_path, "/tmp/leak.txt"),
        Decision::Allow,
        "rules stayed disabled, so nothing enforces (and nothing lies about it)"
    );
}

// ---------------------------------------------------------------------------
// 3. SELF-HEAL — a store poisoned by the pre-#3430 raw UPDATE is repaired.
// ---------------------------------------------------------------------------

#[test]
fn install_defaults_repairs_rows_left_inert_by_a_raw_enable_3430() {
    let _g = env_lock();
    let (_dir, db_path, key_dir) = fresh_env();
    let _env = KeyDirGuard::set(&key_dir);

    keygen(&db_path, &key_dir);
    sign_seed(&db_path, &key_dir);

    // Reproduce the pre-#3430 corruption exactly: flip `enabled`
    // underneath the signature with raw SQL.
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        conn.execute("UPDATE governance_rules SET enabled = 1", [])
            .expect("raw enable");
    }
    assert_eq!(
        probe_tmp_write(&db_path, "/tmp/leak.txt"),
        Decision::Allow,
        "pre-condition: the poisoned store enforces nothing (this IS the bug)"
    );

    let stdout = install_defaults(&db_path, Some(&key_dir)).expect("install-defaults must repair");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON envelope");
    let result = &envelope["result"];
    assert_eq!(
        result["repaired"].as_array().unwrap().len(),
        4,
        "#3430: all four inert-but-enabled rows must be self-healed, got {envelope}"
    );
    assert_eq!(result["enforced"].as_array().unwrap().len(), 4);
    assert!(result["not_enforced"].as_array().unwrap().is_empty());

    match probe_tmp_write(&db_path, "/tmp/leak.txt") {
        Decision::Refuse { rule_id, .. } => assert_eq!(rule_id, "R001"),
        other => panic!("#3430: repaired rule must fire, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. SURFACE HONESTY — `rules list` reports the REAL enforcement state.
// ---------------------------------------------------------------------------

#[test]
fn rules_list_reports_real_enforcement_state_3430() {
    let _g = env_lock();
    let (_dir, db_path, key_dir) = fresh_env();
    let _env = KeyDirGuard::set(&key_dir);

    keygen(&db_path, &key_dir);
    sign_seed(&db_path, &key_dir);
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        conn.execute(
            "UPDATE governance_rules SET enabled = 1 WHERE id = 'R001'",
            [],
        )
        .expect("raw enable");
    }

    let stdout = run_rules(&db_path, &key_dir, RulesAction::List).expect("rules list");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON envelope");
    let rows = envelope["result"].as_array().expect("array");
    let r001 = rows
        .iter()
        .find(|r| r["id"] == "R001")
        .expect("R001 in listing");
    assert_eq!(r001["enabled"], true, "the raw column still reads enabled");
    assert_eq!(
        r001["enforced"], false,
        "#3430: `rules list` must not report an inert rule as live: {r001}"
    );
    assert_eq!(
        r001["enforcement_state"], "skipped_signature_invalid",
        "#3430: the listing must name WHY the rule is dead: {r001}"
    );

    // A disabled, correctly-signed row reports `disabled`, not a
    // signature problem.
    let r002 = rows
        .iter()
        .find(|r| r["id"] == "R002")
        .expect("R002 in listing");
    assert_eq!(r002["enforced"], false);
    assert_eq!(r002["enforcement_state"], "disabled");

    // ALLOWED path for the surface: after the supported ceremony the
    // same listing reports every row as genuinely enforced.
    install_defaults(&db_path, Some(&key_dir)).expect("install-defaults");
    let stdout = run_rules(&db_path, &key_dir, RulesAction::List).expect("rules list");
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON envelope");
    for row in envelope["result"].as_array().expect("array") {
        assert_eq!(
            row["enforced"], true,
            "#3430: every seed row must be enforced after the ceremony: {row}"
        );
        assert_eq!(row["enforcement_state"], "enforced");
    }
}

#[test]
fn install_defaults_wrong_signer_reports_each_inert_rule_and_fails_3496() {
    let _g = env_lock();
    let (dir, db_path, key_dir) = fresh_env();
    let _env = KeyDirGuard::set(&key_dir);
    keygen(&db_path, &key_dir);
    sign_seed(&db_path, &key_dir);

    let wrong_key_dir = dir.path().join("wrong-signer");
    keygen(&db_path, &wrong_key_dir);
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let err = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        governance_install_defaults::run(
            &db_path,
            InstallDefaultsArgs {
                yes: true,
                json: false,
                key_dir: Some(wrong_key_dir),
            },
            &mut out,
        )
        .expect_err("signing with a key other than the resolved verifier must fail")
    };

    let rendered = String::from_utf8(stdout).expect("utf8 stdout");
    let chain = format!("{err:#}");
    assert!(chain.contains("refused to report success (#3430)"));
    for id in ["R001", "R002", "R003", "R004"] {
        assert!(
            rendered.contains(&format!("NOT ENFORCED: {id} (skipped_signature_invalid)")),
            "the non-zero ceremony must identify inert {id}: {rendered}"
        );
    }
    assert!(rendered.contains("0 enforced, 4 inert"));
    assert!(
        !rendered.contains("4 enforced, 0 inert"),
        "a wrong-key ceremony must never claim enforcement: {rendered}"
    );
}
