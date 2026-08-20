// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1961 (R23/R7) — subprocess coverage for the `asi-hard` security-posture
//! enforcement seam. As of #2386 the environment-MUTATING enforcement
//! (`security_profile::enforce_at_boot_pre_runtime`) runs in the SYNCHRONOUS
//! pre-runtime phase of `fn main()` (the #1889 contract — before the tracing
//! appender worker or any tokio runtime worker exists), and the async
//! `src/daemon_runtime.rs::run` body only consumes the READ-ONLY
//! `security_profile::runtime_boot_report()?` to log the pin report (its `?`
//! keeps the fail-closed propagation for direct lib callers). Driven through
//! the real binary (`CARGO_BIN_EXE_ai-memory`) because the boot seam —
//! posture resolve, the `posture == AsiHard` pin-logging loop, and the
//! fail-closed error-propagation on a loosening / garbage posture — is
//! integration-only (see `coverage/policy.md` for the `daemon_runtime.rs`
//! exception) and is reached ONLY when `AI_MEMORY_SECURITY_PROFILE` is set in
//! the process environment. No existing subprocess test sets that env, so the
//! entire `AsiHard` branch (the net-new #1961 lines) is otherwise uncovered.
//!
//! The pure posture-parse + knob-pin table is unit-tested in
//! `src/security_profile.rs::tests`; the shipped `asi-hard` config/env
//! TEMPLATES are pinned by `tests/deploy_templates.rs`. This file pins the
//! CLI dispatch seam that neither of those exercises.
//!
//! NOT feature-gated: the pre-runtime enforcement + the `run`-side report
//! block are in the default-build dispatch path (not behind `--features sal`).
//!
//! Ground truth is the process EXIT CODE + the stderr error text, which the
//! CLI's top-level error handler prints (the boot posture refusals surface as
//! `Err(..)` propagated out of `run` — distinct from the tracing WARN/INFO
//! the pin-logging loop emits, which CLI one-shots do NOT render because they
//! install no subscriber; see `src/main.rs`'s COVERAGE NOTE).

use std::path::{Path, PathBuf};
use std::process::Output;

/// Run `ai-memory --db <db> <args...>` with `AI_MEMORY_NO_CONFIG=1` plus the
/// caller-supplied env overrides (the posture knobs). Returns the captured
/// [`Output`].
fn run_ai_memory(db_path: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("--db").arg(db_path);
    for a in args {
        cmd.arg(a);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn ai-memory")
}

/// A fresh temp DB path under `.local-runs/` (project no-`/tmp` HARD RULE),
/// mirroring `tests/record_stop_cli_dispatch_1955.rs::fresh_db`.
fn fresh_db(label: &str) -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1961-security-profile-dispatch");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let db = dir.path().join("ai-memory.db");
    (dir, db)
}

/// Control: with NO posture set (the compiled-default `standard`), the
/// enforcement is a no-op — `posture == Standard` short-circuits
/// past the `AsiHard` pin-logging loop and the command proceeds normally.
/// Pins the negative half of the boot branch so a future refactor that made
/// `standard` accidentally fail-closed would trip here.
#[test]
fn standard_posture_is_a_noop_and_command_proceeds() {
    let (_dir, db) = fresh_db("standard-noop");
    let out = run_ai_memory(&db, &["stats", "--json"], &[]);
    assert!(
        out.status.success(),
        "standard posture must be a boot no-op; exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stats --json parses under standard posture");
    assert_eq!(v["total"], 0, "fresh db has zero memories; got: {v}");
}

/// `asi-hard` ENGAGED: the `posture == AsiHard` pin-logging branch runs and
/// PINS the fail-closed knob set ON — including `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`
/// (#124), which refuses to open a WIPED database at the db-open seam.
///
/// v1.0.0 #2942 (5-agent vote, #3089 Vote A) narrowed the open-time rollback
/// control with a cold-boot carve-out: a genuinely FRESH asi-hard node (no
/// surviving off-table head anchor) now BOOTS so the operator can run the
/// witness-enrollment ceremony (covered by
/// [`asi_hard_cold_boot_fresh_db_boots_clean_2942`]). The refuse-open PROOF that
/// the asi-hard branch executed and its pins took effect therefore moves to a
/// WIPED node: a `signed_events` head of 0 (genesis-less) BUT a SURVIVING
/// off-table head anchor from a prior require-mode run whose witness pin is no
/// longer resolvable (`Unpinnable`). The surviving-anchor discriminator
/// (`off_table_head_anchor_present`) keeps the verdict `Missing`, so the open is
/// refused — and ONLY under the asi-hard-pinned require-mode (under `standard`
/// the same wiped node would open, exactly as
/// [`standard_posture_is_a_noop_and_command_proceeds`] shows for a clean node).
/// The wiped state is seeded DETERMINISTICALLY via an explicit
/// `AI_MEMORY_WITNESS_KEY_DIR` (asi-hard does not pin that operator-owned dir),
/// so the refusal never depends on ambient default-custody-dir state. Exercises
/// the net-new #1961 `AsiHard` arm.
#[test]
fn asi_hard_engaged_pins_rollback_check_and_refuses_open_on_wiped_db() {
    let (_dir, db) = fresh_db("asi-hard-engaged-wiped");
    // Seed the wiped-vs-fresh discriminator (#2942): a SURVIVING off-table head
    // anchor line but NO enrolled pubkey in the witness key dir → the pin is
    // `Unpinnable` AND an anchor survives, so the cold-boot carve-out does NOT
    // apply and the rollback verdict stays `Missing` (refuse) under require-mode.
    let kdir = tempfile::Builder::new()
        .prefix("asi-hard-wiped-keys-")
        .tempdir()
        .expect("tempdir for witness key dir");
    std::fs::write(
        kdir.path().join("head-anchor.log"),
        "{\"surviving\":\"anchor-line-from-a-prior-require-mode-run\"}\n",
    )
    .expect("write surviving off-table anchor");
    let kdir_s = kdir.path().to_str().expect("utf-8 witness key dir path");
    let out = run_ai_memory(
        &db,
        &["stats", "--json"],
        &[
            ("AI_MEMORY_SECURITY_PROFILE", "asi-hard"),
            ("AI_MEMORY_WITNESS_KEY_DIR", kdir_s),
        ],
    );
    assert!(
        !out.status.success(),
        "asi-hard pins require_rollback_check=1 → a WIPED db (surviving off-table \
         anchor, unresolvable pin) open must be refused; exit={:?} stdout={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("rollback-check refuse-open")
            || stderr.contains("AI_MEMORY_REQUIRE_ROLLBACK_CHECK"),
        "expected the asi-hard-pinned rollback-check refusal; stderr={stderr}"
    );
}

/// v1.0.0 #2942 (5-agent vote, #3089 Vote A) — the asi-hard COLD-BOOT carve-out
/// at the subprocess dispatch seam (the companion of
/// [`asi_hard_engaged_pins_rollback_check_and_refuses_open_on_wiped_db`]). A
/// genuinely fresh asi-hard node — genesis-less, `signed_events` head 0, witness
/// pin NOT yet enrolled, and NO surviving off-table head anchor on the mount —
/// must BOOT CLEAN under the asi-hard-pinned require-mode, so the operator can
/// run the witness-enrollment ceremony (the cold-boot chicken-and-egg). Same
/// asi-hard pins as the wiped case; only the surviving-anchor discriminator
/// differs, flipping the verdict from `Missing` (refuse) to `NotApplicable`
/// (proceed). The witness key dir is pointed at an EMPTY dir so the custody
/// state is deterministic: no pubkey (unenrolled pin) and no `head-anchor.log`
/// (nothing to roll back FROM).
#[test]
fn asi_hard_cold_boot_fresh_db_boots_clean_2942() {
    let (_dir, db) = fresh_db("asi-hard-cold-fresh");
    let kdir = tempfile::Builder::new()
        .prefix("asi-hard-fresh-keys-")
        .tempdir()
        .expect("tempdir for empty witness key dir");
    let kdir_s = kdir.path().to_str().expect("utf-8 witness key dir path");
    let out = run_ai_memory(
        &db,
        &["stats", "--json"],
        &[
            ("AI_MEMORY_SECURITY_PROFILE", "asi-hard"),
            ("AI_MEMORY_WITNESS_KEY_DIR", kdir_s),
        ],
    );
    assert!(
        out.status.success(),
        "asi-hard #2942 cold-boot carve-out: a genuinely fresh db (unenrolled \
         pin + head-0 + no surviving off-table anchor) must BOOT CLEAN under \
         require-mode; exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("stats --json parses on a cold-boot asi-hard fresh db");
    assert_eq!(
        v["total"], 0,
        "fresh cold-boot db has zero memories; got: {v}"
    );
}

/// `asi-hard` + an operator LOOSENING override below the hard floor: boot is
/// REFUSED by the pre-runtime `enforce_at_boot_pre_runtime` in `fn main()`
/// (#2386), which propagates `Err(..)` out of the binary before the runtime
/// is even built. Exercises the fail-closed error-propagation arm distinct
/// from the successful-pin arm above.
#[test]
fn asi_hard_refuses_boot_when_operator_loosens_a_pinned_knob() {
    let (_dir, db) = fresh_db("asi-hard-loosen");
    let out = run_ai_memory(
        &db,
        &["stats", "--json"],
        &[
            ("AI_MEMORY_SECURITY_PROFILE", "asi-hard"),
            ("AI_MEMORY_SECRET_SCREEN_MODE", "off"),
        ],
    );
    assert!(
        !out.status.success(),
        "asi-hard must refuse to boot when a pinned knob is loosened; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("AI_MEMORY_SECRET_SCREEN_MODE")
            && (stderr.contains("refuses to disable") || stderr.contains("hard floor")),
        "expected the asi-hard loosening refusal naming the knob; stderr={stderr}"
    );
}

/// A garbage `AI_MEMORY_SECURITY_PROFILE` token aborts the boot (fail-LOUD,
/// never silent-standard) — the parse-error arm of `SecurityPosture::resolve`
/// propagated through the pre-runtime `enforce_at_boot_pre_runtime()?` in
/// `fn main()` (#2386).
#[test]
fn unrecognised_security_profile_token_aborts_boot() {
    let (_dir, db) = fresh_db("bogus-token");
    let out = run_ai_memory(
        &db,
        &["stats", "--json"],
        &[("AI_MEMORY_SECURITY_PROFILE", "bogus-not-a-posture")],
    );
    assert!(
        !out.status.success(),
        "an unrecognised security-profile token must abort the boot; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("AI_MEMORY_SECURITY_PROFILE") && stderr.contains("unrecognised"),
        "expected the unrecognised-posture boot error; stderr={stderr}"
    );
}
