// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3003 — `ai-memory doctor --posture <name>` MUST exit with the CONTRACTED
//! code 2 on a posture FAIL (Cert §7 disconfirmation clause 2 keys on
//! `run_posture` exit codes), even when the opt-in boot gate
//! `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1` is ARMED and the
//! posture is FAILING.
//!
//! Before the fix, the boot gate refused BEFORE dispatch and `main` bailed
//! with a generic `anyhow` error (process exit 1), so:
//!   - the diagnostic exited 1 (a generic CLI error), NOT the contracted 2, and
//!   - the boot-refusal remediation told the operator to re-run the exact
//!     command that just refused.
//!
//! These two legs pin the fix end-to-end against the REAL binary:
//!   1. `doctor --posture enterprise-federation` under an armed+failing gate
//!      exits 2 and renders the FAIL report (the gate is bypassed for it).
//!   2. a NON-diagnostic command (`boot`) under the same armed+failing gate
//!      still refuses (exit 1) and its remediation is actionable — it names
//!      the diagnostic and states the diagnostic works while the gate is armed.

use std::path::PathBuf;
use std::process::Command;

/// A scratch HOME under the repo's gitignored `.local-runs/` (project
/// no-`/tmp` HARD RULE). Each call makes a fresh unique subdir.
fn scratch_home() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("doctor-posture-3003");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch root");
    let unique = format!(
        "h-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let dir = root.join(unique);
    std::fs::create_dir_all(&dir).expect("create scratch home");
    dir
}

/// Build a `Command` for the built binary with a CLEAN environment carrying
/// only the armed enterprise-federation posture gate (nothing that would make
/// the posture PASS), so `evaluate()` reports a FAIL on the default config.
fn armed_failing_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear();
    // Minimal env the process needs, plus the isolated scratch roots.
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("AI_MEMORY_DB", home.join("scratch.db"));
    // Skip loading the developer host config so the posture evaluates against
    // the compiled default (which, with only the require-flag set, FAILS).
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    // Arm the opt-in enterprise-federation certified-posture boot gate.
    cmd.env("AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE", "1");
    cmd
}

#[test]
fn doctor_posture_exits_two_on_fail_even_when_boot_gate_armed() {
    let home = scratch_home();
    let out = armed_failing_cmd(&home)
        .args(["doctor", "--posture", "enterprise-federation"])
        .output()
        .expect("spawn ai-memory doctor --posture");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let code = out.status.code();

    // The CONTRACTED exit code is 2 on a posture FAIL — never 1 (the generic
    // boot-refusal error the pre-fix path produced).
    assert_eq!(
        code,
        Some(2),
        "doctor --posture must exit 2 on FAIL under an armed gate, got {code:?}\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The report actually rendered (the gate did NOT swallow it).
    assert!(
        stdout.contains("FAIL"),
        "expected the per-control FAIL report on stdout, got:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn non_diagnostic_command_still_refuses_with_actionable_remediation() {
    let home = scratch_home();
    // `boot` is NOT the posture diagnostic, so the armed+failing gate MUST
    // still refuse it before dispatch.
    let out = armed_failing_cmd(&home)
        .args(["boot"])
        .output()
        .expect("spawn ai-memory boot");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let code = out.status.code();

    // The boot gate refuses via `anyhow::bail!` → process exit 1.
    assert_eq!(
        code,
        Some(1),
        "an armed+failing gate must refuse a non-diagnostic command (exit 1), got {code:?}\n\
         stderr:\n{stderr}"
    );
    assert!(stderr.contains("refuses to boot"), "stderr:\n{stderr}");
    // The remediation is actionable: it names the diagnostic AND states the
    // diagnostic works while the gate is armed (it bypasses the refusal),
    // rather than telling the operator to re-run the command that just refused.
    assert!(
        stderr.contains("doctor --posture enterprise-federation"),
        "remediation must name the diagnostic; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("bypasses") && stderr.contains("armed"),
        "remediation must state the diagnostic works while the gate is armed; stderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
