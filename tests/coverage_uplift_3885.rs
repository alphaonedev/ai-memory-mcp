// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3885 — coverage uplift for the two below-floor modules on the promotion
//! tip: `cli/doctor.rs` (+17) and `daemon_runtime.rs` (+32). The gap is not
//! untested NEW code — the new code is well covered — it is PRE-EXISTING
//! dispatch arms and doctor branches that `--lib` tests do not reach.
//!
//! These are `assert_cmd` integration tests that drive the REAL `ai-memory`
//! binary end-to-end (the `tests/dispatch_integration.rs` pattern, which exists
//! precisely to cover the `daemon_runtime::run` `Command::*` arms). Running the
//! binary is what `cargo-llvm-cov --tests` instruments, so the subprocess's
//! `daemon_runtime.rs` + `cli/doctor.rs` lines are attributed. Every test here
//! ASSERTS A REAL CLI CONTRACT — the coverage is a byproduct, per the #3885
//! constraint. A run that only touched lines without asserting would be left
//! red instead (see `run_sync_daemon`, called out in the plan handoff).

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// `ai-memory --db <tmp> …` with the uniform test env (no user config).
fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().unwrap()]);
    cmd
}

/// #3885 — `daemon_runtime.rs` `Command::Notify` dispatch arm (the `2987–2998`
/// run): the arm builds `CliOutput`, calls `cli::commands::notify::cmd_notify`,
/// and returns its exit. The CONTRACT it wires is that `ai-memory notify`
/// records a notification and reports its id on stdout. Asserting that id line
/// exercises the arm end to end.
#[test]
fn notify_dispatch_records_and_reports_id_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("notify.db");
    let out = ai_memory(&db)
        .args([
            "notify",
            "--target-agent-id",
            "ai:recipient@node",
            "--title",
            "coverage probe",
            "--payload",
            "hello",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("notify: id=") && text.contains("to=ai:recipient@node"),
        "`ai-memory notify` must record the notification and report its id + recipient; got: {text:?}"
    );
}

/// #3885 — `cli/doctor.rs` `section_config_health_3166` `Ok(config)` arm (the
/// `2249–2256` run). Every `--lib` test runs with `AI_MEMORY_NO_CONFIG=1`, so
/// `skip_config()` short-circuits BEFORE `AppConfig::load_for_boot()` and the
/// Ok arm never runs. Here we REMOVE `AI_MEMORY_NO_CONFIG` and point
/// `XDG_CONFIG_HOME` at an EMPTY dir, so `load_for_boot()` resolves the
/// absent-config compiled-defaults path and returns `Ok`. The CONTRACT is that
/// `doctor --json` then reports config health as ok/compiled-defaults with the
/// resolved `archive_on_gc`.
#[test]
fn doctor_config_health_reports_compiled_defaults_when_config_absent_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("doctor.db");
    let empty_xdg = tmp.path().join("xdg-empty");
    std::fs::create_dir_all(&empty_xdg).unwrap();

    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    let out = cmd
        // NOT AI_MEMORY_NO_CONFIG — we need skip_config() == false so the
        // load_for_boot() Ok arm is reached.
        .env_remove("AI_MEMORY_NO_CONFIG")
        .env("XDG_CONFIG_HOME", &empty_xdg) // no hooks.toml / config.toml here
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().unwrap(), "doctor", "--json"])
        // NOT .success(): the doctor's OVERALL verdict may be non-zero from an
        // unrelated section (a CRITICAL check), but section_config_health_3166 is
        // emitted regardless, which is the line under test.
        .assert()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ok (or absent — compiled defaults)"),
        "doctor --json config-health must report the load_for_boot Ok / compiled-defaults status when \
         no user config is present; got (first 400 chars): {:?}",
        text.chars().take(400).collect::<String>()
    );
}

/// #3885 — `cli/doctor.rs` per-hook `executors` JSON builder inside `run_hooks`
/// (the `662-672` run). Every current test runs `run_hooks` with an EMPTY hooks
/// list, so the `.map()` produces `[]` and the field-projection lines never run.
/// Here we write a one-hook `hooks.toml` at the default path (via
/// `XDG_CONFIG_HOME`), so `doctor --hooks --json` loads it and emits the
/// executor row. The CONTRACT (per the run_hooks doc: operators sanity-check
/// their `hooks.toml` through this output) is that the emitted JSON carries the
/// hook's own event / mode / namespace / priority / timeout_ms / enabled.
// `config_dir()` honours `XDG_CONFIG_HOME` only on Linux; on macOS it resolves
// ~/Library and would not find this hooks.toml. The coverage sweep runs on Linux.
#[cfg(target_os = "linux")]
#[test]
fn doctor_hooks_json_emits_the_configured_executor_fields_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("doctor.db");
    let xdg = tmp.path().join("xdg");
    let hooks_dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&hooks_dir).unwrap();

    // A real (dummy) command so validate_hook's command check passes.
    let cmd_path = tmp.path().join("hook.sh");
    std::fs::write(&cmd_path, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cmd_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Distinctive values so the assertions prove the EXECUTOR row was emitted
    // from THIS hook, not defaults.
    let hooks_toml = format!(
        "[[hook]]\n\
         event = \"post_store\"\n\
         command = {cmd:?}\n\
         priority = 7\n\
         timeout_ms = 4200\n\
         mode = \"exec\"\n\
         enabled = true\n\
         namespace = \"team/eng\"\n",
        cmd = cmd_path.display().to_string(),
    );
    std::fs::write(hooks_dir.join("hooks.toml"), hooks_toml).unwrap();

    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    let out = cmd
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("XDG_CONFIG_HOME", &xdg)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args(["--db", db.to_str().unwrap(), "doctor", "--hooks", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    for needle in [
        "\"event\": \"post_store\"",
        "\"mode\": \"exec\"",
        "\"namespace\": \"team/eng\"",
        "\"priority\": 7",
        "\"timeout_ms\": 4200",
        "\"enabled\": true",
    ] {
        assert!(
            text.contains(needle),
            "doctor --hooks --json must emit the configured executor field {needle:?}; got (first 600 \
             chars): {:?}",
            text.chars().take(600).collect::<String>()
        );
    }
}

/// #3885 — `daemon_runtime.rs` `Command::Calibrate` arm (2749-2769). No `--lib`
/// or integration test drives `ai-memory calibrate confidence`, so the arm is
/// uncovered in the baseline suite. The CONTRACT: over a corpus, the Form-5
/// calibration driver emits its structured report (window, observation count,
/// per-namespace baselines). Runs offline — no LLM, no postgres.
#[test]
fn calibrate_confidence_emits_its_report_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("cal.db");
    // Calibration operates over a corpus; seed one memory so the store is
    // migrated and there is something to calibrate (an empty db has no corpus).
    ai_memory(&db)
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .args([
            "store",
            "--title",
            "calibration seed",
            "--content",
            "seed body for the calibration report probe",
        ])
        .assert()
        .success();
    let out = ai_memory(&db)
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .args(["calibrate", "confidence"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    for needle in ["window_days", "total_observations", "baselines"] {
        assert!(
            text.contains(needle),
            "`ai-memory calibrate confidence` must emit its calibration report field {needle:?}; got: \
             {text:?}"
        );
    }
}

/// #3885 — `daemon_runtime.rs` `Command::CheckDuplicate` arm (2840-2848). The
/// dedup pre-check verb is not driven by the suite. The CONTRACT: on a corpus
/// with no matching memory, `check-duplicate` reports NO duplicate after
/// scanning. Non-pg, offline.
#[test]
fn check_duplicate_reports_no_duplicate_on_a_fresh_corpus_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("dup.db");
    // check-duplicate builds the semantic embedder; under EMBED_OFFLINE it relies on a pre-staged HF model cache, so a host without one fails at embedder build, not at the assertion below.
    let out = ai_memory(&db)
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .args([
            "check-duplicate",
            "--title",
            "a title with no prior match",
            "--content",
            "content body that exists nowhere in this fresh corpus",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("check-duplicate:") && text.contains("no duplicate"),
        "`ai-memory check-duplicate` must report no duplicate on a fresh corpus; got: {text:?}"
    );
}

/// #3885 — `daemon_runtime.rs` `Command::Namespace` arm (1964-1975). The
/// governance-standard CLI wrapper is not driven by the suite. The CONTRACT:
/// querying a namespace that has no standard bound reports its absence (rather
/// than fabricating one). Non-pg, offline.
#[test]
fn namespace_get_standard_reports_absence_for_an_unconfigured_namespace_3885() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ns.db");
    let out = ai_memory(&db)
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .args([
            "namespace",
            "get-standard",
            "--namespace",
            "team/unconfigured",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("has no standard set"),
        "`ai-memory namespace get-standard` must report absence for an unconfigured namespace; got: \
         {text:?}"
    );
}
