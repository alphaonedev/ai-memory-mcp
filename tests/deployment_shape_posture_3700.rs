// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3700 — the deployment SHAPE decides the default security posture.
//!
//! Real binary boots (env supplied ONLY to the child, `env_clear`), the same
//! harness shape as `tests/federation_peer_posture_3582.rs`. Every test here
//! FAILS on the pre-fix head `f0175b709`, where `SecurityPosture::Standard`
//! is the compiled default regardless of shape and nothing in the boot or
//! `doctor` mentions `#3700`.
//!
//! The four states pinned (the issue's acceptance list):
//!
//! 1. fleet + selector unset + a loosened knob → REFUSES, naming every
//!    disabled knob and the one-line deliberate override;
//! 2. singleton + selector unset → boots unchanged (`standard`, silent);
//! 3. fleet + explicit `standard` → boots, warns ONCE, is recorded;
//! 4. `doctor`'s DEFAULT report states the shape, the posture and whether
//!    they match — CRIT on a fleet running `standard` by omission.

use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{free_port, permissive_attestation_for_tests};

/// A valid, EMPTY peer allowlist: federation is CONFIGURED (fleet-shaped)
/// while denying every peer, so the #3582 gate is satisfied in both postures
/// and only the #3700 shape-vs-posture logic decides the boot.
const EMPTY_ALLOWLIST: &str = "{}";

/// The doctor section name the #3700 fix adds (SECOND in the default report).
const SECTION_DEPLOYMENT_SHAPE: &str = "Deployment shape (#3700)";

/// The bind guard the `--host 0.0.0.0`-without-API-key boots stop at: it sits
/// AFTER the peer gate and the #3700 gate in `bootstrap_serve`, so reaching
/// it proves the shape gate let the boot through.
const BIND_GUARD_MARKER: &str = "without an API key";

/// Upper bound on waiting for a child to either exit or answer `/health`.
const BOOT_DEADLINE: Duration = Duration::from_secs(30);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

fn command(root: &Path) -> Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key sandbox");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("RUST_LOG", "error");
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Create the sqlite store through the production open (migrations land)
/// and register `agent_ids` in it.
fn seed_store(root: &Path, agent_ids: &[&str]) {
    permissive_attestation_for_tests();
    let conn = ai_memory::db::open(&root.join("store.db")).expect("open store");
    for id in agent_ids {
        ai_memory::db::register_agent(&conn, id, "worker", &[]).expect("register agent");
    }
}

fn health_is_200(port: u16) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .build()
        .expect("client");
    client
        .get(format!("http://127.0.0.1:{port}/api/v1/health"))
        .send()
        .is_ok_and(|r| r.status().is_success())
}

/// What a real (`--port <free>`) boot did within [`BOOT_DEADLINE`].
enum BootOutcome {
    /// The child exited on its own (status + captured stderr).
    Exited {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// `/health` answered 200; the child was then killed. Carries the
    /// stderr captured up to the kill.
    Healthy { stderr: String },
}

/// Spawn `serve --port <free>` (loopback) with `extra_env` and drive it to
/// either an exit or a healthy `/health`, capturing stderr either way.
fn boot_on_loopback(root: &Path, extra_env: &[(&str, &str)], settle: Duration) -> BootOutcome {
    let port = free_port();
    let mut cmd = command(root);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child: Child = cmd
        .args(["serve", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let reader = child.stderr.take().map(|err| {
        let sink = std::sync::Arc::clone(&buf);
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let mut g = sink.lock().unwrap();
                g.push_str(&line);
                g.push('\n');
            }
        })
    });
    let deadline = Instant::now() + BOOT_DEADLINE;
    let outcome = loop {
        if let Ok(Some(status)) = child.try_wait() {
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            break BootOutcome::Exited { status, stderr };
        }
        if health_is_200(port) {
            // Let the boot-time record settle before the kill.
            std::thread::sleep(settle);
            let _ = child.kill();
            let _ = child.wait();
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            break BootOutcome::Healthy { stderr };
        }
        assert!(
            Instant::now() < deadline,
            "serve neither exited nor became healthy within {BOOT_DEADLINE:?}; stderr:\n{}",
            buf.lock().unwrap()
        );
        std::thread::sleep(PROBE_INTERVAL);
    };
    outcome
}

fn doctor_json(root: &Path, extra_env: &[(&str, &str)]) -> serde_json::Value {
    let mut cmd = command(root);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.args(["doctor", "--json"]).output().expect("run doctor");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        (0..=2).contains(&code),
        "doctor must diagnose, never refuse (exit {code}); stderr:\n{}",
        stderr(&out)
    );
    serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("doctor --json must parse: {e}\n{}", stdout(&out)))
}

fn section<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    let sections = report["sections"].as_array().expect("sections array");
    sections
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| {
            let names: Vec<&str> = sections.iter().filter_map(|s| s["name"].as_str()).collect();
            panic!("doctor section {name:?} absent (#3700); sections present: {names:?}")
        })
}

fn fact<'a>(section: &'a serde_json::Value, key: &str) -> &'a str {
    section["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .find(|kv| kv[0] == key)
        .and_then(|kv| kv[1].as_str())
        .unwrap_or_else(|| panic!("fact {key:?} absent in {section}"))
}

/// State 1 — fleet by argv (`--quorum-peers`) with two protections
/// explicitly loosened and the selector UNSET: the derived `asi-hard`
/// refuses BEFORE any store is opened, naming BOTH knobs and the one-line
/// deliberate override.
///
/// FAILS ON HEAD: the boot runs `standard`, ignores the loosened knobs and
/// stops at the keyless `0.0.0.0` bind guard instead — stderr carries no
/// `#3700` and no knob name (`assert!(err.contains("#3700"))` fails first).
#[test]
fn fleet_by_argv_with_loosened_knob_refuses_naming_every_knob_and_override_3700() {
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path())
        .env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST)
        .env("AI_MEMORY_REQUIRE_WITNESS", "0")
        .env("AI_MEMORY_CID_ENFORCE", "0")
        .args([
            "serve",
            "--host",
            "0.0.0.0",
            "--quorum-writes",
            "0",
            "--quorum-peers",
            "https://127.0.0.1:1",
        ])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "must refuse; stderr:\n{err}");
    assert!(err.contains("#3700"), "{err}");
    assert!(err.contains("security posture \"asi-hard\""), "{err}");
    assert!(err.contains("outbound_peers"), "{err}");
    assert!(err.contains("AI_MEMORY_REQUIRE_WITNESS=\"0\""), "{err}");
    assert!(err.contains("AI_MEMORY_CID_ENFORCE=\"0\""), "{err}");
    assert!(err.contains("2 protection(s) are DISABLED"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=standard"), "{err}");
    assert!(
        !err.contains(BIND_GUARD_MARKER),
        "the refusal must fire before the bind guard: {err}"
    );
    assert!(
        !root.path().join("store.db").exists(),
        "refused pre-open: no store may be created"
    );
}

/// State 1b — the same fleet shape with NO loosened knob: `asi-hard` is
/// DERIVED (announced on stderr), every protection is pinned, and the boot
/// proceeds to the next gate (the keyless `0.0.0.0` bind guard).
///
/// FAILS ON HEAD: nothing is derived; stderr carries no `#3700`
/// (`assert!(err.contains("#3700"))` fails).
#[test]
fn fleet_by_env_derives_asi_hard_and_pins_3700() {
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path())
        .env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST)
        .args(["serve", "--host", "0.0.0.0"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("#3700"), "{err}");
    assert!(err.contains("DERIVED"), "{err}");
    assert!(err.contains("peer_allowlist"), "{err}");
    assert!(
        !err.contains("protection(s) are DISABLED"),
        "no knob is loosened, so no refusal: {err}"
    );
    assert!(
        err.contains(BIND_GUARD_MARKER),
        "the derived posture must let the boot reach the bind guard: {err}"
    );
}

/// State 2 — a SINGLETON (no fleet signal) with the selector unset keeps
/// `standard` and boots byte-identically: no `#3700` line, no `asi-hard`,
/// the boot reaches the bind guard; and `doctor` states the shape.
///
/// FAILS ON HEAD: the boot half passes (nothing changed there), the doctor
/// half fails because the "Deployment shape (#3700)" section does not exist.
#[test]
fn singleton_unset_boots_unchanged_3700() {
    let root = tempfile::tempdir().unwrap();
    let out = command(root.path())
        .args(["serve", "--host", "0.0.0.0"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains(BIND_GUARD_MARKER), "{err}");
    assert!(!err.contains("#3700"), "singleton must stay silent: {err}");
    assert!(
        !err.contains("asi-hard"),
        "singleton must stay standard: {err}"
    );

    seed_store(root.path(), &[]);
    let report = doctor_json(root.path(), &[]);
    let shape = section(&report, SECTION_DEPLOYMENT_SHAPE);
    assert_eq!(fact(shape, "shape"), "singleton");
    assert_eq!(fact(shape, "posture"), "standard");
    assert_eq!(fact(shape, "posture_origin"), "compiled_default");
    assert_eq!(fact(shape, "shape_matches_posture"), "true");
    assert_eq!(shape["severity"], "info", "{shape}");
    // SECOND in the default report, right after Configuration.
    assert_eq!(
        report["sections"][1]["name"], SECTION_DEPLOYMENT_SHAPE,
        "the shape must be stated at the top of the default report"
    );
}

/// State 3 — a fleet shape under an EXPLICIT `standard`: boots, warns
/// exactly ONCE, and the exception is recorded in the forensic audit
/// stream.
///
/// FAILS ON HEAD: the boot succeeds silently — zero `WARN #3700` lines
/// (`assert_eq!(warns, 1)` fails) and no forensic record.
#[test]
fn fleet_explicit_standard_boots_warns_once_and_is_recorded_3700() {
    let root = tempfile::tempdir().unwrap();
    let outcome = boot_on_loopback(
        root.path(),
        &[
            ("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST),
            ("AI_MEMORY_SECURITY_PROFILE", "standard"),
        ],
        Duration::from_secs(2),
    );
    let err = match outcome {
        BootOutcome::Healthy { stderr } => stderr,
        BootOutcome::Exited { status, stderr } => {
            panic!("explicit standard must boot; exited {status}; stderr:\n{stderr}")
        }
    };
    let warns = err.matches("WARN #3700").count();
    assert_eq!(warns, 1, "exactly one warning, got {warns}:\n{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=standard"), "{err}");
    assert!(err.contains("peer_allowlist"), "{err}");

    // Recorded: the forensic audit stream under AI_MEMORY_AUDIT_DIR carries
    // the exception row.
    let audit_dir = root.path().join("audit");
    let mut recorded = false;
    if let Ok(entries) = std::fs::read_dir(&audit_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("forensic-") && name.ends_with(".jsonl") {
                let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
                if text.contains("deployment_shape.posture_exception") {
                    recorded = true;
                }
            }
        }
    }
    assert!(
        recorded,
        "the deliberate exception must be recorded in {}; stderr:\n{err}",
        audit_dir.display()
    );
}

/// State 1c — a fleet by AGENT REGISTRY alone (two registered agents in the
/// store, no argv/env/config signal) with the selector unset: the shape is
/// learned only after the store opens, where nothing can be pinned, so the
/// boot REFUSES, naming every protection that is off and BOTH one-line
/// choices.
///
/// FAILS ON HEAD: the daemon boots and `/health` answers 200 (the
/// `BootOutcome::Healthy` arm panics).
#[test]
fn fleet_by_agent_registry_after_open_refuses_by_omission_3700() {
    let root = tempfile::tempdir().unwrap();
    seed_store(root.path(), &["ai:shape-alpha", "ai:shape-bravo"]);
    let outcome = boot_on_loopback(root.path(), &[], Duration::ZERO);
    let err = match outcome {
        BootOutcome::Exited { status, stderr } => {
            assert!(!status.success(), "must refuse; stderr:\n{stderr}");
            stderr
        }
        BootOutcome::Healthy { stderr } => {
            panic!("a two-agent registry under standard-by-omission must refuse:\n{stderr}")
        }
    };
    assert!(err.contains("#3700"), "{err}");
    assert!(err.contains("agent_registry"), "{err}");
    assert!(err.contains("by OMISSION"), "{err}");
    assert!(err.contains("AI_MEMORY_REQUIRE_WITNESS unset"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=asi-hard"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=standard"), "{err}");
}

/// State 4 — `doctor` (DEFAULT report, no `--posture`) on the two-agent
/// store: CRIT under `standard` by omission, naming the refusal that the
/// next boot will produce; WARN (recorded exception) under an explicit
/// `standard`. Doctor itself never refuses.
///
/// FAILS ON HEAD: the "Deployment shape (#3700)" section is absent.
#[test]
fn doctor_reports_registry_fleet_under_standard_as_critical_3700() {
    let root = tempfile::tempdir().unwrap();
    seed_store(root.path(), &["ai:shape-alpha", "ai:shape-bravo"]);

    let report = doctor_json(root.path(), &[]);
    let shape = section(&report, SECTION_DEPLOYMENT_SHAPE);
    assert_eq!(shape["severity"], "critical", "{shape}");
    assert_eq!(fact(shape, "shape"), "fleet");
    assert_eq!(fact(shape, "posture"), "standard");
    assert_eq!(fact(shape, "posture_origin"), "compiled_default");
    assert_eq!(fact(shape, "shape_matches_posture"), "false");
    assert_eq!(fact(shape, "registered_agents"), "2");
    assert!(
        fact(shape, "signals_present").contains("agent_registry"),
        "{shape}"
    );
    assert!(fact(shape, "boot_verdict").contains("REFUSES"), "{shape}");
    assert!(
        shape["note"].as_str().unwrap_or("").contains("#3700"),
        "{shape}"
    );

    let report = doctor_json(root.path(), &[("AI_MEMORY_SECURITY_PROFILE", "standard")]);
    let shape = section(&report, SECTION_DEPLOYMENT_SHAPE);
    assert_eq!(shape["severity"], "warning", "{shape}");
    assert_eq!(fact(shape, "posture_origin"), "explicit");
    assert_eq!(fact(shape, "shape_matches_posture"), "false");
    assert!(fact(shape, "boot_verdict").contains("exception"), "{shape}");
}
