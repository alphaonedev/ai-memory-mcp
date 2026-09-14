// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3700 — the deployment-shape DETECTOR on top of the #3714 declared shape.
//!
//! The declared `[deployment] shape` (absent = `singleton`) is the ONLY input
//! that pins a posture (#3714). The detector holds the configured signals
//! (peers, bindings, allowlist, forward URL, wake hub, monitoring scopes,
//! agent registry) against that declaration:
//!
//! - a hardened DECLARED shape with a pinned knob below its floor REFUSES,
//!   naming EVERY disabled knob (the #3714/`security_profile` refusal named
//!   only the first);
//! - signals that look like a stricter shape than declared are a boot WARN
//!   and a forensic record — NEVER a re-posture: promotion is an operator
//!   act, so the WARN states the exact config line;
//! - a singleton without signals stays silent and boots unchanged;
//! - `doctor`'s DEFAULT report carries the detector right after
//!   Configuration.
//!
//! Real binary boots (env supplied ONLY to the child, `env_clear`), the
//! harness shape of `tests/federation_peer_posture_3582.rs`. Each test's doc
//! comment names the assertion that FAILS on the base `dfc39feff`
//! (#3714 without the detector).

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{free_port, permissive_attestation_for_tests};

/// A valid, EMPTY peer allowlist: federation is CONFIGURED (a `federated`
/// observed floor) while denying every peer, so the #3582 gate is satisfied
/// in both postures and only the detector decides what is said.
const EMPTY_ALLOWLIST: &str = "{}";

/// The detector section (SECOND in the default report, right after
/// Configuration; the #3714 declared-shape section is absent under
/// `AI_MEMORY_NO_CONFIG`).
const SECTION_DETECTOR: &str = "Deployment shape detector (#3700)";

/// The bind guard a keyless `--host 0.0.0.0` boot stops at. It sits AFTER
/// the peer gate and the detector in `bootstrap_serve`, so reaching it
/// proves the detector let the boot through.
const BIND_GUARD_MARKER: &str = "without an API key";

const FEDERATED_LINE: &str = "[deployment] shape = \"federated\"";
const TEAM_LINE: &str = "[deployment] shape = \"team\"";

const BOOT_DEADLINE: Duration = Duration::from_secs(45);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// The checked-in TLS fixture pair, passed to every `serve` child so the
/// tests stay valid once transit encryption becomes a floor (#3705).
fn tls_args() -> [String; 4] {
    [
        "--tls-cert".to_string(),
        fixture("valid_cert.pem").to_string_lossy().into_owned(),
        "--tls-key".to_string(),
        fixture("valid_key_pkcs8.pem")
            .to_string_lossy()
            .into_owned(),
    ]
}

/// A child with `config.toml` loading ENABLED (no `AI_MEMORY_NO_CONFIG`);
/// `config_body` is written to `<XDG_CONFIG_HOME>/ai-memory/config.toml`
/// when given, else no file exists and the declared shape is `singleton`.
fn command_with_config(root: &Path, config_body: Option<&str>) -> Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key sandbox");
    }
    let xdg = root.join("home/.config");
    if let Some(body) = config_body {
        let dir = xdg.join("ai-memory");
        std::fs::create_dir_all(&dir).expect("mkdir config dir");
        std::fs::write(dir.join("config.toml"), body).expect("write config.toml");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", xdg)
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("RUST_LOG", "error");
    cmd
}

/// A child with no config file at all (`AI_MEMORY_NO_CONFIG=1`): the
/// declared shape is `singleton`.
fn command(root: &Path) -> Command {
    let mut cmd = command_with_config(root, None);
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Create the store through the production open (migrations land) and
/// register `agent_ids` in it.
fn seed_store(root: &Path, agent_ids: &[&str]) {
    permissive_attestation_for_tests();
    let conn = ai_memory::db::open(&root.join("store.db")).expect("open store");
    for id in agent_ids {
        ai_memory::db::register_agent(&conn, id, "worker", &[]).expect("register agent");
    }
}

/// `/api/v1/health` over the TLS listener (fixture cert: verification off).
fn health_is_200(port: u16) -> bool {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(PROBE_TIMEOUT)
        .build()
        .expect("client");
    client
        .get(format!("https://127.0.0.1:{port}/api/v1/health"))
        .send()
        .is_ok_and(|r| r.status().is_success())
}

enum BootOutcome {
    Exited {
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// `/health` answered 200; the child was then killed.
    Healthy { stderr: String },
}

/// Spawn `serve --port <free>` (loopback, TLS fixture) from `cmd` and drive
/// it to an exit or a healthy `/health`, capturing stderr either way.
fn boot_on_loopback(mut cmd: Command) -> BootOutcome {
    let port = free_port();
    let mut child: Child = cmd
        .args(["serve", "--port", &port.to_string()])
        .args(tls_args())
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
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            return BootOutcome::Exited { status, stderr };
        }
        if health_is_200(port) {
            // Let the boot-time record settle before the kill.
            std::thread::sleep(Duration::from_secs(1));
            let _ = child.kill();
            let _ = child.wait();
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            return BootOutcome::Healthy { stderr };
        }
        assert!(
            Instant::now() < deadline,
            "serve neither exited nor became healthy within {BOOT_DEADLINE:?}; stderr:\n{}",
            buf.lock().unwrap()
        );
        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// A keyless `--host 0.0.0.0` boot: refused at the bind guard when every
/// earlier gate let it through. Returns stderr.
fn boot_to_bind_guard(mut cmd: Command) -> Output {
    cmd.args(["serve", "--host", "0.0.0.0"])
        .args(tls_args())
        .output()
        .expect("run serve")
}

fn doctor_json(mut cmd: Command) -> serde_json::Value {
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

/// (1) A hardened DECLARED shape (`federated`, pinned `asi-hard` by #3714)
/// with TWO protections explicitly set below the floor: refused, and the
/// refusal names BOTH knobs, the config line and the operator-act rule.
///
/// FAILS ON BASE dfc39feff: the #3714 pin plus `security_profile` refuse at
/// the FIRST offending knob only and never mention `#3700` — the
/// `err.contains("#3700")` assertion fails, and only one of the two knob
/// names appears.
#[test]
fn hardened_declared_shape_with_loosened_knobs_refuses_naming_every_knob_3700() {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = command_with_config(root.path(), Some("[deployment]\nshape = \"federated\"\n"));
    cmd.env("AI_MEMORY_REQUIRE_WITNESS", "0")
        .env("AI_MEMORY_CID_ENFORCE", "0");
    let out = boot_to_bind_guard(cmd);
    let err = stderr(&out);
    assert!(!out.status.success(), "must refuse; stderr:\n{err}");
    assert!(err.contains("#3700"), "{err}");
    assert!(err.contains(FEDERATED_LINE), "{err}");
    assert!(err.contains("AI_MEMORY_REQUIRE_WITNESS=\"0\""), "{err}");
    assert!(err.contains("AI_MEMORY_CID_ENFORCE=\"0\""), "{err}");
    assert!(
        err.contains("2 protection(s) are set BELOW the floor"),
        "{err}"
    );
    assert!(err.contains("operator acts"), "{err}");
    assert!(
        !err.contains(BIND_GUARD_MARKER),
        "the refusal must fire before the bind guard: {err}"
    );
    assert!(
        !root.path().join("store.db").exists(),
        "refused pre-open: no store may be created"
    );
}

/// (2) Federation signals (a configured peer allowlist) with NO declared
/// shape: the boot proceeds (to the bind guard) under `standard`, and the
/// detector WARNs — naming the config line that would declare what the
/// signals show, that every protection is OFF, and that nothing was
/// re-postured.
///
/// FAILS ON BASE dfc39feff: no `#3700` line at all
/// (`err.contains("WARN #3700")` fails).
#[test]
fn undeclared_federation_signals_warn_and_never_repose_3700() {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = command(root.path());
    cmd.env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST);
    let out = boot_to_bind_guard(cmd);
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains(BIND_GUARD_MARKER), "{err}");
    assert!(err.contains("WARN #3700"), "{err}");
    assert!(err.contains(FEDERATED_LINE), "{err}");
    assert!(err.contains("peer_allowlist"), "{err}");
    assert!(err.contains("OFF"), "{err}");
    assert!(err.contains("nothing was re-postured"), "{err}");
    assert!(
        !err.contains("asi-hard"),
        "an undeclared promotion must never pin a posture: {err}"
    );
}

/// (3) A singleton without signals boots quietly, and `doctor`'s DEFAULT
/// report carries the detector right after Configuration, with nothing to
/// say.
///
/// FAILS ON BASE dfc39feff: the boot half passes; the detector section is
/// absent (`section()` panics).
#[test]
fn singleton_without_signals_boots_quiet_and_doctor_reports_detector_3700() {
    let root = tempfile::tempdir().unwrap();
    let out = boot_to_bind_guard(command(root.path()));
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains(BIND_GUARD_MARKER), "{err}");
    assert!(
        !err.contains("#3700"),
        "a singleton must stay silent: {err}"
    );

    seed_store(root.path(), &[]);
    let report = doctor_json(command(root.path()));
    assert_eq!(
        report["sections"][1]["name"], SECTION_DETECTOR,
        "the detector sits right after Configuration; got {}",
        report["sections"]
    );
    let det = section(&report, SECTION_DETECTOR);
    assert_eq!(fact(det, "declared_shape"), "singleton");
    assert_eq!(fact(det, "observed_floor"), "singleton");
    assert_eq!(fact(det, "undeclared_promotion"), "false");
    assert_eq!(fact(det, "posture"), "standard");
    assert_eq!(det["severity"], "info", "{det}");
}

/// (4) A store with TWO registered agents under a declared `singleton`: the
/// registry raises the observed floor to `team` after the store opens. The
/// daemon still BOOTS unchanged (`standard`), WARNs once naming the `team`
/// config line and the registry signal, and `doctor` reports the mismatch
/// as CRIT.
///
/// FAILS ON BASE dfc39feff: the daemon boots without any `WARN #3700`
/// (`assert_eq!(warns, 1)` fails).
#[test]
fn registry_raised_floor_warns_but_boots_unchanged_3700() {
    let root = tempfile::tempdir().unwrap();
    seed_store(root.path(), &["ai:shape-alpha", "ai:shape-bravo"]);
    let err = match boot_on_loopback(command(root.path())) {
        BootOutcome::Healthy { stderr } => stderr,
        BootOutcome::Exited { status, stderr } => {
            panic!("a registry-raised floor must not refuse; exited {status}; stderr:\n{stderr}")
        }
    };
    let warns = err.matches("WARN #3700").count();
    assert_eq!(warns, 1, "exactly one warning, got {warns}:\n{err}");
    assert!(err.contains(TEAM_LINE), "{err}");
    assert!(err.contains("agent_registry"), "{err}");
    assert!(err.contains("OFF"), "posture stayed standard: {err}");
    assert!(err.contains("nothing was re-postured"), "{err}");
    assert!(!err.contains("asi-hard"), "{err}");

    let report = doctor_json(command(root.path()));
    let det = section(&report, SECTION_DETECTOR);
    assert_eq!(fact(det, "declared_shape"), "singleton");
    assert_eq!(fact(det, "observed_floor"), "team");
    assert_eq!(fact(det, "registered_agents"), "2");
    assert_eq!(fact(det, "undeclared_promotion"), "true");
    assert_eq!(fact(det, "posture"), "standard");
    assert_eq!(det["severity"], "critical", "{det}");
    assert_eq!(fact(det, "promotion_line"), TEAM_LINE);
}

/// (5) Regression pin — a DECLARED `federated` node whose signals match
/// (allowlist configured, every knob unset): the #3714 floor pins
/// `asi-hard`, the detector has nothing to say, and the boot reaches the
/// bind guard. This pins the "matching declaration is quiet" contract; it
/// MAY PASS on the base dfc39feff (there is no detector to be noisy there).
#[test]
fn declared_federated_with_matching_signals_is_quiet_3700() {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = command_with_config(root.path(), Some("[deployment]\nshape = \"federated\"\n"));
    cmd.env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST);
    let out = boot_to_bind_guard(cmd);
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(
        !err.contains("WARN #3700"),
        "a matching declaration must not be warned about: {err}"
    );
    assert!(
        !err.contains("protection(s) are set BELOW the floor"),
        "nothing is loosened, so no refusal: {err}"
    );
    // The #3714 shape floor is in force (its declared at-rest gap WARN
    // names the federated line) and the boot proceeds to the bind guard.
    assert!(err.contains(FEDERATED_LINE), "{err}");
    assert!(err.contains(BIND_GUARD_MARKER), "{err}");
}

/// (6) `doctor` on a fleet that is UNPROTECTED: two registered agents AND a
/// configured allowlist, no declared shape — the observed floor is
/// `federated`, the posture is `standard`, so the detector is CRIT and
/// states the exact promotion line.
///
/// FAILS ON BASE dfc39feff: the detector section is absent (`section()`
/// panics).
#[test]
fn doctor_reports_unprotected_fleet_as_critical_3700() {
    let root = tempfile::tempdir().unwrap();
    seed_store(root.path(), &["ai:shape-alpha", "ai:shape-bravo"]);
    let mut cmd = command(root.path());
    cmd.env("AI_MEMORY_FED_PEER_ATTESTATION", EMPTY_ALLOWLIST);
    let report = doctor_json(cmd);
    let det = section(&report, SECTION_DETECTOR);
    assert_eq!(det["severity"], "critical", "{det}");
    assert_eq!(fact(det, "declared_shape"), "singleton");
    assert_eq!(fact(det, "observed_floor"), "federated");
    assert_eq!(fact(det, "undeclared_promotion"), "true");
    assert_eq!(fact(det, "posture"), "standard");
    assert_eq!(fact(det, "registered_agents"), "2");
    assert!(fact(det, "boot_verdict").contains("UNPROTECTED"), "{det}");
    assert_eq!(fact(det, "promotion_line"), FEDERATED_LINE);
    assert!(
        det["note"].as_str().unwrap_or("").contains("#3700"),
        "{det}"
    );
}
