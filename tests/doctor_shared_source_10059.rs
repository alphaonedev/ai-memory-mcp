//! #10059 — the daemon peer list and outbound scope come from ONE shared source
//! (`AI_MEMORY_FED_QUORUM_PEERS` + `AI_MEMORY_FED_PEER_OUTBOUND_SCOPE`) under
//! the enterprise-federation posture, so a fresh `doctor --posture` process
//! judges check #23 against exactly what `serve` binds to (3-agent vote
//! (71472661) V2-10059, option A).
//!
//! Driven through the real binary. Every process gets a fresh sandbox under
//! `<repo>/.local-runs/` (never a tmpfs path) with its own HOME, key dir and
//! store path, and a cleared environment.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use ai_memory::enterprise_federation_posture::{
    ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE as POSTURE_ENV, POSTURE_ENTERPRISE_FEDERATION,
};
use ai_memory::federation::outbound_scope::OUTBOUND_SCOPE_ENV;
use ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV;
use ai_memory::federation::shared_source::{PEERS_ENV, SharedSourceError};

/// The one peer of the shared source.
const PEER: &str = "https://peer-1.example.org:9077";
/// A second peer the source does not name.
const OTHER_PEER: &str = "https://peer-2.example.org:9077";
/// A narrowed outbound scope for [`PEER`].
const NARROWED: &str = r#"{"https://peer-1.example.org:9077":{"allowed_namespaces":["public/*"]}}"#;
/// Label of check #23.
const OUTBOUND_SCOPE_CONTROL: &str = "federation outbound scope";
/// Prefix of the line a bound boot prints (`shared_source::boot_line`).
const BOOT_LINE_PREFIX: &str = "ai-memory: INFO federation shared source bound: ";
/// How long the outside-posture boot test waits for the store to open.
const BOOT_DEADLINE: Duration = Duration::from_secs(60);
/// Poll interval of that wait.
const BOOT_POLL: Duration = Duration::from_millis(100);

/// A fresh sandbox directory under `<repo>/.local-runs/`.
fn sandbox(name: &str) -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create .local-runs");
    tempfile::Builder::new()
        .prefix(&format!("shared-source-10059-{name}-"))
        .tempdir_in(root)
        .expect("sandbox")
}

/// The binary with a cleared environment rooted in `root`.
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(root)
        .env_clear()
        .env("TMPDIR", root)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env(PEER_ATTESTATION_ENV, "{}");
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    cmd
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `serve` under the posture with `--quorum-peers <flag>` and `envs`.
fn posture_serve(root: &Path, flag: &str, envs: &[(&str, &str)]) -> Output {
    let mut cmd = command(root);
    cmd.env(POSTURE_ENV, "1");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.args([
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--quorum-writes",
        "1",
        "--quorum-peers",
        flag,
    ])
    .output()
    .expect("spawn serve")
}

/// The `actual` and `pass` of check #23 from a fresh `doctor --posture`.
fn doctor_check23(root: &Path, envs: &[(&str, &str)]) -> (bool, String, Output) {
    let mut cmd = command(root);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd
        .args([
            "doctor",
            "--posture",
            POSTURE_ENTERPRISE_FEDERATION,
            "--json",
        ])
        .output()
        .expect("spawn doctor");
    let payload: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("doctor --json: {e}; stderr={}", stderr(&out)));
    let rows: Vec<&serde_json::Value> = payload["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .filter(|c| c["control"].as_str() == Some(OUTBOUND_SCOPE_CONTROL))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one check #23 row");
    let pass = rows[0]["pass"].as_bool().expect("pass is a bool");
    let actual = rows[0]["actual"].as_str().expect("actual").to_string();
    (pass, actual, out)
}

/// C-1 — a divergent outbound scope (a key naming no peer of the source)
/// refuses `serve` with the key and the fix.
#[test]
fn divergent_outbound_scope_refuses_serve_10059() {
    let sb = sandbox("divergent-scope");
    let scope = format!(r#"{{"{OTHER_PEER}":{{"allowed_namespaces":["public/*"]}}}}"#);
    let out = posture_serve(
        sb.path(),
        PEER,
        &[(PEERS_ENV, PEER), (OUTBOUND_SCOPE_ENV, &scope)],
    );
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains(&format!("{OUTBOUND_SCOPE_ENV}: key "))
            && err.contains(&format!(
                "names no peer of {PEERS_ENV}; list the peer there or remove the key, then restart"
            )),
        "{err}"
    );
    assert!(!err.contains(BOOT_LINE_PREFIX), "{err}");
    assert!(!sb.path().join("store.db").exists());
}

/// C-2/C-9 — under the posture a `--quorum-peers` that differs from the
/// source, or a source that is absent, refuses with the exact text.
#[test]
fn divergent_or_absent_source_refuses_serve_with_exact_text_10059() {
    let sb = sandbox("divergent-flag");
    let out = posture_serve(
        sb.path(),
        &format!("{PEER},{OTHER_PEER}"),
        &[(PEERS_ENV, PEER), (OUTBOUND_SCOPE_ENV, NARROWED)],
    );
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    let want = SharedSourceError::Divergent { flag: 2, source: 1 }.to_string();
    assert!(err.contains(&want), "want {want:?} in {err}");
    assert!(!sb.path().join("store.db").exists());

    let sb = sandbox("absent-source");
    let out = posture_serve(sb.path(), PEER, &[(OUTBOUND_SCOPE_ENV, NARROWED)]);
    let err = stderr(&out);
    assert!(!out.status.success(), "{err}");
    let want = SharedSourceError::Absent.to_string();
    assert!(err.contains(&want), "want {want:?} in {err}");
    assert!(!sb.path().join("store.db").exists());
}

/// C-6/C-9 — a matching flag binds (the boot gate after it is the existing
/// enterprise-federation gate), and the digest the boot prints is the digest
/// a fresh doctor prints for the same source. No credential in either.
#[test]
fn matching_flag_binds_and_boot_digest_equals_doctor_digest_10059() {
    let credentialed = "https://user:s3cret@peer-1.example.org:9077";
    let scope = format!(r#"{{"{credentialed}":{{"allowed_namespaces":["public/*"]}}}}"#);
    let envs = [
        (PEERS_ENV, credentialed),
        (OUTBOUND_SCOPE_ENV, scope.as_str()),
    ];
    let sb = sandbox("matching-flag");
    let out = posture_serve(sb.path(), credentialed, &envs);
    let err = stderr(&out);
    let line = err
        .lines()
        .find(|l| l.starts_with(BOOT_LINE_PREFIX))
        .unwrap_or_else(|| panic!("no boot binding line in {err}"));
    assert!(!err.contains("s3cret"), "{err}");
    let boot_digest = line
        .split("digest ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("digest in boot line");
    assert!(boot_digest.starts_with("sha256:"), "{line}");

    let mut doctor_envs = envs.to_vec();
    doctor_envs.push((POSTURE_ENV, "1"));
    let (pass, actual, _) = doctor_check23(sb.path(), &doctor_envs);
    assert!(pass, "{actual}");
    assert!(
        actual.contains(&format!("; digest {boot_digest}; ")),
        "boot digest {boot_digest} must equal the doctor digest: {actual}"
    );
    assert!(
        actual.contains("an edit applies only after a daemon restart"),
        "{actual}"
    );
    assert!(!actual.contains("s3cret"), "{actual}");
}

/// C-3/C-8 — a doctor without the posture signal FAILs check #23 even with a
/// valid source, and a doctor under the posture with no source FAILs it.
#[test]
fn doctor_fails_check23_without_posture_or_source_10059() {
    let sb = sandbox("doctor-fail");
    let (pass, actual, _) = doctor_check23(
        sb.path(),
        &[(PEERS_ENV, PEER), (OUTBOUND_SCOPE_ENV, NARROWED)],
    );
    assert!(!pass, "{actual}");
    assert!(
        actual.ends_with(&SharedSourceError::PostureAbsent.to_string()),
        "{actual}"
    );
    let (pass, actual, _) = doctor_check23(
        sb.path(),
        &[(POSTURE_ENV, "1"), (OUTBOUND_SCOPE_ENV, NARROWED)],
    );
    assert!(!pass, "{actual}");
    assert!(
        actual.ends_with(&SharedSourceError::Absent.to_string()),
        "{actual}"
    );
}

/// C-8 — outside the posture `serve --quorum-peers` with no source is not
/// refused by the binding: it gets past it and opens the store.
#[test]
fn outside_posture_serve_boots_without_a_source_10059() {
    let sb = sandbox("outside-posture");
    let mut child = command(sb.path())
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--quorum-writes",
            "1",
            "--quorum-peers",
            PEER,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let store = sb.path().join("store.db");
    let started = Instant::now();
    let mut exited = None;
    while started.elapsed() < BOOT_DEADLINE && !store.exists() {
        if let Some(status) = child.try_wait().expect("try_wait") {
            exited = Some(status);
            break;
        }
        std::thread::sleep(BOOT_POLL);
    }
    if exited.is_none() {
        let _ = child.kill();
    }
    let out = child.wait_with_output().expect("wait serve");
    let err = stderr(&out);
    assert!(exited.is_none(), "serve exited early ({exited:?}): {err}");
    assert!(store.exists(), "serve never opened the store: {err}");
    assert!(!err.contains(PEERS_ENV), "{err}");
    assert!(!err.contains(BOOT_LINE_PREFIX), "{err}");
}
