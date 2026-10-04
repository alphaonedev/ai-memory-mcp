// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5036 / #5039(A): `scripts/recapture-cert-3607-posture.sh` used to RECORD the
//! four-leg posture ladder (legs 2/2/1/0; bare 12/10 > hardened 20/2 >
//! sqlcipher 22/0) without ever ASSERTING it, so the cert leg exited 0 on any
//! ladder shape (a check that cannot fail measures nothing). These tests drive
//! the real recapture script, in a scratch repo root, against stub binaries:
//!
//! * a healthy ladder must still exit 0 (no false red);
//! * a posture-bypassed ladder (every leg exits 0 with 22 PASS), a drifted
//!   count, and a missing leg-4 binary must each exit non-zero (fail closed);
//! * the transcript header must carry the run date, not a frozen literal;
//! * the committed cert evidence must satisfy the gate and the gate's own
//!   planted-mutant self-test must reject every mutant.
//!
//! Precedent copied (no new posture decision): the fail-closed, self-testing
//! cert-leg gate shape of `scripts/check-cert-leg-nonvacuity.sh` (#3552).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GATE: &str = "check-posture-ladder.py";
const RECAPTURE: &str = "recapture-cert-3607-posture.sh";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Fresh scratch repo root under the gitignored `.local-runs/` (no-/tmp rule).
fn scratch(tag: &str) -> PathBuf {
    let dir = repo()
        .join(".local-runs")
        .join("cert-3607-ladder-5036")
        .join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
    fs::create_dir_all(dir.join("scripts")).expect("scratch scripts dir");
    fs::create_dir_all(dir.join("docs/compliance/evidence/cert-3607")).expect("scratch evidence");
    for name in [RECAPTURE, GATE] {
        let src = repo().join("scripts").join(name);
        if src.is_file() {
            fs::copy(&src, dir.join("scripts").join(name)).expect("copy script");
        }
    }
    dir
}

/// A python stub standing in for the ai-memory binary. `mode`:
/// `healthy` reproduces the certified ladder; `bypass` is a posture
/// regression where every diagnostic passes and the boot gate never refuses;
/// `drift` keeps the exit codes but changes the leg-2 check counts.
fn stub(path: &Path, mode: &str, marker: &str) {
    let body = format!(
        r#"#!/usr/bin/env python3
# {marker}
import os, sys
mode = "{mode}"
args = sys.argv[1:]
def lines(p, f):
    return "".join("[PASS] c%d\n" % i for i in range(p)) + "".join("[FAIL] c%d\n" % i for i in range(f))
if args[:2] == ["rules", "keygen"] or args[:1] == ["stats"]:
    sys.exit(0)
if args == ["doctor"]:
    if mode == "bypass":
        print(lines(22, 0)); sys.exit(0)
    print("ai-memory refuses to boot: 1 required control(s) missing or below floor:\n  - AI_MEMORY_ENCRYPT_AT_REST: needs sqlcipher")
    sys.exit(1)
sqlcipher = "AI_MEMORY_DB_PASSPHRASE" in os.environ
hardened = "AI_MEMORY_SECURITY_PROFILE" in os.environ
if mode == "bypass":
    print(lines(22, 0)); sys.exit(0)
if sqlcipher:
    print(lines(22, 0)); sys.exit(0)
if hardened:
    print(lines(19, 3) if mode == "drift" else lines(20, 2)); sys.exit(2)
print(lines(12, 10)); sys.exit(2)
"#
    );
    fs::write(path, body).expect("write stub");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
}

fn run_recapture(root: &Path, default_mode: &str, with_sqlcipher: bool) -> Output {
    let default_bin = root.join("bin-default");
    let sqlcipher_bin = root.join("bin-sqlcipher");
    stub(&default_bin, default_mode, "default build");
    if with_sqlcipher {
        stub(&sqlcipher_bin, default_mode, "sqlcipher build");
    }
    Command::new("bash")
        .arg(root.join("scripts").join(RECAPTURE))
        .current_dir(root)
        .env("DEFAULT_BIN", &default_bin)
        .env("SQLCIPHER_BIN", &sqlcipher_bin)
        .env("TMPDIR", root.join("tmp"))
        .output()
        .expect("spawn recapture script")
}

fn describe(o: &Output) -> String {
    format!(
        "status={:?}\nstdout:\n{}\nstderr:\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn healthy_ladder_still_passes_5036() {
    let root = scratch("healthy");
    let out = run_recapture(&root, "healthy", true);
    assert!(
        out.status.success(),
        "healthy 2/2/1/0 ladder must pass:\n{}",
        describe(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("LADDER ASSERTED GREEN"),
        "{}",
        describe(&out)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bypassed_posture_ladder_fails_closed_5036() {
    let root = scratch("bypass");
    let out = run_recapture(&root, "bypass", true);
    assert!(
        !out.status.success(),
        "a posture-bypassed ladder (every leg exit 0) must NOT exit 0:\n{}",
        describe(&out)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn drifted_counts_fail_closed_5036() {
    let root = scratch("drift");
    let out = run_recapture(&root, "drift", true);
    assert!(
        !out.status.success(),
        "hardened 19/3 instead of 20/2 must NOT exit 0:\n{}",
        describe(&out)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn missing_leg4_binary_fails_closed_5036() {
    let root = scratch("noleg4");
    let out = run_recapture(&root, "healthy", false);
    assert!(
        !out.status.success(),
        "a skipped leg 4 (e4=missing) must NOT exit 0:\n{}",
        describe(&out)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn transcript_header_carries_run_date_5039a() {
    let before = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let root = scratch("date");
    let out = run_recapture(&root, "healthy", true);
    let after = chrono::Utc::now().format("%Y-%m-%d").to_string();
    assert!(out.status.success(), "{}", describe(&out));
    let transcript = fs::read_to_string(
        root.join("docs/compliance/evidence/cert-3607/posture-legs-exit-codes.txt"),
    )
    .expect("transcript written");
    let header = transcript.lines().next().unwrap_or_default();
    assert!(
        !header.contains("2026-09-11"),
        "frozen date literal remains: {header}"
    );
    assert!(
        header.contains(&format!("({before} #3607")) || header.contains(&format!("({after} #3607")),
        "header must carry the UTC run date: {header}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn committed_evidence_satisfies_gate_and_self_test_rejects_all_mutants_5036() {
    let gate = repo().join("scripts").join(GATE);
    let ev = repo().join("docs/compliance/evidence/cert-3607");
    let live = Command::new("python3")
        .arg(&gate)
        .arg(&ev)
        .output()
        .expect("spawn gate");
    assert!(
        live.status.success(),
        "committed cert-3607 evidence must be GREEN:\n{}",
        describe(&live)
    );
    // The self-test plants mutants beside the evidence dir; run it on a copy so
    // the tracked tree is never written to.
    let root = scratch("selftest");
    let copy = root.join("ev");
    fs::create_dir_all(&copy).expect("copy dir");
    for entry in fs::read_dir(&ev).expect("read evidence") {
        let entry = entry.expect("dirent");
        if entry.path().is_file() {
            fs::copy(entry.path(), copy.join(entry.file_name())).expect("copy evidence");
        }
    }
    let st = Command::new("python3")
        .arg(&gate)
        .arg(&copy)
        .arg("--self-test")
        .output()
        .expect("spawn self-test");
    assert!(
        st.status.success(),
        "self-test must reject every mutant:\n{}",
        describe(&st)
    );
    assert!(
        String::from_utf8_lossy(&st.stdout).contains("6/6 mutants rejected"),
        "{}",
        describe(&st)
    );
    let _ = fs::remove_dir_all(&root);
}
