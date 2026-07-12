// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Drive the two non-Rust conformance readers against the CC0 corpus
//! (#1944 acceptance: ≥2 independent non-Rust reference consumers; #1837).
//!
//! Each test shells out to an interpreter IF it is installed and asserts the
//! reader exits 0 over `conformance/` (every vector passes, including the
//! MUST-REJECT tampered-signature vector where the runtime can check
//! signatures). When the interpreter is absent the test SKIPS with a loud
//! note rather than failing — CI images that carry python3/node exercise the
//! readers; minimal images don't break.
//!
//! The readers are stdlib-only by design (see `conformance/README.md`), so no
//! package installation is ever needed here.

use std::path::PathBuf;
use std::process::Command;

/// Corpus root, relative to the crate root.
const CORPUS_DIR: &str = "conformance";
/// Reader sub-path for the Python reference implementation.
const PYTHON_READER: &str = "readers/reader.py";
/// Reader sub-path for the Node reference implementation.
const NODE_READER: &str = "readers/reader.mjs";

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR)
}

/// Run `interpreter <reader> --corpus <root>`; `Ok(None)` means the
/// interpreter is not installed (skip), `Ok(Some(output))` is a completed
/// run.
fn run_reader(interpreter: &str, reader: &str) -> Option<std::process::Output> {
    let root = corpus_root();
    match Command::new(interpreter)
        .arg(root.join(reader))
        .arg("--corpus")
        .arg(&root)
        .output()
    {
        Ok(output) => Some(output),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("failed to spawn {interpreter}: {e}"),
    }
}

/// Assert a completed reader run passed every vector.
fn assert_reader_passed(interpreter: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{interpreter} conformance reader reported failures \
         (exit {:?}).\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code(),
    );
    assert!(
        !stdout.contains("FAIL "),
        "{interpreter} reader printed a FAIL line despite exit 0:\n{stdout}",
    );
}

#[test]
fn python_reader_passes_corpus() {
    let Some(output) = run_reader("python3", PYTHON_READER) else {
        eprintln!("SKIP: python3 not installed — python conformance reader not exercised");
        return;
    };
    assert_reader_passed("python3", &output);
    // The stdlib-only run cannot verify Ed25519 (no vendored crypto by
    // policy); it must still pass every structural obligation and report the
    // signature checks as explicit partial passes, never silent ones.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS (partial)"),
        "python stdlib run should report signature checks as partial passes:\n{stdout}",
    );
}

#[test]
fn node_reader_passes_corpus_including_signatures() {
    let Some(output) = run_reader("node", NODE_READER) else {
        eprintln!("SKIP: node not installed — node conformance reader not exercised");
        return;
    };
    assert_reader_passed("node", &output);
    // Node has WebCrypto Ed25519, so ALL verdicts — including the
    // MUST-REJECT tampered vector and the full equivocation proof — are
    // fully verified: no partial passes allowed.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("partial"),
        "node reader must fully verify every vector (no partials):\n{stdout}",
    );
    assert!(
        stdout.contains("PASS signed/write_v2_tampered"),
        "node reader must prove rejection of the tampered signature:\n{stdout}",
    );
}
