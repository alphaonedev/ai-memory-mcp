// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Drive the non-Rust conformance readers against the CC0 corpus and PROVE
//! the ROADMAP §11.6 / `docs/spec/PORTABILITY-V2.md` obligation:
//! **≥2 independent non-Rust reference readers that re-derive the signed
//! bytes and check the signed-record family** (#1944, #1837).
//!
//! # Why this file is written fail-CLOSED (#2452)
//!
//! Until #2452 these tests SKIPped-and-PASSed: `run_reader` returned `None`
//! when the interpreter was missing, the test printed a note and returned,
//! and libtest scored it `ok`. Three separate things were wrong with that:
//!
//! 1. **A missing prerequisite scored as a PASS.** A green run did not mean
//!    the portability guarantee held; it could mean nothing was checked.
//! 2. **The note was invisible.** libtest captures `eprintln!` for passing
//!    tests, so the "loud" SKIP line never reached the operator's terminal
//!    or the CI log. The pass was not merely wrong, it was silent.
//!    (Measured: the pre-fix binary run with an interpreter-free PATH
//!    prints `test result: ok. 2 passed` and NOT ONE SKIP line.)
//! 3. **The "≥2" was never asserted.** Two independent tests that each
//!    vanish independently cannot express "at least two". With `python3`
//!    present and `node` absent the mandated 2 silently became 1, green.
//!
//! The contract now:
//!
//! * **Default (CI, release, and any unconfigured host): fail CLOSED.** An
//!   absent interpreter, an unusable interpreter, or fewer than
//!   [`REQUIRED_NON_RUST_READERS`] readers that actually completed a
//!   verification is a hard FAILURE carrying [`UNPROVABLE_TOKEN`].
//! * **Local developers without the non-Rust toolchains** may set
//!   `AI_MEMORY_CONFORMANCE_ALLOW_SKIP=1`. That is legitimate — but the run
//!   is then reported as **UNPROVEN**, on the real process stderr (bypassing
//!   libtest capture), never as "passed". `scripts/check-conformance-readers.sh`
//!   HARD-BLOCKS that variable from appearing anywhere under `.github/`, so
//!   the escape hatch can never become CI's behaviour.
//!
//! # Honest scope of what "verify" means per reader
//!
//! Both readers discharge the SPEC SECTION-7 STRUCTURAL obligation in full:
//! restricted-CBOR decode, **re-encode-and-compare** against the original
//! bytes, domain-tag / element-count pins, and the whole-corpus digest
//! anchor. Only `node` additionally checks the Ed25519 SIGNATURES (WebCrypto);
//! the Python reader is stdlib-only by policy (no vendored crypto) and
//! reports its signature verdicts as explicit `PASS (partial)`. So the count
//! of readers that verify SIGNATURES is 1, not 2 — a spec-vs-implementation
//! gap that `scripts/check-conformance-readers.sh` now measures and pins
//! rather than papers over. Do not read a green run here as "two readers
//! checked the signatures".
//!
//! The authoritative CI proof is `scripts/check-conformance-readers.sh`,
//! wired into `.github/workflows/c8-precheck.yml` — it needs no cargo build,
//! self-tests itself by planting failures, and carries the R-203
//! reproduction of the pre-#2452 silent pass.
//!
//! This file deliberately has **zero crate dependencies** (`std` only) so
//! that gate can compile it standalone with `rustc --test` and demonstrate
//! its before/after behaviour without a cargo build. Do not `use ai_memory::`
//! here.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output};

/// Corpus root, relative to the crate root.
const CORPUS_DIR: &str = "conformance";

/// ROADMAP §11.6, **not relaxed**: the number of independent non-Rust
/// readers that must actually verify the corpus for the portability claim
/// to hold. Lowering this is a spec change, not a test change.
const REQUIRED_NON_RUST_READERS: usize = 2;

/// Explicit local-developer opt-out. Set to `1`/`true` to downgrade a
/// missing interpreter from a hard failure to an explicitly UNPROVEN run.
/// Forbidden under `.github/` by `scripts/check-conformance-readers.sh`.
const ALLOW_SKIP_ENV: &str = "AI_MEMORY_CONFORMANCE_ALLOW_SKIP";

/// Stable token on every fail-closed abort. Asserted by the gate's
/// self-test, so a harness error (a compile failure, a wrong path, exit
/// 127) can never masquerade as "the guard correctly refused".
const UNPROVABLE_TOKEN: &str = "conformance proof UNPROVABLE (#2452)";

/// Stable token on the opted-out path. Written to the real process stderr,
/// not through `eprintln!`, because libtest swallows captured output for
/// passing tests — which is how the pre-#2452 SKIP note stayed invisible.
const UNPROVEN_TOKEN: &str = "CONFORMANCE UNPROVEN (#2452)";

/// Corpus items every reader must report a PASS verdict for, by NAME, for
/// its run to count as a verification. An exit-0 reader that printed none
/// of these verified nothing; naming them is what stops a no-op stub from
/// scoring as a pass.
///
/// Matched as "a line starting `PASS ` that contains this name", NOT as a
/// literal `PASS <name>` prefix: the Python arm honestly labels its
/// signature verdicts `PASS (partial) <name>`, and a prefix pin would have
/// silently required the stdlib reader to LIE about its limitation in order
/// to satisfy the check.
const REQUIRED_VECTOR_NAMES: &[&str] = &[
    "corpus_digest",
    "signed/write_v2_signed",
    "signed/write_v2_tampered",
    "signed/equivocation_proof_real",
];

/// A non-Rust reference reader: which interpreter can run it, and how to
/// recognise a usable one.
struct Reader {
    /// Human label used in failure messages.
    label: &'static str,
    /// Interpreter executables to try, in order. Windows images ship
    /// `python.exe` rather than `python3.exe`, so the probe is a list and
    /// the version string is what decides, never the file name.
    candidates: &'static [&'static str],
    /// Substring the interpreter's `--version` output must contain for it
    /// to count. Guards against `python` being a Python 2, and against the
    /// Windows Store `python3.exe` app-execution-alias stub.
    version_marker: &'static str,
    /// Reader script, relative to the corpus root.
    script: &'static str,
}

/// The declared reader inventory. `scripts/check-conformance-readers.sh`
/// cross-checks that this table still has ≥ [`REQUIRED_NON_RUST_READERS`]
/// entries on distinct runtimes.
const READERS: &[Reader] = &[
    Reader {
        label: "python",
        candidates: &["python3", "python"],
        version_marker: "Python 3",
        script: "readers/reader.py",
    },
    Reader {
        label: "node",
        candidates: &["node", "nodejs"],
        version_marker: "v",
        script: "readers/reader.mjs",
    },
];

// BEGIN conformance fail-closed gate (#2452) -- fail CLOSED
//
// Everything between these sentinels is the fail-closed core. A missing or
// unusable prerequisite funnels through `fail_closed` and PANICS; the only
// other exit is the explicitly opted-out UNPROVEN path, which never claims
// to have proven anything. `scripts/check-conformance-readers.sh` audits
// this region statically: deleting a sentinel, deleting an abort site, or
// re-introducing a silent-skip phrase is itself a violation.

/// Canonical fail-closed abort. Every prerequisite that could otherwise
/// decay into a silent pass funnels through here.
fn fail_closed(what: &str, detail: &str) -> ! {
    panic!(
        "{UNPROVABLE_TOKEN}: {what}. {detail}\n\
         The >={REQUIRED_NON_RUST_READERS}-non-Rust-reader portability proof \
         (ROADMAP 11.6 / docs/spec/PORTABILITY-V2.md) CANNOT be discharged on \
         this host, so it is reported as a FAILURE, never as a pass.\n\
         Install the missing runtime, or -- for local work only -- set \
         {ALLOW_SKIP_ENV}=1 to run with the proof explicitly UNPROVEN. \
         That variable is HARD-BLOCKED from CI."
    );
}

/// True when the developer has explicitly accepted an unproven run.
fn skip_explicitly_allowed() -> bool {
    matches!(
        std::env::var(ALLOW_SKIP_ENV)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Report an unproven run on the REAL process stderr. `eprintln!` is
/// captured by libtest for passing tests, so it is not used here: an
/// invisible warning is indistinguishable from no warning at all.
fn report_unproven(what: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "\n================ {UNPROVEN_TOKEN} ================\n\
         {what}\n\
         This run did NOT verify the >={REQUIRED_NON_RUST_READERS}-non-Rust-reader \
         portability guarantee. It is UNPROVEN, not passed.\n\
         ================================================\n"
    );
}

/// Resolve a usable interpreter for `reader`, or abort fail-closed.
/// Returns `None` only when the developer opted out explicitly.
fn resolve_interpreter(reader: &Reader) -> Option<&'static str> {
    let mut tried = Vec::new();
    for candidate in reader.candidates {
        let Ok(out) = Command::new(candidate).arg("--version").output() else {
            tried.push(format!("{candidate}: not found on PATH"));
            continue;
        };
        if !out.status.success() {
            tried.push(format!(
                "{candidate}: --version exited {:?}",
                out.status.code()
            ));
            continue;
        }
        // Some runtimes print the version on stdout, some on stderr.
        let mut version = String::from_utf8_lossy(&out.stdout).into_owned();
        version.push_str(&String::from_utf8_lossy(&out.stderr));
        if version.contains(reader.version_marker) {
            return Some(candidate);
        }
        tried.push(format!(
            "{candidate}: version {:?} lacks the required marker {:?}",
            version.trim(),
            reader.version_marker
        ));
    }

    if skip_explicitly_allowed() {
        report_unproven(&format!(
            "no usable {} interpreter ({})",
            reader.label,
            tried.join("; ")
        ));
        return None;
    }
    fail_closed(
        &format!(
            "no usable {} interpreter for {}",
            reader.label, reader.script
        ),
        &format!("candidates tried: {}", tried.join("; ")),
    );
}

// END conformance fail-closed gate (#2452)

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR)
}

/// Run `<interpreter> <reader> --corpus <root>` to completion. A spawn
/// failure here is a hard error: the interpreter was already proven usable
/// by `resolve_interpreter`, so failing to launch it is a real defect.
fn run_reader(interpreter: &str, reader: &Reader) -> Output {
    let root = corpus_root();
    match Command::new(interpreter)
        .arg(root.join(reader.script))
        .arg("--corpus")
        .arg(&root)
        .output()
    {
        Ok(output) => output,
        Err(e) => fail_closed(
            &format!("failed to spawn {interpreter} for {}", reader.script),
            &format!("{e}"),
        ),
    }
}

/// Assert a completed reader run verified every vector.
fn assert_reader_passed(label: &str, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{label} conformance reader reported failures \
         (exit {:?}).\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status.code(),
    );
    assert!(
        !stdout.contains("FAIL "),
        "{label} reader printed a FAIL line despite exit 0:\n{stdout}",
    );
    // An exit-0 reader that printed nothing verified nothing. The corpus
    // anchor and both signature vectors are the load-bearing lines; their
    // absence is how a no-op reader would otherwise score as a pass.
    for name in REQUIRED_VECTOR_NAMES {
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("PASS ") && line.contains(name)),
            "{label} reader never reported a PASS verdict for {name:?} -- an \
             exit-0 run that did not verify the signed family is a silent \
             no-op:\n{stdout}",
        );
    }
}

#[test]
fn python_reader_verifies_corpus() {
    let reader = &READERS[0];
    let Some(interpreter) = resolve_interpreter(reader) else {
        return; // explicitly opted out; already reported UNPROVEN
    };
    let output = run_reader(interpreter, reader);
    assert_reader_passed(reader.label, &output);
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
fn node_reader_verifies_corpus_including_signatures() {
    let reader = &READERS[1];
    let Some(interpreter) = resolve_interpreter(reader) else {
        return; // explicitly opted out; already reported UNPROVEN
    };
    let output = run_reader(interpreter, reader);
    assert_reader_passed(reader.label, &output);
    // Node has WebCrypto Ed25519, so ALL verdicts -- including the
    // MUST-REJECT tampered vector and the full equivocation proof -- are
    // fully verified: no partial passes allowed.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("partial"),
        "node reader must fully verify every vector (no partials):\n{stdout}",
    );
}

/// The obligation itself, as a COUNT.
///
/// The two tests above can each degrade independently; this one cannot be
/// satisfied by one reader. It is what makes "≥2 independent non-Rust
/// readers" falsifiable rather than aspirational.
#[test]
fn at_least_two_non_rust_readers_verify_the_corpus() {
    let mut verified = Vec::new();
    for reader in READERS {
        let Some(interpreter) = resolve_interpreter(reader) else {
            continue; // explicitly opted out; already reported UNPROVEN
        };
        let output = run_reader(interpreter, reader);
        assert_reader_passed(reader.label, &output);
        verified.push(reader.label);
    }

    if verified.len() < REQUIRED_NON_RUST_READERS {
        if skip_explicitly_allowed() {
            report_unproven(&format!(
                "only {} of the required {REQUIRED_NON_RUST_READERS} non-Rust readers ran ({:?})",
                verified.len(),
                verified
            ));
            return;
        }
        fail_closed(
            &format!(
                "only {} of the required {REQUIRED_NON_RUST_READERS} non-Rust readers verified the corpus",
                verified.len()
            ),
            &format!("readers that ran: {verified:?}"),
        );
    }
}
