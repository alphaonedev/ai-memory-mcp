// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8179 source guard: no certificate-verification bypass may be (re)introduced.
//!
//! `CodeQL` flags `danger_accept_invalid_certs`, but `CodeQL` is not a required
//! check, so a re-added bypass would otherwise survive every test. This guard
//! walks `tests/` and `src/` and fails with every `file:line` that calls
//! `danger_accept_invalid_certs` or `danger_accept_invalid_hostnames` outside
//! a `//` or `//!` comment.
//!
//! Exactly ONE site is permitted: `src/cli/sync.rs`, the operator opt-in
//! `--insecure-skip-server-verify`. It is pinned by file AND by enclosing match
//! arm: the matching line must sit inside the `SyncTlsMode::AcceptAny` arm (one
//! of the 8 preceding non-blank lines names it) and may occur only once in that
//! file. A second occurrence anywhere, or that one moved out of the arm, fails.
//! Tests use the pinned-root helper in `tests/common/tls.rs` instead.

use std::path::{Path, PathBuf};

const BYPASS_CALLS: [&str; 2] = [
    "danger_accept_invalid_certs",
    "danger_accept_invalid_hostnames",
];
/// The single permitted production file (`--insecure-skip-server-verify`).
const PERMITTED_FILE: &str = "src/cli/sync.rs";
/// The match arm that must enclose the permitted call.
const PERMITTED_ARM: &str = "SyncTlsMode::AcceptAny";
/// How many preceding non-blank lines may separate the arm from the call.
const ARM_LOOKBACK_LINES: usize = 8;
const SCANNED_DIRS: [&str; 2] = ["tests", "src"];

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn has_bypass(line: &str) -> bool {
    !is_comment(line) && BYPASS_CALLS.iter().any(|c| line.contains(c))
}

/// Offending `file:line` strings for one file's text; `rel` is the
/// repo-relative path with `/` separators.
fn violations_in(rel: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let hits: Vec<usize> = (0..lines.len()).filter(|&i| has_bypass(lines[i])).collect();
    let mut out = Vec::new();
    for (n, &i) in hits.iter().enumerate() {
        let in_arm = rel == PERMITTED_FILE
            && n == 0
            && lines[..i]
                .iter()
                .rev()
                .filter(|l| !l.trim().is_empty())
                .take(ARM_LOOKBACK_LINES)
                .any(|l| l.contains(PERMITTED_ARM));
        if !in_arm {
            out.push(format!("{rel}:{}", i + 1));
        }
    }
    out
}


struct AllowRow {
    file: &'static str,
    reason: &'static str,
}

const RUSTLS_ALLOW: [AllowRow; 0] = [];

/// RED stub: the old walk (tests and src only).
fn scan_tree(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for d in SCANNED_DIRS {
        if root.join(d).is_dir() {
            collect_rs(&root.join(d), &mut files);
        }
    }
    let mut bad = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "tests/no_insecure_tls_guard_8179.rs" {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read");
        bad.extend(violations_in(&rel, &text));
    }
    bad
}

/// RED stub: no allow-list checking yet.
fn allow_list_problems(_root: &Path, _rows: &[AllowRow]) -> Vec<String> {
    Vec::new()
}

/// A scratch crate tree under `CARGO_TARGET_TMPDIR` (never the system temp).
fn fixture_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("guard-8179-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("fixture tempdir");
    for (rel, body) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir fixture");
        std::fs::write(&path, body).expect("write fixture");
    }
    dir
}

const ARM_FIXTURE: &str = "match m {\n    SyncTlsMode::AcceptAny => {\n        b.danger_accept_invalid_certs(true);\n    }\n}\n";
const ACCEPT_ANY_VERIFIER: &str = "struct Trusting;\nimpl rustls::client::danger::ServerCertVerifier for Trusting {\n    fn verify_server_cert(&self) -> Result<Verified, Error> {\n        Ok(Verified::assertion())\n    }\n}\n";

#[test]
fn no_certificate_verification_bypass_in_compiled_rs_8179() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bad = allow_list_problems(root, &RUSTLS_ALLOW);
    bad.extend(scan_tree(root));
    assert!(
        bad.is_empty(),
        "certificate-verification bypass found (use the pinned-root helper in tests/common/tls.rs; \
         the only permitted reqwest site is the {PERMITTED_ARM} arm for --insecure-skip-server-verify in \
         {PERMITTED_FILE}; rustls overrides only in the RUSTLS_ALLOW files):\n{}",
        bad.join("\n")
    );
}

#[test]
fn guard_pins_the_single_sync_arm_8179() {
    assert!(violations_in(PERMITTED_FILE, ARM_FIXTURE).is_empty());
    // moved out of the arm
    let moved = "fn f() {\n    b.danger_accept_invalid_certs(true);\n}\n";
    let got = violations_in(PERMITTED_FILE, moved);
    assert_eq!(got.len(), 1);
    assert!(got[0].starts_with(&format!("{PERMITTED_FILE}:2")));
    // a second occurrence in the permitted file
    let twice = format!("{ARM_FIXTURE}{ARM_FIXTURE}");
    assert_eq!(violations_in(PERMITTED_FILE, &twice).len(), 1);
    // the arm text in any other file does not excuse it
    assert_eq!(violations_in("src/other.rs", ARM_FIXTURE).len(), 1);
    // comments are ignored
    assert!(
        violations_in(
            "tests/x.rs",
            "// danger_accept_invalid_certs(true)\n//! danger_accept_invalid_hostnames\n/* danger_accept_invalid_certs */\n"
        )
        .is_empty()
    );
}

/// Code r2 (6388326855): a comment naming the arm must not satisfy the pin or
/// shift the window, so the real arm's insecure body is still inspected.
#[test]
fn comment_naming_the_arm_does_not_excuse_or_hide_8179() {
    let decoy_line = "// SyncTlsMode::AcceptAny is the opt-in\nfn helper(b: B) {\n    b.danger_accept_invalid_certs(true);\n}\n";
    let got = violations_in(PERMITTED_FILE, decoy_line);
    assert_eq!(got.len(), 1, "decoy line comment excused the call: {got:?}");
    let decoy_block = "/* SyncTlsMode::AcceptAny => */\nfn helper(b: B) {\n    b.danger_accept_invalid_certs(true);\n}\n";
    assert_eq!(violations_in(PERMITTED_FILE, decoy_block).len(), 1);
    // a comment above the REAL arm whose body is insecure: the body is inspected
    let real = "// SyncTlsMode::AcceptAny: opt-in\nmatch m {\n    SyncTlsMode::AcceptAny => {\n        b.danger_accept_invalid_certs(true);\n        cfg.dangerous().with_custom_certificate_verifier(v);\n    }\n}\n";
    let got = violations_in(PERMITTED_FILE, real);
    assert!(
        got.iter().any(|v| v.contains(":5:")),
        "insecure arm body not inspected: {got:?}"
    );
}

/// Security r2 (c): comment lines inside the located arm are not counted
/// against the look-back window.
#[test]
fn comment_lines_inside_the_arm_are_not_counted_8179() {
    let mut text = String::from("match m {\n    SyncTlsMode::AcceptAny => {\n");
    for n in 0..(ARM_LOOKBACK_LINES + 4) {
        text.push_str(&format!("        // rationale line {n}\n"));
    }
    text.push_str("        /* block\n           comment */\n");
    text.push_str("        b.danger_accept_invalid_certs(true);\n    }\n}\n");
    assert!(
        violations_in(PERMITTED_FILE, &text).is_empty(),
        "comment lines shifted the arm window"
    );
}

/// Security r2 (a): the rustls accept-any shapes.
#[test]
fn rustls_accept_any_shapes_are_flagged_8179() {
    let named = "let v = Arc::new(tls::DangerousAnyServerVerifier);\n";
    assert_eq!(violations_in("src/other.rs", named).len(), 1);
    let unconditional = violations_in("src/other.rs", ACCEPT_ANY_VERIFIER);
    assert!(
        unconditional.iter().any(|v| v.contains("returns Ok unconditionally")),
        "an innocuously named accept-any verifier slipped through: {unconditional:?}"
    );
    let builder = "let c = rustls::ClientConfig::builder()\n    .dangerous()\n    .with_custom_certificate_verifier(v)\n    .with_no_client_auth();\n";
    assert!(!violations_in("src/other.rs", builder).is_empty());
    let setter = "cfg.dangerous().set_certificate_verifier(v);\n";
    assert!(!violations_in("tests/x.rs", setter).is_empty());
    let danger = "let b = ClientBuilder::new().danger();\n";
    assert!(!violations_in("tests/x.rs", danger).is_empty());
    // a verifier that can reject is fine, and `dangerous_op()` is not the builder
    let strict = "impl ServerCertVerifier for Pin {\n    fn verify_server_cert(&self) -> R {\n        if ok { Ok(V) } else { Err(E) }\n    }\n}\nfn is_dangerous(x: u8) {}\nlet z = dangerous_op();\n";
    assert!(violations_in("src/other.rs", strict).is_empty());
    // the allow-listed files may use the rustls shapes, but not the reqwest bypass
    assert!(violations_in("tests/mtls_nodelay_acceptor.rs", ACCEPT_ANY_VERIFIER).is_empty());
    assert!(violations_in("tests/mtls_nodelay_acceptor.rs", named).is_empty());
    assert_eq!(
        violations_in(
            "tests/mtls_nodelay_acceptor.rs",
            "b.danger_accept_invalid_certs(true);\n"
        )
        .len(),
        1
    );
}

/// Security r2 (b): every compiled `.rs`, not only `src/` and `tests/`.
#[test]
fn examples_benches_and_build_rs_are_scanned_8179() {
    for rel in ["examples/demo.rs", "benches/b.rs", "build.rs"] {
        let tree = fixture_tree(&[(rel, ACCEPT_ANY_VERIFIER)]);
        let bad = scan_tree(tree.path());
        assert!(
            bad.iter().any(|v| v.starts_with(rel)),
            "{rel} with an accept-any verifier passed: {bad:?}"
        );
    }
}

#[test]
fn include_targets_are_followed_and_must_exist_8179() {
    let tree = fixture_tree(&[
        ("src/lib.rs", "include!(\"../extra/hidden.rs\");\n"),
        ("extra/hidden.rs", "static V: DangerousAnyServerVerifier = X;\n"),
    ]);
    let bad = scan_tree(tree.path());
    assert!(
        bad.iter().any(|v| v.starts_with("extra/hidden.rs:1")),
        "include! target not scanned: {bad:?}"
    );
    let missing = fixture_tree(&[("src/lib.rs", "include!(\"../extra/nope.rs\");\n")]);
    let bad = scan_tree(missing.path());
    assert!(
        bad.iter().any(|v| v.contains("include target missing")),
        "missing include! target passed: {bad:?}"
    );
    let path_attr = fixture_tree(&[
        ("benches/b.rs", "#[path = \"../benchmarks/m.rs\"]\nmod m;\n"),
        ("benchmarks/m.rs", "cfg.dangerous();\n"),
    ]);
    let bad = scan_tree(path_attr.path());
    assert!(bad.iter().any(|v| v.starts_with("benchmarks/m.rs:1")), "{bad:?}");
    // a clean include passes
    let clean = fixture_tree(&[
        ("src/lib.rs", "include!(\"gen.rs\");\n"),
        ("src/gen.rs", "fn ok() {}\n"),
    ]);
    assert!(scan_tree(clean.path()).is_empty());
}

#[test]
fn stale_allow_list_row_fails_8179() {
    let tree = fixture_tree(&[("src/real.rs", "fn f() {}\n")]);
    let rows = [
        AllowRow {
            file: "src/real.rs",
            reason: "exists",
        },
        AllowRow {
            file: "src/gone.rs",
            reason: "file was deleted",
        },
    ];
    let bad = allow_list_problems(tree.path(), &rows);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].contains("src/gone.rs"));
    // the real allow-list names only files that exist
    assert!(allow_list_problems(Path::new(env!("CARGO_MANIFEST_DIR")), &RUSTLS_ALLOW).is_empty());
}
