// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #3436 — BEHAVIOURAL half: drive the built binary, not the source.
//!
//! `tests/cli_stdout_hygiene_3436.rs` pins the CONTROLS by scanning source
//! text (the funnel exists, the match has no catch-all, the gate precedes
//! the dispatch). That is the right shape for "this structure cannot
//! regress", and the wrong shape for "the operator actually sees this":
//! a source scan cannot tell whether the refusal reaches exit status,
//! whether stdout is genuinely empty, or whether a `--json` document is
//! parseable. Fable's review asked for the other half, so this file runs
//! `env!("CARGO_BIN_EXE_ai-memory")` and asserts on real streams.
//!
//! Four behaviours, matching the four defects #3436 closes:
//!
//! * (a) a verb with no JSON form REFUSES `--json` — non-zero exit, EMPTY
//!   stdout, refusal on stderr;
//! * (b) `rules keygen --json` puts EXACTLY ONE parseable JSON document on
//!   stdout and its human status line on stderr;
//! * (c) `verify-reflection-chain <unknown>` exits 1 NOT FOUND (and
//!   `--format json` says `ok:false, not_found:true`) while a real id
//!   exits 0 — the vacuous-`ok:true` defect;
//! * (d) `gc --json` still exits 0 with JSON — the OVER-refusal guard, so
//!   the fix cannot be "refuse everything".

use std::path::{Path, PathBuf};
use std::process::Output;

/// Fresh per-test directory under `.local-runs/` — the project's no-`/tmp`
/// HARD RULE. Holds the scratch DB and any key material the verb writes, so
/// nothing lands in the operator's real config/key dirs (#3355).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3436-cli-hygiene");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Run the built binary with CWD pinned inside `dir`, `--db` pointed at a
/// scratch file, and `AI_MEMORY_KEY_DIR` / `HOME` redirected to sibling paths so a
/// key-writing verb can never touch the operator's real key dir.
fn run(dir: &Path, args: &[&str]) -> Output {
    let db = dir.join("scratch.db");
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).ok();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .arg("--db")
        .arg(&db)
        .args(args)
        // Never read the developer's real config, and never write their keys.
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("home/.config"));
    cmd.output().expect("spawn ai-memory")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// Count the JSON documents on a stream. "JSON-only stdout" means exactly
/// one parseable document — not "starts with `{`", which a human line
/// followed by JSON would also satisfy.
fn json_documents(s: &str) -> Result<Vec<serde_json::Value>, String> {
    serde_json::Deserializer::from_str(s)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{e}"))
}

// ---------------------------------------------------------------------------
// (a) DENIED — a verb with no JSON form refuses `--json`
// ---------------------------------------------------------------------------

/// Every argv shape here parses cleanly in clap, so a non-zero exit can only
/// come from the #3436 gate — not from a usage error.
#[test]
fn unsupported_json_verbs_refuse_with_empty_stdout_3436() {
    let dir = fresh_dir("refuse");
    let cfg = dir.path().join("client-config.json");
    std::fs::write(&cfg, "{}\n").expect("seed client config");
    let cfg_s = cfg.display().to_string();

    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("man", vec!["man", "--json"]),
        (
            "install",
            vec!["install", "cursor", "--config", &cfg_s, "--json"],
        ),
        ("config check", vec!["config", "check", "--json"]),
    ];

    for (label, args) in cases {
        let out = run(dir.path(), &args);
        let so = stdout_of(&out);
        let se = stderr_of(&out);
        assert!(
            !out.status.success(),
            "{label}: --json must be REFUSED, not silently ignored (exit {:?})\nstdout: {so}",
            out.status.code()
        );
        assert!(
            so.trim().is_empty(),
            "{label}: stdout must be EMPTY on refusal — a caller parsing it must get \
             nothing rather than human text:\n{so}"
        );
        assert!(
            se.contains("--json") && se.contains("REFUSED"),
            "{label}: the refusal must say so on stderr:\n{se}"
        );
        assert!(
            se.contains("NOTHING WAS EXECUTED"),
            "{label}: the operator must be told nothing ran:\n{se}"
        );
    }
}

// ---------------------------------------------------------------------------
// (d) ALLOWED — the fix must not become "refuse everything"
// ---------------------------------------------------------------------------

/// `gc` honours the dispatcher's global `--json`, so it must still succeed
/// and still emit JSON. Without this, "refuse `--json`" could regress into
/// refusing verbs that support it.
#[test]
fn gc_json_still_succeeds_with_json_on_stdout_3436() {
    let dir = fresh_dir("gc");
    let out = run(dir.path(), &["gc", "--json"]);
    let so = stdout_of(&out);
    assert!(
        out.status.success(),
        "gc --json must still exit 0 (exit {:?})\nstdout: {so}\nstderr: {}",
        out.status.code(),
        stderr_of(&out)
    );
    let docs =
        json_documents(&so).unwrap_or_else(|e| panic!("gc --json stdout not JSON: {e}\n{so}"));
    assert_eq!(docs.len(), 1, "gc --json must emit ONE document:\n{so}");
}

// ---------------------------------------------------------------------------
// (b) `rules keygen --json` — exactly one JSON doc on stdout
// ---------------------------------------------------------------------------

/// The reported defect: `keygen_operator` wrote its fingerprint line to
/// stdout UNCONDITIONALLY, immediately before `emit_ok`'s envelope on the
/// same stream, so stdout held human text + JSON and no caller could pipe it
/// into `jq`. Asserting "exactly one document" is what discriminates the fix.
#[test]
fn rules_keygen_json_emits_one_document_and_status_on_stderr_3436() {
    let dir = fresh_dir("keygen");
    let out = run(dir.path(), &["rules", "keygen", "--json"]);
    let so = stdout_of(&out);
    let se = stderr_of(&out);
    assert!(
        out.status.success(),
        "rules keygen --json must succeed (exit {:?})\nstdout: {so}\nstderr: {se}",
        out.status.code()
    );
    let docs = json_documents(&so)
        .unwrap_or_else(|e| panic!("stdout is not pure JSON ({e}) — the human line leaked:\n{so}"));
    assert_eq!(
        docs.len(),
        1,
        "stdout must carry EXACTLY ONE JSON document under --json:\n{so}"
    );
    // The status line is rerouted, never dropped.
    assert!(
        se.contains("Ed25519 operator key generated"),
        "the fingerprint status line must still reach the operator, on stderr:\n{se}"
    );
    assert!(
        !so.contains("Ed25519 operator key generated"),
        "the status line must NOT be on stdout under --json:\n{so}"
    );
}

// ---------------------------------------------------------------------------
// (c) verify-reflection-chain — unknown id is NOT FOUND, real id verifies
// ---------------------------------------------------------------------------

/// Store one memory through the real binary and return its id.
fn seed_memory(dir: &Path) -> String {
    let out = run(
        dir,
        &[
            "store",
            "--title",
            "chain root 3436",
            "--content",
            "content for the verify-reflection-chain behavioural test",
            "--namespace",
            "hygiene-3436",
            "--json",
        ],
    );
    let so = stdout_of(&out);
    assert!(
        out.status.success(),
        "seeding a memory must succeed: {so}{}",
        stderr_of(&out)
    );
    let v: serde_json::Value =
        serde_json::from_str(so.trim()).unwrap_or_else(|e| panic!("store --json: {e}\n{so}"));
    v["id"]
        .as_str()
        .unwrap_or_else(|| panic!("store --json must return an id:\n{so}"))
        .to_string()
}

/// DENIED: an unresolvable root exits 1 (NOT FOUND), distinct from exit 2
/// (verification FAILED). Pre-#3436 the empty walk made `ok` vacuously true
/// and this exited 0 — a verifier certifying a memory it never found.
#[test]
fn verify_reflection_chain_unknown_id_is_not_found_exit_1_3436() {
    let dir = fresh_dir("verify-unknown");
    // Seed first so the DB and schema exist: this must fail on the ID, not
    // on a missing database.
    let _real = seed_memory(dir.path());

    let out = run(
        dir.path(),
        &[
            "verify-reflection-chain",
            "00000000-0000-4000-8000-000000003436",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unknown root must exit 1 NOT FOUND, not 0 (vacuous ok) and not 2 \
         (verification failed)\nstdout: {}\nstderr: {}",
        stdout_of(&out),
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("not found"),
        "the refusal must name the condition:\n{}",
        stderr_of(&out)
    );

    // The JSON form carries the same verdict as data.
    let jout = run(
        dir.path(),
        &[
            "verify-reflection-chain",
            "00000000-0000-4000-8000-000000003436",
            "--format",
            "json",
        ],
    );
    assert_eq!(jout.status.code(), Some(1), "json form must also exit 1");
    let so = stdout_of(&jout);
    let v: serde_json::Value =
        serde_json::from_str(so.trim()).unwrap_or_else(|e| panic!("--format json: {e}\n{so}"));
    assert_eq!(v["ok"], serde_json::json!(false), "{so}");
    assert_eq!(v["not_found"], serde_json::json!(true), "{so}");
}

/// ALLOWED: a REAL id still verifies and still exits 0 — the not-found gate
/// must not turn into a blanket refusal.
#[test]
fn verify_reflection_chain_real_id_still_exits_zero_3436() {
    let dir = fresh_dir("verify-real");
    let id = seed_memory(dir.path());
    let out = run(dir.path(), &["verify-reflection-chain", &id]);
    assert!(
        out.status.success(),
        "a real id must still verify (exit {:?})\nstdout: {}\nstderr: {}",
        out.status.code(),
        stdout_of(&out),
        stderr_of(&out)
    );
}
