// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-12 — smoke suite for the five new CLI
//! subcommands that close the MCP/CLI parity gap:
//!
//! - `kg-query` (MCP `memory_kg_query`)
//! - `find-paths` (MCP `memory_find_paths`)
//! - `recall-observations` (MCP `memory_recall_observations`)
//! - `check-duplicate` (MCP `memory_check_duplicate`)
//! - `replay` (MCP `memory_replay`)
//!
//! Each test invokes the binary via `assert_cmd` against a fresh
//! sqlite DB under `tempfile`, asserts exit code 0 (or expected
//! error), and validates the basic output shape. The substrate
//! semantic coverage already lives in the MCP tool unit tests; this
//! suite is purely the wire-layer smoke.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn fresh_db() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("ai-memory.db");
    // Pre-create the schema by opening once; the CLI commands all
    // require an existing DB and the test doesn't drive a `store`
    // step.
    let _ = ai_memory::storage::open(&path).expect("open db");
    (dir, path)
}

/// `--help` is the most basic smoke check — clap must wire the new
/// variant + Args struct without panicking. Run for all five.
#[test]
fn fx12_kg_query_help_exits_ok() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["kg-query", "--help"])
        .assert()
        .success();
}

#[test]
fn fx12_find_paths_help_exits_ok() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["find-paths", "--help"])
        .assert()
        .success();
}

#[test]
fn fx12_recall_observations_help_exits_ok() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["recall-observations", "--help"])
        .assert()
        .success();
}

#[test]
fn fx12_check_duplicate_help_exits_ok() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["check-duplicate", "--help"])
        .assert()
        .success();
}

#[test]
fn fx12_replay_help_exits_ok() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["replay", "--help"])
        .assert()
        .success();
}

/// `recall-observations --json` against an empty DB returns a
/// well-formed JSON envelope with `count: 0`. Pins the wire shape
/// without requiring any seed data.
#[test]
fn fx12_recall_observations_empty_db_json_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "recall-observations",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
    assert!(envelope["observations"].is_array());
}

/// `kg-query --json --source-id <fake>` against an empty DB exits
/// with a non-zero status because the source id doesn't exist.
/// Pins the substrate validation path reaches the CLI.
#[test]
fn fx12_kg_query_missing_args_fails_clearly() {
    let (_dir, db) = fresh_db();
    // No --source-id and no --by-source-uri → CLI-side guard fires.
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--db", db.to_str().unwrap(), "kg-query", "--json"])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("source-id") || stderr.contains("kg-query"),
        "stderr should mention the missing arg; got: {stderr}"
    );
}

/// `find-paths` requires both source-id and target-id (clap-enforced).
/// Smoke: omit them and confirm clap rejects.
#[test]
fn fx12_find_paths_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["find-paths", "--json"])
        .assert()
        .failure();
}

/// `check-duplicate` requires `--title` and `--content`. Smoke clap
/// rejection before any DB work happens.
#[test]
fn fx12_check_duplicate_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["check-duplicate"])
        .assert()
        .failure();
}

/// `replay` requires `--memory-id`. Smoke clap rejection.
#[test]
fn fx12_replay_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["replay"])
        .assert()
        .failure();
}

/// `--help` on the top-level binary must list all 5 new subcommands.
/// Regression guard against accidentally removing the dispatch arm.
#[test]
fn fx12_top_level_help_lists_all_five_new_subcommands() {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for name in [
        "kg-query",
        "find-paths",
        "recall-observations",
        "check-duplicate",
        "replay",
    ] {
        assert!(
            stdout.contains(name),
            "top-level --help must list `{name}`; got:\n{stdout}"
        );
    }
}
