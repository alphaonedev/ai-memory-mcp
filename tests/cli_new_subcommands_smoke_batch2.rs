// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — smoke suite for the 16 new CLI
//! subcommands that close the residual MCP/CLI parity gap from the
//! FX-12 audit:
//!
//! - `reflect`
//! - `subscribe` / `unsubscribe` / `list-subscriptions` /
//!   `subscription-replay` / `subscription-dlq-list`
//! - `notify` / `inbox`
//! - `ingest-multistep`
//! - `kg-invalidate` / `kg-timeline`
//! - `entity-register` / `entity-get-by-alias`
//! - `dependents-of-invalidated` / `reflection-origin`
//! - `quota-status`
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
    // require an existing DB.
    let _ = ai_memory::storage::open(&path).expect("open db");
    (dir, path)
}

/// Helper — list of all 16 new subcommand names.
const NEW_SUBCOMMANDS: &[&str] = &[
    "reflect",
    "subscribe",
    "unsubscribe",
    "list-subscriptions",
    "subscription-replay",
    "subscription-dlq-list",
    "notify",
    "inbox",
    "ingest-multistep",
    "kg-invalidate",
    "kg-timeline",
    "entity-register",
    "entity-get-by-alias",
    "dependents-of-invalidated",
    "reflection-origin",
    "quota-status",
];

// ─── --help smoke for every new subcommand ────────────────────────

#[test]
fn fxc3_all_new_subcommands_help_exits_ok() {
    for name in NEW_SUBCOMMANDS {
        Command::cargo_bin("ai-memory")
            .unwrap()
            .env("AI_MEMORY_NO_CONFIG", "1")
            .args([name, "--help"])
            .assert()
            .success();
    }
}

// ─── Top-level --help must list every new subcommand ─────────────

#[test]
fn fxc3_top_level_help_lists_all_new_subcommands() {
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for name in NEW_SUBCOMMANDS {
        assert!(
            stdout.contains(name),
            "top-level --help must list `{name}`; got:\n{stdout}"
        );
    }
}

// ─── Missing-required-arg → non-zero exit, stable error ──────────

#[test]
fn fxc3_reflect_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["reflect"])
        .assert()
        .failure();
}

#[test]
fn fxc3_subscribe_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["subscribe"])
        .assert()
        .failure();
}

#[test]
fn fxc3_unsubscribe_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["unsubscribe"])
        .assert()
        .failure();
}

#[test]
fn fxc3_subscription_replay_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["subscription-replay"])
        .assert()
        .failure();
}

#[test]
fn fxc3_notify_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["notify"])
        .assert()
        .failure();
}

#[test]
fn fxc3_ingest_multistep_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["ingest-multistep"])
        .assert()
        .failure();
}

#[test]
fn fxc3_kg_invalidate_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["kg-invalidate"])
        .assert()
        .failure();
}

#[test]
fn fxc3_kg_timeline_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["kg-timeline"])
        .assert()
        .failure();
}

#[test]
fn fxc3_entity_register_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["entity-register"])
        .assert()
        .failure();
}

#[test]
fn fxc3_entity_get_by_alias_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["entity-get-by-alias"])
        .assert()
        .failure();
}

#[test]
fn fxc3_dependents_of_invalidated_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["dependents-of-invalidated"])
        .assert()
        .failure();
}

#[test]
fn fxc3_reflection_origin_missing_required_args_fails() {
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["reflection-origin"])
        .assert()
        .failure();
}

// ─── Happy-path round-trip against an empty DB ───────────────────

/// `list-subscriptions --json` against an empty DB returns `count: 0`.
#[test]
fn fxc3_list_subscriptions_empty_db_json_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--db", db.to_str().unwrap(), "list-subscriptions", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `subscription-dlq-list --json` empty-DB shape.
#[test]
fn fxc3_subscription_dlq_list_empty_db_json_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "subscription-dlq-list",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `inbox --json --agent-id ai:alice` empty-DB shape.
#[test]
fn fxc3_inbox_empty_db_json_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "inbox",
            "--agent-id",
            "ai:alice",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `quota-status --json` empty-DB shape.
#[test]
fn fxc3_quota_status_empty_db_json_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--db", db.to_str().unwrap(), "quota-status", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `subscription-replay --subscription-id unknown --since RFC3339` —
/// caller-ownership gate returns `count: 0` envelope, not an error.
#[test]
fn fxc3_subscription_replay_unknown_id_returns_empty_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "subscription-replay",
            "--subscription-id",
            "unknown",
            "--since",
            "2024-01-01T00:00:00Z",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `entity-register` → round-trips to `entity-get-by-alias`.
#[test]
fn fxc3_entity_register_then_get_by_alias_roundtrip() {
    let (_dir, db) = fresh_db();
    Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "entity-register",
            "--canonical-name",
            "Charlie",
            "--namespace",
            "people",
            "--aliases",
            "chuck,charles",
            "--json",
        ])
        .assert()
        .success();

    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "entity-get-by-alias",
            "--alias",
            "chuck",
            "--namespace",
            "people",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["found"].as_bool(), Some(true));
    assert_eq!(envelope["canonical_name"].as_str(), Some("Charlie"));
}

/// `dependents-of-invalidated --memory-id nope` → empty envelope.
#[test]
fn fxc3_dependents_of_invalidated_unknown_id_returns_empty() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "dependents-of-invalidated",
            "--memory-id",
            "nope-id",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert_eq!(envelope["count"].as_u64(), Some(0));
}

/// `ingest-multistep --content X --json` — tier-locked advisory
/// on the keyword tier (default for CLI without config).
#[test]
fn fxc3_ingest_multistep_tier_locked_returns_envelope() {
    let (_dir, db) = fresh_db();
    let assert = Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db.to_str().unwrap(),
            "ingest-multistep",
            "--content",
            "hello world",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
    assert!(envelope.get("tier-locked").is_some());
}
