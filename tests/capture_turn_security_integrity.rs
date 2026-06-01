// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

//! v0.7.0 #1413 + #1414 + #1415 critical security pin for the
//! `memory_capture_turn` MCP tool. The 6-agent review (reviewer 3
//! security finding F3.1, memory `cd28329a`) showed the pre-fix
//! handler bypassed every CLAUDE.md-promised gate:
//!
//! 1. agent_id was taken verbatim from `req.metadata.agent_id` with
//!    no cross-check against the MCP-handshake caller, so any MCP
//!    client could fabricate memories attributed to any agent_id.
//! 2. `host_signature_b64` + `host_pubkey_b64` were declared on the
//!    wire and documented as gating `attest_level = "signed_by_peer"`
//!    but the handler never read either field.
//! 3. The documented `signed_events` row tagged `layer = "L4"` was
//!    never written — audit could not prove which layer caught each
//!    turn.
//!
//! This integration test pins the post-fix contract:
//!
//! - **agent_id agreement** — supplying `metadata.agent_id` that
//!   disagrees with the resolved caller is rejected with
//!   `INVALID_INPUT`.
//! - **Signature pairing contract** — exactly one of
//!   `host_signature_b64` / `host_pubkey_b64` is `INVALID_INPUT`.
//! - **Allowlist enforcement** — a `host_pubkey_b64` not on the
//!   `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` env-var allowlist returns
//!   `HOST_PUBKEY_NOT_ENROLLED`.
//! - **Signature verification** — a tampered signature returns
//!   `INVALID_INPUT: signature_verification_failed`.
//! - **Signed-by-peer success path** — a verified signature lands a
//!   memory with `attest_level: "signed_by_peer"` in the response,
//!   and the `signed_events` chain row carries the same attest_level.
//! - **Self-signed default path** — absent signature fields yield
//!   `attest_level: "self_signed"`.
//! - **signed_events row presence** — every successful capture
//!   writes exactly one row tagged `event_type = "memory_capture_turn"`
//!   inside the same transaction.

use ai_memory::mcp::handle_capture_turn;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::PathBuf;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1413-capture-turn-security-test")
}

fn fresh_db() -> (tempfile::TempDir, Connection) {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("capture-turn.db");
    let conn = ai_memory::storage::open(&db_path).expect("open db");
    (dir, conn)
}

fn count_signed_events_rows(conn: &Connection, event_type: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        rusqlite::params![event_type],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn signed_events_attest_level(conn: &Connection, memory_id_substr: &str) -> Option<String> {
    // The L4 row carries the memory_id NEITHER as payload_hash NOR in
    // a column — the audit row's link is via temporal-+-payload-hash
    // correlation. The simplest pinning here is "look at the most-
    // recent memory_capture_turn row" since each test does at most
    // one capture per fresh DB.
    let _ = memory_id_substr; // reserved if we later carry memory_id in event metadata
    conn.query_row(
        "SELECT attest_level FROM signed_events \
         WHERE event_type = 'memory_capture_turn' \
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// F3.1 — agent_id agreement check
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rejects_metadata_agent_id_that_disagrees_with_resolved_caller() {
    let (_dir, conn) = fresh_db();
    let resolved_caller = "ai:legitimate-host@example:pid-1";
    let err = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-spoof",
            "host_turn_index": 0,
            "role": "user",
            "content": "spoofed turn",
            "metadata": { "agent_id": "ai:spoofed-victim" }
        }),
        Some(resolved_caller),
    )
    .expect_err("disagreement must error");
    assert!(
        err.starts_with("INVALID_INPUT"),
        "expected INVALID_INPUT prefix, got: {err}"
    );
    assert!(
        err.contains("metadata.agent_id"),
        "error message names the field, got: {err}"
    );
}

#[test]
fn accepts_metadata_agent_id_that_matches_resolved_caller() {
    let (_dir, conn) = fresh_db();
    let resolved_caller = "ai:matched-host";
    let resp = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-match",
            "host_turn_index": 0,
            "role": "user",
            "content": "matched turn",
            "metadata": { "agent_id": resolved_caller }
        }),
        Some(resolved_caller),
    )
    .expect("matching agent_id ok");
    assert_eq!(resp["layer"].as_str(), Some("L4"));
    assert_eq!(resp["attest_level"].as_str(), Some("self_signed"));
}

#[test]
fn stamps_caller_into_metadata_when_metadata_omits_agent_id() {
    // When the caller supplies metadata WITHOUT agent_id, the handler
    // patches in the resolved caller so audit attribution is never
    // empty. Body-supplied non-agent_id keys are preserved verbatim.
    let (_dir, conn) = fresh_db();
    let resolved_caller = "ai:patched-host";
    let resp = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-patched",
            "host_turn_index": 0,
            "role": "user",
            "content": "patched turn",
            "metadata": { "custom": "value" }
        }),
        Some(resolved_caller),
    )
    .expect("ok");
    let memory_id = resp["memory_id"].as_str().expect("memory_id present");
    // Re-fetch the row and check metadata.
    let metadata_json: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            rusqlite::params![memory_id],
            |row| row.get(0),
        )
        .expect("fetch metadata");
    let metadata: Value = serde_json::from_str(&metadata_json).expect("parse metadata");
    assert_eq!(metadata["agent_id"].as_str(), Some(resolved_caller));
    assert_eq!(metadata["custom"].as_str(), Some("value"));
}

// ─────────────────────────────────────────────────────────────────────────────
// F3.4 / R2.F2.7 — host_signature path: pairing, allowlist, verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rejects_signature_without_pubkey() {
    let (_dir, conn) = fresh_db();
    let err = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-paired-1",
            "host_turn_index": 0,
            "role": "user",
            "content": "x",
            "host_signature_b64": B64_STD.encode([0u8; 64])
        }),
        None,
    )
    .expect_err("sig without pubkey must error");
    assert!(err.starts_with("INVALID_INPUT"), "got: {err}");
    assert!(
        err.contains("both be present or both absent"),
        "expected paired-fields message, got: {err}"
    );
}

#[test]
fn rejects_pubkey_without_signature() {
    let (_dir, conn) = fresh_db();
    let err = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-paired-2",
            "host_turn_index": 0,
            "role": "user",
            "content": "x",
            "host_pubkey_b64": B64_STD.encode([0u8; 32])
        }),
        None,
    )
    .expect_err("pubkey without sig must error");
    assert!(err.starts_with("INVALID_INPUT"), "got: {err}");
}

#[test]
fn rejects_unenrolled_host_pubkey() {
    // SAFETY: env var is process-global. This test sets it to a
    // known-different pubkey so the verify path lands on the
    // not-enrolled arm regardless of any operator config. We restore
    // it on drop via the test scope helper below.
    let (_dir, conn) = fresh_db();
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_b64 = B64_STD.encode(pubkey_bytes);

    let canonical = format!("{}\0{}\0{}\0{}", "session-unenrolled", 0i64, "user", "x");
    let sig = signing_key.sign(canonical.as_bytes());

    // Set the allowlist to a DIFFERENT pubkey so this one is not
    // enrolled. Use a deterministic-different value.
    let other_pubkey_b64 = B64_STD.encode([0xFEu8; 32]);
    let _guard = EnvVarGuard::set(
        "AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST",
        other_pubkey_b64.as_str(),
    );

    let err = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-unenrolled",
            "host_turn_index": 0,
            "role": "user",
            "content": "x",
            "host_signature_b64": B64_STD.encode(sig.to_bytes()),
            "host_pubkey_b64": pubkey_b64
        }),
        None,
    )
    .expect_err("unenrolled pubkey must error");
    assert!(
        err.starts_with("HOST_PUBKEY_NOT_ENROLLED:"),
        "expected HOST_PUBKEY_NOT_ENROLLED prefix, got: {err}"
    );
}

#[test]
fn rejects_tampered_signature_with_enrolled_pubkey() {
    let (_dir, conn) = fresh_db();
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_b64 = B64_STD.encode(signing_key.verifying_key().to_bytes());
    let _guard = EnvVarGuard::set("AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST", pubkey_b64.as_str());

    // Sign a DIFFERENT payload than what we send so verify_strict
    // rejects.
    let wrong_canonical = format!("{}\0{}\0{}\0{}", "session-tamper", 0i64, "user", "decoy");
    let sig = signing_key.sign(wrong_canonical.as_bytes());

    let err = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-tamper",
            "host_turn_index": 0,
            "role": "user",
            "content": "real content (not what was signed)",
            "host_signature_b64": B64_STD.encode(sig.to_bytes()),
            "host_pubkey_b64": pubkey_b64
        }),
        None,
    )
    .expect_err("tampered sig must error");
    assert!(
        err.contains("signature_verification_failed"),
        "expected signature_verification_failed, got: {err}"
    );
}

#[test]
fn accepts_verified_signature_and_lands_signed_by_peer_attest_level() {
    let (_dir, conn) = fresh_db();
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_b64 = B64_STD.encode(signing_key.verifying_key().to_bytes());
    let _guard = EnvVarGuard::set("AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST", pubkey_b64.as_str());

    let canonical = format!(
        "{}\0{}\0{}\0{}",
        "session-signed", 0i64, "user", "verified turn"
    );
    let sig = signing_key.sign(canonical.as_bytes());

    let resp = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-signed",
            "host_turn_index": 0,
            "role": "user",
            "content": "verified turn",
            "host_signature_b64": B64_STD.encode(sig.to_bytes()),
            "host_pubkey_b64": pubkey_b64
        }),
        Some("ai:signed-host"),
    )
    .expect("verified sig must succeed");

    assert_eq!(resp["attest_level"].as_str(), Some("signed_by_peer"));
    assert_eq!(resp["dedup_hit"].as_bool(), Some(false));
    assert_eq!(resp["layer"].as_str(), Some("L4"));

    // Pin: signed_events row carries the same attest_level.
    let level = signed_events_attest_level(&conn, "").expect("signed_events row");
    assert_eq!(level, "signed_by_peer");
}

// ─────────────────────────────────────────────────────────────────────────────
// F3.1 / R2.F2.8 — signed_events row presence + attest_level on the
// unsigned (default) path.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn writes_signed_events_row_on_every_successful_capture() {
    let (_dir, conn) = fresh_db();
    let resp = handle_capture_turn(
        &conn,
        &json!({
            "host_session_id": "session-audit",
            "host_turn_index": 0,
            "role": "user",
            "content": "audit-pinned turn"
        }),
        Some("ai:audit-host"),
    )
    .expect("ok");
    assert_eq!(resp["attest_level"].as_str(), Some("self_signed"));

    // One memory_capture_turn audit row exists.
    assert_eq!(
        count_signed_events_rows(&conn, "memory_capture_turn"),
        1,
        "exactly one L4 signed_events row per successful capture"
    );

    // attest_level on the audit row matches the response.
    let level = signed_events_attest_level(&conn, "").expect("audit row");
    assert_eq!(level, "self_signed");
}

#[test]
fn dedup_hit_does_not_emit_a_second_signed_events_row() {
    // Idempotency contract: re-delivery of the same (session, turn)
    // returns dedup_hit:true but must NOT add a second audit row.
    let (_dir, conn) = fresh_db();
    let params = json!({
        "host_session_id": "session-idem-audit",
        "host_turn_index": 0,
        "role": "user",
        "content": "idem"
    });
    let _ = handle_capture_turn(&conn, &params, Some("ai:idem-host")).expect("first ok");
    let second = handle_capture_turn(&conn, &params, Some("ai:idem-host")).expect("second ok");
    assert_eq!(second["dedup_hit"].as_bool(), Some(true));
    assert_eq!(
        count_signed_events_rows(&conn, "memory_capture_turn"),
        1,
        "dedup-hit must not write a second audit row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers — env-var guard so the allowlist tests don't leak.
// ─────────────────────────────────────────────────────────────────────────────

/// Serializes every `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` mutation in
/// this binary. `cargo test` runs the integration tests in ONE binary
/// with all `#[test]` fns on parallel threads by default — the prior
/// "single-threaded by default" assumption was false, so three tests
/// (`rejects_unenrolled_host_pubkey`, `rejects_tampered_signature_*`,
/// `accepts_verified_signature_*`) raced on the same process-global
/// env var. A loser saw a peer's allowlist value and got
/// `HOST_PUBKEY_NOT_ENROLLED` where it expected
/// `signature_verification_failed`. The guard holds this lock for its
/// whole lifetime so the set → read(handle_capture_turn) → restore
/// window is atomic across tests.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvVarGuard {
    name: &'static str,
    previous: Option<String>,
    // Dropped LAST (declaration order), so the env var is restored by
    // the `Drop` impl while the lock is still held, then released.
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: &str) -> Self {
        // Poisoning is irrelevant — the lock guards a `()`; recover the
        // guard so one panicking test does not cascade-fail the rest.
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::env::var(name).ok();
        // SAFETY: set_var/remove_var are unsafe on Edition 2024 / Rust
        // 1.83+ for multi-thread soundness. ENV_LOCK serializes every
        // mutation + dependent read in this binary, so no other thread
        // touches the environment inside the critical section. The
        // guard restores on drop.
        unsafe {
            std::env::set_var(name, value);
        }
        EnvVarGuard {
            name,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: see EnvVarGuard::set
        unsafe {
            match &self.previous {
                Some(prev) => std::env::set_var(self.name, prev),
                None => std::env::remove_var(self.name),
            }
        }
    }
}
