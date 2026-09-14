// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3720 — `AI_MEMORY_ENCRYPT_AT_REST` is per-record content encryption on
//! the DEFAULT build, both backends; it is not a SQLCipher switch. CLAUDE.md
//! env-table row 37 said "sqlcipher build only", talking an operator on a
//! standard build out of a control they already had. Pinned two ways:
//!
//! * the DOC: row 37's Surface cell carries no build condition and its Notes
//!   name the real mechanism and the key lifecycle; the honest-limitations
//!   list names the default-build envelope, not only SQLCipher;
//! * the THING: this test binary is a default build (no `sqlcipher`
//!   feature), and a real `ai-memory store` with the knob set writes a
//!   `0x03` envelope, empties `content`, and mints the per-agent x25519 key
//!   files under the key dir — the measurement the doc must describe.

#![allow(clippy::missing_panics_doc)]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::process::Command;

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel} must exist: {e}"))
}

fn row_37() -> Vec<String> {
    let doc = repo_file("CLAUDE.md");
    let line = doc
        .lines()
        .find(|l| l.starts_with("| 37 | `AI_MEMORY_ENCRYPT_AT_REST`"))
        .expect("CLAUDE.md env-table row 37 for AI_MEMORY_ENCRYPT_AT_REST");
    line.split('|').map(|c| c.trim().to_string()).collect()
}

#[test]
fn row_37_surface_cell_carries_no_build_condition_3720() {
    let cells = row_37();
    // | 37 | name | type | default | surface | class | notes |
    let surface = &cells[5];
    assert!(
        !surface.to_ascii_lowercase().contains("sqlcipher"),
        "row 37's Surface cell must not condition the knob on a sqlcipher build: {surface}"
    );
    assert!(
        surface.contains("default build") && surface.contains("both backends"),
        "row 37's Surface names the default build and both backends: {surface}"
    );
}

#[test]
fn row_37_notes_name_the_mechanism_and_the_key_lifecycle_3720() {
    let cells = row_37();
    let notes = &cells[7];
    for needle in [
        "NOT SQLCipher",
        "ChaCha20-Poly1305",
        "X25519",
        "encrypted_envelope",
        "title / tags / metadata stay plaintext",
        "`[encryption].at_rest",
        "minted on first use",
        "no rotation and no escrow",
        "#3717",
        "No passphrase is involved",
    ] {
        assert!(
            notes.contains(needle),
            "row 37 Notes must say {needle:?}; got: {notes}"
        );
    }
}

#[test]
fn honest_limitations_names_the_default_build_envelope_3720() {
    let doc = repo_file("docs/compliance/honest-limitations.md");
    assert!(
        doc.contains("on the **default build** and on **both backends**"),
        "honest-limitations must name the default-build content envelope, not only SQLCipher"
    );
}

/// The thing the doc describes, measured on this default-build binary.
#[test]
fn default_build_store_with_the_knob_seals_content_and_mints_x25519_keys_3720() {
    assert!(
        !ai_memory::build_features::has_feature("sqlcipher"),
        "this pin is about the DEFAULT build; a sqlcipher build is a different control"
    );
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch dir under the repo");
    let db = dir.path().join("at-rest-3720.db");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let keys = dir.path().join("keys");
    key_dir_sandbox::mkdir_0700(&keys);
    let agent = "ai:at-rest-3720";

    let output = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", &home)
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_ENCRYPT_AT_REST", "1")
        .args([
            "--db",
            db.to_str().expect("db"),
            "--agent-id",
            agent,
            "--json",
            "store",
            "--namespace",
            "at-rest-3720",
            "--title",
            "sealed on a default build",
            "--content",
            "the plaintext that must not reach the content column",
        ])
        .output()
        .expect("ai-memory store");
    assert!(
        output.status.success(),
        "store must succeed with the knob set on a default build: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The row: envelope present (0x03), content column empty.
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only");
    let (content, envelope): (String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT content, encrypted_envelope FROM memories WHERE namespace = 'at-rest-3720'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the stored row");
    let envelope = envelope.expect("encrypted_envelope must be written on a default build");
    assert_eq!(content, "", "content column is emptied when sealed");
    assert_eq!(
        envelope.first().copied(),
        Some(ai_memory::encryption::RECORD_ENVELOPE_VERSION),
        "a 0x03 per-record envelope"
    );
    assert!(
        !String::from_utf8_lossy(&envelope).contains("plaintext that must not reach"),
        "the envelope must not carry the plaintext"
    );

    // The keys: minted on first use under the key dir, private key 0600.
    let priv_key = keys.join(format!("{agent}.x25519.priv"));
    let pub_key = keys.join(format!("{agent}.x25519.pub"));
    assert!(
        priv_key.is_file(),
        "x25519 private key minted at {}",
        priv_key.display()
    );
    assert!(
        pub_key.is_file(),
        "x25519 public key minted at {}",
        pub_key.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&priv_key)
            .expect("priv metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "private key mode");
    }
}
