// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6790 / Wave-1 S1 — a DB passphrase request on a build WITHOUT sqlcipher
//! must refuse to open, never fall through to a plaintext database.
//!
//! This case sets `AI_MEMORY_DB_PASSPHRASE`, the variable `db::open` reads on
//! every open. It lived in the shared lib test binary, where hundreds of
//! unrelated tests open a database without the env lock, so a concurrent open
//! could observe the variable and take the sqlcipher refusal
//! (`macos-fed,sqlite` shard, run 38015742119). An integration test runs in its
//! own process, so no other test can observe the write — the #2146 /
//! `tests/config_precedence.rs` precedent.

#![cfg(not(feature = "sqlcipher"))]

mod common;
use common::EnvVarGuard;

#[test]
fn passphrase_set_on_non_sqlcipher_refuses_open_s1() {
    let _guard = EnvVarGuard::set("AI_MEMORY_DB_PASSPHRASE", "s1-test-passphrase".to_string());
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let err = ai_memory::db::open(tmp.path())
        .expect_err("passphrase + non-sqlcipher must refuse, not open plaintext");
    let msg = err.to_string();
    assert!(
        msg.contains("sqlcipher"),
        "refusal must name sqlcipher: {msg}"
    );
    assert!(
        msg.contains("AI_MEMORY_DB_PASSPHRASE") || msg.contains("passphrase"),
        "refusal must name the passphrase request: {msg}"
    );
}

#[test]
fn passphrase_unset_on_non_sqlcipher_still_opens_6790() {
    // Control: the refusal is caused by the passphrase request, not by every
    // open in this binary. `remove` holds the same env lock as the case above.
    let _guard = EnvVarGuard::remove("AI_MEMORY_DB_PASSPHRASE");
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    ai_memory::db::open(tmp.path()).expect("no passphrase requested => plain open succeeds");
}
