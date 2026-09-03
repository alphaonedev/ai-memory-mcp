// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

//! v1.0.0 #3355 — the test suite must never mint keys in the OPERATOR'S key store.
//!
//! # What happened
//!
//! `encryption::keypair_persist_dir` forked on `#[cfg(test)]`: the test arm
//! returned an ephemeral tempdir, the other arm returned
//! `identity::keypair::default_key_dir()`. **`cfg(test)` is true only while
//! compiling THIS crate's own unit tests.** An integration test in `tests/`
//! links the already-built rlib — compiled WITHOUT `cfg(test)` — so it took
//! the production arm and minted per-agent X25519 keypairs in the real
//! `~/.config/ai-memory/keys`. 43 fixture keypairs accumulated on the
//! maintainer's machine: `agent-bad-2383.x25519`, `pg-commit-b-wrong.x25519`,
//! `test-agent-228-tamper.x25519`, `r56-erase-agent.x25519`, and so on.
//!
//! The sandbox was worse than none: it held on one side of the crate boundary
//! and evaporated on the other, so the unit suite *looked* hermetic. That is
//! why this went unnoticed for two months.
//!
//! # What this binary pins
//!
//! 1. the `cfg(test)` fork never comes back (`no_cfg_test_fork`);
//! 2. every test binary that can resolve the DEFAULT key dir arms the sandbox
//!    (`every_key_minting_test_binary_arms_the_sandbox`) — the census the
//!    issue asked for, so a NEW test cannot reintroduce the leak silently;
//! 3. arming actually moves resolution off the operator's key dir, and a
//!    minted X25519 keypair lands in the sandbox — the behavioural proof.
//!
//! Nothing here writes to, or deletes from, the operator's key directory. The
//! two behavioural tests only *list* it, to prove they did not add to it.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// The census
// ---------------------------------------------------------------------------

/// Source text with `//` comments stripped.
///
/// The scan must look at CODE, not prose. An earlier draft matched the raw
/// bytes and flagged four files whose only mention of at-rest encryption was
/// a doc comment or a posture *label*. A guard that cries wolf is a guard the
/// next engineer silences.
fn code_only(path: &Path) -> String {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    raw.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Does this file reach a path that resolves the DEFAULT key directory?
///
/// These are the four ways a test can end up writing into whatever
/// `default_key_dir()` resolves to. Anything that passes an EXPLICIT
/// directory (`get_or_create_keypair_in`, `keypair::save(&kp, dir)`) is
/// deliberately absent: it cannot reach the operator's store, so demanding a
/// sandbox there would be noise.
fn default_key_dir_triggers(code: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    // 1. Resolving the default dir outright.
    if code.contains("default_key_dir(") {
        hits.push("default_key_dir()");
    }
    // 2. The no-directory X25519 mint. `get_or_create_keypair_in` takes an
    //    explicit dir and is excluded by the `_in` suffix check below.
    if code
        .match_indices("get_or_create_keypair(")
        .any(|(i, _)| !preceded_by_ident_char(code, i))
    {
        hits.push("encryption::get_or_create_keypair()");
    }
    // 3. Turning at-rest encryption ON: every store then routes through
    //    `seal_content` -> `get_or_create_keypair` -> the default dir.
    if enables_at_rest(code) {
        hits.push("enables AI_MEMORY_ENCRYPT_AT_REST");
    }
    if code.contains("set_config_at_rest(") {
        hits.push("encryption::set_config_at_rest()");
    }
    hits
}

fn preceded_by_ident_char(code: &str, at: usize) -> bool {
    code[..at]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// `set_var(..ENCRYPT_AT_REST..)` / `.env(..ENCRYPT_AT_REST..)` — the var
/// being SET, not merely named. `posture_control15_pg_resolution_3106.rs`
/// names the same const as a doctor-row *label* and is hermetic; matching the
/// bare name would flag it forever.
fn enables_at_rest(code: &str) -> bool {
    ["set_var(", ".env("].iter().any(|setter| {
        code.match_indices(setter).any(|(i, _)| {
            let tail = &code[i..];
            let end = tail.find(')').map_or(tail.len(), |e| e + 1);
            let call = &tail[..end];
            call.contains("ENV_ENCRYPT_AT_REST") || call.contains("AI_MEMORY_ENCRYPT_AT_REST")
        })
    })
}

/// Evidence that the file arms the sandbox (directly or via the shared
/// `tests/common/key_dir_sandbox.rs` helper, which delegates to the same
/// library funnel).
fn arms_the_sandbox(code: &str) -> bool {
    code.contains("key_dir_sandbox")
        || code.contains("install_test_key_dir_sandbox")
        || code.contains("AI_MEMORY_KEY_DIR")
}

fn all_test_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("tests"), &mut out);
    out.sort();
    out
}

/// THE GUARD. A test binary that can resolve the default key directory must
/// arm the sandbox, or it writes into the operator's real key store.
#[test]
fn every_key_minting_test_binary_arms_the_sandbox_3355() {
    let mut offenders: Vec<String> = Vec::new();
    let mut armed = 0usize;

    for path in all_test_sources() {
        // The helper itself IS the arming mechanism.
        if path.ends_with("common/key_dir_sandbox.rs") {
            continue;
        }
        let code = code_only(&path);
        let triggers = default_key_dir_triggers(&code);
        if triggers.is_empty() {
            continue;
        }
        if arms_the_sandbox(&code) {
            armed += 1;
        } else {
            offenders.push(format!(
                "  {} — reaches: {}",
                path.display(),
                triggers.join(", ")
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "#3355: {} test source(s) can resolve the DEFAULT key directory without \
         arming the key-dir sandbox. Each will mint keypairs in the OPERATOR'S \
         real ~/.config/ai-memory/keys:\n{}\n\nFix — add to the top of the test \
         binary:\n\n    #[path = \"common/key_dir_sandbox.rs\"]\n    mod \
         key_dir_sandbox;\n\nand call `key_dir_sandbox::pin();` at the start of \
         each test (it is idempotent). For `assert_cmd`/`Command` children also \
         pass `.env(\"AI_MEMORY_KEY_DIR\", key_dir_sandbox::pin())`, or strip \
         every `AI_MEMORY_*` and pass an explicit key dir.",
        offenders.len(),
        offenders.join("\n")
    );

    // The census must not silently become vacuous — a refactor that renames
    // `get_or_create_keypair` would otherwise leave this test passing while
    // checking nothing at all.
    assert!(
        armed >= 5,
        "#3355: the trigger set matched only {armed} armed binaries; it was \
         calibrated against 6. Either the key-minting surface was renamed (update \
         `default_key_dir_triggers`) or the census has gone blind."
    );
}

/// The exact shape that caused #3355 must never return.
#[test]
fn keypair_persist_dir_has_no_cfg_test_fork_3355() {
    let src = std::fs::read_to_string("src/encryption/mod.rs").expect("read encryption/mod.rs");
    let code = src
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(
        code.matches("fn keypair_persist_dir(").count(),
        1,
        "#3355: `keypair_persist_dir` must have exactly ONE implementation. A \
         second, `cfg`-gated one is how the leak happened: the sandbox held for \
         `cargo test --lib` and silently evaporated for every integration test, \
         which links the rlib built without `cfg(test)`."
    );
    let lines: Vec<&str> = code.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("fn keypair_persist_dir(") {
            // The three lines above the signature carry any `cfg` attribute.
            let prev = lines[i.saturating_sub(3)..i].join(" ");
            assert!(
                !prev.contains("cfg(test)") && !prev.contains("cfg(not(test))"),
                "#3355: `keypair_persist_dir` is `cfg(test)`-forked again. Tests \
                 must arm `identity::keypair::install_test_key_dir_sandbox()` \
                 explicitly instead — one mechanism that works on BOTH sides of \
                 the crate boundary."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The behavioural proof
// ---------------------------------------------------------------------------

/// The operator's real key directory, if this host has one. Read-only.
///
/// Asks the library for the PLATFORM default rather than re-deriving
/// `~/.config/ai-memory/keys` here — a second spelling of the path would be
/// free to drift from the one the product actually uses, and then this guard
/// would be watching the wrong directory.
fn operator_key_dir() -> Option<PathBuf> {
    ai_memory::identity::keypair::platform_default_key_dir()
}

fn list_dir(p: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(p) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn arming_the_sandbox_moves_resolution_off_the_operator_key_dir_3355() {
    let sandbox = ai_memory::identity::keypair::install_test_key_dir_sandbox();
    let resolved =
        ai_memory::identity::keypair::default_key_dir().expect("key dir resolves once armed");
    assert_eq!(
        resolved, sandbox,
        "#3355: arming must make `default_key_dir()` resolve to the sandbox"
    );
    if let Some(real) = operator_key_dir() {
        assert_ne!(
            resolved, real,
            "#3355: the armed key dir must NOT be the operator's real key store"
        );
    }
}

/// The direct proof that the defect is closed: mint an X25519 keypair through
/// the very call that leaked (`get_or_create_keypair`, no explicit dir) and
/// show the material lands in the sandbox while the operator's key dir is
/// untouched.
#[test]
fn x25519_keys_land_in_the_sandbox_not_the_operator_key_dir_3355() {
    let sandbox = ai_memory::identity::keypair::install_test_key_dir_sandbox();
    let real = operator_key_dir();
    let before = real.as_deref().map(list_dir);

    // A name in the shape of the fixtures that actually leaked.
    let agent = "guard-3355-fixture-agent";
    let kp = ai_memory::encryption::get_or_create_keypair(agent).expect("mint x25519 keypair");
    assert_eq!(kp.agent_id, agent);

    assert!(
        sandbox.join(format!("{agent}.x25519.priv")).exists(),
        "#3355: the minted private key must land in the sandbox {}",
        sandbox.display()
    );

    if let (Some(real), Some(before)) = (real.as_deref(), before) {
        let after = list_dir(real);
        let added: Vec<&String> = after.iter().filter(|f| !before.contains(f)).collect();
        assert!(
            added.is_empty(),
            "#3355: minting a keypair added {added:?} to the OPERATOR'S key dir {}",
            real.display()
        );
    }
}
