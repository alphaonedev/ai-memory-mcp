// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-11 (FX-C4-batch2, 2026-05-26) — feature-flag audit.
//!
//! Asserts that every `[features]` entry declared in `Cargo.toml`
//! is consumed by at least one `cfg(feature = "<name>")` in src/
//! or tests/. A feature with zero consumers is dead substrate —
//! the operator who finds `e2e` in Cargo.toml will wonder which
//! paths it gates and either delete the flag or wire it up. This
//! test surfaces the gap mechanically so the audit cannot silently
//! drift again.
//!
//! Discriminator carve-outs documented inline:
//! - `default` — the meta feature, only consumed implicitly.
//! - `sqlite-bundled` — read by `rusqlite/bundled`; surfaces in
//!   `Cargo.toml [dependencies]` shape only.
//! - `sqlcipher` — same shape; consumed by `rusqlite/...-sqlcipher-...`.
//! - `e2e` — consumed by the local-runner script
//!   `scripts/run-session-boot-lifetime-tests.sh` per the
//!   Cargo.toml comment; the script-based consumer is honoured.

use std::fs;
use std::path::Path;

/// Walk a directory recursively, returning every file path with the
/// given extension.
fn walk(root: &Path, ext: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path, ext));
        } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    out
}

#[test]
fn arch_11_every_feature_flag_has_a_consumer_or_is_carve_out() {
    let cargo = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");

    // Parse the [features] section: every line of the shape
    // `<name> = ...` between `[features]` and the next `[section]`.
    let features_start = cargo.find("[features]").expect("locate [features] section");
    let after_features = &cargo[features_start + "[features]".len()..];
    let features_end = after_features.find("\n[").unwrap_or(after_features.len());
    let block = &after_features[..features_end];

    let mut features: Vec<String> = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let name = trimmed[..eq].trim();
            if !name.is_empty() {
                features.push(name.to_string());
            }
        }
    }
    assert!(
        !features.is_empty(),
        "ARCH-11: failed to parse any features out of Cargo.toml [features] block",
    );

    // Carve-outs honoured by the gate. These flags are load-bearing
    // through Cargo.toml composition rules, NOT through `cfg(...)`
    // attributes, so the in-tree grep returns zero hits but the
    // flag is not dead.
    let carve_outs: &[&str] = &[
        "default",        // meta-feature, implicit consumer (Cargo)
        "sqlite-bundled", // rusqlite/bundled — Cargo dep composition
        "sqlcipher",      // rusqlite/bundled-sqlcipher-vendored-openssl — Cargo
        "sal",            // composed by sal-postgres (Cargo) AND consumed via cfg in src/
        "sal-postgres",   // consumed via cfg in src/
        "e2e",            // consumed by scripts/run-session-boot-lifetime-tests.sh
                          // — script-based consumer; see Cargo.toml comment for
                          //   the canonical wiring.
    ];

    // Build a haystack of every src/ + tests/ .rs file content so
    // the substring search runs once over the corpus.
    let mut haystack = String::new();
    for path in walk(Path::new("src"), "rs") {
        if let Ok(s) = fs::read_to_string(&path) {
            haystack.push_str(&s);
            haystack.push('\n');
        }
    }
    for path in walk(Path::new("tests"), "rs") {
        if let Ok(s) = fs::read_to_string(&path) {
            haystack.push_str(&s);
            haystack.push('\n');
        }
    }

    let mut missing = Vec::new();
    for feature in &features {
        if carve_outs.contains(&feature.as_str()) {
            continue;
        }
        let needle = format!("feature = \"{feature}\"");
        if !haystack.contains(&needle) {
            missing.push(feature.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "ARCH-11 feature-flag audit: the following features have ZERO `cfg(feature = ...)` \
         consumers in src/ or tests/ AND are not in the documented carve-out list: {missing:?}. \
         Either wire each flag up, document it as a carve-out in this test, or remove \
         it from Cargo.toml.",
    );
}
