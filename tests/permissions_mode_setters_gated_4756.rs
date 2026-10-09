// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4756 — the test-only `PermissionsMode` writers and their serialisation
//! lock are compiled OUT of non-test builds: each of
//! `override_active_permissions_mode_for_test`,
//! `clear_permissions_mode_override_for_test` and
//! `lock_permissions_mode_for_test` in `src/config.rs` carries
//! `#[cfg(any(test, feature = "test-support"))]`, so a release library or an
//! embedding crate cannot reach `clear_permissions_mode_override_for_test`
//! (which downgrades `Enforce` to the `Advisory` pre-init fallback).
//!
//! The gate is a compile-time property, so this cell pins the SOURCE: the
//! attribute must sit on the item (doc comments, `#[doc(hidden)]` and
//! `#[must_use]` may lie between). Integration tests keep reaching the three
//! through the `test-support` self-feature already declared in `Cargo.toml`.

const GATE: &str = "#[cfg(any(test, feature = \"test-support\"))]";

const GATED: [&str; 3] = [
    "pub fn override_active_permissions_mode_for_test",
    "pub fn clear_permissions_mode_override_for_test",
    "pub fn lock_permissions_mode_for_test",
];

fn config_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The attribute lines directly above `item` (skipping doc comments and the
/// other attributes), as a joined string.
fn attributes_above<'a>(lines: &[&'a str], item: &str) -> Vec<&'a str> {
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with(item))
        .unwrap_or_else(|| panic!("{item} not found in src/config.rs"));
    lines[..at]
        .iter()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///")
        })
        .copied()
        .collect()
}

#[test]
fn test_only_permissions_mode_writers_are_cfg_gated_4756() {
    let src = config_source();
    let lines: Vec<&str> = src.lines().collect();
    for item in GATED {
        let attrs = attributes_above(&lines, item);
        assert!(
            attrs.iter().any(|a| a.trim() == GATE),
            "{item} must carry {GATE}; attributes found: {attrs:?}"
        );
    }
}

/// The production boot setter stays reachable: `src/main.rs` installs the
/// resolved mode through it, so it must NOT be gated.
#[test]
fn production_boot_setter_stays_ungated_4756() {
    let src = config_source();
    let lines: Vec<&str> = src.lines().collect();
    let attrs = attributes_above(&lines, "pub fn set_active_permissions_mode");
    assert!(
        !attrs.iter().any(|a| a.contains("cfg(")),
        "set_active_permissions_mode is the boot setter and must stay ungated: {attrs:?}"
    );
}
