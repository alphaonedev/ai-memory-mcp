// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1980 (2×5 vote 288ef0ef) — regression guard for the illustrative
//! refuse-by-default signed-rule-pack TEMPLATE.
//!
//! The vote's content finding (refuter a0f92306): the shipped template must be
//! ILLUSTRATIVE (fake matchers) + DISABLED + UNSIGNED — never a prescriptive
//! "blessed" policy, and never one whose matchers refuse real common operations
//! (`refuse process_spawn cargo` / `refuse /tmp` would break the substrate's own
//! build). This test pins those properties so the template can't silently drift
//! into a dangerous or auto-active state.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;

use serde_json::Value;

fn template() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/governance/refuse-by-default-rules.template.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read template {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("template is valid JSON")
}

/// The closed action-kind vocabulary the agent-action engine accepts.
const VALID_KINDS: &[&str] = &[
    "filesystem_write",
    "network_request",
    "process_spawn",
    "bash",
    "custom",
];

#[test]
fn template_rules_are_disabled_unsigned_refuse_and_well_formed() {
    let t = template();
    let rules = t
        .get("rules")
        .and_then(Value::as_array)
        .expect("template has a rules array");
    assert!(
        !rules.is_empty(),
        "template ships at least one example rule"
    );

    for r in rules {
        let id = r.get("id").and_then(Value::as_str).expect("rule has id");

        // DISABLED — the substrate default is never flipped by shipping this.
        assert_eq!(
            r.get("enabled").and_then(Value::as_bool),
            Some(false),
            "rule {id} must ship DISABLED"
        );

        // UNSIGNED — the template carries NO signature (the operator signs it).
        assert!(
            r.get("signature").is_none(),
            "rule {id} must ship UNSIGNED (no signature field)"
        );

        // Well-formed kind + a non-empty per-kind matcher object.
        let kind = r
            .get("kind")
            .and_then(Value::as_str)
            .expect("rule has kind");
        assert!(
            VALID_KINDS.contains(&kind),
            "rule {id}: unknown kind {kind}"
        );
        let matcher = r
            .get("matcher")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("rule {id}: matcher must be a JSON object"));
        assert!(!matcher.is_empty(), "rule {id}: matcher must be non-empty");

        // severity present (the template is a refuse-by-default illustration).
        assert!(
            r.get("severity").and_then(Value::as_str).is_some(),
            "rule {id}: severity present"
        );
    }
}

#[test]
fn template_matchers_are_illustrative_never_real_operations() {
    // The load-bearing safety property: copying the template verbatim must
    // refuse NOTHING real. Every matcher value is a deliberately-fake token, and
    // must NOT collide with operations the substrate itself performs (writing
    // /tmp, spawning cargo) — those would be a false-positive footgun.
    let t = template();
    let rules = t.get("rules").and_then(Value::as_array).expect("rules");

    // Tokens that would indicate a REAL (dangerous-to-bless) matcher.
    const FORBIDDEN_REAL: &[&str] = &["/tmp", "/var/tmp", "cargo", "/usr", "/etc", "/home"];
    // Tokens that mark a value as deliberately illustrative/fake.
    const ILLUSTRATIVE: &[&str] = &["example", "invalid", "forbidden"];

    for r in rules {
        let id = r.get("id").and_then(Value::as_str).unwrap_or("?");
        let matcher = r.get("matcher").expect("matcher");
        let matcher_str = serde_json::to_string(matcher).unwrap();

        for real in FORBIDDEN_REAL {
            assert!(
                !matcher_str.contains(real),
                "rule {id}: matcher {matcher_str} names a REAL path/binary ({real}) — the \
                 template must stay illustrative so it refuses nothing real"
            );
        }
        assert!(
            ILLUSTRATIVE.iter().any(|tok| matcher_str.contains(tok)),
            "rule {id}: matcher {matcher_str} must be visibly illustrative \
             (contain example/invalid/forbidden)"
        );

        // The reason must flag the rule as an example the operator replaces.
        let reason = r.get("reason").and_then(Value::as_str).unwrap_or("");
        assert!(
            reason.to_uppercase().contains("EXAMPLE"),
            "rule {id}: reason must mark it as an EXAMPLE to replace; got {reason:?}"
        );
    }
}
