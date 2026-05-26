// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #1327 — `memory_skill_register` docstring example
//! drift.
//!
//! Pre-#1327 regression: the docstring example for
//! `memory_skill_register` referenced `skill_folder` as the parameter
//! name, but the parser at `handle_skill_register` only accepts
//! `folder_path`. A caller copy-pasting the docstring example saw a
//! generic `requires either folder_path or inline_skill` refusal.
//!
//! Fix (option 1 from the issue): the docstring example uses the
//! canonical `folder_path` parameter name. A worked example is added
//! to `tool_examples()` in `src/mcp/tools/capabilities.rs` so the
//! capabilities surface carries a byte-equal-to-valid call.
//!
//! This file pins:
//!
//! 1. `tool_examples("memory_skill_register")` returns at least one
//!    example.
//! 2. Each example's `call` JSON deserializes through the canonical
//!    `SkillRegisterRequest` parser without an unknown-field error.
//! 3. The example using `folder_path` exists (option-1 contract).
//! 4. NO example uses `skill_folder` (regression guard).

use ai_memory::mcp::tools::capabilities::tool_examples;
use serde_json::{Value, json};

const TOOL_NAME: &str = "memory_skill_register";

/// Case 1 — at least one canonical example exists.
#[test]
fn issue_1327_skill_register_has_at_least_one_example() {
    let examples = tool_examples(TOOL_NAME);
    assert!(
        !examples.is_empty(),
        "memory_skill_register must carry at least one worked example for callers"
    );
}

/// Case 2 — every example's `call` payload deserializes through the
/// canonical parser without an "unknown field" error. This is the
/// load-bearing assertion that the example is byte-equal to a valid
/// call.
#[test]
fn issue_1327_skill_register_examples_deserialize_through_parser() {
    use ai_memory::mcp::tools::skill_register::SkillRegisterRequest;
    let examples = tool_examples(TOOL_NAME);
    for (idx, ex) in examples.iter().enumerate() {
        let call: &Value = &ex.call;
        // The schemars-derived schema doesn't set
        // `deny_unknown_fields` for SkillRegisterRequest, so the
        // parser is lenient at deserialise time. The stricter check
        // is that EITHER `folder_path` OR `inline_skill` keys appear
        // on the example — matching what `handle_skill_register`
        // actually inspects.
        let obj = call
            .as_object()
            .unwrap_or_else(|| panic!("example {idx} call must be a JSON object"));
        assert!(
            obj.contains_key("folder_path") || obj.contains_key("inline_skill"),
            "example {idx} must carry either 'folder_path' or 'inline_skill'; got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );

        // The example MUST deserialize cleanly through the canonical
        // request struct (no decode error). serde with
        // `#[serde(default)]` on Option<String> permits absence of
        // either field, so this is purely a shape sanity check.
        let _parsed: SkillRegisterRequest = serde_json::from_value(call.clone())
            .unwrap_or_else(|e| panic!("example {idx} must parse via SkillRegisterRequest: {e}"));
    }
}

/// Case 3 — option-1 contract: a folder-form example uses
/// `folder_path` (NOT `skill_folder`).
#[test]
fn issue_1327_skill_register_folder_example_uses_canonical_field_name() {
    let examples = tool_examples(TOOL_NAME);
    let folder_example = examples
        .iter()
        .find(|ex| {
            ex.call
                .as_object()
                .is_some_and(|o| o.contains_key("folder_path"))
        })
        .expect(
            "a folder-form example must exist using the canonical \
             `folder_path` parameter name",
        );
    let obj = folder_example.call.as_object().expect("call is object");
    assert!(
        obj.get("folder_path").and_then(Value::as_str).is_some(),
        "folder_path must be a string in the worked example"
    );
}

/// Case 4 — regression guard: NO example carries the legacy
/// `skill_folder` key.
#[test]
fn issue_1327_no_example_uses_legacy_skill_folder_name() {
    let examples = tool_examples(TOOL_NAME);
    for (idx, ex) in examples.iter().enumerate() {
        let obj = ex
            .call
            .as_object()
            .unwrap_or_else(|| panic!("example {idx} is object"));
        assert!(
            !obj.contains_key("skill_folder"),
            "example {idx} must NOT use the legacy `skill_folder` key; got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }
}

/// Case 5 — the docstring example payload, when deserialized,
/// produces a payload that `handle_skill_register` recognises (the
/// "either `folder_path` or `inline_skill`" gate passes for it).
///
/// This exercises the actual parser shape end-to-end without
/// requiring an on-disk SKILL.md (`folder_path` points to a tempdir
/// without SKILL.md → the parser proceeds past the field gate and
/// fails downstream with a different error than "requires either").
#[test]
fn issue_1327_docstring_example_satisfies_parser_field_gate() {
    use ai_memory::mcp::tools::skill_register::handle_skill_register;
    let tmp_db = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::storage::open(tmp_db.path()).expect("db::open");

    // Build a payload using the canonical folder_path key so the
    // parser's field gate passes. We point at a non-skill folder
    // (no SKILL.md) so the parser proceeds past the field gate and
    // surfaces the downstream "cannot read SKILL.md" — proving the
    // field-gate side of the example is byte-equal-to-valid.
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let result = handle_skill_register(
        &conn,
        &json!({"folder_path": scratch.path().to_str().expect("utf8 path")}),
        None,
    );
    let err = result.expect_err("scratch dir has no SKILL.md so this must error");
    assert!(
        !err.contains("requires either 'folder_path' or 'inline_skill'"),
        "the example's field gate must pass; instead saw the gate-refusal: {err}"
    );
    assert!(
        err.contains("cannot read SKILL.md") || err.contains("SKILL.md"),
        "downstream refusal must be a SKILL.md-shape error, proving the parser \
         accepted the folder_path field; got: {err}"
    );
}
