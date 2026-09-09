// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_auto_tag` handler.
//!
//! Tier D (LLM-bound) module. The envelope below — input validation,
//! optional-client gating, DB get/update, tag-union semantics, error
//! surfacing — is deterministically tested at ≥95% via a
//! `wiremock`-backed real `OllamaClient`. The single
//! `llm.auto_tag(...)` dispatch is exercised through the same path so
//! the parse-then-store pipeline is end-to-end verified without a
//! live Ollama daemon. Real-LLM tag-quality is validated by the
//! LongMemEval benchmark (see `benchmarks/longmemeval/`); see L0.7-5
//! playbook §6 for the contract.

use crate::llm::OllamaClient;
use crate::{db, validate};
use serde_json::{Value, json};

/// Generate and persist tags through the caller-scoped, governed update funnel.
/// The read and ownership checks run before content reaches the external model.
/// An absent caller retains the ordinary single-operator read posture; substrate
/// rows remain excluded because this tool does not accept a namespace selector.
pub(super) fn handle_auto_tag(
    conn: &rusqlite::Connection,
    llm: Option<&OllamaClient>,
    params: &Value,
    caller: Option<&str>,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let llm = llm.ok_or("auto-tagging requires smart or autonomous tier (Ollama LLM)")?;
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // #3348 read visibility precedes #1786 ownership: mutation permission
    // alone does not grant permission to send a row to the model.
    let mem = db::get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
    if !crate::visibility::is_readable_on_query(&mem, caller, None) {
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    }
    if let Some(c) = caller
        && !crate::visibility::caller_owns_for_mutation(&mem, c, false)
    {
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    }
    // COVERAGE: LLM response variability. The call below produces a
    // Vec<String> derived from the model's response; envelope is
    // tested at ≥95% via wiremock-driven success / error / shape
    // cases below; real-LLM tag quality is validated end-to-end via
    // the LongMemEval benchmark (see `benchmarks/longmemeval/`).
    let tags = llm
        .auto_tag(&mem.title, &mem.content, None)
        .map_err(|e| e.to_string())?;
    // Apply tags to the memory
    let mut all_tags = mem.tags.clone();
    for t in &tags {
        if !all_tags.contains(t) {
            all_tags.push(t.clone());
        }
    }
    // #3381 — the WRITE goes through the governed update funnel. Embedder /
    // vector-index are deliberately `None`: a tags-only patch changes neither
    // title nor content, so there is nothing to re-embed and passing them
    // would be the only behavioural difference from the pre-fix raw write.
    let mut update_params = json!({ "id": &mem.id, (crate::mcp::param_names::TAGS): &all_tags });
    if let Some(caller) = caller {
        update_params[crate::mcp::param_names::AGENT_ID] = json!(caller);
    }
    let updated = crate::mcp::update::handle_update(conn, &update_params, None, None, mcp_client)?;
    // The governed funnel may answer `pending` (namespace requires approval)
    // or `ask` (a permission rule) INSTEAD of writing. Surface that envelope
    // verbatim rather than reporting tags that were never persisted — a
    // success-shaped body on an unperformed write is itself a defect.
    if matches!(
        updated.get("status").and_then(Value::as_str),
        Some("pending" | "ask")
    ) {
        let mut out = updated;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("new_tags".into(), json!(&tags));
            obj.insert("all_tags".into(), json!(&all_tags));
        }
        return Ok(out);
    }
    Ok(json!({"id": id, "new_tags": tags, "all_tags": all_tags}))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_auto_tag ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_auto_tag`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct AutoTagRequest {
    /// Memory ID.
    pub id: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_auto_tag`.
#[allow(dead_code)]
pub struct AutoTagTool;

impl McpTool for AutoTagTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_AUTO_TAG
    }
    fn description() -> &'static str {
        "LLM-generate tags for a memory (smart/autonomous tier)."
    }
    fn docs() -> &'static str {
        "LLM auto-tagging. Smart/autonomous tier."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<AutoTagRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_auto_tag`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn auto_tag_parity_986() {
        let derived = derived_props_for::<AutoTagRequest>();
        assert_property_set_parity("memory_auto_tag", &derived);
        assert_descriptions_match("memory_auto_tag", &derived);
    }

    #[test]
    fn auto_tag_tool_metadata_986() {
        assert_eq!(AutoTagTool::name(), "memory_auto_tag");
        assert_eq!(AutoTagTool::family(), "power");
    }
}

/// Test entry point for the isolated auto-tag envelope suite (#3381/#3523).
/// Forwards to the production handler without changing caller or control flow.
/// Absent from builds without `test` or `test-support`.
///
/// # Errors
/// Returns the production handler's validation, visibility, governance or model error.
#[cfg(any(test, feature = "test-support"))]
pub fn handle_auto_tag_for_tests(
    conn: &rusqlite::Connection,
    llm: Option<&OllamaClient>,
    params: &Value,
    caller: Option<&str>,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    handle_auto_tag(conn, llm, params, caller, mcp_client)
}
