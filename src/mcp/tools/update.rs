// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_update` handler.

use crate::embeddings::Embed;
use crate::hnsw::VectorSearchIndex;
use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::models::{EditSource, LifecycleState, Tier};
use crate::storage::VersionConflict;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.6 (#987): per-tool McpTool impl for `memory_update` (lifecycle family) ---

/// v0.7.0 #972 D1.6 (#987) — request body for `memory_update`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct UpdateRequest {
    /// Memory ID.
    pub id: String,

    #[serde(default)]
    pub title: Option<String>,

    #[serde(default)]
    pub content: Option<String>,

    #[schemars(
        description = "#1974 patch: raw text appended to the end of current content (verbatim, no separator). Mutually exclusive with `content` and `content_replace_*`; empty is rejected."
    )]
    #[serde(default)]
    pub content_append: Option<String>,

    #[schemars(
        description = "#1974 patch: substring to replace in current content. MUST occur exactly once (0 or >1 matches → typed error, never a silent first-match). Requires `content_replace_to`; mutually exclusive with `content`/`content_append`."
    )]
    #[serde(default)]
    pub content_replace_from: Option<String>,

    #[schemars(
        description = "#1974 patch: replacement text for the unique `content_replace_from` match (may be empty = deletion). Requires `content_replace_from`."
    )]
    #[serde(default)]
    pub content_replace_to: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tags: Option<Vec<String>>,

    #[serde(default)]
    pub priority: Option<i64>,

    #[serde(default)]
    pub confidence: Option<f64>,

    /// RFC3339 or null to clear.
    #[serde(default)]
    pub expires_at: Option<String>,

    /// JSON metadata.
    ///
    /// **#1009 fix:** typed as `Map<String, Value>` (same as
    /// StoreRequest::metadata — emits `type: "object"` on the wire,
    /// aligns the implementation with the pinned F15 #859/#912 discovery
    /// contract).
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, Value>>,

    #[schemars(description = "#884 If-Match; mismatch → 409 envelope.")]
    #[serde(default)]
    pub expected_version: Option<i64>,

    #[schemars(
        description = "#888/#1600 'human'/'agent'=in-place; 'llm'/'hook'=archive+supersede; omitted derives from caller id (ai:* => agent)."
    )]
    #[serde(default)]
    pub edit_source: Option<String>,

    #[schemars(description = "#906 update source_uri.")]
    #[serde(default)]
    pub source_uri: Option<String>,

    #[schemars(
        description = "#1834 claim-bitemporal: close/move the claim's valid_until (RFC3339). valid_from is immutable."
    )]
    #[serde(default)]
    pub valid_until: Option<String>,

    #[schemars(
        description = "#1709 Pillar-2 lifecycle transition target (open|active|blocked|done|abandoned). Illegal transitions are rejected; terminals go nowhere."
    )]
    #[serde(default)]
    pub lifecycle_state: Option<String>,

    // v0.9.0 G10.1 (#1827) — optional macaroon capability token. Plain `//`
    // so schemars emits only the concise attribute description.
    #[serde(default)]
    #[schemars(
        description = "#1827 capability token (cap1:..) — may flip a governance Deny/Pending on this update to Allow within its caveats."
    )]
    pub capability: Option<String>,
}

/// v0.7.0 #972 D1.6 (#987) — `McpTool` impl for `memory_update`.
#[allow(dead_code)]
pub struct UpdateTool;

impl McpTool for UpdateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_UPDATE
    }
    fn description() -> &'static str {
        "Update an existing memory by ID (only provided fields change)."
    }
    fn docs() -> &'static str {
        "Partial update by id. Omitted fields preserved. Tier monotone-only. metadata.agent_id preserved."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<UpdateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Lifecycle.name()
    }
}

#[cfg(test)]
mod d1_6_987_tests {
    //! D1.6 (#987) — schema parity for `memory_update`.
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn update_parity_987() {
        let derived = derived_props_for::<UpdateRequest>();
        assert_property_set_parity("memory_update", &derived);
        assert_descriptions_match("memory_update", &derived);
    }

    #[test]
    fn update_tool_metadata_987() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        assert_eq!(UpdateTool::name(), "memory_update");
        assert_eq!(UpdateTool::family(), "lifecycle");
    }
}

pub(super) fn handle_update(
    conn: &rusqlite::Connection,
    params: &Value,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // Resolve prefix if exact ID not found
    let resolved_id = if db::get(conn, id).map_err(|e| e.to_string())?.is_some() {
        id.to_string()
    } else if let Some(mem) = db::get_by_prefix(conn, id).map_err(|e| e.to_string())? {
        mem.id
    } else {
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    };
    let title = params["title"].as_str();
    // #1974 — the full-replacement `content`; the opt-in patch primitive
    // (assembled below) takes precedence and is mutually exclusive with it.
    let raw_content = params["content"].as_str();
    let tier = params["tier"].as_str().and_then(Tier::from_str);
    let namespace = params["namespace"].as_str();
    let tags: Option<Vec<String>> = params["tags"].as_array().map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    });
    // B4 (R2-LOW) — clamp instead of panic. Validation below enforces 1-10.
    let priority = params["priority"]
        .as_i64()
        .map(|p| i32::try_from(p).unwrap_or(i32::MAX));
    let confidence = params["confidence"].as_f64();
    let expires_at = params["expires_at"].as_str();
    // v0.7.0 Provenance Gap 2 (#906) — opt-in source_uri patch.
    // Validated below before reaching the storage layer; storage path
    // trusts the value as already-validated.
    let source_uri = params["source_uri"].as_str();
    // v1.0.0 #1834 — opt-in claim-bitemporal valid_until patch (valid_from
    // immutable). Validated below before reaching storage.
    let valid_until = params["valid_until"].as_str();
    // v0.7.0 Provenance Gap 1 (#884) — optimistic-concurrency
    // `expected_version` param. When supplied + non-null, the
    // underlying storage::update_with_expected_version refuses the
    // mutation with a typed VersionConflict envelope if the stored
    // row's `version` no longer matches.
    let mut expected_version = params["expected_version"].as_i64();
    // #1974 — opt-in content patch primitive. Assemble the FULL replacement
    // content from the CURRENT stored content plus a single append XOR
    // unique-match replace op, then thread the result through the SAME
    // `validate_content` (empty-reject + secret-screen of the RESULT, below)
    // and version-gated CAS a full-content update takes — so the patch is a
    // pre-step, not a new write path. The read pins the version the content
    // was assembled against and threads it as `expected_version` (TOCTOU
    // fail-close: a concurrent write between the read and the CAS surfaces as
    // a VersionConflict); a caller-supplied `expected_version` must agree
    // with the observed version, else it is rejected here before any write.
    let patch = crate::content_patch::ContentPatch {
        append: params[param_names::CONTENT_APPEND].as_str(),
        replace_from: params[param_names::CONTENT_REPLACE_FROM].as_str(),
        replace_to: params[param_names::CONTENT_REPLACE_TO].as_str(),
    };
    let patched_content: Option<String> = if patch.is_active() {
        if raw_content.is_some() {
            return Err("content cannot be combined with content_append/content_replace_* (full replacement and patch are mutually exclusive)".into());
        }
        let current = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
        if let Some(expected) = expected_version
            && expected != current.version
        {
            return Err(conflict_or_string(&anyhow::Error::new(VersionConflict {
                id: resolved_id.clone(),
                expected,
                current: current.version,
            })));
        }
        expected_version = Some(current.version);
        Some(patch.apply(&current.content).map_err(|e| e.to_string())?)
    } else {
        None
    };
    // The patched result (when present) is the effective content for the
    // rest of the flow — validation, re-embed, and the CAS all see it.
    let content: Option<&str> = patched_content.as_deref().or(raw_content);
    // v0.8.0 Pillar 2 (#1709) — optional lifecycle transition target.
    // An explicit, non-parseable value is REJECTED here (naming the valid
    // set); the legality of a parseable transition (current → requested)
    // is enforced after the in-place update lands (below).
    let lifecycle_state_req = params["lifecycle_state"].as_str();
    validate::validate_lifecycle_state(lifecycle_state_req).map_err(|e| e.to_string())?;
    let requested_lifecycle = lifecycle_state_req.and_then(LifecycleState::from_str);
    // #1600 — resolve the caller agent id ONCE, up front: it feeds
    // both the omitted-`edit_source` default below and the K9 /
    // governance write gate further down.
    let agent_id = crate::identity::resolve_agent_id(params["agent_id"].as_str(), mcp_client)
        .map_err(|e| e.to_string())?;
    // #1786 — owner gate: refuse a cross-owner update. The MCP update path calls
    // raw `db::update_with_*` directly (bypassing the SAL trait + the HTTP
    // `require_caller_owns_memory`). Keyed on the ENFORCED-read caller
    // (`resolve_read_visibility_caller`, env-only) so it fires ONLY when
    // `AI_MEMORY_AGENT_ID` is set (multi-tenant opt-in), leaving the
    // single-operator trust-all default byte-unchanged. `allow_inbox = false`
    // mirrors the HTTP `PUT /memories/{id}` gate (#954).
    if let Some(caller) = crate::identity::resolve_read_visibility_caller() {
        let target = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
        if !crate::visibility::caller_owns_for_mutation(&target, &caller, false) {
            return Err(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into());
        }
    }
    // v0.7.0 Provenance Gap 5 (#888) — typed `edit_source`
    // discriminator. `Llm` and `Hook` route through the
    // append-and-archive path so the pre-edit content is preserved
    // in `archived_memories` for rewind via `memory_archive_list`;
    // `Human` and `Agent` (#1600) mutate in place.
    //
    // #1600 — (b) an UNKNOWN explicit value is now a validation ERROR
    // naming the valid set (pre-fix it silently defaulted to Human,
    // mis-attributing programmatic edits in the audit trail); (c) an
    // OMITTED value derives its default from the resolved caller id
    // (`ai:`-prefixed NHI callers → Agent, else Human).
    let edit_source = match params[param_names::EDIT_SOURCE].as_str() {
        Some(s) => EditSource::from_str(s).ok_or_else(|| {
            format!(
                "invalid edit_source '{s}' (expected {})",
                EditSource::ALL.map(|v| v.as_str()).join("|")
            )
        })?,
        None => EditSource::default_for_agent_id(&agent_id),
    };

    if let Some(t) = title {
        validate::validate_title(t).map_err(|e| e.to_string())?;
    }
    if let Some(c) = content {
        validate::validate_content(c).map_err(|e| e.to_string())?;
    }
    if let Some(ns) = &namespace {
        validate::validate_namespace(ns).map_err(|e| e.to_string())?;
    }
    if let Some(ref t) = tags {
        validate::validate_tags(t).map_err(|e| e.to_string())?;
    }
    if let Some(p) = priority {
        validate::validate_priority(p).map_err(|e| e.to_string())?;
    }
    if let Some(c) = confidence {
        validate::validate_confidence(c).map_err(|e| e.to_string())?;
    }
    if let Some(ts) = expires_at {
        // Allow past dates in update for programmatic TTL management and GC testing
        validate::validate_expires_at_format(ts).map_err(|e| e.to_string())?;
    }
    if let Some(uri) = source_uri {
        validate::validate_source_uri(uri).map_err(|e| e.to_string())?;
    }
    if let Some(v) = valid_until {
        validate::validate_valid_at(v).map_err(|e| e.to_string())?;
    }

    let metadata = if params["metadata"].is_object() {
        let m = params["metadata"].clone();
        validate::validate_metadata(&m).map_err(|e| e.to_string())?;
        // Preserve existing metadata.agent_id — provenance is immutable.
        // Without this, any MCP caller could rewrite the author of any memory.
        let existing = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .map_or_else(|| serde_json::json!({}), |m| m.metadata);
        let mut merged = crate::identity::preserve_provenance_keys(&existing, &m);
        // v0.9.0 §25.3 S1 (D3-012, #1870) — a caller mutating metadata
        // can NOT carry (or forge) a `loader_observed` model-family
        // attestation: only the substrate loader may assert it. Downgrade
        // to `claimed` (fail-safe: attestation is only ever LOST here).
        crate::identity::downgrade_loader_attest_on_caller_mutation(&mut merged);
        Some(merged)
    } else {
        None
    };

    // v0.7.0 H1 (HIGH) — write-gate parity for the mutating `update`
    // verb. Pre-fix, `memory_update` mutated stored rows WITHOUT
    // passing through the K9 permission gate or the K3/Task-1.9
    // governance gate that `memory_store` / `memory_delete` /
    // `memory_promote` all enforce — so a namespace that denies stores
    // could be written-around by storing once then patching, and an
    // update could mutate a row in a governed namespace ungated. An
    // update is a store-class mutation: we gate it under the SAME
    // `Op::MemoryStore` / `GovernedAction::Store` policy surface (there
    // is no distinct update-op on the wire). The gate runs against the
    // EFFECTIVE target namespace — the new namespace when the caller is
    // moving the row, else the row's current namespace — so a move INTO
    // a governed namespace is gated by that destination's policy.
    {
        let existing = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
        let effective_namespace = namespace.unwrap_or(existing.namespace.as_str()).to_string();
        // #1600 — `agent_id` was hoisted above (it also drives the
        // omitted-`edit_source` default).
        let mem_owner = existing
            .metadata
            .get(param_names::AGENT_ID)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let gate_payload = json!({
            "id": resolved_id,
            "title": title.unwrap_or(existing.title.as_str()),
            "namespace": effective_namespace,
        });

        use crate::permissions::{Op, PermissionContext, Permissions};
        let ctx = PermissionContext {
            op: Op::MemoryStore,
            namespace: effective_namespace.clone(),
            agent_id: agent_id.clone(),
            payload: gate_payload.clone(),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    "update",
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": "update",
                    "memory_id": resolved_id,
                }));
            }
        }

        use crate::models::{GovernanceDecision, GovernedAction};
        // v0.9.0 G10.1 (#1827) — edge-parse the optional `capability`
        // param ONCE; inert unless `[capabilities].enabled`.
        let capability = crate::governance::capability::parse_presented_token(
            params[param_names::CAPABILITY].as_str(),
            &agent_id,
        );
        match db::enforce_governance(
            conn,
            GovernedAction::Store,
            &effective_namespace,
            &agent_id,
            Some(&resolved_id),
            mem_owner.as_deref(),
            &gate_payload,
            capability.as_ref(),
        )
        .map_err(|e| e.to_string())?
        {
            GovernanceDecision::Allow => {}
            GovernanceDecision::Deny(refusal) => {
                return Err(crate::governance::deny_message(
                    "update",
                    crate::governance::DenyGate::Governance,
                    &refusal.reason,
                ));
            }
            GovernanceDecision::Pending(pending_id) => {
                return Ok(json!({
                    "status": "pending",
                    "pending_id": pending_id,
                    "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                    "action": "update",
                    "memory_id": resolved_id,
                }));
            }
        }
    }

    // v0.7.0 Provenance Gap 5 (#888) — append-and-archive branch.
    // When `edit_source` is `Llm` or `Hook`, we archive the OLD row
    // with `archive_reason='superseded'`, then mint a NEW row
    // carrying the patched content + a `supersedes` link new→old.
    // Caller's `expected_version` is still honored as the gate.
    if edit_source.appends_and_archives() {
        let result = db::update_with_archive_on_supersede(
            conn,
            &resolved_id,
            title,
            content,
            tier.as_ref(),
            namespace,
            tags.as_ref(),
            priority,
            confidence,
            expires_at,
            metadata.as_ref(),
            source_uri,
            expected_version,
            edit_source,
        )
        .map_err(|e| conflict_or_string(&e))?;
        // Re-embed the NEW row when content changed.
        if let Some(emb) = embedder {
            let new_id = &result.new_id;
            let mem = db::get(conn, new_id).map_err(|e| e.to_string())?;
            if let Some(ref m) = mem {
                let text = crate::embeddings::embedding_document(&m.title, &m.content);
                if let Ok(embedding) = emb.embed(&text) {
                    let _ = db::set_embedding(conn, new_id, &embedding, &emb.space_fingerprint());
                    if let Some(idx) = vector_index {
                        idx.remove(new_id);
                        idx.insert(new_id.clone(), embedding);
                    }
                }
            }
        }
        let new_mem = db::get(conn, &result.new_id).map_err(|e| e.to_string())?;
        return Ok(json!({
            "updated": true,
            "edit_source": edit_source.as_str(),
            "memory": new_mem,
            "superseded_id": result.archived_id,
            "new_id": result.new_id,
        }));
    }

    // FBL-12 (v1.0.0 pre-ship 3x7) — charge the storage-byte GROWTH of
    // this in-place update against the row OWNER's per-namespace storage
    // cap BEFORE the write lands. Pre-fix every update funnel (this MCP
    // path, the HTTP PUT path, and the #1974 content_append/replace patch
    // assembled above) skipped the quota entirely — only `insert` charged
    // it — so an agent could grow each stored row to MAX_CONTENT_SIZE
    // while its `current_storage_bytes` counter reflected only the
    // store-time bytes (an unbounded-growth bypass of the per-agent
    // storage cap). Keyed on the immutable row owner (`metadata.agent_id`)
    // + effective namespace; a legacy-unowned row (empty owner) is
    // uncharged, mirroring the insert path's `if !agent_id.is_empty()`.
    let quota_charge: Option<(String, String, i64)> = {
        let existing = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
        let owner = existing
            .metadata
            .get(param_names::AGENT_ID)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if owner.is_empty() {
            None
        } else {
            let eff_ns = namespace.unwrap_or(existing.namespace.as_str()).to_string();
            let new_meta = metadata
                .clone()
                .unwrap_or_else(|| existing.metadata.clone());
            let new_title = title.unwrap_or(existing.title.as_str());
            let new_content = content.unwrap_or(existing.content.as_str());
            let new_bytes =
                crate::quotas::coordination_payload_bytes(&[new_title, new_content], &[&new_meta]);
            let old_bytes = crate::quotas::coordination_payload_bytes(
                &[&existing.title, &existing.content],
                &[&existing.metadata],
            );
            match crate::quotas::charge_update_growth(conn, &owner, &eff_ns, old_bytes, new_bytes) {
                Ok(0) => None,
                Ok(delta) => Some((owner, eff_ns, delta)),
                Err(crate::quotas::QuotaCheckError::Quota(qe)) => return Err(qe.to_string()),
                Err(crate::quotas::QuotaCheckError::Sql(se)) => {
                    return Err(format!("quota check failed: {se}"));
                }
            }
        }
    };

    let (found, content_changed) = match db::update_with_expected_version(
        conn,
        &resolved_id,
        title,
        content,
        tier.as_ref(),
        namespace,
        tags.as_ref(),
        priority,
        confidence,
        expires_at,
        metadata.as_ref(),
        source_uri,
        expected_version,
        // v1.0.0 #1834 — opt-in valid_until patch (valid_from immutable).
        valid_until,
    ) {
        Ok(v) => v,
        Err(e) => {
            // FBL-12 — refund the growth charge when the write itself
            // fails (e.g. a VersionConflict) so a retry storm on a
            // conflicting update cannot slowly inflate the counter.
            if let Some((ref owner, ref ns, delta)) = quota_charge {
                let _ = crate::quotas::refund_storage_only(conn, owner, ns, delta);
            }
            return Err(conflict_or_string(&e));
        }
    };

    if !found {
        // FBL-12 — refund on the not-found tail (the row vanished
        // between the charge and the write); the growth never landed.
        if let Some((ref owner, ref ns, delta)) = quota_charge {
            let _ = crate::quotas::refund_storage_only(conn, owner, ns, delta);
        }
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    }

    // v0.8.0 Pillar 2 (#1709) — lifecycle transition enforcement. When the
    // caller supplies a `lifecycle_state` that DIFFERS from the stored
    // value, enforce `current.can_transition_to(requested)` (the typed
    // state machine in `models::LifecycleState`). An illegal transition is
    // rejected with a clear error; a legal one is persisted (and bumps the
    // Gap-1 `version`). A request equal to the stored state is a no-op (no
    // self-loop, no error). This is the consumer that makes the column
    // load-bearing rather than inert.
    if let Some(requested) = requested_lifecycle {
        let current = db::get(conn, &resolved_id)
            .map_err(|e| e.to_string())?
            .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?
            .lifecycle_state;
        if requested != current {
            if !current.can_transition_to(requested) {
                return Err(format!(
                    "illegal lifecycle transition '{}' -> '{}' (legal: {})",
                    current.as_str(),
                    requested.as_str(),
                    LifecycleState::all()
                        .iter()
                        .filter(|s| current.can_transition_to(**s))
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("|"),
                ));
            }
            db::set_lifecycle_state(conn, &resolved_id, requested).map_err(|e| e.to_string())?;
        }
    }

    // Regenerate embedding when title or content changed
    if content_changed && let Some(emb) = embedder {
        let mem = db::get(conn, &resolved_id).map_err(|e| e.to_string())?;
        if let Some(ref m) = mem {
            let text = crate::embeddings::embedding_document(&m.title, &m.content);
            if let Ok(embedding) = emb.embed(&text) {
                let _ = db::set_embedding(conn, &resolved_id, &embedding, &emb.space_fingerprint());
                if let Some(idx) = vector_index {
                    idx.remove(&resolved_id);
                    idx.insert(resolved_id.clone(), embedding);
                }
            }
        }
    }

    let mem = db::get(conn, &resolved_id).map_err(|e| e.to_string())?;
    Ok(json!({
        "updated": true,
        "edit_source": edit_source.as_str(),
        "memory": mem,
    }))
}

/// v0.7.0 Provenance Gap 1 (#884) — emit a structured CONFLICT
/// envelope as a JSON string when the underlying storage layer
/// returns a typed [`VersionConflict`]. Other errors stringify
/// verbatim so existing callers and tests continue to see the
/// historic error text.
fn conflict_or_string(e: &anyhow::Error) -> String {
    if let Some(vc) = e.downcast_ref::<VersionConflict>() {
        json!({
            "status": "conflict",
            "id": vc.id,
            "expected_version": vc.expected,
            "current_version": vc.current,
        })
        .to_string()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    //! L0.7-3 Tier B chunk-A — coverage tests for `handle_update`.
    //!
    //! Six-category template:
    //! A. happy path — title/content/tier/namespace/tags/priority/confidence/expires_at/metadata
    //! B. validation — every gated branch
    //! D. state-dependent — id not found
    //! E. idempotency — repeat update yields same shape
    //! Embedder-bound: `None` path AND `Some(&dyn Embed)` path (re-embed on content change)

    use super::*;
    use crate::embeddings::test_support::MockEmbedder;
    use crate::hnsw::VectorIndex;
    use crate::models::{Memory, Tier as MTier};
    use crate::storage as db;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn make_mem(title: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: MTier::Mid,
            namespace: "test".to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: vec!["a".to_string()],
            priority: 5,
            confidence: 0.5,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:owner"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    // FBL-12 (v1.0.0 pre-ship 3x7) — a content-growing in-place update
    // charges the storage-byte GROWTH against the row OWNER's storage
    // quota. Pre-fix every update funnel charged ZERO, so an agent could
    // grow each row toward MAX_CONTENT_SIZE while its
    // `current_storage_bytes` counter stayed at the store-time value — an
    // unbounded-growth bypass of the per-agent storage cap.
    #[test]
    fn fbl12_content_growing_update_charges_storage_quota() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("quota-grow"); // owner "ai:owner", namespace "test"
        let id = db::insert(&conn, &mem).expect("ins");
        let before = crate::quotas::get_status(&conn, "ai:owner", "test")
            .expect("status")
            .current_storage_bytes;
        let big = "x".repeat(20_000);
        handle_update(
            &conn,
            &json!({ "id": id, "content": big }),
            None,
            None,
            None,
        )
        .expect("update ok");
        let after = crate::quotas::get_status(&conn, "ai:owner", "test")
            .expect("status")
            .current_storage_bytes;
        assert!(
            after >= before + 15_000,
            "content growth must charge the storage-bytes delta (before={before}, after={after})"
        );
    }

    // FBL-12 — a SHRINKING update charges nothing: the caller can never
    // bank negative storage credit, and a shrink is never refused.
    #[test]
    fn fbl12_shrinking_update_charges_nothing() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mut mem = make_mem("quota-shrink");
        mem.content = "y".repeat(10_000);
        let id = db::insert(&conn, &mem).expect("ins");
        let before = crate::quotas::get_status(&conn, "ai:owner", "test")
            .expect("status")
            .current_storage_bytes;
        handle_update(
            &conn,
            &json!({ "id": id, "content": "tiny" }),
            None,
            None,
            None,
        )
        .expect("update ok");
        let after = crate::quotas::get_status(&conn, "ai:owner", "test")
            .expect("status")
            .current_storage_bytes;
        assert_eq!(
            before, after,
            "a shrink must not change the storage counter"
        );
    }

    // A. happy path — update multiple fields, no embedder
    #[test]
    fn happy_path_updates_all_fields_no_embedder() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("orig");
        let id = db::insert(&conn, &mem).expect("ins");
        let out = handle_update(
            &conn,
            &json!({
                "id": id,
                "title": "new title",
                "content": "new body content here",
                "tier": MTier::Long.as_str(),
                "namespace": "ns2",
                "tags": ["x", "y"],
                "priority": 7,
                "confidence": 0.9,
                "expires_at": "2030-01-01T00:00:00Z",
                "metadata": {"k": "v"},
            }),
            None,
            None,
            None,
        )
        .expect("ok");
        assert_eq!(out["updated"].as_bool(), Some(true));
        let m = &out["memory"];
        assert_eq!(m["title"].as_str(), Some("new title"));
        assert_eq!(m["namespace"].as_str(), Some("ns2"));
        // agent_id immutability preserved
        assert_eq!(
            m["metadata"]["agent_id"].as_str(),
            Some("ai:owner"),
            "agent_id must be preserved through update"
        );
    }

    // A. prefix resolution branch
    #[test]
    fn prefix_resolution_branch() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mut mem = make_mem("p");
        mem.id = "fedcba98-1111-2222-3333-444455556666".to_string();
        let _ = db::insert(&conn, &mem).expect("ins");
        let out = handle_update(
            &conn,
            &json!({"id": "fedcba98", "title": "renamed"}),
            None,
            None,
            None,
        )
        .expect("prefix ok");
        assert_eq!(out["memory"]["title"].as_str(), Some("renamed"));
    }

    // Embedder Some-path: content changed → re-embed + index touched
    #[test]
    fn embedder_some_path_reembeds_when_content_changes() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("xyz");
        let id = db::insert(&conn, &mem).expect("ins");
        let mock = MockEmbedder::new_local().expect("mock");
        let idx = VectorIndex::empty();
        let out = handle_update(
            &conn,
            &json!({"id": id.clone(), "content": "completely new content"}),
            Some(&mock as &dyn crate::embeddings::Embed),
            Some(&idx),
            None,
        )
        .expect("ok");
        assert_eq!(out["updated"].as_bool(), Some(true));
        // embedding was written
        let emb = db::get_embedding(&conn, &id).expect("ok").expect("some");
        assert_eq!(emb.len(), 384);
    }

    // Embedder Some-path but no content change (only tags) → no re-embed
    #[test]
    fn embedder_some_path_skips_when_content_unchanged() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("nochange");
        let id = db::insert(&conn, &mem).expect("ins");
        let mock = MockEmbedder::new_local().expect("mock");
        let out = handle_update(
            &conn,
            &json!({"id": id.clone(), "tags": ["new-tag"]}),
            Some(&mock as &dyn crate::embeddings::Embed),
            None,
            None,
        )
        .expect("ok");
        assert_eq!(out["updated"].as_bool(), Some(true));
        // no embedding stored
        let emb = db::get_embedding(&conn, &id).expect("ok");
        assert!(emb.is_none());
    }

    // B. missing id
    #[test]
    fn missing_id_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let err = handle_update(&conn, &json!({}), None, None, None).unwrap_err();
        assert!(err.contains("id is required"));
    }

    // B. invalid id format
    #[test]
    fn invalid_id_format_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let err = handle_update(&conn, &json!({"id": ""}), None, None, None).unwrap_err();
        assert!(!err.is_empty());
    }

    // D. id not found
    #[test]
    fn unknown_id_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let err = handle_update(
            &conn,
            &json!({"id": "11111111-aaaa-bbbb-cccc-dddddddddddd", "title": "x"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("not found"));
    }

    // B. invalid title (empty)
    #[test]
    fn invalid_title_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err =
            handle_update(&conn, &json!({"id": id, "title": ""}), None, None, None).unwrap_err();
        assert!(!err.is_empty());
    }

    // B. invalid content (empty)
    #[test]
    fn invalid_content_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err =
            handle_update(&conn, &json!({"id": id, "content": ""}), None, None, None).unwrap_err();
        assert!(!err.is_empty());
    }

    // B. invalid namespace (has space)
    #[test]
    fn invalid_namespace_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err = handle_update(
            &conn,
            &json!({"id": id, "namespace": "has space"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // B. invalid priority (out of range)
    #[test]
    fn invalid_priority_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err =
            handle_update(&conn, &json!({"id": id, "priority": 99}), None, None, None).unwrap_err();
        assert!(!err.is_empty());
    }

    // B. invalid confidence
    #[test]
    fn invalid_confidence_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err = handle_update(
            &conn,
            &json!({"id": id, "confidence": 5.0}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // B. invalid expires_at format
    #[test]
    fn invalid_expires_at_errors() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("ins");
        let err = handle_update(
            &conn,
            &json!({"id": id, "expires_at": "not-a-date"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // metadata.agent_id immutability when caller tries to overwrite
    #[test]
    fn metadata_preserves_existing_agent_id() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("immut");
        let id = db::insert(&conn, &mem).expect("ins");
        let out = handle_update(
            &conn,
            &json!({"id": id, "metadata": {"agent_id": "ai:other", "note": "hi"}}),
            None,
            None,
            None,
        )
        .expect("ok");
        assert_eq!(
            out["memory"]["metadata"]["agent_id"].as_str(),
            Some("ai:owner"),
            "agent_id immutable"
        );
        assert_eq!(out["memory"]["metadata"]["note"].as_str(), Some("hi"));
    }

    // E. idempotency
    #[test]
    fn idempotent_repeated_update() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("idem");
        let id = db::insert(&conn, &mem).expect("ins");
        let one = handle_update(&conn, &json!({"id": &id, "priority": 8}), None, None, None)
            .expect("ok 1");
        let two = handle_update(&conn, &json!({"id": &id, "priority": 8}), None, None, None)
            .expect("ok 2");
        assert_eq!(one["updated"], two["updated"]);
    }

    // v0.7.0 Provenance Gap 5 (#888) — edit_source=llm routes through the
    // append-and-archive supersede write path: the OLD row lands in
    // archived_memories with archive_reason='superseded', a fresh NEW row
    // is minted carrying the patched content + metadata.superseded_id, and
    // the response surfaces `superseded_id` + `new_id`. Covers the
    // `if edit_source.appends_and_archives()` arm in handle_update
    // (lines 107-148), including the embedder Some-path re-embed of the
    // NEW row + vector-index insert.
    #[test]
    fn edit_source_llm_appends_and_archives_with_embedder() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("pre-supersede");
        let id = db::insert(&conn, &mem).expect("ins");
        let mock = MockEmbedder::new_local().expect("mock");
        let idx = VectorIndex::empty();
        let out = handle_update(
            &conn,
            &json!({
                "id": &id,
                "content": "llm-rewritten content body",
                "edit_source": "llm",
            }),
            Some(&mock as &dyn crate::embeddings::Embed),
            Some(&idx),
            None,
        )
        .expect("supersede ok");
        assert_eq!(out["updated"].as_bool(), Some(true));
        assert_eq!(out["edit_source"].as_str(), Some("llm"));
        // archived_id == original id; new_id is a freshly-minted uuid
        assert_eq!(out["superseded_id"].as_str(), Some(id.as_str()));
        let new_id = out["new_id"].as_str().expect("new_id present");
        assert_ne!(new_id, id);
        // NEW row carries the patched content + superseded_id pointer
        let new_mem = &out["memory"];
        assert_eq!(
            new_mem["content"].as_str(),
            Some("llm-rewritten content body")
        );
        assert_eq!(
            new_mem["metadata"]["superseded_id"].as_str(),
            Some(id.as_str())
        );
        // Embedding written for the NEW row, indexed by new_id
        let emb = db::get_embedding(&conn, new_id)
            .expect("emb ok")
            .expect("some");
        assert_eq!(emb.len(), 384);
    }

    // v0.7.0 Provenance Gap 5 (#888) — edit_source=hook variant of the
    // append-and-archive path WITHOUT an embedder. Covers the Hook arm of
    // `EditSource::appends_and_archives()`, plus the None-embedder branch
    // inside the supersede block (lines 126 falsy path), AND the
    // happy-path return for the supersede shape (lines 141-147).
    #[test]
    fn edit_source_hook_appends_and_archives_no_embedder() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("pre-hook");
        let id = db::insert(&conn, &mem).expect("ins");
        let out = handle_update(
            &conn,
            &json!({
                "id": &id,
                "title": "hook-edited title",
                "edit_source": "hook",
            }),
            None,
            None,
            None,
        )
        .expect("hook supersede ok");
        assert_eq!(out["edit_source"].as_str(), Some("hook"));
        assert_eq!(out["superseded_id"].as_str(), Some(id.as_str()));
        let new_id = out["new_id"].as_str().expect("new_id present");
        assert_ne!(new_id, id);
        assert_eq!(out["memory"]["title"].as_str(), Some("hook-edited title"));
        // No embedder → no embedding row for the new id.
        assert!(
            db::get_embedding(&conn, new_id).expect("ok").is_none(),
            "no embedder ⇒ no embedding persisted on the new row"
        );
    }

    // v0.7.0 Provenance Gap 1 (#884) — when `expected_version` is supplied
    // and drifts from the stored row's version, the storage layer returns
    // a typed VersionConflict; handle_update funnels it through
    // `conflict_or_string`, which emits a JSON CONFLICT envelope as the
    // Err string. Covers lines 165 (map_err on the in-place path) +
    // 199-208 (the VersionConflict downcast arm) end-to-end.
    #[test]
    fn expected_version_conflict_returns_json_envelope() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("verconflict");
        let id = db::insert(&conn, &mem).expect("ins");
        // Bump version to 2 with a no-expectation update, so the next
        // expected_version=1 call drifts.
        let _ = handle_update(&conn, &json!({"id": &id, "priority": 6}), None, None, None)
            .expect("bump");
        let err = handle_update(
            &conn,
            &json!({
                "id": &id,
                "title": "stale write",
                "expected_version": 1,
            }),
            None,
            None,
            None,
        )
        .unwrap_err();
        // Err is the JSON CONFLICT envelope minted by conflict_or_string.
        let v: serde_json::Value = serde_json::from_str(&err).expect("json envelope");
        assert_eq!(v["status"].as_str(), Some("conflict"));
        assert_eq!(v["id"].as_str(), Some(id.as_str()));
        assert_eq!(v["expected_version"].as_i64(), Some(1));
        assert_eq!(v["current_version"].as_i64(), Some(2));
    }

    // v0.7.0 Provenance Gap 2 (#906) — source_uri opt-in patch is
    // validated before the storage write. Covers the
    // `if let Some(uri) = source_uri { validate::validate_source_uri(...) }`
    // arm at lines 85-87 — both the happy validate-pass branch and the
    // reject branch for a bare string without a recognised scheme.
    #[test]
    fn source_uri_valid_passes_through_and_invalid_rejects() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("srcuri");
        let id = db::insert(&conn, &mem).expect("ins");
        // Happy: doc: scheme is accepted by validate_source_uri.
        let ok = handle_update(
            &conn,
            &json!({"id": &id, "source_uri": "doc:internal-ref-42"}),
            None,
            None,
            None,
        )
        .expect("valid source_uri");
        assert_eq!(ok["updated"].as_bool(), Some(true));
        assert_eq!(
            ok["memory"]["source_uri"].as_str(),
            Some("doc:internal-ref-42")
        );
        // Reject: bare string without a recognised scheme.
        let err = handle_update(
            &conn,
            &json!({"id": &id, "source_uri": "example.com/no-scheme"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(!err.is_empty(), "source_uri must be rejected");
        assert!(
            err.to_lowercase().contains("source uri")
                || err.to_lowercase().contains("source_uri")
                || err.to_lowercase().contains("scheme"),
            "error should reference source uri / scheme; got: {err}"
        );
    }

    // v0.7.0 H1 (HIGH) regression — the mutating `update` verb must pass
    // through the same write-gate as `store`/`delete`/`promote`. Install
    // a `write: Owner` governance policy on a namespace, then attempt an
    // update by a non-owner agent and assert it is denied. Pre-fix this
    // returned Ok(updated) because `handle_update` never consulted
    // governance.
    fn install_write_owner_policy(conn: &rusqlite::Connection, ns: &str, owner: &str) {
        use crate::models::{ApproverType, CorePolicy, GovernancePolicy, default_metadata};
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: crate::models::GovernanceLevel::Owner,
                approver: ApproverType::Human,
                ..CorePolicy::default()
            },
            ..Default::default()
        };
        let mut metadata = default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String(owner.to_string()),
            );
            obj.insert(
                "governance".to_string(),
                serde_json::to_value(&policy).unwrap(),
            );
        }
        let mut standard = make_mem("std");
        standard.namespace = format!("_standards-{ns}");
        standard.title = format!("std-{ns}");
        standard.metadata = metadata;
        let sid = db::insert(conn, &standard).expect("insert standard");
        db::set_namespace_standard(conn, ns, &sid, None).expect("set standard");
    }

    #[test]
    fn governance_deny_blocks_update_by_non_owner() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let _gate = crate::config::lock_permissions_mode_for_test();
        crate::config::override_active_permissions_mode_for_test(
            crate::config::PermissionsMode::Enforce,
        );
        let conn = fresh_conn();
        let ns = "gov-deny-upd";
        install_write_owner_policy(&conn, ns, "ai:alice");
        let mut mem = make_mem("target");
        mem.namespace = ns.to_string();
        mem.metadata = json!({"agent_id": "ai:alice"});
        let id = db::insert(&conn, &mem).expect("insert");
        let err = handle_update(
            &conn,
            &json!({"id": id, "title": "evil rewrite", "agent_id": "ai:eve"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("governance") || err.contains("denied") || err.contains("owner"),
            "non-owner update must be gated; got: {err}"
        );
        crate::config::clear_permissions_mode_override_for_test();
    }

    /// v0.7.x issue #1600 regression — explicit `edit_source: "agent"`
    /// is honoured: in-place mutation (NO append-and-archive — same id,
    /// no superseded_id/new_id in the response) and the response echoes
    /// `edit_source = "agent"`.
    #[test]
    fn issue_1600_explicit_agent_edit_source_mutates_in_place() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("agent-inplace");
        let id = db::insert(&conn, &mem).expect("ins");
        let out = handle_update(
            &conn,
            &json!({
                "id": &id,
                "content": "agent-edited content body",
                "edit_source": "agent",
            }),
            None,
            None,
            None,
        )
        .expect("agent edit ok");
        assert_eq!(out["updated"].as_bool(), Some(true));
        assert_eq!(out["edit_source"].as_str(), Some("agent"));
        assert!(
            out.get("superseded_id").is_none() && out.get("new_id").is_none(),
            "#1600: agent edits must NOT route append-and-archive"
        );
        assert_eq!(out["memory"]["id"].as_str(), Some(id.as_str()));
        assert_eq!(
            out["memory"]["content"].as_str(),
            Some("agent-edited content body")
        );
    }

    /// v0.7.x issue #1600 regression — an UNKNOWN `edit_source` value
    /// is a validation ERROR naming the valid set (pre-fix it silently
    /// defaulted to Human and mutated in place).
    #[test]
    fn issue_1600_unknown_edit_source_errors_listing_valid_values() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("robot-reject");
        let id = db::insert(&conn, &mem).expect("ins");
        let err = handle_update(
            &conn,
            &json!({"id": &id, "title": "should not land", "edit_source": "robot"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("invalid edit_source 'robot'"),
            "must name the rejected value; got: {err}"
        );
        for valid in EditSource::ALL {
            assert!(
                err.contains(valid.as_str()),
                "error must list '{}' in the valid set; got: {err}",
                valid.as_str()
            );
        }
        // The silently-defaulting pre-fix behaviour mutated the row.
        let row = db::get(&conn, &id).expect("get").expect("row");
        assert_eq!(row.title, "robot-reject", "row must be untouched");
    }

    /// v0.7.x issue #1600 regression — OMITTED `edit_source` derives
    /// from the resolved caller agent id: an `ai:`-prefixed NHI caller
    /// defaults to `agent` (in-place), every other shape keeps the
    /// historical `human` default.
    #[test]
    fn issue_1600_omitted_edit_source_derives_from_caller_id() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("derive-default");
        let id = db::insert(&conn, &mem).expect("ins");
        // ai:-prefixed caller → agent.
        let out = handle_update(
            &conn,
            &json!({"id": &id, "priority": 7, "agent_id": "ai:grok-4@dogfood:pid-9"}),
            None,
            None,
            None,
        )
        .expect("ok");
        assert_eq!(
            out["edit_source"].as_str(),
            Some("agent"),
            "#1600: omitted edit_source + ai:-prefixed caller must default to agent"
        );
        assert!(out.get("new_id").is_none(), "agent default stays in-place");
        // Non-NHI caller shape → human (the historical default).
        let out = handle_update(
            &conn,
            &json!({"id": &id, "priority": 8, "agent_id": "host:box-1"}),
            None,
            None,
            None,
        )
        .expect("ok");
        assert_eq!(
            out["edit_source"].as_str(),
            Some("human"),
            "non-ai callers keep the historical human default"
        );
    }

    #[test]
    fn governance_allows_update_in_ungoverned_namespace() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        // Default (no namespace standard) → write-gate is transparent.
        let conn = fresh_conn();
        let mem = make_mem("ok");
        let id = db::insert(&conn, &mem).expect("insert");
        let out = handle_update(
            &conn,
            &json!({"id": id, "title": "fine rewrite"}),
            None,
            None,
            None,
        )
        .expect("ungoverned update should pass the gate");
        assert_eq!(out["updated"].as_bool(), Some(true));
    }

    // v0.8.0 Pillar 2 (#1709) — lifecycle transition enforcement on the
    // `memory_update` path. A legal advance persists; an illegal one is
    // rejected with a typed error; a no-op (same state) succeeds silently.

    #[test]
    fn lifecycle_legal_open_to_active_to_done_persists() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("lc-legal");
        let id = db::insert(&conn, &mem).expect("insert");
        // Fresh row is `open`.
        let stored = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(stored.lifecycle_state, LifecycleState::Open);
        // open -> active (legal).
        let out = handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "active"}),
            None,
            None,
            None,
        )
        .expect("open->active is legal");
        assert_eq!(out["updated"].as_bool(), Some(true));
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
            LifecycleState::Active
        );
        // active -> done (legal).
        handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "done"}),
            None,
            None,
            None,
        )
        .expect("active->done is legal");
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
            LifecycleState::Done
        );
    }

    #[test]
    fn lifecycle_illegal_open_to_done_is_rejected() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("lc-skip");
        let id = db::insert(&conn, &mem).expect("insert");
        let err = handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "done"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("illegal lifecycle transition")
                && err.contains("open")
                && err.contains("done"),
            "open->done must be rejected; got: {err}"
        );
        // Stored state is unchanged.
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
            LifecycleState::Open
        );
    }

    #[test]
    fn lifecycle_illegal_terminal_done_to_active_is_rejected() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("lc-terminal");
        let id = db::insert(&conn, &mem).expect("insert");
        // Drive to terminal `done` via the legal path.
        handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "active"}),
            None,
            None,
            None,
        )
        .expect("open->active");
        handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "done"}),
            None,
            None,
            None,
        )
        .expect("active->done");
        // done -> active (illegal: terminals go nowhere).
        let err = handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "active"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("illegal lifecycle transition"),
            "done->active must be rejected; got: {err}"
        );
    }

    #[test]
    fn lifecycle_unknown_value_is_rejected() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("lc-bogus");
        let id = db::insert(&conn, &mem).expect("insert");
        let err = handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "frobnicated"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("invalid lifecycle_state"),
            "unknown lifecycle_state must be rejected; got: {err}"
        );
    }

    #[test]
    fn lifecycle_same_state_is_noop_not_error() {
        // #1874 — depends-on-unset AI_MEMORY_AGENT_ID (see mcp::link tests).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let mem = make_mem("lc-noop");
        let id = db::insert(&conn, &mem).expect("insert");
        // open -> open is a no-op (no self-loop, but also no error).
        let out = handle_update(
            &conn,
            &json!({"id": &id, "lifecycle_state": "open"}),
            None,
            None,
            None,
        )
        .expect("open->open must be a silent no-op");
        assert_eq!(out["updated"].as_bool(), Some(true));
        assert_eq!(
            db::get(&conn, &id).unwrap().unwrap().lifecycle_state,
            LifecycleState::Open
        );
    }

    // ---- #1974 content patch primitive (append / unique-match replace) ----

    fn patch_conn_with(content: &str) -> (rusqlite::Connection, String) {
        let conn = fresh_conn();
        let mut mem = make_mem("patch");
        mem.content = content.to_string();
        let id = db::insert(&conn, &mem).expect("ins");
        (conn, id)
    }

    #[test]
    fn content_append_concatenates_onto_current() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("base");
        let out = handle_update(
            &conn,
            &json!({"id": id, "content_append": " tail"}),
            None,
            None,
            None,
        )
        .expect("append ok");
        assert_eq!(out["memory"]["content"].as_str(), Some("base tail"));
        // Auto-captured version threaded → CAS bumped 1 → 2.
        assert_eq!(out["memory"]["version"].as_i64(), Some(2));
    }

    #[test]
    fn content_append_empty_rejected() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("base");
        let err = handle_update(
            &conn,
            &json!({"id": id, "content_append": ""}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("content_append must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn content_replace_unique_ok() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("alpha beta gamma");
        let out = handle_update(
            &conn,
            &json!({"id": id, "content_replace_from": "beta", "content_replace_to": "BETA"}),
            None,
            None,
            None,
        )
        .expect("replace ok");
        assert_eq!(out["memory"]["content"].as_str(), Some("alpha BETA gamma"));
    }

    #[test]
    fn content_replace_not_found_errors() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("alpha beta");
        let err = handle_update(
            &conn,
            &json!({"id": id, "content_replace_from": "zzz", "content_replace_to": "x"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("not found in current content"), "got: {err}");
        // Fail-closed: no bytes changed.
        let after = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(after.content, "alpha beta");
        assert_eq!(after.version, 1);
    }

    #[test]
    fn content_replace_multiple_errors_no_write() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("x x x");
        let err = handle_update(
            &conn,
            &json!({"id": id, "content_replace_from": "x", "content_replace_to": "y"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("matched 3 times"), "got: {err}");
        // No partial write: the row is unchanged (fail-closed on non-unique).
        let after = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(after.content, "x x x");
        assert_eq!(after.version, 1);
    }

    #[test]
    fn content_and_patch_mutually_exclusive() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("base");
        let err = handle_update(
            &conn,
            &json!({"id": id, "content": "full", "content_append": " tail"}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn append_plus_replace_is_rejected() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("a b");
        let err = handle_update(
            &conn,
            &json!({
                "id": id,
                "content_append": " tail",
                "content_replace_from": "a",
                "content_replace_to": "z",
            }),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn empty_patched_result_rejected() {
        // Replacing the entire content with "" assembles an empty result,
        // which validate_content refuses (proves the RESULT is re-validated,
        // not the fragment).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("solo");
        let err = handle_update(
            &conn,
            &json!({"id": id, "content_replace_from": "solo", "content_replace_to": ""}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("content cannot be empty"), "got: {err}");
        // Fail-closed: the original bytes survive the refused delete-to-empty.
        assert_eq!(db::get(&conn, &id).unwrap().unwrap().content, "solo");
    }

    #[test]
    fn patch_version_fail_close_on_stale_expected() {
        // A caller-supplied expected_version that disagrees with the observed
        // version is refused BEFORE any write (TOCTOU fail-close).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("base"); // version == 1
        let err = handle_update(
            &conn,
            &json!({"id": id, "content_append": " tail", "expected_version": 999}),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("conflict"), "got: {err}");
        let after = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(after.content, "base", "no write on version conflict");
    }

    #[test]
    fn patch_matching_expected_version_succeeds() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("base"); // version == 1
        let out = handle_update(
            &conn,
            &json!({"id": id, "content_append": " tail", "expected_version": 1}),
            None,
            None,
            None,
        )
        .expect("matching version ok");
        assert_eq!(out["memory"]["content"].as_str(), Some("base tail"));
    }

    #[test]
    fn patch_preserves_all_non_content_fields() {
        // Data-integrity: a content patch mutates ONLY the durable TEXT; every
        // other field (tags, priority, namespace, confidence, provenance
        // agent_id) is preserved byte-for-byte — identical to what a full
        // `content` replacement does.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("keep-fields");
        let before = db::get(&conn, &id).unwrap().unwrap();
        let out = handle_update(
            &conn,
            &json!({"id": id, "content_append": " +"}),
            None,
            None,
            None,
        )
        .expect("append ok");
        assert_eq!(out["memory"]["content"].as_str(), Some("keep-fields +"));
        let after = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(after.tags, before.tags);
        assert_eq!(after.priority, before.priority);
        assert_eq!(after.namespace, before.namespace);
        assert!((after.confidence - before.confidence).abs() < f64::EPSILON);
        assert_eq!(after.tier, before.tier);
        assert_eq!(
            after.metadata.get("agent_id"),
            before.metadata.get("agent_id"),
            "immutable provenance agent_id preserved across patch"
        );
    }

    #[test]
    fn patch_leaves_genesis_cid_consistent() {
        // #1825 — the content-id is a GENESIS/immutable content-address that
        // sits ALONGSIDE the UUID; the in-place update path (which the patch
        // threads through) does NOT re-stamp it, so the stored cid stays a
        // stable reference and its cid_genesis pre-image stays consistent (no
        // corruption). This asserts the patch inherits that behaviour exactly.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("genesis body");
        let cid_before = db::get(&conn, &id).unwrap().unwrap().cid;
        assert!(cid_before.is_some(), "insert stamps a genesis cid");
        handle_update(
            &conn,
            &json!({"id": id, "content_append": " edit"}),
            None,
            None,
            None,
        )
        .expect("append ok");
        let after = db::get(&conn, &id).unwrap().unwrap();
        assert_eq!(after.content, "genesis body edit");
        assert_eq!(
            after.cid, cid_before,
            "genesis cid is stable across an in-place content patch"
        );
    }

    #[test]
    fn patch_snapshots_prior_content_for_undo() {
        // #1727 composition: a content-changing patch archives the prior
        // content under archive_reason='in_place_edit' (because it threads
        // through the SAME update_with_expected_version path), so undo-edit
        // can recover the pre-patch text — the durable prior TEXT is never
        // lost. Verified via the archive snapshot slot (encryption off in
        // tests → content column holds plaintext).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let (conn, id) = patch_conn_with("original");
        handle_update(
            &conn,
            &json!({"id": id, "content_replace_from": "original", "content_replace_to": "revised"}),
            None,
            None,
            None,
        )
        .expect("replace ok");
        assert_eq!(db::get(&conn, &id).unwrap().unwrap().content, "revised");
        // The pre-patch content is retrievable from the in_place_edit snapshot.
        let snapshot_content: Option<String> = conn
            .query_row(
                "SELECT content FROM archived_memories \
                 WHERE id = ?1 AND archive_reason = ?2",
                rusqlite::params![id, crate::models::field_names::ARCHIVE_REASON_IN_PLACE_EDIT],
                |r| r.get(0),
            )
            .ok();
        assert_eq!(
            snapshot_content.as_deref(),
            Some("original"),
            "prior TEXT preserved in in_place_edit snapshot for undo"
        );
    }
}
