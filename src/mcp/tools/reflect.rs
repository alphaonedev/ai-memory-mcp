// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_reflect` handler.

use crate::db;
use crate::embeddings::Embed;
use crate::hnsw::VectorSearchIndex;
use crate::mcp::param_names;
use crate::models::field_names;
use crate::models::{GovernedAction, Tier};
use serde_json::{Value, json};
use std::path::Path;

/// v0.7.0 recursive-learning Task 4/8 (issue #655) — handler for the
/// `memory_reflect` MCP tool.
///
/// Wraps [`db::reflect`] (the atomic substrate primitive) with MCP-shape
/// arg parsing, agent_id resolution, embedding generation (best effort),
/// and the post-write subscription dispatch. Returns the JSON envelope
/// `{id, reflection_depth, reflects_on, namespace}` documented in the
/// tool's input schema.
///
/// Errors are returned as plain strings (MCP convention). Substrate
/// errors are matched in arm-priority order so Task 5/8 can plug in the
/// `signed_events` audit emission against the `DepthExceeded` variant
/// without touching the happy-path code.

/// v0.7.0 #1338 — map a substrate-level [`db::ReflectError`] into the
/// stable wire-shaped error string the MCP handler returns.
///
/// Extracted from the inline `match db::reflect_with_hooks(...)` arm
/// inside [`handle_reflect`] so each branch is independently
/// reachable from unit tests — the `HookVeto` and `Database` variants
/// in particular cannot be triggered by an end-to-end `handle_reflect`
/// call today (no MCP-side `pre_reflect` hook is installed, and
/// `Database` requires a SQL fault the test harness can't easily
/// inject) but the wire-string discipline they enforce must still
/// stay pinned by the test suite.
///
/// Stability contract — each branch maps to a stable string prefix:
/// * `Validation(m)` → raw `m` (substrate sets the operator-readable
///   reason; the MCP layer surfaces it verbatim).
/// * `SourceNotFound(id)` → `"source memory not found: <id>"`.
/// * `DepthExceeded { attempted, cap, namespace }` →
///   `"REFLECTION_DEPTH_EXCEEDED: reflection depth N would exceed
///    namespace max_reflection_depth M (namespace='ns')"` — Task 5/8
///   audit emission keys off this prefix.
/// * `HookVeto { reason, code }` →
///   `"REFLECTION_HOOK_VETO (code=C): <reason>"`. Currently
///   unreachable from the MCP dispatch path (no in-substrate hook
///   registered) but pinned so the wire-shape can't drift under a
///   future MCP-side hook wire-in.
/// * `Database(m)` → raw `m`.
pub(crate) fn map_reflect_error_to_wire_string(err: db::ReflectError) -> String {
    match err {
        db::ReflectError::Validation(m) => m,
        db::ReflectError::SourceNotFound(id) => format!("source memory not found: {id}"),
        db::ReflectError::DepthExceeded {
            attempted,
            cap,
            namespace,
        } => {
            // Stable error string shape — Task 5/8 will key its audit
            // emission off this refusal. Keep the structured triple
            // visible (attempted=N, cap=M, namespace='...') so the
            // log analyser doesn't need a regex.
            format!(
                "REFLECTION_DEPTH_EXCEEDED: reflection depth {attempted} would exceed \
                 namespace max_reflection_depth {cap} (namespace='{namespace}')"
            )
        }
        db::ReflectError::HookVeto { reason, code } => {
            // v0.7.0 Task 6/8 — a pre_reflect hook callback returned
            // Deny, vetoing the reflection. The MCP handler today
            // does NOT register any in-substrate hooks (the MCP-side
            // hook chain wiring is G7+'s problem), so this arm is
            // currently unreachable on the MCP path. We surface a
            // stable error-string shape anyway so a future MCP-side
            // hook wire-in lands without churning this arm.
            format!("REFLECTION_HOOK_VETO (code={code}): {reason}")
        }
        db::ReflectError::DecorrelationRefused {
            distinct_attested_families,
            attested_rows,
            quorum_n,
            namespace,
        } => {
            // v0.9.0 §25.3 S2 (D3-021, #1767) — enforce-mode refusal on an
            // evidence-backed attested monoculture. Stable string shape
            // keyed off `REFLECTION_DECORRELATION_REFUSED` (matches the
            // signed audit event slug) with the structured counts visible.
            format!(
                "REFLECTION_DECORRELATION_REFUSED: attested model-family decorrelation quorum not \
                 met ({distinct_attested_families} distinct attested families across \
                 {attested_rows} attested rows < required {quorum_n}, namespace='{namespace}')"
            )
        }
        db::ReflectError::Database(m) => m,
    }
}

/// v0.7.1 #1665 — desugar the top-level `entity_id` convenience param
/// into the canonical `metadata.entity_id` key.
///
/// Precedence is **metadata-wins**: when `metadata.entity_id` is already
/// present and non-blank it is left untouched, and a differing top-level
/// alias is logged at warn-level (shadowed). A blank / whitespace-only
/// `top_level` is treated as absent (mirrors the trim+non-empty filter the
/// write-time extractor applies in `crate::storage::extract_mentioned_entity_id`
/// and the runtime resolver in `crate::hooks::post_reflect::auto_persona::resolve_entity_id`).
///
/// Called by BOTH reflect parsers ([`parse_reflect_input`] for the SAL/HTTP
/// path and [`handle_reflect`] for the stdio path) before the
/// [`db::ReflectInput`] is built, so the binding rides through identically
/// on every backend AND through the L1-8 pending → execute round-trip (the
/// payload serialises the already-desugared `input.metadata`).
fn fold_entity_id_into_metadata(metadata: &mut Value, top_level: Option<&str>) {
    let Some(alias) = top_level.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    let existing = metadata
        .get(field_names::ENTITY_ID)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match existing {
        Some(present) => {
            if present != alias {
                tracing::warn!(
                    target: "mcp.reflect",
                    "top-level entity_id alias shadowed by metadata.entity_id (using metadata)"
                );
            }
        }
        None => {
            if !metadata.is_object() {
                *metadata = serde_json::json!({});
            }
            metadata[field_names::ENTITY_ID] = Value::String(alias.to_string());
        }
    }
}

/// Parse a `memory_reflect` request `Value` into a [`db::ReflectInput`]
/// plus the optional caller-asserted `depth` (#1325). Shared by the
/// sqlite MCP path ([`handle_reflect`]) and the postgres SAL HTTP path
/// ([`crate::handlers::route_1111::handle_reflect_http`]) so the wire
/// argument contract lives in exactly one place.
///
/// # Errors
/// Returns a wire-ready error string when a required field is missing
/// or malformed (`source_ids`, `title`, `content`, `tier`, `depth`).
// Only the postgres SAL HTTP branch (sal-gated) calls this in a non-test
// build; the unit tests below exercise it in every feature set.
#[cfg_attr(not(feature = "sal"), allow(dead_code))]
pub(crate) fn parse_reflect_input(
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<(db::ReflectInput, Option<i64>), String> {
    let source_ids_arr = params[param_names::SOURCE_IDS]
        .as_array()
        .ok_or("source_ids is required (array of memory IDs)")?;
    if source_ids_arr.is_empty() {
        return Err("source_ids cannot be empty".to_string());
    }
    let mut source_ids: Vec<String> = Vec::with_capacity(source_ids_arr.len());
    for (i, v) in source_ids_arr.iter().enumerate() {
        match v.as_str() {
            Some(s) => source_ids.push(s.to_string()),
            None => return Err(format!("source_ids[{i}] must be a string")),
        }
    }
    let title = params["title"]
        .as_str()
        .ok_or(crate::errors::msg::TITLE_REQUIRED)?
        .to_string();
    let content = params["content"]
        .as_str()
        .ok_or(crate::errors::msg::CONTENT_REQUIRED)?
        .to_string();
    let tier_str = params["tier"].as_str().unwrap_or(Tier::Mid.as_str());
    let tier =
        Tier::from_str(tier_str).ok_or_else(|| crate::errors::msg::invalid("tier", tier_str))?;
    let namespace = params["namespace"].as_str().map(str::to_string);
    let priority = i32::try_from(params["priority"].as_i64().unwrap_or(5)).unwrap_or(5);
    let confidence = params[param_names::CONFIDENCE].as_f64().unwrap_or(1.0);
    let tags: Vec<String> = params["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut metadata = if params["metadata"].is_object() {
        params["metadata"].clone()
    } else {
        serde_json::json!({})
    };
    let caller_depth: Option<i64> = params
        .get(param_names::DEPTH)
        .and_then(serde_json::Value::as_i64);
    if let Some(d) = caller_depth {
        if d < 0 {
            return Err(format!(
                "CALLER_DEPTH_MISMATCH: depth must be a non-negative integer (got depth={d})"
            ));
        }
    }
    let explicit_agent_id = params["agent_id"].as_str().or_else(|| {
        metadata
            .get(param_names::AGENT_ID)
            .and_then(serde_json::Value::as_str)
    });
    let agent_id = crate::identity::resolve_agent_id(explicit_agent_id, mcp_client)
        .map_err(|e| e.to_string())?;
    // v0.7.1 #1665 — desugar the top-level `entity_id` convenience param
    // into `metadata.entity_id` before building the input, so the binding
    // is identical across both reflect parsers and the L1-8 round-trip.
    fold_entity_id_into_metadata(&mut metadata, params[param_names::ENTITY_ID].as_str());
    let input = db::ReflectInput {
        source_ids,
        title,
        content,
        namespace,
        tier,
        tags,
        priority,
        confidence,
        // Vendor-neutral substrate default (#1175) — role-categorical,
        // not vendor; NHI identity lives in `metadata.agent_id`.
        source: crate::validate::DEFAULT_NHI_SOURCE.to_string(),
        agent_id,
        metadata,
    };
    Ok((input, caller_depth))
}

pub fn handle_reflect(
    conn: &rusqlite::Connection,
    db_path: &Path,
    params: &Value,
    embedder: Option<&dyn Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    mcp_client: Option<&str>,
    // Issue #815 — when `Some`, every `reflects_on` edge written by
    // this reflect call is signed with this keypair. When `None`
    // (operator hasn't generated a daemon keypair, or the caller is
    // a test harness without one) the edges land unsigned, matching
    // the pre-#815 behaviour. Same signature shape as `handle_link`
    // and `handle_persona_generate` use for the H2 link-signing
    // surface so the dispatcher in `mcp::mod` can pass through the
    // shared `active_keypair` argument verbatim.
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> Result<Value, String> {
    // ─── Argument parsing ───────────────────────────────────────────
    let source_ids_arr = params[param_names::SOURCE_IDS]
        .as_array()
        .ok_or("source_ids is required (array of memory IDs)")?;
    if source_ids_arr.is_empty() {
        return Err("source_ids cannot be empty".to_string());
    }
    let mut source_ids: Vec<String> = Vec::with_capacity(source_ids_arr.len());
    for (i, v) in source_ids_arr.iter().enumerate() {
        match v.as_str() {
            Some(s) => source_ids.push(s.to_string()),
            None => return Err(format!("source_ids[{i}] must be a string")),
        }
    }
    let title = params["title"]
        .as_str()
        .ok_or(crate::errors::msg::TITLE_REQUIRED)?
        .to_string();
    let content = params["content"]
        .as_str()
        .ok_or(crate::errors::msg::CONTENT_REQUIRED)?
        .to_string();
    let tier_str = params["tier"].as_str().unwrap_or(Tier::Mid.as_str());
    let tier =
        Tier::from_str(tier_str).ok_or_else(|| crate::errors::msg::invalid("tier", tier_str))?;
    let namespace = params["namespace"].as_str().map(str::to_string);
    let priority = i32::try_from(params["priority"].as_i64().unwrap_or(5)).unwrap_or(5);
    let confidence = params[param_names::CONFIDENCE].as_f64().unwrap_or(1.0);
    let tags: Vec<String> = params["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut metadata = if params["metadata"].is_object() {
        params["metadata"].clone()
    } else {
        serde_json::json!({})
    };

    // v0.7.0 #1325 — caller-asserted depth cap. When the caller passes
    // `depth: N`, the substrate-computed depth (max(source depths) + 1)
    // MUST equal `N` or the call is refused with the stable error slug
    // `CALLER_DEPTH_MISMATCH`. This honors the docstring example
    // (`{"source_ids": […], "depth": 1}`) without silently accepting
    // the field. Omission preserves backward-compat: the substrate
    // computes depth as before.
    //
    // The pre-#1325 path silently dropped the field, leaving operators
    // who set it convinced the substrate honored their cap when it
    // didn't. The fix surfaces a typed refusal slug that fits the
    // existing `REFLECTION_DEPTH_EXCEEDED` / `REFLECTION_HOOK_VETO`
    // family of stable string-prefix errors.
    let caller_depth: Option<i64> = params
        .get(param_names::DEPTH)
        .and_then(serde_json::Value::as_i64);
    if let Some(d) = caller_depth {
        if d < 0 {
            return Err(format!(
                "CALLER_DEPTH_MISMATCH: depth must be a non-negative integer (got depth={d})"
            ));
        }
    }

    // NHI: resolve agent_id via the same precedence chain memory_store
    // uses, so the reflection memory's `metadata.agent_id` is consistent
    // with regular stores.
    let explicit_agent_id = params["agent_id"].as_str().or_else(|| {
        metadata
            .get(param_names::AGENT_ID)
            .and_then(serde_json::Value::as_str)
    });
    let agent_id = crate::identity::resolve_agent_id(explicit_agent_id, mcp_client)
        .map_err(|e| e.to_string())?;

    // v0.7.1 #1665 — desugar the top-level `entity_id` convenience param
    // into `metadata.entity_id` before building the input, so the binding
    // is identical across both reflect parsers and the L1-8 round-trip.
    fold_entity_id_into_metadata(&mut metadata, params[param_names::ENTITY_ID].as_str());

    let mut input = db::ReflectInput {
        source_ids,
        title: title.clone(),
        content: content.clone(),
        namespace,
        tier,
        tags,
        priority,
        confidence,
        // v0.7.x (issue #1175): vendor-neutral substrate default.
        // The pre-#1175 hardcode of `"claude"` was a heterogeneous-NHI
        // monoculture defect (forensic queries on `source = 'claude'`
        // silently missed every reflection minted by a non-Anthropic
        // NHI). Vendor identification continues to live in
        // `metadata.agent_id` via the `ai:<client>@<host>:pid-<pid>`
        // resolution ladder — `source` is now the role-categorical
        // value `"nhi"` for every AI NHI write regardless of vendor.
        source: crate::validate::DEFAULT_NHI_SOURCE.to_string(),
        agent_id,
        metadata,
    };

    // #3014 — the reflection is a memory-creating TENANT write; cross the
    // attestation posture like `store`. `memory_reflect` presents no caller
    // signature, so under global-strict attestation it is REFUSED here
    // (fail-closed, BEFORE the approval-queue branch below — no pending row is
    // queued and no provenance-less durable row lands). The INTERNAL curator
    // reflection pass runs through the SAL trait (`MemoryStore::reflect`,
    // for_admin/bypass_visibility) and never reaches this MCP handler, so it
    // is exempt.
    //
    // The permissive-path `attest_level="claimed"` STAMP is directed at a
    // THROWAWAY object, NOT `input.metadata`, so it does NOT ride into the
    // pending-approval `pending_actions` payload (the #1176 caller-intent /
    // lossless-capture invariant: the queued payload.metadata must be exactly
    // what the caller supplied). The durable `attest_level` is stamped at the
    // shared reflect WRITE funnel (`db::reflect_with_hooks`) instead, so BOTH
    // a directly-created reflection AND an approve→execute one land it. Any
    // caller-supplied `attest_level` is scrubbed first — it is a
    // substrate-stamped system key, never caller-authoritative (a caller
    // cannot forge `agent_attested` onto an unsigned reflection).
    if let Some(obj) = input.metadata.as_object_mut() {
        obj.remove(crate::models::field_names::ATTEST_LEVEL);
    }
    let mut attest_sink = serde_json::Value::Object(serde_json::Map::new());
    crate::identity::attest::gate_unsigned_surface_attestation(&mut attest_sink)
        .map_err(|e| e.to_string())?;

    // ─── #1325: caller-asserted depth mismatch refusal ──────────────
    // When the caller passed `depth: N`, verify it matches the
    // substrate-computed value `max(src depths) + 1` BEFORE the write.
    // Mirrors the same source-load pattern the L1-8 gate (below) uses.
    // Mismatch returns `CALLER_DEPTH_MISMATCH` so callers can detect
    // wire/intent drift without combing through the post-write
    // `reflection_depth` field.
    if let Some(caller_d) = caller_depth {
        let max_src_depth = input
            .source_ids
            .iter()
            .filter_map(|id| db::get(conn, id).ok().flatten())
            .map(|m| m.reflection_depth)
            .max()
            .unwrap_or(0);
        let computed = i64::from(max_src_depth.saturating_add(1));
        if caller_d != computed {
            return Err(format!(
                "CALLER_DEPTH_MISMATCH: caller asserted depth={caller_d} but \
                 substrate computed reflection_depth={computed} from sources \
                 (max(source_depths)+1). Omit the `depth` field to defer to the \
                 substrate, or pass the matching value."
            ));
        }
    }

    // ─── L1-8: require_approval_above_depth gate ────────────────────
    // Evaluated BEFORE the substrate write so we can intercept deep
    // reflections and queue a pending_actions row without writing a
    // partial reflection.  The gate fires only when the resolved
    // namespace chain carries a non-None `require_approval_above_depth`
    // threshold AND the proposed depth exceeds it.
    //
    // Implementation note: computing `new_depth` here mirrors step 3 of
    // `db::reflect_with_hooks` — we load the source memories to find the
    // max existing depth, add 1, then compare against the threshold.
    // This is intentionally a thin MCP-layer pre-check; the substrate
    // still enforces `max_reflection_depth` independently on the write
    // path, so the two gates compose: approval-above-depth fires first,
    // the substrate depth-cap fires second on the actual write.
    {
        let target_namespace = input.namespace.clone().or_else(|| {
            // Mirror the substrate default: first source's namespace.
            input
                .source_ids
                .first()
                .and_then(|id| db::get(conn, id).ok().flatten())
                .map(|m| m.namespace)
        });

        if let Some(ref ns) = target_namespace {
            // L1-8: read the approval threshold directly from the
            // namespace's governance metadata blob — avoids adding a
            // new field to the GovernancePolicy struct (which would
            // require updating every GovernancePolicy { … } literal).
            if let Some(threshold) = db::resolve_require_approval_above_depth(conn, ns) {
                // Compute proposed depth: max(source depths) + 1.
                let max_src_depth = input
                    .source_ids
                    .iter()
                    .filter_map(|id| db::get(conn, id).ok().flatten())
                    .map(|m| m.reflection_depth)
                    .max()
                    .unwrap_or(0);
                #[allow(clippy::cast_sign_loss)]
                let new_depth_u32: u32 = max_src_depth.max(0).saturating_add(1) as u32;

                if new_depth_u32 > threshold {
                    // Serialise enough of the input to reconstruct the
                    // call when the approver resolves the pending row.
                    //
                    // v0.7.x (issue #1176): `metadata` MUST be included
                    // — `execute_reflect_from_payload` (`src/storage/mod.rs`,
                    // fn `execute_reflect_from_payload`) reads
                    // `payload["metadata"]` to rebuild the
                    // `ReflectInput.metadata` field, which the
                    // substrate then merges with the canonical
                    // `agent_id` + `reflection_metadata` blob. The
                    // pre-#1176 payload omitted `metadata` entirely,
                    // so an L1-8-gated reflection bound via
                    // `metadata.entity_id` (or any other caller-
                    // supplied key) silently lost the binding on the
                    // pending → execute round-trip — sibling defect
                    // to #1172, surfaced by the Block 1 QC audit.
                    let payload = json!({
                        (field_names::SOURCE_IDS): input.source_ids,
                        "title": input.title,
                        "content": input.content,
                        "namespace": ns,
                        "tier": input.tier.as_str(),
                        "tags": input.tags,
                        "priority": input.priority,
                        (field_names::CONFIDENCE): input.confidence,
                        "agent_id": input.agent_id,
                        "metadata": input.metadata,
                        "proposed_depth": new_depth_u32,
                    });
                    let pending_id = db::queue_pending_action(
                        conn,
                        GovernedAction::Reflect,
                        ns,
                        None,
                        &input.agent_id,
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                    crate::subscriptions::dispatch_approval_requested(conn, &pending_id, db_path);
                    return Ok(json!({
                        "status": "pending",
                        (field_names::PENDING_ID): pending_id,
                        "reason": "governance requires approval for reflections above depth threshold",
                        "action": "reflect",
                        "namespace": ns,
                        "proposed_depth": new_depth_u32,
                        "require_approval_above_depth": threshold,
                    }));
                }
            }
        }
    }

    // ─── Substrate write ────────────────────────────────────────────
    // Error mapping is deliberate: `DepthExceeded` is left as a distinct
    // string shape so Task 5/8 can match on the prefix when wiring the
    // `signed_events` audit emission (and so the HTTP layer can map it
    // back to the typed `MemoryError::ReflectionDepthExceeded` variant).
    //
    // v0.7.0 QW-1 — when the resolved namespace policy opts into
    // `auto_export_reflections_to_filesystem`, install the
    // `post_reflect` hook that deferred-spawns the markdown disk
    // write. The hook is a Box<dyn Fn> spawning std::thread::spawn,
    // so the response path stays as fast as the unhooked write.
    let hooks = {
        let target_ns = input.namespace.clone().or_else(|| {
            input
                .source_ids
                .first()
                .and_then(|id| db::get(conn, id).ok().flatten())
                .map(|m| m.namespace)
        });
        let auto_export = target_ns
            .as_deref()
            .and_then(|ns| db::resolve_governance_policy(conn, ns))
            .map(|p| p.effective_auto_export_reflections_to_filesystem())
            .unwrap_or(false);
        let mut h = if auto_export {
            crate::hooks::post_reflect::build_post_reflect_hook(
                db_path.to_path_buf(),
                crate::hooks::post_reflect::AutoExportConfig::default_for_home(),
            )
        } else {
            db::ReflectHooks::empty()
        };
        // Issue #815 — `build_post_reflect_hook` leaves `active_keypair`
        // None because signing is the handler's concern, not the
        // auto-export hook's. Plug the dispatcher-supplied keypair in
        // so the `create_link_signed` call inside
        // `storage::reflect_with_hooks` reaches the signed path.
        h.active_keypair = active_keypair;
        h
    };
    let outcome = match db::reflect_with_hooks(conn, &input, &hooks) {
        Ok(o) => o,
        Err(e) => return Err(map_reflect_error_to_wire_string(e)),
    };

    // ─── Best-effort post-write side effects ────────────────────────
    // Generate + persist an embedding for the new reflection memory so
    // semantic recall can find it. Failure is logged, not fatal — the
    // memory is already committed.
    if let Some(emb) = embedder {
        let text = crate::embeddings::embedding_document(title, content);
        match emb.embed(&text) {
            Ok(embedding) => {
                if let Err(e) =
                    db::set_embedding(conn, &outcome.id, &embedding, &emb.space_fingerprint())
                {
                    tracing::warn!(
                        "failed to store embedding for reflection {}: {}",
                        &outcome.id,
                        e
                    );
                }
                if let Some(idx) = vector_index {
                    idx.insert(outcome.id.clone(), embedding);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "failed to generate embedding for reflection {}: {}",
                    &outcome.id,
                    e
                );
            }
        }
    }

    // Fire the standard `memory_store` webhook event so downstream
    // subscribers see the new memory the same way they would a direct
    // store. Task 6/8 will layer `pre_reflect` / `post_reflect` hook
    // events on top of this baseline.
    crate::subscriptions::dispatch_event(
        conn,
        crate::mcp::registry::tool_names::MEMORY_STORE,
        &outcome.id,
        &outcome.namespace,
        Some(&input.agent_id),
        db_path,
    );

    Ok(json!({
        "id": outcome.id,
        (field_names::REFLECTION_DEPTH): outcome.reflection_depth,
        (crate::models::link::REL_REFLECTS_ON): outcome.reflects_on,
        "namespace": outcome.namespace,
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_reflect ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_reflect`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ReflectRequest {
    /// Sources reflected on; one reflects_on link per id.
    pub source_ids: Vec<String>,

    /// Reflection title.
    pub title: String,

    /// Reflection content.
    pub content: String,

    /// Target namespace. Defaults to first source's namespace.
    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default)]
    pub priority: Option<i64>,

    #[serde(default)]
    pub confidence: Option<f64>,

    /// Reflection writer NHI; default synthesized.
    #[serde(default)]
    pub agent_id: Option<String>,

    /// Merged with system reflection_metadata; caller keys win. The
    /// `entity_id` key here binds the reflection to an entity (drives
    /// auto-persona cadence); set it directly or via the top-level
    /// `entity_id` convenience param below (#1665).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,

    /// v0.7.1 #1665 — entity this reflection is about. Convenience alias
    /// for `metadata.entity_id`: it sets that key when you have not. If
    /// both are supplied and differ, `metadata.entity_id` wins (a warn is
    /// logged); a blank/whitespace value is ignored. A `[entity:X]` title
    /// marker remains the lower-precedence fallback. Reflection-kind only;
    /// drives auto-persona cadence (the generator counts reflections whose
    /// denormalised `mentioned_entity_id` equals this).
    #[serde(default)]
    pub entity_id: Option<String>,

    /// v0.7.0 #1325 — caller-asserted reflection depth (cap-style).
    /// When set, MUST equal max(source_depths)+1 or the call is
    /// refused with `CALLER_DEPTH_MISMATCH`. Omit to defer to the
    /// substrate-computed value (backward-compatible).
    #[serde(default)]
    pub depth: Option<i64>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_reflect`.
#[allow(dead_code)]
pub struct ReflectTool;

impl McpTool for ReflectTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_REFLECT
    }
    fn description() -> &'static str {
        "Persist a reflection memory plus reflects_on provenance links to each source."
    }
    fn docs() -> &'static str {
        "Task 4/8 (#655): substrate-native recursive-learning primitive. reflection_depth = max(source_depths)+1; gated by namespace governance.max_reflection_depth (Task 2/8) — refusal returns REFLECTION_DEPTH_EXCEEDED. New memory + N reflects_on links land in one atomic txn."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<ReflectRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_reflect`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn reflect_parity_986() {
        let derived = derived_props_for::<ReflectRequest>();
        assert_property_set_parity("memory_reflect", &derived);
        assert_descriptions_match("memory_reflect", &derived);
    }

    #[test]
    fn reflect_tool_metadata_986() {
        assert_eq!(ReflectTool::name(), "memory_reflect");
        assert_eq!(ReflectTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_reflect`.
    //!
    //! Areas covered:
    //! - argument parsing edge cases (empty array, non-string entry)
    //! - error mapping: SourceNotFound, Validation, DepthExceeded
    //! - happy path with mock embedder (post-write embedding store)
    //! - happy path without embedder (no-op for embedding side effect)

    use super::*;
    use crate::embeddings::test_support::MockEmbedder;
    use crate::models::{Memory, MemoryKind};
    use crate::storage as db;
    use serde_json::json;

    // ── #1549 parse_reflect_input coverage ──────────────────────────
    #[test]
    fn parse_reflect_input_happy_path() {
        let params = json!({
            "source_ids": ["a", "b"],
            "title": "t",
            "content": "c",
            "namespace": "ns",
            "tier": "long",
            "priority": 7,
            "confidence": 0.5,
            "tags": ["x", "y"],
            "agent_id": "ai:tester@host",
        });
        let (input, caller_depth) = parse_reflect_input(&params, None).expect("parse ok");
        assert_eq!(input.source_ids, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(input.title, "t");
        assert_eq!(input.content, "c");
        assert_eq!(input.namespace.as_deref(), Some("ns"));
        assert_eq!(input.tier, Tier::Long);
        assert_eq!(input.priority, 7);
        assert!((input.confidence - 0.5).abs() < f64::EPSILON);
        assert_eq!(input.tags, vec!["x".to_string(), "y".to_string()]);
        assert_eq!(input.agent_id, "ai:tester@host");
        assert_eq!(caller_depth, None);
    }

    #[test]
    fn parse_reflect_input_defaults_when_optional_fields_absent() {
        let params = json!({ "source_ids": ["a"], "title": "t", "content": "c" });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        // tier defaults to Mid; priority 5; confidence 1.0; namespace None.
        assert_eq!(input.tier, Tier::Mid);
        assert_eq!(input.priority, 5);
        assert!((input.confidence - 1.0).abs() < f64::EPSILON);
        assert!(input.namespace.is_none());
        assert!(input.tags.is_empty());
    }

    #[test]
    fn parse_reflect_input_missing_source_ids_errors() {
        let err = parse_reflect_input(&json!({ "title": "t", "content": "c" }), None).unwrap_err();
        assert!(err.contains("source_ids is required"), "got: {err}");
    }

    #[test]
    fn parse_reflect_input_empty_source_ids_errors() {
        let err = parse_reflect_input(
            &json!({ "source_ids": [], "title": "t", "content": "c" }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("source_ids cannot be empty"), "got: {err}");
    }

    #[test]
    fn parse_reflect_input_non_string_source_errors() {
        let err = parse_reflect_input(
            &json!({ "source_ids": [1], "title": "t", "content": "c" }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("must be a string"), "got: {err}");
    }

    #[test]
    fn parse_reflect_input_missing_title_errors() {
        let err =
            parse_reflect_input(&json!({ "source_ids": ["a"], "content": "c" }), None).unwrap_err();
        assert!(err.contains("title is required"), "got: {err}");
    }

    #[test]
    fn parse_reflect_input_negative_depth_is_caller_depth_mismatch() {
        let err = parse_reflect_input(
            &json!({ "source_ids": ["a"], "title": "t", "content": "c", "depth": -1 }),
            None,
        )
        .unwrap_err();
        assert!(err.contains("CALLER_DEPTH_MISMATCH"), "got: {err}");
    }

    #[test]
    fn parse_reflect_input_returns_caller_depth_when_present() {
        let (_, caller_depth) = parse_reflect_input(
            &json!({ "source_ids": ["a"], "title": "t", "content": "c", "depth": 3 }),
            None,
        )
        .expect("parse ok");
        assert_eq!(caller_depth, Some(3));
    }

    fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = db::open(tmp.path()).expect("db::open");
        (conn, tmp)
    }

    fn seed_observation(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({"agent_id": "ai:test"}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
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
        };
        db::insert(conn, &mem).expect("insert")
    }

    // ── v0.7.1 #1665 — top-level entity_id desugar coverage ─────────
    #[test]
    fn fold_entity_id_absent_is_noop() {
        let mut md = json!({"agent_id": "ai:x"});
        fold_entity_id_into_metadata(&mut md, None);
        assert!(md.get(crate::models::field_names::ENTITY_ID).is_none());
    }

    #[test]
    fn fold_entity_id_blank_is_noop() {
        let mut md = json!({});
        fold_entity_id_into_metadata(&mut md, Some("   "));
        assert!(md.get(crate::models::field_names::ENTITY_ID).is_none());
    }

    #[test]
    fn fold_entity_id_inserts_trimmed_when_absent() {
        let mut md = json!({});
        fold_entity_id_into_metadata(&mut md, Some("  acme  "));
        assert_eq!(md[crate::models::field_names::ENTITY_ID], json!("acme"));
    }

    #[test]
    fn fold_entity_id_metadata_wins_on_conflict() {
        let mut md = json!({"entity_id": "real"});
        fold_entity_id_into_metadata(&mut md, Some("alias"));
        assert_eq!(md[crate::models::field_names::ENTITY_ID], json!("real"));
    }

    #[test]
    fn fold_entity_id_replaces_non_object_metadata() {
        let mut md = json!(null);
        fold_entity_id_into_metadata(&mut md, Some("acme"));
        assert_eq!(md[crate::models::field_names::ENTITY_ID], json!("acme"));
    }

    // #1665 audit follow-up — the common shape: a caller-set
    // metadata.entity_id with NO top-level param must be left intact (the
    // None early-return must not blank an existing binding).
    #[test]
    fn fold_entity_id_none_preserves_existing_metadata() {
        let mut md = json!({"entity_id": "real", "agent_id": "ai:x"});
        fold_entity_id_into_metadata(&mut md, None);
        assert_eq!(md[crate::models::field_names::ENTITY_ID], json!("real"));
        assert_eq!(md["agent_id"], json!("ai:x"));
    }

    // #1665 audit follow-up — a non-string top-level entity_id (number /
    // bool / object) yields `as_str() == None` in both parsers, so it is
    // ignored rather than coerced.
    #[test]
    fn parse_reflect_input_non_string_entity_id_ignored() {
        let params = json!({
            "source_ids": ["a"], "title": "t", "content": "c",
            "entity_id": 42,
        });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        assert!(
            input
                .metadata
                .get(crate::models::field_names::ENTITY_ID)
                .is_none()
        );
    }

    #[test]
    fn parse_reflect_input_top_level_entity_id_binds_metadata() {
        let params = json!({
            "source_ids": ["a"], "title": "t", "content": "c",
            "entity_id": "ent-1",
        });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        assert_eq!(
            input.metadata[crate::models::field_names::ENTITY_ID],
            json!("ent-1")
        );
    }

    #[test]
    fn parse_reflect_input_nested_metadata_entity_id_wins() {
        let params = json!({
            "source_ids": ["a"], "title": "t", "content": "c",
            "entity_id": "alias",
            "metadata": {"entity_id": "real"},
        });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        assert_eq!(
            input.metadata[crate::models::field_names::ENTITY_ID],
            json!("real")
        );
    }

    #[test]
    fn parse_reflect_input_blank_entity_id_ignored() {
        let params = json!({
            "source_ids": ["a"], "title": "t", "content": "c",
            "entity_id": "   ",
        });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        assert!(
            input
                .metadata
                .get(crate::models::field_names::ENTITY_ID)
                .is_none()
        );
    }

    // Integration: top-level entity_id flows through handle_reflect (stdio
    // parser) into the denormalised `mentioned_entity_id` column that
    // `count_entity_reflections` reads for auto-persona cadence — proving
    // the param → metadata → extractor → indexed-column chain end-to-end.
    #[test]
    fn handle_reflect_top_level_entity_id_populates_mentioned_column() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "team/alpha", "seed");
        let out = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src], "title": "refl", "content": "body",
                "namespace": "team/alpha", "entity_id": "  ent-42  ",
            }),
            None,
            None,
            None,
            None,
        )
        .expect("reflect ok");
        let id = out["id"].as_str().expect("id");
        let mem = db::get(&conn, id).expect("get").expect("exists");
        assert_eq!(
            mem.metadata[crate::models::field_names::ENTITY_ID],
            json!("ent-42"),
            "stored metadata.entity_id must be the trimmed top-level value"
        );
        let mentioned: Option<String> = conn
            .query_row(
                "SELECT mentioned_entity_id FROM memories WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .expect("query mentioned_entity_id");
        assert_eq!(
            mentioned.as_deref(),
            Some("ent-42"),
            "denormalised mentioned_entity_id must match for cadence counting"
        );
    }

    // Backward-compat: omitting entity_id leaves metadata untouched.
    #[test]
    fn parse_reflect_input_omitted_entity_id_no_key() {
        let params = json!({ "source_ids": ["a"], "title": "t", "content": "c" });
        let (input, _) = parse_reflect_input(&params, None).expect("parse ok");
        assert!(
            input
                .metadata
                .get(crate::models::field_names::ENTITY_ID)
                .is_none()
        );
    }

    // Validation: source_ids missing.
    #[test]
    fn missing_source_ids_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"title": "t", "content": "c"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("source_ids"), "got: {err}");
    }

    // Validation: empty source_ids.
    #[test]
    fn empty_source_ids_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"source_ids": [], "title": "t", "content": "c"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    // Validation: non-string source_id entry.
    #[test]
    fn non_string_source_id_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"source_ids": ["ok", 42], "title": "t", "content": "c"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("must be a string"), "got: {err}");
    }

    // Validation: missing title.
    #[test]
    fn missing_title_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"source_ids": ["x"], "content": "c"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    // Validation: missing content.
    #[test]
    fn missing_content_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"source_ids": ["x"], "title": "t"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("content"), "got: {err}");
    }

    // Validation: invalid tier.
    #[test]
    fn invalid_tier_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({"source_ids": ["x"], "title": "t", "content": "c", "tier": "bogus"}),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("invalid tier"), "got: {err}");
    }

    // SourceNotFound: source id not in DB.
    #[test]
    fn source_not_found_errors() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": ["11111111-2222-3333-4444-555555555555"],
                "title": "t",
                "content": "c",
            }),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .unwrap_err();
        assert!(err.contains("source memory not found"), "got: {err}");
    }

    // Happy path without embedder — substrate write succeeds.
    #[test]
    fn happy_path_without_embedder() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "rfl-ns", "obs");
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "reflection",
                "content": "I see the observation",
            }),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .expect("ok");
        assert!(resp["id"].is_string());
        assert_eq!(resp["reflection_depth"].as_i64(), Some(1));
        assert_eq!(resp["namespace"].as_str(), Some("rfl-ns"));
    }

    // Happy path with embedder — embedding stored on the reflection memory.
    #[test]
    fn happy_path_with_embedder_stores_embedding() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "rfl-emb", "obs");
        let emb = MockEmbedder::new_local().unwrap();
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "t",
                "content": "c",
            }),
            Some(&emb),
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .expect("ok");
        let new_id = resp["id"].as_str().unwrap();
        // Embedding column populated on the new reflection.
        let has_emb: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1 AND embedding IS NOT NULL",
                rusqlite::params![new_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(has_emb, 1, "embedding must be set");
    }

    // Approval-gate path: governance threshold triggers the K10 pending queue.
    #[test]
    fn approval_gate_above_depth_queues_pending() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "rfl-gate", "obs");
        // Seed a namespace_meta row + standard memory with governance
        // setting `max_reflection_depth: 5` (compiled default) and
        // `require_approval_above_depth: 0` so a depth=1 reflection
        // immediately falls above the threshold.
        let std_mem_id = seed_observation(&conn, "rfl-gate", "std");
        // Manually patch metadata.governance with require_approval_above_depth=0
        // v0.7.0 #1036 (Agent-3 #7) — test fixture seed. Non-version-
        // bumping by design: test isolates a single namespace-standard
        // row; no caller observes the pre-update version. Pinned by
        // `tests/non_version_bumping_sites_1036.rs`.
        let gov_metadata = json!({
            "governance": {
                "write": "any",
                "require_approval_above_depth": 0,
            },
        });
        conn.execute(
            "UPDATE memories SET metadata = json(?1) WHERE id = ?2",
            rusqlite::params![gov_metadata.to_string(), &std_mem_id],
        )
        .unwrap();
        db::set_namespace_standard(&conn, "rfl-gate", &std_mem_id, None).unwrap();
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "t",
                "content": "c",
                "namespace": "rfl-gate",
            }),
            None,
            None,
            None,
            None, // active_keypair — #815 regression coverage uses the dedicated mcp/mod.rs test
        )
        .expect("ok");
        // Approval gate fires before substrate write.
        assert_eq!(resp["status"].as_str(), Some("pending"));
        assert!(resp["pending_id"].is_string());
    }

    // ─── #1338 coverage closure — pre-existing error-path branches ─────
    //
    // The Per-Module Coverage Threshold gate flagged `mcp/tools/reflect.rs`
    // at 92.47% < 95% on PR #1338 because the following 13 lines of
    // production code were never exercised by the existing test suite:
    //
    //   L284-286  auto_export = true → build_post_reflect_hook
    //   L301      Validation pattern arm  (via map_reflect_error_to_wire_string)
    //   L319/327-329  HookVeto pattern arm (via map_reflect_error_to_wire_string)
    //   L341-343  db::set_embedding failure tracing
    //   L348      vector_index.insert on embedding success
    //   L351-354  embedder.embed failure tracing
    //
    // The HookVeto + Database arms are structurally unreachable from
    // `handle_reflect` today (no MCP-side `pre_reflect` hook is wired
    // in, and a SQL fault inside `reflect_with_hooks` would imply a
    // corrupt DB the integration harness can't easily fabricate); the
    // wire-string discipline they pin is exercised through the
    // refactored `map_reflect_error_to_wire_string` helper directly.

    use crate::embeddings::test_support::FailingEmbedder;
    use crate::hnsw::VectorIndex;
    use crate::models::{
        ApproverType, CorePolicy, ExportPolicy, GovernanceLevel, GovernancePolicy,
    };

    /// Seed a namespace governance standard whose policy opts into
    /// `auto_export_reflections_to_filesystem`. Mirrors the helper
    /// used inside `hooks/post_reflect/auto_export.rs::tests` so the
    /// shape of the standard row stays consistent across crates.
    fn enable_auto_export_on_namespace(conn: &rusqlite::Connection, ns: &str) {
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Any,
                promote: GovernanceLevel::Any,
                delete: GovernanceLevel::Owner,
                approver: ApproverType::Human,
                inherit: true,
                max_reflection_depth: None,
                required_scope: None,
            },
            export: ExportPolicy {
                auto_export_reflections_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let gov_metadata = json!({
            "agent_id": "ai:test",
            "governance": serde_json::to_value(&policy).unwrap(),
        });
        let std_mem_id = seed_observation(conn, ns, "__standard__");
        conn.execute(
            "UPDATE memories SET metadata = json(?1) WHERE id = ?2",
            rusqlite::params![gov_metadata.to_string(), &std_mem_id],
        )
        .unwrap();
        db::set_namespace_standard(conn, ns, &std_mem_id, None).unwrap();
    }

    /// Test 1 — L284-286: the `auto_export = true` branch fires
    /// `build_post_reflect_hook`. We seed a namespace-standard with
    /// `auto_export_reflections_to_filesystem: Some(true)` so the
    /// resolver inside `handle_reflect` picks the hooked code path
    /// instead of `ReflectHooks::empty()`. Closes coverage on the
    /// three lines of the `if auto_export { ... }` branch body.
    #[test]
    fn auto_export_branch_builds_post_reflect_hook() {
        let (conn, tmp) = fresh_db();
        enable_auto_export_on_namespace(&conn, "rfl-auto-export");
        let src = seed_observation(&conn, "rfl-auto-export", "obs");
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "reflection that fires auto-export hook",
                "content": "body",
                "namespace": "rfl-auto-export",
            }),
            None,
            None,
            None,
            None,
        )
        .expect("auto-export branch must not change reflect success semantics");
        // The handler returns the canonical success envelope regardless
        // of which hook bundle was chosen — auto-export is a Notify-class
        // side-effect, the disk write happens on a detached worker
        // thread (see hooks/post_reflect/auto_export.rs:127).
        assert!(resp["id"].is_string(), "got: {resp}");
        assert_eq!(resp["reflection_depth"].as_i64(), Some(1));
        assert_eq!(resp["namespace"].as_str(), Some("rfl-auto-export"));
    }

    /// Test 2 — L301 (`Validation` arm via helper): substrate-side
    /// validation rejects a source id that contains characters outside
    /// the SPIFFE-style allowlist. The MCP layer's `.as_str()` parse
    /// accepts the string; `db::reflect_with_hooks` then runs
    /// `validate_id` on each source id and returns
    /// `ReflectError::Validation`. The wire-string surfaced is the
    /// substrate's raw reason — no MCP-layer reshape.
    #[test]
    fn substrate_validation_error_propagates_raw_reason() {
        let (conn, tmp) = fresh_db();
        let err = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                // Space character — passes MCP `.as_str()` parse but
                // tripwires substrate validate_id's `[A-Za-z0-9_:.@-]`
                // charset gate.
                "source_ids": ["bad id with spaces"],
                "title": "t",
                "content": "c",
            }),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        // Substrate's validate_id error text surfaces verbatim — it
        // contains "path-traversal guard" or "characters outside the
        // allowed set" depending on which gate trips first. Either way
        // the source-id prefix the substrate adds (`source_ids[0]:`)
        // appears in the message.
        assert!(
            err.contains("source_ids[0]"),
            "substrate Validation error must surface verbatim with index prefix; got: {err}"
        );
    }

    /// Test 3 — L348: when an embedder succeeds AND a vector index is
    /// supplied, the post-write side-effect inserts into the index.
    /// Pinned so a future refactor can't drop the `idx.insert(...)`
    /// arm without surfacing a behaviour regression.
    #[test]
    fn embedder_success_populates_vector_index() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "rfl-vec", "obs");
        let emb = MockEmbedder::new_local().unwrap();
        let idx = VectorIndex::empty();
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "vec-indexed",
                "content": "the in-memory hnsw index sees this",
            }),
            Some(&emb),
            Some(&idx),
            None,
            None,
        )
        .expect("ok");
        let new_id = resp["id"].as_str().unwrap();
        // The new reflection memory must be queryable via the index
        // (cosine-similar to its own embedding ⇒ trivially the top
        // hit). Confirms `idx.insert(...)` ran on the success arm.
        let probe = emb
            .embed("vec-indexed the in-memory hnsw index sees this")
            .unwrap();
        let hits = idx.search(&probe, 1);
        assert_eq!(
            hits.len(),
            1,
            "vector index must have indexed the reflection"
        );
        assert_eq!(hits[0].id, new_id, "top hit must be the new reflection id");
    }

    /// Test 4 — L341-343: `db::set_embedding` failure path is a warn-
    /// log, not fatal. We force the failure by pre-seeding a memory in
    /// the same namespace that has an established embedding dim of
    /// 768 (the nomic mock); the reflection's MiniLM mock produces a
    /// 384-dim vector, so `set_embedding` returns
    /// `EmbeddingDimMismatch` and the handler logs+continues. The
    /// reflection itself still commits successfully.
    #[test]
    fn set_embedding_failure_logs_warn_and_still_returns_ok() {
        let (conn, tmp) = fresh_db();
        // Seed an observation, then attach a 768-dim embedding so the
        // namespace's established dim locks at 768. The reflection
        // we mint immediately after this point will be embedded with
        // the 384-dim MiniLM mock, tripwiring the dim invariant
        // inside set_embedding.
        let src = seed_observation(&conn, "rfl-emb-fail", "obs");
        let stable_seed_embedding: Vec<f32> = (0..768).map(|i| (i as f32) * 0.001).collect();
        db::set_embedding(
            &conn,
            &src,
            &stable_seed_embedding,
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .expect("seed 768-dim embedding");
        let emb = MockEmbedder::new_local().unwrap(); // 384-dim
        // Handle_reflect must succeed end-to-end; the substrate write
        // is independent of the embedding-store side-effect.
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "embedding store will fail",
                "content": "but the reflection still commits",
                "namespace": "rfl-emb-fail",
            }),
            Some(&emb),
            None,
            None,
            None,
        )
        .expect("substrate write succeeds; set_embedding failure is logged not propagated");
        let new_id = resp["id"].as_str().unwrap();
        // The reflection row exists; the embedding column is NULL
        // because set_embedding's dim-invariant check rejected the
        // 384-dim vector before the UPDATE ran.
        let has_emb: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1 AND embedding IS NOT NULL",
                rusqlite::params![new_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(
            has_emb, 0,
            "embedding column must be NULL — set_embedding refused the dim-mismatched vector"
        );
    }

    /// Test 5 — L351-354: `embedder.embed` failure path is a warn-log,
    /// not fatal. `FailingEmbedder` always returns `Err`; the handler
    /// must still return the canonical success envelope because the
    /// substrate write already committed before the embedder ran.
    #[test]
    fn embedder_generation_failure_logs_warn_and_still_returns_ok() {
        let (conn, tmp) = fresh_db();
        let src = seed_observation(&conn, "rfl-emb-gen-fail", "obs");
        let emb = FailingEmbedder;
        let resp = handle_reflect(
            &conn,
            tmp.path(),
            &json!({
                "source_ids": [src],
                "title": "embedder will refuse",
                "content": "the reflection still commits",
            }),
            Some(&emb),
            None,
            None,
            None,
        )
        .expect("substrate write succeeds; embedder failure is logged not propagated");
        let new_id = resp["id"].as_str().unwrap();
        // Embedding column is NULL — emb.embed returned Err before
        // set_embedding could run.
        let has_emb: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1 AND embedding IS NOT NULL",
                rusqlite::params![new_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(has_emb, 0, "embedder.embed Err arm must skip set_embedding");
    }

    // ─── map_reflect_error_to_wire_string — unreachable-from-handler arms ─

    /// Test 6 — L319/327-329 (HookVeto arm): pin the wire-string
    /// discipline for the `HookVeto` variant. The arm is structurally
    /// unreachable from `handle_reflect` today (no MCP-side
    /// `pre_reflect` hook is wired in), but the wire-shape it produces
    /// is part of the stable string-prefix family
    /// (`REFLECTION_DEPTH_EXCEEDED` / `REFLECTION_HOOK_VETO` /
    /// `CALLER_DEPTH_MISMATCH`) that callers + audit emission depend
    /// on. Exercising the mapper directly closes the coverage gap
    /// without contorting `handle_reflect`'s production signature.
    #[test]
    fn map_reflect_error_hook_veto_shape() {
        let err = db::ReflectError::HookVeto {
            reason: "operator denied".to_string(),
            code: 451,
        };
        let wire = map_reflect_error_to_wire_string(err);
        assert_eq!(wire, "REFLECTION_HOOK_VETO (code=451): operator denied");
        assert!(
            wire.starts_with("REFLECTION_HOOK_VETO"),
            "HookVeto wire shape must lead with the stable slug"
        );
    }

    /// Test 7 — `Database` arm: pin the raw-string passthrough. Also
    /// structurally unreachable from `handle_reflect` today (a SQL
    /// fault inside the atomic reflect transaction implies a corrupt
    /// DB the test harness can't fabricate cleanly); exercising the
    /// mapper covers the production line.
    #[test]
    fn map_reflect_error_database_passthrough() {
        let err = db::ReflectError::Database("disk I/O error: device busy".to_string());
        let wire = map_reflect_error_to_wire_string(err);
        assert_eq!(wire, "disk I/O error: device busy");
    }

    /// Test 8 — `Validation` arm passthrough through the helper. The
    /// MCP layer surfaces substrate validation errors verbatim — pin
    /// the no-reshape discipline.
    #[test]
    fn map_reflect_error_validation_passthrough() {
        let err = db::ReflectError::Validation("title cannot be empty".to_string());
        let wire = map_reflect_error_to_wire_string(err);
        assert_eq!(wire, "title cannot be empty");
    }

    /// Test 9 — `SourceNotFound` arm formatting. The MCP layer
    /// prefixes the id with `"source memory not found: "`.
    #[test]
    fn map_reflect_error_source_not_found_format() {
        let err = db::ReflectError::SourceNotFound("11111111-2222".to_string());
        let wire = map_reflect_error_to_wire_string(err);
        assert_eq!(wire, "source memory not found: 11111111-2222");
    }

    /// Test 10 — `DepthExceeded` arm formatting. Stable error string
    /// shape; Task 5/8 audit emission keys off this prefix.
    #[test]
    fn map_reflect_error_depth_exceeded_format() {
        let err = db::ReflectError::DepthExceeded {
            attempted: 6,
            cap: 5,
            namespace: "research".to_string(),
        };
        let wire = map_reflect_error_to_wire_string(err);
        assert_eq!(
            wire,
            "REFLECTION_DEPTH_EXCEEDED: reflection depth 6 would exceed namespace \
             max_reflection_depth 5 (namespace='research')"
        );
        assert!(wire.starts_with("REFLECTION_DEPTH_EXCEEDED"));
    }
}
