// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_swarm_rewind` handler — v1.0.0 #3322 (#3266 MVG piece 1/3).
//!
//! ONE atomic, resumable operator command that intercepts and UNWINDS a memory
//! cascade rooted at `--to <checkpoint|claim-id>` without data loss, and
//! reports its lineage token/cost.
//!
//! ## DRY contract
//!
//! No orchestration logic lives here — the atomic rewind (invalidate root +
//! contaminate the derived swarm + freeze affected routines + emit the signed
//! `swarm.rewind` event + compute the #3323 lineage cost) is the single funnel
//! [`crate::storage::swarm_rewind`]. This module only resolves `--to`, applies
//! the governance/owner gates (symmetric with [`crate::mcp::handle_kg_invalidate`]),
//! and renders the wire envelope. The CLI verb `swarm-rewind` forwards HERE, so
//! there is exactly ONE gated entry point across both surfaces.

use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

/// v1.0.0 #3322 — request body for `memory_swarm_rewind`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SwarmRewindRequest {
    /// The rewind target: a claim-id / memory id (the cascade root), OR a
    /// checkpoint id whose `condition`/`metadata` names a `memory_id`/`root_id`
    /// root. Everything transitively derived from the resolved root is
    /// contaminated (hidden, reversibly) and the root itself is invalidated.
    pub to: String,

    /// Max provenance-DAG depth swept downstream of the root. Defaults to and
    /// is clamped to the server lineage ceiling.
    #[serde(default)]
    pub max_depth: Option<usize>,

    /// Operator-supplied ids of the routines this cascade affected, to FREEZE
    /// (a `Draft → Frozen` regulatory hold). Defaults to none. Freeze is
    /// idempotent and non-destructive; there is deliberately no auto-discovery
    /// (no memory→routine linkage exists) so the operator names the set —
    /// fail-closed: freeze nothing rather than guess wrong.
    #[serde(default)]
    pub freeze_routines: Option<Vec<String>>,

    /// When true, PREVIEW only: return the projected effect (contaminated
    /// count + lineage cost) with ZERO writes and no audit row. Lets a fleet
    /// operator inspect a cascade before committing to unwinding it.
    #[serde(default)]
    pub dry_run: bool,

    /// #3171 — operator-as-actor: the id recorded as the ISSUER of the signed
    /// rewind event. Under the multi-tenant posture (`AI_MEMORY_AGENT_ID` set)
    /// it is BOUND to the caller (a caller may only rewind as itself).
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v1.0.0 #3322 — `McpTool` impl for `memory_swarm_rewind`.
#[allow(dead_code)]
pub struct SwarmRewindTool;

impl McpTool for SwarmRewindTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SWARM_REWIND
    }
    fn description() -> &'static str {
        "Atomically intercept and unwind a memory cascade: invalidate the root, contaminate its \
         derived swarm, freeze affected routines, and report the lineage token/cost."
    }
    fn docs() -> &'static str {
        "#3266 MVG. `to` is a claim-id/memory-id (the cascade root) or a checkpoint id that \
         references one. In ONE atomic transaction the root and every record transitively derived \
         from it (over derived_from/reflects_on/derives_from) are stamped `contaminated` — hidden \
         from ordinary recall but never deleted (the durable text is untouched; the pre-taint \
         lifecycle_state is recorded so a future restore is exact). Operator-named routines are \
         frozen (idempotent). ONE signed `swarm.rewind` event is appended to the audit chain. \
         Returns the #3323 lineage cost (tokens + micro-USD) of the rewound subtree. Idempotent: \
         re-running an already-rewound root is a no-op that appends no duplicate event. `dry_run` \
         previews the effect with zero writes. Refused while the record plane is stopped, and a \
         root already tombstoned/quarantined (already contained) is refused."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SwarmRewindRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// Resolve `--to <checkpoint|claim-id>` to `(root_memory_id, target_kind)`.
///
/// A claim-id IS a memory id (the `ClaimView` projection's `id_uuid` is the
/// `Memory` row's id), so a raw by-id namespace probe (which sees rows in ANY
/// lifecycle state, so an already-contaminated root resolves for the idempotent
/// re-run) decides the memory arm. Otherwise a checkpoint id is resolved and
/// its `condition`/`metadata` is consulted for a `memory_id`/`root_id`
/// pointing at the cascade root. Fail-closed: an unresolvable target, or a
/// checkpoint that names no root, is an error rather than a silent no-op.
fn resolve_rewind_target(
    conn: &rusqlite::Connection,
    to: &str,
) -> Result<(String, &'static str), String> {
    // Memory / claim-id arm — raw existence probe (any lifecycle state).
    if db::namespace_by_id(conn, to)
        .map_err(|e| format!("swarm_rewind target probe: {e}"))?
        .is_some()
    {
        return Ok((to.to_string(), "memory"));
    }

    // Checkpoint arm — resolve the checkpoint, then extract a root memory id
    // from its condition/metadata.
    if let Some(cp) = crate::checkpoints::get(conn, to)
        .map_err(|e| format!("swarm_rewind checkpoint probe: {e}"))?
    {
        let root = checkpoint_root_memory_id(&cp).ok_or_else(|| {
            format!(
                "swarm_rewind: checkpoint {to} references no rewind root \
                 (condition/metadata.memory_id|root_id)"
            )
        })?;
        if db::namespace_by_id(conn, &root)
            .map_err(|e| format!("swarm_rewind checkpoint root probe: {e}"))?
            .is_none()
        {
            return Err(format!(
                "swarm_rewind: checkpoint {to} root memory {root} not found"
            ));
        }
        return Ok((root, "checkpoint"));
    }

    Err(format!("swarm_rewind: target {to} not found"))
}

/// Pull a `memory_id` / `root_id` string out of a checkpoint's `condition` or
/// `metadata` JSON. Present-only: `None` when the checkpoint carries no such
/// reference.
fn checkpoint_root_memory_id(cp: &crate::models::Checkpoint) -> Option<String> {
    for obj in [&cp.condition, &cp.metadata] {
        for key in ["memory_id", "root_id"] {
            if let Some(s) = obj
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// v1.0.0 #3322 — the `memory_swarm_rewind` substrate handler. `pub` so the
/// CLI verb and the integration fleet can drive it directly; still only
/// registered as the MCP `memory_swarm_rewind` tool.
///
/// # Errors
///
/// * `to is required` / `to cannot be empty`.
/// * governance deny (permission rule) / owner-gate refusal.
/// * unresolvable `--to` target.
/// * substrate errors from [`crate::storage::swarm_rewind`] (root not found,
///   root already contained, record plane stopped, ...).
pub fn handle_swarm_rewind(conn: &rusqlite::Connection, params: &Value) -> Result<Value, String> {
    let to = params[param_names::TO]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("to is required")?;

    // Depth: default + clamp to the server lineage ceiling (fail-closed — a
    // crafted huge depth cannot widen the sweep past the bounded ceiling).
    let max_depth = params[param_names::MAX_DEPTH]
        .as_u64()
        .and_then(|d| usize::try_from(d).ok())
        .filter(|&d| d >= 1)
        .unwrap_or(db::LINEAGE_MAX_DEPTH)
        .min(db::LINEAGE_MAX_DEPTH);

    let dry_run = params[param_names::DRY_RUN].as_bool().unwrap_or(false);

    let freeze_routines: Vec<String> = params[param_names::FREEZE_ROUTINES]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Resolve the cascade root up front so the governance gate can key on its
    // namespace (symmetric with `handle_kg_invalidate`).
    let (root_id, target_kind) = resolve_rewind_target(conn, to)?;

    // K9 permission gate — evaluate by the ROOT memory's namespace, bound to
    // the enforced-read caller (no caller-chosen subject on a cascade-hiding
    // op). Gated symmetrically with `memory_kg_invalidate`.
    {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let link_ns = db::namespace_by_id(conn, &root_id)
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| crate::DEFAULT_NAMESPACE.to_string());
        let agent_id = crate::identity::resolve_governance_subject(
            params[param_names::AGENT_ID].as_str(),
            None,
            "rewind a cascade",
        )
        .map_err(|e| e.to_string())?;
        let ctx = PermissionContext {
            op: Op::MemoryLink,
            namespace: link_ns,
            agent_id,
            payload: json!({
                "root_id": root_id,
                (crate::storage::SWARM_REWIND_TARGET_KIND_KEY): target_kind,
                "operation": crate::governance::action_labels::SWARM_REWIND,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    crate::governance::action_labels::SWARM_REWIND,
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": crate::governance::action_labels::SWARM_REWIND,
                    "root_id": root_id,
                }));
            }
        }
    }

    // #1778 owner gate — refuse rewinding a root owned by a DIFFERENT agent
    // under the multi-tenant posture. Keyed on the enforced-read caller, so it
    // fires ONLY when AI_MEMORY_AGENT_ID is set; single-operator default
    // unchanged. A hidden (already-contaminated) root returns `None` from the
    // visibility-filtered `get`, so the idempotent re-run is not blocked here.
    if let Some(caller) = crate::identity::resolve_read_visibility_caller()
        && let Some(root) = db::get(conn, &root_id).map_err(|e| e.to_string())?
        && !crate::visibility::caller_owns_for_mutation(&root, &caller, false)
    {
        return Err(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into());
    }

    // Actor recorded on the signed event: the ENFORCED read-visibility caller
    // (never the self-asserted request field), falling back to the `system`
    // sentinel when no enforced identity is configured.
    let actor =
        crate::identity::resolve_read_visibility_caller().unwrap_or_else(|| "system".to_string());

    // Belt-and-braces: validate the resolved root id is a well-formed id
    // (defence in depth against a malformed checkpoint reference).
    validate::RequestValidator::validate_id(&root_id).map_err(|e| e.to_string())?;

    let report = db::swarm_rewind(
        conn,
        &root_id,
        max_depth,
        &actor,
        target_kind,
        &freeze_routines,
        dry_run,
    )
    .map_err(|e| format!("swarm_rewind: {e}"))?;

    Ok(render_report(&report))
}

/// Render a [`crate::storage::SwarmRewindReport`] into the wire envelope.
fn render_report(r: &crate::storage::SwarmRewindReport) -> Value {
    json!({
        "root_id": r.root_id,
        (crate::storage::SWARM_REWIND_TARGET_KIND_KEY): r.target_kind,
        "dry_run": r.dry_run,
        "already_rewound": r.already_rewound,
        "root_contaminated": r.root_contaminated,
        "descendants_stamped": r.descendants_stamped,
        "descendants_already_contaminated": r.descendants_already_contaminated,
        "descendants_skipped_system_only": r.descendants_skipped_system_only,
        "descendants_total": r.descendants_total,
        "routines_requested": r.routines_requested,
        (crate::storage::SWARM_REWIND_ROUTINES_FROZEN_KEY): r.routines_frozen,
        "signed_event_id": r.signed_event_id,
        "cost": {
            "scope_key": r.cost.scope_key,
            "tokens_written": r.cost.tokens_written,
            "tokens_recalled": r.cost.tokens_recalled,
            "tokens_total": r.cost.tokens_total,
            "micro_usd": r.cost.micro_usd,
            "usd": r.cost.usd,
            "write_events": r.cost.write_events,
            "recall_events": r.cost.recall_events,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn swarm_rewind_parity_986() {
        let derived = derived_props_for::<SwarmRewindRequest>();
        assert_property_set_parity("memory_swarm_rewind", &derived);
        assert_descriptions_match("memory_swarm_rewind", &derived);
    }

    #[test]
    fn swarm_rewind_tool_metadata() {
        assert_eq!(SwarmRewindTool::name(), "memory_swarm_rewind");
        assert_eq!(SwarmRewindTool::family(), "power");
    }

    #[test]
    fn missing_to_returns_error() {
        let conn = db::open(std::path::Path::new(":memory:")).expect("open");
        let err = handle_swarm_rewind(&conn, &json!({})).unwrap_err();
        assert!(err.contains("to is required"), "got: {err}");
    }

    #[test]
    fn unknown_target_returns_error() {
        let conn = db::open(std::path::Path::new(":memory:")).expect("open");
        let err = handle_swarm_rewind(&conn, &json!({"to": "nope-id"})).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }
}
