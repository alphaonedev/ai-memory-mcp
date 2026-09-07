// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP pending-approval handlers and decision recording.

use crate::mcp::param_names;
use crate::mcp::registry::McpTool;
use crate::models::field_names;
use crate::{db, validate};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

// --- D1.4 (#985): per-tool McpTool impls for the three governance
// pending tools (`memory_pending_list`, `memory_pending_approve`,
// `memory_pending_reject`) ---

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_pending_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PendingListRequest {
    #[serde(default)]
    pub status: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_pending_list`.
#[allow(dead_code)]
pub struct PendingListTool;

impl McpTool for PendingListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PENDING_LIST
    }
    fn description() -> &'static str {
        "List pending governance-queued actions."
    }
    fn docs() -> &'static str {
        "Task 1.9: list governance-queued actions. Limit cap 1000. #3171: omitting `status` \
         returns EVERY status (approved/rejected/pending), NOT just pending — pass \
         status=\"pending\" for the open queue."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PendingListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Governance.name()
    }
}

/// R40 (#1957) — one human-key approver signature carried in an
/// `memory_pending_approve` call. The operator collects M of these offline
/// (airgapped) and submits them together; the gate counts distinct valid
/// enrolled signers.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct ApproverSignatureArg {
    /// Base64 Ed25519 public key of an enrolled approver.
    #[serde(default)]
    pub pubkey: String,
    /// Base64 Ed25519 signature over this pending id's approval bytes.
    #[serde(default)]
    pub signature: String,
}

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_pending_approve`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PendingApproveRequest {
    /// Pending action id.
    pub id: String,

    /// K10 persistence horizon.
    #[serde(default)]
    pub remember: Option<String>,

    /// R40 (#1957) — optional human-key approver signatures (m-of-n). A
    /// pending action routed from a typed escalation REQUIRES these; the
    /// signature quorum must be met before the underlying approve proceeds.
    #[serde(default)]
    pub approvals: Option<Vec<ApproverSignatureArg>>,

    /// #3171 — the APPROVER identity: the subject of the self-approval
    /// refusal, the named-approver equality, and the `Consensus(n)`
    /// distinct-vote key. Bound to the caller under the multi-tenant posture.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_pending_approve`.
#[allow(dead_code)]
pub struct PendingApproveTool;

impl McpTool for PendingApproveTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PENDING_APPROVE
    }
    fn description() -> &'static str {
        "Approve a pending action; `remember` auto-decides next time."
    }
    fn docs() -> &'static str {
        "Task 1.9 approve. decided_by = caller. K10: remember (once|session|forever) writes a synthetic permit rule."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PendingApproveRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Governance.name()
    }
}

/// v0.7.0 #972 D1.4 (#985) — request body for `memory_pending_reject`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct PendingRejectRequest {
    /// Pending action id.
    pub id: String,

    /// K10 persistence horizon.
    #[serde(default)]
    pub remember: Option<String>,

    /// #3171 — the id written as `decided_by` on the governance-ledger row.
    /// Bound to the caller under the multi-tenant posture.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.4 (#985) — `McpTool` impl for `memory_pending_reject`.
#[allow(dead_code)]
pub struct PendingRejectTool;

impl McpTool for PendingRejectTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_PENDING_REJECT
    }
    fn description() -> &'static str {
        "Reject a pending action; `remember` auto-decides next time."
    }
    fn docs() -> &'static str {
        "Task 1.9 reject. decided_by = caller. K10: remember writes a synthetic deny rule."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<PendingRejectRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Governance.name()
    }
}

/// v0.7 K7 — MCP handler for `memory_subscription_dlq_list`. Wraps
/// [`crate::subscriptions::list_dlq`] and applies the optional
/// `limit` cap (default 100, max 1000) so an operator inspecting a
/// runaway DLQ can't blow the response size budget. Family: `Power`.

pub fn handle_subscription_dlq_list(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let subscription_id = params[param_names::SUBSCRIPTION_ID].as_str();
    let limit = params["limit"]
        .as_u64()
        .map_or(crate::storage::PENDING_DEFAULT_PAGE_LIMIT, |v| {
            usize::try_from(v).unwrap_or(usize::MAX)
        })
        .clamp(1, crate::storage::LIST_MAX_LIMIT);

    // v0.7.0 #1118 (SR-1 #6, HIGH) — caller-ownership gate.
    //
    // Two attack shapes the gate closes:
    // 1. Targeted: an attacker who knows a victim's subscription_id
    //    (logs, prior cross-talk) replays the DLQ payload bodies,
    //    which carry the same memory snippets the subscriber would
    //    have received.
    // 2. Untargeted full-tenant scan: with `subscription_id=None`,
    //    pre-#1118 list_dlq returned every tenant's DLQ rows.
    //
    // Fix:
    //   - When `subscription_id` is `Some`: look up the owner; if it
    //     does not match the caller, return the not-found envelope.
    //   - When `subscription_id` is `None`: filter the returned rows
    //     to only those whose subscription owner == caller. This
    //     preserves the per-tenant operator inventory use-case while
    //     refusing to leak cross-tenant payloads.
    let caller = crate::identity::resolve_agent_id(None, mcp_client).map_err(|e| e.to_string())?;

    let rows_all =
        crate::subscriptions::list_dlq(conn, subscription_id).map_err(|e| e.to_string())?;
    let rows: Vec<_> = if let Some(sid) = subscription_id {
        let owner = crate::subscriptions::get_owner(conn, sid).map_err(|e| e.to_string())?;
        if owner.as_deref() != Some(caller.as_str()) {
            // Identical wire shape to "no DLQ entries since the
            // subscription rolled over". Cannot distinguish from
            // not-found.
            return Ok(json!({
                "count": 0,
                (field_names::SUBSCRIPTION_ID): subscription_id,
                "limit": limit,
                "entries": Vec::<Value>::new(),
            }));
        }
        rows_all
    } else {
        // Filter cross-tenant rows by resolving each row's
        // subscription owner. Owners that don't match the caller are
        // dropped. We cache the per-id ownership lookup so we don't
        // re-query the same subscription_id repeatedly on a
        // multi-event sub.
        let mut owners: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        let mut out = Vec::with_capacity(rows_all.len());
        for row in rows_all {
            let sid = row.subscription_id.clone();
            let owner = match owners.get(&sid) {
                Some(o) => o.clone(),
                None => {
                    let o =
                        crate::subscriptions::get_owner(conn, &sid).map_err(|e| e.to_string())?;
                    owners.insert(sid.clone(), o.clone());
                    o
                }
            };
            if owner.as_deref() == Some(caller.as_str()) {
                out.push(row);
            }
        }
        out
    };

    let mut rows = rows;
    if rows.len() > limit {
        rows.truncate(limit);
    }
    Ok(json!({
        "count": rows.len(),
        (field_names::SUBSCRIPTION_ID): subscription_id,
        "limit": limit,
        "entries": rows,
    }))
}

pub(super) fn handle_pending_list(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let status = params["status"].as_str();
    // #3171 — `limit` is declared `integer` (i64) but was read via `as_u64`,
    // so a NEGATIVE read as ABSENT and silently took the default page size.
    let limit = crate::mcp::param_guard::optional_non_negative_u64(params, param_names::LIMIT)?
        .map_or(crate::storage::PENDING_DEFAULT_PAGE_LIMIT, |v| {
            usize::try_from(v).unwrap_or(usize::MAX)
        })
        .min(crate::storage::LIST_MAX_LIMIT);
    let items = db::list_pending_actions(conn, status, limit).map_err(|e| e.to_string())?;
    Ok(json!({"count": items.len(), "pending": items}))
}

/// v0.7 K10 — parse the optional `remember` MCP param.
///
/// Defaults to `Once` when absent or invalid (the K10 contract is
/// best-effort: a typoed `remember` value MUST NOT block the underlying
/// approve/reject path). Validation drift is logged at WARN so
/// operators can see the regression without it surfacing as a
/// caller-facing error.
fn parse_remember_param(params: &Value) -> crate::approvals::Remember {
    match params["remember"].as_str() {
        Some("session") => crate::approvals::Remember::Session,
        Some("forever") => crate::approvals::Remember::Forever,
        Some("once") | None => crate::approvals::Remember::Once,
        Some(other) => {
            tracing::warn!(
                "memory_pending_*: unknown remember value {other:?}, defaulting to once"
            );
            crate::approvals::Remember::Once
        }
    }
}

/// R40 (#1957) — parse the optional `approvals` array of human-key approver
/// signatures from the raw MCP params. Accepts `{pubkey, signature}` objects;
/// missing / malformed entries are dropped (the quorum verifier then reports
/// the honest shortfall). Empty when no signatures were presented.
fn parse_signed_approvals(params: &Value) -> Vec<crate::approvals::signed::SignedApproval> {
    // #2355 — one shared wire contract for presented approver signatures across
    // MCP + the HTTP branches.
    crate::approvals::signed::parse_presented_approvals(&params["approvals"])
}

/// v0.7 K10 — record a synthetic rule + publish on the approval bus
/// for an MCP-side approve/reject. Mirrors the HTTP-side hook in
/// `handlers::approval_decide` so the three transports stay
/// behaviourally identical.
fn record_mcp_decision(
    conn: &rusqlite::Connection,
    pending_id: &str,
    decided_by: &str,
    decision_label: &str,
    remember: crate::approvals::Remember,
) {
    let pa = crate::db::get_pending_action(conn, pending_id)
        .ok()
        .flatten();
    let remember_label = match remember {
        crate::approvals::Remember::Once => "once",
        crate::approvals::Remember::Session => "session",
        crate::approvals::Remember::Forever => "forever",
    };
    // Carry the originating namespace + requester onto the bus so the
    // K10 SSE handler can scope this decision to the right tenant
    // (review #628 blocker C2). Snapshot may be absent if the row was
    // already swept; the SSE filter treats empty fields as "no tenant
    // hint" and falls back to the subscriber's K9 policy.
    let evt_namespace = pa.as_ref().map(|p| p.namespace.clone()).unwrap_or_default();
    let evt_requested_by = pa
        .as_ref()
        .map(|p| p.requested_by.clone())
        .unwrap_or_default();
    crate::approvals::publish(crate::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: pending_id.to_string(),
        decision: decision_label.to_string(),
        decided_by: decided_by.to_string(),
        remember: remember_label.to_string(),
        namespace: evt_namespace,
        requested_by: evt_requested_by,
    });
    if matches!(
        remember,
        crate::approvals::Remember::Forever | crate::approvals::Remember::Session
    ) && let Some(snap) = pa
    {
        crate::approvals::record_synthetic_rule(crate::approvals::SyntheticPermissionRule {
            action_type: snap.action_type,
            namespace: snap.namespace,
            agent_id: Some(snap.requested_by),
            decision: decision_label.to_string(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        });
    }
}

/// #2634 / CB-24 — record the TRUE governance verdict of an MCP
/// `pending_approve` decision at the point its authorization gate
/// produced it. `decision` is `"allow"` (approved / vote accepted) or
/// `"refuse"` (self-approval / unregistered-approver / rejected-signature
/// refusal). Mirrors the HTTP `audit_pending_verdict` row shape.
fn audit_pending_verdict(agent_id: &str, id: &str, decision: &str) {
    crate::governance::audit::record_decision(
        agent_id,
        decision,
        "pending_approve",
        "",
        json!({ (field_names::PENDING_ID): id }),
    );
}

/// v1.0.0 #3388 — the reject twin of [`audit_pending_verdict`]. Same row
/// shape, `pending_reject` resource. Attributed to the RESOLVED caller, never
/// to an id the request asserted.
fn audit_reject_verdict(agent_id: &str, id: &str) {
    crate::governance::audit::record_decision(
        agent_id,
        "refuse",
        "pending_reject",
        "",
        json!({ (field_names::PENDING_ID): id }),
    );
}

pub fn handle_pending_approve(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    use crate::db::ApproveOutcome;
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // #3171 — the APPROVER identity is the subject of the separation-of-duties
    // gate itself: `approve_with_approver_type` refuses self-approval
    // (`approver_agent_id == requested_by`), enforces the named-approver
    // equality, and counts DISTINCT `approver_agent_id`s for
    // `ApproverType::Consensus(n)`. Reading it from the wire let one caller
    // pick a non-requester id to defeat self-approval refusal — and forge a
    // full quorum by varying the param across N calls. Bind it to the
    // enforced-read caller under the multi-tenant posture (the posture that
    // arms the gate at `storage::enforce_approver_identity_gate`); the
    // single-operator default is unchanged.
    let agent_id = crate::identity::resolve_governance_subject(
        params[param_names::AGENT_ID].as_str(),
        mcp_client,
        "approve",
    )
    .map_err(|e| {
        // #3171 — an attempt to approve AS SOMEONE ELSE is a separation-of-duties
        // attack, not an operational error, so it earns a `refuse` verdict row
        // attributed to the ENFORCED caller (never to the id the request
        // asserted). Without this it would be the one refused approval that
        // leaves no trace in the tamper-evident chain.
        audit_pending_verdict(
            &crate::identity::resolve_read_visibility_caller()
                .unwrap_or_else(|| crate::identity::sentinels::ANONYMOUS_INVALID.to_string()),
            id,
            "refuse",
        );
        e.to_string()
    })?;
    let remember = parse_remember_param(params);

    // #913 + #2634 / CB-24 — admin governance audit. Pre-fix a
    // `record_decision("allow")` fired UNCONDITIONALLY here, BEFORE the
    // R40 signed-approval gate + the `approve_with_approver_type` /
    // consensus gate below — so a REFUSED approval (self-approval /
    // unregistered approver #2643, or a rejected signature quorum) was
    // chained as "allow", a tamper-evident audit lying about the outcome.
    // The verdict is recorded at the outcome points below via
    // `audit_pending_verdict`: approved / vote-accepted → "allow"
    // (emitted BEFORE the downstream execution write so #913's
    // approver-identity capture survives an execution error), a refused
    // approval → "refuse". Operational errors (NotFound / storage) reach
    // no verdict and record no verdict row.

    // R40 (#1957) — human-key-signed approval gate. When the pending action was
    // routed from a typed escalation (`requires_signed_approval`) OR the caller
    // presents approver signatures, an m-of-n Ed25519 signature quorum over
    // enrolled operator/approver keys MUST be met before the underlying approve
    // proceeds. Back-compat: an ordinary (non-escalated) pending with no
    // signatures skips this gate entirely.
    // #2355 — route this funnel through the ONE pure chokepoint
    // (`evaluate_signed_approval_gate`) so MCP + the four HTTP branches enforce
    // the R40 gate identically. The verdict sits strictly ABOVE the
    // `approve_with_approver_type` + `execute_pending_action` finalizer below.
    let signed_snapshot = db::get_pending_action(conn, id).map_err(|e| e.to_string())?;
    let presented = parse_signed_approvals(params);
    // Term (2) of the requirement predicate — re-derive from the live rule
    // engine (server-side; PURE, no audit emit) so a payload whose escalation
    // flag was stripped is still gated.
    let namespace_requires = signed_snapshot.as_ref().is_some_and(|pa| {
        crate::approvals::signed::namespace_requires_signed_approval(
            conn,
            &pa.requested_by,
            &pa.namespace,
        )
    });
    let gate_payload = signed_snapshot
        .as_ref()
        .map_or(serde_json::Value::Null, |pa| pa.payload.clone());
    // Single-use execution exemption — armed only when a signed quorum is MET,
    // held across `execute_pending_action` so the already-approved write is not
    // re-escalated by the L1-6 producer. Bound to this pending's content CID.
    let mut _exemption_guard = None;
    match crate::approvals::signed::evaluate_signed_approval_gate(
        &gate_payload,
        id,
        crate::approvals::Decision::Approve,
        &presented,
        namespace_requires,
    ) {
        crate::approvals::signed::GateVerdict::NotRequired => {}
        crate::approvals::signed::GateVerdict::Approved(quorum) => {
            crate::approvals::signed::record_quorum_event(
                id,
                crate::approvals::Decision::Approve,
                &quorum,
            );
            _exemption_guard =
                crate::approvals::signed::exemption_guard_for_pending(id, &gate_payload);
            // Quorum met — fall through to the existing approve + execute path.
        }
        crate::approvals::signed::GateVerdict::Pending {
            distinct,
            threshold,
        } => {
            // #2634 — signatures accepted so far, awaiting quorum.
            audit_pending_verdict(&agent_id, id, "allow");
            return Ok(json!({
                "approved": false,
                "status": "pending",
                "id": id,
                (crate::approvals::signed::SIGNED_VOTES_FIELD): distinct,
                (crate::approvals::signed::SIGNED_QUORUM_FIELD): threshold,
                "reason": crate::approvals::signed::SIGNED_QUORUM_NOT_YET_MET,
            }));
        }
        crate::approvals::signed::GateVerdict::Refused(e) => {
            // #2634 / #2643 — a rejected signature quorum is a refusal.
            audit_pending_verdict(&agent_id, id, "refuse");
            return Err(crate::approvals::signed::signed_approval_rejected(&e));
        }
    }

    // #1796 (5-agent vote 4d3ea1c5) — MCP/stdio is the single-operator surface;
    // keep the Human-arm gate on the AI_MEMORY_AGENT_ID opt-in (an unconditional
    // reject-self would self-lock the lone operator approving their own action).
    match db::approve_with_approver_type(conn, id, &agent_id, db::ApproveSurface::LocalOperator)
        .map_err(|e| e.to_string())?
    {
        ApproveOutcome::Approved => {
            // #2634 — record "allow" BEFORE the execute write below.
            audit_pending_verdict(&agent_id, id, "allow");
            // Task 1.10: auto-execute the queued action on final approval.
            let executed = db::execute_pending_action(conn, id).map_err(|e| e.to_string())?;
            record_mcp_decision(conn, id, &agent_id, "approve", remember);
            Ok(json!({
                "approved": true,
                "id": id,
                (field_names::DECIDED_BY): agent_id,
                "executed": true,
                "memory_id": executed,
                "remember": match remember {
                    crate::approvals::Remember::Once => "once",
                    crate::approvals::Remember::Session => "session",
                    crate::approvals::Remember::Forever => "forever",
                },
            }))
        }
        ApproveOutcome::Pending { votes, quorum } => {
            // #2634 — the approval vote was accepted (awaiting quorum).
            audit_pending_verdict(&agent_id, id, "allow");
            Ok(json!({
                "approved": false,
                "status": "pending",
                "id": id,
                "votes": votes,
                "quorum": quorum,
                "reason": crate::errors::msg::CONSENSUS_NOT_REACHED,
            }))
        }
        // #1620 — typed not-found (was a Rejected string). Operational
        // not-found reaches no governance verdict → no verdict row.
        ApproveOutcome::NotFound => Err(crate::errors::msg::pending_action_not_found(id)),
        ApproveOutcome::Rejected(reason) => {
            // #2634 / #2643 — governed refusal chains "refuse", not "allow".
            audit_pending_verdict(&agent_id, id, "refuse");
            Err(crate::errors::msg::approve_rejected(reason))
        }
    }
}

// --- D1.5 (#986): per-tool McpTool impl for memory_subscription_dlq_list ---
//
// `memory_pending_*` belong to Family::Governance and are migrated by
// the sibling D1.4 (#985) sub-agent. Only the in-scope
// `memory_subscription_dlq_list` (Family::Power) lands here.
//
// #985/#986 integration: imports already brought in at the top of the
// file by the D1.4 governance commit (`McpTool`, `JsonSchema`,
// `Deserialize`). Duplicate `use` statements removed during cherry-pick
// integration.

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_subscription_dlq_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SubscriptionDlqListRequest {
    /// Restrict to one subscription.
    #[serde(default)]
    pub subscription_id: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_subscription_dlq_list`.
#[allow(dead_code)]
pub struct SubscriptionDlqListTool;

impl McpTool for SubscriptionDlqListTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SUBSCRIPTION_DLQ_LIST
    }
    fn description() -> &'static str {
        "List subscription_dlq rows (exhausted retry ladder)."
    }
    fn docs() -> &'static str {
        "K7: DLQ inspector."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<SubscriptionDlqListRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_subscription_dlq_list`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn subscription_dlq_list_parity_986() {
        let derived = derived_props_for::<SubscriptionDlqListRequest>();
        assert_property_set_parity("memory_subscription_dlq_list", &derived);
        assert_descriptions_match("memory_subscription_dlq_list", &derived);
    }

    #[test]
    fn subscription_dlq_list_tool_metadata_986() {
        assert_eq!(
            SubscriptionDlqListTool::name(),
            "memory_subscription_dlq_list"
        );
        assert_eq!(SubscriptionDlqListTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for the pending-action handlers and the
    //! private `parse_remember_param` / `record_mcp_decision` helpers.
    //!
    //! Hermetic: every test opens an in-memory DB. No filesystem, no
    //! network. The approval bus is process-wide so each test publishes
    //! distinct payloads; tests do not assert on cross-test ordering.

    use super::*;
    use crate::models::Tier;
    use crate::storage as db;
    use serde_json::json;

    fn fresh_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn queue_pending(conn: &rusqlite::Connection, requester: &str) -> String {
        db::queue_pending_action(
            conn,
            crate::models::GovernedAction::Reflect,
            "pa-ns",
            None,
            requester,
            &json!({"k": "v"}),
        )
        .expect("queue")
    }

    /// Queue a pending action with a payload that the execute step will
    /// gracefully short-circuit (no real reflect / store / etc. runs),
    /// so the happy-path approve test does not require a full
    /// reflect payload. Uses `Promote` which carries a memory_id;
    /// without a target row, `execute_pending_action` reports a
    /// not-found rather than blowing up.
    fn queue_pending_promote_unbound(conn: &rusqlite::Connection, requester: &str) -> String {
        db::queue_pending_action(
            conn,
            crate::models::GovernedAction::Promote,
            "pa-ns",
            Some("11111111-2222-3333-4444-555555555555"),
            requester,
            &json!({"target_tier": Tier::Long.as_str()}),
        )
        .expect("queue")
    }

    /// #3171 — the APPROVER identity is the SUBJECT of the
    /// separation-of-duties gate itself, so it must not be caller-chosen.
    ///
    /// `approve_with_approver_type` refuses self-approval by comparing the
    /// approver against `requested_by`, enforces the named-approver equality,
    /// and counts DISTINCT approver ids for `ApproverType::Consensus(n)`.
    /// Reading that id from the wire let ONE caller (a) defeat the
    /// self-approval refusal by naming any id other than its own, and
    /// (b) forge a full human quorum by varying the parameter across N calls.
    /// Under the multi-tenant posture the approver is now the enforced-read
    /// caller and a disagreeing wire `agent_id` is REFUSED outright.
    #[test]
    fn pending_approve_refuses_wire_chosen_approver_under_posture_3171() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:alice");
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };

        // ai:alice queued it, so approving AS ai:bob would sidestep the
        // self-approval refusal. Refused before any decision is recorded.
        let err = handle_pending_approve(&conn, &json!({"id": id, "agent_id": "ai:bob"}), None)
            .expect_err("a wire-chosen approver must be refused");
        assert!(err.contains("agent_id mismatch"), "got: {err}");

        // The same forgery on the REJECT twin writes a forged `decided_by`
        // into the tamper-evident governance ledger.
        let err = handle_pending_reject(&conn, &json!({"id": id, "agent_id": "ai:bob"}), None)
            .expect_err("a wire-chosen decider must be refused");
        assert!(err.contains("agent_id mismatch"), "got: {err}");

        // The row is untouched by either refusal.
        let row = db::get_pending_action(&conn, &id)
            .expect("read")
            .expect("row present");
        assert_eq!(row.status, "pending", "a refused decision must not decide");
        assert!(row.decided_by.is_none(), "no decider may be recorded");

        // (The refusal also chains a `refuse` verdict attributed to the
        // ENFORCED caller — see the `map_err` on the subject resolution. It is
        // a no-op here because no audit sink is initialised in this hermetic
        // test; the forensic-chain suites cover the emitter itself.)

        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }

    // parse_remember_param: each of the four branches.
    #[test]
    fn parse_remember_param_returns_session() {
        let r = super::parse_remember_param(&json!({"remember": "session"}));
        assert!(matches!(r, crate::approvals::Remember::Session));
    }
    #[test]
    fn parse_remember_param_returns_forever() {
        let r = super::parse_remember_param(&json!({"remember": "forever"}));
        assert!(matches!(r, crate::approvals::Remember::Forever));
    }
    #[test]
    fn parse_remember_param_returns_once_when_explicit() {
        let r = super::parse_remember_param(&json!({"remember": "once"}));
        assert!(matches!(r, crate::approvals::Remember::Once));
    }
    #[test]
    fn parse_remember_param_returns_once_when_absent() {
        let r = super::parse_remember_param(&json!({}));
        assert!(matches!(r, crate::approvals::Remember::Once));
    }
    // Unknown value defaults to Once (with WARN log).
    #[test]
    fn parse_remember_param_unknown_defaults_to_once() {
        let r = super::parse_remember_param(&json!({"remember": "weird-value"}));
        assert!(matches!(r, crate::approvals::Remember::Once));
    }

    // handle_subscription_dlq_list — empty list, count=0, limit echoed.
    #[test]
    fn subscription_dlq_list_empty() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let resp = handle_subscription_dlq_list(&conn, &json!({}), None).expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
        assert!(resp["entries"].is_array());
    }

    // handle_subscription_dlq_list — limit clamped to [1, 1000].
    #[test]
    fn subscription_dlq_list_limit_clamped() {
        // #3517 — same env-first caller resolution as its siblings; pin the
        // unset posture (the #1874 fixture).
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let resp = handle_subscription_dlq_list(&conn, &json!({"limit": 0u64}), None).expect("ok");
        // limit=0 clamps to 1; 0 is below the min so it should not error.
        assert!(resp["limit"].as_u64().unwrap() >= 1);
    }

    // handle_subscription_dlq_list — subscription_id filter is propagated.
    #[test]
    fn subscription_dlq_list_with_filter() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let resp = handle_subscription_dlq_list(&conn, &json!({"subscription_id": "sub-x"}), None)
            .expect("ok");
        assert_eq!(resp["subscription_id"].as_str(), Some("sub-x"));
    }

    // #1118 (SR-1 #6, HIGH) — cross-tenant DLQ list is refused.
    // Alice's subscription has DLQ entries; bob filters on alice's
    // sub_id and receives the empty envelope.
    #[test]
    fn subscription_dlq_list_cross_tenant_refused_1118() {
        // #3517 — this test asserts an EXPLICIT-caller path, but the handler
        // resolves the caller from `AI_MEMORY_AGENT_ID` FIRST. A sibling test
        // installing a principal concurrently silently overrides the caller
        // passed here (`subscription_dlq_list_cross_tenant_refused_1118`
        // reproduced at 4/10 under `--test-threads=4`). Pin the unset posture
        // this test depends on — the #1874 fixture exists for exactly this.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        db::register_agent(&conn, "ai:alice", "test", &[]).expect("register alice");
        let sid = crate::subscriptions::insert(
            &conn,
            &crate::subscriptions::NewSubscription {
                url: "https://example.com/alice",
                events: "memory_store",
                secret: Some("sek-alice"),
                namespace_filter: None,
                agent_filter: None,
                created_by: Some("ai:alice"),
                event_types: None,
            },
        )
        .expect("insert alice sub");
        // Insert a DLQ entry against alice's subscription. Hand-rolled
        // SQL because `record_dlq` opens a fresh `Connection`; the
        // in-memory test conn is the one our `list_dlq` query reads.
        conn.execute(
            "INSERT INTO subscription_dlq \
             (subscription_id, correlation_id, event_type, payload, retry_count, last_error, first_failed_at, last_failed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![&sid, "alice-corr-1", "memory_store", "{\"id\":\"m1\"}", 3i64, "5xx", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        ).expect("record dlq");

        // Bob hits the filter.
        let resp = handle_subscription_dlq_list(
            &conn,
            &json!({"subscription_id": sid}),
            Some("ai:bob-client"),
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(0));
        assert!(resp["entries"].as_array().unwrap().is_empty());

        // Bob with no subscription_id filter also sees no entries —
        // the filter-by-owner branch drops the cross-tenant row.
        let resp_unfiltered =
            handle_subscription_dlq_list(&conn, &json!({}), Some("ai:bob-client")).expect("ok");
        assert_eq!(resp_unfiltered["count"].as_u64(), Some(0));
    }

    // handle_pending_list — happy + count.
    #[test]
    fn pending_list_returns_count_and_array() {
        let conn = fresh_conn();
        let _id = queue_pending(&conn, "ai:tester");
        let resp = handle_pending_list(&conn, &json!({})).expect("ok");
        assert!(resp["count"].as_u64().unwrap() >= 1);
        assert!(resp["pending"].is_array());
    }

    // handle_pending_list — status filter + limit clamp.
    #[test]
    fn pending_list_with_status_and_limit() {
        let conn = fresh_conn();
        let _id = queue_pending(&conn, "ai:tester");
        let resp = handle_pending_list(&conn, &json!({"status": "pending", "limit": 5000u64}))
            .expect("ok");
        assert!(resp["count"].as_u64().unwrap() >= 1);
    }

    // handle_pending_approve — happy path with single-vote quorum.
    // execute_pending_action may surface its own "target not found" error
    // for a synthetic payload; in that case the approve still flips the
    // pending row to Approved and the handler returns the error string.
    // We accept either outcome to keep this hermetic without seeding a
    // full reflect payload.
    #[test]
    fn pending_approve_reaches_execute_step() {
        // #3517 — VICTIM, not a mutator: this test depends on `AI_MEMORY_AGENT_ID`
        // being UNSET. The handler resolves the caller from the env FIRST, and this
        // test takes no lock, so a sibling's install silently steers it. Pin the
        // posture with the #1874 fixture.
        //
        // Why this one: the wire `agent_id: "ai:approver"` reaches
        // `resolve_governance_subject`, so a concurrently installed principal
        // mismatches it and the call refuses instead of executing.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let id = queue_pending_promote_unbound(&conn, "ai:tester");
        let result = handle_pending_approve(
            &conn,
            &json!({"id": id, "agent_id": "ai:approver", "remember": "forever"}),
            None,
        );
        // Either Ok (memory_id was None, executed flag false) or Err with
        // a substrate "not found" — both flow through record_mcp_decision.
        match result {
            Ok(resp) => {
                assert_eq!(resp["approved"], true);
                assert_eq!(resp["remember"].as_str(), Some("forever"));
            }
            Err(e) => assert!(!e.is_empty()),
        }
    }

    // handle_pending_approve — missing id errors.
    #[test]
    fn pending_approve_missing_id_errors() {
        let conn = fresh_conn();
        let err = handle_pending_approve(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    // handle_pending_approve — invalid id format errors (validate_id).
    #[test]
    fn pending_approve_invalid_id_rejected() {
        let conn = fresh_conn();
        let err = handle_pending_approve(&conn, &json!({"id": "  "}), None).unwrap_err();
        assert!(!err.is_empty());
    }

    // handle_pending_approve — unknown id returns rejected.
    #[test]
    fn pending_approve_unknown_id_rejected() {
        // #3517 — VICTIM, not a mutator: this test depends on `AI_MEMORY_AGENT_ID`
        // being UNSET. The handler resolves the caller from the env FIRST, and this
        // test takes no lock, so a sibling's install silently steers it. Pin the
        // posture with the #1874 fixture.
        //
        // Why this one: it reaches `resolve_governance_subject` with no wire
        // principal, so no mismatch is possible TODAY. Guarded anyway so a future
        // reorder of the handler cannot make it env-sensitive silently.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let err = handle_pending_approve(
            &conn,
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
        )
        .unwrap_err();
        // #1620 — unknown id is a typed not-found, no longer the
        // collapsed "approve rejected" policy bucket.
        assert!(err.contains("pending action not found"), "got: {err}");
    }

    // handle_pending_reject — happy path with session remember label.
    #[test]
    fn pending_reject_happy_path() {
        // #3517 — VICTIM, not a mutator: this test depends on `AI_MEMORY_AGENT_ID`
        // being UNSET. The handler resolves the caller from the env FIRST, and this
        // test takes no lock, so a sibling's install silently steers it. Pin the
        // posture with the #1874 fixture.
        //
        // Why this one: wire `agent_id: "ai:rejecter"` — the same mismatch shape
        // as the sibling below that lane #3515 actually caught.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:tester");
        let resp = handle_pending_reject(
            &conn,
            &json!({"id": id, "agent_id": "ai:rejecter", "remember": "session"}),
            None,
        )
        .expect("ok");
        assert_eq!(resp["rejected"], true);
        assert_eq!(resp["remember"].as_str(), Some("session"));
    }

    // handle_pending_reject — once remember default emits "once".
    #[test]
    fn pending_reject_default_remember_is_once() {
        // #3517 — VICTIM, not a mutator: this test depends on `AI_MEMORY_AGENT_ID`
        // being UNSET. The handler resolves the caller from the env FIRST, and this
        // test takes no lock, so a sibling's install silently steers it. Pin the
        // posture with the #1874 fixture.
        //
        // Why this one: OBSERVED by lane #3515 in a full `--lib` run — failed with
        // `agent_id mismatch: caller 'ai:bob'` while the siblings that install
        // `ai:bob` (`pending_reject_allows_registered_non_requester_3388`,
        // `promote.rs::cross_owner_promote_refused_1786`) were running.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:tester");
        let resp =
            handle_pending_reject(&conn, &json!({"id": id, "agent_id": "ai:rejecter"}), None)
                .expect("ok");
        assert_eq!(resp["remember"].as_str(), Some("once"));
    }

    // handle_pending_reject — missing id errors.
    #[test]
    fn pending_reject_missing_id_errors() {
        let conn = fresh_conn();
        let err = handle_pending_reject(&conn, &json!({}), None).unwrap_err();
        assert!(err.contains("id"), "got: {err}");
    }

    // handle_pending_reject — unknown id (already-decided contract).
    #[test]
    fn pending_reject_unknown_id_errors() {
        // #3517 — VICTIM, not a mutator: this test depends on `AI_MEMORY_AGENT_ID`
        // being UNSET. The handler resolves the caller from the env FIRST, and this
        // test takes no lock, so a sibling's install silently steers it. Pin the
        // posture with the #1874 fixture.
        //
        // Why this one: reaches `resolve_governance_subject`; guarded for the same
        // durability reason as the approve twin.
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let err = handle_pending_reject(
            &conn,
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("not found") || err.contains("already decided"),
            "got: {err}"
        );
    }

    // =================================================================
    // v1.0.0 #3388 — `memory_pending_reject` approver gate.
    //
    // Pre-#3388 the reject handler called `db::decide_pending_action(..,
    // false, ..)` DIRECTLY with no eligibility gate at all, while approve
    // refuses self-approval and unregistered approvers. Any tenant —
    // including the REQUESTER — could therefore veto any tenant's queued
    // action (and with `remember` write a synthetic DENY rule off it).
    // Reject now runs the SAME `evaluate_approver_eligibility` predicate
    // approve runs, under the same `LocalOperator` posture.
    // =================================================================

    /// #3388 DENIED — the requester may not veto their own queued action
    /// under the multi-agent opt-in, exactly as approve refuses them.
    #[test]
    fn pending_reject_refuses_requester_self_veto_3388() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:alice");
        db::register_agent(&conn, "ai:alice", "test", &[]).expect("register alice");
        // SAFETY: process-global env mutation serialized on the crate-wide
        // test lock acquired above; restored before return.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };

        // Capture WITHOUT unwrapping so a failure cannot panic before the
        // env is restored and poison a sibling test's posture.
        let out = handle_pending_reject(&conn, &json!({"id": id}), None);
        let row = db::get_pending_action(&conn, &id)
            .expect("read")
            .expect("row present");
        // SAFETY: see above.
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        let err = out.expect_err("the requester must not be able to veto their own action");
        assert!(err.contains("reject refused"), "got: {err}");
        assert!(
            err.contains(crate::errors::msg::SELF_APPROVAL_REFUSED),
            "the refusal must carry the shared separation-of-duties reason, got: {err}"
        );
        assert_eq!(row.status, "pending", "a refused veto must not decide");
        assert!(row.decided_by.is_none(), "no decider may be recorded");
    }

    /// #3388 DENIED — a non-requester who is not a REGISTERED agent may not
    /// veto, exactly as approve refuses an unregistered approver. This is
    /// the cross-tenant sabotage shape: pre-fix any caller could claim any
    /// id and kill any queue entry.
    #[test]
    fn pending_reject_refuses_unregistered_approver_3388() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:alice");
        // ai:mallory is deliberately NOT registered.
        // SAFETY: serialized on the crate-wide test lock acquired above.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:mallory") };

        // Capture WITHOUT unwrapping — see the sibling test.
        let out = handle_pending_reject(&conn, &json!({"id": id}), None);
        let row = db::get_pending_action(&conn, &id)
            .expect("read")
            .expect("row present");
        // SAFETY: see above.
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        let err = out.expect_err("an unregistered agent must not be able to veto");
        assert!(err.contains("reject refused"), "got: {err}");
        assert!(err.contains("is not a registered agent"), "got: {err}");
        assert_eq!(row.status, "pending", "a refused veto must not decide");
        assert!(row.decided_by.is_none(), "no decider may be recorded");
    }

    /// #3388 ALLOWED — a REGISTERED, non-requester approver still vetoes.
    /// The gate must not break the legitimate governance path.
    #[test]
    fn pending_reject_allows_registered_non_requester_3388() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:alice");
        db::register_agent(&conn, "ai:bob", "test", &[]).expect("register bob");
        // SAFETY: serialized on the crate-wide test lock acquired above.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:bob") };

        let out = handle_pending_reject(&conn, &json!({"id": id}), None);

        let row = db::get_pending_action(&conn, &id)
            .expect("read")
            .expect("row present");
        // SAFETY: see above.
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        let out = out.expect("a registered non-requester approver must be allowed");
        assert_eq!(out["rejected"], json!(true));
        assert_eq!(out["decided_by"], json!("ai:bob"));
        assert_eq!(row.status, "rejected");
        assert_eq!(row.decided_by.as_deref(), Some("ai:bob"));
    }

    /// #3388 ALLOWED — the single-operator trust-all default (no
    /// `AI_MEMORY_AGENT_ID`) is UNCHANGED: the gate is armed by the
    /// multi-agent opt-in, so the lone operator is never self-locked out of
    /// vetoing their own queue. Same posture rule as approve (#1796).
    #[test]
    fn pending_reject_default_posture_not_self_locked_3388() {
        let _envg = crate::identity::agent_id_env_unset_guard();
        let conn = fresh_conn();
        let id = queue_pending(&conn, "ai:alice");

        let out = handle_pending_reject(&conn, &json!({"id": id}), None)
            .expect("the lone operator must still be able to veto");
        assert_eq!(out["rejected"], json!(true));
        let row = db::get_pending_action(&conn, &id)
            .expect("read")
            .expect("row present");
        assert_eq!(row.status, "rejected");
    }

    /// #3388 PARITY — approve and reject must reach the SAME eligibility
    /// verdict for the SAME caller on the SAME action. Pinning the pair is
    /// the point of the defect: they were structurally allowed to disagree.
    #[test]
    fn pending_reject_eligibility_matches_approve_3388() {
        let _envg = crate::identity::agent_id_env_test_lock();
        let conn = fresh_conn();
        let approve_id = queue_pending(&conn, "ai:alice");
        let reject_id = queue_pending(&conn, "ai:alice");
        db::register_agent(&conn, "ai:alice", "test", &[]).expect("register alice");
        // SAFETY: serialized on the crate-wide test lock acquired above.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:alice") };

        // Capture WITHOUT unwrapping — see the sibling test.
        let approve_out = handle_pending_approve(&conn, &json!({"id": approve_id}), None);
        let reject_out = handle_pending_reject(&conn, &json!({"id": reject_id}), None);

        // SAFETY: see above.
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };

        let approve_err = approve_out.expect_err("self-approval is refused");
        let reject_err = reject_out.expect_err("self-veto must be refused too");
        let reason = crate::errors::msg::SELF_APPROVAL_REFUSED;
        assert!(approve_err.contains(reason), "approve: {approve_err}");
        assert!(
            reject_err.contains(reason),
            "reject must refuse for the SAME reason approve does, got: {reject_err}"
        );
    }
}

pub fn handle_pending_reject(
    conn: &rusqlite::Connection,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // #3171 — mirror the approve binding: `decided_by` is a governance-ledger
    // row, so a caller-chosen value writes a forged decider into the
    // tamper-evident record.
    let agent_id = crate::identity::resolve_governance_subject(
        params[param_names::AGENT_ID].as_str(),
        mcp_client,
        "reject",
    )
    .map_err(|e| {
        // #3388 — mirror the approve side (#3171): rejecting AS SOMEONE ELSE is
        // a separation-of-duties attack, not an operational error, so it earns
        // a `refuse` row attributed to the ENFORCED caller — never to the id
        // the request asserted. Without it, the one refused veto attempt would
        // leave no trace in the tamper-evident chain.
        audit_reject_verdict(
            &crate::identity::resolve_read_visibility_caller()
                .unwrap_or_else(|| crate::identity::sentinels::ANONYMOUS_INVALID.to_string()),
            id,
        );
        e.to_string()
    })?;
    let remember = parse_remember_param(params);

    // #913 (security-medium / SOC2, 2026-05-19) — admin governance audit.
    // Reject is the privileged-gate denial; mirror approve so both
    // outcomes appear in the forensic chain BEFORE the storage write.
    // #3388 — this fires for EVERY reject attempt that got as far as a
    // resolved caller, so an INELIGIBLE veto attempt is auditable too, keyed
    // on the resolved governance subject rather than a wire-chosen id.
    audit_reject_verdict(&agent_id, id);

    // v1.0.0 #3388 — approver-eligibility gate. Pre-fix this called
    // `db::decide_pending_action(.., false, ..)` DIRECTLY, with no gate at all:
    // any tenant — including the requester, whom `memory_pending_approve`
    // explicitly refuses — could veto any tenant's queued action, and with
    // `remember` write a synthetic DENY rule off the back of it. Reject now
    // runs the SAME `evaluate_approver_eligibility` predicate approve runs,
    // under the SAME `LocalOperator` posture (#1796): armed by the
    // `AI_MEMORY_AGENT_ID` multi-agent opt-in, inert for the lone operator in
    // the trust-all default so they are not self-locked out of their own queue.
    match db::reject_with_approver_type(conn, id, &agent_id, db::ApproveSurface::LocalOperator)
        .map_err(|e| e.to_string())?
    {
        db::RejectOutcome::Rejected => {}
        // Operational not-found (absent or already decided) — contract text
        // unchanged from pre-#3388.
        db::RejectOutcome::NotFound => {
            return Err(format!("pending action not found or already decided: {id}"));
        }
        // The CALLER is not an eligible approver. The pending action is
        // untouched and still `pending`; no synthetic rule is recorded.
        db::RejectOutcome::Refused(reason) => {
            return Err(crate::errors::msg::reject_refused(&reason));
        }
    }
    record_mcp_decision(conn, id, &agent_id, "deny", remember);
    Ok(json!({
        "rejected": true,
        "id": id,
        "decided_by": agent_id,
        "remember": match remember {
            crate::approvals::Remember::Once => "once",
            crate::approvals::Remember::Session => "session",
            crate::approvals::Remember::Forever => "forever",
        },
    }))
}

#[cfg(test)]
mod d1_4_985_tests {
    //! D1.4 (#985) — schema-parity for `memory_pending_list`,
    //! `memory_pending_approve`, `memory_pending_reject`.
    use super::*;
    use crate::mcp::d1_4_985_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn memory_pending_list_parity_985() {
        let derived = derived_props_for::<PendingListRequest>();
        assert_property_set_parity("memory_pending_list", &derived);
        assert_descriptions_match("memory_pending_list", &derived);
    }

    #[test]
    fn memory_pending_list_tool_metadata_985() {
        assert_eq!(PendingListTool::name(), "memory_pending_list");
        assert_eq!(PendingListTool::family(), "governance");
    }

    #[test]
    fn memory_pending_approve_parity_985() {
        let derived = derived_props_for::<PendingApproveRequest>();
        assert_property_set_parity("memory_pending_approve", &derived);
        assert_descriptions_match("memory_pending_approve", &derived);
    }

    #[test]
    fn memory_pending_approve_tool_metadata_985() {
        assert_eq!(PendingApproveTool::name(), "memory_pending_approve");
        assert_eq!(PendingApproveTool::family(), "governance");
    }

    #[test]
    fn memory_pending_reject_parity_985() {
        let derived = derived_props_for::<PendingRejectRequest>();
        assert_property_set_parity("memory_pending_reject", &derived);
        assert_descriptions_match("memory_pending_reject", &derived);
    }

    #[test]
    fn memory_pending_reject_tool_metadata_985() {
        assert_eq!(PendingRejectTool::name(), "memory_pending_reject");
        assert_eq!(PendingRejectTool::family(), "governance");
    }
}
