// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — `memory_checkpoint_*` MCP stdio tools. Thin
//! wrappers over the `crate::checkpoints` sqlite free-functions that expose the
//! attested-checkpoint coordination substrate (ROADMAP §11.4) to MCP callers.
//! Mirrors the `crate::signals` / `mcp::tools::signal` split: the handlers hold
//! a bare `rusqlite::Connection` (not a SAL store), so they call the
//! free-functions directly. `handle_checkpoint_resolve` additionally takes the
//! dispatch context's `active_keypair` so the resolution is Ed25519-attested in
//! place via [`crate::checkpoints::resolve`] when a signing keypair is
//! available.

use crate::identity::keypair::AgentKeypair;
use crate::mcp::param_names;
// #3007 — the local `epoch_advance` gate decodes the operator's detached
// signature from URL-safe base64, the MCP Ed25519-signature convention (see
// `crate::mcp::server_identity`).
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

/// JSON response field carrying the serialized checkpoint object (SSOT for the
/// repeated output key across the `memory_checkpoint_*` handlers).
const RESP_CHECKPOINT: &str = "checkpoint";

/// MCP handler for `memory_checkpoint_create`. Builds a
/// [`crate::models::Checkpoint`] from the request params in the
/// [`crate::models::CheckpointState::Pending`] state, inserts it, and returns
/// the created checkpoint as JSON plus its id.
///
/// # Errors
/// Returns the stringified `rusqlite` error on insert failure.
pub fn handle_checkpoint_create(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let namespace = params
        .get(param_names::NAMESPACE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut title = params
        .get(param_names::TITLE)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // #3007 (code half) — a caller-supplied `condition_type` that names no known
    // variant is a security-typed discriminator; REJECT it (like
    // `action_transition` / `check_agent_action` reject an unknown state/kind)
    // instead of silently coercing to `Approval` — a caller asking for `quorum`
    // must never get an `approval` gate. An ABSENT value still defaults.
    //
    // NOTE (#3007 epoch half, DEFERRED to a 5-agent vote): whether the LOCAL
    // MCP resolve lane must additionally gate a caller-mintable, caller-
    // resolvable `epoch_advance` freeze anchor (the federation lane gates it via
    // the per-resolution enrolled-key signature, env #125) is a T3 posture
    // decision left OUT of this change. Only the silent-coercion half is fixed
    // here; the epoch-advance local-gate design is untouched.
    let condition_type = match params
        .get(param_names::CONDITION_TYPE)
        .and_then(Value::as_str)
    {
        Some(s) => crate::models::ConditionType::from_str(s)
            .ok_or_else(|| format!("invalid condition_type: {s}"))?,
        None => crate::models::ConditionType::default(),
    };
    let mut condition = params
        .get(param_names::CONDITION)
        .cloned()
        .unwrap_or_else(|| json!({}));
    let created_by = params
        .get(param_names::CREATED_BY)
        .and_then(Value::as_str)
        .map(str::to_string);
    let deadline_at = params.get(param_names::DEADLINE_AT).and_then(Value::as_i64);
    let mut metadata = params
        .get(param_names::METADATA)
        .cloned()
        .unwrap_or_else(|| json!({}));

    // #2998 — validate the coordination create inputs + resolve an always-
    // attributed actor. #2994 — screen the caller-origin credential vectors
    // (title / condition / metadata) before the direct insert.
    crate::coordination_guard::require_namespace(&namespace)?;
    crate::coordination_guard::require_text(
        param_names::TITLE,
        &title,
        crate::coordination_guard::MAX_TEXT_FIELD_BYTES,
    )?;
    crate::coordination_guard::require_payload_size(param_names::CONDITION, &condition)?;
    let created_by = crate::coordination_guard::resolve_actor(created_by.as_deref())?;
    crate::secret_screen::screen_text_field_for_caller(&mut title).map_err(|r| r.to_string())?;
    crate::secret_screen::screen_json_field_for_caller(&mut condition)
        .map_err(|r| r.to_string())?;
    if !metadata.is_null() {
        crate::secret_screen::screen_json_field_for_caller(&mut metadata)
            .map_err(|r| r.to_string())?;
    }

    let cp = crate::models::Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        namespace,
        title,
        condition_type,
        condition,
        state: crate::models::CheckpointState::Pending,
        created_by,
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: chrono::Utc::now().timestamp(),
        deadline_at,
        resolved_at: None,
        metadata,
    };

    // #1807 — validate supplied metadata size + charge the creator's
    // per-namespace storage quota for the condition + metadata payload
    // (storage_only). An unspecified-creator checkpoint (empty `created_by`)
    // is not charged. Metadata defaults to an empty object, but an explicit
    // JSON null is not a validatable object, so validation only runs when a
    // metadata object was supplied. T-exempt precedent-copy; 5-agent review
    // (memory `4d3ea1c5`) deemed #1807 legitimate.
    if !cp.metadata.is_null() {
        crate::validate::validate_metadata(&cp.metadata).map_err(|e| e.to_string())?;
    }
    if !cp.created_by.is_empty() {
        let bytes =
            crate::quotas::coordination_payload_bytes(&[&cp.title], &[&cp.condition, &cp.metadata]);
        crate::quotas::check_and_record_storage_only(conn, &cp.created_by, &cp.namespace, bytes)
            .map_err(|e| e.to_string())?;
    }

    // PR-1 / L5 (#2708-sibling, CWE-284) — close the LOCAL creation path too: a
    // caller must NOT be able to create a PENDING checkpoint whose kind/namespace
    // names a substrate-RESERVED anchor (audit-head witness, governance verdict/
    // enforcement, peer-head entanglement, re-anchor). The
    // substrate emits its OWN anchors via `crate::checkpoints::insert` directly
    // (bypassing this handler), so this refusal never blocks a legitimate
    // substrate emission — only a caller minting a reserved-kind pending anchor
    // that a later resolution could then steer the audit-signal spine with.
    // Reuses the SAME pure predicate as the federation ingress (`stored = None`
    // — there is no pre-existing row on a create).
    if !crate::federation::receive_auth::inbound_checkpoint_kind_authorized(
        cp.condition_type,
        &cp.namespace,
        None,
    ) {
        return Err(format!(
            "condition_type '{}' / namespace '{}' names a substrate-reserved checkpoint \
             anchor and cannot be created by a caller",
            cp.condition_type.as_str(),
            cp.namespace
        ));
    }

    crate::checkpoints::insert(conn, &cp).map_err(|e| e.to_string())?;

    // #1722 — coordination observability: best-effort audit row for the
    // create, attributed to the creating agent (`created_by`, "" when
    // unspecified). Identity = checkpoint id / creator / "create".
    crate::coordination_audit::emit(
        conn,
        crate::coordination_audit::CHECKPOINT_CREATE,
        &cp.created_by,
        &[&cp.id, &cp.created_by, "create"],
    );

    Ok(json!({
        (param_names::ID): cp.id,
        (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_checkpoint_resolve`. Resolves a pending checkpoint
/// to `resolved` / `rejected`, attesting the resolution in place when `keypair`
/// is `Some` and `can_sign()`. Returns the resolved checkpoint plus the
/// resulting attestation level (`self_signed` vs `unsigned`).
///
/// # Errors
/// Returns an error string when `state` is not a valid resolution state, when
/// no row matches the id, or on the stringified `rusqlite` update error.
pub fn handle_checkpoint_resolve(
    conn: &rusqlite::Connection,
    params: &Value,
    keypair: Option<&AgentKeypair>,
) -> Result<Value, String> {
    // #3171 Fable MED (3) — schema-REQUIRED `id` and `resolved_by` must
    // refuse missing/blank rather than persist empty attribution.
    let id = crate::mcp::param_guard::require_str(params, param_names::ID)?;
    let state = params
        .get(param_names::STATE)
        .and_then(Value::as_str)
        .and_then(crate::models::CheckpointState::from_str)
        .filter(|s| {
            matches!(
                s,
                crate::models::CheckpointState::Resolved | crate::models::CheckpointState::Rejected
            )
        })
        .ok_or_else(|| "state must be one of: resolved, rejected".to_string())?;
    let resolved_by = crate::mcp::param_guard::require_str(params, param_names::RESOLVED_BY)?;
    let resolution = params.get(param_names::RESOLUTION).and_then(Value::as_str);
    let resolution_note = params
        .get(param_names::RESOLUTION_NOTE)
        .and_then(Value::as_str);
    let now = chrono::Utc::now().timestamp();

    // #3007 (authz half, Wave-2 Cluster B) — the local MCP resolve lane must NOT
    // auto-sign an `epoch_advance` freeze anchor with the DAEMON key. The daemon
    // keypair is available to whatever local process drives this handler, so a
    // daemon-signed epoch anchor is caller-mintable AUTHORITY (the freeze anchor
    // the #1878 epoch-apply consumer trusts). Under the certified / asi-hard
    // posture we ENGAGE a gate that MIRRORS the shipped federation receive authz
    // (`authorize_remote_checkpoint_resolution`, #1936/#1947) and REUSES its
    // exact `resolution_signable` byte format: the resolution is signed
    // (verify:true) ONLY when `resolved_by` presents a detached Ed25519
    // signature that verifies against `resolved_by`'s LOCALLY-ENROLLED key over
    // the canonical resolution. Absent / not-enrolled / forged → the state still
    // resolves but stays Unsigned (verify:false) — DEGRADE, never daemon-sign a
    // caller-mintable freeze anchor. ADVISORY (no gate; the daemon signs as
    // before) under standard posture so single-node dev is unaffected.
    let stored = crate::checkpoints::get(conn, id).map_err(|e| e.to_string())?;
    // Engage the operator-attestation lane exactly when the SHARED
    // `withhold_daemon_signature` predicate (epoch_advance under the certified /
    // asi-hard posture) would refuse to daemon-sign this resolution — SINGLE-
    // SOURCED so this MCP accept-path gate and the `checkpoints::resolve` /
    // postgres withhold gates can never drift. `is_epoch_anchor` therefore comes
    // from the STORED row's condition_type, not caller params.
    let epoch_gate = stored
        .as_ref()
        .is_some_and(crate::checkpoints::withhold_daemon_signature);

    // Choose the attestation lane BEFORE the resolve:
    //   - `resolve_keypair`       — the key `resolve()` signs with (None on the
    //                               epoch lane; the daemon key on the legacy lane).
    //   - `resolve_at`            — the `resolved_at` persisted (the operator-
    //                               signed instant on an epoch Accept; else `now`).
    //   - `external_attestation`  — Some((sig, enrolled_pubkey)) to store AFTER
    //                               the resolve on an epoch Accept; None otherwise.
    let (resolve_keypair, resolve_at, external_attestation): (
        Option<&AgentKeypair>,
        i64,
        Option<(Vec<u8>, Vec<u8>)>,
    ) = if epoch_gate {
        let stored = stored.as_ref().expect("epoch_gate implies a stored row");
        // The operator's detached Ed25519 signature over the canonical
        // resolution (URL-safe base64). Absent / malformed → empty bytes, which
        // `authorize_remote_checkpoint_resolution` treats as RejectUnsigned
        // under the engaged `require_sig = true`.
        let presented_sig = params
            .get(param_names::SIGNATURE)
            .and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim()).ok())
            .unwrap_or_default();
        // The operator signs over a SPECIFIC `resolved_at` (inside the signed
        // surface), so the caller supplies it and the resolved row persists THAT
        // value — otherwise the re-derived bytes could never verify. An absent
        // value can only yield an Unsigned outcome, so `now` is a safe default.
        let signed_at = params
            .get(param_names::RESOLVED_AT)
            .and_then(Value::as_i64)
            .unwrap_or(now);
        // Re-derive the would-be-resolved signable via the SHIPPED
        // `resolution_signable` (verbatim byte format) over a synthetic view of
        // the post-resolve row.
        let synthetic = crate::models::Checkpoint {
            state,
            resolved_by: Some(resolved_by.to_string()),
            resolution: resolution.map(str::to_string),
            resolved_at: Some(signed_at),
            ..stored.clone()
        };
        let signable = crate::checkpoints::resolution_signable(&synthetic);
        let enrolled = crate::identity::verify::lookup_peer_public_key(resolved_by);
        // Reuse the federation receive verdict fn VERBATIM. `require_sig = true`:
        // the gate is engaged, so an absent signature fails closed to Unsigned.
        match crate::federation::receive_auth::authorize_remote_checkpoint_resolution(
            &signable,
            &presented_sig,
            enrolled.as_ref(),
            true,
        ) {
            // v1.0.0 #3164 (ERRORS-09) — the verdict CARRIES the verifying key
            // that authenticated the resolution, so the attestation is built
            // from the value the gate actually verified against. The prior
            // `enrolled.expect("Accept implies an enrolled verifying key")`
            // was sound only because `require_sig` is hardcoded `true` two
            // lines up; the sibling HTTP caller already passes the RUNTIME
            // flag, so wiring the same flag here would have turned a remote
            // peer's unsigned resolution into a panic on an MCP tool.
            crate::federation::receive_auth::CheckpointResolutionAuthz::Accept(verified_key) => (
                None,
                signed_at,
                Some((presented_sig, verified_key.to_bytes().to_vec())),
            ),
            // AcceptUnverified (unreachable while `require_sig = true`, but no
            // longer a panic if that ever changes) / RejectUnsigned /
            // RejectNotEnrolled / RejectForged: withhold the daemon key so the
            // anchor resolves Unsigned (verify:false).
            _ => (None, now, None),
        }
    } else {
        // Legacy lane — non-epoch kinds, or standard posture (advisory): the
        // daemon keypair signs as before (byte-identical to pre-#3007).
        (keypair, now, None)
    };
    let operator_attested = external_attestation.is_some();

    let resolved = crate::checkpoints::resolve(
        conn,
        id,
        state,
        resolved_by,
        resolution,
        resolution_note,
        resolve_at,
        resolve_keypair,
    )
    .map_err(|e| e.to_string())?;
    match resolved {
        crate::checkpoints::ResolveOutcome::NotFound => Err(format!("checkpoint not found: {id}")),
        // #2995 — first-resolution-wins: an already-resolved checkpoint is a
        // conflict; the prior signed attestation is kept and this resolve
        // refused, rather than silently overwriting the authority record.
        crate::checkpoints::ResolveOutcome::Conflict(existing) => Err(format!(
            "checkpoint {id} already resolved by {} ({}); first resolution wins",
            existing.resolved_by.as_deref().unwrap_or(""),
            existing.state.as_str()
        )),
        crate::checkpoints::ResolveOutcome::Resolved(mut cp) => {
            // #3007 — on the epoch Accept path `resolve()` withheld the daemon
            // key, so the row is currently Unsigned. Persist the operator's
            // externally-verified attestation now (signature + enrolled pubkey)
            // so `verify()` attests the resolution to the OPERATOR, not the
            // daemon (separation of duties). No-op on every other lane.
            if let Some((sig, pubkey)) = external_attestation {
                crate::checkpoints::store_resolution_attestation(conn, id, &sig, &pubkey)
                    .map_err(|e| e.to_string())?;
                cp.signature = sig;
                cp.resolver_pubkey = pubkey;
            }
            // #1722 — coordination observability: best-effort audit row for the
            // resolution, attributed to the resolving agent (`resolved_by`).
            // Identity = checkpoint id / resolver / target state.
            crate::coordination_audit::emit(
                conn,
                crate::coordination_audit::CHECKPOINT_RESOLVE,
                resolved_by,
                &[id, resolved_by, state.as_str()],
            );
            let attest_level = if cp.signature.is_empty() {
                crate::models::AttestLevel::Unsigned.as_str()
            } else if operator_attested {
                // Signed against `resolved_by`'s ENROLLED key (not self-signed).
                crate::models::AttestLevel::PeerAttested.as_str()
            } else {
                crate::models::AttestLevel::SelfSigned.as_str()
            };
            Ok(json!({
                (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
                "attest_level": attest_level,
            }))
        }
    }
}

/// MCP handler for `memory_checkpoint_query`. Lists a namespace's checkpoints
/// narrowed by an optional `condition_type` AND an optional `state`,
/// newest-first, capped at `limit` (default 50).
///
/// # Errors
/// Returns `"namespace is required"` when the schema-required `namespace` is
/// missing/blank, `"invalid condition_type: .."` / `"invalid state: .."` when
/// a filter names no known variant (#3171), or the stringified `rusqlite`
/// error on query failure.
pub fn handle_checkpoint_query(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    // #3171 — `namespace` is schema-REQUIRED; an `unwrap_or_default()` read
    // answered an empty-namespace query with a plausible empty list.
    let namespace = crate::mcp::param_guard::require_str(params, param_names::NAMESPACE)?;
    // #3171 — an UNKNOWN `condition_type` / `state` used to drop the filter
    // and return strictly MORE checkpoints than the caller asked for (e.g. a
    // typo'd `state: "pendingg"` surfaced already-resolved gates as if they
    // were open). REJECT the unknown discriminant, mirroring the #3007
    // `handle_checkpoint_create` gate. An ABSENT filter still means "all".
    let condition_type = crate::mcp::param_guard::optional_enum(
        params,
        param_names::CONDITION_TYPE,
        crate::models::ConditionType::from_str,
    )?;
    let state = crate::mcp::param_guard::optional_enum(
        params,
        param_names::STATE,
        crate::models::CheckpointState::from_str,
    )?;
    let limit = params
        .get(param_names::LIMIT)
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let limit = usize::try_from(limit).unwrap_or(50);

    let checkpoints = crate::checkpoints::query(conn, namespace, condition_type, state, limit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "checkpoints": serde_json::to_value(&checkpoints).map_err(|e| e.to_string())?,
    }))
}

/// MCP handler for `memory_checkpoint_verify`. Fetches a checkpoint by id and
/// reports its Ed25519 attested-resolution verification status. The
/// `checkpoint` field is `null` when no row matches, mirroring how
/// `memory_signal_read` reports an absent row.
///
/// # Errors
/// Returns `"id is required"` when the schema-required `id` is missing,
/// blank, or not a JSON string (#3365), or the stringified `rusqlite` error
/// on query failure.
pub fn handle_checkpoint_verify(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    // #3365 (#3171 residue) — `id` is schema-REQUIRED. This is the worst of
    // the family: the `""` fallback made `memory_checkpoint_verify {}` return
    // `{"checkpoint": null, "verified": false}`, which reads as "the
    // attestation FAILED VERIFICATION" rather than "you did not name a
    // checkpoint". Refuse instead — a verification verdict must never be
    // manufactured from a malformed request.
    let id = crate::mcp::param_guard::require_str(params, param_names::ID)?;
    let found = crate::checkpoints::get(conn, id).map_err(|e| e.to_string())?;
    match found {
        None => Ok(json!({ (RESP_CHECKPOINT): Value::Null, "verified": false })),
        Some(cp) => Ok(json!({
            (RESP_CHECKPOINT): serde_json::to_value(&cp).map_err(|e| e.to_string())?,
            "verified": crate::checkpoints::verify(&cp),
        })),
    }
}

// --- per-tool McpTool impls (v0.8.0 Pillar 1, #1709) ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_create`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointCreateRequest {
    pub namespace: String,

    pub title: String,

    /// Condition type (`approval` / `external_signal` /
    /// `condition_predicate` / `deadline`). Defaults to `approval`.
    #[serde(default)]
    pub condition_type: Option<String>,

    /// JSON condition spec for the gate. Defaults to `{}`.
    #[serde(default)]
    pub condition: Value,

    /// Agent id that created the checkpoint.
    #[serde(default)]
    pub created_by: Option<String>,

    /// Epoch-seconds deadline after which the checkpoint may expire.
    #[serde(default)]
    pub deadline_at: Option<i64>,

    /// Arbitrary JSON metadata. Defaults to `{}`.
    #[serde(default)]
    pub metadata: Value,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_resolve`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointResolveRequest {
    pub id: String,

    /// Resolution state — one of `resolved` / `rejected`.
    pub state: String,

    pub resolved_by: String,

    /// Structured resolution payload (free-form string).
    #[serde(default)]
    pub resolution: Option<String>,

    /// Human-readable note explaining the resolution.
    #[serde(default)]
    pub resolution_note: Option<String>,

    /// #3171 / #3007 — the resolver's DETACHED Ed25519 signature over the
    /// canonical resolution, URL-safe base64. Consumed only on the
    /// `epoch_advance` freeze-anchor lane under the certified / asi-hard
    /// posture, where an absent or unverifiable signature DEGRADES the
    /// resolution to `verify:false` instead of daemon-signing it. Honoured
    /// but undeclared until the tool-contract audit, so an operator had no
    /// documented way to supply it.
    #[serde(default)]
    pub signature: Option<String>,

    /// #3171 / #3007 — the exact `resolved_at` (epoch seconds) the
    /// `signature` above was computed over; ignored on every other lane.
    #[serde(default)]
    pub resolved_at: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_query`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointQueryRequest {
    pub namespace: String,

    /// Narrow to a single condition type when set.
    #[serde(default)]
    pub condition_type: Option<String>,

    /// Narrow to a single lifecycle state when set.
    #[serde(default)]
    pub state: Option<String>,

    #[serde(default)]
    pub limit: Option<i64>,
}

/// v0.8.0 Pillar 1 (#1709) — request body for `memory_checkpoint_verify`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckpointVerifyRequest {
    pub id: String,
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_create`.
#[allow(dead_code)]
pub struct CheckpointCreateTool;

impl McpTool for CheckpointCreateTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_CREATE
    }
    fn description() -> &'static str {
        "Create a pending attested-checkpoint coordination gate (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): create a checkpoint in the pending state, gated on an external condition."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointCreateRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_resolve`.
#[allow(dead_code)]
pub struct CheckpointResolveTool;

impl McpTool for CheckpointResolveTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_RESOLVE
    }
    fn description() -> &'static str {
        "Resolve a checkpoint (resolved/rejected), Ed25519-attested when signing (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): resolve a checkpoint; the resolution self-signs when a signing keypair is available."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointResolveRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_query`.
#[allow(dead_code)]
pub struct CheckpointQueryTool;

impl McpTool for CheckpointQueryTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_QUERY
    }
    fn description() -> &'static str {
        "Query checkpoints by namespace/condition_type/state, newest-first (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): list a namespace's checkpoints, optionally narrowed by condition_type and state."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointQueryRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

/// v0.8.0 Pillar 1 (#1709) — `McpTool` impl for `memory_checkpoint_verify`.
#[allow(dead_code)]
pub struct CheckpointVerifyTool;

impl McpTool for CheckpointVerifyTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECKPOINT_VERIFY
    }
    fn description() -> &'static str {
        "Fetch a checkpoint by id and verify its attested resolution (#1709)."
    }
    fn docs() -> &'static str {
        "Pillar 1 (#1709): fetch a checkpoint and verify its Ed25519 attested-resolution signature."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<CheckpointVerifyRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_6_1709_tests {
    //! D1.6 (#987) parity tests for the Pillar-1 `memory_checkpoint_*` tools.
    use super::*;

    #[test]
    fn checkpoint_create_tool_metadata() {
        assert_eq!(CheckpointCreateTool::name(), "memory_checkpoint_create");
        assert_eq!(CheckpointCreateTool::family(), "power");
        assert!(!CheckpointCreateTool::description().is_empty());
        assert!(!CheckpointCreateTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_resolve_tool_metadata() {
        assert_eq!(CheckpointResolveTool::name(), "memory_checkpoint_resolve");
        assert_eq!(CheckpointResolveTool::family(), "power");
        assert!(!CheckpointResolveTool::description().is_empty());
        assert!(!CheckpointResolveTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_query_tool_metadata() {
        assert_eq!(CheckpointQueryTool::name(), "memory_checkpoint_query");
        assert_eq!(CheckpointQueryTool::family(), "power");
        assert!(!CheckpointQueryTool::description().is_empty());
        assert!(!CheckpointQueryTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_verify_tool_metadata() {
        assert_eq!(CheckpointVerifyTool::name(), "memory_checkpoint_verify");
        assert_eq!(CheckpointVerifyTool::family(), "power");
        assert!(!CheckpointVerifyTool::description().is_empty());
        assert!(!CheckpointVerifyTool::docs().is_empty());
    }

    #[test]
    fn checkpoint_create_schema_requires_core_fields() {
        let schema = CheckpointCreateTool::input_schema();
        let obj = schema.as_object().expect("schema is an object");
        assert!(
            obj.contains_key("properties"),
            "schema must advertise properties"
        );
        let required = obj
            .get("required")
            .and_then(Value::as_array)
            .expect("required is an array");
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        for name in &["namespace", "title"] {
            assert!(
                required_names.contains(name),
                "required must include {name}"
            );
        }
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    fn fresh() -> rusqlite::Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    #[test]
    fn create_query_resolve_verify_roundtrips_over_mcp() {
        let conn = fresh();
        // Create a pending checkpoint.
        let created = handle_checkpoint_create(
            &conn,
            &json!({
                "namespace": "_cp",
                "title": "ship the release",
                "condition_type": "approval",
                "condition": {"who": "operator"},
                "created_by": "agent-a",
            }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        assert_eq!(created["checkpoint"]["state"].as_str(), Some("pending"));
        assert_eq!(
            created["checkpoint"]["condition_type"].as_str(),
            Some("approval")
        );

        // Query for the namespace finds it.
        let queried =
            handle_checkpoint_query(&conn, &json!({ "namespace": "_cp" })).expect("query ok");
        let arr = queried["checkpoints"]
            .as_array()
            .expect("checkpoints array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"].as_str(), Some(id.as_str()));

        // Query narrowed by state=pending still finds it.
        let pending =
            handle_checkpoint_query(&conn, &json!({ "namespace": "_cp", "state": "pending" }))
                .expect("query ok");
        assert_eq!(pending["checkpoints"].as_array().expect("array").len(), 1);

        // Resolve it (unsigned — no keypair).
        let resolved = handle_checkpoint_resolve(
            &conn,
            &json!({
                "id": id,
                "state": "resolved",
                "resolved_by": "agent-b",
                "resolution": "approved",
                "resolution_note": "looks good",
            }),
            None,
        )
        .expect("resolve ok");
        assert_eq!(resolved["attest_level"].as_str(), Some("unsigned"));
        assert_eq!(resolved["checkpoint"]["state"].as_str(), Some("resolved"));
        assert_eq!(
            resolved["checkpoint"]["resolved_by"].as_str(),
            Some("agent-b")
        );

        // Verify reports false for the unsigned resolution.
        let verified = handle_checkpoint_verify(&conn, &json!({ "id": id })).expect("verify ok");
        assert_eq!(verified["verified"].as_bool(), Some(false));
        assert_eq!(verified["checkpoint"]["state"].as_str(), Some("resolved"));
    }

    #[test]
    fn verify_absent_returns_null_checkpoint() {
        let conn = fresh();
        let got = handle_checkpoint_verify(&conn, &json!({ "id": "missing" })).expect("verify ok");
        assert!(got["checkpoint"].is_null());
        assert_eq!(got["verified"].as_bool(), Some(false));
    }

    #[test]
    fn resolve_rejects_invalid_state() {
        let conn = fresh();
        let created = handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "pending", "resolved_by": "x" }),
            None,
        )
        .expect_err("invalid state must error");
        assert!(err.contains("resolved"), "error names valid states: {err}");
    }

    #[test]
    fn resolve_missing_id_errors() {
        let conn = fresh();
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": "nope", "state": "resolved", "resolved_by": "x" }),
            None,
        )
        .expect_err("missing id must error");
        assert!(err.contains("not found"), "error reports absence: {err}");
    }

    /// #3171 Fable MED (3) — blank/absent schema-REQUIRED strings refuse.
    #[test]
    fn resolve_refuses_blank_id_and_resolved_by_3171() {
        let conn = fresh();
        let created = handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("create ok");
        let id = created[param_names::ID].as_str().expect("id present");
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "state": "resolved", "resolved_by": "x" }),
            None,
        )
        .expect_err("absent id must refuse");
        assert!(err.contains("id is required"), "got: {err}");
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": "  ", "state": "resolved", "resolved_by": "x" }),
            None,
        )
        .expect_err("blank id must refuse");
        assert!(err.contains("id is required"), "got: {err}");
        let err = handle_checkpoint_resolve(&conn, &json!({ "id": id, "state": "resolved" }), None)
            .expect_err("absent resolved_by must refuse");
        assert!(err.contains("resolved_by is required"), "got: {err}");
        let err = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "resolved", "resolved_by": "" }),
            None,
        )
        .expect_err("blank resolved_by must refuse");
        assert!(err.contains("resolved_by is required"), "got: {err}");
    }

    /// PR-1 / L5 (#2708-sibling, CWE-284) — a caller must NOT be able to CREATE a
    /// pending checkpoint whose kind/namespace names a substrate-reserved anchor
    /// (audit-head witness, governance verdict/enforcement,
    /// peer-head entanglement, re-anchor). Closing the local creation path in
    /// addition to the federation ingress means a reserved-kind pending anchor
    /// cannot be minted in the first place, so a later resolution has nothing to
    /// steer the audit-signal spine with.
    #[test]
    fn create_refuses_reserved_anchor_kind_and_namespace() {
        let conn = fresh();

        // Reserved by KIND (the wire condition_type names a substrate anchor).
        let by_kind = handle_checkpoint_create(
            &conn,
            &json!({
                "namespace": "team/ops",
                "title": "forge a witness",
                "condition_type": "audit_head_witness",
            }),
        )
        .expect_err("reserved kind create must error");
        assert!(
            by_kind.contains("substrate-reserved"),
            "error names the reserved-anchor refusal: {by_kind}"
        );

        // Reserved by NAMESPACE (benign kind, reserved location).
        let by_ns = handle_checkpoint_create(
            &conn,
            &json!({
                "namespace": crate::governance::audit::WITNESS_CHECKPOINT_NAMESPACE,
                "title": "squat the witness namespace",
                "condition_type": "approval",
            }),
        )
        .expect_err("reserved namespace create must error");
        assert!(
            by_ns.contains("substrate-reserved"),
            "error names the reserved-anchor refusal: {by_ns}"
        );

        // Nothing landed under the reserved witness namespace.
        assert!(
            crate::checkpoints::query(
                &conn,
                crate::governance::audit::WITNESS_CHECKPOINT_NAMESPACE,
                None,
                None,
                16,
            )
            .expect("query")
            .is_empty(),
            "no reserved-kind checkpoint may be created locally"
        );

        // A benign caller checkpoint still creates normally.
        handle_checkpoint_create(
            &conn,
            &json!({ "namespace": "team/ops", "title": "normal gate", "condition_type": "approval" }),
        )
        .expect("benign create ok");
    }

    /// #1722 — resolving a checkpoint appends one
    /// `coordination.checkpoint_resolve` audit row attributed to the
    /// resolving agent; the append-only chain stays intact.
    #[test]
    fn resolve_emits_signed_events_audit_row_1722() {
        let conn = fresh();
        let created = handle_checkpoint_create(
            &conn,
            &json!({ "namespace": "_cp", "title": "t", "created_by": "agent-a" }),
        )
        .expect("create ok");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();

        handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "resolved", "resolved_by": "agent-b" }),
            None,
        )
        .expect("resolve ok");

        let (count, agent): (i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(agent_id), '') FROM signed_events \
                 WHERE event_type = ?1",
                rusqlite::params![crate::coordination_audit::CHECKPOINT_RESOLVE],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query audit row");
        assert_eq!(count, 1, "one coordination.checkpoint_resolve row");
        assert_eq!(agent, "agent-b", "row attributed to the resolver");

        let report = crate::signed_events::verify_audit_trail(&conn, None, None).expect("verify");
        assert!(report.chain_intact, "chain must verify; report={report:?}");
    }

    /// #3007 (code half) — a caller-supplied `condition_type` naming no known
    /// variant is REJECTED, not silently coerced to `approval`. An absent value
    /// still defaults; a known value still works. Also pins the #2998 namespace
    /// validation on this surface.
    #[test]
    fn create_rejects_unknown_condition_type_3007() {
        let conn = fresh();
        // `quorum` / `EpochAdvance` (wrong case) / `bogus` all named `approval`
        // pre-fix — now each is refused.
        for bad in ["quorum", "EpochAdvance", "bogus"] {
            let err = handle_checkpoint_create(
                &conn,
                &json!({ "namespace": "_cp", "title": "t", "condition_type": bad }),
            )
            .expect_err("unknown condition_type must reject, not coerce to approval");
            assert!(
                err.contains("invalid condition_type"),
                "error names the rejected value: {err}"
            );
        }
        // A known value + an absent value both still create.
        handle_checkpoint_create(
            &conn,
            &json!({ "namespace": "_cp", "title": "t", "condition_type": "deadline" }),
        )
        .expect("known condition_type ok");
        handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("absent condition_type defaults");
        // #2998 — path-traversal namespace refused.
        assert!(
            handle_checkpoint_create(&conn, &json!({ "namespace": "../x", "title": "t" })).is_err(),
            "path-traversal namespace refused"
        );
    }

    #[test]
    fn create_defaults_condition_type_to_approval() {
        let conn = fresh();
        let created = handle_checkpoint_create(&conn, &json!({ "namespace": "_cp", "title": "t" }))
            .expect("create ok");
        assert_eq!(
            created["checkpoint"]["condition_type"].as_str(),
            Some("approval")
        );
        assert!(
            created["checkpoint"]["created_at"]
                .as_i64()
                .expect("created_at")
                > 0
        );
    }

    // ---- #3007 (Wave-2 Cluster B) — local epoch_advance resolve authz -----
    //
    // These two tests run in an ISOLATED CHILD process (#2905) because they set
    // process-global env (`AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` to
    // engage the gate, `AI_MEMORY_KEY_DIR` to a tempdir so the operator key
    // enrolls without touching the real keystore). Both create a
    // caller-mintable `epoch_advance` freeze anchor and resolve it.

    /// Create + resolve helper: mint an `epoch_advance` checkpoint and return
    /// `(conn, id, namespace)`.
    fn fresh_epoch_anchor() -> (rusqlite::Connection, String, String) {
        let conn = fresh();
        let ns = "_epoch".to_string();
        let created = handle_checkpoint_create(
            &conn,
            &json!({ "namespace": ns, "title": "freeze", "condition_type": "epoch_advance",
                     "created_by": "attacker" }),
        )
        .expect("epoch_advance create ok (caller-mintable)");
        let id = created[param_names::ID]
            .as_str()
            .expect("id present")
            .to_string();
        (conn, id, ns)
    }

    /// Attacker resolves a caller-mintable `epoch_advance` anchor with the
    /// daemon key but NO enrolled-operator signature → the anchor still resolves
    /// but stays Unsigned + verify:false (the daemon key is withheld). Proves
    /// the gate DEGRADES, never daemon-signs a caller-mintable freeze anchor.
    #[test]
    fn epoch_advance_resolve_without_enrolled_sig_stays_unsigned_3007() {
        if crate::config::run_env_isolated_child_or_spawn(
            "mcp::checkpoint::handler_tests::epoch_advance_resolve_without_enrolled_sig_stays_unsigned_3007",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        let key_dir = crate::test_support::secure_tempdir();
        // SAFETY: single-threaded isolated child; guarded by test_env_lock.
        unsafe {
            std::env::set_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                "1",
            );
            std::env::set_var(crate::identity::keypair::KEY_DIR_ENV, key_dir.path());
        }

        let (conn, id, _ns) = fresh_epoch_anchor();
        // The daemon HAS a signing key available — the pre-#3007 lane would
        // daemon-sign. The gate must withhold it.
        let daemon_kp = crate::identity::keypair::generate("daemon").expect("daemon key");
        let out = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "resolved", "resolved_by": "attacker",
                     "resolution": "approved" }),
            Some(&daemon_kp),
        )
        .expect("resolve applies (Unsigned) — the state flip is not blocked");
        assert_eq!(
            out["attest_level"].as_str(),
            Some(crate::models::AttestLevel::Unsigned.as_str()),
            "an epoch_advance resolved without an enrolled-operator sig must be Unsigned"
        );
        // And the persisted row does NOT verify (no daemon-minted attestation).
        let stored = crate::checkpoints::get(&conn, &id)
            .expect("get")
            .expect("row");
        assert!(stored.signature.is_empty(), "no signature persisted");
        assert!(
            !crate::checkpoints::verify(&stored),
            "a caller-mintable freeze anchor must not verify"
        );

        unsafe {
            std::env::remove_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
            );
            std::env::remove_var(crate::identity::keypair::KEY_DIR_ENV);
        }
    }

    /// The SAME anchor resolved WITH a valid Ed25519 signature by
    /// `resolved_by`'s enrolled operator key is accepted + signed (verify:true),
    /// attested to the operator (PeerAttested), never the daemon.
    #[test]
    fn epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007() {
        if crate::config::run_env_isolated_child_or_spawn(
            "mcp::checkpoint::handler_tests::epoch_advance_resolve_with_enrolled_operator_sig_accepts_signed_3007",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        let key_dir = crate::test_support::secure_tempdir();
        // SAFETY: single-threaded isolated child; guarded by test_env_lock.
        unsafe {
            std::env::set_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
                "1",
            );
            std::env::set_var(crate::identity::keypair::KEY_DIR_ENV, key_dir.path());
        }

        let (conn, id, ns) = fresh_epoch_anchor();

        // Enroll the operator key (full keypair) so `lookup_peer_public_key`
        // finds its public half in the key dir; keep the in-memory handle to
        // sign with.
        let operator = crate::identity::keypair::generate("operator-x").expect("op key");
        crate::identity::keypair::save(&operator, key_dir.path()).expect("enroll operator key");

        // Sign the EXACT canonical resolution bytes the handler will re-derive:
        // reuse `SignableCheckpointResolution` + `sign_checkpoint_resolution`.
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let signed_at: i64 = 1_800_000_000;
        let signable = crate::identity::sign::SignableCheckpointResolution {
            checkpoint_id: &id,
            namespace: &ns,
            state: "resolved",
            resolved_by: "operator-x",
            resolution: Some("approved"),
            resolved_at: signed_at,
        };
        let sig = crate::identity::sign::sign_checkpoint_resolution(&operator, &signable)
            .expect("operator signs");
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

        // A daemon key is ALSO available — the gate must sign with the OPERATOR
        // attestation, not the daemon key.
        let daemon_kp = crate::identity::keypair::generate("daemon").expect("daemon key");
        let out = handle_checkpoint_resolve(
            &conn,
            &json!({ "id": id, "state": "resolved", "resolved_by": "operator-x",
                     "resolution": "approved", "resolved_at": signed_at,
                     "signature": sig_b64 }),
            Some(&daemon_kp),
        )
        .expect("resolve ok");
        assert_eq!(
            out["attest_level"].as_str(),
            Some(crate::models::AttestLevel::PeerAttested.as_str()),
            "an enrolled-operator-signed epoch_advance resolution is operator-attested"
        );
        let stored = crate::checkpoints::get(&conn, &id)
            .expect("get")
            .expect("row");
        assert!(!stored.signature.is_empty(), "operator signature persisted");
        assert_eq!(
            stored.resolver_pubkey,
            operator.public.to_bytes().to_vec(),
            "attested under the OPERATOR's enrolled key, never the daemon key"
        );
        assert!(
            crate::checkpoints::verify(&stored),
            "the operator-attested freeze anchor must verify"
        );

        unsafe {
            std::env::remove_var(
                crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
            );
            std::env::remove_var(crate::identity::keypair::KEY_DIR_ENV);
        }
    }

    /// #3171 — an UNKNOWN `condition_type` / `state` filter must be
    /// REFUSED, not silently dropped. Pre-fix `.and_then(from_str)`
    /// turned a typo into "no filter", so a caller asking for the
    /// still-open gates got the RESOLVED ones back too — strictly more
    /// rows than requested, on a coordination-safety surface.
    #[test]
    fn checkpoint_query_refuses_unknown_discriminants_3171() {
        let conn = fresh();
        handle_checkpoint_create(
            &conn,
            &json!({ "namespace": "_cp", "title": "t", "created_by": "ai:w" }),
        )
        .expect("create ok");

        let e = handle_checkpoint_query(&conn, &json!({ "namespace": "_cp", "state": "pendingg" }))
            .expect_err("unknown state refused");
        assert_eq!(e, "invalid state: pendingg");
        let e = handle_checkpoint_query(
            &conn,
            &json!({ "namespace": "_cp", "condition_type": "quorumm" }),
        )
        .expect_err("unknown condition_type refused");
        assert_eq!(e, "invalid condition_type: quorumm");
        let e = handle_checkpoint_query(&conn, &json!({ "namespace": "_cp", "state": 3 }))
            .expect_err("non-string state refused");
        assert_eq!(e, "invalid state: expected a string");

        // Missing/blank namespace is refused (was an empty-namespace query).
        let e = handle_checkpoint_query(&conn, &json!({})).expect_err("ns required");
        assert_eq!(e, "namespace is required");

        // CONTROL: known discriminants still filter, absent still means "all".
        let all = handle_checkpoint_query(&conn, &json!({ "namespace": "_cp" })).expect("all");
        assert_eq!(all["checkpoints"].as_array().expect("array").len(), 1);
        let pending =
            handle_checkpoint_query(&conn, &json!({ "namespace": "_cp", "state": "pending" }))
                .expect("pending");
        assert_eq!(pending["checkpoints"].as_array().expect("array").len(), 1);
    }
}
