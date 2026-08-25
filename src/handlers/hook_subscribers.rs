// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use crate::models::ConfidenceSource;
use crate::models::field_names;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::db;
use crate::identity::sentinels;
use crate::models::{Memory, Tier};
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;
use super::{fanout_or_pending, list_namespaces, resolve_caller_agent_id};

/// Marker tag on namespace-standard rows (#1558 batch 6).
const NAMESPACE_STANDARD_TAG: &str = "_namespace_standard";

#[derive(Deserialize)]
pub struct InboxQuery {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub unread_only: Option<bool>,
    #[serde(default)]
    pub limit: Option<u64>,
}

pub async fn get_inbox(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InboxQuery>,
) -> impl IntoResponse {
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the inbox read below. The self-asserted `X-Agent-Id` selects the
    // `_inbox/<owner>` namespace, so under `enforce` a shared-key `Claimed`
    // caller forging `X-Agent-Id: <victim>` (owner == victim) would otherwise
    // read the victim's inbox; refuse it here. Inert for zero-config
    // deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "get_inbox",
    ) {
        return resp;
    }
    // #901 (security-high, 2026-05-19) — sibling of #874. The pre-#901
    // path TRUSTED `?agent_id=` query as identity, allowing any caller
    // to read any agent's inbox by passing `?agent_id=victim`. Header
    // is now the only trusted source; the query value (if present)
    // must match the authenticated caller, else 403.
    let owner = match resolve_caller_agent_id(None, &headers, None) {
        Ok(id) => id,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
        }
    };
    if let Some(claimed) = q.agent_id.as_deref()
        && claimed != owner
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": crate::errors::msg::AGENT_ID_QUERY_MISMATCH})),
        )
            .into_response();
    }

    // v0.7.0 Wave-3 Continuation 4 (Bucket B / S32+S58) — postgres
    // inbox now reads from the `_inbox/<owner>` namespace via the SAL
    // `list` projection, matching what `notify` (Phase 16) already
    // writes. The handler walks the namespace and projects each row
    // into the inbox-message wire shape. Subscriptions still ride the
    // legacy sqlite `subscriptions` table; the inbox itself does not
    // need that surface — `notify` lands the message directly under
    // `_inbox/<target>` and the inbox is a straight namespace read.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ns = crate::inbox_namespace(&owner);
        let ctx = crate::store::CallerContext::for_agent(&owner);
        let cap = q
            .limit
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(100)
            .clamp(1, 1000);
        let filter = crate::store::Filter {
            namespace: Some(ns),
            limit: cap,
            ..Default::default()
        };
        return match app.store.list(&ctx, &filter).await {
            Ok(rows) => {
                let unread_only = q.unread_only.unwrap_or(false);
                let messages: Vec<serde_json::Value> = rows
                    .into_iter()
                    .filter(|m| {
                        // v1.0.0 #3027 — the unread marker is `access_count`,
                        // exactly as the sqlite/MCP twin derives it
                        // (`src/mcp/tools/notify.rs`: `!unread_only ||
                        // m.access_count == 0`). The pre-fix pg arm filtered on
                        // `metadata.read == true`, a key NO production writer
                        // ever sets — so `unread_only=true` filtered NOTHING and
                        // `unread_count` equalled `messages.len()` forever, while
                        // the in-code comment claimed sqlite parity. Reading a
                        // message bumps `access_count`, which is a real column on
                        // BOTH backends (`memories.access_count`, populated by
                        // the postgres row mapper), so the two arms now derive the
                        // SAME fact from the SAME durable field.
                        !unread_only || m.access_count == 0
                    })
                    .map(|m| {
                        json!({
                            "id": m.id,
                            "title": m.title,
                            "payload": m.content,
                            "content": m.content,
                            "priority": m.priority,
                            "tier": m.tier.as_str(),
                            "namespace": m.namespace,
                            "metadata": m.metadata,
                            (field_names::CREATED_AT): m.created_at,
                            (field_names::UPDATED_AT): m.updated_at,
                            // #3027 — surface the same read-state pair the
                            // sqlite/MCP inbox projects, so a client cannot be
                            // told a message is unread by one backend and read
                            // by the other.
                            "read": m.access_count > 0,
                            (field_names::ACCESS_COUNT): m.access_count,
                            "agent_id": m.metadata
                                .get("agent_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                            (field_names::FROM_AGENT_ID): m.metadata
                                .get(field_names::FROM_AGENT_ID)
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                            (field_names::TARGET_AGENT_ID): m.metadata
                                .get(field_names::TARGET_AGENT_ID)
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                        })
                    })
                    .collect();
                // #3027 — count from the SAME derived marker the filter uses.
                let unread_count = messages
                    .iter()
                    .filter(|m| m.get("read").and_then(serde_json::Value::as_bool) != Some(true))
                    .count();
                (
                    StatusCode::OK,
                    Json(json!({
                        "agent_id": owner,
                        "messages": messages,
                        "unread_count": unread_count,
                        (field_names::STORAGE_BACKEND): "postgres",
                    })),
                )
                    .into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let mut params = json!({"agent_id": owner});
    if let Some(u) = q.unread_only {
        params[field_names::UNREAD_ONLY] = json!(u);
    }
    if let Some(l) = q.limit {
        params["limit"] = json!(l);
    }
    let lock = app.db.lock().await;
    // #1557 — pass the authenticated, already-403-checked `owner` as the
    // visibility caller so the `handle_inbox` owner-bind double-enforces it
    // (defense-in-depth; the upstream X-Agent-Id 403 remains the primary gate).
    let result = crate::mcp::handle_inbox(&lock.0, &params, None, Some(owner.as_str()));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}
// --- /api/v1/namespaces/{ns}/standard (POST / GET / DELETE) ----------------
//    +/api/v1/namespaces (POST with body.namespace, GET/DELETE with ?namespace=)
//
// S34/S35 drive the standard via the bare `/api/v1/namespaces` surface; the
// `/namespaces/{ns}/standard` path is kept for API-shape parity with the MCP
// tool namespace. Both share a single underlying implementation.

#[derive(Deserialize)]
pub struct NamespaceStandardBody {
    /// The memory id representing the standard.
    #[serde(default)]
    pub id: Option<String>,
    /// Optional parent namespace for chain lookups.
    #[serde(default)]
    pub parent: Option<String>,
    /// Optional governance policy to merge into the standard's metadata.
    #[serde(default)]
    pub governance: Option<serde_json::Value>,
    /// Accepted for the path-less `/namespaces` form — ignored when the
    /// namespace is supplied via a URL segment.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Some scenarios nest the payload under `standard` (S34 does so).
    #[serde(default)]
    pub standard: Option<Box<NamespaceStandardBody>>,
}

fn flatten_standard_body(body: NamespaceStandardBody) -> NamespaceStandardBody {
    // When the caller nests fields under `standard: { … }` (S34 shape), pull
    // the inner payload up to the top level so the single code path below
    // can read it uniformly.
    if let Some(inner) = body.standard {
        let mut merged = *inner;
        if merged.namespace.is_none() {
            merged.namespace = body.namespace;
        }
        if merged.id.is_none() {
            merged.id = body.id;
        }
        if merged.parent.is_none() {
            merged.parent = body.parent;
        }
        if merged.governance.is_none() {
            merged.governance = body.governance;
        }
        merged
    } else {
        body
    }
}

fn namespace_standard_params(ns: &str, body: &NamespaceStandardBody) -> serde_json::Value {
    let mut params = json!({"namespace": ns});
    if let Some(ref id) = body.id {
        params["id"] = json!(id);
    }
    if let Some(ref p) = body.parent {
        params["parent"] = json!(p);
    }
    if let Some(ref g) = body.governance {
        params[field_names::GOVERNANCE] = g.clone();
    }
    params
}

/// v0.7.0 G-PHASE-E-2 (#707) — merge an incoming governance JSON blob
/// onto an existing one, key-by-key. Mirrors the helper in
/// `mcp::tools::namespace`. Incoming keys override existing ones; keys
/// present only on the existing blob (e.g. an operator-set
/// `require_approval_above_depth`) survive untouched.
///
/// Only consumed on the SAL/postgres branch at line ~1064; gate the
/// definition to match so default-features builds don't emit a
/// dead-code warning.
#[cfg(feature = "sal")]
fn merge_governance_fields_http(
    existing: Option<&serde_json::Value>,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut merged = serde_json::Map::new();
    if let Some(existing_obj) = existing.and_then(serde_json::Value::as_object) {
        for (k, v) in existing_obj {
            merged.insert(k.clone(), v.clone());
        }
    }
    if let Some(incoming_obj) = incoming.as_object() {
        for (k, v) in incoming_obj {
            merged.insert(k.clone(), v.clone());
        }
    } else {
        return incoming.clone();
    }
    serde_json::Value::Object(merged)
}

async fn set_namespace_standard_inner(
    app: &AppState,
    ns: &str,
    body: NamespaceStandardBody,
    headers: Option<&HeaderMap>,
) -> axum::response::Response {
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the #929 caller-vs-recorded-owner mutation check below. A namespace
    // standard is the governance policy gating EVERY downstream write into the
    // namespace, and mutation is authorized by `recorded_owner == caller`; so
    // under `enforce` a shared-key `Claimed` caller forging
    // `X-Agent-Id: <victim>` (caller == recorded_owner == victim) could
    // otherwise rewrite the victim's namespace policy. Refuse it here. Inert
    // for zero-config deployments (both public entry points — path + qs forms
    // — route through this inner helper).
    if let Some(h) = headers
        && let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
            &app.enrolled_agent_keys,
            app.http_identity_mode,
            h,
            "set_namespace_standard",
        )
    {
        return resp;
    }
    // #913 (security-medium / SOC2, 2026-05-19) — admin governance audit.
    // `set_namespace_standard` mutates the governance policy that gates
    // EVERY downstream write into the namespace; the chain entry must be
    // emitted BEFORE the storage write so the audit trail survives a
    // failed downstream write. Mirrors the #911 pattern in
    // `register_agent` / `archive_purge`.
    let header_agent_id =
        headers.and_then(|h| h.get(crate::HEADER_AGENT_ID).and_then(|v| v.to_str().ok()));
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| sentinels::ANONYMOUS_INVALID.to_string());
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        "namespace_set_standard",
        "",
        json!({
            "namespace": ns,
            (field_names::STANDARD_ID): body.id.clone(),
            "parent": body.parent.clone(),
            "has_governance": body.governance.is_some(),
        }),
    );

    let body = flatten_standard_body(body);

    // v0.7.0 Wave-3 Continuation 2 (Phase 11) — postgres-backed
    // namespace standard write path. The trait method handles the
    // structural namespace_meta upsert; governance metadata that the
    // sqlite path layers into the standard memory's metadata is
    // captured by storing the policy in the placeholder memory's
    // metadata.governance JSONB field via the trait's standard
    // store path.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // #955 SECURITY-medium (Track A QC sweep, 2026-05-20) — drop
        // the "ai:http" literal fallback. The outer function already
        // resolved `caller` from headers above (with
        // `anonymous:invalid` as the explicit non-header fallback);
        // reuse it so the SAL #910 visibility filter sees the actual
        // request principal in both call paths instead of a synthetic
        // daemon-side placeholder. Pre-fix the "ai:http" literal made
        // the standard write 404 when looking up its own placeholder
        // and let any MCP-via-headers=None caller claim the literal
        // principal as the daemon identity.
        let ctx = if let Some(h) = headers {
            crate::handlers::parity::http_caller_ctx(h, None)
        } else {
            crate::store::CallerContext::for_agent(&caller)
        };
        // Resolve standard_id: caller-supplied or auto-seed a placeholder.
        let standard_id = if let Some(id) = body.id.clone() {
            id
        } else {
            // Try to find an existing placeholder via list().
            let filter = crate::store::Filter {
                namespace: Some(ns.to_string()),
                limit: 50,
                ..Default::default()
            };
            let existing = match app.store.list(&ctx, &filter).await {
                Ok(rows) => rows
                    .into_iter()
                    .find(|m| m.tags.iter().any(|t| t == NAMESPACE_STANDARD_TAG))
                    .map(|m| m.id),
                Err(_) => None,
            };
            if let Some(id) = existing {
                id
            } else {
                let now = Utc::now().to_rfc3339();
                // #929 SECURITY-high (Track A P6, 2026-05-20) — anchor
                // ownership to the caller on first-write. Pre-fix
                // stamped "system" and any subsequent caller could
                // overwrite. The uniform ownership-gate below catches
                // mutation by non-owners.
                // scope=shared preserves multi-reader visibility under
                // the SAL #910 filter so consumers across the
                // namespace can read the governance policy.
                let placeholder_agent_id =
                    if caller.is_empty() || caller == sentinels::ANONYMOUS_INVALID {
                        sentinels::SYSTEM_PRINCIPAL.to_string()
                    } else {
                        caller.clone()
                    };
                let mut metadata = serde_json::json!({
                    "agent_id": placeholder_agent_id,
                    "scope": "shared",
                });
                if let Some(g) = body.governance.clone()
                    && let Some(obj) = metadata.as_object_mut()
                {
                    obj.insert(crate::META_KEY_GOVERNANCE.to_string(), g);
                }
                let placeholder = Memory {
                    id: Uuid::new_v4().to_string(),
                    tier: Tier::Long,
                    namespace: ns.to_string(),
                    title: format!("_standard:{ns}"),
                    content: format!("namespace standard for {ns}"),
                    tags: vec![NAMESPACE_STANDARD_TAG.to_string()],
                    priority: 5,
                    confidence: 1.0,
                    source: "api".into(),
                    access_count: 0,
                    created_at: now.clone(),
                    updated_at: now,
                    last_accessed_at: None,
                    expires_at: None,
                    metadata,
                    reflection_depth: 0,
                    memory_kind: crate::models::MemoryKind::Observation,
                    entity_id: None,
                    persona_version: None,
                    citations: Vec::new(),
                    source_uri: None,
                    source_span: None,
                    confidence_source: ConfidenceSource::CallerProvided,
                    confidence_signals: None,
                    confidence_decayed_at: None,
                    version: 1,
                    lifecycle_state: crate::models::LifecycleState::Open,
                    cid: None,
                    valid_from: None,
                    valid_until: None,
                };
                match app.store.store(&ctx, &placeholder).await {
                    Ok(id) => id,
                    Err(e) => return store_err_to_response(e),
                }
            }
        };

        // #929 SECURITY-high (Track A P6, 2026-05-20) — uniform
        // ownership gate on the postgres path. Catches both the
        // body.id-supplied branch and the auto-seed reuse branch.
        // First-writes land on a placeholder stamped with the
        // caller's id (above), so an immediate re-fetch returns the
        // caller as owner and this gate is a no-op for first writes.
        // Subsequent writes by a different caller hit the !is_unowned
        // branch and 403.
        // #2541 — same authorize helper as MCP; no silent ownership claim.
        //
        // #2709 SECURITY-high (CB-4 / CWE-284, 2026-08-04) — the ownership
        // probe MUST NOT fold a #910 visibility denial into "skip authz".
        // `PostgresStore::get` under the tenant-scoped request `ctx`
        // (`bypass_visibility=false`) returns `Err(NotFound)` for BOTH a
        // genuinely-absent row AND a foreign-owned `scope=private` row the
        // caller cannot see. The pre-fix `if let Ok(resolved_mem)` arm
        // therefore SKIPPED the ownership check whenever `body.id` named
        // another agent's non-shared memory — so `POST /namespaces/{ns}/
        // standard {"id": <alice's private id>}` with `X-Agent-Id: bob`
        // bound Alice's private memory as the namespace governance standard
        // (a silent authz bypass; the sqlite twin at the `db::get` branch
        // below never had this hole because storage-level `db::get` does
        // NOT fold visibility). Fetch the row for the ownership check under
        // a bypass-visibility probe ctx (the same `AI_HTTP_INTERNAL`
        // admin-bind principal the get-standard binding probe uses, and the
        // #2447 fold-avoiding precedent) so a hidden foreign row is
        // RESOLVED and `authorize_namespace_standard_bind` runs the real
        // ownership check against the REQUEST principal
        // (`ctx.effective_principal()`), never the probe principal. The row
        // is used ONLY for the ownership gate — it is never returned to the
        // caller, so this does NOT weaken the #2537/#2707 read-path
        // withholding. A `NotFound` from the probe means the row genuinely
        // does not exist → skip authz + proceed, exactly as the sqlite
        // `Ok(None)` branch does (first-write / non-existent id).
        let ownership_probe_ctx =
            crate::store::CallerContext::for_admin(sentinels::AI_HTTP_INTERNAL);
        let caller_principal = ctx.effective_principal();

        // #2542 — resolve the DECLARED parent's currently-bound standard memory
        // so the bind gate can refuse a graft onto a parent chain the caller
        // does not own (a tenant-isolation + approval-bypass hazard). Fetch it
        // under the SAME bypass-visibility probe ctx as the bound-memory gate,
        // so a foreign `scope=private` parent standard is RESOLVED for the
        // ownership check rather than folded into NotFound → skip-authz (the
        // #2709 hole). `None` = no parent declared / parent has no standard /
        // severed pointer → UNOWNED → allowed. Postgres `set_namespace_standard`
        // never `-`-auto-detects a parent, so this authorizes only an EXPLICITLY
        // declared graft; the federation edge and Route 2 governance filter are
        // the backstops for an inferred parent that reached pg via replication.
        let parent_standard: Option<Memory> = if let Some(p) = body.parent.as_deref() {
            match app
                .store
                .get_namespace_standard(&ownership_probe_ctx, p)
                .await
            {
                Ok(Some((parent_sid, _))) => {
                    match app.store.get(&ownership_probe_ctx, &parent_sid).await {
                        Ok(m) => Some(m),
                        Err(crate::store::StoreError::NotFound { .. }) => None,
                        Err(e) => return store_err_to_response(e),
                    }
                }
                Ok(None) => None,
                Err(e) => return store_err_to_response(e),
            }
        } else {
            None
        };

        match app.store.get(&ownership_probe_ctx, &standard_id).await {
            Ok(resolved_mem) => {
                if let Err(msg) = crate::mcp::authorize_namespace_standard_bind(
                    caller_principal,
                    &resolved_mem,
                    parent_standard.as_ref(),
                ) {
                    tracing::warn!(
                        target: super::AUTHZ_TRACE_TARGET,
                        "POST /namespaces/{{ns}}/standard 403 (postgres path): {msg} (ns={ns}, id={standard_id})"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": msg,
                            "caller": caller_principal
                        })),
                    )
                        .into_response();
                }
            }
            // Genuinely-absent id — parity with the sqlite `Ok(None)` arm (the
            // #929 bound-owner gate is a no-op for a first-write / non-existent
            // id). #2542 — the declared parent must STILL be entitled on this
            // arm, else a graft slips through when the bound memory is absent.
            Err(crate::store::StoreError::NotFound { .. }) => {
                if let Err(msg) = crate::mcp::authorize_namespace_standard_parent(
                    caller_principal,
                    parent_standard.as_ref(),
                ) {
                    tracing::warn!(
                        target: super::AUTHZ_TRACE_TARGET,
                        "POST /namespaces/{{ns}}/standard 403 (postgres path, parent graft): {msg} (ns={ns})"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": msg,
                            "caller": caller_principal
                        })),
                    )
                        .into_response();
                }
            }
            Err(e) => return store_err_to_response(e),
        }

        // v0.7.0 Wave-3 Continuation 5 (Bucket C / S35+S53+S60+S80) —
        // when the caller supplied a `governance` policy AND a pre-
        // existing standard_id, merge the policy into the standard
        // memory's `metadata.governance` so `resolve_governance_policy`
        // (which reads exactly this field via `from_metadata`) finds
        // the policy on the next write. Without this merge step the
        // postgres adapter's chain walk lands on a memory whose
        // metadata has no `governance` key, returns `None`, and the
        // intruder's write is allowed through.
        if let Some(g) = body.governance.clone() {
            // Load the standard memory FIRST so we can merge the
            // incoming `g` onto the existing `metadata.governance`
            // blob — this preserves extra fields like
            // `require_approval_above_depth` that live outside the
            // typed `GovernancePolicy` struct (v0.7.0 G-PHASE-E-2,
            // #707). Mirrors the SQLite handler's merge in
            // `mcp::tools::namespace::handle_namespace_set_standard`.
            let standard_mem = match app.store.get(&ctx, &standard_id).await {
                Ok(m) => m,
                Err(e) => return store_err_to_response(e),
            };
            let merged = merge_governance_fields_http(
                standard_mem.metadata.get(crate::META_KEY_GOVERNANCE),
                &g,
            );
            // Validate the merged blob's typed shape. Deserialising
            // drops unknown fields but the typed sub-set must still
            // parse + pass policy validation. Mirrors the SQLite path
            // at `mcp::tools::namespace`.
            let policy: crate::models::GovernancePolicy = match serde_json::from_value(
                merged.clone(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": crate::errors::msg::invalid(crate::META_KEY_GOVERNANCE, e)})),
                        )
                            .into_response();
                }
            };
            if let Err(e) = validate::validate_governance_policy(&policy) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": crate::errors::msg::invalid(crate::META_KEY_GOVERNANCE, e)})),
                )
                    .into_response();
            }
            let mut metadata = if standard_mem.metadata.is_object() {
                standard_mem.metadata.clone()
            } else {
                json!({})
            };
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(crate::META_KEY_GOVERNANCE.to_string(), merged);
            }
            let patch = crate::store::UpdatePatch {
                metadata: Some(metadata),
                ..Default::default()
            };
            if let Err(e) = app.store.update(&ctx, &standard_id, patch).await {
                return store_err_to_response(e);
            }
        }
        return match app
            .store
            .set_namespace_standard(&ctx, ns, &standard_id, body.parent.as_deref())
            .await
        {
            Ok(()) => (
                StatusCode::CREATED,
                Json(json!({
                    "namespace": ns,
                    (field_names::STANDARD_ID): standard_id,
                    "parent": body.parent,
                    (field_names::STORAGE_BACKEND): "postgres",
                })),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }

    // Auto-seed a placeholder standard memory when the caller didn't supply
    // an `id`. S34's body is `{governance: …}` with no id — we create a
    // minimal standard memory so the governance policy has a home.
    let lock = app.db.lock().await;
    let resolved_id = if let Some(id) = body.id.clone() {
        id
    } else {
        // Look for an existing placeholder first to keep repeat calls
        // idempotent; otherwise insert a new row.
        let existing = db::list(
            &lock.0,
            Some(ns),
            None,
            1,
            0,
            None,
            None,
            None,
            Some(NAMESPACE_STANDARD_TAG),
            None,
            None, // #1834 valid_at (no as-of)
        )
        .ok()
        .and_then(|v| v.into_iter().next());
        if let Some(m) = existing {
            // #929 / #2541 — authorize bind; never silent claim rewrite. This is
            // a pre-check on the BOUND memory only (`None` parent); the declared
            // parent's #2542 entitlement is enforced downstream by
            // `handle_namespace_set_standard`, which this path delegates to.
            if let Err(msg) = crate::mcp::authorize_namespace_standard_bind(&caller, &m, None) {
                tracing::warn!(
                    target: super::AUTHZ_TRACE_TARGET,
                    "POST /namespaces/{{ns}}/standard 403: {msg} (ns={ns})"
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": msg,
                        "caller": caller
                    })),
                )
                    .into_response();
            }
            m.id
        } else {
            let now = Utc::now().to_rfc3339();
            // #929 — first-write anchors ownership to the caller, not
            // the legacy "system" sentinel. scope=shared preserves
            // multi-reader visibility under the SAL #910 filter.
            let placeholder_agent_id =
                if caller.is_empty() || caller == sentinels::ANONYMOUS_INVALID {
                    sentinels::SYSTEM_PRINCIPAL.to_string()
                } else {
                    caller.clone()
                };
            let placeholder = Memory {
                cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
                valid_from: None,
                valid_until: None,
                id: Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: ns.to_string(),
                title: format!("_standard:{ns}"),
                content: format!("namespace standard for {ns}"),
                tags: vec![NAMESPACE_STANDARD_TAG.to_string()],
                priority: 5,
                confidence: 1.0,
                source: "api".into(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata: serde_json::json!({
                    "agent_id": placeholder_agent_id,
                    "scope": "shared",
                }),
                reflection_depth: 0,
                memory_kind: crate::models::MemoryKind::Observation,
                entity_id: None,
                persona_version: None,
                citations: Vec::new(),
                source_uri: None,
                source_span: None,
                confidence_source: ConfidenceSource::CallerProvided,
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
                lifecycle_state: crate::models::LifecycleState::Open,
            };
            match db::insert(&lock.0, &placeholder) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("namespace_standard: placeholder insert failed: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
                    )
                        .into_response();
                }
            }
        }
    };

    // #929 SECURITY-high (Track A P6, 2026-05-20) — uniform ownership
    // gate. Catches the path where the caller supplied `body.id`
    // directly (bypassing the auto-seed lookup above). Load the
    // resolved standard memory by id, check ownership. The auto-seed
    // path already validated above and re-checking here is a no-op for
    // it; the body.id-supplied path goes through this gate once.
    // #2541 — body.id path uses the same authorize helper (no claim rewrite).
    if let Ok(Some(resolved_mem)) = db::get(&lock.0, &resolved_id) {
        // Pre-check on the BOUND memory only (`None` parent); the declared
        // parent's #2542 entitlement is enforced by the delegated
        // `handle_namespace_set_standard` below.
        if let Err(msg) =
            crate::mcp::authorize_namespace_standard_bind(&caller, &resolved_mem, None)
        {
            tracing::warn!(
                target: super::AUTHZ_TRACE_TARGET,
                "POST /namespaces/{{ns}}/standard 403 (body.id path): {msg} (ns={ns}, id={resolved_id})"
            );
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": msg,
                    "caller": caller
                })),
            )
                .into_response();
        }
    }

    let mut effective = body;
    effective.id = Some(resolved_id.clone());
    let mut params = namespace_standard_params(ns, &effective);
    // #929 SECURITY-high follow-up (2026-05-20) — thread the HTTP-
    // resolved caller through to the MCP entry so its #929 ownership
    // gate sees the same principal as the HTTP-handler gate. Without
    // this the MCP entry's `resolve_agent_id(params["agent_id"], None)`
    // falls back to the daemon process identity (`host:<host>:pid-…`),
    // which never matches a row-owner anchored to the HTTP caller's
    // X-Agent-Id — 400-rejects every legitimate first-write on the
    // HTTP standard surface. Verified via Track A re-probe agent
    // `aaab899d6a4bab36f` 2026-05-20 (re-verify #929 close pending).
    if let Some(obj) = params.as_object_mut() {
        obj.insert("agent_id".to_string(), json!(caller));
    }
    let result = crate::mcp::handle_namespace_set_standard(&lock.0, &params);
    // Capture the standard memory so we can fan it out to peers — cluster
    // visibility of governance rules matters for S34/S35.
    let standard_mem = db::get(&lock.0, &resolved_id).ok().flatten();
    // v0.6.2 (S35): also capture the freshly-written namespace_meta row
    // so peers learn the explicit (namespace, standard_id, parent) tuple.
    // Without this, peers auto-detect a parent via `-` prefix which may
    // disagree with what the originator set.
    let meta_entry = db::get_namespace_meta_entry(&lock.0, ns).ok().flatten();
    drop(lock);

    match result {
        Ok(v) => {
            if let Some(ref mem) = standard_mem
                && let Some(resp) = fanout_or_pending(app, mem).await
            {
                return resp;
            }
            if let (Some(entry), Some(fed)) = (meta_entry.as_ref(), app.federation.as_ref()) {
                match crate::federation::broadcast_namespace_meta_quorum(fed, entry).await {
                    Ok(tracker) => {
                        if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                            // #869 — typed 503 envelope via the shared helper.
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return super::under_replicated_response(&payload);
                        }
                    }
                    Err(err) => {
                        let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                        return super::under_replicated_response(&payload);
                    }
                }
            }
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

pub async fn set_namespace_standard(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(ns): Path<String>,
    Json(body): Json<NamespaceStandardBody>,
) -> impl IntoResponse {
    set_namespace_standard_inner(&app, &ns, body, Some(&headers)).await
}

#[derive(Deserialize)]
pub struct NamespaceStandardQuery {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub inherit: Option<bool>,
}

pub async fn get_namespace_standard(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(ns): Path<String>,
    Query(q): Query<NamespaceStandardQuery>,
) -> impl IntoResponse {
    // #1655 — the path-form GET must work on BOTH backends. Delegate to the
    // query-string handler, which already has the postgres SAL arm (via
    // `app.store.get_namespace_standard`) AND the sqlite fallback, by
    // injecting the path `{ns}` into the query shape. Pre-#1655 this handler
    // used the sqlite-only `Db` extractor + a raw `handle_namespace_get_standard`
    // rusqlite call, so the postgres gate 501'd the route on a postgres-backed
    // daemon even though the SAL method the qs form uses was implemented.
    let merged = NamespaceStandardQuery {
        namespace: Some(ns),
        inherit: q.inherit,
    };
    get_namespace_standard_qs(State(app), headers, Query(merged))
        .await
        .into_response()
}

pub async fn clear_namespace_standard(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(ns): Path<String>,
) -> impl IntoResponse {
    clear_namespace_standard_inner(&app, &ns, Some(&headers)).await
}

// Query-string forms for the S34/S35 `/api/v1/namespaces?namespace=…` shape.
pub async fn set_namespace_standard_qs(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NamespaceStandardBody>,
) -> impl IntoResponse {
    let Some(ns) = body
        .namespace
        .clone()
        .or_else(|| body.standard.as_ref().and_then(|s| s.namespace.clone()))
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::NAMESPACE_REQUIRED})),
        )
            .into_response();
    };
    set_namespace_standard_inner(&app, &ns, body, Some(&headers)).await
}

pub async fn get_namespace_standard_qs(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NamespaceStandardQuery>,
) -> impl IntoResponse {
    // If no namespace is supplied this shares a route with the existing
    // `list_namespaces` GET; the router chains the two so a plain
    // `GET /api/v1/namespaces` still returns the list.
    let Some(ns) = q.namespace.clone() else {
        // #945 SECURITY-medium (Track A QC sweep, 2026-05-20) —
        // list_namespaces now requires admin via require_admin;
        // thread headers through so the gate sees the X-Agent-Id.
        return list_namespaces(State(app), headers).await.into_response();
    };

    // v1.0.0 #2543 / #959 residual — explicit HTTP fetch of a namespace
    // standard is gated through the SAME canonical
    // `visibility::is_visible_to_caller` predicate as #2537 injection and
    // MCP `memory_namespace_get_standard`. Pre-fix this route passed
    // `None` (sqlite) / `CallerContext::for_admin` (postgres), so any
    // caller who could name a namespace received title + content + the
    // full governance blob of a default-private standard. Withholding
    // matches the MCP honesty shape: count-only `standards_withheld`,
    // never the withheld id / owner / namespace (existence-oracle pin).
    let visibility_caller = match resolve_caller_agent_id(None, &headers, None) {
        Ok(id) => id,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
        }
    };

    // v0.7.0 Wave-3 Continuation 5 (Bucket C / S35) — postgres-backed
    // daemons resolve the namespace standard via the SAL trait. When
    // `inherit=true` we walk the parent chain (already cached in
    // `namespace_meta.parent_namespace`) leaf→root to find the nearest
    // ancestor that has a standard memory. Without inherit we look up
    // the exact namespace.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // Binding lookup is namespace_meta (not a visibility-scoped memory
        // row). Admin context keeps the binding probe stable; body bytes
        // still go through `is_visible_to_caller` after a separate get.
        let bind_ctx = crate::store::CallerContext::for_admin(sentinels::AI_HTTP_INTERNAL);
        let inherit = q.inherit.unwrap_or(false);
        // Build chain leaf → root (most-specific first) by trimming
        // `/segment` until empty. The chain matches the SQLite
        // semantics in `db::resolve_namespace_standard` for the
        // simple namespace-hierarchy case.
        let mut chain: Vec<String> = vec![ns.clone()];
        if inherit {
            let mut cur = ns.clone();
            while let Some(pos) = cur.rfind('/') {
                cur.truncate(pos);
                if cur.is_empty() {
                    break;
                }
                chain.push(cur.clone());
            }
        }

        if inherit {
            // S35 contract — return the FULL chain of standards from
            // leaf → root so the caller sees both child and parent
            // rules layered into one view. Mirrors the sqlite
            // `handle_namespace_get_standard` inherit branch which
            // returns `chain` + `standards` arrays.
            let mut standards: Vec<serde_json::Value> = Vec::new();
            let mut withheld: usize = 0;
            for candidate in &chain {
                if let Ok(Some((standard_id, parent))) =
                    app.store.get_namespace_standard(&bind_ctx, candidate).await
                {
                    // #2543 — fetch the body under admin (so SAL private
                    // filter does not collapse Withheld into Absent), then
                    // apply the canonical predicate before any title /
                    // content / governance bytes enter the response.
                    match app.store.get(&bind_ctx, &standard_id).await {
                        Ok(m)
                            if crate::visibility::is_visible_to_caller(&m, &visibility_caller) =>
                        {
                            standards.push(json!({
                                "namespace": candidate,
                                (field_names::STANDARD_ID): standard_id,
                                "id": standard_id,
                                "title": m.title,
                                "content": m.content,
                                "priority": m.priority,
                                (field_names::PARENT_NAMESPACE): parent,
                                (field_names::GOVERNANCE): m.metadata
                                    .get(crate::META_KEY_GOVERNANCE)
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            }));
                        }
                        Ok(_) => {
                            // Binding exists; body not visible — honesty
                            // count only (never the namespace name of a
                            // withheld chain link).
                            withheld += 1;
                        }
                        Err(_) => {
                            // Dangling binding: surface id without body
                            // (matches pre-fix dangling shape).
                            standards.push(json!({
                                "namespace": candidate,
                                (field_names::STANDARD_ID): standard_id,
                                "id": standard_id,
                                (field_names::PARENT_NAMESPACE): parent,
                            }));
                        }
                    }
                }
            }
            // Pick the closest (leaf-most) *visible* entry as the resolved
            // standard for the response root level so existing
            // single-standard consumers still see the expected
            // `standard_id` when the caller may read it.
            let closest = standards.first().cloned().unwrap_or(json!({}));
            let mut body = json!({
                "namespace": ns,
                "chain": chain,
                "standards": standards,
                "count": standards.len(),
                "resolved_namespace": closest.get("namespace").cloned()
                    .unwrap_or(serde_json::Value::Null),
                (field_names::STANDARD_ID): closest.get(field_names::STANDARD_ID).cloned()
                    .unwrap_or(serde_json::Value::Null),
                "id": closest.get("id").cloned()
                    .unwrap_or(serde_json::Value::Null),
                (field_names::PARENT_NAMESPACE): closest.get(field_names::PARENT_NAMESPACE).cloned()
                    .unwrap_or(serde_json::Value::Null),
                (field_names::STORAGE_BACKEND): "postgres",
            });
            if withheld > 0 {
                body[field_names::STANDARDS_WITHHELD] = json!(withheld);
            }
            return (StatusCode::OK, Json(body)).into_response();
        }
        // Non-inherit form — single exact-match lookup.
        match app.store.get_namespace_standard(&bind_ctx, &ns).await {
            Ok(Some((standard_id, parent))) => {
                // #2543 — if the bound memory exists and is not visible,
                // do not leak its id (MCP honesty shape).
                match app.store.get(&bind_ctx, &standard_id).await {
                    Ok(m) if !crate::visibility::is_visible_to_caller(&m, &visibility_caller) => {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "namespace": ns,
                                (field_names::STANDARD_ID): serde_json::Value::Null,
                                "id": serde_json::Value::Null,
                                (field_names::STANDARDS_WITHHELD): 1,
                                (field_names::STORAGE_BACKEND): "postgres",
                            })),
                        )
                            .into_response();
                    }
                    _ => {}
                }
                return (
                    StatusCode::OK,
                    Json(json!({
                        "namespace": ns,
                        "resolved_namespace": ns,
                        (field_names::STANDARD_ID): standard_id,
                        "id": standard_id,
                        (field_names::PARENT_NAMESPACE): parent,
                        (field_names::STORAGE_BACKEND): "postgres",
                    })),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(e) => return store_err_to_response(e),
        }
        return (
            StatusCode::OK,
            Json(json!({
                "namespace": ns,
                (field_names::STANDARD_ID): serde_json::Value::Null,
                "id": serde_json::Value::Null,
                (field_names::PARENT_NAMESPACE): serde_json::Value::Null,
                (field_names::STORAGE_BACKEND): "postgres",
            })),
        )
            .into_response();
    }

    let mut params = json!({"namespace": ns});
    if let Some(inh) = q.inherit {
        params["inherit"] = json!(inh);
    }
    let lock = app.db.lock().await;
    // #2543 — pass the HTTP principal into the shared MCP choke so the
    // sqlite arm cannot diverge from postgres / injection / tool surfaces.
    let result =
        crate::mcp::handle_namespace_get_standard(&lock.0, &params, Some(&visibility_caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

pub async fn clear_namespace_standard_qs(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<NamespaceStandardQuery>,
) -> impl IntoResponse {
    let Some(ns) = q.namespace else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::NAMESPACE_REQUIRED})),
        )
            .into_response();
    };
    clear_namespace_standard_inner(&app, &ns, Some(&headers)).await
}

/// v0.6.2 (S35 follow-up): shared implementation for path and query-string
/// clear handlers. Runs the local clear then, on success, fans the cleared
/// namespace out to peers via `broadcast_namespace_meta_clear_quorum`.
/// Returns 503 `quorum_not_met` when federation is configured and the quorum
/// contract fails — matching the pattern established by
/// `set_namespace_standard_inner`.
async fn clear_namespace_standard_inner(
    app: &AppState,
    ns: &str,
    headers: Option<&HeaderMap>,
) -> axum::response::Response {
    // #2131 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the #929 caller-vs-recorded-owner clear check below. Sibling of the
    // set_namespace_standard gate: clearing a namespace standard DELETES the
    // governance policy gating EVERY downstream write into the namespace, and
    // clear is authorized by `recorded_owner == caller`; so under `enforce` a
    // shared-key `Claimed` caller forging `X-Agent-Id: <victim>` (caller ==
    // recorded_owner == victim) could otherwise DISARM governance over the
    // victim's whole namespace by deleting its `namespace_meta` row. Refuse it
    // here. Inert for zero-config deployments (both public entry points — path
    // + qs forms — route through this inner helper).
    if let Some(h) = headers
        && let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
            &app.enrolled_agent_keys,
            app.http_identity_mode,
            h,
            crate::OP_CLEAR_NAMESPACE_STANDARD,
        )
    {
        return resp;
    }
    // #913 (security-medium / SOC2, 2026-05-19) — admin governance audit.
    // Clearing a namespace standard removes the governance policy that
    // gates downstream writes; the chain entry MUST land before the
    // storage write so the audit trail captures intent.
    let header_agent_id =
        headers.and_then(|h| h.get(crate::HEADER_AGENT_ID).and_then(|v| v.to_str().ok()));
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| sentinels::ANONYMOUS_INVALID.to_string());
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        crate::mcp::AUDIT_KIND_NAMESPACE_CLEAR_STANDARD,
        "",
        json!({
            "namespace": ns,
        }),
    );

    // v0.7.0 Wave-3 Continuation 2 (Phase 11) — postgres-backed clear.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // v0.7.0 ship-hardening (2026-05-19): use the resolved caller
        // from the X-Agent-Id header. Pre-fix this hardcoded "ai:http"
        // which made the standard-clear lookup miss its target memory
        // when caller != "ai:http". `caller` here is the
        // header-resolved id used for the audit-record above.
        let ctx = crate::store::CallerContext::for_agent(caller.clone());
        return match app.store.clear_namespace_standard(&ctx, ns).await {
            Ok(true) => (
                StatusCode::OK,
                Json(json!({
                    "cleared": true,
                    "namespace": ns,
                    (field_names::STORAGE_BACKEND): "postgres",
                })),
            )
                .into_response(),
            Ok(false) => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "no namespace_meta row matched"})),
            )
                .into_response(),
            Err(e) => store_err_to_response(e),
        };
    }
    // #2719 (CB-6 / 2704-F1, CWE-284) — thread the header-resolved caller into
    // the clear params EXACTLY like `set_namespace_standard_inner` (the SET path
    // above) does. Pre-fix this passed only `{namespace}`, so
    // `handle_namespace_clear_standard`'s `identity_claimed` probe
    // (`params.agent_id` present + non-empty) was FALSE and the entire #1777
    // owner gate + #2545 unresolvable-refusal block was SKIPPED — letting any
    // api-key/keyless network caller DELETE a namespace's governance standard on
    // a sqlite daemon (dropping the #2503 severed floor, re-opening the #2545
    // attack on the network surface). Threading `caller` runs the same gate the
    // MCP + postgres surfaces already enforce; a keyless caller resolves to
    // `anonymous:invalid` (mirroring SET), which is refused against a named
    // owner but still passes for an unowned/`system` standard (unowned-pass).
    let mut params = json!({"namespace": ns});
    if let Some(obj) = params.as_object_mut() {
        obj.insert("agent_id".to_string(), json!(caller));
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_namespace_clear_standard(&lock.0, &params);
    drop(lock);
    match result {
        Ok(v) => {
            if let Some(fed) = app.federation.as_ref() {
                let namespaces = vec![ns.to_string()];
                match crate::federation::broadcast_namespace_meta_clear_quorum(fed, &namespaces)
                    .await
                {
                    Ok(tracker) => {
                        if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                            // #869 — typed 503 envelope via the shared helper.
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return super::under_replicated_response(&payload);
                        }
                    }
                    Err(err) => {
                        let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                        return super::under_replicated_response(&payload);
                    }
                }
            }
            (StatusCode::OK, Json(v)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

// --- /api/v1/session/start (POST) ------------------------------------------

#[derive(Deserialize)]
pub struct SessionStartBody {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

pub async fn session_start(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SessionStartBody>,
) -> impl IntoResponse {
    // agent_id is optional for session_start; but if supplied it must validate.
    if let Some(ref id) = body.agent_id
        && let Err(e) = validate::validate_agent_id(id)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
        )
            .into_response();
    }
    // #2135 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the session-start read resolves + applies its `scope=private` visibility
    // filter. Pre-fix, a shared-transport-key caller forging `X-Agent-Id:
    // <victim>` (or `agent_id` body) resolved `caller=victim` and read the
    // victim's private memory content out of `handle_session_start`. Requires
    // the enrolled-keys map, hence the `State<AppState>` signature (was
    // `State<Db>`, which cannot reach `enrolled_agent_keys`). Inert for
    // zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "session_start",
    ) {
        return resp;
    }
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    // v0.7.0 #1420 — resolve the caller for the post-list visibility
    // filter. Pre-fix, `header_agent_id` was dropped ("identity
    // currently informational") and `handle_session_start(..., None)`
    // skipped the filter, leaking cross-agent `scope=private` rows.
    //
    // session_start historically accepted `agent_id` from EITHER body
    // OR header (both optional), so we preserve that contract instead
    // of using the stricter `resolve_http_agent_id` (which demands a
    // header for write surfaces). Precedence: header → body →
    // synthesized `anonymous:req-<uuid>`. When both header + body are
    // supplied and disagree, return 400 — same mismatch posture as
    // every other write surface (#910 norm).
    if let (Some(h), Some(b)) = (header_agent_id, body.agent_id.as_deref())
        && h != b
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "agent_id body parameter does not match X-Agent-Id header"})),
        )
            .into_response();
    }
    let caller = header_agent_id
        .map(str::to_string)
        .or_else(|| body.agent_id.clone())
        .unwrap_or_else(crate::identity::anonymous_request_id);
    let mut params = json!({});
    if let Some(ref n) = body.namespace {
        params["namespace"] = json!(n);
    }
    if let Some(l) = body.limit {
        params["limit"] = json!(l);
    }

    // FBL-09 (v1.0.0 pre-ship 3x7) — serve session_start context from the
    // CONFIGURED store on a postgres-backed daemon. Pre-fix this handler
    // locked the LOCAL sqlite `app.db` and ran `mcp::handle_session_start`
    // against it on EVERY backend, so a postgres-fleet agent booting via
    // HTTP got recent-memory context from the (empty/unrelated) local
    // sqlite file — silently hiding the fleet's real corpus. Route the
    // recent-memory list + the `scope=private` visibility post-filter
    // through the SAL trait (`app.store.list`), matching the postgres
    // `list_memories` precedent. (The sqlite decorator enrichment +
    // namespace-standard injection are rusqlite-conn-bound; their absence
    // on postgres is consistent with the existing postgres `list_memories`
    // path, which likewise serves plain rows — tracked as the follow-up
    // parity item, not a wrong-backend data defect.)
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        if let Some(ns) = body.namespace.as_deref()
            && let Err(e) = validate::validate_namespace(ns)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": crate::errors::msg::invalid("namespace", e)})),
            )
                .into_response();
        }
        let limit = usize::try_from(body.limit.unwrap_or(10))
            .unwrap_or(usize::MAX)
            .min(50);
        let filter = crate::store::Filter {
            namespace: body.namespace.clone(),
            tier: None,
            tags_any: Vec::new(),
            agent_id: None,
            since: None,
            until: None,
            valid_at: None,
            limit,
            // #1876 — subscription-mirror listing serves the first window.
            offset: 0,
            active_embedding_space: None,
            // #2580 — metadata-equality pushdown axis unused on this path.
            metadata_eq: None,
            // #3185/#3127 — keyword-search-only axis; list ignores it.
            source_uri: None,
        };
        let ctx = crate::store::CallerContext::for_agent(&caller);
        return match app.store.list(&ctx, &filter).await {
            Ok(mems) => {
                let visible: Vec<crate::models::Memory> = mems
                    .into_iter()
                    .filter(|m| crate::visibility::is_visible_to_caller(m, &caller))
                    .collect();
                let mut v = json!({
                    "memories": &visible,
                    "count": visible.len(),
                    "mode": crate::mcp::SESSION_START_MODE,
                    "session_id": Uuid::new_v4().to_string(),
                });
                if let Some(ref a) = body.agent_id
                    && let Some(obj) = v.as_object_mut()
                {
                    obj.insert("agent_id".into(), json!(a));
                }
                (StatusCode::OK, Json(v)).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    let result = crate::mcp::handle_session_start(&lock.0, &params, None, Some(&caller));
    drop(lock);
    match result {
        Ok(mut v) => {
            // Stamp a stable session id so callers (S36) can correlate
            // subsequent writes. We don't persist sessions today; the id is
            // advisory and round-tripped via metadata by the caller.
            if let Some(obj) = v.as_object_mut() {
                obj.entry("session_id")
                    .or_insert_with(|| json!(Uuid::new_v4().to_string()));
                if let Some(ref a) = body.agent_id {
                    obj.insert("agent_id".into(), json!(a));
                }
            }
            (StatusCode::OK, Json(v)).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}
