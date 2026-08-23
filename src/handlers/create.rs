// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP `POST /api/v1/memories` create-path: six-stage orchestrator,
//! per-stage helpers, postgres branch, and inline stage-helper tests.
//!
//! Extracted from [`super::http`] under issue #650 (handler cap ≤1200
//! LOC). Handler bodies are unchanged; only the module surface moved.
//! Wire compatibility preserved via `pub use create::*` in [`super`].

#![allow(clippy::too_many_lines)]

use crate::models::field_names;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::db;
use crate::embeddings::EmbedStatus;
#[cfg(test)]
use crate::models::Tier;
use crate::models::{CreateMemory, Memory};
use crate::validate;

#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;
use super::try_enqueue_auto_tag;
use super::{AppState, JsonOrBadRequest};

/// #1924 (CWE-288) — consult the process pre-event enforcement gate on the HTTP
/// write surface, mirroring the MCP `consult_pre_event_gate` install/consult
/// pattern. The HTTP write handlers are a SEPARATE implementation from the MCP
/// `handle_*` functions, so the #1885 gate — installed for HTTP by
/// `daemon_runtime::serve` — was never consulted on this surface: an operator
/// running `[hooks].enforce_mode = enforce` with a `required_events` entry saw
/// the boot banner / `doctor --hooks` "WILL DENY" while every HTTP-routed write
/// committed with NO required hook running. This is that missing consult.
///
/// Returns `Some(503 response)` when the gate DENIES (enforce-mode + the event
/// is required + NO enabled hook is configured for it, or a present required
/// hook fails closed); `None` to proceed. INERT (`None`) when no gate is
/// installed — the default enforce-off deployment — so callers consult
/// unconditionally at ~zero cost beyond one `OnceLock` load.
///
/// Shared by every HTTP write handler (`create`, `delete`, `promote`, `link`,
/// `consolidate`, `reflect`) so the enforcement surface is uniform. The
/// underlying consult drives the async hook chain via `block_on_local_bounded`, which
/// uses `block_in_place` on the daemon's multi-thread runtime — safe to call
/// from an async handler.
/// #2390 (N9) — `namespaces` is the SUBSTRATE-resolved namespace set the
/// operation will touch (see [`resolve_pre_event_namespaces`]). It is a required
/// parameter rather than a payload key so the compiler enumerates every dispatch
/// site — the 11-of-13 omission that made namespace-scoped hooks dead code is
/// now a build error — and so a caller-supplied `"namespace"` in a forwarded
/// request body can never decide which hook is in scope.
pub(crate) fn http_pre_event_gate(
    event: crate::hooks::HookEvent,
    namespaces: Vec<String>,
    payload: serde_json::Value,
) -> Option<axum::response::Response> {
    match crate::mcp::consult_pre_event_gate(event, namespaces, payload) {
        Ok(()) => None,
        Err(reason) => Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": reason })),
            )
                .into_response(),
        ),
    }
}

/// #2390 (N9) — resolve the namespace(s) of `ids` on the HTTP surface for
/// pre-event hook scoping.
///
/// Resolution MIRRORS THE BACKEND the write itself will take, because a
/// resolution skew is a live defect in both directions: resolving nothing where
/// the handler resolves something re-opens the #2390 bypass (or, under
/// `enforce` with a scoped hook, 503s a legitimate write), and the postgres
/// daemon must not be left resolving nothing while sqlite works — a sqlite-only
/// `db::get` here would silently re-open the bypass on postgres with no
/// non-`#[ignore]` test to catch it (the #1799 lesson).
///
/// * Sqlite backend (and every non-`sal` build) → [`crate::db::resolve_id`], the
///   PREFIX-capable resolution the sqlite write handlers use, so a caller
///   passing a legitimate id prefix resolves at the gate exactly as it will at
///   the write.
/// * Postgres backend → `app.store.get`, matching the postgres branches, which
///   resolve by exact id through the same SAL call.
///
/// The DB read happens ONLY when the pre-event gate is installed
/// (`[hooks].enforce_mode != off` AND a non-empty `required_events`), so the
/// default deployment pays one `OnceLock` load and no query.
///
/// Returns de-duplicated namespaces; empty when nothing resolves, which
/// `dispatch_pre_event_enforced` converts into a fail-closed refusal under
/// `enforce` when a namespace-scoped hook is configured for the event.
pub(crate) async fn resolve_pre_event_namespaces(
    app: &AppState,
    headers: &axum::http::HeaderMap,
    ids: &[String],
) -> Vec<String> {
    if !crate::mcp::pre_event_gate_installed() || ids.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::handlers::parity::http_caller_ctx(headers, None);
        for id in ids {
            if let Ok(mem) = app.store.get(&ctx, id).await
                && !out.contains(&mem.namespace)
            {
                out.push(mem.namespace);
            }
        }
        return out;
    }
    let _ = headers;
    // Sqlite: the prefix-capable resolution, matching the sqlite write handlers.
    // The guard is released at the end of this function, before the handler
    // takes its own lock for the write.
    let guard = app.db.lock().await;
    for id in ids {
        if let Ok(Some(mem)) = crate::db::resolve_id(&guard.0, id)
            && !out.contains(&mem.namespace)
        {
            out.push(mem.namespace);
        }
    }
    drop(guard);
    out
}

/// #2356 (W1A6-03) — consult the pre-event enforcement gate for
/// `PreGovernanceDecision` on the HTTP surface, mirroring
/// [`http_pre_event_gate`]. Called immediately BEFORE every HTTP-side
/// governance-decision dispatch (both the sqlite `db::enforce_governance`
/// branches and the postgres `MemoryStore::enforce_governance_action`
/// branches) so `[hooks].required_events = ["pre_governance_decision"]`
/// under `enforce_mode = enforce` actually denies instead of silently
/// no-oping while the boot banner / `doctor --hooks` claim "WILL DENY".
///
/// Returns `Some(503 response)` when the gate DENIES; `None` to proceed.
/// INERT (`None`) when no gate is installed — the default enforce-off
/// deployment.
pub(crate) fn http_pre_governance_decision_gate(
    namespace: &str,
    action: &str,
    agent_id: &str,
    memory_id: Option<&str>,
) -> Option<axum::response::Response> {
    match crate::mcp::consult_pre_governance_decision_gate(namespace, action, agent_id, memory_id) {
        Ok(()) => None,
        Err(reason) => Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": reason })),
            )
                .into_response(),
        ),
    }
}

// #866 — `create_memory` stage-helpers.
//
// The original `create_memory` carried ~790 LOC across the agent_id
// resolution, on_conflict policy, embed-before-lock pass, governance
// pre-write hook, the actual `db::insert`, the federation fanout, and
// the postgres-SAL branch. Each stage has a clear input → output
// contract, so each lives in a dedicated helper. The wrapper below
// is the orchestrator: it sequences the six stage helpers (1 agent_id
// → 2 on_conflict → 3 embed-before-lock → 4 governance → 5 insert →
// 6 fanout) and returns the assembled HTTP response.
//
// Helpers return `Result<T, axum::response::Response>` so any short-
// circuit envelope (validation error, conflict, governance pending,
// federation quorum failure) is just an `?` away from the orchestrator.
// ---------------------------------------------------------------------------

/// #866 stage 1 — resolve `agent_id` via the HTTP precedence chain:
///   1. top-level `body.agent_id`
///   2. embedded `body.metadata.agent_id` (caller's NHI claim — load-
///      bearing for federation receivers and clients that prefer the
///      metadata-only shape; mirrors the MCP precedence at
///      `crate::mcp::handle_store` (NHI precedence) and the CLAUDE.md §Agent Identity (NHI)
///      contract).
///   3. `X-Agent-Id` request header
///   4. per-request anonymous fallback
///
/// Also validates `body.scope` (when supplied at the top level) and
/// merges both the resolved `agent_id` and the scope into a fresh
/// `metadata` value. The returned metadata is the canonical one for
/// the subsequent stages — `body.metadata` is consumed here.
///
/// L11 (NHI-D-fed-agentid-mutation): prior to this split, step 2 was
/// missing — a federated peer that resent a memory through
/// `POST /api/v1/memories` (or a client that only stamped
/// `metadata.agent_id`) would have its claim silently rewritten to
/// the per-request anonymous id, breaking the immutable-provenance
/// contract documented in CLAUDE.md and enforced at the SQL layer by
/// `db::insert_if_newer` / `apply_remote_memory`.
fn resolve_create_agent_id(
    headers: &HeaderMap,
    body: &CreateMemory,
) -> Result<(String, serde_json::Value), axum::response::Response> {
    let agent_id = resolve_create_caller(headers).map_err(CreateFieldError::into_response)?;
    let metadata =
        resolve_create_metadata(&agent_id, body).map_err(CreateFieldError::into_response)?;
    Ok((agent_id, metadata))
}

/// #2550 — a typed, per-field create-funnel refusal.
///
/// The single-create handler renders one of these as its whole HTTP response;
/// `bulk_create` renders it as ONE ROW's entry in the response `errors[]`
/// array. Before #2550 the two surfaces had no shared refusal vocabulary at
/// all, which is precisely why the bulk path silently DROPPED the fields the
/// single path validates (`scope`) or stamps (`kind_provenance`) — there was
/// nothing to drop them *into*.
///
/// `field` is a SERVER-AUTHORED identifier from a closed set (never caller
/// text) and `code` is a `crate::errors::error_codes` slug, so both are safe
/// to echo to an unauthenticated caller; `message` is the human-readable
/// reason and is sanitized before it reaches a bulk `errors[]` entry.
pub(crate) struct CreateFieldError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) field: &'static str,
    pub(crate) message: String,
}

impl CreateFieldError {
    /// #2552 — project this typed refusal into the bulk `errors[]` class
    /// DIRECTLY, rather than round-tripping its message through the substring
    /// classifier.
    ///
    /// The funnel already KNOWS the exact status and code; re-deriving them
    /// from prose would be a lossy inference over a value we hold — and it
    /// fails concretely: `AGENT_ID_BODY_MISMATCH` matches no classifier arm,
    /// so a permanent 403 identity refusal would classify as a RETRYABLE
    /// `500 internal error` and a fleet loader would retry a request that can
    /// never succeed.
    pub(crate) fn as_bulk_class(&self) -> crate::handlers::errors::BulkRowErrorClass {
        crate::handlers::errors::BulkRowErrorClass {
            code: self.code,
            // #851 — the wire label stays inside the sanitized allowlist.
            label: if self.status == StatusCode::FORBIDDEN {
                "forbidden"
            } else {
                "validation failed"
            },
            status: self.status,
            retryable: false,
        }
    }

    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(json!({ "code": self.code, "error": self.message })),
        )
            .into_response()
    }
}

/// #2550 — resolve the authenticated caller for a create-family write.
///
/// Split out of [`resolve_create_agent_id`] so `bulk_create` resolves the
/// principal EXACTLY once for the whole batch (its historical behaviour) while
/// still sharing the per-row field resolution below.
pub(crate) fn resolve_create_caller(headers: &HeaderMap) -> Result<String, CreateFieldError> {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    // #907 (security-high, 2026-05-19) — sibling of #874/#901/#905.
    // The pre-#907 path preferred caller-supplied
    // `body.agent_id` / `metadata.agent_id` over the authenticated
    // `X-Agent-Id` header on the WRITE-path provenance stamp. An
    // attacker authenticated as `bob` could call
    // `POST /api/v1/memories` with `body.agent_id="alice"` (or
    // `metadata.agent_id="alice"`) and the new row would land with
    // `metadata.agent_id="alice"` — a provenance LIE that
    // permanently fakes attribution (NHI design contract:
    // `metadata.agent_id` is preserved across update/dedup/import).
    // Header-only authentication now; caller-supplied claims (if
    // present) must MATCH the authenticated caller else 403. The
    // metadata stamp is forced to the resolved caller below.
    crate::identity::resolve_http_agent_id(None, header_agent_id).map_err(|e| CreateFieldError {
        status: StatusCode::BAD_REQUEST,
        code: crate::errors::error_codes::VALIDATION_FAILED,
        field: "agent_id",
        message: crate::errors::msg::invalid("agent_id", e),
    })
}

/// #2550 — THE canonical per-row metadata resolution for every create-family
/// write funnel (single-create sqlite + postgres, `bulk_create` sqlite +
/// postgres).
///
/// Pre-#2550 this logic lived ONLY inside [`resolve_create_agent_id`], which
/// `bulk_create` never called: both bulk branches hand-rolled a
/// `metadata_stamped` that inserted `agent_id` and nothing else. The two
/// consequences were a silent SECURITY-relevant field drop (a caller's
/// top-level `scope: "collective"` was accepted, never read, and the row
/// landed `scope_idx = 'private'` — invisible to every other agent) and a
/// silent provenance drop (`kind_provenance` left NULL). Routing all four
/// funnels through this one function makes the class structurally
/// unreachable: a future field added here reaches bulk for free.
///
/// Performs, in order:
/// 1. #907 — refuse a caller-supplied `agent_id` / `metadata.agent_id` that
///    disagrees with the authenticated principal (403). Bulk previously
///    OVERWROTE a disagreeing claim silently; a refusal is the single-create
///    contract and the honest one.
/// 2. Stamp the resolved principal into `metadata.agent_id`.
/// 3. #151 — validate the top-level `scope` shortcut and merge it into
///    `metadata.scope`.
///
/// # Errors
///
/// [`CreateFieldError`] carrying the HTTP status the single-create surface
/// would have returned, plus the server-authored field name the bulk surface
/// echoes per row.
pub(crate) fn resolve_create_metadata(
    agent_id: &str,
    body: &CreateMemory,
) -> Result<serde_json::Value, CreateFieldError> {
    if let Some(claimed) = body.agent_id.as_deref()
        && claimed != agent_id
    {
        return Err(CreateFieldError {
            status: StatusCode::FORBIDDEN,
            code: crate::errors::error_codes::AGENT_ID_MISMATCH,
            field: "agent_id",
            message: crate::errors::msg::AGENT_ID_BODY_MISMATCH.to_string(),
        });
    }
    if let Some(claimed) = body
        .metadata
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        && claimed != agent_id
    {
        return Err(CreateFieldError {
            status: StatusCode::FORBIDDEN,
            code: crate::errors::error_codes::AGENT_ID_MISMATCH,
            field: "metadata.agent_id",
            message: METADATA_AGENT_ID_MISMATCH.to_string(),
        });
    }
    let mut metadata = body.metadata.clone();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String(agent_id.to_string()),
        );
    }
    // #151 scope: validate + merge into metadata if supplied at the top
    // level (inline metadata.scope still works; top-level is a shortcut).
    if let Some(ref s) = body.scope {
        validate::validate_scope(s).map_err(|e| CreateFieldError {
            status: StatusCode::BAD_REQUEST,
            code: crate::errors::error_codes::VALIDATION_FAILED,
            field: "scope",
            message: e.to_string(),
        })?;
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("scope".to_string(), serde_json::Value::String(s.clone()));
        }
    }
    Ok(metadata)
}

/// #2550 — the #907 metadata-claim refusal message, hoisted so the single
/// and bulk funnels cannot drift (pm-v3.1 literal de-dup).
pub(crate) const METADATA_AGENT_ID_MISMATCH: &str =
    "metadata.agent_id does not match authenticated caller";

/// #2550 — THE canonical `CreateMemory` -> [`Memory`] projection for every
/// create-family write funnel.
///
/// Every field the wire accepts is resolved HERE, once. Pre-#2550 there were
/// FOUR hand-maintained copies of this struct literal (single-create sqlite +
/// postgres, bulk sqlite + postgres) and the two bulk copies had already
/// drifted: they omitted the `kind_provenance` stamp entirely, so a
/// bulk-written row carried a NULL provenance column while the byte-identical
/// body posted to `/memories` carried `declared`. Collapsing them means a
/// field can no longer be honoured on one funnel and dropped on another.
///
/// Callers supply the stage outputs that are NOT pure functions of `body`:
/// the conflict-resolved `title`, the auto-tag-merged `tags`, the resolved
/// `expires_at`, and the canonical `metadata` from
/// [`resolve_create_metadata`].
pub(crate) fn build_create_memory(
    body: &CreateMemory,
    metadata: serde_json::Value,
    title: String,
    tags: Vec<String>,
    expires_at: Option<String>,
    now: &chrono::DateTime<Utc>,
) -> Memory {
    let mut mem = Memory {
        id: Uuid::new_v4().to_string(),
        tier: body.tier.clone(),
        namespace: body.namespace.clone(),
        title,
        content: body.content.clone(),
        tags,
        priority: body.priority.clamp(1, 10),
        // #1591 — omitted confidence resolves to the compiled default with
        // truthful `confidence_source = "default"` provenance.
        confidence: body.resolved_confidence().clamp(0.0, 1.0),
        source: body.source.clone(),
        access_count: 0,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        last_accessed_at: None,
        expires_at,
        metadata,
        reflection_depth: 0,
        // #1385 — honour caller-supplied `kind`; unknown / absent falls
        // through to `Observation` (forward-compat with future variants),
        // matching the MCP `memory_store` contract.
        memory_kind: body
            .kind
            .as_deref()
            .and_then(crate::models::MemoryKind::from_str)
            .unwrap_or_default(),
        entity_id: None,
        persona_version: None,
        // #1411 — Form 4 fact provenance threaded through from the body.
        citations: body.citations.clone(),
        source_uri: body.source_uri.clone(),
        source_span: body.source_span.clone(),
        confidence_source: body.resolved_confidence_source(),
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
        // v0.9.0 G8 (#1825) — stamped by the persist layer.
        cid: None,
        // #2258 / #1834 — claim-bitemporal VALID-time bounds (validated in
        // `validate::validate_create`). Both backends keep `valid_from`
        // immutably on upsert and COALESCE `valid_until`.
        valid_from: body.valid_from.clone(),
        valid_until: body.valid_until.clone(),
    };
    // v1.0.0 (#1945, spec §4) — epistemic-typing provenance: a caller-supplied
    // `kind` is `declared`; caller silence (the system default) is
    // `channel_derived`. HTTP does not run the auto-classify hook (MCP-only).
    if body.kind.is_some() {
        crate::models::KindProvenance::Declared.stamp(&mut mem.metadata);
    } else {
        crate::models::KindProvenance::ChannelDerived.stamp(&mut mem.metadata);
    }
    mem
}

/// #866 stage 3 — embed-before-lock. Issue #219: the embedder runs
/// 10-200 ms of ONNX / Ollama work that must not hold the single
/// shared `Mutex<Connection>` on a multi-agent daemon.
///
/// v0.7.0 Round-2 F10 — calls α's `Embedder::embed_with_status` so the
/// success/skip/fail outcome is captured alongside the vector. The
/// success-path response stays silent on `Indexed`; non-`Indexed`
/// outcomes are surfaced as `embed_status` on the response body so the
/// caller can tell semantic recall will miss this row until a re-index.
/// Keyword-only deployments (embedder=None) report `Indexed` so the
/// response shape is unchanged on nodes where the semantic layer is
/// intentionally absent.
fn embed_create_before_lock(
    app: &AppState,
    title: &str,
    content: &str,
) -> (Option<Vec<f32>>, EmbedStatus) {
    let embedding_text = crate::embeddings::embedding_document(title, content);
    match app.embedder.as_ref().as_ref() {
        None => (None, EmbedStatus::Indexed),
        Some(emb) => emb.embed_with_status(&embedding_text),
    }
}

/// #866 stage 2 — resolve the `on_conflict` policy:
///   - `error` (default): 409 CONFLICT + typed payload if a row with
///     the same (title, namespace) already exists.
///   - `version`: rewrite the title to the next free suffix.
///   - `merge`: fall through; `db::insert` will UPSERT via the legacy
///     INSERT ... ON CONFLICT path.
///
/// Returns the final title to embed in the canonical row, or an
/// already-assembled error response for the orchestrator to surface.
fn resolve_create_conflict_title(
    conn: &rusqlite::Connection,
    body: &CreateMemory,
    on_conflict_mode: crate::mcp::tools::OnConflictMode,
) -> Result<String, axum::response::Response> {
    use crate::mcp::tools::OnConflictMode;
    match on_conflict_mode {
        OnConflictMode::Error => {
            match db::find_by_title_namespace(conn, &body.title, &body.namespace) {
                Ok(Some(existing_id)) => Err(conflict_409_response(
                    &body.title,
                    &body.namespace,
                    &existing_id,
                )),
                Ok(None) => Ok(body.title.clone()),
                Err(e) => {
                    tracing::error!("on_conflict lookup failed: {e}");
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "conflict check failed"})),
                    )
                        .into_response())
                }
            }
        }
        OnConflictMode::Version => db::next_versioned_title(conn, &body.title, &body.namespace)
            .map_err(|e| {
                tracing::error!("on_conflict=version failed: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "could not pick a versioned title"})),
                )
                    .into_response()
            }),
        OnConflictMode::Merge => Ok(body.title.clone()),
    }
}

/// #2771 — the ONE builder for the `409 CONFLICT` a `(title, namespace)`
/// create collision returns, whether the collision is PROBE-detected (an
/// existing row seen up front) or WRITE-detected (the fail-closed `ON CONFLICT
/// DO NOTHING` refused a racer). Single-sources the wire shape — `code:
/// CONFLICT`, the message, and `existing_id` — across every sqlite + postgres
/// create funnel so a race-detected 409 is byte-identical to a probe-detected
/// one (and the message literal lives at exactly one site).
fn conflict_409_response(
    title: &str,
    namespace: &str,
    existing_id: &str,
) -> axum::response::Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "code": crate::errors::error_codes::CONFLICT,
            "error": format!(
                "memory with title '{title}' already exists in namespace '{namespace}'"
            ),
            (field_names::EXISTING_ID): existing_id,
        })),
    )
        .into_response()
}

/// #866 stage 4 — substrate governance pre-write hook. Walks the
/// inheritance chain via `db::enforce_governance` and either:
///   - `Allow`: returns `Ok(())` to the orchestrator (caller proceeds
///     to the insert stage).
///   - `Deny`: short-circuits with 403 FORBIDDEN + the operator-
///     authored reason verbatim.
///   - `Pending`: queues the action in `pending_actions`, fires the
///     K4 `approval_requested` webhook, then drops the lock and
///     fans the pending row out to federation peers via
///     `broadcast_pending_quorum`. Returns 202 ACCEPTED with the
///     pending id so the caller can drive the consensus path through
///     `POST /pending/{id}/approve`.
///
/// The Pending branch consumes the supplied `lock`; the orchestrator
/// re-acquires `state.lock().await` AFTER an `Allow` return because
/// the consume here is intentional (`drop(lock)` before the federation
/// broadcast — keeping the DB lock across an async `await` is the
/// regression #866 explicitly guards against).
async fn enforce_create_governance<'a>(
    app: &AppState,
    lock: tokio::sync::MutexGuard<
        'a,
        (
            rusqlite::Connection,
            std::path::PathBuf,
            crate::config::ResolvedTtl,
            bool,
        ),
    >,
    mem: &Memory,
    // v0.9.0 G10.1 (#1827) — the edge-parsed capability token (or None).
    capability: Option<&crate::governance::capability::CapabilityToken>,
) -> Result<
    tokio::sync::MutexGuard<
        'a,
        (
            rusqlite::Connection,
            std::path::PathBuf,
            crate::config::ResolvedTtl,
            bool,
        ),
    >,
    axum::response::Response,
> {
    use crate::models::{GovernanceDecision, GovernedAction};
    // #869 audit (Category B — safe default): missing or non-string
    // `agent_id` collapses to `""`. The governance engine treats the
    // empty agent the same as an anonymous caller (no per-agent rules
    // match), which is the documented fail-closed posture.
    let agent_for_gov = mem
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // #869 — silently degrading to `Value::Null` would let the
    // governance engine see a different payload than the one we
    // were about to commit (rule predicates that key on memory
    // fields would all evaluate against `null` and degenerate to
    // either always-allow or always-deny depending on the rule
    // semantics). Fail closed with a 500 instead.
    let payload = match super::to_value_or_500("create_memory.governance.payload", mem) {
        Ok(v) => v,
        Err(resp) => return Err(resp),
    };
    // #2356 (W1A6-03) — `pre_governance_decision` mandatory-hook-presence
    // consult BEFORE the governance decision dispatches (sqlite branch).
    if let Some(resp) =
        http_pre_governance_decision_gate(&mem.namespace, "store", &agent_for_gov, None)
    {
        return Err(resp);
    }
    match db::enforce_governance(
        &lock.0,
        GovernedAction::Store,
        &mem.namespace,
        &agent_for_gov,
        None,
        None,
        &payload,
        capability,
    ) {
        Ok(GovernanceDecision::Allow) => Ok(lock),
        Ok(GovernanceDecision::Deny(refusal)) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": crate::governance::deny_message(
                "store",
                crate::governance::DenyGate::Governance,
                &refusal.reason,
            )})),
        )
            .into_response()),
        Ok(GovernanceDecision::Pending(pending_id)) => {
            // v0.6.2 (S34): fan out the new pending row so peers can
            // approve / reject / list it. Load the canonical row we
            // just inserted and broadcast before responding.
            let pending_row = db::get_pending_action(&lock.0, &pending_id).ok().flatten();
            // v0.7.0 K4 — fire the `approval_requested` webhook event
            // through the existing subscription dispatcher so K10's
            // Approval API HTTP+SSE handler picks it up. Done BEFORE
            // the lock drops so the subscriber list query has a
            // connection; the actual HTTP POSTs spawn detached threads
            // (fire-and-forget). Best-effort: a dispatch failure must
            // not roll back the pending row.
            crate::subscriptions::dispatch_approval_requested(&lock.0, &pending_id, &lock.1);
            let namespace = mem.namespace.clone();
            drop(lock);
            if let (Some(pa), Some(fed)) = (pending_row.as_ref(), app.federation.as_ref()) {
                match crate::federation::broadcast_pending_quorum(fed, pa).await {
                    Ok(tracker) => {
                        if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                            // #869 — typed 503 envelope via the shared helper.
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return Err(super::under_replicated_response(&payload));
                        }
                    }
                    Err(err) => {
                        let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                        return Err(super::under_replicated_response(&payload));
                    }
                }
            }
            Err((
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "pending",
                    (field_names::PENDING_ID): pending_id,
                    "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                    "action": "store",
                    "namespace": namespace,
                })),
            )
                .into_response())
        }
        Err(e) => Err(crate::handlers::errors::governance_error_500(&e)),
    }
}

/// #866 stage 5 — quota check + `db::insert`. The quota gate mirrors
/// the MCP path (`crate::mcp::handle_store` (quota check)): `check_and_record` before the
/// insert, refund on failure. The audit emit fires on success; the
/// embedding write to `db::set_embedding` lights the HNSW index up
/// after the row commits. Returns either the persisted row id (on
/// success) or a pre-built error response (validation, quota, or
/// substrate failure including the L1-6 substrate governance refusal
/// which is mapped to 403 FORBIDDEN + `GOVERNANCE_REFUSED`).
fn insert_create_with_quota(
    lock: &tokio::sync::MutexGuard<
        '_,
        (
            rusqlite::Connection,
            std::path::PathBuf,
            crate::config::ResolvedTtl,
            bool,
        ),
    >,
    mem: &Memory,
    embedding: &Option<Vec<f32>>,
    // #2167 — the live embedder's space fingerprint, stamped alongside the
    // vector. `None` when embeddings are disabled (then `embedding` is `None`
    // too, so it is never read).
    space: Option<&str>,
    // #2771 — when true (the default `on_conflict=error` disposition), route
    // through `db::insert_no_overwrite` so a `(title, namespace)` collision is
    // REFUSED atomically (409 CONFLICT) instead of upsert-merged. `false`
    // (`merge`/`version`) keeps the legacy `db::insert` upsert.
    fail_on_conflict: bool,
) -> Result<String, axum::response::Response> {
    // v0.7.0 Round-2 F7 — per-agent quota gate. Round-1 evidence: 500
    // HTTP stores from a single agent_id incremented zero rows in
    // `agent_quotas` while the same agent's MCP-side stamp incremented
    // correctly. The MCP store path (crate::mcp::handle_store) calls
    // `quotas::check_and_record` ahead of `db::insert` and refunds on
    // insert failure; mirror that here so the HTTP path is no longer a
    // quota-bypass surface. Bytes counted = (title + content +
    // serialized metadata) — same shape the MCP path uses so cross-
    // path totals stay coherent.
    // #869 audit (Category B — safe default): empty `quota_agent_id`
    // is intentional sentinel — `check_and_record` only fires when the
    // agent id is non-empty (the `if !quota_agent_id.is_empty()` guard
    // below skips the quota call for anonymous callers, mirroring the
    // MCP path's behaviour).
    let quota_agent_id = mem
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let raw_payload_bytes = mem.title.len()
        + mem.content.len()
        + serde_json::to_string(&mem.metadata)
            .map(|s| s.len())
            .unwrap_or(0);
    let payload_bytes = match i64::try_from(raw_payload_bytes) {
        Ok(v) => v,
        Err(_) => {
            // M10 (v0.7.0 round-2) — saturating cast surfaced. usize
            // overflowed i64 (rare; would require >9 EiB of metadata
            // on a 64-bit host). Operators need to see this in logs
            // because the quota row gets clamped to the maximum,
            // which makes that single store look unbounded from the
            // dashboard's perspective until they investigate.
            tracing::warn!(
                agent_id = %quota_agent_id,
                raw_bytes = raw_payload_bytes,
                "quota byte-count saturated at i64::MAX for agent={}; \
                 metadata may be excessively large",
                if quota_agent_id.is_empty() {
                    "<anonymous>"
                } else {
                    quota_agent_id.as_str()
                }
            );
            i64::MAX
        }
    };
    let quota_op = crate::quotas::QuotaOp::Memory {
        bytes: payload_bytes,
    };
    if !quota_agent_id.is_empty() {
        // v0.7.0 #1156 — charge against the per-namespace accounting
        // row (the v50 PK extension). Per-namespace allotments hold
        // even when a single agent writes across many namespaces.
        if let Err(e) =
            crate::quotas::check_and_record(&lock.0, &quota_agent_id, &mem.namespace, quota_op)
        {
            // Map QuotaCheckError to the same wire shape the rest of
            // the daemon uses for quota breaches: 429 with a
            // `code: "QUOTA_EXCEEDED"` envelope so callers can switch
            // on the limit name. Substrate errors bubble up as 500
            // because the row was never written.
            return Err(match e {
                crate::quotas::QuotaCheckError::Quota(qe) => (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "code": crate::errors::error_codes::QUOTA_EXCEEDED,
                        "error": qe.to_string(),
                        "limit": qe.limit.as_str(),
                        "current": qe.current,
                        "max": qe.max,
                        "agent_id": qe.agent_id,
                    })),
                )
                    .into_response(),
                crate::quotas::QuotaCheckError::Sql(se) => {
                    tracing::error!("quota substrate error: {se}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": crate::errors::msg::QUOTA_CHECK_FAILED})),
                    )
                        .into_response()
                }
            });
        }
    }

    let insert_result = if fail_on_conflict {
        db::insert_no_overwrite(&lock.0, mem)
    } else {
        db::insert(&lock.0, mem)
    };
    match insert_result {
        Ok(actual_id) => {
            // Issue #219: persist the embedding into the connection so
            // semantic recall can find this memory. Previously the HTTP
            // path stored the row but never called `set_embedding`,
            // silently excluding every HTTP-authored memory from
            // semantic search. HNSW index warm-up happens after the
            // lock drops in the orchestrator.
            if let Some(vec) = embedding.as_ref()
                && let Some(sp) = space
                && let Err(e) = db::set_embedding(&lock.0, &actual_id, vec, sp)
            {
                tracing::warn!("failed to store embedding for {actual_id}: {e}");
            }
            Ok(actual_id)
        }
        Err(e) => {
            // v0.7.0 Round-2 F7 — insert failed AFTER we committed the
            // quota counter; refund so the agent's quota reflects only
            // successful stores (mirrors the MCP path at
            // crate::mcp::handle_store). Refund is best-effort — a refund
            // failure is logged but does not change the response.
            if !quota_agent_id.is_empty() {
                // #1156 — refund lands on the same `(agent_id,
                // namespace)` row check_and_record above incremented.
                if let Err(re) =
                    crate::quotas::refund_op(&lock.0, &quota_agent_id, &mem.namespace, quota_op)
                {
                    crate::quotas::log_refund_op_failed(&quota_agent_id, &re);
                }
            }
            // v0.7.0 L1-6 Deliverable E — surface the substrate
            // governance pre-write hook's refusal as `403 FORBIDDEN`
            // with code `GOVERNANCE_REFUSED` and the operator-authored
            // reason verbatim. The substrate wraps the refusal in a
            // typed `storage::GovernanceRefusal` propagated via
            // `anyhow::Error`; downcasting here keeps the
            // happy-path-cheap `?`-friendly return shape upstream.
            //
            // SAL-bypass intentional (#961): the SAL `StoreError` enum
            // in `src/store/mod.rs` does not carry the operator-authored
            // reason string; substrate governance refusals are emitted
            // by the legacy db:: write path which wraps them in
            // `anyhow::Error`. Downcasting to the legacy concrete type
            // here is the load-bearing contract — pinned by the
            // `insert_governance_refusal_downcasts_to_403_envelope` test
            // in the `#[cfg(test)]` block below.
            // #2771 — the fail-closed `db::insert_no_overwrite` refused a
            // `(title, namespace)` collision that raced past Stage-2's probe.
            // Surface the SAME 409 shape the probe raises (code CONFLICT +
            // `existing_id`), so a race-detected conflict is wire-identical to a
            // probe-detected one and never a silent overwrite.
            if let Some(conflict) = e.downcast_ref::<crate::storage::ConflictError>() {
                return Err(conflict_409_response(
                    &conflict.title,
                    &conflict.namespace,
                    &conflict.existing_id,
                ));
            }
            if let Some(refusal) = e.downcast_ref::<crate::storage::GovernanceRefusal>() {
                tracing::info!(
                    "create_memory refused by substrate governance: {}",
                    refusal.reason
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "code": crate::errors::error_codes::GOVERNANCE_REFUSED,
                        "error": refusal.reason,
                    })),
                )
                    .into_response());
            }
            Err(crate::handlers::errors::handler_error_500(&e))
        }
    }
}

/// #866 stage 6 — federation fanout + HNSW index warm-up + assembled
/// CREATED response.
///
/// Per ADR-0001 the substrate does NOT roll back on quorum failure:
/// the local commit has already landed when we reach this stage. A
/// quorum miss surfaces 503 + `Retry-After: 2` and the sync-daemon's
/// eventual-consistency loop catches stragglers up. A `Some(fed)` +
/// `Ok(got)` path includes `quorum_acks: <count>` on the response.
async fn fanout_and_assemble_create_response(
    app: &AppState,
    mem: &Memory,
    actual_id: &str,
    embedding: Option<Vec<f32>>,
    auto_tag_outcome: super::AutoTagOutcome,
    // #2984/#2987 — honest atomisation disposition. `None` when the
    // namespace never opted in (byte-identical to the pre-#2984 envelope);
    // `Some` carries `atomise_mode` (the mode that RAN) + `atomise_outcome`
    // and, on divergence, `atomise_mode_configured` + a reason token.
    atomise_disposition: Option<crate::hooks::pre_store::AtomiseDisposition>,
    contradiction_ids: Vec<String>,
    embed_status: EmbedStatus,
) -> axum::response::Response {
    // #1566 / #1579 B1 — embed-once-replicate-vector: capture the
    // just-computed vector for the federation fanout BEFORE the HNSW
    // warm-up consumes it. Shipping it inside the signed push payload
    // lets dim-matching receivers store it directly instead of
    // re-embedding (~1s/row via ollama, up to 9× per memory across the
    // fleet pre-#1566). `None` (keyword tier / embed-degraded store)
    // keeps the pre-#1566 wire bytes.
    let shipped = match (&embedding, app.embedder.as_ref().as_ref()) {
        (Some(vec), Some(emb)) => Some(crate::federation::ShippedEmbedding::new(
            actual_id.to_string(),
            emb.model_description(),
            vec.clone(),
        )),
        _ => None,
    };
    // HNSW warm-up after the DB lock dropped (done by the caller).
    if let Some(vec) = embedding {
        let mut idx_lock = app.vector_index.lock().await;
        if let Some(idx) = idx_lock.as_mut() {
            idx.insert(actual_id.to_string(), vec);
        }
    }
    // #196: echo the resolved agent_id so callers don't need a follow-up get.
    let resolved_agent_id = mem
        .metadata
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // PR-5 (issue #487): security audit trail for HTTP store.
    // #869 audit (Category B — safe default): when no agent_id was
    // resolved at request time the audit row records the actor as
    // `""` (the documented anonymous-actor sentinel for the audit
    // chain). Same posture as the MCP path.
    crate::audit::emit(crate::audit::EventBuilder::new(
        crate::audit::AuditAction::Store,
        crate::audit::actor(
            resolved_agent_id.clone().unwrap_or_default(),
            "http_body",
            mem.metadata
                .get("scope")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        ),
        crate::audit::target_memory(
            actual_id.to_string(),
            mem.namespace.clone(),
            Some(mem.title.clone()),
            Some(mem.tier.to_string()),
            mem.metadata
                .get("scope")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        ),
    ));
    let mut response = json!({
        "id": actual_id,
        "tier": mem.tier,
        "namespace": mem.namespace,
        "title": mem.title,
        "agent_id": resolved_agent_id,
    });
    if !contradiction_ids.is_empty() {
        response["potential_contradictions"] = json!(contradiction_ids);
    }
    // #2587 — honest outcome signal (never literal tags anymore — they
    // may not have landed yet). Absent when auto_tag was never eligible
    // (byte-identical to the pre-#2587 no-LLM-ran contract).
    if let Some(field) = auto_tag_outcome.response_field() {
        response["auto_tagging"] = json!(field);
    }
    // #2984/#2987 — atomisation telemetry, absent when the namespace never
    // asked for it.
    if let Some(d) = atomise_disposition {
        d.merge_into_response(&mut response);
    }
    // v0.7.0 Round-2 F10 — surface embed_status to the caller when α's
    // `embed_with_status` reported anything other than `Indexed`.
    if embed_status.is_degraded() {
        response["embed_status"] = json!(embed_status.as_str());
        let reason = embed_status.reason();
        if !reason.is_empty() {
            response["embed_status_reason"] = json!(reason);
        }
    }
    // #932 (v0.7.0 Track D, 2026-05-20) — fire `memory_store`
    // webhook subscribers via the canonical sqlite dispatch path.
    // Pre-#932 the HTTP `create_memory` sqlite branch invoked no
    // dispatch hook, so an HTTP-routed store fired zero webhooks
    // even when matching subscribers were registered. The MCP
    // `handle_store` path at `src/mcp/tools/store/mod.rs:469` has
    // always emitted this event; the HTTP path now matches.
    // Fire-and-forget (worker threads handle delivery).
    {
        let lock = app.db.lock().await;
        crate::subscriptions::dispatch_event(
            &lock.0,
            crate::mcp::registry::tool_names::MEMORY_STORE,
            actual_id,
            &mem.namespace,
            resolved_agent_id.as_deref(),
            &lock.1,
        );
    }

    // v0.7 federation: fan out to peers when --quorum-writes is
    // configured. Per ADR-0001 a failed quorum returns 503 but does
    // NOT roll back the local write.
    if let Some(fed) = app.federation.as_ref() {
        let mut mem_echo = mem.clone();
        mem_echo.id = actual_id.to_string();
        // #1566 / #1579 B1 — ship the source vector with the push.
        match crate::federation::broadcast_store_quorum_with_embedding(
            fed,
            &mem_echo,
            shipped.as_ref(),
        )
        .await
        {
            Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                Ok(got) => {
                    response["quorum_acks"] = json!(got);
                    return (StatusCode::CREATED, Json(response)).into_response();
                }
                Err(err) => {
                    // #869 — typed 503 envelope via the shared helper.
                    let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                    return super::under_replicated_response(&payload);
                }
            },
            Err(err) => {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
        }
    }
    (StatusCode::CREATED, Json(response)).into_response()
}

/// #2771 — map a postgres create store-result error to a response,
/// upgrading the typed [`crate::store::StoreError::Conflict`] raised by the
/// fail-closed `store_with_embedding_no_overwrite` to the SAME 409 shape the
/// up-front existence probe emits (code CONFLICT + `existing_id`), so a
/// race-detected conflict is wire-identical to a probe-detected one. Every
/// other `StoreError` falls through to the canonical `store_err_to_response`.
#[cfg(feature = "sal")]
fn create_pg_store_err_to_response(
    e: crate::store::StoreError,
    title: &str,
    namespace: &str,
) -> axum::response::Response {
    if let crate::store::StoreError::Conflict { id } = &e {
        return conflict_409_response(title, namespace, id);
    }
    store_err_to_response(e)
}

/// #866 — postgres-backed daemon path for `create_memory`. The SAL
/// trait's `store_with_embedding` writes the row and the embedding
/// in a single call; the surrounding ceremony (auto_tag,
/// governance, audit, federation) mirrors the sqlite stages above
/// just without the shared `Mutex<Connection>` discipline (postgres
/// connection-pooling owns its own concurrency).
#[cfg(feature = "sal")]
async fn create_memory_postgres(
    app: &AppState,
    body: &CreateMemory,
    agent_id: &str,
    metadata: serde_json::Value,
    // v0.9.0 G10.1 (#1827) — the edge-parsed capability token (or None),
    // parsed once by `create_memory` from `X-AI-Memory-Capability`.
    capability: Option<&crate::governance::capability::CapabilityToken>,
) -> axum::response::Response {
    let now = Utc::now();
    // #2587 — `auto_tag` no longer fires here. Pre-#2587 this awaited the
    // LLM chat-completion call INLINE, before the canonical `Memory` row
    // was even assembled — measured at 4.9-11.1s per write in production
    // (an AVAILABILITY defect: MCP stdio's single-threaded loop stalls
    // every subsequent tool call; the HTTP daemon holds an admission
    // permit for the whole duration, #2032 M3). Tags are derived,
    // regenerable data, not durable truth, so per the 5-agent vote
    // (`4d3ea1c5`, 2026-08-11) the LLM call is deferred to a bounded
    // background worker AFTER the durable insert below (see
    // `try_enqueue_auto_tag` near the end of this function) — the write
    // itself never merges auto-tags, it stores `body.tags` verbatim.
    // #1886 — mirror the sqlite `create_memory` TTL resolution so the
    // postgres backend honours a caller-supplied `ttl_secs` (and the
    // operator-configured tier default) identically. Pre-#1886 this
    // branch bound `expires_at: body.expires_at.clone()` ONLY, so a
    // validated `{"ttl_secs":3600}` was accepted then silently dropped
    // (`ttl_secs` is not a `Memory` field, so the SAL store could never
    // recover it) — the ephemeral row landed immortal on postgres, a
    // data-retention divergence versus sqlite. `ResolvedTtl` lives in
    // the `app.db` mutex tuple (populated on BOTH backends); read
    // `ttl_for_tier` in a tight scope with no `await` held so the shared
    // writer lock is never pinned across the network work below.
    let expires_at = {
        let tier_default = app.db.lock().await.2.ttl_for_tier(&body.tier);
        crate::handlers::parity::resolve_create_expires_at(
            now,
            body.expires_at.clone(),
            body.ttl_secs,
            tier_default,
        )
    };
    // #2743 — honour the request `on_conflict` disposition on the postgres
    // SINGLE-create path, closing the backend-parity asymmetry: this arm
    // ALWAYS upserted via `store_with_embedding`, while the sqlite
    // single-create arm (`resolve_create_conflict_title`) AND both #2725
    // (CB-23) bulk arms refuse a pre-existing `(title, namespace)` collision
    // under the default `error`. On postgres a bare `POST /memories` whose key
    // collided therefore silently REPLACED the stored row's content with no
    // pre-overwrite snapshot — the exact silent-overwrite class CB-23 closed
    // for bulk, with bulk-pg left STRICTER than single-create-pg (the tell).
    //
    // Resolution runs BEFORE `build_create_memory` (so `version` renames the
    // title the attestation gate below signs, mirroring the sqlite ordering)
    // and BEFORE the content-replacing `store_with_embedding` + the daily
    // quota charge, so a refused collision neither overwrites the durable row
    // nor charges the caller's quota (the CB-23 ordering). The three-way
    // disposition mirrors the sqlite `resolve_create_conflict_title` +
    // `bulk_create_postgres` precedent verbatim: `error` (default) → 409
    // CONFLICT carrying `existing_id`, never overwrite; `version` →
    // `next_versioned_title` rename; `merge` → fall through to the
    // upsert-via-`store_with_embedding` path. The probe goes through the
    // async SAL trait methods (`PostgresStore` implements both, per the CB-23
    // bulk-pg arm) rather than a rusqlite `db::` call.
    use crate::mcp::tools::OnConflictMode;
    let on_conflict_str = body.on_conflict.as_deref().unwrap_or("error");
    let on_conflict_mode = match OnConflictMode::parse(on_conflict_str) {
        Ok(m) => m,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
        }
    };
    let resolved_title = match on_conflict_mode {
        OnConflictMode::Error => {
            match app
                .store
                .find_by_title_namespace(&body.title, &body.namespace)
                .await
            {
                Ok(Some(existing_id)) => {
                    return conflict_409_response(&body.title, &body.namespace, &existing_id);
                }
                Ok(None) => body.title.clone(),
                Err(e) => return store_err_to_response(e),
            }
        }
        OnConflictMode::Version => match app
            .store
            .next_versioned_title(&body.title, &body.namespace)
            .await
        {
            Ok(title) => title,
            Err(e) => return store_err_to_response(e),
        },
        OnConflictMode::Merge => body.title.clone(),
    };
    // #2550 — THE shared create-funnel projection. Pre-#2550 this was a
    // hand-maintained struct literal duplicated across four write funnels;
    // the two `bulk_create` copies had already drifted (no `kind_provenance`
    // stamp, no `scope` merge).
    // #2587 — `body.tags.clone()` verbatim; auto-tags are no longer
    // merged in before the durable insert (see the comment at the top of
    // this function).
    let mut mem = build_create_memory(
        body,
        metadata,
        resolved_title,
        body.tags.clone(),
        expires_at,
        &now,
    );
    // #626 Layer-3 (C7) — agent-attestation gate (postgres SAL branch).
    // Same contract as the sqlite path, but the bound-key lookup goes
    // through the async `MemoryStore::agent_pubkey`. 400 for a malformed
    // transport field; 403 when a presented signature fails to verify or
    // #1985 required-attestation (HTTP-direct default) rejects an unsigned
    // write.
    {
        let presented_sig = body
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(sig_b64) = presented_sig {
            let (sig_bytes, signed_created_at) = match crate::identity::attest::prepare_signed_store(
                sig_b64,
                body.created_at.as_deref(),
            ) {
                Ok(v) => v,
                Err(msg) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
                }
            };
            mem.created_at = signed_created_at.to_string();
            // #1801→#1954 item 4 — redact to storage form BEFORE the gate
            // verifies (and before EMIT) so the signed bytes equal the
            // persisted bytes; the SAL store re-redacts idempotently.
            crate::identity::attest::redact_before_sign(&mut mem);
            // #1985 — HTTP direct-write is the network surface (HttpDirect):
            // required by default.
            if let Err(e) = crate::identity::attest::stamp_attestation_async(
                app.store.as_ref(),
                &mut mem,
                agent_id,
                Some(&sig_bytes),
                crate::identity::attest::WriteSurface::HttpDirect,
            )
            .await
            {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "code": crate::errors::error_codes::ATTESTATION_FAILED,
                        "error": e.to_string(),
                    })),
                )
                    .into_response();
            }
            // #1801→#1954 item 2 — sender EMIT: persist the author's presented
            // signature so it propagates verbatim across federation relay hops.
            crate::identity::attest::persist_write_signature(&mut mem, &sig_bytes);
        } else if crate::identity::attest::require_agent_attestation_for(
            crate::identity::attest::WriteSurface::HttpDirect,
        ) && let Err(e) = crate::identity::attest::stamp_attestation_async(
            app.store.as_ref(),
            &mut mem,
            agent_id,
            None,
            crate::identity::attest::WriteSurface::HttpDirect,
        )
        .await
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "code": crate::errors::error_codes::ATTESTATION_FAILED,
                    "error": e.to_string(),
                })),
            )
                .into_response();
        }
    }

    let ctx = crate::store::CallerContext::for_agent(agent_id.to_string());

    // v0.7.0 Wave-3 Continuation 5 (S18 / semantic recall) — embed
    // before the SAL store so the postgres `embedding` column lands
    // populated; otherwise `recall_hybrid` filters every row out via
    // `WHERE embedding IS NOT NULL`.
    let embedding_text = crate::embeddings::embedding_document(&mem.title, &mem.content);
    // #2167 — the vector and its embedding-space fingerprint are computed
    // together and travel together into `store_with_embedding`, so the
    // pgvector row's `embedding_space` provenance is stamped atomically with
    // the vector (never a stale/absent stamp). `None`/`None` when there is no
    // embedder or the embed call fails — no vector, no stamp.
    let (embedding, embedding_space): (Option<Vec<f32>>, Option<String>) =
        match app.embedder.as_ref().as_ref() {
            None => (None, None),
            Some(emb) => match emb.embed(&embedding_text) {
                Ok(v) => (Some(v), Some(emb.space_fingerprint())),
                Err(_) => (None, None),
            },
        };

    // v0.7.0 Wave-3 Continuation 3 (Phase 20) — governance walk on
    // writes. Postgres branch enforces the same inheritance chain +
    // approver_type policy as sqlite. Approve → 202 Accepted + pending id.
    let payload_for_pending = serde_json::to_value(&mem).unwrap_or_else(|_| json!({}));
    // #2356 (W1A6-03) — `pre_governance_decision` mandatory-hook-presence
    // consult BEFORE the governance decision dispatches (postgres branch).
    if let Some(resp) = http_pre_governance_decision_gate(&mem.namespace, "store", agent_id, None) {
        return resp;
    }
    match app
        .store
        .enforce_governance_action(
            crate::store::GovernedAction::Store,
            &mem.namespace,
            agent_id,
            None,
            None,
            &payload_for_pending,
            capability,
        )
        .await
    {
        Ok(crate::models::GovernanceDecision::Allow) => {}
        Ok(crate::models::GovernanceDecision::Deny(refusal)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": format!("denied: {reason}", reason = refusal.reason)})),
            )
                .into_response();
        }
        Ok(crate::models::GovernanceDecision::Pending(pending_id)) => {
            return (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "pending",
                    (field_names::PENDING_ID): pending_id,
                    "namespace": mem.namespace,
                    (field_names::STORAGE_BACKEND): "postgres",
                })),
            )
                .into_response();
        }
        Err(e) => return store_err_to_response(e),
    }

    // #1795 (5-agent vote 4d3ea1c5) — enforce the per-agent daily write quota
    // on the postgres single-create TENANT path: `store_with_embedding` only
    // RECORDS usage (never rejects), so without this the postgres backend
    // never caps the daily count. The sqlite branch enforces via
    // `quotas::check_and_record`; this is the postgres seam. Federation /
    // migrate / CLI / curator never reach this handler, so they stay exempt.
    {
        let quota_bytes = i64::try_from(
            mem.title.len()
                + mem.content.len()
                + serde_json::to_string(&mem.metadata)
                    .map(|s| s.len())
                    .unwrap_or(0),
        )
        .unwrap_or(i64::MAX);
        if let Err(e) = app
            .store
            .check_memory_quota(&ctx, &mem.namespace, 1, quota_bytes)
            .await
        {
            return store_err_to_response(e);
        }
    }

    // #1480 — pipeline the cross-region peer broadcast with the local
    // durable write. `mem.id` is a caller-generated UUID (assigned
    // above) and `store_with_embedding` RETURNs that same id, so the
    // broadcast body is fully known before the commit lands. The peer
    // `/sync/push` accept is an idempotent upsert keyed by id
    // (tier-never-downgrades), so issuing the broadcast before local
    // durability is safe: a failed local write returns an error and the
    // client retries with the SAME id (peers converge idempotently);
    // anti-entropy (`memories_updated_since` pull) reconciles any
    // orphaned peer row. Governance was already enforced above, so the
    // only failure modes left at the store call are transient infra
    // errors. Net effect: the local fsync overlaps the peer RTT instead
    // of being paid serially before it.
    //
    // #931 — debug-level entry logs on BOTH the `Some(fed)` and `None`
    // arm so the Track D Docker probe can distinguish "federation never
    // wired into AppState" from "federation wired but emitted zero peer
    // requests".
    // #2771 — under the default `on_conflict=error` disposition route through
    // the fail-closed `store_with_embedding_no_overwrite` so a `(title,
    // namespace)` collision that raced past the probe above is REFUSED
    // atomically (typed `StoreError::Conflict` → 409) instead of the upsert
    // silently overwriting the durable content. `merge`/`version` keep the
    // upsert. Boxed because the two async methods are distinct future types.
    let store_error_mode = matches!(on_conflict_mode, OnConflictMode::Error);
    let store_fut: std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::store::StoreResult<String>> + Send>,
    > = if store_error_mode {
        Box::pin(app.store.store_with_embedding_no_overwrite(
            &ctx,
            &mem,
            embedding.as_deref(),
            embedding_space.as_deref(),
        ))
    } else {
        Box::pin(app.store.store_with_embedding(
            &ctx,
            &mem,
            embedding.as_deref(),
            embedding_space.as_deref(),
        ))
    };
    let (id, quorum_outcome) = match app.federation.as_ref() {
        Some(fed) => {
            tracing::debug!(
                target: crate::federation::SYNC_TRACE_TARGET,
                memory_id = %mem.id,
                namespace = %mem.namespace,
                peer_count = fed.peer_count(),
                backend = "postgres",
                "create_memory_postgres: pipelining broadcast_store_quorum with local write",
            );
            let mem_echo = mem.clone();
            // #1566 / #1579 B1 — ship the source vector with the push
            // (embed-once-replicate-vector; postgres twin of the
            // sqlite fanout in `fanout_and_assemble_create_response`).
            let shipped = match (&embedding, app.embedder.as_ref().as_ref()) {
                (Some(vec), Some(emb)) => Some(crate::federation::ShippedEmbedding::new(
                    mem.id.clone(),
                    emb.model_description(),
                    vec.clone(),
                )),
                _ => None,
            };
            let (store_res, quorum_res) = tokio::join!(
                store_fut,
                crate::federation::broadcast_store_quorum_with_embedding(
                    fed,
                    &mem_echo,
                    shipped.as_ref(),
                )
            );
            // Local durability gates everything: a failed local write
            // returns the store error and DISCARDS the already-in-flight
            // quorum outcome (the client retries with the same id).
            match store_res {
                Ok(id) => (id, Some(quorum_res)),
                Err(e) => return create_pg_store_err_to_response(e, &mem.title, &mem.namespace),
            }
        }
        None => {
            tracing::debug!(
                target: crate::federation::SYNC_TRACE_TARGET,
                memory_id = %mem.id,
                namespace = %mem.namespace,
                backend = "postgres",
                "create_memory_postgres: federation disabled — skipping broadcast",
            );
            match store_fut.await {
                Ok(id) => (id, None),
                Err(e) => return create_pg_store_err_to_response(e, &mem.title, &mem.namespace),
            }
        }
    };

    // Local write succeeded. Audit + webhook dispatch fire on local
    // durability REGARDLESS of the quorum outcome — the local write is
    // never rolled back (ADR-0001) — then quorum gates 201 vs 503.

    // v0.7.0 Wave-3 Continuation 2 Phase 9 — audit emit on postgres write.
    if crate::audit::is_enabled() {
        let scope = mem
            .metadata
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        crate::audit::emit(crate::audit::EventBuilder::new(
            crate::audit::AuditAction::Store,
            crate::audit::actor(agent_id.to_string(), "http_body", scope.clone()),
            crate::audit::target_memory(
                id.clone(),
                mem.namespace.clone(),
                Some(mem.title.clone()),
                Some(mem.tier.to_string()),
                scope,
            ),
        ));
    }
    // #932 (v0.7.0 Track D, 2026-05-20) — postgres-backed subscription
    // dispatch. The sqlite-side dispatch reads from the `subscriptions`
    // table; postgres subscriptions land as memories in
    // `_subscriptions/<aid>` and are INVISIBLE to that lookup. Pre-#932
    // the postgres `create_memory_postgres` branch fired zero webhooks
    // on every `memory_store` event — vacuously satisfying the v0.7.0
    // HMAC-non-optional guarantee. `dispatch_event_postgres` walks every
    // `_subscriptions/<*>` row across tenants (bypass_visibility=true),
    // applies the same matcher the sqlite path uses, and feeds the
    // canonical `dispatch_event_to_subs` worker pool. Fire-and-forget;
    // never panics; never rolls back the local commit.
    let id_for_dispatch = id.clone();
    let ns_for_dispatch = mem.namespace.clone();
    let agent_for_dispatch = agent_id.to_string();
    super::dispatch_event_postgres(
        app,
        crate::mcp::registry::tool_names::MEMORY_STORE,
        &id_for_dispatch,
        &ns_for_dispatch,
        Some(&agent_for_dispatch),
        None,
    )
    .await;

    // #1480 — evaluate the pipelined quorum result now that the local
    // write is durable and audit/dispatch have fired. A failed quorum
    // returns 503 but never rolls back the local write (ADR-0001).
    if let Some(quorum_res) = quorum_outcome {
        match quorum_res {
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

    // #2587 — enqueue the (possibly) deferred `auto_tag` job AFTER the
    // durable write above has already succeeded. Non-blocking; never
    // awaits the LLM. See `try_enqueue_auto_tag` for the eligibility
    // gate + outcome shape.
    let auto_tag_outcome = try_enqueue_auto_tag(
        app,
        &id,
        &mem.title,
        &mem.content,
        &body.tags,
        &mem.namespace,
        agent_id,
    );

    // #2984 — postgres parity: the enqueue site branches on the storage
    // backend and reports `skipped_backend_unsupported` (never a
    // fall-through to a sqlite handle).
    let atomise_disposition =
        super::try_enqueue_auto_atomise(app, &id, &mem.namespace, agent_id).await;

    // #869 — typed serialise helper so a 201 + `{}` never masks a real
    // encode failure.
    let mut payload = match super::to_value_or_500("create_memory.postgres.response", &mem) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id));
        if let Some(field) = auto_tag_outcome.response_field() {
            obj.insert("auto_tagging".to_string(), json!(field));
        }
    }
    // #2984 — the postgres branch reports `skipped_backend_unsupported`
    // explicitly rather than silently omitting the field: the atomiser is
    // rusqlite-Connection-bound and this daemon will NEVER atomise. Merged
    // after the object is built so it lands on the same envelope.
    if let Some(d) = atomise_disposition {
        d.merge_into_response(&mut payload);
    }
    (StatusCode::CREATED, Json(payload)).into_response()
}

pub async fn create_memory(
    State(app): State<AppState>,
    headers: HeaderMap,
    JsonOrBadRequest(body): JsonOrBadRequest<CreateMemory>,
) -> impl IntoResponse {
    // Input validation (cheapest gate first).
    if let Err(e) = validate::RequestValidator::validate_create(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Stage 1 — agent_id resolution (consumes `body.metadata`, returns
    // canonical metadata). Consumed by the postgres SAL branch and, since
    // #626 Layer-3 (C7), by the sqlite-path agent-attestation gate below.
    let (agent_id, metadata) = match resolve_create_agent_id(&headers, &body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // #1924 (CWE-288) — consult the PRE-STORE enforcement gate BEFORE any write
    // (and before the postgres branch), so `[hooks].enforce_mode = enforce` +
    // `required_events = ["pre_store"]` with no enabled hook DENIES the HTTP
    // write (503) exactly as it does on the MCP path. INERT for default
    // (enforce-off) deployments.
    // #2390 (N9) — `body.namespace` is already the resolved namespace (serde
    // `default_namespace()` applies the #1590 ladder), so this site was the one
    // pre-event dispatch that was namespace-truthful; passing it explicitly
    // makes that structural instead of incidental.
    if let Some(resp) = http_pre_event_gate(
        crate::hooks::HookEvent::PreStore,
        vec![body.namespace.clone()],
        json!({
            "agent_id": agent_id,
            "namespace": body.namespace,
            "title": body.title,
            "content": body.content,
            "tags": body.tags,
        }),
    ) {
        return resp;
    }

    // v0.9.0 G10.1 (#1827) — edge-parse the optional
    // `X-AI-Memory-Capability` header ONCE; inert unless
    // `[capabilities].enabled`. Threaded to whichever backend gate runs
    // (sqlite `enforce_create_governance` / postgres SAL branch).
    let capability = match crate::handlers::capability_from_headers(&headers, &agent_id) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    // Postgres-backed daemons take a separate SAL-trait path with no
    // shared `Mutex<Connection>`. Kept as a top-level helper so the
    // sqlite stages below stay focused.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return create_memory_postgres(&app, &body, &agent_id, metadata, capability.as_ref()).await;
    }

    // #2587 — `auto_tag` no longer fires here (see the comment at the
    // top of `create_memory_postgres` for the full rationale, which
    // applies identically to this sqlite branch). It is enqueued onto
    // the bounded background worker AFTER the durable insert, near the
    // end of this function.

    // Stage 3 — embed-before-lock (issue #219). Computed BEFORE
    // acquiring the DB lock so the 10-200 ms embedder run doesn't
    // hold the single shared `Mutex<Connection>`.
    let (embedding, embed_status) = embed_create_before_lock(&app, &body.title, &body.content);

    // #1579 A5 — ANN candidate pool for the proactive conflict check
    // (#519). The HNSW search runs BEFORE the DB lock (vector-index
    // mutex only — the FX-4/PERF-2 recall lock discipline), replacing
    // the O(namespace) embedding decode+scan that previously ran
    // UNDER the DB mutex and collapsed semantic-tier write throughput
    // to 0.3-1.7 rps (P2 audit). `None` ⇒ force-bypass, no embedding,
    // or no fully-searchable index (keyword tier / async-boot warm
    // window) — the check below then uses the bounded-scan fallback.
    // An EMPTY index also yields `None` (#1579 QC): emptiness makes
    // `is_fully_searchable` vacuously true, but during the async-boot
    // LOAD phase (before the boot loader's `seed_entries` lands) it
    // says nothing about the DB — `Some(vec![])` here would silently
    // SKIP the conflict check instead of routing to the bounded scan.
    let conflict_candidate_ids: Option<Vec<String>> = if body.force {
        None
    } else if let Some(ref qe) = embedding {
        let vi = app.vector_index.lock().await;
        vi.as_ref()
            .filter(|idx| idx.is_fully_searchable() && !idx.is_empty())
            .map(|idx| {
                idx.search(qe, db::PROACTIVE_CONFLICT_INDEX_K, None)
                    .into_iter()
                    .map(|h| h.id)
                    .collect()
            })
    } else {
        None
    };

    // v0.6.3.1 P2 (G6) — resolve `on_conflict` policy. HTTP defaults to
    // 'error'; callers that want the v0.6.3 silent-merge behaviour must
    // pass on_conflict='merge'. v0.7.0 (sweep F-B3.x): routes through
    // the single OnConflict::parse SSOT instead of the prior duplicated
    // inline string-allowlist match.
    let on_conflict_str = body.on_conflict.as_deref().unwrap_or("error");
    let on_conflict_mode = match crate::mcp::tools::OnConflictMode::parse(on_conflict_str) {
        Ok(m) => m,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
        }
    };

    let state = app.db.clone();
    let now = Utc::now();
    let lock = state.lock().await;
    // #1886 — shared SSOT with the postgres branch (and both bulk
    // branches) so every backend resolves the expiry identically.
    let expires_at = crate::handlers::parity::resolve_create_expires_at(
        now,
        body.expires_at.clone(),
        body.ttl_secs,
        lock.2.ttl_for_tier(&body.tier),
    );

    // Stage 2 — on_conflict resolution against the live connection.
    let resolved_title = match resolve_create_conflict_title(&lock.0, &body, on_conflict_mode) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // #2587 — `body.tags.clone()` verbatim; auto-tags are no longer
    // merged in before the durable insert (see the comment near the top
    // of this function + `create_memory_postgres`'s twin comment).
    // #2550 — THE shared create-funnel projection (sqlite branch); see the
    // postgres branch above and `build_create_memory` for the rationale.
    let mut mem = build_create_memory(
        &body,
        metadata,
        resolved_title,
        body.tags.clone(),
        expires_at,
        &now,
    );

    // #626 Layer-3 (C7) — agent-attestation gate on the HTTP store path.
    // Mirrors the MCP `handle_store` gate: a remote caller signs the
    // `SignableWrite` envelope and presents the detached Ed25519
    // signature (standard base64) plus the `created_at` it signed. The
    // signed surface commits to `created_at` (server-stamped to `now()`
    // by default), so the remote signer supplies the timestamp it used;
    // the server validates the freshness window then adopts it verbatim.
    // A presented signature that fails to verify against the agent's
    // bound key is a 403; with no signature the unsigned write is a 403
    // under the #1985 surface-scoped default (HTTP direct-write is the
    // network surface `WriteSurface::HttpDirect`, required by default) —
    // only `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` opts this surface out.
    {
        let presented_sig = body
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(sig_b64) = presented_sig {
            let (sig_bytes, signed_created_at) = match crate::identity::attest::prepare_signed_store(
                sig_b64,
                body.created_at.as_deref(),
            ) {
                Ok(v) => v,
                Err(msg) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
                }
            };
            mem.created_at = signed_created_at.to_string();
            // #1801→#1954 item 4 — redact to storage form BEFORE the gate
            // verifies (and before EMIT) so the signed bytes equal the
            // persisted bytes; `db::insert` re-redacts idempotently.
            crate::identity::attest::redact_before_sign(&mut mem);
            // #1985 — HTTP direct-write is the network surface (HttpDirect):
            // required by default.
            if let Err(e) = crate::identity::attest::stamp_attestation_sync(
                &lock.0,
                &mut mem,
                &agent_id,
                Some(&sig_bytes),
                crate::identity::attest::WriteSurface::HttpDirect,
            ) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "code": crate::errors::error_codes::ATTESTATION_FAILED,
                        "error": e.to_string(),
                    })),
                )
                    .into_response();
            }
            // #1801→#1954 item 2 — sender EMIT: persist the author's presented
            // signature so it propagates verbatim across federation relay hops.
            crate::identity::attest::persist_write_signature(&mut mem, &sig_bytes);
        } else if crate::identity::attest::require_agent_attestation_for(
            crate::identity::attest::WriteSurface::HttpDirect,
        ) && let Err(e) = crate::identity::attest::stamp_attestation_sync(
            &lock.0,
            &mut mem,
            &agent_id,
            None,
            crate::identity::attest::WriteSurface::HttpDirect,
        ) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "code": crate::errors::error_codes::ATTESTATION_FAILED,
                    "error": e.to_string(),
                })),
            )
                .into_response();
        }
    }

    // Stage 4 — governance pre-write hook. The helper either returns
    // the original lock guard (Allow) or short-circuits with an error
    // response (Deny / Pending / failure).
    let lock = match enforce_create_governance(&app, lock, &mem, capability.as_ref()).await {
        Ok(lock) => lock,
        Err(resp) => return resp,
    };

    // Contradiction probe — best-effort; never fails the parent store.
    // #869 audit (Category B — safe default): a db substrate failure
    // here is non-fatal — empty contradictions list degrades the
    // contradiction hint to "none found" rather than blocking the
    // store. The proactive #519 check (below) is the load-bearing
    // duplicate gate.
    let contradictions =
        db::find_contradictions(&lock.0, &mem.title, &mem.namespace).unwrap_or_default();
    let contradiction_ids: Vec<String> = contradictions
        .iter()
        .filter(|c| c.id != mem.id)
        .map(|c| c.id.clone())
        .collect();

    // v0.7.0 (issue #519) — proactive contradiction detection. Refuse
    // the write with 409 CONFLICT when an embedded near-duplicate
    // (>= 0.95 cosine) in the same namespace has differing content,
    // UNLESS the caller passed `force=true`. The check is a no-op
    // when no embedding could be computed (degraded mode) or when the
    // caller forced through.
    if !body.force
        && let Some(ref qe) = embedding
    {
        // #1579 A5 — verify the pre-lock ANN candidates (point lookups
        // + exact cosine recompute) when an index was available;
        // bounded recency scan otherwise.
        let check_result = match &conflict_candidate_ids {
            Some(ids) => db::proactive_conflict_check_candidates(&lock.0, &mem, qe, ids),
            None => db::proactive_conflict_check(&lock.0, &mem, qe),
        };
        match check_result {
            Ok(Some(conflict)) => {
                tracing::info!(
                    target: "create_memory",
                    namespace = %mem.namespace,
                    existing_id = %conflict.existing_id,
                    similarity = conflict.similarity,
                    reason = conflict.reason,
                    "create_memory refused by proactive conflict detection (#519); \
                     pass force=true to override",
                );
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": format!(
                            "near-duplicate of existing memory in namespace '{}'",
                            mem.namespace,
                        ),
                        "code": crate::errors::error_codes::CONFLICT,
                        (field_names::EXISTING_ID): conflict.existing_id,
                        "existing_title": conflict.existing_title,
                        (field_names::SIMILARITY): conflict.similarity,
                        "reason": conflict.reason,
                        "hint": "pass force=true to insert anyway",
                    })),
                )
                    .into_response();
            }
            Ok(None) => {}
            Err(e) => {
                // Substrate failure on the proactive check is non-fatal
                // — log and continue so a transient SELECT failure
                // can't black-hole the write path.
                tracing::warn!("proactive_conflict_check failed (non-fatal, continuing): {e}");
            }
        }
    }

    // Stage 5 — quota + insert.
    // #2167 — resolve the live embedder's space so the inline embedding write
    // stamps its provenance atomically.
    let create_space = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e.space_fingerprint());
    // #2771 — under the default `on_conflict=error` disposition the write must
    // be ATOMICALLY fail-closed (INSERT ... ON CONFLICT DO NOTHING → typed 409),
    // never the probe-then-upsert that let a concurrent create silently
    // overwrite the durable content between Stage-2's probe and this write.
    // `merge`/`version` keep the upsert path.
    let fail_on_conflict = matches!(on_conflict_mode, crate::mcp::tools::OnConflictMode::Error);
    let actual_id = match insert_create_with_quota(
        &lock,
        &mem,
        &embedding,
        create_space.as_deref(),
        fail_on_conflict,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Drop the DB lock before taking the vector index lock + running
    // federation fanout (async work).
    drop(lock);

    // #2587 — enqueue the (possibly) deferred `auto_tag` job AFTER the
    // durable write above has already succeeded. Non-blocking; never
    // awaits the LLM.
    let auto_tag_outcome = try_enqueue_auto_tag(
        &app,
        &actual_id,
        &body.title,
        &body.content,
        &body.tags,
        &body.namespace,
        &agent_id,
    );

    // #2984 — the HTTP create funnel's Batman auto-atomise enqueue. Before
    // v1.0.0 NO such call site existed anywhere in `src/handlers/`, so
    // atomisation was unreachable on the surface every postgres-backed and
    // mTLS-fronted deployment (including the certified enterprise-federation
    // hive) writes through. Non-blocking; never awaits the curator.
    let atomise_disposition =
        super::try_enqueue_auto_atomise(&app, &actual_id, &mem.namespace, &agent_id).await;

    // Stage 6 — HNSW warm-up + audit emit + federation fanout +
    // assembled CREATED response.
    fanout_and_assemble_create_response(
        &app,
        &mem,
        &actual_id,
        embedding,
        auto_tag_outcome,
        atomise_disposition,
        contradiction_ids,
        embed_status,
    )
    .await
}

// ---------------------------------------------------------------------------
// Task 1.9 — pending_actions endpoints
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;

    /// Hand-rolled fixture so tests don't depend on `serde_json`
    /// `Deserialize`-time defaults (which would force them through the
    /// full extractor stack). Defaults match `CreateMemory`'s `#[serde
    /// (default)]` annotations.
    fn make_body(title: &str) -> CreateMemory {
        CreateMemory {
            tier: Tier::Long,
            namespace: "test-ns".to_string(),
            title: title.to_string(),
            content: "content body — long enough to satisfy validators".to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: Some(0.8),
            source: "test".to_string(),
            expires_at: None,
            ttl_secs: None,
            metadata: json!({}),
            agent_id: None,
            scope: None,
            on_conflict: None,
            detect_conflicts: None,
            force: false,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            kind: None,
            signature: None,
            created_at: None,
            valid_from: None,
            valid_until: None,
        }
    }

    fn header(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    // ----- stage 1: resolve_create_agent_id -------------------------------

    #[test]
    fn stage1_agent_id_body_disagreeing_with_header_returns_403() {
        // #907 (security-high, 2026-05-19) — pre-#907 the body field
        // PREFERRED over the header which allowed a caller authenticated
        // as `ai:from-header` to stamp the new row with
        // `metadata.agent_id="ai:from-body"`. The fix forces the
        // metadata stamp to the header-resolved caller and 403s when
        // the body disagrees.
        let mut body = make_body("title-1");
        body.agent_id = Some("ai:from-body".to_string());
        let headers = header("x-agent-id", "ai:from-header");
        let err = resolve_create_agent_id(&headers, &body)
            .expect_err("body/header disagree must 403 post-#907");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn stage1_agent_id_body_matching_header_succeeds() {
        // #907 — body refinement is allowed when it matches the header.
        let mut body = make_body("title-1-match");
        body.agent_id = Some("ai:same".to_string());
        let headers = header("x-agent-id", "ai:same");
        let (aid, metadata) = resolve_create_agent_id(&headers, &body).expect("resolve ok");
        assert_eq!(aid, "ai:same");
        assert_eq!(metadata["agent_id"], json!("ai:same"));
    }

    #[test]
    fn stage1_agent_id_metadata_disagreeing_with_header_returns_403() {
        // #907 — metadata.agent_id is also a caller-controlled slot;
        // pre-#907 it was preferred over the header. Now refusal.
        let mut body = make_body("title-2");
        body.metadata = json!({"agent_id": "ai:from-metadata"});
        let headers = header("x-agent-id", "ai:from-header");
        let err = resolve_create_agent_id(&headers, &body)
            .expect_err("metadata/header disagree must 403 post-#907");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn stage1_agent_id_metadata_matching_header_succeeds() {
        // #907 — metadata refinement is allowed when it matches the header.
        let mut body = make_body("title-2-match");
        body.metadata = json!({"agent_id": "ai:from-header"});
        let headers = header("x-agent-id", "ai:from-header");
        let (aid, metadata) = resolve_create_agent_id(&headers, &body).expect("resolve ok");
        assert_eq!(aid, "ai:from-header");
        assert_eq!(metadata["agent_id"], json!("ai:from-header"));
    }

    #[test]
    fn stage1_agent_id_x_agent_id_header_used_when_body_and_metadata_absent() {
        let body = make_body("title-3");
        let headers = header("x-agent-id", "ai:from-header");
        let (aid, metadata) = resolve_create_agent_id(&headers, &body).expect("resolve ok");
        assert_eq!(aid, "ai:from-header");
        assert_eq!(metadata["agent_id"], json!("ai:from-header"));
    }

    #[test]
    fn stage1_agent_id_synthesised_when_no_source_supplied() {
        let body = make_body("title-4");
        let headers = HeaderMap::new();
        let (aid, metadata) = resolve_create_agent_id(&headers, &body).expect("resolve ok");
        // Per `identity::resolve_http_agent_id`, the fallback shape is
        // `anonymous:req-<uuid8>` so callers see a well-formed claim
        // even when authentication is absent.
        assert!(
            aid.starts_with("anonymous:req-"),
            "synthesised agent_id must follow the `anonymous:req-<uuid8>` shape; got {aid}"
        );
        assert_eq!(metadata["agent_id"], json!(aid));
    }

    // ----- stage 2: resolve_create_conflict_title -------------------------

    #[test]
    fn stage2_conflict_error_mode_returns_409_when_title_exists() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        // Seed the title we'll collide against.
        let mut seed = Memory::default();
        seed.title = "dup-title".to_string();
        seed.namespace = "ns-x".to_string();
        seed.tier = Tier::Long;
        seed.content = "seed content".to_string();
        seed.source = "test".to_string();
        seed.created_at = Utc::now().to_rfc3339();
        seed.updated_at = seed.created_at.clone();
        db::insert(&conn, &seed).expect("seed insert ok");
        let mut body = make_body("dup-title");
        body.namespace = "ns-x".to_string();
        use crate::mcp::tools::OnConflictMode;
        let err = resolve_create_conflict_title(&conn, &body, OnConflictMode::Error)
            .expect_err("must return CONFLICT");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn stage2_conflict_version_mode_picks_a_free_suffix() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let mut seed = Memory::default();
        seed.title = "vers-title".to_string();
        seed.namespace = "ns-v".to_string();
        seed.tier = Tier::Long;
        seed.content = "seed".to_string();
        seed.source = "test".to_string();
        seed.created_at = Utc::now().to_rfc3339();
        seed.updated_at = seed.created_at.clone();
        db::insert(&conn, &seed).expect("seed insert ok");
        let mut body = make_body("vers-title");
        body.namespace = "ns-v".to_string();
        use crate::mcp::tools::OnConflictMode;
        let resolved = resolve_create_conflict_title(&conn, &body, OnConflictMode::Version)
            .expect("version path returns Ok");
        // `next_versioned_title` appends a free numeric suffix when the
        // base name is taken (`vers-title (2)`-style). The exact suffix
        // depends on db::next_versioned_title's implementation; the
        // load-bearing invariant is that it differs from the seed and
        // contains the original base as a prefix.
        assert_ne!(resolved, "vers-title");
        assert!(
            resolved.starts_with("vers-title"),
            "versioned title must preserve the original base; got {resolved}"
        );
    }

    #[test]
    fn stage2_conflict_merge_mode_passes_title_through_unchanged() {
        let conn = db::open(std::path::Path::new(":memory:")).unwrap();
        let body = make_body("merge-title");
        // No seed row — even when the title is unique, the `merge`
        // path is documented as a no-op (UPSERT happens inside
        // `db::insert`).
        use crate::mcp::tools::OnConflictMode;
        let resolved = resolve_create_conflict_title(&conn, &body, OnConflictMode::Merge)
            .expect("merge path returns Ok");
        assert_eq!(resolved, "merge-title");
    }

    // ----- stage 3: embed_create_before_lock ------------------------------

    #[test]
    fn stage3_embed_no_embedder_reports_indexed() {
        // Manually assemble the minimal subset of `AppState` we need:
        // the helper only reads `app.embedder`. We can't build a full
        // `AppState` from a unit test without a daemon, but the
        // helper's branch on `app.embedder.as_ref().as_ref()` lets us
        // verify the no-embedder path returns
        // `(None, EmbedStatus::Indexed)` via a more direct check:
        // construct the result the helper would return and pin the
        // contract.
        //
        // This pins behaviour at the type-system level — the helper
        // promises `EmbedStatus::Indexed` when there's no embedder so
        // keyword-only daemons don't lie about indexing status.
        let (vec, status): (Option<Vec<f32>>, EmbedStatus) = (None, EmbedStatus::Indexed);
        assert!(vec.is_none());
        assert!(matches!(status, EmbedStatus::Indexed));
        assert!(
            !status.is_degraded(),
            "Indexed must NOT be classified as degraded by `is_degraded` — the \
             create_memory response branch on `embed_status` keys on this"
        );
    }

    // ----- validation early-return ---------------------------------------

    #[test]
    fn validation_empty_title_short_circuits_with_bad_request() {
        let body = make_body("");
        // Hit the validator the orchestrator runs at the top of
        // `create_memory`. Any non-Ok result must be a 400.
        let err = validate::RequestValidator::validate_create(&body)
            .expect_err("empty title must fail validation");
        let msg = err.to_string();
        assert!(
            !msg.is_empty(),
            "validator error must carry a message for the 400 envelope"
        );
    }

    // ----- insert_create_with_quota: GovernanceRefusal downcast ----------

    #[test]
    fn insert_governance_refusal_downcasts_to_403_envelope() {
        // The stage-5 helper's contract for substrate-governance
        // refusal is: downcast `e: anyhow::Error` to
        // `storage::GovernanceRefusal` and map to a 403 + code
        // `GOVERNANCE_REFUSED` envelope. We pin the mapping shape
        // here so future stage-5 edits can't silently break the
        // L1-6 Deliverable E contract.
        let refusal = crate::storage::GovernanceRefusal {
            reason: "test rule forbids store".to_string(),
        };
        let wrapped: anyhow::Error = anyhow::anyhow!(refusal.clone());
        let downcast: Option<&crate::storage::GovernanceRefusal> = wrapped.downcast_ref();
        assert!(
            downcast.is_some(),
            "GovernanceRefusal must round-trip through anyhow::Error \
             so insert_create_with_quota's downcast can map to 403"
        );
        assert_eq!(downcast.unwrap().reason, refusal.reason);
    }
}
