// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1111 — 14 missing HTTP routes for the MCP-only tools the
//! SR-4 three-surface-parity audit flagged.
//!
//! Pre-#1111 these handlers existed only on the MCP wire; an HTTP
//! caller asking for `POST /api/v1/memory_smart_load` (or any of the
//! 13 siblings) got 404. Each route here is a thin wrapper around the
//! existing `crate::mcp::handle_<name>` substrate primitive so the JSON
//! envelope is byte-equal across the MCP and HTTP surfaces.
//!
//! ## Routes added
//!
//! | Path                                         | Handler                                    |
//! |----------------------------------------------|--------------------------------------------|
//! | `POST /api/v1/memory_smart_load`             | [`handle_smart_load_http`]                 |
//! | `POST /api/v1/memory_reflect`                | [`handle_reflect_http`]                    |
//! | `POST /api/v1/memory_recall_observations`    | [`handle_recall_observations_http`]        |
//! | `POST /api/v1/memory_reflection_origin`      | [`handle_reflection_origin_http`]          |
//! | `POST /api/v1/memory_dependents_of_invalidated` | [`handle_dependents_of_invalidated_http`] |
//! | `POST /api/v1/memory_export_reflection`      | [`handle_export_reflection_http`]          |
//! | `POST /api/v1/memory_atomise`                | [`handle_atomise_http`]                    |
//! | `POST /api/v1/memory_calibrate_confidence`   | [`handle_calibrate_confidence_http`]       |
//! | `POST /api/v1/memory_verify`                 | [`handle_verify_http`]                     |
//! | `POST /api/v1/memory_replay`                 | [`handle_replay_http`]                     |
//! | `POST /api/v1/memory_subscription_replay`    | [`handle_subscription_replay_http`]        |
//! | `POST /api/v1/memory_subscription_dlq_list`  | [`handle_subscription_dlq_list_http`]      |
//! | `POST /api/v1/memory_rule_list`              | [`handle_rule_list_http`]                  |
//! | `POST /api/v1/memory_check_agent_action`     | [`handle_check_agent_action_http`]         |
//!
//! ## Wire contract
//!
//! Every handler accepts the same JSON body shape the MCP `arguments`
//! bag accepts and returns the same JSON envelope the MCP `tools/call`
//! response wraps. Errors surface as `400 Bad Request` with
//! `{"error": "<substrate string>"}`.
//!
//! Caller identity is extracted via the existing
//! `crate::handlers::parity::resolve_caller_agent_id` chain so the same
//! `X-Agent-Id` header semantics apply across the existing 60 routes
//! and these 14 new ones.

#[cfg(feature = "sal")]
use crate::models::field_names;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;

/// Build the `Bad Request` envelope used by every #1111 handler when
/// the substrate primitive returns `Err(String)`. Kept as a free
/// function so the 14 handlers below stay 3-5 line wrappers.
fn err_response(e: String) -> axum::response::Response {
    tracing::warn!(error = %e, "HTTP route #1111 substrate refusal");
    (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response()
}

/// #1552 — shared federation fanout for the reflect write path, called by both
/// the postgres SAL branch and the sqlite branch of [`handle_reflect_http`].
///
/// The reflect path previously returned WITHOUT broadcasting, so on a federated
/// hive a reflection (and its `reflects_on` edges) reached cross-region peers
/// only via async catch-up (`/sync/since`) instead of the synchronous W-quorum
/// every regular `POST /memories` write gets. This helper broadcasts the new
/// reflection memory to the quorum (gating the response exactly like a normal
/// write) and then best-effort broadcasts each outbound `reflects_on` edge —
/// peers reconcile a missed edge from the local row via catch-up, and the edge
/// wire row is unsigned here (matching the `links.rs` create-path precedent
/// where receivers land it unsigned until `export_links` reconciliation pulls
/// the signed row).
///
/// Returns `Some(response)` when the memory quorum is NOT met (a typed 503 the
/// caller must return verbatim), or `None` on success / when federation is
/// disabled (the single-node no-op path) so the caller proceeds to its 200
/// envelope.
async fn reflect_fanout(
    fed: Option<&crate::federation::FederationConfig>,
    mem: &crate::models::Memory,
    links: &[crate::models::MemoryLink],
) -> Option<axum::response::Response> {
    let fed = fed?;
    match crate::federation::broadcast_store_quorum(fed, mem).await {
        Ok(tracker) => {
            if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return Some(super::under_replicated_response(&payload));
            }
        }
        Err(e) => {
            tracing::warn!("reflect memory fanout error (local committed): {e:?}");
        }
    }
    for link in links.iter().filter(|l| {
        l.relation == crate::models::MemoryLinkRelation::ReflectsOn && l.source_id == mem.id
    }) {
        if let Err(e) = crate::federation::broadcast_link_quorum(fed, link).await {
            tracing::warn!("reflect edge fanout error (local committed): {e:?}");
        }
    }
    None
}

/// `POST /api/v1/memory_smart_load` — substrate-routed family
/// load with intent-string keyword + embedder voting. Wraps
/// [`crate::mcp::handle_smart_load`]; embedder is pulled from
/// `AppState` so the HTTP surface picks up the same model the MCP
/// dispatch uses.
pub async fn handle_smart_load_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #2137 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the caller is resolved from `X-Agent-Id` for the forwarded load_family
    // read (smart_load wraps load_family). Pre-fix, a shared-transport-key
    // caller forging `X-Agent-Id: <victim>` read the victim's private
    // family-tagged content. Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "smart_load",
    ) {
        return resp;
    }
    // #1555 — resolve the caller from headers so the forwarded load_family read
    // applies the scope=private visibility filter (the always-on intent loader
    // must not surface another tenant's private family-tagged rows). Reuses the
    // shared `resolve_caller_agent_id` helper (non-sal-safe, anonymous-fallback
    // handling lives inside it, not duplicated here); the empty principal owns
    // no private row.
    let caller =
        crate::handlers::parity::resolve_caller_agent_id(None, &headers, None).unwrap_or_default();
    // #3064 lane L-PGP family F2 — postgres SAL dispatch. The family PICK is
    // pure Rust (`mcp::tools::load_family::pick_family_for_intent`) and the
    // family-tagged READ rides the SAME `app.store.list` path
    // `POST /api/v1/memory_load_family` already uses on postgres, so the
    // handler never reaches `app.db.lock()` (the empty scratch sqlite) on that
    // backend. Pre-fix the route was fail-closed 501 for exactly that reason.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return smart_load_http_via_store(&app, &headers, &body).await;
    }
    let lock = app.db.lock().await;
    let embedder = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e as &dyn crate::embeddings::Embed);
    let result = crate::mcp::handle_smart_load(&lock.0, &body, embedder, Some(caller.as_str()));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 lane L-PGP family F2 — the postgres arm of
/// [`handle_smart_load_http`].
///
/// Mirrors the sqlite path step for step so the wire envelope is identical:
///
/// 1. `intent` is required and is TRIMMED before routing (same validation
///    order and same message as `mcp::handle_smart_load`, so a missing
///    `intent` is a 400 on both backends).
/// 2. `namespace`, when present, is validated with the SAME
///    `validate::validate_namespace` the sqlite `handle_load_family` applies,
///    so a malformed namespace refuses rather than silently listing the whole
///    corpus.
/// 3. `k` defaults to 20 and clamps to `1..=100` — the `handle_load_family`
///    contract, restated here because the postgres read does not pass through
///    that function.
/// 4. the family pick and the envelope build are the SHARED pure helpers, so
///    the routing decision and the JSON shape cannot drift between backends.
///
/// Never touches `app.db`: the read is `MemoryStore::list` through
/// [`crate::handlers::power_consolidation::load_family_rows_via_store`].
#[cfg(feature = "sal")]
async fn smart_load_http_via_store(
    app: &AppState,
    headers: &HeaderMap,
    body: &Value,
) -> axum::response::Response {
    let Some(intent_raw) = body["intent"].as_str() else {
        return err_response("intent is required".to_string());
    };
    let intent = intent_raw.trim();
    let namespace = body
        .get(crate::mcp::param_names::NAMESPACE)
        .and_then(Value::as_str);
    if let Some(ns) = namespace
        && let Err(e) = crate::validate::validate_namespace(ns)
    {
        return err_response(e.to_string());
    }
    let k_raw = body
        .get(crate::mcp::param_names::K)
        .and_then(Value::as_u64)
        .unwrap_or(20);
    let k = usize::try_from(k_raw).unwrap_or(usize::MAX).clamp(1, 100);

    let embedder = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e as &dyn crate::embeddings::Embed);
    let (family, score, source) = crate::mcp::pick_family_for_intent(intent, embedder);
    let family_name = family.name();
    tracing::info!(
        target: crate::mcp::load_family::SMART_LOAD_LOG_TARGET,
        chosen_family = family_name,
        score = score,
        source = source,
        intent_len = intent.len(),
        "smart_load routed intent to family (postgres)"
    );

    let rows = match crate::handlers::power_consolidation::load_family_rows_via_store(
        app,
        headers,
        family_name,
        namespace,
        k,
    )
    .await
    {
        Ok(rows) => rows,
        Err(resp) => return resp,
    };
    let inner = json!({
        "family": family_name,
        "namespace": namespace,
        "k": k,
        "count": rows.len(),
        "memories": rows,
    });
    let envelope = crate::mcp::smart_load_envelope(family_name, score, source, intent, &inner);
    (StatusCode::OK, Json(envelope)).into_response()
}

/// `POST /api/v1/memory_reflect` — substrate reflection over a
/// memory set. Wraps [`crate::mcp::handle_reflect`]. The embedder,
/// vector index, and daemon active keypair flow in from `AppState` so
/// every `reflects_on` edge written here is signed when the operator
/// has a daemon keypair on disk (matching the MCP behaviour).
pub async fn handle_reflect_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #2140 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate. Under
    // `enforce`, a shared-transport-key caller forging `X-Agent-Id: <victim>`
    // is refused before the reflection is written or the victim's private
    // source memories are read. Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "reflect",
    ) {
        return resp;
    }
    // #2140 — reflect trusted the BODY `agent_id` with the request headers
    // IGNORED (both the postgres `parse_reflect_input` branch and the sqlite
    // `handle_reflect` branch read `body.agent_id`), so a caller could read a
    // victim's private sources AND forge a reflection AUTHORED as the victim
    // via the body alone — a vector the header-keyed gate above does not close
    // (its anonymous carve-out admits the no-header caller). Bind the
    // effective principal HEADER-AUTHORITATIVELY (the body `agent_id` is only
    // a refinement that MUST match), then OVERRIDE the body `agent_id` with
    // the bound caller so no downstream branch can honor a divergent body id.
    //
    // #2156 — the binding is gated on the SAME enrollment condition the
    // `enforce_idor_identity` gate above short-circuits on
    // (`enforce_for_request`'s `enrolled.is_empty()` check): with ZERO
    // per-agent keys enrolled the binding is INERT and the body passes
    // through unchanged, preserving the shipped #1317 header-optional
    // contract (body-only `agent_id`, no `X-Agent-Id` header, zero-config
    // deployment) and the PR's inert-out-of-the-box guarantee. Under an
    // enrolled posture the binding stays ACTIVE and still refuses the #2140
    // no-header + body-`agent_id:<victim>` forge vector.
    let mut body = body;
    if !app.enrolled_agent_keys.is_empty() {
        let body_agent = body.get("agent_id").and_then(Value::as_str);
        let caller =
            match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None) {
                Ok(id) => id,
                Err(e) => return err_response(e),
            };
        if let Some(obj) = body.as_object_mut() {
            obj.insert("agent_id".to_string(), Value::String(caller));
        }
    }
    // #1924 (CWE-288) — consult the PRE-REFLECT enforcement gate before the
    // reflection write (HTTP parity with the MCP gate). INERT by default.
    // #2390 (N9) — a reflection lands in `namespace` when supplied, else in the
    // namespace of the FIRST source memory (`storage::reflect` step 4); source
    // namespaces fold in too because the write emits `reflects_on` edges onto
    // those rows. Pre-fix the raw caller body was the payload, so a caller-
    // supplied `"namespace"` decided the scope and an omitted one skipped every
    // scoped `pre_reflect` hook.
    let reflect_source_ids: Vec<String> = body
        .get(crate::mcp::param_names::SOURCE_IDS)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut reflect_namespaces: Vec<String> = body
        .get(crate::mcp::param_names::NAMESPACE)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| vec![s.to_owned()])
        .unwrap_or_default();
    for ns in
        crate::handlers::create::resolve_pre_event_namespaces(&app, &headers, &reflect_source_ids)
            .await
    {
        if !reflect_namespaces.contains(&ns) {
            reflect_namespaces.push(ns);
        }
    }
    if let Some(resp) = crate::handlers::create::http_pre_event_gate(
        crate::hooks::HookEvent::PreReflect,
        reflect_namespaces,
        body.clone(),
    ) {
        return resp;
    }
    // Postgres SAL path (#1549): route the recursive-learning reflect
    // through `MemoryStore::reflect` (the inherent native-sqlx port —
    // governance cap, depth-exceeded signed_events audit, atomic memory
    // + signed reflects_on links). Mirrors the sqlite MCP path's
    // argument contract + `REFLECTION_DEPTH_EXCEEDED` / `CALLER_DEPTH_MISMATCH`
    // wire slugs + `{id, reflection_depth, reflects_on, namespace}` shape.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let (mut input, caller_depth) = match crate::mcp::parse_reflect_input(&body, None) {
            Ok(parsed) => parsed,
            Err(e) => return err_response(e),
        };
        // #2857 — resolve the caller identity HEADER-AUTHORITATIVELY when an
        // `X-Agent-Id` header is present, matching how GET /memories/{id},
        // recall, and store resolve it (`resolve_http_agent_id` / the
        // `resolve_caller_agent_id` parity helper). `parse_reflect_input`
        // reads the caller id from the request BODY only, so on the postgres
        // SAL branch — where source existence is checked through the SAL
        // `MemoryStore::get` scope=private visibility gate keyed on the
        // `CallerContext` principal — a source written and GET-able under
        // `X-Agent-Id: <owner>` (no body `agent_id`) was invisible to reflect,
        // producing a false `400 "source memory not found"` for a memory that
        // demonstrably exists (the store-vs-lookup owner-scoping mismatch).
        // The body `agent_id` stays a REFINEMENT that MUST match the header,
        // so the #2140 forge protection is unchanged. When NO header is present
        // the shipped #1317 body-only zero-config contract stands (the
        // body-derived `input.agent_id` is kept verbatim) — resolving
        // header-authoritatively there would 403 a legitimate body-only caller.
        if headers.contains_key(crate::HEADER_AGENT_ID) {
            let body_agent = body.get("agent_id").and_then(Value::as_str);
            match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None) {
                Ok(id) => input.agent_id = id,
                Err(e) => return err_response(e),
            }
        }
        let caller = crate::store::CallerContext::for_agent(&input.agent_id);
        // #1325 caller-asserted depth pre-check (parity with the sqlite
        // MCP path): compare the asserted `depth` to the substrate-
        // computed `max(source depths) + 1` before the write.
        if let Some(caller_d) = caller_depth {
            let mut max_src_depth: i32 = 0;
            for sid in &input.source_ids {
                if let Ok(m) = app.store.get(&caller, sid).await {
                    max_src_depth = max_src_depth.max(m.reflection_depth);
                }
            }
            let computed = i64::from(max_src_depth.max(0).saturating_add(1));
            if caller_d != computed {
                return err_response(format!(
                    "CALLER_DEPTH_MISMATCH: caller asserted depth={caller_d} but \
                     substrate computed reflection_depth={computed} from sources \
                     (max(source_depths)+1). Omit the `depth` field to defer to the \
                     substrate, or pass the matching value."
                ));
            }
        }
        let active_keypair = app.active_keypair.as_ref().as_ref();
        let outcome = match app.store.reflect(&caller, &input, active_keypair).await {
            Ok(outcome) => outcome,
            Err(e) => return err_response(crate::mcp::map_reflect_error_to_wire_string(e)),
        };
        // #1552 — federation fanout parity (shared `reflect_fanout` helper,
        // covered by the sqlite-branch fanout test). Read the reflection memory
        // + its edges back through the trait, then broadcast.
        if app.federation.is_some() {
            if let Ok(mem) = app.store.get(&caller, &outcome.id).await {
                let links = app
                    .store
                    .get_links_for_anchor(&outcome.id)
                    .await
                    .unwrap_or_default();
                if let Some(resp) =
                    reflect_fanout(app.federation.as_ref().as_ref(), &mem, &links).await
                {
                    return resp;
                }
            }
        }
        return (
            StatusCode::OK,
            Json(json!({
                "id": outcome.id,
                (field_names::REFLECTION_DEPTH): outcome.reflection_depth,
                (crate::models::link::REL_REFLECTS_ON): outcome.reflects_on,
                "namespace": outcome.namespace,
            })),
        )
            .into_response();
    }
    let lock = app.db.lock().await;
    let db_path = lock.1.clone();
    let embedder = app
        .embedder
        .as_ref()
        .as_ref()
        .map(|e| e as &dyn crate::embeddings::Embed);
    let vec_lock = app.vector_index.lock().await;
    // v0.9 #1005 — deref through the boxed seam to the trait object.
    let vector_index = vec_lock.as_deref();
    let active_keypair = app.active_keypair.as_ref().as_ref();
    let result = crate::mcp::handle_reflect(
        &lock.0,
        &db_path,
        &body,
        embedder,
        vector_index,
        // HTTP callers have no MCP-stdio clientInfo; the substrate
        // primitive falls back to the `body.agent_id` / synthesised id.
        None,
        active_keypair,
    );
    drop(vec_lock);
    // #1552 — federation fanout parity for the sqlite reflect path. Capture
    // the reflection memory + its `reflects_on` edges WHILE the db lock is
    // held; the fanout itself must run AFTER the lock drops because peers POST
    // back to our `/sync/push` and we would deadlock on the shared `Db` Mutex
    // otherwise (same ordering the consolidate sqlite branch documents).
    let fanout = match &result {
        Ok(v) => v.get("id").and_then(|x| x.as_str()).and_then(|id| {
            let mem = crate::db::get(&lock.0, id).ok().flatten();
            let links = crate::db::get_links(&lock.0, id).unwrap_or_default();
            mem.map(|m| (m, links))
        }),
        Err(_) => None,
    };
    drop(lock);
    if let Some((mem, links)) = fanout.as_ref() {
        if let Some(resp) = reflect_fanout(app.federation.as_ref().as_ref(), mem, links).await {
            return resp;
        }
    }
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_recall_observations` — Provenance Gap 3
/// recall-consumption observation read. Read-only over the
/// `recall_observations` table; no caller-ownership gate (already
/// scoped per-row by `agent_id`).
pub async fn handle_recall_observations_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Postgres SAL path (#1549): read the recall-consumption ledger
    // through `MemoryStore::list_recall_observations`. Mirrors the
    // sqlite MCP path's filter parsing + `{observations, count}` shape.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let recall_id = body
            .get("recall_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let consumed = body.get("consumed").and_then(Value::as_bool);
        let since = body
            .get("since")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let until = body
            .get("until")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let limit = body
            .get("limit")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .map_or(crate::mcp::RECALL_OBS_DEFAULT_LIMIT, |n| {
                n.min(crate::mcp::RECALL_OBS_MAX_LIMIT)
            });
        return match app
            .store
            .list_recall_observations(recall_id, consumed, since, until, limit)
            .await
        {
            Ok(rows) => {
                let count = rows.len();
                (
                    StatusCode::OK,
                    Json(json!({ (field_names::OBSERVATIONS): rows, "count": count })),
                )
                    .into_response()
            }
            Err(e) => err_response(e.to_string()),
        };
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_recall_observations(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_reflection_origin` — walk a reflection
/// memory backward along `reflects_on` edges to surface the original
/// observation set. Read-only.
pub async fn handle_reflection_origin_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Postgres SAL path (#1549): walk reflection origin metadata through
    // `MemoryStore::get_reflection_origin`. Mirrors the sqlite MCP path's
    // `memory_id` validation + response shape + "memory not found" 4xx.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let memory_id = match body["memory_id"].as_str() {
            Some(s) if !s.is_empty() => s,
            Some(_) => return err_response(crate::errors::msg::MEMORY_ID_EMPTY.to_string()),
            None => return err_response(crate::errors::msg::MEMORY_ID_REQUIRED.to_string()),
        };
        return match app.store.get_reflection_origin(memory_id).await {
            Ok(Some(record)) => (
                StatusCode::OK,
                Json(json!({
                    "memory_id": record.memory_id,
                    (field_names::PEER_ORIGIN): record.peer_origin,
                    (field_names::SIGNING_AGENT): record.signing_agent,
                    (field_names::ORIGINAL_DEPTH): record.original_depth,
                    (field_names::LOCAL_DEPTH_AT_ARRIVAL): record.local_depth_at_arrival,
                    (field_names::IS_REFLECTION): record.is_reflection,
                })),
            )
                .into_response(),
            Ok(None) => err_response(crate::errors::msg::memory_not_found(memory_id)),
            Err(e) => err_response(e.to_string()),
        };
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_reflection_origin(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_dependents_of_invalidated` — surface the
/// transitive closure of memories that derive from an invalidated row.
/// L2-3 / #668 substrate. Read-only.
pub async fn handle_dependents_of_invalidated_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #3064 batch B — postgres SAL dispatch. Direct list is
    // `MemoryStore::list_dependents_of_invalidated`; opt-in
    // `transitive` reuses `lineage_descendants` (sqlite
    // `db::transitive_suspects` is an alias of that).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return dependents_http_via_store(&app, &body).await;
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_dependents_of_invalidated(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 batch B — postgres arm of [`handle_dependents_of_invalidated_http`].
/// ERRORS-01: store faults go through [`super::store_err_to_response`].
#[cfg(feature = "sal")]
async fn dependents_http_via_store(app: &AppState, params: &Value) -> axum::response::Response {
    use crate::mcp::param_names;
    use crate::store::StoreError;

    let memory_id = match params.get(param_names::MEMORY_ID).and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        Some(_) => return err_response(crate::errors::msg::MEMORY_ID_EMPTY.to_string()),
        None => return err_response(crate::errors::msg::MEMORY_ID_REQUIRED.to_string()),
    };
    if let Err(e) = crate::validate::validate_id(&memory_id) {
        return err_response(e.to_string());
    }
    let dependents = match app.store.list_dependents_of_invalidated(&memory_id).await {
        Ok(v) => v,
        Err(e) => return super::store_err_to_response(e),
    };
    let rendered: Vec<Value> = dependents
        .iter()
        .map(|d| {
            json!({
                "id": d.id,
                "namespace": d.namespace,
            })
        })
        .collect();
    let mut out = json!({
        "memory_id": memory_id,
        "count": rendered.len(),
        (field_names::DEPENDENTS): rendered,
    });
    if params
        .get(param_names::TRANSITIVE)
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        match app
            .store
            .lineage_descendants(&memory_id, crate::db::LINEAGE_MAX_DEPTH)
            .await
        {
            Ok(suspects) => {
                let rendered_suspects: Vec<Value> = suspects
                    .iter()
                    .map(|n| {
                        json!({
                            "id": n.id,
                            "cid": n.cid,
                            "relation": n.relation,
                            "depth": n.depth,
                        })
                    })
                    .collect();
                if let Value::Object(map) = &mut out {
                    map.insert(
                        field_names::TRANSITIVE_COUNT.to_string(),
                        json!(rendered_suspects.len()),
                    );
                    map.insert(
                        field_names::TRANSITIVE_SUSPECTS.to_string(),
                        Value::Array(rendered_suspects),
                    );
                }
            }
            Err(StoreError::NotFound { .. }) => {
                if let Value::Object(map) = &mut out {
                    map.insert(field_names::TRANSITIVE_COUNT.to_string(), json!(0));
                    map.insert(field_names::TRANSITIVE_SUSPECTS.to_string(), json!([]));
                }
            }
            Err(e) => return super::store_err_to_response(e),
        }
    }
    Json(out).into_response()
}

/// `POST /api/v1/memory_export_reflection` — export a reflection
/// memory + its full reflects_on lineage as a structured JSON bundle.
/// Read-only; no caller-ownership gate (the lineage walk uses
/// substrate visibility filters).
pub async fn handle_export_reflection_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #3064 batch C — postgres SAL dispatch. `get` (admin-bypass, matching
    // sqlite `db::get` with no caller gate) + `list_outbound_reflects_on`
    // + the same CLI renderer the MCP handler uses.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return export_reflection_http_via_store(&app, &body).await;
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_export_reflection(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 batch C — postgres arm of [`handle_export_reflection_http`].
#[cfg(feature = "sal")]
async fn export_reflection_http_via_store(
    app: &AppState,
    params: &Value,
) -> axum::response::Response {
    use crate::cli::commands::export_reflections::{self, ExportFormat, ReflectsOnEdge};
    use crate::mcp::param_names;
    use crate::models::MemoryKind;
    use crate::store::{CallerContext, StoreError};

    let memory_id = match params.get(param_names::MEMORY_ID).and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        Some(_) => return err_response(crate::errors::msg::MEMORY_ID_EMPTY.to_string()),
        None => return err_response(crate::errors::msg::MEMORY_ID_REQUIRED.to_string()),
    };
    if let Err(e) = crate::validate::validate_id(&memory_id) {
        return err_response(e.to_string());
    }
    let format_str = match params.get(param_names::FORMAT) {
        None | Some(Value::Null) => "md",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                return err_response(
                    "format must be a string ('md', 'markdown' or 'json')".to_string(),
                );
            }
        },
    };
    let format = match format_str.to_lowercase().as_str() {
        "md" | "markdown" => ExportFormat::Markdown,
        "json" => ExportFormat::Json,
        other => {
            return err_response(crate::errors::msg::unsupported_export_format(other));
        }
    };
    // sqlite `db::get` is unfiltered; SAL `get` with `for_admin` is the
    // bypass_visibility twin so private reflections still export (parity).
    let ctx = CallerContext::for_admin("http:export-reflection");
    let mem = match app.store.get(&ctx, &memory_id).await {
        Ok(m) => m,
        Err(StoreError::NotFound { .. }) => {
            return err_response(crate::errors::msg::memory_not_found(&memory_id));
        }
        Err(e) => return super::store_err_to_response(e),
    };
    if !matches!(mem.memory_kind, MemoryKind::Reflection) {
        return err_response(format!("memory is not a reflection: {memory_id}"));
    }
    let edges = match app.store.list_outbound_reflects_on(&memory_id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|e| ReflectsOnEdge {
                target_id: e.target_id,
                attest_level: e.attest_level,
                created_at: e.created_at,
            })
            .collect::<Vec<_>>(),
        Err(e) => return super::store_err_to_response(e),
    };
    let attest_level = export_reflections::summarise_attest_level(&edges);
    let content = export_reflections::render_payload(&mem, &edges, attest_level, format);
    let ns_clean = mem.namespace.trim_matches('/');
    let ext = format.extension();
    let suggested = if ns_clean.is_empty() {
        format!("{}.{ext}", mem.id)
    } else {
        format!("{ns_clean}/{}.{ext}", mem.id)
    };
    Json(json!({
        "content": content,
        "suggested_filename": suggested,
    }))
    .into_response()
}

/// `POST /api/v1/memory_atomise` — WT-1-F atomiser. Decomposes a
/// long-form memory into atomic propositions. HTTP dispatch passes
/// `handler: None` so the substrate uses its default per-tier
/// behaviour (no live LLM curator). Operators who want the
/// LLM-curated atomisation path drive it through MCP where the daemon
/// owns the `AtomiseToolHandler`. The tier is pulled from
/// `AppState.tier_config` so HTTP and MCP agree on feature-tier
/// gating.
pub async fn handle_atomise_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #3064 lane L-PGP family F5 — postgres arm. This route is STORAGE-FREE
    // on the HTTP surface (see `atomise_http_via_store`), so the postgres
    // branch answers it without touching `app.db` at all.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return atomise_http_via_store(&app, &body);
    }
    let lock = app.db.lock().await;
    let tier = app.tier_config.tier;
    let result = crate::mcp::tools::handle_atomise(&lock.0, &body, None, tier, None);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 lane L-PGP family F5 — the postgres arm of [`handle_atomise_http`].
///
/// This route needs no SAL port because the HTTP surface has NEVER been able
/// to reach the atomisation engine: the engine lives on an
/// `AtomiseToolHandler` the daemon only owns on the MCP dispatch path, and
/// this handler's call site has always passed `handler: None`. Every HTTP
/// `memory_atomise` call therefore terminates in the tier-locked advisory
/// envelope, on EITHER backend, before any storage access — so the honest
/// answer on postgres is that same envelope, not a `501` implying the route
/// works on sqlite when it does not.
///
/// The safety is STRUCTURAL rather than a promise: `mcp::atomise_precheck` is
/// driven with `handler_present = false`, which by construction can only
/// return `TierLocked` or a validation `Err`. The `EngineRequired` arm is
/// therefore unreachable today AND fails CLOSED with the documented 501
/// envelope if a future change ever wires a real handler onto this surface —
/// it can never silently fall through to `app.db`, the empty scratch sqlite.
#[cfg(feature = "sal")]
fn atomise_http_via_store(app: &AppState, body: &Value) -> axum::response::Response {
    match crate::mcp::tools::atomise_precheck(body, app.tier_config.tier, false) {
        Ok(crate::mcp::tools::AtomisePrecheck::TierLocked(envelope)) => {
            (StatusCode::OK, Json(envelope)).into_response()
        }
        Ok(crate::mcp::tools::AtomisePrecheck::EngineRequired(_)) => {
            // Unreachable while this call site passes `handler_present = false`.
            // If it ever becomes reachable, the `rusqlite`-bound engine has NO
            // postgres implementation, so refuse loudly with the substrate's
            // own fail-closed envelope rather than running it against the
            // wrong database.
            tracing::error!(
                "atomise_http_via_store reached EngineRequired on postgres — the                  rusqlite-bound atomisation engine has no postgres implementation;                  refusing rather than dispatching against the scratch database"
            );
            crate::handlers::postgres_not_implemented(crate::handlers::routes::MEMORY_ATOMISE)
        }
        Err(e) => err_response(e),
    }
}

/// v1.0.0 #3507 — the resolved calibration principal for one HTTP request.
///
/// `principal` + `is_admin` are only read on the `sal` postgres arm (they
/// build the [`crate::store::CallerContext`] the SAL method gates on); the
/// sqlite arm consumes `audience` directly.
struct CalibrateHttpCaller {
    #[cfg_attr(not(feature = "sal"), allow(dead_code))]
    principal: String,
    #[cfg_attr(not(feature = "sal"), allow(dead_code))]
    is_admin: bool,
    audience: crate::confidence::calibrate::CalibrationAudience,
}

/// v1.0.0 #3507 — resolve WHOSE rows this request's calibration may
/// aggregate, or return the refusal response the handler short-circuits on.
///
/// The ladder, fail-closed at every rung:
///
/// 1. `X-Agent-Id` MUST be present and non-empty. Without it
///    `resolve_caller_agent_id` synthesises a per-request
///    `anonymous:req-<uuid8>` that owns no rows, so an unauthenticated
///    caller would get an aggregate over exactly the world-readable
///    namespaces — a smaller disclosure than the pre-#3507 global sweep but
///    still a cross-namespace one. Refuse instead.
/// 2. A malformed header is a `400` from the shared resolver, never the
///    `anonymous:invalid` sentinel.
/// 3. An ADMIN caller — admitted by
///    [`crate::handlers::admin_role::is_admin_caller_trusted`], which
///    requires BOTH the allow-list AND request authn (#1570) AND the #2093
///    per-agent-key attestation — keeps the GLOBAL aggregate. This is the
///    ONLY admin arm on any surface, and it reuses the existing predicate
///    rather than introducing a `for_admin` privacy-bypass construction.
/// 4. Everyone else is scoped to their own principal.
fn resolve_calibrate_http_caller(
    app: &AppState,
    headers: &HeaderMap,
) -> Result<CalibrateHttpCaller, axum::response::Response> {
    let header_present = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().is_empty());
    if !header_present {
        return Err(forbidden_calibrate_caller());
    }
    let principal = crate::handlers::parity::resolve_caller_agent_id(None, headers, None)
        .map_err(err_response)?;
    let is_admin = crate::handlers::admin_role::is_admin_caller_trusted(app, headers, &principal);
    let audience = if is_admin {
        crate::confidence::calibrate::CalibrationAudience::admin()
    } else {
        crate::confidence::calibrate::CalibrationAudience::for_caller(&principal)
            .map_err(|_| forbidden_calibrate_caller())?
    };
    Ok(CalibrateHttpCaller {
        principal,
        is_admin,
        audience,
    })
}

/// The `403` envelope for a calibration request with no usable caller.
fn forbidden_calibrate_caller() -> axum::response::Response {
    tracing::warn!(
        target: "handlers::route_1111",
        "memory_calibrate_confidence refused: no resolvable caller identity (#3507)"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": crate::confidence::calibrate::CALLER_REQUIRED_REFUSAL,
        })),
    )
        .into_response()
}

/// `POST /api/v1/memory_calibrate_confidence` — Form 5 calibration
/// driver. Reads `confidence_shadow_observations`, emits per-
/// (namespace, source) baselines over the window. Read-only over the
/// shadow-observations table for a caller-scoped sweep; the admin sweep
/// additionally rides the `recall_outcome` ledger backfill.
///
/// v1.0.0 #3507 — the report is a CALLER-SCOPED aggregate. The caller is
/// resolved from `X-Agent-Id` BEFORE any substrate access, on BOTH the
/// sqlite and the postgres arm, so neither backend can serve the pre-#3507
/// cross-namespace global sweep to an ordinary caller.
pub async fn handle_calibrate_confidence_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let caller = match resolve_calibrate_http_caller(&app, &headers) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // #3064 lane L-PGP family F3 — postgres SAL dispatch through
    // `MemoryStore::calibrate_confidence_report`. Pre-fix this route took
    // `app.db.lock()` unconditionally, so on a postgres daemon it would have
    // swept the EMPTY scratch sqlite and reported an all-zero calibration as
    // if it were the corpus's — which is why the gate refused it outright.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return calibrate_confidence_http_via_store(&app, &caller, &body).await;
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_calibrate_confidence(&lock.0, &body, &caller.audience);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 lane L-PGP family F3 — the postgres arm of
/// [`handle_calibrate_confidence_http`].
///
/// Restates the SAME argument contract `mcp::handle_calibrate_confidence`
/// applies before it reaches the substrate, in the SAME order, so a refusal
/// carries the identical message on both backends:
///
/// * `days` defaults to `DEFAULT_WINDOW_DAYS` and must be non-negative;
/// * `days` must not exceed `validate::MAX_DURATION_DAYS` (the #3384
///   bounded-window refusal — a caller-controlled window must never reach
///   chrono's panicking duration arithmetic).
///
/// The substrate-error prefix is preserved verbatim so an operator's log
/// greps match across backends.
///
/// v1.0.0 #3507 — `caller` carries the ALREADY-RESOLVED principal + admin
/// verdict from [`resolve_calibrate_http_caller`], so this arm cannot admit
/// a caller the sqlite arm would refuse. The [`crate::store::CallerContext`]
/// is built with `for_admin_checked`, which forces the admin bool into the
/// type signature (#1062) rather than constructing a privacy bypass
/// unconditionally.
#[cfg(feature = "sal")]
async fn calibrate_confidence_http_via_store(
    app: &AppState,
    caller: &CalibrateHttpCaller,
    body: &Value,
) -> axum::response::Response {
    let days = body
        .get("days")
        .and_then(Value::as_i64)
        .unwrap_or(crate::confidence::calibrate::DEFAULT_WINDOW_DAYS);
    if days < 0 {
        return err_response("days must be non-negative".to_string());
    }
    if days > crate::validate::MAX_DURATION_DAYS {
        return err_response(format!(
            "days must not exceed {} days (got {days})",
            crate::validate::MAX_DURATION_DAYS
        ));
    }
    let ctx =
        crate::store::CallerContext::for_admin_checked(caller.principal.clone(), caller.is_admin);
    match app
        .store
        .calibrate_confidence_report(&ctx, days, chrono::Utc::now())
        .await
    {
        Ok(report) => (StatusCode::OK, Json(json!({ "report": report }))).into_response(),
        Err(e) => err_response(format!("memory_calibrate_confidence substrate error: {e}")),
    }
}

/// `POST /api/v1/memory_verify` — verify a link's per-edge
/// Ed25519 signature against the bound `observed_by` public key.
/// Read-only.
pub async fn handle_verify_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #3064 — postgres SAL dispatch. `PostgresStore::verify_link` already
    // exists; the gate used to 501 this route so the sqlite MCP handler
    // never ran against the empty scratch db.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return verify_http_via_store(&app, &body).await;
    }
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_verify(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 — postgres arm of [`handle_verify_http`]. Parses the MCP body
/// into [`crate::store::VerifyFilter`] (SAL `link_id` is
/// `source|target|relation`) and maps [`crate::store::VerifyLinkReport`]
/// onto the MCP `memory_verify` envelope. ERRORS-01: store faults go
/// through [`super::store_err_to_response`].
#[cfg(feature = "sal")]
async fn verify_http_via_store(app: &AppState, params: &Value) -> axum::response::Response {
    use crate::mcp::param_names;
    use crate::store::{StoreError, VerifyFilter};

    let parsed: Result<(String, String, String), String> =
        if let Some(lid) = params.get(param_names::LINK_ID).and_then(Value::as_str) {
            // MCP composite is `source--relation-->target` (not the SAL
            // `source|target|relation` form `verify_link` uses).
            match lid.split_once("-->").and_then(|(left, target)| {
                left.split_once("--")
                    .map(|(source, relation)| (source, target, relation))
            }) {
                Some((source, target, relation))
                    if !source.is_empty() && !target.is_empty() && !relation.is_empty() =>
                {
                    Ok((source.to_string(), target.to_string(), relation.to_string()))
                }
                _ => Err(format!(
                    "link_id '{lid}' is not in the expected form \
                     'source_id--relation-->target_id'"
                )),
            }
        } else {
            let src = params.get(param_names::SOURCE_ID).and_then(Value::as_str);
            let dst = params.get(param_names::TARGET_ID).and_then(Value::as_str);
            match (src, dst) {
                (Some(s), Some(d)) => {
                    let rel = params
                        .get(param_names::RELATION)
                        .and_then(Value::as_str)
                        .unwrap_or(crate::models::MemoryLinkRelation::RelatedTo.as_str());
                    Ok((s.to_string(), d.to_string(), rel.to_string()))
                }
                _ => Err(crate::errors::msg::MEMORY_VERIFY_ARGS_REQUIRED.to_string()),
            }
        };
    let (source_id, target_id, relation) = match parsed {
        Ok(t) => t,
        Err(e) => return err_response(e),
    };
    if let Err(e) =
        crate::validate::RequestValidator::validate_link_triple(&source_id, &target_id, &relation)
    {
        return err_response(e.to_string());
    }
    let filter = VerifyFilter {
        source_id: None,
        target_id: None,
        link_id: Some(format!("{source_id}|{target_id}|{relation}")),
    };
    match app.store.verify_link(filter).await {
        Ok(report) => {
            // SAL `verified` is true for structurally-valid UNSIGNED
            // rows (LINKS_VERIFY / cert harness). MCP `memory_verify`
            // reports `signature_verified=false` on that path — map
            // here so postgres HTTP matches sqlite MCP (ERRORS-09:
            // don't conflate the two verdicts).
            let signature_verified = report.verified && report.signature_present;
            let signed_by = if signature_verified {
                report.observed_by.map_or(Value::Null, Value::String)
            } else {
                Value::Null
            };
            let signed_at = if signature_verified {
                report.signed_at.map_or(Value::Null, Value::String)
            } else {
                Value::Null
            };
            Json(json!({
                "signature_verified": signature_verified,
                (field_names::ATTEST_LEVEL): report.attest_level,
                "signed_by": signed_by,
                "signed_at": signed_at,
            }))
            .into_response()
        }
        Err(StoreError::NotFound { id }) => err_response(format!("link not found: {id}")),
        Err(e) => super::store_err_to_response(e),
    }
}

/// `POST /api/v1/memory_replay` — substrate audit-chain replay
/// for a memory id. Caller-ownership gate is enforced inside
/// [`crate::mcp::handle_replay`] (issue #1075 SR-1 #1 HIGH).
pub async fn handle_replay_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the substrate ownership gate `handle_replay` applies to the forwarded
    // caller. Under `enforce`, a shared-key `Claimed` caller forging
    // `X-Agent-Id: <victim>` cannot replay the victim's memory operations.
    // Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "replay",
    ) {
        return resp;
    }
    // Resolve caller id so the substrate ownership gate has a
    // header-attributed principal. Mirror the inbox handler.
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let mut owned = body.clone();
    if let Some(obj) = owned.as_object_mut() {
        obj.insert("agent_id".to_string(), Value::String(caller.clone()));
    }
    // #3064 batch D — postgres SAL dispatch. Never `app.db.lock()`.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return replay_http_via_store(&app, &owned, &caller).await;
    }
    let lock = app.db.lock().await;
    // #1571 — the header-attributed principal is the bound caller; the
    // body `agent_id` was already forced to match above.
    let result = crate::mcp::handle_replay(&lock.0, &owned, None, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// #3064 batch D — postgres arm of [`handle_replay_http`].
/// `replay_transcript_union` + `get` visibility + `fetch_transcript_content`.
/// Envelope matches sqlite [`crate::mcp::handle_replay`]. ERRORS-01.
#[cfg(feature = "sal")]
async fn replay_http_via_store(
    app: &AppState,
    params: &Value,
    caller: &str,
) -> axum::response::Response {
    use crate::mcp::param_names;
    use crate::store::{CallerContext, StoreError};
    use crate::transcripts::replay::REPLAY_VERBOSE_THRESHOLD_BYTES;

    let memory_id = match params.get(param_names::MEMORY_ID).and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        Some(_) => return err_response(crate::errors::msg::MEMORY_ID_EMPTY.to_string()),
        None => return err_response(crate::errors::msg::MEMORY_ID_REQUIRED.to_string()),
    };
    if let Err(e) = crate::validate::validate_id(&memory_id) {
        return err_response(e.to_string());
    }
    let verbose = params
        .get("verbose")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let depth: Option<u32> = match params.get(param_names::DEPTH) {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) if n < 0 => Some(0),
            Some(n) => Some(u32::try_from(n).unwrap_or(u32::MAX)),
            None => return err_response("depth must be an integer or null".to_string()),
        },
    };

    let entries = match app.store.replay_transcript_union(&memory_id, depth).await {
        Ok(v) => v,
        Err(e) => return super::store_err_to_response(e),
    };

    let vis_ctx = CallerContext::for_agent(caller);
    for entry in &entries {
        match app.store.get(&vis_ctx, &entry.memory_id).await {
            Ok(_) => {}
            Err(StoreError::NotFound { .. }) => {
                return Json(json!({
                    "memory_id": memory_id,
                    (field_names::TRANSCRIPTS): Vec::<Value>::new(),
                    "count": 0,
                }))
                .into_response();
            }
            Err(e) => return super::store_err_to_response(e),
        }
    }

    for entry in &entries {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let ctx = PermissionContext {
            op: Op::MemoryReplay,
            namespace: entry.namespace.clone(),
            agent_id: caller.to_string(),
            payload: json!({
                "memory_id": memory_id,
                (field_names::TRANSCRIPT_ID): entry.transcript_id,
                (field_names::SOURCE_MEMORY_ID): entry.memory_id,
            }),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return err_response(crate::governance::deny_message(
                    "replay",
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Json(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": "replay",
                    "memory_id": memory_id,
                }))
                .into_response();
            }
        }
    }

    let mut transcripts_json: Vec<Value> = Vec::with_capacity(entries.len());
    for entry in entries {
        let truncate = !verbose && entry.original_size > REPLAY_VERBOSE_THRESHOLD_BYTES;
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), Value::String(entry.transcript_id.clone()));
        obj.insert(
            field_names::CREATED_AT.into(),
            Value::String(entry.created_at),
        );
        obj.insert(
            field_names::COMPRESSED_SIZE.into(),
            json!(entry.compressed_size),
        );
        obj.insert(
            field_names::ORIGINAL_SIZE.into(),
            json!(entry.original_size),
        );
        obj.insert(
            field_names::SPAN_START.into(),
            entry
                .span_start
                .map_or(Value::Null, |v| Value::Number(v.into())),
        );
        obj.insert(
            field_names::SPAN_END.into(),
            entry
                .span_end
                .map_or(Value::Null, |v| Value::Number(v.into())),
        );
        obj.insert(
            field_names::SOURCE_MEMORY_ID.into(),
            Value::String(entry.memory_id),
        );
        if truncate {
            obj.insert("truncated".into(), Value::Bool(true));
        } else {
            let content = match app
                .store
                .fetch_transcript_content(&entry.transcript_id)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    return err_response(format!(
                        "transcript {} disappeared between metadata read and content fetch",
                        entry.transcript_id
                    ));
                }
                Err(e) => return super::store_err_to_response(e),
            };
            obj.insert("content".into(), Value::String(content));
        }
        transcripts_json.push(Value::Object(obj));
    }

    Json(json!({
        "memory_id": memory_id,
        (field_names::TRANSCRIPTS): transcripts_json,
        "count": transcripts_json.len(),
    }))
    .into_response()
}

/// `POST /api/v1/memory_subscription_replay` — replay HMAC-signed
/// webhook deliveries for a subscription. Caller-ownership gate
/// enforced inside [`crate::mcp::handle_subscription_replay`] (issue
/// #1115 SR-1 #5 HIGH): only the subscription's owner can replay it.
pub async fn handle_subscription_replay_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the substrate ownership gate `handle_subscription_replay` applies. Under
    // `enforce`, a shared-key `Claimed` caller forging `X-Agent-Id: <victim>`
    // cannot replay the victim's webhook deliveries. Inert for zero-config
    // deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "subscription_replay",
    ) {
        return resp;
    }
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_subscription_replay(&lock.0, &body, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_subscription_dlq_list` — list dead-lettered
/// webhook deliveries. Caller-ownership gate enforced inside
/// [`crate::mcp::handle_subscription_dlq_list`] (issue #1118 SR-1 #6
/// HIGH): non-admin callers can only see DLQ rows for their own
/// subscriptions.
pub async fn handle_subscription_dlq_list_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the substrate ownership gate `handle_subscription_dlq_list` applies.
    // Under `enforce`, a shared-key `Claimed` caller forging
    // `X-Agent-Id: <victim>` cannot list the victim's dead-lettered webhook
    // deliveries. Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "subscription_dlq_list",
    ) {
        return resp;
    }
    let body_agent = body.get("agent_id").and_then(Value::as_str);
    let caller = match crate::handlers::parity::resolve_caller_agent_id(body_agent, &headers, None)
    {
        Ok(id) => id,
        Err(e) => return err_response(e),
    };
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_subscription_dlq_list(&lock.0, &body, Some(&caller));
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_rule_list` — list the substrate-level
/// agent-action governance rules. Read-only.
pub async fn handle_rule_list_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_rule_list(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_check_agent_action` — dry-run an agent
/// action against the substrate rules table. Read-only over the rules
/// table; writes a `governance.check` audit row (audit emit failure
/// surfaces as 500 via the substrate primitive).
pub async fn handle_check_agent_action_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_check_agent_action(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}
