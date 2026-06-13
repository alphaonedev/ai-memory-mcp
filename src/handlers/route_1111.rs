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
                return Some(super::quorum_not_met_response(&payload));
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
    // #1555 — resolve the caller from headers so the forwarded load_family read
    // applies the scope=private visibility filter (the always-on intent loader
    // must not surface another tenant's private family-tagged rows). Reuses the
    // shared `resolve_caller_agent_id` helper (non-sal-safe, anonymous-fallback
    // handling lives inside it, not duplicated here); the empty principal owns
    // no private row.
    let caller =
        crate::handlers::parity::resolve_caller_agent_id(None, &headers, None).unwrap_or_default();
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

/// `POST /api/v1/memory_reflect` — substrate reflection over a
/// memory set. Wraps [`crate::mcp::handle_reflect`]. The embedder,
/// vector index, and daemon active keypair flow in from `AppState` so
/// every `reflects_on` edge written here is signed when the operator
/// has a daemon keypair on disk (matching the MCP behaviour).
pub async fn handle_reflect_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Postgres SAL path (#1549): route the recursive-learning reflect
    // through `MemoryStore::reflect` (the inherent native-sqlx port —
    // governance cap, depth-exceeded signed_events audit, atomic memory
    // + signed reflects_on links). Mirrors the sqlite MCP path's
    // argument contract + `REFLECTION_DEPTH_EXCEEDED` / `CALLER_DEPTH_MISMATCH`
    // wire slugs + `{id, reflection_depth, reflects_on, namespace}` shape.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let (input, caller_depth) = match crate::mcp::parse_reflect_input(&body, None) {
            Ok(parsed) => parsed,
            Err(e) => return err_response(e),
        };
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
    let vector_index = vec_lock.as_ref();
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
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_dependents_of_invalidated(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
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
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_export_reflection(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
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
    let lock = app.db.lock().await;
    let tier = app.tier_config.tier;
    let result = crate::mcp::tools::handle_atomise(&lock.0, &body, None, tier, None);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
    }
}

/// `POST /api/v1/memory_calibrate_confidence` — Form 5 calibration
/// driver. Reads `confidence_shadow_observations`, emits per-
/// (namespace, source) baselines over the window. Read-only over the
/// shadow-observations table.
pub async fn handle_calibrate_confidence_http(
    State(app): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_calibrate_confidence(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
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
    let lock = app.db.lock().await;
    let result = crate::mcp::handle_verify(&lock.0, &body);
    drop(lock);
    match result {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => err_response(e),
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

/// `POST /api/v1/memory_subscription_replay` — replay HMAC-signed
/// webhook deliveries for a subscription. Caller-ownership gate
/// enforced inside [`crate::mcp::handle_subscription_replay`] (issue
/// #1115 SR-1 #5 HIGH): only the subscription's owner can replay it.
pub async fn handle_subscription_replay_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
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
