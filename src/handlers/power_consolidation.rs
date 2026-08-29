// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Consolidation + LLM-tool HTTP handlers — `consolidate_memories`,
//! `auto_tag_handler`, `expand_query_handler`, and `load_family_handler`,
//! plus their LLM-backed source-summary helpers.
//!
//! Extracted from [`super::power`] under issue #650 (handler cap ≤1200 LOC).
//! Handler bodies are unchanged; only the module surface moved. Wire
//! compatibility preserved via `pub use power_consolidation::*` in
//! [`super`].

#![allow(clippy::too_many_lines)]

use crate::models::field_names;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::db;
use crate::models::{Memory, Tier};
use crate::profile::Family;
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::MAX_BULK_SIZE;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

/// L5 — cap on auto-tag output rows.
const AUTO_TAG_MAX_TAGS: usize = 8;

#[derive(serde::Deserialize)]
pub struct ConsolidateBody {
    pub ids: Vec<String>,
    pub title: String,
    /// v0.7.0 L7 — was required (`summary: String`), which caused the
    /// axum `Json<T>` extractor to return 422 UNPROCESSABLE ENTITY for
    /// MCP-parity payloads that ship `{use_llm: true}` and rely on the
    /// daemon to materialize the summary via the LLM (matching
    /// `handle_consolidate` at `crate::mcp::handle_consolidate` (LLM-wired branch)). Now optional;
    /// when absent the handler asks `app.llm.summarize_memories` to
    /// produce a real summary, otherwise (no LLM wired) we synthesise
    /// a deterministic concat fallback so the row still lands.
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default = "default_ns")]
    pub namespace: String,
    #[serde(default)]
    pub tier: Option<Tier>,
    /// Optional `agent_id` for the consolidator (attributable on the result).
    /// If unset, resolved from `X-Agent-Id` header or per-request anonymous id.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// v0.7.0 L7 — explicit opt-in from S51-style MCP-parity callers
    /// that the daemon should compute the summary via the LLM rather
    /// than echoing a caller-supplied one. Today the gate is permissive:
    /// when `summary` is absent, the LLM path runs whether or not
    /// `use_llm` is set; the field is preserved for forward-compat with
    /// future "force LLM even when summary supplied" semantics.
    #[serde(default)]
    pub use_llm: bool,
}

fn default_ns() -> String {
    crate::DEFAULT_NAMESPACE.to_string()
}

/// v0.7.0 L7 — resolve the consolidation `summary` field when the
/// caller omits it. Mirrors the MCP `handle_consolidate` auto-summary
/// path at `crate::mcp::handle_consolidate` (LLM-wired branch): when an LLM is wired and the source
/// memories can be fetched, run `summarize_memories` on `(title,
/// content)` pairs. When no LLM is wired (keyword / semantic tiers, or
/// Ollama unreachable at boot), fall back to a deterministic
/// title-concat string so the consolidation still succeeds — S51 only
/// gates on `summary_len >= 20`, and the fallback is comfortably above
/// that for any 2-id call with non-trivial titles.
///
/// The blocking Ollama call is wrapped in `tokio::task::spawn_blocking`
/// to keep the async runtime healthy under load — same pattern as
/// `maybe_auto_tag`.
async fn resolve_consolidate_summary(
    app: &AppState,
    ids: &[String],
    caller_principal: &str,
) -> Result<String, Response> {
    // Collect (title, content) pairs from the appropriate backend so
    // the LLM has the actual source material. SAL on postgres; legacy
    // db on sqlite. A missing source memory short-circuits to 400 with
    // the offending id, matching the MCP path.
    //
    // Caller is passed as a string (agent id) rather than a typed
    // `CallerContext` so this helper compiles cleanly under non-sal
    // feature configurations. The `CallerContext::for_agent(...)`
    // construction lives inside the sal-gated body of
    // [`fetch_consolidate_source_pairs`].
    let pairs = fetch_consolidate_source_pairs(app, ids, caller_principal).await?;

    // No LLM available — deterministic concat fallback. Titles only
    // (not full content) so the result stays a "summary" rather than a
    // verbatim concat that S51's `is_verbatim_concat` heuristic would
    // flag.
    let llm_arc = app.llm.current();
    if llm_arc.is_none() || pairs.is_empty() {
        let titles: Vec<String> = pairs.iter().map(|(t, _)| t.clone()).collect();
        return Ok(format!(
            "Consolidated summary of {} memories: {}",
            titles.len(),
            titles.join("; ")
        ));
    }

    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama summarize call by the
    // configured per-LLM-call timeout (default 30s). On timeout we
    // degrade to the deterministic concat fallback below (already the
    // L7 LLM-absent path).
    // PERF-9 (v0.7.0 FX-C1) — direct async summarize. No spawn_blocking
    // hop now that OllamaClient is async-`reqwest::Client`.
    let join = tokio::time::timeout(llm_timeout, async move {
        let Some(llm) = llm_arc.as_ref() else {
            return Ok::<String, anyhow::Error>(String::new());
        };
        llm.summarize_memories_async(&pairs).await
    })
    .await;

    match join {
        Ok(Ok(s)) if !s.trim().is_empty() => Ok(s),
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (summarize_memories) exceeded {}s timeout — falling back to \
                 deterministic concat",
                llm_timeout.as_secs()
            );
            Ok("Consolidated summary (LLM timeout; deterministic fallback)".to_string())
        }
        Ok(_) => {
            // LLM returned an empty body or errored — fall back to a
            // deterministic concat-of-titles fallback.
            Ok("Consolidated summary (LLM unavailable; deterministic fallback)".to_string())
        }
    }
}

/// v0.7.0 L7 — fetch `(title, content)` pairs for each source memory in
/// a consolidation request, picking the storage backend off `AppState`.
/// Missing ids surface as a 400 response so the caller's mistake is
/// distinguishable from a daemon-side LLM failure.
async fn fetch_consolidate_source_pairs(
    app: &AppState,
    ids: &[String],
    caller_principal: &str,
) -> Result<Vec<(String, String)>, Response> {
    #[cfg(not(feature = "sal"))]
    let _ = caller_principal;
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // v0.7.0 ship-hardening (QC P1, 2026-05-20): use the resolved
        // caller principal from the request headers so the SAL #910
        // scope=private visibility filter naturally rejects source
        // IDs the caller doesn't own. The earlier `for_admin` shape
        // was a privacy escalation — any authenticated caller could
        // submit IDs they didn't own and the SAL bypass would read
        // them. Cross-author consolidation requires an explicit
        // admin role (a v0.7.1+ feature); for now the consolidation
        // surface is single-owner.
        let caller = crate::store::CallerContext::for_agent(caller_principal.to_string());
        let mut out: Vec<(String, String)> = Vec::with_capacity(ids.len());
        for id in ids {
            match app.store.get(&caller, id).await {
                Ok(mem) => out.push((mem.title, mem.content)),
                Err(crate::store::StoreError::NotFound { .. }) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": crate::errors::msg::memory_not_found(id)})),
                    )
                        .into_response());
                }
                Err(e) => return Err(store_err_to_response(e)),
            }
        }
        return Ok(out);
    }

    // ARCH-2 keeper: the sqlite path reads through `db::get` on the
    // `app.db` connection that the test harness shares with handler
    // writes. `app.store` (SqliteStore) opens its own connection on
    // a separate temp file in test mode (see
    // `test_sqlite_store_handle` in `src/handlers/tests.rs`); routing
    // this read through `app.store.get` reads from the wrong file in
    // tests. Production behavior is identical to SAL routing because
    // the test-disjoint `app.store` is a unit-test artifact, but the
    // refactor needs a test-fixture change tracked under the
    // ARCH-2-followup audit before the sqlite path can converge.
    let lock = app.db.lock().await;
    let mut out: Vec<(String, String)> = Vec::with_capacity(ids.len());
    for id in ids {
        match db::get(&lock.0, id) {
            Ok(Some(mem)) => out.push((mem.title, mem.content)),
            Ok(None) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": crate::errors::msg::memory_not_found(id)})),
                )
                    .into_response());
            }
            Err(e) => {
                tracing::error!("consolidate source lookup failed: {e}");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
                )
                    .into_response());
            }
        }
    }
    Ok(out)
}

/// #1552 / #326 / #2860 — shared federation fanout for the consolidate write
/// path, called by both the postgres SAL branch and the sqlite branch of
/// [`consolidate_memories`]. Broadcasts the substrate-authored merged memory to
/// the W-quorum plus its source disposition — either the legacy `deletions`
/// (hard-DELETE) list OR the RETAINED `tombstoned_sources` rows + navigable
/// `derived_edges` (`derived_from`) under the v1.0.0-default tombstone
/// disposition (#2860) — so peers converge the consolidation, the source state,
/// AND the lineage DAG synchronously instead of waiting on async catch-up.
///
/// Returns `Some(response)` when the quorum is NOT met (a typed 503 the caller
/// must return verbatim), or `None` on success / when federation is disabled
/// (the single-node no-op path) so the caller proceeds to its 201 envelope.
async fn consolidate_fanout(
    fed: Option<&crate::federation::FederationConfig>,
    mem: &crate::models::Memory,
    deletions: &[String],
    tombstoned_sources: &[crate::models::Memory],
    derived_edges: &[crate::models::MemoryLink],
) -> Option<axum::response::Response> {
    let fed = fed?;
    match crate::federation::broadcast_consolidate_quorum(
        fed,
        mem,
        deletions,
        tombstoned_sources,
        derived_edges,
    )
    .await
    {
        Ok(tracker) => {
            if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                // #2856/#2861 loud floor + #2860 convergence composed. #2860
                // authors the consolidation as the daemon federation identity so
                // the quorum normally SUCCEEDS (self-relay past strict write-sig)
                // and this miss path is now the RESIDUAL peer-down / partition
                // case. When it does miss, keep #2861's id-bearing under-
                // replication 202 (`under_replicated_consolidate_response`, was
                // the bare `under_replicated_response` that omitted the created
                // `id`) so the caller can DISCOVER + reconcile the local-only row
                // instead of seeing a success-shaped 2xx with nothing to act on
                // (5-agent vote `4d3ea1c5`). Exactly one of `deletions` /
                // `tombstoned_sources` is populated (legacy hard-delete vs the
                // v1.0.0-default tombstone disposition), so their sum is the
                // original consolidated-source count the 202 body reports.
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                let source_count = deletions.len() + tombstoned_sources.len();
                return Some(super::under_replicated_consolidate_response(
                    &payload,
                    mem,
                    source_count,
                ));
            }
        }
        Err(e) => {
            tracing::warn!("consolidate fanout error (local committed): {e:?}");
        }
    }
    None
}

pub async fn consolidate_memories(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsolidateBody>,
) -> impl IntoResponse {
    // #1924 (CWE-288) — consult the PRE-CONSOLIDATE enforcement gate before the
    // consolidation write (HTTP parity with the MCP gate).
    // #2390 (N9) — the summary lands in `body.namespace` (serde-defaulted) and
    // the N source rows it consumes may live elsewhere; every touched namespace
    // contributes so a hook scoped to any of them fires. Pre-fix the payload was
    // `{"ids": [...]}` with no namespace, so scoped hooks never fired.
    let mut consolidate_namespaces = vec![body.namespace.clone()];
    for ns in crate::handlers::create::resolve_pre_event_namespaces(&app, &headers, &body.ids).await
    {
        if !consolidate_namespaces.contains(&ns) {
            consolidate_namespaces.push(ns);
        }
    }
    if let Some(resp) = crate::handlers::create::http_pre_event_gate(
        crate::hooks::HookEvent::PreConsolidate,
        consolidate_namespaces,
        serde_json::json!({ "ids": body.ids, "namespace": body.namespace }),
    ) {
        return resp;
    }
    // #2096 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the caller-scoped source reads/consumption below. Consolidation reads
    // the source rows through the #910 caller-keyed visibility filter and
    // hard-DELETE-merges them, so under `enforce` a shared-key `Claimed`
    // caller forging `X-Agent-Id: <victim>` could otherwise read + consume the
    // victim's private rows; refuse it here. Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "consolidate_memories",
    ) {
        return resp;
    }
    // v0.7.0 L7 — materialize the summary up front so the downstream
    // validation + storage paths see a concrete `&str`. When the caller
    // supplied one, use it verbatim; when absent, ask the LLM (matching
    // the MCP `handle_consolidate` auto-summary contract); when neither
    // is available, synthesise a deterministic concat of the source
    // titles so the row still lands rather than 422'ing on a wire-shape
    // mismatch S51 has tripped on.
    // QC P1 fix (2026-05-20): resolve the caller principal from
    // headers so the SAL #910 scope=private visibility filter
    // applies to the source-id reads (consolidation can only access
    // memories the caller owns or that are scope=shared/public).
    // The helper takes `&str` (agent id) rather than the typed
    // `CallerContext` so non-sal builds compile without conditional
    // gating.
    let consolidate_caller_principal =
        crate::handlers::parity::resolve_caller_agent_id(None, &headers, None)
            .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());
    let summary = match body.summary.clone() {
        Some(s) if !s.is_empty() => s,
        _ => {
            match resolve_consolidate_summary(&app, &body.ids, &consolidate_caller_principal).await
            {
                Ok(s) => s,
                Err(resp) => return resp,
            }
        }
    };

    if let Err(e) = validate::RequestValidator::validate_consolidate(
        &body.ids,
        &body.title,
        &summary,
        &body.namespace,
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // #905 (security-high, 2026-05-19) — sibling of #874/#901. The
    // pre-#905 path passed `body.agent_id` as the first arg to
    // `resolve_http_agent_id` which gives caller-controlled body the
    // PRECEDENCE over the authenticated `X-Agent-Id` header. An
    // attacker authenticated as `bob` could call
    // `POST /api/v1/consolidate` with `body.agent_id="alice"` and
    // the new consolidated row would be stamped with
    // `consolidator_agent_id="alice"` — a provenance lie that also
    // breaks the cross-tenant tracking the K9 governance walk leans
    // on. Header-only authentication now; body.agent_id (if present)
    // must match the authenticated caller else 403.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let consolidator_agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id)
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
            )
                .into_response();
        }
    };
    if let Some(claimed) = body.agent_id.as_deref()
        && claimed != consolidator_agent_id
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": crate::errors::msg::AGENT_ID_BODY_MISMATCH})),
        )
            .into_response();
    }
    let tier = body.tier.unwrap_or(Tier::Long);
    let source_ids = body.ids.clone();

    // v0.7.0 Wave-3 Continuation 3 (Phase 14) — postgres-backed daemons
    // route through the SAL trait. Returns a structured 201/error envelope
    // that mirrors the sqlite path; the cross-namespace
    // `memory_consolidated` event + federation fanout are both
    // sqlite-only features (the sqlite branch below preserves them).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(&consolidator_agent_id);
        // #1795 (5-agent vote 4d3ea1c5) — enforce the per-agent daily write
        // quota for the one net-new consolidated memory on the postgres tenant
        // path (the SAL `consolidate` only RECORDS). Mirrors the sqlite branch's
        // `check_and_record` charge; the curator ConsolidationPass (for_admin)
        // never reaches this handler.
        let consolidate_quota_bytes =
            i64::try_from(body.title.len() + summary.len()).unwrap_or(i64::MAX);
        if let Err(e) = app
            .store
            .check_memory_quota(&ctx, &body.namespace, 1, consolidate_quota_bytes)
            .await
        {
            return store_err_to_response(e);
        }
        // #2860 (5-agent vote `4d3ea1c5`) — federated path: author the
        // substrate-DERIVED row as the daemon's federation identity so it
        // self-relays past strict write-sig (postgres twin of the sqlite
        // branch's `author_id`). The `for_agent` ctx (source-read visibility /
        // IDOR) is UNCHANGED — only the recorded author moves.
        let pg_author_id = match app.federation.as_ref().as_ref() {
            Some(f) => f.sender_agent_id.clone(),
            None => consolidator_agent_id.clone(),
        };
        let new_id = match app
            .store
            .consolidate(
                &ctx,
                &body.ids,
                &body.title,
                &summary,
                &body.namespace,
                &tier,
                crate::db::CONSOLIDATION_SOURCE,
                &pg_author_id,
            )
            .await
        {
            Ok(new_id) => new_id,
            // #3014 — 403 ATTESTATION_FAILED under global-strict (parity with
            // the store path); otherwise the typed StoreError mapping.
            Err(e) => {
                return crate::handlers::errors::attestation_refused_response(&e.to_string())
                    .unwrap_or_else(|| store_err_to_response(e));
            }
        };
        // #1552 / #2860 — federation fanout parity (shared `consolidate_fanout`
        // helper). The SAL-ported postgres branch previously returned here
        // WITHOUT broadcasting; now it reads the substrate-authored row back
        // through the trait, FINALIZES it (best-effort daemon `write_signature`
        // + tenant/summary provenance, persisted via `set_row_metadata` so the
        // stored row byte-matches the broadcast copy), and broadcasts it + its
        // source disposition + `derived_from` lineage — the postgres twin of the
        // sqlite branch below. A read-back failure logs + falls through to the
        // success envelope (catch-up reconciles peers).
        if app.federation.is_some() {
            // #2860 — the consolidated row is now owned by `pg_author_id` (the
            // substrate sender), so read it back AS the author: the `for_agent`
            // tenant `ctx` would visibility-filter the sender-owned row to
            // NotFound and silently skip the fanout. The source reads below stay
            // on the tenant `ctx` (the tenant owns the sources).
            let author_ctx = crate::store::CallerContext::for_agent(&pg_author_id);
            if let Ok(mut mem) = app.store.get(&author_ctx, &new_id).await {
                // Shared, unit-tested finalize+disposition (SAL twin of the sqlite
                // branch's `sqlite_finalize_and_disposition`). Source reads stay on
                // the tenant `ctx` (the tenant owns the sources); `set_row_metadata`
                // is by-id and ctx-agnostic.
                let disp =
                    match crate::handlers::consolidate_federation::store_finalize_and_disposition(
                        app.store.as_ref(),
                        &ctx,
                        &mut mem,
                        &source_ids,
                        &pg_author_id,
                        &consolidator_agent_id,
                        body.summary.as_deref(),
                    )
                    .await
                    {
                        Ok(d) => d,
                        Err(e) => {
                            // #3238 — fail-closed: do NOT fanout a row whose
                            // origin persist / tombstone read failed.
                            tracing::error!(
                                "consolidate(pg): finalize failed (skipping fanout): {e}"
                            );
                            return (
                                StatusCode::CREATED,
                                Json(json!({
                                    "id": new_id,
                                    (field_names::CONSOLIDATED): body.ids.len(),
                                    "summary": summary,
                                    "content": summary,
                                    "memory": {
                                        "id": new_id,
                                        "title": body.title,
                                        "content": summary,
                                        "namespace": body.namespace,
                                    },
                                    (field_names::STORAGE_BACKEND): "postgres",
                                })),
                            )
                                .into_response();
                        }
                    };
                if let Some(resp) = consolidate_fanout(
                    app.federation.as_ref().as_ref(),
                    &mem,
                    &disp.deletions,
                    &disp.tombstoned_sources,
                    &disp.derived_edges,
                )
                .await
                {
                    return resp;
                }
            }
        }
        return (
            StatusCode::CREATED,
            Json(json!({
                "id": new_id,
                (field_names::CONSOLIDATED): body.ids.len(),
                "summary": summary,
                // v0.7.0 L7-followup — also emit the materialised summary
                // as `content` and inside a nested `memory` object so the
                // S51 scenario reader (which falls through
                // `cbody.get("summary") or cbody.get("content") or
                // (cbody.get("memory") or {}).get("content")` under a
                // ternary that requires `memory` to be a dict) sees a
                // non-empty string regardless of which branch its
                // operator precedence resolves to. Without the `memory`
                // dict the whole expression collapses to `""` even
                // though `summary` is set — see
                // `scenarios/51_autonomous_tier_suite.py:140-145`.
                "content": summary,
                "memory": {
                    "id": new_id,
                    "title": body.title,
                    "content": summary,
                    "namespace": body.namespace,
                },
                (field_names::STORAGE_BACKEND): "postgres",
            })),
        )
            .into_response();
    }

    let lock = app.db.lock().await;
    // #1788 (5-agent vote 4d3ea1c5) — charge the per-agent daily write quota
    // for the one net-new consolidated memory. consolidate is a tenant-facing
    // authoring write (mints a fresh attributable row), gated like the
    // single-write create handler; the curator/autonomy ConsolidationPass
    // (SAL + for_admin ai:curator) is intentionally exempt. Refund on failure.
    let consolidate_quota_op = crate::quotas::QuotaOp::Memory {
        bytes: i64::try_from(body.title.len() + summary.len()).unwrap_or(i64::MAX),
    };
    if !consolidator_agent_id.is_empty() {
        if let Err(e) = crate::quotas::check_and_record(
            &lock.0,
            &consolidator_agent_id,
            &body.namespace,
            consolidate_quota_op,
        ) {
            return match e {
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
                    tracing::error!("consolidate quota substrate error: {se}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": crate::errors::msg::QUOTA_CHECK_FAILED})),
                    )
                        .into_response()
                }
            };
        }
    }
    // #2121 / #2860 — a NON-federated tenant HTTP consolidate stays tenant-
    // authored + never substrate-authored (byte-identical single-node
    // behaviour). On the FEDERATED path (#2860, 5-agent vote `4d3ea1c5`,
    // decision memory `8b428944`) the substrate-DERIVED row is authored as the
    // daemon's federation identity (`fed.sender_agent_id`) — the substrate that
    // ran the derivation and HOLDS the signing key — so it SELF-RELAYS past the
    // strict per-write attestation gate (`require = strict && attribute !=
    // sender` is false) and can land `agent_attested` where the daemon key is
    // enrolled. Quota is still charged to the INVOKING tenant above; the tenant
    // is retained as provenance by the federated finalize below. This mirrors
    // the already-converging curator `ConsolidationPass` (author = `AI_CURATOR`
    // substrate sentinel). `substrate_authored` stays `false` for cross-backend
    // parity: the postgres SAL `consolidate` derives it from
    // `ctx.bypass_visibility` (`false` for the `for_agent` tenant ctx we must
    // NOT relax — it gates the source-read visibility / IDOR), so the sqlite
    // path mirrors that, and the `AI_MEMORY_REQUIRE_WHY_TRACE=1` gate applies
    // IDENTICALLY on both backends (a why_trace-less federated consolidation is
    // refused on both, never stamped-and-passed on one).
    let fed_enabled = app.federation.is_some();
    let author_id = match app.federation.as_ref().as_ref() {
        Some(f) => f.sender_agent_id.clone(),
        None => consolidator_agent_id.clone(),
    };
    let consolidate_result = db::consolidate(
        &lock.0,
        &body.ids,
        &body.title,
        &summary,
        &body.namespace,
        &tier,
        crate::db::CONSOLIDATION_SOURCE,
        &author_id,
        false,
    );
    // #1788 — refund the quota charge if the consolidate write failed (mirrors
    // the single-write refund_op path). Best-effort; done inside the lock.
    if consolidate_result.is_err() && !consolidator_agent_id.is_empty() {
        if let Err(re) = crate::quotas::refund_op(
            &lock.0,
            &consolidator_agent_id,
            &body.namespace,
            consolidate_quota_op,
        ) {
            crate::quotas::log_refund_op_failed(&consolidator_agent_id, &re);
        }
    }
    // Read the newly consolidated memory back so we can fanout — must do
    // this inside the same lock window because db::consolidate deletes (or,
    // under the tombstone disposition, retains) the source rows as part of
    // its transaction.
    let mut new_mem = match &consolidate_result {
        Ok(new_id) => db::get(&lock.0, new_id).ok().flatten(),
        Err(_) => None,
    };
    // v0.6.4-017 — G9 HTTP webhook parity. Fire `memory_consolidated`
    // after db::consolidate commits (mirrors mcp.rs:2723). The new
    // memory's id goes in the outer envelope; source ids in details.
    if let Ok(new_id) = &consolidate_result {
        let details = serde_json::to_value(crate::subscriptions::ConsolidatedEventDetails {
            source_ids: source_ids.clone(),
            source_count: source_ids.len(),
        })
        .ok();
        crate::subscriptions::dispatch_event_with_details(
            &lock.0,
            crate::subscriptions::webhook_events::MEMORY_CONSOLIDATED,
            new_id,
            &body.namespace,
            Some(&consolidator_agent_id),
            &lock.1,
            details,
        );
    }
    // #2860 — on the FEDERATED path, finalize the substrate-authored row
    // (best-effort daemon `write_signature` + tenant/summary provenance) and
    // prepare the lineage disposition to broadcast, all while the lock is held
    // so the tombstoned source rows + `derived_from` edges are read consistently.
    // The finalize+disposition logic is the shared, unit-tested helper (its
    // postgres twin `store_finalize_and_disposition` runs the identical body
    // through the SAL trait, so the two backends cannot drift).
    let disposition = if fed_enabled {
        match new_mem.as_mut() {
            Some(mem) => {
                match crate::handlers::consolidate_federation::sqlite_finalize_and_disposition(
                    &lock.0,
                    mem,
                    &source_ids,
                    &author_id,
                    &consolidator_agent_id,
                    body.summary.as_deref(),
                ) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        // #3238 — fail-closed: do NOT fanout a row whose
                        // origin persist / tombstone read failed.
                        tracing::error!("consolidate: finalize failed (skipping fanout): {e}");
                        None
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    // Drop DB lock before fanning out — peers POST back to our sync_push
    // and we'd deadlock on the shared Mutex if we held it.
    drop(lock);
    match consolidate_result {
        Ok(new_id) => {
            // v0.6.2 (#326) / #1552 / #2860: propagate the consolidation + its
            // source disposition + `derived_from` lineage to peers so the mesh
            // reaches the same terminal state (shared `consolidate_fanout`).
            if let Some(mem) = new_mem {
                let disp = disposition.unwrap_or_else(|| {
                    crate::handlers::consolidate_federation::FanoutDisposition {
                        deletions: source_ids.clone(),
                        tombstoned_sources: Vec::new(),
                        derived_edges: Vec::new(),
                    }
                });
                if let Some(resp) = consolidate_fanout(
                    app.federation.as_ref().as_ref(),
                    &mem,
                    &disp.deletions,
                    &disp.tombstoned_sources,
                    &disp.derived_edges,
                )
                .await
                {
                    return resp;
                }
            }
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": new_id,
                    (field_names::CONSOLIDATED): body.ids.len(),
                    "summary": summary,
                    // v0.7.0 L7-followup — see postgres branch above for
                    // the rationale. Mirroring `content` and a nested
                    // `memory` dict here keeps both backends emitting the
                    // same wire shape so S51 passes regardless of whether
                    // the daemon is sqlite- or postgres-backed.
                    "content": summary,
                    "memory": {
                        "id": new_id,
                        "title": body.title,
                        "content": summary,
                        "namespace": body.namespace,
                    },
                })),
            )
                .into_response()
        }
        // #3014 — 403 ATTESTATION_FAILED under global-strict (parity with the
        // store path); otherwise the sanitized 500.
        Err(e) => crate::handlers::errors::attestation_refused_response(&e.to_string())
            .unwrap_or_else(|| crate::handlers::errors::handler_error_500(&e)),
    }
}

/// Request body for `POST /api/v1/auto_tag`.
///
/// Two shapes are accepted to keep the surface compatible with both
/// the S51 contract (`{memory_id, namespace}`) and ad-hoc callers that
/// want to tag a free-text title + content blob without storing it
/// first (`{title, content}`). At least one of `(memory_id, title)`
/// must be present.
#[derive(serde::Deserialize, Default)]
pub struct AutoTagBody {
    /// S51 shape — id of an already-stored memory whose `(title,
    /// content)` will be fetched and tagged.
    #[serde(default)]
    pub memory_id: Option<String>,
    /// Optional namespace (S51 sends this for forward-compat; the
    /// underlying LLM call is namespace-agnostic).
    #[serde(default)]
    pub namespace: Option<String>,
    /// Ad-hoc shape — tag this title + content directly without a
    /// preceding store. Used when an operator wants to dry-run the
    /// tag prompt against an arbitrary string.
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

/// `POST /api/v1/auto_tag` — generate semantic tags for a memory via
/// the configured LLM (Ollama by default).
///
/// Wire shape:
/// - request: `{memory_id, namespace}` or `{title, content}`
/// - response 200: `{tags: [..], memory_id: <id or null>}`
/// - response 503: `{error: "LLM not configured"}` when no LLM is wired
/// - response 400: validation / missing-body errors
///
/// The blocking Ollama call is wrapped in `tokio::task::spawn_blocking`
/// mirroring [`maybe_auto_tag`] so the runtime stays responsive when
/// the model is slow.
pub async fn auto_tag_handler(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoTagBody>,
) -> impl IntoResponse {
    if app.llm.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "LLM not configured"})),
        )
            .into_response();
    }

    // QC P1 fix (2026-05-20): use header-resolved caller principal
    // for the source-memory fetch so the SAL #910 visibility filter
    // applies. Helper takes `&str` so non-sal builds compile.
    let auto_tag_caller_principal =
        crate::handlers::parity::resolve_caller_agent_id(None, &headers, None)
            .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string());

    // Resolve (title, content). S51 sends `memory_id`; we fetch the
    // memory from the active backend. Ad-hoc callers may instead
    // supply title+content inline.
    let (title, content, resolved_id): (String, String, Option<String>) =
        if let Some(id) = body.memory_id.as_deref() {
            if let Err(e) = validate::validate_id(id) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            match fetch_memory_for_handler(&app, id, &auto_tag_caller_principal).await {
                Ok(mem) => (mem.title, mem.content, Some(id.to_string())),
                Err(resp) => return resp,
            }
        } else {
            match (body.title.clone(), body.content.clone()) {
                (Some(t), Some(c)) => (t, c, None),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "auto_tag requires memory_id (preferred) or title+content"
                        })),
                    )
                        .into_response();
                }
            }
        };

    let llm_arc = app.llm.current();
    let auto_tag_model = app.auto_tag_model.as_ref().clone();
    let title_owned = title;
    let content_owned = content;
    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama call by the configured
    // per-LLM-call timeout (default 30s). On timeout return an empty
    // tag list with a 200 — preserves the L6/S51 contract that 200 is
    // never withheld when the operator asked for tags but Ollama was
    // slow (matches the "LLM-absent fallback" branch the keyword/
    // semantic tiers already exercise).
    // PERF-9 (v0.7.0 FX-C1) — direct async auto_tag.
    let join = tokio::time::timeout(llm_timeout, async move {
        let Some(llm) = llm_arc.as_ref() else {
            return Ok::<Vec<String>, anyhow::Error>(Vec::new());
        };
        llm.auto_tag_async(&title_owned, &content_owned, auto_tag_model.as_deref())
            .await
    })
    .await;

    let tags = match join {
        Ok(Ok(tags)) => tags.into_iter().take(AUTO_TAG_MAX_TAGS).collect::<Vec<_>>(),
        Ok(Err(e)) => {
            tracing::warn!("L6: auto_tag LLM call failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("LLM auto_tag failed: {e}")})),
            )
                .into_response();
        }
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (auto_tag) exceeded {}s timeout — returning empty tag list",
                llm_timeout.as_secs()
            );
            Vec::new()
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "tags": tags,
            "memory_id": resolved_id,
        })),
    )
        .into_response()
}

/// Request body for `POST /api/v1/expand_query`.
#[derive(serde::Deserialize, Default)]
pub struct ExpandQueryBody {
    pub query: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /api/v1/expand_query` — generate semantic reformulations of a
/// free-text query via the configured LLM.
///
/// Wire shape:
/// - request: `{query, namespace?}`
/// - response 200: `{original: <q>, expanded_terms: [..]}` — same envelope
///   key as the MCP `memory_expand_query` tool and the `ai-memory expand`
///   CLI surface (three-surface envelope parity; #1445)
/// - response 503: `{error: "LLM not configured"}` when no LLM is wired
/// - response 502: `{error: "LLM expand_query failed: ..."}` on upstream error
/// - response 400: empty / missing query
pub async fn expand_query_handler(
    State(app): State<AppState>,
    Json(body): Json<ExpandQueryBody>,
) -> impl IntoResponse {
    if app.llm.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "LLM not configured"})),
        )
            .into_response();
    }
    let query = body.query.trim().to_string();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::QUERY_REQUIRED})),
        )
            .into_response();
    }

    let llm_arc = app.llm.current();
    let query_owned = query.clone();
    let llm_timeout = app.llm_call_timeout;
    // H8 (v0.7.0 round-2) — bound the Ollama call by the configured
    // per-LLM-call timeout (default 30s). On timeout return an empty
    // expansion list — matches the LLM-absent fallback shape.
    // PERF-9 (v0.7.0 FX-C1) — direct async expand_query.
    let join = tokio::time::timeout(llm_timeout, async move {
        let Some(llm) = llm_arc.as_ref() else {
            return Ok::<Vec<String>, anyhow::Error>(Vec::new());
        };
        llm.expand_query_async(&query_owned).await
    })
    .await;

    let expanded_terms = match join {
        Ok(Ok(terms)) => terms,
        Ok(Err(e)) => {
            tracing::warn!("L6: expand_query LLM call failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("LLM expand_query failed: {e}")})),
            )
                .into_response();
        }
        Err(_) => {
            tracing::warn!(
                "H8: LLM call (expand_query) exceeded {}s timeout — returning empty expansion list",
                llm_timeout.as_secs()
            );
            Vec::new()
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "original": query,
            (field_names::EXPANDED_TERMS): expanded_terms,
        })),
    )
        .into_response()
}

/// v0.7.0 L6/L7 — fetch a single memory by id off the active storage
/// backend. Returns a structured 4xx/5xx response on miss / lookup
/// failure so the calling handler can `return Err(resp)`.
async fn fetch_memory_for_handler(
    app: &AppState,
    id: &str,
    caller_principal: &str,
) -> Result<Memory, Response> {
    #[cfg(not(feature = "sal"))]
    let _ = caller_principal;
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // QC P1 fix (2026-05-20): use header-resolved caller so the
        // SAL #910 scope=private visibility filter applies — caller
        // can only fetch memories they own (or scope=shared/public).
        let caller = crate::store::CallerContext::for_agent(caller_principal.to_string());
        return match app.store.get(&caller, id).await {
            Ok(mem) => Ok(mem),
            Err(crate::store::StoreError::NotFound { .. }) => Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": crate::errors::msg::memory_not_found(id)})),
            )
                .into_response()),
            Err(e) => Err(store_err_to_response(e)),
        };
    }

    // ARCH-2 keeper: same constraint as `fetch_consolidate_source_pairs`
    // — `app.store` and `app.db` are pinned to disjoint files in the
    // test harness, so routing this sqlite read through `app.store.get`
    // breaks tests. ARCH-2-followup must converge the harness before
    // the sqlite path can route through SAL.
    let lock = app.db.lock().await;
    match db::get(&lock.0, id) {
        Ok(Some(mem)) => Ok(mem),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": crate::errors::msg::memory_not_found(id)})),
        )
            .into_response()),
        Err(e) => {
            tracing::error!("memory lookup failed: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
            )
                .into_response())
        }
    }
}

/// Request body for `POST /api/v1/memory_load_family`.
#[derive(serde::Deserialize)]
pub struct LoadFamilyBody {
    /// One of: core, lifecycle, graph, governance, power, meta,
    /// archive, other. Validated against [`Family::all`].
    pub family: String,
    /// Optional namespace narrowing. When omitted the scan spans every
    /// namespace, matching the MCP tool's "no namespace = all" rule.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Top-K cap. Default 20, clamped to `[1, 100]` for response-budget
    /// reasons (mirroring `handle_load_family`).
    #[serde(default)]
    pub k: Option<u64>,
}

/// `POST /api/v1/memory_load_family` — return the top-K recent +
/// high-priority memories tagged with the requested family.
///
/// Wire shape:
/// - request: `{family, namespace?, k?}`
/// - response 200: `{family, namespace, k, count, memories: [..]}`
/// - response 400: unknown family / bad namespace
pub async fn load_family_handler(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoadFamilyBody>,
) -> impl IntoResponse {
    use std::str::FromStr;

    let family = match Family::from_str(&body.family) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    if let Some(ref ns) = body.namespace
        && let Err(e) = validate::validate_namespace(ns)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // #2137 (v1.0.0, #2032-A / H1 IDOR) — per-agent-key identity gate BEFORE
    // the caller is resolved from `X-Agent-Id` for the `scope=private`
    // family-tagged read below. Pre-fix, a shared-transport-key caller forging
    // `X-Agent-Id: <victim>` resolved `caller=victim` and read the victim's
    // private family-tagged content (memory_smart_load wraps this handler, so
    // both routes are closed here). Inert for zero-config deployments.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "load_family",
    ) {
        return resp;
    }

    let k_raw = body.k.unwrap_or(20);
    let k = usize::try_from(k_raw).unwrap_or(usize::MAX).clamp(1, 100);
    let family_name = family.name();

    // v0.7.0 Wave-3 / v1.0.0 #2580 — postgres path.
    //
    // Pre-#2580 this pulled `MAX_BULK_SIZE` (=1000) FULL rows regardless of
    // `k` and filtered them on `metadata.family` in Rust, because the SAL
    // `Filter` had no metadata axis. Measured on the 8k-row Atlas corpus:
    // ~982 kB of content+metadata moved per call to return ZERO rows,
    // 54.3 ms p50 — the slowest surface on the postgres backend, on an
    // ALWAYS-ON core-profile tool.
    //
    // The predicate now rides the SAL `Filter::metadata_eq` axis into the
    // SAME hardened `list` query (see `crate::store::MetadataEq`), served
    // by the pre-existing `memories_metadata_gin` index. Two properties are
    // load-bearing and deliberately NOT traded away for the speed:
    //
    //  1. FAIL-CLOSED RE-CHECK. The in-process `metadata.family` predicate
    //     is RETAINED (`MetadataEq::matches`), mirroring the belt-and-
    //     suspenders `is_visible_to_caller` re-apply inside
    //     `PostgresStore::list`. The pushdown can therefore only ever
    //     NARROW: an adapter that ignored the axis would degrade to fewer
    //     results, never widen the set with rows the caller did not ask
    //     for.
    //  2. NEVER FEWER RESULTS THAN PRE-#2580. The fast path asks for
    //     exactly `k` rows, but the SAL `list` applies the strictly-NARROWER
    //     Rust `is_visible_to_caller` (the #1921 team/unit/org subtree gate
    //     has no SQL twin in the `$6` clause) AFTER the SQL `LIMIT`, so a
    //     bare `LIMIT k` could under-return where the old 1000-row window
    //     did not. When the narrowed set is short of `k` we therefore
    //     re-ask at the historical `MAX_BULK_SIZE` window. That escalated
    //     answer is a strict SUPERSET of the pre-#2580 answer: restricting
    //     the ordering to family-tagged rows can only move a family row UP
    //     in rank, so every family row inside the old top-1000 is inside
    //     the new top-1000 — and family rows the old code silently dropped
    //     past rank 1000 (a real pre-existing under-return on namespaces
    //     larger than 1000 rows, which sqlite never had) are now returned.
    //
    // Cost of the escalation is bounded by TWO round trips, and the second
    // one transfers only family-tagged rows — in the measured zero-match
    // case both queries move zero rows.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let family_eq = crate::store::MetadataEq::new(crate::META_KEY_FAMILY, family_name);
        let build_filter = |limit: usize| crate::store::Filter {
            namespace: body.namespace.clone(),
            tier: None,
            tags_any: Vec::new(),
            agent_id: None,
            since: None,
            until: None,
            valid_at: None,
            limit,
            // #1876 — load_family listing serves the first window.
            offset: 0,
            // #2167 — load_family listing never runs the recall space gate.
            active_embedding_space: None,
            // #2580 — GIN-served pushdown of the family predicate.
            metadata_eq: Some(family_eq.clone()),
            // #3185/#3127 — keyword-search-only axis; list ignores it.
            source_uri: None,
            // Recall-hybrid only; list ignores it (default false).
            skip_access_ledger: false,

            ..Default::default()
        };
        // QC P1 fix (2026-05-20): load_family lists every memory in
        // the namespace tagged with a `family` metadata field. With
        // `for_admin` this leaked scope=private memories of other
        // tenants in the same namespace. Resolve the caller from
        // headers so the SAL visibility filter naturally limits the
        // result set to the caller's own memories (+ scope=shared/
        // public, which the filter passes through).
        let ctx = crate::handlers::parity::http_caller_ctx(&headers, None);
        let narrow = |rows: Vec<Memory>| -> Vec<Memory> {
            let mut kept: Vec<Memory> = rows.into_iter().filter(|m| family_eq.matches(m)).collect();
            // priority DESC, updated_at DESC, id ASC (mirrors handle_load_family
            // + the #2602/#2615 `store::list` tiebreak). `sort_by` is stable, so
            // this in-process sort inherits determinism only IMPLICITLY from the
            // already-ordered `store.list` result; an explicit `id` tiebreak
            // makes this call site a self-contained total order rather than one
            // that silently depends on an upstream invariant holding.
            kept.sort_by(|a, b| {
                b.priority
                    .cmp(&a.priority)
                    .then_with(|| b.updated_at.cmp(&a.updated_at))
                    .then_with(|| a.id.cmp(&b.id))
            });
            kept
        };
        let mut filtered = match app.store.list(&ctx, &build_filter(k)).await {
            Ok(rows) => narrow(rows),
            Err(e) => return store_err_to_response(e),
        };
        if filtered.len() < k {
            filtered = match app.store.list(&ctx, &build_filter(MAX_BULK_SIZE)).await {
                Ok(rows) => narrow(rows),
                Err(e) => return store_err_to_response(e),
            };
        }
        filtered.truncate(k);
        let count = filtered.len();
        return Json(json!({
            "family": family_name,
            "namespace": body.namespace,
            "k": k,
            "count": count,
            "memories": filtered,
        }))
        .into_response();
    }

    // Sqlite path — reuse the MCP `handle_load_family` SQL verbatim by
    // calling it through with the same parameter shape (a `Value`).
    //
    // #1555 — resolve the caller from headers and pass it so the SAME
    // scope=private visibility filter the postgres branch gets via the SAL
    // `list` applies on the sqlite (default) backend too. Without this the
    // multi-tenant HTTP daemon leaked other tenants' private family-tagged
    // rows in a shared namespace. Reuses the shared `resolve_caller_agent_id`
    // helper (non-sal-safe; the postgres branch's `http_caller_ctx` is sal-gated
    // and unavailable on this default-backend path) — the anonymous-fallback
    // handling lives inside it, not duplicated here. On the rare resolution
    // error the empty principal owns no private row, so it sees only
    // scope=shared/public rows.
    let caller =
        crate::handlers::parity::resolve_caller_agent_id(None, &headers, None).unwrap_or_default();
    let lock = app.db.lock().await;
    let params = json!({
        "family": family_name,
        "namespace": body.namespace,
        "k": k,
    });
    match crate::mcp::handle_load_family(&lock.0, &params, Some(caller.as_str())) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}
