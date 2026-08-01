// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP `POST /api/v1/memories/bulk` — the fleet write surface.
//!
//! Extracted from [`super::memories_query`] by #2550/#2551/#2552/#2588/#2594,
//! which were five symptoms of ONE root cause: `bulk_create`
//! **re-implemented** the single-create funnel instead of calling it, and each
//! issue is a different stage the re-implementation omitted.
//!
//! | issue | omitted stage |
//! |---|---|
//! | #2550 | field resolution — caller `scope` and `kind_provenance` dropped |
//! | #2552 | error mapping — every row error collapsed to `"validation failed"` |
//! | #2594 | embedding — zero references to `app.embedder` on either backend |
//! | #2551 | accounting — `created` counted rows SENT, not rows PERSISTED |
//! | #2588 | exit discipline — a total quota rollback returned HTTP 200 |
//!
//! The fix is structural, not five patches: the per-row projection now routes
//! through [`crate::handlers::create::resolve_create_metadata`] +
//! [`crate::handlers::create::build_create_memory`], the same two functions the
//! single-create sqlite and postgres branches call. A field added there reaches
//! all four funnels for free; it can no longer be honoured on one and silently
//! dropped on another.
//!
//! # Response envelope (#2551 / #2552)
//!
//! ```json
//! {
//!   "sent": 3, "created": 1, "updated": 0, "deduped": 1, "rejected": 1,
//!   "errors":       [{"index": 2, "code": "VALIDATION_FAILED",
//!                     "field": "create", "error": "validation failed"}],
//!   "deduped_rows": [{"index": 0, "superseded_by": 1}],
//!   "pending":      [],
//!   "warnings":     []
//! }
//! ```
//!
//! The reconciliation identity a fleet loader asserts on is
//! `created + updated + deduped + rejected + pending.len() == sent`.
//! `created` counts rows this call INSERTED and `updated` counts rows it
//! upserted onto an already-existing `(title, namespace)`; both are persisted,
//! and `created + updated` is the number of distinct rows the batch wrote.
//! `deduped` counts input rows whose content is NOT what is stored because a
//! LATER row in the same batch shared their `(title, namespace)` — an in-batch
//! collapse is a **result the caller must be told about**, not a silent
//! success, so each one is additionally addressable by input index in
//! `deduped_rows[]`.
//!
//! `warnings[]` is deliberately SEPARATE from `errors[]`: a post-commit
//! federation quorum/catchup failure means the row IS durable locally
//! (ADR-0001 never rolls a local commit back on a quorum miss), so folding it
//! into `errors[]` — as the pre-#2551 code did — made `rejected` unreconcilable
//! and would have made the response status a function of peer reachability on a
//! fully-persisted batch.

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;

use crate::db;
use crate::embeddings::EmbedStatus;
use crate::models::field_names;
use crate::models::{CreateMemory, Memory};
use crate::validate;

use super::AppState;
use super::BULK_FANOUT_CONCURRENCY;
#[cfg(feature = "sal")]
use super::StorageBackend;
use super::create::{build_create_memory, resolve_create_caller, resolve_create_metadata};
use super::errors::{BulkRowErrorClass, classify_bulk_row_error};

/// #2594 — how many rows are handed to `Embedder::embed_batch` per call.
///
/// The whole batch in ONE call would post up to `max_page_size` (default 1000)
/// documents to a vendor endpoint in a single request; chunking keeps each
/// round trip bounded while still collapsing N single-row calls into N/100.
/// Mirrors the compiled default of the paced backfill sweep
/// (`AI_MEMORY_EMBED_BACKFILL_BATCH`, env #38) so the two vectorisation paths
/// pace identically.
const BULK_EMBED_CHUNK: usize = 100;

/// #2588 — the `tracing` target for the one-per-call bulk summary line.
///
/// Pre-#2588 a bulk call that rejected every row emitted NOTHING at any log
/// level, so an operator correlating a lost corpus load had no server-side
/// trace at all. One line per CALL (never per row) so a 1000-row rejection
/// cannot flood the log.
const BULK_TRACE_TARGET: &str = "bulk_create";

// ---------------------------------------------------------------------------
// #2551 / #2552 — the per-row outcome ledger.
// ---------------------------------------------------------------------------

/// #2551 / #2552 / #2588 — accumulates the truthful per-row outcome of a bulk
/// write and renders the response envelope + HTTP status.
///
/// Every counter is DERIVED from an observed per-row outcome. In particular
/// `created` is never `allowed.len()` — that was exactly the #2551 defect,
/// where the handler reused `store_batch`'s input-arity id vector as a
/// persisted-row count and reported 7,912 created for 7,855 landed.
struct BulkLedger {
    sent: usize,
    created: usize,
    updated: usize,
    errors: Vec<serde_json::Value>,
    deduped_rows: Vec<serde_json::Value>,
    pending: Vec<serde_json::Value>,
    warnings: Vec<&'static str>,
    /// Highest-precedence rejection class seen, for the whole-request status.
    worst: Option<BulkRowErrorClass>,
    embed_status: EmbedStatus,
}

impl BulkLedger {
    fn new(sent: usize) -> Self {
        Self {
            sent,
            created: 0,
            updated: 0,
            errors: Vec::new(),
            deduped_rows: Vec::new(),
            pending: Vec::new(),
            warnings: Vec::new(),
            worst: None,
            embed_status: EmbedStatus::Indexed,
        }
    }

    /// #2552 — record a per-row rejection with its INPUT INDEX, its
    /// server-authored `field`, and a machine-readable `code`.
    ///
    /// `raw` is the underlying error text; only its #851 sanitized
    /// classification reaches the wire. The full detail is logged so operators
    /// can still debug.
    fn reject(&mut self, index: usize, field: &str, raw: &str) {
        let class = classify_bulk_row_error(raw);
        tracing::warn!(
            target: BULK_TRACE_TARGET,
            row = index,
            code = class.code,
            "bulk_create: row rejected: {raw}"
        );
        let mut entry = json!({
            "index": index,
            "code": class.code,
            "error": class.label,
        });
        // #2552 (security amendment) — `field` is echoed ONLY when it has the
        // server-authored slug SHAPE. `ValidationError::field` is a closed set
        // authored in `src/validate.rs`, but a shape guard at the serializer
        // means no future refactor can route caller-influenced text through
        // this channel and re-open the #851 leak class.
        if let Some(obj) = entry.as_object_mut()
            && is_server_authored_field(field)
        {
            obj.insert("field".to_string(), json!(field));
        }
        self.errors.push(entry);
        if self
            .worst
            .is_none_or(|w| status_precedence(&class) < status_precedence(&w))
        {
            self.worst = Some(class);
        }
    }

    /// #2551 — record an input row whose content was superseded, within this
    /// same request, by a LATER row sharing its `(title, namespace)`.
    fn dedupe(&mut self, index: usize, superseded_by: usize) {
        self.deduped_rows
            .push(json!({ "index": index, "superseded_by": superseded_by }));
    }

    /// Record a post-commit replication failure. The row IS durable locally,
    /// so this is a WARNING, never a rejection (see the module docs).
    fn warn(&mut self, raw: &str) {
        let class = classify_bulk_row_error(raw);
        tracing::warn!(target: BULK_TRACE_TARGET, "bulk_create: {raw}");
        if !self.warnings.contains(&class.label) {
            self.warnings.push(class.label);
        }
    }

    fn deduped(&self) -> usize {
        self.deduped_rows.len()
    }

    fn rejected(&self) -> usize {
        self.errors.len()
    }

    /// Rows this call durably wrote (inserted + upserted).
    fn persisted(&self) -> usize {
        self.created + self.updated
    }

    /// #2588 — the whole-request HTTP status.
    ///
    /// * every input row landed as its own distinct row -> `200 OK`
    /// * NOTHING persisted and rows were rejected -> the dominant cause's
    ///   typed status (`429` quota / `503` replication / `500` internal /
    ///   `403` governance / `409` conflict / `400` validation). Pre-#2588 this
    ///   returned `200` with `created: 0` — 31,000 rows were lost behind it.
    /// * every row queued for governance approval -> `202 ACCEPTED`, matching
    ///   the single-create `Pending` contract
    /// * anything else (a genuinely PARTIAL application) -> `207 Multi-Status`
    ///
    /// 207 is deliberately 2xx: the batch is not idempotent for rows whose
    /// title the substrate rewrote, so a 4xx on a partial fill would arm
    /// retry middleware to replay writes that already landed.
    fn status(&self) -> StatusCode {
        if self.rejected() == 0 && self.deduped() == 0 && self.pending.is_empty() {
            return StatusCode::OK;
        }
        if self.persisted() == 0 && self.pending.is_empty() {
            return self
                .worst
                .map_or(StatusCode::INTERNAL_SERVER_ERROR, |c| c.status);
        }
        if self.persisted() == 0 && self.rejected() == 0 && self.deduped() == 0 {
            return StatusCode::ACCEPTED;
        }
        StatusCode::MULTI_STATUS
    }

    fn into_response(self) -> axum::response::Response {
        let status = self.status();
        let (deduped, rejected) = (self.deduped(), self.rejected());
        if status != StatusCode::OK {
            // #2588 item 3 — ONE structured summary line per call.
            tracing::warn!(
                target: BULK_TRACE_TARGET,
                sent = self.sent,
                created = self.created,
                updated = self.updated,
                deduped,
                rejected,
                pending = self.pending.len(),
                status = status.as_u16(),
                dominant_cause = self.worst.map_or("", |c| c.code),
                "bulk_create: batch did not fully apply",
            );
        }
        let mut body = json!({
            "sent": self.sent,
            // #2551 — rows this call INSERTED. Pre-#2551 this field carried
            // the number of rows SENT, which is why 7,912 was reported for
            // 7,855 landed.
            "created": self.created,
            "updated": self.updated,
            "deduped": deduped,
            "rejected": rejected,
            "errors": self.errors,
            // #2551 — emitted on BOTH backends. The sqlite branch historically
            // omitted `pending` entirely, so the same batch produced a
            // different envelope shape per backend.
            "pending": self.pending,
        });
        if let Some(obj) = body.as_object_mut() {
            if !self.deduped_rows.is_empty() {
                obj.insert("deduped_rows".to_string(), json!(self.deduped_rows));
            }
            if !self.warnings.is_empty() {
                obj.insert("warnings".to_string(), json!(self.warnings));
            }
            // #2594 — the bulk envelope now carries the same embed truthfulness
            // the single-create response has always carried, so a caller can
            // tell that a stored row is not yet semantically recallable.
            if self.embed_status.is_degraded() {
                obj.insert(
                    "embed_status".to_string(),
                    json!(self.embed_status.as_str()),
                );
                let reason = self.embed_status.reason();
                if !reason.is_empty() {
                    obj.insert("embed_status_reason".to_string(), json!(reason));
                }
            }
        }
        (status, Json(body)).into_response()
    }
}

/// #2552 — shape guard for the echoed `field` attribution (see
/// [`BulkLedger::reject`]).
fn is_server_authored_field(field: &str) -> bool {
    !field.is_empty()
        && field.len() <= 64
        && field
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
}

/// #2588 — rejection-cause precedence for the whole-request status when
/// NOTHING was persisted. LOWER wins.
///
/// A count-majority "dominant cause" is unsound: 300 quota-rejected rows plus
/// 200 invalid rows would report `400`, telling a fleet loader "never retry"
/// and permanently dropping the 300 rows that were merely throttled. RETRYABLE
/// causes therefore outrank permanent ones unconditionally.
fn status_precedence(class: &BulkRowErrorClass) -> u8 {
    use crate::errors::error_codes as codes;
    match class.code {
        codes::QUOTA_EXCEEDED => 0,
        codes::REPLICATION_UNAVAILABLE => 1,
        codes::INTERNAL_ERROR => 2,
        codes::GOVERNANCE_REFUSED => 3,
        codes::CONFLICT => 4,
        codes::NOT_FOUND => 5,
        _ => 6,
    }
}

// ---------------------------------------------------------------------------
// #2551 — persisted-row classification.
// ---------------------------------------------------------------------------

/// One input row that cleared every pre-write gate and was handed to the
/// persist stage.
struct PreparedRow {
    /// Position in the caller's submitted array — the only handle a fleet
    /// loader has to correlate an outcome back to its source record (#2552).
    index: usize,
    mem: Memory,
    /// #1919 — per-row attestation fields, captured before `mem` is built.
    signature: Option<String>,
    signed_created_at: Option<String>,
    /// #2594 — the vector computed for this row before any DB lock was taken.
    embedding: Option<Vec<f32>>,
}

/// #2551 — classify persisted rows into created / updated / deduped.
///
/// `outcomes` is `(input_index, minted_id, returned_id)` in SUBMISSION ORDER.
///
/// Both backends omit `id` from their `ON CONFLICT DO UPDATE SET` list
/// (`src/store/postgres.rs` `store_batch`; `src/storage/mod.rs` `insert`), so
/// `RETURNING id` yields the PRE-EXISTING row's id on a conflict and the
/// freshly-minted `Uuid::new_v4()` on a true insert. `returned == minted` is
/// therefore an exact, zero-round-trip insert-vs-update discriminator.
///
/// Rows that share a returned id were collapsed by the upsert. The persist
/// funnels keep the LAST occurrence of each `(title, namespace)` — postgres by
/// explicit pre-INSERT dedup, sqlite by sequential upsert — so the last input
/// position in a group is the one whose content is durable and every earlier
/// position is DEDUPED. The grouping key is the RETURNED ID, never a
/// recomputed `(title, namespace)`: both funnels may rewrite `title` (secret
/// screening / redaction) before the dedup key is taken, so a handler-side key
/// recomputation would silently drift from the SAL.
fn classify_persisted(outcomes: &[(usize, String, String)], ledger: &mut BulkLedger) {
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (idx, minted, returned) in outcomes {
        if let Some(entry) = groups.iter_mut().find(|(id, _)| id == returned) {
            entry.1.push(*idx);
        } else {
            groups.push((returned.clone(), vec![*idx]));
        }
        let _ = minted;
    }
    for (returned, members) in &groups {
        // At most ONE input row can have minted the surviving id, so this
        // answers "did THIS call create the row?" for the whole group.
        let created = outcomes
            .iter()
            .any(|(idx, minted, ret)| members.contains(idx) && ret == returned && minted == ret);
        if created {
            ledger.created += 1;
        } else {
            ledger.updated += 1;
        }
        if let Some((&survivor, superseded)) = members.split_last() {
            for &idx in superseded {
                ledger.dedupe(idx, survivor);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// #2594 — embed-before-lock for the whole batch.
// ---------------------------------------------------------------------------

/// #2594 — compute one vector per prepared row BEFORE any DB lock is taken.
///
/// Pre-#2594 `bulk_create` contained zero references to `app.embedder` on
/// either backend, so a caller who ingested 100k rows in bulk got a success
/// envelope and a corpus that returned nothing from semantic recall until the
/// paced backfill sweep caught up — and in an MCP-stdio or CLI-only topology
/// (no `serve` daemon) that sweep never runs at all. Single-create has always
/// embedded inline; this closes the asymmetry.
///
/// Uses `Embedder::embed_batch` so a 1000-row ingest costs `ceil(N/100)` vendor
/// round trips rather than N. A failure DEGRADES (rows are still written — the
/// durable memory TEXT is the source of truth and vectors are regenerable
/// derived data) and is reported truthfully via `embed_status`.
fn embed_bulk_rows(
    app: &AppState,
    rows: &mut [PreparedRow],
    ledger: &mut BulkLedger,
) -> Option<String> {
    let Some(emb) = app.embedder.as_ref().as_ref() else {
        return None;
    };
    if rows.is_empty() {
        return None;
    }
    let space = emb.space_fingerprint();
    let mut degraded: Option<String> = None;
    for chunk_start in (0..rows.len()).step_by(BULK_EMBED_CHUNK) {
        let chunk_end = (chunk_start + BULK_EMBED_CHUNK).min(rows.len());
        let docs: Vec<String> = rows[chunk_start..chunk_end]
            .iter()
            .map(|r| crate::embeddings::embedding_document(&r.mem.title, &r.mem.content))
            .collect();
        let refs: Vec<&str> = docs.iter().map(String::as_str).collect();
        match emb.embed_batch(&refs) {
            Ok(vectors) if vectors.len() == refs.len() => {
                for (row, vector) in rows[chunk_start..chunk_end].iter_mut().zip(vectors) {
                    row.embedding = Some(vector);
                }
            }
            Ok(vectors) => {
                // Arity mismatch: refuse to guess which row each vector
                // belongs to. Mis-attributing a vector would make recall
                // return WRONG results, which the North Star ranks strictly
                // worse than returning fewer.
                let reason = format!(
                    "embedder returned {} vectors for {} inputs",
                    vectors.len(),
                    refs.len()
                );
                tracing::warn!(target: BULK_TRACE_TARGET, "bulk_create: {reason}");
                degraded = Some(reason);
            }
            Err(e) => {
                let reason = e.to_string();
                tracing::warn!(target: BULK_TRACE_TARGET, "bulk_create: embed_batch failed: {reason}");
                degraded = Some(reason);
            }
        }
    }
    if let Some(reason) = degraded {
        ledger.embed_status = EmbedStatus::Failed(reason);
    }
    Some(space)
}

// ---------------------------------------------------------------------------
// The handler.
// ---------------------------------------------------------------------------

pub async fn bulk_create(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(bodies): Json<Vec<CreateMemory>>,
) -> impl IntoResponse {
    if bodies.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": format!("bulk operations limited to {} items", app.max_page_size)}),
            ),
        )
            .into_response();
    }
    let now = Utc::now();
    let mut ledger = BulkLedger::new(bodies.len());

    // #910 SAL-level — resolve the caller ONCE so the per-row metadata stamp
    // matches the authenticated principal. Header-only authentication;
    // anonymous callers stamp `anonymous:req-<uuid>`.
    let caller =
        resolve_create_caller(&headers).unwrap_or_else(|_| crate::identity::anonymous_request_id());

    // #1919 (CWE-288 / CWE-345) — bulk_create MUST enforce the SAME
    // required-agent-attestation gate (#1751) that single-create enforces.
    // Fail the WHOLE batch (403 ATTESTATION_FAILED, BEFORE any persistence or
    // fanout) when required-attestation is on and ANY row is unsigned. Per-row
    // signature VERIFICATION is applied inside each backend loop below.
    // #1985 — `/memories/bulk` is an HTTP direct-write endpoint, so it
    // classifies as `WriteSurface::HttpDirect`: required by default.
    let require_attest = crate::identity::attest::require_agent_attestation_for(
        crate::identity::attest::WriteSurface::HttpDirect,
    );
    if require_attest
        && bodies.iter().any(|b| {
            b.signature
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        })
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "code": crate::errors::error_codes::ATTESTATION_FAILED,
                "error": "bulk_create requires every row to carry an agent-attestation \
                          signature when AI_MEMORY_REQUIRE_AGENT_ATTESTATION is set",
            })),
        )
            .into_response();
    }

    // N8 (#2389, CWE-288) — consult the PRE-STORE enforcement gate ONCE for the
    // whole batch BEFORE any write, so `[hooks].enforce_mode = enforce` +
    // `required_events = ["pre_store"]` with no enabled hook DENIES the bulk
    // write (503) exactly as it does on the single-create path (#1924) and the
    // MCP path (#1885). The gate is a content-invariant PRESENCE check, so ONE
    // per-request consult is exact parity with single-create.
    // #2390 (N9) — every distinct namespace in the batch contributes so a hook
    // scoped to ANY of them fires. INERT for default (enforce-off) deployments.
    let mut bulk_namespaces: Vec<String> = Vec::new();
    for b in &bodies {
        if !bulk_namespaces.contains(&b.namespace) {
            bulk_namespaces.push(b.namespace.clone());
        }
    }
    if let Some(resp) = super::create::http_pre_event_gate(
        crate::hooks::HookEvent::PreStore,
        bulk_namespaces,
        json!({
            "agent_id": caller,
            "bulk": true,
            "count": bodies.len(),
        }),
    ) {
        return resp;
    }

    // v0.9.0 G10.1 (#1827) — edge-parse the optional `X-AI-Memory-Capability`
    // header ONCE; the same token gates every row in the batch.
    let capability = super::capability_from_headers(&headers, &caller);

    // ---- Stage 1 (NO DB LOCK) — validate + project every row. --------------
    //
    // #2550 — the projection routes through the SHARED create funnel, so
    // `scope`, `kind_provenance` and every other field resolve exactly as they
    // do on `POST /memories`.
    // #1911 — `ResolvedTtl` lives in the `app.db` mutex tuple (populated on
    // BOTH backends); snapshot it ONCE rather than re-locking per row.
    let resolved_ttl = app.db.lock().await.2.clone();
    let mut prepared: Vec<PreparedRow> = Vec::with_capacity(bodies.len());
    for (index, body) in bodies.iter().enumerate() {
        if let Err(e) = validate::RequestValidator::validate_create(body) {
            ledger.reject(index, &e.field, &e.to_string());
            continue;
        }
        let metadata = match resolve_create_metadata(&caller, body) {
            Ok(m) => m,
            Err(e) => {
                ledger.reject(index, e.field, &e.message);
                continue;
            }
        };
        let expires_at = crate::handlers::parity::resolve_create_expires_at(
            now,
            body.expires_at.clone(),
            body.ttl_secs,
            resolved_ttl.ttl_for_tier(&body.tier),
        );
        let mem = build_create_memory(
            body,
            metadata,
            body.title.clone(),
            body.tags.clone(),
            expires_at,
            &now,
        );
        prepared.push(PreparedRow {
            index,
            mem,
            signature: body.signature.clone(),
            signed_created_at: body.created_at.clone(),
            embedding: None,
        });
    }

    // ---- Stage 2 (NO DB LOCK) — embed (#2594, #219 embed-before-lock). -----
    let embedding_space = embed_bulk_rows(&app, &mut prepared, &mut ledger);

    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return bulk_create_postgres(
            &app,
            &headers,
            &caller,
            capability.as_ref(),
            require_attest,
            prepared,
            embedding_space,
            ledger,
        )
        .await;
    }

    bulk_create_sqlite(
        &app,
        &caller,
        capability.as_ref(),
        require_attest,
        prepared,
        embedding_space,
        ledger,
    )
    .await
}

/// Sqlite persist stage.
///
/// #2550-cluster note: this branch additionally gained the namespace-GOVERNANCE
/// consult it never had. The postgres bulk branch has enforced it since
/// F-A2A1.5 (#705) and single-create enforces it on both backends
/// (`create::enforce_create_governance`), but the sqlite bulk branch went
/// straight from the quota check to `db::insert` — the same
/// re-implementation-omits-a-stage root cause as the five filed issues, on the
/// security-most-relevant stage of the funnel.
async fn bulk_create_sqlite(
    app: &AppState,
    caller: &str,
    capability: Option<&crate::governance::capability::CapabilityToken>,
    require_attest: bool,
    prepared: Vec<PreparedRow>,
    embedding_space: Option<String>,
    mut ledger: BulkLedger,
) -> axum::response::Response {
    use crate::models::{GovernanceDecision, GovernedAction};

    let mut outcomes: Vec<(usize, String, String)> = Vec::new();
    let mut committed: Vec<(Memory, Option<Vec<f32>>)> = Vec::new();
    {
        let lock = app.db.lock().await;
        for mut row in prepared {
            // #1919 (CWE-288) — per-row agent attestation, mirroring the
            // single-create sqlite gate. A forged / unverifiable signature (or,
            // under required-attestation, an unsigned row — already
            // batch-rejected above, kept here as a fail-closed backstop)
            // REJECTS the row so it is never persisted or fanned out.
            if let Some(sig_b64) = row
                .signature
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                match crate::identity::attest::prepare_signed_store(
                    sig_b64,
                    row.signed_created_at.as_deref(),
                ) {
                    Ok((sig_bytes, signed_created_at)) => {
                        row.mem.created_at = signed_created_at.to_string();
                        // #1801→#1954 item 4 — redact to storage form BEFORE
                        // the gate verifies (and before EMIT) so the signed
                        // bytes equal the persisted bytes.
                        crate::identity::attest::redact_before_sign(&mut row.mem);
                        if let Err(e) = crate::identity::attest::stamp_attestation_sync(
                            &lock.0,
                            &mut row.mem,
                            caller,
                            Some(&sig_bytes),
                            crate::identity::attest::WriteSurface::HttpDirect,
                        ) {
                            ledger.reject(row.index, "signature", &e.to_string());
                            continue;
                        }
                        // #1801→#1954 item 2 — sender EMIT so the author's
                        // signature propagates verbatim across relay hops.
                        crate::identity::attest::persist_write_signature(&mut row.mem, &sig_bytes);
                    }
                    Err(msg) => {
                        ledger.reject(row.index, "signature", &msg);
                        continue;
                    }
                }
            } else if require_attest
                && let Err(e) = crate::identity::attest::stamp_attestation_sync(
                    &lock.0,
                    &mut row.mem,
                    caller,
                    None,
                    crate::identity::attest::WriteSurface::HttpDirect,
                )
            {
                ledger.reject(row.index, "signature", &e.to_string());
                continue;
            }

            // Namespace governance — sqlite parity with the postgres bulk
            // branch (F-A2A1.5 #705) and with single-create.
            let agent_for_gov = row
                .mem
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or(crate::identity::sentinels::DAEMON_PRINCIPAL);
            // #2356 (W1A6-03) — `pre_governance_decision` presence consult
            // BEFORE the per-row governance decision dispatches.
            if let Err(reason) = crate::mcp::consult_pre_governance_decision_gate(
                &row.mem.namespace,
                "store",
                agent_for_gov,
                None,
            ) {
                ledger.reject(row.index, "namespace", &reason);
                continue;
            }
            let payload = serde_json::to_value(&row.mem).unwrap_or_else(|_| json!({}));
            match db::enforce_governance(
                &lock.0,
                GovernedAction::Store,
                &row.mem.namespace,
                agent_for_gov,
                None,
                None,
                &payload,
                capability,
            ) {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    ledger.reject(
                        row.index,
                        "namespace",
                        &format!("denied by governance: {}", refusal.reason),
                    );
                    continue;
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    ledger.pending.push(json!({
                        "index": row.index,
                        "title": row.mem.title,
                        "namespace": row.mem.namespace,
                        (field_names::PENDING_ID): pending_id,
                    }));
                    continue;
                }
                Err(e) => {
                    ledger.reject(row.index, "namespace", &e.to_string());
                    continue;
                }
            }

            // #1788 (5-agent vote 4d3ea1c5) — charge the per-agent daily write
            // quota PER ROW so the bulk surface is not a quota-bypass
            // amplifier. A row that would exceed the cap is rejected and NOT
            // persisted (partial fill).
            let quota_op = crate::quotas::QuotaOp::Memory {
                bytes: memory_quota_bytes(&row.mem),
            };
            if !caller.is_empty()
                && let Err(e) =
                    crate::quotas::check_and_record(&lock.0, caller, &row.mem.namespace, quota_op)
            {
                match e {
                    crate::quotas::QuotaCheckError::Quota(qe) => {
                        ledger.reject(row.index, "quota", &qe.to_string());
                    }
                    crate::quotas::QuotaCheckError::Sql(se) => {
                        tracing::error!("bulk_create: quota substrate error: {se}");
                        ledger.reject(row.index, "quota", crate::errors::msg::QUOTA_CHECK_FAILED);
                    }
                }
                continue;
            }

            match db::insert(&lock.0, &row.mem) {
                Ok(returned_id) => {
                    // Issue #219 parity — persist the vector so semantic recall
                    // can find this row immediately (#2594).
                    if let (Some(vec), Some(space)) = (row.embedding.as_ref(), &embedding_space)
                        && let Err(e) = db::set_embedding(&lock.0, &returned_id, vec, space)
                    {
                        tracing::warn!("failed to store embedding for {returned_id}: {e}");
                    }
                    outcomes.push((row.index, row.mem.id.clone(), returned_id));
                    committed.push((row.mem, row.embedding));
                }
                Err(e) => {
                    // #1788 — refund the quota charge since the insert failed.
                    if !caller.is_empty()
                        && let Err(re) = crate::quotas::refund_op(
                            &lock.0,
                            caller,
                            &row.mem.namespace,
                            crate::quotas::QuotaOp::Memory {
                                bytes: memory_quota_bytes(&row.mem),
                            },
                        )
                    {
                        crate::quotas::log_refund_op_failed(caller, &re);
                    }
                    ledger.reject(row.index, "store", &e.to_string());
                }
            }
        }
    }
    classify_persisted(&outcomes, &mut ledger);

    // #2594 — HNSW warm-up AFTER the DB lock drops, mirroring single-create.
    if !committed.is_empty() {
        let mut idx_lock = app.vector_index.lock().await;
        if let Some(idx) = idx_lock.as_mut() {
            for (mem, embedding) in &committed {
                if let Some(vec) = embedding {
                    idx.insert(mem.id.clone(), vec.clone());
                }
            }
        }
    }

    // Stage 3 — federation fanout, once per successfully-inserted row, bounded
    // by `BULK_FANOUT_CONCURRENCY` so 500 rows x 3 peers cannot exhaust the
    // reqwest connection pool. A quorum miss does NOT abort the other rows
    // (bulk semantics, deliberately weaker than `create_memory`'s 503
    // short-circuit) and lands in `warnings[]`, never `errors[]` — the local
    // commit is durable (ADR-0001).
    let committed_mems: Vec<Memory> = committed.into_iter().map(|(mem, _)| mem).collect();
    if let Some(fed) = app.federation.as_ref() {
        let sem = Arc::new(tokio::sync::Semaphore::new(BULK_FANOUT_CONCURRENCY));
        let mut joins: tokio::task::JoinSet<(String, Result<(), String>)> =
            tokio::task::JoinSet::new();
        for mem in &committed_mems {
            let fed = fed.clone();
            let mem = mem.clone();
            let sem = sem.clone();
            joins.spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    return (mem.id.clone(), Err("fanout semaphore closed".to_string()));
                };
                let id = mem.id.clone();
                let outcome = match crate::federation::broadcast_store_quorum(&fed, &mem).await {
                    Ok(tracker) => match crate::federation::finalise_quorum(&tracker) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(err.to_string()),
                    },
                    Err(e) => {
                        tracing::warn!(
                            "bulk_create: fanout for {id} failed (local committed): {e:?}"
                        );
                        Ok(())
                    }
                };
                (id, outcome)
            });
        }
        while let Some(res) = joins.join_next().await {
            match res {
                Ok((id, Err(err))) => ledger.warn(&format!("fanout for {id}: {err}")),
                Ok((_, Ok(()))) => {}
                Err(e) => tracing::warn!("bulk_create: fanout task join error: {e:?}"),
            }
        }

        // v0.6.2 Patch 2 (S40): terminal catchup batch — one batched
        // `sync_push` per peer with every committed row closes the
        // eventual-consistency gap the per-row retry can leave.
        if !committed_mems.is_empty() {
            let catchup_errors = crate::federation::bulk_catchup_push(fed, &committed_mems).await;
            for (peer_id, err) in catchup_errors {
                ledger.warn(&format!("catchup to peer {peer_id}: {err}"));
            }
        }
    }
    ledger.into_response()
}

/// Postgres persist stage — the surviving rows land in ONE multi-row INSERT
/// via `store_batch` (#1481).
#[cfg(feature = "sal")]
async fn bulk_create_postgres(
    app: &AppState,
    headers: &HeaderMap,
    caller: &str,
    capability: Option<&crate::governance::capability::CapabilityToken>,
    require_attest: bool,
    prepared: Vec<PreparedRow>,
    embedding_space: Option<String>,
    mut ledger: BulkLedger,
) -> axum::response::Response {
    use crate::models::GovernanceDecision;

    let _ = headers;
    let ctx = crate::store::CallerContext::for_agent(caller.to_string())
        .with_capability(capability.cloned());

    let mut allowed: Vec<PreparedRow> = Vec::with_capacity(prepared.len());
    for mut row in prepared {
        // #1919 (CWE-288) — per-row agent attestation (postgres twin).
        if let Some(sig_b64) = row
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match crate::identity::attest::prepare_signed_store(
                sig_b64,
                row.signed_created_at.as_deref(),
            ) {
                Ok((sig_bytes, signed_created_at)) => {
                    row.mem.created_at = signed_created_at.to_string();
                    crate::identity::attest::redact_before_sign(&mut row.mem);
                    if let Err(e) = crate::identity::attest::stamp_attestation_async(
                        app.store.as_ref(),
                        &mut row.mem,
                        caller,
                        Some(&sig_bytes),
                        crate::identity::attest::WriteSurface::HttpDirect,
                    )
                    .await
                    {
                        ledger.reject(row.index, "signature", &e.to_string());
                        continue;
                    }
                    crate::identity::attest::persist_write_signature(&mut row.mem, &sig_bytes);
                }
                Err(msg) => {
                    ledger.reject(row.index, "signature", &msg);
                    continue;
                }
            }
        } else if require_attest
            && let Err(e) = crate::identity::attest::stamp_attestation_async(
                app.store.as_ref(),
                &mut row.mem,
                caller,
                None,
                crate::identity::attest::WriteSurface::HttpDirect,
            )
            .await
        {
            ledger.reject(row.index, "signature", &e.to_string());
            continue;
        }

        // F-A2A1.5 (#705) — namespace governance, per row.
        let agent_id = row
            .mem
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or(crate::identity::sentinels::DAEMON_PRINCIPAL)
            .to_string();
        // #2356 (W1A6-03) — presence consult before the decision dispatches.
        if let Err(reason) = crate::mcp::consult_pre_governance_decision_gate(
            &row.mem.namespace,
            "store",
            &agent_id,
            None,
        ) {
            ledger.reject(row.index, "namespace", &reason);
            continue;
        }
        let payload = serde_json::to_value(&row.mem).unwrap_or_else(|_| json!({}));
        match app
            .store
            .enforce_governance_action(
                crate::store::GovernedAction::Store,
                &row.mem.namespace,
                &agent_id,
                None,
                None,
                &payload,
                ctx.capability.as_ref(),
            )
            .await
        {
            Ok(GovernanceDecision::Allow) => {}
            Ok(GovernanceDecision::Deny(refusal)) => {
                ledger.reject(
                    row.index,
                    "namespace",
                    &format!("denied by governance: {}", refusal.reason),
                );
                continue;
            }
            Ok(GovernanceDecision::Pending(pending_id)) => {
                ledger.pending.push(json!({
                    "index": row.index,
                    "title": row.mem.title,
                    "namespace": row.mem.namespace,
                    (field_names::PENDING_ID): pending_id,
                }));
                continue;
            }
            Err(e) => {
                ledger.reject(row.index, "namespace", &e.to_string());
                continue;
            }
        }

        // #1795 (5-agent vote 4d3ea1c5) — per-agent daily write quota with
        // PARTIAL-FILL parity to the sqlite branch. `check_memory_quota` is a
        // pure read (the batched `store_batch` records later), so the
        // cumulative count is `already-allowed + this row`.
        let pending_count = i64::try_from(allowed.len())
            .unwrap_or(i64::MAX)
            .saturating_add(1);
        if let Err(e) = app
            .store
            .check_memory_quota(
                &ctx,
                &row.mem.namespace,
                pending_count,
                memory_quota_bytes(&row.mem),
            )
            .await
        {
            ledger.reject(row.index, "quota", &e.to_string());
            continue;
        }

        allowed.push(row);
    }

    let mut outcomes: Vec<(usize, String, String)> = Vec::new();
    if !allowed.is_empty() {
        let memories: Vec<Memory> = allowed.iter().map(|r| r.mem.clone()).collect();
        match app.store.store_batch(&ctx, &memories).await {
            Ok(ids) if ids.len() == allowed.len() => {
                for (row, returned) in allowed.iter().zip(ids.iter()) {
                    outcomes.push((row.index, row.mem.id.clone(), returned.clone()));
                }
                // #2594 — stamp the vectors for the rows that actually landed.
                // The batch is atomic, so this runs only on a committed batch.
                if let Some(space) = embedding_space.as_deref() {
                    let entries: Vec<(String, Vec<f32>)> = allowed
                        .iter()
                        .zip(ids.iter())
                        .filter_map(|(row, id)| {
                            row.embedding.as_ref().map(|v| (id.clone(), v.clone()))
                        })
                        .collect();
                    if !entries.is_empty()
                        && let Err(e) = app.store.set_embeddings_batch(&ctx, &entries, space).await
                    {
                        // Degrade, never fail: the durable TEXT landed and the
                        // paced backfill sweep regenerates the vectors.
                        tracing::warn!("bulk_create(postgres): set_embeddings_batch failed: {e}");
                        ledger.embed_status =
                            EmbedStatus::Failed("embedding vectors were not persisted".to_string());
                    }
                }
            }
            Ok(ids) => {
                // A returned vector that is not 1:1 with the input would make
                // every per-row outcome a guess. Refuse to guess.
                let detail = format!(
                    "store_batch returned {} ids for {} rows",
                    ids.len(),
                    allowed.len()
                );
                tracing::error!("bulk_create(postgres): {detail}");
                for row in &allowed {
                    ledger.reject(row.index, "store", &detail);
                }
            }
            Err(e) => {
                // #2588 — the batch is ATOMIC: a quota breach (or any other
                // failure) inside `store_batch` rolls the WHOLE transaction
                // back, so EVERY allowed row was lost. Pre-#2588 this pushed
                // ONE opaque `"internal error"` string and still returned
                // HTTP 200 — 31,000 rows were dropped behind exactly that
                // shape. Every lost row now gets its own typed, indexed
                // rejection, and `BulkLedger::status` turns the total loss
                // into the dominant cause's status (429 for quota).
                let detail = e.to_string();
                tracing::warn!("bulk_create(postgres): store_batch failed: {detail}");
                for row in &allowed {
                    ledger.reject(row.index, "store", &detail);
                }
            }
        }
    }
    classify_persisted(&outcomes, &mut ledger);
    ledger.into_response()
}

/// Shared quota byte-count: `title + content + serialized metadata`, the same
/// shape the MCP and single-create paths use so cross-path totals stay
/// coherent.
fn memory_quota_bytes(mem: &Memory) -> i64 {
    i64::try_from(
        mem.title.len()
            + mem.content.len()
            + serde_json::to_string(&mem.metadata)
                .map(|s| s.len())
                .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}
