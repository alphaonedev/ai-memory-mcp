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
//! | #2724 | post-commit stages — no audit emit, no subscription dispatch, no postgres federation fanout |
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
//!   "sent": 4, "created": 1, "updated": 1, "deduped": 1, "rejected": 1,
//!   "errors":       [{"index": 2, "code": "CONFLICT",
//!                     "error": "conflict: already exists",
//!                     "existing_id": "…"}],
//!   "deduped_rows": [{"index": 0, "superseded_by": 1}],
//!   "updated_rows": [{"index": 3, "superseded_by": "…"}],
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
//! # `on_conflict` — pre-existing-row disposition (#2725, CB-23)
//!
//! Each input row carries the SAME `on_conflict` vocabulary as single-create
//! (`error` | `merge` | `version`, parsed by
//! [`crate::mcp::tools::OnConflictMode`]) and defaults to **`error`**, matching
//! the sqlite single-create default. The disposition applies ONLY to a
//! collision with a **pre-existing stored** `(title, namespace)` row — NOT to an
//! in-batch sibling, which is the `deduped_rows[]` collapse above:
//!
//! * **`error`** (default) — a row colliding with a pre-existing row is
//!   REJECTED into `errors[]` as a `CONFLICT` carrying the `existing_id`, and
//!   the stored content is left UNTOUCHED. Pre-#2725 bulk had no default, so
//!   every such row silently and unrecoverably OVERWROTE the pre-existing
//!   content via `db::insert`'s upsert arm — a data-integrity defect, because
//!   `insert_inner` takes no pre-overwrite snapshot (unlike `db::update`), so
//!   the prior content was gone and `ai-memory undo-edit` had nothing to
//!   restore.
//! * **`merge`** — the caller's explicit opt-in to the content-replacing
//!   upsert. Each row that replaced a pre-existing row is disclosed by input
//!   index in `updated_rows[]` (`{index, superseded_by: <stored id>}`),
//!   mirroring the `deduped_rows[]` shape, so a loader can tell which of its
//!   records overwrote existing content.
//! * **`version`** — the row's title is rewritten to the next free suffix so it
//!   lands as a NEW row and never overwrites.
//!
//! A conflict-rejected row counts in `rejected`, never in `updated`, so the
//! reconciliation identity holds. `updated_rows[]` is a disclosure array (like
//! `deduped_rows[]`), never a counter, so it does not enter the identity.
//!
//! `warnings[]` is deliberately SEPARATE from `errors[]`: a post-commit
//! federation quorum/catchup failure means the row IS durable locally
//! (ADR-0001 never rolls a local commit back on a quorum miss), so folding it
//! into `errors[]` — as the pre-#2551 code did — made `rejected` unreconcilable
//! and would have made the response status a function of peer reachability on a
//! fully-persisted batch.
//!
//! # Post-commit stages (#2724, CB-22)
//!
//! Once the durable write has landed, single-create runs three post-commit
//! stages that bulk had omitted on one or both backends (a fourth
//! re-implementation-omits-a-stage symptom of the same root cause):
//!
//! 1. **Audit** — one `AuditAction::Store` row per persisted memory
//!    ([`crate::audit::emit`]), so a fleet corpus load is not an invisible gap
//!    in the tamper-evident chain. Bulk emitted ZERO on both backends.
//! 2. **Subscription dispatch** — the `memory_store` lifecycle event
//!    ([`crate::subscriptions::dispatch_event`] on sqlite,
//!    `dispatch_event_postgres` on postgres) so a registered `memory_store`
//!    subscriber sees bulk-ingested rows. Bulk fired ZERO on both backends.
//! 3. **Federation fanout** — the postgres bulk branch ended at the batched
//!    insert with no `broadcast_store_quorum` / `bulk_catchup_push`, so a
//!    postgres daemon with `--quorum-peers` silently did not replicate bulk
//!    rows. The sqlite branch already fanned out; this closes the postgres gap.
//!
//! All three fire ONCE per DISTINCT persisted row (`created + updated`) — an
//! in-batch `(title, namespace)` collapse is one durable row, so it draws one
//! audit line, one dispatch, and one broadcast, never one per input index —
//! and NEVER for a rejected / skipped / pending row. This does not touch the
//! reconciliation identity: the ledger counters are unchanged; a post-commit
//! federation failure still lands only in `warnings[]`.

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
use crate::mcp::param_names::ON_CONFLICT;
use crate::mcp::tools::OnConflictMode;
use crate::models::field_names;
use crate::models::{CreateMemory, Memory};
use crate::validate;

use super::AppState;
use super::BULK_FANOUT_CONCURRENCY;
#[cfg(feature = "sal")]
use super::StorageBackend;
use super::create::{build_create_memory, resolve_create_caller, resolve_create_metadata};
#[cfg(feature = "sal")]
use super::errors::classify_store_err;
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

/// #2588 — how many per-row detail lines one call may emit before the rest are
/// suppressed.
///
/// Two obligations pull against each other here. #851 requires the FULL raw
/// detail to reach the operator log, because only the sanitized label reaches
/// the wire and an operator otherwise cannot debug at all. #2588 requires that
/// a 500-row rejection not flood the log. The resolution is a bounded prefix
/// plus the always-emitted per-call summary: the first failures carry their
/// full detail, the rest are counted rather than printed, and the summary line
/// always reports the true totals — so the log is never a lie about how many
/// rows failed, only about which of them it chose to spell out.
const BULK_ROW_LOG_LIMIT: usize = 20;

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
    /// #2725 (CB-23) — input index → superseded (pre-existing) row id for
    /// rows that were UPDATED under an explicit overwrite `on_conflict`.
    /// A disclosure array mirroring `deduped_rows`, never a counter.
    updated_rows: Vec<serde_json::Value>,
    pending: Vec<serde_json::Value>,
    warnings: Vec<&'static str>,
    /// Highest-precedence rejection class seen, for the whole-request status.
    worst: Option<BulkRowErrorClass>,
    /// #2588 — per-row detail lines emitted so far (see `BULK_ROW_LOG_LIMIT`).
    logged: usize,
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
            updated_rows: Vec::new(),
            pending: Vec::new(),
            warnings: Vec::new(),
            worst: None,
            logged: 0,
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
        self.reject_class(index, field, classify_bulk_row_error(raw), raw);
    }

    /// #2552 — record a rejection whose typed class the caller already knows
    /// (see [`super::create::CreateFieldError::as_bulk_class`]).
    fn reject_class(&mut self, index: usize, field: &str, class: BulkRowErrorClass, raw: &str) {
        self.logged += 1;
        if self.logged <= BULK_ROW_LOG_LIMIT {
            tracing::warn!(
                target: BULK_TRACE_TARGET,
                row = index,
                code = class.code,
                "bulk_create: row rejected: {raw}"
            );
        } else if self.logged == BULK_ROW_LOG_LIMIT + 1 {
            tracing::warn!(
                target: BULK_TRACE_TARGET,
                limit = BULK_ROW_LOG_LIMIT,
                "bulk_create: further per-row detail suppressed for this call; \
                 the summary line below carries the true totals"
            );
        }
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
            .push(json!({ "index": index, (field_names::SUPERSEDED_BY): superseded_by }));
    }

    /// #2725 (CB-23) — record an input row that REPLACED a pre-existing stored
    /// row under an explicit overwrite `on_conflict` (`merge`). `superseded_by`
    /// is the stored id whose content was overwritten (never rewritten by the
    /// conflict arm, so it is the pre-existing row's id). Mirrors the
    /// `deduped_rows[]` disclosure shape; a disclosure only, not a counter.
    fn updated_row(&mut self, index: usize, superseded_by: &str) {
        self.updated_rows
            .push(json!({ "index": index, (field_names::SUPERSEDED_BY): superseded_by }));
    }

    /// #2725 (CB-23) — record a row REJECTED because its `(title, namespace)`
    /// collides with a PRE-EXISTING stored row under the default
    /// `on_conflict=error`. Echoes the `existing_id` (as single-create's 409
    /// does) so a loader can reconcile without a second lookup. Classified as
    /// `CONFLICT` so it participates in the dominant-cause status precedence.
    fn reject_conflict(&mut self, index: usize, existing_id: &str) {
        let class = crate::handlers::errors::BulkRowErrorClass {
            code: crate::errors::error_codes::CONFLICT,
            label: "conflict: already exists",
            status: StatusCode::CONFLICT,
            retryable: false,
        };
        self.reject_class(
            index,
            "",
            class,
            &format!(
                "on_conflict=error: (title, namespace) collides with existing row {existing_id}"
            ),
        );
        if let Some(entry) = self.errors.last_mut().and_then(|e| e.as_object_mut()) {
            entry.insert(field_names::EXISTING_ID.to_string(), json!(existing_id));
        }
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
        // #2588 — ALWAYS emitted when the batch did not fully apply, and
        // never suppressed: it is the one line an operator correlating a lost
        // corpus load can rely on. Pre-#2588 a call that rejected every row
        // logged nothing at any level.
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
            // #2725 (CB-23) — input index → superseded id for rows updated
            // under an explicit overwrite `on_conflict`.
            if !self.updated_rows.is_empty() {
                obj.insert("updated_rows".to_string(), json!(self.updated_rows));
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
        codes::GOVERNANCE_REFUSED | codes::AGENT_ID_MISMATCH => 3,
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
    /// #2725 (CB-23) — the per-row pre-existing-collision disposition, parsed
    /// once in stage 1 from `body.on_conflict` (default `error`), resolved
    /// against the live DB in the persist stage.
    on_conflict: OnConflictMode,
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
    // Group input positions by the id the persist stage actually returned,
    // preserving submission order within each group.
    let mut order: Vec<&str> = Vec::new();
    let mut groups: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    // At most ONE input row can have minted the surviving id, so a single
    // flag per group answers "did THIS call create the row?".
    let mut minted_here: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (idx, minted, returned) in outcomes {
        let key = returned.as_str();
        groups
            .entry(key)
            .or_insert_with(|| {
                order.push(key);
                Vec::new()
            })
            .push(*idx);
        if minted == returned {
            minted_here.insert(key);
        }
    }
    for returned in order {
        let members = &groups[returned];
        let created = minted_here.contains(returned);
        if created {
            ledger.created += 1;
        } else {
            ledger.updated += 1;
        }
        if let Some((&survivor, superseded)) = members.split_last() {
            for &idx in superseded {
                ledger.dedupe(idx, survivor);
            }
            // #2725 (CB-23) — a group whose returned id was NOT minted by any
            // of its members upserted onto a PRE-EXISTING stored row, so the
            // survivor's content REPLACED it. `returned` is that pre-existing
            // row's id (the conflict arm never rewrites `id`). Reachable only
            // under an explicit overwrite `on_conflict` (`merge`); the default
            // `error` rejects a pre-existing collision BEFORE it reaches the
            // persist stage, so an updated group never carries a default row.
            if !created {
                ledger.updated_row(survivor, returned);
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
// #2724 (CB-22) — post-commit stages: audit, subscription dispatch, fanout.
// ---------------------------------------------------------------------------

/// Collapse committed rows to ONE entry per persisted id (last-wins),
/// mirroring the upsert's surviving-content rule.
///
/// Several input rows can share a persisted id after an in-batch
/// `(title, namespace)` collapse (sqlite sequential upsert / postgres
/// pre-INSERT dedup). The post-commit stages must fire ONCE per distinct
/// durable row — `created + updated` of them — not once per input index, so a
/// collapsed pair draws one audit line, one dispatch, and one broadcast. The
/// LAST occurrence wins so the surviving CONTENT (the same row the upsert kept)
/// is the one that is audited / dispatched / fanned out.
fn distinct_committed_rows(mems: Vec<Memory>) -> Vec<Memory> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: std::collections::HashMap<String, Memory> = std::collections::HashMap::new();
    for mem in mems {
        if !by_id.contains_key(&mem.id) {
            order.push(mem.id.clone());
        }
        by_id.insert(mem.id.clone(), mem);
    }
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

/// #2724 (F1) — one `AuditAction::Store` audit row per persisted memory,
/// matching single-create (`create::fanout_and_assemble_create_response` on
/// sqlite, `create_memory_postgres` on postgres). Pre-#2724 a bulk load left
/// ZERO Store rows in the tamper-evident chain on both backends. Gated ONCE on
/// [`crate::audit::is_enabled`] so a disabled subsystem costs nothing.
fn emit_bulk_store_audit(committed: &[Memory]) {
    if !crate::audit::is_enabled() {
        return;
    }
    for mem in committed {
        let scope = mem
            .metadata
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // #869 — an absent agent_id records the documented `""` anonymous-actor
        // sentinel, matching both single-create paths.
        let agent = mem
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        crate::audit::emit(crate::audit::EventBuilder::new(
            crate::audit::AuditAction::Store,
            crate::audit::actor(agent, "http_body", scope.clone()),
            crate::audit::target_memory(
                mem.id.clone(),
                mem.namespace.clone(),
                Some(mem.title.clone()),
                Some(mem.tier.to_string()),
                scope,
            ),
        ));
    }
}

/// #2724 (F2) — fire the `memory_store` subscription lifecycle event for every
/// persisted row, matching single-create. Fire-and-forget (worker threads
/// handle delivery); never rolls back the local commit. Respects the same
/// backend split single-create uses: the sqlite path reads the `subscriptions`
/// table under the shared writer lock, the postgres path walks the
/// `_subscriptions/<*>` mirror rows via the SAL. Pre-#2724 a `memory_store`
/// subscriber received NOTHING from a bulk write on either backend.
async fn dispatch_bulk_store_events(app: &AppState, committed: &[Memory]) {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        for mem in committed {
            let agent = mem.metadata.get("agent_id").and_then(|v| v.as_str());
            super::dispatch_event_postgres(
                app,
                crate::mcp::registry::tool_names::MEMORY_STORE,
                &mem.id,
                &mem.namespace,
                agent,
                None,
            )
            .await;
        }
        return;
    }

    // Sqlite: one lock for the whole batch (each dispatch is a fast table read
    // + fire-and-forget spawn), mirroring single-create's single-lock dispatch.
    let lock = app.db.lock().await;
    for mem in committed {
        let agent = mem.metadata.get("agent_id").and_then(|v| v.as_str());
        crate::subscriptions::dispatch_event(
            &lock.0,
            crate::mcp::registry::tool_names::MEMORY_STORE,
            &mem.id,
            &mem.namespace,
            agent,
            &lock.1,
        );
    }
}

/// #2724 (F3) — federation fanout for a committed bulk batch. Shared by BOTH
/// backends so the postgres branch (which had NONE) replicates bulk rows
/// exactly as the sqlite branch always has.
///
/// One `broadcast_store_quorum` per persisted row, bounded by
/// [`BULK_FANOUT_CONCURRENCY`] so 500 rows × 3 peers cannot exhaust the reqwest
/// pool; then one batched `bulk_catchup_push` per peer to close the
/// eventual-consistency gap the per-row retry can leave. A quorum miss does NOT
/// abort the other rows (bulk semantics, deliberately weaker than
/// `create_memory`'s 503 short-circuit) and lands in `warnings[]`, never
/// `errors[]` — the local commit is durable (ADR-0001).
async fn bulk_federation_fanout(
    app: &AppState,
    committed_mems: &[Memory],
    ledger: &mut BulkLedger,
) {
    let Some(fed) = app.federation.as_ref() else {
        return;
    };
    if committed_mems.is_empty() {
        return;
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(BULK_FANOUT_CONCURRENCY));
    let mut joins: tokio::task::JoinSet<(String, Result<(), String>)> = tokio::task::JoinSet::new();
    for mem in committed_mems {
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
                    tracing::warn!("bulk_create: fanout for {id} failed (local committed): {e:?}");
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

    // v0.6.2 Patch 2 (S40): terminal catchup batch — one batched `sync_push`
    // per peer with every committed row closes the eventual-consistency gap the
    // per-row retry can leave.
    let catchup_errors = crate::federation::bulk_catchup_push(fed, committed_mems).await;
    for (peer_id, err) in catchup_errors {
        ledger.warn(&format!("catchup to peer {peer_id}: {err}"));
    }
}

/// #2724 (CB-22) — run every post-commit stage single-create runs, once per
/// DISTINCT persisted row, for rows that actually committed. Audit → dispatch →
/// fanout, the same order single-create uses.
async fn run_bulk_post_commit(app: &AppState, committed_mems: &[Memory], ledger: &mut BulkLedger) {
    if committed_mems.is_empty() {
        return;
    }
    emit_bulk_store_audit(committed_mems);
    dispatch_bulk_store_events(app, committed_mems).await;
    bulk_federation_fanout(app, committed_mems, ledger).await;
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
        // #2725 (CB-23) — parse the per-row `on_conflict` disposition up front,
        // sharing the single-create SSOT (`error` | `merge` | `version`,
        // default `error`). An unknown token rejects the row (single-create
        // returns 400 for the same input) rather than silently defaulting.
        let on_conflict =
            match OnConflictMode::parse(body.on_conflict.as_deref().unwrap_or("error")) {
                Ok(m) => m,
                Err(msg) => {
                    ledger.reject(index, ON_CONFLICT, &msg);
                    continue;
                }
            };
        let metadata = match resolve_create_metadata(&caller, body) {
            Ok(m) => m,
            Err(e) => {
                ledger.reject_class(index, e.field, e.as_bulk_class(), &e.message);
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
            on_conflict,
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
    // #2874 — keys that have DURABLY LANDED earlier in THIS batch. Drives the
    // fail-closed write routing below: the FIRST occurrence of an `error`-mode
    // key writes through `db::insert_no_overwrite` (fail-closed against a row
    // that raced past the Stage-2 pre-existing probe), while a later in-batch
    // SIBLING whose key already landed here keeps the legacy upsert so the
    // #2725 last-wins in-batch dedup is preserved (never a self-conflict).
    let mut landed_this_batch: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    {
        let lock = app.db.lock().await;
        // #2725 (CB-23) — snapshot each `error`-mode row's PRE-EXISTING
        // `(title, namespace)` → id BEFORE the sequential upsert loop inserts
        // anything, so a row colliding with an in-batch sibling (which this
        // loop is about to create) is NOT mistaken for a pre-existing
        // collision — that stays the `deduped_rows[]` collapse. `None` caches a
        // confirmed miss so a repeated key is probed once. Only `error` rows
        // consult it (`version` renames, `merge` upserts unconditionally).
        let mut pre_existing: std::collections::HashMap<(String, String), Option<String>> =
            std::collections::HashMap::new();
        for row in &prepared {
            if row.on_conflict != OnConflictMode::Error {
                continue;
            }
            let key = (row.mem.title.clone(), row.mem.namespace.clone());
            if let std::collections::hash_map::Entry::Vacant(slot) = pre_existing.entry(key) {
                let existing =
                    db::find_by_title_namespace(&lock.0, &row.mem.title, &row.mem.namespace)
                        .ok()
                        .flatten();
                slot.insert(existing);
            }
        }
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

            // #2725 (CB-23) — resolve the pre-existing-collision disposition
            // BEFORE any content-replacing write (and before the quota charge,
            // so a rejected row needs no refund). Default `error` REFUSES a
            // pre-existing collision (carrying its id) rather than silently
            // overwriting the stored content via `db::insert`'s upsert arm;
            // `version` renames to a fresh title; `merge` opts into the upsert.
            match row.on_conflict {
                OnConflictMode::Error => {
                    let key = (row.mem.title.clone(), row.mem.namespace.clone());
                    if let Some(existing_id) = pre_existing.get(&key).and_then(|o| o.as_deref()) {
                        ledger.reject_conflict(row.index, existing_id);
                        continue;
                    }
                }
                OnConflictMode::Version => {
                    match db::next_versioned_title(&lock.0, &row.mem.title, &row.mem.namespace) {
                        Ok(title) => row.mem.title = title,
                        Err(e) => {
                            ledger.reject(row.index, ON_CONFLICT, &e.to_string());
                            continue;
                        }
                    }
                }
                OnConflictMode::Merge => {}
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

            // #2874 — under the default `on_conflict=error` disposition the
            // write must be ATOMICALLY fail-closed so a row racing into
            // `(title, namespace)` BETWEEN the Stage-2 pre-existing probe and
            // this write can no longer be silently upsert-overwritten (the
            // North-Star lost-update the single-create #2771 fix already closed
            // on the create funnel). The FIRST occurrence of a key routes
            // through `db::insert_no_overwrite` (`INSERT … ON CONFLICT DO
            // NOTHING` → typed `ConflictError`); an in-batch SIBLING whose key
            // already LANDED in this batch keeps the legacy upsert so the #2725
            // last-wins in-batch dedup is preserved (NOT turned into a
            // self-conflict). `merge`/`version` always keep the upsert.
            let key = (row.mem.title.clone(), row.mem.namespace.clone());
            let fail_closed =
                row.on_conflict == OnConflictMode::Error && !landed_this_batch.contains(&key);
            let insert_result = if fail_closed {
                db::insert_no_overwrite(&lock.0, &row.mem)
            } else {
                db::insert(&lock.0, &row.mem)
            };
            match insert_result {
                Ok(returned_id) => {
                    landed_this_batch.insert(key);
                    // Issue #219 parity — persist the vector so semantic recall
                    // can find this row immediately (#2594).
                    if let (Some(vec), Some(space)) = (row.embedding.as_ref(), &embedding_space)
                        && let Err(e) = db::set_embedding(&lock.0, &returned_id, vec, space)
                    {
                        tracing::warn!("failed to store embedding for {returned_id}: {e}");
                    }
                    outcomes.push((row.index, row.mem.id.clone(), returned_id.clone()));
                    // Adopt the PERSISTED id before the row leaves this loop.
                    // `db::insert` returns the EXISTING row's id when the
                    // write landed on the `(title, namespace)` conflict arm,
                    // and both consumers below key on it: the HNSW index would
                    // otherwise be seeded with an id that resolves to NOTHING
                    // in the database (recall returns a hit whose `get` 404s —
                    // a WRONG result, not merely a missing one), and the
                    // federation fanout would publish the minted id to peers,
                    // creating a DIVERGENT row there for content that upserted
                    // here. Single-create has done this since #866
                    // (`fanout_and_assemble_create_response` sets
                    // `mem_echo.id = actual_id`); bulk re-implemented the
                    // funnel and omitted it, so an upsert drifted ids across
                    // the fleet.
                    row.mem.id = returned_id;
                    committed.push((row.mem, row.embedding));
                }
                Err(e) => {
                    // #1788 — refund the quota charge since the insert failed
                    // (a fail-closed conflict never landed a row, so the
                    // per-row charge above must be returned, exactly as any
                    // other write failure).
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
                    // #2874 — the fail-closed `db::insert_no_overwrite` refused
                    // a `(title, namespace)` collision that raced past Stage-2's
                    // probe. Surface it as the SAME typed 409-class conflict
                    // (carrying `existing_id`) the pre-existing-collision arm
                    // emits — NEVER a silent overwrite, and distinct from a
                    // generic store error. Mirrors single-create #2771.
                    if let Some(conflict) = e.downcast_ref::<crate::storage::ConflictError>() {
                        ledger.reject_conflict(row.index, &conflict.existing_id);
                    } else {
                        ledger.reject(row.index, "store", &e.to_string());
                    }
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

    // #2724 (CB-22) — post-commit stages, once per distinct persisted row:
    // audit emit + subscription dispatch + federation fanout, matching
    // single-create. The sqlite branch already fanned out; #2724 folds in the
    // audit + dispatch stages it omitted and shares the fanout with postgres.
    let committed_mems =
        distinct_committed_rows(committed.into_iter().map(|(mem, _)| mem).collect());
    run_bulk_post_commit(app, &committed_mems, &mut ledger).await;
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

        // #2725 (CB-23) — pre-existing-collision disposition (postgres twin).
        // The batched INSERT runs only AFTER this loop, so a
        // `find_by_title_namespace` hit here is necessarily a PRE-EXISTING row,
        // never an in-batch sibling (in-batch collapse stays the
        // `deduped_rows[]` path via `store_batch`'s last-wins upsert). Default
        // `error` refuses the overwrite (carrying the id); `version` renames;
        // `merge` opts into the content-replacing upsert.
        match row.on_conflict {
            OnConflictMode::Error => {
                match app
                    .store
                    .find_by_title_namespace(&row.mem.title, &row.mem.namespace)
                    .await
                {
                    Ok(Some(existing_id)) => {
                        ledger.reject_conflict(row.index, &existing_id);
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        ledger.reject_class(
                            row.index,
                            ON_CONFLICT,
                            classify_store_err(&e),
                            &e.to_string(),
                        );
                        continue;
                    }
                }
            }
            OnConflictMode::Version => {
                match app
                    .store
                    .next_versioned_title(&row.mem.title, &row.mem.namespace)
                    .await
                {
                    Ok(title) => row.mem.title = title,
                    Err(e) => {
                        ledger.reject_class(
                            row.index,
                            ON_CONFLICT,
                            classify_store_err(&e),
                            &e.to_string(),
                        );
                        continue;
                    }
                }
            }
            OnConflictMode::Merge => {}
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
            ledger.reject_class(row.index, "quota", classify_store_err(&e), &e.to_string());
            continue;
        }

        allowed.push(row);
    }

    let mut outcomes: Vec<(usize, String, String)> = Vec::new();
    // #2724 (F3) — the memories that durably committed, each carrying the
    // PERSISTED id the write returned, so the post-commit stages below
    // (audit / dispatch / federation fanout) key on the same id every other
    // consumer keys on.
    let mut committed_mems: Vec<Memory> = Vec::new();

    // #2874 — partition the surviving rows by conflict disposition. Under the
    // default `on_conflict=error` the write MUST be ATOMICALLY fail-closed so a
    // row racing into `(title, namespace)` BETWEEN the Stage-2 probe and the
    // write can no longer be silently upsert-overwritten by `store_batch`'s
    // `ON CONFLICT DO UPDATE` arm — the North-Star lost-update the single-create
    // #2771 fix already closed on the create funnel. `error` rows route per-row
    // through the certified `store_with_embedding_no_overwrite` twin (#2771);
    // `merge`/`version` keep the batched upsert (task-mandated). The per-row
    // `error` lane trades `store_batch`'s single round-trip for reuse of the
    // just-certified no-overwrite primitive — 5-agent vote `4d3ea1c5`, option B
    // (a batched `store_batch_no_overwrite` is the tracked throughput
    // optimisation if error-mode bulk volume is measured to warrant it). Only a
    // batch that mixes `error` with `merge`/`version` on the SAME key (a
    // self-contradictory request no sane loader sends) splits atomicity across
    // the two lanes; the reconciling envelope invariant holds either way.
    let space = embedding_space.as_deref();
    let (error_rows, batch_rows): (Vec<PreparedRow>, Vec<PreparedRow>) = allowed
        .into_iter()
        .partition(|r| r.on_conflict == OnConflictMode::Error);

    // --- error lane: per-row fail-closed, IN INPUT ORDER. `partition`
    // preserves relative order within the lane, so the FIRST occurrence of a
    // key writes through the no-overwrite twin (a raced / pre-existing
    // collision => typed `StoreError::Conflict` => `reject_conflict`, NEVER an
    // overwrite) while a later in-batch SIBLING whose key already landed here
    // keeps the upsert so its content wins LAST exactly as #2725 pins — never a
    // self-conflict.
    let mut landed: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::with_capacity(error_rows.len());
    for row in error_rows {
        let key = (row.mem.title.clone(), row.mem.namespace.clone());
        let store_res = if landed.contains(&key) {
            app.store
                .store_with_embedding(&ctx, &row.mem, row.embedding.as_deref(), space)
                .await
        } else {
            app.store
                .store_with_embedding_no_overwrite(&ctx, &row.mem, row.embedding.as_deref(), space)
                .await
        };
        match store_res {
            Ok(id) => {
                landed.insert(key);
                outcomes.push((row.index, row.mem.id.clone(), id.clone()));
                let mut mem = row.mem.clone();
                mem.id = id;
                committed_mems.push(mem);
            }
            Err(crate::store::StoreError::Conflict { id }) => {
                // The no-overwrite write refused a `(title, namespace)`
                // collision that raced past Stage-2's probe. Surface the SAME
                // typed 409-class conflict (carrying `existing_id`) the
                // pre-existing arm emits — NEVER a silent overwrite. Mirrors
                // single-create #2771 (`store_with_embedding_no_overwrite`
                // charges no quota on the DO-NOTHING arm — the tx never
                // commits — so there is no charge to refund here).
                ledger.reject_conflict(row.index, &id);
            }
            Err(e) => {
                ledger.reject_class(row.index, "store", classify_store_err(&e), &e.to_string());
            }
        }
    }

    // --- merge/version lane: the existing atomic batched upsert (#1481),
    // semantics UNCHANGED, plus the post-commit vector stamp for the rows that
    // landed.
    if !batch_rows.is_empty() {
        let memories: Vec<Memory> = batch_rows.iter().map(|r| r.mem.clone()).collect();
        match app.store.store_batch(&ctx, &memories).await {
            Ok(ids) if ids.len() == batch_rows.len() => {
                for (row, returned) in batch_rows.iter().zip(ids.iter()) {
                    outcomes.push((row.index, row.mem.id.clone(), returned.clone()));
                    let mut mem = row.mem.clone();
                    mem.id = returned.clone();
                    committed_mems.push(mem);
                }
                // #2594 — one entry per PERSISTED id, LAST-wins (the same rule
                // the upsert used to pick the surviving content). Several input
                // rows can share a returned id (in-batch `(title, namespace)`
                // collapse), and duplicate ids in one multi-row UPDATE are the
                // shape postgres refuses with "cannot affect row a second time";
                // pairing surviving CONTENT with an earlier row's VECTOR would
                // also score a row against text it does not hold (a wrong
                // result, which outranks a missing one).
                if let Some(space) = embedding_space.as_deref() {
                    let mut by_id: std::collections::HashMap<&str, &Vec<f32>> =
                        std::collections::HashMap::new();
                    for (row, id) in batch_rows.iter().zip(ids.iter()) {
                        if let Some(v) = row.embedding.as_ref() {
                            by_id.insert(id.as_str(), v);
                        }
                    }
                    let entries: Vec<(String, Vec<f32>)> = by_id
                        .into_iter()
                        .map(|(id, v)| (id.to_string(), v.clone()))
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
                    batch_rows.len()
                );
                tracing::error!("bulk_create(postgres): {detail}");
                for row in &batch_rows {
                    ledger.reject(row.index, "store", &detail);
                }
            }
            Err(e) => {
                // #2588 — the batch is ATOMIC: a quota breach (or any other
                // failure) inside `store_batch` rolls the WHOLE transaction
                // back, so EVERY merge/version row in the batch was lost. Every
                // lost row gets its own typed, indexed rejection, and
                // `BulkLedger::status` turns the total loss into the dominant
                // cause's status (429 for quota).
                let class = classify_store_err(&e);
                let detail = e.to_string();
                tracing::warn!("bulk_create(postgres): store_batch failed: {detail}");
                for row in &batch_rows {
                    ledger.reject_class(row.index, "store", class, &detail);
                }
            }
        }
    }
    classify_persisted(&outcomes, &mut ledger);

    // #2724 (CB-22) — post-commit stages the postgres bulk branch had omitted
    // ENTIRELY: audit emit + subscription dispatch + federation fanout, once
    // per distinct persisted row, matching `create_memory_postgres`. Pre-#2724
    // a postgres daemon with `--quorum-peers` did not replicate bulk rows and a
    // `memory_store` subscriber saw nothing from a bulk load.
    let committed_mems = distinct_committed_rows(committed_mems);
    run_bulk_post_commit(app, &committed_mems, &mut ledger).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the `(input_index, minted_id, returned_id)` triples the persist
    /// stage produces, from a compact `(minted, returned)` spec.
    fn outcomes(spec: &[(&str, &str)]) -> Vec<(usize, String, String)> {
        spec.iter()
            .enumerate()
            .map(|(i, (m, r))| (i, (*m).to_string(), (*r).to_string()))
            .collect()
    }

    /// #2551 — a batch of distinct fresh rows is all `created`.
    #[test]
    fn classify_all_fresh_inserts_are_created() {
        let mut l = BulkLedger::new(3);
        classify_persisted(&outcomes(&[("a", "a"), ("b", "b"), ("c", "c")]), &mut l);
        assert_eq!((l.created, l.updated, l.deduped()), (3, 0, 0));
    }

    /// #2551 — a row that upserted an EXISTING `(title, namespace)` is
    /// `updated`, never `created`. The discriminator is that no input row
    /// minted the id the persist stage returned.
    #[test]
    fn classify_upsert_of_preexisting_row_is_updated() {
        let mut l = BulkLedger::new(1);
        classify_persisted(&outcomes(&[("minted", "preexisting")]), &mut l);
        assert_eq!((l.created, l.updated, l.deduped()), (0, 1, 0));
        // #2725 (CB-23) — the updated row discloses its superseded (pre-existing)
        // id by input index, mirroring `deduped_rows[]`.
        assert_eq!(l.updated_rows.len(), 1);
        assert_eq!(l.updated_rows[0]["index"], 0);
        assert_eq!(l.updated_rows[0]["superseded_by"], "preexisting");
    }

    /// #2725 (CB-23) — a fresh/created group emits NO `updated_rows` entry, and
    /// an in-batch collapse (created + deduped) is likewise never an update.
    #[test]
    fn classify_created_and_dedup_emit_no_updated_rows() {
        let mut l = BulkLedger::new(3);
        classify_persisted(
            &outcomes(&[("r0", "r0"), ("r1", "r1"), ("r2", "r0")]),
            &mut l,
        );
        assert_eq!((l.created, l.updated, l.deduped()), (2, 0, 1));
        assert!(l.updated_rows.is_empty());
    }

    /// #2725 (CB-23) — a conflict rejection is a `CONFLICT`-class error that
    /// carries the `existing_id` and drives the dominant-cause status.
    #[test]
    fn reject_conflict_is_a_conflict_with_existing_id() {
        use crate::errors::error_codes;
        let mut l = BulkLedger::new(1);
        l.reject_conflict(0, "row-abc");
        assert_eq!(l.rejected(), 1);
        assert_eq!(l.updated, 0);
        assert_eq!(l.errors[0]["code"], error_codes::CONFLICT);
        assert_eq!(l.errors[0]["index"], 0);
        assert_eq!(l.errors[0]["existing_id"], "row-abc");
        assert_eq!(l.status(), StatusCode::CONFLICT);
    }

    /// #2551 — the in-batch collapse, in the shape the POSTGRES branch
    /// produces: `store_batch` drops all but the LAST duplicate before the
    /// INSERT, so the surviving id is the LAST row's minted id.
    #[test]
    fn classify_in_batch_collapse_postgres_shape() {
        let mut l = BulkLedger::new(3);
        classify_persisted(
            &outcomes(&[("r0", "r2"), ("r1", "r1"), ("r2", "r2")]),
            &mut l,
        );
        assert_eq!((l.created, l.updated, l.deduped()), (2, 0, 1));
        assert_eq!(l.deduped_rows[0]["index"], 0);
        assert_eq!(l.deduped_rows[0]["superseded_by"], 2);
    }

    /// #2551 — the SAME request on the SQLITE branch, whose sequential
    /// upserts make the surviving id the FIRST row's minted id. The counters
    /// must come out IDENTICAL to the postgres shape above, or the two
    /// backends would report different truth for the same batch.
    #[test]
    fn classify_in_batch_collapse_sqlite_shape_matches_postgres() {
        let mut l = BulkLedger::new(3);
        classify_persisted(
            &outcomes(&[("r0", "r0"), ("r1", "r1"), ("r2", "r0")]),
            &mut l,
        );
        assert_eq!((l.created, l.updated, l.deduped()), (2, 0, 1));
        assert_eq!(l.deduped_rows[0]["index"], 0);
        assert_eq!(
            l.deduped_rows[0]["superseded_by"], 2,
            "the LAST input position in the group is the one whose content survived"
        );
    }

    /// #2588 — a retryable cause outranks a permanent one, so a mixed batch
    /// that persisted nothing tells the fleet to back off rather than to
    /// discard the rows it could still write.
    #[test]
    fn status_precedence_is_retryable_first_not_count_majority() {
        let mut l = BulkLedger::new(3);
        // Two permanent causes, then ONE retryable — a count-majority would
        // pick 400 and permanently drop the quota-throttled row.
        l.reject(0, "create", "title cannot be empty");
        l.reject(1, "create", "title cannot be empty");
        l.reject(
            2,
            "quota",
            "QUOTA_EXCEEDED: agent a namespace n hit memories_per_day (5/5)",
        );
        assert_eq!(l.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// #2588 — the four status classes.
    #[test]
    fn status_classes() {
        assert_eq!(BulkLedger::new(0).status(), StatusCode::OK);

        let mut clean = BulkLedger::new(1);
        classify_persisted(&outcomes(&[("a", "a")]), &mut clean);
        assert_eq!(clean.status(), StatusCode::OK);

        let mut partial = BulkLedger::new(2);
        classify_persisted(&outcomes(&[("a", "a")]), &mut partial);
        partial.reject(1, "create", "title cannot be empty");
        assert_eq!(partial.status(), StatusCode::MULTI_STATUS);

        let mut all_pending = BulkLedger::new(1);
        all_pending.pending.push(json!({"index": 0}));
        assert_eq!(all_pending.status(), StatusCode::ACCEPTED);
    }

    /// #2551 — a DEDUPED row is a partial application even though nothing
    /// was rejected. Without this the #2551 batch (57 rows' content silently
    /// discarded, `errors: []`) would answer 200 again.
    #[test]
    fn dedup_alone_is_a_partial_application() {
        let mut l = BulkLedger::new(2);
        classify_persisted(&outcomes(&[("a", "a"), ("b", "a")]), &mut l);
        assert_eq!(l.rejected(), 0);
        assert_eq!(l.deduped(), 1);
        assert_eq!(l.status(), StatusCode::MULTI_STATUS);
    }

    /// #2552 — `field` is echoed only when it has the server-authored slug
    /// shape, so no future refactor can route caller text through it.
    #[test]
    fn field_shape_guard_rejects_caller_influenced_text() {
        assert!(is_server_authored_field("create"));
        assert!(is_server_authored_field("metadata.agent_id"));
        assert!(!is_server_authored_field(""));
        assert!(!is_server_authored_field("Title With Spaces"));
        assert!(!is_server_authored_field("<script>"));
        assert!(!is_server_authored_field(&"x".repeat(65)));
    }

    /// #2594 — with no embedder the funnel is a no-op and reports NO
    /// degradation: a keyword-tier deployment is not "degraded", it is
    /// correctly configured.
    #[test]
    fn embed_is_inert_without_an_embedder() {
        let mut l = BulkLedger::new(0);
        assert!(!l.embed_status.is_degraded());
        l.embed_status = EmbedStatus::Failed("boom".to_string());
        assert!(l.embed_status.is_degraded());
    }
}

#[cfg(test)]
mod log_bound_tests {
    use super::*;

    /// #2588 — per-row detail is bounded, but the COUNTERS never are: the
    /// summary must report every rejection even when most detail lines were
    /// suppressed, or the log would understate the loss.
    #[test]
    fn per_row_logging_is_bounded_but_counters_are_not() {
        let n = BULK_ROW_LOG_LIMIT * 3;
        let mut l = BulkLedger::new(n);
        for i in 0..n {
            l.reject(i, "create", "title cannot be empty");
        }
        assert_eq!(l.rejected(), n, "every rejection is counted");
        assert_eq!(l.logged, n, "and every one is accounted for");
        assert_eq!(l.errors.len(), n, "and every one reaches the caller");
    }
}
