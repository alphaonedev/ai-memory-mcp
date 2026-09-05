// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation `/sync/push` signing-verification + postgres-SAL receive path.
//!
//! Extracted from [`super::federation_receive`] under issue #650
//! (handler cap ≤1200 LOC). Bodies are unchanged; only the module
//! surface moved. Items are exposed as `pub(super)` so the public
//! [`super::federation_receive::sync_push`] orchestrator can call them.

#![allow(clippy::too_many_lines)]

#[cfg(feature = "sal")]
use crate::models::field_names;
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use std::sync::OnceLock;

use ed25519_dalek::VerifyingKey;

use crate::federation::identity::chain::{CHAIN_HEADER, CertChain, DEFAULT_MAX_CHAIN_DEPTH};
use crate::federation::identity::credential::{CREDENTIAL_HEADER, SignedCredential};
use crate::federation::identity::trust_bundle::TrustBundle;
use crate::federation::signing as fed_signing;

#[cfg(feature = "sal")]
use super::AppState;
#[cfg(feature = "sal")]
use super::federation_receive::{
    ATTESTATION_TRACE_TARGET, SyncPushBody, apply_inbound_write_attestation,
    check_sender_clock_skew, extract_peer_id, next_utc_midnight, resolve_inbound_attribution,
    resolve_inbound_decider, signal_author_authorized,
};
#[cfg(feature = "sal")]
use crate::validate;

/// #2447 / #1934 (CWE-284) — resolve a stored row's namespace by id for the
/// postgres receive twin's namespace-scope gates, BYPASSING the #910
/// `scope=private` SAL visibility filter.
///
/// [`crate::store::postgres::PostgresStore::get`] deliberately folds a
/// visibility denial into [`crate::store::StoreError::NotFound`] so the trait
/// never leaks existence to a caller lacking read permission. That is correct
/// for a tenant read and FATAL here: a tenant-scoped context would report a
/// hidden foreign row as "no such row", which is exactly the fail-OPEN input
/// the scope gates must never see — `Ok(None)` MUST mean "provably no local
/// row". The federation receive path is a peer/operator surface, never a
/// tenant-facing handler, and the resolved value is used ONLY to render a
/// REFUSAL decision: the row itself is never returned to the peer. This mirrors
/// the sqlite twin, which reads through the unscoped `db::get`.
///
/// `Ok(None)` = provably no row. `Err(_)` = unresolvable; every caller MUST
/// fail closed (skip the item) rather than treat it as absent.
///
/// ## #2488 — a SCALAR projection, never `get`
///
/// This routes through [`crate::store::MemoryStore::namespace_by_id`] (`SELECT
/// namespace, version FROM memories WHERE id = $1`) rather than
/// `MemoryStore::get` (`SELECT *`). Two reasons, both of which were live
/// defects before #2488, and both documented in full on the trait method:
/// the `SELECT *` shipped the embedding vector + stored `tsv` + full content +
/// `encrypted_envelope` per probed id to learn one string, and — the
/// load-bearing one — the full-row mapper is pinned to
/// `DecryptFailurePolicy::FailClosed`, so a row whose at-rest envelope will not
/// open on this node returned `Err`, landing in this gate's fail-closed arm and
/// making that row PERMANENTLY un-erasable by federation with no operator
/// escape hatch. `SELECT namespace` cannot fail for the decrypt reason at all.
#[cfg(feature = "sal")]
async fn resolve_stored_namespace(
    app: &AppState,
    probe_principal: String,
    id: &str,
) -> Result<Option<String>, crate::store::StoreError> {
    let ns_probe_ctx = crate::store::CallerContext::for_admin(probe_principal);
    app.store.namespace_by_id(&ns_probe_ctx, id).await
}

/// #3075 — the operator context the postgres federation-RECEIVE APPLY lanes use
/// for their SAL writes.
///
/// ## Why `for_admin` (privacy bypass) and not `for_agent`
///
/// This is a PARITY requirement, not a convenience. The sqlite twin
/// ([`super::federation_receive::sync_push`]) applies every one of these lanes
/// through the RAW `db::*` free functions — `db::set_namespace_standard`,
/// `db::clear_namespace_standard`, `db::archive_memory`, `db::restore_archived`,
/// `db::upsert_pending_action` — none of which consult a caller identity at all.
/// The federation authorization on those lanes is the PEER-SCOPE gate
/// (`receive_auth::inbound_*_authorized`, #2447/#2478/#2479) plus the per-lane
/// crypto attestation, NOT the local owner/tenant gate.
///
/// Several postgres trait methods DO carry a local caller-owns gate for their
/// TENANT-facing surfaces (`clear_namespace_standard`'s #1777/#2545 owner gate,
/// `archive_by_ids`' #3193 caller-owns gate, `archive_restore`'s #3271 twin).
/// Routing a federated apply through a tenant-scoped context would make the pg
/// receiver refuse rows the sqlite receiver applies — a SILENT cross-backend
/// divergence in exactly the direction #2488 warns about (a lane confined on one
/// funnel only), whose visible symptom is two peers answering `get_standard`
/// with different governance. So the federated apply runs with the bypass and
/// the peer-scope gate stays the sole authorization, byte-for-byte as on sqlite.
///
/// This adds NO reach a peer did not already have: every call site below runs
/// AFTER the lane's `receive_auth` verdict, and `/sync/push` is a peer/operator
/// surface (the #238 envelope gate + #29 signature + #30 nonce + #43 enrollment
/// all precede this funnel), never a tenant-facing handler. The principal is the
/// attested sender so the write is attributable in the audit trail.
#[cfg(feature = "sal")]
fn federation_apply_ctx(receive_principal: String) -> crate::store::CallerContext {
    crate::store::CallerContext::for_admin(receive_principal)
}

/// #2478 / #3075 — postgres PROBE half of the pending effect-namespace gate.
///
/// The DECISION lives once in
/// [`super::federation_receive::pending_namespaces_authorized_resolved`]; this
/// function only resolves, through the SAL trait, the stored namespaces of the
/// rows a pending action's EXECUTION would touch by id. The sqlite twin does
/// the same through `db::namespace_by_id`, so the two backends differ only in
/// HOW a namespace is read — never in what the answer means, which is the
/// #2488 lesson (the delete lane broke in OPPOSITE directions on the two
/// funnels because each carried its own copy of the gate).
///
/// The probe list is built here rather than inside the verdict so the #2488
/// ELISION is preserved: when Layer 1 is unarmed for this peer no stored
/// namespace can change the outcome, so a zero-config deployment pays ZERO
/// extra round-trips. A probe that cannot be answered is recorded as
/// [`ProbedNamespace::Unresolvable`], on which the shared verdict fails CLOSED.
#[cfg(feature = "sal")]
#[allow(clippy::too_many_arguments)]
async fn pending_effect_namespaces_authorized(
    app: &AppState,
    sender_agent_id: &str,
    base_lane: &str,
    pa: &crate::models::PendingAction,
    stored_pending_namespace: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_ns_scope: bool,
) -> bool {
    use crate::handlers::federation_receive::{
        ProbedNamespace, pending_namespaces_authorized_resolved, pending_scope_by_id_targets,
        pending_scope_needs_by_id_probe,
    };

    let mut probes: Vec<(&str, ProbedNamespace)> = Vec::new();
    if pending_scope_needs_by_id_probe(peer_id, attest_cfg) {
        for memory_id in pending_scope_by_id_targets(pa) {
            let probed =
                match resolve_stored_namespace(app, sender_agent_id.to_string(), memory_id).await {
                    Ok(Some(namespace)) => ProbedNamespace::Resolved(namespace),
                    Ok(None) => ProbedNamespace::Absent,
                    Err(e) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            pending_id = %pa.id,
                            memory_id = %memory_id,
                            "sync_push(store): pending by-id namespace probe failed (#2478 \
                             fail-closed): {e}"
                        );
                        ProbedNamespace::Unresolvable
                    }
                };
            probes.push((memory_id, probed));
        }
    }
    pending_namespaces_authorized_resolved(
        base_lane,
        pa,
        stored_pending_namespace,
        &probes,
        attest_cfg,
        peer_id,
        require_push_ns_scope,
    )
}

/// #2479 / #3075 — postgres READER for the severed-out-of-scope-parent WARN.
///
/// The DECISION (unchanged-link short circuit, `namespace_allowed` verdict, WARN
/// text) lives once in
/// [`super::federation_receive::warn_on_severed_out_of_scope_parent_resolved`];
/// this function only supplies the stored `parent_namespace` the sqlite twin
/// reads through `db::get_namespace_meta_entry`. Observability-only and
/// deliberately fail-OPEN on a read error, exactly as the sqlite twin is: the
/// scope verdict has ALREADY been rendered by the caller and nothing downstream
/// consults this result, so a storage fault costs the log line and nothing else.
/// (`get_namespace_standard` returns `(standard_id, parent_namespace)`; only the
/// parent is used.)
#[cfg(feature = "sal")]
async fn warn_on_severed_out_of_scope_parent_via_store(
    app: &AppState,
    sender_agent_id: &str,
    lane: &str,
    namespace: &str,
    declared_parent: Option<&str>,
    attest_cfg: &crate::federation::peer_attestation::PeerAttestationConfig,
    peer_id: Option<&str>,
) {
    let read_ctx = federation_apply_ctx(sender_agent_id.to_string());
    let stored_parent = match app.store.get_namespace_standard(&read_ctx, namespace).await {
        Ok(Some((_standard_id, parent))) => parent,
        Ok(None) => return,
        Err(e) => {
            crate::handlers::federation_receive::warn_severed_parent_unreadable(
                lane, namespace, peer_id, &e,
            );
            return;
        }
    };
    crate::handlers::federation_receive::warn_on_severed_out_of_scope_parent_resolved(
        lane,
        namespace,
        stored_parent.as_deref(),
        declared_parent,
        attest_cfg,
        peer_id,
    );
}

#[cfg(feature = "sal")]
#[allow(clippy::too_many_lines)]
pub(super) async fn sync_push_via_store(
    app: AppState,
    headers: HeaderMap,
    body: SyncPushBody,
) -> Response {
    if let Err(e) = validate::validate_agent_id(&body.sender_agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid sender_agent_id: {e}")})),
        )
            .into_response();
    }
    // Postgres-backed /sync/push must honour the same operator-tuned cap
    // as the sqlite fall-through in `sync_push` (federation_receive.rs):
    // both gate the documented-in-scope `/sync/push` batch size on
    // `app.max_page_size` (the resolved [limits] value), not the compiled
    // MAX_BULK_SIZE default — otherwise an operator who raises the cap
    // would have postgres peers silently rejected at the old 1000.
    let cap = app.max_page_size;
    if body.memories.len() > cap
        || body.deletions.len() > cap
        || body.archives.len() > cap
        || body.restores.len() > cap
        || body.pendings.len() > cap
        || body.pending_decisions.len() > cap
        || body.namespace_meta.len() > cap
        || body.namespace_meta_clears.len() > cap
        // #1556 — `links` was previously omitted from this predicate (the same
        // gap as the sqlite twin); cap it so a peer cannot bypass the batch
        // bound via an oversized links array.
        || body.links.len() > cap
        // #1566 / #1579 B1 — shipped-vector array, the largest
        // per-element payload on this surface (sqlite-twin parity).
        || body.embeddings.len() > cap
        // #1718 — signals subcollection (sqlite-twin parity).
        || body.signals.len() > cap
        // #1718 — action_transitions subcollection (sqlite-twin parity).
        || body.action_transitions.len() > cap
        // FED-RQ-01 (#1936) — checkpoints subcollection (sqlite-twin parity).
        || body.checkpoints.len() > cap
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {cap} entries per subcollection")
            })),
        )
            .into_response();
    }

    let ctx = crate::store::CallerContext::for_agent(body.sender_agent_id.clone());
    // Wave-2 B5 — SAL `/sync/push` write-dispatch record-stop CHOKEPOINT
    // (postgres twin of `refuse_if_record_stopped` on the sqlite path).
    // Every receive write below is fenced here so a new funnel cannot
    // slip past a per-op miss (ERRORS-09).
    match app.store.record_stop_status(&ctx).await {
        Ok(st) if st.stopped => {
            return super::postgres_gate::store_err_to_response(
                crate::store::StoreError::Stopped {
                    issued_by: st.issued_by,
                    scope: st.scope,
                },
            );
        }
        Ok(_) => {}
        Err(crate::store::StoreError::UnsupportedCapability { .. }) => {}
        Err(e) => return super::postgres_gate::store_err_to_response(e),
    }
    let mut applied = 0usize;
    let mut noop = 0usize;
    let mut skipped = 0usize;
    let mut attestation_rejections = Vec::new();
    let mut deleted = 0usize;
    let mut links_applied = 0usize;
    let mut latest_seen: Option<String> = None;
    // #3075 — every `/sync/push` subcollection is now trait-covered on a
    // postgres receiver, so this honest-non-ack tally is structurally ZERO. The
    // FIELD stays on the wire: senders read it (and
    // `success_report_non_ack_reason` keys off it), so dropping the entry would
    // be a silent wire change on a fleet mid-upgrade. A future subcollection
    // that lands without a pg apply MUST be added back to this tally rather
    // than omitted — an unreported lane is the silent drop this counter exists
    // to prevent.
    let unsupported_on_postgres = 0usize;
    let mut quota_refused = 0usize;
    let mut first_quota_refusal: Option<crate::quotas::QuotaError> = None;

    // v0.7.0 S6-LOW2 — observability-only sender_clock skew detection
    // (parity with the sqlite path).
    check_sender_clock_skew(&body.sender_agent_id, &body);

    // #1464 (v0.8.0, P0) — per-memory authorship gate inputs (parity with
    // the sqlite path). The outer `sync_push` already verified the body
    // signature (#791) + sender↔x-peer-id attestation (#238) before
    // dispatching here, so the peer-id + allowlist are the authority for
    // gating each row's claimed `metadata.agent_id`.
    let peer_header_owned = extract_peer_id(&headers).map(str::to_string);
    let attest_cfg = crate::federation::peer_attestation::PeerAttestationConfig::from_env();

    // #1566 / #1579 B1 — embed-once-replicate-vector + ack-after-commit
    // (sqlite-twin parity; see `federation_receive::sync_push`). The
    // pre-#1566 shape re-embedded EVERY applied row synchronously
    // (~1s/row via ollama) before responding — the receive cost rode
    // inside the sender's quorum-ack window (deadline_exceeded → DLQ)
    // and every memory was embedded up to 9× across the fleet. Now a
    // dim-matching shipped vector is stored directly (one UPDATE) and
    // everything else defers to the detached background task spawned
    // before the response below. The periodic PG embed backfill sweep
    // is the restart safety net (fixed under #1579 A4 by WS-postgres).
    let receiver_dim = app
        .embedder
        .as_ref()
        .as_ref()
        .map(crate::embeddings::Embedder::dim);
    // #2168 (SEC, data-integrity) — the receiver's OWN configured
    // embedding-space fingerprint (`<canonical_model_id>#<prefix_scheme>`),
    // resolved from the SAME `app.embedder` the local embed path uses.
    // Cross-backend parity with the sqlite funnel: compared per-row
    // against each shipped vector's fingerprint so a same-dimension vector
    // from a FOREIGN embedding model is never stored verbatim.
    let receiver_fp = app
        .embedder
        .as_ref()
        .as_ref()
        .map(crate::embeddings::Embedder::space_fingerprint);
    let shipped_by_id: std::collections::HashMap<&str, &crate::federation::ShippedEmbedding> = body
        .embeddings
        .iter()
        .map(|se| (se.memory_id.as_str(), se))
        .collect();
    let mut deferred_embed: Vec<(String, String)> = Vec::new();

    // ---- memories ----------------------------------------------------
    // #2447 (CWE-284) — loop-invariant inputs to the inbound-WRITE namespace
    // scope gate (sqlite-twin parity; the verdict function is shared verbatim
    // so both backends behave identically). `ns_scope_needs_existing` also
    // short-circuits the per-memory stored-namespace probe: when Layer 1 is not
    // armed for this peer the stored namespace cannot change the verdict, so a
    // zero-config deployment pays ZERO extra round-trips.
    let require_push_ns_scope =
        crate::federation::receive_auth::require_push_namespace_scope_enabled();
    let ns_scope_needs_existing =
        crate::federation::receive_auth::inbound_write_needs_existing_namespace(
            peer_header_owned.as_deref(),
            &attest_cfg,
        );
    for mem in &body.memories {
        if let Err(e) = validate::RequestValidator::validate_memory(mem) {
            tracing::warn!("sync_push: skipping memory {} ({}): {e}", mem.id, mem.title);
            skipped += 1;
            continue;
        }
        if latest_seen
            .as_deref()
            .is_none_or(|current| mem.updated_at.as_str() > current)
        {
            latest_seen = Some(mem.updated_at.clone());
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #2447 (CWE-284, security-high) — confine the inbound WRITE lane to
        // the peer's `allowed_namespaces` scope (sqlite-twin parity). Both the
        // CLAIMED namespace and — because `merge_memory` LWWs the `namespace`
        // field and `PostgresStore::merge_inbound` field-merges any inbound row
        // whose `id` matches an existing local row — the STORED namespace of a
        // colliding row must be in scope, or a `public/*`-scoped peer could
        // relocate + clobber a `secure/ops` row by pushing its id. A failed
        // probe fails CLOSED. Reject-before-apply: nothing reaches the store.
        let existing_ns = if ns_scope_needs_existing {
            match resolve_stored_namespace(&app, body.sender_agent_id.clone(), &mem.id).await {
                Ok(ns) => ns,
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        memory_id = %mem.id,
                        "sync_push: namespace-scope pre-resolve failed for {}: {e}; \
                         refusing the write (#2447 fail-closed)",
                        mem.id
                    );
                    skipped += 1;
                    continue;
                }
            }
        } else {
            None
        };
        if !crate::federation::receive_auth::inbound_write_namespace_authorized(
            "memories",
            &mem.id,
            &mem.namespace,
            existing_ns.as_deref(),
            &attest_cfg,
            peer_header_owned.as_deref(),
            require_push_ns_scope,
        ) {
            skipped += 1;
            continue;
        }
        // v0.7.0 S6-M2 — per-agent quota gate. `agent_quotas` lives on
        // the SQLite metadata DB even on postgres-backed daemons
        // (Wave-3 hasn't migrated the row to the SAL trait yet), so
        // the postgres path consults the same `app.db` connection the
        // sqlite path uses. F7 closure (#639) — federation receive
        // never bypasses the cap that the equivalent HTTP POST sees.
        // #1464 (v0.8.0, P0) — build the row first, then gate its quota +
        // ownership attribution (sqlite-twin parity). `resolve_governance_policy`
        // is async on the store, so resolve it before taking the quota lock.
        let local_cap = app
            .store
            .resolve_governance_policy(&mem.namespace)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(crate::models::GovernancePolicy::default)
            .effective_max_reflection_depth();
        let mut to_insert = crate::federation::reflection_bookkeeping::stamp_reflection_origin(
            mem,
            &body.sender_agent_id,
            local_cap,
        );
        // #3464 — sanitize signed identity fields before claim honor and
        // attestation verification, matching the SQLite push path. Persisted
        // `agent_attested` bytes must be exactly the bytes verified here.
        crate::handlers::federation_receive::strip_federated_pubkey_binding_or_warn(&mut to_insert);
        // #1464 — capture the originally-claimed author BEFORE attribution
        // may rewrite it (sqlite-twin parity), so the content-attestation
        // step can skip rows re-attributed to the sender.
        let original_claim = to_insert
            .metadata
            .get(crate::META_KEY_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        // #2340 (FBL-32) — redact to the TO-BE-PERSISTED form FIRST (postgres
        // twin of the sqlite receive path). Moved AHEAD of attribution for #2863
        // so BOTH the crypto-attest HONOR check and the attestation stamp verify
        // over exactly the bytes `PostgresStore::merge_inbound` persists. Redact
        // touches only content/title/write_signature; attribution reads/writes
        // only agent_id/attest_level, so the reorder is behavior-preserving.
        crate::federation::receive_auth::redact_inbound_before_attestation(&mut to_insert);
        // #2863 — resolve the CLAIMED author's enrolled key up front so a
        // cryptographically-attested third-party claim (a valid propagated
        // write_signature) is HONORED rather than re-attributed to the daemon
        // relay sender. Reused as the attestation bound key when the claim is
        // honored (attribute == claimed). The enrolled-key lookup resolves
        // through the SAL `agent_pubkey` trait method so both backends match.
        let claim_bound_key =
            match crate::identity::attest::presented_attestation_author_needing_bound_key(
                &to_insert,
                original_claim.as_deref(),
            ) {
                // #2865 — DB registry FIRST, enrolled key-dir as a MISS-ONLY
                // fallback (postgres twin of the sqlite path), so a third-party
                // author whose FEDERATION identity key is cross-enrolled in the
                // key-dir (not DB-bound) is HONORED rather than re-attributed.
                Some(c) => crate::handlers::federation_receive::historical_author_key_or_warn(
                    app.store
                        .agent_pubkey_for_attestation_at(c, &to_insert.created_at)
                        .await,
                    c,
                ),
                None => None,
            };
        let claim_write_attested = original_claim.as_deref().is_some_and(|c| {
            crate::handlers::federation_receive::inbound_claim_is_write_attested(
                &to_insert,
                c,
                claim_bound_key.as_ref(),
            )
        });
        let attribute_agent = resolve_inbound_attribution(
            &mut to_insert,
            &body.sender_agent_id,
            &attest_cfg,
            peer_header_owned.as_deref(),
            claim_write_attested,
        );
        // #1464 (v0.8.0) — per-write CONTENT attestation (postgres twin of
        // the sqlite receive path). Verify any presented
        // `metadata.write_signature` against the attributed author's enrolled
        // key → `agent_attested` vs `claimed`; reject forged, or (strict,
        // opt-in) an unsigned honored third-party claim. When the claim was
        // honored, `attribute_agent == original_claim`, so reuse the key already
        // looked up above (avoids a second lookup, #2863).
        let bound_pubkey = if Some(attribute_agent.as_str()) == original_claim.as_deref() {
            claim_bound_key.clone()
        } else if let Some(author) =
            crate::identity::attest::presented_attestation_author_needing_bound_key(
                &to_insert,
                original_claim.as_deref(),
            )
        {
            // #2865 — same DB-first, enrolled-key-dir MISS-ONLY fallback as the
            // claim key above (postgres twin), so a peer's cross-enrolled
            // FEDERATION identity key verifies a propagated write_signature and
            // reaches agent_attested out-of-box, backend-uniform with sqlite.
            crate::handlers::federation_receive::historical_author_key_or_warn(
                app.store
                    .agent_pubkey_for_attestation_at(author, &to_insert.created_at)
                    .await,
                author,
            )
        } else {
            None
        };
        if let Err(e) = apply_inbound_write_attestation(
            &mut to_insert,
            &attribute_agent,
            &body.sender_agent_id,
            original_claim.as_deref(),
            bound_pubkey.as_ref(),
            crate::federation::receive_auth::require_write_sig_enabled(),
        ) {
            // #3502 — the SSOT refusal funnel shared with the sqlite twin
            // (`federation_receive::report_inbound_attestation_rejection`), so
            // the cause taxonomy, the WARN fields and the response entry cannot
            // drift between backends.
            attestation_rejections.push(
                crate::handlers::federation_receive::report_inbound_attestation_rejection(
                    &to_insert,
                    &attribute_agent,
                    &body.sender_agent_id,
                    bound_pubkey.as_ref(),
                    crate::handlers::StorageBackend::Postgres,
                    &e,
                ),
            );
            skipped += 1;
            continue;
        }
        // v1.0.0 R19/A3 (#1948) — route-IN quarantine of a provenance-less
        // (non-`agent_attested`) relayed write (postgres twin). Opt-in +
        // permissive default; sets lifecycle_state=Quarantined so the
        // downstream merge persists it.
        crate::handlers::federation_receive::maybe_quarantine_unattributed(
            &mut to_insert,
            crate::federation::receive_auth::quarantine_unattributed_enabled(),
        );
        let bytes_estimate = i64::try_from(
            to_insert.title.len() + to_insert.content.len() + to_insert.metadata.to_string().len(),
        )
        .unwrap_or(i64::MAX);
        {
            let conn = app.db.lock().await;
            // v0.7.0 #1156 — charge against the per-namespace
            // accounting row on the postgres-receive path too.
            // #1544 — storage-bytes-only charge on the postgres receive
            // path too (see federation_receive.rs for the full rationale:
            // replication != authorship; the daily write-count charge
            // caused a cross-tenant DoS + the 429 DLQ storm). 5-agent vote
            // (memory 4d3ea1c5).
            match crate::quotas::check_and_record_storage_only(
                &conn.0,
                &attribute_agent,
                &mem.namespace,
                bytes_estimate,
            ) {
                Ok(()) => {}
                Err(crate::quotas::QuotaCheckError::Quota(q)) => {
                    tracing::warn!(
                        target: "federation::quota",
                        peer = %body.sender_agent_id,
                        attribute_agent = %attribute_agent,
                        limit = q.limit.as_str(),
                        current = q.current,
                        max = q.max,
                        "sync_push (postgres): per-agent quota exceeded"
                    );
                    // v0.7.0 #1099 (SR-1 #4, HIGH) — sign with daemon
                    // key on the postgres-path quota-refusal audit row.
                    let _ = crate::signed_events::append_signed_event(
                        &conn.0,
                        &crate::signed_events::SignedEvent::with_daemon_signature(
                            crate::signed_events::payload_hash(
                                format!(
                                    "peer={} agent={} limit={} current={} max={}",
                                    body.sender_agent_id,
                                    attribute_agent,
                                    q.limit.as_str(),
                                    q.current,
                                    q.max,
                                )
                                .as_bytes(),
                            ),
                            attribute_agent.clone(),
                            "federation.quota_refused".to_string(),
                            chrono::Utc::now().to_rfc3339(),
                            // v73 (#1822, G5a): no cause bound here yet.
                            None,
                        ),
                    );
                    quota_refused += 1;
                    if first_quota_refusal.is_none() {
                        first_quota_refusal = Some(q);
                    }
                    drop(conn);
                    break;
                }
                Err(crate::quotas::QuotaCheckError::Sql(e)) => {
                    tracing::warn!(
                        "sync_push (postgres): quota substrate read failed for {}: {e}",
                        attribute_agent
                    );
                    skipped += 1;
                    continue;
                }
            }
        }
        // (`local_cap`, `to_insert` + the #1464 attribution gate were
        // resolved above the quota gate — honouring operator-set
        // per-namespace reflection caps via the SAL `resolve_governance_policy`
        // (both backends) and applying any per-memory re-attribution — so
        // the exact persisted row is stored here.)
        // #2314 — route the postgres receive funnel through the HARDENED
        // `merge_inbound` (previously dead code): it carries the G30
        // forget-tombstone resurrection guard, the G29 secret-screen
        // redact, the #1719 attestation sanitize + #1755 updated_at clamp,
        // and the same-id `merge_memory` field-merge — the exact guard set
        // the sqlite funnel gets from `db::merge_inbound`/`insert_if_newer`.
        // Pre-fix this called `apply_remote_memory`, which had NONE of the
        // receive-lane guards (a stale peer could resurrect a forgotten
        // row; a same-id/different-title push error-skipped forever).
        // #2863 — pass the receiver's VERIFIED verdict (postgres twin) so the
        // merge-over-existing path re-asserts `agent_attested` atomically when the
        // persisted row is byte-identical to the signed unit this node verified;
        // `row_is_agent_attested` reads the post-`apply` `to_insert`.
        match app
            .store
            .merge_inbound(
                &ctx,
                &to_insert,
                crate::handlers::federation_receive::row_is_agent_attested(&to_insert),
            )
            .await
        {
            Ok(applied_id) => {
                applied += 1;
                // v1.0.0 R19/A3 (#1948) — route-OUT dequarantine-on-attest
                // (postgres twin). `merge_inbound` PRESERVES an existing
                // row's lifecycle_state (merge_memory keeps the local
                // state), so a now-attested write clears any prior
                // quarantine via the SAL raw-UPDATE surface.
                if crate::handlers::federation_receive::row_is_agent_attested(&to_insert) {
                    let _ = app.store.dequarantine(&applied_id).await;
                }
                // v0.7.0 Wave-3 Continuation 5 (S18+S79 federation
                // semantic recall) — the postgres `embedding` column
                // must land populated or peer-side semantic recall
                // surfaces empty. #1566 / #1579 B1: prefer the
                // sender's shipped vector (dim-matching → one UPDATE,
                // no embed at all); otherwise defer the local embed
                // to the background task spawned before the response.
                // #1584 (SEC) — finite + L2-norm validation of the
                // shipped vector before it lands (dim gate alone lets a
                // NaN/non-normalized vector poison cosine ranking).
                // `None` (or dim mismatch) defers a local re-embed.
                let clean_shipped = shipped_by_id.get(mem.id.as_str()).and_then(|se| {
                    // #1566 / #1579 B1 — dim gate: store a shipped vector
                    // directly only when its dimensionality matches the local
                    // embedder AND the sender's claimed dim matches the payload.
                    if receiver_dim != Some(se.dim) || se.vector.len() != se.dim {
                        return None;
                    }
                    // #2168 (SEC, data-integrity) — vector-space fingerprint
                    // gate (cross-backend twin of the sqlite funnel). A
                    // same-dimension vector produced by a DIFFERENT embedding
                    // model (or the same model under a different prefix scheme)
                    // lives in a different coordinate space: stored verbatim it
                    // would silently poison this node's cosine recall. Compare
                    // the shipped fingerprint against the receiver's configured
                    // embedder fingerprint; a mismatch falls through to the
                    // EXISTING deferred local re-embed so the row still lands
                    // (CRDT-safe) and is re-embedded under the LOCAL model. CORE
                    // INVARIANT: a foreign-fingerprint vector NEVER enters the
                    // local space — worst case the row is re-embed-pending,
                    // never poisoned. Degrade, never corrupt.
                    let shipped_fp = crate::embeddings::embedding_space_fingerprint(&se.model);
                    if receiver_fp.as_deref() != Some(shipped_fp.as_str()) {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            memory_id = %applied_id,
                            peer_id = %body.sender_agent_id,
                            shipped_fingerprint = %shipped_fp,
                            local_fingerprint = %receiver_fp.as_deref().unwrap_or("<none>"),
                            "sync_push (postgres): refusing foreign-embedding-model shipped \
                             vector (#2168) — deferring local re-embed under the local model"
                        );
                        return None;
                    }
                    // #1584 (SEC) — finite + L2-norm the accepted
                    // (matching-space) vector before it is stored.
                    crate::federation::sanitize_shipped_vector(&se.vector)
                        .map(|v| (v, se.model.clone()))
                });
                match clean_shipped {
                    Some((vector, model)) => {
                        // #2167 §2-EXC — SHIPPED vector stamps the sender's
                        // CLAIMED space (`mint(se.model)`); recall excludes it
                        // unless it equals the active space (degraded-not-wrong).
                        let claimed_space = crate::embeddings::embedding_space_fingerprint(&model);
                        if let Err(e) = app
                            .store
                            .update_embedding(&ctx, &applied_id, Some(&vector), &claimed_space)
                            .await
                        {
                            tracing::warn!(
                                "sync_push (postgres): storing shipped embedding failed \
                                 for {applied_id} (model {model}): {e} — deferring local embed",
                            );
                            deferred_embed.push((
                                applied_id.clone(),
                                crate::embeddings::embedding_document(&mem.title, &mem.content),
                            ));
                        }
                    }
                    None => deferred_embed.push((
                        applied_id.clone(),
                        crate::embeddings::embedding_document(&mem.title, &mem.content),
                    )),
                }
                // F2 audit-chain emit: every accepted federation push
                // chains through the same audit log as a local Store.
                // Phase-9 wiring — file-based audit module is backend-
                // blind so this works for postgres-backed daemons.
                if crate::audit::is_enabled() {
                    let owner = mem
                        .metadata
                        .get("agent_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&body.sender_agent_id);
                    crate::audit::emit(
                        crate::audit::EventBuilder::new(
                            crate::audit::AuditAction::Store,
                            crate::audit::actor(owner, "federation_push", None),
                            crate::audit::target_memory(
                                mem.id.clone(),
                                mem.namespace.clone(),
                                Some(mem.title.clone()),
                                Some(mem.tier.as_str().to_string()),
                                None,
                            ),
                        )
                        .outcome(crate::audit::AuditOutcome::Allow),
                    );
                }
            }
            Err(e) => {
                // Refund the quota we charged so a downstream write
                // failure doesn't leak counters (saturating; safe).
                {
                    let conn = app.db.lock().await;
                    // #1156 — refund on the same `(agent_id,
                    // namespace)` row check_and_record_storage_only
                    // incremented (#1544 — storage-bytes only; the daily
                    // write-count is never charged on receive).
                    let _ = crate::quotas::refund_storage_only(
                        &conn.0,
                        &attribute_agent,
                        &mem.namespace,
                        bytes_estimate,
                    );
                }
                tracing::warn!("sync_push: apply_remote_memory failed for {}: {e}", mem.id);
                skipped += 1;
            }
        }
    }

    // v0.7.0 S6-M2 — quota refusal short-circuit (postgres path).
    if let Some(q) = first_quota_refusal.take() {
        // #1566 / #1579 B1 — rows applied before the refusal are
        // committed; their deferred embeds still run (sqlite-twin
        // parity) instead of waiting for the backfill sweep.
        spawn_deferred_embedding_refresh_via_store(&app, &ctx, deferred_embed);
        let reset_at = next_utc_midnight();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("x-quota-reset-at", reset_at.as_str()),
                ("x-quota-limit", q.limit.as_str()),
            ],
            Json(json!({
                "error": "QUOTA_EXCEEDED",
                "limit": q.limit.as_str(),
                "current": q.current,
                "max": q.max,
                "agent_id": q.agent_id,
                "applied_before_refusal": applied,
                (crate::handlers::QUOTA_REFUSED_FIELD): quota_refused,
                (crate::handlers::ATTESTATION_REJECTIONS_FIELD): &attestation_rejections,
                "reset_at": reset_at,
                (field_names::STORAGE_BACKEND): "postgres",
            })),
        )
            .into_response();
    }

    // ---- deletions ---------------------------------------------------
    for del_id in &body.deletions {
        if validate::validate_id(del_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #1934 (CWE-284) POSTGRES PARITY, landed with #2447 — the #1934 fix
        // confined the SQLITE delete loop to the peer's `allowed_namespaces`
        // but never reached this twin, so a `public/*`-scoped peer could
        // hard-delete a `secure/ops` row on any postgres-backed node by id.
        // `PostgresStore::apply_remote_deletion` discards its `_ctx` entirely
        // (deliberately — see the trait doc), so nothing downstream re-checks.
        //
        // #2488 (CWE-284, GA blocker) — the #2447 form wrapped this whole gate
        // in `ns_scope_needs_existing`, i.e. in `inbound_write_needs_existing_
        // namespace`, which is the read-ELISION predicate and returns FALSE for
        // an enrolled peer whose `allowed_namespaces` is empty — exactly the
        // peer shape Layer 2 was voted in to refuse. So the gate was
        // structurally unreachable for that shape and `apply_remote_deletion`
        // ran unguarded: the peer that may not write anywhere could still
        // destroy anything. The guard is now the ENROLLED posture
        // (`has_allowlist()`), the shared verdict decides, and the probe stays
        // elided on the Layer-2-only shapes where its answer cannot change the
        // verdict — so the fix costs ZERO extra reads versus pre-#2488.
        // A missing row stays a no-op (the peer may have GC'd it); an
        // UNRESOLVABLE row fails closed with a distinguishable cause.
        // Fable 5 1×7 vote (4d3ea1c5).
        if attest_cfg.has_allowlist() {
            let needs_stored = crate::federation::receive_auth::peer_declares_namespace_scope(
                peer_header_owned.as_deref(),
                &attest_cfg,
            );
            let stored_ns = if needs_stored {
                match resolve_stored_namespace(&app, body.sender_agent_id.clone(), del_id).await {
                    Ok(Some(namespace)) => Some(namespace),
                    Ok(None) => {
                        noop += 1;
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            memory_id = %del_id,
                            cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                            error = %e,
                            "sync_push: refusing federated deletion of {del_id} — the target \
                             row's namespace is UNRESOLVABLE on this node, so the scope gate \
                             cannot decide (#1934/#2488 fail-closed). This row cannot be \
                             federated-deleted until the read succeeds; investigate the \
                             storage error rather than the peer's scope."
                        );
                        skipped += 1;
                        continue;
                    }
                }
            } else {
                None
            };
            if !crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                crate::federation::receive_auth::LANE_DELETIONS,
                del_id,
                stored_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            ) {
                skipped += 1;
                continue;
            }
        }
        match app.store.apply_remote_deletion(&ctx, del_id).await {
            Ok(true) => deleted += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push: apply_remote_deletion failed for {del_id}: {e}");
                skipped += 1;
            }
        }
    }

    // ---- links -------------------------------------------------------
    //
    // H3 verify path: when a link arrives with a signature + observed_by,
    // verify against the locally enrolled public key. Tampered = skip.
    // Unknown observed_by = accept-and-flag as unsigned. Successful =
    // peer_attested. Mirrors the sqlite-backed handler's H3 contract.
    for link in &body.links {
        if validate::RequestValidator::validate_link_triple(
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        )
        .is_err()
        {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #2711 (CWE-284, CB-7) — namespace confinement for links[] on the
        // POSTGRES funnel (sqlite-twin parity; the sqlite lane is #2489). A link
        // binds two endpoints, so BOTH endpoints' STORED namespaces are the
        // subject — a claimed-only gate would let a `public/*`-scoped peer relate
        // (and thereby relocate-by-reference) a `secure/ops` row by id. Gate only
        // under the ENROLLED posture (`has_allowlist()`); zero-config stays
        // byte-identical faith replication. A failed probe fails CLOSED (skip);
        // a missing endpoint under Layer 1 cannot prove scope, so it fails CLOSED
        // too. The probe is the SCALAR `MemoryStore::namespace_by_id` (never a
        // full-row `get` — the #2488 decrypt-fail-closed / over-read lesson).
        if attest_cfg.has_allowlist() {
            let needs_stored = crate::federation::receive_auth::peer_declares_namespace_scope(
                peer_header_owned.as_deref(),
                &attest_cfg,
            );
            let src_ns = if needs_stored {
                match resolve_stored_namespace(&app, body.sender_agent_id.clone(), &link.source_id)
                    .await
                {
                    Ok(ns) => ns,
                    Err(e) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            memory_id = %link.source_id,
                            error = %e,
                            "sync_push (postgres): refusing federated link — source namespace \
                             unresolvable (#2711 fail-closed)"
                        );
                        skipped += 1;
                        continue;
                    }
                }
            } else {
                None
            };
            let dst_ns = if needs_stored {
                match resolve_stored_namespace(&app, body.sender_agent_id.clone(), &link.target_id)
                    .await
                {
                    Ok(ns) => ns,
                    Err(e) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            memory_id = %link.target_id,
                            error = %e,
                            "sync_push (postgres): refusing federated link — target namespace \
                             unresolvable (#2711 fail-closed)"
                        );
                        skipped += 1;
                        continue;
                    }
                }
            } else {
                None
            };
            // Missing endpoint under Layer 1: fail closed (cannot prove scope).
            if needs_stored && (src_ns.is_none() || dst_ns.is_none()) {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    source_id = %link.source_id,
                    target_id = %link.target_id,
                    "sync_push (postgres): refusing federated link — endpoint missing so scope \
                     cannot decide (#2711)"
                );
                skipped += 1;
                continue;
            }
            let src_ok = crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                crate::federation::receive_auth::LANE_LINKS,
                &link.source_id,
                src_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            );
            let dst_ok = crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                crate::federation::receive_auth::LANE_LINKS,
                &link.target_id,
                dst_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            );
            if !src_ok || !dst_ok {
                skipped += 1;
                continue;
            }
        }
        let attest_level = match (link.signature.as_deref(), link.observed_by.as_deref()) {
            (Some(sig_bytes), Some(observed_by)) => {
                match crate::identity::verify::lookup_peer_public_key(observed_by) {
                    Some(pubkey) => {
                        let signable = crate::identity::sign::SignableLink {
                            src_id: &link.source_id,
                            dst_id: &link.target_id,
                            relation: link.relation.as_str(),
                            observed_by: Some(observed_by),
                            created_at: Some(link.created_at.as_str()),
                            valid_from: link.valid_from.as_deref(),
                            valid_until: link.valid_until.as_deref(),
                        };
                        match crate::identity::verify::verify(&pubkey, &signable, sig_bytes) {
                            Ok(()) => crate::models::AttestLevel::PeerAttested.as_str(),
                            Err(e) => {
                                tracing::warn!(
                                    "sync_push: signature rejected for link \
                                     ({} -> {} / {}) from observed_by={}: {e}",
                                    link.source_id,
                                    link.target_id,
                                    link.relation,
                                    observed_by
                                );
                                skipped += 1;
                                continue;
                            }
                        }
                    }
                    None => crate::models::AttestLevel::Unsigned.as_str(),
                }
            }
            _ => crate::models::AttestLevel::Unsigned.as_str(),
        };
        match app.store.apply_remote_link(&ctx, link, attest_level).await {
            Ok(()) => links_applied += 1,
            Err(e) => {
                tracing::warn!(
                    "sync_push: apply_remote_link failed ({} -> {} / {}): {e}",
                    link.source_id,
                    link.target_id,
                    link.relation
                );
                skipped += 1;
            }
        }
    }

    // #3075 — the `unsupported_on_postgres` bucket that used to sit HERE is
    // gone: `archives[]`, `restores[]`, `pendings[]`, `pending_decisions[]`,
    // `namespace_meta[]`, `namespace_meta_clears[]` and `checkpoints[]` all
    // apply through the SAL trait now, each behind the SAME `receive_auth`
    // verdict the sqlite receiver runs (see their loops below). The counter
    // itself is retained and reported as zero — see its declaration above for
    // why the field must not be dropped from the wire, and what a future
    // un-migrated subcollection must do instead of omitting itself.
    //
    // #1718 — signals round-trip via the SAL trait (`apply_remote_signal`:
    // accept-and-flag-unsigned, idempotent on the UUID, forged-sig refused) —
    // sqlite-twin parity. The #1544 storage-bytes quota lives on the SQLite
    // metadata DB even on postgres-backed daemons (same as the memories loop
    // above), so it is charged via `app.db` before the trait write.
    let mut signals_applied = 0usize;
    let require_signal_sig = crate::federation::receive_auth::require_signal_sig_enabled();
    for sig in &body.signals {
        if validate::validate_id(&sig.id).is_err() {
            skipped += 1;
            continue;
        }
        // #1843 (v0.8.1) — bind `from_agent` to the enrolled peer's authorship
        // (sqlite-twin parity; see `federation_receive::signal_author_authorized`).
        // The forged-signature check lives inside `apply_remote_signal` below; the
        // author binding is checked here, before the quota charge + trait write,
        // and is a PER-SIGNAL skip — the rest of the push still applies.
        if !signal_author_authorized(
            sig,
            &body.sender_agent_id,
            &attest_cfg,
            peer_header_owned.as_deref(),
            require_signal_sig,
        ) {
            skipped += 1;
            continue;
        }
        // #2711 (CWE-284, CB-7) — namespace confinement for signals[] on the
        // POSTGRES funnel (sqlite-twin parity; the sqlite lane is #2489).
        // Authorship (`signal_author_authorized` above) answers "who authored";
        // this choke answers "may this peer write in the signal's namespace". The
        // subject is the signal's own claimed namespace. Zero-config short-circuits
        // inside `inbound_write_namespace_authorized` (`!has_allowlist()`).
        if !crate::federation::receive_auth::inbound_write_namespace_authorized(
            crate::federation::receive_auth::LANE_SIGNALS,
            &sig.id,
            &sig.namespace,
            None,
            &attest_cfg,
            peer_header_owned.as_deref(),
            require_push_ns_scope,
        ) {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #3049 / #3269 / #3278 — federation-RECEIVE secret screen for the
        // coordination plane on the POSTGRES funnel (sqlite-twin parity; the
        // sqlite lane screens at `federation_receive::sync_push`). Before this,
        // the postgres receive path applied signal `subject` / `body` /
        // `reference_ids` VERBATIM via `apply_remote_signal` — a credential
        // shipped by an `off`-mode or hostile peer landed unscreened. REDACT-
        // only, and AFTER the authorship / namespace gates above so those see
        // the bytes the peer signed. When the screen mutates the SIGNED surface
        // (`subject`/`body`) the helper clears the now-stale attestation, so the
        // subsequent `apply_remote_signal` verify accepts it as unsigned (#2340).
        let screened_signal = crate::secret_screen::redact_signal_for_storage(sig);
        let sig = screened_signal.as_ref().unwrap_or(sig);
        let bytes = i64::try_from(sig.body.to_string().len()).unwrap_or(i64::MAX);
        {
            let lock = app.db.lock().await;
            if let Err(e) = crate::quotas::check_and_record_storage_only(
                &lock.0,
                &sig.from_agent,
                &sig.namespace,
                bytes,
            ) {
                tracing::warn!(
                    "sync_push(store): signal {} refused by storage quota: {e}",
                    sig.id
                );
                skipped += 1;
                continue;
            }
        }
        match app.store.apply_remote_signal(&ctx, sig).await {
            Ok(_) => signals_applied += 1,
            Err(crate::store::StoreError::InvalidInput { .. }) => {
                tracing::warn!(
                    "sync_push(store): signal {} refused (invalid signature)",
                    sig.id
                );
                skipped += 1;
            }
            Err(e) => {
                tracing::warn!("sync_push(store): signal apply failed for {}: {e}", sig.id);
                skipped += 1;
            }
        }
    }

    // #1718 — action transitions round-trip via the SAL trait. FAIL-CLOSED
    // authorization (sqlite-twin parity): each op is authorized against the
    // attested actor's enrolled key + best-effort local lease before the atomic
    // compare-and-swap on the expected `from_state`. No storage quota — a
    // transition mutates existing action state, not net-new storage.
    let mut action_transitions_applied = 0usize;
    let require_tx_sig = crate::federation::receive_auth::require_transition_sig_enabled();
    for op in &body.action_transitions {
        if validate::validate_id(&op.action_id).is_err() {
            skipped += 1;
            continue;
        }
        let local = match app.store.action_get(&ctx, &op.action_id).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                noop += 1;
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "sync_push(store): action get failed for {}: {e}",
                    op.action_id
                );
                skipped += 1;
                continue;
            }
        };
        // #2711 (CWE-284, CB-7) — namespace confinement for action_transitions[]
        // on the POSTGRES funnel (sqlite-twin parity; the sqlite lane is #2649).
        // Authentication is not authorization: the crypto authz below answers
        // "who signed"; this choke answers "may this peer touch the STORED action
        // namespace". Subject is the **stored** namespace already loaded for the
        // signable — no extra read. Zero-config short-circuits inside the helper.
        if !crate::federation::receive_auth::inbound_write_namespace_authorized(
            crate::federation::receive_auth::LANE_ACTION_TRANSITIONS,
            &op.action_id,
            &local.namespace,
            Some(local.namespace.as_str()),
            &attest_cfg,
            peer_header_owned.as_deref(),
            require_push_ns_scope,
        ) {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        let enrolled = op
            .claimed_by
            .as_deref()
            .and_then(crate::identity::verify::lookup_peer_public_key);
        let lease_holder = app
            .store
            .lease_get(&ctx, &op.action_id)
            .await
            .ok()
            .flatten()
            .map(|l| l.holder);
        let signable = crate::identity::sign::SignableTransition {
            action_id: &op.action_id,
            namespace: &local.namespace,
            from_state: op.from_state.as_str(),
            to_state: op.to_state.as_str(),
            claimed_by: op.claimed_by.as_deref(),
            nonce: &op.nonce,
            created_at: op.updated_at,
        };
        match crate::federation::receive_auth::authorize_remote_transition(
            &signable,
            &op.signature,
            enrolled.as_ref(),
            lease_holder.as_deref(),
            require_tx_sig,
        ) {
            crate::federation::receive_auth::TransitionAuthz::Accept => {
                // #1805 — per-transition nonce anti-replay (postgres twin of the
                // sqlite federation_receive path). The signed transition nonce
                // was never recorded; record it in the per-peer nonce cache and
                // refuse a replay (a captured signed op re-wrapped in a fresh
                // envelope replays through CAS on a cyclic/ABA edge). Empty
                // nonce = unsigned op → not gated. Rides #1718 / 4d3ea1c5.
                if !op.nonce.is_empty() {
                    use base64::Engine as _;
                    let nstr = base64::engine::general_purpose::STANDARD.encode(&op.nonce);
                    if matches!(
                        app.federation_nonce_cache
                            .record_and_check(peer_header_owned.as_deref().unwrap_or(""), &nstr),
                        crate::identity::replay::ReplayDecision::Replay
                    ) {
                        tracing::warn!(
                            target: crate::federation::SIGNING_TRACE_TARGET,
                            action_id = %op.action_id,
                            "sync_push(store): replayed action-transition nonce refused (#1805)"
                        );
                        skipped += 1;
                        continue;
                    }
                }
                match app
                    .store
                    .action_transition_cas(
                        &ctx,
                        &op.action_id,
                        op.from_state,
                        op.to_state,
                        op.claimed_by.as_deref(),
                        op.updated_at,
                    )
                    .await
                {
                    Ok(crate::actions::CasOutcome::Applied(_)) => action_transitions_applied += 1,
                    Ok(_) => noop += 1,
                    Err(e) => {
                        tracing::warn!(
                            "sync_push(store): action transition {} cas failed: {e}",
                            op.action_id
                        );
                        skipped += 1;
                    }
                }
            }
            verdict => {
                tracing::warn!(
                    "sync_push(store): action transition {} refused ({verdict:?})",
                    op.action_id
                );
                skipped += 1;
            }
        }
    }

    // #2447 (CWE-284) — the by-id sibling lanes (`archives[]` / `restores[]`)
    // and the governance-STANDARD lanes probe under the whole ENROLLED posture,
    // not just a declared scope, so Layer 2's disposition of an unscoped
    // enrolled peer is IDENTICAL on every lane and on both backends.
    let ns_gate_enrolled = attest_cfg.has_allowlist();
    // ---- pendings / pending_decisions (#2478, #2529, #1920, #3075) -----
    //
    // The GOVERNANCE lanes. `pendings[]` injects UNDECIDED rows; decisions
    // converge through `pending_decisions[]`. Both apply through the SAL trait
    // with the sqlite receiver's gate chain, in the same order:
    //
    //   * #2529 — a wire row claiming a TERMINAL status is refused (a peer must
    //     not inject a pre-approved row and skip the decision path), and a
    //     locally-DECIDED row is never clobbered by a replay;
    //   * #1920 (CWE-862) — `pending_author_authorized` gates WHO a pending may
    //     be attributed to, so a hostile peer cannot file an action as an
    //     arbitrary `requested_by` and approve it in the same request;
    //   * #2478 (CWE-284) — the effect-namespace gate. The subject is the UNION
    //     of every namespace the EXECUTION would touch (claimed payload
    //     namespaces + the stored namespace of every by-id target), NOT the
    //     pending row's declared `namespace`, because `execute_pending_action`
    //     never reads that field. Unknown `action_type` is default-deny. The
    //     VERDICT is the shared `pending_namespaces_authorized_resolved`; only
    //     the by-id PROBE differs per backend, and the elision keeps a
    //     zero-config deployment at ZERO extra reads;
    //   * #3278 — the payload secret screen, AFTER the authorship + scope gates
    //     so they read the bytes the peer signed, and BEFORE the upsert.
    //
    // The APPROVE arm routes through `approve_with_approver_type` (the hardened
    // gate: self-approval refusal, registered-approver, approver-type policy),
    // never the raw `pending_decide`, which would trust the wire `decider`. The
    // REJECT arm grants no authority, so it keeps the idempotent
    // `pending_decide(false)` transition — but under the #2532 scope gate and
    // with the decider REBOUND to the attested peer (#2720), so a forged
    // operator id never reaches the signed audit row.
    let mut pendings_applied = 0usize;
    let mut pending_decisions_applied = 0usize;
    for pa in &body.pendings {
        if validate::validate_id(&pa.id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        if pa.status != crate::handlers::federation_receive::PENDING_STATUS_PENDING {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                pending_id = %pa.id,
                status = %pa.status,
                "sync_push(store): refusing federated pendings entry with non-pending status \
                 (#2529) — use pending_decisions[] to converge decisions"
            );
            skipped += 1;
            continue;
        }
        if !crate::handlers::federation_receive::pending_author_authorized(
            pa,
            &body.sender_agent_id,
            &attest_cfg,
            peer_header_owned.as_deref(),
        ) {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                pending_id = %pa.id,
                requested_by = %pa.requested_by,
                sender = %body.sender_agent_id,
                peer_id = %peer_header_owned.as_deref().unwrap_or(""),
                "sync_push(store): peer not authorized to inject a pending action attributed \
                 to requested_by (#1920) — skipping"
            );
            skipped += 1;
            continue;
        }
        // Probe the LOCAL row once, for the #2529 terminal-status refusal and
        // the #2478 stored-namespace subject.
        let probe_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        let local_pending = match app.store.get_pending(&probe_ctx, &pa.id).await {
            Ok(row) => row,
            Err(e) => {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %pa.id,
                    cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                    "sync_push(store): refusing federated pendings entry — local governance \
                     row unresolvable (#2478/#2529 fail-closed): {e}"
                );
                skipped += 1;
                continue;
            }
        };
        if let Some(existing) = local_pending.as_ref() {
            if existing.status != crate::handlers::federation_receive::PENDING_STATUS_PENDING {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %pa.id,
                    local_status = %existing.status,
                    "sync_push(store): refusing federated pendings upsert — local row is \
                     already decided (#2529); decisions converge via pending_decisions[]"
                );
                skipped += 1;
                continue;
            }
        }
        if ns_gate_enrolled {
            let stored_pending_ns = local_pending.as_ref().map(|row| row.namespace.clone());
            if !pending_effect_namespaces_authorized(
                &app,
                &body.sender_agent_id,
                crate::federation::receive_auth::LANE_PENDINGS,
                pa,
                stored_pending_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            )
            .await
            {
                skipped += 1;
                continue;
            }
        }
        let screened_pa = crate::secret_screen::redact_pending_action_for_storage(pa);
        let pa = screened_pa.as_ref().unwrap_or(pa);
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        match app.store.apply_remote_pending_action(&apply_ctx, pa).await {
            Ok(()) => {
                pendings_applied += 1;
                // v0.7.0 K4 — peer-originated pending rows fire the
                // `approval_requested` event here too, so local approval-API
                // subscribers see a uniform queue regardless of which node
                // minted the row. The subscription plane lives on the sqlite
                // metadata DB on BOTH backends (the local pending-create
                // handlers dispatch through `app.db` identically), so this is
                // the same call the sqlite receive loop makes.
                let lock = app.db.lock().await;
                crate::subscriptions::dispatch_approval_requested(&lock.0, &pa.id, &lock.1);
            }
            Err(e) => {
                tracing::warn!(
                    "sync_push(store): apply_remote_pending_action failed for {}: {e}",
                    pa.id
                );
                skipped += 1;
            }
        }
    }
    for dec in &body.pending_decisions {
        if validate::validate_id(&dec.id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // The pending row is resolved from LOCAL STORAGE, never from the
        // `pendings[]` entry of this same request: that entry is
        // attacker-controlled, so gating against it would be a TOCTOU on the
        // gate's own input. It is also resolved BEFORE the approve, never
        // between approve and execute — the consensus arm durably appends the
        // vote and can flip `status` at threshold, so a refusal landing after
        // it would leave an approved-but-unexecuted row.
        let probe_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        let pa = match app.store.get_pending(&probe_ctx, &dec.id).await {
            Ok(Some(pa)) => pa,
            // Unknown pending — the converged no-op. Counting it `skipped`
            // would make every converged replica non-ack forever (#2491).
            Ok(None) => {
                noop += 1;
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %dec.id,
                    cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                    "sync_push(store): refusing federated pending decision — the target \
                     governance row is UNRESOLVABLE on this node (#2478/#2532 fail-closed): {e}"
                );
                skipped += 1;
                continue;
            }
        };
        // Both arms pass the SAME base lane: the destructive
        // `pending_decisions (delete)` variant is selected INSIDE the shared
        // verdict, from the pending action's own effect, not from the wire.
        if ns_gate_enrolled
            && !pending_effect_namespaces_authorized(
                &app,
                &body.sender_agent_id,
                crate::federation::receive_auth::LANE_PENDING_DECISIONS,
                &pa,
                None,
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            )
            .await
        {
            if !dec.approved {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %dec.id,
                    namespace = %pa.namespace,
                    "sync_push(store): refusing federated pending REJECT — peer not \
                     authorized for the pending's effect namespaces (#2532); unauthorized \
                     veto closed"
                );
            }
            skipped += 1;
            continue;
        }
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        if dec.approved {
            // #2478 — the `deleted` counter must report rows DESTROYED, not
            // deletes attempted, or the 200 envelope lies in the other
            // direction. The executor's delete arm discards the boolean, so
            // probe first. An Err resolves to `false`, which UNDER-reports
            // rather than claiming a destruction that may not have happened.
            let delete_target_existed = pa.action_type
                == crate::models::GovernedAction::Delete.as_str()
                && match pa.memory_id.as_deref() {
                    Some(mid) => matches!(
                        resolve_stored_namespace(&app, body.sender_agent_id.clone(), mid).await,
                        Ok(Some(_))
                    ),
                    None => false,
                };
            match app
                .store
                .approve_with_approver_type(&apply_ctx, &dec.id, &dec.decider)
                .await
            {
                Ok(crate::store::ApproveOutcome::Approved) => {
                    pending_decisions_applied += 1;
                    match app.store.execute_pending_action(&apply_ctx, &dec.id).await {
                        Ok(_) => {
                            if delete_target_existed {
                                deleted += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "sync_push(store): execute_pending_action failed for {}: {e}",
                                dec.id
                            );
                            // #2478 — without this the decision counted APPLIED
                            // while its side effect never landed and `skipped`
                            // stayed 0, so the sender ACKed a write that does
                            // not exist here.
                            skipped += 1;
                        }
                    }
                }
                // Consensus-gated: the relayed vote was recorded but quorum is
                // not yet met on this peer — nothing to execute.
                Ok(crate::store::ApproveOutcome::Pending { .. }) => pending_decisions_applied += 1,
                Ok(crate::store::ApproveOutcome::Rejected(reason)) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        pending_id = %dec.id,
                        decider = %dec.decider,
                        "sync_push(store): refusing forged / unauthorized federated approval \
                         (#1920): {reason}"
                    );
                    skipped += 1;
                }
                // The postgres adapter reports an unknown pending as a typed
                // NotFound where the sqlite free function reports
                // `ApproveOutcome::NotFound`; both are the converged no-op.
                Err(crate::store::StoreError::NotFound { .. }) => noop += 1,
                Err(e) => {
                    tracing::warn!(
                        "sync_push(store): approve_with_approver_type failed for {}: {e}",
                        dec.id
                    );
                    skipped += 1;
                }
            }
        } else {
            // #2720 F-12 (CWE-346) — bind the decider to the attested peer,
            // never the self-asserted wire `dec.decider`, so the signed
            // `pending_action.denied` audit row records the real actor.
            let bound_decider = resolve_inbound_decider(
                &dec.decider,
                &body.sender_agent_id,
                &attest_cfg,
                peer_header_owned.as_deref(),
            );
            match app
                .store
                .decide_pending_action(&apply_ctx, &dec.id, false, &bound_decider)
                .await
            {
                Ok(true) => pending_decisions_applied += 1,
                Ok(false) => noop += 1, // already decided — converged state
                Err(e) => {
                    tracing::warn!(
                        "sync_push(store): decide_pending_action (reject) failed for {}: {e}",
                        dec.id
                    );
                    skipped += 1;
                }
            }
        }
    }

    // ---- checkpoints (FED-RQ-01 #1936, #125, #2708, L5, #3075) ---------
    //
    // Federated commit-checkpoint RESOLUTIONS — the separation-of-duties freeze
    // anchor. FAIL-CLOSED authorization, sqlite-twin parity, step for step:
    //
    //   * only RESOLVED checkpoints federate (a pending one carries no
    //     attestation, so there is nothing to authorize or apply);
    //   * #2708 (CB-3, CWE-284) namespace confinement on BOTH the CLAIMED wire
    //     namespace and the STORED by-id namespace, because the CAS keys on
    //     `(id, state)` only: a peer scoped to `public/*` must not resolve a
    //     `secure/ops` freeze anchor by presenting a benign wire namespace. The
    //     stored probe is ELIDED when Layer 1 is not armed for this peer, so a
    //     zero-config deployment pays ZERO extra reads, and FAILS CLOSED when
    //     it cannot resolve;
    //   * #125 / FED-RQ-01: the resolution's Ed25519 attestation is verified
    //     against the RESOLVER'S locally-ENROLLED key — never the wire
    //     `resolver_pubkey` (the #1718/#87 authority-lane discipline) — through
    //     the SHARED `receive_auth::authorize_remote_checkpoint_resolution`, so
    //     `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` now binds on a pg receiver
    //     exactly as it does on sqlite. A forged signature is refused
    //     UNCONDITIONALLY, regardless of the knob;
    //   * #3049 secret screen AFTER the attestation check, so the resolver-key
    //     verification still runs over the bytes the resolver actually signed;
    //   * the receiver NEVER re-signs (v0.8.0 local-substrate rule): the apply
    //     goes through `apply_remote_checkpoint_resolution`, NOT
    //     `checkpoint_resolve`, which would stamp this node's own attestation
    //     onto another node's verdict.
    //
    // Per-item skip on unverifiable / conflict — the batch survives. No storage
    // quota (a resolution is a state change, not net-new authorship, #1544).
    let mut checkpoints_applied = 0usize;
    let mut checkpoints_conflicted = 0usize;
    let require_checkpoint_sig = crate::federation::receive_auth::require_checkpoint_sig_enabled();
    for cp in &body.checkpoints {
        if validate::validate_id(&cp.id).is_err()
            || validate::validate_namespace(&cp.namespace).is_err()
        {
            skipped += 1;
            continue;
        }
        if cp.state == crate::models::CheckpointState::Pending {
            skipped += 1;
            continue;
        }
        let existing_cp_ns = if ns_scope_needs_existing {
            let probe_ctx = federation_apply_ctx(body.sender_agent_id.clone());
            match app.store.checkpoint_get(&probe_ctx, &cp.id).await {
                Ok(row) => row.map(|c| c.namespace),
                Err(e) => {
                    // Fail CLOSED: an unresolvable existence probe cannot be
                    // reported as "provably no local row" — that is exactly the
                    // input the stored-vs-claimed relocate bypass needs.
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        checkpoint_id = %cp.id,
                        cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                        "sync_push(store): checkpoint namespace-scope pre-resolve failed for {}: \
                         {e}; refusing the resolution (#2708 fail-closed)",
                        cp.id
                    );
                    skipped += 1;
                    continue;
                }
            }
        } else {
            None
        };
        if !crate::federation::receive_auth::inbound_write_namespace_authorized(
            crate::federation::receive_auth::LANE_CHECKPOINTS,
            &cp.id,
            &cp.namespace,
            existing_cp_ns.as_deref(),
            &attest_cfg,
            peer_header_owned.as_deref(),
            require_push_ns_scope,
        ) {
            skipped += 1;
            continue;
        }
        let enrolled = cp
            .resolved_by
            .as_deref()
            .and_then(crate::identity::verify::lookup_peer_public_key);
        let signable = crate::checkpoints::resolution_signable(cp);
        match crate::federation::receive_auth::authorize_remote_checkpoint_resolution(
            &signable,
            &cp.signature,
            enrolled.as_ref(),
            require_checkpoint_sig,
        ) {
            // #3164 — `Accept(key)` is the authenticated verdict;
            // `AcceptUnverified` is the permissive rollout window. Both apply.
            crate::federation::receive_auth::CheckpointResolutionAuthz::Accept(_)
            | crate::federation::receive_auth::CheckpointResolutionAuthz::AcceptUnverified => {
                if body.dry_run {
                    noop += 1;
                    continue;
                }
                let screened_cp = crate::secret_screen::redact_checkpoint_for_storage(cp);
                let cp = screened_cp.as_ref().unwrap_or(cp);
                let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
                match app
                    .store
                    .apply_remote_checkpoint_resolution(&apply_ctx, cp)
                    .await
                {
                    Ok(crate::checkpoints::InboundResolutionOutcome::Applied) => {
                        checkpoints_applied += 1;
                    }
                    Ok(crate::checkpoints::InboundResolutionOutcome::Noop) => noop += 1,
                    Ok(crate::checkpoints::InboundResolutionOutcome::Conflict) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            checkpoint_id = %cp.id,
                            "sync_push(store): inbound checkpoint resolution conflicts with a \
                             different local resolution — first-resolution-wins, keeping local \
                             (#1936)"
                        );
                        checkpoints_conflicted += 1;
                        skipped += 1;
                    }
                    Ok(crate::checkpoints::InboundResolutionOutcome::RefusedReservedKind) => {
                        // PR-1 / L5 (#2708-sibling, CWE-284): a wire-reachable
                        // `/sync/push` MUST NOT steer the substrate's own
                        // audit-signal spine. Per-item skip; batch survives.
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            checkpoint_id = %cp.id,
                            condition_type = %cp.condition_type.as_str(),
                            namespace = %cp.namespace,
                            "sync_push(store): refusing inbound resolution of a \
                             substrate-reserved checkpoint anchor (L5 audit-signal poisoning, \
                             #2708-sibling); skipping this entry, batch survives"
                        );
                        skipped += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "sync_push(store): checkpoint resolution apply failed for {}: {e}",
                            cp.id
                        );
                        skipped += 1;
                    }
                }
            }
            verdict => {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    checkpoint_id = %cp.id,
                    "sync_push(store): inbound checkpoint resolution refused ({verdict:?}) (#1936)"
                );
                skipped += 1;
            }
        }
    }

    // ---- archives / restores (#2447, #3075) ----------------------------
    //
    // v0.6.2 (S29) sqlite-twin parity. `archives[]` is the SOFT move of a live
    // row into `archived_memories` (distinct from `deletions[]`, which hard
    // deletes); `restores[]` is its inverse. Both apply through the SAL trait
    // (`apply_remote_archive` / `apply_remote_restore`, both adapters) instead
    // of reporting the lane `unsupported_on_postgres` (#3075).
    //
    // #2447 — both lanes are the same BY-ID reach into a foreign namespace the
    // #1934 delete gate closed, one step softer: an archive still removes the
    // row from every live read of a namespace the peer was denied, and an
    // ARCHIVED row is the input `restores[]` resurrects. So both are confined
    // with the shared `inbound_by_id_namespace_authorized` verdict on the
    // row's STORED namespace, resolved through the SCALAR by-id projection —
    // `namespace_by_id` for archives (the row is still live) and
    // `archived_namespace_by_id` for restores (the row is in the archive
    // table, which is the whole point of the lane). A missing row stays a
    // no-op; an UNRESOLVABLE probe fails CLOSED, because reporting a read
    // fault as "provably no local row" is exactly the input a
    // stored-vs-claimed relocate bypass needs (#2497).
    //
    // The #1848 / G30 forget-tombstone gate on `restores[]` is NOT here: it
    // lives inside `apply_remote_restore` on BOTH adapters, so it cannot be
    // omitted by a future caller that reaches the trait method another way.
    let mut archived = 0usize;
    let mut restored = 0usize;
    for arch_id in &body.archives {
        if validate::validate_id(arch_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        if ns_gate_enrolled {
            match resolve_stored_namespace(&app, body.sender_agent_id.clone(), arch_id).await {
                Ok(Some(namespace)) => {
                    if !crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                        crate::federation::receive_auth::LANE_ARCHIVES,
                        arch_id,
                        Some(&namespace),
                        &attest_cfg,
                        peer_header_owned.as_deref(),
                        require_push_ns_scope,
                    ) {
                        skipped += 1;
                        continue;
                    }
                }
                Ok(None) => {
                    noop += 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        memory_id = %arch_id,
                        cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                        "sync_push(store): archive pre-resolve failed for {arch_id}: {e}; \
                         refusing the archive (#2447 fail-closed)"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        match app.store.apply_remote_archive(&apply_ctx, arch_id).await {
            Ok(true) => archived += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push(store): apply_remote_archive failed for {arch_id}: {e}");
                skipped += 1;
            }
        }
    }
    for res_id in &body.restores {
        if validate::validate_id(res_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        if ns_gate_enrolled {
            let probe_ctx = federation_apply_ctx(body.sender_agent_id.clone());
            match app.store.archived_namespace_by_id(&probe_ctx, res_id).await {
                Ok(Some(namespace)) => {
                    if !crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                        crate::federation::receive_auth::LANE_RESTORES,
                        res_id,
                        Some(&namespace),
                        &attest_cfg,
                        peer_header_owned.as_deref(),
                        require_push_ns_scope,
                    ) {
                        skipped += 1;
                        continue;
                    }
                }
                Ok(None) => {
                    noop += 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        memory_id = %res_id,
                        cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                        "sync_push(store): restore pre-resolve failed for {res_id}: {e}; \
                         refusing the restore (#2447 fail-closed)"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        match app.store.apply_remote_restore(&apply_ctx, res_id).await {
            Ok(true) => restored += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push(store): apply_remote_restore failed for {res_id}: {e}");
                skipped += 1;
            }
        }
    }

    // ---- namespace_meta / namespace_meta_clears (#2479, #3075) ---------
    //
    // v0.6.2 (S35) sqlite-twin parity: apply the peer's governance-STANDARD
    // rows through `MemoryStore::{set,clear}_namespace_standard` so a
    // postgres-backed receiver converges on the originator's inheritance chain
    // instead of reporting the whole lane `unsupported_on_postgres` (#3075).
    //
    // AUTHORIZATION IS THE SQLITE VERDICT, VERBATIM. Both loops call
    // `receive_auth::inbound_namespace_meta_authorized`, which is backend-blind
    // (no connection, no probe — `namespace_meta`'s PRIMARY KEY is the namespace
    // itself, so there is no stored-vs-claimed split to resolve and the #2447
    // relocate bypass has no subject here). That covers, in one shared
    // function: the #2479 Amendment E UNCONDITIONAL refusal on the GLOBAL `*`
    // standard for any peer that did not declare `**`, the row's own namespace,
    // the declared `parent_namespace` it splices above that namespace, and the
    // #2536 deep-descendant probe. A refusal increments the additive
    // `namespace_meta_refused` counter AND `skipped` — identical to the sqlite
    // twin, and deliberately not folded, because this funnel enqueues nothing to
    // the push DLQ (#2498) so the sender is the only party that can retry.
    let mut namespace_meta_applied = 0usize;
    let mut namespace_meta_cleared = 0usize;
    let mut namespace_meta_refused = 0usize;
    for entry in &body.namespace_meta {
        if validate::validate_namespace(&entry.namespace).is_err()
            || validate::validate_id(&entry.standard_id).is_err()
        {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        if ns_gate_enrolled {
            if !crate::federation::receive_auth::inbound_namespace_meta_authorized(
                crate::federation::receive_auth::LANE_NAMESPACE_META,
                &entry.namespace,
                entry.parent_namespace.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            ) {
                namespace_meta_refused += 1;
                skipped += 1;
                continue;
            }
            // AFTER the verdict, never before: a refused entry severs nothing,
            // so warning about it would be false (sqlite-twin ordering).
            warn_on_severed_out_of_scope_parent_via_store(
                &app,
                &body.sender_agent_id,
                crate::federation::receive_auth::LANE_NAMESPACE_META,
                &entry.namespace,
                entry.parent_namespace.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
            )
            .await;
        }
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        match app
            .store
            .set_namespace_standard(
                &apply_ctx,
                &entry.namespace,
                &entry.standard_id,
                entry.parent_namespace.as_deref(),
            )
            .await
        {
            Ok(()) => namespace_meta_applied += 1,
            Err(e) => {
                tracing::warn!(
                    "sync_push(store): set_namespace_standard failed for {}: {e}",
                    entry.namespace
                );
                skipped += 1;
            }
        }
    }
    for ns in &body.namespace_meta_clears {
        if validate::validate_namespace(ns).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // The DESTRUCTIVE twin: `clear_namespace_standard` removes the standard
        // AND the parent link in one statement, and because governance is
        // allow-on-silence an absent policy resolves PERMISSIVE — so this lane
        // DISARMS a namespace (and, by inheritance, its descendants). No
        // `standard_id` rides this lane, hence no parent to gate: the namespace
        // is the whole subject (sqlite-twin reasoning, verbatim).
        if ns_gate_enrolled {
            if !crate::federation::receive_auth::inbound_namespace_meta_authorized(
                crate::federation::receive_auth::LANE_NAMESPACE_META_CLEARS,
                ns,
                None,
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            ) {
                namespace_meta_refused += 1;
                skipped += 1;
                continue;
            }
            warn_on_severed_out_of_scope_parent_via_store(
                &app,
                &body.sender_agent_id,
                crate::federation::receive_auth::LANE_NAMESPACE_META_CLEARS,
                ns,
                None,
                &attest_cfg,
                peer_header_owned.as_deref(),
            )
            .await;
        }
        let apply_ctx = federation_apply_ctx(body.sender_agent_id.clone());
        match app.store.clear_namespace_standard(&apply_ctx, ns).await {
            Ok(true) => namespace_meta_cleared += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push(store): clear_namespace_standard failed for {ns}: {e}");
                skipped += 1;
            }
        }
    }

    // #1566 / #1579 B1 — ack-after-commit: the response (the sender's
    // quorum ack) returns now; rows still needing a locally-computed
    // vector are embedded by this detached task.
    spawn_deferred_embedding_refresh_via_store(&app, &ctx, deferred_embed);

    (
        StatusCode::OK,
        Json(json!({
            "applied": applied,
            "deleted": deleted,
            // #3075 — archive / restore lane counters, sqlite-twin names.
            "archived": archived,
            // #3075 / FED-RQ-01 — checkpoint-resolution counters, sqlite-twin names.
            // #3075 — governance-queue lane counters, sqlite-twin names.
            "pendings_applied": pendings_applied,
            "pending_decisions_applied": pending_decisions_applied,
            "checkpoints_applied": checkpoints_applied,
            "checkpoints_conflicted": checkpoints_conflicted,
            "restored": restored,
            "links_applied": links_applied,
            "signals_applied": signals_applied,
            "action_transitions_applied": action_transitions_applied,
            // #3075 — governance-STANDARD lane counters, sqlite-twin names.
            "namespace_meta_applied": namespace_meta_applied,
            "namespace_meta_cleared": namespace_meta_cleared,
            // #2479 — additive; see the sqlite twin's declaration for why this
            // is not folded into `skipped`.
            "namespace_meta_refused": namespace_meta_refused,
            "noop": noop,
            (crate::handlers::SKIPPED_FIELD): skipped,
            (crate::handlers::QUOTA_REFUSED_FIELD): quota_refused,
            (crate::handlers::ATTESTATION_REJECTIONS_FIELD): &attestation_rejections,
            (crate::handlers::UNSUPPORTED_ON_POSTGRES_FIELD): unsupported_on_postgres,
            "dry_run": body.dry_run,
            "receiver_agent_id": body.sender_agent_id,
            (field_names::STORAGE_BACKEND): "postgres",
            "note": "every /sync/push subcollection round-trips via the SAL trait on \
                     this backend (#3075): memories / deletions / links / signals / \
                     action_transitions / archives / restores / namespace_meta / \
                     namespace_meta_clears / checkpoints / pendings / \
                     pending_decisions",
        })),
    )
        .into_response()
}

/// #1566 / #1579 B1 — deferred receive-side embedding refresh for the
/// SAL-routed (postgres) receive path. Trait twin of
/// `federation_receive::spawn_deferred_embedding_refresh`: the embed
/// runs on the blocking pool OFF the request path and the vector lands
/// via `MemoryStore::update_embedding`. Errors are logged and the row
/// is left for the periodic PG embed backfill sweep (#1579 A4) — same
/// best-effort posture as the pre-#1566 inline embed, minus the
/// quorum-window coupling. No-op when `rows` is empty or the receiver
/// runs keyword-only (no embedder).
#[cfg(feature = "sal")]
fn spawn_deferred_embedding_refresh_via_store(
    app: &AppState,
    ctx: &crate::store::CallerContext,
    rows: Vec<(String, String)>,
) {
    if rows.is_empty() || app.embedder.as_ref().as_ref().is_none() {
        return;
    }
    let store = app.store.clone();
    let embedder = app.embedder.clone();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        for (id, text) in rows {
            let emb = embedder.clone();
            let embed_res =
                tokio::task::spawn_blocking(move || emb.as_ref().as_ref().map(|e| e.embed(&text)))
                    .await;
            let vec = match embed_res {
                Ok(Some(Ok(v))) => v,
                Ok(Some(Err(e))) => {
                    tracing::warn!("sync_push (postgres): deferred embed failed for {id}: {e}");
                    continue;
                }
                // Embedder vanished (impossible — checked above and the
                // Arc is immutable) — nothing left to do for any row.
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!("sync_push (postgres): deferred embed join error for {id}: {e}");
                    continue;
                }
            };
            // #2167 — LOCAL re-embed lands in the receiver's ACTIVE space.
            let space = match embedder.as_ref().as_ref() {
                Some(e) => e.space_fingerprint(),
                None => return,
            };
            if let Err(e) = store.update_embedding(&ctx, &id, Some(&vec), &space).await {
                tracing::warn!(
                    "sync_push (postgres): deferred update_embedding failed for {id}: {e}"
                );
            }
        }
    });
}

/// v0.7.0 FED-P2d — process-wide federation trust bundle, loaded once
/// from the environment on first verify and cached for the daemon's
/// lifetime. An empty bundle (no `AI_MEMORY_FED_TRUST_BUNDLE_DIR`, a
/// missing dir, or a dir with no valid issuer keys) is the signal to
/// fall through to the legacy per-peer `.pub` enrolment path, so a
/// node that has not adopted CA-rooted credentials behaves exactly as
/// it did pre-P2. A load error is logged once and treated as empty
/// (never partitions a federation pair on a misconfigured bundle dir).
///
/// FED-P3 replaces this boot-once cache with an `AppState`-threaded,
/// reloadable bundle so an operator can rotate the trust root without
/// a daemon restart; the receiver-verify call sites are unchanged by
/// that swap because both take `&TrustBundle`.
fn cached_trust_bundle() -> &'static TrustBundle {
    static BUNDLE: OnceLock<TrustBundle> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        TrustBundle::load_from_env().unwrap_or_else(|e| {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                error = %e,
                "failed to load federation trust bundle; continuing with legacy per-peer verify"
            );
            TrustBundle::new()
        })
    })
}

/// v0.7.0 FED-P2d — resolve the Ed25519 verifying key the receiver
/// should check a peer's `X-Memory-Sig` against.
///
/// Precedence:
///   1. **CA-rooted credential** — when the trust bundle is non-empty
///      AND the peer presented an `X-Memory-Cred` header that the
///      bundle can verify AND the credential's subject binds to the
///      claimed `X-Peer-Id`, use the credential's subject key.
///   2. **Legacy per-peer enrolment** — otherwise fall through to the
///      historical on-disk `.pub` key for the peer-id.
///
/// Credential verification NEVER hard-fails the request here: any
/// parse / trust / binding failure logs a WARN and returns the legacy
/// key (or `None`), so a transient or malformed credential can never
/// partition a federation pair that also has a legacy enrolled key.
/// The enforcement matrix in the caller still decides the outcome from
/// the `(sig_header, resolved_key)` pair — this function only swaps the
/// key *source*, leaving the four-arm policy untouched.
fn resolve_peer_verifying_key(
    headers: &HeaderMap,
    peer_id: Option<&str>,
    bundle: &TrustBundle,
    now_unix: i64,
) -> Option<VerifyingKey> {
    // FED-P4-e (§8) — signed-vs-unsigned-ratio SLO: bucket every inbound
    // identity resolution by whether the peer presented a credential at
    // all, independent of trust-bundle state or verify outcome.
    crate::metrics::record_federation_inbound_cred(headers.contains_key(CREDENTIAL_HEADER));

    if !bundle.is_empty()
        && let Some(cred_value) = headers.get(CREDENTIAL_HEADER).and_then(|v| v.to_str().ok())
    {
        // FED-P4 — a hierarchical peer additionally carries its
        // intermediate CA cert(s) in CHAIN_HEADER; absent ⇒ single-level
        // (P2/P3) verify, byte-identical to pre-P4.
        let chain_value = headers.get(CHAIN_HEADER).and_then(|v| v.to_str().ok());
        match verify_credential_pubkey(cred_value, chain_value, peer_id, bundle, now_unix) {
            Some(vk) => {
                // FED-P4-e (§8) — verify-failure-rate SLO.
                crate::metrics::record_federation_cred_verify(true);
                return Some(vk);
            }
            None => crate::metrics::record_federation_cred_verify(false),
        }
    }
    peer_id.and_then(|pid| {
        crate::governance::audit::load_daemon_verifying_key(pid)
            .ok()
            .flatten()
    })
}

/// v0.7.0 FED-P2d / FED-P4 — verify a wire `X-Memory-Cred` (+ optional
/// `X-Memory-Cred-Chain`) against the trust bundle and bind it to the
/// claimed peer-id.
///
/// Returns the leaf credential's subject verifying key only when ALL hold:
///   - the leaf header value parses as a `SignedCredential`,
///   - any presented intermediate-chain header parses,
///   - the assembled chain verifies against the bundle: the anchor's
///     issuer is trusted, every link's signature + window + name + domain
///     binding holds, and the depth is within `DEFAULT_MAX_CHAIN_DEPTH`
///     (a one-level chain — no chain header — reduces to the exact P2/P3
///     `bundle.verify` semantics),
///   - the leaf's `subject_agent_id` equals the claimed `X-Peer-Id`
///     (identity binding — prevents a valid credential for agent A from
///     authenticating a push attributed to agent B).
///
/// Any failure logs a WARN against `federation::signing` and returns
/// `None`, signalling the caller to fall through to the legacy path.
fn verify_credential_pubkey(
    cred_value: &str,
    chain_value: Option<&str>,
    peer_id: Option<&str>,
    bundle: &TrustBundle,
    now_unix: i64,
) -> Option<VerifyingKey> {
    let leaf = match SignedCredential::from_header_value(cred_value) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                tag = e.tag(),
                peer_id = %peer_id.unwrap_or(""),
                "sync: X-Memory-Cred malformed; falling back to legacy per-peer verify"
            );
            return None;
        }
    };
    let intermediates = match chain_value {
        Some(value) => match CertChain::intermediates_from_header_value(value) {
            Ok(inters) => inters,
            Err(e) => {
                tracing::warn!(
                    target: crate::federation::SIGNING_TRACE_TARGET,
                    tag = e.tag(),
                    peer_id = %peer_id.unwrap_or(""),
                    "sync: X-Memory-Cred-Chain malformed; falling back to legacy"
                );
                return None;
            }
        },
        None => Vec::new(),
    };
    let chain = CertChain::new(leaf, intermediates);
    let cred = match chain.verify(bundle, now_unix, DEFAULT_MAX_CHAIN_DEPTH) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                tag = e.tag(),
                peer_id = %peer_id.unwrap_or(""),
                "sync: X-Memory-Cred chain failed trust-bundle verification; falling back to legacy"
            );
            return None;
        }
    };
    if peer_id != Some(cred.subject_agent_id.as_str()) {
        tracing::warn!(
            target: crate::federation::SIGNING_TRACE_TARGET,
            peer_id = %peer_id.unwrap_or(""),
            cred_subject = %cred.subject_agent_id,
            "sync: X-Memory-Cred subject does not match X-Peer-Id; refusing credential binding"
        );
        return None;
    }
    match cred.subject_verifying_key() {
        Ok(vk) => Some(vk),
        Err(e) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                tag = e.tag(),
                peer_id = %peer_id.unwrap_or(""),
                "sync: X-Memory-Cred subject key malformed; falling back to legacy"
            );
            None
        }
    }
}

/// v0.7.0 #791 — verify the `X-Memory-Sig` header against the raw
/// body bytes the receiver observed. Returns `Some(Response)` to
/// short-circuit with a 401 when verification is required and fails;
/// `None` when verification passed OR the receiver is opted out via
/// `AI_MEMORY_FED_REQUIRE_SIG=0`.
///
/// **Enforcement matrix** (with `AI_MEMORY_FED_REQUIRE_SIG=1`, the
/// v0.7.0 default):
///
/// | sig header | key enrolled | outcome                              |
/// |------------|--------------|--------------------------------------|
/// | present    | yes          | verify; refuse on bad sig            |
/// | present    | no           | refuse (cannot verify untrusted sig) |
/// | absent     | yes          | refuse (enrolled peer must sign)     |
/// | absent     | no           | allow + WARN (degraded permissive)   |
///
/// The "neither side enrolled" allow-with-warn arm keeps an
/// unenrolled federation pair operational while the strict-deny
/// arms fire once an operator enrols a peer key.
/// `AI_MEMORY_FED_REQUIRE_SIG=0` bypasses every branch.
pub(super) fn verify_signature_or_reject(
    headers: &HeaderMap,
    body_bytes: &[u8],
    peer_id: Option<&str>,
    federation_nonce_cache: &crate::identity::replay::FederationNonceCache,
) -> Option<Response> {
    if !fed_signing::require_sig() {
        return None;
    }
    let sig_header = headers
        .get(fed_signing::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok());
    let nonce_header = headers
        .get(fed_signing::NONCE_HEADER)
        .and_then(|v| v.to_str().ok());
    let pubkey = resolve_peer_verifying_key(
        headers,
        peer_id,
        cached_trust_bundle(),
        chrono::Utc::now().timestamp(),
    );

    match (sig_header, pubkey.as_ref()) {
        (Some(sig), Some(pk)) => {
            // v0.7.0 #922 — nonce-bound signature verify when nonce
            // header is present; legacy body-only verify otherwise.
            let verify_result = if let Some(nonce) = nonce_header {
                fed_signing::verify_header_with_nonce(Some(sig), body_bytes, nonce, pk)
            } else {
                fed_signing::verify_header(Some(sig), body_bytes, pk)
            };
            if let Err(e) = verify_result {
                tracing::warn!(
                    target: crate::federation::SIGNING_TRACE_TARGET,
                    tag = e.tag(),
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_push: X-Memory-Sig verification failed"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": e.tag(),
                            "note": "AI_MEMORY_FED_REQUIRE_SIG=1 enforces per-message Ed25519 \
                                     signatures on /sync/push; set =0 to revert to v0.6.x \
                                     permissive",
                        })),
                    )
                        .into_response(),
                );
            }
            // v0.7.0 #922 — apply nonce-freshness gate.
            let pid_for_cache = peer_id.unwrap_or("");
            match nonce_header {
                Some(nonce) if !nonce.is_empty() => {
                    match federation_nonce_cache.record_and_check(pid_for_cache, nonce) {
                        crate::identity::replay::ReplayDecision::Fresh => None,
                        crate::identity::replay::ReplayDecision::Replay => {
                            tracing::warn!(
                                target: crate::federation::SIGNING_TRACE_TARGET,
                                tag = fed_signing::VerifyError::ReplayedNonce.tag(),
                                peer_id = %pid_for_cache,
                                "sync_push: X-Memory-Nonce replay detected"
                            );
                            Some(
                                (
                                    StatusCode::UNAUTHORIZED,
                                    Json(json!({
                                        "error": fed_signing::VerifyError::ReplayedNonce.tag(),
                                        "note": "AI_MEMORY_FED_REQUIRE_NONCE=1 enforces per-message nonce freshness.",
                                    })),
                                )
                                    .into_response(),
                            )
                        }
                    }
                }
                _ => {
                    if fed_signing::require_nonce() {
                        tracing::warn!(
                            target: crate::federation::SIGNING_TRACE_TARGET,
                            tag = fed_signing::VerifyError::NonceMissing.tag(),
                            peer_id = %pid_for_cache,
                            "sync_push: X-Memory-Nonce header absent — strict refusal"
                        );
                        Some(
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "error": fed_signing::VerifyError::NonceMissing.tag(),
                                    "note": "AI_MEMORY_FED_REQUIRE_NONCE=1 requires X-Memory-Nonce; set =0 to bypass.",
                                })),
                            )
                                .into_response(),
                        )
                    } else {
                        tracing::warn!(
                            target: crate::federation::SIGNING_TRACE_TARGET,
                            peer_id = %pid_for_cache,
                            "sync_push: X-Memory-Nonce absent — permissive, accepting"
                        );
                        None
                    }
                }
            }
        }
        (Some(_), None) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: X-Memory-Sig present but no enrolled public key for peer-id"
            );
            Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "x_memory_sig_no_enrolled_key",
                        "note": "AI_MEMORY_FED_REQUIRE_SIG=1 and the peer sent a signature, \
                                 but no public key is enrolled for the peer-id; enrol via \
                                 `ai-memory identity import` or set =0 to bypass.",
                    })),
                )
                    .into_response(),
            )
        }
        (None, Some(_)) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: enrolled peer omitted X-Memory-Sig header"
            );
            Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": fed_signing::VerifyError::Missing.tag(),
                        "note": "AI_MEMORY_FED_REQUIRE_SIG=1 enforces per-message Ed25519 \
                                 signatures for enrolled peers; set =0 to revert to v0.6.x \
                                 permissive.",
                    })),
                )
                    .into_response(),
            )
        }
        (None, None) => {
            // v0.7.0 #1088 (SR-1 #3, MEDIUM) — fail-CLOSED on
            // unenrolled-peer attribution spoofing. v0.8.0 #1789 flipped
            // the secure default ON: enrollment is REQUIRED by default,
            // and the companion escape hatch
            // `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` opens a rollout
            // window that accepts unenrolled peers on this SAME arm.
            // 5-agent vote (memory `4d3ea1c5`) fixed the flip.
            if require_peer_enrollment_enabled() && !allow_unenrolled_peers_enabled() {
                tracing::warn!(
                    target: crate::federation::SIGNING_TRACE_TARGET,
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_push: refusing unenrolled peer-id (peer enrollment required, v0.8 secure default #1789)"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "peer_not_enrolled",
                            "note": "Federation requires peer enrollment by default at \
                                     v0.8 (#1789): X-Peer-Id without an enrolled Ed25519 \
                                     key is refused. Enroll the peer's key via the operator \
                                     workflow, or set AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0 \
                                     to revert to v0.7.x permissive, OR set \
                                     AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 to allow \
                                     unenrolled peers during a rollout window.",
                        })),
                    )
                        .into_response(),
                );
            }
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: unsigned (no enrolled key for peer-id) — strict enforcement skipped"
            );
            None
        }
    }
}

/// Env var gating peer-enrollment enforcement. Hoisted to a named const
/// (v1.0.0 §5.3 cutline ruling) — was a bare literal at the single
/// `std::env::var` call site inside [`require_peer_enrollment_enabled`];
/// `crate::enterprise_federation_posture` reuses this const rather than
/// re-declaring the env-var-name string.
pub(crate) const REQUIRE_PEER_ENROLLMENT_ENV: &str = "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT";

/// v0.8.0 #1789 — `true` when peer-enrollment is required (the v0.8
/// **secure default**). UNSET — or any non-falsy value — returns `true`:
/// federation refuses an `X-Peer-Id` without an enrolled Ed25519 key.
/// An explicit falsy value (`0` / `false` / `no` / `off`, case-insensitive,
/// trimmed) returns `false`, reverting to the v0.7.x permissive posture
/// where unenrolled peers are accepted. Honored by both
/// `verify_signature_or_reject` and `verify_get_signature_or_reject`
/// so the `(None, None)` arm fails closed on both surfaces by default.
///
/// History: at v0.7.0 (#1088) this defaulted OFF (permissive) and only
/// `1`/`true` opted IN to strict enforcement. v0.8.0 (#1789) flipped the
/// secure default ON; the companion escape hatch
/// `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` (`allow_unenrolled_peers_enabled`)
/// preserves a rollout opt-out. The 5-agent vote (memory `4d3ea1c5`)
/// fixed this flip.
///
/// `pub(crate)` (v1.0.0 §5.3 cutline ruling) — reused verbatim by
/// `crate::enterprise_federation_posture::evaluate` so the
/// `doctor --posture enterprise-federation` check + the boot gate
/// share the EXACT same resolution logic as the receive-path gate
/// instead of re-deriving the truthy/falsy grammar a second time.
pub(crate) fn require_peer_enrollment_enabled() -> bool {
    match std::env::var(REQUIRE_PEER_ENROLLMENT_ENV) {
        Ok(v) => peer_enrollment_value_enabled(&v),
        // UNSET → secure default ON (#1789).
        Err(_) => true,
    }
}

/// Value-level half of [`require_peer_enrollment_enabled`]'s grammar: given
/// an already-resolved value, is peer-enrollment still REQUIRED? Explicit
/// falsy values (`0`/`false`/`no`/`off`, case-INSENSITIVE, trimmed) revert to
/// the v0.7.x permissive posture; everything else — the truthy set and any
/// other non-empty string — keeps the v0.8 secure default ON.
///
/// Split out of [`require_peer_enrollment_enabled`] (#3033) as the ONE
/// grammar SSOT both the live receive gate AND the `asi-hard` KNOBS
/// `meets_floor` predicate for `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` share,
/// so the boot-refusal floor is decided by the EXACT parse the runtime uses
/// (case-insensitive here — deliberately unlike the case-sensitive
/// [`crate::federation::receive_auth::flag_value_default_on`] siblings) rather
/// than a re-derived grammar (the NB1 false-red class).
pub(crate) fn peer_enrollment_value_enabled(v: &str) -> bool {
    let t = v.trim();
    !(t.eq_ignore_ascii_case("0")
        || t.eq_ignore_ascii_case("false")
        || t.eq_ignore_ascii_case("no")
        || t.eq_ignore_ascii_case("off"))
}

/// Env var gating the unenrolled-peer rollout escape hatch. Hoisted to a
/// named const (v1.0.0 §5.3 cutline ruling B1 fix) — was a bare literal
/// at the single `std::env::var` call site inside
/// [`allow_unenrolled_peers_enabled`]; `crate::enterprise_federation_posture`
/// reuses this const AND the function itself rather than re-deriving the
/// combined `require_peer_enrollment_enabled() && !allow_unenrolled_peers_enabled()`
/// gate a second time.
pub(crate) const ALLOW_UNENROLLED_PEERS_ENV: &str = "AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS";

/// v0.8.0 #1789 — companion permissive escape hatch (env #44).
/// Returns `true` when `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` is truthy
/// (`1` / `true` / `yes` / `on`, case-insensitive, trimmed), `false`
/// otherwise (the default). When enabled it accepts unenrolled peers on
/// the `(None, None)` arm even though enrollment is required by the v0.8
/// secure default — the rollout window opt-out so the #1789 flip is not a
/// hard break with no escape. Honored by both `verify_signature_or_reject`
/// and `verify_get_signature_or_reject`.
///
/// `pub(crate)` (v1.0.0 §5.3 cutline ruling B1) — reused verbatim by
/// `crate::enterprise_federation_posture::evaluate` so the peer-enrollment
/// posture check shares the EXACT combined predicate the live receive
/// gate uses, instead of checking only half of it.
pub(crate) fn allow_unenrolled_peers_enabled() -> bool {
    std::env::var(ALLOW_UNENROLLED_PEERS_ENV)
        .map(|v| allow_unenrolled_peers_value_enabled(&v))
        .unwrap_or(false)
}

/// Value-level half of [`allow_unenrolled_peers_enabled`]. Trimmed `1` /
/// case-insensitive `true`/`yes`/`on` arms the hatch; every other token
/// (including empty) keeps it CLOSED. Shared with the `asi-hard` KNOBS
/// `meets_floor` (#3201) so a value the live receive gate would not honour
/// cannot refuse boot (NB1).
#[must_use]
pub(crate) fn allow_unenrolled_peers_value_enabled(v: &str) -> bool {
    let t = v.trim();
    t == "1"
        || t.eq_ignore_ascii_case("true")
        || t.eq_ignore_ascii_case("yes")
        || t.eq_ignore_ascii_case("on")
}

// ---------------------------------------------------------------------------
// #1031 (Agent-5 #2) — verify per-message signature on GET /sync/since
// ---------------------------------------------------------------------------
//
// Pre-#1031 `/sync/since` accepted `X-Peer-Id` without ever verifying a
// signature, so an attacker who cleared api-key middleware or rode the
// mTLS bypass at `transport.rs:644` could spoof `X-Peer-Id` and project
// every `federation_share=true` row PLUS every `scope=private` row
// owned by the spoofed peer — the visibility gate (`is_visible_to_caller`)
// trusted the spoofed header as the caller identity.
//
// The fix mirrors `/sync/push`: require an `X-Memory-Sig` over canonical
// GET-request bytes binding `method + path + canonical-query`, and
// chain through the same `FederationNonceCache` for replay protection.
// Canonical bytes:
//
//   "GET" || 0x0A || super::routes::SYNC_SINCE || 0x0A || canonical_query
//
// where `canonical_query` is the request's raw query string verbatim
// (the caller fixes the param ordering before signing — a future
// hardening can normalise + sort, but stability of the
// signer-vs-verifier byte stream is the load-bearing property right
// now). The same enforcement matrix that gates `/sync/push` applies:
// `AI_MEMORY_FED_REQUIRE_SIG=1` (v0.7.0 default) enforces; `=0` reverts
// to v0.6.x permissive for peer-rollout windows.

/// v0.7.0 #1031 — build canonical bytes for a federation GET request.
///
/// `method` is uppercased (`"GET"`); `path` is the request URI's path
/// component verbatim; `query` is the request's raw query string
/// (without the leading `?`). The three components are joined by
/// `0x0A` (newline) so a downstream verifier reproduces the same
/// byte stream from the routing layer's `Method` + `Uri` extractors
/// without re-parsing.
#[must_use]
pub(super) fn canonical_get_bytes(method: &str, path: &str, query: &str) -> Vec<u8> {
    // #2290 — delegate to the federation-signing SSOT so the receiver
    // verifier and every outbound catch-up client sign/verify byte-identical
    // canonical bytes (they cannot drift).
    fed_signing::canonical_get_bytes(method, path, query)
}

/// v0.7.0 #1031 — verify an `X-Memory-Sig` header against the
/// canonical GET-request bytes and apply the nonce-freshness gate.
///
/// Returns `Some(Response)` to short-circuit the handler with a 401
/// when verification is required and fails; `None` when verification
/// passed OR the receiver opted out via `AI_MEMORY_FED_REQUIRE_SIG=0`.
///
/// Wire shape mirrors `/sync/push`:
///   - `X-Memory-Sig: ed25519=<b64>` — signature over
///     `canonical_get_bytes(method, path, query) || 0x00 || X-Memory-Nonce`
///   - `X-Memory-Nonce: <opaque>` — per-message freshness token
///   - `X-Peer-Id: <peer>` — identifies which enrolled key to verify against
///
/// Enforcement matrix matches `verify_signature_or_reject`:
///
/// | sig header | nonce | key enrolled | outcome                              |
/// |------------|-------|--------------|--------------------------------------|
/// | present    | any   | yes          | verify; refuse on bad sig            |
/// | present    | any   | no           | refuse (cannot verify untrusted sig) |
/// | absent     | any   | yes          | refuse (enrolled peer must sign)     |
/// | absent     | any   | no           | allow + WARN (degraded permissive)   |
///
/// The "neither side enrolled" allow-with-warn arm keeps an
/// unenrolled federation pair operational while the strict-deny
/// arms fire once an operator enrols a peer key.
/// `AI_MEMORY_FED_REQUIRE_SIG=0` bypasses every branch (mirrors the
/// `/sync/push` env-var posture).
pub(super) fn verify_get_signature_or_reject(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    peer_id: Option<&str>,
    federation_nonce_cache: &crate::identity::replay::FederationNonceCache,
) -> Option<Response> {
    if !fed_signing::require_sig() {
        return None;
    }
    let sig_header = headers
        .get(fed_signing::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok());
    let nonce_header = headers
        .get(fed_signing::NONCE_HEADER)
        .and_then(|v| v.to_str().ok());
    let pubkey = resolve_peer_verifying_key(
        headers,
        peer_id,
        cached_trust_bundle(),
        chrono::Utc::now().timestamp(),
    );

    let canonical = canonical_get_bytes(method, path, query);

    match (sig_header, pubkey.as_ref()) {
        (Some(sig), Some(pk)) => {
            let verify_result = if let Some(nonce) = nonce_header {
                fed_signing::verify_header_with_nonce(Some(sig), &canonical, nonce, pk)
            } else {
                fed_signing::verify_header(Some(sig), &canonical, pk)
            };
            if let Err(e) = verify_result {
                tracing::warn!(
                    target: crate::federation::SIGNING_TRACE_TARGET,
                    tag = e.tag(),
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_since: X-Memory-Sig verification failed"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": e.tag(),
                            "note": "AI_MEMORY_FED_REQUIRE_SIG=1 enforces per-message Ed25519 \
                                     signatures on /sync/since; set =0 to revert to v0.6.x \
                                     permissive (#1031)",
                        })),
                    )
                        .into_response(),
                );
            }
            // Nonce-freshness gate (same shape as /sync/push).
            let pid_for_cache = peer_id.unwrap_or("");
            match nonce_header {
                Some(nonce) if !nonce.is_empty() => {
                    match federation_nonce_cache.record_and_check(pid_for_cache, nonce) {
                        crate::identity::replay::ReplayDecision::Fresh => None,
                        crate::identity::replay::ReplayDecision::Replay => {
                            tracing::warn!(
                                target: crate::federation::SIGNING_TRACE_TARGET,
                                tag = fed_signing::VerifyError::ReplayedNonce.tag(),
                                peer_id = %pid_for_cache,
                                "sync_since: X-Memory-Nonce replay detected"
                            );
                            Some(
                                (
                                    StatusCode::UNAUTHORIZED,
                                    Json(json!({
                                        "error": fed_signing::VerifyError::ReplayedNonce.tag(),
                                        "note": "AI_MEMORY_FED_REQUIRE_NONCE=1 enforces per-message nonce freshness on /sync/since (#1031).",
                                    })),
                                )
                                    .into_response(),
                            )
                        }
                    }
                }
                _ => {
                    if fed_signing::require_nonce() {
                        tracing::warn!(
                            target: crate::federation::SIGNING_TRACE_TARGET,
                            tag = fed_signing::VerifyError::NonceMissing.tag(),
                            peer_id = %pid_for_cache,
                            "sync_since: X-Memory-Nonce header absent — strict refusal"
                        );
                        Some(
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "error": fed_signing::VerifyError::NonceMissing.tag(),
                                    "note": "AI_MEMORY_FED_REQUIRE_NONCE=1 requires X-Memory-Nonce on /sync/since (#1031); set =0 to bypass.",
                                })),
                            )
                                .into_response(),
                        )
                    } else {
                        tracing::warn!(
                            target: crate::federation::SIGNING_TRACE_TARGET,
                            peer_id = %pid_for_cache,
                            "sync_since: X-Memory-Nonce absent — permissive, accepting"
                        );
                        None
                    }
                }
            }
        }
        (Some(_), None) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_since: X-Memory-Sig present but no enrolled public key for peer-id (#1031)"
            );
            Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "x_memory_sig_no_enrolled_key",
                        "note": "AI_MEMORY_FED_REQUIRE_SIG=1 and the peer sent a signature, \
                                 but no public key is enrolled for the peer-id; enrol via \
                                 `ai-memory identity import` or set =0 to bypass (#1031).",
                    })),
                )
                    .into_response(),
            )
        }
        (None, Some(_)) => {
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_since: enrolled peer omitted X-Memory-Sig header (#1031)"
            );
            Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": fed_signing::VerifyError::Missing.tag(),
                        "note": "AI_MEMORY_FED_REQUIRE_SIG=1 enforces per-message Ed25519 \
                                 signatures on /sync/since for enrolled peers; set =0 to revert \
                                 to v0.6.x permissive (#1031).",
                    })),
                )
                    .into_response(),
            )
        }
        (None, None) => {
            // v0.7.0 #1088 — same fail-CLOSED arm as
            // `verify_signature_or_reject`. v0.8.0 #1789 flipped the
            // secure default ON: enrollment is REQUIRED by default, and
            // the companion escape hatch
            // `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` opens a rollout
            // window that accepts unenrolled peers on this SAME arm.
            // 5-agent vote (memory `4d3ea1c5`) fixed the flip.
            if require_peer_enrollment_enabled() && !allow_unenrolled_peers_enabled() {
                tracing::warn!(
                    target: crate::federation::SIGNING_TRACE_TARGET,
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_since: refusing unenrolled peer-id (peer enrollment required, v0.8 secure default #1789)"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "peer_not_enrolled",
                            "note": "Federation requires peer enrollment by default at \
                                     v0.8 (#1789): X-Peer-Id without an enrolled Ed25519 \
                                     key is refused on /sync/since. Enroll the peer's key \
                                     via the operator workflow, or set \
                                     AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0 to revert to \
                                     v0.7.x permissive, OR set \
                                     AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 to allow \
                                     unenrolled peers during a rollout window.",
                        })),
                    )
                        .into_response(),
                );
            }
            tracing::warn!(
                target: crate::federation::SIGNING_TRACE_TARGET,
                peer_id = %peer_id.unwrap_or(""),
                "sync_since: unsigned (no enrolled key for peer-id) — strict enforcement skipped"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// #961 regression coverage — SAL boundary cleanup (Wave-2 Tier-B1).
//
// Pre-fix, `sync_push_via_store` stamped reflection rows with the
// compiled-in default `max_reflection_depth` cap because the comment
// at the call site falsely claimed `resolve_governance_policy` was
// sqlite-only. Post-fix, the call routes through the SAL trait method
// `MemoryStore::resolve_governance_policy`, so postgres-backed daemons
// honour operator-set per-namespace caps the same way sqlite does in
// `federation_receive::sync_push`.
//
// The fragile, fixture-heavy end-to-end test would bring up a full
// `AppState` against an in-memory SqliteStore (the sql-postgres adapter
// has no test fixture without a live postgres instance). Instead, the
// test below pins the load-bearing semantic on the SAL trait surface:
// resolve_governance_policy on a fresh SqliteStore returns `None`, and
// the call-site's `.ok().flatten().unwrap_or_else(...)` chain therefore
// hands back the compiled-in default cap. The "store wired with a
// policy returns that policy" half is already pinned by `SqliteStore`
// trait impl tests in `src/store/sqlite.rs::1639` and the postgres
// adapter's coverage in `src/store/postgres.rs::5288+`. Composed
// together this anchors the post-#961 contract.
#[cfg(test)]
mod verify_arm_tests {
    //! cov3 — direct coverage for the `verify_signature_or_reject` /
    //! `verify_get_signature_or_reject` enforcement-matrix arms the HTTP
    //! integration suites do not reach: the `(sig, no-enrolled-key)`
    //! refusal, the `(None, None)` `peer_not_enrolled` #1088 strict arm,
    //! the require-sig-off bypass, and the `canonical_get_bytes` builder.
    //! These functions are `pub(super)` so the test calls them directly
    //! with synthetic headers rather than going through the router.

    use super::{
        allow_unenrolled_peers_enabled, canonical_get_bytes, require_peer_enrollment_enabled,
        verify_get_signature_or_reject, verify_signature_or_reject,
    };
    use crate::federation::signing::{
        ED25519_PREFIX, REQUIRE_NONCE_ENV, REQUIRE_SIG_ENV, SIGNATURE_HEADER,
    };
    use crate::identity::replay::FederationNonceCache;
    use axum::http::{HeaderMap, HeaderValue};
    use base64::Engine as _;

    // #1789 — delegate to the ONE crate-level `fed_env_test_lock` so the
    // strict enrollment tests here serialise against the permissive
    // opt-back guard the `tests` module's `http_sync_*` handler tests use.
    // A second independent lock would not serialise the two test sets,
    // letting a parallel run leak the flipped enrollment env across them.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::handlers::fed_env_test_lock()
    }

    fn sig_header_value() -> HeaderValue {
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        HeaderValue::from_str(&format!("{ED25519_PREFIX}{b64}")).unwrap()
    }

    #[test]
    fn canonical_get_bytes_joins_with_newlines() {
        let out = canonical_get_bytes("GET", "/api/v1/sync/since", "limit=10");
        assert_eq!(out, b"GET\n/api/v1/sync/since\nlimit=10");
        // Empty query still emits the trailing newline boundary.
        let out2 = canonical_get_bytes("GET", "/p", "");
        assert_eq!(out2, b"GET\n/p\n");
    }

    #[test]
    fn require_peer_enrollment_env_arms() {
        let _g = env_lock();
        // SAFETY: env mutation under the test-scoped lock.
        // v0.8.0 #1789 — UNSET is now the SECURE DEFAULT (strict), the
        // inverse of the v0.7.0 permissive default.
        unsafe {
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
        assert!(
            require_peer_enrollment_enabled(),
            "unset → strict (v0.8 secure default #1789)"
        );
        unsafe {
            std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "1");
        }
        assert!(require_peer_enrollment_enabled(), "1 → strict");
        unsafe {
            std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "true");
        }
        assert!(require_peer_enrollment_enabled(), "true → strict");
        unsafe {
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
    }

    #[test]
    fn require_peer_enrollment_falsy_opt_out() {
        let _g = env_lock();
        // v0.8.0 #1789 — explicit falsy values revert to v0.7.x permissive.
        // SAFETY: env mutation under the test-scoped lock.
        for falsy in ["0", "false", "FALSE", "no", "No", "off", "OFF", " off "] {
            unsafe {
                std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", falsy);
            }
            assert!(
                !require_peer_enrollment_enabled(),
                "{falsy:?} → permissive (falsy opt-out)"
            );
        }
        // Truthy + any other non-falsy string keeps the secure default ON.
        for truthy in ["1", "true", "yes", "on", "anything-else"] {
            unsafe {
                std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", truthy);
            }
            assert!(
                require_peer_enrollment_enabled(),
                "{truthy:?} → strict (non-falsy)"
            );
        }
        unsafe {
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
    }

    #[test]
    fn allow_unenrolled_peers_env_arms() {
        let _g = env_lock();
        // v0.8.0 #1789 — companion escape hatch (#44). Default false;
        // truthy 1/true/yes/on enables it.
        // SAFETY: env mutation under the test-scoped lock.
        unsafe {
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        assert!(
            !allow_unenrolled_peers_enabled(),
            "unset → escape hatch closed"
        );
        for truthy in ["1", "true", "TRUE", "yes", "Yes", "on", "ON", " on "] {
            unsafe {
                std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", truthy);
            }
            assert!(
                allow_unenrolled_peers_enabled(),
                "{truthy:?} → escape hatch open"
            );
        }
        for non_truthy in ["0", "false", "no", "off", "garbage"] {
            unsafe {
                std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", non_truthy);
            }
            assert!(
                !allow_unenrolled_peers_enabled(),
                "{non_truthy:?} → escape hatch closed"
            );
        }
        unsafe {
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
    }

    #[test]
    fn push_require_sig_off_bypasses() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "0");
        }
        let cache = FederationNonceCache::default();
        let out = verify_signature_or_reject(&HeaderMap::new(), b"{}", Some("peer-x"), &cache);
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        assert!(out.is_none(), "REQUIRE_SIG=0 bypasses every branch");
    }

    #[test]
    fn push_sig_present_no_enrolled_key_refuses() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
        }
        let mut headers = HeaderMap::new();
        headers.insert(SIGNATURE_HEADER, sig_header_value());
        let cache = FederationNonceCache::default();
        // peer-id has no on-disk key → (Some, None) arm.
        let out = verify_signature_or_reject(&headers, b"{}", Some("no-such-peer"), &cache);
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        let resp = out.expect("sig-present + no-key MUST refuse");
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn push_none_none_permissive_when_falsy_opt_out() {
        let _g = env_lock();
        // v0.8.0 #1789 — UNSET is now strict, so the permissive arm is
        // reached by an explicit falsy opt-out. (Preserved-intent: this
        // test still pins that the (None,None) arm CAN allow.)
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        let cache = FederationNonceCache::default();
        // No sig, no enrolled key, falsy opt-out → allow-with-WARN (None).
        let out = verify_signature_or_reject(&HeaderMap::new(), b"{}", Some("unenrolled"), &cache);
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
        assert!(
            out.is_none(),
            "(None,None) permissive arm must allow under falsy opt-out"
        );
    }

    #[test]
    fn push_none_none_permissive_when_escape_hatch() {
        let _g = env_lock();
        // v0.8.0 #1789 — escape hatch: enrollment required by default but
        // AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 allows unenrolled peers
        // during a rollout window.
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
            std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", "1");
        }
        let cache = FederationNonceCache::default();
        let out = verify_signature_or_reject(&HeaderMap::new(), b"{}", Some("unenrolled"), &cache);
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        assert!(
            out.is_none(),
            "(None,None) escape-hatch arm must allow during rollout"
        );
    }

    #[test]
    fn push_none_none_strict_refuses_by_default_1789() {
        let _g = env_lock();
        // v0.8.0 #1789 — UNSET is the secure default; refuses with no
        // opt-out set. The escape hatch is explicitly removed so the
        // strict path is deterministic.
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        let cache = FederationNonceCache::default();
        let out = verify_signature_or_reject(&HeaderMap::new(), b"{}", Some("unenrolled"), &cache);
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        let resp = out.expect("#1789 secure default must refuse unenrolled peer");
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn get_require_sig_off_bypasses() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "0");
        }
        let cache = FederationNonceCache::default();
        let out = verify_get_signature_or_reject(
            "GET",
            "/api/v1/sync/since",
            "limit=10",
            &HeaderMap::new(),
            Some("peer-x"),
            &cache,
        );
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
        }
        assert!(out.is_none());
    }

    #[test]
    fn get_sig_present_no_enrolled_key_refuses() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::set_var(REQUIRE_NONCE_ENV, "0");
        }
        let mut headers = HeaderMap::new();
        headers.insert(SIGNATURE_HEADER, sig_header_value());
        let cache = FederationNonceCache::default();
        let out = verify_get_signature_or_reject(
            "GET",
            "/api/v1/sync/since",
            "limit=10",
            &headers,
            Some("no-such-peer"),
            &cache,
        );
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var(REQUIRE_NONCE_ENV);
        }
        let resp = out.expect("get sig-present + no-key MUST refuse");
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn get_none_none_strict_refuses_1088() {
        let _g = env_lock();
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "1");
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        let cache = FederationNonceCache::default();
        let out = verify_get_signature_or_reject(
            "GET",
            "/api/v1/sync/since",
            "limit=10",
            &HeaderMap::new(),
            Some("unenrolled"),
            &cache,
        );
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
        }
        let resp = out.expect("#1088 strict must refuse on GET path");
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn get_none_none_escape_hatch_allows_1789() {
        let _g = env_lock();
        // v0.8.0 #1789 — escape hatch on the GET surface mirrors push.
        unsafe {
            std::env::set_var(REQUIRE_SIG_ENV, "1");
            std::env::remove_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT");
            std::env::set_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS", "1");
        }
        let cache = FederationNonceCache::default();
        let out = verify_get_signature_or_reject(
            "GET",
            "/api/v1/sync/since",
            "limit=10",
            &HeaderMap::new(),
            Some("unenrolled"),
            &cache,
        );
        unsafe {
            std::env::remove_var(REQUIRE_SIG_ENV);
            std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        }
        assert!(
            out.is_none(),
            "escape hatch must allow unenrolled peer on GET during rollout"
        );
    }
}

#[cfg(all(test, feature = "sal"))]
mod sal_boundary_961_tests {
    use crate::models::GovernancePolicy;
    use crate::store::MemoryStore;

    #[tokio::test]
    async fn fresh_sqlite_store_resolve_governance_policy_returns_none_so_fallback_uses_default() {
        // The fixture mirrors `src/store/sqlite.rs::fresh_store()`:
        // open a SqliteStore against a freshly-allocated tempfile. No
        // namespace_meta rows exist, so any namespace lookup must
        // return `None` and the call-site's unwrap_or_else fallback
        // fires.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let store = crate::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore");
        let policy_opt = store
            .resolve_governance_policy("any/ns")
            .await
            .expect("resolve_governance_policy");
        // Fresh DB carries no policy rows.
        assert!(policy_opt.is_none(), "fresh DB must have no policy");
        // The call-site collapses Err→fallback and None→fallback the
        // same way; pin the default cap so a future change to
        // GovernancePolicy::default() that drifts the cap is caught.
        let local_cap = policy_opt
            .unwrap_or_else(GovernancePolicy::default)
            .effective_max_reflection_depth();
        assert_eq!(
            local_cap,
            GovernancePolicy::default().effective_max_reflection_depth(),
            "fallback cap must match the compiled default (parity with pre-#961 behavior)"
        );
    }
}

// ---------------------------------------------------------------------------
// FED-P2d — receiver-side credential-path pubkey resolution
// ---------------------------------------------------------------------------
//
// Pins the surgical key-source swap in `resolve_peer_verifying_key`:
// when the trust bundle trusts the credential's issuer AND the
// credential binds to the claimed peer-id, the resolved key is the
// credential's subject key; on any bundle-empty / cred-absent /
// cred-invalid / wrong-subject condition the resolver falls through to
// the legacy per-peer path (which, with no on-disk enrolment in these
// isolated tests, yields `None`). The four-arm enforcement matrix in
// the verify functions is unchanged — these tests only exercise the
// key *source*.
#[cfg(test)]
mod fed_p2d_credential_resolution_tests {
    use super::{resolve_peer_verifying_key, verify_credential_pubkey};
    use crate::federation::identity::credential::CREDENTIAL_HEADER;
    use crate::federation::identity::issuer::{FederationIssuer, IssuerConfig};
    use crate::federation::identity::trust_bundle::TrustBundle;
    use axum::http::{HeaderMap, HeaderValue};
    use ed25519_dalek::SigningKey;

    const TEST_ISSUER_ID: &str = "ca:test-issuer";
    const TEST_TRUST_DOMAIN: &str = "test.federation.local";
    const TEST_PEER_ID: &str = "host:peer-a";
    const TEST_NOW_UNIX: i64 = 1_700_000_000;

    fn fixed_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_issuer() -> FederationIssuer {
        FederationIssuer::new(
            fixed_signing_key(7),
            IssuerConfig::new(TEST_ISSUER_ID, TEST_TRUST_DOMAIN),
        )
    }

    fn headers_with_cred(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CREDENTIAL_HEADER,
            HeaderValue::from_str(value).expect("valid header value"),
        );
        headers
    }

    #[test]
    fn credential_path_returns_subject_key_when_issuer_trusted() {
        let issuer = test_issuer();
        let subject_signing = fixed_signing_key(42);
        let subject_pub = subject_signing.verifying_key();
        let signed = issuer
            .issue(TEST_PEER_ID, &subject_pub, TEST_NOW_UNIX)
            .expect("issue credential");
        let bundle = TrustBundle::new().with_issuer(TEST_ISSUER_ID, issuer.verifying_key());

        let resolved = verify_credential_pubkey(
            &signed.to_header_value().expect("encode credential"),
            None,
            Some(TEST_PEER_ID),
            &bundle,
            TEST_NOW_UNIX,
        );
        assert_eq!(
            resolved.map(|k| k.to_bytes()),
            Some(subject_pub.to_bytes()),
            "trusted credential must resolve to the subject's key"
        );
    }

    #[test]
    fn resolve_uses_credential_when_bundle_trusts_issuer() {
        let issuer = test_issuer();
        let subject_signing = fixed_signing_key(99);
        let subject_pub = subject_signing.verifying_key();
        let signed = issuer
            .issue(TEST_PEER_ID, &subject_pub, TEST_NOW_UNIX)
            .expect("issue credential");
        let bundle = TrustBundle::new().with_issuer(TEST_ISSUER_ID, issuer.verifying_key());
        let headers = headers_with_cred(&signed.to_header_value().expect("encode"));

        let resolved =
            resolve_peer_verifying_key(&headers, Some(TEST_PEER_ID), &bundle, TEST_NOW_UNIX);
        assert_eq!(
            resolved.map(|k| k.to_bytes()),
            Some(subject_pub.to_bytes()),
            "resolver must prefer the trusted credential's subject key"
        );
    }

    #[test]
    fn empty_bundle_falls_through_to_legacy_path() {
        // Empty bundle: even a present, well-formed credential is ignored;
        // resolution falls to the legacy per-peer path, which has no
        // on-disk enrolment in this isolated test → None.
        let issuer = test_issuer();
        let subject_pub = fixed_signing_key(13).verifying_key();
        let signed = issuer
            .issue(TEST_PEER_ID, &subject_pub, TEST_NOW_UNIX)
            .expect("issue credential");
        let headers = headers_with_cred(&signed.to_header_value().expect("encode"));

        let resolved = resolve_peer_verifying_key(
            &headers,
            Some(TEST_PEER_ID),
            &TrustBundle::new(),
            TEST_NOW_UNIX,
        );
        assert!(
            resolved.is_none(),
            "empty bundle must defer to the legacy path (no enrolment → None)"
        );
    }

    #[test]
    fn absent_credential_falls_through_to_legacy_path() {
        let issuer = test_issuer();
        let bundle = TrustBundle::new().with_issuer(TEST_ISSUER_ID, issuer.verifying_key());
        let resolved = resolve_peer_verifying_key(
            &HeaderMap::new(),
            Some(TEST_PEER_ID),
            &bundle,
            TEST_NOW_UNIX,
        );
        assert!(
            resolved.is_none(),
            "no X-Memory-Cred header must defer to the legacy path"
        );
    }

    #[test]
    fn wrong_subject_credential_is_refused() {
        // A credential validly minted for a DIFFERENT subject must not
        // authenticate a push attributed to TEST_PEER_ID — the identity
        // binding (subject_agent_id == peer_id) blocks it.
        let issuer = test_issuer();
        let other_subject_pub = fixed_signing_key(55).verifying_key();
        let signed = issuer
            .issue("host:peer-b", &other_subject_pub, TEST_NOW_UNIX)
            .expect("issue credential for peer-b");
        let bundle = TrustBundle::new().with_issuer(TEST_ISSUER_ID, issuer.verifying_key());

        let resolved = verify_credential_pubkey(
            &signed.to_header_value().expect("encode"),
            None,
            Some(TEST_PEER_ID),
            &bundle,
            TEST_NOW_UNIX,
        );
        assert!(
            resolved.is_none(),
            "credential whose subject != peer-id must be refused (no cross-binding)"
        );
    }

    #[test]
    fn untrusted_issuer_credential_is_refused() {
        // Issuer not in the bundle → UnknownIssuer → None (fall through).
        let issuer = test_issuer();
        let subject_pub = fixed_signing_key(21).verifying_key();
        let signed = issuer
            .issue(TEST_PEER_ID, &subject_pub, TEST_NOW_UNIX)
            .expect("issue credential");
        // Bundle trusts a DIFFERENT issuer key.
        let bundle = TrustBundle::new()
            .with_issuer("ca:other-issuer", fixed_signing_key(200).verifying_key());

        let resolved = verify_credential_pubkey(
            &signed.to_header_value().expect("encode"),
            None,
            Some(TEST_PEER_ID),
            &bundle,
            TEST_NOW_UNIX,
        );
        assert!(
            resolved.is_none(),
            "credential from an untrusted issuer must be refused"
        );
    }

    #[test]
    fn malformed_credential_value_is_refused() {
        let issuer = test_issuer();
        let bundle = TrustBundle::new().with_issuer(TEST_ISSUER_ID, issuer.verifying_key());
        let resolved = verify_credential_pubkey(
            "v1=not-valid-base64-cbor!!!",
            None,
            Some(TEST_PEER_ID),
            &bundle,
            TEST_NOW_UNIX,
        );
        assert!(
            resolved.is_none(),
            "a malformed X-Memory-Cred value must be refused, not panic"
        );
    }

    // FED-P4 — hierarchical chain on the receiver verify path.
    #[test]
    fn hierarchical_chain_resolves_leaf_key_against_root_only_bundle() {
        use crate::federation::identity::chain::CHAIN_HEADER;

        // Root signs an intermediate region CA; the region CA signs the
        // node leaf. The receiver enrols ONLY the root key.
        let root = FederationIssuer::new(
            fixed_signing_key(70),
            IssuerConfig::new("ca:root", TEST_TRUST_DOMAIN),
        );
        let region = FederationIssuer::new(
            fixed_signing_key(71),
            IssuerConfig::new("region/nyc/ca", TEST_TRUST_DOMAIN),
        );
        // #1554 — the leaf MUST be within the region CA's delegated namespace
        // (`region/nyc`, i.e. the CA id minus the `/ca` marker). A regional
        // intermediate may only vouch for subjects in its own region; this is a
        // legitimate in-namespace delegation. (The flat P2/P3 path with generic
        // ids like `host:peer-a` is unaffected — `verify_link` runs only for
        // chained certs.)
        let leaf_id = "region/nyc/peer-a";
        let anchor = root
            .issue_intermediate(region.issuer_id(), &region.verifying_key(), TEST_NOW_UNIX)
            .expect("issue intermediate");

        let node_pub = fixed_signing_key(72).verifying_key();
        let chain = region
            .issue_chained(leaf_id, &node_pub, vec![anchor], TEST_NOW_UNIX)
            .expect("issue chained");

        let bundle = TrustBundle::new().with_issuer("ca:root", root.verifying_key());

        let mut headers = HeaderMap::new();
        headers.insert(
            CREDENTIAL_HEADER,
            HeaderValue::from_str(&chain.leaf.to_header_value().expect("encode leaf"))
                .expect("header"),
        );
        headers.insert(
            CHAIN_HEADER,
            HeaderValue::from_str(
                &chain
                    .intermediates_header_value()
                    .expect("encode chain")
                    .expect("two-level chain emits header"),
            )
            .expect("header"),
        );

        let resolved = resolve_peer_verifying_key(&headers, Some(leaf_id), &bundle, TEST_NOW_UNIX);
        assert_eq!(
            resolved.map(|k| k.to_bytes()),
            Some(node_pub.to_bytes()),
            "root-only bundle must resolve the leaf key through the presented chain"
        );
    }

    // FED-P4 — a tampered intermediate (not signed by the trusted root)
    // must fail the chain and fall through to the legacy path (None here).
    #[test]
    fn hierarchical_chain_with_untrusted_root_is_refused() {
        use crate::federation::identity::chain::CHAIN_HEADER;

        // The intermediate is signed by a DIFFERENT (untrusted) root.
        let rogue_root = FederationIssuer::new(
            fixed_signing_key(80),
            IssuerConfig::new("ca:root", TEST_TRUST_DOMAIN),
        );
        let region = FederationIssuer::new(
            fixed_signing_key(81),
            IssuerConfig::new("region/nyc/ca", TEST_TRUST_DOMAIN),
        );
        let anchor = rogue_root
            .issue_intermediate(region.issuer_id(), &region.verifying_key(), TEST_NOW_UNIX)
            .expect("issue intermediate");
        let node_pub = fixed_signing_key(82).verifying_key();
        let chain = region
            .issue_chained(TEST_PEER_ID, &node_pub, vec![anchor], TEST_NOW_UNIX)
            .expect("issue chained");

        // Bundle trusts a genuine root whose key differs from rogue_root.
        let genuine_root = FederationIssuer::new(
            fixed_signing_key(83),
            IssuerConfig::new("ca:root", TEST_TRUST_DOMAIN),
        );
        let bundle = TrustBundle::new().with_issuer("ca:root", genuine_root.verifying_key());

        let mut headers = HeaderMap::new();
        headers.insert(
            CREDENTIAL_HEADER,
            HeaderValue::from_str(&chain.leaf.to_header_value().expect("encode leaf"))
                .expect("header"),
        );
        headers.insert(
            CHAIN_HEADER,
            HeaderValue::from_str(
                &chain
                    .intermediates_header_value()
                    .expect("encode chain")
                    .expect("header present"),
            )
            .expect("header"),
        );

        let resolved =
            resolve_peer_verifying_key(&headers, Some(TEST_PEER_ID), &bundle, TEST_NOW_UNIX);
        assert!(
            resolved.is_none(),
            "a chain anchored in an untrusted root must be refused"
        );
    }
}
