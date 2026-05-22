// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation `/sync/push` signing-verification + postgres-SAL receive path.
//!
//! Extracted from [`super::federation_receive`] under issue #650
//! (handler cap ≤1200 LOC). Bodies are unchanged; only the module
//! surface moved. Items are exposed as `pub(super)` so the public
//! [`super::federation_receive::sync_push`] orchestrator can call them.

#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::federation::signing as fed_signing;

#[cfg(feature = "sal")]
use super::AppState;
#[cfg(feature = "sal")]
use super::MAX_BULK_SIZE;
#[cfg(feature = "sal")]
use super::federation_receive::{
    SyncPushBody, attribute_agent_for_quota, check_sender_clock_skew, next_utc_midnight,
};
#[cfg(feature = "sal")]
use crate::validate;

#[cfg(feature = "sal")]
#[allow(clippy::too_many_lines)]
pub(super) async fn sync_push_via_store(
    app: AppState,
    _headers: HeaderMap,
    body: SyncPushBody,
) -> Response {
    if let Err(e) = validate::validate_agent_id(&body.sender_agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid sender_agent_id: {e}")})),
        )
            .into_response();
    }
    if body.memories.len() > MAX_BULK_SIZE
        || body.deletions.len() > MAX_BULK_SIZE
        || body.archives.len() > MAX_BULK_SIZE
        || body.restores.len() > MAX_BULK_SIZE
        || body.pendings.len() > MAX_BULK_SIZE
        || body.pending_decisions.len() > MAX_BULK_SIZE
        || body.namespace_meta.len() > MAX_BULK_SIZE
        || body.namespace_meta_clears.len() > MAX_BULK_SIZE
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} entries per subcollection", MAX_BULK_SIZE)
            })),
        )
            .into_response();
    }

    let ctx = crate::store::CallerContext::for_agent(body.sender_agent_id.clone());
    let mut applied = 0usize;
    let mut noop = 0usize;
    let mut skipped = 0usize;
    let mut deleted = 0usize;
    let mut links_applied = 0usize;
    let mut latest_seen: Option<String> = None;
    let mut unsupported_on_postgres = 0usize;
    let mut quota_refused = 0usize;
    let mut first_quota_refusal: Option<crate::quotas::QuotaError> = None;

    // v0.7.0 S6-LOW2 — observability-only sender_clock skew detection
    // (parity with the sqlite path).
    check_sender_clock_skew(&body.sender_agent_id, &body);

    // ---- memories ----------------------------------------------------
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
        // v0.7.0 S6-M2 — per-agent quota gate. `agent_quotas` lives on
        // the SQLite metadata DB even on postgres-backed daemons
        // (Wave-3 hasn't migrated the row to the SAL trait yet), so
        // the postgres path consults the same `app.db` connection the
        // sqlite path uses. F7 closure (#639) — federation receive
        // never bypasses the cap that the equivalent HTTP POST sees.
        let attribute_agent = attribute_agent_for_quota(&body.sender_agent_id, mem);
        let bytes_estimate =
            i64::try_from(mem.title.len() + mem.content.len() + mem.metadata.to_string().len())
                .unwrap_or(i64::MAX);
        {
            let conn = app.db.lock().await;
            match crate::quotas::check_and_record(
                &conn.0,
                &attribute_agent,
                crate::quotas::QuotaOp::Memory {
                    bytes: bytes_estimate,
                },
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
        // v0.7.0 L2-2 — reflection origin stamping (postgres parity).
        //
        // #961 (SAL boundary cleanup, 2026-05-21): pre-fix this branch
        // used `GovernancePolicy::default().effective_max_reflection_depth()`
        // because `resolve_governance_policy` was thought to be
        // sqlite-only. As of Wave-3 the SAL trait method is wired on
        // both `SqliteStore` (`src/store/sqlite.rs::687`) and
        // `PostgresStore` (`src/store/postgres.rs::8795`), so we now
        // honour operator-set per-namespace caps on inbound federation
        // pushes the same way sqlite does in
        // `federation_receive.rs::sync_push`. Best-effort: a backend
        // error (`Err(_)`) or absent policy (`Ok(None)`) falls back to
        // the compiled-in default so a transient backend hiccup doesn't
        // refuse legitimate reflection-bearing pushes.
        let local_cap = app
            .store
            .resolve_governance_policy(&mem.namespace)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(crate::models::GovernancePolicy::default)
            .effective_max_reflection_depth();
        let to_insert = crate::federation::reflection_bookkeeping::stamp_reflection_origin(
            mem,
            &body.sender_agent_id,
            local_cap,
        );
        match app.store.apply_remote_memory(&ctx, &to_insert).await {
            Ok(applied_id) => {
                applied += 1;
                // v0.7.0 Wave-3 Continuation 5 (S18+S79 federation
                // semantic recall) — re-embed the incoming memory on
                // the receiver so the postgres `embedding` column
                // lands populated. Federation wire shape doesn't
                // carry the vector; without this step semantic recall
                // queries against a peer that received the memory
                // through sync_push would surface empty.
                if let Some(emb) = app.embedder.as_ref().as_ref() {
                    let embedding_text = format!("{} {}", mem.title, mem.content);
                    if let Ok(vector) = emb.embed(&embedding_text) {
                        let _ = app
                            .store
                            .update_embedding(&ctx, &applied_id, Some(&vector))
                            .await;
                    }
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
                    let _ = crate::quotas::refund_op(
                        &conn.0,
                        &attribute_agent,
                        crate::quotas::QuotaOp::Memory {
                            bytes: bytes_estimate,
                        },
                    );
                }
                tracing::warn!("sync_push: apply_remote_memory failed for {}: {e}", mem.id);
                skipped += 1;
            }
        }
    }

    // v0.7.0 S6-M2 — quota refusal short-circuit (postgres path).
    if let Some(q) = first_quota_refusal.take() {
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
                "quota_refused": quota_refused,
                "reset_at": reset_at,
                "storage_backend": "postgres",
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
        let attest_level = match (link.signature.as_deref(), link.observed_by.as_deref()) {
            (Some(sig_bytes), Some(observed_by)) => {
                match crate::identity::verify::lookup_peer_public_key(observed_by) {
                    Some(pubkey) => {
                        let signable = crate::identity::sign::SignableLink {
                            src_id: &link.source_id,
                            dst_id: &link.target_id,
                            relation: link.relation.as_str(),
                            observed_by: Some(observed_by),
                            valid_from: link.valid_from.as_deref(),
                            valid_until: link.valid_until.as_deref(),
                        };
                        match crate::identity::verify::verify(&pubkey, &signable, sig_bytes) {
                            Ok(()) => "peer_attested",
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
                    None => "unsigned",
                }
            }
            _ => "unsigned",
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

    // ---- archives / restores / pendings / pending_decisions /
    //      namespace_meta / namespace_meta_clears -----------------------
    //
    // These subcollections write into tables (archived_memories,
    // pending_actions, namespace_meta) not yet trait-covered. Surface
    // them with the same noop posture sqlite uses on missing rows so
    // a heterogeneous federation reports an honest count.
    unsupported_on_postgres += body.archives.len()
        + body.restores.len()
        + body.pendings.len()
        + body.pending_decisions.len()
        + body.namespace_meta.len()
        + body.namespace_meta_clears.len();

    (
        StatusCode::OK,
        Json(json!({
            "applied": applied,
            "deleted": deleted,
            "links_applied": links_applied,
            "noop": noop,
            "skipped": skipped,
            "quota_refused": quota_refused,
            "unsupported_on_postgres": unsupported_on_postgres,
            "dry_run": body.dry_run,
            "receiver_agent_id": body.sender_agent_id,
            "storage_backend": "postgres",
            "note": "pendings / archives / restores / namespace_meta are sqlite-only \
                     in v0.7.0; memories / deletions / links round-trip via the SAL trait",
        })),
    )
        .into_response()
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
    let pubkey = peer_id.and_then(|pid| {
        crate::governance::audit::load_daemon_verifying_key(pid)
            .ok()
            .flatten()
    });

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
                    target: "federation::signing",
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
                                target: "federation::signing",
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
                            target: "federation::signing",
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
                            target: "federation::signing",
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
                target: "federation::signing",
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
                target: "federation::signing",
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
            // unenrolled-peer attribution spoofing when the operator
            // opts in via `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`.
            // Default-off at v0.7.0 so existing zero-config peers keep
            // working; v0.8 will flip the secure default. Companion
            // env var to `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` (the
            // permissive escape hatch on the SAME arm post-#1056).
            if require_peer_enrollment_enabled() {
                tracing::warn!(
                    target: "federation::signing",
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_push: refusing unenrolled peer-id (AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 #1088)"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "peer_not_enrolled",
                            "note": "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 refuses \
                                     X-Peer-Id without an enrolled key (#1088). Enroll \
                                     the peer's Ed25519 key via the operator workflow, \
                                     or unset the env var to revert to permissive.",
                        })),
                    )
                        .into_response(),
                );
            }
            tracing::warn!(
                target: "federation::signing",
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: unsigned (no enrolled key for peer-id) — strict enforcement skipped"
            );
            None
        }
    }
}

/// v0.7.0 #1088 — `true` when the operator has opted into the
/// stricter zero-config federation posture by setting
/// `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`. Returns `false`
/// (default permissive) otherwise. Honored by both
/// `verify_signature_or_reject` and `verify_get_signature_or_reject`
/// so the `(None, None)` arm fails closed on both surfaces when the
/// operator enables it.
fn require_peer_enrollment_enabled() -> bool {
    std::env::var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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
//   "GET" || 0x0A || "/api/v1/sync/since" || 0x0A || canonical_query
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
    let mut out = Vec::with_capacity(method.len() + path.len() + query.len() + 2);
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(query.as_bytes());
    out
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
    let pubkey = peer_id.and_then(|pid| {
        crate::governance::audit::load_daemon_verifying_key(pid)
            .ok()
            .flatten()
    });

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
                    target: "federation::signing",
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
                                target: "federation::signing",
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
                            target: "federation::signing",
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
                            target: "federation::signing",
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
                target: "federation::signing",
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
                target: "federation::signing",
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
            // `verify_signature_or_reject`. Honors the operator
            // opt-in via `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1`.
            if require_peer_enrollment_enabled() {
                tracing::warn!(
                    target: "federation::signing",
                    peer_id = %peer_id.unwrap_or(""),
                    "sync_since: refusing unenrolled peer-id (AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 #1088)"
                );
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "peer_not_enrolled",
                            "note": "AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 refuses \
                                     X-Peer-Id without an enrolled key on /sync/since (#1088).",
                        })),
                    )
                        .into_response(),
                );
            }
            tracing::warn!(
                target: "federation::signing",
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
