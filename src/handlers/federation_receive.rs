// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::federation::peer_attestation::{
    self, AttestError, PEER_ID_HEADER, PeerAttestationConfig,
};
use crate::models::{Memory, MemoryLink};
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::federation_signing_check::sync_push_via_store;
use super::federation_signing_check::verify_signature_or_reject;

/// Tracing target for receive-side peer-attestation checks
/// (#1558 tracing-target SSOT).
/// `pub(crate)` (was `pub(super)`) since #2340 so the shared
/// [`crate::federation::receive_auth::redact_inbound_before_attestation`]
/// helper can WARN under the same target both receive twins use.
pub(crate) const ATTESTATION_TRACE_TARGET: &str = "federation::attestation";

/// v0.7.0 federation security — extract the peer's self-claimed
/// `x-peer-id` header. Lowercase form per HTTP/2 wire convention;
/// axum's `HeaderMap` lookup is case-insensitive so callers can send
/// the canonical `X-Peer-Id`.
///
/// v0.7.0 #1049 (Agent-5 #9) — validates the header value through
/// `validate::validate_agent_id` before returning so the raw header
/// content cannot inject CRLF/terminal-escape sequences into
/// downstream tracing log files or be smuggled into the
/// `FederationNonceCache` key (where exotic bytes would create
/// per-peer cache fragmentation an attacker could weaponise to
/// flood-evict legitimate peer entries). Returns `None` for any
/// header that fails the agent_id shape check — same observable
/// outcome as the header being absent.
pub(super) fn extract_peer_id(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(PEER_ID_HEADER).and_then(|v| v.to_str().ok())?;
    // Reject anything that fails the agent_id shape per CLAUDE.md
    // §"Agent Identity": `^[A-Za-z0-9_\-:@./]{1,128}$`. The strict
    // shape is the load-bearing property — no whitespace, no nulls,
    // no control chars (CRLF), no shell metacharacters.
    if crate::validate::validate_agent_id(raw).is_err() {
        tracing::warn!(
            target: "federation::peer_id",
            "extract_peer_id: dropped malformed X-Peer-Id header (#1049 validation gate)"
        );
        return None;
    }
    Some(raw)
}

/// Operator guidance for an `enforce`-mode refusal of a client cert that
/// carries no operator binding. One const per note (pm-v3.1
/// no-scattered-literals discipline); both are rendered by
/// [`unbound_cert_refusal_response`].
const CERT_BINDING_UNBOUND_NOTE: &str = "#2045: this client certificate's fingerprint has no entry in \
     AI_MEMORY_FED_CERT_PEER_BINDING_MAP, so its peer identity cannot be \
     cross-checked against the asserted x-peer-id. Add the fingerprint→peer-id \
     binding, or set AI_MEMORY_FED_CERT_PEER_BINDING=warn to downgrade to a WARN \
     during rollout.";

/// Operator guidance for an `enforce`-mode refusal of a bound cert that
/// asserted no `X-Peer-Id` header.
const CERT_BINDING_NO_HEADER_NOTE: &str = "#2045: this client certificate carries an operator binding but the request \
     asserted no x-peer-id header, so the cross-check cannot run. Send x-peer-id, \
     or set AI_MEMORY_FED_CERT_PEER_BINDING=warn to downgrade to a WARN during \
     rollout.";

/// Render the `401 peer_id_cert_unbound` envelope for an `enforce`-mode
/// refusal where the cross-check could not run at all (unbound cert /
/// missing header), as distinct from `peer_id_cert_mismatch` where it ran
/// and disagreed.
fn unbound_cert_refusal_response(note: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "peer_id_cert_unbound",
            "note": note,
        })),
    )
        .into_response()
}

/// #2045 L6 — cross-check the mTLS client cert's operator-bound peer
/// identity against the `X-Peer-Id` the request asserts. Returns
/// `Some(Response)` (a `401 peer_id_cert_mismatch`) to short-circuit the
/// handler when the posture is `enforce` and the asserted id does not match
/// the cert binding; `None` to proceed.
///
/// Degradations that ALWAYS proceed (never brick a working federation):
///   - posture `off`;
///   - no [`crate::tls::ClientCertPeerId`] extension (plain HTTP, or no
///     `AI_MEMORY_FED_CERT_PEER_BINDING_MAP` configured so the peer-binding
///     acceptor was not installed).
///
/// # FAIL-CLOSED under `enforce` (behaviour change, security fix)
///
/// Two further degradations used to proceed in EVERY posture, including
/// `enforce`:
///
///   - the presenting cert's fingerprint carries no binding ("legacy" cert —
///     which, because [`crate::tls::ClientCertPeerId`] is `None` both for an
///     unmapped fingerprint AND for a connection that presented no client
///     cert at all, also covers a non-mTLS request arriving over the
///     peer-binding acceptor);
///   - the request asserts no `X-Peer-Id`.
///
/// Both are now refused under `enforce` (they still proceed under `warn` /
/// `off`). The doc for this gate calls it "the compensating control for the
/// `FED_REQUIRE_SIG=0` window" — a control that any holder of an UNBOUND
/// TLS-accepted cert could skip by simply not being in the binding map (or
/// by omitting the header) was not a control at all: it left that window
/// with header-asserted, forgeable identity. `warn` remains the default and
/// the documented rollout posture for reaching `enforce` without bricking.
///
/// A mismatch under `warn` logs and proceeds; under `enforce` it is refused.
/// This is INDEPENDENT of `AI_MEMORY_FED_REQUIRE_SIG` — it is the
/// compensating control for the `FED_REQUIRE_SIG=0` window (#2032 L6).
pub(super) fn enforce_cert_peer_binding(
    cert_peer: Option<&crate::tls::ClientCertPeerId>,
    asserted_peer_id: Option<&str>,
) -> Option<Response> {
    let mode = crate::tls::cert_peer_binding_mode();
    if mode == crate::tls::CertPeerBindingMode::Off {
        return None;
    }
    let enforce = mode == crate::tls::CertPeerBindingMode::Enforce;
    // No extension at all ⇒ the request did not arrive over the peer-binding
    // mTLS acceptor (plain HTTP / no binding map) — nothing to cross-check.
    let cert_peer = cert_peer?;
    let Some(bound) = cert_peer.0.as_deref() else {
        // mTLS cert present but its fingerprint carries NO operator binding
        // (a "legacy" cert).
        if enforce {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                asserted_peer_id = asserted_peer_id.unwrap_or(""),
                "cert↔x-peer-id: presenting client cert has NO operator binding \
                 (legacy) — refusing (AI_MEMORY_FED_CERT_PEER_BINDING=enforce)"
            );
            return Some(unbound_cert_refusal_response(CERT_BINDING_UNBOUND_NOTE));
        }
        tracing::debug!(
            target: ATTESTATION_TRACE_TARGET,
            asserted_peer_id = asserted_peer_id.unwrap_or(""),
            "cert↔x-peer-id: presenting client cert has no operator binding \
             (legacy) — cross-check skipped, never bricks (#2045)"
        );
        return None;
    };
    // A bound cert with no asserted peer-id has nothing to contradict —
    // but under `enforce` an absent header is the same forgeable-identity
    // hole as an unbound cert: the cross-check simply does not run.
    let Some(asserted) = asserted_peer_id else {
        if enforce {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                bound_peer_id = %bound,
                "cert↔x-peer-id: bound client cert presented WITHOUT an x-peer-id \
                 header — refusing (AI_MEMORY_FED_CERT_PEER_BINDING=enforce)"
            );
            return Some(unbound_cert_refusal_response(CERT_BINDING_NO_HEADER_NOTE));
        }
        return None;
    };
    if asserted == bound {
        return None;
    }
    if mode == crate::tls::CertPeerBindingMode::Enforce {
        tracing::warn!(
            target: ATTESTATION_TRACE_TARGET,
            bound_peer_id = %bound,
            asserted_peer_id = %asserted,
            "cert↔x-peer-id mismatch — refusing (AI_MEMORY_FED_CERT_PEER_BINDING=enforce, #2045)"
        );
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "peer_id_cert_mismatch",
                    "note": "#2045: the asserted x-peer-id does not match the mTLS client cert's \
                             operator-bound peer identity. Set AI_MEMORY_FED_CERT_PEER_BINDING=warn \
                             to downgrade to a WARN during rollout.",
                })),
            )
                .into_response(),
        );
    }
    tracing::warn!(
        target: ATTESTATION_TRACE_TARGET,
        bound_peer_id = %bound,
        asserted_peer_id = %asserted,
        "cert↔x-peer-id mismatch — allowing (AI_MEMORY_FED_CERT_PEER_BINDING=warn; set =enforce to \
         refuse, #2045)"
    );
    None
}

/// v0.7.0 #238 — render a 403 envelope when the body-claimed
/// `sender_agent_id` does not attest to the wire-level `x-peer-id`
/// header. Surfaces both values so the operator can diff exactly
/// what the peer claimed against what the substrate expected.
fn attestation_refusal_response(err: &AttestError) -> Response {
    let (claimed, peer_header) = match err {
        AttestError::HeaderMissing => (String::new(), String::new()),
        AttestError::Mismatch {
            claimed,
            peer_header,
        } => (claimed.clone(), peer_header.clone()),
    };
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": err.tag(),
            "claimed": claimed,
            "peer_header": peer_header,
            "note": "set AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1 to opt out (legacy peers); \
                     pre-v0.7.0 federation peers must be upgraded to send `x-peer-id`.",
        })),
    )
        .into_response()
}

/// FED-RQ-03 — bounded-retry budget for the local governance policy read.
/// Three attempts with a linear 10/20 ms backoff bounds the added latency at
/// ~30 ms on the fault path and zero on the happy path, well under the 2 s
/// daemon p99 SLO.
const POLICY_READ_ATTEMPTS: u32 = 3;

/// Base backoff between policy-read attempts, in milliseconds (multiplied by
/// the attempt index for a linear ramp).
const POLICY_READ_BACKOFF_MS: u64 = 10;

/// FED-RQ-03 — closed-set error tag for a push refused because the LOCAL
/// governance policy could not be read (as distinct from
/// [`crate::federation::receive_auth::STALE_POLICY_ERROR_TAG`], where it was
/// read and the sender was behind).
const POLICY_READ_UNAVAILABLE_TAG: &str = "policy_read_unavailable";

/// Render the `503` fail-closed refusal for a push whose staleness could not
/// be determined because the local governance policy read kept failing.
///
/// `503` (not `409`) is deliberate: the condition is transient and the peer
/// SHOULD retry, so a genuine fault degrades to a retry rather than a
/// dropped write.
fn policy_read_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": POLICY_READ_UNAVAILABLE_TAG,
            // Fable HIGH (#3133): never echo the raw rusqlite/IO error to a
            // federation PEER. The detail is already logged at
            // ATTESTATION_TRACE_TARGET at the call site; the wire carries
            // only the closed-set tag + the operator-facing retry note.
            "note": "FED-RQ-03: the receiver could not read its own committed governance \
                     policy_version after a bounded retry, so this push's staleness is \
                     undeterminable and it is refused fail-closed. This is retryable — \
                     re-send once the receiver's governance store recovers. Set \
                     AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 to disable the freshness gate \
                     entirely during a heterogeneous-policy rollout window.",
        })),
    )
        .into_response()
}

/// FED-RQ-03 (#1947, 5-agent vote wd8wtmg0n) — render the receive-path refusal
/// for a push governed by a STALE governance `policy_version`. A `409 CONFLICT`
/// (the sender's governance state conflicts with / is behind the receiver's
/// committed policy) with a typed error tag + the two sequences so the peer
/// can see exactly how far behind it is, plus the `=0` opt-out for a
/// deliberate heterogeneous-policy rollout window.
fn stale_policy_refusal_response(sender_seq: i64, local_seq: i64) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": crate::federation::receive_auth::STALE_POLICY_ERROR_TAG,
            (crate::models::field_names::SENDER_POLICY_SEQ): sender_seq,
            "local_policy_seq": local_seq,
            "note": "FED-RQ-03 (#1947): this push is governed by a governance policy_version \
                     behind the receiver's committed policy; advance the sender's governance \
                     policy (ai-memory rules … --sign) to the current version and retry. Set \
                     AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 to accept stale-policy pushes during \
                     a heterogeneous-policy rollout window.",
        })),
    )
        .into_response()
}

/// FED-RQ-03 (#1947) — the cross-node policy_version REFUSE-STALE gate, shared
/// by BOTH backends (invoked before the postgres dispatch in [`sync_push`], so
/// a stale push is refused reject-before-apply on sqlite AND postgres and
/// never touches any `MemoryStore` apply path — postgres-clean, independent of
/// #1990). Returns `Some(response)` to refuse, `None` to continue.
///
/// The local committed policy is read from the sqlite governance connection
/// (`app.db`) — the sole rules store on every backend (amendment 7); on a node
/// with no governance tables `current_policy_version` degrades to the `seq=0`
/// sentinel, under which nothing is ever strictly-lower, so the gate is a
/// natural no-op (fail-OPEN).
///
/// # FAIL-CLOSED on a policy-read fault (behaviour change, security fix)
///
/// A policy-read ERROR used to be fail-OPEN: the `Err` was swallowed and the
/// push ACCEPTED. That let a peer ride out the gate by inducing a transient
/// governance-read fault (e.g. `SQLITE_BUSY` from concurrent pushes it
/// generates itself) and apply under a stale policy — an authority gate that
/// maps `Err` → accept (ERRORS-19/ERRORS-06).
///
/// The read is now retried with a short bounded backoff; if every attempt
/// fails the push is refused `503` (retryable — the peer re-sends once the
/// fault clears, so a genuine transient fault degrades to a retry rather than
/// data loss). The documented operator opt-out is UNCHANGED: with
/// `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0` the gate is disabled and a read
/// fault still accepts, exactly as before.
async fn refuse_if_stale_policy(app: &AppState, body: &SyncPushBody) -> Option<Response> {
    use crate::federation::receive_auth::{
        PolicyFreshnessVerdict, evaluate_inbound_policy_freshness, require_policy_current_enabled,
    };
    let require = require_policy_current_enabled();
    // Short-lived lock: read the local committed governance policy version,
    // then release before the (independently-locked) apply loops run.
    //
    // Bounded retry (SQLITE_BUSY and friends are transient by construction).
    // Each attempt re-acquires the lock so a competing writer can make
    // progress between tries.
    //
    // The retry budget applies ONLY when the gate is enabled: with
    // `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0` a read fault still accepts, so
    // retrying would add latency a peer could amplify for nothing.
    let attempts = if require { POLICY_READ_ATTEMPTS } else { 1 };
    let mut last_err: Option<String> = None;
    let mut local = None;
    for attempt in 0..attempts {
        {
            let lock = app.db.lock().await;
            match crate::governance::policy_version::current_policy_version(&lock.0) {
                Ok(pv) => {
                    local = Some(pv);
                    break;
                }
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(std::time::Duration::from_millis(
                POLICY_READ_BACKOFF_MS * u64::from(attempt + 1),
            ))
            .await;
        }
    }
    let Some(local) = local else {
        let error = last_err.unwrap_or_default();
        if !require {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                error = %error,
                "sync_push: FED-RQ-03 local policy read failed — accepting because the \
                 gate is disabled (AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0)"
            );
            return None;
        }
        tracing::error!(
            target: ATTESTATION_TRACE_TARGET,
            sender = %body.sender_agent_id,
            error = %error,
            attempts,
            "sync_push: FED-RQ-03 local policy read failed after bounded retry — \
             REFUSING 503 (fail-closed: staleness is undeterminable, so the push \
             must not be applied under an unknown policy)"
        );
        return Some(policy_read_unavailable_response());
    };
    match evaluate_inbound_policy_freshness(body.sender_policy_seq, local.seq, require) {
        PolicyFreshnessVerdict::Accept => None,
        PolicyFreshnessVerdict::RefuseStale {
            sender_seq,
            local_seq,
        } => {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                sender = %body.sender_agent_id,
                sender_policy_seq = sender_seq,
                local_policy_seq = local_seq,
                local_policy_digest = %local.digest_hex(),
                sender_policy_digest = %body.sender_policy_digest_hex.as_deref().unwrap_or(""),
                "sync_push: refusing inbound push governed by a STALE governance policy_version \
                 (FED-RQ-03 #1947) — advance the sender's governance policy to the current version"
            );
            Some(stale_policy_refusal_response(sender_seq, local_seq))
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3 foundation (issue #224) — HTTP sync endpoints.
//
// These shipped in v0.6.0 GA as SKELETONS running a timestamp-aware merge
// (`db::insert_if_newer`). v0.8.0 Pillar-3 (#1709) WIRED the #224
// field-level CRDT-lite merge: the reconciliation site below now routes
// through `db::merge_inbound`, which field-merges a divergent same-`id`
// inbound row via `crate::models::merge_memory` (tags union, max-merge on
// the counters, metadata deep-merge, agent_id/governance immutable-to-
// local) and falls through to `insert_if_newer` for fresh / dedup rows.
// Streaming, resume-on-interrupt, and per-peer auth tokens remain v0.8.0+
// targets.
// ---------------------------------------------------------------------------

/// v0.7.0 S6-LOW2 — log a warning when the sender's claimed wall-clock
/// is more than this many seconds ahead of the receiver's. Threshold is
/// deliberately permissive: ~1 minute of skew is normal for hosts with
/// NTP drift after a sleep cycle. Anything beyond that is operator-
/// signal that the cluster's clocks need attention.
const CLOCK_SKEW_WARN_THRESHOLD_SECS: i64 = 60;

/// v0.7.0 S6-LOW2 — observability-only clock-skew check. Compares the
/// sender's reported wall-clock (or the highest entry in
/// `sender_clock.entries` when the wall-clock field is absent) against
/// the receiver's `chrono::Utc::now()`. When the delta exceeds
/// [`CLOCK_SKEW_WARN_THRESHOLD_SECS`] in either direction, emits a
/// `tracing::warn!` so operators can spot a misconfigured peer. NEVER
/// rejects the push — federation must be tolerant of clock drift; the
/// log is the entire enforcement surface.
pub(super) fn check_sender_clock_skew(sender_agent_id: &str, body: &SyncPushBody) {
    let sender_ts_str: Option<&str> = body
        .sender_wall_clock
        .as_deref()
        .or_else(|| body.sender_clock.entries.values().max().map(String::as_str));
    let Some(ts_str) = sender_ts_str else {
        return; // No clock signal at all → nothing to compare.
    };
    let Ok(sender_at) = chrono::DateTime::parse_from_rfc3339(ts_str) else {
        tracing::debug!(
            sender = %sender_agent_id,
            sender_ts = %ts_str,
            "sync_push: sender clock not RFC3339; skipping skew check"
        );
        return;
    };
    let now = chrono::Utc::now();
    let skew_secs = sender_at
        .with_timezone(&chrono::Utc)
        .signed_duration_since(now)
        .num_seconds();
    if skew_secs.abs() > CLOCK_SKEW_WARN_THRESHOLD_SECS {
        tracing::warn!(
            target: "federation::clock_skew",
            sender = %sender_agent_id,
            skew_secs,
            sender_ts = %ts_str,
            receiver_ts = %now.to_rfc3339(),
            "sync_push: sender_clock skew exceeds {CLOCK_SKEW_WARN_THRESHOLD_SECS}s threshold \
             (observability-only; push accepted)",
        );
    }
}

/// v0.7.0 S6-M2 / #1464 (v0.8.0, P0, security-high) — resolve the
/// quota + ownership attribution for an inbound federated memory, gating
/// the claimed `metadata.agent_id` against the operator's per-peer
/// authorship allowlist. Returns the agent id the substrate will charge
/// for the row, and mutates `to_insert` in place when a claim is refused.
///
/// ## The hole this closes
///
/// Pre-#1464 the receiver trusted `metadata.agent_id` VERBATIM. The
/// docstring used to claim "a misbehaving peer cannot substitute another
/// agent's id without crashing the upstream signature check (H3)" — that
/// was FALSE (§17 honesty): #791 signs the whole BODY by the *sender*,
/// not each row's author, and `Memory` carries no per-write signature to
/// re-verify. So an enrolled peer `mallory` could push a memory claiming
/// `metadata.agent_id = "alice"` and have alice charged for quota AND
/// recorded as owner (the #1720 owner-keyed visibility row).
///
/// ## The gate (#1464 — chosen by a 5-agent adversarial vote, 4-1)
///
/// Extend the shipped #238 allowlist ([`PeerScope::allowed_sender_agent_ids`])
/// from the body-sender to per-memory granularity:
///   1. No `metadata.agent_id` → attribute to `sender_agent_id` (legacy /
///      unauthored push).
///   2. Claim == `sender_agent_id` → the #238-attested body author; trust.
///   3. Enrolled posture (operator configured an allowlist): trust the
///      claim only if the operator authorized this peer to author as that
///      agent (`scope_for(peer_id).allowed_sender_agent_ids`). Otherwise
///      attribute to the sender AND rewrite `to_insert.metadata.agent_id`
///      to the sender so a forged claim cannot own the row, stamping
///      `attest_level = "claimed"` so downstream knows it is a bare claim.
///   4. Zero-config (no allowlist): preserve the faith-based posture
///      (#1056 / #238 — an unenrolled mesh trusts signed peer-ids; the
///      operator opts into authorship enforcement by enrolling peers).
///
/// This preserves legitimate multi-author relay provenance (a hub/curator
/// relaying a fleet of agents the operator allowlisted) while closing the
/// forge hole for unauthorized claims.
///
/// #2863 — `claim_write_attested` is an INDEPENDENT honor path: when the row
/// carries a `metadata.write_signature` that VERIFIES against the CLAIMED
/// author's locally-enrolled key (computed caller-side over the POST-redaction
/// bytes via [`inbound_claim_is_write_attested`], because the enrolled-key
/// lookup straddles the sync-sqlite / async-pg boundary), the claim is honored
/// regardless of the allowlist. A valid Ed25519 signature over the 6-field
/// `SignableWrite` is unforgeable proof of authorship independent of which peer
/// relayed it — strictly stronger than the operational `allowed_sender_agent_ids`
/// allowlist, which is the authorization for UNSIGNED bare claims. This closes
/// the #2860 re-broadcast divergence where a tombstoned consolidation SOURCE
/// authored by A but relayed under the daemon federation identity was
/// re-attributed to the daemon and downgraded from `agent_attested` to
/// `claimed` at the peer. An unsigned / forged / unenrolled-author claim still
/// re-attributes exactly as before (the honor path requires a VERIFIED enrolled
/// signature, never mere presence).
pub(super) fn resolve_inbound_attribution(
    to_insert: &mut Memory,
    sender_agent_id: &str,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
    claim_write_attested: bool,
) -> String {
    let Some(claimed) = to_insert
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
        return sender_agent_id.to_string();
    };
    // The #238-attested body author is always trusted to author as itself.
    if claimed == sender_agent_id {
        return claimed;
    }
    // A relayed third-party claim is honored when EITHER (#2863) it carries a
    // write_signature that cryptographically verifies against the claimed
    // author's enrolled key, OR (enrolled posture) the operator authorized this
    // peer to author as that agent. Zero-config (no allowlist) preserves the
    // faith-based posture.
    let authorized = claim_write_attested
        || if attest_cfg.has_allowlist() {
            peer_id
                .and_then(|p| attest_cfg.scope_for(p))
                .is_some_and(|scope| scope.allowed_sender_agent_ids.iter().any(|a| a == &claimed))
        } else {
            true
        };
    if authorized {
        return claimed;
    }
    // Unauthorized relayed claim: do not trust it for quota OR ownership.
    tracing::warn!(
        target: ATTESTATION_TRACE_TARGET,
        memory_id = %to_insert.id,
        claimed_agent = %claimed,
        sender = %sender_agent_id,
        peer_id = %peer_id.unwrap_or(""),
        "sync_push: peer not authorized to author as claimed agent_id (#1464); \
         re-attributing the row to the sender"
    );
    if let Some(obj) = to_insert.metadata.as_object_mut() {
        obj.insert(
            crate::META_KEY_AGENT_ID.to_string(),
            serde_json::Value::String(sender_agent_id.to_string()),
        );
        obj.insert(
            crate::models::field_names::ATTEST_LEVEL.to_string(),
            serde_json::Value::String(
                crate::identity::verify::AttestLevel::Claimed
                    .as_str()
                    .to_string(),
            ),
        );
    }
    sender_agent_id.to_string()
}

/// #2863 — does this inbound row's presented `metadata.write_signature` VERIFY
/// against `claimed_author`'s locally-enrolled key over the 6-field
/// `SignableWrite`? Reuses the EXACT `attest_write` path the write-sig lane
/// stamps with (over the POST-redaction persisted bytes — call this AFTER
/// [`crate::federation::receive_auth::redact_inbound_before_attestation`]), so
/// the honor decision [`resolve_inbound_attribution`] makes and the level
/// [`apply_inbound_write_attestation`] stamps cannot disagree. A valid Ed25519
/// signature is unforgeable proof of authorship independent of which peer
/// relayed it; `claimed_bound_key` MUST come from the LOCAL enrolled keystore
/// (`agent_pubkey`), never a wire-presented key. Returns `false` on any absent
/// signature / unenrolled key / verification failure (fail-closed).
pub(super) fn inbound_claim_is_write_attested(
    mem: &Memory,
    claimed_author: &str,
    claimed_bound_key: Option<&str>,
) -> bool {
    let presented_sig = mem
        .metadata
        .get(crate::models::field_names::WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
        });
    matches!(
        crate::identity::attest::resolve_write_attest_level(
            mem,
            claimed_author,
            claimed_bound_key,
            presented_sig.as_deref(),
            false,
        ),
        Ok(crate::identity::verify::AttestLevel::AgentAttested)
    )
}

/// #2720 F-12 (CWE-346) — bind the DECIDER of an inbound federated pending
/// REJECT to the attested peer, never the self-asserted wire `decider`.
///
/// ## The hole this closes
///
/// The APPROVE arm routes through [`crate::db::approve_with_approver_type`]
/// (self-approval refusal + `is_registered_agent` + approver-type policy), but
/// the REJECT arm called [`crate::db::decide_pending_action`] with the wire
/// `PendingDecision::decider` VERBATIM. So an in-scope peer could stamp
/// `pending_actions.decided_by` — AND the signed `pending_action.denied` audit
/// row it emits — with ANY identity string, including a real operator's:
/// forging the governance audit trail. #2532 made REJECT symmetric on WHERE
/// (namespace scope) but it stayed asymmetric on WHO.
///
/// This is a faithful mirror of the memory lane's
/// [`resolve_inbound_attribution`] identity discipline (and the signal lane's
/// [`signal_author_authorized`]): a relayed third-party claim is trusted ONLY
/// when the operator authorized this peer to author as that agent (the
/// per-peer [`crate::federation::peer_attestation::PeerScope::allowed_sender_agent_ids`]
/// allowlist), or when it self-relays (`decider == sender_agent_id`).
/// Zero-config (no allowlist) preserves the faith-based posture, byte-identical
/// to pre-fix. Unlike a signal, a `PendingDecision` carries no signed canonical
/// bytes over `decider`, so — exactly like a memory — an unauthorized claim is
/// REBOUND to the attested sender rather than skipped, keeping the reject
/// converging (the originator killed the action) while the audit records the
/// real attested actor.
///
/// Returns the decider string to record on the deny transition.
#[must_use]
pub(super) fn resolve_inbound_decider(
    claimed_decider: &str,
    sender_agent_id: &str,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
) -> String {
    // The #238-attested sender is always trusted to decide as itself.
    if claimed_decider == sender_agent_id {
        return claimed_decider.to_string();
    }
    // Enrolled posture: a relayed third-party decider is trusted ONLY if the
    // operator authorized this peer to author as that agent. Zero-config
    // (no allowlist) preserves the faith-based posture.
    let authorized = if attest_cfg.has_allowlist() {
        peer_id
            .and_then(|p| attest_cfg.scope_for(p))
            .is_some_and(|scope| {
                scope
                    .allowed_sender_agent_ids
                    .iter()
                    .any(|a| a == claimed_decider)
            })
    } else {
        true
    };
    if authorized {
        return claimed_decider.to_string();
    }
    tracing::warn!(
        target: ATTESTATION_TRACE_TARGET,
        claimed_decider = %claimed_decider,
        sender = %sender_agent_id,
        peer_id = %peer_id.unwrap_or(""),
        "sync_push: peer not authorized to reject-as the claimed decider (#2720 F-12); \
         rebinding the decision actor to the attested sender so the signed audit \
         trail records the real actor"
    );
    sender_agent_id.to_string()
}

/// #1843 (v0.8.1, security-high) — author-binding authorization for an inbound
/// relayed signal, shared verbatim by the sqlite (`sync_push`) and postgres
/// (`sync_push_via_store`) receive loops so both backends behave identically.
///
/// ## The hole this closes (CWE-346)
///
/// A federated signal's `from_agent` is set by the wire. The receive loop's
/// forged-signature check ([`crate::signals::verify`]) validates the signature
/// against the signal's OWN wire-supplied `sender_pubkey` — it never binds
/// `from_agent` to the enrolled peer's authorship allowlist nor to
/// `from_agent`'s locally-enrolled key. So an enrolled peer could relay a signal
/// forged as ANY agent. The memory lane ([`resolve_inbound_attribution`]) and
/// the transition lane
/// ([`crate::federation::receive_auth::authorize_remote_transition`]) already
/// close this for their subcollections. A signal cannot be cleanly
/// re-attributed (`from_agent` is inside the signed canonical bytes), so the
/// disposition here is a PER-SIGNAL skip — never re-attribution, never a drop of
/// the rest of the batch.
///
/// Returns `true` when the signal may be stored, `false` (with an author-naming
/// WARN already emitted) when the caller must `skipped += 1; continue`.
///
/// Two composed layers (5-agent vote `4d3ea1c5`):
///
/// - **Layer 1 (always-on base).** Gated on the SAME primitive
///   [`resolve_inbound_attribution`] uses — [`PeerAttestationConfig::has_allowlist`].
///   Under an enrolled posture, a relayed signal is trusted only when it
///   self-relays (`from_agent == sender_agent_id`) OR `from_agent` is in the
///   peer's [`peer_attestation::PeerScope::allowed_sender_agent_ids`].
///   Zero-config (no allowlist) does NOTHING new — byte-identical faith-based
///   behavior.
/// - **Layer 2 (opt-in `require_signal_sig`).** When the operator sets
///   `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG`
///   ([`crate::federation::receive_auth::require_signal_sig_enabled`]),
///   additionally require `signal.signature` to verify against `from_agent`'s
///   locally-ENROLLED key ([`crate::identity::verify::lookup_peer_public_key`])
///   — NOT the wire `sender_pubkey`. An unenrolled / unverified author is
///   skipped. A *forged* signature is already skipped by [`crate::signals::verify`]
///   regardless of this knob.
#[must_use]
pub(super) fn signal_author_authorized(
    sig: &crate::models::Signal,
    sender_agent_id: &str,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
    require_signal_sig: bool,
) -> bool {
    // Layer 1 — enrolled-posture authorship allowlist (mirrors the memory lane).
    if attest_cfg.has_allowlist() && sig.from_agent != sender_agent_id {
        let authorized = peer_id
            .and_then(|p| attest_cfg.scope_for(p))
            .is_some_and(|scope| {
                scope
                    .allowed_sender_agent_ids
                    .iter()
                    .any(|a| a == &sig.from_agent)
            });
        if !authorized {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                signal_id = %sig.id,
                from_agent = %sig.from_agent,
                sender = %sender_agent_id,
                peer_id = %peer_id.unwrap_or(""),
                "sync_push: peer not authorized to relay a signal authored as from_agent \
                 — skipping (#1843); batch survives"
            );
            return false;
        }
    }
    // Layer 2 — opt-in strict author-signature against the enrolled key.
    if require_signal_sig {
        let verified = crate::identity::verify::lookup_peer_public_key(&sig.from_agent)
            .is_some_and(|key| crate::signals::verify_with_key(sig, key.as_bytes()));
        if !verified {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                signal_id = %sig.id,
                from_agent = %sig.from_agent,
                "sync_push: AI_MEMORY_FED_REQUIRE_SIGNAL_SIG set but signal is not validly \
                 signed by from_agent's enrolled key — skipping (#1843)"
            );
            return false;
        }
    }
    true
}

/// #2865 — resolve the attributed author's bound Ed25519 public key (base64)
/// for the `/sync/push` per-write CONTENT-attestation lane
/// ([`apply_inbound_write_attestation`]): the DB `agent_pubkey` registry FIRST,
/// then the on-disk ENROLLED key store ([`crate::identity::verify::lookup_peer_public_key`],
/// the key-dir) as a MISS-ONLY fallback.
///
/// **Why the fallback (the #2865 gap).** A daemon authors a federated
/// consolidation as its FEDERATION identity (e.g. `ai:hive-memory-1`,
/// #2860/#2862). A normally-enrolled mesh cross-enrolls a peer's federation
/// public key into the key-dir — the SAME source the PULL author lane
/// ([`attest_inbound_pull_memory`]), the signal-author lane
/// ([`signal_author_authorized`]), and the transition-author lane already
/// trust — but does NOT bind it into the per-node DB `agent_pubkey` registry.
/// Pre-#2865 the push lane resolved the author key from the DB registry ONLY,
/// so the propagated `metadata.write_signature` could not be verified and the
/// row landed `attest_level=claimed` — quarantined at peers under
/// `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` (asi-hard). Consulting the key-dir
/// as a fallback brings the push lane to parity with the pull lane and makes
/// daemon-authored derived content converge at `agent_attested` OUT-OF-BOX,
/// with no manual DB-bind step. 5-agent vote (`4d3ea1c5`), unanimous.
///
/// **Trust (why this is not a new grant).** The key-dir is
/// operator/enrollment-controlled and is NOT writable over the wire — no
/// `/sync/*` receive handler writes it — so reading it grants no new trust; it
/// is the identical source three inbound author lanes already use. The fallback
/// is MISS-ONLY (`registry_key.or_else(...)`): a key bound into the DB registry
/// (e.g. the cert-round author via the admin `PUT /api/v1/agents/{id}/pubkey`
/// route, or `ai-memory agents bind-key`) ALWAYS wins, so a stale/rotated
/// key-dir entry can never shadow the authoritative registry key. And
/// [`apply_inbound_write_attestation`] VERIFIES the presented signature against
/// whichever key resolves — a wrong/absent key can only DEGRADE the row to
/// `claimed`, never mis-attest it (a forged signature is rejected
/// unconditionally). The key-dir [`ed25519_dalek::VerifyingKey`] is encoded
/// URL-safe-no-pad exactly as the pull lane encodes it;
/// [`crate::identity::keypair::decode_public_base64`] accepts both that and the
/// STANDARD form the DB registry stores.
#[must_use]
pub fn resolve_author_bound_key(
    registry_key: Option<String>,
    attribute_agent: &str,
) -> Option<String> {
    use base64::Engine as _;
    registry_key.or_else(|| {
        crate::identity::verify::lookup_peer_public_key(attribute_agent)
            .map(|vk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes()))
    })
}

/// Test seam for [`resolve_author_bound_key`] taking an explicit key
/// directory (mirrors the [`crate::identity::verify::lookup_peer_public_key`]
/// / `lookup_peer_public_key_in` pairing) so a regression test can populate a
/// tempdir key-dir without touching the operator's real key store or mutating
/// `AI_MEMORY_KEY_DIR`.
#[must_use]
pub fn resolve_author_bound_key_in(
    registry_key: Option<String>,
    attribute_agent: &str,
    key_dir: &std::path::Path,
) -> Option<String> {
    use base64::Engine as _;
    registry_key.or_else(|| {
        crate::identity::verify::lookup_peer_public_key_in(attribute_agent, key_dir)
            .map(|vk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes()))
    })
}

/// #1464 (v0.8.0) — per-write CONTENT attestation on the federation receive
/// path. The ATTRIBUTION lane ([`resolve_inbound_attribution`]) resolves
/// WHO a relayed memory is attributed to; this resolves WHETHER the relayed
/// CONTENT is cryptographically attested to that author.
///
/// When the relayed memory carries a base64 detached Ed25519 signature in
/// `metadata.write_signature`, it is verified — through the same store-path
/// [`crate::identity::attest::stamp_attestation`] gate (#626), which
/// recomputes `sha256(content)` over the PERSISTED content bytes (never
/// trusting a presented digest) and re-derives the canonical `SignableWrite`
/// envelope — against the attributed author's locally ENROLLED Ed25519 key
/// (`bound_pubkey_b64`, resolved per-backend by the caller). A valid
/// signature upgrades the row to `attest_level=agent_attested`; an unsigned
/// relayed write keeps `attest_level=claimed` (the documented accept-and-flag
/// data-lane posture). `agent_attested` commits to the six `SignableWrite`
/// fields ONLY (agent_id, namespace, title, kind, created_at,
/// sha256(content)) — NOT tags/priority/metadata.
///
/// Composition rules (the data-lane security semantics, single-sourced here
/// so both the sqlite and postgres receive paths behave identically):
/// - **Re-attributed rows are skipped.** When an unauthorized third-party
///   claim was already downgraded to `claimed` + re-attributed to the sender
///   by [`resolve_inbound_attribution`] (`original_claim != attribute_agent`),
///   a signature minted by the *original* claimant must NOT be checked
///   against the re-attributed sender (it would spuriously read as forged).
///   The row already correctly landed `claimed`; leave it.
/// - **Strict mode is third-party-only.** `require_write_sig_env`
///   (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, default ON at v1.0.0 per
///   `FED_REQUIRE_WRITE_SIG_DEFAULT` — #1801->#1954; `=0` reverts) is honored only for a
///   HONORED third-party relayed claim (`attribute_agent != sender_agent_id`);
///   self-authored relays stay faith-based (already gated by the #238
///   envelope attestation + #29 signature + #30 nonce + #43 enrollment), so a
///   strict operator never bricks self-authored replication.
///
/// On the honored path this re-stamps `attest_level` from WHAT WE VERIFIED,
/// overriding any peer-asserted `attest_level` in the inbound metadata (a
/// peer cannot self-assert `agent_attested`).
///
/// # Errors
///
/// Returns `Err` when a presented signature is forged/malformed, or when
/// strict mode requires a signature that is absent/unverifiable for a honored
/// third-party claim. The caller rejects (skips) that single memory without
/// aborting the batch. 5-agent vote (`4d3ea1c5`).
pub(super) fn apply_inbound_write_attestation(
    to_insert: &mut Memory,
    attribute_agent: &str,
    sender_agent_id: &str,
    original_claim: Option<&str>,
    bound_pubkey_b64: Option<&str>,
    require_write_sig_env: bool,
) -> anyhow::Result<()> {
    // Skip re-attributed rows — the original claimant's signature would not
    // verify against the re-attributed sender, and the row already correctly
    // landed `claimed`.
    if original_claim.is_some_and(|c| c != attribute_agent) {
        return Ok(());
    }
    let presented_sig: Option<Vec<u8>> = to_insert
        .metadata
        .get(crate::models::field_names::WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
        });
    // Strict requirement applies only to HONORED third-party relayed claims.
    let require = require_write_sig_env && attribute_agent != sender_agent_id;
    crate::identity::attest::stamp_attestation(
        to_insert,
        attribute_agent,
        bound_pubkey_b64,
        presented_sig.as_deref(),
        require,
    )
    .map(|_| ())
}

/// #2715 (CB-11 / B-4, data-integrity/federation) — attested apply-gate for the
/// federation PULL paths (the `serve` catch-up puller
/// [`crate::federation::receive::catchup_once_with_store`] + the `sync-daemon`
/// [`crate::daemon_runtime::sync_cycle_once`]), the read-direction sibling of the
/// `/sync/push` per-write content-attestation gate ([`apply_inbound_write_attestation`]).
///
/// Both pullers previously applied pulled rows with only a namespace check and
/// NO content attestation — a forged `metadata.write_signature` that the push
/// receive path would REJECT was silently accepted through the pull door, and
/// every row landed with whatever `attest_level` the wire asserted. This closes
/// that bypass with the SAME cryptographic core the push path uses.
///
/// A pulled row is applied by the AUTHOR's own claim: unlike push there is no
/// distinct #238-attested relayer (`sender_agent_id`) on the `/sync/since` GET
/// response, so we verify the presented signature against the CLAIMED author and
/// pass `sender == author`, which makes the strict-flip's honored-third-party
/// REFUSAL inert here (it only fires for a relayer honoring someone else's
/// claim). This gate's job is therefore FORGERY REJECTION + honest
/// `attest_level`, never a self-authored-relay brick:
///   - a presented signature that does NOT verify against the author's enrolled
///     key → `Err` → refuse (skip the row, fail-closed — the durable text on the
///     peer is unchanged and re-pull is harmless);
///   - a signature that verifies → `agent_attested`;
///   - no signature, or an author with no locally-enrolled key → `claimed`
///     (DEGRADE, never corrupt — the pull direction has no attested relayer to
///     hold accountable, so an unsigned row is accepted-and-flagged).
///
/// The author key is resolved from the on-disk ENROLLED key store
/// ([`crate::identity::verify::lookup_peer_public_key`]) — the SAME source the
/// federation signal-author and transition-author lanes use — so the gate is
/// backend-UNIFORM (sqlite + postgres pulls behave identically; the sqlite-only
/// `db::agent_pubkey` registration source the push path uses is deliberately NOT
/// used here). No `.is_ok()` / `if let Ok` is used as a security predicate — a
/// forged signature is an explicit `Err` that returns `false`.
///
/// #2340 (FBL-32) — redacts to the TO-BE-PERSISTED form FIRST so the attestation
/// verifies + stamps over exactly the bytes the storage funnel
/// (`insert_if_newer` / `apply_remote_memory`, which both secret-screen-degrade
/// on the receive path) will persist; a stale cross-mode `write_signature` is
/// dropped inside the redactor and the row lands honestly `claimed` instead of a
/// false `agent_attested`.
///
/// Returns `true` when the (now-attested) row may be applied, `false` when it
/// must be skipped.
#[must_use]
pub(crate) fn attest_inbound_pull_memory(mem: &mut Memory) -> bool {
    let Some(author) = mem
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
        // No claimed author → no owner claim to verify a signature against.
        // Apply unchanged (byte-identical to the pre-#2715 pull behaviour for
        // an author-less row).
        return true;
    };
    // #2340 — redact BEFORE verify/stamp so the attestation commits over the
    // persisted bytes (see fn docs).
    crate::federation::receive_auth::redact_inbound_before_attestation(mem);
    // #2865 — single-source the author-key resolution through the shared
    // helper. The pull lane has no DB-registry source (it is backend-uniform by
    // design), so it passes `None` and the helper resolves the enrolled key-dir
    // key exactly as before (byte-identical) — the same resolver the push lane
    // now falls back to.
    let author_bound_key = resolve_author_bound_key(None, &author);
    match apply_inbound_write_attestation(
        mem,
        &author,
        &author,
        None,
        author_bound_key.as_deref(),
        crate::federation::receive_auth::require_write_sig_enabled(),
    ) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                memory_id = %mem.id,
                author = %author,
                error = %e,
                "federation pull: per-write content attestation failed — refusing \
                 forged/unverifiable inbound memory (#2715 B-4); skipping this row, \
                 the batch survives and re-pull is harmless"
            );
            false
        }
    }
}

/// v1.0.0 R19/A3 (#1948, decision `560c8007`) — route-IN quarantine of a
/// provenance-less inbound relayed memory (write boundary only).
///
/// Call AFTER [`apply_inbound_write_attestation`] has stamped `attest_level`.
/// When `quarantine_enabled`
/// (`AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`, resolved by
/// [`crate::federation::receive_auth::quarantine_unattributed_enabled`], default
/// OFF/permissive) AND the row did NOT reach
/// [`crate::models::AttestLevel::AgentAttested`] (i.e. it landed `claimed` — no
/// verified per-write content signature), the row's `lifecycle_state` is set to
/// [`crate::models::LifecycleState::Quarantined`].
///
/// The row is still STORED (the bytes converge — CRDT-safe); only this node's
/// local read/egress view hides it via the fail-closed
/// [`crate::models::lifecycle_visible_clause`] allow-list, until a route-out
/// dequarantine (attest upgrade or operator). With the knob off this is a
/// byte-identical no-op (the pre-#1948 accept-visible posture). Honest caveat:
/// a quarantined row does not relay onward (black-hole until dequarantine).
pub(super) fn maybe_quarantine_unattributed(to_insert: &mut Memory, quarantine_enabled: bool) {
    if !quarantine_enabled {
        return;
    }
    if !row_is_agent_attested(to_insert) {
        to_insert.lifecycle_state = crate::models::LifecycleState::Quarantined;
        // #2966 (L6 5-agent vote 4d3ea1c5) — the pre-#2966 code flipped the
        // row to Quarantined and emitted NOTHING while /sync/push returned
        // 200 (the #2444 silent-hide anti-pattern). Make the black-hole
        // observable: one metric increment per quarantined row + a WARN
        // naming id/namespace/agent_id ONLY (never content or secrets). The
        // attributed author is the row's claimed `metadata.agent_id`.
        crate::metrics::inc_fed_quarantined_unattributed();
        let agent_id = to_insert
            .metadata
            .get(crate::META_KEY_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        tracing::warn!(
            target: "federation.quarantine.unattributed",
            id = %to_insert.id,
            namespace = %to_insert.namespace,
            agent_id = %agent_id,
            "sync_push: quarantined provenance-less inbound relayed memory \
             (AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED #123 / #1948) — stored \
             lifecycle_state=quarantined, hidden from local reads until \
             dequarantine-on-attest or operator dequarantine (#2966)"
        );
    }
}

/// Whether a memory's stamped `metadata.attest_level` is
/// [`crate::models::AttestLevel::AgentAttested`] — i.e. its per-write content
/// signature verified against the attributed author's enrolled key. Shared by
/// the route-IN quarantine ([`maybe_quarantine_unattributed`]) and route-OUT
/// dequarantine-on-attest decisions (#1948).
pub(super) fn row_is_agent_attested(mem: &Memory) -> bool {
    mem.metadata
        .get(crate::models::field_names::ATTEST_LEVEL)
        .and_then(serde_json::Value::as_str)
        == Some(crate::identity::verify::AttestLevel::AgentAttested.as_str())
}

/// #1920 (CWE-862) — authorship gate for an inbound federated PENDING
/// action, mirroring [`resolve_inbound_attribution`] (memories) and
/// [`signal_author_authorized`] (signals). A pending action is an
/// authority-granting request: it is later approved + executed as a
/// `store` / `delete` / `promote` / `reflect` side effect, so a hostile
/// peer must NOT be able to inject one attributed to an arbitrary
/// `requested_by` (or smuggle a forged `payload.metadata.agent_id`). The
/// `pendings[]` loop runs BEFORE `pending_decisions[]`, so an ungated
/// upsert + a forged approval in the SAME request is the exploit.
///
/// Returns `true` when the peer may relay this pending row:
/// - Zero-config (no allowlist): faith-based — accept (byte-identical to
///   the pre-fix posture the other lanes preserve for an unenrolled mesh).
/// - Enrolled posture: accept only when every claimed author (the
///   `requested_by` and, when present, the store payload's
///   `metadata.agent_id`) either self-relays (`== sender_agent_id`) or is
///   in the peer's [`peer_attestation::PeerScope::allowed_sender_agent_ids`].
#[must_use]
pub(super) fn pending_author_authorized(
    pa: &crate::models::PendingAction,
    sender_agent_id: &str,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
) -> bool {
    if !attest_cfg.has_allowlist() {
        return true;
    }
    let payload_agent = pa
        .payload
        .get("metadata")
        .and_then(|m| m.get(crate::META_KEY_AGENT_ID))
        .and_then(serde_json::Value::as_str);
    let scope = peer_id.and_then(|p| attest_cfg.scope_for(p));
    let authorized = |claimed: &str| -> bool {
        claimed == sender_agent_id
            || scope.is_some_and(|s| s.allowed_sender_agent_ids.iter().any(|a| a == claimed))
    };
    authorized(&pa.requested_by) && payload_agent.is_none_or(authorized)
}

/// #2478 — payload key naming the namespace a `store` / `reflect` pending
/// action writes into.
///
/// Mirrors the key [`crate::storage::execute_pending_action`] and its
/// `execute_reflect_from_payload` helper read out of `pa.payload`. The two MUST
/// stay in lockstep: this resolver is only a correct security gate for as long
/// as it names the same key the executor obeys.
const PENDING_PAYLOAD_NAMESPACE_KEY: &str = "namespace";

/// The namespaces an approved `pending_actions` row would actually TOUCH when
/// [`crate::storage::execute_pending_action`] replays it (#2478).
///
/// `claimed` are namespaces the execution DECLARES or WRITES INTO; `by_id` are
/// ids of EXISTING local rows it destroys, mutates, or derives from, whose
/// STORED namespace the wire never names and must therefore be resolved.
pub(super) struct PendingEffect<'a> {
    claimed: Vec<&'a str>,
    by_id: Vec<&'a str>,
    /// The `delete` arm — selects the DESTRUCTIVE Layer-2 refusal prose.
    destructive: bool,
}

/// Read a string field out of a pending action's payload.
fn pending_payload_str<'a>(pa: &'a crate::models::PendingAction, key: &str) -> Option<&'a str> {
    pa.payload.get(key).and_then(serde_json::Value::as_str)
}

/// Parse an `action_type` string into the closed [`crate::models::GovernedAction`]
/// vocabulary, keyed off that enum's own `as_str` SSOT so no literal is
/// re-declared here. `None` for anything else — the caller treats that as a
/// refusal (default-deny).
fn governed_action_of(action_type: &str) -> Option<crate::models::GovernedAction> {
    use crate::models::GovernedAction as G;
    [G::Store, G::Delete, G::Promote, G::Reflect]
        .into_iter()
        .find(|candidate| candidate.as_str() == action_type)
}

/// #2478 (CWE-284) — resolve every namespace the execution of `pa` would reach.
///
/// # Why `pa.namespace` alone would be theatre
///
/// [`crate::storage::execute_pending_action`] **never reads `pa.namespace`**.
/// Its `store` arm deserialises `pa.payload` into a `Memory` and inserts
/// `mem.namespace`; its `promote` arm clones the target into
/// `payload.to_namespace`; its `reflect` arm writes into `payload.namespace`
/// (falling back to `pa.namespace`) and mints a signed `reflects_on` edge onto
/// every `payload.source_ids[i]`; only its `delete` arm touches
/// `pa.memory_id`. A gate on the row's own declared namespace would let a peer
/// scoped to `public/**` send `namespace: "public/ok"` with
/// `payload.namespace: "secure/ops"` and land the arbitrary-namespace write
/// exactly as before — while a regression test asserting "the pendings lane is
/// namespace-confined" went green over it. This resolver returns the UNION of
/// everything the executor can reach and the caller requires ALL of it to be in
/// scope.
///
/// # Default-deny on an unknown arm
///
/// The `action_type` is parsed into [`crate::models::GovernedAction`] and
/// matched EXHAUSTIVELY, so adding a variant to that enum is a compile error
/// here rather than an arm that silently slips past the gate; an unparseable
/// `action_type` yields `None`, which the caller refuses. Nothing legitimate is
/// lost — the executor's own fall-through arm errors on it anyway.
pub(super) fn pending_action_effect(
    pa: &crate::models::PendingAction,
) -> Option<PendingEffect<'_>> {
    use crate::models::GovernedAction as G;

    let action = governed_action_of(&pa.action_type)?;

    // The row's own declared namespace is where `upsert_pending_action` files
    // it AND the `reflect` arm's namespace fallback, so it is always in the
    // set. An EMPTY value is left in DELIBERATELY: it matches no glob, so a
    // scoped peer is refused rather than waved through, and no legitimate
    // sender produces one (`queue_pending_action` requires a namespace).
    let mut claimed: Vec<&str> = vec![pa.namespace.as_str()];
    let mut by_id: Vec<&str> = Vec::new();
    let mut destructive = false;

    match action {
        G::Store => claimed.extend(pending_payload_str(pa, PENDING_PAYLOAD_NAMESPACE_KEY)),
        G::Delete => {
            destructive = true;
            by_id.extend(pa.memory_id.as_deref());
        }
        G::Promote => {
            // BOTH branches reach an existing row by id: with `to_namespace`
            // present `promote_to_namespace` CLONES it into that namespace (so
            // the destination is a write and must be in scope too); without it
            // the arm is a tier-bump + expiry-clear on that same row.
            by_id.extend(pa.memory_id.as_deref());
            claimed.extend(pending_payload_str(
                pa,
                crate::models::field_names::TO_NAMESPACE,
            ));
        }
        G::Reflect => {
            claimed.extend(pending_payload_str(pa, PENDING_PAYLOAD_NAMESPACE_KEY));
            // `reflect` READS every source row and writes a signed
            // `reflects_on` edge onto it, so each source's stored namespace is
            // touched even though the wire never names it.
            by_id.extend(
                pa.payload
                    .get(crate::models::field_names::SOURCE_IDS)
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str),
            );
        }
    }

    Some(PendingEffect {
        claimed,
        by_id,
        destructive,
    })
}

/// #2478 (CWE-284) — namespace confinement for the `/sync/push` governance
/// lanes (`pendings[]` + `pending_decisions[]`), routed through the SAME shared
/// Layer-1/Layer-2 verdict the `memories[]` / `deletions[]` / `archives[]` /
/// `restores[]` lanes use, so this lane's disposition of all four peer shapes
/// is byte-identical to theirs and the empty-scope case honours
/// `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` instead of hard-coding a verdict.
///
/// Callers MUST wrap this in the ENROLLED posture (`attest_cfg.has_allowlist()`)
/// exactly as the sibling lanes do — with no allowlist configured the shared
/// helpers already return `true`, but the wrap is what keeps the zero-config
/// posture free of the probes below (the #2491 outage was a gate that ran
/// unconditionally).
///
/// `stored_pending_namespace` is the namespace of the pending row ALREADY at
/// `pa.id`, or `None` when there provably is none. It is load-bearing, not
/// belt-and-braces: `upsert_pending_action` is `ON CONFLICT(id) DO UPDATE` over
/// every column including `namespace`, so a claimed-only gate would let a
/// `public/**` peer RELOCATE and overwrite a `secure/ops` governance row by
/// pushing its id under an in-scope namespace — the same merge-clobber vector
/// Layer 1's stored-namespace check closes for `memories[]` (#2447).
///
/// # Probe stability
///
/// The receive handler holds the sqlite mutex across the whole request, and no
/// primitive re-namespaces a row in place (`update` takes no namespace;
/// `promote_to_namespace` CLONES), so the by-id probe answers here are stable
/// through to the execute. A future in-place re-namespace primitive would void
/// that and must revisit this gate.
///
/// Returns `true` when the entry may proceed; `false` with an
/// operator-actionable WARN already emitted, in which case the caller must
/// `skipped += 1; continue`.
#[must_use]
pub(super) fn pending_namespaces_authorized(
    conn: &rusqlite::Connection,
    base_lane: &str,
    pa: &crate::models::PendingAction,
    stored_pending_namespace: Option<&str>,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
    require_push_namespace_scope: bool,
) -> bool {
    use crate::federation::receive_auth::{
        LANE_PENDING_DECISION_DELETE, LANE_PENDING_DECISIONS, inbound_by_id_namespace_authorized,
        inbound_write_namespace_authorized, peer_declares_namespace_scope,
    };

    let Some(effect) = pending_action_effect(pa) else {
        tracing::warn!(
            target: ATTESTATION_TRACE_TARGET,
            pending_id = %pa.id,
            action_type = %pa.action_type,
            peer_id = %peer_id.unwrap_or(""),
            "sync_push: refusing federated {base_lane} entry — unknown pending action_type, \
             so the namespaces its execution would touch cannot be resolved (#2478 \
             default-deny). A new action_type must be taught to `pending_action_effect` \
             before it may cross a federation boundary."
        );
        return false;
    };

    // Approving a `delete`-typed pending reaches `storage::delete` exactly as
    // `deletions[]` does, so it takes the destructive refusal prose. Injecting
    // one into `pendings[]` only files a row, so that lane keeps its own.
    let lane = if effect.destructive && base_lane == LANE_PENDING_DECISIONS {
        LANE_PENDING_DECISION_DELETE
    } else {
        base_lane
    };

    // Every namespace the execution declares or writes into.
    for namespace in effect.claimed {
        if !inbound_write_namespace_authorized(
            lane,
            &pa.id,
            namespace,
            None,
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        ) {
            return false;
        }
    }

    // #2488 ELISION (not a gate): Layer 1 unarmed ⇒ no stored namespace can
    // change the verdict, and the loop above has already applied the Layer-2
    // verdict for this peer. Skipping here is what keeps the enrolled-unscoped
    // and header-absent shapes at ZERO extra reads.
    if !peer_declares_namespace_scope(peer_id, attest_cfg) {
        return true;
    }

    // The governance row this upsert would overwrite (see the doc above).
    if stored_pending_namespace.is_some()
        && !inbound_by_id_namespace_authorized(
            lane,
            &pa.id,
            stored_pending_namespace,
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        )
    {
        return false;
    }

    // Existing rows the execution destroys, mutates, or derives from. The probe
    // is the SCALAR `db::namespace_by_id`: `db::get` maps through
    // `row_to_memory`'s fail-closed at-rest decrypt, which would make a row with
    // an unopenable envelope permanently un-actionable by federation (#2497).
    for memory_id in effect.by_id {
        let stored = match db::namespace_by_id(conn, memory_id) {
            Ok(Some(namespace)) => namespace,
            // Provably no such local row — there is nothing in any namespace to
            // protect. The arm itself is then a no-op (`delete`) or errors
            // downstream (`promote` / `reflect`); either way this gate has no
            // subject and must not manufacture a refusal.
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %pa.id,
                    memory_id = %memory_id,
                    cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                    error = %e,
                    "sync_push: refusing federated {lane} entry — a row its execution would \
                     touch has an UNRESOLVABLE namespace on this node, so the scope gate \
                     cannot decide (#2478 fail-closed). Investigate the storage error rather \
                     than the peer's scope."
                );
                return false;
            }
        };
        if !inbound_by_id_namespace_authorized(
            lane,
            memory_id,
            Some(&stored),
            attest_cfg,
            peer_id,
            require_push_namespace_scope,
        ) {
            return false;
        }
    }

    true
}

/// #2479 — OBSERVABILITY ONLY: warn when an inbound `namespace_meta` write or
/// clear would SEVER an inheritance link to a namespace OUTSIDE the peer's
/// scope. Never returns a verdict and never changes one.
///
/// # The loss this makes visible
///
/// `set_namespace_standard` is `ON CONFLICT(namespace) DO UPDATE SET … ,
/// parent_namespace = ?4`, and when the wire carries no parent the value it
/// writes comes from `auto_detect_parent` — which resolves from the namespace
/// STRING, not from what is already stored. So an entirely in-scope push can
/// silently NULL an operator-configured link to an out-of-scope ancestor, and a
/// clear deletes it outright. Both are unintentional config loss (the North Star
/// constraint), and neither is visible anywhere today.
///
/// # Why a WARN and not a refusal
///
/// The #2479 vote weighed refusing on the STORED parent and rejected it twice
/// over. It would BRICK the row: a namespace whose operator-set parent is out of
/// a peer's scope could never be updated by that peer again, which is the
/// stale-stricter failure made permanent (#2491/#2497 availability lesson). And
/// it would not even hold — the loop applies entries in wire order, so entry #1
/// could rewrite the parent to an in-scope value and entry #2 would then pass
/// the probe, laundering the gate inside a single request. A verdict that can be
/// laundered in-batch is worse than an honest log line, because it reads as a
/// control while providing none.
///
/// Consequently this read is DELIBERATELY best-effort in the fail-OPEN
/// direction: a storage error logs and proceeds. That is safe here precisely
/// because nothing downstream consults the result — the inverse of the
/// `CAUSE_NAMESPACE_PROBE_UNRESOLVABLE` sites, where an unresolvable probe MUST
/// fail closed because a verdict depends on it.
///
/// # Honest note on the `Err` arm — it is UNREACHABLE today
///
/// Both `namespace_meta` accessors currently collapse a read error into "no
/// row": `db::get_namespace_parent` ends in a bare `.ok()`, and
/// `db::get_namespace_meta_entry` — despite its `Result` signature — is
/// `#[allow(clippy::unnecessary_wraps)]` and does the same before wrapping in
/// `Ok`. So the `Err` arm below cannot fire as the code stands, and a genuine
/// storage fault is indistinguishable from "this namespace has no meta row",
/// which silently costs this WARN. It reads through `get_namespace_meta_entry`
/// anyway for two reasons: it returns the whole row (the caller needs the
/// parent AND the fact a row exists), and its signature can already CARRY an
/// error, so tightening that accessor later is a one-line change there rather
/// than a call-site rewrite here. Do not restate this site as "fails closed on
/// a read error" — it does not, by design and, today, by accessor.
fn warn_on_severed_out_of_scope_parent(
    conn: &rusqlite::Connection,
    lane: &str,
    namespace: &str,
    declared_parent: Option<&str>,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
) {
    let stored_parent = match db::get_namespace_meta_entry(conn, namespace) {
        Ok(Some(row)) => row.parent_namespace,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                namespace = %namespace,
                peer_id = %peer_id.unwrap_or(""),
                error = %e,
                "sync_push: could not read the existing namespace_meta row before a federated \
                 {lane} entry, so a severed out-of-scope parent link would go unreported \
                 (#2479 observability-only; the scope verdict itself is unaffected)"
            );
            return;
        }
    };
    let Some(stored_parent) = stored_parent else {
        return;
    };
    // Unchanged link — nothing is severed.
    if declared_parent == Some(stored_parent.as_str()) {
        return;
    }
    if crate::federation::peer_attestation::namespace_allowed(peer_id, &stored_parent, attest_cfg) {
        return;
    }
    tracing::warn!(
        target: ATTESTATION_TRACE_TARGET,
        namespace = %namespace,
        stored_parent = %stored_parent,
        declared_parent = %declared_parent.unwrap_or(""),
        peer_id = %peer_id.unwrap_or(""),
        "sync_push: federated {lane} entry REPLACES an inheritance link to a namespace outside \
         this peer's scope — '{namespace}' currently inherits from '{stored_parent}', which the \
         peer may not act in, and this entry drops or re-points that link (#2479). The entry is \
         APPLIED: the peer is in scope for '{namespace}' itself, and refusing here would leave \
         the row permanently un-updatable by this peer. If the link is load-bearing, re-assert \
         it locally or widen the peer's allowed_namespaces to cover '{stored_parent}'."
    );
}

/// v0.7.0 S6-M2 — compute the next UTC midnight in RFC3339, used as
/// the `X-Quota-Reset-At` header value when a federation receive is
/// refused for hitting `memories_per_day` or `links_per_day`. Storage
/// caps reset on midnight UTC via `quotas::reset_daily`. The header
/// matches the HTTP POST refusal surface so clients have one timer
/// to consult regardless of which entry point hit the cap.
pub(super) fn next_utc_midnight() -> String {
    use chrono::{Duration, Timelike};
    let now = chrono::Utc::now();
    let next = now
        .with_hour(0)
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .map(|midnight_today| midnight_today + Duration::days(1))
        .unwrap_or_else(|| now + Duration::days(1));
    next.to_rfc3339()
}

/// #1566 / #1579 B1 — deferred receive-side embedding refresh.
///
/// Spawns a detached task that embeds each `(memory_id,
/// embedding_document)` pair OFF the request path: the embed itself
/// runs on the blocking pool (the embedder is CPU-/network-heavy —
/// ~1s/row via ollama), the DB lock is held only for the per-row
/// `set_embedding` UPDATE, and the HNSW index is touched last (its
/// own mutex, never overlapping the DB lock). Errors are logged and
/// the row is left for the boot-time embed backfill
/// (`db::get_unembedded_ids` selects `embedding IS NULL`, which covers
/// federation-applied rows) — same best-effort posture as the
/// pre-#1566 inline loop, minus the quorum-window coupling.
///
/// No-op when `rows` is empty or the receiver runs keyword-only (no
/// embedder): rows stay FTS-recallable, matching the pre-#1566
/// behaviour where the embed loop was gated on `app.embedder`.
fn spawn_deferred_embedding_refresh(app: &AppState, rows: Vec<(String, String)>) {
    if rows.is_empty() || app.embedder.as_ref().as_ref().is_none() {
        return;
    }
    let db = app.db.clone();
    let embedder = app.embedder.clone();
    let vector_index = app.vector_index.clone();
    tokio::spawn(async move {
        for (id, text) in rows {
            let emb = embedder.clone();
            let embed_res =
                tokio::task::spawn_blocking(move || emb.as_ref().as_ref().map(|e| e.embed(&text)))
                    .await;
            let vec = match embed_res {
                Ok(Some(Ok(v))) => v,
                Ok(Some(Err(e))) => {
                    tracing::warn!("sync_push: deferred embed failed for {id}: {e}");
                    continue;
                }
                // Embedder vanished (impossible — checked above and the
                // Arc is immutable) — nothing left to do for any row.
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!("sync_push: deferred embed join error for {id}: {e}");
                    continue;
                }
            };
            // #2167 — this is a LOCAL re-embed (the shipped vector was
            // rejected/absent), so it lands in the receiver's ACTIVE space.
            let space = match embedder.as_ref().as_ref() {
                Some(e) => e.space_fingerprint(),
                None => return,
            };
            {
                let lock = db.lock().await;
                if let Err(e) = db::set_embedding(&lock.0, &id, &vec, &space) {
                    tracing::warn!("sync_push: set_embedding failed for {id}: {e}");
                    continue;
                }
            }
            let mut idx_lock = vector_index.lock().await;
            if let Some(idx) = idx_lock.as_mut() {
                idx.remove(&id);
                idx.insert(id.clone(), vec);
            }
        }
    });
}

/// Request body for `POST /api/v1/sync/push`.
#[derive(Deserialize)]
pub struct SyncPushBody {
    /// Claimed `agent_id` of the peer pushing data. Recorded in
    /// `sync_state` for vector clock advancement.
    ///
    /// v0.7.0 #238 — this body field is now ATTESTED against the
    /// wire-level `x-peer-id` HTTP header before any substrate write
    /// fires. See `src/federation/peer_attestation.rs` for the
    /// decision matrix, env bypass, and operator runbook. Pre-v0.7.0
    /// federation clients that don't send `x-peer-id` are accepted
    /// only when the operator opts in via
    /// `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`.
    pub sender_agent_id: String,
    /// Vector clock the sender had at push time. v0.7.0 S6-LOW2: now
    /// consulted for observability-only clock-skew detection — the
    /// receiver logs a `tracing::warn!` when the sender's latest
    /// claimed observation is >60s ahead of the receiver's wall clock.
    /// Full clock reconciliation (CRDT-lite merge) lands with Task 3a.1.
    #[serde(default)]
    pub sender_clock: crate::models::VectorClock,
    /// v0.7.0 S6-LOW2 — sender's wall-clock RFC3339 timestamp at push
    /// time. Optional: when absent, skew detection falls back to the
    /// highest timestamp in `sender_clock.entries`. Observability-only;
    /// never enforced.
    #[serde(default)]
    pub sender_wall_clock: Option<String>,
    /// FED-RQ-03 (#1947) — the sender's committed governance `policy_version`
    /// sequence at push time
    /// (`crate::governance::policy_version::current_policy_version().seq`).
    /// ADDITIVE + backward-compatible: `#[serde(default)]` so pre-#1947 peers
    /// (which never advertise it) decode byte-identically to `None`. The
    /// receiver's FED-RQ-03 gate refuses a push whose advertised seq is
    /// STRICTLY BEHIND the local committed policy (a DETECTED-stale value);
    /// `None` is fail-OPEN (undeterminable → accept). Decision surface:
    /// `crate::federation::receive_auth::evaluate_inbound_policy_freshness`.
    /// Send-side advertising rides the DEFERRED epoch-manifest federation
    /// (ADR-002) — the authoritative attested epoch is the signed
    /// `SignableEpochManifest`; this unsigned field is the minimal receive
    /// gate for an HONEST stale peer that opts to advertise.
    #[serde(default)]
    pub sender_policy_seq: Option<i64>,
    /// FED-RQ-03 (#1947) — the lowercase-hex whole-ruleset governance policy
    /// digest paired with `sender_policy_seq` (mirrors the
    /// `SignableEpochManifest` `(policy_seq, policy_digest_hex)` pair).
    /// Diagnostic only in the MINIMAL gate (staleness is seq-ordered); carried
    /// so a same-seq policy DIVERGENCE is observable in the refusal WARN.
    #[serde(default)]
    pub sender_policy_digest_hex: Option<String>,
    /// Memories the sender is offering. Applied via the v0.8.0 Pillar-3
    /// (#1709 / #224) field-level CRDT-lite merge (`db::merge_inbound`):
    /// a divergent same-`id` inbound row is field-merged via
    /// `crate::models::merge_memory`; fresh / `(title, namespace)`-dedup
    /// rows fall through to the timestamp-aware `insert_if_newer` LWW path.
    pub memories: Vec<Memory>,
    /// #1566 / #1579 B1 — source-side embedding vectors for the rows
    /// in `memories` (embed-once-replicate-vector). Inside the
    /// Ed25519-signed body bytes, so vector integrity is covered by
    /// the same `X-Memory-Sig` + nonce replay protection as the rows.
    /// `#[serde(default)]` keeps decode TOLERANT of absence: pushes
    /// from pre-#1566 peers parse identically (empty vec), and the
    /// receive path falls back to the deferred background-embed for
    /// any applied row without a dim-matching shipped vector.
    #[serde(default)]
    pub embeddings: Vec<crate::federation::ShippedEmbedding>,
    /// Memory IDs the sender has deleted and wants propagated. Applied
    /// via `db::delete`. v0.6.0.1: simple remove (no tombstone row); a
    /// concurrent newer `insert_if_newer` from another peer could revive
    /// the row — a Last-Writer-Wins quirk we live with until v0.7's
    /// CRDT-lite tombstone table lands. In the common 4-node mesh, the
    /// same delete reaches every peer well before any revival window.
    #[serde(default)]
    pub deletions: Vec<String>,
    /// v0.6.2 (S29): memory IDs the sender has explicitly archived and
    /// wants propagated. Applied via `db::archive_memory` — a soft move
    /// from `memories` to `archived_memories`. Missing-on-peer IDs no-op.
    /// Distinct from `deletions`, which is a hard DELETE.
    #[serde(default)]
    pub archives: Vec<String>,
    /// v0.6.2 (S29): memory IDs the sender has restored from archive and
    /// wants propagated. Applied via `db::restore_archived` — moves the
    /// row from `archived_memories` back into `memories`. The inverse of
    /// `archives`. Missing-on-peer IDs (no row in the peer's archive
    /// table, or a live row already exists) no-op so replays are safe.
    #[serde(default)]
    pub restores: Vec<String>,
    /// v0.6.2 (#325): memory links the sender wants propagated. Applied
    /// via `db::create_link` on each peer. Duplicates are a no-op thanks
    /// to the unique `(source_id, target_id, relation)` constraint on
    /// `memory_links`.
    #[serde(default)]
    pub links: Vec<MemoryLink>,
    /// v0.6.2 (S34): pending-action rows the sender wants propagated.
    /// Applied via `db::upsert_pending_action` — preserves the originator's
    /// id + status + approvals so the cluster agrees on pending state.
    /// Without this, `POST /api/v1/pending/{id}/approve` on a peer 404s
    /// because the row only exists on the originator.
    #[serde(default)]
    pub pendings: Vec<crate::models::PendingAction>,
    /// v0.6.2 (S34): pending-action decisions the sender wants propagated
    /// so approve/reject on any node lands consistently. Applied via
    /// `db::decide_pending_action` — already-decided rows no-op, replay-safe.
    #[serde(default)]
    pub pending_decisions: Vec<crate::models::PendingDecision>,
    /// v0.6.2 (S35): namespace-standard meta rows the sender wants
    /// propagated. Applied via `db::set_namespace_standard(conn, ns,
    /// standard_id, parent.as_deref())` so the peer's inheritance-chain
    /// walk uses the originator's explicit parent (not a locally
    /// auto-detected one).
    #[serde(default)]
    pub namespace_meta: Vec<crate::models::NamespaceMetaEntry>,
    /// v0.6.2 (S35 follow-up): namespaces whose standard the sender has
    /// *cleared* and wants propagated. Applied via `db::clear_namespace_standard`
    /// — missing-on-peer namespaces no-op so replays are safe. Without
    /// this, alice clearing a standard on node-1 left the row visible on
    /// node-2's peer, breaking cross-peer rule-lifecycle assertions.
    #[serde(default)]
    pub namespace_meta_clears: Vec<String>,
    /// #1718 v0.8.0 Pillar-1 — signed inter-agent signals the sender wants
    /// propagated (the v60 `signals` table). Applied accept-and-flag-unsigned
    /// like memories/links (a signal is a *message*, not an authority grant):
    /// idempotent on the signal UUID, a present-but-invalid signature is
    /// refused as forged, an unsigned signal lands verbatim. See
    /// `crate::federation::receive_auth` for why action *transitions* (the
    /// authority-granting sibling) are fail-closed instead.
    #[serde(default)]
    pub signals: Vec<crate::models::Signal>,
    /// #1718 v0.8.0 Pillar-1 — coordination-action state transitions the sender
    /// wants propagated (the v59 `actions` table). Applied FAIL-CLOSED: a
    /// transition is an *authority-granting* write, so each op is cryptographically
    /// authorized (`receive_auth::authorize_remote_transition`) before the atomic
    /// compare-and-swap on the expected `from_state` (#1718 H1/H2; 5-agent vote
    /// `4d3ea1c5`). An op for an action this node does not have is a no-op.
    #[serde(default)]
    pub action_transitions: Vec<crate::federation::sync::ActionTransitionOp>,
    /// FED-RQ-01 (#1936) — resolved commit-checkpoints the sender wants
    /// propagated (the v61 `checkpoints` table). Applied FAIL-CLOSED like
    /// `action_transitions`: a resolved checkpoint is an *authority-granting*
    /// write (the separation-of-duties freeze anchor), so each row's Ed25519
    /// resolution attestation is verified against the resolver's locally-enrolled
    /// key (`receive_auth::authorize_remote_checkpoint_resolution`) before the
    /// first-resolution-wins CRDT apply (`checkpoints::apply_inbound_resolution`).
    /// The `EpochAdvance` epoch-freeze checkpoint rides this transport (§25.2).
    /// Reuses the `Checkpoint` model on the wire (like `signals` reuse `Signal`)
    /// so the subject + its attested resolution travel together; the receiver
    /// NEVER re-signs (the v0.8.0 local-substrate rule).
    #[serde(default)]
    pub checkpoints: Vec<crate::models::Checkpoint>,
    /// Preview mode — classify and count, do not write.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize)]
pub struct SyncSinceQuery {
    /// Return memories with `updated_at > since`. Absent = full snapshot.
    pub since: Option<String>,
    /// Pagination cap. Defaults to 500.
    pub limit: Option<usize>,
    /// Caller's claimed `agent_id`; optional but recorded in `sync_state`
    /// so the caller can later push incremental updates.
    pub peer: Option<String>,
}

/// v0.7.0 Wave-3 Continuation 2 — postgres-backed federation push.
///
/// Dispatches each `Memory` row through `app.store.apply_remote_memory`
/// (idempotent insert-if-newer) and each link / deletion through the
/// matching trait method. Other subcollections (pendings, archives,
/// restores, namespace_meta, pending_decisions) are governance- /
/// archive-state-machine concerns whose write paths live on tables
/// not yet trait-covered; they surface as skipped with a structured
/// `unsupported_on_postgres` count in the response envelope so a
/// heterogeneous (sqlite ↔ postgres) federation degrades gracefully
/// without silent drops.
///
/// Heterogeneous federation contract: a sqlite peer's push of N
/// memories + M links + K deletions reaches steady-state on the
/// postgres receiver via the trait calls. Audit emission for every
/// accepted federation push fires through `audit::emit` regardless
/// of backend (Phase 9).
pub async fn sync_push(
    State(app): State<AppState>,
    headers: HeaderMap,
    cert_peer: Option<axum::Extension<crate::tls::ClientCertPeerId>>,
    body_bytes: Bytes,
) -> impl IntoResponse {
    // v0.7.0 #791 — verify the per-message signature BEFORE
    // deserialising the body. Keeps the verifier's input identical
    // to the wire bytes (signer + verifier MUST agree byte-for-byte).
    let peer_header_owned = extract_peer_id(&headers).map(str::to_string);

    // #2045 L6 — bind the presenting mTLS client cert to the asserted
    // `X-Peer-Id`. Refuses (`enforce`) / warns (`warn`) on a cert↔peer-id
    // mismatch; a no-op when the posture is `off`, no binding map is
    // configured, or the request did not arrive over the peer-binding mTLS
    // acceptor. Runs BEFORE the postgres dispatch so both backends gate.
    if let Some(rejection) = enforce_cert_peer_binding(
        cert_peer.as_ref().map(|e| &e.0),
        peer_header_owned.as_deref(),
    ) {
        return rejection;
    }

    // v0.7.0 #1056 (Agent-2 #6) — TOFU spoofing guard. The
    // (no sig, no enrolled key) arm of `verify_signature_or_reject`
    // allows the request through with a WARN ("strict enforcement
    // skipped") so an unenrolled federation pair stays operational.
    // That permissive posture lets an attacker who knows a legitimate
    // peer's id but has NOT yet been enrolled (heterogeneous rollout
    // window — operator enrols half the mesh) impersonate the
    // unenrolled half. Close the window by refusing any push whose
    // claimed `x-peer-id` is NOT in the operator-configured peer
    // allowlist (`AI_MEMORY_FED_PEER_ATTESTATION`). When NO allowlist
    // is configured (the default zero-config state), this gate is a
    // no-op and the legacy posture stands — so the security uplift
    // only fires when the operator has explicitly enrolled peers.
    if let Some(peer_id) = peer_header_owned.as_deref() {
        let attest_cfg = peer_attestation::PeerAttestationConfig::from_env();
        if attest_cfg.has_allowlist() && attest_cfg.scope_for(peer_id).is_none() {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                peer_id = %peer_id,
                "sync_push: x-peer-id is not in operator allowlist — refusing (#1056 TOFU guard)"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "x_peer_id_not_in_allowlist",
                    "note": "#1056: x-peer-id is not in AI_MEMORY_FED_PEER_ATTESTATION; \
                             enrol the peer or unset the env to restore zero-config posture.",
                })),
            )
                .into_response();
        }
    }
    // v0.7.0 #922 — chained nonce-freshness check after signature verifies.
    if let Some(rejection) = verify_signature_or_reject(
        &headers,
        &body_bytes,
        peer_header_owned.as_deref(),
        &app.federation_nonce_cache,
    ) {
        return rejection;
    }

    // Deserialise the body now that the signature has been verified.
    let body: SyncPushBody = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("malformed sync_push body: {e}")})),
            )
                .into_response();
        }
    };

    let state = app.db.clone();

    // v0.7.0 #238 — body-claimed sender_agent_id MUST attest against
    // the wire-level `x-peer-id` header (or be the unauthored-push
    // legacy shape). Backwards-compat via
    // `AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`. Runs BEFORE the
    // postgres-dispatch branch so both backends share the same
    // refusal posture. See `src/federation/peer_attestation.rs`.
    // (peer_header_owned already extracted above for signature check)
    let attest_cfg = PeerAttestationConfig::from_env();
    if !peer_attestation::trust_body_agent_id_bypass() {
        if let Err(e) = peer_attestation::attest_sender(
            peer_header_owned.as_deref(),
            Some(body.sender_agent_id.as_str()),
            &attest_cfg,
        ) {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                tag = e.tag(),
                claimed = %body.sender_agent_id,
                peer_header = %peer_header_owned.as_deref().unwrap_or(""),
                "sync_push: sender_agent_id failed attestation against x-peer-id header"
            );
            return attestation_refusal_response(&e);
        }
    } else {
        // Bypass set — log once per request at WARN so the operator
        // can see the legacy posture is in effect.
        tracing::warn!(
            target: ATTESTATION_TRACE_TARGET,
            "sync_push: AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1 — bypassing #238 \
             sender_agent_id attestation (legacy compat)"
        );
    }

    // FED-RQ-03 (#1947, 5-agent vote wd8wtmg0n) — cross-node governance
    // policy_version REFUSE-STALE gate. Runs BEFORE the postgres-dispatch
    // branch (and before any apply loop) so a push governed by a stale
    // governance policy is refused reject-before-apply IDENTICALLY on sqlite
    // and postgres, never reaching a `MemoryStore` verbatim-apply path
    // (postgres-clean, independent of #1990). Fail-OPEN on absent / opt-out /
    // read-error; refuses only a DETECTED-stale sender epoch (see
    // `receive_auth::evaluate_inbound_policy_freshness` for the rollout-safety
    // ordering).
    if let Some(refusal) = refuse_if_stale_policy(&app, &body).await {
        return refusal;
    }

    // v0.7.0 Wave-3 Continuation 2 — postgres-backed federation
    // dispatches through the SAL trait for memories / deletions /
    // links. Pendings / archives / restores / namespace_meta /
    // pending_decisions remain sqlite-only (governance write paths
    // and archive-state-machine state sit on tables not yet covered
    // by the trait surface — those subcollections, when present in a
    // push from a sqlite peer, surface in `skipped` with a structured
    // note in the response envelope).
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return sync_push_via_store(app, headers, body).await;
    }

    if let Err(e) = validate::validate_agent_id(&body.sender_agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("invalid sender_agent_id: {e}")})),
        )
            .into_response();
    }
    // Cap memories per push, matching the bulk-create limit. Without
    // this a malicious peer with a valid mTLS cert could flood the
    // receiver and bottleneck the shared SQLite Mutex (red-team #242).
    if body.memories.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} memories per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    // #1566 / #1579 B1 — the shipped-vector array is bounded by the
    // same cap as its sibling subcollections (red-team #242 posture:
    // vectors are the LARGEST per-element payload on this surface, so
    // an unbounded array would be the cheapest flood vector).
    if body.embeddings.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} embeddings per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    if body.deletions.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} deletions per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    if body.archives.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} archives per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    if body.restores.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} restores per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    if body.pendings.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} pendings per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    if body.signals.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("sync_push limited to {} signals per request", app.max_page_size)
            })),
        )
            .into_response();
    }
    if body.action_transitions.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} action_transitions per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    if body.checkpoints.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} checkpoints per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    if body.pending_decisions.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} pending_decisions per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    if body.namespace_meta.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} namespace_meta per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    if body.namespace_meta_clears.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} namespace_meta_clears per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    // #1556 — `links` was the sole subcollection missing this cap. The link
    // loop below does a synchronous insert (and an Ed25519 verify when the
    // link carries signature+observed_by) per element while holding the shared
    // write Mutex; without a bound a peer could send ~15-20k links per 2 MiB
    // body (15-20x every sibling cap) to saturate the lock — the red-team #242
    // DoS the other caps exist to prevent. Checked pre-lock like its siblings.
    if body.links.len() > app.max_page_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "sync_push limited to {} links per request",
                    app.max_page_size
                )
            })),
        )
            .into_response();
    }
    // Receiver's local identity — default to the caller-supplied header,
    // fall back to the anonymous placeholder. Recorded in sync_state rows.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let local_agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid x-agent-id: {e}")})),
            )
                .into_response();
        }
    };

    // v0.7.0 S6-LOW2 — observability-only sender_clock skew detection.
    // Logs a warn when the sender's clock claim is >60s out from ours;
    // does not gate the push. Federation must be tolerant of drift.
    check_sender_clock_skew(&body.sender_agent_id, &body);

    let lock = state.lock().await;
    let mut applied = 0usize;
    let mut noop = 0usize;
    let mut skipped = 0usize;
    let mut deleted = 0usize;
    let mut archived = 0usize;
    let mut restored = 0usize;
    let mut latest_seen: Option<String> = None;
    // v0.7.0 S6-M2 — federation quota refusals. Counted alongside
    // `skipped` so the existing response envelope shape doesn't change,
    // and surfaced as a distinct field so an operator can tell the
    // difference between "peer pushed garbage" and "peer overran its
    // daily cap". The first quota refusal also short-circuits the
    // whole memory loop with a 429 response (matches the HTTP POST
    // store refusal: callers MUST back off, not just skip the offender).
    let mut quota_refused = 0usize;
    let mut first_quota_refusal: Option<crate::quotas::QuotaError> = None;

    // v0.6.0.1 (#322): peers that apply a synced memory must also refresh
    // their embedding + HNSW index so downstream semantic recall surfaces
    // the row. Without this, scenario-18 observed a2a-hermes r14 black-hole
    // pattern: substrate CRUD fanout works, but semantic recall on peers
    // silently misses propagated writes.
    //
    // #1566 / #1579 B1 (2026-06-10) — embed-once-replicate-vector +
    // ack-after-commit. The pre-#1566 shape embedded every applied row
    // synchronously (~1s/row via ollama) while STILL HOLDING the DB
    // lock, inside the sender's quorum-ack window — the mechanism
    // behind the deadline_exceeded → DLQ cascade (the 62k-row #1578
    // event) and the up-to-9× duplicate embedding across the fleet.
    // Now:
    //   - a dim-matching shipped vector is stored directly under the
    //     already-held lock (one cheap UPDATE, microseconds);
    //   - everything else is DEFERRED to a detached background task
    //     spawned after the response is decided (see
    //     `spawn_deferred_embedding_refresh`), so the ack never waits
    //     on the embedder. FTS keeps the rows keyword-recallable in
    //     the gap, and the boot-time embed backfill
    //     (`db::get_unembedded_ids` — `embedding IS NULL` covers
    //     federation-applied rows) is the restart safety net.
    let receiver_dim = app
        .embedder
        .as_ref()
        .as_ref()
        .map(crate::embeddings::Embedder::dim);
    // #2168 (SEC, data-integrity) — the receiver's OWN configured
    // embedding-space fingerprint (`<canonical_model_id>#<prefix_scheme>`),
    // resolved from the SAME `app.embedder` the local embed path uses.
    // Compared per-row against each shipped vector's fingerprint so a
    // same-dimension vector from a FOREIGN embedding model is never stored
    // verbatim into the local space (see the receive gate below).
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
    // #2167 §3.3 layer 2 — carry the shipped vector's CLAIMED space alongside
    // (id, vec) so the ANN-index insert can be gated on claimed == active
    // (defense-in-depth: a foreign-space vector is stored+flagged but NEVER
    // indexed, even if it somehow reached this vec).
    let mut hnsw_updates: Vec<(String, Vec<f32>, String)> = Vec::new();
    // #2447 (CWE-284) — loop-invariant inputs to the inbound-WRITE namespace
    // scope gate. `ns_scope_needs_existing` also short-circuits the per-memory
    // existing-row probe below: when Layer 1 is not armed for this peer the
    // stored namespace cannot change the verdict, so zero-config deployments
    // pay ZERO extra reads on the federation hot path.
    let require_push_ns_scope =
        crate::federation::receive_auth::require_push_namespace_scope_enabled();
    let ns_scope_needs_existing =
        crate::federation::receive_auth::inbound_write_needs_existing_namespace(
            peer_header_owned.as_deref(),
            &attest_cfg,
        );
    // The by-id sibling lanes (`archives[]` / `restores[]`) probe under the
    // whole ENROLLED posture, not just a declared scope, so Layer 2's
    // disposition of an unscoped enrolled peer is IDENTICAL on every lane.
    let ns_gate_enrolled = attest_cfg.has_allowlist();
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
        // the peer's per-peer `allowed_namespaces` scope, like the read
        // (`/sync/since`) and delete (#1934) lanes. Pre-fix this loop consulted
        // NEITHER the peer's namespace scope NOR the target row's, so a peer
        // scoped to `public/*` could push a row whose `namespace` is
        // `secure/ops` (and, because `merge_memory` LWWs the `namespace` field,
        // could RELOCATE + clobber an existing `secure/ops` row by pushing its
        // id under an in-scope namespace). Resolve the existing row's namespace
        // when Layer 1 is armed and refuse either namespace out of scope.
        // Reject-before-apply: nothing is written and the batch survives.
        let existing_ns = if ns_scope_needs_existing {
            match db::namespace_by_id(&lock.0, &mem.id) {
                Ok(ns) => ns,
                Err(e) => {
                    // Fail CLOSED: an unresolvable existence probe cannot be
                    // reported as "provably no local row" — that is exactly the
                    // input the merge-clobber bypass needs.
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
        // v0.7.0 S6-M2 — per-agent quota gate. F7 (#639) closed this
        // on the HTTP POST store path but federation receive was a
        // back-door bypass: an mTLS peer could push N memories per
        // second past the local `agent_quotas.max_memories_per_day`
        // ceiling because `merge_inbound` (the #1709/#224 reconciliation
        // writer wrapping `insert_if_newer`) is the substrate-level
        // upsert and doesn't consult quotas. Charge each accepted
        // memory against the original author's quota row so the cap
        // is a true cluster-wide budget. On refusal: emit a signed
        // refusal event (for the cryptographic audit chain) and
        // short-circuit the loop with `quota_refused`; the outer
        // handler renders 429 + X-Quota-Reset-At so callers back off.
        // #1464 (v0.8.0, P0) — build the row first, then resolve its quota
        // + ownership attribution by gating the claimed `metadata.agent_id`
        // against the per-peer authorship allowlist (see
        // `resolve_inbound_attribution`). Done before the quota gate so the
        // gate charges the attributed agent, and so the persisted row's
        // owner (`metadata.agent_id`) reflects any re-attribution.
        let cap_for_namespace = db::resolve_governance_policy(&lock.0, &mem.namespace)
            .unwrap_or_else(crate::models::GovernancePolicy::default)
            .effective_max_reflection_depth();
        let mut to_insert = crate::federation::reflection_bookkeeping::stamp_reflection_origin(
            mem,
            &body.sender_agent_id,
            cap_for_namespace,
        );
        // #1464 — capture the originally-claimed author BEFORE attribution
        // may rewrite it, so the content-attestation step can skip rows that
        // get re-attributed to the sender (an unauthorized third-party claim).
        let original_claim = to_insert
            .metadata
            .get(crate::META_KEY_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        // #2340 (FBL-32) — redact to the TO-BE-PERSISTED form FIRST. Moved
        // AHEAD of attribution for #2863 so BOTH the crypto-attest HONOR check
        // and the attestation stamp below verify over exactly the bytes
        // `db::merge_inbound` will persist (the funnel's own redact is then an
        // idempotent no-op). The reorder is behavior-preserving: redact touches
        // only content/title/write_signature while attribution reads/writes only
        // agent_id/attest_level. A cross-mode raw-signed row has its stale
        // write_signature dropped inside the helper and lands honestly `claimed`.
        crate::federation::receive_auth::redact_inbound_before_attestation(&mut to_insert);
        // #2863 — resolve the CLAIMED author's enrolled key up front so a
        // cryptographically-attested third-party claim (a valid propagated
        // write_signature) is HONORED rather than re-attributed to the daemon
        // relay sender (the #2860 re-broadcast divergence). Reused below as the
        // attestation bound key when the claim is honored (attribute == claimed).
        let claim_bound_key = original_claim.as_deref().and_then(|c| {
            // #2865 — DB registry FIRST, enrolled key-dir as a MISS-ONLY
            // fallback, so a third-party author whose FEDERATION identity key
            // is cross-enrolled in the key-dir (not DB-bound) is HONORED
            // rather than re-attributed to the relay sender.
            resolve_author_bound_key(db::agent_pubkey(&lock.0, c).ok().flatten(), c)
        });
        let claim_write_attested = original_claim.as_deref().is_some_and(|c| {
            inbound_claim_is_write_attested(&to_insert, c, claim_bound_key.as_deref())
        });
        let attribute_agent = resolve_inbound_attribution(
            &mut to_insert,
            &body.sender_agent_id,
            &attest_cfg,
            peer_header_owned.as_deref(),
            claim_write_attested,
        );
        // #1464 (v0.8.0) — per-write CONTENT attestation. Verify any
        // presented `metadata.write_signature` against the attributed
        // author's enrolled key → upgrade to `agent_attested` (vs `claimed`);
        // reject a forged signature, or (strict, opt-in) an unsigned honored
        // third-party relayed claim. Skips re-attributed rows internally.
        // Hoist the author's bound key so the refusal WARN can distinguish
        // missing-author-key from missing-signature (item 7 observability —
        // the manual substitute for the deferred TOFU key distribution). When
        // the claim was honored, `attribute_agent == original_claim`, so reuse
        // the key already looked up above (avoids a second lookup, #2863).
        let author_bound_key = if Some(attribute_agent.as_str()) == original_claim.as_deref() {
            claim_bound_key.clone()
        } else {
            // #2865 — same DB-first, enrolled-key-dir MISS-ONLY fallback as the
            // claim key above (the honored branch already carries it via
            // `claim_bound_key`). Lets a peer's cross-enrolled FEDERATION
            // identity key verify a propagated write_signature and reach
            // agent_attested out-of-box, with no manual DB-bind step.
            resolve_author_bound_key(
                db::agent_pubkey(&lock.0, &attribute_agent).ok().flatten(),
                &attribute_agent,
            )
        };
        if let Err(e) = apply_inbound_write_attestation(
            &mut to_insert,
            &attribute_agent,
            &body.sender_agent_id,
            original_claim.as_deref(),
            author_bound_key.as_deref(),
            crate::federation::receive_auth::require_write_sig_enabled(),
        ) {
            // #1801→#1954 item 7 — split the generic AttestationRequired WARN
            // into three actionable causes (unenrolled-author / missing-signature
            // / forged-or-malformed) so an operator gets a precise signal.
            // A missing/unenrolled author key under the strict flip carries the
            // closed-set DLQ cause token `unenrolled_author_strict`
            // (`push_dlq::classify_quarantine_cause`).
            let has_write_sig = to_insert
                .metadata
                .get(crate::models::field_names::WRITE_SIGNATURE)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.trim().is_empty());
            if author_bound_key.is_none() {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    memory_id = %to_insert.id,
                    attribute_agent = %attribute_agent,
                    sender = %body.sender_agent_id,
                    cause = crate::federation::receive_auth::CAUSE_UNENROLLED_AUTHOR_STRICT,
                    error = %e,
                    "sync_push: honored third-party relay refused — ORIGIN author has no \
                     locally-enrolled key to verify the propagated write_signature against; \
                     enroll author {attribute_agent}'s Ed25519 key at this node (unenrolled_author_strict, #1464/#1801→#1954)"
                );
            } else if !has_write_sig {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    memory_id = %to_insert.id,
                    attribute_agent = %attribute_agent,
                    sender = %body.sender_agent_id,
                    cause = crate::federation::receive_auth::CAUSE_MISSING_SIGNATURE,
                    error = %e,
                    "sync_push: honored third-party relay refused — no metadata.write_signature \
                     present under the strict flip (author must EMIT the signature at store time, #1801→#1954)"
                );
            } else {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    memory_id = %to_insert.id,
                    attribute_agent = %attribute_agent,
                    sender = %body.sender_agent_id,
                    cause = crate::federation::receive_auth::CAUSE_FORGED_OR_MALFORMED,
                    error = %e,
                    "sync_push: per-write content attestation failed; rejecting memory (#1464)"
                );
            }
            skipped += 1;
            continue;
        }
        // v1.0.0 R19/A3 (#1948) — route-IN quarantine of a provenance-less
        // (non-`agent_attested`) relayed write. Opt-in + permissive default.
        maybe_quarantine_unattributed(
            &mut to_insert,
            crate::federation::receive_auth::quarantine_unattributed_enabled(),
        );
        let bytes_estimate = i64::try_from(
            to_insert.title.len() + to_insert.content.len() + to_insert.metadata.to_string().len(),
        )
        .unwrap_or(i64::MAX);
        // v0.7.0 #1156 — charge against the per-namespace accounting
        // row. Federation peers can no longer drain an agent's cap by
        // fanning across namespaces (the per-namespace dimension keeps
        // each namespace's allotment intact).
        // #1544 — charge the per-agent STORAGE-BYTES ceiling only (NOT the
        // daily write-COUNT) on the federation RECEIVE path. Replicating an
        // already-attested peer memory is not net-new authorship: the
        // pre-#1544 daily-count charge double-counted a memory that already
        // cleared the author's quota at its origin AND let an enrolled peer
        // exhaust an absent author's daily cap (503-ing that author's own
        // local writes — a cross-tenant DoS) AND 429-stormed the push DLQ
        // past 1000/day. Storage-bytes stays enforced (anti-flood). The
        // five inbound controls (enrollment + mTLS pin + attestation +
        // signature + nonce) gate fan-in; see 5-agent vote (memory 4d3ea1c5).
        match crate::quotas::check_and_record_storage_only(
            &lock.0,
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
                    "sync_push: per-agent quota exceeded; refusing federation push"
                );
                // Emit a signed audit event so the refusal lands in the
                // tamper-evident chain alongside the F7-equivalent HTTP
                // POST refusal. Best-effort: audit-write failure is
                // logged but does not change the refusal control flow.
                let _ = crate::signed_events::append_signed_event(
                    &lock.0,
                    // v0.7.0 #1099 (SR-1 #4, HIGH) — sign the quota-
                    // refusal audit row with the daemon's installed
                    // signing key when one is available. Pre-#1099 the
                    // row always landed unsigned.
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
                // Short-circuit: any further memories in this push
                // would only deepen the cap breach. The remainder of
                // the loop posture (skipping the rest) matches the
                // HTTP POST bulk-create refusal — first cap hit
                // returns 429 with the remaining batch unprocessed.
                break;
            }
            Err(crate::quotas::QuotaCheckError::Sql(e)) => {
                tracing::warn!(
                    "sync_push: quota substrate read failed for {}: {e}",
                    attribute_agent
                );
                skipped += 1;
                continue;
            }
        }
        // (`cap_for_namespace`, `to_insert` + the #1464 per-write
        // attribution gate were resolved above the quota gate so the gate
        // operates on the exact row — with any re-attribution applied —
        // that is persisted here. `stamp_reflection_origin` carried the
        // `peer_origin` / `original_depth` / local-cap metadata.)
        // #2863 — pass the receiver's VERIFIED verdict so the merge-over-existing
        // path re-asserts `agent_attested` atomically when the persisted row is
        // byte-identical to the signed unit this node just verified (the merge's
        // `sanitize` otherwise demotes it to `claimed`). `row_is_agent_attested`
        // reads the post-`apply` `to_insert` (THIS node's verdict, never a peer
        // self-assertion).
        match db::merge_inbound(&lock.0, &to_insert, row_is_agent_attested(&to_insert)) {
            Ok(actual_id) => {
                applied += 1;
                // v1.0.0 R19/A3 (#1948) — route-OUT dequarantine-on-attest.
                // `merge_inbound` PRESERVES an existing row's lifecycle_state
                // on conflict, so when the author's write NOW verifies
                // (agent_attested) we clear any prior quarantine via a raw
                // UPDATE (no-op on a non-quarantined row).
                if row_is_agent_attested(&to_insert) {
                    let _ = db::dequarantine(&lock.0, &actual_id);
                }
                // #1566 / #1579 B1 — store a dim-matching shipped
                // vector directly (no local embed at all); anything
                // else falls back to the deferred background embed.
                // `se.vector.len() == se.dim` guards a malformed
                // sender whose claimed dim disagrees with the payload.
                // #1584 (SEC) — the dim gate is necessary but not
                // sufficient: a shipped vector with NaN/±Inf components
                // or a non-unit norm poisons cosine ranking.
                // `sanitize_shipped_vector` rejects non-finite vectors
                // and L2-normalizes the rest; `None` (or a dim mismatch)
                // falls back to a local re-embed.
                let clean_shipped = shipped_by_id.get(mem.id.as_str()).and_then(|se| {
                    // #1566 / #1579 B1 — dim gate: store a shipped vector
                    // directly only when its dimensionality matches the local
                    // embedder AND the sender's claimed dim matches the payload.
                    if receiver_dim != Some(se.dim) || se.vector.len() != se.dim {
                        return None;
                    }
                    // #2168 (SEC, data-integrity) — vector-space fingerprint
                    // gate. A same-dimension vector produced by a DIFFERENT
                    // embedding model (or the same model under a different
                    // prefix scheme) lives in a different coordinate space:
                    // stored verbatim it would silently poison this node's
                    // cosine recall. Compare the shipped fingerprint against
                    // the receiver's configured embedder fingerprint; a
                    // mismatch falls through to the EXISTING deferred local
                    // re-embed so the row still lands (CRDT-safe) and is
                    // re-embedded under the LOCAL model. CORE INVARIANT: a
                    // foreign-fingerprint vector NEVER enters the local space —
                    // worst case the row is re-embed-pending, never poisoned.
                    // Degrade, never corrupt.
                    let shipped_fp = crate::embeddings::embedding_space_fingerprint(&se.model);
                    if receiver_fp.as_deref() != Some(shipped_fp.as_str()) {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            memory_id = %actual_id,
                            peer_id = %body.sender_agent_id,
                            shipped_fingerprint = %shipped_fp,
                            local_fingerprint = %receiver_fp.as_deref().unwrap_or("<none>"),
                            "sync_push: refusing foreign-embedding-model shipped vector \
                             (#2168) — deferring local re-embed under the local model"
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
                        // #2167 §2-EXC — a SHIPPED vector is stamped with the
                        // sender's CLAIMED space (`mint(se.model)`), NOT the
                        // receiver's. Recall then excludes it unless it equals
                        // the active space (degraded-not-wrong); a foreign
                        // shipped vector heals via deferred/boot re-embed.
                        let claimed_space = crate::embeddings::embedding_space_fingerprint(&model);
                        match db::set_embedding(&lock.0, &actual_id, &vector, &claimed_space) {
                            Ok(()) => hnsw_updates.push((actual_id, vector, claimed_space)),
                            Err(e) => {
                                tracing::warn!(
                                    "sync_push: storing shipped embedding failed for \
                                 {actual_id} (model {model}): {e} — deferring local embed",
                                );
                                deferred_embed.push((
                                    actual_id,
                                    crate::embeddings::embedding_document(&mem.title, &mem.content),
                                ));
                            }
                        }
                    }
                    None => deferred_embed.push((
                        actual_id,
                        crate::embeddings::embedding_document(&mem.title, &mem.content),
                    )),
                }
            }
            Err(e) => {
                // Best-effort refund so a downstream insert failure
                // doesn't leak quota counters. `refund_op` saturates at
                // zero so a buggy double-refund cannot poison the row.
                // #1156 — refund on the same `(agent_id, namespace)`
                // row the check_and_record above incremented.
                let _ = crate::quotas::refund_op(
                    &lock.0,
                    &attribute_agent,
                    &mem.namespace,
                    crate::quotas::QuotaOp::Memory {
                        bytes: bytes_estimate,
                    },
                );
                tracing::warn!("sync_push: merge_inbound failed for {}: {e}", mem.id);
                skipped += 1;
            }
        }
    }

    // v0.7.0 S6-M2 — quota refusal short-circuit. The first refusal in
    // the loop produces a 429 with X-Quota-Reset-At so callers back off
    // (matches the HTTP POST store refusal envelope from F7 / #639).
    if let Some(q) = first_quota_refusal.take() {
        drop(lock);
        // #1566 / #1579 B1 — rows applied BEFORE the refusal are
        // committed and stay committed (the 429 covers the remainder
        // of the batch); index their stored shipped vectors and defer
        // the rest exactly like the success path, instead of leaving
        // them for the next boot backfill.
        if !hnsw_updates.is_empty() {
            let mut idx_lock = app.vector_index.lock().await;
            if let Some(idx) = idx_lock.as_mut() {
                // #2167 §3.3 layer 2 — explicit insert-time space gate (see the
                // success-path loop below): index only claimed == active.
                let active_space = crate::embeddings::active_embedding_space();
                for (id, vec, claimed) in hnsw_updates {
                    if active_space
                        .as_deref()
                        .is_some_and(|a| a != claimed.as_str())
                    {
                        continue;
                    }
                    idx.remove(&id);
                    idx.insert(id, vec);
                }
            }
        }
        spawn_deferred_embedding_refresh(&app, deferred_embed);
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
                "reset_at": reset_at,
            })),
        )
            .into_response();
    }

    // Process deletions (v0.6.0.1 — scenario 10 fanout). Invalid ids are
    // skipped silently; missing rows count as no-op. Peers that have
    // already GC'd the row see identical post-state.
    for del_id in &body.deletions {
        if validate::validate_id(del_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #1934 (CWE-284) — confine deletions to the peer's per-peer
        // `allowed_namespaces` scope, like the read (`/sync/since`) and
        // write (`memories[]`, #2447) lanes.
        //
        // The pre-#2447 form of this comment claimed the write lane was
        // already confined "via `resolve_inbound_attribution`". That was
        // FALSE — that resolver gates WHO you may claim to be, never WHICH
        // namespace you may write into — and the false claim is why #1934
        // closed believing the whole class was covered while the write lane
        // stayed wide open. #2447 actually confines it.
        // Pre-fix the delete loop consulted NEITHER the peer's namespace
        // scope NOR per-row ownership, so a peer scoped to `public/*`
        // could hard-delete rows in `secure/ops` or any other agent's
        // namespace by guessing ids. Resolve the target row's namespace
        // and refuse ids outside the peer's scope. A missing row stays a
        // no-op (unchanged — the peer may have already GC'd it).
        //
        // #2491 (data-integrity, live outage) — the #1934 form called
        // `peer_attestation::namespace_allowed` UNCONDITIONALLY, with no
        // enrolled-posture wrapper. Its `scope_for(peer) == None` arm falls
        // through to `sync_trust_peer_bypass()`, which is FALSE by default, so
        // in the zero-config posture (and on any header-absent push) EVERY
        // federated deletion was refused and counted `skipped` inside an HTTP
        // 200 — no DLQ, no retry, replicas diverging permanently while the
        // origin believed the erasure propagated. This is the same trap
        // `receive_auth.rs` already documented for the write lane; the delete
        // lane never got the `has_allowlist()` guard.
        //
        // #2488 — route through the SHARED by-id verdict (not a third hand-
        // rolled variant) so this lane's disposition of all four peer shapes
        // (zero-config, enrolled-scoped, enrolled-unscoped, header-absent) is
        // byte-identical to the `memories[]` / `archives[]` / `restores[]`
        // lanes and to the postgres twin, and so the empty-scope case honours
        // `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` instead of hard-coding
        // deny. The probe is the SCALAR `db::namespace_by_id` — `db::get` maps
        // through `row_to_memory`'s fail-closed at-rest decrypt, which made a
        // row with an unopenable envelope permanently un-erasable (see the
        // `namespace_by_id` doc). Fable 5 1×7 vote (4d3ea1c5).
        if ns_gate_enrolled {
            let needs_stored = crate::federation::receive_auth::peer_declares_namespace_scope(
                peer_header_owned.as_deref(),
                &attest_cfg,
            );
            let stored_ns = if needs_stored {
                match db::namespace_by_id(&lock.0, del_id) {
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
        match db::delete(&lock.0, del_id) {
            Ok(true) => deleted += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push: delete failed for {del_id}: {e}");
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S29): process explicit archives. Soft-move from `memories`
    // to `archived_memories` — distinct from deletions which hard-delete.
    // Missing rows count as no-op (peer may have already archived or
    // never received the original write).
    for arch_id in &body.archives {
        if validate::validate_id(arch_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #2447 — `archives[]` is the same by-id reach into a foreign namespace
        // the #1934 delete gate closed, one step softer (a recoverable move to
        // `archived_memories` rather than a hard DELETE) — but it still removes
        // the row from every live read of a namespace the peer was denied, and
        // an ARCHIVED row is the input `restores[]` below resurrects. Confine
        // it to the peer's scope with the same resolve-then-refuse shape. A
        // missing row stays a no-op; an unresolvable one fails closed.
        if ns_gate_enrolled {
            match db::namespace_by_id(&lock.0, arch_id) {
                Ok(Some(namespace)) => {
                    if !crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                        "archives",
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
                        "sync_push: archive pre-resolve failed for {arch_id}: {e}; \
                         refusing the archive (#2447 fail-closed)"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }
        match db::archive_memory(&lock.0, arch_id, Some("sync_push")) {
            Ok(true) => archived += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push: archive_memory failed for {arch_id}: {e}");
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S29): process explicit restores — the inverse of archives.
    // Move the row from `archived_memories` back into `memories`.
    // No-op posture matches archives: missing rows (peer hasn't received
    // the archive, or the row is already live) count as noop so replays
    // and out-of-order restore/archive pairs don't error.
    for res_id in &body.restores {
        if validate::validate_id(res_id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #1848 (security review S5, gap G30; 5-agent vote 4d3ea1c5 option B):
        // this federation /sync/push restores[] path is the AUTOMATIC,
        // peer-triggered resurrection vector. A peer must NOT undo a local
        // forget by pushing a restore of a tombstoned id — so the G30 tombstone
        // gate lives HERE, not on the operator restore_archived (an authorized
        // un-forget per #1771). Tombstoned → no-op (matches the loop's posture).
        // #2447 — `restores[]` is the resurrection twin of `archives[]`: it
        // moves a row BACK into the live `memories` table, so an unscoped
        // restore lets a `public/*` peer re-materialise rows in a namespace it
        // was denied (including the pre-merge snapshot the #2447 clobber path
        // would have left behind). The row lives in `archived_memories` at this
        // point, hence the archive-table twin of the namespace probe. The G30
        // tombstone gate below is orthogonal and still runs.
        if ns_gate_enrolled {
            match db::archived_namespace_by_id(&lock.0, res_id) {
                Ok(Some(namespace)) => {
                    if !crate::federation::receive_auth::inbound_by_id_namespace_authorized(
                        "restores",
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
                        "sync_push: restore pre-resolve failed for {res_id}: {e}; \
                         refusing the restore (#2447 fail-closed)"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }
        match db::memory_is_tombstoned(&lock.0, res_id) {
            Ok(true) => {
                noop += 1;
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!("sync_push: tombstone check failed for {res_id}: {e}");
                skipped += 1;
                continue;
            }
        }
        match db::restore_archived(&lock.0, res_id) {
            Ok(true) => restored += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push: restore_archived failed for {res_id}: {e}");
                skipped += 1;
            }
        }
    }

    // v0.6.2 (#325): process incoming links. Duplicates are expected on
    // retry / re-sync and collapse to a no-op via the unique index on
    // (source_id, target_id, relation). Invalid ids are skipped silently
    // — same posture as deletions.
    //
    // v0.7 H3: when a link arrives with a signature + observed_by claim,
    // verify it against the public key associated with that claim before
    // landing the row. Tampered signatures → reject with a warn log.
    // Unknown observed_by (no enrolled key on this host) → accept-and-
    // flag as `unsigned` so federation back-compat holds for peers that
    // haven't enrolled yet. Successful verify → land with attest_level
    // `peer_attested`.
    let mut links_applied = 0usize;
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

        // Gate 1 / #2489 — namespace confinement for links[] via the shared
        // by-id choke (source AND target stored namespaces). Structural
        // lane token: receive_auth::LANE_LINKS / push_lanes::Links.
        // Zero-config (`!ns_gate_enrolled`) stays byte-identical faith replication.
        if ns_gate_enrolled {
            use crate::federation::receive_auth::{
                LANE_LINKS, inbound_by_id_namespace_authorized, peer_declares_namespace_scope,
            };
            let needs_stored =
                peer_declares_namespace_scope(peer_header_owned.as_deref(), &attest_cfg);
            let probe = |id: &str| -> Result<Option<String>, anyhow::Error> {
                if !needs_stored {
                    return Ok(None);
                }
                match db::namespace_by_id(&lock.0, id) {
                    Ok(ns) => Ok(ns),
                    Err(e) => Err(e),
                }
            };
            let src_ns = match probe(&link.source_id) {
                Ok(ns) => ns,
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        memory_id = %link.source_id,
                        error = %e,
                        "sync_push: refusing federated link — source namespace unresolvable (#2489)"
                    );
                    skipped += 1;
                    continue;
                }
            };
            let dst_ns = match probe(&link.target_id) {
                Ok(ns) => ns,
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        memory_id = %link.target_id,
                        error = %e,
                        "sync_push: refusing federated link — target namespace unresolvable (#2489)"
                    );
                    skipped += 1;
                    continue;
                }
            };
            // Missing endpoint under Layer 1: fail closed (cannot prove scope).
            if needs_stored && (src_ns.is_none() || dst_ns.is_none()) {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    source_id = %link.source_id,
                    target_id = %link.target_id,
                    "sync_push: refusing federated link — endpoint missing so scope cannot decide (#2489)"
                );
                skipped += 1;
                continue;
            }
            let src_ok = inbound_by_id_namespace_authorized(
                LANE_LINKS,
                &link.source_id,
                src_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            );
            let dst_ok = inbound_by_id_namespace_authorized(
                LANE_LINKS,
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

        // Decide attest_level via the H3 verify path before insert.
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
                            Ok(()) => crate::models::AttestLevel::PeerAttested.as_str(),
                            Err(e) => {
                                // Tampered / malformed-sig: refuse to land
                                // the row. The receiver-side warn log is
                                // the operator's signal that a peer is
                                // misbehaving (or that a key rotation
                                // got out of sync).
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
                    None => {
                        // No public key enrolled for this peer →
                        // accept-and-flag as unsigned. Operators can
                        // later enroll the key (`identity import`) and
                        // re-sync to upgrade the row's attest_level on
                        // a subsequent re-send.
                        crate::models::AttestLevel::Unsigned.as_str()
                    }
                }
            }
            // No signature on the wire (legacy v0.6.x peer) or no
            // observed_by claim → treat as unsigned. Same posture as
            // pre-H3 federation.
            _ => crate::models::AttestLevel::Unsigned.as_str(),
        };

        match db::create_link_inbound(&lock.0, link, attest_level) {
            Ok(()) => links_applied += 1,
            Err(e) => {
                tracing::warn!(
                    "sync_push: create_link_inbound failed ({} -> {} / {}): {e}",
                    link.source_id,
                    link.target_id,
                    link.relation
                );
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S34): process incoming pending-action rows. Uses
    // `upsert_pending_action` so replays / races converge on the
    // originator's canonical row. Invalid ids skipped silently.
    let mut pendings_applied = 0usize;
    for pa in &body.pendings {
        if validate::validate_id(&pa.id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #2529 (CWE-284) — `pendings[]` is the injection lane for UNDECIDED
        // governance rows. Decisions converge through `pending_decisions[]`.
        // Refuse wire rows that already claim a terminal status, so a peer
        // cannot inject a pre-approved/rejected row and skip the decision path.
        if pa.status != "pending" {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                pending_id = %pa.id,
                status = %pa.status,
                "sync_push: refusing federated pendings entry with non-pending status \
                 (#2529) — use pending_decisions[] to converge decisions"
            );
            skipped += 1;
            continue;
        }
        // #1920 (CWE-862) — gate the pending upsert behind the per-peer
        // authorship allowlist so a hostile peer cannot inject a pending
        // action attributed to an arbitrary `requested_by` (or a forged
        // payload author) and then approve+execute it in the same request.
        if !pending_author_authorized(
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
                "sync_push: peer not authorized to inject a pending action attributed to \
                 requested_by (#1920) — skipping"
            );
            skipped += 1;
            continue;
        }
        // Probe local row once for #2529 terminal-status refuse + #2478 ns.
        let local_pending = match db::get_pending_action(&lock.0, &pa.id) {
            Ok(row) => row,
            Err(e) => {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %pa.id,
                    cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                    error = %e,
                    "sync_push: refusing federated pendings entry — local governance row \
                     unresolvable (#2478/#2529 fail-closed)"
                );
                skipped += 1;
                continue;
            }
        };
        // #2529 — a locally DECIDED pending is terminal from the wire's view.
        // Refuse resurrection / clobber of decided_by / approvals / status.
        if let Some(ref existing) = local_pending {
            if existing.status != "pending" {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %pa.id,
                    local_status = %existing.status,
                    "sync_push: refusing federated pendings upsert — local row is already \
                     decided (#2529); decisions converge via pending_decisions[]"
                );
                skipped += 1;
                continue;
            }
        }
        // #2478 (CWE-284) — #1920 gates WHO a pending may be attributed to; it
        // never consults a namespace. Confine the injection to the peer's scope
        // through the SAME shared verdict the memories/deletions lanes use, so
        // an out-of-scope governance row cannot be parked here for a later
        // approval (by the `pending_decisions[]` loop below, or by a LOCAL
        // operator through an approve surface that has no peer scope to consult).
        //
        // ZERO-CONFIG RESIDUAL, stated rather than implied: like every sibling
        // lane this whole gate short-circuits on `has_allowlist()`, so a
        // deployment with no `AI_MEMORY_FED_PEER_ATTESTATION` keeps the
        // arbitrary-namespace primitive. That is parity with #2447/#2488, not an
        // oversight — but this lane's sink is strictly more destructive than
        // `memories[]`, so it is named here and in the PR body.
        if ns_gate_enrolled {
            let stored_pending_ns = local_pending.as_ref().map(|row| row.namespace.clone());
            if !pending_namespaces_authorized(
                &lock.0,
                crate::federation::receive_auth::LANE_PENDINGS,
                pa,
                stored_pending_ns.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
                require_push_ns_scope,
            ) {
                skipped += 1;
                continue;
            }
        }
        match db::upsert_pending_action(&lock.0, pa) {
            Ok(()) => {
                pendings_applied += 1;
                // v0.7.0 K4 — peer-originated pending rows fire the
                // `approval_requested` event on this peer too so local
                // approval-API subscribers get a uniform view of the
                // queue regardless of which node minted the row.
                // `upsert_*` is idempotent (`ON CONFLICT(id) DO UPDATE`)
                // — replays of the same row currently re-fire the
                // event; that's the documented K4 behaviour and matches
                // the existing `pending_action_expired` semantics. K7
                // (subscription reliability) layers DLQ + dedup on top.
                if pa.status == "pending" {
                    crate::subscriptions::dispatch_approval_requested(&lock.0, &pa.id, &lock.1);
                }
            }
            Err(e) => {
                tracing::warn!("sync_push: upsert_pending_action failed for {}: {e}", pa.id);
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S34): process incoming pending-action decisions. No-op on
    // already-decided rows; that's the steady-state when the originator
    // and this peer both saw the decision. Rejected decisions still
    // transition status so retries on either side see `status != 'pending'`.
    let mut pending_decisions_applied = 0usize;
    for dec in &body.pending_decisions {
        if validate::validate_id(&dec.id).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #1920 (CWE-862) — an APPROVAL is authority-granting (it triggers
        // the pending action's store/delete/promote/reflect side effect),
        // so route it through the SAME hardened governance gate the HTTP
        // approve surface uses (`approve_with_approver_type`), NOT the raw
        // `decide_pending_action` which trusted the attacker-supplied
        // `decider` verbatim. `ApproveSurface::Http` fires the self-approval
        // reject + registered-approver + approver-type-policy checks
        // UNCONDITIONALLY — the strongest posture, correct here because the
        // federation lane has a real adversary (a hostile-but-enrolled
        // peer). Only a genuinely-approved action is executed; a forged
        // approval (`decider` == requester, or an unregistered decider) is
        // refused. A REJECT merely DENIES a pending (converges toward the
        // originator's rejected state) and grants no authority, so it keeps
        // the idempotent `decide_pending_action(false)` transition.
        if dec.approved {
            // #2478 (CWE-284) — the APPROVE arm is the one that EXECUTES, and
            // `db::execute_pending_action` reaches `insert()` in the payload's
            // namespace, `delete()` on `pa.memory_id`, `promote_to_namespace()`
            // into `payload.to_namespace`, and `reflect()` over every
            // `payload.source_ids[i]` — none of which any pre-#2478 gate on this
            // lane consulted (`pending_author_authorized` inspects only
            // `requested_by` and the payload's `metadata.agent_id`).
            //
            // The pending row is resolved from LOCAL STORAGE, never from the
            // `pendings[]` entry of this same request: that entry is
            // attacker-controlled, so gating against it would be a TOCTOU on the
            // gate's own input. It is also resolved BEFORE
            // `approve_with_approver_type`, never between approve and execute —
            // the consensus arm durably appends the vote and can flip `status`
            // to `approved` at threshold, so a refusal landing after it would
            // leave an approved-but-unexecuted row: divergence plus a landmine
            // for whoever approves next.
            let pa = match db::get_pending_action(&lock.0, &dec.id) {
                Ok(Some(pa)) => pa,
                // Unknown pending — the converged no-op that
                // `ApproveOutcome::NotFound` already counted below. Counting it
                // `skipped` instead would make every converged replica non-ack
                // forever, which is the #2491 class this campaign closed.
                Ok(None) => {
                    noop += 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        pending_id = %dec.id,
                        cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                        error = %e,
                        "sync_push: refusing federated pending decision — the target \
                         governance row is UNRESOLVABLE on this node, so the namespaces its \
                         execution would touch cannot be resolved (#2478 fail-closed)."
                    );
                    skipped += 1;
                    continue;
                }
            };
            if ns_gate_enrolled
                && !pending_namespaces_authorized(
                    &lock.0,
                    crate::federation::receive_auth::LANE_PENDING_DECISIONS,
                    &pa,
                    None,
                    &attest_cfg,
                    peer_header_owned.as_deref(),
                    require_push_ns_scope,
                )
            {
                skipped += 1;
                continue;
            }
            // #2478 — the `deleted` counter must report rows DESTROYED, not
            // deletes attempted, or the 200 envelope lies in the other
            // direction. The executor's delete arm discards `db::delete`'s
            // boolean (`delete(conn, &mid)?; Some(mid)`), so after the fact the
            // handler cannot tell a removal from a no-op on an absent id —
            // hence this pre-probe. The sqlite mutex is held across the whole
            // handler, so the probe and the execute observe the same row set. An
            // Err resolves to `false`, which UNDER-reports rather than claiming
            // a destruction that may not have happened.
            let delete_target_existed =
                pa.action_type == crate::models::GovernedAction::Delete.as_str()
                    && pa.memory_id.as_deref().is_some_and(|mid| {
                        matches!(db::namespace_by_id(&lock.0, mid), Ok(Some(_)))
                    });
            match db::approve_with_approver_type(
                &lock.0,
                &dec.id,
                &dec.decider,
                db::ApproveSurface::Http,
            ) {
                Ok(db::ApproveOutcome::Approved) => {
                    pending_decisions_applied += 1;
                    // Replay the pending payload so the target write lands
                    // on this peer — matches the originator's post-approve
                    // state.
                    match db::execute_pending_action(&lock.0, &dec.id) {
                        Ok(_) => {
                            // #2478 — a pending-executed hard DELETE was
                            // previously invisible in the 200: it incremented no
                            // destructive counter at all, so an operator reading
                            // the envelope could not tell that rows had been
                            // erased by this push.
                            if delete_target_existed {
                                deleted += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "sync_push: execute_pending_action failed for {}: {e}",
                                dec.id
                            );
                            // #2478 — without this the decision counted APPLIED
                            // while its side effect never landed and `skipped`
                            // stayed 0, so `success_report_non_ack_reason` saw a
                            // clean report and the sender ACKed a write that does
                            // not exist here.
                            skipped += 1;
                        }
                    }
                }
                // Consensus-gated: the relayed vote was recorded but quorum
                // is not yet met on this peer — nothing to execute.
                Ok(db::ApproveOutcome::Pending { .. }) => pending_decisions_applied += 1,
                // Already decided / unknown pending — converged / no-op.
                Ok(db::ApproveOutcome::NotFound) => noop += 1,
                Ok(db::ApproveOutcome::Rejected(reason)) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        pending_id = %dec.id,
                        decider = %dec.decider,
                        "sync_push: refusing forged / unauthorized federated approval (#1920): \
                         {reason}"
                    );
                    skipped += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "sync_push: approve_with_approver_type failed for {}: {e}",
                        dec.id
                    );
                    skipped += 1;
                }
            }
        } else {
            // #2532 (CWE-284) — REJECT was left ungated by the #2478 vote
            // (`4d3ea1c5`) on the theory that refusing a reject leaves the row
            // `pending` and still APPROVABLE, preserving an authority path the
            // originator killed. Re-analysis for multi-tenant enrollment:
            // an enrolled peer with scope `public/*` must NOT permanently veto
            // a `secure/**` tenant's queue. A correctly enrolled originator of a
            // pending for namespace N is in-scope for N, so legitimate reject
            // convergence still passes the same shared `pending_namespaces_*`
            // gate as APPROVE. Leaving a foreign pending approvable after an
            // out-of-scope refuse is the correct multi-tenant outcome — only
            // in-scope peers may decide. Probe the LOCAL row (never wire body).
            let pa = match db::get_pending_action(&lock.0, &dec.id) {
                Ok(Some(pa)) => pa,
                Ok(None) => {
                    // Converged no-op: nothing to reject (same as approve NotFound).
                    noop += 1;
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        pending_id = %dec.id,
                        cause = crate::federation::receive_auth::CAUSE_NAMESPACE_PROBE_UNRESOLVABLE,
                        error = %e,
                        "sync_push: refusing federated pending REJECT — local governance \
                         row unresolvable (#2532 fail-closed)"
                    );
                    skipped += 1;
                    continue;
                }
            };
            if ns_gate_enrolled
                && !pending_namespaces_authorized(
                    &lock.0,
                    crate::federation::receive_auth::LANE_PENDING_DECISIONS,
                    &pa,
                    None,
                    &attest_cfg,
                    peer_header_owned.as_deref(),
                    require_push_ns_scope,
                )
            {
                tracing::warn!(
                    target: ATTESTATION_TRACE_TARGET,
                    pending_id = %dec.id,
                    namespace = %pa.namespace,
                    "sync_push: refusing federated pending REJECT — peer not authorized \
                     for the pending's effect namespaces (#2532); unauthorized veto closed"
                );
                skipped += 1;
                continue;
            }
            // #2720 F-12 (CWE-346) — bind the decider to the attested peer, never
            // the self-asserted wire `dec.decider`. Mirrors the memory lane's
            // `resolve_inbound_attribution`: an unauthorized third-party claim is
            // rebound to the sender so the signed `pending_action.denied` audit
            // row records the real attested actor, not a forged operator id.
            let bound_decider = resolve_inbound_decider(
                &dec.decider,
                &body.sender_agent_id,
                &attest_cfg,
                peer_header_owned.as_deref(),
            );
            match db::decide_pending_action(&lock.0, &dec.id, false, &bound_decider) {
                Ok(true) => pending_decisions_applied += 1,
                Ok(false) => noop += 1, // already decided — converged state
                Err(e) => {
                    tracing::warn!(
                        "sync_push: decide_pending_action (reject) failed for {}: {e}",
                        dec.id
                    );
                    skipped += 1;
                }
            }
        }
    }

    // #1718 v0.8.0 Pillar-1 — process incoming signals. Accept-and-flag-unsigned
    // (a signal is a message, not an authority grant — same posture as
    // memories/links; the authority-granting action *transition* sibling is
    // fail-closed in `receive_auth`). Idempotent on the signal UUID; a
    // present-but-invalid signature is refused as forged. #1544: the receive
    // path charges the storage-bytes quota only (replication is not net-new
    // authorship) — a refusal skips the offending signal without 429-ing the
    // whole push (signals are not the primary write surface).
    let mut signals_applied = 0usize;
    let require_signal_sig = crate::federation::receive_auth::require_signal_sig_enabled();
    for sig in &body.signals {
        if validate::validate_id(&sig.id).is_err() {
            skipped += 1;
            continue;
        }
        if !sig.signature.is_empty() && !crate::signals::verify(sig) {
            tracing::warn!(
                "sync_push: signal {} has an invalid signature — skipping (forged)",
                sig.id
            );
            skipped += 1;
            continue;
        }
        // #1843 (v0.8.1) — bind `from_agent` to the enrolled peer's authorship
        // before storing. The forged-signature check above only proves the
        // signal verifies against its OWN wire `sender_pubkey`; it never binds
        // `from_agent` to anything, so an enrolled peer could relay a signal
        // authored as ANY agent (CWE-346 — the memory + transition lanes already
        // close this). Signals carry `from_agent` inside the signed canonical
        // bytes, so a forged author cannot be cleanly re-attributed: the
        // disposition is a PER-SIGNAL skip — never a re-attribution and never a
        // drop of the rest of the batch (co-resident memories/links/transitions
        // in the same push still apply). 5-agent vote `4d3ea1c5`.
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
        // Gate 1 / #2489 — namespace confinement for signals[] (claimed ns).
        // Structural lane token: receive_auth::LANE_SIGNALS / push_lanes::Signals.
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
        match crate::signals::get(&lock.0, &sig.id) {
            Ok(Some(_)) => {
                noop += 1; // already have it — idempotent replay
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("sync_push: signal get failed for {}: {e}", sig.id);
                skipped += 1;
                continue;
            }
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        let bytes = i64::try_from(sig.body.to_string().len()).unwrap_or(i64::MAX);
        if let Err(e) = crate::quotas::check_and_record_storage_only(
            &lock.0,
            &sig.from_agent,
            &sig.namespace,
            bytes,
        ) {
            tracing::warn!("sync_push: signal {} refused by storage quota: {e}", sig.id);
            skipped += 1;
            continue;
        }
        match crate::signals::insert(&lock.0, sig) {
            Ok(_) => signals_applied += 1,
            Err(e) => {
                tracing::warn!("sync_push: signal insert failed for {}: {e}", sig.id);
                skipped += 1;
            }
        }
    }

    // #1718 v0.8.0 Pillar-1 — process incoming action-state transitions.
    // FAIL-CLOSED authorization (a transition is an authority-granting write,
    // unlike signals/memories): each op is cryptographically authorized via
    // `receive_auth::authorize_remote_transition` (signature verified against
    // the attested actor's ENROLLED key + best-effort local lease-holder auth;
    // 5-agent vote `4d3ea1c5`) BEFORE the atomic compare-and-swap on the
    // expected `from_state` (H1). An op for an action this node does not have,
    // or that loses the CAS, is a safe no-op. No storage quota is charged: a
    // transition mutates existing action state — it is not net-new storage
    // (#1544 scope is replication bytes, not state changes).
    let mut action_transitions_applied = 0usize;
    let require_tx_sig = crate::federation::receive_auth::require_transition_sig_enabled();
    for op in &body.action_transitions {
        if validate::validate_id(&op.action_id).is_err() {
            skipped += 1;
            continue;
        }
        let local = match crate::actions::get(&lock.0, &op.action_id) {
            Ok(Some(a)) => a,
            Ok(None) => {
                noop += 1; // action unknown here — nothing to transition
                continue;
            }
            Err(e) => {
                tracing::warn!("sync_push: action get failed for {}: {e}", op.action_id);
                skipped += 1;
                continue;
            }
        };
        // Gate 1 / #2649 — authentication is not authorization. Crypto authz
        // (authorize_remote_transition) answers "who signed"; this choke answers
        // "may this peer touch the stored action namespace". Subject is the
        // **stored** namespace already loaded for the signable — no extra read.
        // Zero-config (`!has_allowlist`) short-circuits inside the helper.
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
        let lease_holder = crate::actions::lease_get(&lock.0, &op.action_id)
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
                // #1805 — per-transition nonce anti-replay. The transition
                // nonce is signed (tamper-evident) but was never recorded, so a
                // captured signed transition re-wrapped in a FRESH outer
                // envelope replays through CAS on a cyclic/ABA edge (CAS is
                // causal ordering, not anti-replay). Record it in the per-peer
                // nonce cache (the #30 envelope-nonce store) and refuse a
                // repeat. Rides the #1718 / 4d3ea1c5 fail-closed posture; an
                // empty nonce = unsigned op (heterogeneous rollout) → not gated.
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
                            "sync_push: replayed action-transition nonce refused (#1805)"
                        );
                        skipped += 1;
                        continue;
                    }
                }
                match crate::actions::transition_cas(
                    &lock.0,
                    &op.action_id,
                    op.from_state,
                    op.to_state,
                    op.claimed_by.as_deref(),
                    op.updated_at,
                ) {
                    Ok(crate::actions::CasOutcome::Applied(_)) => action_transitions_applied += 1,
                    Ok(_) => noop += 1, // CAS miss / not-found / illegal edge — safe no-op
                    Err(e) => {
                        tracing::warn!(
                            "sync_push: action transition {} cas failed: {e}",
                            op.action_id
                        );
                        skipped += 1;
                    }
                }
            }
            verdict => {
                tracing::warn!(
                    "sync_push: action transition {} refused ({verdict:?})",
                    op.action_id
                );
                skipped += 1;
            }
        }
    }

    // FED-RQ-01 (#1936) — process incoming resolved commit-checkpoints.
    // FAIL-CLOSED authorization (a resolution is an authority-granting write,
    // like action_transitions): each resolution's Ed25519 attestation is
    // verified against the RESOLVER'S enrolled key (never the wire
    // `resolver_pubkey` — the #1718/#87 authority-lane discipline) via
    // `receive_auth::authorize_remote_checkpoint_resolution` BEFORE the
    // first-resolution-wins CRDT apply (`checkpoints::apply_inbound_resolution`).
    // The receiver NEVER re-signs; the sender's attestation is persisted
    // verbatim (v0.8.0 local-substrate rule). Per-item skip on
    // unverifiable/conflict — the batch survives. No storage quota is charged
    // (a resolution is a state change, not net-new authorship — #1544 scope).
    // Format spine votes: `4d3ea1c5` + #1947 decision `00d599ec`.
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
        // Only RESOLVED checkpoints federate — a pending checkpoint carries no
        // resolution attestation, so there is nothing to authorize or apply.
        if cp.state == crate::models::CheckpointState::Pending {
            skipped += 1;
            continue;
        }
        // Gate 1 / #2650 — format validation is not scope. Resolver-key crypto
        // answers "who resolved"; this choke answers "may this peer write a
        // freeze-anchor resolution touching this checkpoint".
        //
        // #2708 (CB-3, CWE-284, security-high) — the write subject is NOT the
        // attacker-chosen wire `cp.namespace` on the pending→resolved arm. The
        // `apply_inbound_resolution` CAS keys on `(id, state)` only: when a
        // local row exists it resolves THAT row and never writes its namespace,
        // so a peer scoped to `public/*` could otherwise present a `public/ok`
        // wire namespace and resolve a `secure/ops` freeze anchor by id (the
        // #2447 stored-vs-claimed split, applied to checkpoints). Mirror the
        // memories lane exactly (`inbound_write_namespace_authorized` with BOTH
        // the claimed AND the STORED namespace): resolve the local row's stored
        // namespace by id and refuse when EITHER is out of scope. This keeps
        // the two legitimate arms intact — a first-landing resolution (no local
        // row) creates under the claimed namespace (checked; stored is None),
        // while a resolution of a locally-pending anchor is confined to that
        // anchor's STORED namespace. The probe is elided when Layer 1 is not
        // armed for this peer (`ns_scope_needs_existing`), so zero-config
        // deployments pay ZERO extra reads. Postgres still skips apply entirely
        // (#2464/#1936) — confinement still runs so both backends refuse
        // out-of-scope rows the same way.
        let existing_cp_ns = if ns_scope_needs_existing {
            match crate::checkpoints::namespace_by_id(&lock.0, &cp.id) {
                Ok(ns) => ns,
                Err(e) => {
                    // Fail CLOSED: an unresolvable existence probe cannot be
                    // reported as "provably no local row" — that is exactly the
                    // input the stored-vs-claimed relocate bypass needs.
                    tracing::warn!(
                        target: ATTESTATION_TRACE_TARGET,
                        checkpoint_id = %cp.id,
                        "sync_push: checkpoint namespace-scope pre-resolve failed for {}: {e}; \
                         refusing the resolution (#2708 fail-closed)",
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
            // #3164 — `Accept(key)` is the authenticated verdict (the key that
            // verified the resolution); `AcceptUnverified` is the permissive
            // `require_checkpoint_sig = false` rollout window. Both apply the
            // resolution, which is byte-identical to the pre-split behaviour of
            // the single `Accept` arm — the split exists so no caller can
            // mistake the permissive outcome for an authenticated one.
            crate::federation::receive_auth::CheckpointResolutionAuthz::Accept(_)
            | crate::federation::receive_auth::CheckpointResolutionAuthz::AcceptUnverified => {
                if body.dry_run {
                    noop += 1;
                    continue;
                }
                match crate::checkpoints::apply_inbound_resolution(&lock.0, cp) {
                    Ok(crate::checkpoints::InboundResolutionOutcome::Applied) => {
                        checkpoints_applied += 1;
                    }
                    Ok(crate::checkpoints::InboundResolutionOutcome::Noop) => noop += 1,
                    Ok(crate::checkpoints::InboundResolutionOutcome::Conflict) => {
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            checkpoint_id = %cp.id,
                            "sync_push: inbound checkpoint resolution conflicts with a different \
                             local resolution — first-resolution-wins, keeping local (#1936)"
                        );
                        checkpoints_conflicted += 1;
                        skipped += 1;
                    }
                    Ok(crate::checkpoints::InboundResolutionOutcome::RefusedReservedKind) => {
                        // PR-1 / L5 (#2708-sibling, CWE-284): the CLAIMED wire or
                        // STORED by-id checkpoint names a substrate-RESERVED
                        // anchor (audit-head witness, governance verdict/
                        // enforcement, peer-head entanglement,
                        // re-anchor). A wire-reachable `/sync/push` MUST NOT steer
                        // the substrate's own audit-signal spine — per-item skip,
                        // the batch survives.
                        tracing::warn!(
                            target: ATTESTATION_TRACE_TARGET,
                            checkpoint_id = %cp.id,
                            condition_type = %cp.condition_type.as_str(),
                            namespace = %cp.namespace,
                            "sync_push: refusing inbound resolution of a substrate-reserved \
                             checkpoint anchor (L5 audit-signal poisoning, #2708-sibling); \
                             skipping this entry, batch survives"
                        );
                        skipped += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "sync_push: checkpoint resolution apply failed for {}: {e}",
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
                    "sync_push: inbound checkpoint resolution refused ({verdict:?}) (#1936)"
                );
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S35): process incoming namespace_meta rows. Applies via
    // `set_namespace_standard` so the peer's inheritance-chain walk has
    // the originator's explicit parent link. The standard memory itself
    // rides on the same push via `memories` (or arrived earlier through
    // `broadcast_store_quorum`); the namespace-meta row closes the gap.
    let mut namespace_meta_applied = 0usize;
    // #2479 (CWE-284) — sender-visible refusal count for BOTH governance-standard
    // lanes. It is deliberately NOT folded into `skipped`: this funnel enqueues
    // nothing to the push DLQ (#2498), so a refused entry is LOST rather than
    // retried, and `skipped` already aggregates malformed ids, absent standard
    // memories and quota refusals — the sender, the only party that can retry,
    // could not attribute it. A governance-replication stop is invisible in a
    // way a memory-replication stop is not: both nodes keep answering
    // `get_standard` confidently with divergent policy.
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
        // #2479 (CWE-284) — confine the governance-STANDARD bind to the peer's
        // namespace scope. `set_namespace_standard` writes the explicit parent
        // that `build_namespace_chain` walks, and that chain is what
        // `resolve_governance_policy` consumes, so an ungated row re-writes the
        // rules every subsequent LOCAL write to that namespace is judged
        // against. Gates the UNION of the row's own namespace and the parent it
        // splices above it; see `inbound_namespace_meta_authorized` for the
        // reach this does NOT close (descendants by inheritance; the namespace
        // the `standard_id` memory itself lives in).
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
            // so warning about it would be false.
            warn_on_severed_out_of_scope_parent(
                &lock.0,
                crate::federation::receive_auth::LANE_NAMESPACE_META,
                &entry.namespace,
                entry.parent_namespace.as_deref(),
                &attest_cfg,
                peer_header_owned.as_deref(),
            );
        }
        match db::set_namespace_standard(
            &lock.0,
            &entry.namespace,
            &entry.standard_id,
            entry.parent_namespace.as_deref(),
        ) {
            Ok(()) => namespace_meta_applied += 1,
            Err(e) => {
                tracing::warn!(
                    "sync_push: set_namespace_standard failed for {}: {e}",
                    entry.namespace
                );
                skipped += 1;
            }
        }
    }

    // v0.6.2 (S35 follow-up): process incoming namespace_meta_clears. Applies
    // via `db::clear_namespace_standard` so the peer drops its meta row and
    // subsequent `get_standard` returns empty. Missing-on-peer namespaces
    // no-op (`changed == 0`) — replays are safe.
    let mut namespace_meta_cleared = 0usize;
    for ns in &body.namespace_meta_clears {
        if validate::validate_namespace(ns).is_err() {
            skipped += 1;
            continue;
        }
        if body.dry_run {
            noop += 1;
            continue;
        }
        // #2479 (CWE-284) — the DESTRUCTIVE twin. `clear_namespace_standard` is
        // a bare `DELETE FROM namespace_meta WHERE namespace = ?` with no
        // existence precondition and no tombstone: it removes the standard AND
        // the parent link in one statement, and because governance is
        // allow-on-silence an absent policy resolves PERMISSIVE — so this lane
        // DISARMS a namespace (and, by inheritance, its descendants) rather than
        // merely rewriting it. There is no `standard_id` on this lane, hence no
        // parent to gate: the namespace is the whole subject.
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
            // AFTER the verdict — see the sibling loop above.
            warn_on_severed_out_of_scope_parent(
                &lock.0,
                crate::federation::receive_auth::LANE_NAMESPACE_META_CLEARS,
                ns,
                None,
                &attest_cfg,
                peer_header_owned.as_deref(),
            );
        }
        match db::clear_namespace_standard(&lock.0, ns) {
            Ok(true) => namespace_meta_cleared += 1,
            Ok(false) => noop += 1,
            Err(e) => {
                tracing::warn!("sync_push: clear_namespace_standard failed for {ns}: {e}");
                skipped += 1;
            }
        }
    }

    // Advance the vector clock with the highest `updated_at` we observed.
    // Skipped in dry-run mode since the caller is only previewing.
    if !body.dry_run
        && let Some(at) = latest_seen.as_deref()
        && let Err(e) = db::sync_state_observe(&lock.0, &local_agent_id, &body.sender_agent_id, at)
    {
        tracing::warn!("sync_push: sync_state_observe failed: {e}");
    }

    // v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — CRDT-lite merge: fold
    // the sender's vector clock into the receiver's persisted sync-state
    // (pointwise max), monotonic (an older incoming timestamp never
    // regresses a newer stored entry). Skipped in dry-run.
    //
    // v1.0.0 #2718 / CB-14 (relates #2670) — this fold is now PER-KEY
    // AUTHORIZED. Pre-fix it called the un-gated `db::sync_state_merge`,
    // which folded EVERY entry in `body.sender_clock`, so a hostile /
    // buggy peer A could inject an arbitrarily-high timestamp for peer
    // B's key and permanently PIN B's cursor (every later pull from B
    // then returns zero rows). A peer is only authorized to advance its
    // OWN clock entry, so the fold now accepts ONLY the entry keyed by
    // `body.sender_agent_id` — the sender can move its own clock forward
    // and NOTHING ELSE. Peer A's push can never touch peer B's entry.
    if !body.dry_run
        && let Err(e) = db::sync_state_merge_authorized(
            &lock.0,
            &local_agent_id,
            &body.sender_agent_id,
            &body.sender_clock,
        )
    {
        tracing::warn!("sync_push: sync_state_merge failed: {e}");
    }

    // #1566 / #1579 B1 — the pre-#1566 synchronous embed loop lived
    // here (one `emb.embed()` per applied row, ~1s/row via ollama,
    // WHILE HOLDING the DB lock and inside the sender's quorum-ack
    // window). It is gone: dim-matching shipped vectors were stored
    // inline above (cheap UPDATE under the already-held lock), and
    // every other applied row is handed to the detached background
    // task spawned after the response is decided below.

    // Receiver's current clock, returned so the sender can learn which
    // peers the receiver has seen. Phase 3 Task 3a.1 will use this to
    // short-circuit redundant pushes.
    let receiver_clock = db::sync_state_load(&lock.0, &local_agent_id)
        .unwrap_or_else(|_| crate::models::VectorClock::default());

    // Release DB lock before touching the HNSW index — the vector index
    // has its own mutex and holding both serializes unrelated writers.
    drop(lock);
    if !hnsw_updates.is_empty() {
        let mut idx_lock = app.vector_index.lock().await;
        if let Some(idx) = idx_lock.as_mut() {
            // #2167 §3.3 layer 2 — explicit insert-time space gate: index a
            // federated vector ONLY when its claimed space equals the active
            // space. Skip only when the active space is KNOWN and differs (a
            // foreign row stays stored + keyword-recallable, never scored); an
            // unseeded active space trusts the upstream #2168 receive gate, so
            // this never regresses indexing.
            let active_space = crate::embeddings::active_embedding_space();
            for (id, vec, claimed) in hnsw_updates {
                if active_space
                    .as_deref()
                    .is_some_and(|a| a != claimed.as_str())
                {
                    continue;
                }
                idx.remove(&id);
                idx.insert(id, vec);
            }
        }
    }

    // #1566 / #1579 B1 — ack-after-commit: hand the rows that still
    // need a locally-computed vector to the detached background task.
    // The HTTP response (the sender's quorum ack) returns immediately.
    spawn_deferred_embedding_refresh(&app, deferred_embed);

    (
        StatusCode::OK,
        Json(json!({
            "applied": applied,
            "deleted": deleted,
            "archived": archived,
            "restored": restored,
            "links_applied": links_applied,
            "pendings_applied": pendings_applied,
            "pending_decisions_applied": pending_decisions_applied,
            "signals_applied": signals_applied,
            "action_transitions_applied": action_transitions_applied,
            "checkpoints_applied": checkpoints_applied,
            "checkpoints_conflicted": checkpoints_conflicted,
            "namespace_meta_applied": namespace_meta_applied,
            "namespace_meta_cleared": namespace_meta_cleared,
            // #2479 — additive; see the declaration for why this is not folded
            // into `skipped`.
            "namespace_meta_refused": namespace_meta_refused,
            "noop": noop,
            (crate::handlers::SKIPPED_FIELD): skipped,
            (crate::handlers::QUOTA_REFUSED_FIELD): quota_refused,
            "dry_run": body.dry_run,
            "receiver_agent_id": local_agent_id,
            "receiver_clock": receiver_clock,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // ---- #1464 per-write CONTENT attestation (apply_inbound_write_attestation) ----

    use crate::identity::{attest, keypair};
    use base64::Engine as _;

    /// A relayed memory authored by `author`, with the identity-bearing
    /// `SignableWrite` fields populated so a real per-write signature can be
    /// minted + verified.
    fn wsig_mem(author: &str) -> Memory {
        Memory {
            id: "m-1464-wsig".to_string(),
            namespace: "team/alpha".to_string(),
            title: "kubernetes deployment guide".to_string(),
            content: "scale the deployment to three replicas".to_string(),
            created_at: "2026-06-01T12:00:00+00:00".to_string(),
            metadata: serde_json::json!({ "agent_id": author }),
            ..Memory::default()
        }
    }

    fn pk_b64(kp: &keypair::AgentKeypair) -> String {
        base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes())
    }

    fn put_write_sig(mem: &mut Memory, sig: &[u8]) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        mem.metadata.as_object_mut().unwrap().insert(
            crate::models::field_names::WRITE_SIGNATURE.to_string(),
            serde_json::json!(b64),
        );
    }

    /// A valid presented per-write signature, verified against the author's
    /// enrolled key, upgrades a HONORED third-party relayed claim from
    /// `claimed` to `agent_attested`. (The signature is inserted into
    /// `metadata` AFTER signing — proving `SignableWrite`'s exclusion of
    /// `metadata` keeps the signature stable as the key is added.)
    #[test]
    fn write_attestation_valid_sig_upgrades_to_agent_attested_1464() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        put_write_sig(&mut mem, &sig);
        apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay",
            Some(author),
            Some(&pk_b64(&kp)),
            false,
        )
        .expect("valid sig must verify");
        assert_eq!(mem.metadata["attest_level"], "agent_attested");
    }

    /// A forged/tampered presented signature is rejected unconditionally
    /// (even under the permissive default).
    #[test]
    fn write_attestation_forged_sig_rejected_1464() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        let mut sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        sig[0] ^= 0xFF; // flip a byte
        put_write_sig(&mut mem, &sig);
        let err = apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay",
            Some(author),
            Some(&pk_b64(&kp)),
            false,
        );
        assert!(err.is_err(), "forged signature must be rejected");
    }

    /// An unsigned relayed write keeps `attest_level=claimed` under the
    /// permissive default — and a peer-asserted `agent_attested` in the
    /// inbound metadata is overridden to `claimed` (a peer cannot self-assert
    /// attestation).
    #[test]
    fn write_attestation_unsigned_stays_claimed_permissive_1464() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        // Peer lies: claims agent_attested with no signature.
        mem.metadata.as_object_mut().unwrap().insert(
            "attest_level".to_string(),
            serde_json::json!("agent_attested"),
        );
        apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay",
            Some(author),
            Some(&pk_b64(&kp)),
            false,
        )
        .expect("unsigned permissive must pass");
        assert_eq!(mem.metadata["attest_level"], "claimed");
    }

    // ---- #2715 (CB-11 / B-4) per-write attestation on the federation PULL
    //      paths (serve catch-up puller + sync-daemon), via
    //      `attest_inbound_pull_memory` — the read-direction sibling gate ----

    /// Serialize the `AI_MEMORY_KEY_DIR` mutation these tests need (the pull
    /// gate resolves the author key from the on-disk enrolled key store) with
    /// every other key-dir test in the process.
    struct KeyDirEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
    }
    impl KeyDirEnvGuard {
        fn set(dir: &std::path::Path) -> Self {
            let lock = keypair::key_dir_env_lock()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = std::env::var_os(keypair::KEY_DIR_ENV);
            // SAFETY: single-threaded test mutation, serialized by the lock held
            // for this guard's lifetime.
            unsafe { std::env::set_var(keypair::KEY_DIR_ENV, dir) };
            Self { _lock: lock, prev }
        }
    }
    impl Drop for KeyDirEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prev.take() {
                    Some(v) => std::env::set_var(keypair::KEY_DIR_ENV, v),
                    None => std::env::remove_var(keypair::KEY_DIR_ENV),
                }
            }
        }
    }

    /// A VALID presented `write_signature`, verified against the author's
    /// locally-enrolled key, upgrades a pulled row to `agent_attested` and is
    /// applied. (The key source is the on-disk store, resolved by the gate
    /// itself — not passed in, unlike the push-side tests above.)
    #[test]
    fn pull_attestation_valid_sig_upgrades_and_applies_2715() {
        let dir = tempfile::tempdir().expect("key dir");
        let author = "alice";
        let kp = keypair::generate(author).expect("gen");
        keypair::save(&kp, dir.path()).expect("enroll alice");
        let _g = KeyDirEnvGuard::set(dir.path());

        let mut mem = wsig_mem(author);
        let sig = attest::sign_memory_write(&kp, &mem, author).expect("sign");
        put_write_sig(&mut mem, &sig);

        assert!(
            attest_inbound_pull_memory(&mut mem),
            "a validly-signed pulled row must be applied"
        );
        assert_eq!(
            mem.metadata["attest_level"], "agent_attested",
            "a verified write_signature upgrades the pulled row to agent_attested"
        );
    }

    /// THE SECURITY CORE: a FORGED presented signature (present but not
    /// verifiable against the author's enrolled key) is REFUSED on the pull
    /// path — the forgery a peer could previously smuggle through the catch-up
    /// door that `/sync/push` would have rejected (#2715 B-4). No `.is_ok()`
    /// masking — the gate returns `false` on the explicit `Err`.
    #[test]
    fn pull_attestation_forged_sig_refused_2715() {
        let dir = tempfile::tempdir().expect("key dir");
        let author = "alice";
        let kp = keypair::generate(author).expect("gen");
        keypair::save(&kp, dir.path()).expect("enroll alice");
        let _g = KeyDirEnvGuard::set(dir.path());

        let mut mem = wsig_mem(author);
        let mut sig = attest::sign_memory_write(&kp, &mem, author).expect("sign");
        sig[0] ^= 0xFF; // forge
        put_write_sig(&mut mem, &sig);

        assert!(
            !attest_inbound_pull_memory(&mut mem),
            "a forged write_signature on the pull path must be REFUSED (skip the row)"
        );
    }

    /// An UNSIGNED pulled row is accept-and-FLAGGED: it lands `claimed`
    /// (DEGRADE, never corrupt — the pull direction has no attested relayer to
    /// hold accountable), and is applied. A peer-asserted `agent_attested` is
    /// overridden to `claimed` (a peer cannot self-assert attestation).
    #[test]
    fn pull_attestation_unsigned_lands_claimed_2715() {
        let dir = tempfile::tempdir().expect("key dir");
        let author = "alice";
        let kp = keypair::generate(author).expect("gen");
        keypair::save(&kp, dir.path()).expect("enroll alice");
        let _g = KeyDirEnvGuard::set(dir.path());

        let mut mem = wsig_mem(author);
        // Peer lies: claims agent_attested with no signature.
        mem.metadata.as_object_mut().unwrap().insert(
            "attest_level".to_string(),
            serde_json::json!("agent_attested"),
        );

        assert!(
            attest_inbound_pull_memory(&mut mem),
            "an unsigned pulled row is accepted (flagged claimed), never dropped"
        );
        assert_eq!(
            mem.metadata["attest_level"], "claimed",
            "unsigned pulled row must be flagged claimed, overriding the peer's self-assertion"
        );
    }

    /// A pulled row with NO claimed author (`metadata.agent_id` absent) has no
    /// owner claim to attest against — applied unchanged (no env / key needed).
    #[test]
    fn pull_attestation_no_author_applies_unchanged_2715() {
        let mut mem = Memory {
            id: "m-2715-no-author".to_string(),
            namespace: "team/alpha".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            created_at: "2026-06-01T12:00:00+00:00".to_string(),
            metadata: serde_json::json!({}),
            ..Memory::default()
        };
        assert!(
            attest_inbound_pull_memory(&mut mem),
            "an author-less pulled row carries no claim to verify; applied unchanged"
        );
    }

    /// Strict mode (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`) refuses an unsigned
    /// HONORED third-party relayed claim.
    #[test]
    fn write_attestation_strict_third_party_unsigned_rejected_1464() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        let err = apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay", // attribute(author) != sender → third-party
            Some(author),
            Some(&pk_b64(&kp)),
            true, // strict
        );
        assert!(err.is_err(), "strict third-party unsigned must be rejected");
    }

    /// Strict mode never bricks a SELF-authored relay (attribute == sender):
    /// the requirement is third-party-only, so an unsigned self relay still
    /// lands `claimed`.
    #[test]
    fn write_attestation_strict_self_authored_unsigned_passes_1464() {
        let mut mem = wsig_mem("ai:relay");
        apply_inbound_write_attestation(
            &mut mem,
            "ai:relay",
            "ai:relay", // attribute == sender → self-authored
            Some("ai:relay"),
            None,
            true, // strict, but does not apply to self
        )
        .expect("strict self-authored unsigned must still pass");
        assert_eq!(mem.metadata["attest_level"], "claimed");
    }

    /// A RE-ATTRIBUTED row (original third-party claim downgraded to the
    /// sender by `resolve_inbound_attribution`) is skipped: a signature
    /// minted by the original claimant must NOT be checked against the
    /// re-attributed sender (it would spuriously read as forged). The row
    /// keeps its already-stamped `claimed`.
    #[test]
    fn write_attestation_reattributed_row_skipped_1464() {
        // Post-attribution state: an unauthorized "bob" claim was rewritten
        // to sender "ai:relay" + stamped claimed.
        let mut mem = wsig_mem("bob");
        {
            let obj = mem.metadata.as_object_mut().unwrap();
            obj.insert("agent_id".to_string(), serde_json::json!("ai:relay"));
            obj.insert("attest_level".to_string(), serde_json::json!("claimed"));
        }
        // A signature bob minted (would be forged against ai:relay).
        let kp_bob = keypair::generate("bob").unwrap();
        let sig = attest::sign_memory_write(&kp_bob, &mem, "bob").unwrap();
        put_write_sig(&mut mem, &sig);
        // original_claim "bob" != attribute "ai:relay" → re-attributed → skip.
        apply_inbound_write_attestation(&mut mem, "ai:relay", "ai:relay", Some("bob"), None, true)
            .expect("re-attributed row must be skipped, not rejected");
        assert_eq!(mem.metadata["attest_level"], "claimed");
    }

    // ── #1801→#1954 sender-EMIT regression tests (item 8) ────────────────────

    /// (a) The store-time EMIT helper [`attest::persist_write_signature`]
    /// produces a `metadata.write_signature` that BYTE-ALIGNS with the
    /// receiver: a honored third-party relayed write carrying the propagated
    /// origin signature + an enrolled author key upgrades to `agent_attested`
    /// under the strict flip (`require = true`).
    #[test]
    fn emit_signature_verifies_at_receiver_agent_attested_1801() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        // Author node: sign then EMIT (the real store-path helper, not the
        // test's put_write_sig) so this test pins the EMIT encoding itself.
        let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        attest::persist_write_signature(&mut mem, &sig);
        // Relayed as a third-party (attribute author != sender relay), strict.
        apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay",
            Some(author),
            Some(&pk_b64(&kp)),
            true,
        )
        .expect("propagated origin signature must attest under the strict flip");
        assert_eq!(mem.metadata["attest_level"], "agent_attested");
    }

    /// (e, part 1) EMIT is NON-CLOBBERING: an intermediate relay MUST NOT
    /// overwrite a propagated third-party origin signature with its own key
    /// (item 3). A second `persist_write_signature` with different bytes is a
    /// no-op while the field is present.
    #[test]
    fn emit_never_overwrites_propagated_origin_signature_1801() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        let origin_sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        attest::persist_write_signature(&mut mem, &origin_sig);
        let origin_b64 = mem.metadata[crate::models::field_names::WRITE_SIGNATURE]
            .as_str()
            .unwrap()
            .to_string();
        // A relay tries to (re)emit with a different signature — must be a no-op.
        let relay_kp = keypair::generate("ai:relay").unwrap();
        let relay_sig = attest::sign_memory_write(&relay_kp, &mem, "ai:relay").unwrap();
        attest::persist_write_signature(&mut mem, &relay_sig);
        assert_eq!(
            mem.metadata[crate::models::field_names::WRITE_SIGNATURE]
                .as_str()
                .unwrap(),
            origin_b64,
            "the propagated origin signature must be preserved verbatim"
        );
    }

    /// (e, part 2) Two-hop A→B→C: an origin-stamped signature survives the
    /// intermediate relay B (verbatim metadata forwarding + non-clobber) and
    /// verifies at hop-2 (C) against the origin author's enrolled key.
    #[test]
    fn two_hop_origin_signature_verifies_at_hop2_1801() {
        let author = "ai:alpha";
        let kp = keypair::generate(author).unwrap();
        // Hop A (author): store + EMIT.
        let mut mem = wsig_mem(author);
        let sig = attest::sign_memory_write(&kp, &mem, author).unwrap();
        attest::persist_write_signature(&mut mem, &sig);
        // Hop B (relay "ai:beta"): forwards verbatim. B is NOT the author, so
        // it never re-emits; even a stray emit is a non-clobbering no-op.
        attest::persist_write_signature(&mut mem, b"not-a-real-signature-bytes-ignored");
        // Hop C (final receiver): verify against the ORIGIN author's key.
        apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:beta",
            Some(author),
            Some(&pk_b64(&kp)),
            true,
        )
        .expect("origin signature must verify at hop-2 after relay through B");
        assert_eq!(mem.metadata["attest_level"], "agent_attested");
    }

    /// (d) Explicit opt-out: with the requirement resolved permissive
    /// (`AI_MEMORY_FED_REQUIRE_WRITE_SIG=0` → `require = false`), a honored
    /// third-party UNSIGNED relay is byte-identical to the pre-flip posture —
    /// accepted and stamped `claimed`, never refused. (The env→bool resolution
    /// itself is pinned in `receive_auth::tests`.)
    #[test]
    fn opt_out_permissive_third_party_unsigned_stays_claimed_1801() {
        let author = "ai:curator";
        let kp = keypair::generate(author).unwrap();
        let mut mem = wsig_mem(author);
        apply_inbound_write_attestation(
            &mut mem,
            author,
            "ai:relay", // third-party (attribute author != sender)
            Some(author),
            Some(&pk_b64(&kp)),
            false, // == AI_MEMORY_FED_REQUIRE_WRITE_SIG=0
        )
        .expect("permissive opt-out must accept an unsigned third-party relay");
        assert_eq!(mem.metadata["attest_level"], "claimed");
    }

    /// #1464 (v0.8.0, P0, security-high) — the per-memory authorship gate
    /// `resolve_inbound_attribution` must close the forge hole: an enrolled
    /// peer cannot have an unauthorized claimed `metadata.agent_id` trusted
    /// for quota OR ownership. Pins all five arms.
    #[test]
    fn resolve_inbound_attribution_gates_per_memory_claims_1464() {
        use crate::federation::peer_attestation::PeerScope;
        use std::collections::HashMap;

        fn claiming(agent: &str) -> Memory {
            Memory {
                id: "m-1464".to_string(),
                metadata: serde_json::json!({ "agent_id": agent }),
                ..Memory::default()
            }
        }

        // Enrolled config: peer "ai:relay" is authorized to author as "bob".
        let mut peers = HashMap::new();
        peers.insert(
            "ai:relay".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec!["bob".to_string()],
                ..PeerScope::default()
            },
        );
        let cfg = PeerAttestationConfig::from_peers(peers);
        let zero = PeerAttestationConfig::default();

        // (1) Zero-config faith posture (no allowlist): the claim is trusted
        // verbatim and NOT rewritten (preserve #1056/#238 behaviour).
        let mut m = claiming("alice");
        assert_eq!(
            resolve_inbound_attribution(&mut m, "ai:relay", &zero, Some("ai:relay"), false),
            "alice"
        );
        assert_eq!(m.metadata["agent_id"], "alice");

        // (2) Enrolled, peer NOT authorized to author as "alice" → attribute
        // to the sender AND rewrite ownership; stamp the bare-claim level.
        let mut m2 = claiming("alice");
        assert_eq!(
            resolve_inbound_attribution(&mut m2, "ai:relay", &cfg, Some("ai:relay"), false),
            "ai:relay"
        );
        assert_eq!(
            m2.metadata["agent_id"], "ai:relay",
            "ownership re-attributed"
        );
        assert_eq!(m2.metadata["attest_level"], "claimed");

        // (3) Enrolled, peer authorized to author as "bob" → trusted, preserved.
        let mut m3 = claiming("bob");
        assert_eq!(
            resolve_inbound_attribution(&mut m3, "ai:relay", &cfg, Some("ai:relay"), false),
            "bob"
        );
        assert_eq!(m3.metadata["agent_id"], "bob");

        // (4) Self-authored (claim == sender, the #238-attested body author)
        // → trusted regardless of the allowlist.
        let mut m4 = claiming("ai:relay");
        assert_eq!(
            resolve_inbound_attribution(&mut m4, "ai:relay", &cfg, Some("ai:relay"), false),
            "ai:relay"
        );

        // (5) No claim at all → attribute to the sender.
        let mut m5 = Memory {
            id: "m-none".to_string(),
            metadata: serde_json::json!({}),
            ..Memory::default()
        };
        assert_eq!(
            resolve_inbound_attribution(&mut m5, "ai:relay", &cfg, Some("ai:relay"), false),
            "ai:relay"
        );
    }

    /// #2863 — fed-consolidate-source-attest-parity (fix #1: attribution).
    /// Drives the receive loop's attribution + apply sequence for a re-broadcast
    /// tombstoned SOURCE relayed under the daemon federation identity (sender !=
    /// the source's author). A third-party claim carrying a write_signature that
    /// VERIFIES against the CLAIMED author's ENROLLED key is HONORED (lands
    /// `agent_attested`); an unsigned / forged / unenrolled-author claim still
    /// re-attributes to the sender and lands `claimed`.
    #[test]
    fn rebroadcast_source_honors_crypto_attested_claim_2863() {
        use crate::federation::peer_attestation::PeerScope;
        use std::collections::HashMap;

        // Mirror of the receive-loop sequence (redact omitted — no secret in the
        // fixture): compute the crypto-attest signal, resolve attribution,
        // resolve the bound key exactly as the caller does, stamp.
        fn drive(
            mem: &mut Memory,
            sender: &str,
            cfg: &PeerAttestationConfig,
            peer: Option<&str>,
            claimed_key: Option<&str>,
            require: bool,
        ) -> String {
            let original_claim = mem
                .metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let claim_write_attested = original_claim
                .as_deref()
                .is_some_and(|c| inbound_claim_is_write_attested(mem, c, claimed_key));
            let attribute =
                resolve_inbound_attribution(mem, sender, cfg, peer, claim_write_attested);
            // Caller key-reuse: when the claim was honored (attribute == claim),
            // the bound key is the claimed author's; otherwise the re-attributed
            // sender's key (unenrolled in this fixture → None).
            let bound = if Some(attribute.as_str()) == original_claim.as_deref() {
                claimed_key
            } else {
                None
            };
            apply_inbound_write_attestation(
                mem,
                &attribute,
                sender,
                original_claim.as_deref(),
                bound,
                require,
            )
            .expect("apply must not reject (honored verifies; re-attributed skips)");
            attribute
        }

        let author = "ai:hive-author";
        let daemon = "ai:hive-memory-1"; // #2860 re-broadcast sender (fed identity)
        let kp = keypair::generate(author).unwrap();
        let author_pk = pk_b64(&kp);
        // Enrolled peer authorized ONLY as itself — hive-author is a third party.
        let mut peers = HashMap::new();
        peers.insert(daemon.to_string(), PeerScope::default());
        let cfg = PeerAttestationConfig::from_peers(peers);

        let signed = |author_id: &str| -> Memory {
            let mut m = wsig_mem(author_id);
            let sig = attest::sign_memory_write(&kp, &m, author_id).unwrap();
            put_write_sig(&mut m, &sig);
            m
        };

        // (a) Self-relay signed (sender == author) → agent_attested [control].
        let mut a = signed(author);
        assert_eq!(
            drive(&mut a, author, &cfg, Some(author), Some(&author_pk), true),
            author
        );
        assert_eq!(a.metadata["attest_level"], "agent_attested");

        // (b) THE FIX: third-party signed, enrolled peer NOT authorized as
        // hive-author, author key enrolled → HONORED → agent_attested. (Pre-fix
        // this re-attributed to `daemon` and landed `claimed`.)
        let mut b = signed(author);
        assert_eq!(
            drive(&mut b, daemon, &cfg, Some(daemon), Some(&author_pk), true),
            author,
            "#2863: a crypto-attested third-party claim must be honored, not re-attributed"
        );
        assert_eq!(b.metadata["attest_level"], "agent_attested");
        assert_eq!(
            b.metadata["agent_id"], author,
            "authorship preserved as the true author"
        );

        // (c) Third-party UNSIGNED → re-attributed → claimed.
        let mut c = wsig_mem(author);
        assert_eq!(
            drive(&mut c, daemon, &cfg, Some(daemon), Some(&author_pk), false),
            daemon
        );
        assert_eq!(c.metadata["attest_level"], "claimed");

        // (d) Third-party FORGED sig (present but invalid) → NOT honored (verify,
        // not presence) → re-attributed → claimed.
        let mut d = wsig_mem(author);
        let mut sig = attest::sign_memory_write(&kp, &d, author).unwrap();
        sig[0] ^= 0xFF;
        put_write_sig(&mut d, &sig);
        assert_eq!(
            drive(&mut d, daemon, &cfg, Some(daemon), Some(&author_pk), false),
            daemon
        );
        assert_eq!(d.metadata["attest_level"], "claimed");

        // (e) Third-party signed but author key NOT enrolled (bound_key=None) →
        // cannot verify → not honored → re-attributed → claimed (fail-closed).
        let mut e = signed(author);
        assert_eq!(
            drive(&mut e, daemon, &cfg, Some(daemon), None, false),
            daemon
        );
        assert_eq!(e.metadata["attest_level"], "claimed");
    }

    /// #1920 ADVERSARIAL — a hostile-but-enrolled peer must not be able to
    /// inject a pending action attributed to an arbitrary `requested_by`
    /// (the first half of the forge-governance-approval exploit: inject
    /// pending P for `victim`, then approve it in the same request).
    /// `pending_author_authorized` is the gate now protecting the
    /// `pendings[]` upsert.
    #[test]
    fn pending_author_authorized_gates_forged_requester_1920() {
        use crate::federation::peer_attestation::PeerScope;
        use crate::models::PendingAction;
        use std::collections::HashMap;

        fn pending(requested_by: &str, payload_agent: Option<&str>) -> PendingAction {
            let payload = payload_agent.map_or_else(
                || serde_json::json!({}),
                |a| serde_json::json!({ "metadata": { "agent_id": a } }),
            );
            PendingAction {
                id: "P-1920".to_string(),
                action_type: "store".to_string(),
                memory_id: None,
                namespace: "secure/ops".to_string(),
                payload,
                requested_by: requested_by.to_string(),
                requested_at: "2026-07-01T00:00:00Z".to_string(),
                status: "pending".to_string(),
                decided_by: None,
                decided_at: None,
                approvals: vec![],
            }
        }

        // Enrolled: peer "ai:relay" may author only as "bob".
        let mut peers = HashMap::new();
        peers.insert(
            "ai:relay".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec!["bob".to_string()],
                ..PeerScope::default()
            },
        );
        let cfg = PeerAttestationConfig::from_peers(peers);
        let zero = PeerAttestationConfig::default();

        // EXPLOIT (blocked): forge a pending requested_by="victim".
        let forged = pending("victim", Some("victim"));
        assert!(
            !pending_author_authorized(&forged, "ai:relay", &cfg, Some("ai:relay")),
            "#1920: enrolled peer must NOT inject a pending attributed to an unauthorized agent"
        );

        // Payload smuggling (blocked): requested_by ok but payload author forged.
        let smuggled = pending("bob", Some("victim"));
        assert!(
            !pending_author_authorized(&smuggled, "ai:relay", &cfg, Some("ai:relay")),
            "#1920: a forged payload metadata.agent_id must also be gated"
        );

        // Legit: authorized third-party author ("bob") → accepted.
        let ok = pending("bob", Some("bob"));
        assert!(pending_author_authorized(
            &ok,
            "ai:relay",
            &cfg,
            Some("ai:relay")
        ));

        // Legit: self-relay (requested_by == sender) → accepted.
        let selfrelay = pending("ai:relay", None);
        assert!(pending_author_authorized(
            &selfrelay,
            "ai:relay",
            &cfg,
            Some("ai:relay")
        ));

        // Zero-config (unenrolled mesh): faith-based — accepted (back-compat).
        assert!(pending_author_authorized(
            &forged,
            "ai:relay",
            &zero,
            Some("ai:relay")
        ));
    }

    /// #2720 F-12 (CWE-346) ADVERSARIAL — a federated pending REJECT must not
    /// stamp the signed audit trail with an arbitrary wire-supplied decider.
    /// [`resolve_inbound_decider`] binds the recorded actor to the attested peer
    /// (mirroring `resolve_inbound_attribution`): an unauthorized third-party
    /// claim is rebound to the sender, an authorized one is kept, self-relay is
    /// kept, and zero-config stays faith-based.
    #[test]
    fn resolve_inbound_decider_rebinds_forged_decider_2720() {
        use crate::federation::peer_attestation::PeerScope;
        use std::collections::HashMap;

        // Enrolled: peer "ai:relay" may decide only as "bob".
        let mut peers = HashMap::new();
        peers.insert(
            "ai:relay".to_string(),
            PeerScope {
                allowed_sender_agent_ids: vec!["bob".to_string()],
                ..PeerScope::default()
            },
        );
        let cfg = PeerAttestationConfig::from_peers(peers);
        let zero = PeerAttestationConfig::default();

        // EXPLOIT (rebound): forge a reject decided_by a real operator id.
        assert_eq!(
            resolve_inbound_decider("ai:victim-operator", "ai:relay", &cfg, Some("ai:relay")),
            "ai:relay",
            "#2720 F-12: an unauthorized decider must be rebound to the attested sender"
        );

        // Legit: an authorized third-party decider ("bob") is preserved.
        assert_eq!(
            resolve_inbound_decider("bob", "ai:relay", &cfg, Some("ai:relay")),
            "bob",
            "#2720 F-12: an operator-authorized relayed decider is kept"
        );

        // Legit: self-relay (decider == sender) is preserved.
        assert_eq!(
            resolve_inbound_decider("ai:relay", "ai:relay", &cfg, Some("ai:relay")),
            "ai:relay",
            "#2720 F-12: the attested sender may decide as itself"
        );

        // Zero-config (unenrolled mesh): faith-based — the claim is kept.
        assert_eq!(
            resolve_inbound_decider("ai:victim-operator", "ai:relay", &zero, Some("ai:relay")),
            "ai:victim-operator",
            "#2720 F-12: zero-config preserves the faith-based (byte-identical) posture"
        );
    }

    /// v0.7.0 #1049 (Agent-5 #9) — `extract_peer_id` validates the
    /// header value through `crate::validate::validate_agent_id`
    /// before returning. The validator rejects whitespace, null
    /// bytes, control characters (CR/LF), shell metacharacters,
    /// and anything over 128 bytes. This unit suite pins both the
    /// happy path (legitimate agent-id-shaped values pass) and
    /// representative rejection arms.
    fn build_headers(value: &str) -> Option<HeaderMap> {
        // HeaderMap rejects some invalid bytes at insertion time
        // (e.g. ASCII control chars). Use HeaderValue::from_bytes
        // and ignore failures so the test can probe the validator
        // path; if HeaderValue refuses the byte sequence too, the
        // header is unreachable from the wire so we skip that case.
        let hv = HeaderValue::from_bytes(value.as_bytes()).ok()?;
        let mut h = HeaderMap::new();
        h.insert(PEER_ID_HEADER, hv);
        Some(h)
    }

    #[test]
    fn extract_peer_id_accepts_legitimate_agent_id_1049() {
        let h = build_headers("ai:peer-alpha").expect("legitimate value fits in HeaderValue");
        assert_eq!(extract_peer_id(&h), Some("ai:peer-alpha"));
    }

    #[test]
    fn extract_peer_id_accepts_hostname_form_1049() {
        let h = build_headers("host:laptop.local:pid-42").expect("legitimate value fits");
        assert_eq!(extract_peer_id(&h), Some("host:laptop.local:pid-42"));
    }

    #[test]
    fn extract_peer_id_rejects_value_with_whitespace_1049() {
        let h = build_headers("peer one").expect("space fits in HeaderValue");
        assert_eq!(
            extract_peer_id(&h),
            None,
            "#1049: whitespace in peer-id MUST be rejected by the validator"
        );
    }

    #[test]
    fn extract_peer_id_rejects_value_with_shell_metacharacters_1049() {
        let h = build_headers("peer$attacker").expect("$ fits in HeaderValue");
        assert_eq!(
            extract_peer_id(&h),
            None,
            "#1049: shell metacharacters in peer-id MUST be rejected"
        );
    }

    #[test]
    fn extract_peer_id_rejects_oversized_value_1049() {
        // 129-byte string exceeds the validator's 1..=128 length cap.
        let oversized = "a".repeat(129);
        let h = build_headers(&oversized).expect("129-byte ASCII fits in HeaderValue");
        assert_eq!(
            extract_peer_id(&h),
            None,
            "#1049: oversized peer-id (>128 bytes) MUST be rejected"
        );
    }

    #[test]
    fn extract_peer_id_absent_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(extract_peer_id(&h), None);
    }

    // -- #1948 route-IN quarantine helper -------------------------------

    /// #2966 — serializes the two tests that observe the process-global
    /// `ai_memory_fed_quarantined_unattributed_total` counter so their exact
    /// delta assertions cannot race each other's increments (the only two
    /// callers of `maybe_quarantine_unattributed` in the lib test binary).
    static QUARANTINE_METRIC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn route_in_quarantines_only_unattributed_and_only_when_enabled() {
        use crate::models::LifecycleState;
        let _guard = QUARANTINE_METRIC_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Knob OFF (permissive): a claimed (unattributed) row stays Open.
        let mut claimed = wsig_mem("ai:curator");
        claimed
            .metadata
            .as_object_mut()
            .unwrap()
            .insert("attest_level".to_string(), serde_json::json!("claimed"));
        maybe_quarantine_unattributed(&mut claimed, false);
        assert_eq!(claimed.lifecycle_state, LifecycleState::Open);

        // Knob ON + claimed → quarantined.
        maybe_quarantine_unattributed(&mut claimed, true);
        assert_eq!(claimed.lifecycle_state, LifecycleState::Quarantined);
        assert!(!row_is_agent_attested(&claimed));

        // Knob ON but agent_attested → NOT quarantined (provenance present).
        let mut attested = wsig_mem("ai:curator");
        attested.metadata.as_object_mut().unwrap().insert(
            "attest_level".to_string(),
            serde_json::json!("agent_attested"),
        );
        assert!(row_is_agent_attested(&attested));
        maybe_quarantine_unattributed(&mut attested, true);
        assert_eq!(attested.lifecycle_state, LifecycleState::Open);
    }

    /// #2966 (L6 5-agent vote `4d3ea1c5`) — the route-IN quarantine must be
    /// OBSERVABLE, not a silent hide (#2444). Assert the Prometheus counter
    /// `ai_memory_fed_quarantined_unattributed_total` increments once per row
    /// actually quarantined, and does NOT move on the byte-identical no-op
    /// paths (knob OFF, or knob ON but the row is agent-attested).
    #[test]
    fn quarantine_increments_counter_only_on_actual_quarantine_2966() {
        use crate::models::LifecycleState;
        let _guard = QUARANTINE_METRIC_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let base = crate::metrics::fed_quarantined_unattributed_count();

        // Knob OFF: byte-identical no-op — row stays Open, counter unmoved.
        let mut off = wsig_mem("ai:curator");
        off.metadata
            .as_object_mut()
            .unwrap()
            .insert("attest_level".to_string(), serde_json::json!("claimed"));
        maybe_quarantine_unattributed(&mut off, false);
        assert_eq!(off.lifecycle_state, LifecycleState::Open);
        assert_eq!(
            crate::metrics::fed_quarantined_unattributed_count(),
            base,
            "knob OFF must not touch the quarantine counter"
        );

        // Knob ON + unattributed → quarantined AND counter += 1.
        let mut claimed = wsig_mem("ai:curator");
        claimed
            .metadata
            .as_object_mut()
            .unwrap()
            .insert("attest_level".to_string(), serde_json::json!("claimed"));
        maybe_quarantine_unattributed(&mut claimed, true);
        assert_eq!(claimed.lifecycle_state, LifecycleState::Quarantined);
        assert_eq!(
            crate::metrics::fed_quarantined_unattributed_count(),
            base + 1,
            "an actual quarantine must increment the counter exactly once"
        );

        // Knob ON but agent_attested → NOT quarantined, counter unmoved.
        let mut attested = wsig_mem("ai:curator");
        attested.metadata.as_object_mut().unwrap().insert(
            "attest_level".to_string(),
            serde_json::json!("agent_attested"),
        );
        maybe_quarantine_unattributed(&mut attested, true);
        assert_eq!(attested.lifecycle_state, LifecycleState::Open);
        assert_eq!(
            crate::metrics::fed_quarantined_unattributed_count(),
            base + 1,
            "an agent-attested row must not increment the counter"
        );
    }
}
