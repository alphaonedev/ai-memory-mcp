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
pub(super) const ATTESTATION_TRACE_TARGET: &str = "federation::attestation";

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
pub(super) fn resolve_inbound_attribution(
    to_insert: &mut Memory,
    sender_agent_id: &str,
    attest_cfg: &PeerAttestationConfig,
    peer_id: Option<&str>,
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
    // Enrolled posture: a relayed third-party claim is trusted ONLY if the
    // operator authorized this peer to author as that agent. Zero-config
    // (no allowlist) preserves the faith-based posture.
    let authorized = if attest_cfg.has_allowlist() {
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
///   (`AI_MEMORY_FED_REQUIRE_WRITE_SIG`, default off) is honored only for a
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
            {
                let lock = db.lock().await;
                if let Err(e) = db::set_embedding(&lock.0, &id, &vec) {
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
    body_bytes: Bytes,
) -> impl IntoResponse {
    // v0.7.0 #791 — verify the per-message signature BEFORE
    // deserialising the body. Keeps the verifier's input identical
    // to the wire bytes (signer + verifier MUST agree byte-for-byte).
    let peer_header_owned = extract_peer_id(&headers).map(str::to_string);

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
    let shipped_by_id: std::collections::HashMap<&str, &crate::federation::ShippedEmbedding> = body
        .embeddings
        .iter()
        .map(|se| (se.memory_id.as_str(), se))
        .collect();
    let mut deferred_embed: Vec<(String, String)> = Vec::new();
    let mut hnsw_updates: Vec<(String, Vec<f32>)> = Vec::new();
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
        let attribute_agent = resolve_inbound_attribution(
            &mut to_insert,
            &body.sender_agent_id,
            &attest_cfg,
            peer_header_owned.as_deref(),
        );
        // #1464 (v0.8.0) — per-write CONTENT attestation. Verify any
        // presented `metadata.write_signature` against the attributed
        // author's enrolled key → upgrade to `agent_attested` (vs `claimed`);
        // reject a forged signature, or (strict, opt-in) an unsigned honored
        // third-party relayed claim. Skips re-attributed rows internally.
        if let Err(e) = apply_inbound_write_attestation(
            &mut to_insert,
            &attribute_agent,
            &body.sender_agent_id,
            original_claim.as_deref(),
            db::agent_pubkey(&lock.0, &attribute_agent)
                .ok()
                .flatten()
                .as_deref(),
            crate::federation::receive_auth::require_write_sig_enabled(),
        ) {
            tracing::warn!(
                target: ATTESTATION_TRACE_TARGET,
                memory_id = %to_insert.id,
                attribute_agent = %attribute_agent,
                sender = %body.sender_agent_id,
                error = %e,
                "sync_push: per-write content attestation failed; rejecting memory (#1464)"
            );
            skipped += 1;
            continue;
        }
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
        match db::merge_inbound(&lock.0, &to_insert) {
            Ok(actual_id) => {
                applied += 1;
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
                let clean_shipped = shipped_by_id
                    .get(mem.id.as_str())
                    .filter(|se| receiver_dim == Some(se.dim) && se.vector.len() == se.dim)
                    .and_then(|se| {
                        crate::federation::sanitize_shipped_vector(&se.vector)
                            .map(|v| (v, se.model.clone()))
                    });
                match clean_shipped {
                    Some((vector, model)) => {
                        match db::set_embedding(&lock.0, &actual_id, &vector) {
                            Ok(()) => hnsw_updates.push((actual_id, vector)),
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
                for (id, vec) in hnsw_updates {
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
        match db::decide_pending_action(&lock.0, &dec.id, dec.approved, &dec.decider) {
            Ok(true) => {
                pending_decisions_applied += 1;
                // On approve, replay the pending payload so the target
                // write (store/delete/promote) actually lands on this
                // peer — matches the originator's post-approve state.
                if dec.approved {
                    match db::execute_pending_action(&lock.0, &dec.id) {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                "sync_push: execute_pending_action failed for {}: {e}",
                                dec.id
                            );
                        }
                    }
                }
            }
            Ok(false) => noop += 1, // already decided — converged state
            Err(e) => {
                tracing::warn!(
                    "sync_push: decide_pending_action failed for {}: {e}",
                    dec.id
                );
                skipped += 1;
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

    // v0.6.2 (S35): process incoming namespace_meta rows. Applies via
    // `set_namespace_standard` so the peer's inheritance-chain walk has
    // the originator's explicit parent link. The standard memory itself
    // rides on the same push via `memories` (or arrived earlier through
    // `broadcast_store_quorum`); the namespace-meta row closes the gap.
    let mut namespace_meta_applied = 0usize;
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
    // the sender's full vector clock into the receiver's persisted
    // sync-state (pointwise max). Additive over the per-peer `observe`
    // above — `observe` advances only what THIS push told us about the
    // sender, whereas the merge enriches the receiver clock with every
    // peer the sender has transitively observed, so the receiver's clock
    // reflects all known peer timestamps (the reconciliation foundation
    // for redundant-push short-circuiting). Monotonic: an older incoming
    // timestamp never regresses a newer stored entry. Skipped in dry-run.
    if !body.dry_run
        && let Err(e) = db::sync_state_merge(&lock.0, &local_agent_id, &body.sender_clock)
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
            for (id, vec) in hnsw_updates {
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
            "namespace_meta_applied": namespace_meta_applied,
            "namespace_meta_cleared": namespace_meta_cleared,
            "noop": noop,
            "skipped": skipped,
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
        let cfg = PeerAttestationConfig { peers };
        let zero = PeerAttestationConfig::default();

        // (1) Zero-config faith posture (no allowlist): the claim is trusted
        // verbatim and NOT rewritten (preserve #1056/#238 behaviour).
        let mut m = claiming("alice");
        assert_eq!(
            resolve_inbound_attribution(&mut m, "ai:relay", &zero, Some("ai:relay")),
            "alice"
        );
        assert_eq!(m.metadata["agent_id"], "alice");

        // (2) Enrolled, peer NOT authorized to author as "alice" → attribute
        // to the sender AND rewrite ownership; stamp the bare-claim level.
        let mut m2 = claiming("alice");
        assert_eq!(
            resolve_inbound_attribution(&mut m2, "ai:relay", &cfg, Some("ai:relay")),
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
            resolve_inbound_attribution(&mut m3, "ai:relay", &cfg, Some("ai:relay")),
            "bob"
        );
        assert_eq!(m3.metadata["agent_id"], "bob");

        // (4) Self-authored (claim == sender, the #238-attested body author)
        // → trusted regardless of the allowlist.
        let mut m4 = claiming("ai:relay");
        assert_eq!(
            resolve_inbound_attribution(&mut m4, "ai:relay", &cfg, Some("ai:relay")),
            "ai:relay"
        );

        // (5) No claim at all → attribute to the sender.
        let mut m5 = Memory {
            id: "m-none".to_string(),
            metadata: serde_json::json!({}),
            ..Memory::default()
        };
        assert_eq!(
            resolve_inbound_attribution(&mut m5, "ai:relay", &cfg, Some("ai:relay")),
            "ai:relay"
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
}
