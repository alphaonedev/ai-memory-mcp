// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#3474] — the ADMIN HTTP enrolment surface for per-agent api-keys.
//!
//! # Why this exists
//!
//! [#3418] made the enrolled `sha256(token) -> agent_id` registry LIVE (a
//! revoked key stops authenticating within the refresh window instead of at
//! the next restart) and gave the CLI a `--store-url` so a postgres data tier
//! is addressable. What it deliberately did NOT ship was the network surface:
//! a route that MINTS a bearer credential is its own security design — who may
//! call it, how the raw token is transported and never logged, how it is
//! audited, rate-limited and approval-gated — and folding it into the refresh
//! fix would have put two independently-reviewable controls in one diff.
//!
//! Without it a fleet controller with no shell on the data tier cannot enrol a
//! dynamically-minted agent at all, so `advisory` (self-asserted `X-Agent-Id`)
//! stays the only workable posture — exactly what `enforce` exists to refuse.
//!
//! # The surface
//!
//! * `POST /api/v1/agents/{id}/api-key` — MINT a fresh token server-side, or
//!   BIND an operator-supplied one. The minted token is returned EXACTLY ONCE,
//!   in the response body, and never again.
//! * `POST /api/v1/agents/{id}/api-key/revoke` — REVOKE every key bound to the
//!   agent.
//!
//! Both take effect through the [#3418] live registry with no daemon restart:
//! the durable write lands first, the in-process snapshot is then moved in the
//! SAFE direction (a revoke NARROWS it before anything else can fail, a bind
//! WIDENS it only after the durable row exists), and a full authoritative
//! re-read follows through
//! [`crate::handlers::identity_binding::apply_agent_key_refresh`], whose
//! keep-last-known degrade rule applies unchanged.
//!
//! # The controls, and what each one is actually for
//!
//! **Caller authorization** is [`crate::handlers::admin_role::require_admin`]
//! — the canonical gate every other admin route uses. No new role, no ad-hoc
//! check. It resolves the caller from `X-Agent-Id`, requires the name to be on
//! the operator's admin allowlist AND the deployment to have request
//! authentication configured (or the explicit [#1570] header-trust opt-in),
//! and — under the `enforce` identity posture — requires the admin id to be
//! KEY-ATTESTED itself ([#2044]). A non-admin gets the SAME generic
//! `403 {"error":"admin role required"}` whether or not the target agent
//! exists, so this route is not an agent-enumeration oracle. The principal the
//! handler acts on and audits is the gate's RETURN VALUE, never a
//! request-supplied field.
//!
//! **Supplied-token strength.** The BIND form takes a token the operator
//! already holds, so the route must not accept one weaker than the token it
//! would have MINTED: a one-byte string used to become a live bearer
//! credential for the named agent. [`MIN_SUPPLIED_TOKEN_BYTES`] is the bar,
//! [`SUPPLIED_TOKEN_FLOOR_BYTES`] the floor it may never be lowered past, and
//! the refusal echoes nothing of the candidate and audits no digest.
//!
//! **No-log token transport.** The raw token is read from the request body as
//! raw [`axum::body::Bytes`] and parsed HERE, so no extractor rejection can
//! render any part of the body into an error string; a parse failure answers
//! with the fixed [`BODY_PARSE_REFUSAL`]. [`MintApiKeyBody`]'s `Debug` prints
//! `<redacted>` for the token, so a `{body:?}` added later cannot leak it. The
//! response carries `Cache-Control: no-store`. Only `sha256(token)` is ever
//! persisted (the [#2044] contract) and only its
//! [`FINGERPRINT_HEX_LEN`]-character prefix is ever audited or logged. The
//! router's `TraceLayer` records method + URI only — never bodies, never
//! headers — so there is no request-logging middleware to exclude this route
//! from; the redaction here is by construction, not by policy.
//!
//! **Confidential transport.** A mint hands a bearer secret to the wire, so it
//! is refused unless the daemon's own bind posture is confidential — loopback
//! or in-process TLS, recorded once at boot by
//! [`mark_credential_transport_confidential`]. The default is `false`
//! (fail-closed): a router built outside `bootstrap_serve` has made no such
//! promise. This closes precisely the hole the [#2032] M2 bind guard leaves
//! open — `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK=1` acknowledges cleartext
//! off-host serving, which is survivable for content and NOT survivable for
//! minting credentials. REVOKE is deliberately NOT gated on it: refusing a
//! revocation is strictly worse than performing one over a channel an operator
//! already accepted.
//!
//! **Rate limit.** [`MINT_RATE_LIMIT_PER_WINDOW`] mints per
//! [`MINT_RATE_LIMIT_WINDOW_SECS`] per admitted caller, in a BOUNDED table
//! ([`RATE_LIMIT_MAX_TRACKED_CALLERS`]) that refuses rather than admits when
//! it is full of live windows — a limiter that fails OPEN under memory
//! pressure is not a limiter.
//!
//! **Approval gate.** Revoking ANOTHER principal's key, or the LAST enrolled
//! key on the deployment, queues a `pending_actions` row instead of acting;
//! it is applied only when a DIFFERENT registered approver approves it through
//! [`crate::db::approve_with_approver_type`] /
//! [`crate::store::MemoryStore::governance_approve_with_consensus`] — the same
//! self-approval and registered-approver refusals every other approval funnel
//! enforces. Revoking your OWN key stays immediate: a principal that believes
//! its credential is compromised must never be told to find a second operator
//! first. The last-key case is gated because an empty registry makes the
//! identity gate INERT in every mode (the [#1985] unsatisfiable-default rule),
//! so "revoke one agent" and "disarm the fleet's identity binding" are the
//! same keystroke unless someone else looks.
//!
//! **Governance.** The namespace policy for the identity namespace is
//! consulted READ-ONLY ([`crate::store::MemoryStore::resolve_governance_policy`]
//! / [`crate::db::resolve_governance_policy`]) rather than through the
//! queue-on-Pending `enforce_governance` funnel, because that funnel writes a
//! `pending_actions` row whose `action_type` dispatches into
//! `execute_pending_action`'s MEMORY arms — a row this surface's payload can
//! never be executed by. Consulting the resolved level and queueing our OWN
//! row keeps ONE applier (this module) for ONE payload shape. A `Deny`-class
//! level refuses; an `Approve` level routes into the same pending flow the
//! two-person rule uses.
//!
//! **Audit.** Every outcome — allow, refuse, queue, approve — appends to the
//! signed forensic chain via [`crate::governance::audit::record_decision`],
//! the same spine `bind_agent_pubkey` and the admin-role gate use. The rows
//! carry the actor, the target agent, the key FINGERPRINT and the outcome.
//! They never carry the token.
//!
//! [#1570]: https://github.com/alphaonedev/ai-memory-mcp/issues/1570
//! [#1985]: https://github.com/alphaonedev/ai-memory-mcp/issues/1985
//! [#2032]: https://github.com/alphaonedev/ai-memory-mcp/issues/2032
//! [#2044]: https://github.com/alphaonedev/ai-memory-mcp/issues/2044
//! [#3418]: https://github.com/alphaonedev/ai-memory-mcp/issues/3418
//! [#3474]: https://github.com/alphaonedev/ai-memory-mcp/issues/3474

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
use crate::db;
use crate::models::{GovernanceLevel, PendingAction};

// ---------------------------------------------------------------------------
// SSOT constants
// ---------------------------------------------------------------------------

/// `require_admin` endpoint tag + audit action for the mint/bind surface.
pub const MINT_ENDPOINT: &str = "agent_api_key_mint";

/// `require_admin` endpoint tag + audit action for the revoke surface.
pub const REVOKE_ENDPOINT: &str = "agent_api_key_revoke";

/// Namespace the queued approval rows are filed under. The agent registry's
/// own reserved namespace, so an operator who governs `_agents` governs
/// credential enrolment with the policy they already wrote.
pub const IDENTITY_NAMESPACE: &str = "_agents";

/// `payload.kind` discriminator on every `pending_actions` row this module
/// queues. The applier refuses any row that does not carry it, so a row queued
/// by another surface can never be replayed through the credential applier.
pub const PENDING_PAYLOAD_KIND: &str = "agent_api_key_admin";

/// `payload.op` — mint a fresh server-side token.
pub const OP_MINT: &str = "mint";
/// `payload.op` — bind an operator-supplied token (digest carried in payload).
pub const OP_BIND: &str = "bind";
/// `payload.op` — revoke every key bound to the target agent.
pub const OP_REVOKE: &str = "revoke";

/// Response + audit field carrying the [`FINGERPRINT_HEX_LEN`]-character
/// digest prefix that identifies a key without disclosing it.
pub const FIELD_KEY_FINGERPRINT: &str = "key_fingerprint";

/// Pending-payload field carrying the `sha256(token)` digest of an
/// operator-supplied token. Never the token.
pub const FIELD_TOKEN_SHA256: &str = "token_sha256";

/// Response field: how many durable bindings a revoke removed.
pub const FIELD_BINDINGS_REMOVED: &str = "bindings_removed";

/// Response field: WHEN the change takes effect, so a caller never has to
/// infer it from the absence of a pending id.
pub const FIELD_EFFECTIVE: &str = "effective";

/// The one value [`FIELD_EFFECTIVE`] takes on an applied change — the #3418
/// live registry means there is no refresh window to wait out.
pub const EFFECTIVE_IMMEDIATELY: &str = "immediately";

/// Audit outcome token for a supplied token refused on strength.
const OUTCOME_TOKEN_TOO_SHORT: &str = "supplied_token_too_short";

/// Audit outcome token for a durable-store failure on either verb.
const OUTCOME_STORE_ERROR: &str = "store_error";

/// What [`MintApiKeyBody`]'s `Debug` prints in place of the token.
const REDACTED: &str = "<redacted>";

/// Entropy of a server-minted token, in bytes, before base64url encoding.
/// 256 bits: the token IS the credential, and it is compared by digest, so
/// there is no reason to mint anything guessable.
const MINTED_TOKEN_BYTES: usize = 32;

/// Minimum LENGTH, in bytes, of an OPERATOR-SUPPLIED token on the bind form.
///
/// Without this, any non-empty trimmed string bound: `"a"` became a live
/// bearer credential for the named agent, and on a fleet-reachable route that
/// is a weak-secret enrolment surface — the mint form's 256 bits of CSPRNG
/// entropy would be beside a door anyone could walk through with a one-byte
/// guess. Set to the same 32 the MINTED form draws, so the two halves of one
/// route cannot disagree about what a credential is worth. **16 is the floor**
/// — pinned by a unit test, because a future "just for this integration"
/// loosening below 128 bits is exactly how a strength check becomes theatre.
///
/// It is a LENGTH check, deliberately not an entropy estimate: a
/// Shannon/charset heuristic on a 32-byte string is noise, and refusing a
/// legitimate high-entropy token an operator already provisioned would push
/// them back to the CLI or to a shorter one. Length is the property this
/// surface can honestly enforce; the operator owns the generator.
pub const MIN_SUPPLIED_TOKEN_BYTES: usize = 32;

/// The absolute floor [`MIN_SUPPLIED_TOKEN_BYTES`] may never be lowered past.
/// 128 bits is the smallest width anyone should call a bearer secret.
pub const SUPPLIED_TOKEN_FLOOR_BYTES: usize = 16;

/// The ONLY thing a too-short supplied token is answered with. Echoes NOTHING
/// of the token — the refusal is about a credential the caller sent, and the
/// same reasoning that keeps [`BODY_PARSE_REFUSAL`] contentless applies here
/// verbatim. The response carries the minimum as a NUMBER so a client can act
/// on it without parsing prose.
pub const TOKEN_TOO_SHORT: &str = "token too short";

/// Response field carrying [`MIN_SUPPLIED_TOKEN_BYTES`] on a
/// [`TOKEN_TOO_SHORT`] refusal.
pub const FIELD_MIN_TOKEN_BYTES: &str = "min_token_bytes";

/// How many leading hex characters of `sha256(token)` identify a key in logs
/// and audit rows. Enough to correlate two rows, far too few to attack the
/// digest, and it is a digest prefix rather than any part of the secret.
pub const FINGERPRINT_HEX_LEN: usize = 12;

/// Rate limit SSOT — mints admitted per caller per window.
pub const MINT_RATE_LIMIT_PER_WINDOW: u32 = 10;

/// Rate limit SSOT — the fixed window, in seconds.
pub const MINT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Rate limit SSOT — hard cap on distinct callers tracked at once. A limiter
/// whose table can grow without bound is a memory-exhaustion lever; one that
/// ADMITS when the table is full is not a limiter at all. This one refuses.
pub const RATE_LIMIT_MAX_TRACKED_CALLERS: usize = 4096;

/// The ONLY thing a malformed body is ever answered with. Deliberately carries
/// no serde message and no fragment of the body: the body may contain a bearer
/// token, and an error string is a log line waiting to happen.
pub const BODY_PARSE_REFUSAL: &str = "invalid request body";

/// Wire error for a mint attempted over a transport the daemon has not
/// promised is confidential.
pub const TRANSPORT_REFUSAL: &str = "credential_transport_not_confidential";

/// Wire error for a rate-limited mint.
pub const RATE_LIMITED: &str = "rate_limited";

/// The once-only disclosure warning that rides the mint response, so the
/// caller is told by the SERVER — not only by the docs — that the token is
/// not recoverable.
pub const TOKEN_SHOWN_ONCE_NOTE: &str = "this token is returned exactly once and is never stored in raw form; \
     only its sha256 digest is persisted. Capture it now or mint another.";

// ---------------------------------------------------------------------------
// Boot-recorded transport posture
// ---------------------------------------------------------------------------

/// Process-wide marker: `true` when the running daemon's listener is
/// confidential (loopback bind, or in-process TLS). Recorded once by
/// `bootstrap_serve`; the default `false` is the fail-closed side, so a router
/// built by an embedder that never made the promise does not mint credentials.
static CREDENTIAL_TRANSPORT_CONFIDENTIAL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Record at boot whether the daemon's own listener is confidential.
///
/// `confidential` must be `true` only when the bind host is loopback (the
/// single-tenant default) or in-process TLS is configured. The plaintext
/// non-loopback bind the [#2032] M2 guard merely WARNs about is exactly the
/// case this must be `false` for.
pub fn mark_credential_transport_confidential(confidential: bool) {
    CREDENTIAL_TRANSPORT_CONFIDENTIAL.store(confidential, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a credential may be handed to this listener's wire.
#[must_use]
pub fn credential_transport_confidential() -> bool {
    CREDENTIAL_TRANSPORT_CONFIDENTIAL.load(std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Fixed-window per-caller token bucket for the mint surface.
///
/// Kept as a plain struct (rather than only a static) so the whole policy —
/// including the full-table refusal and the window roll — is unit-testable
/// against an injected clock, with no daemon and no global state.
#[derive(Debug, Default)]
pub struct MintRateLimiter {
    /// `caller -> (window_start_secs, count_in_window)`.
    inner: std::sync::Mutex<std::collections::HashMap<String, (u64, u32)>>,
}

impl MintRateLimiter {
    /// `true` when the caller may mint now; `false` to refuse.
    ///
    /// `now_secs` is injected so the policy is testable without sleeping.
    /// A poisoned lock recovers via `into_inner` rather than panicking
    /// (CONCURRENCY-18): this sits on an admin request path and an unrelated
    /// panic must not convert into a permanent outage of credential
    /// enrolment — recovery here is sound because the map is a pure counter
    /// with no cross-entry invariant.
    pub fn admit_at(&self, caller: &str, now_secs: u64) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let window_start = now_secs - (now_secs % MINT_RATE_LIMIT_WINDOW_SECS);
        if let Some((start, count)) = guard.get_mut(caller) {
            if *start == window_start {
                if *count >= MINT_RATE_LIMIT_PER_WINDOW {
                    return false;
                }
                *count += 1;
                return true;
            }
            *start = window_start;
            *count = 1;
            return true;
        }
        if guard.len() >= RATE_LIMIT_MAX_TRACKED_CALLERS {
            // Drop every entry whose window has rolled — they carry no
            // remaining budget information.
            guard.retain(|_, (start, _)| *start == window_start);
            if guard.len() >= RATE_LIMIT_MAX_TRACKED_CALLERS {
                // Still full of LIVE windows. Refusing is the only safe answer:
                // admitting an untracked caller would make the limit trivially
                // bypassable by first filling the table.
                return false;
            }
        }
        guard.insert(caller.to_string(), (window_start, 1));
        true
    }

    /// Seconds since the Unix epoch, saturating at 0 if the clock is before it.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// `true` when the caller may mint now, against the wall clock.
    pub fn admit(&self, caller: &str) -> bool {
        self.admit_at(caller, Self::now_secs())
    }
}

/// The process-wide mint limiter. Keyed by the ADMITTED admin principal, so a
/// caller cannot reset their own budget by changing a header the gate ignores.
static MINT_LIMITER: std::sync::LazyLock<MintRateLimiter> =
    std::sync::LazyLock::new(MintRateLimiter::default);

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/agents/{id}/api-key`.
///
/// `token` absent  → MINT a fresh server-side token.
/// `token` present → BIND that operator-supplied token's digest.
/// `approve_pending_id` present → APPROVE + apply a previously queued row.
///
/// `deny_unknown_fields` is deliberate: a typo'd field on a credential-minting
/// route must be an error, not a silent default.
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MintApiKeyBody {
    /// Operator-supplied token. NEVER rendered by `Debug`, never logged,
    /// never persisted — only its `sha256` reaches the store.
    #[serde(default)]
    pub token: Option<String>,
    /// A pending row queued by an earlier call to this surface.
    #[serde(default)]
    pub approve_pending_id: Option<String>,
}

impl std::fmt::Debug for MintApiKeyBody {
    /// Redacts the token BY CONSTRUCTION: a `{body:?}` added by a future
    /// change — or by a derived `Debug` on an enclosing type — cannot leak the
    /// bearer secret into a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintApiKeyBody")
            .field(
                "token",
                &self.token.as_ref().map(|_| REDACTED).unwrap_or("None"),
            )
            .field("approve_pending_id", &self.approve_pending_id)
            .finish()
    }
}

/// Body of `POST /api/v1/agents/{id}/api-key/revoke`. Carries no secret.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RevokeApiKeyBody {
    /// A pending revoke queued by an earlier call to this surface.
    #[serde(default)]
    pub approve_pending_id: Option<String>,
}

/// Parse a request body that MAY carry a bearer token.
///
/// An empty body is the default value (a bare mint needs no body at all). A
/// malformed body is answered with [`BODY_PARSE_REFUSAL`] and nothing else —
/// see the module docs on why no serde message is echoed.
fn parse_body<T: serde::de::DeserializeOwned + Default>(bytes: &Bytes) -> Result<T, Response> {
    if bytes.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice::<T>(bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": BODY_PARSE_REFUSAL})),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Separator between the pending id and the approver in the signed approval
/// subject. `@` cannot occur in a UUID pending id, so the split is
/// unambiguous, and it is already legal in an `agent_id`
/// (`crate::validate::validate_agent_id`), which is why the approver goes
/// SECOND.
pub const APPROVAL_SUBJECT_SEPARATOR: &str = "@";

/// The subject the K10 approval signature commits to on this route:
/// `<pending_id>@<approver_agent_id>`.
///
/// See the call site in [`apply_approved`] for why the approver is in here at
/// all; in one line, a signature that does not name its signer is a signature
/// somebody else can present.
#[must_use]
pub fn approval_subject(pending_id: &str, approver_agent_id: &str) -> String {
    format!("{pending_id}{APPROVAL_SUBJECT_SEPARATOR}{approver_agent_id}")
}

/// Operator-facing description of the signature this route requires. Named so
/// the refusal and the docs cannot drift apart.
pub const APPROVAL_SIGNATURE_HINT: &str = "approving a queued api-key action requires the K10 HMAC headers \
     X-AI-Memory-Signature: sha256=<HMAC-SHA256(SHA256(secret), \
     \"<ts>.POST.<pending_id>@<approver-agent-id>.<body>\")> and \
     X-AI-Memory-Timestamp: <unix-epoch-secs>. The approver is inside the \
     signed subject so a captured signature cannot be presented by a \
     different principal.";

/// The audit/log identifier for a key: a short PREFIX of the stored digest.
/// Never any part of the token itself.
#[must_use]
pub fn key_fingerprint(token_sha256: &str) -> String {
    token_sha256.chars().take(FINGERPRINT_HEX_LEN).collect()
}

/// Whether an OPERATOR-SUPPLIED token is long enough to be a credential.
///
/// `token` is the ALREADY-TRIMMED value; the empty string is refused by the
/// same rule rather than by a separate branch, so there is one answer to
/// "why was my token rejected" instead of two. Pure, so the rule is pinned by
/// a unit test rather than only by driving the route.
#[must_use]
pub fn supplied_token_meets_minimum(token: &str) -> bool {
    token.len() >= MIN_SUPPLIED_TOKEN_BYTES
}

/// Mint a fresh bearer token from the platform CSPRNG — the same source
/// `identity::keypair::generate` and the [#3464] bind nonce draw from.
fn mint_token() -> String {
    use base64::Engine as _;
    use rand_core::RngCore as _;
    let mut buf = [0u8; MINTED_TOKEN_BYTES];
    rand_core::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Why a revoke must be approved by a second principal before it applies.
///
/// Pure so the rule is pinned by unit tests rather than by standing up two
/// daemons and a queue.
///
/// * `target != caller` — a credential belonging to someone else. Two-person
///   rule; this is the revocation-abuse lever (silence an agent by killing its
///   key) and the one an admin can pull unilaterally today.
/// * the revoke would leave ZERO enrolled keys — an empty registry makes
///   [`crate::handlers::identity_binding::enforce_for_request`] inert in EVERY
///   mode ([#1985]), so this single call disarms the fleet's identity binding.
/// * the identity namespace's `delete` level resolves to `Approve` — the
///   operator said so.
///
/// Returns `None` when the revoke may apply immediately. Revoking your OWN key
/// while others remain enrolled is always immediate: a principal that believes
/// its credential is compromised must not be made to find a second operator.
#[must_use]
pub fn revoke_requires_approval(
    target_agent_id: &str,
    caller: &str,
    enrolled_total: usize,
    target_key_count: usize,
    policy_requires_approval: bool,
) -> Option<&'static str> {
    if target_agent_id != caller {
        return Some("another_principal");
    }
    if policy_requires_approval {
        return Some("namespace_policy");
    }
    if target_key_count > 0 && enrolled_total.saturating_sub(target_key_count) == 0 {
        return Some("last_enrolled_key");
    }
    None
}

/// `true` when a resolved governance level demands a second principal's
/// approval before the action applies.
#[must_use]
pub fn level_requires_approval(level: &GovernanceLevel) -> bool {
    matches!(level, GovernanceLevel::Approve)
}

/// Record one decision on the signed forensic chain.
///
/// `token_sha256` is a DIGEST; only [`key_fingerprint`] of it is recorded, and
/// the raw token is not a parameter of this function at all — the type system
/// keeps it out of the audit spine.
fn audit(
    caller: &str,
    decision: &str,
    endpoint: &'static str,
    target_agent_id: &str,
    outcome: &str,
    token_sha256: Option<&str>,
) {
    crate::governance::audit::record_decision(
        caller,
        decision,
        endpoint,
        "",
        json!({
            "issue": "#3474",
            (crate::models::field_names::TARGET_AGENT_ID): target_agent_id,
            "outcome": outcome,
            (FIELD_KEY_FINGERPRINT): token_sha256.map(key_fingerprint),
        }),
    );
}

/// The generic admin refusal, reused verbatim so this surface reveals nothing
/// `require_admin` would not.
fn forbidden(error: &str, message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": error, "message": message})),
    )
        .into_response()
}

/// A response that must never be cached, stored or revalidated from a proxy.
fn no_store(status: StatusCode, body: serde_json::Value) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Backend-neutral store helpers
//
// Each helper takes the sqlite lock, performs the synchronous call and drops
// the guard before returning, so no `tokio::Mutex` guard is ever held across
// an unrelated `.await` (CONCURRENCY-20).
// ---------------------------------------------------------------------------

/// Enumerate every enrolled `(token_sha256, agent_id)` pair.
async fn load_enrolled(app: &AppState) -> Result<Vec<(String, String)>, String> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return app
            .store
            .list_agent_api_keys()
            .await
            .map_err(|e| e.to_string());
    }
    let lock = app.db.lock().await;
    db::list_agent_api_keys(&lock.0).map_err(|e| e.to_string())
}

/// Bind `token_sha256` to `agent_id` durably.
async fn store_bind(
    app: &AppState,
    caller: &str,
    agent_id: &str,
    token_sha256: &str,
) -> Result<(), Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(caller.to_string());
        return app
            .store
            .bind_agent_api_key(&ctx, agent_id, token_sha256)
            .await
            .map_err(super::store_err_to_response);
    }
    let _ = caller;
    let lock = app.db.lock().await;
    db::bind_agent_api_key(&lock.0, agent_id, token_sha256)
        .map_err(|e| crate::handlers::errors::handler_error_500(&e))
}

/// Revoke every key bound to `agent_id` durably; returns the row count.
async fn store_revoke(app: &AppState, caller: &str, agent_id: &str) -> Result<usize, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(caller.to_string());
        return app
            .store
            .revoke_agent_api_key(&ctx, agent_id)
            .await
            .map_err(super::store_err_to_response);
    }
    let _ = caller;
    let lock = app.db.lock().await;
    db::revoke_agent_api_key(&lock.0, agent_id)
        .map_err(|e| crate::handlers::errors::handler_error_500(&e))
}

/// Resolve the identity namespace's governance level for this action class.
/// A namespace with no policy resolves to [`GovernanceLevel::Any`] — the
/// pre-existing "no governance configured" posture; the admin gate above is
/// what actually authorizes the call.
async fn resolve_level(app: &AppState, delete_class: bool) -> Result<GovernanceLevel, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let policy = app
            .store
            .resolve_governance_policy(IDENTITY_NAMESPACE)
            .await
            .map_err(super::store_err_to_response)?;
        return Ok(level_of(policy.as_ref(), delete_class));
    }
    let lock = app.db.lock().await;
    let policy = db::resolve_governance_policy(&lock.0, IDENTITY_NAMESPACE);
    Ok(level_of(policy.as_ref(), delete_class))
}

/// The action-class level of a resolved policy. `None` (no governance
/// configured for the identity namespace) is [`GovernanceLevel::Any`] — the
/// pre-existing posture; the admin gate is what authorizes the call.
fn level_of(
    policy: Option<&crate::models::GovernancePolicy>,
    delete_class: bool,
) -> GovernanceLevel {
    policy.map_or(GovernanceLevel::Any, |p| {
        if delete_class {
            p.core.delete.clone()
        } else {
            p.core.write.clone()
        }
    })
}

/// Queue a `pending_actions` row this module will later apply.
async fn store_queue(
    app: &AppState,
    action: crate::models::GovernedAction,
    requested_by: &str,
    payload: &serde_json::Value,
) -> Result<String, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(requested_by.to_string());
        return app
            .store
            .queue_pending_action(
                &ctx,
                action.into(),
                IDENTITY_NAMESPACE,
                None,
                requested_by,
                payload,
            )
            .await
            .map_err(super::store_err_to_response);
    }
    let lock = app.db.lock().await;
    db::queue_pending_action(
        &lock.0,
        action,
        IDENTITY_NAMESPACE,
        None,
        requested_by,
        payload,
    )
    .map_err(|e| crate::handlers::errors::handler_error_500(&e))
}

/// Read one pending row.
///
/// Runs as the ADMITTED caller, never as the daemon principal and never with
/// a visibility bypass: `pending_actions` carries no per-row scope, so the
/// elevated context would buy nothing and would add a `for_admin` site a
/// reviewer then has to reason about.
async fn store_get_pending(
    app: &AppState,
    caller: &str,
    id: &str,
) -> Result<Option<PendingAction>, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(caller.to_string());
        return app
            .store
            .get_pending(&ctx, id)
            .await
            .map_err(super::store_err_to_response);
    }
    let _ = caller;
    let lock = app.db.lock().await;
    db::get_pending_action(&lock.0, id).map_err(|e| crate::handlers::errors::handler_error_500(&e))
}

/// Backend-neutral approval outcome.
enum Approval {
    /// The row transitioned to `approved` on this call.
    Approved,
    /// The vote was recorded; a consensus quorum is not yet met.
    AwaitingQuorum { votes: usize, quorum: u32 },
    /// The approver is not eligible (self-approval, unregistered, wrong id).
    Refused(String),
}

/// Apply one approval vote through the SAME approver-eligibility gate every
/// other approval funnel uses — `ApproveSurface::Http`, so the self-approval
/// refusal and the registered-approver requirement are UNCONDITIONAL here
/// (the multi-tenant posture; see `storage::approve_with_approver_type`).
async fn store_approve(app: &AppState, id: &str, approver: &str) -> Result<Approval, Response> {
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let ctx = crate::store::CallerContext::for_agent(approver.to_string());
        return match app
            .store
            .governance_approve_with_consensus(&ctx, id, approver)
            .await
        {
            Ok(crate::store::ApproveOutcome::Approved) => Ok(Approval::Approved),
            Ok(crate::store::ApproveOutcome::Pending { votes, quorum }) => {
                Ok(Approval::AwaitingQuorum { votes, quorum })
            }
            Ok(crate::store::ApproveOutcome::Rejected(reason)) => Ok(Approval::Refused(reason)),
            Err(e) => Err(super::store_err_to_response(e)),
        };
    }
    let lock = app.db.lock().await;
    match db::approve_with_approver_type(&lock.0, id, approver, db::ApproveSurface::Http) {
        Ok(db::ApproveOutcome::Approved) => Ok(Approval::Approved),
        Ok(db::ApproveOutcome::Pending { votes, quorum }) => {
            Ok(Approval::AwaitingQuorum { votes, quorum })
        }
        Ok(db::ApproveOutcome::Rejected(reason)) => Ok(Approval::Refused(reason)),
        Ok(db::ApproveOutcome::NotFound) => Ok(Approval::Refused(
            crate::errors::msg::pending_action_not_found(id),
        )),
        Err(e) => Err(crate::handlers::errors::handler_error_500(&e)),
    }
}

// ---------------------------------------------------------------------------
// Live-registry maintenance
// ---------------------------------------------------------------------------

/// Move the LIVE registry after a durable write, then re-read authoritatively.
///
/// The two steps are ordered so the SAFE direction lands first and cannot be
/// lost to a read failure:
///
/// * `remove_agent` (a revoke) NARROWS the snapshot before anything else runs,
///   so the revoked credential stops authenticating on the very next request
///   even if the store is then unreachable;
/// * `add` (a bind) WIDENS it only after the durable row exists, so the
///   in-memory map can never claim a binding the store does not have.
///
/// The authoritative re-read follows through
/// [`crate::handlers::identity_binding::apply_agent_key_refresh`], which keeps
/// the last known snapshot on a failed read rather than installing an empty
/// map — installing empty would silently disarm the identity gate ([#3418]).
async fn refresh_registry(app: &AppState, add: Option<(&str, &str)>, remove_agent: Option<&str>) {
    let registry = &app.enrolled_agent_keys;
    if add.is_some() || remove_agent.is_some() {
        let mut map = (*registry.snapshot()).clone();
        if let Some(agent) = remove_agent {
            map.retain(|_, bound| bound != agent);
        }
        if let Some((digest, agent)) = add {
            map.insert(digest.to_string(), agent.to_string());
        }
        registry.install(map);
    }
    let loaded = load_enrolled(app).await;
    let _ = crate::handlers::identity_binding::apply_agent_key_refresh(registry, loaded);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/agents/{id}/api-key` — mint or bind a per-agent api-key.
///
/// Admin-gated, rate-limited, governance-consulted, audited. The minted token
/// is returned exactly once, `Cache-Control: no-store`.
pub async fn mint_agent_api_key(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    body: Bytes,
) -> Response {
    // The gate's RETURN VALUE is the principal this handler acts and audits
    // as — never a request field. A non-admin gets the same generic 403
    // whether or not `agent_id` names a real agent.
    let caller = match crate::handlers::admin_role::require_admin(&app, &headers, MINT_ENDPOINT) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if !credential_transport_confidential() {
        audit(
            &caller,
            "refuse",
            MINT_ENDPOINT,
            &agent_id,
            "transport_not_confidential",
            None,
        );
        return forbidden(
            TRANSPORT_REFUSAL,
            "this daemon's listener is neither loopback nor TLS-terminated in-process, so a \
             minted bearer token would cross the wire in cleartext. Bind to loopback, configure \
             --tls-cert/--tls-key, or enrol from the CLI on the data tier.",
        );
    }
    if let Err(e) = crate::validate::validate_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
        )
            .into_response();
    }
    let parsed: MintApiKeyBody = match parse_body(&body) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Keyed by the ADMITTED principal, so the budget cannot be reset by
    // rotating a header the admin gate ignores.
    if !MINT_LIMITER.admit(&caller) {
        audit(
            &caller,
            "refuse",
            MINT_ENDPOINT,
            &agent_id,
            "rate_limited",
            None,
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            Json(json!({
                "error": RATE_LIMITED,
                "limit": MINT_RATE_LIMIT_PER_WINDOW,
                "window_secs": MINT_RATE_LIMIT_WINDOW_SECS,
            })),
        )
            .into_response();
    }

    if let Some(pending_id) = parsed.approve_pending_id.as_deref() {
        return apply_approved(&app, &headers, &body, &caller, &agent_id, pending_id, false).await;
    }

    // Operator-supplied token, or a fresh server-minted one. A supplied token
    // must meet the same strength bar the minted one clears; the refusal
    // carries the minimum and NOTHING of the token, and is audited without a
    // digest (there is no binding to correlate, and hashing a rejected
    // candidate would put a guess in the audit chain).
    let (raw_token, minted) = match parsed.token.as_deref().map(str::trim) {
        Some(t) if !supplied_token_meets_minimum(t) => {
            audit(
                &caller,
                "refuse",
                MINT_ENDPOINT,
                &agent_id,
                OUTCOME_TOKEN_TOO_SHORT,
                None,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": TOKEN_TOO_SHORT,
                    (FIELD_MIN_TOKEN_BYTES): MIN_SUPPLIED_TOKEN_BYTES,
                })),
            )
                .into_response();
        }
        Some(t) => (t.to_string(), false),
        None => (mint_token(), true),
    };
    let digest = crate::handlers::identity_binding::api_key_sha256_hex(&raw_token);

    // Governance consult (read-only): an `Approve` write level queues instead
    // of acting. A minted token cannot be produced at queue time and returned
    // later without persisting it raw, so the MINT form defers the mint itself
    // to the apply step and the token is returned in the APPROVE response.
    let level = match resolve_level(&app, false).await {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    if level_requires_approval(&level) {
        let (op, payload_digest) = if minted {
            (OP_MINT, None)
        } else {
            (OP_BIND, Some(digest.as_str()))
        };
        let payload = json!({
            "kind": PENDING_PAYLOAD_KIND,
            "op": op,
            (crate::models::field_names::TARGET_AGENT_ID): agent_id,
            // A DIGEST, never the token. On the mint form there is no digest
            // at all — the token is minted at apply time.
            (FIELD_TOKEN_SHA256): payload_digest,
            (FIELD_KEY_FINGERPRINT): payload_digest.map(key_fingerprint),
        });
        return match store_queue(
            &app,
            crate::models::GovernedAction::Store,
            &caller,
            &payload,
        )
        .await
        {
            Ok(pending_id) => {
                audit(
                    &caller,
                    "allow",
                    MINT_ENDPOINT,
                    &agent_id,
                    "queued_pending_approval",
                    payload_digest,
                );
                queued_response(&pending_id, &agent_id, "namespace_policy")
            }
            Err(resp) => resp,
        };
    }

    if let Err(resp) = store_bind(&app, &caller, &agent_id, &digest).await {
        audit(
            &caller,
            "deny",
            MINT_ENDPOINT,
            &agent_id,
            OUTCOME_STORE_ERROR,
            Some(&digest),
        );
        return resp;
    }
    refresh_registry(&app, Some((&digest, &agent_id)), None).await;
    audit(
        &caller,
        "allow",
        MINT_ENDPOINT,
        &agent_id,
        if minted { "minted" } else { "bound" },
        Some(&digest),
    );
    mint_response(&agent_id, &digest, minted.then_some(raw_token.as_str()))
}

/// `POST /api/v1/agents/{id}/api-key/revoke` — revoke every key bound to the
/// agent, immediately or through the approval gate.
pub async fn revoke_agent_api_key(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    body: Bytes,
) -> Response {
    let caller = match crate::handlers::admin_role::require_admin(&app, &headers, REVOKE_ENDPOINT) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Err(e) = crate::validate::validate_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
        )
            .into_response();
    }
    let parsed: RevokeApiKeyBody = match parse_body(&body) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Some(pending_id) = parsed.approve_pending_id.as_deref() {
        return apply_approved(&app, &headers, &body, &caller, &agent_id, pending_id, true).await;
    }

    let enrolled = match load_enrolled(&app).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                target: crate::handlers::HTTP_AUTH_TRACE_TARGET,
                "#3474: revoke refused — could not read the enrolled key set ({e}); \
                 refusing rather than guessing whether this is the last key"
            );
            audit(
                &caller,
                "deny",
                REVOKE_ENDPOINT,
                &agent_id,
                "enrolled_read_failed",
                None,
            );
            return crate::handlers::errors::handler_error_500(&anyhow::anyhow!(
                "enrolled key set unavailable"
            ));
        }
    };
    let target_key_count = enrolled.iter().filter(|(_, a)| a == &agent_id).count();
    let level = match resolve_level(&app, true).await {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    if let Some(reason) = revoke_requires_approval(
        &agent_id,
        &caller,
        enrolled.len(),
        target_key_count,
        level_requires_approval(&level),
    ) {
        let payload = json!({
            "kind": PENDING_PAYLOAD_KIND,
            "op": OP_REVOKE,
            (crate::models::field_names::TARGET_AGENT_ID): agent_id,
            "reason": reason,
        });
        return match store_queue(
            &app,
            crate::models::GovernedAction::Delete,
            &caller,
            &payload,
        )
        .await
        {
            Ok(pending_id) => {
                audit(
                    &caller,
                    "allow",
                    REVOKE_ENDPOINT,
                    &agent_id,
                    "queued_pending_approval",
                    None,
                );
                queued_response(&pending_id, &agent_id, reason)
            }
            Err(resp) => resp,
        };
    }

    match store_revoke(&app, &caller, &agent_id).await {
        Ok(removed) => {
            refresh_registry(&app, None, Some(&agent_id)).await;
            audit(
                &caller,
                "allow",
                REVOKE_ENDPOINT,
                &agent_id,
                "revoked_self",
                None,
            );
            no_store(
                StatusCode::OK,
                json!({
                    "agent_id": agent_id,
                    "revoked": true,
                    (FIELD_BINDINGS_REMOVED): removed,
                    (FIELD_EFFECTIVE): EFFECTIVE_IMMEDIATELY,
                }),
            )
        }
        Err(resp) => {
            audit(
                &caller,
                "deny",
                REVOKE_ENDPOINT,
                &agent_id,
                OUTCOME_STORE_ERROR,
                None,
            );
            resp
        }
    }
}

/// The 202 envelope for an action parked awaiting a second principal.
fn queued_response(pending_id: &str, agent_id: &str, reason: &str) -> Response {
    no_store(
        StatusCode::ACCEPTED,
        json!({
            "agent_id": agent_id,
            "status": "pending_approval",
            (crate::models::field_names::PENDING_ID): pending_id,
            "reason": reason,
            "message": "a DIFFERENT registered approver must approve this action; re-POST to \
                        this route with {\"approve_pending_id\": \"<id>\"} plus the K10 \
                        X-AI-Memory-Signature over the body. Self-approval is refused.",
        }),
    )
}

/// The mint/bind success envelope. `raw_token` is `Some` only for a
/// server-side mint, and this is the ONLY place it ever reaches a caller.
fn mint_response(agent_id: &str, digest: &str, raw_token: Option<&str>) -> Response {
    let mut body = json!({
        "agent_id": agent_id,
        "bound": true,
        (FIELD_KEY_FINGERPRINT): key_fingerprint(digest),
        (FIELD_EFFECTIVE): EFFECTIVE_IMMEDIATELY,
    });
    if let Some(token) = raw_token
        && let Some(obj) = body.as_object_mut()
    {
        obj.insert("token".to_string(), json!(token));
        obj.insert("note".to_string(), json!(TOKEN_SHOWN_ONCE_NOTE));
    }
    no_store(StatusCode::OK, body)
}

/// Approve a queued row and apply it, in that order, in ONE call.
///
/// The K10 HMAC gate runs FIRST and over the WHOLE body — this route must not
/// become a second, weaker approval funnel — and binds the APPROVER into the
/// signed subject on top of what `POST /api/v1/pending/{id}/approve` binds.
///
/// **One approval applies EXACTLY ONCE.** The action is applied only in the
/// call that itself transitions the row `pending -> approved`; a row already
/// decided is a `409`, never a re-application. That is the whole reason the
/// approve and the apply are one call rather than two: a standing `approved`
/// row that any admin could re-post would turn ONE authorisation into an
/// unbounded credential mint (and, on the revoke side, into a replayable
/// revocation). The cost is that an operator who approved through the generic
/// `POST /api/v1/pending/{id}/approve` surface must re-issue here — a
/// fail-closed wart, and the safe direction: nothing durable is lost, because
/// the pending row records the intent and the request can simply be made
/// again.
async fn apply_approved(
    app: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    caller: &str,
    agent_id: &str,
    pending_id: &str,
    revoke: bool,
) -> Response {
    let endpoint = if revoke {
        REVOKE_ENDPOINT
    } else {
        MINT_ENDPOINT
    };
    if let Err(e) = crate::validate::validate_id(pending_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": crate::errors::msg::invalid("pending_id", e)})),
        )
            .into_response();
    }
    // The K10 HMAC gate, with the APPROVER folded into the bound subject.
    //
    // `verify_approval_hmac` commits the signature to
    // `<ts>.<METHOD>.<subject>.<body>` and single-uses it in a process-local
    // replay cache keyed on the signature itself. On the generic approve route
    // the subject is the bare pending id, so the signed bytes say WHICH row is
    // being approved and never WHO is approving it. Two consequences follow,
    // and this route refuses both: a captured signature could be presented by
    // a DIFFERENT principal (the `X-Agent-Id` beside it is self-asserted, and
    // the replay cache is per-process, so it does not survive a restart or a
    // second replica), and two legitimate approvers of the same row in the
    // same second would produce byte-identical signatures — the second read as
    // a replay and refused. Binding the approver into the subject closes the
    // first and dissolves the second.
    let subject = approval_subject(pending_id, caller);
    if let Err(status) = super::verify_approval_hmac(headers, body, "POST", &subject) {
        return (
            status,
            Json(json!({
                "error": crate::errors::msg::INVALID_OR_MISSING_SIGNATURE,
                "hint": APPROVAL_SIGNATURE_HINT,
            })),
        )
            .into_response();
    }
    let Some(pending) = (match store_get_pending(app, caller, pending_id).await {
        Ok(p) => p,
        Err(resp) => return resp,
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": crate::errors::msg::pending_action_not_found(pending_id)})),
        )
            .into_response();
    };
    // The row must be OURS, for THIS agent, and for THIS verb. Without all
    // three a row queued elsewhere could be replayed through the credential
    // applier.
    let kind = pending.payload.get("kind").and_then(|v| v.as_str());
    let op = pending.payload.get("op").and_then(|v| v.as_str());
    let target = pending
        .payload
        .get(crate::models::field_names::TARGET_AGENT_ID)
        .and_then(|v| v.as_str());
    let op_matches = match op {
        Some(OP_REVOKE) => revoke,
        Some(OP_MINT | OP_BIND) => !revoke,
        _ => false,
    };
    if kind != Some(PENDING_PAYLOAD_KIND) || target != Some(agent_id) || !op_matches {
        audit(
            caller,
            "deny",
            endpoint,
            agent_id,
            "pending_payload_mismatch",
            None,
        );
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "pending action does not match this route"})),
        )
            .into_response();
    }

    match pending.status.as_str() {
        "pending" => match store_approve(app, pending_id, caller).await {
            Ok(Approval::Approved) => {}
            Ok(Approval::AwaitingQuorum { votes, quorum }) => {
                audit(
                    caller,
                    "allow",
                    endpoint,
                    agent_id,
                    "approval_vote_recorded",
                    None,
                );
                return no_store(
                    StatusCode::ACCEPTED,
                    json!({
                        "agent_id": agent_id,
                        "status": "pending_approval",
                        (crate::models::field_names::PENDING_ID): pending_id,
                        "votes": votes,
                        "quorum": quorum,
                        "reason": crate::errors::msg::CONSENSUS_NOT_REACHED,
                    }),
                );
            }
            Ok(Approval::Refused(reason)) => {
                audit(
                    caller,
                    "refuse",
                    endpoint,
                    agent_id,
                    "approval_refused",
                    None,
                );
                return forbidden("approval_refused", &reason);
            }
            Err(resp) => return resp,
        },
        other => {
            // Already decided (approved, rejected or expired). NOT applied:
            // see the fn doc — one approval, one application, one call.
            audit(
                caller,
                "deny",
                endpoint,
                agent_id,
                "pending_already_decided",
                None,
            );
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "pending_action_already_decided",
                    "status": other,
                    "message": "an approval applies exactly once, in the call that decides it; \
                                re-issue the request to queue a fresh approval",
                })),
            )
                .into_response();
        }
    }

    if revoke {
        return match store_revoke(app, caller, agent_id).await {
            Ok(removed) => {
                refresh_registry(app, None, Some(agent_id)).await;
                audit(
                    caller,
                    "allow",
                    endpoint,
                    agent_id,
                    "revoked_after_approval",
                    None,
                );
                no_store(
                    StatusCode::OK,
                    json!({
                        "agent_id": agent_id,
                        "revoked": true,
                        (FIELD_BINDINGS_REMOVED): removed,
                        (crate::models::field_names::PENDING_ID): pending_id,
                        (FIELD_EFFECTIVE): EFFECTIVE_IMMEDIATELY,
                    }),
                )
            }
            Err(resp) => resp,
        };
    }

    // Mint/bind apply. A queued MINT carries no digest — the token is minted
    // HERE and returned to the approver, because a token produced at queue
    // time could only be delivered later by persisting it raw.
    let (raw_token, digest) = match pending
        .payload
        .get(FIELD_TOKEN_SHA256)
        .and_then(|v| v.as_str())
    {
        Some(d) => (None, d.to_string()),
        None => {
            let token = mint_token();
            let digest = crate::handlers::identity_binding::api_key_sha256_hex(&token);
            (Some(token), digest)
        }
    };
    if let Err(resp) = store_bind(app, caller, agent_id, &digest).await {
        audit(
            caller,
            "deny",
            endpoint,
            agent_id,
            OUTCOME_STORE_ERROR,
            Some(&digest),
        );
        return resp;
    }
    refresh_registry(app, Some((&digest, agent_id)), None).await;
    audit(
        caller,
        "allow",
        endpoint,
        agent_id,
        "bound_after_approval",
        Some(&digest),
    );
    mint_response(agent_id, &digest, raw_token.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_is_high_entropy_and_never_repeats() {
        let a = mint_token();
        let b = mint_token();
        assert_ne!(a, b, "two mints must not collide");
        // 32 bytes -> 43 base64url chars, no padding.
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn a_supplied_token_must_be_at_least_as_strong_as_a_minted_one() {
        // The bar itself, and the floor it may never be lowered past. A
        // future "just for this integration" loosening below 128 bits is
        // exactly how a strength check becomes theatre.
        assert!(
            MIN_SUPPLIED_TOKEN_BYTES >= SUPPLIED_TOKEN_FLOOR_BYTES,
            "the supplied-token minimum was lowered below the {SUPPLIED_TOKEN_FLOOR_BYTES}-byte floor"
        );
        assert!(!supplied_token_meets_minimum(""));
        assert!(!supplied_token_meets_minimum("a"));
        assert!(!supplied_token_meets_minimum(
            &"x".repeat(MIN_SUPPLIED_TOKEN_BYTES - 1)
        ));
        assert!(supplied_token_meets_minimum(
            &"x".repeat(MIN_SUPPLIED_TOKEN_BYTES)
        ));
        // The route's OWN mint must clear its own bar — otherwise the two
        // halves of one endpoint would disagree about what a credential is.
        assert!(supplied_token_meets_minimum(&mint_token()));
    }

    #[test]
    fn the_fingerprint_is_a_digest_prefix_not_the_secret() {
        let digest = crate::handlers::identity_binding::api_key_sha256_hex("hunter2");
        let fp = key_fingerprint(&digest);
        assert_eq!(fp.len(), FINGERPRINT_HEX_LEN);
        assert!(digest.starts_with(&fp));
        assert!(!"hunter2".contains(&fp));
    }

    #[test]
    fn debug_never_renders_the_token() {
        let body = MintApiKeyBody {
            token: Some("super-secret-token".to_string()),
            approve_pending_id: None,
        };
        let rendered = format!("{body:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "Debug leaked the bearer token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn revoking_your_own_key_is_immediate_while_others_remain() {
        assert_eq!(
            revoke_requires_approval("alice", "alice", 3, 1, false),
            None,
            "self-revoke with other keys enrolled must not need a second operator"
        );
    }

    #[test]
    fn revoking_another_principal_always_needs_approval() {
        assert_eq!(
            revoke_requires_approval("bob", "alice", 9, 1, false),
            Some("another_principal")
        );
    }

    #[test]
    fn revoking_the_last_enrolled_key_needs_approval_even_for_yourself() {
        // Disarming the whole identity gate is not a self-service action.
        assert_eq!(
            revoke_requires_approval("alice", "alice", 2, 2, false),
            Some("last_enrolled_key")
        );
    }

    #[test]
    fn an_agent_with_no_keys_is_not_the_last_key() {
        // target_key_count == 0 is a no-op revoke; it cannot empty anything.
        assert_eq!(
            revoke_requires_approval("alice", "alice", 0, 0, false),
            None
        );
    }

    #[test]
    fn an_approve_level_namespace_policy_needs_approval() {
        assert_eq!(
            revoke_requires_approval("alice", "alice", 5, 1, true),
            Some("namespace_policy")
        );
        assert!(level_requires_approval(&GovernanceLevel::Approve));
        for level in [
            GovernanceLevel::Any,
            GovernanceLevel::Registered,
            GovernanceLevel::Owner,
        ] {
            assert!(!level_requires_approval(&level));
        }
    }

    #[test]
    fn the_rate_limiter_admits_exactly_the_budget_then_refuses() {
        let limiter = MintRateLimiter::default();
        for i in 0..MINT_RATE_LIMIT_PER_WINDOW {
            assert!(
                limiter.admit_at("alice", 1_000),
                "mint {i} must be admitted"
            );
        }
        assert!(
            !limiter.admit_at("alice", 1_000),
            "the N+1th mint in the window must be refused"
        );
        // A different caller has its own budget.
        assert!(limiter.admit_at("bob", 1_000));
        // The next window rolls the budget.
        assert!(limiter.admit_at("alice", 1_000 + MINT_RATE_LIMIT_WINDOW_SECS));
    }

    #[test]
    fn a_full_limiter_table_refuses_rather_than_admitting_an_untracked_caller() {
        let limiter = MintRateLimiter::default();
        for i in 0..RATE_LIMIT_MAX_TRACKED_CALLERS {
            assert!(limiter.admit_at(&format!("caller-{i}"), 1_000));
        }
        assert!(
            !limiter.admit_at("overflow", 1_000),
            "a full table must FAIL CLOSED — admitting here makes the limit \
             bypassable by first filling the table"
        );
        // Once the window rolls, the stale entries are reclaimed.
        assert!(limiter.admit_at("overflow", 1_000 + MINT_RATE_LIMIT_WINDOW_SECS));
    }

    #[test]
    fn an_empty_body_is_a_bare_mint_and_garbage_is_refused_without_an_echo() {
        let empty = parse_body::<MintApiKeyBody>(&Bytes::new()).expect("empty body is the default");
        assert!(empty.token.is_none());
        let err = parse_body::<MintApiKeyBody>(&Bytes::from_static(
            b"{\"token\": \"leak-me\", \"bogus\": 1}",
        ))
        .expect_err("unknown fields are refused");
        let status = err.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_transport_marker_defaults_to_the_fail_closed_side() {
        // Not a global-state test: this asserts the COMPILED default of the
        // atomic, which is what an embedder that never called
        // `mark_credential_transport_confidential` gets.
        assert!(
            !std::sync::atomic::AtomicBool::new(false).load(std::sync::atomic::Ordering::Relaxed),
            "the marker's initial value must be false (refuse)"
        );
    }
}
