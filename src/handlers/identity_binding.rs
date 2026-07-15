// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2044 (v1.0.0, #2032-A) — HTTP-surface per-agent-key principal binding.
//!
//! Closes the two highest findings of the #2032 adversarial assessment, which
//! share ONE root cause: on the HTTP surface the `X-Agent-Id` header is a
//! SELF-ASSERTED principal while the `api_key` is only a SHARED transport
//! credential. So any api-key-bearing caller could
//!
//!   * **H1 (IDOR/BOLA)** set `X-Agent-Id: <victim>` and read/mutate another
//!     agent's `scope=private` rows on `GET/PUT/DELETE/promote /memories/{id}`;
//!   * **M1 (admin spoof)** set `X-Agent-Id: <admin>` and pass the
//!     [`crate::handlers::admin_role::require_admin`] allowlist gate.
//!
//! The fix is **per-agent-key principal binding**: a request asserting
//! `X-Agent-Id: X` must prove control of agent `X`'s enrolled per-agent api-key
//! (a server-held secret in the `agent_api_keys` table, `sha256(token) →
//! agent_id`) before the header identity is honored on the IDOR-sensitive
//! read/mutate and admin paths. The principal is keyed to a server-held secret,
//! NEVER a header (the #1570/#1582 lesson). Per the #1950 read-path freeze this
//! introduces NO new signed request envelope — it reuses the presented
//! per-agent key.
//!
//! The [`crate::handlers::api_key_auth`] middleware resolves an
//! [`AuthenticatedPrincipal`] from the presented key and injects it into the
//! request extensions; the IDOR/admin gates consume the carried
//! [`AuthLevel`]. Posture is the tri-state
//! [`crate::config::HttpIdentityMode`] (`off`/`advisory`/`enforce`, default
//! `advisory`).

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::HttpIdentityMode;

/// The provenance of the caller's resolved `agent_id` on the HTTP surface.
///
/// Carried on [`AuthenticatedPrincipal`] and consumed by the IDOR/admin gates
/// (via [`enforce_sensitive_identity`]). Ordering is significant:
/// `Claimed < KeyAuthenticated < SignatureAttested` by assurance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// Self-asserted `X-Agent-Id` only — proven possession of the SHARED
    /// transport credential (or a keyless bind), NOT of this principal. The
    /// spoofable level the #2044 fix distrusts on sensitive paths.
    Claimed,
    /// The presented `X-API-Key` is an enrolled PER-AGENT key whose
    /// `sha256(token)` resolved to this `agent_id` (`agent_api_keys` table).
    /// Cryptographic-secret possession of this principal.
    KeyAuthenticated,
    /// Reserved — a per-request Ed25519 `SignableWrite` attestation. NOT
    /// produced by this train (#1950 froze the read/mutate request envelope);
    /// the additive `ai-memory/recall-attestation/v1` lands post-v1.0.
    SignatureAttested,
}

impl AuthLevel {
    /// Lowercase wire tag for audit surfaces.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::KeyAuthenticated => "key_authenticated",
            Self::SignatureAttested => "signature_attested",
        }
    }

    /// `true` when the level proves cryptographic-secret possession of the
    /// principal (i.e. NOT merely `Claimed`). This is the bar the `enforce`
    /// posture requires on IDOR-sensitive read/mutate + admin paths.
    #[must_use]
    pub fn is_key_bound(self) -> bool {
        matches!(self, Self::KeyAuthenticated | Self::SignatureAttested)
    }
}

/// The request principal resolved by [`crate::handlers::api_key_auth`] and
/// stored in the axum request extensions. Present on EVERY request that
/// traversed the middleware with an `api_key` configured; absent on the keyless
/// bind (treated as [`AuthLevel::Claimed`] by the consumers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    /// The resolved principal. For a `KeyAuthenticated` level this is the
    /// key-derived `agent_id`; for `Claimed` it is the self-asserted
    /// `X-Agent-Id` (or the anonymous fallback).
    pub agent_id: String,
    /// How `agent_id` was established.
    pub level: AuthLevel,
}

/// Lowercase hex `sha256` of an api-key token — the stored `agent_api_keys`
/// lookup key. The raw token is NEVER persisted (only its digest), so a DB read
/// cannot recover the bearer secret.
#[must_use]
pub fn api_key_sha256_hex(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        // `write!` into a `String` is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// #2044 — re-derive the caller's [`AuthLevel`] SELF-CONTAINEDLY from the
/// presented `X-API-Key` header and the boot-seeded enrolled per-agent-key map.
///
/// Returns [`AuthLevel::KeyAuthenticated`] iff the presented api-key is an
/// enrolled per-agent key whose bound `agent_id` EQUALS `caller` (the header the
/// [`crate::handlers::api_key_auth`] middleware already bound to the key-derived
/// principal). Otherwise [`AuthLevel::Claimed`] — a shared-transport-key or
/// keyless caller whose `X-Agent-Id` is self-asserted. This is the level the
/// IDOR/admin gates consume; deriving it here (rather than trusting a header or
/// a caller-controlled field) keeps the principal keyed to a server-held secret.
#[must_use]
pub fn resolve_auth_level(
    enrolled: &std::collections::HashMap<String, String>,
    headers: &axum::http::HeaderMap,
    caller: &str,
) -> AuthLevel {
    if enrolled.is_empty() {
        return AuthLevel::Claimed;
    }
    let token = headers
        .get(crate::HEADER_API_KEY)
        .and_then(|v| v.to_str().ok());
    let Some(token) = token else {
        return AuthLevel::Claimed;
    };
    let hash = api_key_sha256_hex(token);
    match enrolled.get(&hash) {
        Some(agent_id) if agent_id == caller => AuthLevel::KeyAuthenticated,
        _ => AuthLevel::Claimed,
    }
}

/// #2044 — convenience wrapper: re-derive the caller's [`AuthLevel`] from the
/// request + enrolled map ([`resolve_auth_level`]) and apply the posture gate
/// ([`enforce_sensitive_identity`]) in one call. Returns `Some(403)` to refuse.
/// This is the single line every IDOR-sensitive read/mutate handler and
/// [`crate::handlers::admin_role::require_admin`] invokes.
#[must_use]
pub fn enforce_for_request(
    enrolled: &std::collections::HashMap<String, String>,
    mode: HttpIdentityMode,
    headers: &axum::http::HeaderMap,
    caller: &str,
    endpoint: &str,
) -> Option<Response> {
    let level = resolve_auth_level(enrolled, headers, caller);
    enforce_sensitive_identity(mode, level, caller, endpoint)
}

/// #2044 (v1.0.0, #2032-A / H1 IDOR) — the one-line IDOR gate for the
/// object-level read/mutate handlers (`GET/PUT/DELETE/promote /memories/{id}`).
/// Resolves the caller from the (middleware-bound) `X-Agent-Id` header and
/// applies [`enforce_for_request`]. Under `enforce`, a `Claimed` (shared-key)
/// caller acting as a NAMED principal is refused BEFORE the ownership /
/// visibility check — closing the cross-tenant IDOR where a shared-key holder
/// sets `X-Agent-Id: <victim>` to read/edit the victim's `scope=private` rows.
#[must_use]
pub fn enforce_idor_identity(
    enrolled: &std::collections::HashMap<String, String>,
    mode: HttpIdentityMode,
    headers: &axum::http::HeaderMap,
    endpoint: &str,
) -> Option<Response> {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());
    enforce_for_request(enrolled, mode, headers, &caller, endpoint)
}

/// #2044 — the shared IDOR/admin identity gate.
///
/// Consumed at the top of every IDOR-sensitive read/mutate handler and by
/// [`crate::handlers::admin_role::require_admin`]. Given the resolved posture,
/// the caller's re-derived [`AuthLevel`] (see [`resolve_auth_level`]), and the
/// `caller` id the handler is about to act as, returns:
///
///   * `None` — proceed (identity is acceptable for this posture);
///   * `Some(403)` — refuse (`enforce` posture, the caller is only `Claimed`
///     for an identity that is not the trivially-safe anonymous request id).
///
/// Under `advisory` (the v1.0.0 default) a `Claimed` sensitive caller is
/// ALLOWED but WARNed — inert + silent for a single-operator deployment because
/// `resolve_auth_level` returns `Claimed` and the anonymous/`==caller`
/// short-circuits fire. Under `off` the gate is a no-op.
#[must_use]
pub fn enforce_sensitive_identity(
    mode: HttpIdentityMode,
    level: AuthLevel,
    caller: &str,
    endpoint: &str,
) -> Option<Response> {
    if mode == HttpIdentityMode::Off {
        return None;
    }
    // A key-bound caller (a per-agent key whose bound agent_id == the header the
    // middleware already bound) is always acceptable — it proved possession of
    // this principal's server-held secret.
    if level.is_key_bound() {
        return None;
    }
    // A request-scoped anonymous id (`anonymous:req-…`) is not an assertion of
    // another agent's identity — it only ever sees non-private rows and owns
    // nothing durable, so it is never an IDOR/admin lever. Let it through in
    // both advisory and enforce (mirrors the create-path anonymous carve-out).
    if caller.starts_with(crate::identity::sentinels::ANONYMOUS_REQ_PREFIX) {
        return None;
    }
    match mode {
        HttpIdentityMode::Off => None,
        HttpIdentityMode::Advisory => {
            tracing::warn!(
                target: crate::handlers::AUTHZ_TRACE_TARGET,
                endpoint,
                caller,
                "#2044 advisory: request acts as named principal {caller:?} on \
                 {endpoint} without a per-agent-key attestation (X-Agent-Id is \
                 self-asserted). Enroll a per-agent api-key + set \
                 AI_MEMORY_HTTP_REQUIRE_ATTESTED_IDENTITY=enforce to refuse this."
            );
            None
        }
        HttpIdentityMode::Enforce => {
            tracing::warn!(
                target: crate::handlers::AUTHZ_TRACE_TARGET,
                endpoint,
                caller,
                "#2044 enforce: refused unattested named principal {caller:?} on {endpoint}"
            );
            Some(
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "attested_identity_required",
                        "message": "X-Agent-Id is self-asserted; present the agent's \
                                    enrolled per-agent api-key (X-API-Key) to act as \
                                    this principal",
                        "endpoint": endpoint,
                    })),
                )
                    .into_response(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_stable_and_hex() {
        let h = api_key_sha256_hex("hunter2");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls.
        assert_eq!(h, api_key_sha256_hex("hunter2"));
        assert_ne!(h, api_key_sha256_hex("hunter3"));
    }

    #[test]
    fn auth_level_ordering_and_key_bound() {
        assert!(AuthLevel::Claimed < AuthLevel::KeyAuthenticated);
        assert!(AuthLevel::KeyAuthenticated < AuthLevel::SignatureAttested);
        assert!(!AuthLevel::Claimed.is_key_bound());
        assert!(AuthLevel::KeyAuthenticated.is_key_bound());
        assert!(AuthLevel::SignatureAttested.is_key_bound());
    }

    #[test]
    fn off_mode_is_noop() {
        assert!(
            enforce_sensitive_identity(HttpIdentityMode::Off, AuthLevel::Claimed, "alice", "ep")
                .is_none()
        );
    }

    #[test]
    fn advisory_allows_claimed_named_principal() {
        // H1/M1 advisory posture: WARN but allow (default; inert for single-op).
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Advisory,
                AuthLevel::Claimed,
                "alice",
                "ep"
            )
            .is_none()
        );
    }

    #[test]
    fn enforce_refuses_claimed_named_principal() {
        // M1 regression: an unattested named principal is refused under enforce.
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Enforce,
                AuthLevel::Claimed,
                "alice",
                "ep"
            )
            .is_some()
        );
    }

    #[test]
    fn enforce_allows_key_bound_caller() {
        assert!(
            enforce_sensitive_identity(
                HttpIdentityMode::Enforce,
                AuthLevel::KeyAuthenticated,
                "alice",
                "ep"
            )
            .is_none()
        );
    }

    #[test]
    fn enforce_allows_anonymous_request_id() {
        let anon = format!(
            "{}deadbeef",
            crate::identity::sentinels::ANONYMOUS_REQ_PREFIX
        );
        assert!(
            enforce_sensitive_identity(HttpIdentityMode::Enforce, AuthLevel::Claimed, &anon, "ep")
                .is_none()
        );
    }

    #[test]
    fn resolve_auth_level_empty_map_is_claimed() {
        let map = std::collections::HashMap::new();
        let headers = axum::http::HeaderMap::new();
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::Claimed
        );
    }

    #[test]
    fn resolve_auth_level_matches_enrolled_key() {
        let mut map = std::collections::HashMap::new();
        map.insert(api_key_sha256_hex("alice-token"), "alice".to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            crate::HEADER_API_KEY,
            axum::http::HeaderValue::from_static("alice-token"),
        );
        // Key bound to alice, acting as alice → KeyAuthenticated.
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::KeyAuthenticated
        );
        // Same key, acting as bob → Claimed (cannot borrow alice's attestation).
        assert_eq!(
            resolve_auth_level(&map, &headers, "bob"),
            AuthLevel::Claimed
        );
    }

    #[test]
    fn resolve_auth_level_shared_key_is_claimed() {
        let mut map = std::collections::HashMap::new();
        map.insert(api_key_sha256_hex("alice-token"), "alice".to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            crate::HEADER_API_KEY,
            axum::http::HeaderValue::from_static("shared-global-key"),
        );
        assert_eq!(
            resolve_auth_level(&map, &headers, "alice"),
            AuthLevel::Claimed
        );
    }
}
