// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 federation security — peer attestation + scope-allowlist
//! substrate for `/api/v1/sync/push` and `/api/v1/sync/since`.
//!
//! ## Gap context (red-team #230, issues #238 + #239)
//!
//! - **#238** — `SyncPushBody::sender_agent_id` is a body-claimed
//!   identity. Pre-v0.7.0 the receiver logged it for audit and used
//!   it to charge per-agent quotas, but never attested it against
//!   anything. A peer with a valid mTLS cert could claim ANY
//!   `agent_id` in the body, defeating per-agent audit-trail
//!   integrity.
//! - **#239** — `/api/v1/sync/since` returned every memory newer
//!   than the watermark with no per-peer namespace scope. Compromise
//!   of one mTLS peer key exfiltrated the entire database.
//!
//! ## Substrate honesty (operator-must-read)
//!
//! The cryptographic anchor for "this connection is from an authorised
//! peer" today is the mTLS client-cert fingerprint pin
//! (`src/tls.rs::FingerprintAllowlistVerifier`). axum-server 0.8 does
//! **not** propagate the verified peer certificate (or its SAN/CN) to
//! axum handlers — there is no per-request extension that exposes the
//! rustls server connection. Closing that gap requires either a
//! non-trivial axum-server PR or a new x509-parser dependency wired
//! into a custom `ClientCertVerifier` that stashes per-connection
//! state. **That work was once planned for v0.8.0 but never landed; it
//! remains unimplemented as of v0.9.0**, still tracked under the
//! follow-up to issues #238/#239 in the PR body that landed this
//! module. Until it ships, the mTLS client-cert fingerprint pin remains
//! the sole cryptographic peer anchor.
//!
//! What this module DOES give v0.7.0:
//!
//! 1. A NEW required outbound header `x-peer-id` carrying the peer's
//!    self-claim of its `sender_agent_id`. The federation client
//!    (`src/federation/sync.rs::post_once`) attaches it on every
//!    outbound `/sync/push` and `/sync/since` request. The receiver
//!    cross-checks `body.sender_agent_id` against this header — the
//!    body field can no longer silently disagree with the wire-level
//!    peer-id without an explicit operator override.
//! 2. An operator-configured allowlist that binds **claimed peer-id**
//!    to **allowed sender_agent_ids** + **allowed namespaces**.
//!    Loaded from the env var `AI_MEMORY_FED_PEER_ATTESTATION` (JSON;
//!    see [`PeerAttestationConfig::from_env`] for the schema). Peers
//!    not in the allowlist still get a clear refusal envelope.
//! 3. Opt-in env bypasses so the live Mac Mini test cell and the
//!    DigitalOcean campaign keep working without config updates
//!    (`AI_MEMORY_FED_TRUST_BODY_AGENT_ID=1`,
//!    `AI_MEMORY_FED_SYNC_TRUST_PEER=1`).
//!
//! The end-to-end trust chain in v0.7.0 is therefore:
//!
//! ```text
//! Operator configures mTLS allowlist (fingerprints)
//!  └─ rustls verifies peer client cert at handshake
//!     └─ HTTP request reaches handler ONLY if cert was pinned
//!        └─ handler reads `x-peer-id` header (operator-bound to
//!           fingerprints via deployment runbook, NOT cryptographic-
//!           ally tied to the cert TODAY)
//!           └─ this module validates body.sender_agent_id /
//!              filters /sync/since projection.
//! ```
//!
//! The weak link is the operator-bound binding between fingerprint
//! and `x-peer-id`. v0.8.0 will replace that with the cert-SAN
//! attestation surface and remove this caveat.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Env var carrying the operator's per-peer attestation allowlist
/// (JSON). **Absent / empty** = genuine zero-config (faith-based
/// replication; [`PeerAttestationConfig::has_allowlist`] is false).
/// **Present but unparseable** = configured-broken posture (#2504):
/// `has_allowlist` is true with an empty peer map so destructive
/// inbound lanes fail closed rather than degrading to "trust everyone".
pub const PEER_ATTESTATION_ENV: &str = "AI_MEMORY_FED_PEER_ATTESTATION";

/// Env var that, when set to `"1"`, disables the #238 attestation
/// check and reverts `/sync/push` to its pre-v0.7.0 posture (accept
/// any body-claimed `sender_agent_id`). Backwards-compat for test
/// cells where the operator hasn't yet wired the allowlist.
pub const TRUST_BODY_AGENT_ID_ENV: &str = "AI_MEMORY_FED_TRUST_BODY_AGENT_ID";

/// Env var that, when set to `"1"`, disables the #239 namespace-
/// allowlist check and reverts `/sync/since` to its pre-v0.7.0
/// "full dump" posture. Backwards-compat for the v0.6.x federation
/// mesh and the live test cells that don't yet ship a peer-scope
/// allowlist.
pub const SYNC_TRUST_PEER_ENV: &str = "AI_MEMORY_FED_SYNC_TRUST_PEER";

/// HTTP header carrying the peer's self-claim of `sender_agent_id`.
/// Lowercase per the HTTP/2 wire convention; axum's `HeaderMap`
/// lookups are case-insensitive.
pub const PEER_ID_HEADER: &str = "x-peer-id";

/// Allowlist row for a single peer (keyed by claimed peer-id).
///
/// The `allowed_sender_agent_ids` field, when empty, is interpreted
/// as "peer may push memories where `body.sender_agent_id` equals
/// the peer-id itself" — the minimal-trust default for a peer that
/// only authors as itself. When non-empty, it overrides that default
/// and the list (exact strings, no glob) is the authoritative set of
/// `body.sender_agent_id` values the peer may claim.
///
/// `allowed_namespaces` follows the glob convention used elsewhere
/// in the codebase: `*` matches a single segment, `**` matches any
/// suffix. Empty = peer may not pull any namespace (default-deny).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerScope {
    /// Exact `body.sender_agent_id` values this peer may claim on
    /// `/sync/push`. Empty = only the peer-id itself.
    #[serde(default)]
    pub allowed_sender_agent_ids: Vec<String>,
    /// Glob patterns matched against `Memory::namespace` on
    /// `/sync/since`. Empty = peer may not pull any rows
    /// (default-deny) unless [`SYNC_TRUST_PEER_ENV`] is set.
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
}

/// Operator-configured federation peer-attestation map. Loaded from
/// the [`PEER_ATTESTATION_ENV`] env var as JSON:
///
/// ```json
/// {
///   "peer-node-1": {
///     "allowed_sender_agent_ids": ["ai:peer-node-1@host", "alice"],
///     "allowed_namespaces": ["public/*", "shared/team-x/**"]
///   },
///   "peer-node-2": {
///     "allowed_namespaces": ["public/*"]
///   }
/// }
/// ```
///
/// ## Zero-config vs present-but-broken (#2504)
///
/// - **Env unset / empty string** — genuine zero-config: `has_allowlist()` is
///   false; inbound write/delete lanes keep faith-based replication (#2491).
/// - **Env set to valid JSON (including `{}`)** — configured posture:
///   `has_allowlist()` is true. An empty peer map means no peer is enrolled
///   (fail closed for namespace + TOFU), **not** zero-config.
/// - **Env set but unparseable** — same as configured-with-empty-map for the
///   gate switch, so a typo cannot disable the federated-delete namespace
///   gate by falling through to zero-config (#2504).
#[derive(Clone, Debug, Default)]
pub struct PeerAttestationConfig {
    pub peers: HashMap<String, PeerScope>,
    /// #2504 — true when `AI_MEMORY_FED_PEER_ATTESTATION` was present
    /// (non-empty). Distinguishes Unset from `{}` / parse-error.
    env_present: bool,
}

/// Reason a body-claimed `sender_agent_id` failed attestation against
/// the wire-level `x-peer-id` header.
#[derive(Debug, Clone)]
pub enum AttestError {
    /// `x-peer-id` header absent AND env bypass NOT set. Caller
    /// should return 403.
    HeaderMissing,
    /// `x-peer-id` header present, body field present, no allowlist
    /// row exists for this peer-id, AND `body.sender_agent_id` does
    /// not equal the header. The peer is claiming an identity it has
    /// no operator-configured permission to claim.
    Mismatch {
        claimed: String,
        peer_header: String,
    },
}

impl AttestError {
    /// Stable machine-readable tag for the error envelope.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::HeaderMissing => "peer_id_header_missing",
            Self::Mismatch { .. } => "sender_agent_id_mismatch",
        }
    }
}

impl PeerAttestationConfig {
    /// Construct a configured allowlist (tests + programmatic loaders).
    /// Marks the config as **present** so `has_allowlist()` is true even
    /// when `peers` is empty (`{}` posture).
    #[must_use]
    pub fn from_peers(peers: HashMap<String, PeerScope>) -> Self {
        Self {
            peers,
            env_present: true,
        }
    }

    /// Load the allowlist from the [`PEER_ATTESTATION_ENV`] env var.
    ///
    /// - **Unset env** ([`VarError::NotPresent`](std::env::VarError::NotPresent))
    ///   → zero-config (`has_allowlist() == false`). This is the ONLY
    ///   zero-config path.
    /// - **Present but empty / whitespace-only** → documented-intentional
    ///   zero-config (F-2), with a one-shot WARN distinguishing it from a
    ///   genuine unset (the realistic producer is an unexpanded
    ///   `AI_MEMORY_FED_PEER_ATTESTATION="${FED_PEERS}"` shell reference).
    /// - **Valid JSON** (including `{}`) → configured posture (`has_allowlist()
    ///   == true`); empty peer map fails closed for enrollment.
    /// - **Parse error / unknown fields** → configured-broken (#2504): peers
    ///   empty but `has_allowlist() == true` so destructive lanes do **not**
    ///   degrade to faith-based replication. WARN states the real per-lane
    ///   consequence (delete is NOT default-deny under the old fallback).
    /// - **Present but not valid UTF-8**
    ///   ([`VarError::NotUnicode`](std::env::VarError::NotUnicode)) →
    ///   configured-broken (#2722), identical posture to a parse error. On
    ///   Linux env values are arbitrary bytes, so a mis-encoded (e.g. Latin-1)
    ///   `EnvironmentFile` reaches the daemon here; it MUST fail closed, not
    ///   silently disable the allowlist by falling through to zero-config.
    ///
    /// The `Err` arms are matched EXHAUSTIVELY (not via a catch-all `_`) so a
    /// future [`std::env::VarError`] variant is a compile error rather than a
    /// silent fall-through to zero-config (rust-skills `pat-exhaustive-enum`).
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(PEER_ATTESTATION_ENV) {
            // Present, non-empty value — valid JSON, `{}`, or a parse error
            // routed to the CONFIGURED-BROKEN posture (#2504).
            Ok(s) if !s.trim().is_empty() => Self::from_present_value(&s),
            // Present but empty / whitespace-only — documented-intentional
            // zero-config (F-2). Emit ONE informational WARN (deduped so a
            // per-request `from_env` — `federation_receive.rs` — does not
            // spam it) then fall through to zero-config.
            Ok(_) => {
                warn_present_but_empty_once();
                Self::default()
            }
            // #2722 — `std::env::var` returns `NotUnicode` when the variable
            // IS PRESENT but not valid UTF-8 (Linux env values are arbitrary
            // bytes). Route it into the SAME CONFIGURED-BROKEN branch as a
            // JSON parse error so a mis-encoded `EnvironmentFile` fails closed
            // (unenrolled peers refused; federated DELETE not wide-open)
            // instead of silently disabling the allowlist.
            Err(std::env::VarError::NotUnicode(_)) => {
                tracing::warn!(
                    target: "federation::peer_attestation",
                    env = PEER_ATTESTATION_ENV,
                    "peer-attestation env var is present but NOT valid UTF-8 \
                     — treating as CONFIGURED-BROKEN (#2722): confinement \
                     gates stay ON with an empty peer map (unenrolled peers \
                     refused; federated DELETE is NOT wide-open). Linux env \
                     values are arbitrary bytes — a mis-encoded (e.g. Latin-1) \
                     EnvironmentFile lands here. Fix the value's encoding (or \
                     remove the env var for genuine zero-config faith \
                     replication)."
                );
                Self::configured_broken()
            }
            // The ONLY zero-config path: the variable is genuinely unset.
            Err(std::env::VarError::NotPresent) => Self::default(),
        }
    }

    /// Parse a present, non-empty env value into a config. Valid JSON
    /// (including `{}`) yields the configured posture; a parse error / unknown
    /// field yields the CONFIGURED-BROKEN posture (#2504).
    fn from_present_value(s: &str) -> Self {
        match serde_json::from_str::<HashMap<String, PeerScope>>(s) {
            Ok(peers) => Self {
                peers,
                env_present: true,
            },
            Err(e) => {
                tracing::warn!(
                    target: "federation::peer_attestation",
                    env = PEER_ATTESTATION_ENV,
                    error = %e,
                    "failed to parse peer-attestation env var as JSON — \
                     treating as CONFIGURED-BROKEN (#2504): confinement \
                     gates stay ON with an empty peer map (unenrolled \
                     peers refused; federated DELETE is NOT wide-open). \
                     Fix the JSON (or remove the env var for genuine \
                     zero-config faith replication). deny_unknown_fields \
                     is enabled on PeerScope — typo'd keys fail here too."
                );
                Self::configured_broken()
            }
        }
    }

    /// #2504 / #2722 — env was present but yielded no usable peer map (parse
    /// error, unknown field, or non-UTF-8 bytes). `has_allowlist()` stays
    /// true with an empty peer map so destructive inbound lanes fail closed
    /// rather than degrading to "trust everyone".
    fn configured_broken() -> Self {
        Self {
            peers: HashMap::new(),
            env_present: true,
        }
    }

    /// Lookup scope for a claimed peer-id. Returns `None` when the
    /// operator has not configured any row for this peer.
    #[must_use]
    pub fn scope_for(&self, peer_id: &str) -> Option<&PeerScope> {
        self.peers.get(peer_id)
    }

    /// Whether the operator has an **active** peer-attestation config.
    ///
    /// - **false** only for genuine zero-config (env unset/empty AND no
    ///   programmatic peers) — handlers use faith-based replication.
    /// - **true** when the env var was present (even if JSON was `{}` or
    ///   unparseable — #2504) OR when peers were supplied programmatically.
    ///
    /// #1056 TOFU and #2447/#2488 namespace confinement both key off this
    /// switch; #2504 ensures a typo cannot flip it to false.
    #[must_use]
    pub fn has_allowlist(&self) -> bool {
        self.env_present || !self.peers.is_empty()
    }

    /// #2504 — env was present but peers are empty (parse error or `{}`).
    #[must_use]
    pub fn is_configured_empty(&self) -> bool {
        self.env_present && self.peers.is_empty()
    }
}

/// Emit the "present but empty" zero-config WARN at most once per process.
///
/// F-2 — `from_env` is called per inbound push (`federation_receive.rs`), so a
/// naive `tracing::warn!` would fire on every request; the [`std::sync::Once`]
/// guard collapses it to a single informational line. The present-but-empty
/// case is documented-intentional zero-config, so — unlike the CONFIGURED-BROKEN
/// security WARNs (parse error / #2722 non-UTF-8), which stay per-call to keep
/// the misconfiguration loud — this benign notice is deduped.
fn warn_present_but_empty_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "federation::peer_attestation",
            env = PEER_ATTESTATION_ENV,
            "peer-attestation env var is present but empty / whitespace-only \
             — treating as ZERO-CONFIG faith-based replication \
             (has_allowlist() == false). If you meant to enrol peers, the \
             value is likely an unexpanded shell reference (e.g. \
             AI_MEMORY_FED_PEER_ATTESTATION=\"${{FED_PEERS}}\" with FED_PEERS \
             unset): set it to the JSON allowlist, or remove it entirely to \
             silence this notice."
        );
    });
}

/// Whether the operator has explicitly opted out of #238 attestation
/// (legacy behaviour: trust the body field).
#[must_use]
pub fn trust_body_agent_id_bypass() -> bool {
    matches!(std::env::var(TRUST_BODY_AGENT_ID_ENV).as_deref(), Ok("1"))
}

/// Whether the operator has explicitly opted out of #239 scope
/// filtering (legacy behaviour: full database dump per peer).
#[must_use]
pub fn sync_trust_peer_bypass() -> bool {
    matches!(std::env::var(SYNC_TRUST_PEER_ENV).as_deref(), Ok("1"))
}

/// #238 attestation core.
///
/// Validates that the body-claimed `sender_agent_id` is one this
/// peer (identified by the `x-peer-id` header) is operator-permitted
/// to claim.
///
/// Decision matrix:
///
/// | `peer_header` | `body_sender`         | allowlist row | result            |
/// |---------------|-----------------------|---------------|-------------------|
/// | `None`        | any                   | n/a           | [`AttestError::HeaderMissing`] |
/// | `Some(p)`     | `None` or empty       | n/a           | Ok (legacy unauthored push) |
/// | `Some(p)`     | `Some(s)` where `s == p` | n/a        | Ok (peer authoring as itself) |
/// | `Some(p)`     | `Some(s)` where `s != p` | None        | [`AttestError::Mismatch`] |
/// | `Some(p)`     | `Some(s)` where `s != p` | Some(scope), `s ∈ scope.allowed_sender_agent_ids` | Ok |
/// | `Some(p)`     | `Some(s)` where `s != p` | Some(scope), `s ∉ scope.allowed_sender_agent_ids` | [`AttestError::Mismatch`] |
///
/// `body_sender == Some("")` is treated as `None` to match the wire
/// reality (federation clients pre-v0.7.0 sometimes serialise the
/// field as the empty string instead of omitting it).
///
/// # Errors
///
/// Returns [`AttestError`] when the attestation contract is violated;
/// callers should render 403 with a structured error envelope.
pub fn attest_sender(
    peer_header: Option<&str>,
    body_sender: Option<&str>,
    config: &PeerAttestationConfig,
) -> Result<(), AttestError> {
    let peer = match peer_header.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => p,
        None => return Err(AttestError::HeaderMissing),
    };
    let claimed = match body_sender.map(str::trim).filter(|s| !s.is_empty()) {
        Some(c) => c,
        // Legacy push with no body claim — peer is implicitly authoring as itself.
        None => return Ok(()),
    };
    if claimed == peer {
        return Ok(());
    }
    if let Some(scope) = config.scope_for(peer)
        && scope
            .allowed_sender_agent_ids
            .iter()
            .any(|a| a.as_str() == claimed)
    {
        return Ok(());
    }
    Err(AttestError::Mismatch {
        claimed: claimed.to_string(),
        peer_header: peer.to_string(),
    })
}

/// Glob match used by [`namespace_allowed`] — supports `*` (single
/// segment) and `**` (any suffix). Mirrors the convention used
/// elsewhere in the codebase (governance rules, allowlist patterns).
/// Pure-function ASCII glob; no regex engine to avoid a new dep.
///
/// Re-exported as [`namespace_allowed_test_glob`] for callers that
/// need to drive the per-pattern decision directly (the `sync_since`
/// handler iterates the scope's pattern list itself so the
/// `excluded_for_scope` count stays accurate against the pre-filter
/// projection).
#[must_use]
pub fn namespace_allowed_test_glob(pattern: &str, target: &str) -> bool {
    glob_match(pattern, target)
}

#[must_use]
fn glob_match(pattern: &str, target: &str) -> bool {
    // `**` is the only match-all token. A bare `*` matches exactly ONE
    // top-level segment (#1902) — matching it against any target would
    // silently widen a `["*"]` allowlist to the entire namespace tree,
    // defeating the #239 per-peer scope control.
    if pattern == "**" {
        return true;
    }
    if pattern == "*" {
        return !target.contains('/');
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        // `prefix/**` matches `prefix` itself OR anything starting with `prefix/`.
        return target == prefix || target.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // `prefix/*` matches exactly one path-segment after `prefix/`.
        if let Some(rest) = target.strip_prefix(&format!("{prefix}/")) {
            return !rest.contains('/');
        }
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*/") {
        // `*/suffix` matches exactly one path-segment before `/suffix`.
        if let Some(rest) = target.strip_suffix(&format!("/{suffix}")) {
            return !rest.contains('/');
        }
        return false;
    }
    pattern == target
}

/// #239 scope-filter core.
///
/// Returns `true` when `namespace` is allowed for the peer identified
/// by `peer_header`. Decision matrix:
///
/// | `peer_header` | scope row    | bypass env | result |
/// |---------------|--------------|------------|--------|
/// | `None`        | n/a          | unset      | false (default-deny) |
/// | `None`        | n/a          | set        | true (legacy full dump) |
/// | `Some(p)`     | None         | unset      | false (default-deny) |
/// | `Some(p)`     | None         | set        | true (legacy full dump) |
/// | `Some(p)`     | Some(scope)  | unset/set  | true iff any pattern in `scope.allowed_namespaces` matches `namespace` |
///
/// The bypass env (`AI_MEMORY_FED_SYNC_TRUST_PEER=1`) ONLY widens
/// the "no scope row" case; once a scope row exists for the peer,
/// its namespace list is the authoritative gate and the bypass is
/// ignored (operator's explicit allowlist wins over the legacy
/// override).
#[must_use]
pub fn namespace_allowed(
    peer_header: Option<&str>,
    namespace: &str,
    config: &PeerAttestationConfig,
) -> bool {
    let Some(peer) = peer_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return sync_trust_peer_bypass();
    };
    match config.scope_for(peer) {
        Some(scope) => scope
            .allowed_namespaces
            .iter()
            .any(|p| glob_match(p, namespace)),
        None => sync_trust_peer_bypass(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rows: &[(&str, PeerScope)]) -> PeerAttestationConfig {
        let peers = rows
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        PeerAttestationConfig::from_peers(peers)
    }

    // ---- attest_sender ---------------------------------------------------

    #[test]
    fn attest_header_missing_errors() {
        let cfg = PeerAttestationConfig::default();
        let err = attest_sender(None, Some("alice"), &cfg).unwrap_err();
        assert!(matches!(err, AttestError::HeaderMissing));
        assert_eq!(err.tag(), "peer_id_header_missing");
    }

    #[test]
    fn attest_header_empty_treated_as_missing() {
        let cfg = PeerAttestationConfig::default();
        let err = attest_sender(Some("   "), Some("alice"), &cfg).unwrap_err();
        assert!(matches!(err, AttestError::HeaderMissing));
    }

    #[test]
    fn attest_body_missing_passes_legacy_unauthored() {
        // No body-claimed sender + peer header present = legacy pre-v0.7.0
        // peer that didn't author rows. Accept.
        let cfg = PeerAttestationConfig::default();
        attest_sender(Some("peer-1"), None, &cfg).unwrap();
        attest_sender(Some("peer-1"), Some(""), &cfg).unwrap();
    }

    #[test]
    fn attest_self_authoring_passes() {
        let cfg = PeerAttestationConfig::default();
        attest_sender(Some("peer-1"), Some("peer-1"), &cfg).unwrap();
    }

    #[test]
    fn attest_mismatch_no_allowlist_errors() {
        let cfg = PeerAttestationConfig::default();
        let err = attest_sender(Some("peer-1"), Some("alice"), &cfg).unwrap_err();
        match err {
            AttestError::Mismatch {
                claimed,
                peer_header,
            } => {
                assert_eq!(claimed, "alice");
                assert_eq!(peer_header, "peer-1");
            }
            other => panic!("expected Mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn attest_mismatch_with_matching_allowlist_passes() {
        let cfg = cfg(&[(
            "peer-1",
            PeerScope {
                allowed_sender_agent_ids: vec!["alice".to_string(), "bob".to_string()],
                ..PeerScope::default()
            },
        )]);
        attest_sender(Some("peer-1"), Some("alice"), &cfg).unwrap();
        attest_sender(Some("peer-1"), Some("bob"), &cfg).unwrap();
    }

    #[test]
    fn attest_mismatch_outside_allowlist_errors() {
        let cfg = cfg(&[(
            "peer-1",
            PeerScope {
                allowed_sender_agent_ids: vec!["alice".to_string()],
                ..PeerScope::default()
            },
        )]);
        let err = attest_sender(Some("peer-1"), Some("eve"), &cfg).unwrap_err();
        assert!(matches!(err, AttestError::Mismatch { .. }));
    }

    // ---- glob_match -----------------------------------------------------

    #[test]
    fn glob_wildcard_all() {
        // `**` is the only match-all token.
        assert!(glob_match("**", "anything"));
        assert!(glob_match("**", "anything/even/nested"));
        // A bare `*` matches exactly ONE top-level segment, NOT nested paths
        // (#1902 — a `["*"]` allowlist must not silently grant the whole tree).
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("*", "anything/nested"));
        assert!(!glob_match("*", "a/b/c"));
    }

    #[test]
    fn glob_prefix_double_star() {
        assert!(glob_match("public/**", "public"));
        assert!(glob_match("public/**", "public/a"));
        assert!(glob_match("public/**", "public/a/b/c"));
        assert!(!glob_match("public/**", "private"));
        assert!(!glob_match("public/**", "publicx"));
    }

    #[test]
    fn glob_prefix_single_star() {
        assert!(glob_match("public/*", "public/foo"));
        assert!(!glob_match("public/*", "public/foo/bar"));
        assert!(!glob_match("public/*", "public"));
    }

    #[test]
    fn glob_suffix_single_star() {
        assert!(glob_match("*/notes", "alice/notes"));
        assert!(!glob_match("*/notes", "alice/team/notes"));
        assert!(!glob_match("*/notes", "notes"));
    }

    #[test]
    fn glob_exact_literal() {
        assert!(glob_match("ai-memory-mcp", "ai-memory-mcp"));
        assert!(!glob_match("ai-memory-mcp", "ai-memory"));
    }

    // ---- namespace_allowed ----------------------------------------------

    #[test]
    fn namespace_no_header_no_bypass_denies() {
        // Make sure no test contamination from env vars.
        // SAFETY: the value cleared belongs to this test only;
        // serial-by-default cargo test isolation is sufficient.
        unsafe { std::env::remove_var(SYNC_TRUST_PEER_ENV) };
        let cfg = PeerAttestationConfig::default();
        assert!(!namespace_allowed(None, "any", &cfg));
        assert!(!namespace_allowed(Some(""), "any", &cfg));
    }

    #[test]
    fn namespace_match_via_glob() {
        let cfg = cfg(&[(
            "peer-1",
            PeerScope {
                allowed_namespaces: vec!["public/*".to_string(), "shared/team-x/**".to_string()],
                ..PeerScope::default()
            },
        )]);
        assert!(namespace_allowed(Some("peer-1"), "public/foo", &cfg));
        assert!(namespace_allowed(Some("peer-1"), "shared/team-x/a/b", &cfg));
        assert!(!namespace_allowed(Some("peer-1"), "private/foo", &cfg));
        assert!(!namespace_allowed(Some("peer-1"), "public/foo/bar", &cfg));
    }

    #[test]
    fn namespace_no_scope_row_denies_without_bypass() {
        unsafe { std::env::remove_var(SYNC_TRUST_PEER_ENV) };
        let cfg = PeerAttestationConfig::default();
        assert!(!namespace_allowed(Some("peer-1"), "any", &cfg));
    }

    // ---- PeerAttestationConfig::from_env --------------------------------
    //
    // These three tests all mutate the process-wide PEER_ATTESTATION_ENV
    // env var, so they MUST be serialised against each other under
    // `cargo test --test-threads=N` (N >= 2). Without the shared mutex
    // one test's set_var races another test's remove_var and the
    // assertion non-deterministically observes the wrong configuration.
    // The Coverage CI gate caught this at `--test-threads=2`:
    // `from_env_parse_error_is_empty` saw a valid JSON payload from a
    // concurrent `from_env_parses_valid_json` and failed
    // `cfg.peers.is_empty()`. Same idiom as the rules-store guard.

    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn from_env_absent_is_empty() {
        let _g = lock_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        let cfg = PeerAttestationConfig::from_env();
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn has_allowlist_false_when_zero_config_1056() {
        // v0.7.0 #1056 — zero-config (no env var) means no allowlist,
        // so `has_allowlist()` returns false and the federation
        // handlers fall through to the legacy permissive posture.
        let _g = lock_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        let cfg = PeerAttestationConfig::from_env();
        assert!(
            !cfg.has_allowlist(),
            "#1056: zero-config PeerAttestationConfig MUST report has_allowlist()=false"
        );
    }

    #[test]
    fn has_allowlist_true_when_peers_enrolled_1056() {
        // v0.7.0 #1056 — once an operator enrols at least one peer,
        // `has_allowlist()` flips to true, and the federation
        // handlers' TOFU gate refuses any x-peer-id NOT in the map.
        let _g = lock_env();
        let body = r#"{"enrolled-peer": {"allowed_namespaces": ["ns/*"]}}"#;
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, body) };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(
            cfg.has_allowlist(),
            "#1056: configured PeerAttestationConfig MUST report has_allowlist()=true"
        );
        assert!(cfg.scope_for("enrolled-peer").is_some());
        assert!(
            cfg.scope_for("not-in-map").is_none(),
            "#1056: unknown peer MUST return None (handlers refuse)"
        );
    }

    #[test]
    fn from_env_parses_valid_json() {
        let _g = lock_env();
        let body = r#"{
            "peer-1": {
                "allowed_sender_agent_ids": ["alice", "bob"],
                "allowed_namespaces": ["public/*"]
            }
        }"#;
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, body) };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        let scope = cfg.scope_for("peer-1").expect("peer-1 row present");
        assert_eq!(scope.allowed_sender_agent_ids, vec!["alice", "bob"]);
        assert_eq!(scope.allowed_namespaces, vec!["public/*"]);
    }

    #[test]
    fn from_env_parse_error_is_empty_but_has_allowlist_2504() {
        let _g = lock_env();
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, "not json{{") };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(cfg.peers.is_empty(), "parse error yields no peer rows");
        assert!(
            cfg.has_allowlist(),
            "#2504: parse error MUST NOT degrade to zero-config has_allowlist=false"
        );
        assert!(cfg.is_configured_empty());
    }

    #[test]
    fn from_env_empty_object_is_configured_not_zero_config_2504() {
        let _g = lock_env();
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, "{}") };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(cfg.peers.is_empty());
        assert!(
            cfg.has_allowlist(),
            "#2504 X9d: `{{}}` is present config — fail closed, not faith replication"
        );
    }

    #[test]
    fn from_env_typo_scope_key_is_parse_error_2504() {
        // X9e — misspelled `allowed_namespace` (singular) used to serde-default
        // into enrolled-unscoped with no warning. deny_unknown_fields refuses it.
        let _g = lock_env();
        let body = r#"{"peer-1": {"allowed_namespace": ["public/*"]}}"#;
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, body) };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(
            cfg.peers.is_empty() && cfg.has_allowlist(),
            "#2504 X9e: typo'd PeerScope key must fail closed, not silent unscoped enroll"
        );
    }

    #[test]
    fn parse_error_does_not_namespace_allow_any_peer_2504() {
        let _g = lock_env();
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, "{not-json") };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(
            !namespace_allowed(Some("stranger"), "secure/ops", &cfg),
            "#2504: under parse-error posture no peer may pull/delete out-of-map"
        );
    }

    #[test]
    fn from_env_present_but_empty_is_zero_config_f2() {
        // F-2 — a present-but-empty value (the realistic
        // `AI_MEMORY_FED_PEER_ATTESTATION="${FED_PEERS}"`-with-FED_PEERS-unset
        // producer) is documented-intentional zero-config: it must NOT flip
        // into the configured-broken posture, so `has_allowlist()` stays false
        // and the handlers keep faith-based replication.
        let _g = lock_env();
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, "   ") };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(cfg.peers.is_empty());
        assert!(
            !cfg.has_allowlist(),
            "F-2: present-but-empty env is zero-config, has_allowlist()=false"
        );
        assert!(!cfg.is_configured_empty());
    }

    // #2722 — `std::env::var` returns `Err(VarError::NotUnicode(_))` when the
    // variable IS PRESENT but not valid UTF-8. On Linux env values are
    // arbitrary bytes, so a mis-encoded (e.g. Latin-1) EnvironmentFile with a
    // single non-ASCII byte reaches the daemon here. Before the fix that
    // landed in the `_` arm alongside `NotPresent` and silently disabled the
    // allowlist (env_present=false → federated-delete confinement OFF, TOFU
    // OFF, faith-based attribution ON) — quieter than the parse-error case
    // #2504 was written to fix. The fix routes it to CONFIGURED-BROKEN.
    #[cfg(unix)]
    #[test]
    fn from_env_non_utf8_is_configured_broken_2722() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let _g = lock_env();
        // 0xFF is never a valid UTF-8 byte on its own, so this OsStr is a
        // present-but-non-UTF-8 value → VarError::NotUnicode from `env::var`.
        let non_utf8 = OsStr::from_bytes(&[b'{', 0xFF, b'}']);
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, non_utf8) };
        // Guard the invariant this test relies on: the value really is
        // non-UTF-8 (so `env::var` yields NotUnicode, not Ok).
        assert!(
            matches!(
                std::env::var(PEER_ATTESTATION_ENV),
                Err(std::env::VarError::NotUnicode(_))
            ),
            "#2722 fixture must be present-but-non-UTF-8 (VarError::NotUnicode)"
        );
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(cfg.peers.is_empty(), "#2722: non-UTF-8 yields no peer rows");
        assert!(
            cfg.has_allowlist(),
            "#2722: non-UTF-8 env MUST fail closed (has_allowlist()=true), \
             NOT silently degrade to zero-config"
        );
        assert!(
            cfg.is_configured_empty(),
            "#2722: non-UTF-8 env is the configured-broken (env_present) posture"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_env_refuses_out_of_map_peer_2722() {
        // The security-relevant consequence: under the non-UTF-8
        // configured-broken posture, the delete/pull lanes must refuse a
        // peer that is not in the (empty) map — NOT fall through to the
        // pre-#2504 faith-based allow.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let _g = lock_env();
        unsafe { std::env::remove_var(SYNC_TRUST_PEER_ENV) };
        let non_utf8 = OsStr::from_bytes(&[0xFE, 0xFF]);
        unsafe { std::env::set_var(PEER_ATTESTATION_ENV, non_utf8) };
        let cfg = PeerAttestationConfig::from_env();
        unsafe { std::env::remove_var(PEER_ATTESTATION_ENV) };
        assert!(
            !namespace_allowed(Some("stranger"), "secure/ops", &cfg),
            "#2722: under non-UTF-8 configured-broken posture no peer may \
             pull/delete out-of-map"
        );
    }
}
