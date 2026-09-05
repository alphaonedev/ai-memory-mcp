// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP handler module index. Per-domain handler code lives in the
//! sibling sub-modules; this file is the public-facing re-export
//! surface plus the inline test scaffolding.
//!
//! Issue #650 history: the original `src/handlers.rs` was an 18 574-line
//! monolith. The first split (commit `7f3f676`) carved off
//! `federation_receive`, `hook_subscribers`, `http`, and `transport`.
//! The follow-up split (2026-05-18) closed the remaining ≤1200 LOC cap
//! by extracting per-domain modules for the four still-oversize files
//! (`http`, `transport`, `federation_receive`, `hook_subscribers`,
//! `power`) into focused siblings.
//!
//! Sub-modules:
//!
//! - [`transport`]   — `AppState`, `Db`, `JsonOrBadRequest`, auth
//!   middleware, shared constants (`MAX_BULK_SIZE`,
//!   `BULK_FANOUT_CONCURRENCY`), low-level helpers, health, metrics.
//! - [`postgres_gate`] — `#[cfg(feature = "sal")]` postgres
//!   route-matrix + middleware + `store_err_to_response` sanitiser.
//! - [`http`]        — `auto_tag_eligible` + `try_enqueue_auto_tag` +
//!   `maybe_detect_conflicts` + `ConflictReport` (the LLM hooks the
//!   create path consumes; `auto_tag` itself runs on the bounded
//!   background worker, `crate::background::auto_tag_worker`, #2587).
//! - [`create`]      — `POST /api/v1/memories` create-path orchestrator
//!   + six stage helpers + postgres branch.
//! - [`memories`]    — memory CRUD (`get`/`update`/`delete`/`promote`).
//! - [`memories_query`] — list / search / forget / bulk_create.
//! - [`federation_receive`] — federation receive-side `sync_push` body +
//!   helpers (clock skew, quota attribution, peer-id extraction).
//! - [`federation_signing_check`] — `#[cfg(feature = "sal")]`
//!   `sync_push_via_store` postgres-receive branch + per-message
//!   Ed25519 signature verification (#791).
//! - [`federation_sync_since`] — federation `/sync/since` GET pull.
//! - [`hook_subscribers`]   — inbox + namespace standard handlers +
//!   session-start.
//! - [`subscriptions`] — notify + subscribe + unsubscribe +
//!   list_subscriptions.
//! - [`power`]       — taxonomy / contradictions / list_namespaces /
//!   check_duplicate (non-LLM power-tier reads).
//! - [`power_consolidation`] — consolidate + auto_tag + expand_query +
//!   load_family (LLM-backed power-tier writes).
//! - [`errors`]      — issue #851 HTTP error-sanitization helpers.
//! - [`system`]      — `/api/v1/capabilities` and system reads.
//! - [`parity`]      — cross-cutting HTTP-parity helpers.
//! - [`approvals`]   — v0.7.0 K10 approval API.

/// Tracing target for HTTP-layer authorization (ownership-gate /
/// caller-resolution) denials, shared across the handler sub-modules
/// (#1558 tracing-target SSOT).
pub(crate) const AUTHZ_TRACE_TARGET: &str = "ai_memory::authz";

/// `tracing` target for HTTP authentication events (`api_key_auth` middleware,
/// #2044 per-agent-key boot-seed). One SSOT const per the pm-v3.1 no-hardcoded-
/// literal gate.
pub(crate) const HTTP_AUTH_TRACE_TARGET: &str = "http::auth";

/// #1558 batch 5 wave 3 — `quota_refused` count field on the
/// federation `/sync/push` response envelope (sqlite + postgres
/// arms, quota-413 + success shapes). One spelling across the four
/// production emit sites in `federation_receive` /
/// `federation_signing_check`.
pub(crate) const QUOTA_REFUSED_FIELD: &str = "quota_refused";

/// #2341 (W1A2-01/02) — `skipped` count field on the federation
/// `/sync/push` response envelope (sqlite + postgres arms). Shared with
/// the sender-side ack classifier
/// (`crate::federation::sync::success_report_non_ack_reason`) so the
/// receiver report and the quorum/DLQ ack decision cannot drift apart.
pub(crate) const SKIPPED_FIELD: &str = "skipped";

/// Per-memory attestation refusals in both federation push response paths (#3502).
pub(crate) const ATTESTATION_REJECTIONS_FIELD: &str = "attestation_rejections";

/// #2341 (W1A2-01/02) — `unsupported_on_postgres` count field on the
/// postgres federation `/sync/push` response envelope (the FED-RQ-01
/// honest count of subcollections the pg receiver cannot apply). Shared
/// with the sender-side ack classifier for the same no-drift reason as
/// [`SKIPPED_FIELD`].
pub(crate) const UNSUPPORTED_ON_POSTGRES_FIELD: &str = "unsupported_on_postgres";

/// #1789 — ONE shared test lock serialising every test that mutates the
/// federation peer-enrollment env vars
/// (`AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`,
/// `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS`). Both the strict enrollment
/// tests in [`federation_signing_check`] and the permissive-opt-back
/// guard used by the `tests` module's `http_sync_*` handler tests
/// acquire THIS lock, so a parallel Check-matrix run can never leak the
/// flipped secure-default (#1789 default-ON enrollment) across the two
/// test sets. Promoted to `pub(crate)` from the former module-private
/// `federation_signing_check::verify_arm_tests::env_lock()` so there is
/// a single serialisation point, not two independent locks.
#[cfg(test)]
pub(crate) fn fed_env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub mod accept_provenance;
pub mod admin;
pub mod admin_role;
pub mod agent_api_key;
pub mod approvals;
pub mod archive;
pub mod bulk;
pub mod capture_turn;
pub mod consolidate_federation;
pub mod coordination;
pub mod create;
pub mod errors;
pub mod federation_receive;
pub mod federation_signing_check;
pub mod federation_sync_since;
pub mod governance;
pub mod hook_subscribers;
pub mod http;
pub mod identity_binding;
/// v1.0.0 #3465 — `GET /api/v1/inbox/stream`, the agent-facing SSE
/// wake stream for `memory_notify` (identity-bound to the caller's own
/// inbox, fed from the in-process wake bus, never the webhook lane).
pub mod inbox_stream;
/// #3343 — bounded projections for GET /api/v1/stats and /namespaces.
pub mod inventory;
pub mod kg;
pub mod links;
pub mod memories;
pub mod memories_query;
pub mod parity;
pub mod postgres_gate;
pub mod power;
pub mod power_consolidation;
/// v1.0.0 #2402 — admin-gated operator quarantine inspect/release surface.
pub mod quarantine;
/// #1580 — WAL read-pool for the HTTP SQLite read path.
pub mod read_pool;
pub mod recall;
/// v0.7.0 #1111 — 14 missing HTTP routes for the MCP-only tools the
/// SR-4 three-surface-parity audit flagged. Each handler is a thin
/// wrapper around the existing `crate::mcp::handle_<name>` substrate
/// primitive; wire envelopes are byte-equal across the two surfaces.
pub mod route_1111;
/// #1558 batch 4 — HTTP route-path SSOT: one named const per
/// production route; registration (lib.rs) and match sites
/// (postgres_gate, federation receive, CLI doctor) share them.
pub mod routes;
pub mod share;
pub mod skills;
pub mod subscriptions;
pub mod system;
pub mod transport;
// #1579 B4 — HTTP response-format negotiation (json | toon |
// toon_compact) for the recall/search surfaces.
pub mod wire_format;

// Re-export the public-facing handler surface so external callers
// (router wiring in `src/lib.rs`, integration tests) can still
// reference `handlers::<name>` without knowing which sub-module the
// item came from. Wire compatibility is preserved verbatim.
pub use admin::*;
pub use admin_role::*;
pub use approvals::*;
pub use archive::*;
pub use bulk::*;
pub use capture_turn::*;
pub use coordination::*;
pub use create::*;
pub use errors::*;
pub use federation_receive::*;
pub use federation_sync_since::*;
pub use governance::*;
pub use hook_subscribers::*;
pub use http::*;
pub use inbox_stream::*;
pub use kg::*;
pub use links::*;
pub use memories::*;
pub use memories_query::*;
pub(crate) use parity::*;
#[cfg(feature = "sal")]
pub use postgres_gate::*;
pub use power::*;
pub use power_consolidation::*;
pub use quarantine::*;
pub use recall::*;
pub use route_1111::*;
pub use share::*;
pub use skills::*;
pub use subscriptions::*;
pub use system::*;
pub use transport::*;

/// v0.9.0 G10.1 (#1827) — parse the optional `X-AI-Memory-Capability`
/// header ONCE at the HTTP edge into a macaroon capability token. Inert
/// (`Ok(None)`, zero audit bytes) when the header is absent or
/// `[capabilities].enabled = false`.
///
/// FAIL-CLOSED (behaviour change): a PRESENTED-but-unparseable header is
/// now `Err(403 GOVERNANCE_REFUSED)` instead of being downgraded to `None`
/// / "the bare ACL decides". Omitting the header is unchanged.
///
/// # Errors
///
/// Returns a ready-to-return `403 FORBIDDEN` [`axum::response::Response`]
/// when a non-blank `X-AI-Memory-Capability` header failed to parse.
pub(crate) fn capability_from_headers(
    headers: &axum::http::HeaderMap,
    actor: &str,
) -> std::result::Result<
    Option<crate::governance::capability::CapabilityToken>,
    axum::response::Response,
> {
    use axum::response::IntoResponse as _;
    let presented = match headers.get(crate::governance::capability::HTTP_CAPABILITY_HEADER) {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                // Fable HIGH (#3133): a PRESENTED non-UTF-8 header used to
                // collapse via `to_str().ok()` to `None` = absent = bare ACL
                // — the exact fail-open `parse_presented_token` closed for
                // unparseable tokens. A garbled credential is never
                // "omitted"; refuse 403. The `enabled=false` short-circuit
                // applies to a decodeable-but-ignored credential, not to an
                // undecodable one.
                tracing::warn!(
                    target: crate::governance::GOVERNANCE_TRACE_TARGET,
                    actor = %actor,
                    "capability header presented but is not valid UTF-8; \
                     REFUSING (fail-closed: a presented-but-unusable \
                     credential is never downgraded to anonymous)"
                );
                crate::governance::audit::record_decision(
                    actor,
                    "deny",
                    crate::governance::capability::AUDIT_KIND_REJECT,
                    crate::governance::capability::CapReject::Malformed.code(),
                    serde_json::json!({ "stage": "edge-parse", "cause": "non-utf8-header" }),
                );
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "code": crate::errors::error_codes::GOVERNANCE_REFUSED,
                        "error": crate::governance::capability::edge_reject_message(
                            &crate::governance::capability::CapReject::Malformed,
                        ),
                    })),
                )
                    .into_response());
            }
        },
    };
    crate::governance::capability::parse_presented_token(presented, actor).map_err(|rej| {
        (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "code": crate::errors::error_codes::GOVERNANCE_REFUSED,
                "error": crate::governance::capability::edge_reject_message(&rej),
            })),
        )
            .into_response()
    })
}

#[cfg(test)]
mod capability_from_headers_tests {
    use super::capability_from_headers;
    use crate::governance::capability::{CapabilityConfig, HTTP_CAPABILITY_HEADER};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use std::collections::BTreeMap;

    fn headers_with(value: HeaderValue) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HTTP_CAPABILITY_HEADER, value);
        headers
    }

    fn enabled_cfg() -> CapabilityConfig {
        CapabilityConfig {
            enabled: true,
            issuers: BTreeMap::new(),
        }
    }

    fn disabled_cfg() -> CapabilityConfig {
        CapabilityConfig {
            enabled: false,
            issuers: BTreeMap::new(),
        }
    }

    /// Fable HIGH (#3133): a PRESENTED non-UTF-8 capability header must
    /// 403, never collapse to "absent = bare ACL".
    #[test]
    fn presented_non_utf8_capability_header_is_403() {
        let headers =
            headers_with(HeaderValue::from_bytes(&[0x80, 0x81]).expect("raw header bytes"));
        let err = capability_from_headers(&headers, "test-actor")
            .expect_err("non-UTF-8 presented credential must FAIL CLOSED");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    /// Omitted header is the documented inert path (`Ok(None)`), even when
    /// the master switch is on — a capability-LESS caller stays on the
    /// bare ACL (R9 #1960 additive-only).
    #[test]
    fn absent_header_is_ok_none() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::set_active_capability_config(enabled_cfg());
        let got = capability_from_headers(&HeaderMap::new(), "test-actor")
            .expect("omitted header must not refuse");
        assert!(got.is_none(), "absent header must stay Ok(None)");
        crate::config::clear_capability_config_for_test();
    }

    /// Whitespace-only UTF-8 is equivalent to omitted (trim+empty filter
    /// in `parse_presented_token`); never a 403.
    #[test]
    fn blank_utf8_header_is_ok_none() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::set_active_capability_config(enabled_cfg());
        let got =
            capability_from_headers(&headers_with(HeaderValue::from_static("   ")), "test-actor")
                .expect("whitespace-only header is equivalent to omitted");
        assert!(got.is_none());
        crate::config::clear_capability_config_for_test();
    }

    /// `[capabilities].enabled = false` short-circuits BEFORE parse, so a
    /// presented-but-garbage UTF-8 token stays `Ok(None)` (zero behavioural
    /// delta while the feature is off).
    #[test]
    fn presented_utf8_garbage_is_inert_when_capabilities_disabled() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::set_active_capability_config(disabled_cfg());
        let got = capability_from_headers(
            &headers_with(HeaderValue::from_static("cap1:!!!garbage")),
            "test-actor",
        )
        .expect("disabled master switch must not parse");
        assert!(got.is_none());
        crate::config::clear_capability_config_for_test();
    }

    /// Enabled + PRESENTED UTF-8 that `from_wire` rejects must 403 via
    /// the `map_err` arm — never downgrade to anonymous/bare ACL.
    #[test]
    fn presented_utf8_garbage_is_403_when_capabilities_enabled() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::set_active_capability_config(enabled_cfg());
        let err = capability_from_headers(
            &headers_with(HeaderValue::from_static("cap1:!!!garbage")),
            "test-actor",
        )
        .expect_err("presented-but-unparseable credential must FAIL CLOSED");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        crate::config::clear_capability_config_for_test();
    }

    /// A well-formed-looking but wrong-version envelope is also a
    /// presented-but-unusable credential (not "omitted").
    #[test]
    fn presented_wrong_version_envelope_is_403_when_enabled() {
        let _cap = crate::config::lock_capability_config_for_test();
        crate::config::set_active_capability_config(enabled_cfg());
        let err = capability_from_headers(
            &headers_with(HeaderValue::from_static("cap9:aGk=")),
            "test-actor",
        )
        .expect_err("wrong-version envelope must FAIL CLOSED");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        crate::config::clear_capability_config_for_test();
    }
}

// Inline test scaffold (`#[cfg(test)] mod tests`) preserved verbatim
// from the pre-split mod.rs body. Tracked for future per-domain
// decomposition into `tests/handlers_<domain>.rs` integration test
// crates; the move-out is gated on exposing a stable `AppState`
// constructor helper from production code so tests outside the crate
// can build it without re-inventing fixture wiring (see #650 follow-up).
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
