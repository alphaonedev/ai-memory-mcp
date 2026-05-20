// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum MemoryError {
    NotFound(String),
    ValidationFailed(String),
    DatabaseError(String),
    Conflict(String),
    /// v0.7.0 recursive-learning Task 4/8 (issue #655) — emitted by the
    /// `memory_reflect` write path when the proposed reflection's depth
    /// exceeds the resolved namespace
    /// [`crate::models::GovernancePolicy::effective_max_reflection_depth`]
    /// cap. The variant carries the structured triple so Task 5/8 can
    /// match on it without parsing a string, then emit a `signed_events`
    /// audit row for the refusal decision.
    ///
    /// Wire shape (HTTP): `409 CONFLICT` with code `REFLECTION_DEPTH_EXCEEDED`.
    ReflectionDepthExceeded {
        attempted: u32,
        cap: u32,
        namespace: String,
    },
    /// v0.7.0 L1-2 (issue #659) — emitted by the `memory_link` write path
    /// when adding a `reflects_on` edge would close a cycle in the
    /// reflection graph. Carries `source`, `target`, and the reconstructed
    /// `cycle_path` (ordered `source → … → source`) for the audit row and
    /// the operator-readable error message.
    ///
    /// Wire shape (HTTP / MCP): surfaced as a `String` error at the MCP
    /// layer with code `REFLECTION_CYCLE_DETECTED`.
    ReflectionCycleDetected {
        source: String,
        target: String,
        cycle_path: Vec<String>,
    },
    /// v0.7.0 L1-6 Deliverable E (issue #691) — emitted by
    /// [`crate::storage::insert`], [`crate::storage::insert_with_conflict`],
    /// and [`crate::storage::insert_if_newer`] when the optional
    /// [`crate::storage::GOVERNANCE_PRE_WRITE`] hook returns `Err(reason)`.
    /// The hook is installed once at daemon `serve` boot and consults the
    /// substrate's signed `governance_rules` table via
    /// `governance::agent_action::check_agent_action` against a synthetic
    /// `Custom { custom_kind = "memory_write" }` action; a `Refuse`
    /// decision short-circuits the SQL `INSERT` cleanly (no row written,
    /// no partial state).
    ///
    /// The hook is NOT installed in CLI one-shot mode — operator-direct
    /// CLI invocations stay unimpeded by design (operator standing
    /// directive: rules gate AGENT writes, not the operator's own
    /// hands-on substrate ops).
    ///
    /// Wire shape (HTTP): `403 FORBIDDEN` with code `GOVERNANCE_REFUSED`.
    /// Carries the operator-authored `reason` from the matching
    /// `governance_rules.reason` column verbatim.
    RefusedByGovernance(String),
    /// #963 Phase 2 — substrate gate-evaluator refusal
    /// ([`crate::storage::enforce_governance`] /
    /// `Store::enforce_governance_action`). Distinguished from
    /// [`Self::RefusedByGovernance`] (the substrate pre-write hook) by
    /// carrying the typed [`crate::governance::GovernanceRefusal`]
    /// envelope so handlers can surface
    /// `denied_level` / `namespace` / `owner` in HTTP / MCP / CLI
    /// responses without re-parsing the wire message.
    ///
    /// Wire shape (HTTP): `403 FORBIDDEN` with code `GOVERNANCE_REFUSED`.
    /// The `message()` is the canonical envelope `Display`
    /// (`"<action> denied by governance: <reason>"`), byte-identical to
    /// the pre-#963 free-form `Deny(String)` wire shape.
    RefusedByGovernanceGate(crate::governance::GovernanceRefusal),
}

impl MemoryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "NOT_FOUND",
            Self::ValidationFailed(_) => "VALIDATION_FAILED",
            Self::DatabaseError(_) => "DATABASE_ERROR",
            Self::Conflict(_) => "CONFLICT",
            Self::ReflectionDepthExceeded { .. } => "REFLECTION_DEPTH_EXCEEDED",
            Self::ReflectionCycleDetected { .. } => "REFLECTION_CYCLE_DETECTED",
            Self::RefusedByGovernance(_) | Self::RefusedByGovernanceGate(_) => "GOVERNANCE_REFUSED",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // The substrate refusal is a policy-conflict (caller asked
            // for an action the configured cap forbids); CONFLICT matches
            // the rest of governance-style refusals.
            Self::Conflict(_)
            | Self::ReflectionDepthExceeded { .. }
            | Self::ReflectionCycleDetected { .. } => StatusCode::CONFLICT,
            // L1-6 Deliverable E — a pre-write hook refusal is a typed
            // authorization-style denial: the caller's request was
            // well-formed but the operator-signed governance ruleset
            // explicitly refuses it. 403 FORBIDDEN matches the HTTP
            // semantic the rest of the substrate exposes for "the
            // server understood but refuses to authorize".
            Self::RefusedByGovernance(_) | Self::RefusedByGovernanceGate(_) => {
                StatusCode::FORBIDDEN
            }
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::NotFound(m)
            | Self::ValidationFailed(m)
            | Self::DatabaseError(m)
            | Self::Conflict(m) => m.clone(),
            Self::ReflectionDepthExceeded {
                attempted,
                cap,
                namespace,
            } => format!(
                "reflection depth {attempted} would exceed namespace \
                 max_reflection_depth {cap} (namespace='{namespace}')"
            ),
            Self::ReflectionCycleDetected {
                source,
                target,
                cycle_path,
            } => format!(
                "adding reflects_on edge {source} → {target} would create a cycle: {}",
                cycle_path.join(" → ")
            ),
            Self::RefusedByGovernance(reason) => {
                format!("write refused by substrate governance: {reason}")
            }
            // #963 Phase 2 — the gate-evaluator refusal carries the
            // canonical Display via `GovernanceRefusal::Display`, which
            // is byte-identical to the pre-#963 `Deny(String)` shape:
            // `"<action> denied by governance: <reason>"`. Surface that
            // directly so the HTTP / MCP / CLI surfaces emit the same
            // wire string they did before the typed envelope landed.
            Self::RefusedByGovernanceGate(refusal) => refusal.to_string(),
        }
    }
}

impl IntoResponse for MemoryError {
    fn into_response(self) -> Response {
        let body = ApiError {
            code: self.code(),
            message: self.message(),
        };
        (self.status(), Json(body)).into_response()
    }
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl From<anyhow::Error> for MemoryError {
    fn from(e: anyhow::Error) -> Self {
        // v0.7.0 L1-6 Deliverable E — promote a substrate-layer
        // `GovernanceRefusal` wrapped in `anyhow::Error` (the shape
        // emitted by `storage::insert*` when the pre-write hook fires)
        // into the typed `RefusedByGovernance` variant so HTTP handlers
        // get the right 403 status + `GOVERNANCE_REFUSED` code without
        // every callsite having to downcast manually. Kept as a
        // generic fall-through to `DatabaseError` for all other
        // anyhow chains so this conversion stays additive.
        if let Some(refusal) = e.downcast_ref::<crate::storage::GovernanceRefusal>() {
            return Self::RefusedByGovernance(refusal.reason.clone());
        }
        // #963 Phase 2 — the gate-evaluator refusal envelope (typed
        // `crate::governance::GovernanceRefusal`). Distinct from the
        // pre-write hook refusal above (`crate::storage::GovernanceRefusal`),
        // even though they share a struct name in different modules. The
        // canonical Display is preserved through `RefusedByGovernanceGate`
        // (see `message()` arm), and the typed fields survive the round
        // trip via the variant's payload so downstream handlers can
        // surface `denied_level`/`namespace`/`owner` in JSON.
        if let Some(refusal) = e.downcast_ref::<crate::governance::GovernanceRefusal>() {
            return Self::RefusedByGovernanceGate(refusal.clone());
        }
        // #962 — typed substrate-layer error envelope. Each
        // `StorageError` variant maps to its canonical HTTP status by
        // selecting the right `MemoryError` discriminant; the
        // user-facing message is the variant's `Display` impl so the
        // wire shape stays byte-identical to the pre-#962 `bail!()`
        // strings (preserves `.to_string().starts_with(...)` consumers).
        if let Some(se) = e.downcast_ref::<crate::storage::StorageError>() {
            use crate::storage::StorageError as SE;
            return match se {
                SE::MemoryNotFound { .. } | SE::PendingActionNotFound { .. } => {
                    Self::NotFound(se.to_string())
                }
                SE::AmbiguousIdPrefix { .. } | SE::InvalidArgument { .. } => {
                    Self::ValidationFailed(se.to_string())
                }
                SE::PendingActionStateInvalid { .. }
                | SE::UniqueConflict { .. }
                | SE::ArchiveRestoreCollision { .. }
                | SE::LinkReflectionCycle { .. } => Self::Conflict(se.to_string()),
                SE::LinkPermissionDenied { .. } | SE::ApproverLaundering { .. } => {
                    Self::RefusedByGovernance(se.to_string())
                }
                SE::ArchiveSupersedeFailed { .. } | SE::SqlcipherMissingPassphrase => {
                    Self::DatabaseError(se.to_string())
                }
            };
        }
        Self::DatabaseError(e.to_string())
    }
}

impl From<rusqlite::Error> for MemoryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DatabaseError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes() {
        assert_eq!(MemoryError::NotFound("x".into()).code(), "NOT_FOUND");
        assert_eq!(
            MemoryError::ValidationFailed("x".into()).code(),
            "VALIDATION_FAILED"
        );
        assert_eq!(
            MemoryError::DatabaseError("x".into()).code(),
            "DATABASE_ERROR"
        );
        assert_eq!(MemoryError::Conflict("x".into()).code(), "CONFLICT");
    }

    #[test]
    fn error_status_codes() {
        assert_eq!(
            MemoryError::NotFound("x".into()).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            MemoryError::ValidationFailed("x".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            MemoryError::DatabaseError("x".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            MemoryError::Conflict("x".into()).status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            MemoryError::NotFound("not here".into()).message(),
            "not here"
        );
        assert_eq!(
            MemoryError::ValidationFailed("bad input".into()).message(),
            "bad input"
        );
    }

    #[test]
    fn error_display() {
        let err = MemoryError::NotFound("memory xyz".into());
        let display = format!("{err}");
        assert!(display.contains("NOT_FOUND"));
        assert!(display.contains("memory xyz"));
    }

    #[test]
    fn from_anyhow() {
        let err: MemoryError = anyhow::anyhow!("db broke").into();
        assert_eq!(err.code(), "DATABASE_ERROR");
        assert!(err.message().contains("db broke"));
    }

    /// #963 Phase 2 — a typed `crate::governance::GovernanceRefusal`
    /// wrapped in `anyhow::Error` MUST downcast through
    /// `From<anyhow::Error>` into the new `RefusedByGovernanceGate`
    /// variant (NOT the pre-write-hook `RefusedByGovernance`), preserve
    /// the canonical Display in `message()`, surface
    /// `GOVERNANCE_REFUSED` + 403, and keep the typed fields readable
    /// for downstream JSON projection.
    #[test]
    fn from_anyhow_downcasts_governance_gate_refusal() {
        use crate::governance::GovernanceRefusal;
        use crate::models::{GovernanceLevel, GovernedAction};

        let refusal = GovernanceRefusal::new(
            GovernedAction::Store,
            GovernanceLevel::Owner,
            "ai:bob",
            "caller 'ai:bob' is not the owner ('ai:alice')",
        )
        .with_namespace("team/prod")
        .with_owner("ai:alice");
        let anyhow_err = anyhow::Error::new(refusal.clone());

        let mem_err: MemoryError = anyhow_err.into();
        assert_eq!(mem_err.code(), "GOVERNANCE_REFUSED");
        assert_eq!(mem_err.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            mem_err.message(),
            "store denied by governance: caller 'ai:bob' is not the owner ('ai:alice')",
        );

        match &mem_err {
            MemoryError::RefusedByGovernanceGate(r) => {
                assert_eq!(r.action, GovernedAction::Store);
                assert_eq!(r.denied_level, GovernanceLevel::Owner);
                assert_eq!(r.namespace.as_deref(), Some("team/prod"));
                assert_eq!(r.owner.as_deref(), Some("ai:alice"));
                assert_eq!(r.agent_id, "ai:bob");
                assert_eq!(r, &refusal);
            }
            other => {
                panic!("typed envelope must downcast to RefusedByGovernanceGate; got {other:?}")
            }
        }
    }

    /// The substrate pre-write hook refusal
    /// (`crate::storage::GovernanceRefusal`, a *different type* with the
    /// same name in a different module) still downcasts into the legacy
    /// `RefusedByGovernance(String)` variant. Pins the disambiguation —
    /// the new `From<anyhow::Error>` arm for the gate-evaluator refusal
    /// MUST NOT cannibalise the pre-write-hook path.
    #[test]
    fn from_anyhow_preserves_pre_write_hook_refusal_variant() {
        let hook_refusal = crate::storage::GovernanceRefusal {
            reason: "rule R1 denies write".to_string(),
        };
        let anyhow_err = anyhow::Error::new(hook_refusal);

        let mem_err: MemoryError = anyhow_err.into();
        assert_eq!(mem_err.code(), "GOVERNANCE_REFUSED");
        assert_eq!(mem_err.status(), StatusCode::FORBIDDEN);
        // The pre-write-hook path wraps with "write refused by substrate
        // governance: " — distinct prefix from the gate-evaluator path
        // ("<action> denied by governance: ").
        assert_eq!(
            mem_err.message(),
            "write refused by substrate governance: rule R1 denies write",
        );
        assert!(
            matches!(mem_err, MemoryError::RefusedByGovernance(_)),
            "pre-write-hook refusal must map to RefusedByGovernance, not the new gate variant",
        );
    }

    #[test]
    fn api_error_serializes() {
        let api_err = ApiError {
            code: "TEST",
            message: "test msg".into(),
        };
        let json = serde_json::to_value(&api_err).unwrap();
        assert_eq!(json["code"], "TEST");
        assert_eq!(json["message"], "test msg");
    }

    // -----------------------------------------------------------------
    // W12-H — variant-by-variant display + into_response coverage
    // -----------------------------------------------------------------

    #[test]
    fn error_display_validation() {
        let err = MemoryError::ValidationFailed("bad input".into());
        let s = format!("{err}");
        assert!(s.contains("VALIDATION_FAILED"));
        assert!(s.contains("bad input"));
    }

    #[test]
    fn error_display_database() {
        let err = MemoryError::DatabaseError("conn refused".into());
        let s = format!("{err}");
        assert!(s.contains("DATABASE_ERROR"));
        assert!(s.contains("conn refused"));
    }

    #[test]
    fn error_display_conflict() {
        let err = MemoryError::Conflict("dup".into());
        let s = format!("{err}");
        assert!(s.contains("CONFLICT"));
        assert!(s.contains("dup"));
    }

    #[test]
    fn error_message_database_and_conflict() {
        assert_eq!(MemoryError::DatabaseError("oops".into()).message(), "oops");
        assert_eq!(MemoryError::Conflict("c".into()).message(), "c");
    }

    #[test]
    fn from_rusqlite_error_maps_to_database() {
        let rusqlite_err = rusqlite::Error::InvalidQuery;
        let err: MemoryError = rusqlite_err.into();
        assert_eq!(err.code(), "DATABASE_ERROR");
    }

    #[test]
    fn into_response_carries_status_and_body() {
        use axum::response::IntoResponse;
        let err = MemoryError::NotFound("missing".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn into_response_validation_status() {
        use axum::response::IntoResponse;
        let err = MemoryError::ValidationFailed("v".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn into_response_database_status() {
        use axum::response::IntoResponse;
        let err = MemoryError::DatabaseError("d".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn into_response_conflict_status() {
        use axum::response::IntoResponse;
        let err = MemoryError::Conflict("c".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — ReflectionDepthExceeded variant coverage
    // (Layer 0 Task 4/8 added the variant; no tests followed)
    // -----------------------------------------------------------------

    #[test]
    fn reflection_depth_exceeded_code() {
        let err = MemoryError::ReflectionDepthExceeded {
            attempted: 4,
            cap: 3,
            namespace: "ns/x".into(),
        };
        assert_eq!(err.code(), "REFLECTION_DEPTH_EXCEEDED");
    }

    #[test]
    fn reflection_depth_exceeded_status_is_conflict() {
        let err = MemoryError::ReflectionDepthExceeded {
            attempted: 5,
            cap: 3,
            namespace: "ns/y".into(),
        };
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn reflection_depth_exceeded_message_contains_triple() {
        let err = MemoryError::ReflectionDepthExceeded {
            attempted: 7,
            cap: 3,
            namespace: "ai-memory/research".into(),
        };
        let msg = err.message();
        assert!(msg.contains("7"));
        assert!(msg.contains("3"));
        assert!(msg.contains("ai-memory/research"));
        assert!(msg.contains("max_reflection_depth"));
    }

    #[test]
    fn reflection_depth_exceeded_display() {
        let err = MemoryError::ReflectionDepthExceeded {
            attempted: 4,
            cap: 3,
            namespace: "ns".into(),
        };
        let s = format!("{err}");
        assert!(s.contains("REFLECTION_DEPTH_EXCEEDED"));
        assert!(s.contains("max_reflection_depth"));
    }

    #[test]
    fn reflection_depth_exceeded_into_response_is_conflict() {
        use axum::response::IntoResponse;
        let err = MemoryError::ReflectionDepthExceeded {
            attempted: 4,
            cap: 3,
            namespace: "ns".into(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // -----------------------------------------------------------------
    // L1-2 — ReflectionCycleDetected variant coverage
    // (anti-self-reflection cycle check on memory_link)
    // -----------------------------------------------------------------

    #[test]
    fn reflection_cycle_detected_code() {
        let err = MemoryError::ReflectionCycleDetected {
            source: "uuid-A".into(),
            target: "uuid-B".into(),
            cycle_path: vec!["uuid-B".into(), "uuid-C".into(), "uuid-A".into()],
        };
        assert_eq!(err.code(), "REFLECTION_CYCLE_DETECTED");
    }

    #[test]
    fn reflection_cycle_detected_status_is_conflict() {
        let err = MemoryError::ReflectionCycleDetected {
            source: "src".into(),
            target: "dst".into(),
            cycle_path: vec!["dst".into(), "src".into()],
        };
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn reflection_cycle_detected_message_contains_path() {
        let err = MemoryError::ReflectionCycleDetected {
            source: "uuid-A".into(),
            target: "uuid-B".into(),
            cycle_path: vec!["uuid-B".into(), "uuid-C".into(), "uuid-A".into()],
        };
        let msg = err.message();
        assert!(
            msg.contains("uuid-A"),
            "expected source UUID in message, got: {msg}"
        );
        assert!(
            msg.contains("uuid-B"),
            "expected target UUID in message, got: {msg}"
        );
        assert!(
            msg.contains("uuid-C"),
            "expected cycle path intermediate in message, got: {msg}"
        );
        assert!(
            msg.contains("cycle"),
            "expected cycle context in message, got: {msg}"
        );
    }

    #[test]
    fn reflection_cycle_detected_display_includes_code() {
        let err = MemoryError::ReflectionCycleDetected {
            source: "s".into(),
            target: "t".into(),
            cycle_path: vec!["t".into(), "s".into()],
        };
        let s = format!("{err}");
        assert!(
            s.contains("REFLECTION_CYCLE_DETECTED"),
            "Display should include code prefix; got: {s}"
        );
        assert!(
            s.contains("cycle"),
            "Display should describe the cycle; got: {s}"
        );
    }

    #[test]
    fn reflection_cycle_detected_into_response_is_conflict() {
        use axum::response::IntoResponse;
        let err = MemoryError::ReflectionCycleDetected {
            source: "s".into(),
            target: "t".into(),
            cycle_path: vec!["t".into(), "s".into()],
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // -----------------------------------------------------------------
    // L1-6 Deliverable E — RefusedByGovernance variant coverage
    // (storage::insert pre-write hook refusal path)
    // -----------------------------------------------------------------

    #[test]
    fn refused_by_governance_code() {
        let err = MemoryError::RefusedByGovernance("blocked".into());
        assert_eq!(err.code(), "GOVERNANCE_REFUSED");
    }

    #[test]
    fn refused_by_governance_status_is_forbidden() {
        let err = MemoryError::RefusedByGovernance("blocked".into());
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn refused_by_governance_message_contains_reason() {
        let err = MemoryError::RefusedByGovernance("secrets namespace is read-only".into());
        let msg = err.message();
        assert!(
            msg.contains("secrets namespace is read-only"),
            "expected reason in message, got: {msg}"
        );
        assert!(
            msg.contains("substrate governance"),
            "expected refusal context in message, got: {msg}"
        );
    }

    #[test]
    fn refused_by_governance_display_includes_code_and_reason() {
        let err = MemoryError::RefusedByGovernance("rule R042 fired".into());
        let s = format!("{err}");
        assert!(s.contains("GOVERNANCE_REFUSED"));
        assert!(s.contains("rule R042 fired"));
    }

    #[test]
    fn refused_by_governance_into_response_is_forbidden() {
        use axum::response::IntoResponse;
        let err = MemoryError::RefusedByGovernance("nope".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn from_anyhow_promotes_governance_refusal() {
        // A `GovernanceRefusal` wrapped in `anyhow::Error` round-trips
        // back to the typed `RefusedByGovernance` variant — that's the
        // contract the pre-write hook callers rely on for the 403
        // status mapping.
        let refusal = crate::storage::GovernanceRefusal {
            reason: "test reason".to_string(),
        };
        let any_err: anyhow::Error = anyhow::Error::new(refusal);
        let mapped: MemoryError = any_err.into();
        match mapped {
            MemoryError::RefusedByGovernance(r) => assert_eq!(r, "test reason"),
            other => panic!("expected RefusedByGovernance, got {other:?}"),
        }
    }

    #[test]
    fn from_anyhow_unrelated_falls_through_to_database_error() {
        // Defence-in-depth: a non-governance anyhow chain must still
        // collapse to DatabaseError (we are NOT widening this conversion).
        let any_err = anyhow::anyhow!("plain old db failure");
        let mapped: MemoryError = any_err.into();
        assert_eq!(mapped.code(), "DATABASE_ERROR");
    }

    // ---------------------------------------------------------------
    // #962 — typed StorageError downcast coverage. Pins that every
    // variant lands on the right HTTP status discriminant; the wire
    // body is the variant's Display impl (preserves byte-identical
    // pre-#962 bail!() strings).
    // ---------------------------------------------------------------

    fn map_storage(se: crate::storage::StorageError) -> MemoryError {
        let any_err: anyhow::Error = anyhow::Error::new(se);
        MemoryError::from(any_err)
    }

    #[test]
    fn from_anyhow_storage_memory_not_found_maps_to_notfound() {
        let mapped = map_storage(crate::storage::StorageError::MemoryNotFound {
            id: "m1".into(),
            role: None,
        });
        assert_eq!(mapped.code(), "NOT_FOUND");
        assert_eq!(mapped.status(), StatusCode::NOT_FOUND);
        assert!(mapped.message().contains("memory not found"));
    }

    #[test]
    fn from_anyhow_storage_pending_action_not_found_maps_to_notfound() {
        let mapped = map_storage(crate::storage::StorageError::PendingActionNotFound {
            pending_id: "pa-1".into(),
        });
        assert_eq!(mapped.status(), StatusCode::NOT_FOUND);
        assert!(mapped.message().contains("pending action not found"));
    }

    #[test]
    fn from_anyhow_storage_ambiguous_id_prefix_maps_to_validation() {
        let mapped = map_storage(crate::storage::StorageError::AmbiguousIdPrefix {
            prefix: "ab".into(),
            candidates: vec!["abc1".into(), "abc2".into()],
        });
        assert_eq!(mapped.code(), "VALIDATION_FAILED");
        assert_eq!(mapped.status(), StatusCode::BAD_REQUEST);
        // Wire body must contain the legacy prefix so consumers that
        // string-match `.contains("ambiguous ID prefix")` keep working.
        assert!(mapped.message().contains("ambiguous ID prefix"));
    }

    #[test]
    fn from_anyhow_storage_invalid_argument_maps_to_validation() {
        let mapped = map_storage(crate::storage::StorageError::InvalidArgument {
            reason: "max_depth must be >= 1".into(),
        });
        assert_eq!(mapped.status(), StatusCode::BAD_REQUEST);
        assert_eq!(mapped.message(), "max_depth must be >= 1");
    }

    #[test]
    fn from_anyhow_storage_pending_action_state_invalid_maps_to_conflict() {
        let mapped = map_storage(crate::storage::StorageError::PendingActionStateInvalid {
            pending_id: "pa-9".into(),
            status: "rejected".into(),
        });
        assert_eq!(mapped.code(), "CONFLICT");
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn from_anyhow_storage_unique_conflict_maps_to_conflict() {
        let mapped = map_storage(crate::storage::StorageError::UniqueConflict {
            reason: "title 'X' already exists".into(),
        });
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn from_anyhow_storage_archive_restore_collision_maps_to_conflict() {
        let mapped =
            map_storage(crate::storage::StorageError::ArchiveRestoreCollision { id: "m1".into() });
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
        assert!(mapped.message().contains("already exists in active table"));
    }

    #[test]
    fn from_anyhow_storage_link_reflection_cycle_maps_to_conflict() {
        let mapped = map_storage(crate::storage::StorageError::LinkReflectionCycle {
            source_id: "a".into(),
            target_id: "b".into(),
        });
        // The link handler maps reflects_on cycles to 409 CONFLICT —
        // the graph state conflicts with the new edge.
        assert_eq!(mapped.status(), StatusCode::CONFLICT);
        assert!(
            mapped
                .message()
                .starts_with(crate::storage::LINK_CYCLE_ERR_PREFIX),
            "wire body must preserve the canonical cycle prefix"
        );
    }

    #[test]
    fn from_anyhow_storage_link_permission_denied_maps_to_governance() {
        let mapped = map_storage(crate::storage::StorageError::LinkPermissionDenied {
            reason: "rule R7".into(),
        });
        assert_eq!(mapped.code(), "GOVERNANCE_REFUSED");
        assert_eq!(mapped.status(), StatusCode::FORBIDDEN);
        // `MemoryError::message()` for `RefusedByGovernance` wraps the
        // reason with `"write refused by substrate governance: "`, so we
        // assert containment (not `starts_with`) of the canonical prefix
        // — the typed prefix survives the layered wrap, and the
        // `handlers/links.rs` 403 path that bypasses `MemoryError`
        // serialises `StorageError::Display` directly (see the dedicated
        // unit test in `src/storage/error.rs`).
        assert!(
            mapped
                .message()
                .contains(crate::storage::LINK_PERMISSION_DENIED_ERR_PREFIX),
            "wire body must preserve the canonical denial prefix as a substring"
        );
    }

    #[test]
    fn from_anyhow_storage_approver_laundering_maps_to_governance() {
        let mapped = map_storage(crate::storage::StorageError::ApproverLaundering {
            pending_id: "pa-1".into(),
            claimed: "x".into(),
            requester: "y".into(),
        });
        assert_eq!(mapped.status(), StatusCode::FORBIDDEN);
        assert!(mapped.message().contains("approver-on-behalf laundering"));
    }

    #[test]
    fn from_anyhow_storage_archive_supersede_failed_maps_to_database_error() {
        let mapped = map_storage(crate::storage::StorageError::ArchiveSupersedeFailed {
            archived_id: "arch-1".into(),
        });
        assert_eq!(mapped.code(), "DATABASE_ERROR");
        assert_eq!(mapped.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn from_anyhow_storage_sqlcipher_missing_passphrase_maps_to_database_error() {
        let mapped = map_storage(crate::storage::StorageError::SqlcipherMissingPassphrase);
        assert_eq!(mapped.code(), "DATABASE_ERROR");
        assert!(mapped.message().contains("AI_MEMORY_DB_PASSPHRASE"));
    }

    #[test]
    fn from_anyhow_storage_governance_refusal_still_wins_when_chained() {
        // The original substrate `GovernanceRefusal` mapping is checked
        // first; pinning here so a future refactor can't silently move
        // it past the new StorageError branch and demote a refusal to
        // an internal DB error.
        let refusal = crate::storage::GovernanceRefusal {
            reason: "policy".into(),
        };
        let mapped: MemoryError = anyhow::Error::new(refusal).into();
        assert_eq!(mapped.code(), "GOVERNANCE_REFUSED");
    }
}
