// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Versioned, metadata-only health surface and the HTTP scope chokepoint (#3646).
//! Scope applies before all legacy authentication exemptions. Store-level
//! enforcement is separately tracked in #3672.

#[cfg(feature = "sal-postgres")]
use super::StorageBackend;
use super::{ApiKeyState, AppState};
use axum::{
    Json,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// JSON contract major version; incompatible changes require a new version/path.
pub const SCHEMA_VERSION: u32 = 1;
const FEDERATION_FIELD: &str = "federation";
pub use super::routes::{MONITORING_METRICS as METRICS_PATH, MONITORING_STATUS as STATUS_PATH};
/// Prometheus text exposition media type.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Operator-assigned health-only scope on existing identities. No secrets.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonitoringConfig {
    /// Ordinary enrolled agent principals restricted to health routes.
    #[serde(default)]
    pub agent_ids: Vec<String>,
    /// Existing mTLS certificate peer bindings restricted to health routes.
    #[serde(default)]
    pub peer_ids: Vec<String>,
}

/// Listener facts and identity registry used by the single outer gate.
#[derive(Clone)]
pub(crate) struct AccessState {
    auth: ApiKeyState,
    scopes: MonitoringConfig,
    tls_enabled: bool,
}

impl AccessState {
    pub(crate) fn new(auth: ApiKeyState) -> Self {
        Self {
            scopes: auth.enrolled_agent_keys.monitoring.clone(),
            tls_enabled: auth.enrolled_agent_keys.monitoring_tls,
            auth,
        }
    }
}

/// Exact route allowlist: all other current and future paths are refused.
#[must_use]
pub fn is_health_path(path: &str) -> bool {
    matches!(path, STATUS_PATH | METRICS_PATH)
}

fn refusal(code: StatusCode, reason: &'static str) -> Response {
    (code, Json(json!({"error": reason}))).into_response()
}

/// The outermost HTTP gate; checks both credentials before any bypass branch.
pub(crate) async fn access(State(state): State<AccessState>, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(crate::HEADER_API_KEY)
        .and_then(|v| v.to_str().ok());
    let keys = state.auth.enrolled_agent_keys.snapshot();
    let agent = token.and_then(|v| keys.get(&super::identity_binding::api_key_sha256_hex(v)));
    let peer = if state.auth.mtls_enforced {
        req.extensions()
            .get::<crate::tls::ClientCertPeerId>()
            .and_then(|p| p.0.as_ref())
    } else {
        None
    };
    // A second credential, global key collision, or spoofed X-Agent-Id cannot
    // elevate a health-only principal. Restriction wins over other authority.
    let restricted = agent.is_some_and(|id| state.scopes.agent_ids.contains(id))
        || peer.is_some_and(|id| state.scopes.peer_ids.contains(id));
    let health = is_health_path(req.uri().path());
    let read = matches!(*req.method(), Method::GET | Method::HEAD);
    if restricted && (!health || !read) {
        return refusal(StatusCode::FORBIDDEN, "monitoring_scope_refused");
    }
    let global = token
        .zip(state.auth.key.as_deref())
        .is_some_and(|(a, b)| super::transport::constant_time_eq(a.as_bytes(), b.as_bytes()));
    // Revoked/unresolved keys cannot fall through an auth-off deployment.
    // Once health-only scopes exist, all non-probe requests need a resolved
    // transport principal, even when the legacy shared key is unconfigured.
    if (!state.scopes.agent_ids.is_empty() || !state.scopes.peer_ids.is_empty())
        && !health
        && req.uri().path() != super::routes::HEALTH
        && agent.is_none()
        && peer.is_none()
        && !global
    {
        return refusal(StatusCode::UNAUTHORIZED, "unresolved_transport_principal");
    }
    if health {
        if !state.tls_enabled {
            return refusal(StatusCode::FORBIDDEN, "monitoring_requires_tls");
        }
        if agent.is_none() && peer.is_none() && !global {
            return refusal(
                StatusCode::UNAUTHORIZED,
                "monitoring_requires_authentication",
            );
        }
    }
    next.run(req).await
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HealthState {
    Healthy,
    Degraded,
    Failing,
}

fn health_state(failing: bool, degraded: bool) -> HealthState {
    if failing {
        HealthState::Failing
    } else if degraded {
        HealthState::Degraded
    } else {
        HealthState::Healthy
    }
}

#[derive(Serialize)]
struct Unavailable {
    state: &'static str,
    reason: &'static str,
    issue: u32,
}

const fn unavailable(issue: u32) -> Unavailable {
    Unavailable {
        state: "unavailable",
        reason: "not_yet_instrumented",
        issue,
    }
}

/// Hash identifiers because legacy peer IDs may themselves be credential URLs.
/// The full digest is stable for correlation and never renders endpoint text.
fn identity_ref(id: &str) -> String {
    super::identity_binding::api_key_sha256_hex(id)
}

pub(crate) async fn status(State(app): State<AppState>) -> Response {
    use super::transport::{PROBE_ERROR, PROBE_NOT_APPLICABLE};
    #[cfg(feature = "sal-postgres")]
    let (connection_ok, fts_state) = if app.storage_backend == StorageBackend::Postgres {
        (
            app.store.health_check().await.unwrap_or(false),
            PROBE_NOT_APPLICABLE,
        )
    } else {
        super::transport::sqlite_liveness(&app).await
    };
    #[cfg(not(feature = "sal-postgres"))]
    let (connection_ok, fts_state) = super::transport::sqlite_liveness(&app).await;

    #[cfg(feature = "sal")]
    let schema = app.store.schema_version().await.ok().filter(|v| *v > 0);
    #[cfg(not(feature = "sal"))]
    let schema = super::transport::db_op(std::sync::Arc::clone(&app.db), |db| {
        db.0.query_row(
            crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL,
            [],
            |r| r.get::<_, i64>(0),
        )
    })
    .await
    .ok()
    .and_then(Result::ok)
    .filter(|v| *v > 0);

    let now = chrono::Utc::now().timestamp();
    let verdict = app.runtime.fts_integrity.verdict_at(now);
    let failing = !connection_ok
        || fts_state == PROBE_ERROR
        || schema.is_none()
        || (fts_state != PROBE_NOT_APPLICABLE && verdict.is_unhealthy());
    // Missing critical observations must not become a fleet-wide healthy claim.
    let state = health_state(failing, true);
    let peers: Vec<_> = app
        .federation
        .as_ref()
        .as_ref()
        .map(|f| {
            f.peers
                .iter()
                .map(|p| {
                    json!({
                        "identity_ref": identity_ref(&p.id),
                        "reachability": unavailable(3654),
                        "last_successful_push_age_seconds": unavailable(3654),
                        "last_push_attempt_at_seconds": unavailable(3654),
                        "last_accepted_push_at_seconds": unavailable(3654),
                        "replication_lag": unavailable(3654),
                        "dlq_depth": unavailable(3654),
                        "dlq_oldest_age_seconds": unavailable(3654),
                        "catch_up_progress": unavailable(3654),
                        "clock_skew_seconds": unavailable(3654)
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut reasons = vec!["required_observations_unavailable"];
    if !connection_ok {
        reasons.push("store_connection_failed");
    }
    if schema.is_none() {
        reasons.push("database_schema_unavailable");
    }
    if fts_state == PROBE_ERROR || verdict.is_unhealthy() {
        reasons.push("index_failed");
    }
    if app.embedder.as_ref().is_none() {
        reasons.push("keyword_only_by_design");
    }
    let body = json!({
        "schema_version": SCHEMA_VERSION,
        "software_version": crate::PKG_VERSION,
        "observed_at_seconds": now,
        "status": state,
        "reasons": reasons,
        "backend": app.storage_backend.as_str(),
        "database_schema_version": schema,
        "posture": {"transport": "tls", "authentication": "enrolled_key_or_mtls_or_operator_key", "scope": "health_read_only"},
        "singleton": {
            "process": "responding", "store_connection": if connection_ok { "reachable" } else { "failing" },
            "fts_index": fts_state,
            "fts_integrity": {"state": if fts_state == PROBE_NOT_APPLICABLE { PROBE_NOT_APPLICABLE } else { verdict.as_str() },
                "checked_at_seconds": app.runtime.fts_integrity.checked_at_unix()},
            "embedder_loaded": app.embedder.as_ref().is_some(),
            "embedder_operation_health": unavailable(3653),
            "vector_index_loaded": app.vector_index.lock().await.is_some(),
            "operation_rates_and_latency": unavailable(3653),
            "disk_wal_backup": unavailable(3656)
        },
        (FEDERATION_FIELD): {"enabled": app.federation.as_ref().is_some(), "peers": peers,
            "node_identity_ref": app.federation.as_ref().as_ref().map(|f| identity_ref(&f.sender_agent_id)),
            "quorum_outcomes": unavailable(3653), "nonce_cache": unavailable(3662), "dlq_bookkeeping": unavailable(3658)},
        "wake": {"connected_agents": unavailable(3657), "queue_pressure": unavailable(3657),
            "egress_pressure": unavailable(3657), "drops_by_cause": unavailable(3657),
            "backstop_reliance": unavailable(3657), "fallback_state": unavailable(3657), "agent_liveness": unavailable(3657)},
        "logging_delivery": unavailable(3651),
        "webhook_audit_delivery": unavailable(3659),
        "read_audit_delivery": unavailable(3660),
        "restore_evidence": unavailable(3661)
    });
    (
        if failing {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        },
        Json(body),
    )
        .into_response()
}

pub(crate) async fn metrics() -> Response {
    use prometheus::{Encoder, TextEncoder, core::Collector};
    let m = crate::metrics::registry();
    // Explicit scalar collectors only. Never forward the global registry:
    // labels elsewhere may contain tenant-controlled strings or peer URLs.
    let collectors: [&dyn Collector; 13] = [
        &m.federation_partial_quorum_total,
        &m.admission_shed_total,
        &m.recall_embed_degraded_total,
        &m.rerank_budget_degraded_total,
        &m.query_embed_cache_hits_total,
        &m.autotag_enqueued_total,
        &m.autotag_dropped_total,
        &m.autotag_applied_total,
        &m.autotag_degraded_total,
        &m.atomise_enqueued_total,
        &m.atomise_dropped_total,
        &m.atomise_applied_total,
        &m.atomise_degraded_total,
    ];
    let families: Vec<_> = collectors.iter().flat_map(|c| c.collect()).collect();
    let mut bytes = Vec::new();
    if TextEncoder::new().encode(&families, &mut bytes).is_err() {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "monitoring_encoding_failed",
        );
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issue_3646_degradation_precedence() {
        assert_eq!(health_state(false, false), HealthState::Healthy);
        assert_eq!(health_state(false, true), HealthState::Degraded);
        assert_eq!(health_state(true, true), HealthState::Failing);
        assert_eq!(
            serde_json::to_value(unavailable(3657)).unwrap()["reason"],
            "not_yet_instrumented"
        );
    }
}
