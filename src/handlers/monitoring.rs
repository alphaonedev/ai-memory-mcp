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
/// (The field NAME lives in `models::field_names::SCHEMA_VERSION`; this is its VALUE.)
pub const SCHEMA_VERSION: u32 = 1;
const FEDERATION_FIELD: &str = "federation";
pub use super::routes::{MONITORING_METRICS as METRICS_PATH, MONITORING_STATUS as STATUS_PATH};
/// Prometheus text exposition media type.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Operator-assigned health-only scope on existing identities. No secrets.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
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

/// `state` of every field this surface cannot report a number for.
const UNAVAILABLE_STATE: &str = "unavailable";
const AVAILABLE_STATE: &str = "available";

#[derive(Serialize)]
struct Unavailable {
    state: &'static str,
    reason: &'static str,
    issue: u32,
}

const fn unavailable(issue: u32) -> Unavailable {
    Unavailable {
        state: UNAVAILABLE_STATE,
        reason: "not_yet_instrumented",
        issue,
    }
}

/// A per-peer field that IS instrumented (#3654) but that this node has not
/// observed for the peer. Reporting a number here, a zero included, would be
/// a claim the node never measured.
#[derive(Serialize)]
struct NotObserved {
    state: &'static str,
    reason: &'static str,
}

/// A per-peer field this node HAS observed. Still a signal object, never a
/// bare number: the v1 contract (docs/HEALTH-MONITORING.md) keeps the field's
/// type stable across the unavailable -> available transition, so a client
/// never has to tell "not measured" from a value by its JSON type.
#[derive(Serialize)]
struct Observed {
    state: &'static str,
    value: i64,
}

fn available(value: i64) -> serde_json::Value {
    json!(Observed {
        state: AVAILABLE_STATE,
        value
    })
}

/// Issue that owns the per-peer fields #3654 does not measure.
const PEER_LAG_ISSUE: u32 = 3681;
const NO_PUSH_SUCCESS: &str = "no_push_success_observed";
const NO_PUSH_ATTEMPT: &str = "no_push_attempt_observed";
const DLQ_NOT_MEASURED: &str = "dlq_not_measured";
const DLQ_BACKLOG_EMPTY: &str = "backlog_empty";
const DLQ_OLDEST_UNPARSEABLE: &str = "oldest_failure_unparseable";
const NO_PEER_DATE_HEADER: &str = "no_catchup_response_date_observed";

/// The available signal object when observed, otherwise the explicit
/// not-observed object with its reason.
fn observed(value: Option<i64>, reason: &'static str) -> serde_json::Value {
    value.map_or_else(
        || {
            json!(NotObserved {
                state: UNAVAILABLE_STATE,
                reason
            })
        },
        available,
    )
}

/// The per-peer block of the status payload, from the freshness registry.
///
/// Every timestamp is this node's own observation (`freshness` never takes a
/// peer-supplied instant as freshness). `last_accepted_push_at_seconds` is the
/// last push THIS peer applied (#2341: a 200 that skipped the items is not
/// acceptance), and `last_successful_push_age_seconds` is its age.
/// Reachability comes from pulls only, and is `unknown` without a fresh one.
fn peer_status(
    id: &str,
    fresh: Option<&crate::federation::freshness::PeerFreshness>,
    catchup: Option<std::time::Duration>,
    now: i64,
) -> serde_json::Value {
    use crate::federation::freshness;
    let accepted = fresh.and_then(|f| f.push.last_success_unix);
    let depth = fresh.and_then(|f| f.push_dlq_depth);
    let oldest_age = match (depth, fresh.and_then(|f| f.push_dlq_oldest_failed_unix)) {
        (None, _) => observed(None, DLQ_NOT_MEASURED),
        (Some(0), _) => observed(None, DLQ_BACKLOG_EMPTY),
        (Some(_), None) => observed(None, DLQ_OLDEST_UNPARSEABLE),
        (Some(_), Some(ts)) => available(now.saturating_sub(ts).max(0)),
    };
    json!({
        "identity_ref": identity_ref(id),
        "reachability": freshness::reachability(fresh, catchup, now),
        "last_successful_push_age_seconds":
            observed(accepted.map(|ts| now.saturating_sub(ts).max(0)), NO_PUSH_SUCCESS),
        "last_push_attempt_at_seconds":
            observed(fresh.and_then(|f| f.push.last_attempt_unix), NO_PUSH_ATTEMPT),
        "last_accepted_push_at_seconds": observed(accepted, NO_PUSH_SUCCESS),
        "replication_lag": unavailable(PEER_LAG_ISSUE),
        "dlq_depth": observed(depth, DLQ_NOT_MEASURED),
        "dlq_oldest_age_seconds": oldest_age,
        "catch_up_progress": unavailable(PEER_LAG_ISSUE),
        "clock_skew_seconds": observed(fresh.and_then(|f| f.clock_skew_seconds), NO_PEER_DATE_HEADER)
    })
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
    let catchup = crate::federation::freshness::catchup_interval();
    let peers: Vec<_> = app
        .federation
        .as_ref()
        .as_ref()
        .map(|f| {
            f.peers
                .iter()
                .map(|p| {
                    let fresh = crate::federation::freshness::snapshot_for(&p.id);
                    peer_status(&p.id, fresh.as_ref(), catchup, now)
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
        (crate::models::field_names::SCHEMA_VERSION): SCHEMA_VERSION,
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
    let collectors: [&dyn Collector; 15] = [
        &m.federation_partial_quorum_total,
        &m.admission_shed_total,
        &m.auth_failures_total,
        &m.auth_backoff_sources,
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

    /// #3654 D3: the per-peer fields report what the freshness registry
    /// observed, and an explicit not-observed object otherwise — never a zero
    /// and never `healthy` from silence.
    #[test]
    fn issue_3654_peer_fields_report_only_what_was_observed() {
        use crate::federation::freshness::{DirectionFreshness, PeerFreshness};
        let now = 50_000;
        let catchup_interval = Some(std::time::Duration::from_secs(30));

        // Quiet peer: pulls fine, never pushed to, backlog never measured.
        let quiet = PeerFreshness {
            pull: DirectionFreshness {
                last_attempt_unix: Some(now - 10),
                last_success_unix: Some(now - 10),
                ..DirectionFreshness::default()
            },
            ..PeerFreshness::default()
        };
        let v = peer_status("peer-0", Some(&quiet), catchup_interval, now);
        assert_eq!(v["reachability"]["state"], "reachable");
        for field in [
            "last_successful_push_age_seconds",
            "last_accepted_push_at_seconds",
        ] {
            assert_eq!(v[field]["state"], "unavailable", "{field}");
            assert_eq!(v[field]["reason"], "no_push_success_observed", "{field}");
        }
        assert_eq!(
            v["last_push_attempt_at_seconds"]["reason"],
            "no_push_attempt_observed"
        );
        assert_eq!(v["dlq_depth"]["reason"], "dlq_not_measured");
        assert_eq!(v["replication_lag"]["issue"], 3681);
        assert_eq!(v["catch_up_progress"]["issue"], 3681);

        // Same peer on a node that runs no catch-up loop: reachability is
        // unknown, not reachable, however good the old pull looked.
        let v = peer_status("peer-0", Some(&quiet), None, now);
        assert_eq!(v["reachability"]["state"], "unknown");
        assert_eq!(v["reachability"]["reason"], "no_catchup_loop");

        // A peer that stopped accepting pushes: the last attempt is newer than
        // the last acceptance, the age keeps growing, the backlog is measured.
        let rejecting = PeerFreshness {
            push: DirectionFreshness {
                last_attempt_unix: Some(now - 5),
                last_success_unix: Some(now - 3_600),
                consecutive_failures: 7,
                last_failure_class: Some("not_applied"),
                failing_since_unix: Some(now - 3_500),
            },
            clock_skew_seconds: Some(-2),
            push_dlq_depth: Some(4),
            push_dlq_oldest_failed_unix: Some(now - 3_500),
            ..PeerFreshness::default()
        };
        let v = peer_status("peer-1", Some(&rejecting), catchup_interval, now);
        for (field, value) in [
            ("last_successful_push_age_seconds", 3_600),
            ("last_accepted_push_at_seconds", now - 3_600),
            ("last_push_attempt_at_seconds", now - 5),
            ("dlq_depth", 4),
            ("dlq_oldest_age_seconds", 3_500),
            ("clock_skew_seconds", -2),
        ] {
            // Observed values stay signal objects, never bare numbers.
            assert_eq!(v[field]["state"], "available", "{field}");
            assert_eq!(v[field]["value"], value, "{field}");
        }
        assert_eq!(v["reachability"]["reason"], "no_pull_observation");

        // Measured empty backlog: depth 0 is a measurement, the oldest age is
        // not a number because there is no oldest row.
        let drained = PeerFreshness {
            push_dlq_depth: Some(0),
            ..PeerFreshness::default()
        };
        let v = peer_status("peer-2", Some(&drained), catchup_interval, now);
        assert_eq!(v["dlq_depth"]["state"], "available");
        assert_eq!(v["dlq_depth"]["value"], 0);
        assert_eq!(v["dlq_oldest_age_seconds"]["reason"], "backlog_empty");

        // A peer the registry has never seen.
        let v = peer_status("peer-3", None, catchup_interval, now);
        assert_eq!(v["reachability"]["reason"], "no_pull_observation");
        assert_eq!(
            v["clock_skew_seconds"]["reason"],
            "no_catchup_response_date_observed"
        );
    }
}
