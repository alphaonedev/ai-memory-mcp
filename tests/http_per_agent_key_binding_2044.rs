// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2044 (v1.0.0, #2032-A) — HTTP-surface per-agent-key principal binding.
//!
//! Adversarial regression tests for the two highest findings of the #2032
//! assessment, which share ONE root cause: `X-Agent-Id` is a self-asserted
//! header while the `api_key` is a shared transport credential.
//!
//!   * **H1 (IDOR/BOLA)** — a shared-key caller sets `X-Agent-Id: <victim>` to
//!     act as / read another agent's data.
//!   * **M1 (admin spoof)** — a shared-key caller sets `X-Agent-Id: <admin>`.
//!
//! The fix binds `X-Agent-Id: X` to proven possession of agent X's enrolled
//! per-agent api-key (schema v83 `agent_api_keys`). These tests exercise:
//!   1. the DB / SAL round-trip (`bind → resolve → list`, both digest-keyed);
//!   2. the `api_key_auth` middleware binding + `enforce` refusal of a forged
//!      `X-Agent-Id`; and
//!   3. the shared gate logic (`resolve_auth_level` + `enforce_sensitive_identity`)
//!      that closes H1/M1 for shared-key callers under `enforce`.

use ai_memory::config::HttpIdentityMode;
use ai_memory::handlers::identity_binding::{
    AuthLevel, api_key_sha256_hex, enforce_sensitive_identity, resolve_auth_level,
};
use ai_memory::handlers::{ApiKeyState, api_key_auth};
use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt; // oneshot

// ---------------------------------------------------------------------------
// 1. DB / db-layer round-trip — the raw token is never stored, only sha256.
// ---------------------------------------------------------------------------

#[test]
fn db_bind_resolve_list_roundtrip_is_digest_keyed() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("m.db");
    let conn = ai_memory::db::open(&db_path).unwrap();

    let token = "alice-secret-token";
    let hash = api_key_sha256_hex(token);
    ai_memory::db::bind_agent_api_key(&conn, "alice", &hash).unwrap();

    // Resolve by the SAME digest → alice.
    assert_eq!(
        ai_memory::db::agent_id_for_api_key(&conn, &hash).unwrap(),
        Some("alice".to_string())
    );
    // A different token's digest → not enrolled.
    assert_eq!(
        ai_memory::db::agent_id_for_api_key(&conn, &api_key_sha256_hex("other")).unwrap(),
        None
    );
    // The boot-seed enumeration returns the (digest, agent) pair.
    let all = ai_memory::db::list_agent_api_keys(&conn).unwrap();
    assert_eq!(all, vec![(hash.clone(), "alice".to_string())]);

    // Re-binding the same digest rotates the mapping in place (idempotent).
    ai_memory::db::bind_agent_api_key(&conn, "alice2", &hash).unwrap();
    assert_eq!(
        ai_memory::db::agent_id_for_api_key(&conn, &hash).unwrap(),
        Some("alice2".to_string())
    );
    assert_eq!(ai_memory::db::list_agent_api_keys(&conn).unwrap().len(), 1);

    // #2095 — revoke invalidates a leaked key (returns rows removed; idempotent).
    assert_eq!(
        ai_memory::db::revoke_agent_api_key(&conn, "alice2").unwrap(),
        1
    );
    assert_eq!(
        ai_memory::db::agent_id_for_api_key(&conn, &hash).unwrap(),
        None,
        "revoked key no longer resolves"
    );
    assert!(
        ai_memory::db::list_agent_api_keys(&conn)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ai_memory::db::revoke_agent_api_key(&conn, "alice2").unwrap(),
        0,
        "revoking an already-revoked agent is a no-op"
    );
}

// ---------------------------------------------------------------------------
// 2. Middleware binding — the api_key_auth layer over an echo handler.
// ---------------------------------------------------------------------------

/// Echoes the (possibly middleware-bound) `X-Agent-Id` header. Binding
/// correctness is fully observable here: a per-agent key OVERWRITES the header to
/// the key-derived id; a shared key leaves the self-asserted value untouched.
/// (The `AuthLevel` is re-derived by the gates from the enrolled map + the
/// presented key — see the `identity_binding` unit tests + the route-gate tests
/// — so no request-extension principal is injected to read here.)
async fn echo(headers: HeaderMap) -> impl IntoResponse {
    let agent = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    Json(serde_json::json!({ "agent_id": agent }))
}

fn enrolled(pairs: &[(&str, &str)]) -> Arc<HashMap<String, String>> {
    Arc::new(
        pairs
            .iter()
            .map(|(tok, agent)| (api_key_sha256_hex(tok), (*agent).to_string()))
            .collect(),
    )
}

fn router(auth: ApiKeyState) -> Router {
    Router::new()
        .route("/api/v1/echo", get(echo))
        .layer(axum::middleware::from_fn_with_state(auth, api_key_auth))
}

async fn call(
    app: &Router,
    api_key: &str,
    agent_id: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder().uri("/api/v1/echo").method("GET");
    b = b.header("x-api-key", api_key);
    if let Some(a) = agent_id {
        b = b.header("x-agent-id", a);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn per_agent_key_binds_x_agent_id_and_injects_principal() {
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Advisory,
    };
    let app = router(auth);

    // alice presents her key WITHOUT a header → X-Agent-Id is bound to alice.
    let (st, body) = call(&app, "alice-key", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["agent_id"], "alice");

    // alice presents her key WITH a MATCHING header → honored.
    let (st, body) = call(&app, "alice-key", Some("alice")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["agent_id"], "alice");
}

#[tokio::test]
async fn h1_advisory_corrects_forged_x_agent_id_to_key_principal() {
    // H1 regression (advisory / default): alice's key + a FORGED X-Agent-Id:bob
    // is CORRECTED to alice (the key-bound principal), never honored as bob.
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Advisory,
    };
    let app = router(auth);
    let (st, body) = call(&app, "alice-key", Some("bob")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body["agent_id"], "alice",
        "forged X-Agent-Id must be corrected"
    );
}

#[tokio::test]
async fn h1_enforce_refuses_forged_x_agent_id() {
    // H1/M1 regression (enforce): alice's key + a FORGED X-Agent-Id:bob → 403.
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Enforce,
    };
    let app = router(auth);
    let (st, body) = call(&app, "alice-key", Some("bob")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "identity_binding_mismatch");
}

#[tokio::test]
async fn shared_key_does_not_bind_or_attest() {
    // A shared-transport-key caller: X-Agent-Id passes through self-asserted and
    // NO principal is injected (level "none" → Claimed at the gates). This is
    // the H1/M1 residual that the `enforce` gates refuse for named principals.
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Enforce,
    };
    let app = router(auth);
    let (st, body) = call(&app, "shared-transport", Some("victim")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["agent_id"], "victim"); // self-asserted, unbound
}

#[tokio::test]
async fn unknown_key_is_401() {
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Enforce,
    };
    let app = router(auth);
    let (st, _) = call(&app, "not-a-key", Some("alice")).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn off_mode_disables_binding() {
    // Escape hatch: `off` leaves X-Agent-Id fully self-asserted even for a
    // per-agent key (the proxy-fronted deployment).
    let auth = ApiKeyState {
        key: Some("shared-transport".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled(&[("alice-key", "alice")]),
        identity_mode: HttpIdentityMode::Off,
    };
    let app = router(auth);
    let (st, body) = call(&app, "alice-key", Some("bob")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["agent_id"], "bob"); // not bound under off
}

// ---------------------------------------------------------------------------
// 3. Gate logic — H1 (IDOR read/mutate) + M1 (admin) shared-key refusal.
// ---------------------------------------------------------------------------

#[test]
fn enforce_for_request_is_inert_when_no_keys_enrolled() {
    // Single-operator / feature-off posture: with NO enrolled per-agent keys
    // the gate is inert in EVERY mode — advisory stays zero-WARN and enforce
    // does NOT brick a named caller (the #1985 unsatisfiable-default trap).
    use ai_memory::handlers::identity_binding::enforce_for_request;
    let empty = HashMap::new();
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "shared-transport".parse().unwrap());
    for mode in [
        HttpIdentityMode::Off,
        HttpIdentityMode::Advisory,
        HttpIdentityMode::Enforce,
    ] {
        assert!(
            enforce_for_request(&empty, mode, &headers, "alice", "get_memory").is_none(),
            "empty enrolled map must be inert in {mode:?}"
        );
    }
}

#[test]
fn h1_m1_enforce_refuses_shared_key_named_principal_at_gate() {
    // The gate the memories handlers + require_admin invoke. A shared-key caller
    // (empty/absent per-agent attestation → Claimed) acting as a NAMED principal
    // is refused under enforce; a key-authenticated caller passes.
    let mut map = HashMap::new();
    map.insert(api_key_sha256_hex("alice-key"), "alice".to_string());

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", "shared-transport".parse().unwrap());
    // Shared key, acting as victim → Claimed → refused under enforce (H1 read/
    // mutate + M1 admin).
    let level = resolve_auth_level(&map, &headers, "victim");
    assert_eq!(level, AuthLevel::Claimed);
    assert!(
        enforce_sensitive_identity(HttpIdentityMode::Enforce, level, "victim", "get_memory")
            .is_some()
    );
    // Advisory (default) allows it (inert/WARN posture).
    assert!(
        enforce_sensitive_identity(HttpIdentityMode::Advisory, level, "victim", "get_memory")
            .is_none()
    );

    // alice's per-agent key acting as alice → KeyAuthenticated → allowed.
    let mut h2 = HeaderMap::new();
    h2.insert("x-api-key", "alice-key".parse().unwrap());
    let level2 = resolve_auth_level(&map, &h2, "alice");
    assert_eq!(level2, AuthLevel::KeyAuthenticated);
    assert!(
        enforce_sensitive_identity(
            HttpIdentityMode::Enforce,
            level2,
            "alice",
            "export_memories"
        )
        .is_none()
    );
}
