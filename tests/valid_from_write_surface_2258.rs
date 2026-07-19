// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2258 — the #1834 claim-bitemporal `valid_from` / `valid_until`
//! write surface acceptance suite.
//!
//! Before #2258 the MCP `memory_store`, HTTP `POST /api/v1/memories`, and
//! CLI `ai-memory store` surfaces all hardcoded `valid_from: None` /
//! `valid_until: None` when building the row, so the documented bitemporal
//! backfill semantics were UNREACHABLE from every advertised write surface
//! (the field could only be set via import). These tests pin that a
//! caller-supplied `valid_from` / `valid_until`:
//!
//!   * round-trips through each of the three surfaces to the persisted row,
//!   * is validated as RFC3339 (a malformed bound is a loud error, never a
//!     silently-stored wrong value that would mis-filter `valid_at` recall),
//!   * preserves the immutable-on-upsert contract (`valid_from` set at
//!     create, unchanged on a later merge-upsert; `valid_until` updatable),
//!   * participates correctly in a `valid_at` recall.
//!
//! The interval is HALF-OPEN `[valid_from, valid_until)` per SQL:2011 and
//! the #1834 recall contract. Comparisons are tolerant of the stored
//! canonical form (presence-in-result / instant-parse, never raw-string
//! equality) so the separately-landing valid-time canonicalization lane
//! cannot false-fail this suite.

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::similar_names
)]

use std::sync::{Arc, Once};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::params;
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

// Interval endpoints shared across scenarios.
const T_JAN: &str = "2026-01-01T00:00:00+00:00";
const T_JUN: &str = "2026-06-01T00:00:00+00:00";
const T_SEP: &str = "2026-09-01T00:00:00+00:00";
const T_DEC: &str = "2026-12-01T00:00:00+00:00";

/// The HTTP-direct write surface is fail-CLOSED for unsigned writes under
/// the v1.0.0 default (#1985). These tests exercise the *bitemporal wire
/// plumbing*, not the attestation gate, so opt out of required attestation
/// process-wide (mirrors the `tests/cov3_handlers_sqlite.rs` precedent).
/// This is NOT a `$HOME` mutation, so the `check-test-env-lock.sh` gate
/// does not apply.
fn permissive_attestation() {
    static ONCE: Once = Once::new();
    // SAFETY: set once, to the same permissive value, before the router
    // is built; every store surface here is already permissive by default.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

/// Read the persisted `(valid_from, valid_until)` for a `(namespace, title)`
/// directly from the row, independent of any response-envelope shape.
fn stored_bounds(
    conn: &rusqlite::Connection,
    ns: &str,
    title: &str,
) -> (Option<String>, Option<String>) {
    conn.query_row(
        "SELECT valid_from, valid_until FROM memories WHERE namespace = ?1 AND title = ?2",
        params![ns, title],
        |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        },
    )
    .expect("row present")
}

/// Assert two RFC3339 strings denote the same instant (tolerant of the
/// stored canonical form — `+00:00` vs `Z`, microsecond padding, etc.).
fn assert_same_instant(got: &str, want: &str) {
    let g = chrono::DateTime::parse_from_rfc3339(got)
        .unwrap_or_else(|e| panic!("stored `{got}` is not RFC3339: {e}"));
    let w = chrono::DateTime::parse_from_rfc3339(want).expect("expected RFC3339");
    assert_eq!(
        g, w,
        "instant mismatch: stored `{got}` vs expected `{want}`"
    );
}

// ---------------------------------------------------------------------------
// MCP `memory_store`
// ---------------------------------------------------------------------------

#[test]
fn mcp_store_valid_from_round_trips_and_filters_valid_at() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let ttl = ResolvedTtl::default();
    let ns = "vf-mcp";
    let title = "mcp-bitemporal-claim";

    let params = serde_json::json!({
        "title": title,
        "content": "bitemporal claim body long enough to read as real prose.",
        "namespace": ns,
        "tier": "long",
        "kind": "claim",
        "valid_from": T_JAN,
        "valid_until": T_SEP,
    });
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &db_path, &params, None, None, None, &ttl, false, None, None,
    )
    .expect("MCP store with valid_from/valid_until must succeed");

    let (vf, vu) = stored_bounds(&conn, ns, title);
    assert_same_instant(&vf.expect("valid_from persisted"), T_JAN);
    assert_same_instant(&vu.expect("valid_until persisted"), T_SEP);

    // valid_at participation: inside the half-open interval → present;
    // at/after valid_until (end-exclusive) → filtered.
    let titles = |valid_at: Option<&str>| -> Vec<String> {
        let (rows, _) = ai_memory::db::recall(
            &conn,
            "bitemporal",
            Some(ns),
            50,
            None,
            None,
            None,
            ai_memory::SECS_PER_HOUR,
            ai_memory::SECS_PER_DAY,
            None,
            None,
            false,
            None,
            None,
            valid_at,
        )
        .expect("recall");
        rows.into_iter().map(|(m, _)| m.title).collect()
    };

    assert!(
        titles(Some(T_JUN)).iter().any(|t| t == title),
        "claim must be recalled at valid_at inside [valid_from, valid_until)"
    );
    assert!(
        !titles(Some(T_SEP)).iter().any(|t| t == title),
        "claim must be filtered at valid_at == valid_until (end-exclusive)"
    );
    assert!(
        !titles(Some(T_DEC)).iter().any(|t| t == title),
        "claim must be filtered at valid_at after valid_until"
    );
}

#[test]
fn mcp_store_valid_from_immutable_on_merge_upsert() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let ttl = ResolvedTtl::default();
    let ns = "vf-mcp-upsert";
    let title = "mcp-immutable-claim";

    let base = |vf: &str, vu: &str| {
        serde_json::json!({
            "title": title,
            "content": "immutability probe body long enough to read as prose.",
            "namespace": ns,
            "tier": "long",
            "on_conflict": "merge",
            "valid_from": vf,
            "valid_until": vu,
        })
    };

    ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &db_path,
        &base(T_JAN, T_SEP),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("first store");

    // Merge-upsert with a DIFFERENT valid_from + a later valid_until.
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &db_path,
        &base(T_JUN, T_DEC),
        None,
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
    .expect("merge upsert");

    let (vf, vu) = stored_bounds(&conn, ns, title);
    // valid_from is IMMUTABLE after create — a second store naming a DIFFERENT
    // valid_from can never overwrite the create value.
    assert_same_instant(&vf.expect("valid_from persisted"), T_JAN);
    // The MCP `on_conflict=merge` exact-dup detour is a CONTENT dedup
    // (`db::update` — content / tier / tags / priority / confidence /
    // metadata only); it deliberately does NOT rewrite the claim-bitemporal
    // bounds, so `valid_until` also stays at its create value. Callers change
    // `valid_until` through the dedicated `memory_update` path, not a re-store.
    assert_same_instant(&vu.expect("valid_until persisted"), T_SEP);
}

#[test]
fn mcp_store_rejects_malformed_valid_from() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let ttl = ResolvedTtl::default();

    let params = serde_json::json!({
        "title": "mcp-bad-valid-from",
        "content": "body long enough to satisfy the content validator here.",
        "namespace": "vf-mcp-bad",
        "valid_from": "not-a-timestamp",
    });
    let err = ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &db_path, &params, None, None, None, &ttl, false, None, None,
    )
    .expect_err("malformed valid_from must be rejected");
    assert!(
        err.to_lowercase().contains("valid_at") || err.to_lowercase().contains("rfc3339"),
        "rejection must name the RFC3339/valid_at validator; got: {err}"
    );

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = 'vf-mcp-bad'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(count, 0, "a rejected write must not persist a row");
}

// ---------------------------------------------------------------------------
// CLI `ai-memory store`
// ---------------------------------------------------------------------------

fn cli_store_args(title: &str, ns: &str) -> ai_memory::cli::store::StoreArgs {
    ai_memory::cli::store::StoreArgs {
        tier: "long".to_string(),
        namespace: Some(ns.to_string()),
        title: title.to_string(),
        content: "cli bitemporal claim body long enough to read as prose.".to_string(),
        tags: String::new(),
        priority: 5,
        confidence: None,
        source: "cli".to_string(),
        expires_at: None,
        ttl_secs: None,
        scope: None,
        kind: None,
        citations: None,
        source_uri: None,
        source_span: None,
        valid_from: None,
        valid_until: None,
        entity_id: None,
        sign: false,
        write_v2: None,
        capability: None,
    }
}

#[test]
fn cli_store_valid_from_round_trips() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let cfg = ai_memory::config::AppConfig::default();
    let ns = "vf-cli";
    let title = "cli-bitemporal-claim";

    let mut args = cli_store_args(title, ns);
    args.valid_from = Some(T_JAN.to_string());
    args.valid_until = Some(T_SEP.to_string());

    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    {
        let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
        ai_memory::cli::store::run(&db_path, args, false, &cfg, Some("ai:test"), &mut out)
            .expect("CLI store with valid-from/valid-until must succeed");
    }

    let conn = ai_memory::db::open(&db_path).expect("reopen");
    let (vf, vu) = stored_bounds(&conn, ns, title);
    assert_same_instant(&vf.expect("valid_from persisted"), T_JAN);
    assert_same_instant(&vu.expect("valid_until persisted"), T_SEP);
}

#[test]
fn cli_store_rejects_malformed_valid_until() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let cfg = ai_memory::config::AppConfig::default();
    let ns = "vf-cli-bad";
    let title = "cli-bad-valid-until";

    let mut args = cli_store_args(title, ns);
    args.valid_until = Some("2026-13-99".to_string());

    let mut so = Vec::<u8>::new();
    let mut se = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    let res = ai_memory::cli::store::run(&db_path, args, false, &cfg, Some("ai:test"), &mut out);
    assert!(
        res.is_err(),
        "malformed --valid-until must be rejected, not silently stored"
    );
}

// ---------------------------------------------------------------------------
// HTTP `POST /api/v1/memories`
// ---------------------------------------------------------------------------

fn build_router_fixture() -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder().method(method).uri(path);
    let req = if let Some(body) = body {
        b = b.header("content-type", "application/json");
        b.body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        b.body(Body::empty()).unwrap()
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let parsed = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_store_valid_from_round_trips() {
    permissive_attestation();
    let (router, f) = build_router_fixture();
    let ns = "vf-http";
    let title = "http-bitemporal-claim";

    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/memories",
        Some(serde_json::json!({
            "title": title,
            "content": "http bitemporal claim body long enough to read as prose.",
            "namespace": ns,
            "tier": "long",
            "valid_from": T_JAN,
            "valid_until": T_SEP,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "POST /memories with valid_from/valid_until must 201; body={body}"
    );

    // Read the persisted row back through a fresh connection to the shared
    // sqlite file (committed rows are cross-connection visible). This proves
    // the HTTP surface threaded the bounds all the way to the durable row.
    let conn = ai_memory::db::open(f.path()).expect("reopen shared db");
    let (vf, vu) = stored_bounds(&conn, ns, title);
    assert_same_instant(&vf.expect("valid_from persisted"), T_JAN);
    assert_same_instant(&vu.expect("valid_until persisted"), T_SEP);
}

#[tokio::test]
async fn http_store_rejects_malformed_valid_from() {
    permissive_attestation();
    let (router, _f) = build_router_fixture();

    let (status, _body) = send(
        &router,
        "POST",
        "/api/v1/memories",
        Some(serde_json::json!({
            "title": "http-bad-valid-from",
            "content": "http body long enough to satisfy the content validator.",
            "namespace": "vf-http-bad",
            "valid_from": "nope",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed valid_from on the HTTP surface must 400, not silently store"
    );
}

// ---------------------------------------------------------------------------
// HTTP `POST /api/v1/memories/bulk` — the FOURTH write funnel (#2258 audit).
// bulk_create consumes the same extended CreateMemory DTO + runs
// validate_create per row, so it now REJECTS a malformed bound; before the
// fix it then hardcoded valid_from/valid_until = None at BOTH build sites,
// silently dropping a valid caller value (the exact #2258 failure mode).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_bulk_store_valid_from_round_trips() {
    permissive_attestation();
    let (router, f) = build_router_fixture();
    let ns = "vf-http-bulk";
    let title = "http-bulk-bitemporal-claim";

    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/memories/bulk",
        Some(serde_json::json!([{
            "title": title,
            "content": "http bulk bitemporal claim body long enough to read as prose.",
            "namespace": ns,
            "tier": "long",
            "valid_from": T_JAN,
            "valid_until": T_SEP,
        }])),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "POST /memories/bulk with valid_from/valid_until must 200; body={body}"
    );
    assert_eq!(
        body.get("created").and_then(serde_json::Value::as_u64),
        Some(1),
        "the one bulk row must have been created; body={body}"
    );

    let conn = ai_memory::db::open(f.path()).expect("reopen shared db");
    let (vf, vu) = stored_bounds(&conn, ns, title);
    assert_same_instant(&vf.expect("valid_from persisted"), T_JAN);
    assert_same_instant(&vu.expect("valid_until persisted"), T_SEP);
}

#[tokio::test]
async fn http_bulk_store_rejects_malformed_valid_from() {
    permissive_attestation();
    let (router, f) = build_router_fixture();
    let ns = "vf-http-bulk-bad";
    let title = "http-bulk-bad-valid-from";

    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/memories/bulk",
        Some(serde_json::json!([{
            "title": title,
            "content": "http bulk body long enough to satisfy the content validator.",
            "namespace": ns,
            "valid_from": "not-a-timestamp",
        }])),
    )
    .await;
    // Per-row validate_create failure skips the row into `errors[]` (never a
    // silent store), so `created` is 0 and the row does not persist.
    assert_eq!(status, StatusCode::OK, "bulk envelope is 200; body={body}");
    assert_eq!(
        body.get("created").and_then(serde_json::Value::as_u64),
        Some(0),
        "a malformed-bound bulk row must NOT be created; body={body}"
    );
    let conn = ai_memory::db::open(f.path()).expect("reopen shared db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
            params![ns, title],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(count, 0, "the rejected bulk row must not persist");
}

// ---------------------------------------------------------------------------
// Interval-sanity disposition (#2258 audit MINOR): `valid_from > valid_until`
// is an EMPTY half-open interval, ACCEPTED (not rejected) — consistent with
// the `memory_update` precedent and the North Star (an empty interval yields
// FEWER results, never WRONG results). This pins the deliberate behavior.
// ---------------------------------------------------------------------------

#[test]
fn store_accepts_inverted_interval_as_empty_never_valid() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let ttl = ResolvedTtl::default();
    let ns = "vf-inverted";
    let title = "inverted-interval-claim";

    // valid_from (SEP) is AFTER valid_until (JAN) — an empty interval.
    let params = serde_json::json!({
        "title": title,
        "content": "inverted bitemporal claim body long enough to read as prose.",
        "namespace": ns,
        "tier": "long",
        "valid_from": T_SEP,
        "valid_until": T_JAN,
    });
    ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &db_path, &params, None, None, None, &ttl, false, None, None,
    )
    .expect("an inverted interval is ACCEPTED at the store surface");

    // The row persisted with the caller's (inverted) bounds verbatim.
    let (vf, vu) = stored_bounds(&conn, ns, title);
    assert_same_instant(&vf.expect("valid_from persisted"), T_SEP);
    assert_same_instant(&vu.expect("valid_until persisted"), T_JAN);

    let titles = |valid_at: Option<&str>| -> Vec<String> {
        let (rows, _) = ai_memory::db::recall(
            &conn,
            "inverted",
            Some(ns),
            50,
            None,
            None,
            None,
            ai_memory::SECS_PER_HOUR,
            ai_memory::SECS_PER_DAY,
            None,
            None,
            false,
            None,
            None,
            valid_at,
        )
        .expect("recall");
        rows.into_iter().map(|(m, _)| m.title).collect()
    };

    // No valid_at filter → the row is returned (empty interval only affects
    // valid_at-filtered recall, never legacy recall).
    assert!(
        titles(None).iter().any(|t| t == title),
        "an unfiltered recall must still return the row"
    );
    // Any valid_at → the empty [valid_from, valid_until) interval matches no
    // instant, so the row is filtered out (fewer results, never wrong).
    for at in [T_JAN, T_JUN, T_SEP, T_DEC] {
        assert!(
            !titles(Some(at)).iter().any(|t| t == title),
            "an empty (inverted) interval must never satisfy a valid_at recall (at={at})"
        );
    }
}
