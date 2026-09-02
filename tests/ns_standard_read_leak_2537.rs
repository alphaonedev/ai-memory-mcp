// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::needless_update)]

//! v1.0.0 #2537 — regression pin for the namespace-standard cross-namespace
//! READ LEAK and the `retain()` result/count SUPPRESSION.
//!
//! ## The two defects (both reproduced at `release/v1.0.0` @ `9531ec37`)
//!
//! **HALF 1 — cross-tenant read amplification.**
//! `storage::set_namespace_standard` deliberately permits binding a standard
//! memory that lives in a DIFFERENT namespace (the documented shared-policy
//! feature). `mcp::lookup_namespace_standard` then `db::get`-ed that memory
//! with NO visibility filter and `mcp::inject_namespace_standard` injected
//! the FULL serialized `Memory` — title, content, tags, metadata, owning
//! namespace — into EVERY `memory_recall` / `memory_session_start` response
//! for the bound namespace. Executed at parent: bob (`caller=ai:bob`,
//! `X-Agent-Id: bob`) recalling `t2537-tenant` received
//! `standard.content = "needle CLASSIFIED-ALICE-PAYLOAD"`,
//! `standard.namespace = "t2537-victim"`,
//! `standard.metadata.agent_id = "ai:alice"` — alice's default-private row
//! in a namespace bob never queried, on BOTH the MCP recall surface and the
//! HTTP `POST /api/v1/session/start` surface.
//!
//! **HALF 2 — retrieval suppression.**
//! The same function ran `memories.retain(|m| !standard_ids.contains(m.id))`
//! and rewrote `response["count"]`, so whoever controlled a namespace's
//! binding controlled which row left the results array for EVERY caller
//! recalling that namespace — silently, with the count adjusted so nothing
//! looked missing, and with the row's `decorate_memory_many` trust
//! decoration (`score` / `provenance_tier` / `confidence_tier` /
//! `freshness_state`) stripped on the way to `response["standard"]`.
//! Executed at parent: two matching rows, one bound → `count: 1`.
//!
//! ## What this file pins (5-agent adversarial vote `4d3ea1c5`)
//!
//! - The canonical `visibility::is_visible_to_caller` predicate gates the
//!   injected body — NOT a bespoke namespace-chain carve-out (ranked LAST
//!   4-of-5: `"*"` is a link in every chain, the recall `namespace` argument
//!   is caller-supplied, and `namespace_meta.parent_namespace` is
//!   caller-supplied via `set_standard(parent=…)`).
//! - Withholding is disclosed as a bare `standards_withheld` COUNT — never
//!   the withheld id / owner / namespace, which would make the honesty
//!   marker a cross-tenant existence oracle.
//! - The `retain` is GONE: a matched row stays in `memories` and `count` is
//!   the true match count.
//! - **CONTROLS** — the documented shared-policy flow still works: a
//!   cross-namespace standard the caller CAN see (`scope=shared`, which is
//!   what the HTTP provisioning path stamps) is injected verbatim, and the
//!   caller's own same-namespace standard is injected verbatim.
//! - `caller = None` (single-tenant MCP stdio) is byte-identical to pre-fix.

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const NEEDLE: &str = "needle";
const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
/// Distinctive token that MUST NOT appear anywhere in bob's response body.
const SECRET: &str = "CLASSIFIED-ALICE-PAYLOAD";
const VICTIM_NS: &str = "t2537-victim";
const TENANT_NS: &str = "t2537-tenant";

fn seed(
    conn: &rusqlite::Connection,
    id: &str,
    namespace: &str,
    owner: &str,
    scope: Option<&str>,
    content: &str,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        ai_memory::META_KEY_AGENT_ID.to_string(),
        json!(owner.to_string()),
    );
    if let Some(s) = scope {
        metadata.insert(ai_memory::META_KEY_SCOPE.to_string(), json!(s.to_string()));
    }
    let mem = Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: id.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-2537".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::Value::Object(metadata),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("insert");
    id.to_string()
}

fn recall_as(conn: &rusqlite::Connection, namespace: &str, caller: Option<&str>) -> Value {
    let ttl = ResolvedTtl::default();
    let scoring = ResolvedScoring::default();
    ai_memory::mcp::handle_recall_caller(
        conn,
        &json!({"context": NEEDLE, "namespace": namespace, "limit": 50}),
        None,
        None,
        None,
        false,
        &ttl,
        &scoring,
        None,
        caller,
    )
    .expect("recall ok")
}

/// Seed the cross-namespace-bind fixture: alice's row in `VICTIM_NS` is bound
/// as `TENANT_NS`'s standard. `victim_scope` selects the leak case (`None` →
/// default-private) vs the legitimate shared-policy case (`Some("shared")`).
fn seed_cross_namespace_bind(conn: &rusqlite::Connection, victim_scope: Option<&str>) -> String {
    let victim = seed(
        conn,
        "alice-standard",
        VICTIM_NS,
        ALICE,
        victim_scope,
        &format!("{NEEDLE} {SECRET}"),
    );
    seed(
        conn,
        "bob-own",
        TENANT_NS,
        BOB,
        None,
        &format!("{NEEDLE} bob's own row"),
    );
    ai_memory::db::set_namespace_standard(conn, TENANT_NS, &victim, None).expect("set standard");
    victim
}

// ---------------------------------------------------------------------------
// HALF 1 — cross-namespace read amplification (MCP recall)
// ---------------------------------------------------------------------------

#[test]
fn mcp_recall_withholds_cross_namespace_private_standard_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    seed_cross_namespace_bind(&conn, None); // default => private, owned by alice

    let resp = recall_as(&conn, TENANT_NS, Some(BOB));
    let body = serde_json::to_string(&resp).expect("serialize");
    assert!(
        !body.contains(SECRET),
        "#2537 HALF 1 LEAK: bob received alice's private content via the \
         injected namespace standard. response={body}"
    );
    assert!(
        resp.get("standard").is_none() && resp.get("standards").is_none(),
        "no standard body may be injected when the bound row is invisible; got {resp}"
    );
    assert_eq!(
        resp["standards_withheld"].as_u64(),
        Some(1),
        "#2537: withholding must be DISCLOSED as a count, not silent; got {resp}"
    );
    // The marker must not become an existence oracle over the victim tenant.
    assert!(
        !body.contains(VICTIM_NS) && !body.contains(ALICE) && !body.contains("alice-standard"),
        "#2537: the withheld marker must carry NO id / owner / namespace; response={body}"
    );
    // bob still gets his own row + a truthful count.
    assert_eq!(resp["count"].as_u64(), Some(1), "got {resp}");
    assert_eq!(resp["memories"][0]["id"].as_str(), Some("bob-own"));
}

/// CONTROL — the DOCUMENTED shared-policy flow is preserved. A cross-namespace
/// standard the caller may read (`scope=shared`, which is exactly what the
/// HTTP provisioning path stamps) is still injected verbatim.
#[test]
fn mcp_recall_still_injects_visible_cross_namespace_shared_standard_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    seed_cross_namespace_bind(&conn, Some("shared"));

    let resp = recall_as(&conn, TENANT_NS, Some(BOB));
    assert_eq!(
        resp["standard"]["id"].as_str(),
        Some("alice-standard"),
        "CONTROL: a cross-namespace shared-policy standard must still be \
         injected — a blanket refusal is an availability break (#2491); got {resp}"
    );
    assert!(
        resp["standard"]["content"]
            .as_str()
            .is_some_and(|c| c.contains(SECRET)),
        "CONTROL: the shared standard's body must be served verbatim; got {resp}"
    );
    assert!(
        resp.get("standards_withheld").is_none(),
        "CONTROL: nothing was withheld; got {resp}"
    );
}

/// CONTROL — the owner still receives their OWN standard.
#[test]
fn mcp_recall_owner_still_receives_own_private_standard_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    seed_cross_namespace_bind(&conn, None);

    let resp = recall_as(&conn, TENANT_NS, Some(ALICE));
    assert_eq!(
        resp["standard"]["id"].as_str(),
        Some("alice-standard"),
        "CONTROL: alice owns the standard and must still receive it; got {resp}"
    );
}

/// CONTROL — `caller = None` (single-tenant MCP stdio, no `AI_MEMORY_AGENT_ID`)
/// is byte-identical to the pre-fix trust-all posture.
#[test]
fn mcp_recall_no_caller_preserves_trust_all_posture_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    seed_cross_namespace_bind(&conn, None);

    let resp = recall_as(&conn, TENANT_NS, None);
    assert_eq!(
        resp["standard"]["id"].as_str(),
        Some("alice-standard"),
        "CONTROL: the documented single-tenant trust-all read posture is \
         unchanged when no visibility caller resolves; got {resp}"
    );
}

// ---------------------------------------------------------------------------
// HALF 2 — retrieval suppression + count rewrite
// ---------------------------------------------------------------------------

#[test]
fn bound_standard_stays_in_results_and_count_is_truthful_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    let doc = seed(
        &conn,
        "bob-doc",
        "t2537-sup",
        BOB,
        None,
        &format!("{NEEDLE} suppressed doc"),
    );
    seed(
        &conn,
        "bob-other",
        "t2537-sup",
        BOB,
        None,
        &format!("{NEEDLE} other doc"),
    );

    let before = recall_as(&conn, "t2537-sup", Some(BOB));
    assert_eq!(
        before["count"].as_u64(),
        Some(2),
        "both rows match pre-bind; got {before}"
    );

    ai_memory::db::set_namespace_standard(&conn, "t2537-sup", &doc, None).expect("set standard");
    let after = recall_as(&conn, "t2537-sup", Some(BOB));
    let mems = after["memories"].as_array().expect("memories array");
    assert!(
        mems.iter().any(|m| m["id"] == json!(doc)),
        "#2537 HALF 2 SUPPRESSION: the bound row vanished from `memories` — \
         whoever controls the binding controls what every caller sees; \
         count={} array={mems:?}",
        after["count"]
    );
    assert_eq!(
        after["count"].as_u64(),
        Some(2),
        "#2537 HALF 2: `count` must be the TRUE match count, never silently \
         decremented by a server-side dedup; got {after}"
    );
}

/// #2537 (vote lens 4, `H2-d`) — the row promoted to GOVERNING AUTHORITY must
/// not be the one row delivered without its trust decoration. When the
/// standard is also among the results, the already-decorated value is reused.
#[test]
fn injected_standard_carries_trust_decoration_when_it_matched_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    let doc = seed(
        &conn,
        "bob-doc",
        "t2537-dec",
        BOB,
        None,
        &format!("{NEEDLE} governing doc"),
    );
    ai_memory::db::set_namespace_standard(&conn, "t2537-dec", &doc, None).expect("set standard");

    let resp = recall_as(&conn, "t2537-dec", Some(BOB));
    let std = &resp["standard"];
    assert_eq!(std["id"].as_str(), Some("bob-doc"), "got {resp}");
    for field in [
        "provenance_tier",
        "confidence_tier",
        "freshness_state",
        "score",
    ] {
        assert!(
            !std[field].is_null(),
            "#2537: the injected standard must carry `{field}` (the \
             decorate_memory_many trust signals every other returned row \
             carries); got {std}"
        );
    }
}

// ---------------------------------------------------------------------------
// memory_namespace_get_standard — the sibling unfiltered read (same chokepoint)
// ---------------------------------------------------------------------------

#[test]
fn namespace_get_standard_withholds_invisible_body_2537() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open");
    seed_cross_namespace_bind(&conn, None);

    let resp = ai_memory::mcp::handle_namespace_get_standard(
        &conn,
        &json!({"namespace": TENANT_NS}),
        Some(BOB),
    )
    .expect("get standard ok");
    let body = serde_json::to_string(&resp).expect("serialize");
    assert!(
        !body.contains(SECRET),
        "#2537: `memory_namespace_get_standard` is the SAME body read and must \
         apply the SAME predicate — an injection-only fix leaves an \
         equivalent tool call open. response={body}"
    );
    assert_eq!(resp["standards_withheld"].as_u64(), Some(1), "got {resp}");
    assert!(resp["standard_id"].is_null(), "got {resp}");

    // inherit=true walks the WHOLE chain — same disclosure rule.
    let inherit = ai_memory::mcp::handle_namespace_get_standard(
        &conn,
        &json!({"namespace": TENANT_NS, "inherit": true}),
        Some(BOB),
    )
    .expect("inherit get ok");
    let inherit_body = serde_json::to_string(&inherit).expect("serialize");
    assert!(
        !inherit_body.contains(SECRET),
        "#2537: the inherit=true chain walk must withhold too; got {inherit_body}"
    );
    assert_eq!(inherit["standards_withheld"].as_u64(), Some(1));

    // CONTROL — the owner still reads it.
    let owner = ai_memory::mcp::handle_namespace_get_standard(
        &conn,
        &json!({"namespace": TENANT_NS}),
        Some(ALICE),
    )
    .expect("owner get ok");
    assert_eq!(owner["standard_id"].as_str(), Some("alice-standard"));
    assert!(
        owner["content"]
            .as_str()
            .is_some_and(|c| c.contains(SECRET)),
        "CONTROL: the owner still receives the body; got {owner}"
    );
}

// ---------------------------------------------------------------------------
// HTTP session_start surface
// ---------------------------------------------------------------------------

fn build_router(db_path: &std::path::Path) -> axum::Router {
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn session_start_as(router: &axum::Router, ns: &str, agent: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/session/start")
        .header("Content-Type", "application/json")
        .header("X-Agent-Id", agent)
        .body(Body::from(
            json!({"namespace": ns, "limit": 50}).to_string(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn http_session_start_withholds_cross_namespace_private_standard_2537() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, None);
    }
    let router = build_router(tmp.path());

    let (status, body) = session_start_as(&router, TENANT_NS, BOB).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    assert!(
        !body.contains(SECRET),
        "#2537 HALF 1 LEAK (HTTP session_start): bob received alice's private \
         content via the injected namespace standard. response={body}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed["standards_withheld"].as_u64(), Some(1), "got {body}");
    assert!(parsed.get("standard").is_none(), "got {body}");
}

#[tokio::test]
async fn http_session_start_still_injects_visible_shared_standard_2537() {
    let tmp = NamedTempFile::new().expect("tempfile");
    {
        let conn = ai_memory::db::open(tmp.path()).expect("open");
        seed_cross_namespace_bind(&conn, Some("shared"));
    }
    let router = build_router(tmp.path());

    let (status, body) = session_start_as(&router, TENANT_NS, BOB).await;
    assert_eq!(status, StatusCode::OK, "got {status}: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        parsed["standard"]["id"].as_str(),
        Some("alice-standard"),
        "CONTROL: the documented cross-namespace shared-policy flow must keep \
         working on the HTTP session_start surface; got {body}"
    );
}
