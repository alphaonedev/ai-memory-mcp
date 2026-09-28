// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4073 — the approval handler's shipped rustdoc must state the
//! contract the code enforces.
//!
//! The module and verifier docs gave the HMAC preimage as a two-part
//! timestamp-and-body string, while the verifier binds timestamp, METHOD,
//! pending row and body — so a client following the docs was refused `401` on
//! every decision. The visibility docs also promised `host:` subscribers a
//! see-everything feed that the predicate and the SSE handshake both deny.
//!
//! These pins make the docs EXECUTABLE rather than trusting prose review:
//!
//! * every signing recipe written in `src/handlers/approvals.rs` rustdoc is
//!   extracted, rendered, signed and sent to the REAL
//!   `POST /api/v1/approvals/{id}` route, which must accept it (never `401`);
//! * the older two-part preimage stays rejected (`401`) — the fix is to the
//!   docs, never a weakening of the method/row binding;
//! * the documented `host:` visibility rule is tied to the predicate's actual
//!   host-denial behaviour.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

mod common;

const SOURCE: &str = include_str!("../src/handlers/approvals.rs");
const SECRET: &str = "4073-approval-doc-contract-secret";

/// Process-global HMAC secret + replay cache: one test at a time. Async-aware
/// because the critical section spans `.await` points (CONCURRENCY-20).
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Rustdoc lines (`//!` and `///`) of the approvals handler, markers stripped.
fn doc_lines() -> Vec<&'static str> {
    SOURCE
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            t.strip_prefix("//!").or_else(|| t.strip_prefix("///"))
        })
        .collect()
}

/// Every placeholder chain ending in `<body>` that the rustdoc presents as a
/// signing preimage, e.g. `<unix_ts>.<METHOD>.<pending_id>.<body>`.
fn documented_recipes() -> Vec<String> {
    let mut out = Vec::new();
    for line in doc_lines() {
        let mut rest = line;
        while let Some(end) = rest.find("<body>") {
            let head = &rest[..end];
            // Walk back over `<placeholder>.` segments.
            let mut start = end;
            let bytes = head.as_bytes();
            loop {
                if start == 0 || bytes[start - 1] != b'.' {
                    break;
                }
                let Some(open) = head[..start - 1].rfind('<') else {
                    break;
                };
                if !head[open..start - 1].ends_with('>') {
                    break;
                }
                start = open;
            }
            if start < end {
                out.push(rest[start..end + "<body>".len()].to_string());
            }
            rest = &rest[end + "<body>".len()..];
        }
    }
    out
}

fn render(recipe: &str, ts: &str, pending_id: &str, body: &str) -> String {
    recipe
        .split('.')
        .map(|part| match part {
            "<unix_ts>" | "<timestamp>" | "<ts>" => ts.to_string(),
            "<METHOD>" => "POST".to_string(),
            "<pending_id>" | "<subject>" => pending_id.to_string(),
            "<body>" => body.to_string(),
            other => panic!("undocumented placeholder {other:?} in recipe {recipe:?}"),
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn router() -> axum::Router {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("m.db");
    let conn = ai_memory::db::open(&path).expect("db::open");
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("SqliteStore")),
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    // The tempdir must outlive the router; leak it for the test's lifetime.
    std::mem::forget(tmp);
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

/// POST a decision signed over `preimage`; return (status, body).
async fn decide(
    router: &axum::Router,
    pending_id: &str,
    ts: &str,
    preimage: &str,
    body: &str,
) -> (StatusCode, Value) {
    let key_hash = common::sha256_hex(SECRET);
    let sig = format!("sha256={}", common::hmac_sha256_hex(&key_hash, preimage));
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/approvals/{pending_id}"))
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_AI_MEMORY_TIMESTAMP, ts)
        .header(ai_memory::HEADER_AI_MEMORY_SIGNATURE, sig)
        .header(ai_memory::HEADER_AGENT_ID, "ai:operator-4073")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn every_documented_signing_recipe_is_accepted_by_the_real_verifier_4073() {
    let _g = LOCK.lock().await;
    ai_memory::config::set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    let router = router();
    let recipes = documented_recipes();
    assert!(
        !recipes.is_empty(),
        "the approvals rustdoc must document the signing recipe"
    );
    for (i, recipe) in recipes.iter().enumerate() {
        // A fresh row id + body per recipe keeps the single-use replay cache
        // from conflating two recipes that render identically.
        let pending_id = format!("pending-4073-doc-{i}");
        let body = json!({"decision": "approve", "remember": "once", "n": i}).to_string();
        let ts = chrono::Utc::now().timestamp().to_string();
        let preimage = render(recipe, &ts, &pending_id, &body);
        let (status, resp) = decide(&router, &pending_id, &ts, &preimage, &body).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "a client following the documented recipe {recipe:?} was refused by the \
             signature gate: {resp}"
        );
        assert_ne!(
            resp["error"],
            Value::String(ai_memory::errors::msg::INVALID_OR_MISSING_SIGNATURE.to_string()),
            "recipe {recipe:?}"
        );
    }
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

#[tokio::test]
async fn the_older_two_part_preimage_stays_rejected_4073() {
    let _g = LOCK.lock().await;
    ai_memory::config::set_active_hooks_hmac_secret(Some(SECRET.to_string()));
    let router = router();
    let pending_id = "pending-4073-legacy";
    let body = json!({"decision": "approve", "remember": "once"}).to_string();
    let ts = chrono::Utc::now().timestamp().to_string();
    let (status, _) = decide(&router, pending_id, &ts, &format!("{ts}.{body}"), &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "timestamp+body only must NOT verify: method and row stay bound"
    );
    // Control: the bound preimage over the SAME inputs is accepted.
    let bound = format!("{ts}.POST.{pending_id}.{body}");
    let (status, resp) = decide(&router, pending_id, &ts, &bound, &body).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{resp}");
    ai_memory::config::set_active_hooks_hmac_secret(None);
}

/// The rustdoc of `sse_event_visible_to`, as one string.
fn visibility_doc() -> String {
    let lines: Vec<&str> = SOURCE.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("pub fn sse_event_visible_to("))
        .expect("sse_event_visible_to is defined in approvals.rs");
    let mut doc = Vec::new();
    for l in lines[..at].iter().rev() {
        let t = l.trim_start();
        if let Some(d) = t.strip_prefix("///") {
            doc.push(d.trim());
        } else if !t.starts_with("#[") {
            // Attributes between the docs and the fn are skipped; anything
            // else ends the doc block.
            break;
        }
    }
    doc.reverse();
    doc.join(" ")
}

#[test]
fn documented_host_rule_matches_the_host_denial_4073() {
    let doc = visibility_doc();
    assert!(
        doc.contains("`host:`"),
        "the host: rule must stay documented: {doc}"
    );
    assert!(
        !doc.contains("see everything") && !doc.contains("sees everything"),
        "the docs must not promise host: subscribers a see-all feed: {doc}"
    );
    assert!(
        doc.contains("sees NOTHING") || doc.contains("sees nothing"),
        "the docs must state host: subscribers see nothing: {doc}"
    );
    // ...and that statement is what the predicate does, for both variants.
    let requested = ai_memory::approvals::ApprovalEvent::ApprovalRequested {
        pending_id: "p".into(),
        action_type: "store".into(),
        namespace: "ns-4073".into(),
        requested_by: "host:node-4073".into(),
        requested_at: "2026-09-27T00:00:00Z".into(),
    };
    let decided = ai_memory::approvals::ApprovalEvent::ApprovalDecided {
        pending_id: "p".into(),
        decision: "approve".into(),
        decided_by: "ai:someone".into(),
        remember: "once".into(),
        namespace: "ns-4073".into(),
        requested_by: "host:node-4073".into(),
    };
    for ev in [&requested, &decided] {
        assert!(
            !ai_memory::handlers::sse_event_visible_to("host:node-4073", ev),
            "a host: subscriber must see nothing, even its own-looking rows"
        );
    }
}
