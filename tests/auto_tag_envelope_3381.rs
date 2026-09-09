// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Auto-tag envelope and caller/governance regressions in their own process.
//! Test identity and probe-free APIs stay outside production source (#3523).

use ai_memory::llm::OllamaClient;
use ai_memory::mcp::tools::handle_auto_tag_for_tests as handle_auto_tag;
use ai_memory::storage as db;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a fresh in-memory SQLite DB (via a tempfile, since
/// `:memory:` doesn't survive across the WAL pragma touch).
fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
    std::fs::create_dir_all(".local-runs").expect("scratch directory");
    let tmp = tempfile::NamedTempFile::new_in(".local-runs").expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    (conn, tmp)
}

/// Insert a baseline memory and return its id.
fn seed_memory(conn: &rusqlite::Connection, tags: Vec<String>) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: "tier-d".to_string(),
        title: "subject".to_string(),
        content: "body of memory".to_string(),
        tags,
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:test"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    db::insert(conn, &mem).expect("insert")
}

async fn mount_tags_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(server)
        .await;
}

/// Envelope (1/N): client absent → tier-gating error message.
#[test]
fn rejects_when_llm_absent() {
    let (conn, _tmp) = fresh_db();
    let err = handle_auto_tag(&conn, None, &json!({"id": "anything"}), None, None).unwrap_err();
    assert!(
        err.contains("smart") || err.contains("autonomous") || err.contains("Ollama"),
        "expected tier-gating error, got: {err}"
    );
}

/// Envelope (2/N): missing `id` → typed error.
#[tokio::test(flavor = "multi_thread")]
async fn rejects_when_id_missing() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        handle_auto_tag(&conn, Some(&client), &json!({}), None, None)
            .err()
            .unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(err.contains("id"), "expected id-required, got: {err}");
}

/// Envelope (3/N): `id` field present but contains invalid chars →
/// `validate::validate_id` rejects.
#[tokio::test(flavor = "multi_thread")]
async fn rejects_when_id_fails_validation() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        // shell-metachar should be rejected by validate_id
        handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": "bad; rm -rf /"}),
            None,
            None,
        )
        .err()
        .unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(
        !err.is_empty(),
        "expected validation error on bad id, got empty string"
    );
}

/// Envelope (4/N): `id` is valid but missing from DB → not-found.
#[tokio::test(flavor = "multi_thread")]
async fn rejects_when_memory_not_found() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": "00000000-0000-0000-0000-000000000000"}),
            None,
            None,
        )
        .err()
        .unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(err.contains("not found"), "expected not-found, got: {err}");
}

/// v1.0.0 #3381 — seed a memory owned by `agent_id` in `namespace`.
fn seed_memory_owned(
    conn: &rusqlite::Connection,
    namespace: &str,
    agent_id: &str,
    tags: Vec<String>,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: namespace.to_string(),
        title: "subject".to_string(),
        content: "body of memory".to_string(),
        tags,
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": agent_id, "scope": "private"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    db::insert(conn, &mem).expect("insert")
}

/// #3381 — bind a `write: Approve` governance standard onto `ns`, mirroring
/// the `install_delete_policy` fixture in `mcp::delete`'s tests.
fn install_write_approve_policy(conn: &rusqlite::Connection, ns: &str, owner: &str) {
    use ai_memory::models::{CorePolicy, GovernanceLevel, GovernancePolicy, default_metadata};
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            approver: ai_memory::models::ApproverType::Human,
            ..CorePolicy::default()
        },
        ..Default::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".to_string(), json!(owner));
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(&policy).expect("serialises"),
        );
    }
    let standard = ai_memory::models::Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: format!("std-{ns}"),
        content: "policy".to_string(),
        tags: vec![],
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    let sid = db::insert(conn, &standard).expect("insert standard");
    db::set_namespace_standard(conn, ns, &sid, None).expect("set standard");
}

/// Readable foreign rows still cannot be mutated; owned substrate rows
/// are withheld even when the caller is absent. Neither refusal may egress.
#[tokio::test(flavor = "multi_thread")]
async fn auto_tag_refuses_collective_foreign_and_substrate_rows_3381() {
    let server = MockServer::start().await;
    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        for (namespace, caller) in [
            ("alice/notes", Some("ai:bob")),
            ("_agents", Some("ai:alice")),
            ("_agents", None),
        ] {
            let id = seed_memory_owned(&conn, namespace, "ai:alice", vec!["keep".into()]);
            db::set_row_metadata(
                &conn,
                &id,
                r#"{"agent_id":"ai:alice","scope":"collective"}"#,
            )
            .unwrap();
            let before = db::get(&conn, &id).unwrap().unwrap();
            let err = handle_auto_tag(&conn, Some(&client), &json!({"id": id}), caller, None)
                .expect_err("must refuse before calling the model");
            assert_eq!(err, ai_memory::errors::msg::MEMORY_NOT_FOUND);
            let after = db::get(&conn, &id).unwrap().unwrap();
            assert_eq!(after.tags, before.tags);
            assert_eq!(after.version, before.version);
        }
    })
    .await
    .unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// v1.0.0 #3381 (DENIED direction) — a non-owner is refused BEFORE the LLM
/// call and writes nothing. Pre-fix `ai:bob` calling `memory_auto_tag` on
/// `ai:alice`'s `scope=private` row shipped her title + content to the
/// model and bumped her row's version with tags she never asked for, while
/// `memory_get` on the same id refused him.
///
/// No `/api/chat` route is mounted: if the handler reached the model the
/// error would be an upstream 404, not the not-found mask asserted here.
#[tokio::test(flavor = "multi_thread")]
async fn auto_tag_refuses_non_owner_3381() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    let uri = server.uri();
    let (err, tags_after, version_after) = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let id = seed_memory_owned(&conn, "alice/notes", "ai:alice", vec!["keep".into()]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        let err = handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": id.clone()}),
            Some("ai:bob"),
            None,
        )
        .expect_err("non-owner auto_tag must be refused");
        let mem = db::get(&conn, &id).unwrap().unwrap();
        (err, mem.tags, mem.version)
    })
    .await
    .unwrap();
    assert_eq!(err, ai_memory::errors::msg::MEMORY_NOT_FOUND, "got: {err}");
    // Fail CLOSED: the victim's row is byte-unchanged.
    assert_eq!(tags_after, vec!["keep".to_string()]);
    assert_eq!(version_after, 1, "a refused auto_tag must not bump version");
}

/// An unowned private row is unreadable to an identified caller even
/// though the legacy mutation predicate would allow changing it.
#[tokio::test(flavor = "multi_thread")]
async fn auto_tag_refuses_unreadable_unowned_row_3381() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha"},
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let (err, stored) = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        // metadata = {} : no agent_id, the legacy/unowned shape.
        let id = seed_memory(&conn, vec![]);
        ai_memory::db::set_row_metadata(&conn, &id, "{}").expect("clear owner");
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        let err = handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": id.clone()}),
            Some("ai:bob"),
            None,
        )
        .expect_err("unowned private row must remain unreadable");
        (err, db::get(&conn, &id).unwrap().unwrap().tags)
    })
    .await
    .unwrap();
    assert_eq!(err, ai_memory::errors::msg::MEMORY_NOT_FOUND);
    assert!(stored.is_empty());
}

/// #3381 (ALLOWED direction) — the OWNER still auto-tags, and the union
/// still persists through the governed update funnel.
#[tokio::test(flavor = "multi_thread")]
async fn auto_tag_allows_owner_3381() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha\nbeta"},
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let (out, stored) = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::set("ai:alice");
        let (conn, _tmp) = fresh_db();
        let id = seed_memory_owned(&conn, "alice/notes", "ai:alice", vec!["keep".into()]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        let out = handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": id.clone()}),
            Some("ai:alice"),
            None,
        )
        .expect("owner auto_tag must succeed");
        let mem = db::get(&conn, &id).unwrap().unwrap();
        (out, mem.tags)
    })
    .await
    .unwrap();
    assert_eq!(out["new_tags"].as_array().unwrap().len(), 2);
    assert_eq!(
        stored.len(),
        3,
        "union of keep + alpha + beta, got {stored:?}"
    );
}

/// #3381 — in a `governance.write = "approve"` namespace the tool now
/// QUEUES a pending action exactly as `memory_update` does, instead of
/// committing immediately around the governance funnel. The row must be
/// untouched and the envelope must say `pending` rather than reporting
/// tags that were never persisted.
#[tokio::test(flavor = "multi_thread")]
async fn auto_tag_governed_namespace_queues_pending_3381() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha\nbeta"},
        })))
        .mount(&server)
        .await;
    let uri = server.uri();
    let (out, stored) = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::set("ai:alice");
        let _pm = ai_memory::config::lock_permissions_mode_for_test();
        ai_memory::config::override_active_permissions_mode_for_test(
            ai_memory::config::PermissionsMode::Enforce,
        );
        let (conn, _tmp) = fresh_db();
        let ns = "gov-approve-autotag";
        // #3292: the standard owner auto-allows; a distinct policy owner
        // makes Alice's otherwise-authorized tag update require approval.
        install_write_approve_policy(&conn, ns, "ai:governor");
        let id = seed_memory_owned(&conn, ns, "ai:alice", vec!["keep".into()]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        let out = handle_auto_tag(
            &conn,
            Some(&client),
            &json!({"id": id.clone()}),
            Some("ai:alice"),
            None,
        )
        .expect("pending returns Ok");
        let pending =
            db::get_pending_action(&conn, out["pending_id"].as_str().expect("pending id"))
                .unwrap()
                .expect("persisted pending action");
        assert_eq!(
            pending.requested_by, "ai:alice",
            "#3171: preserve the caller"
        );
        let mem = db::get(&conn, &id).unwrap().unwrap();
        ai_memory::config::clear_permissions_mode_override_for_test();
        (out, mem.tags)
    })
    .await
    .unwrap();
    assert_eq!(out["status"].as_str(), Some("pending"), "got: {out}");
    assert!(out["pending_id"].as_str().is_some(), "got: {out}");
    assert_eq!(
        stored,
        vec!["keep".to_string()],
        "a queued auto_tag must not write the tags"
    );
}

/// Envelope (5/N): happy path — `auto_tag` returns 3 tags; the
/// envelope must:
///   - call `/api/chat` to generate tags,
///   - lowercase + dedupe with existing tags,
///   - persist the union onto the memory row,
///   - shape `{id, new_tags, all_tags}` for the caller.
#[tokio::test(flavor = "multi_thread")]
async fn success_unions_tags_and_persists() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "alpha\nbeta\ngamma"},
        })))
        .mount(&server)
        .await;

    let uri = server.uri();
    let (id, value) = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        // Existing tag "alpha" already lives on the memory; the
        // envelope must NOT duplicate it in `all_tags`.
        let id = seed_memory(&conn, vec!["alpha".to_string()]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        let out = handle_auto_tag(&conn, Some(&client), &json!({"id": id.clone()}), None, None)
            .expect("handler should succeed");
        // Verify DB state — `tags` column carries the union now.
        let mem = db::get(&conn, &id).unwrap().unwrap();
        (id, json!({"out": out, "stored_tags": mem.tags}))
    })
    .await
    .unwrap();

    let out = &value["out"];
    assert_eq!(out["id"], json!(id));
    let new_tags = out["new_tags"].as_array().unwrap();
    assert_eq!(new_tags.len(), 3);
    let all_tags = out["all_tags"].as_array().unwrap();
    // alpha already existed; beta + gamma are new — union is 3.
    assert_eq!(all_tags.len(), 3);
    // Stored row reflects the union.
    let stored = value["stored_tags"].as_array().unwrap();
    assert_eq!(stored.len(), 3);
}

/// Envelope (6/N): LLM returns no tags (blank-only output) — the
/// envelope still completes; `new_tags` is empty and `all_tags`
/// is unchanged from the prior state.
#[tokio::test(flavor = "multi_thread")]
async fn success_with_empty_response_yields_no_new_tags() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "   \n  \n"},
        })))
        .mount(&server)
        .await;

    let uri = server.uri();
    let out = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let id = seed_memory(&conn, vec!["existing".to_string()]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        handle_auto_tag(&conn, Some(&client), &json!({"id": id}), None, None).expect("ok")
    })
    .await
    .unwrap();
    let new_tags = out["new_tags"].as_array().unwrap();
    assert!(new_tags.is_empty());
    let all_tags = out["all_tags"].as_array().unwrap();
    assert_eq!(all_tags.len(), 1);
    assert_eq!(all_tags[0], "existing");
}

/// Envelope (7/N): LLM 500 → error surfaces through `?`.
#[tokio::test(flavor = "multi_thread")]
async fn surfaces_llm_500_error() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(500).set_body_string("oh no"))
        .mount(&server)
        .await;

    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let id = seed_memory(&conn, vec![]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        handle_auto_tag(&conn, Some(&client), &json!({"id": id}), None, None)
            .err()
            .unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(
        err.contains("500") || err.contains("Generate failed"),
        "expected upstream error, got: {err}"
    );
}

/// Envelope (8/N): malformed JSON from LLM → parse error.
#[tokio::test(flavor = "multi_thread")]
async fn surfaces_llm_malformed_json_error() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("not valid")
                .insert_header(ai_memory::HEADER_CONTENT_TYPE, ai_memory::MIME_JSON),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let _identity = ai_memory::identity::test_agent_id::AgentIdOverride::unset();
        let (conn, _tmp) = fresh_db();
        let id = seed_memory(&conn, vec![]);
        let client = OllamaClient::new_for_tests_without_probe(&uri, "test-model").unwrap();
        handle_auto_tag(&conn, Some(&client), &json!({"id": id}), None, None)
            .err()
            .unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(
        err.to_lowercase().contains("parse") || err.to_lowercase().contains("json"),
        "expected parse-error, got: {err}"
    );
}
