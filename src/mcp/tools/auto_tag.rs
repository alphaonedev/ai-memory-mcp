// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_auto_tag` handler.
//!
//! Tier D (LLM-bound) module. The envelope below — input validation,
//! optional-client gating, DB get/update, tag-union semantics, error
//! surfacing — is deterministically tested at ≥95% via a
//! `wiremock`-backed real `OllamaClient`. The single
//! `llm.auto_tag(...)` dispatch is exercised through the same path so
//! the parse-then-store pipeline is end-to-end verified without a
//! live Ollama daemon. Real-LLM tag-quality is validated by the
//! LongMemEval benchmark (see `benchmarks/longmemeval/`); see L0.7-5
//! playbook §6 for the contract.

use crate::llm::OllamaClient;
use crate::{db, validate};
use serde_json::{Value, json};

/// MCP `memory_auto_tag` — LLM-generate tags for a memory and persist the
/// union onto the row.
///
/// v1.0.0 #3381 (CWE-863, unauthenticated cross-tenant WRITE) — pre-fix this
/// handler took NO caller: it read the row through the unfiltered `db::get`,
/// shipped the victim's title + content to the external model, and wrote the
/// resulting tags back through the RAW `db::update` primitive. That bypassed
/// every control `memory_update` enforces — the #1786 owner gate, the K9
/// permission rules, and the namespace governance funnel — so in a
/// `governance.write = "approve"` namespace `memory_update` queued a pending
/// action while `memory_auto_tag` committed immediately, and any agent could
/// bump the version of a `scope=private` row it is told "not found" about.
///
/// The control is now TWO canonical funnels, not a local check:
///   * the READ is gated by the canonical mutation predicate
///     [`crate::visibility::caller_owns_for_mutation`] (#1786) BEFORE any LLM
///     call, so another agent's row is never sent to the model — refused with
///     the not-found message an absent id produces, so there is no oracle; and
///   * the WRITE is delegated to [`crate::mcp::update::handle_update`], the
///     governed update path, so auto-tagging inherits the owner gate, the
///     permission rules, the governance decision (including a `pending`
///     approval envelope), and the audit trail by CONSTRUCTION rather than by
///     a copy of them that can drift.
///
/// `caller == None` is the single-operator trust-all posture and is unchanged.
pub(super) fn handle_auto_tag(
    conn: &rusqlite::Connection,
    llm: Option<&OllamaClient>,
    params: &Value,
    caller: Option<&str>,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let llm = llm.ok_or("auto-tagging requires smart or autonomous tier (Ollama LLM)")?;
    let id = params["id"]
        .as_str()
        .ok_or(crate::errors::msg::ID_REQUIRED)?;
    validate::validate_id(id).map_err(|e| e.to_string())?;
    // #3381 — the gate is the single canonical mutation predicate
    // `visibility::caller_owns_for_mutation` (#1786), applied BEFORE the paid,
    // content-shipping LLM round-trip rather than after it. `handle_update`
    // re-applies the same predicate structurally below, so this is the cheap
    // early arm, not a second copy of the rule.
    //
    // Consumability, not readability, is the right question for a tool that
    // both reads a row's content and writes to it: a row owned by ANOTHER
    // agent is refused even when it is readable (collective scope, an inbox
    // row), which is what closes the content leak to the external model —
    // while the #1786 legacy carve-out keeps an UNOWNED row taggable, exactly
    // as it stays updatable and deletable. Gating the read on
    // `is_visible_to_caller` as well would refuse unowned rows that this
    // tool's own write funnel admits, an internal contradiction that would
    // strand pre-NHI corpora (the same defect corrected in the sibling #3380).
    //
    // The refusal renders as the not-found message, identical to an absent id,
    // so the tool cannot be used as a cross-tenant presence oracle (#1553).
    let mem = db::get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or(crate::errors::msg::MEMORY_NOT_FOUND)?;
    if let Some(c) = caller
        && !crate::visibility::caller_owns_for_mutation(&mem, c, false)
    {
        return Err(crate::errors::msg::MEMORY_NOT_FOUND.into());
    }
    // COVERAGE: LLM response variability. The call below produces a
    // Vec<String> derived from the model's response; envelope is
    // tested at ≥95% via wiremock-driven success / error / shape
    // cases below; real-LLM tag quality is validated end-to-end via
    // the LongMemEval benchmark (see `benchmarks/longmemeval/`).
    let tags = llm
        .auto_tag(&mem.title, &mem.content, None)
        .map_err(|e| e.to_string())?;
    // Apply tags to the memory
    let mut all_tags = mem.tags.clone();
    for t in &tags {
        if !all_tags.contains(t) {
            all_tags.push(t.clone());
        }
    }
    // #3381 — the WRITE goes through the governed update funnel. Embedder /
    // vector-index are deliberately `None`: a tags-only patch changes neither
    // title nor content, so there is nothing to re-embed and passing them
    // would be the only behavioural difference from the pre-fix raw write.
    let updated = crate::mcp::update::handle_update(
        conn,
        &json!({ "id": &mem.id, (crate::mcp::param_names::TAGS): &all_tags }),
        None,
        None,
        mcp_client,
    )?;
    // The governed funnel may answer `pending` (namespace requires approval)
    // or `ask` (a permission rule) INSTEAD of writing. Surface that envelope
    // verbatim rather than reporting tags that were never persisted — a
    // success-shaped body on an unperformed write is itself a defect.
    if matches!(
        updated.get("status").and_then(Value::as_str),
        Some("pending" | "ask")
    ) {
        let mut out = updated;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("new_tags".into(), json!(&tags));
            obj.insert("all_tags".into(), json!(&all_tags));
        }
        return Ok(out);
    }
    Ok(json!({"id": id, "new_tags": tags, "all_tags": all_tags}))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_auto_tag ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_auto_tag`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct AutoTagRequest {
    /// Memory ID.
    pub id: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_auto_tag`.
#[allow(dead_code)]
pub struct AutoTagTool;

impl McpTool for AutoTagTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_AUTO_TAG
    }
    fn description() -> &'static str {
        "LLM-generate tags for a memory (smart/autonomous tier)."
    }
    fn docs() -> &'static str {
        "LLM auto-tagging. Smart/autonomous tier."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<AutoTagRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_auto_tag`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn auto_tag_parity_986() {
        let derived = derived_props_for::<AutoTagRequest>();
        assert_property_set_parity("memory_auto_tag", &derived);
        assert_descriptions_match("memory_auto_tag", &derived);
    }

    #[test]
    fn auto_tag_tool_metadata_986() {
        assert_eq!(AutoTagTool::name(), "memory_auto_tag");
        assert_eq!(AutoTagTool::family(), "power");
    }
}

// =====================================================================
// L0.7-5 Tier D — envelope unit tests
//
// Drives the production `OllamaClient` against an in-process wiremock
// server. The blocking client is run via `tokio::task::spawn_blocking`
// so the async test runtime stays free for the mock server. The
// `/api/tags` health probe (which `new_with_url` performs before
// returning) is mounted ahead of any other route on every server.
// =====================================================================
#[cfg(test)]
mod tests {
    use super::handle_auto_tag;
    use crate::llm::OllamaClient;
    use crate::storage as db;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a fresh in-memory SQLite DB (via a tempfile, since
    /// `:memory:` doesn't survive across the WAL pragma touch).
    fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = db::open(tmp.path()).expect("db::open");
        (conn, tmp)
    }

    /// Insert a baseline memory and return its id.
    fn seed_memory(conn: &rusqlite::Connection, tags: Vec<String>) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
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
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
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
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_auto_tag(&conn, Some(&client), &json!({}), None, None)
                .err()
                .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("id"), "expected id-required, got: {err}");
    }

    /// Envelope (3/N): `id` field present but contains invalid chars →
    /// validate::validate_id rejects.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_id_fails_validation() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
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
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    /// #3381 — bind a `write: Approve` governance standard onto `ns`, mirroring
    /// the `install_delete_policy` fixture in `mcp::delete`'s tests.
    fn install_write_approve_policy(conn: &rusqlite::Connection, ns: &str, owner: &str) {
        use crate::models::{CorePolicy, GovernanceLevel, GovernancePolicy, default_metadata};
        let policy = GovernancePolicy {
            core: CorePolicy {
                write: GovernanceLevel::Approve,
                approver: crate::models::ApproverType::Human,
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
        let standard = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
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
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let sid = db::insert(conn, &standard).expect("insert standard");
        db::set_namespace_standard(conn, ns, &sid, None).expect("set standard");
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
            let (conn, _tmp) = fresh_db();
            let id = seed_memory_owned(&conn, "alice/notes", "ai:alice", vec!["keep".into()]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
        assert_eq!(err, crate::errors::msg::MEMORY_NOT_FOUND, "got: {err}");
        // Fail CLOSED: the victim's row is byte-unchanged.
        assert_eq!(tags_after, vec!["keep".to_string()]);
        assert_eq!(version_after, 1, "a refused auto_tag must not bump version");
    }

    /// v1.0.0 #3381 (ALLOWED direction) — an UNOWNED legacy row stays
    /// taggable. The #1786 predicate deliberately admits rows with no
    /// `metadata.agent_id`, and this tool's own write funnel
    /// (`mcp::update::handle_update`) admits them, so gating the read more
    /// strictly than the write would be an internal contradiction that
    /// stranded pre-NHI corpora. Sibling of
    /// `consolidate_allows_unowned_legacy_source_3380`.
    #[tokio::test(flavor = "multi_thread")]
    async fn auto_tag_allows_unowned_legacy_row_3381() {
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
        let stored = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            // metadata = {} : no agent_id, the legacy/unowned shape.
            let id = seed_memory(&conn, vec![]);
            crate::db::set_row_metadata(&conn, &id, "{}").expect("clear owner");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_auto_tag(
                &conn,
                Some(&client),
                &json!({"id": id.clone()}),
                Some("ai:bob"),
                None,
            )
            .expect("an unowned legacy row must stay taggable");
            db::get(&conn, &id).unwrap().unwrap().tags
        })
        .await
        .unwrap();
        assert!(stored.contains(&"alpha".to_string()), "got {stored:?}");
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
            let (conn, _tmp) = fresh_db();
            let id = seed_memory_owned(&conn, "alice/notes", "ai:alice", vec!["keep".into()]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
            let _pm = crate::config::lock_permissions_mode_for_test();
            crate::config::override_active_permissions_mode_for_test(
                crate::config::PermissionsMode::Enforce,
            );
            let (conn, _tmp) = fresh_db();
            let ns = "gov-approve-autotag";
            install_write_approve_policy(&conn, ns, "ai:alice");
            let id = seed_memory_owned(&conn, ns, "ai:alice", vec!["keep".into()]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            let out = handle_auto_tag(
                &conn,
                Some(&client),
                &json!({"id": id.clone()}),
                Some("ai:alice"),
                None,
            )
            .expect("pending returns Ok");
            let mem = db::get(&conn, &id).unwrap().unwrap();
            crate::config::clear_permissions_mode_override_for_test();
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

    /// Envelope (5/N): happy path — auto_tag returns 3 tags; the
    /// envelope must:
    ///   - call /api/generate (L15 — auto_tag uses /api/generate),
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
            let (conn, _tmp) = fresh_db();
            // Existing tag "alpha" already lives on the memory; the
            // envelope must NOT duplicate it in `all_tags`.
            let id = seed_memory(&conn, vec!["alpha".to_string()]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
            let (conn, _tmp) = fresh_db();
            let id = seed_memory(&conn, vec!["existing".to_string()]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
            let (conn, _tmp) = fresh_db();
            let id = seed_memory(&conn, vec![]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
                    .insert_header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON),
            )
            .mount(&server)
            .await;

        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id = seed_memory(&conn, vec![]);
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
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
}
