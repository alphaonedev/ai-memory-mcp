// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_detect_contradiction` handler.
//!
//! Tier D (LLM-bound) module. The envelope below — input validation,
//! optional-client gating, two-memory lookup, error surfacing,
//! response shaping — is deterministically tested at ≥95% via a
//! `wiremock`-backed real `OllamaClient`. The single
//! `llm.detect_contradiction(...)` dispatch is exercised through the
//! same path. Real-LLM judgement quality is validated by the
//! LongMemEval benchmark (see `benchmarks/longmemeval/`); see L0.7-5
//! playbook §6 for the contract.

use crate::llm::OllamaClient;
use crate::mcp::get::mask_invisible;
use crate::{db, validate};
use serde_json::{Value, json};

/// v1.0.0 #3387 — existence-hiding refusal for `id_a`.
///
/// Returned BOTH when the id resolves to no row AND when it resolves to a row
/// the caller may not see, so the two arms are byte-identical on the wire and
/// the tool cannot be used as a cross-tenant presence oracle. The wire string
/// is unchanged from the pre-#3387 absent-row arm.
const NOT_FOUND_A: &str = "memory A not found";

/// v1.0.0 #3387 — existence-hiding refusal for `id_b`. See [`NOT_FOUND_A`].
const NOT_FOUND_B: &str = "memory B not found";

/// `memory_detect_contradiction` — LLM-judge whether two memories conflict.
///
/// # Caller scoping (v1.0.0 #3387)
///
/// `caller` is the resolved read-visibility principal
/// ([`crate::identity::resolve_read_visibility_caller`]), NOT a wire-supplied
/// `agent_id` — the tool declares no such parameter, so the principal is not
/// caller-choosable. BOTH ids are funnelled through
/// [`crate::mcp::get::mask_invisible`] — the same canonical visibility
/// predicate `memory_get` applies — BEFORE the LLM dispatch, because this tool
/// is doubly content-disclosing: it returns both rows' titles to the caller AND
/// ships both rows' full bodies to an external model. Pre-#3387 there was no
/// gate at all, so a caller who gets a bare "memory not found" from
/// `memory_get` on either id still got that id's title back and had its body
/// exfiltrated to the LLM endpoint.
///
/// `caller == None` is the single-tenant trust-all posture and is preserved.
pub(super) fn handle_detect_contradiction(
    conn: &rusqlite::Connection,
    llm: Option<&OllamaClient>,
    params: &Value,
    caller: Option<&str>,
) -> Result<Value, String> {
    let llm =
        llm.ok_or("contradiction detection requires smart or autonomous tier (Ollama LLM)")?;
    let id_a = params["id_a"].as_str().ok_or("id_a is required")?;
    let id_b = params["id_b"].as_str().ok_or("id_b is required")?;
    validate::validate_id(id_a).map_err(|e| e.to_string())?;
    validate::validate_id(id_b).map_err(|e| e.to_string())?;
    // #3387 — resolve BOTH ids through the caller-scoped read before any LLM
    // call. Fails closed: an unreadable row refuses with the same message an
    // absent row does, and the refusal happens above the `llm.` dispatch so a
    // denied caller causes ZERO egress of either body.
    let mem_a = mask_invisible(db::get(conn, id_a).map_err(|e| e.to_string())?, caller)
        .ok_or(NOT_FOUND_A)?;
    let mem_b = mask_invisible(db::get(conn, id_b).map_err(|e| e.to_string())?, caller)
        .ok_or(NOT_FOUND_B)?;
    // COVERAGE: LLM response variability. The boolean below is derived
    // from the model's free-form yes/no answer. Envelope is tested at
    // ≥95% via wiremock-driven success / error / shape cases; real-LLM
    // contradiction judgement is validated end-to-end via the
    // LongMemEval benchmark (see `benchmarks/longmemeval/`).
    let contradicts = llm
        .detect_contradiction(&mem_a.content, &mem_b.content)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        (crate::models::link::REL_CONTRADICTS): contradicts,
        "memory_a": {"id": id_a, "title": mem_a.title},
        "memory_b": {"id": id_b, "title": mem_b.title}
    }))
}

// --- D1.5 (#986): per-tool McpTool impl for memory_detect_contradiction ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_detect_contradiction`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct DetectContradictionRequest {
    /// First memory ID.
    pub id_a: String,

    /// Second memory ID.
    pub id_b: String,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_detect_contradiction`.
#[allow(dead_code)]
pub struct DetectContradictionTool;

impl McpTool for DetectContradictionTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_DETECT_CONTRADICTION
    }
    fn description() -> &'static str {
        "LLM-check whether two memories contradict each other (smart/autonomous tier)."
    }
    fn docs() -> &'static str {
        "LLM contradiction check. Smart/autonomous tier."
    }
    fn input_schema() -> Value {
        crate::mcp::registry::input_schema_for::<DetectContradictionRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Power.name()
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_detect_contradiction`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn detect_contradiction_parity_986() {
        let derived = derived_props_for::<DetectContradictionRequest>();
        assert_property_set_parity("memory_detect_contradiction", &derived);
        assert_descriptions_match("memory_detect_contradiction", &derived);
    }

    #[test]
    fn detect_contradiction_tool_metadata_986() {
        assert_eq!(
            DetectContradictionTool::name(),
            "memory_detect_contradiction"
        );
        assert_eq!(DetectContradictionTool::family(), "power");
    }
}

// =====================================================================
// L0.7-5 Tier D — envelope unit tests
//
// Drives the production `OllamaClient` against an in-process wiremock
// server. `detect_contradiction` uses /api/chat (not /api/generate)
// and reads `message.content`. The client's blocking nature is bridged
// through `tokio::task::spawn_blocking`.
// =====================================================================
#[cfg(test)]
mod tests {
    use super::handle_detect_contradiction;
    use crate::llm::OllamaClient;
    use crate::storage as db;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = db::open(tmp.path()).expect("db::open");
        (conn, tmp)
    }

    fn seed(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
        seed_owned(conn, title, content, "ai:test")
    }

    /// v1.0.0 #3387 — seed a `scope`-less (i.e. private-by-default) row owned
    /// by `owner`, so the visibility funnel has something to refuse.
    fn seed_owned(conn: &rusqlite::Connection, title: &str, content: &str, owner: &str) -> String {
        seed_scoped(conn, title, content, owner, None)
    }

    /// v1.0.0 #3387 — as [`seed_owned`], with an explicit `metadata.scope`.
    fn seed_scoped(
        conn: &rusqlite::Connection,
        title: &str,
        content: &str,
        owner: &str,
        scope: Option<&str>,
    ) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let metadata = match scope {
            Some(scope) => json!({"agent_id": owner, "scope": scope}),
            None => json!({"agent_id": owner}),
        };
        let mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "tier-d".to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
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
        db::insert(conn, &mem).expect("insert")
    }

    async fn mount_tags_ok(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(server)
            .await;
    }

    /// Envelope (1/N): client absent → tier-gating error.
    #[test]
    fn rejects_when_llm_absent() {
        let (conn, _tmp) = fresh_db();
        let err =
            handle_detect_contradiction(&conn, None, &json!({"id_a": "x", "id_b": "y"}), None)
                .unwrap_err();
        assert!(
            err.contains("smart") || err.contains("autonomous") || err.contains("Ollama"),
            "expected tier-gating error, got: {err}"
        );
    }

    /// Envelope (2/N): id_a missing → typed error.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_id_a_missing() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(&conn, Some(&client), &json!({"id_b": "y"}), None)
                .err()
                .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("id_a"), "expected id_a-required, got: {err}");
    }

    /// Envelope (3/N): id_b missing → typed error.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_id_b_missing() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(&conn, Some(&client), &json!({"id_a": "x"}), None)
                .err()
                .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(err.contains("id_b"), "expected id_b-required, got: {err}");
    }

    /// Envelope (4/N): bad id_a fails validation.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_id_a_fails_validation() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": "bad; rm -rf /", "id_b": "anything"}),
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(!err.is_empty(), "expected validation error on bad id_a");
    }

    /// Envelope (5/N): id_a not present in DB.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_memory_a_not_found() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({
                    "id_a": "00000000-0000-0000-0000-000000000000",
                    "id_b": "11111111-1111-1111-1111-111111111111"
                }),
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(
            err.contains("memory A not found") || err.contains("not found"),
            "expected memory-A-not-found, got: {err}"
        );
    }

    /// Envelope (6/N): id_a in DB but id_b not — must surface
    /// "memory B not found" specifically.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_when_memory_b_not_found() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "A", "alpha");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({
                    "id_a": id_a,
                    "id_b": "11111111-1111-1111-1111-111111111111"
                }),
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(
            err.contains("memory B not found") || err.contains("not found"),
            "expected memory-B-not-found, got: {err}"
        );
    }

    /// Envelope (7/N): happy path — LLM says "yes" → contradicts=true.
    /// Response shape must carry both titles and ids.
    #[tokio::test(flavor = "multi_thread")]
    async fn success_yes_response_yields_contradicts_true() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "yes\n"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "title-a", "the sky is blue");
            let id_b = seed(&conn, "title-b", "the sky is green");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(out["contradicts"], json!(true));
        assert_eq!(out["memory_a"]["title"], "title-a");
        assert_eq!(out["memory_b"]["title"], "title-b");
        assert!(out["memory_a"]["id"].as_str().is_some());
        assert!(out["memory_b"]["id"].as_str().is_some());
    }

    /// Envelope (8/N): "no" response → contradicts=false.
    #[tokio::test(flavor = "multi_thread")]
    async fn success_no_response_yields_contradicts_false() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "no"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "A", "alpha");
            let id_b = seed(&conn, "B", "consistent with alpha");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(out["contradicts"], json!(false));
    }

    /// Envelope (9/N): LLM 500 surfaces through `?`.
    #[tokio::test(flavor = "multi_thread")]
    async fn surfaces_llm_500_error() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "A", "a");
            let id_b = seed(&conn, "B", "b");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                None,
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert!(
            err.contains("500") || err.contains("Chat generate failed"),
            "expected upstream error, got: {err}"
        );
    }

    /// Envelope (10/N): malformed JSON from LLM → parse error.
    #[tokio::test(flavor = "multi_thread")]
    async fn surfaces_llm_malformed_json_error() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("oops not json")
                    .insert_header(crate::HEADER_CONTENT_TYPE, crate::MIME_JSON),
            )
            .mount(&server)
            .await;

        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "A", "a");
            let id_b = seed(&conn, "B", "b");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                None,
            )
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

    /// Envelope (11/N): LLM returns garbage (not yes/no) → handler
    /// completes with contradicts=false (per `starts_with("yes")`
    /// semantics in OllamaClient::detect_contradiction).
    #[tokio::test(flavor = "multi_thread")]
    async fn garbage_response_defaults_to_false() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "mu"},
            })))
            .mount(&server)
            .await;

        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed(&conn, "A", "a");
            let id_b = seed(&conn, "B", "b");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(out["contradicts"], json!(false));
    }

    // =================================================================
    // v1.0.0 #3387 — cross-tenant read-oracle regression.
    //
    // Pre-#3387 this tool did an UNSCOPED `db::get` on both ids: a caller
    // who gets a bare not-found from `memory_get` on either id still got
    // that row's TITLE back in the response AND had its full body shipped
    // to the external LLM endpoint. Both the denied and the allowed path
    // are pinned below; the denied path additionally asserts ZERO egress.
    // =================================================================

    /// Mount a chat endpoint that would answer "yes" if it were ever
    /// reached, so a regression shows up as a SUCCESSFUL response rather
    /// than an incidental transport error.
    async fn mount_chat_yes(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "yes"},
            })))
            .mount(server)
            .await;
    }

    /// Count POSTs that actually reached the model endpoint.
    async fn chat_calls(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("request recording enabled")
            .iter()
            .filter(|r| r.url.path() == "/api/chat")
            .count()
    }

    /// #3387 DENIED (id_a): a non-owner caller is refused with the same
    /// message an absent row yields, and NO LLM call is made.
    #[tokio::test(flavor = "multi_thread")]
    async fn non_owner_refused_on_id_a_with_no_llm_call_3387() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        mount_chat_yes(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed_owned(&conn, "victim-title-a", "victim body a", "ai:victim");
            let id_b = seed_owned(&conn, "victim-title-b", "victim body b", "ai:victim");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                Some("ai:attacker"),
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert_eq!(
            err, "memory A not found",
            "non-owner must get the existence-hiding refusal, got: {err}"
        );
        assert_eq!(
            chat_calls(&server).await,
            0,
            "refused caller must cause ZERO egress of either memory body"
        );
    }

    /// #3387 DENIED (id_b): id_a is the caller's own row, id_b is another
    /// tenant's — refusal must land on B, still with no LLM call, so the
    /// gate cannot be side-stepped by pairing a readable id with a
    /// victim id.
    #[tokio::test(flavor = "multi_thread")]
    async fn non_owner_refused_on_id_b_with_no_llm_call_3387() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        mount_chat_yes(&server).await;
        let uri = server.uri();
        let err = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed_owned(&conn, "own-title", "own body", "ai:attacker");
            let id_b = seed_owned(&conn, "victim-title-b", "victim body b", "ai:victim");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                Some("ai:attacker"),
            )
            .err()
            .unwrap_or_default()
        })
        .await
        .unwrap();
        assert_eq!(
            err, "memory B not found",
            "non-owner must get the existence-hiding refusal on B, got: {err}"
        );
        assert_eq!(
            chat_calls(&server).await,
            0,
            "refused caller must cause ZERO egress of either memory body"
        );
    }

    /// #3387 DENIED, existence-hiding: the refusal for a row that EXISTS
    /// but is invisible is byte-identical to the refusal for a row that
    /// does not exist, so the tool is not a presence oracle.
    #[tokio::test(flavor = "multi_thread")]
    async fn invisible_and_absent_refusals_are_identical_3387() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        mount_chat_yes(&server).await;
        let uri = server.uri();
        let (invisible, absent) = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed_owned(&conn, "victim-title-a", "victim body a", "ai:victim");
            let id_b = seed_owned(&conn, "own-title", "own body", "ai:attacker");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            let invisible = handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                Some("ai:attacker"),
            )
            .err()
            .unwrap_or_default();
            let absent = handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({
                    "id_a": "00000000-0000-0000-0000-000000000000",
                    "id_b": id_b
                }),
                Some("ai:attacker"),
            )
            .err()
            .unwrap_or_default();
            (invisible, absent)
        })
        .await
        .unwrap();
        assert_eq!(
            invisible, absent,
            "existing-but-invisible and absent must be indistinguishable"
        );
        assert_eq!(chat_calls(&server).await, 0, "no egress on either refusal");
    }

    /// #3387 ALLOWED: the owner still gets the full result — the gate
    /// degrades nothing for an entitled caller.
    #[tokio::test(flavor = "multi_thread")]
    async fn owner_caller_still_gets_verdict_3387() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        mount_chat_yes(&server).await;
        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed_owned(&conn, "title-a", "the sky is blue", "ai:owner");
            let id_b = seed_owned(&conn, "title-b", "the sky is green", "ai:owner");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                Some("ai:owner"),
            )
            .expect("owner must be allowed")
        })
        .await
        .unwrap();
        assert_eq!(out["contradicts"], json!(true));
        assert_eq!(out["memory_a"]["title"], "title-a");
        assert_eq!(out["memory_b"]["title"], "title-b");
        assert_eq!(chat_calls(&server).await, 1, "owner reaches the model once");
    }

    /// #3387 ALLOWED: a `collective`-scope row stays readable by any
    /// caller — the gate is the canonical `is_visible_to_caller`
    /// predicate, not a blanket owner-equality check.
    #[tokio::test(flavor = "multi_thread")]
    async fn collective_scope_row_readable_by_other_caller_3387() {
        let server = MockServer::start().await;
        mount_tags_ok(&server).await;
        mount_chat_yes(&server).await;
        let uri = server.uri();
        let out = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let id_a = seed_scoped(
                &conn,
                "shared-a",
                "the sky is blue",
                "ai:owner",
                Some("collective"),
            );
            let id_b = seed_scoped(
                &conn,
                "shared-b",
                "the sky is green",
                "ai:owner",
                Some("collective"),
            );
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_detect_contradiction(
                &conn,
                Some(&client),
                &json!({"id_a": id_a, "id_b": id_b}),
                Some("ai:stranger"),
            )
            .expect("collective rows are visible to every caller")
        })
        .await
        .unwrap();
        assert_eq!(out["contradicts"], json!(true));
        assert_eq!(chat_calls(&server).await, 1);
    }
}
