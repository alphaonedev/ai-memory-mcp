// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_session_start` handler.

use crate::db;
use crate::llm::OllamaClient;
use crate::validate;
use crate::visibility::is_visible_to_caller;
use serde_json::{Value, json};

/// MCP / HTTP entry point for `memory_session_start`.
///
/// `caller` is the resolved caller's agent_id (HTTP: via
/// `resolve_http_agent_id(body.agent_id, header_agent_id)`; MCP: via
/// `ctx.mcp_client` captured from `initialize.clientInfo.name`). When
/// `Some`, the post-list result set is filtered through
/// [`is_visible_to_caller`] so `scope=private` rows owned by OTHER
/// agents are dropped before the caller sees them — closing the
/// v0.7.0 #1420 cross-agent visibility leak (6-agent review
/// reviewer 3 finding F3.3, memory `cd28329a`). When `None`, the
/// post-filter is skipped — this preserves the single-tenant MCP
/// stdio posture where no caller identity was captured at handshake;
/// HTTP always synthesizes a caller (`anonymous:req-…`) so the HTTP
/// surface is never in the `None` branch.
pub(crate) fn handle_session_start(
    conn: &rusqlite::Connection,
    params: &Value,
    llm: Option<&OllamaClient>,
    caller: Option<&str>,
) -> Result<Value, String> {
    let namespace = params["namespace"].as_str();
    // B4 (R2-LOW) — every MCP entry point that accepts a `namespace`
    // arg must call `validate::validate_namespace` so a payload like
    // `{"namespace": "foo bar"}` is rejected with a typed error
    // instead of silently flowing through to `db::list` (where it
    // may interact with FTS5 escape semantics or downstream filters
    // in surprising ways). Skip when omitted — the handler defaults
    // to "all namespaces" in that case.
    if let Some(ns) = namespace {
        validate::validate_namespace(ns).map_err(|e| e.to_string())?;
    }
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(10)).unwrap_or(usize::MAX);

    let raw_results = db::list(
        conn,
        namespace,
        None,
        limit.min(50),
        0,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|e| e.to_string())?;

    // v0.7.0 #1420 — apply scope=private visibility filter. Pre-fix,
    // `handle_session_start` forwarded `db::list`'s un-filtered result
    // to the caller, leaking cross-agent `scope=private` rows. Mirrors
    // the post-filter shape at `src/handlers/memories_query.rs:181-185`
    // (HTTP `list_memories`). When caller is None (single-tenant MCP
    // stdio with no handshake identity), the filter is skipped —
    // legacy behavior preserved for that narrow case.
    let results = if let Some(caller_id) = caller {
        raw_results
            .into_iter()
            .filter(|m| is_visible_to_caller(m, caller_id))
            .collect::<Vec<_>>()
    } else {
        raw_results
    };

    let memories: Vec<Value> = results
        .iter()
        .map(|mem| {
            let mut val = serde_json::to_value(mem).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("score".to_string(), json!(0.0));
            }
            val
        })
        .collect();

    let mut response = json!({
        "memories": memories,
        "count": memories.len(),
        "mode": "session_start",
    });

    if let Some(llm_client) = llm
        && !results.is_empty()
    {
        let pairs: Vec<(String, String)> = results
            .iter()
            .map(|m| (m.title.clone(), m.content.clone()))
            .collect();
        match llm_client.summarize_memories(&pairs) {
            Ok(summary) => {
                response["summary"] = json!(summary);
            }
            Err(e) => {
                tracing::warn!("session_start LLM summary failed: {}", e);
            }
        }
    }

    // Auto-register parent chain from filesystem path — disabled by default
    // to prevent filesystem structure leakage into the memory database.
    // Uncomment or gate behind a config flag if desired.

    // Auto-prepend namespace standard (after LLM summary, separate field)
    super::inject_namespace_standard(conn, namespace, &mut response);

    Ok(response)
}

// --- D1.5 (#986): per-tool McpTool impl for memory_session_start ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_session_start`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct SessionStartRequest {
    /// Namespace filter.
    #[serde(default)]
    pub namespace: Option<String>,

    /// Limit cap 50; default 10.
    #[serde(default)]
    pub limit: Option<i64>,

    /// Output envelope: `json`, `toon`, or `toon_compact` (default).
    #[serde(default)]
    pub format: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_session_start`.
#[allow(dead_code)]
pub struct SessionStartTool;

impl McpTool for SessionStartTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_SESSION_START
    }
    fn description() -> &'static str {
        "Auto-recall recent memories on session start."
    }
    fn docs() -> &'static str {
        "Most-recently-accessed/updated. At smart/autonomous tier, includes LLM summary."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(SessionStartRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "meta"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_session_start`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn session_start_parity_986() {
        let derived = derived_props_for::<SessionStartRequest>();
        assert_property_set_parity("memory_session_start", &derived);
        assert_descriptions_match("memory_session_start", &derived);
    }

    #[test]
    fn session_start_tool_metadata_986() {
        assert_eq!(SessionStartTool::name(), "memory_session_start");
        assert_eq!(SessionStartTool::family(), "meta");
    }
}

#[cfg(test)]
mod tests {
    //! Coverage C-2 — focused tests for `handle_session_start`.

    use super::*;
    use crate::models::{Memory, Tier};
    use crate::storage as db;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = db::open(tmp.path()).expect("db::open");
        (conn, tmp)
    }

    fn seed_memory(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            tags: vec![],
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
        };
        db::insert(conn, &mem).expect("insert")
    }

    // Happy path without LLM — returns memories + count, mode tag.
    #[test]
    fn no_llm_returns_memories_and_count() {
        let (conn, _tmp) = fresh_db();
        let _ = seed_memory(&conn, "ss-ns", "hi");
        let resp =
            handle_session_start(&conn, &json!({"namespace": "ss-ns"}), None, None).expect("ok");
        assert_eq!(resp["mode"], "session_start");
        assert_eq!(resp["count"].as_u64(), Some(1));
        let mems = resp["memories"].as_array().unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0]["score"].as_f64(), Some(0.0));
    }

    // Invalid namespace rejected.
    #[test]
    fn invalid_namespace_rejected() {
        let (conn, _tmp) = fresh_db();
        let err = handle_session_start(&conn, &json!({"namespace": "has spaces"}), None, None)
            .unwrap_err();
        assert!(!err.is_empty());
    }

    // Limit clamped at 50 — pass 1000, ensure no overflow.
    #[test]
    fn large_limit_does_not_explode() {
        let (conn, _tmp) = fresh_db();
        let _ = seed_memory(&conn, "lim-ns", "a");
        let resp = handle_session_start(
            &conn,
            &json!({"namespace": "lim-ns", "limit": 1000}),
            None,
            None,
        )
        .expect("ok");
        // Only seeded one row.
        assert_eq!(resp["count"].as_u64(), Some(1));
    }

    // Namespace omitted — all-namespaces list.
    #[test]
    fn omitted_namespace_returns_all() {
        let (conn, _tmp) = fresh_db();
        let _ = seed_memory(&conn, "ns-a", "a");
        let _ = seed_memory(&conn, "ns-b", "b");
        let resp = handle_session_start(&conn, &json!({}), None, None).expect("ok");
        assert!(resp["count"].as_u64().unwrap() >= 2);
    }

    // LLM-summary happy path — summary field populated.
    #[tokio::test(flavor = "multi_thread")]
    async fn llm_summary_populates_field() {
        let server = MockServer::start().await;
        // Ollama chat endpoint
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"content": "summary text"},
                "done": true,
            })))
            .mount(&server)
            .await;
        // Ensure-model tags endpoint
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let resp = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let _ = seed_memory(&conn, "llm-ns", "title-1");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_session_start(&conn, &json!({"namespace": "llm-ns"}), Some(&client), None)
                .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(resp["summary"].as_str(), Some("summary text"));
    }

    // LLM-summary fails — warning logged, but response still returned.
    #[tokio::test(flavor = "multi_thread")]
    async fn llm_summary_error_is_non_fatal() {
        let server = MockServer::start().await;
        // /api/chat returns 500 — the summarize_memories call fails.
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let resp = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let _ = seed_memory(&conn, "errllm-ns", "title-2");
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_session_start(
                &conn,
                &json!({"namespace": "errllm-ns"}),
                Some(&client),
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        // Summary field absent on error — handler tracing::warns.
        assert!(resp.get("summary").is_none());
        // But the response is still well-formed.
        assert_eq!(resp["count"].as_u64(), Some(1));
    }

    // LLM provided but no memories — summarize not invoked, no panic.
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_results_skip_llm_summarize() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let uri = server.uri();
        let resp = tokio::task::spawn_blocking(move || {
            let (conn, _tmp) = fresh_db();
            let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
            handle_session_start(
                &conn,
                &json!({"namespace": "empty-ns"}),
                Some(&client),
                None,
            )
            .expect("ok")
        })
        .await
        .unwrap();
        assert_eq!(resp["count"].as_u64(), Some(0));
        // No LLM call fired → no summary field.
        assert!(resp.get("summary").is_none());
    }
}
