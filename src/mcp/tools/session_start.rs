// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_session_start` handler.

use crate::boot_cluster::{BOOT_PAYLOAD_LIST_CAP, cluster_payload, overfetch_limit};
use crate::db;
use crate::llm::OllamaClient;
use crate::validate;
use serde_json::{Value, json};

/// The `mode` / read-surface tag for `memory_session_start` — SSOT for the
/// literal so the read-governance gate kind, the response `mode` field, and
/// the HTTP IDOR endpoint label share one site (pm-v3.1 no-hardcoded-literal
/// discipline; the hardcoded-literal ratchet flagged the third occurrence).
pub(crate) const SESSION_START_MODE: &str = "session_start";

/// MCP / HTTP entry point for `memory_session_start`.
///
/// `caller` is the resolved caller's agent_id (HTTP: via
/// `resolve_http_agent_id(body.agent_id, header_agent_id)`; MCP: via
/// `ctx.mcp_client` captured from `initialize.clientInfo.name`). When
/// `Some`, the post-list result set is filtered through
/// [`crate::visibility::is_visible_to_caller`] so `scope=private` rows owned by
/// OTHER agents are dropped before the caller sees them — closing the
/// v0.7.0 #1420 cross-agent visibility leak (6-agent review
/// reviewer 3 finding F3.3, memory `cd28329a`).
///
/// v1.0.0 #3348 — the whole post-filter now runs through
/// [`crate::visibility::is_readable_on_query`] whether or not a caller
/// resolved. `None` USED TO SKIP the filter entirely — the sentence below
/// describes that superseded posture. Substrate namespaces (`_messages/*`,
/// `_agents`, …) are withheld from an unscoped start regardless of caller;
/// ordinary namespaces keep the historical `None` = trust-all contract.
/// Superseded: when `None`, the
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
    // v0.8.0 PE-2 (#1730) — read-action governance gate (zero-config
    // fast-path when no read_action rules exist).
    {
        // Bind the surface name once (the gate kind + the refusal action
        // share it) so the literal lives on a single site — pm-v3.1
        // no-hardcoded-duplication discipline.
        let surface = SESSION_START_MODE;
        let actor = caller
            .or_else(|| params["agent_id"].as_str())
            .unwrap_or_default();
        crate::governance::agent_action::gate_read_surface(conn, actor, surface, namespace, None)
            .map_err(|r| {
            crate::governance::deny_message(
                surface,
                crate::governance::DenyGate::Governance,
                &r.reason,
            )
        })?;
    }
    let limit = usize::try_from(params["limit"].as_u64().unwrap_or(10))
        .unwrap_or(usize::MAX)
        .min(BOOT_PAYLOAD_LIST_CAP);

    let raw_results = db::list(
        conn,
        namespace,
        None,
        overfetch_limit(limit),
        0,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_at (no as-of)
    )
    .map_err(|e| e.to_string())?;

    // v0.7.0 #1420 — apply scope=private visibility filter. Pre-fix,
    // `handle_session_start` forwarded `db::list`'s un-filtered result
    // to the caller, leaking cross-agent `scope=private` rows. Mirrors
    // the post-filter shape at `src/handlers/memories_query.rs:181-185`
    // (HTTP `list_memories`). When caller is None (single-tenant MCP
    // stdio with no handshake identity), the filter is skipped —
    // legacy behavior preserved for that narrow case.
    //
    // v1.0.0 #3348 — the skipped-when-`None` arm was the reported disclosure:
    // an MCP `session_start` with no handshake identity returned other agents'
    // `_messages/*` inbox mail and `_agents` registry rows as boot memories on a
    // shared store. Routed through the visibility SSOT, which withholds
    // substrate namespaces from an unscoped start regardless of caller, and
    // leaves every ordinary namespace on the historical posture.
    let visible = raw_results
        .into_iter()
        .filter(|m| crate::visibility::is_readable_on_query(m, caller, namespace))
        .collect::<Vec<_>>();

    // #3352 — cluster near-duplicates AFTER the visibility filter so a
    // private-other-agent row can never become the representative the
    // caller sees. Over-fetch above fills the `limit` budget with
    // distinct facts once the cluster collapses.
    let clustered = cluster_payload(visible, limit, None);
    let results: Vec<crate::models::Memory> = clustered.iter().map(|c| c.memory.clone()).collect();

    // v0.8.0 #1709 §2.5 T2 — route session_start rows through the shared
    // recall decorator so provenance_tier / confidence_tier / freshness_state
    // are uniform across MCP recall, HTTP recall, and session_start (which
    // previously serialized rows directly, carrying only `score`). The
    // batched decorator issues ONE link-attestation prefetch over the rows
    // (O(1), not per-row); session_start has no recall score, so 0.0.
    let scored: Vec<(crate::models::Memory, f64)> =
        results.iter().map(|m| (m.clone(), 0.0)).collect();
    let mut memories = crate::mcp::decorate_memory_many(&scored, true, conn);
    for (decorated, member) in memories.iter_mut().zip(clustered.iter()) {
        if member.similar_count > 0
            && let Some(obj) = decorated.as_object_mut()
        {
            obj.insert(
                crate::models::field_names::SIMILAR_COUNT.to_string(),
                json!(member.similar_count),
            );
        }
    }

    let mut response = json!({
        "memories": memories,
        "count": memories.len(),
        "mode": SESSION_START_MODE,
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
    super::inject_namespace_standard(conn, namespace, caller, &mut response);

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

    /// #3171 — read-governance actor (single-tenant fallback; the resolved
    /// caller wins when present).
    #[serde(default)]
    pub agent_id: Option<String>,
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
        crate::mcp::registry::input_schema_for::<SessionStartRequest>()
    }
    fn family() -> &'static str {
        crate::profile::Family::Meta.name()
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
            cid: None,
            valid_from: None,
            valid_until: None,
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
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        db::insert(conn, &mem).expect("insert")
    }

    // ---- #3348 — substrate namespaces on the `memory_session_start` funnel --
    //
    // Reported: `boot` listed inbox-derived rows. Pre-#3348 a `None` caller
    // (single-tenant MCP stdio, no handshake identity) skipped the visibility
    // post-filter entirely, so every other agent's `_messages/*` mail was
    // eligible boot context on a shared store.

    fn seed_in(conn: &rusqlite::Connection, ns: &str, title: &str, metadata: serde_json::Value) {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("body for {title}"),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            memory_kind: crate::models::MemoryKind::Observation,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            version: 1,
            ..Memory::default()
        };
        db::insert(conn, &mem).expect("insert");
    }

    fn boot_namespaces(resp: &serde_json::Value) -> Vec<String> {
        resp["memories"]
            .as_array()
            .expect("memories array")
            .iter()
            .filter_map(|m| m["namespace"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn unscoped_session_start_withholds_substrate_rows_3348() {
        let (conn, _tmp) = fresh_db();
        seed_in(&conn, "proj", "own", json!({"agent_id": "ai:alice"}));
        seed_in(
            &conn,
            "_messages/ai:carol",
            "mail",
            json!({"agent_id": "ai:bob", "target_agent_id": "ai:carol"}),
        );
        seed_in(
            &conn,
            "_agents",
            "registry",
            json!({"agent_id": "ai:bob", "scope": "collective"}),
        );

        for caller in [None, Some("ai:alice")] {
            let resp =
                handle_session_start(&conn, &json!({"limit": 50}), None, caller).expect("ok");
            let namespaces = boot_namespaces(&resp);
            assert!(
                !namespaces.iter().any(|n| n.starts_with("_messages/")),
                "#3348: an unscoped session_start must not serve another agent's \
                 inbox mail as boot context (caller={caller:?}); got {namespaces:?}"
            );
            assert!(
                !namespaces.iter().any(|n| n == "_agents"),
                "#3348: a BROAD scope must not make the agent registry ambient boot \
                 context (caller={caller:?}); got {namespaces:?}"
            );
        }
    }

    #[test]
    fn naming_the_inbox_namespace_still_boots_your_own_mail_3348() {
        let (conn, _tmp) = fresh_db();
        seed_in(
            &conn,
            "_messages/ai:carol",
            "mail",
            json!({"agent_id": "ai:bob", "target_agent_id": "ai:carol"}),
        );
        let mine = handle_session_start(
            &conn,
            &json!({"namespace": "_messages/ai:carol", "limit": 50}),
            None,
            Some("ai:carol"),
        )
        .expect("ok");
        assert_eq!(
            boot_namespaces(&mine).len(),
            1,
            "#3348: naming the namespace is the opt-in — the recipient must still \
             reach their OWN inbox"
        );

        let theirs = handle_session_start(
            &conn,
            &json!({"namespace": "_messages/ai:carol", "limit": 50}),
            None,
            Some("ai:dave"),
        )
        .expect("ok");
        assert!(
            boot_namespaces(&theirs).is_empty(),
            "#3348: the opt-in lifts the AMBIENT exclusion only — the owner/inbox \
             predicate still confines the row to its addressee"
        );
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

    fn seed_memory_with_content(
        conn: &rusqlite::Connection,
        ns: &str,
        title: &str,
        content: &str,
    ) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
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

    /// #3352 — 5 near-duplicates + 5 distinct → session_start limit=10
    /// returns 6 memories, with `similar_count` on the collapsed cluster.
    #[test]
    fn session_start_clusters_near_duplicates_3352() {
        let (conn, _tmp) = fresh_db();
        let body = "The Grok A2A channel wiring check requires the inbox \
                    poller to sort messages by created_at rather than priority \
                    so that P10 crowding cannot hide a P9 mail about the same \
                    channel fact.";
        for i in 1..=5 {
            let _ = seed_memory_with_content(
                &conn,
                "ss-dedupe",
                &format!("Grok A2A channel wiring {i}"),
                body,
            );
        }
        let distinct = [
            (
                "Rust ownership aliasing",
                "OWNERSHIP-10 many shared references xor one exclusive mutable borrow at a time.",
            ),
            (
                "Postgres pool sizing",
                "Read-path GET links p95 dropped after the handler stopped taking the writer lock.",
            ),
            (
                "Schema ladder v96",
                "embed_skip durable skip markers land as sqlite 0080 and postgres 0053 after v95.",
            ),
            (
                "TLS listener 9077",
                "Do not restart the live mTLS endpoint; tests must never point at production PG 5445.",
            ),
            (
                "Cargo slot flock",
                "Wrap every clippy and test invocation in cargo-slot.sh with CARGO_BUILD_JOBS set.",
            ),
        ];
        for (title, content) in distinct {
            let _ = seed_memory_with_content(&conn, "ss-dedupe", title, content);
        }
        let resp = handle_session_start(
            &conn,
            &json!({"namespace": "ss-dedupe", "limit": 10}),
            None,
            None,
        )
        .expect("ok");
        assert_eq!(resp["count"].as_u64(), Some(6));
        let mems = resp["memories"].as_array().expect("memories array");
        assert_eq!(mems.len(), 6);
        let similar = mems
            .iter()
            .filter_map(|m| m.get("similar_count").and_then(Value::as_u64))
            .collect::<Vec<_>>();
        assert_eq!(similar, vec![4]);
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
