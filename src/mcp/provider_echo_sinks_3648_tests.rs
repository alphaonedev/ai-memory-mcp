// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3648 — the MCP chat-tool SINKS, end to end through `handle_request` with a
//! mock provider that echoes a secret: the `isError` text a caller sees and
//! the operator log line must both be free of the provider body, and BOTH
//! must carry the bounded diagnostic (the presence control that keeps the
//! absence assertion from being vacuous). The provider boundary itself is
//! pinned by `tests/provider_error_redaction_3648.rs`; this pins that the
//! four tools which render an LLM failure — `memory_expand_query`,
//! `memory_auto_tag`, `memory_consolidate`, `memory_detect_contradiction` —
//! reach the wire and the log ONLY through `error_text::llm` +
//! `mcp_foreign_err` (target `mcp.tool.error`), so a future `.context(body)`
//! at any chat call site fails here rather than reaching a tenant.
use super::*;
use crate::llm::OllamaClient;
use crate::models::{Memory, MemoryKind, Tier};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "provider-echo-credential-3648-mcp";

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn seed(conn: &rusqlite::Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "echo-3648".to_string(),
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
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    crate::db::insert(conn, &mem).expect("seed")
}

/// The real dispatch sink with a live LLM client threaded in — the same
/// argument list `tests::invoke_handle_request` uses, plus `llm`.
fn call_tool(conn: &rusqlite::Connection, llm: &OllamaClient, tool: &str, args: Value) -> Value {
    // No attestation installer: none of the four tools crosses the
    // attested STORE surface (the MCP surface is permissive by default,
    // #1985), and a process-global env write would trip the #3523 arm (e)
    // ratchet for a lib-test module.
    let tier_config = FeatureTier::Keyword.config();
    let resolved_ttl = crate::config::ResolvedTtl::default();
    let resolved_scoring = crate::config::ResolvedScoring::default();
    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3648)),
        method: "tools/call".to_string(),
        params: json!({"name": tool, "arguments": args}),
    };
    let response = handle_request(
        conn,
        std::path::Path::new(":memory:"),
        &request,
        None,
        Some(llm),
        None,
        &tier_config,
        &crate::config::ResolvedModels::from_tier_preset(&tier_config),
        None,
        &resolved_ttl,
        &resolved_scoring,
        true,
        false,
        None,
        &crate::profile::Profile::full(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        "test-session",
    );
    response
        .result
        .expect("tools/call answers with a result envelope")
}

/// One (tool, provider, response) cell: the caller's `isError` text and the
/// operator log line are both secret-free, bounded, and carry the diagnostic.
fn assert_sink(
    conn: &rusqlite::Connection,
    llm: &OllamaClient,
    tool: &str,
    args: Value,
    provider: &str,
    expect_marker: &str,
) {
    let logs = CapturedLog::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, || call_tool(conn, llm, tool, args));
    assert_eq!(result["isError"], true, "{tool}: {result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains(SECRET),
        "{tool}: provider echo reached the MCP caller: {text}"
    );
    assert!(text.len() < 512, "{tool}: error must be bounded: {text}");
    assert!(
        text.contains(provider) && text.contains(expect_marker),
        "{tool}: the bounded diagnostic must reach the caller (presence control): {text}"
    );
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains(crate::mcp::error_text::TRACE_TARGET)
            && rendered.contains(crate::errors::error_codes::LLM_ERROR),
        "{tool}: the operator log must carry the funnel line (presence control): {rendered}"
    );
    assert!(
        rendered.contains(provider) && rendered.contains(expect_marker),
        "{tool}: the operator log must carry the diagnostic: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET),
        "{tool}: provider echo reached the operator log: {rendered}"
    );
}

async fn mount(server: &MockServer, ollama: bool, status: u16, malformed: bool) {
    let body = if malformed {
        format!("{{{SECRET}")
    } else {
        json!({"error": SECRET}).to_string()
    };
    Mock::given(method("POST"))
        .and(path(if ollama {
            "/api/chat"
        } else {
            "/chat/completions"
        }))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

fn run_matrix(uri: String, ollama: bool, status: u16, malformed: bool) {
    // The four tools are driven through `handle_request`, whose dispatch
    // emits a failed-MUTATION audit event (`memory_consolidate` →
    // `AuditAction::Consolidate`) into the PROCESS-GLOBAL audit sink whenever
    // one is installed — and a sibling in this binary installs one for its
    // own count (`provider_redaction_3648_tests`, which read a second event
    // in its buffer on the 9e v2 stack: this test's consolidate refusal).
    // Every test that installs OR feeds that sink serialises on the one
    // lock, held for the whole SYNCHRONOUS dispatch window (this fn runs on
    // a blocking thread, so the std guard never spans an `.await`).
    let _audit_sink = crate::audit::sink_test_lock();
    // #3909 — `memory_detect_contradiction` resolves its read-visibility
    // principal from the process-global `AI_MEMORY_AGENT_ID`; a sibling lib
    // test exporting it mid-window masked the seeded (default-private) rows
    // ("memory A not found"). Hold the AGENT-ID env lock — the one every
    // mutator of that variable takes (`identity::agent_id_env_*_guard`) —
    // for the same synchronous window. Read side only: this test mutates
    // nothing (check-test-env-lock arm (e)); holding the lock is what excludes
    // the writers, and each writer restores the variable before releasing it.
    //
    // LOCK ORDER (required): `audit::sink_test_lock` FIRST, then
    // `identity::agent_id_env_test_lock`. This fn is the SOLE holder of both
    // in the crate; any future fn taking them in the opposite order would form
    // an ABBA deadlock pair with this one. Keep this order everywhere.
    let _agent_id_env = crate::identity::agent_id_env_test_lock();
    let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
    let a = seed(&conn, "echo-a");
    let b = seed(&conn, "echo-b");
    // One client PER TOOL: the client's circuit breaker opens after a run of
    // failures, and the breaker-open message (bounded too, but a different
    // classification) would mask the arm under test on the later tools.
    let client = || {
        if ollama {
            OllamaClient::new_with_url_no_health_check(&uri, "test").unwrap()
        } else {
            OllamaClient::new_openai_compatible(&uri, "test", "test-key").unwrap()
        }
    };
    let provider = if ollama {
        crate::llm::BACKEND_OLLAMA
    } else {
        "openai_compatible"
    };
    // A non-2xx renders the status class; a malformed 2xx renders the parse
    // classification — both are `ProviderFailure` vocabulary, never the body.
    let marker = if malformed {
        "invalid_response"
    } else {
        "http_status=401"
    };
    let _ = status;
    assert_sink(
        &conn,
        &client(),
        "memory_expand_query",
        json!({"query": "hello"}),
        provider,
        marker,
    );
    assert_sink(
        &conn,
        &client(),
        "memory_auto_tag",
        json!({"id": a}),
        provider,
        marker,
    );
    assert_sink(
        &conn,
        &client(),
        "memory_consolidate",
        json!({"ids": [a.clone(), b.clone()], "title": "echo", "namespace": "echo-3648"}),
        provider,
        marker,
    );
    assert_sink(
        &conn,
        &client(),
        "memory_detect_contradiction",
        json!({"id_a": a, "id_b": b}),
        provider,
        marker,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_chat_tool_sinks_never_carry_the_provider_body_3648() {
    for ollama in [false, true] {
        for (status, malformed) in [(401, false), (200, true)] {
            let server = MockServer::start().await;
            mount(&server, ollama, status, malformed).await;
            let uri = server.uri();
            tokio::task::spawn_blocking(move || run_matrix(uri, ollama, status, malformed))
                .await
                .unwrap();
            assert!(!server.received_requests().await.unwrap().is_empty());
        }
    }
}
