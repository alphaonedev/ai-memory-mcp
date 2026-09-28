// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Pillar 3 / Stream E — the `mcp_tool_call` span and its `ok` / `err`
//! events, asserted through a buffer-backed `tracing` capture.
//!
//! #4088: moved out of `mcp::tests` so each capture runs alone in a re-exec'd
//! child process (`config::run_env_isolated_child_or_spawn`). The `tracing`
//! callsite-interest cache is process-global, so a sibling test with no INFO
//! subscriber could pin `mcp_tool_call` to `never` and a capture in the shared
//! binary read an empty trace. Living in their own module also keeps
//! `mcp/mod.rs` under its QUAL-10 ceiling.

use super::*;
use crate::config::FeatureTier;
use serde_json::json;

/// Buffer-backed `MakeWriter` so `tracing` output can be asserted on
/// without polluting test stdout/stderr or installing a global
/// subscriber. Used by the Stream E span coverage tests below.
#[derive(Clone)]
struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn run_with_capture<F: FnOnce()>(f: F) -> String {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = VecWriter(buf.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default()
}

/// Pillar 3 / Stream E coverage — every successful `tools/call` must
/// emit a `mcp_tool_call` span carrying the tool name plus an `ok`
/// event with `elapsed_ms`. This is the single point of latency
/// instrumentation production exporters key off.
#[test]
fn tools_call_emits_span_with_tool_name_and_elapsed_ms() {
    // #3517: `handle_request` resolves the caller from AI_MEMORY_AGENT_ID;
    // hold the shared reader lock for the whole test (parent and child).
    let _agent_id_env_lock = crate::identity::agent_id_env_test_lock();
    // #4088: the `tracing` callsite-interest cache is process-global, so a
    // sibling test with no INFO subscriber can pin `mcp_tool_call` to
    // `never` and this capture reads an empty trace (the #3426
    // mechanism). Run the body alone in a re-exec'd child process.
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::span_capture_4088_tests::tools_call_emits_span_with_tool_name_and_elapsed_ms",
    ) {
        return;
    }
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let tier_config = FeatureTier::Keyword.config();
    let resolved_ttl = crate::config::ResolvedTtl::default();
    let resolved_scoring = crate::config::ResolvedScoring::default();
    let req = super::tests::make_tools_call("memory_list", json!({"limit": 1}));

    let captured = run_with_capture(|| {
        let resp = handle_request(
            &conn,
            std::path::Path::new(":memory:"),
            &req,
            None,
            None,
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
            None,           // federation_forward_url (#318)
            None,           // recall_scope (#518)
            None,           // atomise_handler (WT-1-C)
            None,           // atomise_queue (#2986)
            None,           // ingest_multistep_handler (Form 3 / #756)
            None,           // nag_watcher (#1389/#1398 L1)
            "test-session", // nag_session_id (#1389/#1398 L1)
        );
        assert!(resp.error.is_none(), "expected ok rpc response");
    });

    assert!(
        captured.contains("mcp_tool_call"),
        "missing span name in: {captured}"
    );
    assert!(
        captured.contains("memory_list"),
        "missing tool field in: {captured}"
    );
    assert!(
        captured.contains("elapsed_ms"),
        "missing elapsed_ms field in: {captured}"
    );
    assert!(
        captured.contains(" ok"),
        "missing ok outcome event in: {captured}"
    );
}

/// Failure path — when the underlying handler returns an `Err`, the
/// span emits a `warn` level event with the error message so on-call
/// dashboards can alert on per-tool error rate.
#[test]
fn tools_call_emits_warn_event_on_handler_error() {
    // #3517: `handle_request` resolves the caller from AI_MEMORY_AGENT_ID;
    // hold the shared reader lock for the whole test (parent and child).
    let _agent_id_env_lock = crate::identity::agent_id_env_test_lock();
    // #4088: the `tracing` callsite-interest cache is process-global, so a
    // sibling test with no INFO subscriber can pin `mcp_tool_call` to
    // `never` and this capture reads an empty trace (the #3426
    // mechanism). Run the body alone in a re-exec'd child process.
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::span_capture_4088_tests::tools_call_emits_warn_event_on_handler_error",
    ) {
        return;
    }
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let tier_config = FeatureTier::Keyword.config();
    let resolved_ttl = crate::config::ResolvedTtl::default();
    let resolved_scoring = crate::config::ResolvedScoring::default();
    // memory_get with a missing/invalid id is a deterministic Err
    // path: validate_id rejects empty strings.
    let req = super::tests::make_tools_call("memory_get", json!({"id": ""}));

    let captured = run_with_capture(|| {
        let resp = handle_request(
            &conn,
            std::path::Path::new(":memory:"),
            &req,
            None,
            None,
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
            None,           // federation_forward_url (#318)
            None,           // recall_scope (#518)
            None,           // atomise_handler (WT-1-C)
            None,           // atomise_queue (#2986)
            None,           // ingest_multistep_handler (Form 3 / #756)
            None,           // nag_watcher (#1389/#1398 L1)
            "test-session", // nag_session_id (#1389/#1398 L1)
        );
        // Handler errs are returned as ok_response with isError=true,
        // not RpcError, by design (the JSON-RPC layer is reserved for
        // protocol-level failures).
        assert!(resp.error.is_none());
    });

    assert!(
        captured.contains("mcp_tool_call"),
        "missing span in err path: {captured}"
    );
    assert!(
        captured.contains("memory_get"),
        "missing tool field in err path: {captured}"
    );
    assert!(
        captured.contains("WARN"),
        "missing WARN level on err path: {captured}"
    );
    assert!(
        captured.contains("err"),
        "missing err outcome in: {captured}"
    );
}
