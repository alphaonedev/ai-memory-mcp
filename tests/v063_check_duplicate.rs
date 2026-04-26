// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Pillar 2 / Stream D smoke for `memory_check_duplicate` exercised through
// the v0.6.3 shared harness. The keyword-tier daemon (the default under
// `AI_MEMORY_NO_CONFIG=1`) does not load the embedder, so the tool MUST
// return the documented `requires the embedder; …` error wrapped in the
// MCP `isError: true` envelope rather than panicking or surfacing a raw
// JSON-RPC error code. Locking that contract down here keeps a regression
// in the dispatch path from silently changing how downstream callers
// detect "you need a richer tier to use this tool".

#[path = "v063/mod.rs"]
mod v063;

use serde_json::Value;

#[test]
fn test_check_duplicate_without_embedder_returns_documented_error() {
    let db = v063::tmp_db("check-dup-no-embedder");

    // `--tier keyword` keeps the daemon FTS-only so the embedder is
    // explicitly None — the tier-aware sibling helper exists precisely
    // to insulate this assertion from HuggingFace model downloads being
    // flaky in CI (see also tests/integration.rs::http_capabilities_…
    // line 9682 where the daemon-side test takes the same precaution).
    let lines = v063::mcp_exchange_with_args(
        &db,
        &["--tier", "keyword"],
        &[concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"#,
            r#""name":"memory_check_duplicate","arguments":{"#,
            r#""title":"Postgres tuning notes","#,
            r#""content":"shared_buffers and work_mem reference values"#,
            r#""}}}"#,
        )],
    );
    assert_eq!(lines.len(), 1, "expected one MCP response, got {lines:?}");

    let resp: Value = serde_json::from_str(&lines[0]).expect("parse MCP response");
    assert_eq!(resp["id"], 1);

    // Tool errors come back as ok responses with `isError: true` so a
    // client that switches on the JSON-RPC code can still parse the
    // payload (see src/mcp.rs handle_request: Err arm wraps in
    // `ok_response` with `isError: true`).
    assert_eq!(
        resp["result"]["isError"], true,
        "expected isError: true on no-embedder branch, got {resp}"
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(
        text.contains("memory_check_duplicate requires the embedder"),
        "unexpected error text: {text}"
    );

    // The MCP error path should NOT surface a top-level JSON-RPC `error`
    // — the dispatcher reserves that for unknown methods (-32601).
    assert!(
        resp.get("error").is_none(),
        "tool error must not double up as a JSON-RPC error: {resp}"
    );

    let _ = std::fs::remove_file(&db);
}
