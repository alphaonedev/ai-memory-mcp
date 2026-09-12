// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! Failed MCP mutations must retain their cause in the operator audit trail.
use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn mcp_failed_tool_preserves_operator_cause_3648() {
    let _lock = crate::audit::sink_test_lock();
    let audit = Arc::new(Mutex::new(Vec::new()));
    crate::audit::init_for_test(Arc::clone(&audit));
    let conn = crate::db::open(std::path::Path::new(":memory:")).unwrap();
    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3648)),
        method: "tools/call".to_string(),
        params: json!({
            "name": "memory_update",
            "arguments": {}
        }),
    };
    let response = tests::invoke_handle_request(&conn, &request);
    crate::audit::shutdown_for_test();
    let result = response.result.unwrap();
    assert_eq!(result["isError"], true);
    let cause = result["content"][0]["text"].as_str().unwrap();
    assert!(
        cause.contains("id"),
        "expected a missing-id failure: {cause}"
    );
    let rendered = String::from_utf8(audit.lock().unwrap().clone()).unwrap();
    let events: Vec<Value> = rendered
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1, "expected one failed mutation audit event");
    assert_eq!(
        events[0]["error"], cause,
        "operator must retain the tool failure cause"
    );
}
