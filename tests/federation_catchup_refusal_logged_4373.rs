// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4373 — a catch-up pull that refuses a row at the shared validation must
//! count and WARN with the row id (the old bare `continue` moved the cursor
//! past the row with no trace). The helper returns `false` for the refused row
//! and `true` for a valid one.

use ai_memory::models::Memory;
use serde_json::json;

fn row(version: i64) -> Memory {
    serde_json::from_value(json!({
        "id": "m-4373", "tier": "long", "namespace": "fit-4373", "title": "t",
        "content": "c", "tags": [], "priority": 5, "confidence": 1.0,
        "source": "nhi", "access_count": 0, "created_at": "2026-09-20T00:00:00Z",
        "updated_at": "2026-09-20T00:00:00Z", "version": version,
        "metadata": {"agent_id": "ai:alice-4373"}
    }))
    .expect("memory")
}

#[test]
fn catchup_refusal_is_logged_and_counted_not_silent_4373() {
    assert!(!ai_memory::federation::receive::catchup_row_valid(
        "peer-x",
        &row(i64::MAX)
    ));
    assert!(ai_memory::federation::receive::catchup_row_valid(
        "peer-x",
        &row(7)
    ));
}
