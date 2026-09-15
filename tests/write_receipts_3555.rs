// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3555: a successful capture, including replay, declares its durability.

use serde_json::json;

#[test]
fn capture_receipt_declares_live_sqlite_durability_3555() -> anyhow::Result<()> {
    let root = std::env::var("CARGO_TARGET_DIR")?;
    let scratch = tempfile::Builder::new()
        .prefix("write-receipts-3555-")
        .tempdir_in(root)?;
    let conn = ai_memory::db::open(&scratch.path().join("capture.db"))?;
    for (index, synchronous, fsync) in [(0, "NORMAL", "per-checkpoint"), (1, "FULL", "per-commit")]
    {
        conn.pragma_update(None, "synchronous", synchronous)?;
        let request = json!({
            "host_session_id": "receipt-contract-3555",
            "host_turn_index": index,
            "role": "assistant",
            "content": "A capture receipt must declare its durability.",
        });
        for replay in [false, true] {
            let receipt =
                ai_memory::mcp::handle_capture_turn(&conn, &request, Some("test-agent-3555"))
                    .map_err(anyhow::Error::msg)?;
            assert_eq!(receipt["dedup_hit"], replay);
            assert_eq!(receipt["durability_class"], "local-only", "{receipt}");
            assert_eq!(receipt["fsync"], fsync, "{receipt}");
        }
    }
    Ok(())
}
