// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator diagnostics retain causes while keeping caller text unchanged.

#[path = "common/operator_log_capture.rs"]
mod operator_capture;
use operator_capture::captured;

use ai_memory::mcp::error_text::{DB_ERROR_TEXT, log_foreign, mcp_error_text, mcp_foreign_err};

#[test]
fn operator_log_keeps_full_chain_6457() {
    const INNER: &str = "root storage failure 6457";
    const OUTER: &str = "loading reflection links";
    for direct in [false, true] {
        let error = anyhow::anyhow!(INNER).context(OUTER);
        let (wire, log) = captured(|| {
            if direct {
                mcp_error_text(&log_foreign("chain_probe", error))
            } else {
                mcp_foreign_err("chain_probe", error)
            }
        });
        assert_eq!(wire, DB_ERROR_TEXT);
        assert!(log.contains(OUTER), "outer context absent: {log}");
        assert!(log.contains(INNER), "inner cause absent: {log}");
    }
}

#[test]
fn operator_log_escapes_caller_controls_6822() {
    const HOSTILE: &str = "caller\nforged\r\t\x1b[31m\u{85}\u{2028}\u{2029}\u{202e}";
    for foreign in [false, true] {
        let error = if foreign {
            ai_memory::errors::MemoryError::DatabaseError(HOSTILE.into())
        } else {
            ai_memory::errors::MemoryError::Refused(HOSTILE.into())
        };
        let (wire, log) = captured(|| mcp_foreign_err("control_probe", error));
        assert_eq!(wire, if foreign { DB_ERROR_TEXT } else { HOSTILE });
        assert_eq!(log.lines().count(), 1, "one operator event: {log:?}");
        let line = log.strip_suffix("\n").expect("text event newline");
        assert!(!line.chars().any(char::is_control), "raw control: {log:?}");
        for control in [
            "\\n",
            "\\r",
            "\\t",
            "\\u{1b}",
            "\\u{85}",
            "\\u{2028}",
            "\\u{2029}",
            "\\u{202e}",
        ] {
            assert!(line.contains(control), "missing {control}: {log:?}");
        }
    }
}
