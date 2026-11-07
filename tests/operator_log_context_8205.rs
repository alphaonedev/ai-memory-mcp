// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator diagnostics retain causes while keeping caller text unchanged.

use std::sync::{Arc, Mutex};

use ai_memory::mcp::error_text::{DB_ERROR_TEXT, log_foreign, mcp_error_text, mcp_foreign_err};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn captured<T>(operation: impl FnOnce() -> T) -> (T, String) {
    let sink = Capture::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, operation);
    let bytes = sink.0.lock().expect("capture lock").clone();
    (result, String::from_utf8(bytes).expect("UTF-8 log"))
}

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
