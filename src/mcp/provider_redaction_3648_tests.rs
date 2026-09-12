// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! MCP must log a bounded outcome code, never arbitrary handler text.
use super::log_dispatch_outcome;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn mcp_handler_error_log_is_redacted_3648() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        log_dispatch_outcome(7, &Err("provider-secret-3648".to_string()));
    });
    let rendered = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains(super::MCP_TOOL_FAILED),
        "safe error code must be logged"
    );
    assert!(
        !rendered.contains("provider-secret-3648"),
        "handler error leaked: {rendered}"
    );
}
