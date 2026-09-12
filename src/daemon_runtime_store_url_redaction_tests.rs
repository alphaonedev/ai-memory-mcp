// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3667 — the Postgres SAL boot line must log the store URL with BOTH the
//! userinfo password and every query-form password masked. Mounted from
//! `daemon_runtime.rs` via `#[path]` so the QUAL-10 ceiling of that module
//! is not spent on test-only code.

use super::build_store_handle;

#[tokio::test]
async fn issue_3667_boot_log_redacts_query_password() {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf lock").extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buf = SharedBuf::default();
    let writer_buf = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer_buf.clone())
        .finish();
    // Thread-local default — `#[tokio::test]` runs the future on
    // the current thread, so every log the boot path emits during
    // the await lands in `buf`.
    let _guard = tracing::subscriber::set_default(subscriber);

    let secret = "sup3r-s3cret-pw";
    let url = format!(
        "postgres://ai_memory:AUTH_CANARY@127.0.0.1:invalid/ai_memory?%70assword={secret}&password=SECOND_CANARY"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("unused.db");
    let res = build_store_handle(
        Some(&url),
        &db_path,
        None,
        Some(384),
        false,
        crate::store::PoolConfig::default(),
    )
    .await;
    assert!(res.is_err(), "invalid port must fail before any connection");

    let logs = String::from_utf8_lossy(&buf.0.lock().expect("buf lock")).to_string();
    assert!(
        logs.contains("opening Postgres SAL store at postgres://ai_memory:****@127.0.0.1:invalid/ai_memory?%70assword=****&password=****"),
        "boot line must log the redacted URL; got:\n{logs}"
    );
    assert!(
        !logs.contains(secret)
            && !logs.contains("AUTH_CANARY")
            && !logs.contains("SECOND_CANARY"),
        "store-URL password leaked into the boot log:\n{logs}"
    );
}
