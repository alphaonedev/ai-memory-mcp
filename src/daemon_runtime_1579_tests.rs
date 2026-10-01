// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1579 A3 store-URL redaction regression pin, moved out of `daemon_runtime.rs` (#4090) so the
//! #4090 capture-isolation guard does not raise the QUAL-10 ceiling.

#![cfg(feature = "sal-postgres")]

use super::*;

/// #1579 A3 (SECURITY) — regression pin: the Postgres SAL boot
/// path must log the REDACTED store URL. Pre-fix,
/// `build_store_handle` interpolated the raw `--store-url`
/// (password included) into the INFO boot line, shipping the
/// credential to journald / any log sink. The INFO line fires
/// before the connect attempt, so an unreachable port (`:1`)
/// still exercises the log site; the connect error itself is
/// expected and asserted as `Err`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn issue_1579_a3_boot_log_redacts_store_url_password() {
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

    // #4090: the `tracing` callsite-interest cache and max-level hint are
    // process-global, so in the shared lib binary a sibling test can race
    // this thread-local capture into reading NOTHING (the #3426 / #4088
    // mechanism). Present-plus-absent below turns that into a false red,
    // not a false green, but a redaction guard must not flake: run the
    // body alone in a re-exec'd child. The helper asserts `1 passed`, so
    // a wrong path fails loudly; tests/tracing_capture_isolation_4090.rs
    // keeps every capture site in `src/` isolated.
    if crate::config::run_env_isolated_child_or_spawn(
        "daemon_runtime::daemon_runtime_1579_tests::issue_1579_a3_boot_log_redacts_store_url_password",
    ) {
        return;
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
    let url = format!("postgres://ai_memory:{secret}@127.0.0.1:1/ai_memory");
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
    assert!(res.is_err(), "port 1 must refuse the connection");

    let logs = String::from_utf8_lossy(&buf.0.lock().expect("buf lock")).to_string();
    // #3711 — the boot line renders the store URL through `url_display`
    // (origin + path, userinfo DROPPED), not the old `ai_memory:****@`
    // masker. PRESENT-plus-ABSENT on the same sink: the line must still
    // be emitted with the allowlisted rendering, AND neither the password
    // nor the username may appear anywhere in the log — an absence-only
    // assertion would pass just as well if the boot line stopped being
    // emitted at all.
    assert!(
        logs.contains("opening Postgres SAL store at postgres://127.0.0.1:1/ai_memory"),
        "boot line must log the allowlist-rendered URL; got:\n{logs}"
    );
    assert!(
        !logs.contains(secret),
        "store-URL password leaked into the boot log:\n{logs}"
    );
    assert!(
        !logs.contains("://ai_memory") && !logs.contains("@127.0.0.1"),
        "store-URL userinfo (username or masker) leaked into the boot log:\n{logs}"
    );
}
