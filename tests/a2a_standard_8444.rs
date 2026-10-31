// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: the server speaks the Google `Agent2Agent` (A2A 1.0) standard
//! (JSON-RPC binding, shape S1, posture P1) on the SQLite backend. The
//! PostgreSQL twin is `a2a_standard_8444_pg.rs`; both run the same scenarios.

mod a2a_standard_8444_common;

use a2a_standard_8444_common::{run_suite, sqlite_app_state};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2a_standard_binding_sqlite_8444() {
    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, std::path::PathBuf::from),
    )
    .expect("scratch dir");
    let app = sqlite_app_state(&dir.path().join("a2a-8444.db"));
    run_suite(app).await;
}
