// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: the `Agent2Agent` (A2A 1.0) standard binding on the live PostgreSQL
//! backend (run through the `ci-v2-pg` wrapper). Same scenarios as the SQLite
//! twin `a2a_standard_8444.rs`.
#![cfg(feature = "sal-postgres")]

mod a2a_standard_8444_common;

use a2a_standard_8444_common::{SalStore, app_state_with, run_suite};
use ai_memory::config::ResolvedTtl;
use ai_memory::handlers::{Db, StorageBackend};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2a_standard_binding_postgres_8444() {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("own live PostgreSQL required; never skip");
    {
        let parsed = reqwest::Url::parse(&url).expect("URL");
        assert!(
            !(parsed.path() == "/ai_memory_test" && parsed.port() == Some(5445)),
            "never the live operator DB on :5445"
        );
    }
    // `app.db` is a deliberately EMPTY in-memory sqlite: a handler that reads
    // it instead of `app.store` fails loudly.
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres adapter"),
    ));
    run_suite(app_state_with(db, StorageBackend::Postgres, store)).await;
}
