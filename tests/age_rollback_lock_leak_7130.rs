// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]

//! #7130 — the certified postgres+AGE tier must survive a ROLLBACK of a failed
//! transaction that raced a burst of catalog invalidations.
//!
//! Defect class: Apache AGE 1.8.0 (apache/age#2580) runs its
//! `post_parse_analyze` hook on the ROLLBACK statement of an aborted
//! transaction. When a shared-invalidation catch-up has cleared AGE's
//! extension cache while the session idled in the failed transaction, the hook
//! reads `pg_extension` in the aborted state; the ROLLBACK then fails with
//! `ResourceOwnerEnlarge called after release started` and leaks fast-path
//! locks into that backend's PGPROC. Every later backend that inherits the
//! PGPROC fails at connect with XX000 `failed to re-find shared lock object`
//! until the server restarts — the shared-tier failure the Certified pg+AGE
//! cells reported. The fix lives in the server's AGE build (upstream
//! apache/age 06ce678: `is_age_extension_exists` returns early outside a
//! transaction state); this test pins that the certified server carries it.
//!
//! Gated on `AI_MEMORY_TEST_AGE_URL` (fallback `AI_MEMORY_TEST_POSTGRES_URL`):
//! prints a skip line and returns when unset. `#[ignore]` like the AGE cert
//! siblings; the cert-postgres-age workflow runs it under `--include-ignored`.

use std::time::Duration;

use sqlx::{Connection, PgConnection};

/// Temp tables created and dropped by the invalidation burst: enough to
/// overflow the shared-invalidation queue for an idle peer backend.
const INVALIDATION_BURST: u32 = 1500;
/// How long the failed session idles after the burst so the catch-up signal
/// is processed before it sends ROLLBACK.
const SETTLE: Duration = Duration::from_secs(1);
/// Fresh connections opened after the ROLLBACKs; each could land on a PGPROC
/// a leak poisoned.
const PROBE_CONNECTS: u32 = 20;
/// Rounds of the race; three make the red deterministic on an unpatched AGE.
const ROUNDS: u32 = 3;
const LEAK_MSG: &str = "ResourceOwnerEnlarge called after release started";
const REFIND_MSG: &str = "failed to re-find shared lock object";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

fn burst_sql() -> String {
    format!(
        "DO $b$ BEGIN FOR i IN 1..{INVALIDATION_BURST} LOOP \
         EXECUTE format('CREATE TEMP TABLE r7130_%s (x int)', i); \
         EXECUTE format('DROP TABLE r7130_%s', i); END LOOP; END $b$"
    )
}

async fn one_round(url: &str) {
    let mut failed = PgConnection::connect(url).await.expect("connect session A");
    sqlx::raw_sql("SELECT 1")
        .execute(&mut failed)
        .await
        .expect("prime AGE extension cache");
    sqlx::raw_sql("BEGIN")
        .execute(&mut failed)
        .await
        .expect("begin");
    let div = sqlx::raw_sql("SELECT 1/0").execute(&mut failed).await;
    assert!(
        div.is_err(),
        "SELECT 1/0 must fail to abort the transaction"
    );

    let mut burst = PgConnection::connect(url).await.expect("connect session B");
    sqlx::raw_sql(&burst_sql())
        .execute(&mut burst)
        .await
        .expect("invalidation burst");
    burst.close().await.expect("close session B");

    tokio::time::sleep(SETTLE).await;

    if let Err(e) = sqlx::raw_sql("ROLLBACK").execute(&mut failed).await {
        let msg = e.to_string();
        let class = if msg.contains(LEAK_MSG) {
            "lock leak"
        } else {
            "unexpected error"
        };
        panic!(
            "#7130: ROLLBACK of an aborted transaction failed after an invalidation \
             burst ({class}); the server's AGE build lacks the apache/age#2580 fix: {msg}"
        );
    }
    let alive: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut failed)
        .await
        .expect("session A usable after ROLLBACK");
    assert_eq!(alive, 1);
    failed.close().await.expect("close session A");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live AGE-enabled postgres (AI_MEMORY_TEST_AGE_URL)"]
async fn rollback_after_invalidation_burst_does_not_leak_locks_7130() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_AGE_URL / AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let mut admin = PgConnection::connect(&url).await.expect("connect admin");
    let preload: String = sqlx::query_scalar("SELECT current_setting('shared_preload_libraries')")
        .fetch_one(&mut admin)
        .await
        .expect("read shared_preload_libraries");
    assert!(
        preload.contains("age"),
        "#7130 pins the certified tier: AGE must be preloaded, got {preload:?}"
    );
    // The preloaded hook runs in every database whether or not the extension
    // is created there, so the race needs no CREATE EXTENSION.
    admin.close().await.expect("close admin");

    for _ in 0..ROUNDS {
        one_round(&url).await;
    }

    for i in 0..PROBE_CONNECTS {
        match PgConnection::connect(&url).await {
            Ok(conn) => conn.close().await.expect("close probe"),
            Err(e) => {
                let msg = e.to_string();
                let class = if msg.contains(REFIND_MSG) {
                    "XX000 poisoned PGPROC"
                } else {
                    "unexpected error"
                };
                panic!("#7130: probe connect {i} failed ({class}): {msg}");
            }
        }
    }
}
