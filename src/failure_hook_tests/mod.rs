// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Library-side active fault harness: compiled only under cfg(test), never a deployed artifact.
use crate as library;
mod scenarios;
#[cfg(feature = "sal-postgres")]
use scenarios::PG_ENV;
use scenarios::{CLOCK_ENV, FAIL_ENV, TARGET_ID};

const MODE_ENV: &str = "AI_MEMORY_HOOK_CHILD_MODE";
const DB_ENV: &str = "AI_MEMORY_HOOK_CHILD_DB";
const AUTO_ENV: &str = "AI_MEMORY_HOOK_CHILD_AUTO";
const EXPECT_ENV: &str = "AI_MEMORY_HOOK_EXPECT_OFFSET";
const HEALTHY_ID: &str = "healthy-capture-7029";
const SQLITE_TEST: &str = "failure_hook_tests::active_sqlite_7029";
const CLOCK_TEST: &str = "failure_hook_tests::active_clock_7029";
#[cfg(feature = "sal-postgres")]
const PG_TEST: &str = "failure_hook_tests::active_postgres_7029";

fn assert_child(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "lib-test child failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed"),
        "one exact test must run: {stdout}"
    );
}

#[test]
fn active_sqlite_7029() {
    if let Ok(mode) = std::env::var(MODE_ENV) {
        let path = std::env::var(DB_ENV).expect("private DB path");
        let conn = crate::db::open(std::path::Path::new(&path)).expect("private sqlite");
        let auto = std::env::var(AUTO_ENV).expect("funnel") == "1";
        if mode == "armed" {
            assert_eq!(scenarios::sqlite_counts(&conn), (0, 0, 0));
            let snapshot = scenarios::sqlite_snapshot(&conn);
            let err = scenarios::sqlite_capture(&conn, TARGET_ID, auto).expect_err("armed capture");
            assert!(format!("{err:?}").contains("injected before signed commit"));
            assert_eq!(
                scenarios::sqlite_counts(&conn),
                (0, 0, 0),
                "complete rollback"
            );
            assert_eq!(scenarios::sqlite_snapshot(&conn), snapshot);
            scenarios::sqlite_capture(&conn, HEALTHY_ID, auto).expect("unrelated healthy write");
            let before = scenarios::sqlite_counts(&conn);
            assert_eq!(before, (1, 1, 1));
            let snapshot = scenarios::sqlite_snapshot(&conn);
            assert!(scenarios::sqlite_capture(&conn, TARGET_ID, auto).is_err());
            assert_eq!(
                scenarios::sqlite_counts(&conn),
                before,
                "existing chain survives"
            );
            assert_eq!(scenarios::sqlite_snapshot(&conn), snapshot);
        } else {
            assert_eq!(mode, "retry");
            assert_eq!(scenarios::sqlite_counts(&conn), (1, 1, 1));
            scenarios::sqlite_capture(&conn, TARGET_ID, auto).expect("same target healthy retry");
            assert_eq!(scenarios::sqlite_counts(&conn), (2, 2, 2));
            scenarios::sqlite_capture(&conn, TARGET_ID, auto).expect("idempotent retry");
            assert_eq!(scenarios::sqlite_counts(&conn), (2, 2, 2));
            scenarios::sqlite_stamps(&conn, TARGET_ID);
        }
        return;
    }
    for auto in ["0", "1"] {
        let dir = tempfile::tempdir().expect("private scratch");
        let db = dir.path().join("hook.db");
        let path = db.to_str().expect("fixture path");
        assert_child(&crate::test_support::spawn_test_child(
            SQLITE_TEST,
            &[
                (MODE_ENV, "armed"),
                (DB_ENV, path),
                (AUTO_ENV, auto),
                (FAIL_ENV, TARGET_ID),
            ],
        ));
        assert_child(&crate::test_support::spawn_test_child(
            SQLITE_TEST,
            &[(MODE_ENV, "retry"), (DB_ENV, path), (AUTO_ENV, auto)],
        ));
    }
}

#[test]
fn active_clock_7029() {
    if std::env::var_os(MODE_ENV).is_some() {
        let expected: i64 = std::env::var(EXPECT_ENV)
            .expect("expected offset")
            .parse()
            .expect("offset integer");
        assert_eq!(
            crate::eval_clock::offset_secs(),
            expected,
            "common checked offset domain"
        );
        #[cfg(feature = "sal-postgres")]
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async {
                scenarios::pg::fault_pg_isolated_clock(expected).await;
            });
        scenarios::sqlite_clock(expected);
        return;
    }
    let cases = [
        (None, 0),
        (Some("0"), 0),
        (Some("3600"), crate::SECS_PER_HOUR),
        (Some("-3600"), -crate::SECS_PER_HOUR),
        (Some("86400"), crate::SECS_PER_DAY),
        (Some("-86400"), -crate::SECS_PER_DAY),
        (Some("garbage"), 0),
        (Some("9223372036854775807"), 0),
        (Some("-9223372036854775808"), 0),
    ];
    for (value, offset) in cases {
        let expected = offset.to_string();
        let mut env = vec![(MODE_ENV, "clock"), (EXPECT_ENV, expected.as_str())];
        if let Some(value) = value {
            env.push((CLOCK_ENV, value));
        }
        #[cfg(feature = "sal-postgres")]
        let pg_url = std::env::var(PG_ENV).expect("PG evidence requires native PG URL");
        #[cfg(feature = "sal-postgres")]
        env.push((PG_ENV, pg_url.as_str()));
        assert_child(&crate::test_support::spawn_test_child(CLOCK_TEST, &env));
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn active_postgres_7029() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    if let Ok(mode) = std::env::var(MODE_ENV) {
        runtime.block_on(async {
            let url = std::env::var(PG_ENV).expect("parent-owned DB URL");
            let store = scenarios::pg::fault_pg_connect_owned(&url).await;
            if mode == "armed" {
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (0, 0, 0));
                let snapshot = scenarios::pg::fault_pg_snapshot(&store).await;
                let err = scenarios::pg::fault_pg_capture(&store, TARGET_ID)
                    .await
                    .expect_err("armed PG capture");
                assert!(format!("{err:?}").contains("injected before signed commit"));
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (0, 0, 0));
                assert_eq!(scenarios::pg::fault_pg_snapshot(&store).await, snapshot);
                scenarios::pg::fault_pg_capture(&store, HEALTHY_ID)
                    .await
                    .expect("unrelated PG healthy write");
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (1, 1, 1));
                let snapshot = scenarios::pg::fault_pg_snapshot(&store).await;
                assert!(
                    scenarios::pg::fault_pg_capture(&store, TARGET_ID)
                        .await
                        .is_err()
                );
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (1, 1, 1));
                assert_eq!(scenarios::pg::fault_pg_snapshot(&store).await, snapshot);
            } else {
                assert_eq!(mode, "retry");
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (1, 1, 1));
                scenarios::pg::fault_pg_capture(&store, TARGET_ID)
                    .await
                    .expect("PG same-target retry");
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (2, 2, 2));
                scenarios::pg::fault_pg_capture(&store, TARGET_ID)
                    .await
                    .expect("PG idempotent retry");
                assert_eq!(scenarios::pg::fault_pg_counts(&store).await, (2, 2, 2));
                scenarios::pg::fault_pg_stamps(&store, TARGET_ID).await;
            }
            store.pool().close().await;
        });
        return;
    }
    let (admin, name, store) = runtime.block_on(scenarios::pg::fault_pg_create());
    let mut url = reqwest::Url::parse(&std::env::var(PG_ENV).expect("PG URL")).expect("valid URL");
    url.set_path(&format!("/{name}"));
    let armed = crate::test_support::spawn_test_child(
        PG_TEST,
        &[
            (MODE_ENV, "armed"),
            (PG_ENV, url.as_str()),
            (FAIL_ENV, TARGET_ID),
        ],
    );
    let retry = crate::test_support::spawn_test_child(
        PG_TEST,
        &[(MODE_ENV, "retry"), (PG_ENV, url.as_str())],
    );
    runtime.block_on(scenarios::pg::fault_pg_cleanup(admin, name, store));
    assert_child(&armed);
    assert_child(&retry);
}

/// Review r2 F3 (TEST-02): cleanup must drop the owned database even while a
/// second backend still holds a connection to it.
#[cfg(feature = "sal-postgres")]
#[test]
fn cleanup_drops_owned_db_with_open_connection_7029() {
    let Ok(supplied) = std::env::var(PG_ENV) else {
        eprintln!("skipped: {PG_ENV} is unset");
        return;
    };
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let (admin, name, store) = scenarios::pg::fault_pg_create().await;
        let mut url = reqwest::Url::parse(&supplied).expect("valid URL");
        url.set_path(&format!("/{name}"));
        let held =
            scenarios::pg::fault_pg_pool(url.as_str(), "second connection to the owned database")
                .await;
        let mut admin_url = reqwest::Url::parse(&supplied).expect("valid URL");
        admin_url.set_path("/postgres");
        let admin_probe =
            scenarios::pg::fault_pg_pool(admin_url.as_str(), "probe admin connect").await;
        scenarios::pg::fault_pg_cleanup(admin, name.clone(), store).await;
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM pg_database WHERE datname = $1")
                .bind(&name)
                .fetch_one(&admin_probe)
                .await
                .expect("pg_database lookup");
        held.close().await;
        admin_probe.close().await;
        assert_eq!(remaining, 0, "owned database must be gone after cleanup");
    });
}
