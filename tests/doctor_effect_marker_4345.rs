// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4345 — `doctor` counts `approved` pending actions that carry no execution
//! marker and WARNs; a clean queue is Info. SQLite and (when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set) PostgreSQL census SQL.

use ai_memory::cli::doctor::Severity;
use ai_memory::cli::doctor_effect_marker_4345::{section, warning_note};

fn insert(conn: &rusqlite::Connection, id: &str, status: &str, payload: &str) {
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by, \
         requested_at, status) VALUES (?1, 'store', 'ns', ?2, 'agent', '2026-01-01T00:00:00Z', ?3)",
        rusqlite::params![id, payload, status],
    )
    .expect("insert pending");
}

#[test]
fn sqlite_census_warns_on_approved_without_marker_4345() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(tmp.path()).expect("open");
    assert_eq!(
        ai_memory::storage::count_approved_without_effect_marker(&conn).expect("count"),
        0
    );
    assert!(warning_note(0).is_none());

    insert(&conn, "p-unmarked", "approved", "{}");
    insert(
        &conn,
        "p-marked",
        "approved",
        r#"{"__effect_applied_at":"2026-01-01T00:00:00Z"}"#,
    );
    insert(&conn, "p-pending", "pending", "{}");
    let n = ai_memory::storage::count_approved_without_effect_marker(&conn).expect("count");
    assert_eq!(n, 1, "exactly the one unmarked approved row is counted");
    let report = section(Ok(n), "sqlite");
    assert_eq!(report.severity, Severity::Warning, "{report:?}");
    assert!(warning_note(n).is_some());
}

#[test]
fn unreadable_census_is_a_warning_not_silence_4345() {
    let report = section(Err(anyhow::anyhow!("boom")), "sqlite");
    assert_eq!(report.severity, Severity::Warning);
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_census_sql_counts_unmarked_approved_4345() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "SKIP pg_census_sql_counts_unmarked_approved_4345: no AI_MEMORY_TEST_POSTGRES_URL"
        );
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pool = store.pool();
    let id = uuid::Uuid::new_v4().to_string();
    let count = || async {
        sqlx::query_scalar::<_, i64>(ai_memory::storage::PG_COUNT_APPROVED_UNMARKED_SQL)
            .fetch_one(pool)
            .await
            .expect("census")
    };
    let before = count().await;
    sqlx::query(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by, status) \
         VALUES ($1, 'store', 'ns', '{}'::jsonb, 'agent', 'approved')",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert");
    assert_eq!(count().await, before + 1);
    sqlx::query(
        "UPDATE pending_actions SET payload = jsonb_set(payload, '{__effect_applied_at}', '\"x\"') \
         WHERE id = $1",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("stamp");
    assert_eq!(count().await, before);
    sqlx::query("DELETE FROM pending_actions WHERE id = $1")
        .bind(&id)
        .execute(pool)
        .await
        .expect("cleanup");
}
