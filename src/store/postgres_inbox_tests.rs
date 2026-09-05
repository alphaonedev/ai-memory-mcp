// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod inbox_contract_tests {
    use super::*;

    #[tokio::test]
    async fn live_v98_aliases_live_and_archived_legacy_messages_3401() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let live_id = format!("inbox-live-{}", uuid::Uuid::new_v4());
        let archived_id = format!("inbox-archived-{}", uuid::Uuid::new_v4());
        let canonical = crate::inbox_namespace("ai:sal-test");

        for id in [&live_id, &archived_id] {
            let memory = sample_memory(id, &canonical, id, "canonical inbox migration probe");
            store.store(&ctx, &memory).await.expect("store probe row");
        }
        store
            .archive_by_ids(&ctx, std::slice::from_ref(&archived_id), Some("test-3401"))
            .await
            .expect("archive probe row");

        sqlx::query("UPDATE memories SET namespace = '_messages/ai:sal-test' WHERE id = $1")
            .bind(&live_id)
            .execute(&store.pool)
            .await
            .expect("seed legacy live namespace");
        sqlx::query(
            "UPDATE archived_memories SET namespace = '_messages/ai:sal-test' WHERE id = $1",
        )
        .bind(&archived_id)
        .execute(&store.pool)
        .await
        .expect("seed legacy archived namespace");
        for (table, id) in [("memories", &live_id), ("archived_memories", &archived_id)] {
            sqlx::query(&format!("UPDATE {table} SET metadata = '{{\"agent_id\":\"ai:legacy-sender-3401\",\"recipient_agent_id\":\"ai:sal-test\"}}'::jsonb WHERE id = $1"))
                .bind(id).execute(&store.pool).await.unwrap();
        }
        let live_before: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id = $1")
                .bind(&live_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let archive_before: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM archived_memories m WHERE id = $1")
                .bind(&archived_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        sqlx::query("DELETE FROM schema_version")
            .execute(&store.pool)
            .await
            .expect("clear schema stamp");
        sqlx::query("INSERT INTO schema_version (version) VALUES (97)")
            .execute(&store.pool)
            .await
            .expect("seed v97 schema stamp");

        store.migrate().await.expect("apply v98 migration");

        store.migrate_v98().await.unwrap();
        let live_after: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM memories m WHERE id = $1")
                .bind(&live_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let archive_after: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM archived_memories m WHERE id = $1")
                .bind(&archived_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(live_before, live_after);
        assert_eq!(archive_before, archive_after);
        let rows = store
            .list(
                &ctx,
                &crate::store::Filter {
                    namespace: Some(canonical.clone()),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(rows.iter().any(|m| m.id == live_id));
        let denied = store
            .list(
                &CallerContext::for_agent("ai:other-3401"),
                &crate::store::Filter {
                    namespace: Some(canonical.clone()),
                    limit: 100,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!denied.iter().any(|m| m.id == live_id));
        let archives = store.list_archived(Some(&canonical), 100, 0).await.unwrap();
        assert!(archives.iter().any(|m| m["id"] == archived_id));
        let stamped: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
            .fetch_one(&store.pool)
            .await
            .expect("read v98 schema stamp");
        assert_eq!(stamped, CURRENT_SCHEMA_VERSION);
    }
}
