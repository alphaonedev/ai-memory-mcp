// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 — the production archive must compose in a larger transaction.

use super::{connection::WriteTxn, *};

fn fixture() -> (Connection, String, String) {
    let conn = open(std::path::Path::new(":memory:")).expect("open");
    let seed = |title: &str| {
        let now = Utc::now().to_rfc3339();
        insert_no_overwrite(
            &conn,
            &Memory {
                id: uuid::Uuid::new_v4().to_string(),
                namespace: "archive-tx-3587".into(),
                title: title.into(),
                content: format!("durable {title}"),
                created_at: now.clone(),
                updated_at: now,
                metadata: serde_json::json!({"agent_id": "ai:archive-3587"}),
                ..Memory::default()
            },
        )
        .expect("seed")
    };
    let old = seed("old");
    let next = seed("next");
    create_link(&conn, &old, &next, "related_to").expect("link");
    set_namespace_standard(&conn, "archive-tx-3587", &old, None).expect("standard");
    (conn, old, next)
}

fn count_for(conn: &Connection, table: &str, column: &str, id: &str) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
        [id],
        |row| row.get(0),
    )
    .expect("count")
}

#[test]
fn archive_transaction_rolls_back_snapshot_links_and_standard_3587() {
    let _no_pass = crate::test_support::no_passphrase_guard();
    let (conn, old, _) = fixture();
    let before = serde_json::to_value(get(&conn, &old).expect("get")).expect("snapshot");
    let tx = WriteTxn::begin(&conn).expect("begin");
    assert!(archive_memory_no_tx(&conn, &old, Some("superseded")).expect("archive"));
    assert_eq!(count_for(&conn, "memories", "id", &old), 0);
    assert_eq!(count_for(&conn, "archived_memories", "id", &old), 1);
    assert_eq!(
        count_for(&conn, "archived_memory_links", "source_id", &old),
        1
    );
    assert_eq!(
        get_namespace_standard(&conn, "archive-tx-3587").expect("standard"),
        None
    );
    // A later operation fails after the archive has already mutated all three
    // relations. The caller's rollback must restore the original state.
    assert!(
        conn.execute_batch("SELECT nonexistent_archive_tx_function_3587()")
            .is_err()
    );
    tx.rollback();
    assert!(conn.is_autocommit());
    assert_eq!(
        serde_json::to_value(get(&conn, &old).expect("get")).expect("snapshot"),
        before
    );
    assert_eq!(count_for(&conn, "archived_memories", "id", &old), 0);
    assert_eq!(
        count_for(&conn, "archived_memory_links", "source_id", &old),
        0
    );
    assert_eq!(count_for(&conn, "memory_links", "source_id", &old), 1);
    assert_eq!(
        get_namespace_standard(&conn, "archive-tx-3587").expect("standard"),
        Some(old)
    );
}

#[test]
fn archive_transaction_commits_once_and_missing_id_is_noop_3587() {
    let _no_pass = crate::test_support::no_passphrase_guard();
    let (conn, old, next) = fixture();
    let tx = WriteTxn::begin(&conn).expect("begin");
    assert!(archive_memory_no_tx(&conn, &old, Some("superseded")).expect("archive"));
    assert!(!archive_memory_no_tx(&conn, &old, Some("superseded")).expect("repeat"));
    tx.commit().expect("commit");
    assert_eq!(count_for(&conn, "memories", "id", &old), 0);
    assert_eq!(count_for(&conn, "memories", "id", &next), 1);
    assert_eq!(count_for(&conn, "archived_memories", "id", &old), 1);
    assert_eq!(
        count_for(&conn, "archived_memory_links", "source_id", &old),
        1
    );
    let reason: String = conn
        .query_row(
            "SELECT archive_reason FROM archived_memories WHERE id = ?1",
            [&old],
            |r| r.get(0),
        )
        .expect("reason");
    assert_eq!(reason, "superseded");
}
