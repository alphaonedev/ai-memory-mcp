// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3359: routine guards and all-or-nothing quota accounting on both substrates.

use ai_memory::mcp::handle_action_create;
use ai_memory::models::{Routine, RoutineState};
use ai_memory::routines::materialization::materialize_template;
use serde_json::{Value, json};

const ACTOR: &str = "routine-3359";

fn routine(template: Value) -> Routine {
    Routine {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: format!("routine-{}", uuid::Uuid::new_v4().simple()),
        name: "guard regression".to_string(),
        template,
        parameters: json!([]),
        state: RoutineState::Frozen,
        created_by: ACTOR.to_string(),
        created_at: 1,
        frozen_at: Some(1),
        signature: vec![],
        signer_pubkey: vec![],
        metadata: json!({}),
    }
}

fn valid_template() -> Value {
    json!({"actions": [
        {"kind": "work", "title": "first", "payload": {}, "metadata": {}},
        {"kind": "{{kind}}", "title": "{{title}}", "payload": {"blob": "{{blob}}"}, "metadata": {}}
    ], "edges": [{"from": 0, "to": 1, "type": "requires"}]})
}

fn valid_arguments() -> Value {
    json!({"kind": "work", "title": "second", "blob": "data"})
}

fn denied_cases() -> Vec<(&'static str, Value, Value, &'static str)> {
    let mut cases = Vec::new();
    for (name, field, value, error) in [
        (
            "empty kind",
            "kind",
            String::new(),
            "kind must not be empty",
        ),
        (
            "empty title",
            "title",
            String::new(),
            "title must not be empty",
        ),
        ("title limit", "title", "x".repeat(8193), "title exceeds"),
        ("kind limit", "kind", "x".repeat(257), "kind exceeds"),
        (
            "title CR",
            "title",
            "bad\rtitle".to_string(),
            "control characters",
        ),
        (
            "kind NUL",
            "kind",
            "bad\0kind".to_string(),
            "control characters",
        ),
        (
            "arguments limit",
            "blob",
            "x".repeat(65_536),
            "arguments exceeds",
        ),
    ] {
        let mut args = valid_arguments();
        args[field] = json!(value);
        cases.push((name, valid_template(), args, error));
    }
    let mut template = valid_template();
    template["actions"][1]["payload"] = json!({"a": "{{blob}}", "b": "{{blob}}"});
    let mut args = valid_arguments();
    args["blob"] = json!("x".repeat(33_000));
    cases.push(("expanded payload", template, args, "payload exceeds"));
    let mut template = valid_template();
    template["actions"][1]["metadata"] = json!({"a": "{{blob}}", "b": "{{blob}}"});
    let mut args = valid_arguments();
    args["blob"] = json!("x".repeat(33_000));
    cases.push(("expanded metadata", template, args, "metadata"));
    for edge_type in [json!("typo"), json!(null), json!(7)] {
        let mut template = valid_template();
        template["edges"][0]["type"] = edge_type;
        cases.push((
            "unknown edge",
            template,
            valid_arguments(),
            "invalid edge type",
        ));
    }
    let mut template = valid_template();
    template["actions"][1]["priority"] = json!(1.5);
    cases.push(("priority type", template, valid_arguments(), "priority"));
    let mut template = valid_template();
    template["edges"] = json!([
        {"from": 0, "to": 1, "type": "requires"},
        {"from": 1, "to": 0, "type": "requires"}
    ]);
    cases.push(("cycle", template, valid_arguments(), "cycle"));
    cases
}

fn sqlite_counts(conn: &rusqlite::Connection) -> (i64, i64, i64) {
    conn.query_row(
        "SELECT (SELECT count(*) FROM actions), (SELECT count(*) FROM action_edges), \
         (SELECT coalesce(sum(current_storage_bytes), 0) FROM agent_quotas)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .expect("counts")
}

#[test]
fn sqlite_routine_denied_controls_leave_no_dag_or_charge() {
    for (name, template, arguments, expected) in denied_cases() {
        let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("database");
        let r = routine(template);
        let error = materialize_template(&conn, &r, &arguments, 1).expect_err(name);
        assert!(
            error.contains(expected),
            "{name}: expected {expected}, got {error}"
        );
        assert_eq!(sqlite_counts(&conn), (0, 0, 0), "{name}");
    }
}

#[test]
fn sqlite_valid_routine_matches_direct_charge_and_field_limits() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("database");
    let r = routine(valid_template());
    let mut args = valid_arguments();
    args["title"] = json!("x".repeat(8192));
    args["kind"] = json!("k".repeat(256));
    let ids = materialize_template(&conn, &r, &args, 1).expect("run");
    let (actions, edges, charged) = sqlite_counts(&conn);
    assert_eq!((actions, edges), (2, 1));
    assert!(charged > 0);
    for id in ids {
        let action = ai_memory::actions::get(&conn, &id)
            .expect("get")
            .expect("action");
        handle_action_create(
            &conn,
            &json!({
                "namespace": r.namespace, "agent_id": ACTOR, "kind": action.kind,
                "title": action.title, "payload": action.payload, "metadata": action.metadata
            }),
        )
        .expect("equivalent direct create");
    }
    assert_eq!(sqlite_counts(&conn), (4, 1, charged * 2));
}

#[test]
fn sqlite_routine_quota_exhaustion_rolls_back_earlier_charge_and_action() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("database");
    let r = routine(valid_template());
    ai_memory::quotas::check_and_record_storage_only(&conn, ACTOR, &r.namespace, 0)
        .expect("quota row");
    for cap in [0, 13] {
        conn.execute("UPDATE agent_quotas SET max_storage_bytes = ?1", [cap])
            .expect("cap");
        let error =
            materialize_template(&conn, &r, &valid_arguments(), 1).expect_err("exhausted quota");
        assert!(error.to_lowercase().contains("quota"), "{error}");
        assert_eq!(sqlite_counts(&conn), (0, 0, 0), "cap {cap}");
    }
    conn.execute("UPDATE agent_quotas SET max_storage_bytes = 10000", [])
        .expect("allow quota");
    materialize_template(&conn, &r, &valid_arguments(), 1).expect("run");
    assert!(sqlite_counts(&conn).2 > 0);
}

#[test]
fn sqlite_direct_insert_failure_refunds_charge() {
    let conn = ai_memory::storage::open(std::path::Path::new(":memory:")).expect("database");
    conn.execute_batch("CREATE TRIGGER refuse_action BEFORE INSERT ON actions BEGIN SELECT RAISE(ABORT, 'injected'); END;").expect("trigger");
    assert!(
        handle_action_create(
            &conn,
            &json!({"namespace": "test", "agent_id": ACTOR, "kind": "work", "title": "test"})
        )
        .is_err()
    );
    assert_eq!(sqlite_counts(&conn), (0, 0, 0));
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::{CallerContext, MemoryStore, postgres::PostgresStore};

    async fn counts(store: &PostgresStore, ns: &str) -> (i64, i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT count(*) FROM actions WHERE namespace = $1), \
             (SELECT count(*) FROM action_edges e JOIN actions a ON a.id = e.from_action WHERE a.namespace = $1), \
             (SELECT coalesce(sum(current_storage_bytes), 0)::bigint FROM agent_quotas WHERE namespace = $1)"
        ).bind(ns).fetch_one(store.pool()).await.expect("counts")
    }

    #[tokio::test]
    async fn postgres_routine_controls_and_atomic_quota() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("postgres");
        let ctx = CallerContext::for_agent(ACTOR);
        for (name, template, args, expected) in denied_cases() {
            let r = routine(template);
            store
                .routine_create(&ctx, &r)
                .await
                .expect("frozen fixture");
            let err = store
                .routine_materialize(&ctx, &r.id, &args)
                .await
                .expect_err(name)
                .to_string();
            assert!(
                err.contains(expected),
                "{name}: expected {expected}, got {err}"
            );
            assert_eq!(counts(&store, &r.namespace).await, (0, 0, 0), "{name}");
        }
        let r = routine(valid_template());
        store.routine_create(&ctx, &r).await.expect("routine");
        let ids = store
            .routine_materialize(&ctx, &r.id, &valid_arguments())
            .await
            .expect("allowed");
        let (actions, edges, charged) = counts(&store, &r.namespace).await;
        assert_eq!((actions, edges), (2, 1));
        assert!(charged > 0);
        for id in ids {
            let mut action = store
                .action_get(&ctx, &id)
                .await
                .expect("get")
                .expect("action");
            action.id = uuid::Uuid::new_v4().to_string();
            store
                .action_create(&ctx, &action)
                .await
                .expect("equivalent direct create");
        }
        assert_eq!(counts(&store, &r.namespace).await, (4, 1, charged * 2));
        for headroom in [0_i64, 13] {
            sqlx::query("UPDATE agent_quotas SET max_storage_bytes = current_storage_bytes + $1 WHERE namespace = $2")
                .bind(headroom).bind(&r.namespace).execute(store.pool()).await.expect("exhaust quota");
            let err = store
                .routine_materialize(&ctx, &r.id, &valid_arguments())
                .await
                .expect_err("exhausted")
                .to_string();
            assert!(err.to_lowercase().contains("quota"), "{err}");
            assert_eq!(counts(&store, &r.namespace).await, (4, 1, charged * 2));
        }
        sqlx::query("UPDATE agent_quotas SET max_storage_bytes = 100000 WHERE namespace = $1")
            .bind(&r.namespace)
            .execute(store.pool())
            .await
            .expect("restore quota");
        store
            .routine_materialize(&ctx, &r.id, &valid_arguments())
            .await
            .expect("retry allowed");
        assert_eq!(counts(&store, &r.namespace).await, (6, 2, charged * 3));
    }
}
