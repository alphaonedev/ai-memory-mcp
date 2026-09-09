// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3498: graph/family reads apply the substrate opt-in and owner checks.

use ai_memory::models::Memory;
use serde_json::{Value, json};

const CALLER: &str = "ai:me";

fn seed(conn: &rusqlite::Connection, namespace: &str, target: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        title: format!("{namespace} {}", uuid::Uuid::new_v4()),
        content: "graph visibility regression".to_string(),
        created_at: now.clone(),
        updated_at: now,
        source_uri: Some("doc:visibility-3498".to_string()),
        metadata: json!({"agent_id": target, "scope": if namespace.starts_with("_inbox/") || namespace.starts_with("_messages/") { "private" } else { "collective" }, "target_agent_id": target, "family": "graph"}),
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed memory")
}

fn fixture() -> (rusqlite::Connection, String, String, Vec<String>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    let root = seed(&conn, "ordinary", CALLER);
    let ordinary = seed(&conn, "ordinary", CALLER);
    let hidden = [
        "_inbox/ai:me",
        "_messages/ai:me",
        "_inbox/ai:other",
        "_agents",
        "_agent_sessions",
        "_standards",
    ]
    .into_iter()
    .map(|ns| {
        seed(
            &conn,
            ns,
            if ns.ends_with("other") {
                "ai:other"
            } else {
                CALLER
            },
        )
    })
    .collect::<Vec<_>>();
    for id in std::iter::once(&ordinary).chain(hidden.iter()) {
        ai_memory::db::create_link(&conn, &root, id, "derived_from").expect("seed edge");
    }
    (conn, root, ordinary, hidden)
}

fn assert_rows(out: &Value, key: &str, id_key: &str, ordinary: &str, hidden: &[String]) {
    let rows = out[key].as_array().expect("rows");
    assert!(
        rows.iter().any(|r| r[id_key] == ordinary),
        "allowed row missing: {out}"
    );
    for id in hidden {
        assert!(
            !rows.iter().any(|r| r[id_key] == *id),
            "substrate row leaked: {out}"
        );
    }
}

#[test]
fn family_named_mail_and_ambient_matrix() {
    let (conn, _, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out =
            ai_memory::mcp::handle_load_family(&conn, &json!({"family": "graph", "k": 50}), caller)
                .expect("family");
        assert_rows(&out, "memories", "id", &ordinary, &hidden);
    }
    let out = ai_memory::mcp::handle_load_family(&conn, &json!({"family": "graph", "k": 1}), None)
        .expect("small family page");
    assert_eq!(
        out["count"], 1,
        "hidden rows cannot consume the page: {out}"
    );
    assert_eq!(out["memories"][0]["namespace"], "ordinary");
    for namespace in ["_inbox/ai:me", "_messages/ai:me"] {
        let out = ai_memory::mcp::handle_load_family(
            &conn,
            &json!({"family": "graph", "namespace": namespace}),
            Some(CALLER),
        )
        .expect("own mail");
        assert_eq!(out["count"], 1, "named own mail: {out}");
    }
    let out = ai_memory::mcp::handle_load_family(
        &conn,
        &json!({"family": "graph", "namespace": "_inbox/ai:other"}),
        Some(CALLER),
    )
    .expect("foreign mail");
    assert_eq!(out["count"], 0, "foreign mail: {out}");
}

#[test]
fn kg_query_walk_and_source_uri_withhold_ambient_substrate() {
    let (conn, root, ordinary, hidden) = fixture();
    for params in [
        json!({"source_id": root}),
        json!({"by_source_uri": "doc:visibility-3498"}),
    ] {
        let out = ai_memory::mcp::handle_kg_query(&conn, &params).expect("query");
        assert_rows(&out, "memories", "target_id", &ordinary, &hidden);
    }
    for namespace in ["_inbox/ai:me", "_messages/ai:me"] {
        let out = ai_memory::mcp::handle_kg_query(
            &conn,
            &json!({"source_id": root, "namespace": namespace}),
        )
        .expect("named query");
        assert!(
            out["memories"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["target_namespace"] == namespace),
            "own mail allowed: {out}"
        );
    }
}

#[test]
fn lineage_withholds_substrate_roots_and_neighbors() {
    let (conn, root, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out =
            ai_memory::mcp::handle_lineage(&conn, &json!({"id": root}), caller).expect("lineage");
        assert_rows(&out, "nodes", "id", &ordinary, &hidden);
        for id in &hidden {
            assert!(
                ai_memory::mcp::handle_lineage(&conn, &json!({"id": id}), caller).is_err(),
                "substrate root admitted"
            );
        }
    }
}

#[test]
fn timeline_withholds_substrate_roots_and_targets() {
    let (conn, root, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out = ai_memory::mcp::handle_kg_timeline(&conn, &json!({"source_id": root}), caller)
            .expect("timeline");
        assert_rows(&out, "events", "target_id", &ordinary, &hidden);
        for id in &hidden {
            assert!(
                ai_memory::mcp::handle_kg_timeline(&conn, &json!({"source_id": id}), caller)
                    .is_err(),
                "substrate root admitted"
            );
        }
    }
}

#[test]
fn paths_withhold_substrate_endpoints_and_intermediates() {
    let (conn, root, ordinary, hidden) = fixture();
    for id in &hidden {
        ai_memory::db::create_link(&conn, id, &ordinary, "derived_from").expect("indirect edge");
    }
    for caller in [None, Some(CALLER)] {
        let out = ai_memory::mcp::handle_find_paths(
            &conn,
            &json!({"source_id": root, "target_id": ordinary}),
            caller,
        )
        .expect("paths");
        assert_eq!(out["count"], 1, "only direct ordinary path: {out}");
        for id in &hidden {
            let out = ai_memory::mcp::handle_find_paths(
                &conn,
                &json!({"source_id": root, "target_id": id}),
                caller,
            )
            .expect("denied path");
            assert_eq!(out["count"], 0, "substrate path leaked: {out}");
        }
    }
}
