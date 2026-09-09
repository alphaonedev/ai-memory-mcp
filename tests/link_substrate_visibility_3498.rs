// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3498: configured-caller link target checks, isolated in a subprocess.

use ai_memory::db;
use ai_memory::models::Memory;
use serde_json::json;

#[test]
fn link_target_substrate_gate_3498() {
    const CHILD: &str = "AI_MEMORY_LINK_3498_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "link_target_substrate_gate_3498", "--nocapture"])
            .env(CHILD, "1")
            .env("AI_MEMORY_AGENT_ID", "ai:me")
            .output()
            .expect("isolated caller process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    let conn = ai_memory::db::open(&path).unwrap();
    let seed = |namespace: &str, owner: &str| {
        let now = chrono::Utc::now().to_rfc3339();
        let memory = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: namespace.to_string(),
            title: format!("target {}", uuid::Uuid::new_v4()),
            content: "link gate".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({"agent_id": owner, "scope": "private", "target_agent_id": owner}),
            ..Memory::default()
        };
        ai_memory::db::insert(&conn, &memory).unwrap()
    };
    let root = seed("ordinary", "ai:me");
    for namespace in [
        "ordinary",
        "ordinary-foreign",
        "legacy-unowned",
        "_inbox/ai:me",
        "_messages/ai:me",
        "_inbox/ai:other",
        "_agents",
        "_agent_sessions",
        "_standards",
    ] {
        let target = seed(
            namespace,
            if matches!(namespace, "_inbox/ai:other" | "ordinary-foreign") {
                "ai:other"
            } else {
                "ai:me"
            },
        );
        if namespace == "legacy-unowned" {
            conn.execute(
                "UPDATE memories SET metadata = '{}' WHERE id = ?1",
                [&target],
            )
            .unwrap();
        }
        let result = ai_memory::mcp::dispatch_handle_link_for_test(
            &conn,
            &path,
            &json!({"source_id": root, "target_id": target, "relation": "related_to", "agent_id": "ai:me"}),
            None,
        );
        if matches!(
            namespace,
            "_inbox/ai:other" | "ordinary-foreign" | "legacy-unowned"
        ) {
            assert!(
                result.unwrap_err().contains("cannot see the link target"),
                "MCP preserves target visibility for {namespace}"
            );
            assert!(
                ai_memory::db::get_links(&conn, &target).unwrap().is_empty(),
                "refusal must not write an edge"
            );
        } else {
            assert!(
                result.is_ok(),
                "explicit readable target allowed: {result:?}"
            );
        }
    }
}

#[test]
fn named_kg_namespace_preserves_owner_gate_3498() {
    const CHILD: &str = "AI_MEMORY_KG_3498_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "named_kg_namespace_preserves_owner_gate_3498",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("AI_MEMORY_AGENT_ID", "ai:me")
            .output()
            .expect("isolated caller process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    let root = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "ordinary".to_string(),
        title: "root".to_string(),
        content: "body".to_string(),
        created_at: now.clone(),
        updated_at: now.clone(),
        metadata: json!({"agent_id": "ai:me"}),
        ..Default::default()
    };
    db::insert(&conn, &root).unwrap();
    for prefix in ["_inbox", "_messages"] {
        for recipient in ["ai:me", "ai:other"] {
            let namespace = format!("{prefix}/{recipient}");
            let mail = ai_memory::models::Memory {
                id: uuid::Uuid::new_v4().to_string(),
                namespace: namespace.clone(),
                title: "mail".to_string(),
                content: "body".to_string(),
                created_at: now.clone(),
                updated_at: now.clone(),
                source_uri: Some("doc:mail-3498".to_string()),
                metadata: json!({"agent_id": "ai:sender", "target_agent_id": recipient}),
                ..Default::default()
            };
            db::insert(&conn, &mail).unwrap();
            db::create_link(&conn, &root.id, &mail.id, "related_to").unwrap();
            db::create_link(&conn, &mail.id, &root.id, "derived_from").unwrap();
            let anchored =
                ai_memory::mcp::handle_kg_query(&conn, &json!({"source_id": mail.id})).unwrap();
            assert_eq!(
                anchored["count"].as_u64().unwrap() > 0,
                recipient == "ai:me",
                "explicit inbox source: {anchored}"
            );

            for mut params in [
                json!({"source_id": root.id}),
                json!({"by_source_uri": "doc:mail-3498"}),
            ] {
                params["namespace"] = json!(namespace);
                let out = ai_memory::mcp::handle_kg_query(&conn, &params).unwrap();
                let found = out["memories"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m["target_id"] == mail.id);
                assert_eq!(
                    found,
                    params.get("by_source_uri").is_some() && recipient == "ai:me",
                    "anchor vs reached inbox gate: {out}"
                );
            }
        }
    }
}
