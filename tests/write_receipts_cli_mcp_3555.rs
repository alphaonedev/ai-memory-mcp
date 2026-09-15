// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3555: receipts survive CLI and MCP stdio serialization.
use serde_json::{Value, json};
use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

fn run(db: &Path, sync: &str, args: &[&str], input: &str) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    command
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_DB_SYNCHRONOUS", sync)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .arg("--db")
        .arg(db)
        .arg("--agent-id")
        .arg("receipt-agent-3555")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn isolated CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("CLI output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

fn tool(db: &Path, sync: &str, name: &str, arguments: &Value) -> Value {
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"receipt-agent-3555","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":arguments}}),
    ].map(|frame| frame.to_string()).join("\n") + "\n";
    let output = run(db, sync, &["mcp", "--profile", "full"], &frames);
    let response = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .expect("MCP response");
    assert!(response.get("error").is_none(), "{response}");
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text"),
    )
    .expect("receipt JSON")
}

fn assert_local(receipt: &Value, cadence: &str) {
    assert_eq!(receipt["durability_class"], "local-only", "{receipt}");
    assert_eq!(receipt["fsync"], cadence, "{receipt}");
}

#[test]
fn cli_store_update_capture_receipts_3555() {
    let scratch =
        tempfile::tempdir_in(std::env::var("CARGO_TARGET_DIR").expect("target")).expect("scratch");
    for (sync, cadence) in [("NORMAL", "per-checkpoint"), ("FULL", "per-commit")] {
        let db = scratch.path().join(format!("{sync}.db"));
        let stored: Value = serde_json::from_str(&run(
            &db,
            sync,
            &[
                "store",
                "--json",
                "--title",
                "receipt CLI",
                "--content",
                "CLI durability receipt observation.",
            ],
            "",
        ))
        .expect("store receipt");
        assert_local(&stored, cadence);
        let id = stored["id"].as_str().expect("stored id");
        let updated: Value = serde_json::from_str(&run(
            &db,
            sync,
            &[
                "update",
                id,
                "--json",
                "--content",
                "Updated CLI receipt observation.",
            ],
            "",
        ))
        .expect("update receipt");
        assert_local(&updated, cadence);
        let capture = json!({"host_session_id":"cli-receipt3555","host_turn_index":0,"role":"user","content":"CLI capture receipt observation."});
        let captured: Value = serde_json::from_str(&run(
            &db,
            sync,
            &["capture-turn", "--json"],
            &capture.to_string(),
        ))
        .expect("capture receipt");
        assert_local(&captured, cadence);
    }
}

#[test]
fn mcp_store_update_capture_receipts_3555() {
    let scratch =
        tempfile::tempdir_in(std::env::var("CARGO_TARGET_DIR").expect("target")).expect("scratch");
    for (sync, cadence) in [("NORMAL", "per-checkpoint"), ("FULL", "per-commit")] {
        let db = scratch.path().join(format!("{sync}.db"));
        let stored = tool(
            &db,
            sync,
            "memory_store",
            &json!({"title":"receipt MCP", "content":"MCP durability receipt observation."}),
        );
        assert_local(&stored, cadence);
        let updated = tool(
            &db,
            sync,
            "memory_update",
            &json!({"id":stored["id"],"content":"Updated MCP receipt observation."}),
        );
        assert_local(&updated, cadence);
        let capture = json!({"host_session_id":"mcp-receipt3555","host_turn_index":0,"role":"user","content":"MCP capture receipt observation."});
        let captured = tool(&db, sync, "memory_capture_turn", &capture);
        assert_local(&captured, cadence);
    }
}

#[test]
fn cli_pending_receipt_3555() -> anyhow::Result<()> {
    use ai_memory::models::{
        CorePolicy, GovernanceLevel, GovernancePolicy, GovernedAction, Memory, Tier,
    };
    let _gate = ai_memory::config::lock_permissions_mode_for_test();
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let scratch = tempfile::tempdir_in(std::env::var("CARGO_TARGET_DIR")?)?;
    let conn = ai_memory::db::open(&scratch.path().join("pending.db"))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "_standards-receipt3555".to_owned(),
        title: "receipt policy".to_owned(),
        content: "Pending receipt policy".to_owned(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id":"receipt-owner-3555","governance":policy}),
        ..Memory::default()
    };
    let id = ai_memory::db::insert(&conn, &standard)?;
    ai_memory::db::set_namespace_standard(&conn, "receipt3555", &id, None)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut output = ai_memory::cli::CliOutput {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    let outcome = ai_memory::cli::governance::enforce(
        &conn,
        GovernedAction::Store,
        "receipt3555",
        "receipt-agent-3555",
        None,
        None,
        &json!({}),
        None,
        true,
        &mut output,
    )?;
    assert_eq!(
        outcome,
        ai_memory::cli::governance::GovernanceOutcome::Pending
    );
    let receipt: Value = serde_json::from_slice(&stdout)?;
    assert_eq!(receipt["status"], "pending");
    assert_local(&receipt, "per-commit");
    Ok(())
}
