// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3506: owner-only admission precedes every routine execution side effect.
//! Child processes isolate identity postures without mutating the test runner's
//! environment or holding a blocking environment guard across an await.

use ai_memory::models::{Routine, RoutineState};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const OWNER: &str = "ai:routine-owner-3506";
const STRANGER: &str = "ai:routine-stranger-3506";
const CASE: &str = "AI_MEMORY_ROUTINE_AUTHZ_3506_CASE";

fn sandbox() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("scratch root");
    tempfile::tempdir_in(root).expect("scratch directory")
}

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
}

impl Mcp {
    fn start(path: &std::path::Path, home: &std::path::Path) -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .arg("--db")
            .arg(path)
            .args(["mcp", "--profile", "full", "--tier", "keyword"])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("AI_MEMORY_KEY_DIR", home.join("keys"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("MCP child");
        let input = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Self {
            child,
            input,
            output,
        };
        let init = mcp.request(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "routine-3506", "version": "1"}}}));
        assert!(init.get("error").is_none(), "initialize: {init}");
        mcp
    }

    fn request(&mut self, request: &Value) -> Value {
        writeln!(self.input, "{request}").expect("request");
        self.input.flush().expect("flush");
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, "routine authorization");
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == request.get("id") {
                return response;
            }
        }
    }

    fn run(&mut self, routine_id: &str) -> Result<Value, String> {
        let response = self.request(&json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"memory_routine_run", "arguments":{"routine_id":routine_id,"arguments":{},"agent_id":OWNER}}}));
        if response.get("error").is_some() || response["result"]["isError"] == true {
            return Err(response.to_string());
        }
        serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("tool text"),
        )
        .map_err(|e| e.to_string())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_cases(test: &str) -> Option<String> {
    if let Ok(case) = std::env::var(CASE) {
        return Some(case);
    }
    for case in [
        "owner",
        "stranger",
        "ownerless",
        "local",
        "local-ownerless",
        "context-stranger",
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test binary"));
        command
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CASE, case)
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env_remove("AI_MEMORY_AGENT_ID");
        match case {
            "owner" | "ownerless" => {
                command.env("AI_MEMORY_AGENT_ID", OWNER);
            }
            "stranger" => {
                command.env("AI_MEMORY_AGENT_ID", STRANGER);
            }
            _ => {}
        }
        let output = command.output().expect("isolated authorization test");
        assert!(
            output.status.success(),
            "{test}/{case}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"));
        eprintln!("#3506 {test}/{case} passed");
    }
    None
}

fn fixture(case: &str) -> Routine {
    Routine {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: format!("routine-3506-{}", uuid::Uuid::new_v4().simple()),
        name: "owner admission".to_string(),
        template: json!({"actions": [{"kind": "work", "title": "first"}, {"kind": "work", "title": "second"}], "edges": [{"from": 0, "to": 1, "type": "requires"}]}),
        parameters: json!([]),
        state: RoutineState::Frozen,
        created_by: if case.contains("ownerless") {
            ""
        } else {
            OWNER
        }
        .to_string(),
        created_at: 1,
        frozen_at: Some(1),
        signature: vec![],
        signer_pubkey: vec![],
        metadata: json!({}),
    }
}

fn sqlite_snapshot(conn: &rusqlite::Connection) -> (i64, i64, i64, i64, i64, i64) {
    conn.query_row("SELECT (SELECT count(*) FROM routine_runs), (SELECT count(*) FROM signed_events), (SELECT count(*) FROM actions), (SELECT count(*) FROM action_edges), (SELECT count(*) FROM agent_quotas), (SELECT coalesce(sum(current_storage_bytes), 0) FROM agent_quotas)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).expect("snapshot")
}

fn assert_denied(error: &str, case: &str) {
    let expected = if case.contains("ownerless") {
        ai_memory::routines::materialization::ROUTINE_OWNER_UNKNOWN
    } else {
        "agent_id mismatch"
    };
    assert!(error.contains(expected), "{case}: {error}");
}

#[test]
fn sqlite_owner_authorization() {
    let Some(case) = run_cases("sqlite_owner_authorization") else {
        return;
    };
    let directory = sandbox();
    let path = directory.path().join("mcp.db");
    let conn = ai_memory::storage::open(&path).expect("database");
    let routine = fixture(&case);
    ai_memory::routines::routine_insert(&conn, &routine).expect("fixture");
    let mut mcp = Mcp::start(&path, directory.path());
    let before = sqlite_snapshot(&conn);
    // MCP has no CallerContext, so context-stranger is checked on SAL below.
    if case != "context-stranger" {
        let result = mcp.run(&routine.id);
        if matches!(case.as_str(), "stranger" | "ownerless") {
            assert_denied(&result.expect_err("refused before run"), &case);
            assert_eq!(sqlite_snapshot(&conn), before, "denial has no side effects");
        } else {
            let result = result.expect("admitted");
            assert_eq!(result["run"]["state"], "completed");
            let actor = result["run"]["metadata"]["agent_id"]
                .as_str()
                .expect("run attribution");
            assert!(!actor.is_empty());
            if case != "local-ownerless" {
                assert_eq!(actor, OWNER);
            }
            let actors: i64 = conn
                .query_row(
                    "SELECT count(*) FROM actions WHERE agent_id = ?1",
                    [actor],
                    |r| r.get(0),
                )
                .expect("action actors");
            assert_eq!(actors, 2);
            let audit_actor: String = conn
                .query_row(
                    "SELECT agent_id FROM signed_events WHERE event_type = ?1",
                    [ai_memory::coordination_audit::ROUTINE_RUN],
                    |r| r.get(0),
                )
                .expect("audit actor");
            assert_eq!(audit_actor, actor);
            let charge: i64 = conn.query_row("SELECT current_storage_bytes FROM agent_quotas WHERE agent_id = ?1 AND namespace = ?2", [actor, &routine.namespace], |r| r.get(0)).expect("caller quota");
            assert!(charge > 0);
        }
    }
    #[cfg(feature = "sal")]
    sqlite_sal(&case);
}

#[cfg(feature = "sal")]
fn context(case: &str) -> ai_memory::store::CallerContext {
    let mut ctx = ai_memory::store::CallerContext::for_agent(
        if matches!(case, "stranger" | "context-stranger") {
            STRANGER
        } else {
            OWNER
        },
    );
    // Neither visibility bypass nor as_agent is an execution grant.
    ctx.bypass_visibility = true;
    ctx.as_agent = Some(OWNER.to_string());
    ctx
}

#[cfg(feature = "sal")]
fn sqlite_sal(case: &str) {
    use ai_memory::store::{MemoryStore, sqlite::SqliteStore};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let directory = sandbox();
        let path = directory.path().join("routine.db");
        let store = SqliteStore::open(&path).expect("store");
        let routine = fixture(case);
        let ctx = context(case);
        store.routine_create(&ctx, &routine).await.expect("fixture");
        let conn = rusqlite::Connection::open(&path).expect("inspection");
        let before = sqlite_snapshot(&conn);
        let result = store
            .routine_materialize(&ctx, &routine.id, &json!({}))
            .await;
        if matches!(case, "owner" | "local") {
            assert_eq!(result.expect("owner").len(), 2);
            let after = sqlite_snapshot(&conn);
            assert_eq!((after.2, after.3), (2, 1));
            assert!(after.5 > before.5);
            let actors: i64 = conn
                .query_row(
                    "SELECT count(*) FROM actions WHERE agent_id = ?1",
                    [OWNER],
                    |r| r.get(0),
                )
                .expect("actors");
            assert_eq!(actors, 2);
        } else {
            assert_denied(&result.expect_err("SAL refused").to_string(), case);
            assert_eq!(sqlite_snapshot(&conn), before);
        }
    });
}

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_owner_authorization() {
    use ai_memory::store::{MemoryStore, postgres::PostgresStore};
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: live PostgreSQL requires AI_MEMORY_TEST_POSTGRES_URL");
        return;
    };
    let Some(case) = run_cases("postgres_owner_authorization") else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let store = PostgresStore::connect(&url).await.expect("certified live PostgreSQL");
        let routine = fixture(&case);
        let ctx = context(&case);
        store.routine_create(&ctx, &routine).await.expect("fixture");
        let before = pg_snapshot(&store, &routine.namespace).await;
        let result = store.routine_materialize(&ctx, &routine.id, &json!({})).await;
        if matches!(case.as_str(), "owner" | "local") {
            assert_eq!(result.expect("owner").len(), 2);
            let after = pg_snapshot(&store, &routine.namespace).await;
            assert_eq!((after.2, after.3), (2, 1));
            assert!(after.5 > before.5);
            let actors: i64 = sqlx::query_scalar("SELECT count(*) FROM actions WHERE namespace = $1 AND agent_id = $2").bind(&routine.namespace).bind(OWNER).fetch_one(store.pool()).await.expect("actors");
            assert_eq!(actors, 2);
            let charge: i64 = sqlx::query_scalar("SELECT current_storage_bytes FROM agent_quotas WHERE namespace = $1 AND agent_id = $2").bind(&routine.namespace).bind(OWNER).fetch_one(store.pool()).await.expect("caller quota");
            assert!(charge > 0);
        } else {
            assert_denied(&result.expect_err("SAL refused").to_string(), &case);
            assert_eq!(pg_snapshot(&store, &routine.namespace).await, before);
        }
        store.pool().close().await;
    });
}

#[cfg(feature = "sal-postgres")]
async fn pg_snapshot(
    store: &ai_memory::store::postgres::PostgresStore,
    ns: &str,
) -> (i64, i64, i64, i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM routine_runs WHERE namespace = $1), (SELECT count(*) FROM signed_events), (SELECT count(*) FROM actions WHERE namespace = $1), (SELECT count(*) FROM action_edges e JOIN actions a ON a.id = e.from_action WHERE a.namespace = $1), (SELECT count(*) FROM agent_quotas WHERE namespace = $1), (SELECT coalesce(sum(current_storage_bytes), 0)::bigint FROM agent_quotas WHERE namespace = $1)").bind(ns).fetch_one(store.pool()).await.expect("snapshot")
}
