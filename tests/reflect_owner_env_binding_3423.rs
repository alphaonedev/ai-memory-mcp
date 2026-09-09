// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3423 — the `None`-caller half of the reflection OWNER rule, i.e. the #3171
//! `AI_MEMORY_AGENT_ID` binding every MCP / CLI reflect still runs: a forged
//! wire `agent_id` is refused, a matching one and the ambient default resolve
//! to the enforced caller.
//!
//! Own test binary (own process) because it INSTALLS `AI_MEMORY_AGENT_ID`,
//! which `scripts/check-test-env-lock.sh` arm (d) (#3475) forbids inside the
//! shared lib test binary — the readers on sibling threads take no lock.

use serde_json::json;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";
const REAL: &str = "ai:realcaller";

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Installs the enforced caller for the guard's lifetime and restores the
/// previous value on drop (also on an unwinding panic).
struct AgentIdEnv {
    prev: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl AgentIdEnv {
    fn set(value: &str) -> Self {
        let lock = env_lock();
        let prev = std::env::var_os(ENV_AGENT_ID);
        // SAFETY: this binary's tests serialise every env mutation on
        // `env_lock`, and the binary is its own process (#3475).
        unsafe { std::env::set_var(ENV_AGENT_ID, value) };
        Self { prev, _lock: lock }
    }
}

impl Drop for AgentIdEnv {
    fn drop(&mut self) {
        // SAFETY: still serialised on the lock this guard holds.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(ENV_AGENT_ID, v),
                None => std::env::remove_var(ENV_AGENT_ID),
            }
        }
    }
}

fn seed_source(conn: &rusqlite::Connection, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "team/3423".to_string(),
        title: "reflect source".to_string(),
        content: "a source memory to reflect over".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": owner, "scope": "collective"}),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("insert source")
}

fn reflect(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    src: &str,
    agent_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    let mut params = json!({
        "source_ids": [src],
        "title": format!("a reflection {}", uuid::Uuid::new_v4()),
        "content": "a synthesised insight over the seeded source",
        "namespace": "team/3423",
    });
    if let Some(a) = agent_id {
        params["agent_id"] = json!(a);
    }
    ai_memory::mcp::handle_reflect(conn, db_path, &params, None, None, None, None)
}

#[test]
fn reflect_owner_without_an_authenticated_caller_keeps_the_3171_binding() {
    let _env = AgentIdEnv::set(REAL);
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("reflect-3423.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let src = seed_source(&conn, REAL);

    // DENIED — a self-asserted wire principal that disagrees with the enforced
    // caller is still refused by the #3171 binding (byte-identical to
    // pre-#3423).
    let err = reflect(&conn, &db_path, &src, Some("ai:forged"))
        .expect_err("a forged wire principal must still refuse");
    assert!(err.contains("agent_id mismatch"), "got: {err}");

    // ALLOWED — a matching wire id, and the ambient default, both resolve to
    // the enforced caller, which is what the row is owned by.
    for explicit in [Some(REAL), None] {
        let out = reflect(&conn, &db_path, &src, explicit).expect("reflect ok");
        let id = out["id"].as_str().expect("reflection id");
        let row = ai_memory::db::get(&conn, id)
            .expect("get")
            .expect("reflection row");
        assert_eq!(
            row.metadata["agent_id"].as_str(),
            Some(REAL),
            "the reflection must be owned by the enforced caller (explicit={explicit:?})"
        );
    }
}
