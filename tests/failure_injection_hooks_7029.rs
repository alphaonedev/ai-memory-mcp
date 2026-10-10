// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7029 campaign F — pins the four test-only fault hooks (H1-H4) the
//! failure-injection suites stack on.
//!
//! - H1 `AI_MEMORY_TEST_FAIL_BEFORE_SIGNED_COMMIT=<id>`: the L4 capture funnel
//!   (memories INSERT + dedup row + `signed_events` row in ONE transaction)
//!   returns `Err` between the memories INSERT and the signed-event append,
//!   and the single transaction rolls back. SQLite here; the Postgres cell
//!   runs when `AI_MEMORY_TEST_POSTGRES_URL` is set and skips with a reason
//!   otherwise.
//! - H2 `AI_MEMORY_TEST_CLOCK_OFFSET_SECS=<i64>`: `ai_memory::test_clock::now`
//!   moves by exactly the offset; `0` / unset / unparseable is identity.
//! - H3 `Mcp::pid`: the real child pid.
//! - H4 `AI_MEMORY_TEST_PG_QUOTA_TABLESPACE`: read-through helper.

use std::sync::{Mutex, MutexGuard, PoisonError};

use ai_memory::db;
use ai_memory::models::{CaptureTurnWrite, Memory, Tier, default_metadata};
use ai_memory::recover::durability::{
    ENV_FAIL_BEFORE_SIGNED_COMMIT, fail_before_signed_commit_decision,
};
use ai_memory::signed_events::SignedEvent;
use ai_memory::test_clock::{self, ENV_CLOCK_OFFSET_SECS};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

#[path = "common/postgres_env.rs"]
mod postgres_env;

/// Serialises every test that mutates this process's environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Holds the env lock and restores the prior value of one variable on drop.
struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let prev = std::env::var_os(key);
        // SAFETY: every environment mutation in this test binary happens
        // under `ENV_LOCK`, which this guard holds until it drops.
        unsafe { std::env::set_var(key, value) };
        Self {
            key,
            prev,
            _lock: lock,
        }
    }

    fn unset(key: &'static str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let prev = std::env::var_os(key);
        // SAFETY: serialised by `ENV_LOCK`, held for the guard's lifetime.
        unsafe { std::env::remove_var(key) };
        Self {
            key,
            prev,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            // SAFETY: `_lock` is still held while the prior value is restored.
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            // SAFETY: as above.
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

fn capture_write(id: &str, session: &str) -> CaptureTurnWrite {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String("ai:fi-7029".into());
    let sha = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(id.as_bytes());
        h.finalize().to_vec()
    };
    CaptureTurnWrite {
        memory: Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: "fi-7029".into(),
            title: format!("fi-7029 {id}"),
            content: "failure injection".into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata,
            ..Memory::default()
        },
        sha256: sha.clone(),
        host_kind: "claude-code".into(),
        host_session_id: session.into(),
        host_turn_index: 0,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event: SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "ai:fi-7029".into(),
            event_type: "memory.capture_turn".into(),
            payload_hash: sha,
            signature: None,
            attest_level: "unsigned".into(),
            timestamp: now,
            ..SignedEvent::default()
        },
    }
}

fn count(conn: &rusqlite::Connection, sql: &str, id: &str) -> i64 {
    conn.query_row(sql, rusqlite::params![id], |r| r.get(0))
        .expect("count query")
}

const SQL_MEMORY_BY_ID: &str = "SELECT COUNT(*) FROM memories WHERE id = ?1";
const SQL_DEDUP_BY_MEMORY: &str = "SELECT COUNT(*) FROM transcript_line_dedup WHERE memory_id = ?1";
const SQL_SIGNED_ALL: &str = "SELECT COUNT(*) FROM signed_events WHERE ?1 = ?1";

#[test]
fn h1_decision_matches_only_the_armed_id_7029() {
    let _g = EnvGuard::set(ENV_FAIL_BEFORE_SIGNED_COMMIT, "armed-id");
    assert!(fail_before_signed_commit_decision("armed-id"));
    assert!(!fail_before_signed_commit_decision("other-id"));
    drop(_g);
    let _g = EnvGuard::unset(ENV_FAIL_BEFORE_SIGNED_COMMIT);
    assert!(!fail_before_signed_commit_decision("armed-id"));
}

#[test]
fn h1_sqlite_capture_rolls_back_whole_transaction_7029() {
    let conn = db::open(std::path::Path::new(":memory:")).expect("open");
    let id = uuid::Uuid::new_v4().to_string();
    let write = capture_write(&id, "fi-7029-sess");
    let signed_before = count(&conn, SQL_SIGNED_ALL, "x");

    let armed = EnvGuard::set(ENV_FAIL_BEFORE_SIGNED_COMMIT, &id);
    let err = ai_memory::storage::capture_turn_idempotent(&conn, &write, false)
        .expect_err("H1 armed for this id must fail the capture");
    assert!(
        err.contains("injected before signed commit"),
        "unexpected error: {err}"
    );
    assert_eq!(count(&conn, SQL_MEMORY_BY_ID, &id), 0, "memories row leaked");
    assert_eq!(
        count(&conn, SQL_DEDUP_BY_MEMORY, &id),
        0,
        "dedup row leaked"
    );
    assert_eq!(
        count(&conn, SQL_SIGNED_ALL, "x"),
        signed_before,
        "signed_events chain head moved"
    );
    drop(armed);

    // Disarmed, the same write commits: the hook, not the data, caused the Err.
    let _unset = EnvGuard::unset(ENV_FAIL_BEFORE_SIGNED_COMMIT);
    ai_memory::storage::capture_turn_idempotent(&conn, &write, false).expect("disarmed capture");
    assert_eq!(count(&conn, SQL_MEMORY_BY_ID, &id), 1);
    assert_eq!(count(&conn, SQL_SIGNED_ALL, "x"), signed_before + 1);
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn h1_postgres_capture_rolls_back_whole_transaction_7029() {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    let Some(env) = postgres_env::PostgresTestEnv::new("h1_7029").await else {
        eprintln!("skip: h1_postgres_capture_rolls_back_whole_transaction_7029: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let agent = "ai:fi-7029";
    let ctx = CallerContext::for_agent(agent);
    let id = uuid::Uuid::new_v4().to_string();
    let write = capture_write(&id, "fi-7029-pg-sess");

    let armed = EnvGuard::set(ENV_FAIL_BEFORE_SIGNED_COMMIT, &id);
    let result = store.capture_turn_idempotent(&ctx, &write).await;
    drop(armed);
    let err = result.expect_err("H1 armed for this id must fail the capture");
    assert!(
        format!("{err:?}").contains("injected before signed commit"),
        "unexpected error: {err:?}"
    );
    let admin = CallerContext::for_admin(agent);
    assert!(
        matches!(
            store.get(&admin, &id).await,
            Err(ai_memory::store::StoreError::NotFound { .. })
        ),
        "memories row leaked past the rollback"
    );
}

#[cfg(not(feature = "sal-postgres"))]
#[test]
fn h1_postgres_capture_rolls_back_whole_transaction_7029() {
    eprintln!(
        "skip: h1_postgres_capture_rolls_back_whole_transaction_7029: built without sal-postgres"
    );
}

#[test]
fn h2_offset_moves_now_by_exactly_the_offset_7029() {
    let _g = EnvGuard::set(ENV_CLOCK_OFFSET_SECS, "86400");
    assert_eq!(test_clock::offset_secs(), 86_400);
    let before = chrono::Utc::now();
    let skewed = test_clock::now();
    let after = chrono::Utc::now();
    let day = chrono::Duration::seconds(86_400);
    assert!(
        skewed >= before + day && skewed <= after + day,
        "skewed={skewed} before={before} after={after}"
    );
    drop(_g);

    let _g = EnvGuard::set(ENV_CLOCK_OFFSET_SECS, "-3600");
    let before = chrono::Utc::now();
    let skewed = test_clock::now();
    let after = chrono::Utc::now();
    let hour = chrono::Duration::seconds(3_600);
    assert!(skewed >= before - hour && skewed <= after - hour);
}

#[test]
fn h2_zero_unset_and_garbage_are_identity_7029() {
    for value in ["0", "", "not-a-number", "9223372036854775807"] {
        let _g = EnvGuard::set(ENV_CLOCK_OFFSET_SECS, value);
        let before = chrono::Utc::now();
        let now = test_clock::now();
        let after = chrono::Utc::now();
        // An unparseable value and an offset beyond chrono's range both
        // degrade to the real clock, never to a corrupted timestamp.
        assert!(now >= before && now <= after, "value {value:?}: {now}");
    }
    let _g = EnvGuard::unset(ENV_CLOCK_OFFSET_SECS);
    assert_eq!(test_clock::offset_secs(), 0);
    let before = chrono::Utc::now();
    let now = test_clock::now();
    let after = chrono::Utc::now();
    assert!(now >= before && now <= after);
}

#[test]
fn h2_pg_now_sql_is_identity_without_offset_and_literal_with_one_7029() {
    let _g = EnvGuard::unset(ENV_CLOCK_OFFSET_SECS);
    assert_eq!(test_clock::pg_now_sql(), "NOW()");
    drop(_g);
    let _g = EnvGuard::set(ENV_CLOCK_OFFSET_SECS, "-86400");
    assert_eq!(
        test_clock::pg_now_sql(),
        "(NOW() + INTERVAL '-86400 seconds')"
    );
}

#[test]
fn h3_mcp_pid_is_the_real_direct_child_7029() {
    let fixture = mcp_stdio_child::Fixture::new();
    let mcp = mcp_stdio_child::Mcp::start(&fixture, None);
    let pid = mcp.pid();
    assert_ne!(pid, 0, "pid must be a real process id");
    let pid_i32 = i32::try_from(pid).expect("pid fits pid_t");
    // SAFETY: signal 0 performs only the existence/permission check.
    assert_eq!(unsafe { libc::kill(pid_i32, 0) }, 0, "child must be alive");
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("proc stat");
        // Fields after the parenthesised comm: state, ppid, ...
        let after_comm = stat.rsplit_once(')').expect("comm terminator").1;
        let ppid: u32 = after_comm
            .split_whitespace()
            .nth(1)
            .expect("ppid field")
            .parse()
            .expect("ppid parses");
        assert_eq!(ppid, std::process::id(), "pid must be our direct child");
    }
}

#[test]
fn h4_quota_tablespace_reads_through_the_environment_7029() {
    let _g = EnvGuard::unset(postgres_env::ENV_PG_QUOTA_TABLESPACE);
    assert_eq!(postgres_env::quota_tablespace(), None);
    drop(_g);
    let _g = EnvGuard::set(postgres_env::ENV_PG_QUOTA_TABLESPACE, "fi_quota_ts");
    assert_eq!(postgres_env::quota_tablespace().as_deref(), Some("fi_quota_ts"));
    drop(_g);
    let _g = EnvGuard::set(postgres_env::ENV_PG_QUOTA_TABLESPACE, "  ");
    assert_eq!(
        postgres_env::quota_tablespace(),
        None,
        "blank value is unset"
    );
}
