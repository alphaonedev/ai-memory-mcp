// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Campaign X cell X8 (#7098) - lease audit parity at the SAL layer.
//!
//! Identical scenarios on both backends, driven through the `MemoryStore`
//! trait (no MCP handler in the path):
//!
//! * X8a every lease mutation (`acquire`, `renew`, `release`) writes exactly
//!   one coordination `signed_events` row. Before the fix sqlite wrote them
//!   only from the MCP handler and postgres never wrote them.
//! * X8b the sweep writes its reclaim row inside the sweep transaction.
//! * X8c fail closed: when the audit append is refused, the lease mutation
//!   rolls back and the call returns an error (acquire, renew, release,
//!   sweep). Before the fix the audit was best-effort after the commit.
//!
//! The postgres cells are `#[ignore]` and soft-skip without
//! `AI_MEMORY_TEST_POSTGRES_URL`, like every other live-postgres test.

#![cfg(feature = "sal")]

mod common;

use std::path::PathBuf;

use ai_memory::coordination_audit::{
    ACTION_LEASE_EXPIRE_REQUEUE, LEASE_ACQUIRE, LEASE_RELEASE, LEASE_RENEW, LEASE_SWEEP_RECLAIM,
};
use ai_memory::models::{Action, ActionState};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

const ACTION_ID: &str = "x8-action";
const HOLDER: &str = "ai:x8-holder";
const CALLER: &str = "ai:x8-caller";
const NAMESPACE: &str = "x8/lease";
const ACQUIRED_AT: i64 = 1_000;
const LEASE_TTL_SECS: i64 = 100;
const RENEWED_AT: i64 = 1_050;
const RENEWED_EXPIRY: i64 = 1_300;
const SWEEP_AT: i64 = 5_000;
const FAULT_MESSAGE: &str = "x8 injected audit fault";
const ACTION_CREATED_AT: i64 = 900;
const ACTION_PRIORITY: i64 = 5;

fn action() -> Action {
    Action {
        id: ACTION_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        kind: "x8.lease".to_string(),
        state: ActionState::Pending,
        title: "x8 lease audit target".to_string(),
        payload: serde_json::json!({}),
        priority: ACTION_PRIORITY,
        agent_id: Some(CALLER.to_string()),
        claimed_by: None,
        vector_clock: serde_json::json!({}),
        metadata: serde_json::json!({}),
        created_at: ACTION_CREATED_AT,
        updated_at: ACTION_CREATED_AT,
    }
}

/// What a scenario needs from a backend beyond the `MemoryStore` trait: read
/// the audit table, read the lease row, and refuse one audit event type.
trait Probe {
    async fn events(&self, event_type: &str) -> i64;
    async fn lease_expiry(&self) -> Option<i64>;
    async fn refuse_audit(&self, event_type: &str);
}

async fn seed<S: MemoryStore>(store: &S) {
    store
        .action_create(&CallerContext::for_agent(CALLER), &action())
        .await
        .expect("action_create");
}

/// X8a: acquire, renew and release each write exactly one row.
async fn voluntary_ops_write_one_row_each<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let ctx = CallerContext::for_agent(CALLER);
    store
        .lease_acquire(&ctx, ACTION_ID, HOLDER, ACQUIRED_AT, ACQUIRED_AT + LEASE_TTL_SECS)
        .await
        .expect("acquire");
    assert_eq!(probe.events(LEASE_ACQUIRE).await, 1, "acquire audit row");
    store
        .lease_renew(&ctx, ACTION_ID, HOLDER, RENEWED_AT, RENEWED_EXPIRY)
        .await
        .expect("renew");
    assert_eq!(probe.events(LEASE_RENEW).await, 1, "renew audit row");
    assert!(
        store
            .lease_release(&ctx, ACTION_ID, HOLDER)
            .await
            .expect("release")
    );
    assert_eq!(probe.events(LEASE_RELEASE).await, 1, "release audit row");
    // A release that removes nothing writes nothing.
    assert!(
        !store
            .lease_release(&ctx, ACTION_ID, HOLDER)
            .await
            .expect("second release")
    );
    assert_eq!(probe.events(LEASE_RELEASE).await, 1, "no-op release: no row");
}

/// X8b: the sweep writes a reclaim row for the lease it removed.
async fn sweep_writes_reclaim_row<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let ctx = CallerContext::for_agent(CALLER);
    store
        .lease_acquire(&ctx, ACTION_ID, HOLDER, ACQUIRED_AT, ACQUIRED_AT + 1)
        .await
        .expect("acquire");
    assert_eq!(store.lease_sweep_expired(SWEEP_AT).await.expect("sweep"), 1);
    assert_eq!(probe.events(LEASE_SWEEP_RECLAIM).await, 1, "reclaim row");
    assert_eq!(
        probe.events(ACTION_LEASE_EXPIRE_REQUEUE).await,
        0,
        "a pending action is not requeued"
    );
}

/// X8c: a refused acquire audit leaves no lease.
async fn acquire_audit_fault_rolls_back<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    probe.refuse_audit(LEASE_ACQUIRE).await;
    store
        .lease_acquire(
            &CallerContext::for_agent(CALLER),
            ACTION_ID,
            HOLDER,
            ACQUIRED_AT,
            ACQUIRED_AT + LEASE_TTL_SECS,
        )
        .await
        .expect_err("acquire must fail when its audit row is refused");
    assert_eq!(probe.lease_expiry().await, None, "no lease without its audit");
}

/// X8c: a refused renew audit leaves the old expiry.
async fn renew_audit_fault_rolls_back<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let ctx = CallerContext::for_agent(CALLER);
    let first_expiry = ACQUIRED_AT + LEASE_TTL_SECS;
    store
        .lease_acquire(&ctx, ACTION_ID, HOLDER, ACQUIRED_AT, first_expiry)
        .await
        .expect("acquire");
    probe.refuse_audit(LEASE_RENEW).await;
    store
        .lease_renew(&ctx, ACTION_ID, HOLDER, RENEWED_AT, RENEWED_EXPIRY)
        .await
        .expect_err("renew must fail when its audit row is refused");
    assert_eq!(
        probe.lease_expiry().await,
        Some(first_expiry),
        "renew rolled back with its audit"
    );
}

/// X8c: a refused release audit keeps the lease.
async fn release_audit_fault_rolls_back<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let ctx = CallerContext::for_agent(CALLER);
    store
        .lease_acquire(&ctx, ACTION_ID, HOLDER, ACQUIRED_AT, ACQUIRED_AT + LEASE_TTL_SECS)
        .await
        .expect("acquire");
    probe.refuse_audit(LEASE_RELEASE).await;
    store
        .lease_release(&ctx, ACTION_ID, HOLDER)
        .await
        .expect_err("release must fail when its audit row is refused");
    assert!(
        probe.lease_expiry().await.is_some(),
        "release rolled back with its audit"
    );
}

/// X8c: a refused sweep audit keeps the expired lease for the next sweep.
async fn sweep_audit_fault_rolls_back<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let ctx = CallerContext::for_agent(CALLER);
    store
        .lease_acquire(&ctx, ACTION_ID, HOLDER, ACQUIRED_AT, ACQUIRED_AT + 1)
        .await
        .expect("acquire");
    probe.refuse_audit(LEASE_SWEEP_RECLAIM).await;
    store
        .lease_sweep_expired(SWEEP_AT)
        .await
        .expect_err("sweep must fail when its audit row is refused");
    assert!(
        probe.lease_expiry().await.is_some(),
        "the sweep rolled back with its audit"
    );
}

struct SqliteProbe {
    db_path: PathBuf,
}

impl SqliteProbe {
    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db_path).expect("raw")
    }
}

impl Probe for SqliteProbe {
    async fn events(&self, event_type: &str) -> i64 {
        self.raw()
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                [event_type],
                |r| r.get(0),
            )
            .expect("count")
    }

    async fn lease_expiry(&self) -> Option<i64> {
        self.raw()
            .query_row(
                "SELECT expires_at FROM leases WHERE action_id = ?1",
                [ACTION_ID],
                |r| r.get(0),
            )
            .ok()
    }

    async fn refuse_audit(&self, event_type: &str) {
        self.raw()
            .execute_batch(&format!(
                "CREATE TRIGGER x8_fault BEFORE INSERT ON signed_events \
                 WHEN NEW.event_type = '{event_type}' \
                 BEGIN SELECT RAISE(ABORT, '{FAULT_MESSAGE}'); END;"
            ))
            .expect("trigger");
    }
}

fn open_sqlite(name: &str) -> (tempfile::TempDir, SqliteStore, SqliteProbe) {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join(name);
    let store = SqliteStore::open(&db_path).expect("open");
    (dir, store, SqliteProbe { db_path })
}

#[tokio::test]
async fn sqlite_lease_voluntary_ops_write_one_audit_row_each_7098() {
    let (_dir, store, probe) = open_sqlite("x8a.db");
    voluntary_ops_write_one_row_each(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_lease_sweep_writes_reclaim_row_7098() {
    let (_dir, store, probe) = open_sqlite("x8b.db");
    sweep_writes_reclaim_row(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_lease_acquire_audit_fault_rolls_back_7098() {
    let (_dir, store, probe) = open_sqlite("x8c1.db");
    acquire_audit_fault_rolls_back(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_lease_renew_audit_fault_rolls_back_7098() {
    let (_dir, store, probe) = open_sqlite("x8c2.db");
    renew_audit_fault_rolls_back(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_lease_release_audit_fault_rolls_back_7098() {
    let (_dir, store, probe) = open_sqlite("x8c3.db");
    release_audit_fault_rolls_back(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_lease_sweep_audit_fault_rolls_back_7098() {
    let (_dir, store, probe) = open_sqlite("x8c4.db");
    sweep_audit_fault_rolls_back(&store, &probe).await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use ai_memory::store::postgres::PostgresStore;

    use super::*;

    struct PgProbe {
        pool: sqlx::PgPool,
    }

    impl Probe for PgProbe {
        async fn events(&self, event_type: &str) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
                .bind(event_type)
                .fetch_one(&self.pool)
                .await
                .expect("count")
        }

        async fn lease_expiry(&self) -> Option<i64> {
            sqlx::query_scalar("SELECT expires_at FROM leases WHERE action_id = $1")
                .bind(ACTION_ID)
                .fetch_optional(&self.pool)
                .await
                .expect("lease")
        }

        async fn refuse_audit(&self, event_type: &str) {
            sqlx::query(&format!(
                "CREATE FUNCTION x8_fault() RETURNS trigger LANGUAGE plpgsql AS \
                 $$ BEGIN IF NEW.event_type = '{event_type}' THEN \
                 RAISE EXCEPTION '{FAULT_MESSAGE}'; END IF; RETURN NEW; END $$"
            ))
            .execute(&self.pool)
            .await
            .expect("fn");
            sqlx::query(
                "CREATE TRIGGER x8_fault BEFORE INSERT ON signed_events FOR EACH ROW \
                 EXECUTE FUNCTION x8_fault()",
            )
            .execute(&self.pool)
            .await
            .expect("trigger");
        }
    }

    async fn open_pg(
        name: &str,
    ) -> Option<(common::postgres_env::PostgresTestEnv, PostgresStore, PgProbe)> {
        common::permissive_attestation_for_tests();
        let Some(env) = common::postgres_env::PostgresTestEnv::new(name).await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        let store = PostgresStore::connect(env.url()).await.expect("connect");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(env.url())
            .await
            .expect("inspection pool");
        Some((env, store, PgProbe { pool }))
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_voluntary_ops_write_one_audit_row_each_7098() {
        let Some((_env, store, probe)) = open_pg("x8_a").await else {
            return;
        };
        voluntary_ops_write_one_row_each(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_sweep_writes_reclaim_row_7098() {
        let Some((_env, store, probe)) = open_pg("x8_b").await else {
            return;
        };
        sweep_writes_reclaim_row(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_acquire_audit_fault_rolls_back_7098() {
        let Some((_env, store, probe)) = open_pg("x8_c1").await else {
            return;
        };
        acquire_audit_fault_rolls_back(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_renew_audit_fault_rolls_back_7098() {
        let Some((_env, store, probe)) = open_pg("x8_c2").await else {
            return;
        };
        renew_audit_fault_rolls_back(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_release_audit_fault_rolls_back_7098() {
        let Some((_env, store, probe)) = open_pg("x8_c3").await else {
            return;
        };
        release_audit_fault_rolls_back(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_lease_sweep_audit_fault_rolls_back_7098() {
        let Some((_env, store, probe)) = open_pg("x8_c4").await else {
            return;
        };
        sweep_audit_fault_rolls_back(&store, &probe).await;
    }
}
