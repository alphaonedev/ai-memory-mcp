// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Campaign X cell X3 (#7093) - a vertical promotion is atomic on both
//! backends: the clone and its `derived_from` link commit together.
//!
//! Identical scenarios through `MemoryStore::execute_pending_action` with an
//! approved vertical-promote pending row:
//!
//! * X3a the promotion lands one clone in the destination namespace and one
//!   `derived_from` link from the clone to the source.
//! * X3b when the link insert is refused the call fails and NO clone is left
//!   in the destination namespace. Before the fix the clone was inserted
//!   first and the link ran separately, so a link failure left an orphan
//!   clone (sqlite: two autocommit statements; postgres: two transactions).
//!
//! The postgres cells are `#[ignore]` and soft-skip without
//! `AI_MEMORY_TEST_POSTGRES_URL`, like every other live-postgres test.

#![cfg(feature = "sal")]

mod common;

use std::path::PathBuf;

use ai_memory::models::field_names;
use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

const PARENT_NS: &str = "x3-promote";
const CHILD_NS: &str = "x3-promote/child";
const REQUESTER: &str = "ai:x3-promoter";
const SOURCE_ID: &str = "x3-source";
const PENDING_ID: &str = "x3-pending";
const ACTION_STORE: &str = "store";
const FAULT_MESSAGE: &str = "x3 injected link fault";
const TS: &str = "2026-09-01T00:00:00+00:00";

fn ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent(REQUESTER);
    ctx.bypass_visibility = true;
    ctx
}

fn source() -> Memory {
    Memory {
        id: SOURCE_ID.to_string(),
        tier: Tier::Mid,
        namespace: CHILD_NS.to_string(),
        title: "x3 promote me".to_string(),
        content: "x3 promotion body".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "x3".to_string(),
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        metadata: serde_json::json!({ "agent_id": REQUESTER }),
        ..Default::default()
    }
}

fn payload() -> serde_json::Value {
    serde_json::json!({
        (field_names::MODE): field_names::MODE_VERTICAL,
        "id": SOURCE_ID,
        (field_names::TO_NAMESPACE): PARENT_NS,
    })
}

/// What a scenario needs beyond the trait: queue the approved pending row,
/// count destination rows and links, refuse every link insert.
trait Probe {
    async fn queue_pending(&self);
    async fn destination_rows(&self) -> i64;
    async fn derived_links(&self) -> i64;
    async fn refuse_links(&self);
}

/// X3a: one clone, one `derived_from` link.
async fn promotion_lands_clone_and_link<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    store.store(&ctx(), &source()).await.expect("seed");
    probe.queue_pending().await;
    let clone_id = store
        .execute_pending_action(&ctx(), PENDING_ID)
        .await
        .expect("promote")
        .expect("clone id");
    assert_ne!(clone_id, SOURCE_ID);
    assert_eq!(probe.destination_rows().await, 1, "one clone");
    assert_eq!(probe.derived_links().await, 1, "one derived_from link");
}

/// X3b: a refused link insert leaves no clone behind.
async fn link_fault_leaves_no_orphan_clone<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    store.store(&ctx(), &source()).await.expect("seed");
    probe.queue_pending().await;
    probe.refuse_links().await;
    store
        .execute_pending_action(&ctx(), PENDING_ID)
        .await
        .expect_err("promotion must fail when its link is refused");
    assert_eq!(
        probe.destination_rows().await,
        0,
        "no orphan clone without its provenance link"
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
    async fn queue_pending(&self) {
        self.raw()
            .execute(
                "INSERT INTO pending_actions \
                 (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'approved')",
                rusqlite::params![
                    PENDING_ID,
                    ACTION_STORE,
                    SOURCE_ID,
                    CHILD_NS,
                    payload().to_string(),
                    REQUESTER,
                    TS
                ],
            )
            .expect("queue pending");
    }

    async fn destination_rows(&self) -> i64 {
        self.raw()
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
                [PARENT_NS],
                |r| r.get(0),
            )
            .expect("count")
    }

    async fn derived_links(&self) -> i64 {
        self.raw()
            .query_row(
                "SELECT COUNT(*) FROM memory_links WHERE relation = 'derived_from'",
                [],
                |r| r.get(0),
            )
            .expect("links")
    }

    async fn refuse_links(&self) {
        self.raw()
            .execute_batch(&format!(
                "CREATE TRIGGER x3_fault BEFORE INSERT ON memory_links \
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
async fn sqlite_promotion_lands_clone_and_link_7093() {
    let (_dir, store, probe) = open_sqlite("x3a.db");
    promotion_lands_clone_and_link(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_promotion_link_fault_leaves_no_orphan_clone_7093() {
    let (_dir, store, probe) = open_sqlite("x3b.db");
    link_fault_leaves_no_orphan_clone(&store, &probe).await;
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use ai_memory::store::postgres::PostgresStore;

    use super::*;

    struct PgProbe {
        pool: sqlx::PgPool,
    }

    impl Probe for PgProbe {
        async fn queue_pending(&self) {
            sqlx::query(
                "INSERT INTO pending_actions \
                 (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'approved')",
            )
            .bind(PENDING_ID)
            .bind(ACTION_STORE)
            .bind(SOURCE_ID)
            .bind(CHILD_NS)
            .bind(payload())
            .bind(REQUESTER)
            .bind(chrono::Utc::now())
            .execute(&self.pool)
            .await
            .expect("queue pending");
        }

        async fn destination_rows(&self) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE namespace = $1")
                .bind(PARENT_NS)
                .fetch_one(&self.pool)
                .await
                .expect("count")
        }

        async fn derived_links(&self) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM memory_links WHERE relation = 'derived_from'")
                .fetch_one(&self.pool)
                .await
                .expect("links")
        }

        async fn refuse_links(&self) {
            sqlx::query(&format!(
                "CREATE FUNCTION x3_fault() RETURNS trigger LANGUAGE plpgsql AS \
                 $$ BEGIN RAISE EXCEPTION '{FAULT_MESSAGE}'; END $$"
            ))
            .execute(&self.pool)
            .await
            .expect("fn");
            sqlx::query(
                "CREATE TRIGGER x3_fault BEFORE INSERT ON memory_links FOR EACH ROW \
                 EXECUTE FUNCTION x3_fault()",
            )
            .execute(&self.pool)
            .await
            .expect("trigger");
        }
    }

    async fn open_pg(
        name: &str,
    ) -> Option<(
        common::postgres_env::PostgresTestEnv,
        PostgresStore,
        PgProbe,
    )> {
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
    async fn postgres_promotion_lands_clone_and_link_7093() {
        let Some((_env, store, probe)) = open_pg("x3_a").await else {
            return;
        };
        promotion_lands_clone_and_link(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_promotion_link_fault_leaves_no_orphan_clone_7093() {
        let Some((_env, store, probe)) = open_pg("x3_b").await else {
            return;
        };
        link_fault_leaves_no_orphan_clone(&store, &probe).await;
    }
}
