// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Campaign X cell X5 (#7095) - the link row and its `memory_link.created`
//! audit row commit together, on both backends.
//!
//! Identical scenarios through the `MemoryStore` trait:
//!
//! * X5a a created link writes exactly one `memory_link.created` row, and a
//!   replay of the same edge writes none. Postgres wrote no row at all.
//! * X5b fail closed: when the audit append is refused the link call returns
//!   an error and no `memory_links` row remains. Sqlite logged a warning and
//!   kept the link.
//!
//! The postgres cells are `#[ignore]` and soft-skip without
//! `AI_MEMORY_TEST_POSTGRES_URL`, like every other live-postgres test.

#![cfg(feature = "sal")]

mod common;

use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

const NAMESPACE: &str = "x5/link";
const ADMIN: &str = "operator:x5";
const SOURCE_ID: &str = "x5-a-source";
const TARGET_ID: &str = "x5-b-target";
const LINK_EVENT: &str = "memory_link.created";
const FAULT_MESSAGE: &str = "x5 injected audit fault";
const TS: &str = "2026-09-01T00:00:00+00:00";

fn memory(id: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NAMESPACE.to_string(),
        title: format!("x5 {id}"),
        content: format!("x5 link audit body {id}"),
        priority: 5,
        confidence: 1.0,
        source: "x5".to_string(),
        created_at: TS.to_string(),
        updated_at: TS.to_string(),
        metadata: serde_json::json!({ "agent_id": ADMIN }),
        ..Default::default()
    }
}

fn link() -> MemoryLink {
    MemoryLink {
        source_id: SOURCE_ID.to_string(),
        target_id: TARGET_ID.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: TS.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(TS.to_string()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// What a scenario needs beyond the trait: count audit rows, count link rows,
/// refuse one audit event type.
trait Probe {
    async fn events(&self, event_type: &str) -> i64;
    async fn links(&self) -> i64;
    async fn refuse_audit(&self, event_type: &str);
}

async fn seed<S: MemoryStore>(store: &S) {
    let admin = CallerContext::for_admin(ADMIN);
    store.store(&admin, &memory(SOURCE_ID)).await.expect("src");
    store.store(&admin, &memory(TARGET_ID)).await.expect("dst");
}

/// X5a: one row per created link, none for a replay.
async fn link_writes_one_audit_row<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    let admin = CallerContext::for_admin(ADMIN);
    store.link(&admin, &link()).await.expect("link");
    assert_eq!(probe.links().await, 1, "link row");
    assert_eq!(probe.events(LINK_EVENT).await, 1, "link audit row");
    store.link(&admin, &link()).await.expect("replay");
    assert_eq!(probe.links().await, 1, "replay keeps one link");
    assert_eq!(probe.events(LINK_EVENT).await, 1, "replay writes no row");
}

/// X5b: a refused audit append fails the call and leaves no link.
async fn link_audit_fault_rolls_back<S: MemoryStore, P: Probe>(store: &S, probe: &P) {
    seed(store).await;
    probe.refuse_audit(LINK_EVENT).await;
    store
        .link(&CallerContext::for_admin(ADMIN), &link())
        .await
        .expect_err("link must fail when its audit row is refused");
    assert_eq!(probe.links().await, 0, "no link without its audit");
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

    async fn links(&self) -> i64 {
        self.raw()
            .query_row("SELECT COUNT(*) FROM memory_links", [], |r| r.get(0))
            .expect("links")
    }

    async fn refuse_audit(&self, event_type: &str) {
        self.raw()
            .execute_batch(&format!(
                "CREATE TRIGGER x5_fault BEFORE INSERT ON signed_events \
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
async fn sqlite_link_writes_one_audit_row_7095() {
    let (_dir, store, probe) = open_sqlite("x5a.db");
    link_writes_one_audit_row(&store, &probe).await;
}

#[tokio::test]
async fn sqlite_link_audit_fault_rolls_back_7095() {
    let (_dir, store, probe) = open_sqlite("x5b.db");
    link_audit_fault_rolls_back(&store, &probe).await;
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

        async fn links(&self) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM memory_links")
                .fetch_one(&self.pool)
                .await
                .expect("links")
        }

        async fn refuse_audit(&self, event_type: &str) {
            sqlx::query(&format!(
                "CREATE FUNCTION x5_fault() RETURNS trigger LANGUAGE plpgsql AS \
                 $$ BEGIN IF NEW.event_type = '{event_type}' THEN \
                 RAISE EXCEPTION '{FAULT_MESSAGE}'; END IF; RETURN NEW; END $$"
            ))
            .execute(&self.pool)
            .await
            .expect("fn");
            sqlx::query(
                "CREATE TRIGGER x5_fault BEFORE INSERT ON signed_events FOR EACH ROW \
                 EXECUTE FUNCTION x5_fault()",
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
    async fn postgres_link_writes_one_audit_row_7095() {
        let Some((_env, store, probe)) = open_pg("x5_a").await else {
            return;
        };
        link_writes_one_audit_row(&store, &probe).await;
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
    async fn postgres_link_audit_fault_rolls_back_7095() {
        let Some((_env, store, probe)) = open_pg("x5_b").await else {
            return;
        };
        link_audit_fault_rolls_back(&store, &probe).await;
    }
}
