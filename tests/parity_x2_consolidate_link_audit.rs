// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! campaign:X cell X2a/b — the `memory_link.created` audit of the consolidate
//! tombstone path, on the sqlite and postgres adapters.
//!
//! - #7092: the sqlite tombstone path appended the audit through
//!   `append_signed_event`, which opens its own `BEGIN IMMEDIATE` inside the
//!   consolidate `WriteTxn`; the nested BEGIN failed and the failure was
//!   warn-dropped, so a consolidated edge had NO audit row. Postgres wrote
//!   the edge without any audit row at all. Both backends must append one
//!   `memory_link.created` row per new `derived_from` edge, atomically in
//!   the consolidate transaction, and an audit-append failure must abort the
//!   whole cluster (fail closed) instead of committing an unaudited edge.
//!
//! The postgres cells connect to the shared test database named by
//! `AI_MEMORY_TEST_POSTGRES_URL` and skip cleanly without it. Every cell in
//! this binary takes `SERIAL` so the shared `signed_events` table is only
//! written by one cell at a time (the fault cell installs a trigger that
//! would refuse another cell's audit row).

use std::path::Path;

use ai_memory::models::{Memory, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use serde_json::json;

const OWNER: &str = "ai:owner-x2-audit";
const LINK_CREATED: &str = "memory_link.created";

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn unique_ns(cell: &str) -> String {
    format!("parity-x2a-{cell}-{}", uuid::Uuid::new_v4().simple())
}

fn row(ns: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("content of {title}"),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": OWNER }),
        ..Default::default()
    }
}

/// Every cell wants the tombstone path on; the flags are process-wide and
/// never reset.
fn enable_tombstone_path() {
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    ai_memory::config::set_append_only(false);
}

async fn titles_in_ns(store: &dyn MemoryStore, ctx: &CallerContext, ns: &str) -> Vec<String> {
    let mut filter = Filter::new();
    filter.namespace = Some(ns.to_string());
    // `Filter::new()` carries limit 0, which both adapters clamp to ONE row.
    filter.limit = 100;
    let mut titles: Vec<String> = store
        .list(ctx, &filter)
        .await
        .expect("list")
        .into_iter()
        .map(|m| m.title)
        .collect();
    titles.sort();
    titles
}

/// Backend hooks the shared scenarios need beyond the `MemoryStore` trait.
trait AuditProbe {
    /// Number of `memory_link.created` rows in `signed_events` right now.
    async fn link_created_count(&self) -> i64;
    /// Make every future `memory_link.created` append fail.
    async fn install_audit_fault(&self);
    /// Remove the fault again.
    async fn remove_audit_fault(&self);
}

/// #7092 scenario A: consolidating two visible sources on the tombstone path
/// writes two `derived_from` edges and exactly two `memory_link.created`
/// audit rows.
async fn consolidate_audits_every_edge(store: &dyn MemoryStore, probe: &impl AuditProbe) {
    enable_tombstone_path();
    let ns = unique_ns("audit");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a audit");
    let b = row(&ns, "b audit");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    let before = probe.link_created_count().await;
    store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "summary audit",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await
        .expect("a visible cluster consolidates");
    let after = probe.link_created_count().await;
    assert_eq!(
        after - before,
        2,
        "#7092: one memory_link.created audit row per consolidated edge"
    );
}

/// #7092 scenario B: when the audit append fails the consolidate fails
/// closed. No summary row, and both sources stay visible.
async fn audit_failure_aborts_cluster(store: &dyn MemoryStore, probe: &impl AuditProbe) {
    enable_tombstone_path();
    let ns = unique_ns("fault");
    let ctx = CallerContext::for_agent(OWNER.to_string());
    let a = row(&ns, "a fault");
    let b = row(&ns, "b fault");
    store.store(&ctx, &a).await.expect("seed a");
    store.store(&ctx, &b).await.expect("seed b");
    probe.install_audit_fault().await;
    let result = store
        .consolidate(
            &ctx,
            &[a.id.clone(), b.id.clone()],
            "summary fault",
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            OWNER,
        )
        .await;
    probe.remove_audit_fault().await;
    assert!(
        result.is_err(),
        "#7092: an audit-append failure must refuse the cluster, got {result:?}"
    );
    assert_eq!(
        titles_in_ns(store, &ctx, &ns).await,
        vec!["a fault".to_string(), "b fault".to_string()],
        "#7092: the refused cluster wrote no summary and tombstoned no source"
    );
}

struct SqliteProbe<'a> {
    path: &'a Path,
}

impl SqliteProbe<'_> {
    fn conn(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.path).expect("open probe connection");
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .expect("busy timeout");
        conn
    }
}

impl AuditProbe for SqliteProbe<'_> {
    async fn link_created_count(&self) -> i64 {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                [LINK_CREATED],
                |r| r.get(0),
            )
            .expect("count audit rows")
    }

    async fn install_audit_fault(&self) {
        self.conn()
            .execute_batch(
                "CREATE TRIGGER x7092_audit_fault BEFORE INSERT ON signed_events \
                 WHEN NEW.event_type = 'memory_link.created' \
                 BEGIN SELECT RAISE(ABORT, 'x7092 injected audit fault'); END;",
            )
            .expect("install fault trigger");
    }

    async fn remove_audit_fault(&self) {
        self.conn()
            .execute_batch("DROP TRIGGER IF EXISTS x7092_audit_fault;")
            .expect("drop fault trigger");
    }
}

fn sqlite_store() -> (tempfile::TempDir, SqliteStore, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x2a.db");
    let store = SqliteStore::open(&path).expect("open sqlite store");
    (dir, store, path)
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_audits_every_edge_7092() {
    let _serial = SERIAL.lock().await;
    let (_dir, store, path) = sqlite_store();
    consolidate_audits_every_edge(&store, &SqliteProbe { path: &path }).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_consolidate_audit_failure_aborts_cluster_7092() {
    let _serial = SERIAL.lock().await;
    let (_dir, store, path) = sqlite_store();
    audit_failure_aborts_cluster(&store, &SqliteProbe { path: &path }).await;
}

#[cfg(feature = "sal-postgres")]
struct PgProbe {
    pool: sqlx::PgPool,
}

#[cfg(feature = "sal-postgres")]
impl AuditProbe for PgProbe {
    async fn link_created_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
            .bind(LINK_CREATED)
            .fetch_one(&self.pool)
            .await
            .expect("count audit rows")
    }

    async fn install_audit_fault(&self) {
        sqlx::query(
            "CREATE OR REPLACE FUNCTION x7092_audit_fault() RETURNS trigger AS \
             'BEGIN RAISE EXCEPTION ''x7092 injected audit fault''; END;' \
             LANGUAGE plpgsql",
        )
        .execute(&self.pool)
        .await
        .expect("install fault function");
        sqlx::query("DROP TRIGGER IF EXISTS x7092_audit_fault ON signed_events")
            .execute(&self.pool)
            .await
            .expect("clear stale trigger");
        sqlx::query(
            "CREATE TRIGGER x7092_audit_fault BEFORE INSERT ON signed_events \
             FOR EACH ROW WHEN (NEW.event_type = 'memory_link.created') \
             EXECUTE FUNCTION x7092_audit_fault()",
        )
        .execute(&self.pool)
        .await
        .expect("install fault trigger");
    }

    async fn remove_audit_fault(&self) {
        sqlx::query("DROP TRIGGER IF EXISTS x7092_audit_fault ON signed_events")
            .execute(&self.pool)
            .await
            .expect("drop fault trigger");
    }
}

#[cfg(feature = "sal-postgres")]
async fn pg_parts() -> Option<(ai_memory::store::postgres::PostgresStore, PgProbe)> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect probe pool");
    Some((store, PgProbe { pool }))
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_audits_every_edge_7092() {
    let _serial = SERIAL.lock().await;
    let Some((store, probe)) = pg_parts().await else {
        return;
    };
    consolidate_audits_every_edge(&store, &probe).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_consolidate_audit_failure_aborts_cluster_7092() {
    let _serial = SERIAL.lock().await;
    let Some((store, probe)) = pg_parts().await else {
        return;
    };
    audit_failure_aborts_cluster(&store, &probe).await;
}
