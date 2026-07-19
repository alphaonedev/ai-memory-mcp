// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown)]

//! #1783 (5-agent vote 4d3ea1c5) — AGE projection must be removed on a
//! memory hard-delete so `kg_query`/`find_paths` over the AGE backend
//! don't return ghost edges to a row that no longer exists relationally.
//!
//! Postgres+AGE only. Gated on `AI_MEMORY_TEST_AGE_URL` (fallback
//! `AI_MEMORY_TEST_POSTGRES_URL`) AND the resolved `kg_backend == Age`;
//! prints a skip line + returns cleanly otherwise, so the default
//! `cargo test` (and plain-postgres / SQLite-only contributors) are
//! unaffected. Runs in CI's coverage job (the only lane with the AGE
//! extension installed + the URL set); ci.yml's pgvector-only
//! Postgres-gate self-skips.
//!
//! Coverage:
//!   * `delete` removes the `(:Memory {id})` node + its incident edges,
//!     while a neighbour node + its other edges survive (DETACH DELETE
//!     semantics).
//!   * `forget` (predicate delete, in-tx unprojection) leaves no ghost.
//!   * deferred mode: the cold drainer's existence-guard SKIPS a link
//!     whose memory was hard-deleted between enqueue and drain, so a
//!     pending ADD can never RESURRECT a node the delete removed.

use std::sync::OnceLock;

use ai_memory::config::{AgeProjectionMode, set_age_projection_mode};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};
use sqlx::Row;

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

/// Serialises the tests in THIS binary: the deferred test flips the
/// process-wide `AgeProjectionMode` global, which would otherwise leak
/// into a concurrently-running sync test. (CI runs `--test-threads=1`,
/// but this keeps a local parallel run honest too.)
fn age_mode_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Stable caller id, stamped into every seeded memory's
/// `metadata.agent_id` so the SAL caller-owns gate (`delete` /
/// `assert_caller_owns_for_mutation`) treats the tenant as the owner
/// and permits the delete — without this stamp a tenant delete of an
/// unowned row is refused with `PermissionDenied`.
const TEST_AGENT: &str = "t-4d-1783";

fn mk_memory(namespace: &str, title: &str, now: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "x".to_string(),
        created_at: now.to_string(),
        updated_at: now.to_string(),
        metadata: serde_json::json!({ "agent_id": TEST_AGENT }),
        ..Memory::default()
    }
}

fn mk_link(source_id: &str, target_id: &str, now: &str) -> MemoryLink {
    MemoryLink {
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: now.to_string(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// sqlx wrapper decoding a raw `agtype` scalar off the Postgres wire.
/// Mirrors the private production-side `Agtype` (and the g4 test copy):
/// AGE prefixes the JSON payload with a 1-byte version (0x01).
struct Agtype(String);

impl sqlx::Type<sqlx::Postgres> for Agtype {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("agtype")
    }
    fn compatible(_ty: &sqlx::postgres::PgTypeInfo) -> bool {
        true
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Agtype {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = value.as_bytes()?;
        let payload = if bytes.first() == Some(&1) {
            &bytes[1..]
        } else {
            bytes
        };
        Ok(Agtype(String::from_utf8(payload.to_vec())?))
    }
}

/// Run a `RETURN count(...)`-shaped Cypher body against `memory_graph`
/// and decode the bare agtype integer. The `body` MUST `RETURN`
/// exactly one integer-typed column aliased into the `(c agtype)` slot.
async fn cypher_count(url: &str, body: &str) -> i64 {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("pool");
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("LOAD 'age'")
        .execute(&mut *conn)
        .await
        .expect("load age");
    sqlx::query("SET search_path = ag_catalog, \"$user\", public")
        .execute(&mut *conn)
        .await
        .expect("set search_path");
    let sql = format!("SELECT c FROM cypher('memory_graph', $$ {body} $$) AS (c agtype)");
    let row = sqlx::query(&sql)
        .fetch_one(&mut *conn)
        .await
        .expect("count");
    let raw: Agtype = row.try_get("c").expect("read count");
    raw.0.trim().parse::<i64>().expect("parse count")
}

/// Count of `(:Memory {id})` nodes (0 or 1). Ids are UUIDs ([0-9a-f-]),
/// safe to inline into the single-quoted agtype string literal.
async fn age_node_count(url: &str, id: &str) -> i64 {
    cypher_count(
        url,
        &format!("MATCH (n:Memory {{id: '{id}'}}) RETURN count(n)"),
    )
    .await
}

/// Count of edges incident to `(:Memory {id})` in either direction.
async fn age_incident_edge_count(url: &str, id: &str) -> i64 {
    cypher_count(
        url,
        &format!("MATCH (n:Memory {{id: '{id}'}})-[r]-() RETURN count(r)"),
    )
    .await
}

async fn connect_age_or_skip(url: &str, test: &str) -> Option<PostgresStore> {
    let store = PostgresStore::connect(url)
        .await
        .expect("connect postgres adapter");
    if store.kg_backend() != KgBackend::Age {
        eprintln!("skipping {test}: postgres backend is not AGE (no graph projection)");
        return None;
    }
    Some(store)
}

/// SYNC mode (default): hard-deleting a linked memory must DETACH DELETE
/// its `:Memory` node + every incident edge, while a neighbour node and
/// its OTHER edges survive (no collateral removal).
#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_age_node_and_incident_edges_neighbour_survives_1783() {
    let _g = age_mode_lock().lock().await;
    let test = "delete_removes_age_node_and_incident_edges_neighbour_survives_1783";
    let Some(url) = pg_url() else {
        eprintln!("skipping {test}: AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL not set");
        return;
    };
    let Some(store) = connect_age_or_skip(&url, test).await else {
        return;
    };
    set_age_projection_mode(AgeProjectionMode::Sync);

    let ctx = CallerContext::for_agent(TEST_AGENT.to_string());
    let ns = format!("t4d-1783-del-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    // Chain A→B→C — three nodes, two edges, all projected inline (sync).
    let a = mk_memory(&ns, "a", &now);
    let b = mk_memory(&ns, "b", &now);
    let c = mk_memory(&ns, "c", &now);
    let a_id = store.store(&ctx, &a).await.expect("store a");
    let b_id = store.store(&ctx, &b).await.expect("store b");
    let c_id = store.store(&ctx, &c).await.expect("store c");
    store
        .link(&ctx, &mk_link(&a_id, &b_id, &now))
        .await
        .expect("link a->b");
    store
        .link(&ctx, &mk_link(&b_id, &c_id, &now))
        .await
        .expect("link b->c");

    // Pre-delete: A is projected with one incident edge (A-B); B has two
    // (A-B, B-C).
    assert_eq!(age_node_count(&url, &a_id).await, 1, "A node projected");
    assert_eq!(age_incident_edge_count(&url, &a_id).await, 1, "A has A-B");
    assert_eq!(
        age_incident_edge_count(&url, &b_id).await,
        2,
        "B has A-B + B-C"
    );

    // Hard-delete A.
    store.delete(&ctx, &a_id).await.expect("delete a");

    // The defect: pre-fix A's node + the A-B edge would persist (ghost).
    assert_eq!(
        age_node_count(&url, &a_id).await,
        0,
        "#1783: A's :Memory node must be DETACH DELETEd on hard-delete"
    );
    assert_eq!(
        age_incident_edge_count(&url, &a_id).await,
        0,
        "#1783: the A-B ghost edge must be gone after deleting A"
    );

    // Neighbour survival: B still exists and keeps its OTHER edge (B-C);
    // C is untouched. DETACH DELETE removed only A + edges touching A.
    assert_eq!(
        age_node_count(&url, &b_id).await,
        1,
        "neighbour B must survive A's deletion"
    );
    assert_eq!(
        age_incident_edge_count(&url, &b_id).await,
        1,
        "B keeps its surviving B-C edge after A's deletion"
    );
    assert_eq!(age_node_count(&url, &c_id).await, 1, "C untouched");

    // find_paths from the deleted source returns nothing (relational truth).
    let paths = store
        .find_paths(&a_id, &c_id, Some(4), Some(10))
        .await
        .expect("find_paths post-delete");
    assert!(paths.is_empty(), "no path from a deleted source");
}

/// `forget` (predicate delete, in-tx unprojection) must also clear the
/// AGE projection for every matched memory.
#[tokio::test(flavor = "multi_thread")]
async fn forget_removes_age_projection_1783() {
    let _g = age_mode_lock().lock().await;
    let test = "forget_removes_age_projection_1783";
    let Some(url) = pg_url() else {
        eprintln!("skipping {test}: AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL not set");
        return;
    };
    let Some(store) = connect_age_or_skip(&url, test).await else {
        return;
    };
    set_age_projection_mode(AgeProjectionMode::Sync);

    let ctx = CallerContext::for_agent(TEST_AGENT.to_string());
    let ns = format!("t4d-1783-forget-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    let d = mk_memory(&ns, "d", &now);
    let e = mk_memory(&ns, "e", &now);
    let d_id = store.store(&ctx, &d).await.expect("store d");
    let e_id = store.store(&ctx, &e).await.expect("store e");
    store
        .link(&ctx, &mk_link(&d_id, &e_id, &now))
        .await
        .expect("link d->e");
    assert_eq!(age_node_count(&url, &d_id).await, 1, "D projected");
    assert_eq!(age_node_count(&url, &e_id).await, 1, "E projected");

    // forget the whole namespace.
    let removed = store
        .forget(&ctx, Some(ns.as_str()), None, None, true)
        .await
        .expect("forget namespace");
    assert_eq!(removed, 2, "forget removed both rows");

    assert_eq!(
        age_node_count(&url, &d_id).await,
        0,
        "#1783: forget must unproject D's node"
    );
    assert_eq!(
        age_node_count(&url, &e_id).await,
        0,
        "#1783: forget must unproject E's node"
    );
    assert_eq!(
        age_incident_edge_count(&url, &d_id).await,
        0,
        "#1783: the D-E ghost edge must be gone after forget"
    );
}

/// DEFERRED mode race: when a memory is hard-deleted between a link's
/// outbox-enqueue and the cold drain, the drainer's existence-guard must
/// SKIP the now-orphaned ADD so it can never RESURRECT a node the delete
/// removed. This is what makes deferred mode race-free with no op-column
/// migration (the 5-agent vote synthesis).
#[tokio::test(flavor = "multi_thread")]
async fn deferred_drain_skips_deleted_link_no_resurrection_1783() {
    let _g = age_mode_lock().lock().await;
    let test = "deferred_drain_skips_deleted_link_no_resurrection_1783";
    let Some(url) = pg_url() else {
        eprintln!("skipping {test}: AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL not set");
        return;
    };
    let Some(store) = connect_age_or_skip(&url, test).await else {
        return;
    };

    let ctx = CallerContext::for_agent(TEST_AGENT.to_string());
    let ns = format!("t4d-1783-defer-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    let a = mk_memory(&ns, "a", &now);
    let b = mk_memory(&ns, "b", &now);
    let a_id = store.store(&ctx, &a).await.expect("store a");
    let b_id = store.store(&ctx, &b).await.expect("store b");

    // Deferred: the link enqueues a pending kg_projection_outbox row
    // instead of MERGEing inline — nothing is in AGE yet.
    set_age_projection_mode(AgeProjectionMode::Deferred);
    store
        .link(&ctx, &mk_link(&a_id, &b_id, &now))
        .await
        .expect("deferred link enqueues outbox row");
    assert_eq!(
        age_node_count(&url, &a_id).await,
        0,
        "deferred: nothing projected yet"
    );

    // Hard-delete A BEFORE the drain. FK ON DELETE CASCADE reaps the
    // memory_links row; the outbox ADD row is now orphaned (still pending).
    store.delete(&ctx, &a_id).await.expect("delete a");

    // Drain: the existence-guard sees the relational link is gone and
    // SKIPS the MERGE (dropping the orphaned outbox row) — so A is never
    // resurrected. (`projected` covers ALL pending rows in the shared
    // scratch DB, so it is NOT asserted; the id-specific no-resurrection
    // property below is what matters.)
    let _ = store.drain_kg_projection_outbox(64).await.expect("drain");
    assert_eq!(
        age_node_count(&url, &a_id).await,
        0,
        "#1783: the deleted node A must NOT be resurrected by the drainer's \
         MERGE of the orphaned ADD row"
    );
    assert_eq!(
        age_incident_edge_count(&url, &a_id).await,
        0,
        "#1783: no ghost edge incident to the deleted A may be projected"
    );

    // A second drain must STILL not resurrect A (the orphaned row was
    // stamped projected_at and is excluded from the take-query).
    let _ = store.drain_kg_projection_outbox(64).await.expect("drain 2");
    assert_eq!(
        age_node_count(&url, &a_id).await,
        0,
        "#1783: A stays absent after a repeat drain"
    );

    // In-file hygiene: restore the process default.
    set_age_projection_mode(AgeProjectionMode::Sync);
}
