// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]
#![allow(clippy::needless_update)]

//! #3883 (5-agent vote 4d3ea1c5, option A) — AGE ORPHANED-GRAPH structural
//! classification, live-AGE acceptance.
//!
//! An ORPHANED graph is a `memory_graph` SCHEMA that exists with NO
//! `ag_catalog.ag_graph` registry row — the #3881 real-world shape:
//! `DROP EXTENSION age CASCADE` removes `ag_catalog` + the registry but (on
//! some AGE versions) leaves the plain `memory_graph` schema behind, and
//! re-`CREATE EXTENSION age` brings `ag_catalog` back with no registry row for
//! the surviving schema. The fixture builds that shape version-independently
//! (see `orphan_the_graph`). Against it
//! `create_graph` raises 42P06 `schema "memory_graph" already exists` and every
//! projection MERGE fails — a STRUCTURAL fault, not a transient one.
//!
//! What this pins (postgres+AGE only; f1 runs it — see cell docs):
//!  1. an orphan makes a `link` write COMMIT (the relational row is truth),
//!     enqueue its projection QUARANTINED (`attempt_count = MAX`, `last_error`
//!     carrying the orphan prefix), and tick `age_projection_quarantined_total`
//!     ONCE — never MAX transient retries;
//!  2. the SAME shared classifier (`record_failed_age_projection`) drives
//!     `consolidate` too (A1) — `apply_remote_link` / `archive_restore` call the
//!     identical helper (documented below);
//!  3. repairing the registry lets the drainer SELF-HEAL — orphan rows reset and
//!     project;
//!  4. `ensure_memory_graph` boot on an orphan WARNs and CONTINUES (never fails).
//!
//! Gated on `AI_MEMORY_TEST_AGE_URL` (fallback `AI_MEMORY_TEST_POSTGRES_URL`):
//! prints a skip line + returns when unset, so the default `cargo test` is
//! unaffected. `#[ignore]` like the AGE cert siblings; the cert-postgres-age
//! workflow runs it under `--include-ignored` with the URL set.

use ai_memory::config::{set_consolidate_tombstone_sources, set_lineage_dag};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};

const AGE_GRAPH: &str = "memory_graph";
/// The `last_error` prefix `record_failed_age_projection` stamps on a
/// quarantined orphan row (kept in lockstep with the postgres const of the
/// same value — the source SSOT is `AGE_GRAPH_ORPHAN_LAST_ERROR_PREFIX`).
const ORPHAN_LAST_ERROR_PREFIX: &str = "age_graph_orphan:";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

fn ctx() -> CallerContext {
    CallerContext::for_agent("t-3883-orphan".to_string())
}

fn mk_memory(namespace: &str, title: &str, now: &str) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "x".to_string(),
        created_at: now.to_string(),
        updated_at: now.to_string(),
        metadata: serde_json::json!({ "agent_id": "t-3883-orphan" }),
        ..Memory::default()
    }
}

/// Reproduce the #3881 orphan with AGE still INSTALLED: remove the graph's
/// `ag_label` rows and then its `ag_catalog.ag_graph` registry row, in one
/// transaction, leaving the `memory_graph` SCHEMA in place with no registry
/// row, which is the exact shape `create_graph` then refuses with 42P06.
///
/// Why not `DROP EXTENSION age CASCADE` + `CREATE EXTENSION age` (the #3881
/// real-world path): the survival of the schema across that drop is
/// VERSION-DEPENDENT. MEASURED by f1 on PG 18.6 / AGE 1.8.0 (the certified
/// tier): the drop takes the schema with it, so the fixture produced
/// (schema absent, registry absent), the link re-created the graph, and the
/// cell failed on a missing outbox row for a reason that had nothing to do
/// with the product. The catalog-row construction is version-independent, and
/// the caller asserts BOTH halves of the orphan shape before relying on it.
async fn orphan_the_graph(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM ag_catalog.ag_label WHERE graph = \
         (SELECT graphid FROM ag_catalog.ag_graph WHERE name = $1::name)",
    )
    .bind(AGE_GRAPH)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM ag_catalog.ag_graph WHERE name = $1::name")
        .bind(AGE_GRAPH)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Does the `memory_graph` schema physically exist (the other half of the
/// orphan shape: present schema, absent registry row)?
async fn graph_schema_present(url: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await?;
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1::name)")
            .bind(AGE_GRAPH)
            .fetch_one(&pool)
            .await?,
    )
}

/// Heal the orphan: drop the surviving schema and re-create the graph so the
/// registry row is present again (the #3881 restore pattern).
async fn heal_the_graph(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await?;
    let mut conn = pool.acquire().await?;
    sqlx::query("CREATE EXTENSION IF NOT EXISTS age")
        .execute(&mut *conn)
        .await?;
    sqlx::query("LOAD 'age'").execute(&mut *conn).await?;
    sqlx::query("SET search_path = ag_catalog, \"$user\", public")
        .execute(&mut *conn)
        .await?;
    // #3935 — teardown that survives all THREE entry states heal_the_graph is
    // called against (:174 recovers a crashed prior run): healthy (ag_graph row
    // + schema), ORPHAN (schema present, NO ag_graph row — the `orphan_the_graph`
    // shape: it deletes the `ag_label` + `ag_graph` rows and leaves the schema,
    // version-independent since `DROP EXTENSION age` takes the schema with it on
    // AGE 1.8), and fully absent. A REGISTERED graph MUST be torn down with AGE's
    // `drop_graph`, for a reason that holds regardless of the lane's
    // `shared_preload_libraries`: a raw `DROP SCHEMA ... CASCADE` under an active
    // AGE session fires the object_access hook (`2BP01 table "_ag_label_edge" is
    // for label`); and even where a no-`LOAD age` connection lets the raw drop
    // through (a lane with EMPTY `shared_preload_libraries`), the drop removes the
    // SCHEMA but LEAVES the `ag_graph` registry row — an INVERTED orphan — so the
    // `create_graph` that follows in this fn then FAILS ("graph already exists").
    // Only `drop_graph`, which removes BOTH the registry row and the schema, is a
    // clean teardown of a registered graph. But `drop_graph` ERRORs "graph does
    // not exist" without a registry row, so it is used ONLY when the `ag_graph`
    // row is present; an orphan schema (no row) is dropped raw — `orphan_the_graph`
    // already removed its `ag_label` rows, so the leftover tables are not
    // registered labels and the hook does not fire on them.
    let graph_registered: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = $1::name)",
    )
    .bind(AGE_GRAPH)
    .fetch_one(&mut *conn)
    .await?;
    if graph_registered {
        sqlx::query(&format!("SELECT drop_graph('{AGE_GRAPH}', true)"))
            .execute(&mut *conn)
            .await?;
    } else {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{AGE_GRAPH}\" CASCADE"))
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query(&format!("SELECT create_graph('{AGE_GRAPH}')"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn ag_graph_row_present(url: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await?;
    let mut conn = pool.acquire().await?;
    sqlx::query("LOAD 'age'").execute(&mut *conn).await?;
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = $1::name)",
    )
    .bind(AGE_GRAPH)
    .fetch_one(&mut *conn)
    .await?;
    Ok(present)
}

/// The pending outbox row for one edge: `(attempt_count, last_error)` where
/// `projected_at IS NULL`. `None` when the edge has no pending row (drained).
async fn pending_row(store: &PostgresStore, src: &str, dst: &str) -> Option<(i32, Option<String>)> {
    sqlx::query_as::<_, (i32, Option<String>)>(
        "SELECT attempt_count, last_error FROM kg_projection_outbox \
         WHERE source_id = $1 AND target_id = $2 AND projected_at IS NULL",
    )
    .bind(src)
    .bind(dst)
    .fetch_optional(store.pool())
    .await
    .expect("read pending outbox row")
}

async fn memory_links_count(store: &PostgresStore, src: &str, dst: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2",
    )
    .bind(src)
    .bind(dst)
    .fetch_one(store.pool())
    .await
    .expect("count memory_links")
}

fn quarantined_total() -> u64 {
    ai_memory::metrics::registry()
        .age_projection_quarantined_total
        .get()
}

// Single `#[tokio::test]` (deterministic ordering; the orphan fixture mutates the
// global AGE catalog). `#[ignore]` + env-skip, mirroring the AGE cert siblings.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live AGE-enabled postgres (AI_MEMORY_TEST_AGE_URL); run in cert-postgres-age"]
async fn age_orphan_graph_quarantines_and_self_heals_3883() {
    let Some(url) = pg_url() else {
        eprintln!(
            "skip: kg_age_orphan_graph_3883 requires AI_MEMORY_TEST_AGE_URL / AI_MEMORY_TEST_POSTGRES_URL (unset)"
        );
        return;
    };

    // Start clean so a prior failed run's orphan does not skew the fixture.
    heal_the_graph(&url).await.expect("heal graph before test");

    let mut store = PostgresStore::connect(&url).await.expect("connect store");
    if store.kg_backend() != KgBackend::Age {
        eprintln!(
            "skip: kg_age_orphan_graph_3883 requires the AGE backend (kg_backend resolved to CTE; no projection to orphan)"
        );
        return;
    }

    let ns = format!("t3883-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let a_id = store
        .store(&ctx(), &mk_memory(&ns, "a", &now))
        .await
        .expect("store a");
    let b_id = store
        .store(&ctx(), &mk_memory(&ns, "b", &now))
        .await
        .expect("store b");
    let c_id = store
        .store(&ctx(), &mk_memory(&ns, "c", &now))
        .await
        .expect("store c");

    // ---- Cell 1 — orphan → link Ok + QUARANTINED outbox row, +1 not +MAX ----
    orphan_the_graph(&url).await.expect("orphan the graph");
    assert!(
        !ag_graph_row_present(&url)
            .await
            .expect("probe orphan state"),
        "fixture precondition: ag_graph registry row must be ABSENT after orphaning"
    );
    assert!(
        graph_schema_present(&url)
            .await
            .expect("probe orphan schema"),
        "fixture precondition: the memory_graph SCHEMA must SURVIVE orphaning (else this is an absent graph, not an orphan)"
    );
    // NEVER reuse a backend that saw the graph before the raw catalog delete. MEASURED in CI on
    // f2-linux-fed-2 (PG 18.6 / AGE 1.8.0, 2026-09-24 15:13 EDT): a pooled connection that had
    // cached `memory_graph` ran the link's cypher MERGE after the ag_graph/ag_label rows were
    // deleted under it and AGE SEGFAULTED the backend ("terminated by signal 11"), which
    // restarts the WHOLE shared cluster. A raw DELETE sends AGE no cache invalidation, so the
    // store is rebuilt on fresh backends that only ever see the orphan state.
    store.pool().close().await;
    store = PostgresStore::connect(&url)
        .await
        .expect("reconnect on fresh backends after orphaning");

    let q_before = quarantined_total();
    let link = MemoryLink {
        source_id: a_id.clone(),
        target_id: b_id.clone(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: now.clone(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    store
        .link(&ctx(), &link)
        .await
        .expect("A absorb: link COMMITS against an orphaned graph (relational truth)");

    assert_eq!(
        memory_links_count(&store, &a_id, &b_id).await,
        1,
        "the relational memory_links row must be committed"
    );
    let (attempts, last_err) = pending_row(&store, &a_id, &b_id)
        .await
        .expect("orphan link must leave ONE pending outbox row");
    assert_eq!(
        attempts,
        PostgresStore::MAX_AGE_PROJECTION_ATTEMPTS,
        "orphan row must be enqueued already QUARANTINED (attempt_count = MAX)"
    );
    assert!(
        last_err
            .as_deref()
            .is_some_and(|e| e.starts_with(ORPHAN_LAST_ERROR_PREFIX)),
        "quarantined orphan row's last_error must carry the orphan prefix, got {last_err:?}"
    );
    assert_eq!(
        quarantined_total(),
        q_before + 1,
        "quarantined_total must tick exactly ONCE at detection — not MAX times"
    );

    // One drain while STILL orphaned must NOT retry the quarantined row (the
    // self-heal probe is false, the take-query excludes attempt_count >= MAX).
    let drained = store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain (still orphan)");
    assert_eq!(
        drained, 0,
        "a still-orphaned graph must not project the quarantined row"
    );
    let (attempts_after, _) = pending_row(&store, &a_id, &b_id)
        .await
        .expect("row still pending while orphaned");
    assert_eq!(
        attempts_after,
        PostgresStore::MAX_AGE_PROJECTION_ATTEMPTS,
        "the quarantined row must NOT be taken/incremented while orphaned (no retry storm)"
    );
    assert_eq!(
        quarantined_total(),
        q_before + 1,
        "draining a still-orphaned graph must not add further quarantine ticks"
    );

    // ---- Cell 2 — consolidate shares the SAME absorb helper (A1) ----
    // apply_remote_link and archive_restore call the IDENTICAL
    // `record_failed_age_projection`, so cell 1's assertion structurally covers
    // their disposition; consolidate is pinned here as a second live site.
    set_lineage_dag(true);
    set_consolidate_tombstone_sources(true);
    let merged = store
        .consolidate(
            &ctx(),
            std::slice::from_ref(&c_id),
            "merged",
            "summary",
            &ns,
            &Tier::Long,
            "t-3883-orphan",
            "t-3883-orphan",
        )
        .await
        .expect("A absorb: consolidate COMMITS against an orphaned graph");
    // The tombstone lineage edge (merged -> c) must leave a pending outbox row.
    let consolidate_row = pending_row(&store, &merged, &c_id).await;
    assert!(
        consolidate_row.is_some(),
        "consolidate's derived_from projection must be RECORDED in the outbox under orphan (A1)"
    );

    // ---- Cell 4 — boot on an orphan WARNs and CONTINUES (never fails) ----
    // A6/#3882: a second connect against the orphaned DB must succeed (its
    // ensure_memory_graph emits the structural-reason WARN — visible in the
    // cert run's logs — and commits rather than erroring).
    let boot2 = PostgresStore::connect(&url).await;
    assert!(
        boot2.is_ok(),
        "ensure_memory_graph must WARN-and-continue on an orphaned graph, not fail boot"
    );

    // ---- Cell 3 — heal → next drain SELF-HEALS (resets + projects) ----
    heal_the_graph(&url).await.expect("heal the graph");
    assert!(
        ag_graph_row_present(&url)
            .await
            .expect("probe healed state"),
        "ag_graph registry row must be present again after healing"
    );
    // Same rule in the other direction: these backends cached the ORPHAN state; heal through
    // fresh ones so no connection straddles a catalog change it was not told about.
    store.pool().close().await;
    store = PostgresStore::connect(&url)
        .await
        .expect("reconnect on fresh backends after healing");
    let projected = store
        .drain_kg_projection_outbox(64)
        .await
        .expect("drain (healed)");
    assert!(
        projected >= 1,
        "after repair the drainer must reset the orphan-quarantined rows and project them, got {projected}"
    );
    assert!(
        pending_row(&store, &a_id, &b_id).await.is_none(),
        "the healed orphan row must be projected (projected_at set, no longer pending)"
    );

    // ---- Cell 5 — probe-error fall-through: NOT pinned here (documented) ----
    // A2's "probe error => transient fall-through, never quarantine" needs the
    // ag_catalog.ag_graph SELECT to FAIL mid-tx. The natural lever is REVOKE
    // USAGE ON SCHEMA ag_catalog, but the AGE test role is a superuser that
    // bypasses REVOKE, so it cannot be provoked deterministically here. The
    // fall-through logic is pinned instead by the sqlite-free classifier unit
    // test `issue_3883_orphan_classifier_distinguishes_shapes` in
    // src/store/postgres.rs (a non-orphan-prefixed error is NOT classified as
    // an orphan, so the caller enqueues transient — attempt_count 0 — never
    // quarantines).

    // In-file hygiene: leave the graph healthy for the next AGE test binary.
    heal_the_graph(&url).await.expect("heal graph after test");
}
