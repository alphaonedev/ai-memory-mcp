// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal-postgres")]

//! Postgres+AGE schema-placement repair (#3055) — R-203 evidence.
//!
//! The defect: AGE's recommended setup pins the DATABASE default `search_path`
//! to `ag_catalog, "$user", public`, so an UNQUALIFIED `CREATE TABLE memories
//! ...` lands the ai-memory app tables in `ag_catalog` (the first entry is the
//! create target) — entangling durable application data with the AGE extension
//! catalog. A `DROP EXTENSION age CASCADE` would then take the app tables.
//!
//! The fix ships two halves, both proven here against a LIVE postgres+AGE.
//!
//! `search_path` normalization (`after_connect`): the adapter reorders the
//! session `search_path` so the first REAL app schema wins the
//! unqualified-CREATE target — dropping BOTH `ag_catalog` and `"$user"` from
//! the front and keeping `ag_catalog` last — so creates land in `public` (prod)
//! WITHOUT hard-coding `public`, while a caller-pinned path (the #1381
//! per-test-schema harness's `-c search_path=<test_schema>,public`, carrying no
//! `"$user"`/`ag_catalog`) is left untouched and keeps isolating.
//! `after_connect_demotes_ag_catalog_so_creates_land_in_public_3055` proves an
//! unqualified create lands in `public` (with a forced-`ag_catalog`-first
//! negative control that still shadows), and
//! `creates_land_in_public_not_user_schema_3055` proves the CVE-2018-1058
//! `"$user"` case (a role-named schema present does NOT capture the create).
//! `no_ag_catalog_shadows_after_connect_3055` proves that after a full
//! `connect()` (normalization + relocation + whole ladder) ZERO of the 37 app
//! tables remain in `ag_catalog`.
//!
//! Relocation (installed base): a pre-bootstrap, advisory-locked, idempotent,
//! allowlisted `ALTER TABLE ... SET SCHEMA public` self-heal for tables a
//! pre-fix binary already created in `ag_catalog`.
//! `relocation_guard_moves_and_is_idempotent_3055` exercises the exact
//! guard+move SQL on RANDOMIZED throwaway tables so it never fights the hive.
//!
//! `drop_extension_age_cascade_spares_public_app_data_3055` is the removal
//! proof: `public.memories` (which has no dependency on the `age` extension)
//! survives `DROP EXTENSION age CASCADE`. It is DESTRUCTIVE (drops the `age`
//! extension for the whole database) so it is gated behind
//! `AI_MEMORY_TEST_ALLOW_DROP_EXTENSION=1` in ADDITION to the pg-url env, and
//! restores the extension + `memory_graph` BEFORE any assertion so a failure
//! can never leave a shared database without `age`.
//!
//! Postgres+AGE only. Gated on `AI_MEMORY_TEST_POSTGRES_URL` (fallback
//! `AI_MEMORY_TEST_AGE_URL`); skips cleanly when unset or the backend is not
//! AGE. Run serially (`--test-threads=1`): several tests manipulate
//! `ag_catalog` and the session `search_path`.

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, KgBackend, MemoryStore};
use sqlx::Row;

/// The hard-coded 37-table app allowlist the relocation + demotion fix cover.
/// Kept in lockstep with `RELOCATE_PROBE_SQL` in `src/store/postgres.rs`.
const APP_TABLES: &[&str] = &[
    "memories",
    "memory_links",
    "archived_memories",
    "archived_memory_links",
    "memory_revisions",
    "memory_transcripts",
    "memory_transcript_links",
    "transcript_line_dedup",
    "entity_aliases",
    "forget_tombstones",
    "namespace_meta",
    "pending_actions",
    "sync_state",
    "subscriptions",
    "subscription_events",
    "subscription_dlq",
    "audit_log",
    "signed_events",
    "signed_events_dlq",
    "federation_push_dlq",
    "kg_projection_outbox",
    "agent_lineage",
    "agent_subkey_certs",
    "agent_api_keys",
    "agent_quotas",
    "model_attestations",
    "confidence_shadow_observations",
    "recall_observations",
    "offloaded_blobs",
    "actions",
    "action_edges",
    "leases",
    "signals",
    "checkpoints",
    "routines",
    "routine_runs",
    "schema_version",
];

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_AGE_URL")
        .ok()
        .or_else(|| std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok())
}

/// Connect and require AGE; returns `None` (with a skip line) when the env is
/// unset or the backend resolved to `Cte` (plain postgres, no `ag_catalog`).
async fn age_store_or_skip(test: &str) -> Option<PostgresStore> {
    let url = pg_url()?;
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");
    if store.kg_backend() != KgBackend::Age {
        eprintln!("skipping {test}: postgres backend is not AGE (no ag_catalog placement risk)");
        return None;
    }
    Some(store)
}

/// The schema a relation currently lives in (`public` / `ag_catalog` / absent).
async fn schema_of(pool: &sqlx::PgPool, relname: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT n.nspname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relname = $1 AND n.nspname IN ('public', 'ag_catalog') \
         ORDER BY CASE n.nspname WHEN 'ag_catalog' THEN 0 ELSE 1 END LIMIT 1",
    )
    .bind(relname)
    .fetch_optional(pool)
    .await
    .expect("probe relation schema")
}

/// The ACTUAL schema a relation lives in (any namespace, not just public /
/// `ag_catalog`) — used to prove a create did NOT land in the `$user` schema.
async fn actual_schema_of(pool: &sqlx::PgPool, relname: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT n.nspname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relname = $1 AND c.relkind = 'r' LIMIT 1",
    )
    .bind(relname)
    .fetch_optional(pool)
    .await
    .expect("probe actual relation schema")
}

fn rand_suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// A fresh `connect()` lands the anchor app tables in `public`, never
/// `ag_catalog`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL (Postgres+AGE CI cell)"]
async fn bootstrap_lands_app_tables_in_public_3055() {
    let test = "bootstrap_lands_app_tables_in_public_3055";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();
    for t in [
        "memories",
        "schema_version",
        "memory_links",
        "namespace_meta",
    ] {
        assert_eq!(
            schema_of(pool, t).await.as_deref(),
            Some("public"),
            "#3055: `{t}` must resolve in `public`, not `ag_catalog`"
        );
    }
    let reg: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.memories')::text")
        .fetch_one(pool)
        .await
        .expect("to_regclass public.memories");
    assert_eq!(reg.as_deref(), Some("memories"));
}

/// The core mechanism proof: `after_connect` demotes a leading `ag_catalog`, so
/// an UNQUALIFIED create lands in `public` — and, as a documented negative
/// control, a create run under a deliberately forced `ag_catalog`-first path
/// DOES shadow into `ag_catalog` (why the demotion is load-bearing).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL (Postgres+AGE CI cell)"]
async fn after_connect_demotes_ag_catalog_so_creates_land_in_public_3055() {
    let test = "after_connect_demotes_ag_catalog_so_creates_land_in_public_3055";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();
    let sfx = rand_suffix();
    let fixed = format!("zz3055_fix_{sfx}");
    let hazard = format!("zz3055_haz_{sfx}");

    // (1) On the adapter's own connection, ag_catalog must NOT lead (the
    // after_connect demotion ran), and an unqualified create lands in public.
    let head: Option<String> = sqlx::query_scalar("SELECT (current_schemas(false))[1]")
        .fetch_one(pool)
        .await
        .expect("read search_path head");
    assert_ne!(
        head.as_deref(),
        Some("ag_catalog"),
        "#3055: after_connect must demote a leading ag_catalog (head was {head:?})"
    );
    sqlx::raw_sql(&format!("CREATE TABLE {fixed} (id INT)"))
        .execute(pool)
        .await
        .expect("unqualified create on demoted connection");
    let fixed_schema = schema_of(pool, &fixed).await;

    // (2) Negative control: force ag_catalog first on THIS session and a bare
    // create shadows into ag_catalog — the hazard the demotion neutralizes.
    sqlx::raw_sql(&format!(
        "SET search_path = ag_catalog, public; CREATE TABLE {hazard} (id INT);"
    ))
    .execute(pool)
    .await
    .expect("forced-ag_catalog-first bare create");
    let hazard_schema = schema_of(pool, &hazard).await;

    // Cleanup + reset this pooled session's search_path before asserting.
    let _ = sqlx::raw_sql(&format!(
        "DROP TABLE IF EXISTS public.{fixed}; DROP TABLE IF EXISTS ag_catalog.{fixed}; \
         DROP TABLE IF EXISTS public.{hazard}; DROP TABLE IF EXISTS ag_catalog.{hazard}; \
         SELECT set_config('search_path', 'public, ag_catalog', false);"
    ))
    .execute(pool)
    .await;

    assert_eq!(
        fixed_schema.as_deref(),
        Some("public"),
        "#3055 FIX: an unqualified create on a demoted connection must land in public"
    );
    assert_eq!(
        hazard_schema.as_deref(),
        Some("ag_catalog"),
        "#3055 HAZARD (negative control): a bare create under a forced ag_catalog-first \
         path shadows into ag_catalog — this is what the after_connect demotion prevents"
    );
}

/// CVE-2018-1058 regression: with a schema NAMED AFTER THE CONNECTING ROLE
/// present (the reason `"$user"` is in the Postgres default `search_path`), an
/// unqualified app create must STILL land in `public`, not the `$user` schema —
/// otherwise a hardened per-role-schema deploy would bootstrap all 37 app
/// tables into `$user` and split-brain against a different-role reader. The
/// adapter's connections are already normalized (the `"$user"` token demoted),
/// so the role schema — even once created — is never on the create path.
/// Creates the role-named schema, checks placement, then DROPS it
/// (capture-then-cleanup-then-assert) so the shared tier is left clean even on
/// failure.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL (Postgres+AGE CI cell)"]
async fn creates_land_in_public_not_user_schema_3055() {
    let test = "creates_land_in_public_not_user_schema_3055";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();
    let role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await
        .expect("current_user");
    let sfx = rand_suffix();
    let probe = format!("zz3055_user_{sfx}");

    // Create the role-named schema — the CVE-2018-1058 shape. Explicit CREATE
    // SCHEMA is unaffected by search_path.
    if sqlx::raw_sql(&format!(
        "CREATE SCHEMA IF NOT EXISTS \"{role}\" AUTHORIZATION \"{role}\""
    ))
    .execute(pool)
    .await
    .is_err()
    {
        eprintln!("skipping {test}: cannot create role-named schema (privilege)");
        return;
    }

    // Capture placement WITHOUT asserting — cleanup (dropping the role schema)
    // MUST run before any assertion so the shared tier is left clean on failure.
    let head: Option<String> = sqlx::query_scalar("SELECT (current_schemas(false))[1]")
        .fetch_one(pool)
        .await
        .expect("read search_path head");
    let created_ok = sqlx::raw_sql(&format!("CREATE TABLE {probe} (id INT)"))
        .execute(pool)
        .await
        .is_ok();
    let probe_schema = if created_ok {
        actual_schema_of(pool, &probe).await
    } else {
        None
    };
    let memories_schema = schema_of(pool, "memories").await;

    // Cleanup FIRST (always): drop the probe wherever it landed + the role schema.
    let _ = sqlx::raw_sql(&format!(
        "DROP TABLE IF EXISTS public.{probe}; DROP TABLE IF EXISTS \"{role}\".{probe}; \
         DROP SCHEMA IF EXISTS \"{role}\" CASCADE;"
    ))
    .execute(pool)
    .await;

    assert_ne!(
        head.as_deref(),
        Some(role.as_str()),
        "#3055: the `$user` ({role}) schema must NOT lead the search_path"
    );
    assert!(created_ok, "#3055: the unqualified create must succeed");
    assert_eq!(
        probe_schema.as_deref(),
        Some("public"),
        "#3055 CVE-2018-1058: an unqualified create must land in `public`, not the `$user` schema"
    );
    assert_eq!(
        memories_schema.as_deref(),
        Some("public"),
        "#3055: `memories` must be in `public`, not the `$user` schema"
    );
}

/// After a full `connect()` (demotion + relocation + whole migrate ladder),
/// ZERO of the 37 app tables may remain in `ag_catalog`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL (Postgres+AGE CI cell)"]
async fn no_ag_catalog_shadows_after_connect_3055() {
    let test = "no_ag_catalog_shadows_after_connect_3055";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();
    let shadows: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT c.relname FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'ag_catalog' AND c.relkind = 'r' \
           AND c.relname = ANY($1) ORDER BY c.relname",
    )
    .bind(APP_TABLES)
    .fetch_all(pool)
    .await
    .expect("scan ag_catalog for app-table shadows");
    assert!(
        shadows.is_empty(),
        "#3055 MERGE-BLOCKER: {} app table(s) still in ag_catalog after connect: {shadows:?}",
        shadows.len()
    );
}

/// Relocation mechanism — the exact `to_regclass`-guarded `ALTER TABLE ... SET
/// SCHEMA public` the pre-bootstrap self-heal runs, on RANDOMIZED throwaway
/// tables: moves an `ag_catalog` table (with data) to public, is a no-op on a
/// second run (crash-resume), and SKIPS when a public twin already exists.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL / AI_MEMORY_TEST_AGE_URL (Postgres+AGE CI cell)"]
async fn relocation_guard_moves_and_is_idempotent_3055() {
    let test = "relocation_guard_moves_and_is_idempotent_3055";
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();
    let sfx = rand_suffix();
    let mv = format!("zz3055_move_{sfx}"); // only in ag_catalog -> must move
    let sk = format!("zz3055_skip_{sfx}"); // in both -> guard must skip

    sqlx::raw_sql(&format!(
        "CREATE TABLE ag_catalog.{mv} (id INT); INSERT INTO ag_catalog.{mv}(id) VALUES (1),(2); \
         CREATE TABLE ag_catalog.{sk} (id INT); INSERT INTO ag_catalog.{sk}(id) VALUES (9); \
         CREATE TABLE public.{sk} (id INT);"
    ))
    .execute(pool)
    .await
    .expect("seed throwaway relocation fixtures");

    let guarded = format!(
        "DO $$ BEGIN \
           IF to_regclass('ag_catalog.{mv}') IS NOT NULL AND to_regclass('public.{mv}') IS NULL THEN \
             ALTER TABLE ag_catalog.{mv} SET SCHEMA public; \
           END IF; \
           IF to_regclass('ag_catalog.{sk}') IS NOT NULL AND to_regclass('public.{sk}') IS NULL THEN \
             ALTER TABLE ag_catalog.{sk} SET SCHEMA public; \
           END IF; \
         END $$;"
    );
    sqlx::raw_sql(&guarded)
        .execute(pool)
        .await
        .expect("guarded move #1");
    sqlx::raw_sql(&guarded)
        .execute(pool)
        .await
        .expect("guarded move #2 (idempotent)");

    let mv_schema = schema_of(pool, &mv).await;
    let mv_rows: i64 = sqlx::query_scalar(&format!("SELECT count(*)::bigint FROM public.{mv}"))
        .fetch_one(pool)
        .await
        .unwrap_or(-1);
    let sk_ag_exists: bool = sqlx::query_scalar(&format!(
        "SELECT to_regclass('ag_catalog.{sk}') IS NOT NULL"
    ))
    .fetch_one(pool)
    .await
    .expect("probe skip fixture ag_catalog");
    let sk_pub_rows: i64 = sqlx::query_scalar(&format!("SELECT count(*)::bigint FROM public.{sk}"))
        .fetch_one(pool)
        .await
        .unwrap_or(-1);

    let _ = sqlx::raw_sql(&format!(
        "DROP TABLE IF EXISTS public.{mv}; DROP TABLE IF EXISTS ag_catalog.{mv}; \
         DROP TABLE IF EXISTS public.{sk}; DROP TABLE IF EXISTS ag_catalog.{sk};"
    ))
    .execute(pool)
    .await;

    assert_eq!(
        mv_schema.as_deref(),
        Some("public"),
        "#3055: guarded move must relocate the ag_catalog-only table to public"
    );
    assert_eq!(mv_rows, 2, "#3055: relocated rows must be preserved");
    assert!(
        sk_ag_exists,
        "#3055: the guard must SKIP a table that already has a public twin — its \
         ag_catalog copy must remain (no clobber)"
    );
    assert_eq!(
        sk_pub_rows, 0,
        "#3055: the pre-existing public twin must be left untouched by the skipped move"
    );
}

/// Removal proof — a `DROP EXTENSION age CASCADE` must SPARE `public` app data.
/// DESTRUCTIVE (drops the `age` extension for the whole database, then
/// recreates it); gated behind `AI_MEMORY_TEST_ALLOW_DROP_EXTENSION=1` so it
/// never fires against a shared hive. Skips if the role lacks the privilege.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "destructive; requires AI_MEMORY_TEST_ALLOW_DROP_EXTENSION=1 + pg-url + superuser"]
async fn drop_extension_age_cascade_spares_public_app_data_3055() {
    let test = "drop_extension_age_cascade_spares_public_app_data_3055";
    if std::env::var("AI_MEMORY_TEST_ALLOW_DROP_EXTENSION")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipping {test}: set AI_MEMORY_TEST_ALLOW_DROP_EXTENSION=1 to run (destructive)"
        );
        return;
    }
    let Some(store) = age_store_or_skip(test).await else {
        return;
    };
    let pool = store.pool();

    let ctx = CallerContext::for_agent("t-3055".to_string());
    let ns = format!("t3055-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns,
        title: "survivor".to_string(),
        content: "keep me".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    let mem_id = store
        .store(&ctx, &mem)
        .await
        .expect("store survivor memory");

    // A public table with NO dependency on the age extension — must survive.
    if sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS public.age_survivor_3055 (id TEXT PRIMARY KEY); \
         INSERT INTO public.age_survivor_3055 (id) VALUES ('s') ON CONFLICT DO NOTHING;",
    )
    .execute(pool)
    .await
    .is_err()
    {
        eprintln!("skipping {test}: cannot create public probe (insufficient privilege)");
        return;
    }

    // Perform the cascade, then CAPTURE survival WITHOUT asserting — restore
    // MUST run before any assertion so a failure never leaves the shared
    // database without its `age` extension.
    let dropped = sqlx::query("DROP EXTENSION age CASCADE")
        .execute(pool)
        .await
        .is_ok();

    let mem_still: i64 = if dropped {
        sqlx::query("SELECT count(*)::bigint AS n FROM public.memories WHERE id = $1")
            .bind(&mem_id)
            .fetch_one(pool)
            .await
            .expect("probe public.memories survival")
            .get::<i64, _>("n")
    } else {
        -1
    };
    let survivor_exists: bool = if dropped {
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('public.age_survivor_3055') IS NOT NULL")
            .fetch_one(pool)
            .await
            .expect("probe public survivor")
    } else {
        false
    };

    // RESTORE the extension + graph FIRST (always, even on the skip path), then
    // clean up the test fixtures.
    let _ = sqlx::raw_sql(
        "CREATE EXTENSION IF NOT EXISTS age; \
         LOAD 'age'; \
         SET search_path = ag_catalog, \"$user\", public; \
         SELECT create_graph('memory_graph');",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("DROP TABLE IF EXISTS public.age_survivor_3055")
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM public.memories WHERE id = $1")
        .bind(&mem_id)
        .execute(pool)
        .await;

    if !dropped {
        eprintln!("skipping {test}: role cannot DROP EXTENSION age (needs superuser)");
        return;
    }

    // The removal proof: application data lives in `public`, which has no
    // dependency on the `age` extension, so tearing the extension down cannot
    // reach it. (On AGE 1.x, DROP EXTENSION may LEAVE the `ag_catalog` schema
    // in place; the acute data-loss vector is a full `DROP SCHEMA ag_catalog
    // CASCADE`, which the fix defeats the same way — by keeping app tables out
    // of `ag_catalog` entirely. See `no_ag_catalog_shadows_after_connect_3055`.)
    assert_eq!(
        mem_still, 1,
        "#3055 REMOVAL PROOF: public.memories row must SURVIVE DROP EXTENSION age CASCADE"
    );
    assert!(
        survivor_exists,
        "#3055: a public table (no age dependency) must survive DROP EXTENSION age CASCADE"
    );
}
