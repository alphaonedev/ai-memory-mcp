// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3345 — postgres twin of `curator_report_bloat_3345`.
//!
//! The defect was measured on a SQLite tier, but both halves of the fix have a
//! postgres arm that can drift independently, and both are exercised here
//! against a LIVE cluster:
//!
//! 1. `PostgresStore::list_unembedded` — the boot-spawned backfill's row
//!    selector, on BOTH of its arms (the default one, and the
//!    `AI_MEMORY_PG_HEAL_FOREIGN_SPACE` heal arm). A substrate row offered
//!    here is a paid embedding for a row no ambient read path can return.
//! 2. `MemoryStore::prune_curator_reports` — the backlog collapse: dry run by
//!    default, day-folded before anything is written, non-destructive,
//!    idempotent, and refused outright to a non-admin caller.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; every seeded row is reaped in-test
//! (#2287) and every namespace is uuid-suffixed so concurrent lanes on one
//! cluster cannot collide.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc)]

use ai_memory::autonomy::{CURATOR_REPORTS_DAILY_NAMESPACE, CURATOR_REPORTS_NAMESPACE};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

/// Insert a row directly, bypassing the write funnel: substrate namespaces are
/// deliberately unwritable through `validate_create` (#3362), and this suite
/// needs to reproduce rows the SUBSTRATE itself wrote.
async fn raw_insert(
    store: &PostgresStore,
    namespace: &str,
    title: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    with_expiry: bool,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let expires = with_expiry.then(|| created_at + chrono::Duration::days(365));
    sqlx::query(
        "INSERT INTO memories (id, tier, namespace, title, content, source, priority, \
                               confidence, created_at, updated_at, expires_at, metadata) \
         VALUES ($1, 'mid', $2, $3, $4, 'test-3345', 2, 1.0, $5, $5, $6, '{}'::jsonb)",
    )
    .bind(&id)
    .bind(namespace)
    .bind(title)
    .bind(serde_json::json!({"cycle_ts": created_at.to_rfc3339(), "auto_tagged": 2}).to_string())
    .bind(created_at)
    .bind(expires)
    .execute(store.pool())
    .await
    .expect("raw insert");
    id
}

async fn cleanup(store: &PostgresStore, marker: &str) {
    let _ = sqlx::query("DELETE FROM memories WHERE title LIKE $1")
        .bind(format!("%{marker}%"))
        .execute(store.pool())
        .await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace LIKE $1")
        .bind(format!("%{marker}%"))
        .execute(store.pool())
        .await;
}

/// DENIED + ALLOWED on the live cluster: the backfill selector must offer the
/// ordinary row and no substrate row. Pre-#3345 both `list_unembedded` arms
/// returned every unembedded row regardless of namespace, which is the funnel
/// that paid for 24,801 curator-report embeddings on the measured tier.
#[tokio::test(flavor = "multi_thread")]
async fn list_unembedded_withholds_substrate_rows_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3345 live-pg suite");
    };
    let marker = format!("m3345-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let ordinary_ns = format!("proj/{marker}");

    let ordinary = raw_insert(
        &store,
        &ordinary_ns,
        &format!("ordinary {marker}"),
        now,
        false,
    )
    .await;
    raw_insert(
        &store,
        CURATOR_REPORTS_NAMESPACE,
        &format!("curator {marker}"),
        now,
        false,
    )
    .await;
    raw_insert(
        &store,
        &format!("_messages/ai:{marker}"),
        &format!("mail {marker}"),
        now,
        false,
    )
    .await;
    raw_insert(&store, "_agents", &format!("registry {marker}"), now, false).await;

    let admin = CallerContext::for_admin("test-3345");
    let rows = store
        .list_unembedded(&admin, 500)
        .await
        .expect("list_unembedded");
    let seeded: Vec<&String> = rows
        .iter()
        .filter(|(_, title, _)| title.contains(&marker))
        .map(|(id, _, _)| id)
        .collect();
    let denied_then_allowed = seeded == vec![&ordinary];
    cleanup(&store, &marker).await;
    assert!(
        denied_then_allowed,
        "#3345: the pg backfill must offer only the ordinary row, got {seeded:?}"
    );
}

/// The collapse on postgres: dry run by default, folds each affected UTC day,
/// stamps rather than deletes, and is idempotent on a second apply.
#[tokio::test(flavor = "multi_thread")]
async fn prune_curator_reports_is_dry_run_then_idempotent_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3345 live-pg suite");
    };
    let marker = format!("m3345p-{}", uuid::Uuid::new_v4());
    let admin = CallerContext::for_admin("test-3345");

    // Two historical days, two rows each, no expiry — the f1 backlog shape.
    // Every OTHER report row on this cluster is left with its own expiry so
    // this test's backlog counts are its own.
    let base = chrono::DateTime::parse_from_rfc3339("2026-06-06T00:00:00+00:00")
        .expect("base ts")
        .with_timezone(&chrono::Utc);
    for day in 0..2i64 {
        for hour in 0..2i64 {
            let ts = base + chrono::Duration::days(day) + chrono::Duration::hours(hour);
            raw_insert(
                &store,
                CURATOR_REPORTS_NAMESPACE,
                &format!("curator cycle {marker} d{day}h{hour}"),
                ts,
                false,
            )
            .await;
        }
    }

    async {
        let dry = store
            .prune_curator_reports(&admin, false)
            .await
            .expect("dry run");
        assert!(dry.dry_run, "the default mode must be a dry run");
        assert!(
            dry.backlog >= 4,
            "the dry run must see this suite's 4 backlog rows, got {}",
            dry.backlog
        );
        assert_eq!(dry.stamped, 0, "a dry run must stamp nothing");

        let physical_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM memories WHERE namespace = $1")
                .bind(CURATOR_REPORTS_NAMESPACE)
                .fetch_one(store.pool())
                .await
                .expect("count before");

        let applied = store
            .prune_curator_reports(&admin, true)
            .await
            .expect("apply");
        assert!(
            applied.stamped >= 4,
            "every backlog row must be stamped, got {}",
            applied.stamped
        );
        assert!(
            applied.days_rolled_up >= 2,
            "both seeded days must be folded, got {}",
            applied.days_rolled_up
        );

        let physical_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM memories WHERE namespace = $1")
                .bind(CURATOR_REPORTS_NAMESPACE)
                .fetch_one(store.pool())
                .await
                .expect("count after");
        assert_eq!(
            physical_after, physical_before,
            "#3345: the collapse stamps retention, it never deletes a row"
        );

        let summaries: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM memories WHERE namespace = $1 AND title LIKE '%2026-06-0%'",
        )
        .bind(CURATOR_REPORTS_DAILY_NAMESPACE)
        .fetch_one(store.pool())
        .await
        .expect("summary count");
        assert!(
            summaries >= 2,
            "the day's aggregate must outlive its per-sweep detail, got {summaries}"
        );

        // Stamped from each row's OWN created_at: a June row is already past
        // its window rather than handed a fresh one.
        let still_future: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM memories \
             WHERE namespace = $1 AND title LIKE $2 AND expires_at > NOW()",
        )
        .bind(CURATOR_REPORTS_NAMESPACE)
        .bind(format!("%{marker}%"))
        .fetch_one(store.pool())
        .await
        .expect("future count");
        assert_eq!(
            still_future, 0,
            "a June backlog row must not be given a fresh retention window"
        );

        let again = store
            .prune_curator_reports(&admin, true)
            .await
            .expect("second apply");
        assert_eq!(again.stamped, 0, "the collapse must be idempotent");
    }
    .await;

    cleanup(&store, &marker).await;
    let _ = sqlx::query("DELETE FROM memories WHERE namespace = $1 AND title LIKE '%2026-06-0%'")
        .bind(CURATOR_REPORTS_DAILY_NAMESPACE)
        .execute(store.pool())
        .await;
}

/// The collapse rewrites substrate rows across every owner, so a non-admin
/// caller is REFUSED loudly — never handed a zero-count "success" that would
/// tell an operator their 25k-row backlog was already clean.
#[tokio::test(flavor = "multi_thread")]
async fn prune_curator_reports_refuses_a_non_admin_caller_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3345 live-pg suite");
    };
    let tenant = CallerContext::for_agent("ai:not-admin-3345");
    let err = store
        .prune_curator_reports(&tenant, true)
        .await
        .expect_err("a tenant context must be refused");
    assert!(
        matches!(err, ai_memory::store::StoreError::PermissionDenied { .. }),
        "#3345: the refusal must be typed, not a silent empty result; got {err}"
    );
}

/// `stats.substrate` is derived from the SAME visibility SSOT expression on
/// both backends, so the two cannot disagree about which rows are bookkeeping.
#[tokio::test(flavor = "multi_thread")]
async fn stats_reports_the_substrate_share_pg() {
    let Some(store) = connect().await else {
        panic!("AI_MEMORY_TEST_POSTGRES_URL must be set for the #3345 live-pg suite");
    };
    let marker = format!("m3345s-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let before = store.stats().await.expect("stats before");

    raw_insert(
        &store,
        &format!("proj/{marker}"),
        &format!("ordinary {marker}"),
        now,
        false,
    )
    .await;
    raw_insert(
        &store,
        CURATOR_REPORTS_NAMESPACE,
        &format!("curator {marker}"),
        now,
        true,
    )
    .await;
    raw_insert(&store, "_agents", &format!("registry {marker}"), now, true).await;

    let after = store.stats().await.expect("stats after");
    let deltas = (
        after.total - before.total,
        after.substrate - before.substrate,
    );
    cleanup(&store, &marker).await;
    assert_eq!(
        deltas,
        (3, 2),
        "#3345: `total` stays the RAW physical count (#2334) and `substrate` \
         carries the bookkeeping share; got (total, substrate) deltas {deltas:?}"
    );
}
