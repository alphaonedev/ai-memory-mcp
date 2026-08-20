// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2515 (GA Wave-1 data-integrity blocker) — a re-store / upsert must
//! FLOOR the TTL, never SHORTEN it.
//!
//! # The defect
//!
//! Every LOCAL create/upsert funnel merges an incoming `(title, namespace)`
//! row onto the existing one. The `expires_at` arm used to be the bare
//! `ELSE COALESCE(excluded.expires_at, memories.expires_at)`, which adopts the
//! INCOMING expiry verbatim. Re-storing the same `(title, namespace)` with an
//! EARLIER expiry therefore silently rolled a live row's TTL BACKWARDS — a
//! #1596 never-move-expiry-earlier violation and unintentional data loss
//! (premature GC reap → permanent link-edge loss under the v70 auto-eviction
//! posture).
//!
//! #2515 replaces every such arm with the shipped #2335 tier-aware lattice
//! floor (`MAX` on sqlite, `GREATEST` on postgres over the COALESCE'd pair):
//! a mid/short-tier re-store converges on the LATER expiry regardless of store
//! order; a long-tier row pins to NULL (immortal, #1626). EXPLICIT shortening
//! stays ONLY on the `memory_update` / `db::update` path (untouched here).
//!
//! # The pins
//!
//! * A mid-tier row with a FAR expiry, re-stored with an EARLIER expiry, keeps
//!   the FAR (floored) value — the core anti-shortening contract.
//! * The floor still EXTENDS: a mid-tier row with a NEAR expiry, re-stored with
//!   a LATER expiry, adopts the LATER value (proving it is a real `MAX`, not a
//!   blanket "keep existing").
//!
//! Postgres twins run behind `sal-postgres` + `AI_MEMORY_TEST_POSTGRES_URL` and
//! self-skip cleanly when the substrate is absent.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::validate::canonicalize_valid_time;
use rusqlite::{Connection, params};

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

/// `now + days`, canonicalized to the fixed-UTC rendering the funnel stores.
fn canon_in_days(days: i64) -> String {
    canonicalize_valid_time(&(chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339())
        .expect("canonical expiry")
}

/// Build a mid-tier memory for `(title, namespace)` with the given expiry.
/// A distinct `id` each call so the merge is driven by the `(title, namespace)`
/// unique index (the upsert path), never a PK collision.
fn mid_memory(id: &str, title: &str, namespace: &str, expires: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("body for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: Some(expires.to_string()),
        metadata: serde_json::json!({ "scope": "collective" }),
        ..Memory::default()
    }
}

/// Stored `expires_at` for a live `(title, namespace)` row.
fn stored_expiry(conn: &Connection, title: &str, namespace: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE title = ?1 AND namespace = ?2",
        params![title, namespace],
        |r| r.get(0),
    )
    .expect("row present")
}

#[test]
fn restore_with_earlier_expiry_floors_not_shortens_sqlite() {
    let conn = fresh_sqlite();
    let far = canon_in_days(30);
    let near = canon_in_days(1);
    let (title, ns) = ("floor-me", "expiry-floor-2515");

    // Seed with the FAR expiry, then re-store the SAME (title, namespace) with
    // an EARLIER expiry — the bare-COALESCE bug would have adopted `near`.
    db::insert(&conn, &mid_memory("seed-far", title, ns, &far)).expect("seed far");
    db::insert(&conn, &mid_memory("restore-near", title, ns, &near)).expect("restore near");

    assert_eq!(
        stored_expiry(&conn, title, ns).as_deref(),
        Some(far.as_str()),
        "#2515: a re-store with an EARLIER expiry must FLOOR (keep the later \
         value), never SHORTEN the live TTL"
    );
}

#[test]
fn restore_with_later_expiry_extends_sqlite() {
    let conn = fresh_sqlite();
    let far = canon_in_days(30);
    let near = canon_in_days(1);
    let (title, ns) = ("extend-me", "expiry-floor-2515");

    // Seed NEAR, re-store LATER — the floor must EXTEND (proving it is a real
    // MAX, not a blanket "keep the existing value").
    db::insert(&conn, &mid_memory("seed-near", title, ns, &near)).expect("seed near");
    db::insert(&conn, &mid_memory("restore-far", title, ns, &far)).expect("restore far");

    assert_eq!(
        stored_expiry(&conn, title, ns).as_deref(),
        Some(far.as_str()),
        "#2515: a re-store with a LATER expiry must EXTEND to the later value"
    );
}

#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{canon_in_days, mid_memory};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skipping #2515 postgres floor verify: connect failed: {e}");
                None
            }
        }
    }

    /// Postgres twin of `restore_with_earlier_expiry_floors_not_shortens_sqlite`
    /// — the `GREATEST` floor must keep the later expiry on an earlier re-store.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_restore_with_earlier_expiry_floors_not_shortens_2515() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("floor-2515");
        // Unique namespace so a shared live DB never cross-contaminates.
        let ns = format!("expiry-floor-2515-{}", uuid::Uuid::new_v4());
        let title = "floor-me";
        let far = canon_in_days(30);
        let near = canon_in_days(1);

        pg.store(&ctx, &mid_memory("seed-far", title, &ns, &far))
            .await
            .expect("seed far");
        let id = pg
            .store(&ctx, &mid_memory("restore-near", title, &ns, &near))
            .await
            .expect("restore near");

        let got = pg.get(&ctx, &id).await.expect("get merged row");
        assert_eq!(
            got.expires_at.as_deref(),
            Some(far.as_str()),
            "#2515 pg: a re-store with an EARLIER expiry must FLOOR (keep the \
             later value), never SHORTEN the live TTL"
        );
    }

    /// The floor still EXTENDS on postgres.
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn pg_restore_with_later_expiry_extends_2515() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let ctx = CallerContext::for_admin("floor-2515");
        let ns = format!("expiry-floor-2515-{}", uuid::Uuid::new_v4());
        let title = "extend-me";
        let far = canon_in_days(30);
        let near = canon_in_days(1);

        pg.store(&ctx, &mid_memory("seed-near", title, &ns, &near))
            .await
            .expect("seed near");
        let id = pg
            .store(&ctx, &mid_memory("restore-far", title, &ns, &far))
            .await
            .expect("restore far");

        let got = pg.get(&ctx, &id).await.expect("get merged row");
        assert_eq!(
            got.expires_at.as_deref(),
            Some(far.as_str()),
            "#2515 pg: a re-store with a LATER expiry must EXTEND to the later value"
        );
    }
}
