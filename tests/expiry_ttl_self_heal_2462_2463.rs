// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2462 + #2463 — v54 backfill emits canonical micros+`Z` on its
//! own (independent of the v87 heal), and the sqlite TTL-extension
//! funnels self-heal a legacy non-UTC `expires_at` by comparing instants
//! instead of sqlite TEXT `MAX()`.
//!
//! Postgres stores `expires_at` as `TIMESTAMPTZ`; `GREATEST` is already
//! instant-compare. No product change on that backend — the live pin
//! below (ignored without `AI_MEMORY_TEST_POSTGRES_URL`) asserts the
//! structural twin.

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use ai_memory::validate::canonicalize_valid_time;
use rusqlite::{Connection, params};

fn fresh_sqlite() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory sqlite")
}

fn seed(conn: &Connection, id: &str, tier: Tier, expires_at: Option<&str>) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: id.to_string(),
        tier,
        namespace: "expiry-self-heal".to_string(),
        title: format!("title-{id}"),
        content: format!("content for {id}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: expires_at.map(str::to_string),
        metadata: serde_json::json!({}),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed memory")
}

fn expiry(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT expires_at FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("row present")
}

fn plus_nine_hours(dt: chrono::DateTime<chrono::Utc>) -> String {
    let offset = chrono::FixedOffset::east_opt(32_400).expect("+09:00");
    dt.with_timezone(&offset)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
}

fn plant_legacy_offset(conn: &Connection, id: &str, stored_offset: &str) {
    conn.execute(
        "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
        params![stored_offset, id],
    )
    .expect("plant legacy offset rendering");
}

#[track_caller]
fn assert_canonical_at_rest(stored: Option<&str>, what: &str) {
    let Some(v) = stored else {
        panic!("{what}: expected a stored expires_at, found NULL");
    };
    assert_eq!(
        canonicalize_valid_time(v).as_deref(),
        Some(v),
        "#2463 {what}: stored expires_at {v:?} is not canonical micros+Z"
    );
}

/// Stored `+09:00` of (now+30m) sorts ABOVE the canonical (now+1h) floor
/// as bytes (hour-tens / next-day rollover) but is 30 minutes EARLIER as
/// an instant. sqlite `MAX()` would keep the stale rendering; instant-MAX
/// must take the floor and write it canonically.
#[test]
fn touch_self_heals_legacy_offset_that_would_win_byte_max_2463() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let stored_instant = now + chrono::Duration::minutes(30);
    let stored_offset = plus_nine_hours(stored_instant);
    let canonical_seed =
        canonicalize_valid_time(&stored_instant.to_rfc3339()).expect("canonical seed");
    let id = seed(
        &conn,
        "heal-touch",
        Tier::Short,
        Some(canonical_seed.as_str()),
    );
    plant_legacy_offset(&conn, &id, &stored_offset);
    assert_eq!(
        expiry(&conn, &id).as_deref(),
        Some(stored_offset.as_str()),
        "precondition: raw UPDATE must land the offset spelling"
    );

    db::touch(&conn, &id, 3600, 86_400).expect("touch");

    let after = expiry(&conn, &id);
    assert_canonical_at_rest(after.as_deref(), "touch");
    assert_ne!(
        after.as_deref(),
        Some(stored_offset.as_str()),
        "#2463: touch must not keep the legacy offset rendering"
    );
    let after_dt = chrono::DateTime::parse_from_rfc3339(after.as_deref().expect("some"))
        .expect("parse after")
        .with_timezone(&chrono::Utc);
    assert!(
        after_dt >= stored_instant + chrono::Duration::minutes(20),
        "#2463: floor (now+1h) must win over stored instant (now+30m); got {after_dt}"
    );
}

#[test]
fn touch_many_self_heals_legacy_offset_2463() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let stored_instant = now + chrono::Duration::minutes(30);
    let stored_offset = plus_nine_hours(stored_instant);
    let canonical_seed =
        canonicalize_valid_time(&stored_instant.to_rfc3339()).expect("canonical seed");
    let id = seed(&conn, "heal-tm", Tier::Mid, Some(canonical_seed.as_str()));
    plant_legacy_offset(&conn, &id, &stored_offset);

    let n = db::touch_many(&conn, &[id.as_str()], 3600, 3600).expect("touch_many");
    assert_eq!(n, 1);

    let after = expiry(&conn, &id);
    assert_canonical_at_rest(after.as_deref(), "touch_many");
    assert_ne!(after.as_deref(), Some(stored_offset.as_str()));
}

#[test]
fn fold_self_heals_legacy_offset_2463() {
    let conn = fresh_sqlite();
    let now = chrono::Utc::now();
    let stored_instant = now + chrono::Duration::minutes(30);
    let stored_offset = plus_nine_hours(stored_instant);
    let canonical_seed =
        canonicalize_valid_time(&stored_instant.to_rfc3339()).expect("canonical seed");
    let id = seed(
        &conn,
        "heal-fold",
        Tier::Short,
        Some(canonical_seed.as_str()),
    );
    plant_legacy_offset(&conn, &id, &stored_offset);

    ai_memory::observations::record_recall_with_identity(
        &conn,
        "recall-2463",
        &[ai_memory::observations::Candidate {
            memory_id: id.as_str(),
            retriever: "fts5",
            rank: 1,
            score: 1.0,
        }],
        Some("agent-2463"),
        Some("expiry-self-heal"),
    )
    .expect("record recall observation");

    let folded = db::fold_recall_accesses(&conn, 3600, 86_400).expect("fold");
    assert!(folded > 0);

    let after = expiry(&conn, &id);
    assert_canonical_at_rest(after.as_deref(), "fold");
    assert_ne!(after.as_deref(), Some(stored_offset.as_str()));
}

#[test]
fn touch_leaves_null_expiry_null_2463() {
    let conn = fresh_sqlite();
    let id = seed(&conn, "heal-null", Tier::Short, None);
    // insert() stamps a default TTL; force NULL the way a pre-v54 row looked.
    conn.execute(
        "UPDATE memories SET expires_at = NULL WHERE id = ?1",
        params![id],
    )
    .expect("force NULL");
    db::touch(&conn, &id, 3600, 86_400).expect("touch");
    assert!(
        expiry(&conn, &id).is_none(),
        "#2463: NULL expiry must not be stamped by the floor"
    );
}

#[test]
fn touch_preserves_unparseable_expiry_byte_for_byte_2463() {
    let conn = fresh_sqlite();
    let id = seed(
        &conn,
        "heal-garbage",
        Tier::Short,
        Some("2027-01-01T00:00:00.000000Z"),
    );
    plant_legacy_offset(&conn, &id, "not-a-timestamp");
    db::touch(&conn, &id, 3600, 86_400).expect("touch");
    assert_eq!(
        expiry(&conn, &id).as_deref(),
        Some("not-a-timestamp"),
        "#2463: unparseable stored bytes must pass through (fail-safe)"
    );
}

/// Postgres `expires_at` is `TIMESTAMPTZ`; `GREATEST` compares instants, so
/// the sqlite byte-MAX trap cannot arise. Pin the structural twin: a
/// short-tier row whose stored expiry is 30 minutes from now is extended
/// by the 1h floor, and the SAL read-back is canonical micros+`Z`.
///
/// Agent id is assembled at runtime so this is not a new
/// `CallerContext::for_agent("<literal>")` C8 site.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_greatest_extends_and_reads_canonical_2463() {
    use ai_memory::store::MemoryStore as _;

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — postgres half not exercised");
        return;
    };
    let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("PostgresStore::connect failed: {e}"));
    let agent = format!("agent-{}", 2463);
    let ctx = ai_memory::store::CallerContext::for_agent(agent.clone());
    let now = chrono::Utc::now();
    let soon = now + chrono::Duration::minutes(30);
    let id = format!("heal-2463-{}", now.timestamp_micros());
    let stamp = now.to_rfc3339();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Short,
        namespace: "expiry-self-heal".to_string(),
        title: format!("title-{id}"),
        content: "pg greatest pin".to_string(),
        created_at: stamp.clone(),
        updated_at: stamp,
        expires_at: Some(soon.to_rfc3339()),
        metadata: serde_json::json!({"agent_id": agent}),
        ..Memory::default()
    };
    let _ = pg.delete(&ctx, &id).await;
    pg.store(&ctx, &mem).await.expect("store");
    pg.touch_after_recall(std::slice::from_ref(&id))
        .await
        .expect("pg touch");
    let stored = pg
        .get(&ctx, &id)
        .await
        .expect("get")
        .expires_at
        .expect("pg expiry");
    assert_eq!(
        canonicalize_valid_time(&stored).as_deref(),
        Some(stored.as_str()),
        "#2463 postgres: SAL read-back must be canonical micros+Z"
    );
    let stored_dt = chrono::DateTime::parse_from_rfc3339(&stored)
        .expect("parse")
        .with_timezone(&chrono::Utc);
    assert!(
        stored_dt >= soon + chrono::Duration::minutes(20),
        "#2463 postgres: GREATEST 1h floor must win over stored now+30m; got {stored_dt}"
    );
    let _ = pg.delete(&ctx, &id).await;
}
