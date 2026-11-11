// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9018 — consolidate never hard-deletes a source without an archive row.
//!
//! Invariant, on BOTH backends: after a successful consolidate every source
//! is either still a row in `memories` (tombstone sub-flag ON) or a row in
//! `archived_memories` with `archive_reason = "consolidate"` and its full
//! text (sub-flag OFF, the legacy disposition). Pre-fix the legacy arm ran a
//! bare delete, so the merged-away text had no recovery path.
//!
//! The process-wide lineage flags are atomics, so the cells run serially
//! under one lock. The postgres cell runs only when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set and uses its own scratch database.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::models::field_names;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore};

/// Serializes the cells: the lineage flags are process-wide atomics.
static FLAG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Agent that owns the sources and runs the consolidate.
const TEST_AGENT: &str = "ai:consolidate-9018";
/// Sources merged by each consolidate.
const SOURCES_PER_CELL: usize = 3;
/// Page size of the archive listing (well above `SOURCES_PER_CELL`).
const ARCHIVE_PAGE: usize = 100;
/// Timestamp used for every seeded row.
const SEED_AT: &str = "2026-11-01T00:00:00+00:00";

/// The two dispositions of the tombstone sub-flag.
const TOMBSTONE_CELLS: [bool; 2] = [false, true];

fn set_tombstoning(on: bool) {
    ai_memory::config::set_lineage_dag(on);
    ai_memory::config::set_consolidate_tombstone_sources(on);
    ai_memory::config::set_append_only(false);
}

fn mem(id: &str, ns: &str, n: usize) -> Memory {
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: format!("source {n}"),
        content: format!("source text {n} that must stay recoverable"),
        tags: vec!["c9018".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "user".to_string(),
        access_count: 0,
        created_at: SEED_AT.to_string(),
        updated_at: SEED_AT.to_string(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": TEST_AGENT }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// Seed sources, consolidate them, and assert every source is still a live
/// row or an archive row carrying its text. `live` answers whether an id is
/// still a row in `memories`.
async fn run_cell<S, F, Fut>(store: &S, tombstone: bool, live: F)
where
    S: MemoryStore + ?Sized,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    set_tombstoning(tombstone);
    let ctx = CallerContext::for_agent(TEST_AGENT);
    let ns = format!("c9018-{}", uuid::Uuid::new_v4());
    let ids: Vec<String> = (0..SOURCES_PER_CELL)
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect();
    for (n, id) in ids.iter().enumerate() {
        store
            .store(&ctx, &mem(id, &ns, n))
            .await
            .expect("seed source");
    }
    store
        .consolidate(
            &ctx,
            &ids,
            "merged",
            "a caller summary of the three sources",
            &ns,
            &Tier::Long,
            "consolidation",
            TEST_AGENT,
        )
        .await
        .expect("consolidate");
    let archived = store
        .list_archived(Some(&ns), ARCHIVE_PAGE, 0)
        .await
        .expect("list archive");
    for (n, id) in ids.iter().enumerate() {
        let row = archived.iter().find(|r| r["id"] == id.as_str());
        let still_live = live(id.clone()).await;
        if tombstone {
            assert!(still_live, "tombstone ON keeps source {id} as a row");
            continue;
        }
        assert!(
            !still_live,
            "legacy disposition removes source {id} from memories"
        );
        let row = row.unwrap_or_else(|| panic!("source {id} hard-deleted with no archive row"));
        assert_eq!(
            row[field_names::ARCHIVE_REASON],
            field_names::ARCHIVE_REASON_CONSOLIDATE,
            "{id}"
        );
        assert_eq!(
            row["content"],
            format!("source text {n} that must stay recoverable"),
            "{id}: archived text"
        );
    }
    set_tombstoning(false);
}

#[tokio::test]
async fn consolidate_archive_first_9018_sqlite() {
    let _g = FLAG_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("c9018.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open sqlite");
    for tombstone in TOMBSTONE_CELLS {
        let path = db_path.clone();
        run_cell(&store, tombstone, move |id| {
            let path = path.clone();
            async move {
                let conn = rusqlite::Connection::open(&path).expect("open raw");
                conn.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [&id], |r| {
                    r.get::<_, i64>(0)
                })
                .expect("count live row")
                    > 0
            }
        })
        .await;
    }
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn consolidate_archive_first_9018_postgres() {
    /// Scratch database prefix of this binary.
    const SCRATCH_PREFIX: &str = "ai_memory_c9018";
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let _g = FLAG_LOCK.lock().await;
    let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    for tombstone in TOMBSTONE_CELLS {
        let pool = store.pool().clone();
        run_cell(&store, tombstone, move |id| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM memories WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("count live row")
                    > 0
            }
        })
        .await;
    }
    store.pool().close().await;
}
