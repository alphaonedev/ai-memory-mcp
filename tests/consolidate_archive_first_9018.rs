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
//! #9178 B adds, per cell: the links of an archived source are snapshotted
//! into `archived_memory_links` (and gone from `memory_links`), a namespace
//! standard that names a source is severed with exactly one
//! `substrate.namespace_standard_severed` signed event (the postgres audit
//! anchor), and the tombstone arm leaves links, standard and events alone.
//!
//! The process-wide lineage flags are atomics, so the cells run serially
//! under one lock. The postgres cell runs only when
//! `AI_MEMORY_TEST_POSTGRES_URL` is set and uses its own scratch database.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::models::field_names;
use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
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

/// Raw reads of one backend, outside the SAL (the facts under test).
enum Probe {
    Sqlite(std::path::PathBuf),
    #[cfg(feature = "sal-postgres")]
    Pg(sqlx::PgPool),
}

/// `(source_id, target_id, relation)` rows of a link table touching `ids`.
type LinkRows = Vec<(String, String, String)>;

// Without `sal-postgres` only the synchronous SQLite arm is compiled, so the
// three raw readers have no `.await`; they stay `async` for the postgres arm.
#[cfg_attr(
    not(feature = "sal-postgres"),
    allow(clippy::unused_async, clippy::unused_async_trait_impl)
)]
impl Probe {
    /// Whether `id` is still a row in `memories`.
    async fn live(&self, id: &str) -> bool {
        self.scalar_i64("SELECT COUNT(*) FROM memories WHERE id = ", id)
            .await
            > 0
    }

    /// Signed `substrate.namespace_standard_severed` events (the audit anchor
    /// of the sever).
    async fn severed_events(&self) -> i64 {
        self.scalar_i64(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ",
            ai_memory::signed_events::event_types::SUBSTRATE_NAMESPACE_STANDARD_SEVERED,
        )
        .await
    }

    async fn scalar_i64(&self, prefix: &str, arg: &str) -> i64 {
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("open raw");
                conn.query_row(&format!("{prefix}?1"), [arg], |r| r.get::<_, i64>(0))
                    .expect("raw count")
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => sqlx::query_scalar::<_, i64>(&format!("{prefix}$1"))
                .bind(arg)
                .fetch_one(pool)
                .await
                .expect("raw count"),
        }
    }

    /// `namespace_meta.standard_id` of `ns` (`None` = no meta row).
    async fn standard_of(&self, ns: &str) -> Option<Option<String>> {
        const SQL: &str = "SELECT standard_id FROM namespace_meta WHERE namespace = ";
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("open raw");
                let mut stmt = conn.prepare(&format!("{SQL}?1")).expect("prepare");
                let mut rows = stmt
                    .query_map([ns], |r| r.get::<_, Option<String>>(0))
                    .expect("query");
                rows.next().map(|r| r.expect("row"))
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => sqlx::query_scalar::<_, Option<String>>(&format!("{SQL}$1"))
                .bind(ns)
                .fetch_optional(pool)
                .await
                .expect("standard row"),
        }
    }

    /// The rows of `table` that touch any id in `ids`, sorted.
    async fn link_rows(&self, table: &str, ids: &[String]) -> LinkRows {
        let sql = format!("SELECT source_id, target_id, relation FROM {table}");
        let mut all: LinkRows = match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("open raw");
                let mut stmt = conn.prepare(&sql).expect("prepare");
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .expect("query")
                    .map(|r| r.expect("row"))
                    .collect()
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => sqlx::query_as::<_, (String, String, String)>(&sql)
                .fetch_all(pool)
                .await
                .expect("link rows"),
        };
        all.retain(|(s, t, _)| ids.contains(s) || ids.contains(t));
        all.sort();
        all
    }
}

fn link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: SEED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(SEED_AT.to_string()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Seed sources (one link between the first two, the first bound as the
/// namespace standard), consolidate them, and assert every source is still a
/// live row or an archive row carrying its text, its links snapshotted and its
/// standard binding severed under a signed audit event.
async fn run_cell<S>(store: &S, tombstone: bool, probe: &Probe)
where
    S: MemoryStore + ?Sized,
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
        .link(&ctx, &link(&ids[0], &ids[1]))
        .await
        .expect("seed link");
    store
        .set_namespace_standard(&ctx, &ns, &ids[0], None)
        .await
        .expect("bind the first source as the namespace standard");
    let seeded_link = vec![(
        ids[0].clone(),
        ids[1].clone(),
        MemoryLinkRelation::RelatedTo.as_str().to_string(),
    )];
    assert_eq!(probe.link_rows("memory_links", &ids).await, seeded_link);
    let severed_before = probe.severed_events().await;
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
    let archived_links = probe.link_rows("archived_memory_links", &ids).await;
    let standard = probe.standard_of(&ns).await;
    let severed = probe.severed_events().await - severed_before;
    if tombstone {
        for id in &ids {
            assert!(
                probe.live(id).await,
                "tombstone ON keeps source {id} as a row"
            );
        }
        assert_eq!(archived_links, LinkRows::new(), "no source was archived");
        assert_eq!(
            standard,
            Some(Some(ids[0].clone())),
            "a live standard stays bound"
        );
        assert_eq!(severed, 0, "nothing severed");
        set_tombstoning(false);
        return;
    }
    for (n, id) in ids.iter().enumerate() {
        assert!(
            !probe.live(id).await,
            "legacy disposition removes source {id} from memories"
        );
        let row = archived
            .iter()
            .find(|r| r["id"] == id.as_str())
            .unwrap_or_else(|| panic!("source {id} hard-deleted with no archive row"));
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
    // #9178 B: the cascade reaped the live edge, so the snapshot is the only
    // copy archive_restore can re-insert.
    assert_eq!(
        archived_links, seeded_link,
        "the source links are snapshotted before the delete"
    );
    assert_eq!(
        probe.link_rows("memory_links", &ids).await,
        LinkRows::new(),
        "the live edge went with its sources"
    );
    assert_eq!(
        standard,
        Some(None),
        "the standard binding is severed, not dangling"
    );
    assert_eq!(
        severed, 1,
        "exactly one signed sever event (the audit anchor)"
    );
    set_tombstoning(false);
}

#[tokio::test]
async fn consolidate_archive_first_9018_sqlite() {
    let _g = FLAG_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("c9018.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open sqlite");
    let probe = Probe::Sqlite(db_path);
    for tombstone in TOMBSTONE_CELLS {
        run_cell(&store, tombstone, &probe).await;
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
    let probe = Probe::Pg(store.pool().clone());
    for tombstone in TOMBSTONE_CELLS {
        run_cell(&store, tombstone, &probe).await;
    }
    store.pool().close().await;
}
