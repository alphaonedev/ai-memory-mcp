// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10064 — `ai-memory migrate` must refuse a row sealed at rest at the
//! point of copy, not only at the census.
//!
//! The defect class: a check-then-copy race. The migrate census
//! (`source_census`, #10060) classifies every row through the export page
//! before the copy, but the copy then read the source again through the
//! decrypting paged `list` and wrote each page at once. A row sealed after the
//! census was written to the destination DECRYPTED while the run reported
//! success, and a sealed row inserted after the census was refused only after
//! the other rows had been written.
//!
//! The invariant these cells pin: for every interleaving, a row sealed at the
//! moment the copy reads it refuses the whole run with the exact
//! `SEALED_EXPORT_REFUSED` text, nothing is read into the report, and the
//! destination holds no row and no byte of the sealed plaintext.
//!
//! The race is driven deterministically, with no sleep: `RacingSource` wraps
//! the source store, notices the end of the census (the first export page
//! with no next cursor) and applies its mutation once, just before the
//! post-census read number `fire_at` (a `list` or an export page call).
//! Cells: SQLite -> SQLite for every position and read the mutation can race,
//! and SQLite -> Postgres, Postgres -> SQLite and Postgres -> Postgres; plus a
//! Postgres -> Postgres cell of the plain #10060 census refusal.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ai_memory::export_paging::{ExportCursor, ExportMemoriesPage};
use ai_memory::migrate::{MigrationReport, migrate};
use ai_memory::models::{
    AgentRegistration, ConfidenceSource, LifecycleState, Memory, MemoryKind, MemoryLink, Tier,
};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{
    CallerContext, Capabilities, Filter, MemoryStore, StoreResult, UpdatePatch, VerifyReport,
};

/// Namespace of every seeded row.
const NS: &str = "sealed-migrate-race-10064";

/// Rows seeded per cell.
const ROWS: usize = 6;

/// Migrate batch size: three pages of two.
const BATCH: usize = 2;

/// Id of the sealed row a racing writer inserts after the census.
const INSERTED_ID: &str = "m10064-new";

/// The plaintext a sealed row is sealed from. It must never reach the
/// destination, the report or an error.
const SEALED_MARKER: &str = "sealed migrate race marker 10064 \u{1f512}";

/// Agent id the encryption keypair is minted for.
const KEY_AGENT: &str = "ai:migrate-sealed-race-10064";

/// The exact refusal for one sealed row of `memories` met by the copy,
/// written out here rather than taken from the code under test.
fn expected_copy_refusal(id: &str) -> String {
    format!(
        "source copy refused before any write: SEALED_EXPORT_REFUSED: 1 row(s) of memories \
         are sealed at rest (first id {id}); no export format carries the at-rest envelope, so \
         the export is refused and nothing was written. Move an encrypted store with \
         backup/restore (#10028)"
    )
}

/// The exact #10060 census refusal (the early refusal the census keeps).
/// Only the Postgres census cell uses it.
#[cfg(feature = "sal-postgres")]
fn expected_census_refusal(id: &str) -> String {
    format!(
        "source census refused before any write: SEALED_EXPORT_REFUSED: 1 row(s) of memories \
         are sealed at rest (first id {id}); no export format carries the at-rest envelope, so \
         the export is refused and nothing was written. Move an encrypted store with \
         backup/restore (#10028)"
    )
}

fn row_id(n: usize) -> String {
    format!("m10064-{n}")
}

fn memory_with(id: &str, created: chrono::DateTime<chrono::Utc>) -> Memory {
    let ts = created.to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: format!("title {id}"),
        content: format!("content for {id}"),
        tags: vec!["sealed-migrate-race-10064".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: ts.clone(),
        updated_at: ts,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": KEY_AGENT, "scope": "collective"}),
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

fn memory(n: usize) -> Memory {
    let back = i64::try_from(ROWS - n).unwrap_or(0).saturating_mul(10);
    memory_with(
        &row_id(n),
        chrono::Utc::now() - chrono::Duration::seconds(back),
    )
}

async fn seed(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_agent(KEY_AGENT);
    for n in 0..ROWS {
        store.store(&ctx, &memory(n)).await.expect("seed row");
    }
}

/// The real at-rest envelope of [`SEALED_MARKER`], so a projection that
/// decrypts copies the marker out (the leak the fix closes).
fn sealed_envelope() -> Vec<u8> {
    let _ = ai_memory::identity::test_key_dir::install();
    let kp = ai_memory::encryption::get_or_create_keypair(KEY_AGENT).expect("x25519 keypair");
    ai_memory::encryption::encrypt(SEALED_MARKER, &kp.public)
        .expect("seal marker")
        .to_bytes()
}

/// Where the racing writer seals a row: the source file or the source pool.
enum SourceHandle {
    Sqlite(PathBuf),
    #[cfg(feature = "sal-postgres")]
    Pg(sqlx::PgPool),
}

impl SourceHandle {
    // Without `sal-postgres` only the SQLite arm is compiled and it does not
    // await; the function stays async so both builds share one call shape.
    #[cfg_attr(
        not(feature = "sal-postgres"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn seal(&self, id: &str) {
        match self {
            Self::Sqlite(path) => {
                let conn = rusqlite::Connection::open(path).expect("open source file");
                let changed = conn
                    .execute(
                        "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                        rusqlite::params![sealed_envelope(), id],
                    )
                    .expect("seal a row");
                assert_eq!(changed, 1, "one row sealed");
            }
            #[cfg(feature = "sal-postgres")]
            Self::Pg(pool) => {
                let changed = sqlx::query(
                    "UPDATE memories SET content = '', encrypted_envelope = $1 WHERE id = $2",
                )
                .bind(sealed_envelope())
                .bind(id)
                .execute(pool)
                .await
                .expect("seal a pg row")
                .rows_affected();
                assert_eq!(changed, 1, "one pg row sealed");
            }
        }
    }
}

/// What the racing writer does between the census and the copy.
#[derive(Clone, Debug)]
enum Mutation {
    /// Seal an existing row (case A of the review).
    Seal(String),
    /// Insert a new row and seal it (case B of the review).
    InsertSealed,
}

impl Mutation {
    fn sealed_id(&self) -> String {
        match self {
            Self::Seal(id) => id.clone(),
            Self::InsertSealed => INSERTED_ID.to_string(),
        }
    }
}

/// A source store that seals a row after the census and before the copy
/// read number `fire_at`.
struct RacingSource {
    inner: Box<dyn MemoryStore>,
    handle: SourceHandle,
    mutation: Mutation,
    fire_at: usize,
    census_done: AtomicBool,
    post_census_reads: AtomicUsize,
    fired: AtomicBool,
}

impl RacingSource {
    fn new(
        inner: Box<dyn MemoryStore>,
        handle: SourceHandle,
        mutation: Mutation,
        fire_at: usize,
    ) -> Self {
        Self {
            inner,
            handle,
            mutation,
            fire_at,
            census_done: AtomicBool::new(false),
            post_census_reads: AtomicUsize::new(0),
            fired: AtomicBool::new(false),
        }
    }

    /// Called before every row read: fires the mutation once, before the
    /// post-census read number `fire_at`.
    async fn before_read(&self) {
        if !self.census_done.load(Ordering::SeqCst) {
            return;
        }
        let n = self.post_census_reads.fetch_add(1, Ordering::SeqCst);
        if n == self.fire_at && !self.fired.swap(true, Ordering::SeqCst) {
            match &self.mutation {
                Mutation::Seal(id) => self.handle.seal(id).await,
                Mutation::InsertSealed => {
                    let ctx = CallerContext::for_agent(KEY_AGENT);
                    let row = memory_with(INSERTED_ID, chrono::Utc::now());
                    self.inner
                        .store(&ctx, &row)
                        .await
                        .expect("insert racing row");
                    self.handle.seal(INSERTED_ID).await;
                }
            }
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl MemoryStore for RacingSource {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn store(&self, ctx: &CallerContext, memory: &Memory) -> StoreResult<String> {
        self.inner.store(ctx, memory).await
    }
    async fn get(&self, ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
        self.inner.get(ctx, id).await
    }
    async fn update(&self, ctx: &CallerContext, id: &str, patch: UpdatePatch) -> StoreResult<()> {
        self.inner.update(ctx, id, patch).await
    }
    async fn delete(&self, ctx: &CallerContext, id: &str) -> StoreResult<()> {
        self.inner.delete(ctx, id).await
    }
    async fn list(&self, ctx: &CallerContext, filter: &Filter) -> StoreResult<Vec<Memory>> {
        self.before_read().await;
        self.inner.list(ctx, filter).await
    }
    async fn export_memories_page(
        &self,
        cursor: Option<&ExportCursor>,
        limit: usize,
        as_of: chrono::DateTime<chrono::Utc>,
        namespace: Option<&str>,
    ) -> StoreResult<ExportMemoriesPage> {
        self.before_read().await;
        let page = self
            .inner
            .export_memories_page(cursor, limit, as_of, namespace)
            .await?;
        if page.next_cursor.is_none() {
            self.census_done.store(true, Ordering::SeqCst);
        }
        Ok(page)
    }
    async fn get_embedding_with_space(
        &self,
        ctx: &CallerContext,
        id: &str,
    ) -> StoreResult<Option<(Vec<f32>, Option<String>)>> {
        self.inner.get_embedding_with_space(ctx, id).await
    }
    async fn search(
        &self,
        ctx: &CallerContext,
        query: &str,
        filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        self.inner.search(ctx, query, filter).await
    }
    async fn verify(&self, ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
        self.inner.verify(ctx, id).await
    }
    async fn link(&self, ctx: &CallerContext, link: &MemoryLink) -> StoreResult<()> {
        self.inner.link(ctx, link).await
    }
    async fn list_links(&self, namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
        self.inner.list_links(namespace).await
    }
    async fn register_agent(
        &self,
        ctx: &CallerContext,
        agent: &AgentRegistration,
    ) -> StoreResult<()> {
        self.inner.register_agent(ctx, agent).await
    }
}

async fn admin_rows(store: &dyn MemoryStore) -> Vec<Memory> {
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    store
        .list(&ctx, &Filter::default())
        .await
        .expect("list destination")
}

fn file_holds_marker(path: &Path) -> bool {
    let marker = SEALED_MARKER.as_bytes();
    let mut hit = false;
    for p in [
        path.to_path_buf(),
        path.with_extension("db-wal"),
        PathBuf::from(format!("{}-wal", path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(&p) {
            hit |= bytes.windows(marker.len()).any(|w| w == marker);
        }
    }
    hit
}

/// Exactly one error with the exact text, nothing read or written, and no
/// report text carrying the marker.
fn assert_refused_with(report: &MigrationReport, want: &str, cell: &str) {
    assert_eq!(
        report.errors,
        vec![want.to_string()],
        "{cell}: the run must refuse with the exact sealed-export error"
    );
    assert_eq!(report.memories_read, 0, "{cell}: nothing read");
    assert_eq!(report.memories_written, 0, "{cell}: nothing written");
    assert_eq!(report.links_written, 0, "{cell}: no link written");
    let text = format!("{report:?}");
    assert!(
        !text.contains(SEALED_MARKER),
        "{cell}: the report carried the sealed plaintext"
    );
}

/// The interleavings a SQLite source is driven through: (mutation, fire_at).
/// A row sealed before the read that copies it (position >= 2 * fire_at with
/// pages of two) must refuse; a row inserted after the census lands last in
/// both read orders, so every read the walk makes can race it.
fn sqlite_interleavings() -> Vec<(Mutation, usize)> {
    let mut cells = Vec::new();
    for fire_at in 0..3 {
        for pos in (2 * fire_at)..ROWS {
            cells.push((Mutation::Seal(row_id(pos)), fire_at));
        }
        cells.push((Mutation::InsertSealed, fire_at));
    }
    cells
}

/// SQLite -> SQLite: every interleaving, scoped and unscoped. The run
/// refuses with the exact copy refusal, the destination holds no row and its
/// file no byte of the sealed plaintext.
#[tokio::test]
async fn migrate_refuses_a_row_sealed_after_the_census_sqlite_to_sqlite_10064() {
    for (mutation, fire_at) in sqlite_interleavings() {
        for scope in [None, Some(NS.to_string())] {
            let dir = tempfile::tempdir().expect("tempdir");
            let src_path = dir.path().join("source.db");
            let dst_path = dir.path().join("dest.db");
            let inner = SqliteStore::open(&src_path).expect("open source");
            seed(&inner).await;
            let src = RacingSource::new(
                Box::new(inner),
                SourceHandle::Sqlite(src_path.clone()),
                mutation.clone(),
                fire_at,
            );
            let dst = SqliteStore::open(&dst_path).expect("open destination");
            let cell = format!("sqlite->sqlite {mutation:?} before read {fire_at} scope {scope:?}");

            let report = migrate(&src, &dst, BATCH, scope, false).await;
            assert!(src.fired(), "{cell}: the racing writer never ran");
            assert_refused_with(
                &report,
                &expected_copy_refusal(&mutation.sealed_id()),
                &cell,
            );
            assert!(
                admin_rows(&dst).await.is_empty(),
                "{cell}: destination wrote a row"
            );
            drop(dst);
            assert!(
                !file_holds_marker(&dst_path),
                "{cell}: the destination file holds the sealed plaintext"
            );
        }
    }
}

/// Control: the racing wrapper with a mutation that never fires (it races a
/// read past the end of the walk) migrates every row with no error, so the
/// wrapper itself does not cause the refusal.
#[tokio::test]
async fn racing_wrapper_without_a_race_migrates_every_row_10064() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_path = dir.path().join("source.db");
    let inner = SqliteStore::open(&src_path).expect("open source");
    seed(&inner).await;
    let src = RacingSource::new(
        Box::new(inner),
        SourceHandle::Sqlite(src_path),
        Mutation::Seal(row_id(0)),
        usize::MAX,
    );
    let dst = SqliteStore::open(dir.path().join("dest.db")).expect("open destination");
    let report = migrate(&src, &dst, BATCH, None, false).await;
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    assert_eq!(report.memories_read, 6);
    assert_eq!(report.memories_written, 6);
    let mut got: Vec<String> = admin_rows(&dst).await.into_iter().map(|m| m.id).collect();
    got.sort();
    let want: Vec<String> = [
        "m10064-0", "m10064-1", "m10064-2", "m10064-3", "m10064-4", "m10064-5",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(got, want, "every row landed");
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// The Postgres pairs. Each cell runs in its own scratch database
/// (`common::pg_barrier::ScratchDb`). Self-skips, naming the variable, when
/// `AI_MEMORY_TEST_POSTGRES_URL` is unset (the pattern of
/// `tests/migrate_sealed_10060.rs`).
#[cfg(feature = "sal-postgres")]
mod postgres_cells {
    use super::{
        BATCH, Mutation, NS, RacingSource, SEALED_MARKER, SourceHandle, admin_rows,
        assert_refused_with, expected_census_refusal, expected_copy_refusal, file_holds_marker,
        pg_barrier, row_id, sealed_envelope, seed,
    };
    use ai_memory::migrate::migrate;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::sqlite::SqliteStore;

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_10064mg";

    fn pg_url() -> Option<String> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty());
        if url.is_none() {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        }
        url
    }

    async fn pg_count(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM memories")
            .fetch_one(pg.pool())
            .await
            .expect("count pg rows")
    }

    async fn pg_marker_rows(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM memories WHERE content LIKE '%' || $1 || '%' \
             OR title LIKE '%' || $1 || '%'",
        )
        .bind(SEALED_MARKER)
        .fetch_one(pg.pool())
        .await
        .expect("scan pg rows for the marker")
    }

    async fn scratch_store(url: &str) -> (pg_barrier::ScratchDb, PostgresStore) {
        let scratch = pg_barrier::ScratchDb::create(url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        (scratch, pg)
    }

    /// The Postgres interleavings: one sealed existing row on the second
    /// page, raced before the first and the second copy read, and an
    /// inserted sealed row raced before the first copy read.
    fn pg_interleavings() -> Vec<(Mutation, usize)> {
        vec![
            (Mutation::Seal(row_id(3)), 0),
            (Mutation::Seal(row_id(3)), 1),
            (Mutation::InsertSealed, 0),
        ]
    }

    /// SQLite -> Postgres.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_row_sealed_after_the_census_sqlite_to_postgres_10064() {
        let Some(url) = pg_url() else { return };
        for (mutation, fire_at) in pg_interleavings() {
            let (_scratch, pg) = scratch_store(&url).await;
            let dir = tempfile::tempdir().expect("tempdir");
            let src_path = dir.path().join("source.db");
            let inner = SqliteStore::open(&src_path).expect("open source");
            seed(&inner).await;
            let src = RacingSource::new(
                Box::new(inner),
                SourceHandle::Sqlite(src_path),
                mutation.clone(),
                fire_at,
            );
            let cell = format!("sqlite->postgres {mutation:?} before read {fire_at}");
            let report = migrate(&src, &pg, BATCH, Some(NS.to_string()), false).await;
            assert!(src.fired(), "{cell}: the racing writer never ran");
            assert_refused_with(
                &report,
                &expected_copy_refusal(&mutation.sealed_id()),
                &cell,
            );
            assert_eq!(pg_count(&pg).await, 0, "{cell}: postgres wrote a row");
            assert_eq!(
                pg_marker_rows(&pg).await,
                0,
                "{cell}: plaintext on postgres"
            );
            pg.pool().close().await;
        }
    }

    /// Postgres -> SQLite.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_row_sealed_after_the_census_postgres_to_sqlite_10064() {
        let Some(url) = pg_url() else { return };
        for (mutation, fire_at) in pg_interleavings() {
            let (_scratch, pg) = scratch_store(&url).await;
            seed(&pg).await;
            let pool = pg.pool().clone();
            let src = RacingSource::new(
                Box::new(pg),
                SourceHandle::Pg(pool.clone()),
                mutation.clone(),
                fire_at,
            );
            let dir = tempfile::tempdir().expect("tempdir");
            let dst_path = dir.path().join("dest.db");
            let dst = SqliteStore::open(&dst_path).expect("open destination");
            let cell = format!("postgres->sqlite {mutation:?} before read {fire_at}");
            let report = migrate(&src, &dst, BATCH, None, false).await;
            assert!(src.fired(), "{cell}: the racing writer never ran");
            assert_refused_with(
                &report,
                &expected_copy_refusal(&mutation.sealed_id()),
                &cell,
            );
            assert!(
                admin_rows(&dst).await.is_empty(),
                "{cell}: sqlite wrote a row"
            );
            drop(dst);
            assert!(
                !file_holds_marker(&dst_path),
                "{cell}: the destination file holds the sealed plaintext"
            );
            pool.close().await;
        }
    }

    /// Postgres -> Postgres, the race.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_row_sealed_after_the_census_postgres_to_postgres_10064() {
        let Some(url) = pg_url() else { return };
        for (mutation, fire_at) in pg_interleavings() {
            let (_src_scratch, src_pg) = scratch_store(&url).await;
            let (_dst_scratch, dst_pg) = scratch_store(&url).await;
            seed(&src_pg).await;
            let pool = src_pg.pool().clone();
            let src = RacingSource::new(
                Box::new(src_pg),
                SourceHandle::Pg(pool.clone()),
                mutation.clone(),
                fire_at,
            );
            let cell = format!("postgres->postgres {mutation:?} before read {fire_at}");
            let report = migrate(&src, &dst_pg, BATCH, Some(NS.to_string()), false).await;
            assert!(src.fired(), "{cell}: the racing writer never ran");
            assert_refused_with(
                &report,
                &expected_copy_refusal(&mutation.sealed_id()),
                &cell,
            );
            assert_eq!(pg_count(&dst_pg).await, 0, "{cell}: postgres wrote a row");
            assert_eq!(
                pg_marker_rows(&dst_pg).await,
                0,
                "{cell}: plaintext on postgres"
            );
            pool.close().await;
            dst_pg.pool().close().await;
        }
    }

    /// Postgres -> Postgres, the #10060 census refusal: a row sealed before
    /// the run refuses at the census with nothing written.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_sealed_row_postgres_to_postgres_10064() {
        let Some(url) = pg_url() else { return };
        let (_src_scratch, src_pg) = scratch_store(&url).await;
        let (_dst_scratch, dst_pg) = scratch_store(&url).await;
        seed(&src_pg).await;
        let sealed_id = row_id(2);
        let changed =
            sqlx::query("UPDATE memories SET content = '', encrypted_envelope = $1 WHERE id = $2")
                .bind(sealed_envelope())
                .bind(&sealed_id)
                .execute(src_pg.pool())
                .await
                .expect("seal a pg row")
                .rows_affected();
        assert_eq!(changed, 1, "one pg row sealed");
        let cell = "postgres->postgres sealed before the run";
        for scope in [None, Some(NS.to_string())] {
            let report = migrate(&src_pg, &dst_pg, BATCH, scope, false).await;
            assert_refused_with(&report, &expected_census_refusal(&sealed_id), cell);
        }
        assert_eq!(pg_count(&dst_pg).await, 0, "{cell}: postgres wrote a row");
        assert_eq!(
            pg_marker_rows(&dst_pg).await,
            0,
            "{cell}: plaintext on postgres"
        );
        src_pg.pool().close().await;
        dst_pg.pool().close().await;
    }
}
