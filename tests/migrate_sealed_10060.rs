// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10060 — `ai-memory migrate` must never copy a row sealed at rest
//! out as plaintext and must never drop it.
//!
//! The defect: the migrate memory phase read the source through the paged
//! `list`, whose row projection decrypts a sealed row through the key (the
//! plaintext then landed on the destination) or skips the row it cannot open
//! (the row silently vanished from the migrated copy while the report said
//! success). No migrate format carries the at-rest envelope, so the only
//! correct answer is to refuse the whole run with `SEALED_EXPORT_REFUSED`
//! before the first destination write (decision recorded on #10028: refuse
//! rather than carry the envelope; #10056 tracks carrying it).
//!
//! Every cell is the reviewer's probe: 6 rows, batch size 2, one row sealed,
//! for every position of the sealed row (so the refusal cannot depend on the
//! page the sealed row falls on). The SQLite cell runs SQLite -> SQLite; the
//! Postgres cells run SQLite -> Postgres and Postgres -> SQLite (both
//! directions). A control cell proves a store with encryption off migrates
//! exactly as before.

#![cfg(feature = "sal")]
#![allow(clippy::doc_markdown)]

use ai_memory::migrate::{migrate, plan};
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

/// Namespace of every seeded row.
const NS: &str = "sealed-migrate-10060";

/// Rows seeded per cell (the reviewer's probe).
const ROWS: usize = 6;

/// Migrate batch size (the reviewer's probe): three pages of two.
const BATCH: usize = 2;

/// The plaintext a sealed row is sealed from. It must never reach the
/// destination, the report or an error.
const SEALED_MARKER: &str = "sealed migrate marker 10060 \u{1f512}";

/// Agent id the encryption keypair is minted for.
const KEY_AGENT: &str = "ai:migrate-sealed-10060";

/// The exact refusal for one sealed row of `memories`, written out here
/// rather than taken from the code under test.
fn expected_refusal(id: &str) -> String {
    format!(
        "source census refused before any write: SEALED_EXPORT_REFUSED: 1 row(s) of memories \
         are sealed at rest (first id {id}); no export format carries the at-rest envelope, so \
         the export is refused and nothing was written. Move an encrypted store with \
         backup/restore (#10028)"
    )
}

fn row_id(n: usize) -> String {
    format!("m10060-{n}")
}

fn memory(n: usize) -> Memory {
    let ts = (chrono::Utc::now() - chrono::Duration::seconds(i64::try_from(ROWS - n).unwrap_or(0)))
        .to_rfc3339();
    let id = row_id(n);
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.clone(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: format!("title {id}"),
        content: format!("content for {id}"),
        tags: vec!["sealed-migrate-10060".to_string()],
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

async fn seed(store: &dyn MemoryStore) {
    let ctx = CallerContext::for_agent(KEY_AGENT);
    for n in 0..ROWS {
        store.store(&ctx, &memory(n)).await.expect("seed row");
    }
}

/// The real at-rest envelope of [`SEALED_MARKER`], so a projection that
/// decrypts would copy the marker out (the leak the census closes).
fn sealed_envelope() -> Vec<u8> {
    let _ = ai_memory::identity::test_key_dir::install();
    let kp = ai_memory::encryption::get_or_create_keypair(KEY_AGENT).expect("x25519 keypair");
    ai_memory::encryption::encrypt(SEALED_MARKER, &kp.public)
        .expect("seal marker")
        .to_bytes()
}

fn seal_sqlite_row(path: &std::path::Path, id: &str) {
    let conn = rusqlite::Connection::open(path).expect("open source file");
    let changed = conn
        .execute(
            "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
            rusqlite::params![sealed_envelope(), id],
        )
        .expect("seal a row");
    assert_eq!(changed, 1, "one row sealed");
}

async fn admin_rows(store: &dyn MemoryStore) -> Vec<Memory> {
    let ctx = CallerContext::for_admin(ai_memory::identity::sentinels::AI_MIGRATE);
    store
        .list(&ctx, &Filter::default())
        .await
        .expect("list destination")
}

fn file_holds_marker(path: &std::path::Path) -> bool {
    let marker = SEALED_MARKER.as_bytes();
    let mut hit = false;
    for p in [
        path.to_path_buf(),
        path.with_extension("db-wal"),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
    ] {
        if let Ok(bytes) = std::fs::read(&p) {
            hit |= bytes.windows(marker.len()).any(|w| w == marker);
        }
    }
    hit
}

/// Assert the refusal report: exactly one error, the exact refusal, nothing
/// read or written, and no report text carrying the marker.
fn assert_refused(report: &ai_memory::migrate::MigrationReport, sealed: &str, cell: &str) {
    assert_eq!(
        report.errors,
        vec![expected_refusal(sealed)],
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

/// SQLite -> SQLite, every position of the sealed row: the run (and its dry
/// run) refuses with the exact error, the destination holds no row and no
/// byte of the sealed plaintext.
#[tokio::test]
async fn migrate_refuses_a_sealed_row_sqlite_to_sqlite_10060() {
    for sealed in 0..ROWS {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("source.db");
        let dst_path = dir.path().join("dest.db");
        let src = SqliteStore::open(&src_path).expect("open source");
        let dst = SqliteStore::open(&dst_path).expect("open destination");
        seed(&src).await;
        let sealed_id = row_id(sealed);
        seal_sqlite_row(&src_path, &sealed_id);
        let cell = format!("sqlite->sqlite sealed position {sealed}");

        let planned = plan(&src, BATCH, None).await;
        assert_refused(&planned, &sealed_id, &format!("{cell} (dry run)"));
        let scoped = migrate(&src, &dst, BATCH, Some(NS.to_string()), false).await;
        assert_refused(&scoped, &sealed_id, &format!("{cell} (scoped)"));
        let report = migrate(&src, &dst, BATCH, None, false).await;
        assert_refused(&report, &sealed_id, &cell);

        assert!(
            admin_rows(&dst).await.is_empty(),
            "{cell}: destination wrote a row"
        );
        drop(dst);
        assert!(
            !file_holds_marker(&dst_path),
            "{cell}: the destination file holds the sealed plaintext"
        );
        // The source is untouched: the sealed row still holds its envelope.
        let conn = rusqlite::Connection::open(&src_path).expect("reopen source");
        let still_sealed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE encrypted_envelope IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .expect("count sealed");
        assert_eq!(still_sealed, 1, "{cell}: the source sealed row changed");
    }
}

/// Control: with encryption off (no sealed row) the same probe migrates every
/// row with no error, exactly as before the census.
#[tokio::test]
async fn migrate_of_an_unsealed_store_is_unchanged_10060() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = SqliteStore::open(dir.path().join("source.db")).expect("open source");
    let dst = SqliteStore::open(dir.path().join("dest.db")).expect("open destination");
    seed(&src).await;
    let report = migrate(&src, &dst, BATCH, None, false).await;
    assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    assert_eq!(report.memories_read, ROWS);
    assert_eq!(report.memories_written, ROWS);
    let mut got: Vec<String> = admin_rows(&dst).await.into_iter().map(|m| m.id).collect();
    got.sort();
    let want: Vec<String> = (0..ROWS).map(row_id).collect();
    assert_eq!(got, want, "every row landed");
}

/// #10064 (security review r1 F2) — a namespace outside every scope below.
const OTHER_NS: &str = "sealed-migrate-10064-other";

/// #10064 F2 — the canonical inbox namespace of one agent, and its legacy
/// alias, written out rather than built from the crate constants.
const INBOX_NS: &str = "_inbox/ai:scope-10064";
const LEGACY_INBOX_NS: &str = "_messages/ai:scope-10064";

/// #10064 F2 — the ids of the scope rows.
const OTHER_ID: &str = "m10064-other";
const INBOX_ID: &str = "m10064-inbox";
const LEGACY_ID: &str = "m10064-legacy";

/// #10064 F2 — the base rows plus one row in [`OTHER_NS`], one in
/// [`INBOX_NS`] and one in its legacy alias [`LEGACY_INBOX_NS`].
async fn seed_scope(store: &dyn MemoryStore) {
    seed(store).await;
    let ctx = CallerContext::for_agent(KEY_AGENT);
    for (id, ns) in [
        (OTHER_ID, OTHER_NS),
        (INBOX_ID, INBOX_NS),
        (LEGACY_ID, LEGACY_INBOX_NS),
    ] {
        let mut mem = memory(0);
        mem.id = id.to_string();
        mem.namespace = ns.to_string();
        mem.title = format!("title {id}");
        mem.content = format!("content for {id}");
        store.store(&ctx, &mem).await.expect("seed scope row");
    }
}

/// Migrate `scope` from `src` into a fresh SQLite destination and return the
/// report and the sorted ids that landed.
async fn migrate_scope(
    src: &dyn MemoryStore,
    scope: Option<&str>,
) -> (ai_memory::migrate::MigrationReport, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = SqliteStore::open(dir.path().join("dest.db")).expect("open destination");
    let report = migrate(src, &dst, BATCH, scope.map(str::to_string), false).await;
    let mut got: Vec<String> = admin_rows(&dst).await.into_iter().map(|m| m.id).collect();
    got.sort();
    (report, got)
}

/// #10064 F2, the unsealed half: a scoped run copies exactly its scope, and
/// a canonical inbox scope includes its legacy alias.
async fn assert_scope_unsealed(src: &dyn MemoryStore, cell: &str) {
    let (report, got) = migrate_scope(src, Some(INBOX_NS)).await;
    assert!(report.errors.is_empty(), "{cell}: {:?}", report.errors);
    assert_eq!(
        got,
        vec![INBOX_ID.to_string(), LEGACY_ID.to_string()],
        "{cell}: an inbox scope copies the inbox and its legacy alias"
    );
    let (report, got) = migrate_scope(src, Some(NS)).await;
    assert!(report.errors.is_empty(), "{cell}: {:?}", report.errors);
    let want: Vec<String> = (0..ROWS).map(row_id).collect();
    assert_eq!(got, want, "{cell}: a namespace scope copies only its rows");
}

/// #10064 F2, with [`OTHER_ID`] sealed: a run scoped elsewhere is not refused
/// by it and copies its scope; the store-wide run is refused naming it.
async fn assert_scope_sealed_outside(src: &dyn MemoryStore, cell: &str) {
    let (report, got) = migrate_scope(src, Some(NS)).await;
    assert!(
        report.errors.is_empty(),
        "{cell}: a sealed row outside the scope refused it: {:?}",
        report.errors
    );
    let want: Vec<String> = (0..ROWS).map(row_id).collect();
    assert_eq!(got, want, "{cell}: the scope copied");
    let (report, got) = migrate_scope(src, Some(INBOX_NS)).await;
    assert!(report.errors.is_empty(), "{cell}: {:?}", report.errors);
    assert_eq!(
        got,
        vec![INBOX_ID.to_string(), LEGACY_ID.to_string()],
        "{cell}: the inbox scope copied"
    );
    let planned = plan(src, BATCH, None).await;
    assert_refused(&planned, OTHER_ID, &format!("{cell} (store-wide)"));
}

/// #10064 F2, with [`LEGACY_ID`] sealed as well: the canonical inbox scope
/// is refused naming the legacy-alias row, and nothing lands.
async fn assert_scope_sealed_alias(src: &dyn MemoryStore, cell: &str) {
    let (report, got) = migrate_scope(src, Some(INBOX_NS)).await;
    assert_refused(&report, LEGACY_ID, &format!("{cell} (inbox scope)"));
    assert!(got.is_empty(), "{cell}: the inbox scope wrote a row");
}

/// #10064 F2, SQLite: the census, the copy walk and the cap cover exactly the
/// migrate scope, including the legacy inbox alias.
#[tokio::test]
async fn migrate_scope_is_exactly_the_namespace_and_its_inbox_alias_sqlite_10064() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_path = dir.path().join("source.db");
    let src = SqliteStore::open(&src_path).expect("open source");
    seed_scope(&src).await;
    assert_scope_unsealed(&src, "sqlite").await;
    seal_sqlite_row(&src_path, OTHER_ID);
    assert_scope_sealed_outside(&src, "sqlite").await;
    seal_sqlite_row(&src_path, LEGACY_ID);
    assert_scope_sealed_alias(&src, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// The Postgres directions. Each cell runs in its own scratch database
/// (`common::pg_barrier::ScratchDb`), so no other cell's rows are visible.
/// Self-skips, naming the variable, when `AI_MEMORY_TEST_POSTGRES_URL` is
/// unset (the pattern of `tests/migrate_links_roundtrip.rs`).
#[cfg(feature = "sal-postgres")]
mod postgres_cells {
    use super::{
        BATCH, LEGACY_ID, NS, OTHER_ID, ROWS, SEALED_MARKER, admin_rows, assert_refused,
        assert_scope_sealed_alias, assert_scope_sealed_outside, assert_scope_unsealed,
        file_holds_marker, pg_barrier, row_id, seal_sqlite_row, sealed_envelope, seed, seed_scope,
    };

    /// Seal one Postgres row in place with the real envelope.
    async fn seal_pg_row(pg: &PostgresStore, id: &str) {
        let changed =
            sqlx::query("UPDATE memories SET content = '', encrypted_envelope = $1 WHERE id = $2")
                .bind(sealed_envelope())
                .bind(id)
                .execute(pg.pool())
                .await
                .expect("seal a pg row")
                .rows_affected();
        assert_eq!(changed, 1, "one pg row sealed");
    }

    /// #10064 F2, Postgres source: the same scope cells as the SQLite cell.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_scope_is_exactly_the_namespace_and_its_inbox_alias_postgres_10064() {
        let Some(url) = pg_url() else { return };
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        seed_scope(&pg).await;
        assert_scope_unsealed(&pg, "postgres").await;
        seal_pg_row(&pg, OTHER_ID).await;
        assert_scope_sealed_outside(&pg, "postgres").await;
        seal_pg_row(&pg, LEGACY_ID).await;
        assert_scope_sealed_alias(&pg, "postgres").await;
        pg.pool().close().await;
    }
    use ai_memory::migrate::{migrate, plan};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::sqlite::SqliteStore;

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_10060mg";

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

    /// SQLite -> Postgres, every position of the sealed row.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_sealed_row_sqlite_to_postgres_10060() {
        let Some(url) = pg_url() else { return };
        for sealed in 0..ROWS {
            let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
                .await
                .expect("create scratch database");
            let pg = PostgresStore::connect(&scratch.url())
                .await
                .expect("connect scratch database");
            let dir = tempfile::tempdir().expect("tempdir");
            let src_path = dir.path().join("source.db");
            let src = SqliteStore::open(&src_path).expect("open source");
            seed(&src).await;
            let sealed_id = row_id(sealed);
            seal_sqlite_row(&src_path, &sealed_id);
            let cell = format!("sqlite->postgres sealed position {sealed}");

            let report = migrate(&src, &pg, BATCH, Some(NS.to_string()), false).await;
            assert_refused(&report, &sealed_id, &cell);
            assert_eq!(pg_count(&pg).await, 0, "{cell}: postgres wrote a row");
            assert_eq!(
                pg_marker_rows(&pg).await,
                0,
                "{cell}: plaintext on postgres"
            );
            pg.pool().close().await;
        }
    }

    /// Postgres -> SQLite, every position of the sealed row.
    #[tokio::test(flavor = "multi_thread")]
    async fn migrate_refuses_a_sealed_row_postgres_to_sqlite_10060() {
        let Some(url) = pg_url() else { return };
        for sealed in 0..ROWS {
            let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
                .await
                .expect("create scratch database");
            let pg = PostgresStore::connect(&scratch.url())
                .await
                .expect("connect scratch database");
            seed(&pg).await;
            let sealed_id = row_id(sealed);
            let changed = sqlx::query(
                "UPDATE memories SET content = '', encrypted_envelope = $1 WHERE id = $2",
            )
            .bind(sealed_envelope())
            .bind(&sealed_id)
            .execute(pg.pool())
            .await
            .expect("seal a pg row")
            .rows_affected();
            assert_eq!(changed, 1, "one pg row sealed");
            let dir = tempfile::tempdir().expect("tempdir");
            let dst_path = dir.path().join("dest.db");
            let dst = SqliteStore::open(&dst_path).expect("open destination");
            let cell = format!("postgres->sqlite sealed position {sealed}");

            let planned = plan(&pg, BATCH, None).await;
            assert_refused(&planned, &sealed_id, &format!("{cell} (dry run)"));
            let report = migrate(&pg, &dst, BATCH, Some(NS.to_string()), false).await;
            assert_refused(&report, &sealed_id, &cell);
            assert!(
                admin_rows(&dst).await.is_empty(),
                "{cell}: sqlite wrote a row"
            );
            drop(dst);
            assert!(
                !file_holds_marker(&dst_path),
                "{cell}: the destination file holds the sealed plaintext"
            );
            pg.pool().close().await;
        }
    }
}
