// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared backend oracles for the ordinary library and the separate lib harness.
#![allow(dead_code)]

use super::library as ai_memory;
use ai_memory::models::{CaptureTurnWrite, Memory, Tier, default_metadata};
use chrono::{Duration, Utc};

pub const FAIL_ENV: &str = "AI_MEMORY_TEST_FAIL_BEFORE_SIGNED_COMMIT";
pub const CLOCK_ENV: &str = "AI_MEMORY_TEST_CLOCK_OFFSET_SECS";
pub const PG_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
pub const TARGET_ID: &str = "failure-hook-target-7029";
pub const AGENT: &str = "ai:fi-7029";
pub const NAMESPACE: &str = "fi-7029";
pub const NEEDLE: &str = "clockprobe";
pub const LIMIT: usize = 20;
const EMBEDDING_DIM: usize = 384;
const SPACE: &str = "failure-hook-fixture-space";
const SQL_COUNTS: &str = "SELECT (SELECT COUNT(*) FROM memories), (SELECT COUNT(*) FROM transcript_line_dedup), (SELECT COUNT(*) FROM signed_events)";

pub fn capture_write(id: &str) -> CaptureTurnWrite {
    use sha2::Digest as _;
    let now = Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = AGENT.into();
    metadata["scope"] = "public".into();
    let sha = sha2::Sha256::digest(id.as_bytes()).to_vec();
    CaptureTurnWrite {
        memory: Memory {
            id: id.into(),
            tier: Tier::Long,
            namespace: NAMESPACE.into(),
            title: format!("{NEEDLE} {id}"),
            content: format!("{NEEDLE} {id}"),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata,
            ..Memory::default()
        },
        sha256: sha.clone(),
        host_kind: "claude-code".into(),
        host_session_id: id.into(),
        host_turn_index: 0,
        recovered_at_ms: Utc::now().timestamp_millis(),
        signed_event: ai_memory::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: AGENT.into(),
            event_type: "memory.capture_turn".into(),
            payload_hash: sha,
            signature: None,
            attest_level: "unsigned".into(),
            timestamp: now,
            ..ai_memory::signed_events::SignedEvent::default()
        },
    }
}

pub fn sqlite_counts(conn: &rusqlite::Connection) -> (i64, i64, i64) {
    conn.query_row(SQL_COUNTS, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("snapshot all transaction components")
}

pub fn sqlite_snapshot(conn: &rusqlite::Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "SELECT * FROM memories ORDER BY id",
        "SELECT * FROM transcript_line_dedup ORDER BY sha256",
        "SELECT * FROM signed_events ORDER BY id",
    ]
    .into_iter()
    .map(|sql| {
        let mut query = conn.prepare(sql).expect("snapshot statement");
        let columns = query.column_count();
        query
            .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
            .expect("snapshot rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("snapshot values")
    })
    .collect()
}

pub fn sqlite_capture(conn: &rusqlite::Connection, id: &str, auto: bool) -> Result<(), String> {
    let write = capture_write(id);
    if auto {
        ai_memory::storage::capture_turn_idempotent_auto(
            conn,
            &write.host_session_id,
            &write.memory.content,
            false,
            |index| {
                let mut value = write.clone();
                value.host_turn_index = index;
                Ok(value)
            },
        )
        .map(|_| ())
    } else {
        ai_memory::storage::capture_turn_idempotent(conn, &write, false).map(|_| ())
    }
}

pub fn assert_stamps(created: &str, updated: &str, signed: &str) {
    for stamp in [created, updated, signed] {
        assert_real_stamp(stamp);
    }
}

pub fn assert_real_stamp(stamp: &str) {
    let bound = Duration::minutes(2);
    let actual = chrono::DateTime::parse_from_rfc3339(stamp).expect("timestamp");
    assert!(
        (Utc::now() - actual.with_timezone(&Utc)).abs() < bound,
        "write/signature timestamp must stay on the real clock: {stamp}"
    );
}

fn hard_delete_row() -> Memory {
    let mut memory = capture_write("hard-delete-clock").memory;
    memory.tier = Tier::Short;
    memory.expires_at = Some((Utc::now() - Duration::days(2)).to_rfc3339());
    memory
}

pub fn sqlite_stamps(conn: &rusqlite::Connection, id: &str) {
    let memory = ai_memory::storage::get(conn, id)
        .expect("get")
        .expect("stored memory");
    let signed: String = conn
        .query_row(
            "SELECT timestamp FROM signed_events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("signed timestamp");
    assert_stamps(&memory.created_at, &memory.updated_at, &signed);
}

pub fn clock_rows() -> Vec<(Memory, i64)> {
    let hour = ai_memory::SECS_PER_HOUR;
    let mut rows: Vec<_> = [
        -2 * ai_memory::SECS_PER_DAY,
        -hour / 2,
        hour / 2,
        2 * ai_memory::SECS_PER_DAY,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, expiry)| {
        let mut memory = capture_write(&format!("clock-{index}")).memory;
        memory.tier = Tier::Short;
        memory.expires_at = Some((Utc::now() + Duration::seconds(expiry)).to_rfc3339());
        (memory, expiry)
    })
    .collect();
    rows.push((capture_write("protected-long").memory, i64::MAX));
    rows
}

pub fn expected_ids(rows: &[(Memory, i64)], offset: i64) -> Vec<String> {
    let mut ids: Vec<_> = rows
        .iter()
        .filter(|(_, expiry)| *expiry > offset)
        .map(|(memory, _)| memory.id.clone())
        .collect();
    ids.sort();
    ids
}

pub fn assert_ids(results: Vec<(Memory, f64)>, expected: &[String]) {
    let mut ids: Vec<_> = results.into_iter().map(|(m, _)| m.id).collect();
    ids.sort();
    assert_eq!(ids, expected, "actual TTL selection");
}

pub fn sqlite_clock(offset: i64) {
    // This oracle runs only in an exact, isolated test child. Seed the same
    // process atomic as normal boot, without changing the process environment.
    ai_memory::config::set_append_only(true);
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("private sqlite");
    let rows = clock_rows();
    let embedding = vec![1.0; EMBEDDING_DIM];
    for (memory, _) in &rows {
        ai_memory::storage::insert(&conn, memory).expect("seed clock row");
        ai_memory::storage::set_embedding(&conn, &memory.id, &embedding, SPACE)
            .expect("seed SQLite vector");
    }
    conn.execute(
        "INSERT INTO memory_links (source_id,target_id,relation,created_at,attest_level) VALUES ('clock-0','protected-long','related_to',?1,'unsigned')",
        [Utc::now().to_rfc3339()],
    )
    .expect("seed archived edge");
    let expected = expected_ids(&rows, offset);
    let (results, _) = ai_memory::storage::recall(
        &conn,
        NEEDLE,
        Some(NAMESPACE),
        LIMIT,
        None,
        None,
        None,
        0,
        0,
        None,
        None,
        false,
        None,
        Some(AGENT),
        None,
    )
    .expect("recall");
    assert_ids(results, &expected);
    for (query, vector, space) in [
        (NEEDLE, &[][..], None),
        ("nomatchingkeyword", embedding.as_slice(), Some(SPACE)),
    ] {
        let (results, _) = ai_memory::storage::recall_hybrid(
            &conn,
            query,
            vector,
            Some(NAMESPACE),
            LIMIT,
            None,
            None,
            None,
            None,
            0,
            0,
            None,
            None,
            &ai_memory::config::ResolvedScoring::default(),
            false,
            None,
            Some(AGENT),
            space,
            None,
        )
        .expect("hybrid recall");
        assert_ids(results, &expected);
    }
    let removed = ai_memory::storage::gc(&conn, true).expect("gc");
    assert_eq!(removed, rows.len() - expected.len(), "actual GC count");
    for (memory, _) in &rows {
        assert_eq!(
            ai_memory::storage::get(&conn, &memory.id)
                .expect("post-GC get")
                .is_some(),
            expected.contains(&memory.id),
            "GC survivor {}",
            memory.id
        );
    }
    sqlite_gc_stamps(&conn, removed);
    sqlite_capture(&conn, "healthy-clock-write", false).expect("write under clock offset");
    sqlite_stamps(&conn, "healthy-clock-write");
}

fn sqlite_gc_stamps(conn: &rusqlite::Connection, archived: usize) {
    let doomed = hard_delete_row();
    ai_memory::storage::insert(conn, &doomed).expect("seed hard-delete row");
    assert_eq!(ai_memory::storage::gc(conn, false).expect("hard GC"), 1);
    for (sql, expected) in [
        ("SELECT archived_at FROM archived_memories", archived),
        ("SELECT archived_at FROM archived_memory_links", 1),
        (
            "SELECT forgotten_at FROM forget_tombstones WHERE memory_id='hard-delete-clock'",
            1,
        ),
        (
            "SELECT created_at FROM memory_revisions WHERE kind='EXPIRE'",
            archived + 1,
        ),
    ] {
        let mut query = conn.prepare(sql).expect("GC timestamp query");
        let stamps: Vec<String> = query
            .query_map([], |row| row.get(0))
            .expect("GC timestamps")
            .collect::<Result<_, _>>()
            .expect("timestamp values");
        assert_eq!(stamps.len(), expected, "nonempty GC timestamp evidence");
        for stamp in stamps {
            assert_real_stamp(&stamp);
        }
    }
}

#[cfg(feature = "sal-postgres")]
pub mod pg {
    use super::*;
    use super::ai_memory::store::{CallerContext, Filter, MemoryStore, postgres::PostgresStore};

    /// CREATE succeeds before any tested operation. The owned random database,
    /// not an ambient name/prefix, establishes isolation even with an unsafe URL.
    pub async fn create() -> (sqlx::PgPool, String, PostgresStore) {
        let supplied = std::env::var(PG_ENV).expect("native private PG URL required");
        let mut url = reqwest::Url::parse(&supplied).expect("valid PG URL");
        url.set_path("/postgres");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url.as_str())
            .await
            .expect("PG admin connect");
        let name = format!("ai_memory_hooks_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{name}\" TEMPLATE template0"))
            .execute(&admin)
            .await
            .expect("mint owned database");
        sqlx::query(&format!(
            "COMMENT ON DATABASE \"{name}\" IS 'failure-hook-owned:{name}'"
        ))
        .execute(&admin)
        .await
        .expect("record database ownership");
        assert!(
            !owned(&admin).await,
            "administrative database must be refused"
        );
        url.set_path(&format!("/{name}"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url.as_str())
            .await
            .expect("owned database connect");
        for sql in ["CREATE EXTENSION age", "CREATE EXTENSION vector"] {
            sqlx::query(sql)
                .execute(&pool)
                .await
                .expect("native extension");
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_extension WHERE extname IN ('age','vector')",
        )
        .fetch_one(&pool)
        .await
        .expect("extension evidence");
        assert_eq!(count, 2);
        pool.close().await;
        let store = PostgresStore::connect(url.as_str())
            .await
            .expect("owned store connect");
        assert!(owned(store.pool()).await, "minted ownership evidence");
        (admin, name, store)
    }

    pub async fn owned(pool: &sqlx::PgPool) -> bool {
        sqlx::query_scalar("SELECT COALESCE(shobj_description(oid, 'pg_database') = 'failure-hook-owned:' || datname, false) FROM pg_database WHERE datname = current_database()")
            .fetch_one(pool).await.expect("verify explicit ownership marker")
    }

    pub async fn connect_owned(url: &str) -> PostgresStore {
        let probe = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .expect("ownership probe connection");
        let permitted = owned(&probe).await;
        probe.close().await;
        assert!(
            permitted,
            "refuse unowned database before schema initialization"
        );
        PostgresStore::connect(url)
            .await
            .expect("owned child store")
    }

    pub async fn cleanup(admin: sqlx::PgPool, name: String, store: PostgresStore) {
        store.pool().close().await;
        sqlx::query(&format!("DROP DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .expect("drop only owned database without FORCE");
        admin.close().await;
    }

    /// Join catches assertion panics so the parent can close the pool and drop
    /// the database before propagating a red result (OWNERSHIP-25).
    pub async fn isolated_clock(offset: i64) {
        let (admin, name, store) = create().await;
        let child_store = store.clone();
        let result = tokio::spawn(async move { clock(&child_store, offset).await }).await;
        cleanup(admin, name, store).await;
        result.expect("clock scenario must pass after cleanup");
    }

    pub async fn isolated_capture() {
        let (admin, name, store) = create().await;
        let child_store = store.clone();
        let result = tokio::spawn(async move {
            capture(&child_store, TARGET_ID)
                .await
                .expect("ordinary PG capture");
            assert_eq!(counts(&child_store).await, (1, 1, 1));
            stamps(&child_store, TARGET_ID).await;
        })
        .await;
        cleanup(admin, name, store).await;
        result.expect("capture scenario must pass after cleanup");
    }

    pub async fn counts(store: &PostgresStore) -> (i64, i64, i64) {
        sqlx::query_as(SQL_COUNTS)
            .fetch_one(store.pool())
            .await
            .expect("PG snapshot")
    }

    pub async fn snapshot(store: &PostgresStore) -> Vec<String> {
        let mut snapshot = Vec::new();
        for sql in [
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]') FROM memories t",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY sha256)::text, '[]') FROM transcript_line_dedup t",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text, '[]') FROM signed_events t",
        ] {
            snapshot.push(
                sqlx::query_scalar(sql)
                    .fetch_one(store.pool())
                    .await
                    .expect("full snapshot"),
            );
        }
        snapshot
    }

    pub async fn capture(
        store: &PostgresStore,
        id: &str,
    ) -> Result<(), ai_memory::store::StoreError> {
        store
            .capture_turn_idempotent(&CallerContext::for_agent(AGENT), &capture_write(id))
            .await
            .map(|_| ())
    }

    pub async fn stamps(store: &PostgresStore, id: &str) {
        let memory = store
            .get(&CallerContext::for_agent(AGENT), id)
            .await
            .expect("get");
        let signed: chrono::DateTime<Utc> = sqlx::query_scalar(
            "SELECT timestamp FROM signed_events ORDER BY timestamp DESC LIMIT 1",
        )
        .fetch_one(store.pool())
        .await
        .expect("signed timestamp");
        assert_stamps(&memory.created_at, &memory.updated_at, &signed.to_rfc3339());
    }

    pub async fn clock(store: &PostgresStore, offset: i64) {
        ai_memory::config::set_append_only(true);
        let ctx = CallerContext::for_agent(AGENT);
        let rows = clock_rows();
        let embedding = vec![1.0; EMBEDDING_DIM];
        for (memory, _) in &rows {
            store
                .store_with_embedding(&ctx, memory, Some(&embedding), Some(SPACE))
                .await
                .expect("seed PG clock row");
        }
        sqlx::query("INSERT INTO memory_links (source_id,target_id,relation,created_at,attest_level) VALUES ('clock-0','protected-long','related_to',$1,'unsigned')")
            .bind(Utc::now())
            .execute(store.pool())
            .await
            .expect("seed PG archived edge");
        let expected = expected_ids(&rows, offset);
        let mut filter = Filter::new();
        filter.namespace = Some(NAMESPACE.into());
        filter.limit = LIMIT;
        filter.skip_access_ledger = true;
        assert_ids(
            store
                .recall_hybrid(&ctx, NEEDLE, None, &filter)
                .await
                .expect("PG recall"),
            &expected,
        );
        filter.active_embedding_space = Some(SPACE.into());
        assert_ids(
            store
                .recall_hybrid(&ctx, "nomatchingkeyword", Some(&embedding), &filter)
                .await
                .expect("PG vector recall"),
            &expected,
        );
        let removed = store.run_gc(true).await.expect("PG gc");
        assert_eq!(removed, rows.len() - expected.len());
        for (memory, _) in &rows {
            let present: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id=$1)")
                    .bind(&memory.id)
                    .fetch_one(store.pool())
                    .await
                    .expect("GC survivor");
            assert_eq!(present, expected.contains(&memory.id));
        }
        gc_stamps(store, removed).await;
        capture(store, "healthy-clock-write")
            .await
            .expect("PG write under offset");
        stamps(store, "healthy-clock-write").await;
    }

    async fn gc_stamps(store: &PostgresStore, archived: usize) {
        store
            .store(&CallerContext::for_agent(AGENT), &hard_delete_row())
            .await
            .expect("seed PG hard-delete row");
        assert_eq!(store.run_gc(false).await.expect("PG hard GC"), 1);
        for (sql, expected) in [
            (
                "SELECT archived_at::timestamptz FROM archived_memories",
                archived,
            ),
            ("SELECT archived_at::timestamptz FROM archived_memory_links", 1),
            (
                "SELECT forgotten_at::timestamptz FROM forget_tombstones WHERE memory_id='hard-delete-clock'",
                1,
            ),
            (
                "SELECT created_at::timestamptz FROM memory_revisions WHERE kind='EXPIRE'",
                archived + 1,
            ),
        ] {
            let stamps: Vec<chrono::DateTime<Utc>> = sqlx::query_scalar(sql)
                .fetch_all(store.pool())
                .await
                .expect("PG GC timestamps");
            assert_eq!(stamps.len(), expected, "nonempty PG GC timestamp evidence");
            for stamp in stamps {
                assert_real_stamp(&stamp.to_rfc3339());
            }
        }
    }
}
