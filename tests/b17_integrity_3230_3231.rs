// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! B17 BRANCH 1 integrity regressions.
//!
//! - `#3230` PATCH `expires_at` on a stored-LONG row must NOT arm GC
//!   (effective-tier CASE, sqlite + postgres).
//! - `#3231` `capture_turn` same `(host_session_id, host_turn_index)` is
//!   first-write-wins (in-tx dedup re-probe); a second write with
//!   different content must not clobber the surviving row.

use ai_memory::db;
use ai_memory::models::{CaptureTurnWrite, Memory, Tier, default_metadata};
use ai_memory::signed_events::SignedEvent;

fn open() -> rusqlite::Connection {
    db::open(std::path::Path::new(":memory:")).expect("open")
}

fn seed_long(conn: &rusqlite::Connection, title: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String("ai:b17-3230".into());
    db::insert(
        conn,
        &Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "b17-3230".into(),
            title: title.into(),
            content: "permanent".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Memory::default()
        },
    )
    .expect("insert long")
}

/// #3230 — sqlite twin: a metadata/expiry patch that does NOT change
/// tier must keep a stored-LONG row's `expires_at` NULL.
#[test]
fn sqlite_patch_expires_at_on_stored_long_stays_null_3230() {
    let conn = open();
    let id = seed_long(&conn, "long-sticky");
    let before = db::get(&conn, &id).expect("get").expect("present");
    assert!(
        before.expires_at.is_none(),
        "long insert must land with NULL expiry"
    );

    db::update(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("2099-01-01T00:00:00+00:00"),
        None,
    )
    .expect("patch expires_at");

    let after = db::get(&conn, &id).expect("get").expect("present");
    assert_eq!(after.tier, Tier::Long);
    assert!(
        after.expires_at.is_none(),
        "#3230: PATCH expires_at on stored-LONG must stay NULL, got {:?}",
        after.expires_at
    );
}

fn capture_write(
    session: &str,
    turn: i64,
    title: &str,
    content: &str,
    sha_tag: &str,
) -> CaptureTurnWrite {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String("ai:b17-3231".into());
    let sha = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(sha_tag.as_bytes());
        h.finalize().to_vec()
    };
    CaptureTurnWrite {
        memory: Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "b17-3231".into(),
            title: title.into(),
            content: content.into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata,
            ..Memory::default()
        },
        sha256: sha.clone(),
        host_kind: "claude-code".into(),
        host_session_id: session.into(),
        host_turn_index: turn,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event: SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "ai:b17-3231".into(),
            event_type: "memory.capture_turn".into(),
            payload_hash: sha,
            signature: None,
            attest_level: "unsigned".into(),
            timestamp: now,
            ..SignedEvent::default()
        },
    }
}

/// #3231 — sequential same-(session, turn) capture with different
/// content/sha must return the first memory and leave its content
/// byte-identical (first-write-wins).
///
/// This pins the happy-path contract. It does NOT exercise the in-tx
/// re-probe: the out-of-tx fast-path already hits after the first
/// commit. See `sqlite_capture_turn_concurrent_same_session_turn_fww_3231`.
#[test]
fn sqlite_capture_turn_same_session_turn_is_first_write_wins_3231() {
    let conn = open();
    let session = uuid::Uuid::new_v4().to_string();
    let title = format!("turn-{session}-0");
    let first = capture_write(&session, 0, &title, "first-content", "sha-a");
    let first_id = first.memory.id.clone();
    let r1 = db::capture_turn_idempotent(&conn, &first, true).expect("first");
    assert!(!r1.dedup_hit);
    assert_eq!(r1.memory_id, first_id);

    let second = capture_write(&session, 0, &title, "second-content", "sha-b");
    let r2 = db::capture_turn_idempotent(&conn, &second, true).expect("second");
    assert!(r2.dedup_hit, "same (session, turn) must be a dedup hit");
    assert_eq!(r2.memory_id, first_id);

    let got = db::get(&conn, &first_id).expect("get").expect("present");
    assert_eq!(
        got.content, "first-content",
        "#3231: second capture must not last-write-wins overwrite"
    );
}

/// #3231 — two connections racing the same `(session, turn)` with
/// different sha256. Both miss the out-of-tx fast-path (neither has
/// committed yet); `BEGIN IMMEDIATE` serializes; the loser's in-tx
/// re-probe must return the first writer's `memory_id` and content.
///
/// Pre-fix this test fails: the waiter takes the insert path, ON CONFLICT
/// LWW-overwrites content, and both results report `dedup_hit: false`.
#[test]
fn sqlite_capture_turn_concurrent_same_session_turn_fww_3231() {
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("c3231.db");
    // Bootstrap the ladder on ONE connection first. Two racing `db::open`
    // calls fight the schema-version stamp (SQLITE_BUSY / "database is
    // locked") and never reach capture_turn.
    let boot = db::open(&path).expect("bootstrap");
    drop(boot);
    let conn_a = db::open(&path).expect("open a");
    let conn_b = db::open(&path).expect("open b");
    conn_a
        .busy_timeout(Duration::from_secs(10))
        .expect("busy a");
    conn_b
        .busy_timeout(Duration::from_secs(10))
        .expect("busy b");

    let session = uuid::Uuid::new_v4().to_string();
    let title = format!("turn-{session}-0");
    let write_a = capture_write(&session, 0, &title, "content-a", "sha-a-race");
    let write_b = capture_write(&session, 0, &title, "content-b", "sha-b-race");
    let barrier = Arc::new(Barrier::new(2));

    let b_a = Arc::clone(&barrier);
    let b_b = Arc::clone(&barrier);
    let handle_a = std::thread::spawn(move || {
        b_a.wait();
        db::capture_turn_idempotent(&conn_a, &write_a, true)
    });
    let handle_b = std::thread::spawn(move || {
        b_b.wait();
        db::capture_turn_idempotent(&conn_b, &write_b, true)
    });

    let r_a = handle_a.join().expect("join a").expect("capture a");
    let r_b = handle_b.join().expect("join b").expect("capture b");
    assert_eq!(r_a.memory_id, r_b.memory_id, "same (session, turn) one row");
    assert!(
        r_a.dedup_hit ^ r_b.dedup_hit,
        "exactly one writer must miss (in-tx re-probe); got a.dedup_hit={} b.dedup_hit={}",
        r_a.dedup_hit,
        r_b.dedup_hit
    );
    let expected = if r_a.dedup_hit {
        "content-b"
    } else {
        "content-a"
    };
    let conn = db::open(&path).expect("reopen");
    let got = db::get(&conn, &r_a.memory_id)
        .expect("get")
        .expect("present");
    assert_eq!(
        got.content, expected,
        "#3231 concurrent: first writer's content must survive (LWW would clobber)"
    );
}

/// #3250 follow-up / #1772: `forget_for_caller` archive-links
/// `source_id` subquery must keep namespace+tier+owner grouping.
/// A premature `)` after `agent_id = ?4` made AND bind tighter than OR
/// so unowned rows in OTHER namespaces were snapshotted.
#[test]
fn forget_for_caller_archive_links_source_id_respects_owner_scope() {
    use ai_memory::models::MemoryLinkRelation;
    use rusqlite::params;

    let conn = open();
    let now = chrono::Utc::now().to_rfc3339();
    let unowned = || {
        let mut m = default_metadata();
        m["agent_id"] = serde_json::Value::String(String::new());
        m
    };
    let seed = |title: &str, ns: &str| {
        db::insert(
            &conn,
            &Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: ns.into(),
                title: title.into(),
                content: title.into(),
                created_at: now.clone(),
                updated_at: now.clone(),
                metadata: unowned(),
                ..Memory::default()
            },
        )
        .expect("seed")
    };
    let a = seed("scope-a", "ns-a");
    let a2 = seed("scope-a2", "ns-a");
    let c = seed("scope-c", "ns-b");
    let d = seed("scope-d", "ns-b");
    db::create_link(&conn, &a, &a2, MemoryLinkRelation::RelatedTo.as_str()).expect("link a");
    db::create_link(&conn, &c, &d, MemoryLinkRelation::RelatedTo.as_str()).expect("link c");

    db::forget_for_caller(&conn, Some("ns-a"), None, None, true, "ai:alice").expect("forget ns-a");

    let leaked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memory_links \
             WHERE source_id = ?1 OR target_id = ?1",
            params![&c],
            |r| r.get(0),
        )
        .expect("count leaked");
    assert_eq!(
        leaked, 0,
        "ns-b unowned edge must NOT be snapshotted by ns-a forget_for_caller \
         (source_id owner-group paren)"
    );
    let kept: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM archived_memory_links \
             WHERE source_id = ?1 OR target_id = ?1",
            params![&a],
            |r| r.get(0),
        )
        .expect("count kept");
    assert!(
        kept > 0,
        "ns-a unowned edge must still be snapshotted (got {kept})"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    /// #3230 — postgres trait `update` (no If-Match) PATCH `expires_at` on
    /// stored-LONG must keep expiry NULL.
    #[tokio::test]
    async fn pg_patch_expires_at_on_stored_long_stays_null_3230() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let unique = uuid::Uuid::new_v4();
        let ns = format!("b17-3230-{unique}");
        let mem = Memory {
            id: format!("3230-{unique}"),
            tier: Tier::Long,
            namespace: ns,
            title: format!("long-{unique}"),
            content: "permanent".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: serde_json::json!({ "agent_id": "ai:sal-test" }),
            ..Memory::default()
        };
        let id = store.store(&ctx, &mem).await.expect("store");
        let before = store.get(&ctx, &id).await.expect("get");
        assert!(before.expires_at.is_none());

        store
            .update(
                &ctx,
                &id,
                UpdatePatch {
                    expires_at: Some("2099-01-01T00:00:00+00:00".into()),
                    ..UpdatePatch::default()
                },
            )
            .await
            .expect("patch");
        let after = store.get(&ctx, &id).await.expect("get after");
        assert_eq!(after.tier, Tier::Long);
        assert!(
            after.expires_at.is_none(),
            "#3230 pg trait update: stored-LONG PATCH expires_at must stay NULL, got {:?}",
            after.expires_at
        );

        store
            .update_with_expected_version(
                &ctx,
                &id,
                UpdatePatch {
                    expires_at: Some("2099-06-01T00:00:00+00:00".into()),
                    ..UpdatePatch::default()
                },
                Some(after.version),
            )
            .await
            .expect("if-match patch");
        let after2 = store.get(&ctx, &id).await.expect("get if-match");
        assert!(
            after2.expires_at.is_none(),
            "#3230 pg If-Match: stored-LONG PATCH expires_at must stay NULL, got {:?}",
            after2.expires_at
        );
        let _ = store.delete(&ctx, &id).await;
    }

    /// #3231 — postgres `capture_turn` same (session, turn) is FWW.
    #[tokio::test]
    async fn pg_capture_turn_same_session_turn_is_first_write_wins_3231() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let unique = uuid::Uuid::new_v4();
        let session = format!("sess-{unique}");
        let title = format!("turn-{unique}-0");
        let first = {
            let mut w = capture_write(
                &session,
                0,
                &title,
                "first-content",
                &format!("sha-a-{unique}"),
            );
            w.memory.namespace = format!("b17-3231-{unique}");
            w.memory.metadata = serde_json::json!({ "agent_id": "ai:sal-test" });
            w
        };
        let r1 = store
            .capture_turn_idempotent(&ctx, &first)
            .await
            .expect("first");
        assert!(!r1.dedup_hit);

        let second = {
            let mut w = capture_write(
                &session,
                0,
                &title,
                "second-content",
                &format!("sha-b-{unique}"),
            );
            w.memory.namespace = first.memory.namespace.clone();
            w.memory.metadata = serde_json::json!({ "agent_id": "ai:sal-test" });
            w
        };
        let r2 = store
            .capture_turn_idempotent(&ctx, &second)
            .await
            .expect("second");
        assert!(r2.dedup_hit);
        assert_eq!(r2.memory_id, r1.memory_id);

        let got = store.get(&ctx, &r1.memory_id).await.expect("get");
        assert_eq!(got.content, "first-content");
        let _ = store.delete(&ctx, &r1.memory_id).await;
    }

    /// #3231 pg — two tasks racing the same (session, turn). The
    /// advisory lock + in-tx re-probe must keep the first writer's
    /// content (sequential tests never reach that path).
    #[tokio::test]
    async fn pg_capture_turn_concurrent_same_session_turn_fww_3231() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let unique = uuid::Uuid::new_v4();
        let session = format!("sess-race-{unique}");
        let title = format!("turn-race-{unique}-0");
        let ns = format!("b17-3231-{unique}");
        let first = {
            let mut w = capture_write(&session, 0, &title, "content-a", &format!("sha-a-{unique}"));
            w.memory.namespace = ns.clone();
            w.memory.metadata = serde_json::json!({ "agent_id": "ai:sal-test" });
            w
        };
        let second = {
            let mut w = capture_write(&session, 0, &title, "content-b", &format!("sha-b-{unique}"));
            w.memory.namespace = ns;
            w.memory.metadata = serde_json::json!({ "agent_id": "ai:sal-test" });
            w
        };
        let (r1, r2) = tokio::join!(
            store.capture_turn_idempotent(&ctx, &first),
            store.capture_turn_idempotent(&ctx, &second),
        );
        let r1 = r1.expect("r1");
        let r2 = r2.expect("r2");
        assert_eq!(r1.memory_id, r2.memory_id);
        assert!(
            r1.dedup_hit ^ r2.dedup_hit,
            "exactly one miss; a.dedup_hit={} b.dedup_hit={}",
            r1.dedup_hit,
            r2.dedup_hit
        );
        let expected = if r1.dedup_hit {
            "content-b"
        } else {
            "content-a"
        };
        let got = store.get(&ctx, &r1.memory_id).await.expect("get");
        assert_eq!(got.content, expected);
        let _ = store.delete(&ctx, &r1.memory_id).await;
    }
}
