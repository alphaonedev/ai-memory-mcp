// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Cross-backend PARITY regressions for the write funnels (archive /
//! delete / update), 2026-08.
//!
//! A parity audit of the sqlite (`storage::` free functions +
//! `SqliteStore` SAL adapter) and postgres (`PostgresStore`) write funnels
//! found four divergences where the SAME operation behaved differently per
//! backend. Three are data-integrity issues; one is an authorization gap.
//! Each test below pins the FIXED behaviour so the funnels cannot drift
//! apart again.
//!
//! * **#1 — `archive_reason` default.** sqlite stamped `"archive"`, postgres
//!   stamped `"manual"` for the SAME reason-less archive, so audit trails and
//!   every reason-filtered query/report disagreed across backends. Both now
//!   read ONE SSOT const (`field_names::ARCHIVE_REASON_DEFAULT`).
//! * **#2 — `archive_by_ids` batch atomicity.** postgres wrapped the whole
//!   batch in ONE transaction (all-or-nothing); sqlite looped
//!   `db::archive_memory`, which opens its OWN tx PER ID, so a mid-batch
//!   failure left a PARTIALLY archived batch committed (prefix rows deleted
//!   from `memories`, remainder untouched). sqlite is now all-or-nothing too.
//! * **#3 — `delete` statement atomicity.** sqlite ran the namespace-standard
//!   SEVER, the append-only TOMBSTONE leaf, and the row DELETE as THREE
//!   separate autocommit statements, so a failure between them stranded a
//!   severed governance binding with the memory still live. All three now
//!   share one transaction.
//! * **#4 — SAL-level caller-owns gate.** `PostgresStore::update`/`delete`
//!   enforce `assert_caller_owns_for_mutation` (#1412/#1628);
//!   `SqliteStore::update`/`delete` discarded `ctx` entirely, so any
//!   NON-HTTP SAL caller could rewrite/delete another tenant's row. The
//!   sqlite adapter now enforces the mirror gate.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::path::PathBuf;

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use serde_json::json;

/// Hermetic DB path under `.local-runs/` (never `/tmp`, per project rule).
fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("parity-write-funnels");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn seed(conn: &rusqlite::Connection, ns: &str, title: &str, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "parity-test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn is_live(conn: &rusqlite::Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

fn archive_reason_of(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT archive_reason FROM archived_memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

// ─────────────────────────────────────────────────────────────────────
// #1 — reason-less archive stamps the SHARED default on both backends.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn archive_by_ids_reason_less_default_is_the_shared_ssot_const() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let id = seed(&conn, "parity/ns1", "reason-default", "ai:alice");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let ctx = CallerContext::for_admin("ai:operator");
    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), None)
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1);

    let conn = db::open(&db_path).expect("reopen");
    assert_eq!(
        archive_reason_of(&conn, &id).as_deref(),
        Some(ai_memory::models::field_names::ARCHIVE_REASON_DEFAULT),
        "parity #1: a reason-less archive must stamp the SHARED default \
         const on BOTH backends (sqlite stamped 'archive', postgres \
         stamped 'manual' pre-fix)"
    );
    // Pin the VALUE too, so aligning the const can never silently flip the
    // long-standing sqlite audit-trail value.
    assert_eq!(
        ai_memory::models::field_names::ARCHIVE_REASON_DEFAULT,
        "archive"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #2 — sqlite archive_by_ids is ALL-OR-NOTHING (postgres parity).
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn archive_by_ids_is_all_or_nothing_on_a_mid_batch_failure() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let first = seed(&conn, "parity/ns2", "batch-first", "ai:alice");
    let poison = seed(&conn, "parity/ns2", "batch-poison", "ai:alice");

    // Force the SECOND id's archive to fail, deterministically: a BEFORE
    // DELETE trigger that aborts only for the poison row. `archive_memory`
    // copies the row into `archived_memories` and THEN deletes it, so the
    // abort lands mid-way through the second id — exactly the mid-batch
    // failure the postgres twin rolls back wholesale.
    conn.execute_batch(&format!(
        "CREATE TRIGGER parity_poison_del BEFORE DELETE ON memories
         WHEN OLD.id = '{poison}'
         BEGIN SELECT RAISE(ABORT, 'parity-injected mid-batch failure'); END;"
    ))
    .expect("install trigger");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let ctx = CallerContext::for_admin("ai:operator");
    let err = store
        .archive_by_ids(&ctx, &[first.clone(), poison.clone()], Some("batch"))
        .await
        .expect_err("the poisoned batch must fail");
    // The failure must surface as a backend error, not a silent partial Ok.
    assert!(
        matches!(err, StoreError::Backend(_)),
        "expected a Backend error, got {err:?}"
    );

    let conn = db::open(&db_path).expect("reopen");
    assert!(
        is_live(&conn, &first),
        "parity #2: the FIRST id must still be LIVE — pre-fix each id got its \
         own transaction, so the prefix of the batch was already committed \
         (row deleted from `memories`) when a later id failed"
    );
    assert!(
        archive_reason_of(&conn, &first).is_none(),
        "parity #2: the FIRST id must NOT have an archived copy — the whole \
         batch rolls back together"
    );
    assert!(is_live(&conn, &poison), "the poison row is untouched too");
}

#[tokio::test]
async fn archive_by_ids_commits_the_whole_batch_on_success() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let a = seed(&conn, "parity/ns3", "ok-a", "ai:alice");
    let b = seed(&conn, "parity/ns3", "ok-b", "ai:alice");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let ctx = CallerContext::for_admin("ai:operator");
    let moved = store
        .archive_by_ids(&ctx, &[a.clone(), b.clone()], Some("batch-ok"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 2, "both ids archived");

    let conn = db::open(&db_path).expect("reopen");
    for id in [&a, &b] {
        assert!(
            !is_live(&conn, id),
            "{id} must be archived out of `memories`"
        );
        assert_eq!(archive_reason_of(&conn, id).as_deref(), Some("batch-ok"));
    }
}

// ─────────────────────────────────────────────────────────────────────
// #3 — delete's SEVER + TOMBSTONE + DELETE share ONE transaction.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn delete_rolls_the_namespace_standard_sever_back_with_the_row() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let standard = seed(&conn, "_standards-parity", "std", "ai:operator");
    // Bind the standard so `sever_namespace_standards` has real work to do.
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at) VALUES (?1, ?2, ?3)",
        rusqlite::params!["parity/gov", &standard, chrono::Utc::now().to_rfc3339()],
    )
    .expect("bind standard");

    // Abort the row DELETE, which runs AFTER the sever inside the funnel.
    conn.execute_batch(&format!(
        "CREATE TRIGGER parity_block_del BEFORE DELETE ON memories
         WHEN OLD.id = '{standard}'
         BEGIN SELECT RAISE(ABORT, 'parity-injected delete failure'); END;"
    ))
    .expect("install trigger");

    let err = db::delete(&conn, &standard).expect_err("the delete must fail");
    assert!(
        err.to_string().contains("parity-injected"),
        "expected the injected abort, got: {err}"
    );

    let bound: Option<String> = conn
        .query_row(
            "SELECT standard_id FROM namespace_meta WHERE namespace = ?1",
            rusqlite::params!["parity/gov"],
            |r| r.get(0),
        )
        .expect("read binding");
    assert_eq!(
        bound.as_deref(),
        Some(standard.as_str()),
        "parity #3: the namespace-standard SEVER must roll back with the \
         failed DELETE. Pre-fix the sever ran as its OWN autocommit \
         statement, so it COMMITTED and the namespace lost its governance \
         binding while the memory stayed live — an unrecoverable policy \
         downgrade from a delete that never happened"
    );
    assert!(is_live(&conn, &standard), "the memory row is still live");
}

#[test]
fn delete_still_works_when_the_caller_already_holds_a_transaction() {
    // Regression guard for the #3 fix itself: `delete` is called from INSIDE
    // an open tx (e.g. `consolidate`'s legacy hard-DELETE arm), where a
    // nested `BEGIN` would fail with "cannot start a transaction within a
    // transaction". The funnel must detect the caller's tx and join it.
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let id = seed(&conn, "parity/ns4", "in-caller-tx", "ai:alice");

    conn.execute_batch("BEGIN IMMEDIATE").expect("caller tx");
    let removed = db::delete(&conn, &id).expect("delete inside a caller tx must not nested-BEGIN");
    assert!(removed);
    conn.execute_batch("ROLLBACK").expect("caller rollback");

    assert!(
        is_live(&conn, &id),
        "the caller's ROLLBACK must still undo the delete — the funnel must \
         NOT have committed its own inner transaction"
    );
}

// ─────────────────────────────────────────────────────────────────────
// #4 — SAL-level caller-owns gate on the sqlite update/delete funnels.
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sqlite_sal_update_and_delete_enforce_the_caller_owns_gate() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let alices = seed(&conn, "parity/ns5", "alice-row", "ai:alice");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let bob = CallerContext::for_agent("ai:bob");
    let alice = CallerContext::for_agent("ai:alice");

    // Bob cannot UPDATE alice's row.
    let patch = UpdatePatch {
        content: Some("bob was here".to_string()),
        ..UpdatePatch::default()
    };
    let err = store
        .update(&bob, &alices, patch)
        .await
        .expect_err("bob must not update alice's row");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "parity #4: expected PermissionDenied, got {err:?}"
    );

    // Bob cannot DELETE alice's row either.
    let err = store
        .delete(&bob, &alices)
        .await
        .expect_err("bob must not delete alice's row");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "parity #4: expected PermissionDenied, got {err:?}"
    );

    // The row is untouched by either refusal.
    let conn = db::open(&db_path).expect("reopen");
    assert!(is_live(&conn, &alices));
    drop(conn);

    // Alice (the owner) still succeeds.
    let patch = UpdatePatch {
        content: Some("alice's own edit".to_string()),
        ..UpdatePatch::default()
    };
    store
        .update(&alice, &alices, patch)
        .await
        .expect("the owner must still be able to update");

    // An admin context (bypass_visibility) skips the gate, same as postgres.
    let admin = CallerContext::for_admin("ai:operator");
    store
        .delete(&admin, &alices)
        .await
        .expect("an admin/bypass context must skip the ownership gate");
}

#[tokio::test]
async fn unstamped_row_is_allowed_through_sqlite_sal_gate() {
    // Option B (gatekeeper decision, 2026-08-22) — the sqlite SAL gate mirrors
    // SQLITE'S OWN contract, not postgres's #1628 refusal. An UNSTAMPED row
    // (no `metadata.agent_id`: legacy / pre-v0.6.3 / migrated) stays MUTABLE,
    // exactly as the canonical `visibility::caller_owns_for_mutation`
    // predicate specifies and as the HTTP `require_caller_owns_memory`
    // carve-out and every MCP mutate tool already behave.
    //
    // Why this matters (the reason the tighter posture was rejected): refusing
    // unstamped rows would turn today-writable legacy rows into permanently
    // inaccessible ones for every non-admin caller — a data-loss mode — and it
    // would break the single-operator default, where rows may carry no stamp
    // at all. Cross-backend unification (stamp legacy rows via migration, then
    // refuse everywhere) is tracked as #3124.
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "parity/ns6".to_string(),
        title: "unstamped".to_string(),
        content: "legacy row with no agent_id".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "parity-test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({}),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    let id = db::insert(&conn, &mem).expect("insert unstamped");
    // `insert` may stamp a provenance agent_id; strip it so the row is truly
    // unstamped — the legacy shape the carve-out exists for.
    conn.execute(
        "UPDATE memories SET metadata = json_remove(metadata, '$.agent_id') WHERE id = ?1",
        rusqlite::params![&id],
    )
    .expect("strip agent_id");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let tenant = CallerContext::for_agent("ai:alice");

    // UPDATE by an unrelated tenant is ALLOWED (legacy-unowned carve-out).
    let patch = UpdatePatch {
        content: Some("legacy row edited by a tenant".to_string()),
        ..UpdatePatch::default()
    };
    store.update(&tenant, &id, patch).await.expect(
        "an UNSTAMPED row must stay mutable at the SAL layer — refusing it would \
         strand legacy rows and break the single-operator default",
    );

    // DELETE by an unrelated tenant is likewise ALLOWED.
    store
        .delete(&tenant, &id)
        .await
        .expect("an UNSTAMPED row must stay deletable at the SAL layer");
}

/// The inbox carve-out is wired per-verb exactly as HTTP/MCP wire it:
/// DELETE passes `allow_inbox = true` (the addressed recipient may delete a
/// message sent to it after consuming it) while UPDATE passes `false` (the
/// recipient must NOT rewrite the sender's row).
#[tokio::test]
async fn sqlite_sal_inbox_recipient_may_delete_but_not_update() {
    let (_guard, db_path) = fresh_db_path();
    let conn = db::open(&db_path).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: "parity/ns7".to_string(),
        title: "inbox-msg".to_string(),
        content: "message addressed to bob".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "parity-test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "ai:alice", "target_agent_id": "ai:bob" }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    };
    let id = db::insert(&conn, &mem).expect("insert inbox row");
    drop(conn);

    let store = SqliteStore::open(&db_path).expect("SqliteStore::open");
    let bob = CallerContext::for_agent("ai:bob");

    // UPDATE: inbox carve-out DISABLED -> refused.
    let patch = UpdatePatch {
        content: Some("bob rewrites alice's message".to_string()),
        ..UpdatePatch::default()
    };
    let err = store
        .update(&bob, &id, patch)
        .await
        .expect_err("the inbox recipient must NOT rewrite the sender's row");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "expected PermissionDenied on update, got {err:?}"
    );

    // DELETE: inbox carve-out ENABLED -> allowed.
    store
        .delete(&bob, &id)
        .await
        .expect("the addressed recipient MAY delete a message sent to it");
}

// ─────────────────────────────────────────────────────────────────────
// #1 — the POSTGRES side of the reason-less default.
//
// Fix #1 changed the *postgres* funnel (`"manual"` -> the shared const),
// so the sqlite assertion above alone would not have caught a regression
// on the backend that actually moved. Live-PG gated; skips cleanly when
// `AI_MEMORY_TEST_POSTGRES_URL` is unset, and runs in CI's postgres leg.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{Memory, MemoryKind, Tier, json};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    #[tokio::test]
    async fn pg_archive_by_ids_reason_less_default_matches_the_sqlite_funnel() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        let ctx = CallerContext::for_admin("ai:parity-operator");
        let id = format!("parity-1-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: id.clone(),
            tier: Tier::Mid,
            namespace: format!("parity/pg-{}", uuid::Uuid::new_v4().simple()),
            title: format!("parity-reason-{id}"),
            content: "reason-less archive default".to_string(),
            priority: 5,
            confidence: 1.0,
            source: "parity-test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({ "agent_id": "ai:parity-operator" }),
            memory_kind: MemoryKind::Observation,
            version: 1,
            ..Memory::default()
        };
        store.store(&ctx, &mem).await.expect("store");

        let moved = store
            .archive_by_ids(&ctx, std::slice::from_ref(&id), None)
            .await
            .expect("archive_by_ids");
        assert_eq!(moved, 1);

        let reason: Option<String> =
            sqlx::query_scalar("SELECT archive_reason FROM archived_memories WHERE id = $1")
                .bind(&id)
                .fetch_optional(store.pool())
                .await
                .expect("read archive_reason");

        // Teardown BEFORE asserting (#2287) so a failure never strands rows.
        let _ = sqlx::query("DELETE FROM archived_memories WHERE id = $1")
            .bind(&id)
            .execute(store.pool())
            .await;
        let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
            .bind(&id)
            .execute(store.pool())
            .await;

        assert_eq!(
            reason.as_deref(),
            Some(ai_memory::models::field_names::ARCHIVE_REASON_DEFAULT),
            "parity #1: postgres stamped \"manual\" for a reason-less archive \
             while BOTH sqlite funnels stamped \"archive\", so the same \
             operation produced a different audit-trail value per backend. \
             Both now read the one shared SSOT const"
        );
    }
}
