// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4447 — the federation `/sync/push` by-id lanes (`deletions[]`, `archives[]`,
//! `restores[]`, `links[]`) authorize a target row's STORED namespace on a read
//! that precedes the write transaction, then write by id with no re-check: the
//! sibling of #4023 (which fixed only the `memories[]` merge lane). A
//! broader-scoped writer that moves the row out of the narrow peer's scope
//! between the probe and the write must NOT have the peer's by-id write land on
//! the moved row. The fix re-authorizes the stored namespace of the row the
//! write locks (`FOR UPDATE` on postgres, the write transaction on sqlite),
//! inside the write transaction, and refuses with the typed `PermissionDenied`.
//!
//! Choreography (deterministic, no sleep-based timing):
//!   1. seed a row in the peer's in-scope namespace;
//!   2. a second connection takes the row's lock (`FOR UPDATE` / `BEGIN
//!      IMMEDIATE`);
//!   3. the authorized write is issued — the funnel's earlier scope probe would
//!      have passed (the row is still in scope) and the write BLOCKS on the
//!      lock. The postgres cells wait on `pg_stat_activity`; the sqlite cells
//!      wait on the calling connection's busy handler being invoked (the
//!      handler is what the lock wait calls, so it is the exact barrier);
//!   4. the second connection moves the row out of scope and commits;
//!   5. the write resumes and must refuse, writing nothing.
//!
//! Every lane cell also runs a HAZARD CONTROL: the same moved-row scenario
//! through the UNCHECKED writer does change the row. That proves the scenario
//! is destructive without the fix, so a green cell is not vacuous.
//!
//! Postgres cells are gated on `feature = "sal-postgres"` +
//! `AI_MEMORY_TEST_POSTGRES_URL`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation};
use ai_memory::storage::InboundByIdNamespaceRefused;
use ai_memory::store::{
    CallerContext, FEDERATION_APPLY_ARCHIVE, FEDERATION_APPLY_DELETION, FEDERATION_APPLY_LINK,
    FEDERATION_APPLY_RESTORE, MemoryStore, StoreError,
};

const ORIGINAL_CONTENT: &str = "broad-writer row content";

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn admin_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-4447");
    ctx.bypass_visibility = true;
    ctx
}

fn seed_row(id: &str, namespace: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: namespace.to_string(),
        title: uniq("by-id-row"),
        content: ORIGINAL_CONTENT.to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
        updated_at: "2026-01-02T00:00:00+00:00".to_string(),
        metadata: serde_json::json!({"agent_id": "ai:broad-writer-4447"}),
        ..Default::default()
    }
}

fn link_between(a: &str, b: &str) -> MemoryLink {
    MemoryLink {
        source_id: a.to_string(),
        target_id: b.to_string(),
        relation: MemoryLinkRelation::DerivedFrom,
        created_at: chrono::Utc::now().to_rfc3339(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// The peer's verdict: in scope iff the STORED namespace is under `root`.
fn in_scope(root: &str) -> impl Fn(&str, &str) -> bool + Send + Sync + use<> {
    let prefix = format!("{root}/");
    move |_id: &str, stored: &str| stored.starts_with(&prefix)
}

// ---------------------------------------------------------------------
// sqlite — two-connection cells at the `db::` funnel the receive loop calls.
// ---------------------------------------------------------------------

/// The busy handler's "a lock wait happened" flag. The cells share ONE static
/// (a fn-pointer handler cannot capture), so they serialise on `SQLITE_CELLS`.
static BLOCKED: AtomicBool = AtomicBool::new(false);
static SQLITE_CELLS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn busy_cb(attempt: i32) -> bool {
    BLOCKED.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(10));
    // Bounded: ~20 s of retries, far beyond the cell's own barrier wait.
    attempt < 2000
}

struct SqliteWorld {
    path: std::path::PathBuf,
    store: ai_memory::store::sqlite::SqliteStore,
    _dir: tempfile::TempDir,
}

fn sqlite_world() -> SqliteWorld {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("by-id-4447.db");
    drop(ai_memory::db::open(&path).expect("db::open"));
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore");
    SqliteWorld {
        path,
        store,
        _dir: dir,
    }
}

/// Run `write` on a fresh connection that is BLOCKED by `broad`'s write lock;
/// when the lock wait is observed, run `mutate` on `broad`, commit, and return
/// the write's outcome.
fn race<T: Send + 'static>(
    path: &Path,
    mutate: impl FnOnce(&rusqlite::Connection),
    write: impl FnOnce(&rusqlite::Connection) -> T + Send + 'static,
) -> T {
    let broad = ai_memory::db::open(path).expect("broad connection");
    broad.execute_batch("BEGIN IMMEDIATE").expect("write lock");
    BLOCKED.store(false, Ordering::SeqCst);
    let narrow_path = path.to_path_buf();
    let handle = std::thread::spawn(move || {
        let narrow = ai_memory::db::open(&narrow_path).expect("narrow connection");
        narrow
            .busy_handler(Some(busy_cb))
            .expect("install busy handler");
        write(&narrow)
    });
    let mut waited = false;
    for _ in 0..2000 {
        if BLOCKED.load(Ordering::SeqCst) {
            waited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(waited, "the authorized write never reached the write lock");
    mutate(&broad);
    broad.execute_batch("COMMIT").expect("commit move");
    handle.join().expect("narrow write thread")
}

fn refused<T: std::fmt::Debug>(res: anyhow::Result<T>, lane: &str) {
    match res {
        Err(e) => assert!(
            e.downcast_ref::<InboundByIdNamespaceRefused>().is_some(),
            "#4447 (sqlite {lane}): expected the typed in-transaction refusal, got {e:?}"
        ),
        Ok(v) => panic!(
            "#4447 (sqlite {lane}): a by-id write must not land on a row moved out of the \
             peer's scope, got Ok({v:?})"
        ),
    }
}

fn move_live(conn: &rusqlite::Connection, id: &str, ns: &str) {
    conn.execute(
        "UPDATE memories SET namespace = ?1 WHERE id = ?2",
        rusqlite::params![ns, id],
    )
    .expect("broader writer moves the live row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletions_lane_refused_after_concurrent_move_sqlite_4447() {
    let _g = SQLITE_CELLS.lock().await;
    let w = sqlite_world();
    let (root, secure) = (uniq("public"), uniq("secure/ops"));
    let id = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
        .await
        .expect("seed");

    let (id2, sec2, root2) = (id.clone(), secure.clone(), root.clone());
    let res = race(
        &w.path,
        |b| move_live(b, &id2, &sec2),
        move |c| {
            let auth = in_scope(&root2);
            ai_memory::db::delete_authorized(c, &id, &auth)
        },
    );
    refused(res, "deletions");
    let row = w
        .store
        .get(&admin_ctx(), &id2)
        .await
        .expect("the moved row must still exist");
    assert_eq!(row.namespace, secure, "the moved row is untouched");

    // HAZARD CONTROL: the unchecked delete of a moved row destroys it.
    let hz = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
        .await
        .expect("seed hazard");
    let c = ai_memory::db::open(&w.path).expect("conn");
    move_live(&c, &hz, &secure);
    assert!(ai_memory::db::delete(&c, &hz).expect("unchecked delete"));
    assert!(
        w.store.get(&admin_ctx(), &hz).await.is_err(),
        "hazard control: without the re-check the moved row is deleted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archives_lane_refused_after_concurrent_move_sqlite_4447() {
    let _g = SQLITE_CELLS.lock().await;
    let w = sqlite_world();
    let (root, secure) = (uniq("public"), uniq("secure/ops"));
    let id = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
        .await
        .expect("seed");

    let (id2, sec2, root2) = (id.clone(), secure.clone(), root.clone());
    let res = race(
        &w.path,
        |b| move_live(b, &id2, &sec2),
        move |c| {
            let auth = in_scope(&root2);
            ai_memory::db::archive_memory_authorized(c, &id, Some("sync_push"), &auth)
        },
    );
    refused(res, "archives");
    let live = w.store.get(&admin_ctx(), &id2).await.expect("still live");
    assert_eq!(
        live.namespace, secure,
        "the moved row stays live where it is"
    );

    // HAZARD CONTROL: the unchecked archive of a moved row removes it from live.
    let hz = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
        .await
        .expect("seed hazard");
    let c = ai_memory::db::open(&w.path).expect("conn");
    move_live(&c, &hz, &secure);
    assert!(ai_memory::db::archive_memory(&c, &hz, Some("sync_push")).expect("unchecked archive"));
    assert!(
        w.store.get(&admin_ctx(), &hz).await.is_err(),
        "hazard control: without the re-check the moved row is archived away"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restores_lane_refused_after_concurrent_move_sqlite_4447() {
    let _g = SQLITE_CELLS.lock().await;
    let w = sqlite_world();
    let (root, secure) = (uniq("public"), uniq("secure/ops"));
    let id = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
        .await
        .expect("seed");
    let c = ai_memory::db::open(&w.path).expect("conn");
    assert!(ai_memory::db::archive_memory(&c, &id, None).expect("archive seed"));

    let (id2, sec2, root2) = (id.clone(), secure.clone(), root.clone());
    let res = race(
        &w.path,
        |b| {
            b.execute(
                "UPDATE archived_memories SET namespace = ?1 WHERE id = ?2",
                rusqlite::params![sec2, id2],
            )
            .expect("broader writer re-keys the archived row");
        },
        move |c| {
            let auth = in_scope(&root2);
            ai_memory::db::restore_archived_authorized(c, &id, &auth)
        },
    );
    refused(res, "restores");
    assert!(
        w.store.get(&admin_ctx(), &id2).await.is_err(),
        "the moved archived row must NOT have been restored into the live set"
    );

    // HAZARD CONTROL: the unchecked restore resurrects the moved archived row.
    let hz = uuid::Uuid::new_v4().to_string();
    w.store
        .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
        .await
        .expect("seed hazard");
    assert!(ai_memory::db::archive_memory(&c, &hz, None).expect("archive hazard"));
    c.execute(
        "UPDATE archived_memories SET namespace = ?1 WHERE id = ?2",
        rusqlite::params![secure, hz],
    )
    .expect("re-key hazard");
    assert!(ai_memory::db::restore_archived(&c, &hz).expect("unchecked restore"));
    assert_eq!(
        w.store
            .get(&admin_ctx(), &hz)
            .await
            .expect("restored")
            .namespace,
        secure,
        "hazard control: without the re-check the moved archived row is resurrected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn links_lane_refused_after_concurrent_move_sqlite_4447() {
    let _g = SQLITE_CELLS.lock().await;
    let w = sqlite_world();
    let (root, secure) = (uniq("public"), uniq("secure/ops"));
    let (a, b) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    for id in [&a, &b] {
        w.store
            .store(&admin_ctx(), &seed_row(id, &format!("{root}/shared")))
            .await
            .expect("seed");
    }

    let (b2, sec2, root2) = (b.clone(), secure.clone(), root.clone());
    let link = link_between(&a, &b);
    let l2 = link.clone();
    let res = race(
        &w.path,
        |c| move_live(c, &b2, &sec2),
        move |c| {
            let auth = in_scope(&root2);
            ai_memory::db::create_link_inbound_authorized(c, &l2, "unsigned", &auth)
        },
    );
    refused(res, "links");
    let c = ai_memory::db::open(&w.path).expect("conn");
    assert!(
        ai_memory::db::get_links(&c, &a).expect("links").is_empty(),
        "no edge may be written into a row moved out of the peer's scope"
    );

    // HAZARD CONTROL: the unchecked inbound link lands an edge on the moved row.
    ai_memory::db::create_link_inbound(&c, &link, "unsigned").expect("unchecked link");
    assert_eq!(
        ai_memory::db::get_links(&c, &a).expect("links").len(),
        1,
        "hazard control: without the re-check the cross-namespace edge is written"
    );
}

// ---------------------------------------------------------------------
// Typed refusal parity (SAL trait) + admitting control — both backends.
// ---------------------------------------------------------------------

async fn assert_typed_refusals(backend: &str, store: &dyn MemoryStore) {
    let ctx = admin_ctx();
    let ns = uniq("variant/ns");
    let deny = |_id: &str, _stored: &str| false;
    let allow = |_id: &str, _stored: &str| true;

    // deletions
    let d = uuid::Uuid::new_v4().to_string();
    store.store(&ctx, &seed_row(&d, &ns)).await.expect("seed d");
    match store
        .apply_remote_deletion_authorized(&ctx, &d, &deny)
        .await
    {
        Err(StoreError::PermissionDenied { action, target, .. }) => {
            assert_eq!(
                action, FEDERATION_APPLY_DELETION,
                "{backend} deletion action"
            );
            assert_eq!(target, d, "{backend} deletion target");
        }
        other => panic!("#4447 ({backend}) deletion: expected PermissionDenied, got {other:?}"),
    }
    assert!(
        store.get(&ctx, &d).await.is_ok(),
        "{backend}: refusal deletes nothing"
    );
    assert!(
        store
            .apply_remote_deletion_authorized(&ctx, &d, &allow)
            .await
            .expect("admitted delete"),
        "{backend}: an admitting verdict still deletes"
    );

    // archives
    let a = uuid::Uuid::new_v4().to_string();
    store.store(&ctx, &seed_row(&a, &ns)).await.expect("seed a");
    match store.apply_remote_archive_authorized(&ctx, &a, &deny).await {
        Err(StoreError::PermissionDenied { action, target, .. }) => {
            assert_eq!(action, FEDERATION_APPLY_ARCHIVE, "{backend} archive action");
            assert_eq!(target, a, "{backend} archive target");
        }
        other => panic!("#4447 ({backend}) archive: expected PermissionDenied, got {other:?}"),
    }
    assert!(
        store.get(&ctx, &a).await.is_ok(),
        "{backend}: refusal archives nothing"
    );
    assert!(
        store
            .apply_remote_archive_authorized(&ctx, &a, &allow)
            .await
            .expect("admitted archive"),
        "{backend}: an admitting verdict still archives"
    );

    // restores (the row `a` is archived now)
    match store.apply_remote_restore_authorized(&ctx, &a, &deny).await {
        Err(StoreError::PermissionDenied { action, target, .. }) => {
            assert_eq!(action, FEDERATION_APPLY_RESTORE, "{backend} restore action");
            assert_eq!(target, a, "{backend} restore target");
        }
        other => panic!("#4447 ({backend}) restore: expected PermissionDenied, got {other:?}"),
    }
    assert!(
        store.get(&ctx, &a).await.is_err(),
        "{backend}: refusal restores nothing"
    );
    assert!(
        store
            .apply_remote_restore_authorized(&ctx, &a, &allow)
            .await
            .expect("admitted restore"),
        "{backend}: an admitting verdict still restores"
    );

    // links
    let (x, y) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    for id in [&x, &y] {
        store
            .store(&ctx, &seed_row(id, &ns))
            .await
            .expect("seed endpoint");
    }
    let link = link_between(&x, &y);
    match store
        .apply_remote_link_authorized(&ctx, &link, "unsigned", &deny)
        .await
    {
        Err(StoreError::PermissionDenied { action, .. }) => {
            assert_eq!(action, FEDERATION_APPLY_LINK, "{backend} link action");
        }
        other => panic!("#4447 ({backend}) link: expected PermissionDenied, got {other:?}"),
    }
    store
        .apply_remote_link_authorized(&ctx, &link, "unsigned", &allow)
        .await
        .expect("admitted link");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn by_id_refusals_are_permission_denied_variants_sqlite_4447() {
    let w = sqlite_world();
    assert_typed_refusals("sqlite", &w.store).await;
}

// ---------------------------------------------------------------------
// postgres — SAL trait cells, deterministic on `pg_stat_activity`.
// ---------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use std::sync::Arc;

    fn url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// Wait until a backend of the connection named `app` (the cell's OWN
    /// connection, never a sibling cell's) is blocked on a lock: any row-lock
    /// wait counts, so a stale-placed check that blocks on the DELETE / INSERT
    /// instead of a `FOR UPDATE` / `FOR SHARE` read is still observed.
    async fn wait_blocked(observer: &PostgresStore, app: &str) {
        for _ in 0..400 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND pid <> pg_backend_pid() \
                   AND wait_event_type = 'Lock' AND application_name = $1",
            )
            .bind(app)
            .fetch_one(observer.pool())
            .await
            .expect("pg_stat_activity");
            if waiting > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the authorized write never reached a lock wait");
    }

    async fn connect(url: &str) -> Arc<PostgresStore> {
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"))
    }

    /// Connect with `application_name = app`, so `wait_blocked` can single out
    /// this connection's backend.
    async fn connect_app(url: &str, app: &str) -> Arc<PostgresStore> {
        let sep = if url.contains('?') { '&' } else { '?' };
        connect(&format!("{url}{sep}application_name={app}")).await
    }

    fn typed_refusal<T: std::fmt::Debug>(res: Result<T, StoreError>, lane: &str, action: &str) {
        match res {
            Err(StoreError::PermissionDenied { action: a, .. }) => {
                assert_eq!(a, action, "#4447 (pg {lane}): action");
            }
            other => panic!(
                "#4447 (pg {lane}): a by-id write must not land on a row moved out of the \
                 peer's scope, got {other:?}"
            ),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletions_lane_refused_after_concurrent_move_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP deletions_lane_refused_after_concurrent_move_pg_4447: no URL");
            return;
        };
        let app = uniq("f1-4447");
        let store = connect_app(&url, &app).await;
        let (root, secure) = (uniq("public"), uniq("secure/ops"));
        let id = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
            .await
            .expect("seed");
        let broad = connect(&url).await;
        let mut tx = broad.pool().begin().await.expect("begin");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock row");
        let (s2, id2, root2) = (store.clone(), id.clone(), root.clone());
        let task = tokio::spawn(async move {
            let auth = in_scope(&root2);
            s2.apply_remote_deletion_authorized(&admin_ctx(), &id2, &auth)
                .await
        });
        wait_blocked(&broad, &app).await;
        sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&id)
            .execute(&mut *tx)
            .await
            .expect("move");
        tx.commit().await.expect("commit move");
        typed_refusal(
            task.await.expect("task"),
            "deletions",
            FEDERATION_APPLY_DELETION,
        );
        assert_eq!(
            store
                .get(&admin_ctx(), &id)
                .await
                .expect("still there")
                .namespace,
            secure
        );

        // HAZARD CONTROL.
        let hz = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
            .await
            .expect("seed hazard");
        sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&hz)
            .execute(broad.pool())
            .await
            .expect("move hazard");
        assert!(
            store
                .apply_remote_deletion(&admin_ctx(), &hz)
                .await
                .expect("unchecked delete"),
            "hazard control: without the re-check the moved row is deleted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn archives_lane_refused_after_concurrent_move_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP archives_lane_refused_after_concurrent_move_pg_4447: no URL");
            return;
        };
        let app = uniq("f1-4447");
        let store = connect_app(&url, &app).await;
        let (root, secure) = (uniq("public"), uniq("secure/ops"));
        let id = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
            .await
            .expect("seed");
        let broad = connect(&url).await;
        let mut tx = broad.pool().begin().await.expect("begin");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock row");
        let (s2, id2, root2) = (store.clone(), id.clone(), root.clone());
        let task = tokio::spawn(async move {
            let auth = in_scope(&root2);
            s2.apply_remote_archive_authorized(&admin_ctx(), &id2, &auth)
                .await
        });
        wait_blocked(&broad, &app).await;
        sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&id)
            .execute(&mut *tx)
            .await
            .expect("move");
        tx.commit().await.expect("commit move");
        typed_refusal(
            task.await.expect("task"),
            "archives",
            FEDERATION_APPLY_ARCHIVE,
        );
        assert_eq!(
            store
                .get(&admin_ctx(), &id)
                .await
                .expect("still live")
                .namespace,
            secure
        );

        // HAZARD CONTROL.
        let hz = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
            .await
            .expect("seed hazard");
        sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&hz)
            .execute(broad.pool())
            .await
            .expect("move hazard");
        assert!(
            store
                .apply_remote_archive(&admin_ctx(), &hz)
                .await
                .expect("unchecked archive"),
            "hazard control: without the re-check the moved row is archived away"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restores_lane_refused_after_concurrent_move_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP restores_lane_refused_after_concurrent_move_pg_4447: no URL");
            return;
        };
        let app = uniq("f1-4447");
        let store = connect_app(&url, &app).await;
        let (root, secure) = (uniq("public"), uniq("secure/ops"));
        let id = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&id, &format!("{root}/shared")))
            .await
            .expect("seed");
        assert!(
            store
                .apply_remote_archive(&admin_ctx(), &id)
                .await
                .expect("archive seed")
        );
        let broad = connect(&url).await;
        let mut tx = broad.pool().begin().await.expect("begin");
        sqlx::query("SELECT id FROM archived_memories WHERE id = $1 FOR UPDATE")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .expect("lock archived row");
        let (s2, id2, root2) = (store.clone(), id.clone(), root.clone());
        let task = tokio::spawn(async move {
            let auth = in_scope(&root2);
            s2.apply_remote_restore_authorized(&admin_ctx(), &id2, &auth)
                .await
        });
        wait_blocked(&broad, &app).await;
        sqlx::query("UPDATE archived_memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&id)
            .execute(&mut *tx)
            .await
            .expect("re-key archived row");
        tx.commit().await.expect("commit move");
        typed_refusal(
            task.await.expect("task"),
            "restores",
            FEDERATION_APPLY_RESTORE,
        );
        assert!(
            store.get(&admin_ctx(), &id).await.is_err(),
            "the moved archived row must NOT have been restored into the live set"
        );

        // HAZARD CONTROL.
        let hz = uuid::Uuid::new_v4().to_string();
        store
            .store(&admin_ctx(), &seed_row(&hz, &format!("{root}/shared")))
            .await
            .expect("seed hazard");
        assert!(
            store
                .apply_remote_archive(&admin_ctx(), &hz)
                .await
                .expect("archive hazard")
        );
        sqlx::query("UPDATE archived_memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&hz)
            .execute(broad.pool())
            .await
            .expect("re-key hazard");
        assert!(
            store
                .apply_remote_restore(&admin_ctx(), &hz)
                .await
                .expect("unchecked restore"),
            "hazard control: without the re-check the moved archived row is resurrected"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn links_lane_refused_after_concurrent_move_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP links_lane_refused_after_concurrent_move_pg_4447: no URL");
            return;
        };
        let app = uniq("f1-4447");
        let store = connect_app(&url, &app).await;
        let (root, secure) = (uniq("public"), uniq("secure/ops"));
        let (a, b) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        for id in [&a, &b] {
            store
                .store(&admin_ctx(), &seed_row(id, &format!("{root}/shared")))
                .await
                .expect("seed");
        }
        let link = link_between(&a, &b);
        let broad = connect(&url).await;
        let mut tx = broad.pool().begin().await.expect("begin");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&b)
            .fetch_one(&mut *tx)
            .await
            .expect("lock endpoint");
        let (s2, root2, l2) = (store.clone(), root.clone(), link.clone());
        let task = tokio::spawn(async move {
            let auth = in_scope(&root2);
            s2.apply_remote_link_authorized(&admin_ctx(), &l2, "unsigned", &auth)
                .await
        });
        wait_blocked(&broad, &app).await;
        sqlx::query("UPDATE memories SET namespace = $1 WHERE id = $2")
            .bind(&secure)
            .bind(&b)
            .execute(&mut *tx)
            .await
            .expect("move endpoint");
        tx.commit().await.expect("commit move");
        typed_refusal(task.await.expect("task"), "links", FEDERATION_APPLY_LINK);
        let edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&a)
        .bind(&b)
        .fetch_one(broad.pool())
        .await
        .expect("count");
        assert_eq!(
            edges, 0,
            "no edge may be written into a row moved out of scope"
        );

        // HAZARD CONTROL.
        store
            .apply_remote_link(&admin_ctx(), &link, "unsigned")
            .await
            .expect("unchecked link");
        let edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&a)
        .bind(&b)
        .fetch_one(broad.pool())
        .await
        .expect("count");
        assert_eq!(
            edges, 1,
            "hazard control: without the re-check the cross-namespace edge is written"
        );
    }

    /// R1 (f2r, #4369): the authorized link replay must take ONE lock per
    /// endpoint. If it took `FOR KEY SHARE` (the #4369 replay lock) and then a
    /// `FOR UPDATE` re-check on the same rows, two replays sharing an endpoint
    /// would each hold a key-share and wait for the other's to go: 40P01.
    ///
    /// Deterministic barrier: the test itself holds `FOR KEY SHARE` on both
    /// endpoints for the whole cell. A key-share -> update replay blocks on that
    /// held lock AFTER taking its own key-share, so two of them deadlock; a
    /// single `FOR SHARE` per endpoint is compatible with a held key-share, so
    /// both replays complete while the barrier is still held. The cell awaits
    /// both BEFORE releasing the barrier, so the old shape fails either with
    /// 40P01 or with the timeout (a replay still blocked on the other).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_authorized_link_replays_do_not_deadlock_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP concurrent_authorized_link_replays_do_not_deadlock_pg_4447: no URL");
            return;
        };
        let store = connect(&url).await;
        let root = uniq("public");
        let (a, b) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        for id in [&a, &b] {
            store
                .store(&admin_ctx(), &seed_row(id, &format!("{root}/shared")))
                .await
                .expect("seed");
        }
        let barrier = connect(&url).await;
        let mut tx = barrier.pool().begin().await.expect("begin");
        for id in [&a, &b] {
            sqlx::query("SELECT id FROM memories WHERE id = $1 FOR KEY SHARE")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .expect("hold key-share barrier");
        }
        let mut tasks = Vec::new();
        for relation in [
            MemoryLinkRelation::DerivedFrom,
            MemoryLinkRelation::RelatedTo,
        ] {
            let (s2, root2) = (store.clone(), root.clone());
            let mut link = link_between(&a, &b);
            link.relation = relation;
            tasks.push(tokio::spawn(async move {
                let auth = in_scope(&root2);
                s2.apply_remote_link_authorized(&admin_ctx(), &link, "unsigned", &auth)
                    .await
            }));
        }
        for t in tasks {
            let res = tokio::time::timeout(Duration::from_secs(20), t)
                .await
                .expect(
                    "an authorized link replay is still blocked while only a key-share is \
                     held: it took a lock that conflicts with key-share (upgrade deadlock shape)",
                )
                .expect("task");
            if let Err(e) = &res {
                assert!(
                    !e.to_string().contains("40P01") && !e.to_string().contains("deadlock"),
                    "authorized link replay deadlocked: {e}"
                );
            }
            res.expect("authorized link replay");
        }
        tx.rollback().await.expect("release barrier");
        let edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM memory_links WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&a)
        .bind(&b)
        .fetch_one(barrier.pool())
        .await
        .expect("count");
        assert_eq!(edges, 2, "both replays must land their edge");
    }

    /// R1(a) (code review): even without #4209/#4369, the carrier's LOCAL link
    /// write takes the SOURCE row `FOR UPDATE` and its `memory_links` INSERT then
    /// takes the foreign key's `FOR KEY SHARE` on the TARGET, in that order
    /// whatever the ids. An authorized replay that locked `FOR UPDATE` in
    /// ascending id order deadlocked with it whenever the source sorts after the
    /// target. `FOR SHARE` on both endpoints is compatible with that key-share
    /// and holds a relocation off, so the pair completes.
    ///
    /// Deterministic barrier: the local tx holds the source `FOR UPDATE`; the
    /// replay is observed blocked on it (it already holds the lower id), and
    /// only then does the local tx run its INSERT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authorized_link_replay_does_not_deadlock_with_a_local_link_write_pg_4447() {
        let Some(url) = url() else {
            eprintln!(
                "SKIP authorized_link_replay_does_not_deadlock_with_a_local_link_write_pg_4447: no URL"
            );
            return;
        };
        let app = uniq("f1-4447");
        let store = connect_app(&url, &app).await;
        let root = uniq("public");
        let mut ids = [
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        ];
        ids.sort();
        let [low, high] = ids;
        for id in [&low, &high] {
            store
                .store(&admin_ctx(), &seed_row(id, &format!("{root}/shared")))
                .await
                .expect("seed");
        }
        // The local write: source = the HIGHER id, target = the lower one.
        let local = connect(&url).await;
        let mut tx = local.pool().begin().await.expect("begin");
        sqlx::query("SELECT id FROM memories WHERE id = $1 FOR UPDATE")
            .bind(&high)
            .fetch_one(&mut *tx)
            .await
            .expect("local link locks its source");
        let (s2, root2, l2) = (store.clone(), root.clone(), link_between(&high, &low));
        let task = tokio::spawn(async move {
            let auth = in_scope(&root2);
            s2.apply_remote_link_authorized(&admin_ctx(), &l2, "unsigned", &auth)
                .await
        });
        wait_blocked(&local, &app).await;
        tokio::time::timeout(
            Duration::from_secs(20),
            sqlx::query(
                "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
                 VALUES ($1, $2, 'related_to', now(), 'unsigned')",
            )
            .bind(&high)
            .bind(&low)
            .execute(&mut *tx),
        )
        .await
        .expect("the local link INSERT is blocked by the replay (lock-order deadlock shape)")
        .expect("the local link INSERT must not deadlock with an authorized replay (40P01)");
        tx.commit().await.expect("commit local link");
        tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("the authorized replay never finished")
            .expect("task")
            .expect("the authorized replay must not deadlock with a local link write");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn by_id_refusals_are_permission_denied_variants_pg_4447() {
        let Some(url) = url() else {
            eprintln!("SKIP by_id_refusals_are_permission_denied_variants_pg_4447: no URL");
            return;
        };
        let store = connect(&url).await;
        assert_typed_refusals("postgres", store.as_ref()).await;
    }
}
