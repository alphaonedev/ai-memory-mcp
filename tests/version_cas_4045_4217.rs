// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4045 / #4217 — the version compare-and-set contract, pinned on BOTH
//! backends (5-agent vote 4d3ea1c5, memory 656eb5ff, verdict A amended).
//!
//! * #4045 vote item 2 (error parity): a source whose `version` drifted after
//!   the caller read it refuses the whole consolidation as
//!   `StoreError::Conflict` carrying the drifted id — on sqlite too, where the
//!   typed storage `VersionConflict` used to surface as an opaque
//!   `Backend(String)`. Nothing commits: the sources stay live with their
//!   newer text and no summary row exists.
//! * #4045 vote item 4 / #4217 (every data mutation bumps `version`): the
//!   consolidation source tombstone, the postgres in-place title-slot
//!   overwrite of a destination row, the contradiction marker write and its
//!   reversal, and the agent-registration pubkey bind/revoke all change an
//!   EXISTING row, so each bumps `version`. A reader holding the pre-write
//!   version is then refused by every compare-and-set (If-Match update, a
//!   later version-checked consolidation) instead of silently overwriting the
//!   change. `tests/version_bump_census_4217.rs` is the structural gate.
//!
//! Every cell is RED on the pre-fix tree and GREEN after it.

use ai_memory::db;

const AGENTS_NAMESPACE: &str = "_agents";

fn db_mem(ns: &str, title: &str, content: &str) -> ai_memory::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test-4217".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": "ai:tester-4217" }),
        ..ai_memory::models::Memory::default()
    }
}

fn open_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("db.sqlite")).expect("db::open");
    (dir, conn)
}

fn sqlite_version(conn: &rusqlite::Connection, id: &str) -> i64 {
    conn.query_row("SELECT version FROM memories WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .expect("row version")
}

fn sqlite_registration_version(conn: &rusqlite::Connection, agent: &str) -> i64 {
    conn.query_row(
        "SELECT version FROM memories WHERE namespace = ?1 AND title = ?2",
        [AGENTS_NAMESPACE, &format!("agent:{agent}")],
        |r| r.get(0),
    )
    .expect("registration row version")
}

/// #4217 — the G7 contradiction marker is written onto an EXISTING row; a
/// full-metadata If-Match edit from a pre-marker reader must be refused
/// rather than silently wiping the markers.
#[test]
fn sqlite_contradiction_conserve_and_reverse_bump_loser_version_4217() {
    let (_dir, conn) = open_db();
    let loser = db_mem("cas-4217/conserve", "loser", "the sky is green");
    let winner = db_mem("cas-4217/conserve", "winner", "the sky is blue");
    db::insert(&conn, &loser).expect("insert loser");
    db::insert(&conn, &winner).expect("insert winner");
    let loser = db::get(&conn, &loser.id)
        .expect("get")
        .expect("loser present");
    let before = sqlite_version(&conn, &loser.id);

    db::conserve_contradiction(&conn, &loser, &winner.id, None).expect("conserve");
    assert_eq!(
        sqlite_version(&conn, &loser.id),
        before + 1,
        "the contradiction marker write bumps the loser's version"
    );

    let (src, tgt) = db::canonical_contradiction_pair(&loser.id, &winner.id);
    db::reverse_conserve_contradiction(&conn, &loser.id, src, tgt).expect("reverse");
    assert_eq!(
        sqlite_version(&conn, &loser.id),
        before + 2,
        "clearing the markers bumps the loser's version again"
    );
}

/// #4217 — the agent-registration row's metadata/content change on bind and
/// revoke; both bump its version.
#[test]
fn sqlite_pubkey_bind_and_revoke_bump_registration_version_4217() {
    let (_dir, conn) = open_db();
    let agent = "ai:bind-4217";
    db::register_agent(&conn, agent, "nhi", &[]).expect("register");
    let before = sqlite_registration_version(&conn, agent);
    let kp = ai_memory::identity::keypair::generate(agent).expect("generate");
    db::bind_agent_pubkey_with_keypair(&conn, agent, &kp).expect("bind");
    assert_eq!(
        sqlite_registration_version(&conn, agent),
        before + 1,
        "binding a pubkey bumps the registration row's version"
    );
    db::revoke_agent_pubkey(&conn, agent).expect("revoke");
    assert_eq!(
        sqlite_registration_version(&conn, agent),
        before + 2,
        "revoking the pubkey bumps the registration row's version"
    );
}

#[cfg(feature = "sal")]
mod consolidation_4045 {
    use ai_memory::models::{Memory, Tier};
    use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError, UpdatePatch};

    const AGENT: &str = "ai:curator";

    fn mem(ns: &str, title: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            priority: 5,
            confidence: 1.0,
            source: "test-4045".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ "agent_id": AGENT }),
            ..Memory::default()
        }
    }

    /// The tombstone disposition is the production default; the flags are
    /// process-global, and every cell in this binary wants them ON, so they are
    /// only ever set (never reset) to keep parallel cells race-free.
    fn tombstone_disposition_on() {
        ai_memory::config::set_lineage_dag(true);
        ai_memory::config::set_consolidate_tombstone_sources(true);
    }

    /// Store two sources and return `(ids, versions)` as read back.
    async fn seed_pair(store: &dyn MemoryStore, ns: &str, tag: &str) -> (Vec<String>, Vec<i64>) {
        let ctx = CallerContext::for_admin(AGENT);
        let mut ids = Vec::new();
        let mut versions = Vec::new();
        for n in 0..2 {
            let m = mem(
                ns,
                &format!("{tag}-source-{n}"),
                &format!("{tag} source {n} original text"),
            );
            let id = store.store(&ctx, &m).await.expect("store source");
            versions.push(store.get(&ctx, &id).await.expect("get source").version);
            ids.push(id);
        }
        (ids, versions)
    }

    /// Vote item 2: read versions, commit a newer edit to source 0, then
    /// consolidate with the stale versions. Returns the refusal + the edited id.
    async fn stale_consolidation(store: &dyn MemoryStore, ns: &str) -> (ConsolidateResult, String) {
        let ctx = CallerContext::for_admin(AGENT);
        let (ids, versions) = seed_pair(store, ns, "stale").await;
        store
            .update(
                &ctx,
                &ids[0],
                UpdatePatch {
                    content: Some("distinctive committed v2".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("concurrent edit");
        let result = store
            .consolidate_with_expected_versions(
                &ctx,
                &ids,
                "stale summary",
                "summary of v1 only",
                ns,
                &Tier::Long,
                "consolidation",
                AGENT,
                Some(&versions),
            )
            .await;
        (result, ids[0].clone())
    }

    type ConsolidateResult = Result<String, StoreError>;

    async fn assert_stale_refused_as_conflict(store: &dyn MemoryStore, ns: &str) {
        let (result, edited) = stale_consolidation(store, ns).await;
        match result {
            Err(StoreError::Conflict { id }) => {
                assert_eq!(id, edited, "Conflict names the drifted source")
            }
            other => panic!("a stale source must refuse as StoreError::Conflict, got {other:?}"),
        }
        let ctx = CallerContext::for_admin(AGENT);
        assert_eq!(
            store
                .get(&ctx, &edited)
                .await
                .expect("edited source still live")
                .content,
            "distinctive committed v2",
            "the committed edit survives the refused consolidation"
        );
        let mut filter = Filter::new();
        filter.namespace = Some(ns.to_string());
        filter.limit = 3;
        assert_eq!(
            store
                .list(&ctx, &filter)
                .await
                .expect("list namespace")
                .len(),
            2,
            "no summary row commits and both sources stay live"
        );
    }

    /// Vote item 4: a successful version-checked consolidation tombstones its
    /// sources; returns `(ids, versions read before)` for the raw per-backend read.
    async fn consolidate_fresh_pair(
        store: &dyn MemoryStore,
        ns: &str,
        source_tag: &str,
        title: &str,
    ) -> (Vec<String>, Vec<i64>, String) {
        let ctx = CallerContext::for_admin(AGENT);
        let (ids, versions) = seed_pair(store, ns, source_tag).await;
        let summary_id = store
            .consolidate_with_expected_versions(
                &ctx,
                &ids,
                title,
                &format!("{title} summary text"),
                ns,
                &Tier::Long,
                "consolidation",
                AGENT,
                Some(&versions),
            )
            .await
            .expect("fresh versions consolidate (control)");
        (ids, versions, summary_id)
    }

    // ---------------------------------------------------------------- sqlite

    fn sqlite_store() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        ai_memory::store::sqlite::SqliteStore,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("db.sqlite");
        let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("SqliteStore::open");
        (dir, path, store)
    }

    fn sqlite_row(path: &std::path::Path, id: &str) -> (i64, String) {
        let side = rusqlite::Connection::open(path).expect("side connection");
        side.query_row(
            "SELECT version, lifecycle_state FROM memories WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("raw source row")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_stale_source_version_is_store_conflict_4045() {
        tombstone_disposition_on();
        let (_dir, _path, store) = sqlite_store();
        assert_stale_refused_as_conflict(&store, "cas-4045/sqlite-stale").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_consolidation_tombstone_bumps_source_version_4045() {
        tombstone_disposition_on();
        let (_dir, path, store) = sqlite_store();
        let (ids, versions, _) =
            consolidate_fresh_pair(&store, "cas-4045/sqlite-bump", "bump", "bump").await;
        for (id, before) in ids.iter().zip(versions) {
            let (after, state) = sqlite_row(&path, id);
            assert_eq!(state, "tombstoned", "the source is tombstoned, not deleted");
            assert_eq!(
                after,
                before + 1,
                "the tombstone write bumps the source version"
            );
        }
    }

    // -------------------------------------------------------------- postgres

    #[cfg(feature = "sal-postgres")]
    async fn pg_store() -> Option<ai_memory::store::postgres::PostgresStore> {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skipping postgres #4045 cell: AI_MEMORY_TEST_POSTGRES_URL unset");
            return None;
        };
        Some(
            ai_memory::store::postgres::PostgresStore::connect(&url)
                .await
                .expect("connect postgres adapter"),
        )
    }

    #[cfg(feature = "sal-postgres")]
    async fn pg_row(store: &ai_memory::store::postgres::PostgresStore, id: &str) -> (i64, String) {
        sqlx::query_as("SELECT version, lifecycle_state FROM memories WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .expect("raw row")
    }

    #[cfg(feature = "sal-postgres")]
    fn pg_ns(cell: &str) -> String {
        format!("cas-4045/pg-{cell}-{}", uuid::Uuid::new_v4())
    }

    #[cfg(feature = "sal-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn postgres_stale_source_version_is_store_conflict_4045() {
        tombstone_disposition_on();
        let Some(store) = pg_store().await else {
            return;
        };
        assert_stale_refused_as_conflict(&store, &pg_ns("stale")).await;
    }

    #[cfg(feature = "sal-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn postgres_consolidation_tombstone_bumps_source_version_4045() {
        tombstone_disposition_on();
        let Some(store) = pg_store().await else {
            return;
        };
        let (ids, versions, _) =
            consolidate_fresh_pair(&store, &pg_ns("bump"), "bump", "bump").await;
        for (id, before) in ids.iter().zip(versions) {
            let (after, state) = pg_row(&store, id).await;
            assert_eq!(state, "tombstoned", "the source is tombstoned, not deleted");
            assert_eq!(
                after,
                before + 1,
                "the tombstone write bumps the source version"
            );
        }
    }

    /// Postgres-only: the sqlite twin mints the summary with a plain INSERT, so a
    /// title collision never overwrites an existing row there.
    #[cfg(feature = "sal-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn postgres_reconsolidation_upsert_bumps_destination_version_4045() {
        tombstone_disposition_on();
        let Some(store) = pg_store().await else {
            return;
        };
        let ns = pg_ns("upsert");
        let (_, _, first) = consolidate_fresh_pair(&store, &ns, "round1", "slot").await;
        let (before, _) = pg_row(&store, &first).await;
        let (_, _, second) = consolidate_fresh_pair(&store, &ns, "round2", "slot").await;
        assert_eq!(
            second, first,
            "the title-slot upsert reuses the destination row"
        );
        let (after, _) = pg_row(&store, &first).await;
        assert_eq!(
            after,
            before + 1,
            "overwriting the destination's content in place bumps its version"
        );
    }

    #[cfg(feature = "sal-postgres")]
    async fn pg_registration_version(
        store: &ai_memory::store::postgres::PostgresStore,
        agent: &str,
    ) -> i64 {
        sqlx::query_scalar("SELECT version FROM memories WHERE namespace = $1 AND title = $2")
            .bind(super::AGENTS_NAMESPACE)
            .bind(format!("agent:{agent}"))
            .fetch_one(store.pool())
            .await
            .expect("registration row version")
    }

    /// #4217 postgres twin: pubkey bind and revoke bump the registration row.
    #[cfg(feature = "sal-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
    async fn postgres_pubkey_bind_and_revoke_bump_registration_version_4217() {
        let Some(store) = pg_store().await else {
            return;
        };
        let agent = format!("ai:bind-4217-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent(agent.clone());
        let now = chrono::Utc::now().to_rfc3339();
        store
            .register_agent(
                &ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: agent.clone(),
                    agent_type: "nhi".to_string(),
                    capabilities: Vec::new(),
                    registered_at: now.clone(),
                    last_seen_at: now,
                },
            )
            .await
            .expect("register");
        let before = pg_registration_version(&store, &agent).await;
        let kp = ai_memory::identity::keypair::generate(&agent).expect("generate");
        let proof = ai_memory::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent,
            kp.private.as_ref().expect("generated private key"),
        )
        .await
        .expect("prove possession");
        store
            .bind_agent_pubkey(&ctx, &agent, &kp.public_base64(), proof)
            .await
            .expect("bind");
        assert_eq!(
            pg_registration_version(&store, &agent).await,
            before + 1,
            "binding a pubkey bumps the registration row's version"
        );
        store
            .revoke_agent_pubkey(&ctx, &agent)
            .await
            .expect("revoke");
        assert_eq!(
            pg_registration_version(&store, &agent).await,
            before + 2,
            "revoking the pubkey bumps the registration row's version"
        );
    }
}
