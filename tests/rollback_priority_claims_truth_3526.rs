// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3526 — `curator --rollback` receipt truth for a `PriorityAdjust`
//! reversal, on BOTH backends and BOTH twins.
//!
//! The defect (found by the #3521 coverage lane): the store-backed
//! `autonomy::reverse_rollback_entry_store` `PriorityAdjust` arm restored the
//! prior priority with `get -> mutate -> store.store`. `store.store` is the
//! CREATE funnel, and its `(title, namespace)` upsert-merge resolves
//! `priority = MAX(memories.priority, excluded.priority)` (`GREATEST(...)` on
//! postgres). The row always exists on that path, so the merge always fired: a
//! reversal that RAISES a priority worked, and a reversal that must LOWER one —
//! undoing an earlier raise, which is the whole point — was a silent no-op that
//! still printed `rollback <id>: applied`. On an audited reversal path that is a
//! claims-truth defect: the log says the adjustment was undone, the substrate
//! says otherwise.
//!
//! What this suite pins:
//!
//! * **the LOWERING direction lands** — through the store twin (SAL sqlite +
//!   live postgres), through the rusqlite twin, and end-to-end through the
//!   `ai-memory curator --rollback --store-url sqlite://…` CLI;
//! * **the RAISING direction still works** — the fix is not a swap of one
//!   broken direction for another;
//! * **`db::insert`'s MAX-merge is UNCHANGED** — the create funnel still floors
//!   priority upward on a `(title, namespace)` re-store (other callers depend on
//!   it); it is the ROLLBACK that stopped using it;
//! * **the receipt is asserted against the substrate** — a store that ACCEPTS
//!   the write and does not move the row is REFUSED (`rollback not applied`),
//!   never reported as applied;
//! * **the CLI prints `not applied` and exits non-zero** on a refused reversal,
//!   and leaves the rollback-log row UNTAGGED so the entry stays reversible;
//! * **a reversal whose target row is gone is a no-op, not an `applied`** — the
//!   rusqlite twin used to discard `db::update`'s `found` bool and claim
//!   `applied` for a memory that no longer exists.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names
)]

use ai_memory::autonomy::{self, RollbackEntry};
use ai_memory::models::{
    ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier, default_metadata,
};

const NS: &str = "rb-3526";

/// A seed memory. `title` is the upsert key half that makes the create
/// funnel's MAX-merge reachable, so every case names it explicitly.
fn memory(id: &str, title: &str, priority: i32) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "agent_id".to_string(),
            serde_json::Value::String("ai:curator".to_string()),
        );
    }
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        tags: Vec::new(),
        priority,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
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
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ───────────────────────────────────────────────────────────────────────────
// The rusqlite (direct-connection) twin — `autonomy::reverse_rollback_entry`.
// Unaffected by the MAX-merge (it always wrote through the explicit
// `db::update` funnel), but it must stay in parity on the RECEIPT.
// ───────────────────────────────────────────────────────────────────────────

fn open_conn() -> rusqlite::Connection {
    ai_memory::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

#[test]
fn conn_twin_rollback_lowers_priority_and_reports_applied_3526() {
    let conn = open_conn();
    let mem = memory(&uid("conn-lower"), "conn lower", 4);
    ai_memory::db::insert(&conn, &mem).expect("seed");
    // A prior +5 adjustment raised the row 4 -> 9.
    let (found, _) = ai_memory::db::update(
        &conn,
        &mem.id,
        None,
        None,
        None,
        None,
        None,
        Some(9),
        None,
        None,
        None,
    )
    .expect("raise");
    assert!(found, "the raise must land");

    let entry = RollbackEntry::PriorityAdjust {
        memory_id: mem.id.clone(),
        before: 4,
        after: 9,
    };
    let applied = autonomy::reverse_rollback_entry(&conn, &entry).expect("reverse");
    assert!(applied, "the reversal must report applied");
    let durable = ai_memory::db::get(&conn, &mem.id)
        .expect("read back")
        .expect("row present");
    assert_eq!(
        durable.priority, 4,
        "the DURABLE priority must be the ORIGINAL, not the raised value"
    );
}

#[test]
fn conn_twin_rollback_raises_priority_still_works_3526() {
    let conn = open_conn();
    let mem = memory(&uid("conn-raise"), "conn raise", 9);
    ai_memory::db::insert(&conn, &mem).expect("seed");
    let (found, _) = ai_memory::db::update(
        &conn,
        &mem.id,
        None,
        None,
        None,
        None,
        None,
        Some(4),
        None,
        None,
        None,
    )
    .expect("lower");
    assert!(found, "the lowering adjustment must land");

    let entry = RollbackEntry::PriorityAdjust {
        memory_id: mem.id.clone(),
        before: 9,
        after: 4,
    };
    assert!(
        autonomy::reverse_rollback_entry(&conn, &entry).expect("reverse"),
        "the reversal must report applied"
    );
    assert_eq!(
        ai_memory::db::get(&conn, &mem.id)
            .expect("read back")
            .expect("row present")
            .priority,
        9,
        "the positive direction must keep working"
    );
}

/// Pre-#3526 this arm discarded `db::update`'s `found` bool and returned
/// `true` unconditionally, so `curator --rollback` printed `applied` for a
/// memory that no longer exists. The store twin already returned `false`.
#[test]
fn conn_twin_rollback_of_a_vanished_target_is_a_no_op_3526() {
    let conn = open_conn();
    let entry = RollbackEntry::PriorityAdjust {
        memory_id: uid("conn-gone"),
        before: 4,
        after: 9,
    };
    let applied = autonomy::reverse_rollback_entry(&conn, &entry).expect("reverse");
    assert!(
        !applied,
        "a reversal whose target row does not exist must report a no-op, never `applied`"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The store-backed twin — `autonomy::reverse_rollback_entry_store`.
// ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal")]
mod sal {
    use super::{memory, uid};
    use ai_memory::autonomy::{self, RollbackEntry};
    use ai_memory::cli::CliOutput;
    use ai_memory::cli::curator::{CuratorArgs, run};
    use ai_memory::config::AppConfig;
    use ai_memory::models::{AgentRegistration, Memory, MemoryLink};
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{
        CallerContext, Capabilities, Filter, MemoryStore, StoreError, StoreResult, UpdatePatch,
        VerifyReport,
    };

    const ROLLBACK_NS: &str = "_curator/rollback";

    fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rollback-3526.db");
        (dir, path)
    }

    fn ctx() -> CallerContext {
        CallerContext::for_admin("ai:curator")
    }

    fn args_for(store_url: &std::path::Path) -> CuratorArgs {
        CuratorArgs {
            once: false,
            daemon: false,
            interval_secs: 3_600,
            max_ops: 1,
            dry_run: false,
            include_namespaces: Vec::new(),
            exclude_namespaces: Vec::new(),
            json: false,
            prune_reports: false,
            apply: false,
            rollback: None,
            rollback_last: None,
            reflect: false,
            namespace: None,
            max_depth: None,
            all_namespaces: false,
            store_url: Some(format!("sqlite://{}", store_url.display())),
        }
    }

    /// A rollback-log row: a memory in `_curator/rollback` whose CONTENT is the
    /// serialised `RollbackEntry` — the exact shape the CLI reads.
    fn log_row(title: &str, entry: &RollbackEntry) -> Memory {
        let mut m = memory(&uid("log"), title, 5);
        m.namespace = ROLLBACK_NS.to_string();
        m.content = serde_json::to_string(entry).expect("serialise rollback entry");
        m
    }

    /// The store-backed reversal must LOWER a priority the create funnel's
    /// `MAX(...)` merge refuses to lower.
    #[tokio::test]
    async fn store_twin_rollback_lowers_priority_3526() {
        let (_dir, db) = tmp_db();
        let store = SqliteStore::open(&db).expect("open sal sqlite store");
        let ctx = ctx();
        let target = memory(&uid("sal-lower"), "sal lower", 4);
        store.store(&ctx, &target).await.expect("seed");

        // A prior +5 adjustment raised the row 4 -> 9.
        store
            .update(
                &ctx,
                &target.id,
                UpdatePatch {
                    priority: Some(9),
                    ..Default::default()
                },
            )
            .await
            .expect("raise");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the raise must land before the reversal is exercised"
        );

        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 4,
            after: 9,
        };
        let applied = autonomy::reverse_rollback_entry_store(&store, &ctx, &entry)
            .await
            .expect("reverse");
        assert!(applied, "the reversal must report applied");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            4,
            "#3526: the DURABLE priority must be the ORIGINAL — pre-fix the \
             create-funnel MAX-merge kept 9 while the receipt said `applied`"
        );
    }

    /// The direction that always worked must keep working.
    #[tokio::test]
    async fn store_twin_rollback_raises_priority_3526() {
        let (_dir, db) = tmp_db();
        let store = SqliteStore::open(&db).expect("open sal sqlite store");
        let ctx = ctx();
        let target = memory(&uid("sal-raise"), "sal raise", 9);
        store.store(&ctx, &target).await.expect("seed");
        store
            .update(
                &ctx,
                &target.id,
                UpdatePatch {
                    priority: Some(4),
                    ..Default::default()
                },
            )
            .await
            .expect("lower");

        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 9,
            after: 4,
        };
        assert!(
            autonomy::reverse_rollback_entry_store(&store, &ctx, &entry)
                .await
                .expect("reverse"),
            "the reversal must report applied"
        );
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the positive direction must keep working"
        );
    }

    /// A reversal whose target row is gone is a no-op on both twins.
    #[tokio::test]
    async fn store_twin_rollback_of_a_vanished_target_is_a_no_op_3526() {
        let (_dir, db) = tmp_db();
        let store = SqliteStore::open(&db).expect("open sal sqlite store");
        let entry = RollbackEntry::PriorityAdjust {
            memory_id: uid("sal-gone"),
            before: 4,
            after: 9,
        };
        assert!(
            !autonomy::reverse_rollback_entry_store(&store, &ctx(), &entry)
                .await
                .expect("reverse"),
            "a reversal whose target row does not exist must report a no-op"
        );
    }

    /// #3526 scope guard — `db::insert`'s `(title, namespace)` upsert STILL
    /// merges `priority` with `MAX(...)`. Other callers depend on that; the fix
    /// is that the ROLLBACK stopped using the create funnel, not that the
    /// funnel changed.
    #[tokio::test]
    async fn create_funnel_still_max_merges_priority_3526() {
        let (_dir, db) = tmp_db();
        let store = SqliteStore::open(&db).expect("open sal sqlite store");
        let ctx = ctx();
        let mut target = memory(&uid("sal-merge"), "sal merge", 9);
        store.store(&ctx, &target).await.expect("seed at 9");
        // Re-store the SAME (title, namespace) carrying a LOWER priority.
        target.priority = 4;
        store.store(&ctx, &target).await.expect("re-store at 4");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the create funnel must still floor priority upward (unchanged by #3526)"
        );
    }

    // ── the receipt is asserted against the SUBSTRATE ───────────────────────

    /// A store that ACCEPTS the update and does not move the row — precisely
    /// what the create funnel's MAX-merge did. The reversal must REFUSE, not
    /// report `applied`.
    struct AcceptsButDoesNotApply {
        row: std::sync::Mutex<Memory>,
    }

    #[async_trait::async_trait]
    impl MemoryStore for AcceptsButDoesNotApply {
        fn capabilities(&self) -> Capabilities {
            Capabilities::DURABLE
        }
        async fn store(&self, _ctx: &CallerContext, memory: &Memory) -> StoreResult<String> {
            Ok(memory.id.clone())
        }
        async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
            // CONCURRENCY-20 — the guard is scoped to the read; nothing holds a
            // blocking lock across an await point in this adapter.
            let row = { self.row.lock().expect("row lock").clone() };
            if row.id == id {
                Ok(row)
            } else {
                Err(StoreError::NotFound { id: id.to_string() })
            }
        }
        /// Accepts the patch and writes NOTHING — the pre-#3526 substrate
        /// behaviour for a priority the merge refused to lower.
        async fn update(
            &self,
            _ctx: &CallerContext,
            _id: &str,
            _patch: UpdatePatch,
        ) -> StoreResult<()> {
            Ok(())
        }
        async fn delete(&self, _ctx: &CallerContext, id: &str) -> StoreResult<()> {
            Err(StoreError::NotFound { id: id.to_string() })
        }
        async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
            Ok(Vec::new())
        }
        async fn search(
            &self,
            _ctx: &CallerContext,
            _query: &str,
            _filter: &Filter,
        ) -> StoreResult<Vec<Memory>> {
            Ok(Vec::new())
        }
        async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
            Ok(VerifyReport {
                memory_id: id.to_string(),
                integrity_ok: true,
                findings: Vec::new(),
                signature_verified: false,
                cid_ok: None,
                cid_mismatch: None,
            })
        }
        async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
            Ok(())
        }
        async fn list_links(&self, _namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
            Ok(Vec::new())
        }
        async fn register_agent(
            &self,
            _ctx: &CallerContext,
            _agent: &AgentRegistration,
        ) -> StoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_write_the_substrate_did_not_take_is_refused_not_applied_3526() {
        let target = memory(&uid("liar"), "liar", 9);
        let store = AcceptsButDoesNotApply {
            row: std::sync::Mutex::new(target.clone()),
        };
        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 4,
            after: 9,
        };
        let err = autonomy::reverse_rollback_entry_store(&store, &ctx(), &entry)
            .await
            .expect_err("a write the substrate did not take must be REFUSED")
            .to_string();
        assert!(
            err.contains("rollback not applied"),
            "the refusal must say the reversal was NOT applied; got: {err}"
        );
        assert!(
            err.contains("priority is 9") && err.contains("reversed-to 4"),
            "the refusal must name the durable value and the intended one; got: {err}"
        );
    }

    // ── the CLI receipt ────────────────────────────────────────────────────

    /// End-to-end through `ai-memory curator --rollback --store-url sqlite://…`:
    /// the LOWERING reversal lands on the durable row AND the receipt says
    /// `applied`.
    #[tokio::test]
    async fn cli_store_backed_rollback_lowers_priority_and_says_applied_3526() {
        let (_dir, db) = tmp_db();
        let target = memory(&uid("cli-lower"), "cli lower", 4);
        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 4,
            after: 9,
        };
        let log = log_row("cli lower log", &entry);
        {
            let store = SqliteStore::open(&db).expect("open sal sqlite store");
            let ctx = ctx();
            store.store(&ctx, &target).await.expect("seed target");
            store.store(&ctx, &log).await.expect("seed log");
            // The prior adjustment: 4 -> 9.
            store
                .update(
                    &ctx,
                    &target.id,
                    UpdatePatch {
                        priority: Some(9),
                        ..Default::default()
                    },
                )
                .await
                .expect("raise");
        }

        let cfg = AppConfig::default();
        let mut args = args_for(&db);
        args.rollback = Some(log.id.clone());
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect("store-backed --rollback");
        }
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(
            text.contains("applied") && !text.contains("not applied"),
            "the receipt must report applied; got: {text}"
        );

        let store = SqliteStore::open(&db).expect("reopen sal sqlite store");
        assert_eq!(
            store.get(&ctx(), &target.id).await.expect("read").priority,
            4,
            "#3526: the DURABLE priority must be the ORIGINAL after the CLI rollback"
        );
    }

    /// A REFUSED reversal must print `not applied`, exit non-zero, leave the
    /// log row UNTAGGED (still reversible) and destroy nothing.
    ///
    /// The refusal driven here is the shipped `(title, namespace)` collision
    /// guard: a DIFFERENT id took the original's slot after the consolidation,
    /// so the restore is refused before the summary is deleted (G3 ordering).
    #[tokio::test]
    async fn cli_store_backed_refusal_prints_not_applied_and_leaves_the_entry_reversible_3526() {
        let (_dir, db) = tmp_db();
        let original = memory(&uid("orig"), "collide title", 5);
        let summary = memory(&uid("summary"), "[consolidated] collide", 5);
        let intruder = memory(&uid("intruder"), "collide title", 5);
        let entry = RollbackEntry::Consolidate {
            originals: vec![original],
            result_id: summary.id.clone(),
        };
        let log = log_row("collision log", &entry);
        {
            let store = SqliteStore::open(&db).expect("open sal sqlite store");
            let ctx = ctx();
            store.store(&ctx, &summary).await.expect("seed summary");
            store.store(&ctx, &intruder).await.expect("seed intruder");
            store.store(&ctx, &log).await.expect("seed log");
        }

        let cfg = AppConfig::default();
        let mut args = args_for(&db);
        args.rollback = Some(log.id.clone());
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let err = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run(&db, &args, &cfg, &mut out)
                .await
                .expect_err("a refused reversal must exit non-zero")
                .to_string()
        };
        assert!(
            err.contains("rollback refused"),
            "the error must name the refusal; got: {err}"
        );
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(
            text.contains("not applied"),
            "the receipt must say NOT applied; got: {text}"
        );
        assert!(
            !text.contains(": applied"),
            "a refused reversal must never print an `applied` receipt; got: {text}"
        );

        let store = SqliteStore::open(&db).expect("reopen sal sqlite store");
        let ctx = ctx();
        assert!(
            !store
                .get(&ctx, &log.id)
                .await
                .expect("log row")
                .tags
                .iter()
                .any(|t| t == "_reversed"),
            "a refused reversal must leave the log row UNTAGGED so it stays reversible"
        );
        assert!(
            store.get(&ctx, &summary.id).await.is_ok(),
            "the fail-safe ordering must leave the consolidated summary intact"
        );
        assert!(
            store.get(&ctx, &intruder.id).await.is_ok(),
            "the collision guard must never clobber the occupying row"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Live-postgres arm — the backend an operator running `--store-url
// postgres://…` actually reaches, and the one whose `GREATEST(...)` merge the
// pre-fix rollback rode. Gated on `AI_MEMORY_TEST_POSTGRES_URL` (the
// skip-if-unset convention shared by tests/cov_postgres_core.rs).
// ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{memory, uid};
    use ai_memory::autonomy::{self, RollbackEntry};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, UpdatePatch};

    /// Printed on every arm that actually ran so a CI leg can prove the
    /// postgres cases were EXERCISED rather than silently skipped.
    const RAN_MARKER: &str = "#3526 pg arm RAN";

    async fn connect() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        Some(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        )
    }

    #[tokio::test]
    async fn pg_rollback_lowers_priority_3526() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_admin("ai:curator");
        let target = memory(&uid("pg-lower"), &uid("pg lower"), 4);
        store.store(&ctx, &target).await.expect("seed");
        store
            .update(
                &ctx,
                &target.id,
                UpdatePatch {
                    priority: Some(9),
                    ..Default::default()
                },
            )
            .await
            .expect("raise");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the raise must land before the reversal is exercised"
        );

        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 4,
            after: 9,
        };
        let applied = autonomy::reverse_rollback_entry_store(&store, &ctx, &entry)
            .await
            .expect("reverse");
        assert!(applied, "the reversal must report applied");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            4,
            "#3526: the DURABLE priority must be the ORIGINAL — pre-fix the \
             create funnel's GREATEST(...) merge kept 9 while the receipt said `applied`"
        );

        let _ = store.delete(&ctx, &target.id).await;
        eprintln!("{RAN_MARKER}: pg_rollback_lowers_priority_3526");
    }

    #[tokio::test]
    async fn pg_rollback_raises_priority_3526() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_admin("ai:curator");
        let target = memory(&uid("pg-raise"), &uid("pg raise"), 9);
        store.store(&ctx, &target).await.expect("seed");
        store
            .update(
                &ctx,
                &target.id,
                UpdatePatch {
                    priority: Some(4),
                    ..Default::default()
                },
            )
            .await
            .expect("lower");

        let entry = RollbackEntry::PriorityAdjust {
            memory_id: target.id.clone(),
            before: 9,
            after: 4,
        };
        assert!(
            autonomy::reverse_rollback_entry_store(&store, &ctx, &entry)
                .await
                .expect("reverse"),
            "the reversal must report applied"
        );
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the positive direction must keep working on postgres"
        );

        let _ = store.delete(&ctx, &target.id).await;
        eprintln!("{RAN_MARKER}: pg_rollback_raises_priority_3526");
    }

    /// #3526 scope guard — the postgres create funnel still `GREATEST(...)`-
    /// merges priority. Unchanged; the rollback simply stopped using it.
    #[tokio::test]
    async fn pg_create_funnel_still_max_merges_priority_3526() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_admin("ai:curator");
        let mut target = memory(&uid("pg-merge"), &uid("pg merge"), 9);
        store.store(&ctx, &target).await.expect("seed at 9");
        target.priority = 4;
        store.store(&ctx, &target).await.expect("re-store at 4");
        assert_eq!(
            store.get(&ctx, &target.id).await.expect("read").priority,
            9,
            "the postgres create funnel must still floor priority upward (unchanged by #3526)"
        );

        let _ = store.delete(&ctx, &target.id).await;
        eprintln!("{RAN_MARKER}: pg_create_funnel_still_max_merges_priority_3526");
    }

    /// A reversal whose target row is gone is a no-op on postgres too.
    #[tokio::test]
    async fn pg_rollback_of_a_vanished_target_is_a_no_op_3526() {
        let Some(store) = connect().await else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let ctx = CallerContext::for_admin("ai:curator");
        let entry = RollbackEntry::PriorityAdjust {
            memory_id: uid("pg-gone"),
            before: 4,
            after: 9,
        };
        assert!(
            !autonomy::reverse_rollback_entry_store(&store, &ctx, &entry)
                .await
                .expect("reverse"),
            "a reversal whose target row does not exist must report a no-op"
        );
        eprintln!("{RAN_MARKER}: pg_rollback_of_a_vanished_target_is_a_no_op_3526");
    }
}
