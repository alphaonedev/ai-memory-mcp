// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Consolidation Unit 1 (#3690 / #3695 / #3626 — postgres half).
//!
//! The postgres twin of `tests/title_slot_admission_3690.rs`, driven through
//! the SAL (`store`, `store_with_embedding`, `store_with_embedding_no_overwrite`,
//! `restore_or_conflict`, `find_by_title_namespace`) so every pg create funnel
//! is exercised where its statement lives. Gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` (skips with a line under `--nocapture`).
//!
//! Every hidden-row cell is RED on the pre-fix tree (1ec64196b): the full
//! `memories_title_ns_uidx` let `store` MERGE into a tombstone / quarantined
//! row and hand back its id.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

fn mem(id: &str, ns: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["slot-3690".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-3690".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:tester-3690" }),
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

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

async fn set_state(store: &PostgresStore, id: &str, state: &str) {
    sqlx::query("UPDATE memories SET lifecycle_state = $2 WHERE id = $1")
        .bind(id)
        .bind(state)
        .execute(store.pool())
        .await
        .expect("set lifecycle_state");
}

async fn raw(store: &PostgresStore, id: &str) -> (String, String, i64) {
    sqlx::query_as::<_, (String, String, i64)>(
        "SELECT content, lifecycle_state, version FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .expect("row resident")
}

/// `(id, lifecycle_state, cid, version)` — the identity columns the in-place
/// CAS must leave byte-identical (plus the version it bumps).
async fn identity_of(store: &PostgresStore, id: &str) -> (String, String, Option<String>, i64) {
    sqlx::query_as::<_, (String, String, Option<String>, i64)>(
        "SELECT id, lifecycle_state, cid, version FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .expect("row")
}

async fn count_key(store: &PostgresStore, ns: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM memories WHERE title = 'slot' AND namespace = $1",
    )
    .bind(ns)
    .fetch_one(store.pool())
    .await
    .expect("count")
}

fn conflict_id(err: &StoreError) -> &str {
    match err {
        StoreError::Conflict { id } => id.as_str(),
        other => panic!("expected StoreError::Conflict, got {other:?}"),
    }
}

/// #3690 — the schema claim on the pg side: the ladder tip is 100 and the
/// SHIPPED index (after the ladder, which runs on every connect) is PARTIAL
/// on the ONE predicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_schema_v100_carries_the_partial_title_slot_index_3690() {
    let Some(store) = connect().await else { return };
    let version: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(store.pool())
        .await
        .expect("schema_version");
    assert_eq!(version, 100);
    let indexdef: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'memories_title_ns_uidx'",
    )
    .fetch_one(store.pool())
    .await
    .expect("the title-slot index exists");
    assert!(
        indexdef.contains("WHERE (lifecycle_state <> 'tombstoned'::text)")
            || indexdef.contains(ai_memory::models::TITLE_SLOT_INDEX_PREDICATE),
        "memories_title_ns_uidx must be PARTIAL on the ONE predicate; got: {indexdef}"
    );
    assert!(indexdef.contains("UNIQUE"), "still unique: {indexdef}");
}

/// #3690 — a store beside a consolidation tombstone lands as a fresh, visible
/// row; the tombstone is byte-identical. (Pre-fix: merged into the tombstone,
/// returned its id, invisible forever.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_store_beside_a_tombstone_lands_as_a_fresh_visible_row_3690() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    let ns = uid("ns");
    let (a, b) = (uid("a"), uid("b"));
    store
        .store(&ctx, &mem(&a, &ns, "slot", "consolidated away"))
        .await
        .expect("seed");
    set_state(&store, &a, "tombstoned").await;

    let id = store
        .store(&ctx, &mem(&b, &ns, "slot", "the new text"))
        .await
        .expect("a tombstone holds no slot");
    assert_eq!(id, b, "the store lands as ITS OWN row");
    assert_eq!(
        store.get(&ctx, &b).await.expect("visible").content,
        "the new text"
    );
    assert_eq!(
        raw(&store, &a).await,
        ("consolidated away".to_string(), "tombstoned".to_string(), 1)
    );
    // the embedded hot path too (`store_with_embedding_inner`, Merge arm)
    let c = uid("c");
    let id = store
        .store_with_embedding(&ctx, &mem(&c, &ns, "slot-emb", "x"), None, None)
        .await
        .expect("seed emb");
    assert_eq!(id, c);
    set_state(&store, &c, "tombstoned").await;
    let d = uid("d");
    let id = store
        .store_with_embedding(&ctx, &mem(&d, &ns, "slot-emb", "fresh"), None, None)
        .await
        .expect("beside the tombstone");
    assert_eq!(id, d);
    assert_eq!(raw(&store, &c).await.0, "x");
}

/// #3695 / #3626 — a QUARANTINED / CONTAMINATED occupant keeps its slot: every
/// create arm is refused typed and UNNAMED; the occupant is byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_store_onto_a_hidden_holder_is_a_typed_unnamed_conflict_3695() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    for hidden in ["quarantined", "contaminated"] {
        let ns = uid("ns");
        let a = uid("a");
        store
            .store(&ctx, &mem(&a, &ns, "slot", "peer text"))
            .await
            .expect("seed");
        set_state(&store, &a, hidden).await;

        let err = store
            .store(&ctx, &mem(&uid("b"), &ns, "slot", "local"))
            .await
            .expect_err("store: refused");
        assert_eq!(
            conflict_id(&err),
            "",
            "{hidden}: store never names the hidden row"
        );
        let err = store
            .store_with_embedding(&ctx, &mem(&uid("c"), &ns, "slot", "local"), None, None)
            .await
            .expect_err("store_with_embedding: refused");
        assert_eq!(
            conflict_id(&err),
            "",
            "{hidden}: embed merge never names the hidden row"
        );
        let err = store
            .store_with_embedding_no_overwrite(
                &ctx,
                &mem(&uid("d"), &ns, "slot", "local"),
                None,
                None,
            )
            .await
            .expect_err("no_overwrite: refused");
        assert_eq!(
            conflict_id(&err),
            "",
            "{hidden}: no-overwrite never names the hidden row"
        );
        let err = store
            .store_batch(&ctx, &[mem(&uid("e"), &ns, "slot", "local")])
            .await
            .expect_err("store_batch: refused");
        assert_eq!(
            conflict_id(&err),
            "",
            "{hidden}: the batch never names the hidden row"
        );
        assert_eq!(
            raw(&store, &a).await,
            ("peer text".to_string(), hidden.to_string(), 1),
            "{hidden}: the occupant is byte-identical"
        );
        assert_eq!(
            store
                .find_by_title_namespace("slot", &ns, None)
                .await
                .expect("probe"),
            None,
            "{hidden}: the on_conflict pre-check never hands the hidden id back"
        );
    }
}

/// #3690 — the `on_conflict` pre-check reports only the VISIBLE occupant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_find_by_title_namespace_reports_only_the_visible_occupant_3690() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    let ns = uid("ns");
    let a = uid("a");
    store
        .store(&ctx, &mem(&a, &ns, "slot", "x"))
        .await
        .expect("seed");
    assert_eq!(
        store
            .find_by_title_namespace("slot", &ns, None)
            .await
            .expect("probe"),
        Some(a.clone())
    );
    for state in ["tombstoned", "quarantined", "contaminated"] {
        set_state(&store, &a, state).await;
        assert_eq!(
            store
                .find_by_title_namespace("slot", &ns, None)
                .await
                .expect("probe"),
            None,
            "{state}"
        );
    }
    set_state(&store, &a, "done").await;
    assert_eq!(
        store
            .find_by_title_namespace("slot", &ns, None)
            .await
            .expect("probe"),
        Some(a)
    );
}

/// #2887 / #3690 (vote Q3) — the same-id restore of a TOMBSTONE still merges
/// in place (re-targeted at the PRIMARY KEY) and RE-OPENS it (#2894); a restore
/// whose key a DIFFERENT live row now holds is refused NAMING that row; a
/// same-id restore onto a QUARANTINED row is refused unnamed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_restore_same_id_dispositions_across_hidden_rows_2887_3690_3695() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_admin("ai:curator");
    // tombstone, no live holder -> in-place merge AND re-open (#2894).
    // REQUIREMENT (converted from CHARACTERISATION by #2894): identical to
    // the pre-v100 in-place CAS - same row, identity columns byte-identical
    // except the lifecycle, ONE row under the key, the arm's rewrites moved -
    // and the row is visible afterwards: the lifecycle returns to the
    // snapshot's state via the ONE re-open predicate
    // (`LifecycleState::restore_reopens_row`, rendered into the restore arm
    // by `models::restore_reopen_lifecycle_assignment` on both adapters).
    let ns = uid("ns");
    let a = uid("a");
    store
        .store(&ctx, &mem(&a, &ns, "slot", "pre-tombstone"))
        .await
        .expect("seed");
    set_state(&store, &a, "tombstoned").await;
    let before = identity_of(&store, &a).await;
    assert_eq!(count_key(&store, &ns).await, 1);
    let id = store
        .restore_or_conflict(&ctx, &mem(&a, &ns, "slot", "restored"))
        .await
        .expect("same-id restore of a tombstone succeeds (it did before v100)");
    assert_eq!(id, a, "the restore lands on the SAME row (CAS semantics)");
    let after = identity_of(&store, &a).await;
    assert_eq!(
        (&after.0, &after.2),
        (&before.0, &before.2),
        "identity columns byte-identical (except the re-opened lifecycle)"
    );
    assert_eq!(
        after.1, "open",
        "#2894: a rollback restore re-opens the consolidation tombstone"
    );
    assert_eq!(
        after.3,
        before.3 + 1,
        "the same DO UPDATE arm ran (version bumped once)"
    );
    assert_eq!(raw(&store, &a).await.0, "restored");
    assert_eq!(
        count_key(&store, &ns).await,
        1,
        "never a second row beside the tombstone"
    );
    assert_eq!(
        store
            .get(&ctx, &a)
            .await
            .expect("#2894: restored row visible")
            .content,
        "restored",
        "#2894 FIXED: the restored original is reachable on the read path"
    );

    // a different live row holds the key → refused, naming it. (Fresh
    // namespace: since #2894 the tombstone above re-opened, so it holds its
    // own key again - the holder scenario needs its own key.)
    let ns_hold = uid("ns");
    let t = uid("t");
    store
        .store(&ctx, &mem(&t, &ns_hold, "slot", "original"))
        .await
        .expect("seed tombstone-to-be");
    set_state(&store, &t, "tombstoned").await;
    let h = uid("h");
    store
        .store(&ctx, &mem(&h, &ns_hold, "slot", "live holder"))
        .await
        .expect("a tombstone holds no slot: the holder lands beside it");
    let err = store
        .restore_or_conflict(&ctx, &mem(&t, &ns_hold, "slot", "again"))
        .await
        .expect_err("the live holder wins");
    assert_eq!(conflict_id(&err), h);
    assert_eq!(
        raw(&store, &t).await,
        ("original".to_string(), "tombstoned".to_string(), 1),
        "refused restore touches neither the tombstone nor the holder"
    );
    assert_eq!(
        raw(&store, &h).await,
        ("live holder".to_string(), "open".to_string(), 1)
    );

    // quarantined same id → refused unnamed
    let ns2 = uid("ns");
    let q = uid("q");
    store
        .store(&ctx, &mem(&q, &ns2, "slot", "peer text"))
        .await
        .expect("seed");
    set_state(&store, &q, "quarantined").await;
    let err = store
        .restore_or_conflict(&ctx, &mem(&q, &ns2, "slot", "x"))
        .await
        .expect_err("refused");
    assert_eq!(conflict_id(&err), "");
    assert_eq!(
        raw(&store, &q).await,
        ("peer text".to_string(), "quarantined".to_string(), 1)
    );
}

/// #3690 — a plain MERGE store that reuses a tombstone's OWN id under the
/// same key is refused unnamed, never absorbed (only a RESTORE may do that).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_merge_store_reusing_a_tombstones_id_is_refused_3690() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    let ns = uid("ns");
    let a = uid("a");
    store
        .store(&ctx, &mem(&a, &ns, "slot", "old"))
        .await
        .expect("seed");
    set_state(&store, &a, "tombstoned").await;
    let err = store
        .store(&ctx, &mem(&a, &ns, "slot", "new"))
        .await
        .expect_err("a merge into a tombstone is refused");
    assert_eq!(conflict_id(&err), "");
    assert_eq!(raw(&store, &a).await.0, "old");
}

/// #2894 (amend) - pg twin of `plain_merge_store_onto_own_tombstone_never_reopens_2894`,
/// driven through `store_with_embedding` (the Merge arm of
/// `store_with_embedding_inner`, where the re-open CASE lives on this backend):
/// a plain embed-merge reusing a consolidation tombstone's own id must NOT
/// re-open it. Observed outcome: typed `StoreError::Conflict`, unnamed, the row
/// byte-identical, `get` folding to `NotFound` while the row stays resident.
/// Allowed-path control, not duplicated here:
/// `pg_restore_same_id_dispositions_across_hidden_rows_2887_3690_3695` (tombstone
/// third) proves the restore arm DOES re-open this same shape to `open`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_plain_embed_merge_onto_own_tombstone_never_reopens_2894() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    let ns = uid("ns");
    let a = uid("a");
    store
        .store_with_embedding(&ctx, &mem(&a, &ns, "slot", "old"), None, None)
        .await
        .expect("seed");
    set_state(&store, &a, "tombstoned").await;
    let err = store
        .store_with_embedding(&ctx, &mem(&a, &ns, "slot", "new"), None, None)
        .await
        .expect_err("a plain embed-merge into a tombstone is refused, never re-opened");
    assert_eq!(conflict_id(&err), "", "the tombstone is never named");
    assert_eq!(
        raw(&store, &a).await,
        ("old".to_string(), "tombstoned".to_string(), 1),
        "NOT re-opened: content, lifecycle and version byte-identical"
    );
    assert!(
        matches!(store.get(&ctx, &a).await, Err(StoreError::NotFound { .. })),
        "still hidden on the normal read path"
    );
    assert_eq!(
        count_key(&store, &ns).await,
        1,
        "no second row landed beside the tombstone"
    );
}

// ───────────────────────────────────────────────────────────────────
// #3691 / #3693 / #3626 — the postgres twins of the other Unit-1 lanes
// ───────────────────────────────────────────────────────────────────

/// #3691 — a source quarantined between the snapshot read and the tombstone
/// write (an AFTER-INSERT trigger on the summary row fires inside
/// consolidate's own tx) keeps `quarantined`, the cluster aborts with the
/// typed transition conflict and NO summary row is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_consolidate_aborts_the_cluster_when_a_source_is_quarantined_after_snapshot_3691() {
    let Some(store) = connect().await else { return };
    ai_memory::config::set_lineage_dag(true);
    ai_memory::config::set_consolidate_tombstone_sources(true);
    let ctx = CallerContext::for_admin("ai:consolidator");
    let ns = uid("ns");
    let (a, b) = (uid("a"), uid("b"));
    store
        .store(&ctx, &mem(&a, &ns, "a-3691", "alpha"))
        .await
        .expect("seed a");
    store
        .store(&ctx, &mem(&b, &ns, "b-3691", "beta"))
        .await
        .expect("seed b");
    let summary_title = uid("C-3691");
    let fn_name = format!("quarantine_b_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {fn_name}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             UPDATE memories SET lifecycle_state = 'quarantined' WHERE id = '{b}';
             RETURN NEW;
         END $$;
         CREATE TRIGGER {fn_name} AFTER INSERT ON memories FOR EACH ROW
             WHEN (NEW.title = '{summary_title}') EXECUTE FUNCTION {fn_name}();"
    ))
    .execute(store.pool())
    .await
    .expect("install the race trigger");

    let err = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            &summary_title,
            "merged",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:consolidator",
        )
        .await
        .expect_err("a source that went hidden mid-consolidation aborts the cluster");
    assert!(
        matches!(&err, StoreError::InvalidTransition { detail } if detail.contains(&b)),
        "typed transition conflict naming the source, got {err:?}"
    );
    // The simulated quarantine rode consolidate's own tx, so the rollback
    // reverted it too: the guard's proof is that NO source was tombstoned.
    assert_ne!(
        raw(&store, &b).await.1,
        "tombstoned",
        "the hidden source was never tombstoned"
    );
    assert_eq!(
        raw(&store, &a).await.1,
        "open",
        "the cluster rolled back: a is NOT tombstoned"
    );
    let summaries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE title = $1")
        .bind(&summary_title)
        .fetch_one(store.pool())
        .await
        .expect("count");
    assert_eq!(summaries, 0, "no summary row was committed");
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {fn_name} ON memories; DROP FUNCTION {fn_name}();"
    ))
    .execute(store.pool())
    .await
    .expect("drop trigger");
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
}

/// #3693 — the pg contradiction lane skips hidden rows and still reports the
/// visible sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_find_contradictions_skips_hidden_rows_3693() {
    let Some(store) = connect().await else { return };
    let ctx = CallerContext::for_agent("ai:tester-3690");
    for hidden in ["quarantined", "contaminated", "tombstoned"] {
        let ns = uid("ns");
        let (hid, vis) = (uid("hid"), uid("vis"));
        store
            .store(&ctx, &mem(&hid, &ns, "deploy strategy canary", "peer text"))
            .await
            .expect("seed");
        store
            .store(&ctx, &mem(&vis, &ns, "deploy strategy rollback", "ours"))
            .await
            .expect("seed");
        set_state(&store, &hid, hidden).await;
        let found = store
            .find_contradictions("deploy strategy", &ns)
            .await
            .expect("contradictions");
        let ids: Vec<&str> = found.iter().map(|m| m.id.as_str()).collect();
        assert!(
            !ids.contains(&hid.as_str()),
            "{hidden}: hidden row reported: {ids:?}"
        );
        assert!(
            ids.contains(&vis.as_str()),
            "{hidden}: the visible sibling still is: {ids:?}"
        );
    }
}

async fn owner(store: &PostgresStore, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT metadata->>'agent_id' FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .expect("row")
    .filter(|s| !s.is_empty())
}

/// #3626 — a `(title, namespace)` merge onto an UNSTAMPED row (missing /
/// JSON null / "") leaves it unowned on every pg create funnel that merges;
/// a stamped row keeps its owner.
///
/// Viewer note (the arity ruling): an unstamped `scope=private` row is
/// readable by NO named caller on the read lanes (`is_visible_by_fields`
/// has no owner to match), so a NAMED caller's store onto it is refused
/// unnamed like any occupant it cannot read — pinned first. The merge that
/// #3626 governs is therefore exercised by the trust-all viewer
/// (`bypass_visibility` here; raw `db::insert` / an MCP without
/// `AI_MEMORY_AGENT_ID` on sqlite), and it must leave the row unowned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_upsert_merge_onto_an_unstamped_row_leaves_it_unstamped_3626() {
    let Some(store) = connect().await else {
        return;
    };
    let named = CallerContext::for_agent("ai:tester-3690");
    let ctx = CallerContext::for_admin("ai:substrate-3626");
    for unstamped in [
        serde_json::json!({}),
        serde_json::json!({"agent_id": null}),
        serde_json::json!({"agent_id": ""}),
    ] {
        // plain store
        let ns = uid("ns");
        let legacy = uid("legacy");
        let mut seed = mem(&legacy, &ns, "slot", "legacy text");
        seed.metadata = unstamped.clone();
        store.store(&ctx, &seed).await.expect("seed unstamped");
        let err = store
            .store(&named, &mem(&uid("claimer"), &ns, "slot", "claimed"))
            .await
            .expect_err("a named caller cannot read an owner-less private row: refused");
        assert_eq!(conflict_id(&err), "", "seed {unstamped}: refused unnamed");
        assert_eq!(raw(&store, &legacy).await.0, "legacy text");
        let id = store
            .store(&ctx, &mem(&uid("claimer"), &ns, "slot", "claimed"))
            .await
            .expect("merge (trust-all viewer)");
        assert_eq!(id, legacy);
        assert_eq!(
            owner(&store, &legacy).await,
            None,
            "store: seed {unstamped} must stay unowned"
        );
        assert_eq!(
            raw(&store, &legacy).await.0,
            "claimed",
            "the merge itself still happened"
        );
        // embedded store + batch
        let legacy2 = uid("legacy2");
        let mut seed = mem(&legacy2, &ns, "slot-emb", "legacy text");
        seed.metadata = unstamped.clone();
        store
            .store_with_embedding(&ctx, &seed, None, None)
            .await
            .expect("seed");
        let id = store
            .store_with_embedding(
                &ctx,
                &mem(&uid("claimer"), &ns, "slot-emb", "claimed"),
                None,
                None,
            )
            .await
            .expect("merge");
        assert_eq!(id, legacy2);
        assert_eq!(
            owner(&store, &legacy2).await,
            None,
            "store_with_embedding: seed {unstamped}"
        );
        let ids = store
            .store_batch(&ctx, &[mem(&uid("claimer"), &ns, "slot-emb", "batched")])
            .await
            .expect("batch merge");
        assert_eq!(ids, vec![legacy2.clone()]);
        assert_eq!(
            owner(&store, &legacy2).await,
            None,
            "store_batch: seed {unstamped}"
        );
    }
    // stamped control
    let ns = uid("ns");
    let owned = uid("owned");
    store
        .store(&named, &mem(&owned, &ns, "slot", "owned text"))
        .await
        .expect("seed");
    let mut other = mem(&uid("other"), &ns, "slot", "x");
    other.metadata = serde_json::json!({ "agent_id": "ai:someone-else" });
    store.store(&ctx, &other).await.expect("merge");
    assert_eq!(
        owner(&store, &owned).await.as_deref(),
        Some("ai:tester-3690"),
        "existing owner wins"
    );
}

/// #3696 — pg twin of the scope axis: another agent's `scope=private` live
/// occupant refuses a non-owner viewer typed and unnamed on `store`,
/// `store_with_embedding`, `store_with_embedding_no_overwrite` and
/// `store_batch`; the owner merges; the pre-check never names it to a
/// non-owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_store_onto_another_agents_private_row_is_a_typed_unnamed_conflict_3696() {
    let Some(store) = connect().await else { return };
    let alice = CallerContext::for_agent("ai:alice-3696");
    let bob = CallerContext::for_agent("ai:bob-3696");
    let ns = uid("ns");
    let a = uid("a");
    let mut seed = mem(&a, &ns, "slot", "alice's text");
    seed.metadata = serde_json::json!({ "agent_id": "ai:alice-3696", "scope": "private" });
    store.store(&alice, &seed).await.expect("seed");
    let mut bobs = mem(&uid("b"), &ns, "slot", "bob's text");
    bobs.metadata = serde_json::json!({ "agent_id": "ai:bob-3696", "scope": "private" });

    let err = store.store(&bob, &bobs).await.expect_err("store: refused");
    assert_eq!(conflict_id(&err), "", "the private row is never named");
    let err = store
        .store_with_embedding(&bob, &bobs, None, None)
        .await
        .expect_err("embed: refused");
    assert_eq!(conflict_id(&err), "");
    let err = store
        .store_with_embedding_no_overwrite(&bob, &bobs, None, None)
        .await
        .expect_err("no_overwrite: refused");
    assert_eq!(conflict_id(&err), "");
    let err = store
        .store_batch(&bob, std::slice::from_ref(&bobs))
        .await
        .expect_err("batch: refused");
    assert_eq!(conflict_id(&err), "");
    assert_eq!(
        raw(&store, &a).await,
        ("alice's text".to_string(), "open".to_string(), 1)
    );
    assert_eq!(
        store
            .find_by_title_namespace("slot", &ns, Some("ai:bob-3696"))
            .await
            .expect("probe"),
        None,
        "bob learns nothing from the pre-check"
    );
    assert_eq!(
        store
            .find_by_title_namespace("slot", &ns, Some("ai:alice-3696"))
            .await
            .expect("probe"),
        Some(a.clone())
    );
    // the owner's re-store still merges
    let mut again = mem(&uid("c"), &ns, "slot", "alice v2");
    again.metadata = serde_json::json!({ "agent_id": "ai:alice-3696", "scope": "private" });
    let id = store.store(&alice, &again).await.expect("owner merges");
    assert_eq!(id, a);
    assert_eq!(raw(&store, &a).await.0, "alice v2");
}

/// The Conductor's #3696 pin requirement, pg twin: `Refused` is still the
/// typed `StoreError::Conflict` (the shape a caller acts on) with an EMPTY
/// id, and a VISIBLE occupant returns its REAL id through the SAME funnel
/// and arm — paired on one sink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_refused_conflict_keeps_its_typed_shape_and_a_visible_occupant_keeps_its_id_3696() {
    let Some(store) = connect().await else {
        return;
    };
    let alice = CallerContext::for_agent("ai:alice-3696");
    let bob = CallerContext::for_agent("ai:bob-3696");
    let admin = CallerContext::for_admin("ai:substrate-3696");
    let ns = uid("ns");
    let a = uid("a");
    let mut seed = mem(&a, &ns, "slot", "alice's text");
    seed.metadata = serde_json::json!({ "agent_id": "ai:alice-3696", "scope": "private" });
    store.store(&alice, &seed).await.expect("seed");
    let mut bobs = mem(&uid("b"), &ns, "slot", "bob's text");
    bobs.metadata = serde_json::json!({ "agent_id": "ai:bob-3696", "scope": "private" });
    // hidden to bob: typed Conflict, id EMPTY
    let err = store
        .store_with_embedding_no_overwrite(&bob, &bobs, None, None)
        .await
        .expect_err("slot taken");
    assert!(
        matches!(&err, StoreError::Conflict { id } if id.is_empty()),
        "typed, unnamed: {err:?}"
    );
    // visible (owner, and the trust-all admin): the SAME arm names the real id
    for ctx in [&alice, &admin] {
        let err = store
            .store_with_embedding_no_overwrite(ctx, &bobs, None, None)
            .await
            .expect_err("slot taken");
        assert!(
            matches!(&err, StoreError::Conflict { id } if *id == a),
            "named through the same path: {err:?}"
        );
    }
    // lifecycle axis through the same arm
    set_state(&store, &a, "quarantined").await;
    let err = store
        .store_with_embedding_no_overwrite(&alice, &bobs, None, None)
        .await
        .expect_err("slot taken");
    assert!(
        matches!(&err, StoreError::Conflict { id } if id.is_empty()),
        "typed, unnamed: {err:?}"
    );
    assert_eq!(
        raw(&store, &a).await.0,
        "alice's text",
        "never written into"
    );
}
