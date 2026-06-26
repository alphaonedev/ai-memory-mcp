// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! #1727 (v0.8.0) — NON-DESTRUCTIVE "undo an in-place edit" coverage for
//! [`ai_memory::store::MemoryStore::undo_in_place_edit`].
//!
//! Each case runs against the SQLite SAL adapter (always available). The
//! postgres twin compiles under `sal-postgres` and is `#[ignore]`-gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` (the documented Track-C/D network blocker,
//! issue #79) so `cargo test` stays green; the shared `verify_*` bodies make
//! the contract backend-blind through the trait.
//!
//! Cases:
//! (a) edit content in place, then undo → content reverts, version bumped.
//! (b) `dry_run` returns the diff and applies NOTHING (live row unchanged).
//! (c) non-owner caller → fail-closed (PermissionDenied), no mutation.
//! (d) undo-of-undo (redo) round-trips.
//! (e) edit that RAISED tier, then undo → tier does NOT downgrade (rides the
//!     update tier-monotonicity; documented behaviour).
//! (f) undo with no in_place_edit snapshot → applied=false, no mutation.
//! (g) undo preserves the memory's links (NO destructive delete).

use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use serde_json::json;

const OWNER: &str = "owner-1727";

fn mem(id: &str, owner: &str, title: &str, content: &str, tier: Tier) -> Memory {
    Memory {
        id: id.to_string(),
        tier,
        namespace: "undo-1727".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn fresh_store() -> (SqliteStore, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = SqliteStore::open(tmp.path().join("undo-1727.db")).expect("open SqliteStore");
    (store, tmp)
}

// ── (a) edit then undo → content reverts + version bump ─────────────────
#[tokio::test]
async fn undo_reverts_content_and_bumps_version() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("a1", OWNER, "t", "content-v1", Tier::Long))
        .await
        .expect("seed");

    // Edit v1 → v2 through the in-place update path (snapshots v1).
    store
        .update(
            &admin,
            "a1",
            UpdatePatch {
                content: Some("content-v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit");
    let before = store.get(&admin, "a1").await.expect("get before undo");
    assert_eq!(before.content, "content-v2");
    assert_eq!(before.version, 2, "edit bumped 1 → 2");

    let outcome = store
        .undo_in_place_edit(&admin, "a1", false)
        .await
        .expect("undo");
    assert!(outcome.applied);
    assert_eq!(outcome.before_version, 2);
    assert_eq!(outcome.after_version, Some(3));
    assert_eq!(outcome.before_content, "content-v2");
    assert_eq!(outcome.after_content, "content-v1");

    let after = store.get(&admin, "a1").await.expect("get after undo");
    assert_eq!(after.content, "content-v1", "content reverted");
    assert_eq!(after.version, 3, "undo bumped version monotonically");
}

// ── (b) dry-run applies nothing ─────────────────────────────────────────
#[tokio::test]
async fn dry_run_returns_diff_and_writes_nothing() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("b1", OWNER, "t", "v1", Tier::Long))
        .await
        .expect("seed");
    store
        .update(
            &admin,
            "b1",
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit");

    let outcome = store
        .undo_in_place_edit(&admin, "b1", true)
        .await
        .expect("dry-run undo");
    assert!(!outcome.applied, "dry-run does not apply");
    assert_eq!(outcome.after_version, None);
    assert_eq!(outcome.before_content, "v2");
    assert_eq!(
        outcome.after_content, "v1",
        "diff shows the would-be revert"
    );

    let live = store.get(&admin, "b1").await.expect("get after dry-run");
    assert_eq!(live.content, "v2", "live row UNCHANGED by dry-run");
    assert_eq!(live.version, 2, "version UNCHANGED by dry-run");
}

// ── (c) non-owner caller fails closed, no mutation ──────────────────────
#[tokio::test]
async fn non_owner_caller_fails_closed() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("c1", OWNER, "t", "v1", Tier::Long))
        .await
        .expect("seed");
    store
        .update(
            &admin,
            "c1",
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit");

    // A different, non-bypass caller must be refused.
    let intruder = CallerContext::for_agent("intruder-xyz");
    let err = store
        .undo_in_place_edit(&intruder, "c1", false)
        .await
        .expect_err("non-owner must be denied");
    assert!(
        matches!(err, StoreError::PermissionDenied { .. }),
        "expected PermissionDenied, got {err:?}"
    );

    // Even a dry-run by the intruder is refused (no diff leak).
    let dry_err = store
        .undo_in_place_edit(&intruder, "c1", true)
        .await
        .expect_err("non-owner dry-run must be denied");
    assert!(matches!(dry_err, StoreError::PermissionDenied { .. }));

    let live = store
        .get(&admin, "c1")
        .await
        .expect("get after denied undo");
    assert_eq!(live.content, "v2", "no mutation on denial");
    assert_eq!(live.version, 2);
}

// ── (d) undo-of-undo (redo) round-trips ─────────────────────────────────
#[tokio::test]
async fn undo_of_undo_round_trips() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("d1", OWNER, "t", "v1", Tier::Long))
        .await
        .expect("seed");
    store
        .update(
            &admin,
            "d1",
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit");

    // First undo: v2 → v1 (auto-snapshots v2 as the new in_place_edit).
    let undo1 = store
        .undo_in_place_edit(&admin, "d1", false)
        .await
        .expect("undo1");
    assert!(undo1.applied);
    assert_eq!(store.get(&admin, "d1").await.unwrap().content, "v1");

    // Redo (undo of the undo): v1 → v2 again.
    let undo2 = store
        .undo_in_place_edit(&admin, "d1", false)
        .await
        .expect("undo2");
    assert!(undo2.applied);
    assert_eq!(undo2.after_content, "v2", "redo restores v2");
    let live = store.get(&admin, "d1").await.expect("get after redo");
    assert_eq!(live.content, "v2", "redo round-trips back to v2");
    assert_eq!(live.version, 4, "two undos bumped 2 → 3 → 4");
}

// ── (e) tier-raise edit then undo does NOT downgrade tier ───────────────
#[tokio::test]
async fn undo_does_not_downgrade_tier() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    // Seed at Mid, raise to Long while editing content (snapshot carries
    // tier=mid). Undo applies the snapshot's mid tier through the update
    // path, which is tier-monotonic and so REFUSES the downgrade.
    store
        .store(&admin, &mem("e1", OWNER, "t", "v1", Tier::Mid))
        .await
        .expect("seed");
    store
        .update(
            &admin,
            "e1",
            UpdatePatch {
                content: Some("v2".to_string()),
                tier: Some(Tier::Long),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit raising tier");
    assert_eq!(store.get(&admin, "e1").await.unwrap().tier, Tier::Long);

    let outcome = store
        .undo_in_place_edit(&admin, "e1", false)
        .await
        .expect("undo");
    assert!(outcome.applied);
    let after = store.get(&admin, "e1").await.expect("get after undo");
    assert_eq!(after.content, "v1", "content reverts");
    assert_eq!(
        after.tier,
        Tier::Long,
        "tier rides the update tier-monotonicity — undo does NOT downgrade Long → Mid"
    );
}

// ── (f) no in_place_edit snapshot → applied=false, no mutation ──────────
#[tokio::test]
async fn no_snapshot_is_noop() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("f1", OWNER, "t", "only-content", Tier::Long))
        .await
        .expect("seed");

    let outcome = store
        .undo_in_place_edit(&admin, "f1", false)
        .await
        .expect("undo with no snapshot");
    assert!(!outcome.applied, "no snapshot → nothing applied");
    assert_eq!(outcome.after_version, None);
    assert_eq!(outcome.before_content, outcome.after_content);

    let live = store.get(&admin, "f1").await.expect("get after no-op");
    assert_eq!(live.content, "only-content", "no mutation");
    assert_eq!(live.version, 1);

    // A truly-missing id surfaces NotFound.
    let err = store
        .undo_in_place_edit(&admin, "does-not-exist", false)
        .await
        .expect_err("missing id");
    assert!(matches!(err, StoreError::NotFound { .. }), "got {err:?}");
}

// ── (g) undo preserves links (proves NO destructive delete) ─────────────
#[tokio::test]
async fn undo_preserves_links() {
    let (store, _tmp) = fresh_store();
    let admin = CallerContext::for_admin(OWNER);
    store
        .store(&admin, &mem("g1", OWNER, "src", "v1", Tier::Long))
        .await
        .expect("seed src");
    store
        .store(&admin, &mem("g2", OWNER, "dst", "other", Tier::Long))
        .await
        .expect("seed dst");
    store
        .link(
            &admin,
            &MemoryLink {
                source_id: "g1".to_string(),
                target_id: "g2".to_string(),
                relation: MemoryLinkRelation::RelatedTo,
                created_at: chrono::Utc::now().to_rfc3339(),
                signature: None,
                observed_by: None,
                valid_from: None,
                valid_until: None,
                attest_level: None,
            },
        )
        .await
        .expect("create link");

    let links_before = store.list_links(None).await.expect("list before");
    assert_eq!(links_before.len(), 1, "one link before edit");

    // Edit then undo the SOURCE memory.
    store
        .update(
            &admin,
            "g1",
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("edit src");
    let outcome = store
        .undo_in_place_edit(&admin, "g1", false)
        .await
        .expect("undo src");
    assert!(outcome.applied);
    assert_eq!(store.get(&admin, "g1").await.unwrap().content, "v1");

    let links_after = store.list_links(None).await.expect("list after");
    assert_eq!(
        links_after.len(),
        1,
        "link SURVIVES the undo — proves no raw DELETE+cascade of the live row"
    );
    assert_eq!(links_after[0].source_id, "g1");
    assert_eq!(links_after[0].target_id, "g2");
}

// ── Postgres parity gate (compiles under sal-postgres; ignored without
//     AI_MEMORY_TEST_POSTGRES_URL per the Track-C/D blocker, issue #79). ──
#[cfg(feature = "sal-postgres")]
mod postgres_side {
    use super::{OWNER, mem};
    use ai_memory::models::Tier;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skipping pg undo parity: connect failed: {e} (issue #79)");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_undo_reverts_and_bumps_version() {
        let Some(pg) = live_pg().await else { return };
        let admin = CallerContext::for_admin(OWNER);
        let id = format!("pg-undo-a-{}", uuid::Uuid::new_v4());
        pg.store(&admin, &mem(&id, OWNER, &id, "content-v1", Tier::Long))
            .await
            .expect("seed");
        // Edit via the optimistic in-place path (update_with_expected_version),
        // which is the postgres path that writes the #1725 `in_place_edit`
        // snapshot. (#1799 also makes the non-If-Match TRAIT `update` snapshot
        // — see `pg_trait_update_snapshots_in_place_edit_1799` below — so both
        // postgres edit paths are now undoable.)
        pg.update_with_expected_version(
            &admin,
            &id,
            UpdatePatch {
                content: Some("content-v2".to_string()),
                ..UpdatePatch::default()
            },
            Some(1),
        )
        .await
        .expect("edit");
        let outcome = pg
            .undo_in_place_edit(&admin, &id, false)
            .await
            .expect("undo");
        assert!(outcome.applied);
        assert_eq!(outcome.after_content, "content-v1");
        assert_eq!(pg.get(&admin, &id).await.unwrap().content, "content-v1");
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_undo_non_owner_denied() {
        let Some(pg) = live_pg().await else { return };
        let admin = CallerContext::for_admin(OWNER);
        let id = format!("pg-undo-c-{}", uuid::Uuid::new_v4());
        pg.store(&admin, &mem(&id, OWNER, &id, "v1", Tier::Long))
            .await
            .expect("seed");
        pg.update_with_expected_version(
            &admin,
            &id,
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
            Some(1),
        )
        .await
        .expect("edit");
        let intruder = CallerContext::for_agent("intruder-xyz");
        let err = pg
            .undo_in_place_edit(&intruder, &id, false)
            .await
            .expect_err("non-owner denied");
        assert!(
            matches!(err, StoreError::PermissionDenied { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_undo_dry_run_writes_nothing() {
        let Some(pg) = live_pg().await else { return };
        let admin = CallerContext::for_admin(OWNER);
        let id = format!("pg-undo-b-{}", uuid::Uuid::new_v4());
        pg.store(&admin, &mem(&id, OWNER, &id, "v1", Tier::Long))
            .await
            .expect("seed");
        pg.update_with_expected_version(
            &admin,
            &id,
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
            Some(1),
        )
        .await
        .expect("edit");
        let outcome = pg
            .undo_in_place_edit(&admin, &id, true)
            .await
            .expect("dry-run");
        assert!(!outcome.applied);
        assert_eq!(pg.get(&admin, &id).await.unwrap().content, "v2");
    }

    // ── #1799 — the postgres TRAIT `update` (non-If-Match COALESCE path)
    //     MUST snapshot prior content under archive_reason='in_place_edit'
    //     so an edit routed here (PUT without If-Match / CLI / federation
    //     catchup) is undoable, closing the partial-#1725 backend asymmetry
    //     (#1798 R-02). Pre-#1799 the trait `update` did a blind one-shot
    //     UPDATE with NO snapshot → undo found nothing. ─────────────────────
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_trait_update_snapshots_in_place_edit_1799() {
        let Some(pg) = live_pg().await else { return };
        let admin = CallerContext::for_admin(OWNER);
        let id = format!("pg-trait-1799-{}", uuid::Uuid::new_v4());
        pg.store(&admin, &mem(&id, OWNER, &id, "v1", Tier::Long))
            .await
            .expect("seed");

        // Edit via the TRAIT `update` (NOT update_with_expected_version) —
        // the exact non-If-Match path the defect lived on.
        pg.update(
            &admin,
            &id,
            UpdatePatch {
                content: Some("v2".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("trait update edit");
        assert_eq!(
            pg.get(&admin, &id).await.unwrap().content,
            "v2",
            "live row now holds the edited content"
        );

        // Proof the snapshot was created BY THE TRAIT UPDATE PATH: undo
        // reverts content back to "v1". `applied == true` + the reverted
        // content together prove the `in_place_edit` archive row exists with
        // the pre-edit content "v1".
        let outcome = pg
            .undo_in_place_edit(&admin, &id, false)
            .await
            .expect("undo after trait update");
        assert!(
            outcome.applied,
            "undo applied — proves the trait update wrote an in_place_edit snapshot"
        );
        assert_eq!(
            outcome.after_content, "v1",
            "undo reverts to the snapshotted pre-edit content"
        );
        assert_eq!(
            pg.get(&admin, &id).await.unwrap().content,
            "v1",
            "live row reverted to v1 — the snapshot the trait update created round-trips"
        );
    }

    // ── #1799 — a no-content-change trait update (priority only) must NOT
    //     create an in_place_edit snapshot (undo finds nothing). ────────────
    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — Track C blocker per issue #79"]
    async fn pg_trait_update_no_content_change_no_snapshot_1799() {
        let Some(pg) = live_pg().await else { return };
        let admin = CallerContext::for_admin(OWNER);
        let id = format!("pg-trait-1799-nochg-{}", uuid::Uuid::new_v4());
        pg.store(&admin, &mem(&id, OWNER, &id, "only-content", Tier::Long))
            .await
            .expect("seed");

        // Priority-only patch: content + title untouched → no snapshot.
        pg.update(
            &admin,
            &id,
            UpdatePatch {
                priority: Some(9),
                ..UpdatePatch::default()
            },
        )
        .await
        .expect("priority-only trait update");

        let outcome = pg
            .undo_in_place_edit(&admin, &id, false)
            .await
            .expect("undo with no snapshot");
        assert!(
            !outcome.applied,
            "no content change → no in_place_edit snapshot → undo is a no-op"
        );
        assert_eq!(
            pg.get(&admin, &id).await.unwrap().content,
            "only-content",
            "live content unchanged"
        );
    }
}
