// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3124 — postgres twin of `tests/unstamped_policy_3124.rs`: the ONE
//! cross-backend unstamped-row policy on the postgres SAL adapter.
//!
//! * the #1412 / #1628 funnels (trait `update` / `delete`) REFUSE an unstamped
//!   row in BOTH postures — `warn` never loosens a funnel that already refused
//!   (R1);
//! * the funnels that admitted an unstamped row before #3124 (link create,
//!   archive restore) keep admitting it under `warn` (and report it) and
//!   refuse it under `refuse`;
//! * a MALFORMED (non-string) owner is never matched — `->>` renders a JSON
//!   number as text, which let a caller of the same spelling match it pre-#3124;
//! * the doctor census query counts the same three classes as sqlite.
//!
//! Live-postgres gated via the SKIP-IF-URL-UNSET convention of the shipped
//! `*_pg` suite: each test self-skips (with a `skip:` line) when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset and runs the real assertions when
//! it points at a live database.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use ai_memory::identity::owner_stamp::{
    ENV_UNSTAMPED_MUTATION, MODE_REFUSE, MODE_WARN, PG_CENSUS_SQL, REASON_UNSTAMPED_REFUSED,
};
use ai_memory::models::{Memory, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};
use common::EnvVarGuard;
use serde_json::{Value, json};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

async fn live_pg() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn posture(mode: &str) -> EnvVarGuard {
    common::ensure_no_config_env();
    EnvVarGuard::set(ENV_UNSTAMPED_MUTATION, mode.to_string())
}

/// Store a row through the admin lane, then force its `metadata` to exactly
/// `metadata` (the store funnel stamps provenance; the legacy shapes under
/// test are the ones it no longer produces). Returns the id.
async fn seed(store: &PostgresStore, ns: &str, title: &str, metadata: &Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("{title}-{}", uuid::Uuid::new_v4()),
        content: format!("{title} content"),
        priority: 5,
        confidence: 1.0,
        source: "unstamped-3124".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({}),
        version: 1,
        ..Memory::default()
    };
    let id = store
        .store(&CallerContext::for_admin("ai:operator"), &mem)
        .await
        .expect("seed store");
    sqlx::query("UPDATE memories SET metadata = $2::jsonb WHERE id = $1")
        .bind(&id)
        .bind(metadata.to_string())
        .execute(store.pool())
        .await
        .expect("force metadata");
    id
}

async fn content_of(store: &PostgresStore, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT content FROM memories WHERE id = $1")
        .bind(id)
        .fetch_optional(store.pool())
        .await
        .expect("content probe")
}

fn ns() -> String {
    format!("unstamped-3124-pg-{}", uuid::Uuid::new_v4())
}

fn patch(content: &str) -> UpdatePatch {
    UpdatePatch {
        content: Some(content.to_string()),
        ..UpdatePatch::default()
    }
}

/// R1 — the #1628 funnels refuse an unstamped row in BOTH postures, and an
/// owned row stays mutable (ALLOWED control).
#[test]
fn pg_update_and_delete_refuse_unstamped_in_both_postures() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let _p = posture(mode);
        runtime().block_on(async {
            let Some(store) = live_pg().await else { return };
            let ns = ns();
            let unstamped = seed(&store, &ns, "pg-unstamped", &json!({})).await;
            let empty = seed(&store, &ns, "pg-empty", &json!({"agent_id": ""})).await;
            let owned = seed(&store, &ns, "pg-owned", &json!({"agent_id": "ai:bob"})).await;
            let bob = CallerContext::for_agent("ai:bob");
            for id in [&unstamped, &empty] {
                let err = store
                    .update(&bob, id, patch("must not land"))
                    .await
                    .expect_err("DENIED: pg refuses an unstamped row in every posture");
                assert!(
                    matches!(err, StoreError::PermissionDenied { .. }),
                    "{mode}: {err:?}"
                );
                let err = store.delete(&bob, id).await.expect_err("DENIED delete");
                assert!(
                    matches!(err, StoreError::PermissionDenied { .. }),
                    "{mode}: {err:?}"
                );
            }
            store
                .update(&bob, &owned, patch("owner edit"))
                .await
                .expect("ALLOWED: an owned row stays mutable");
            assert_eq!(
                content_of(&store, &unstamped).await.as_deref(),
                Some("pg-unstamped content")
            );
            assert_eq!(
                content_of(&store, &owned).await.as_deref(),
                Some("owner edit")
            );
        });
    }
}

/// R2 — a malformed (non-string) owner is never matched, even by a caller
/// spelled like its text rendering.
#[test]
fn pg_malformed_owner_is_never_matched() {
    let _p = posture(MODE_WARN);
    runtime().block_on(async {
        let Some(store) = live_pg().await else { return };
        let ns = ns();
        let id = seed(&store, &ns, "pg-malformed", &json!({"agent_id": 123})).await;
        let caller = CallerContext::for_agent("123");
        let err = store
            .update(&caller, &id, patch("x"))
            .await
            .expect_err("DENIED: a malformed owner is never matched");
        assert!(
            matches!(err, StoreError::PermissionDenied { .. }),
            "{err:?}"
        );
    });
}

/// The lenient pg funnel (link create) follows the knob: `warn` admits and
/// reports; `refuse` refuses; an owned source stays linkable.
#[test]
fn pg_link_create_follows_the_posture() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let _p = posture(mode);
        runtime().block_on(async {
            let Some(store) = live_pg().await else { return };
            let ns = ns();
            let src = seed(&store, &ns, "pg-link-src", &json!({})).await;
            let dst = seed(&store, &ns, "pg-link-dst", &json!({})).await;
            let owned = seed(&store, &ns, "pg-link-own", &json!({"agent_id": "ai:bob"})).await;
            let bob = CallerContext::for_agent("ai:bob");
            let link = |source: &str| MemoryLink {
                source_id: source.to_string(),
                target_id: dst.clone(),
                relation: MemoryLinkRelation::RelatedTo,
                created_at: chrono::Utc::now().to_rfc3339(),
                signature: None,
                observed_by: None,
                valid_from: None,
                valid_until: None,
                attest_level: None,
                source_cid: None,
                target_cid: None,
            };
            let before = ai_memory::metrics::unstamped_mutation_allowed_count("postgres", "link");
            let result = store.link(&bob, &link(&src)).await;
            store
                .link(&bob, &link(&owned))
                .await
                .expect("ALLOWED: an owned source stays linkable");
            if mode == MODE_WARN {
                result.expect("warn keeps the pre-#3124 pg link outcome");
                assert!(
                    ai_memory::metrics::unstamped_mutation_allowed_count("postgres", "link")
                        > before
                );
            } else {
                let err = result.expect_err("DENIED: refuse refuses the unstamped source");
                assert!(
                    matches!(err, StoreError::PermissionDenied { .. }),
                    "{err:?}"
                );
            }
        });
    }
}

/// The lenient pg archive-restore funnel follows the knob.
#[test]
fn pg_archive_restore_follows_the_posture() {
    for mode in [MODE_WARN, MODE_REFUSE] {
        let _p = posture(mode);
        runtime().block_on(async {
            let Some(store) = live_pg().await else { return };
            let ns = ns();
            let id = seed(&store, &ns, "pg-restore", &json!({})).await;
            let admin = CallerContext::for_admin("ai:operator");
            let moved = store
                .archive_by_ids(&admin, std::slice::from_ref(&id), Some("3124"))
                .await
                .expect("admin archive");
            assert_eq!(moved, 1);
            let restored = store
                .archive_restore(&CallerContext::for_agent("ai:bob"), &id)
                .await
                .expect("restore");
            assert_eq!(
                restored,
                mode == MODE_WARN,
                "{mode}: restore of an unstamped row"
            );
            assert_eq!(content_of(&store, &id).await.is_some(), mode == MODE_WARN);
        });
    }
}

/// The trait `update` refusal on an unstamped row carries a stable reason
/// that is not the cross-owner text (the operator is told to re-own, not
/// that someone else owns the row).
#[test]
fn pg_unstamped_refusal_reason_is_stable() {
    let _p = posture(MODE_REFUSE);
    runtime().block_on(async {
        let Some(store) = live_pg().await else { return };
        let ns = ns();
        let id = seed(&store, &ns, "pg-reason", &json!({})).await;
        let err = store
            .update(&CallerContext::for_agent("ai:bob"), &id, patch("x"))
            .await
            .expect_err("DENIED");
        let StoreError::PermissionDenied { reason, .. } = err else {
            panic!("expected PermissionDenied");
        };
        assert!(!reason.contains("does not own memory (owner:"), "{reason}");
        // The sqlite twin carries the shared #3124 reason; pg keeps its
        // #1628 wire-pinned text. Both name the missing stamp.
        assert!(
            reason.contains("agent_id") || reason == REASON_UNSTAMPED_REFUSED,
            "{reason}"
        );
    });
}

/// The doctor census query counts unstamped / malformed / archived-unstamped
/// rows with the same definition as sqlite.
#[test]
fn pg_census_counts_the_three_classes() {
    // Serialise with the other tests in this binary (they seed rows too).
    let _p = posture(MODE_WARN);
    runtime().block_on(async {
        let Some(store) = live_pg().await else { return };
        let before: (i64, i64, i64) = sqlx::query_as(PG_CENSUS_SQL)
            .fetch_one(store.pool())
            .await
            .expect("census");
        let ns = ns();
        seed(&store, &ns, "c-missing", &json!({})).await;
        seed(&store, &ns, "c-null", &json!({"agent_id": null})).await;
        seed(&store, &ns, "c-empty", &json!({"agent_id": ""})).await;
        seed(&store, &ns, "c-number", &json!({"agent_id": 7})).await;
        seed(&store, &ns, "c-owned", &json!({"agent_id": "ai:bob"})).await;
        let arch = seed(&store, &ns, "c-archived", &json!({})).await;
        store
            .archive_by_ids(
                &CallerContext::for_admin("ai:operator"),
                std::slice::from_ref(&arch),
                Some("3124"),
            )
            .await
            .expect("archive");
        let after: (i64, i64, i64) = sqlx::query_as(PG_CENSUS_SQL)
            .fetch_one(store.pool())
            .await
            .expect("census");
        assert_eq!(after.0 - before.0, 3, "unstamped");
        assert_eq!(after.1 - before.1, 1, "malformed");
        assert_eq!(after.2 - before.2, 1, "archived unstamped");
    });
}
