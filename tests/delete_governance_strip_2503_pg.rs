// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2503 — POSTGRES twin of `tests/delete_governance_strip_2503.rs`.
//!
//! ## Why a full twin and not a control file
//!
//! The #2479 pg companion could be CONTROLS only, because that lane was
//! structurally unreachable on postgres. This one is not: `PostgresStore` has
//! its own `delete`, its own `apply_remote_deletion`, its own `archive_by_ids`,
//! its own gc sweeps, and TWO independent governance walks. Every one of them
//! carried the defect, and three of them carried it in a DIFFERENT DIRECTION
//! from sqlite — which is the #2488 lesson stated as a test file:
//!
//! - `apply_remote_deletion` (the ATTACKER-REACHABLE federated `deletions[]`
//!   arm) performed NO `namespace_meta` maintenance at all, so the identical
//!   push CLEARED the binding on sqlite and left it DANGLING on postgres.
//! - `archive_by_ids` likewise omitted what both sqlite archive funnels do.
//! - The gc sweeps used `standard_id NOT IN (SELECT id FROM memories)`, which
//!   is NULL-blind: a severed row was never matched on postgres, while the
//!   sqlite `NOT EXISTS` form matched EVERY severed row and would have deleted
//!   them all on the next tick. The two backends already disagreed about NULL
//!   before this issue.
//! - `get_namespace_standard` decoded `standard_id` as a non-nullable `String`
//!   on BOTH backends, so a severed row was a hard error rather than
//!   "no standard bound" — a 5xx for a state the substrate now creates.
//!
//! Row state is asserted with RAW SQL over an independent sqlx pool, never
//! through `get_namespace_standard` (which deliberately collapses NULL to
//! `None`, so it cannot distinguish "row deleted" from "row severed").
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip. Deliberately NOT `#[ignore]`: the PR postgres job does not pass
//! `--include-ignored`, so an ignored test silently never runs.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{
    ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn live_pg() -> Option<(PostgresStore, sqlx::PgPool)> {
    let url = pg_url()?;
    let store = match PostgresStore::connect(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            return None;
        }
    };
    let probe = match sqlx::PgPool::connect(&url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skip: raw probe pool connect failed: {e}");
            return None;
        }
    };
    Some((store, probe))
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn approve_write_policy() -> GovernancePolicy {
    GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..GovernancePolicy::default()
    }
}

/// A policy-bearing standard memory living in `standard_ns`.
fn standard_memory(standard_ns: &str, owner: &str, policy: &GovernancePolicy) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: standard_ns.to_string(),
        title: format!("standard-{}", uuid::Uuid::new_v4()),
        content: "policy".to_string(),
        priority: 9,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({
            "agent_id": owner,
            "governance": serde_json::to_value(policy).unwrap(),
        }),
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// RAW row state: `(row_exists, standard_id, parent_namespace)`.
async fn raw_meta_row(
    pool: &sqlx::PgPool,
    namespace: &str,
) -> (bool, Option<String>, Option<String>) {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT standard_id, parent_namespace FROM namespace_meta WHERE namespace = $1",
    )
    .bind(namespace)
    .fetch_optional(pool)
    .await
    .expect("raw namespace_meta probe");
    match row {
        Some((sid, parent)) => (true, sid, parent),
        None => (false, None, None),
    }
}

async fn cleanup(pool: &sqlx::PgPool, namespaces: &[&str]) {
    for ns in namespaces {
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(pool)
            .await;
    }
}

// ─────────────────────────────────────────────────────────────────────
// EXPLOIT cells
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn exploit_pg_delete_strips_out_of_scope_victim_binding_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:op-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let attacker_ns = uniq("public-ok-2503");
    let victim_ns = uniq("secure-ops-2503");
    let victim_parent = uniq("secure-2503");

    let std_mem = standard_memory(&attacker_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, Some(&victim_parent))
        .await
        .expect("bind victim namespace");

    assert_eq!(
        store
            .resolve_governance_policy(&victim_ns)
            .await
            .expect("resolve")
            .map(|p| p.core.write),
        Some(GovernanceLevel::Approve),
        "precondition: the victim namespace must be governed"
    );

    store.delete(&ctx, &std_id).await.expect("delete standard");

    let (row_exists, standard, parent) = raw_meta_row(&pool, &victim_ns).await;
    assert!(
        row_exists,
        "#2503: the victim's namespace_meta row must SURVIVE the delete"
    );
    assert_eq!(standard, None, "#1642: severed, not dangling");
    assert_eq!(
        parent.as_deref(),
        Some(victim_parent.as_str()),
        "#2503: the parent_namespace inheritance link must be preserved"
    );

    let after = store
        .resolve_governance_policy(&victim_ns)
        .await
        .expect("resolve after")
        .expect("#2503: a severed binding must resolve to the floor, never None");
    assert_eq!(after.core.write, GovernanceLevel::Owner);
    assert_eq!(after.core.promote, GovernanceLevel::Owner);
    assert_eq!(after.core.delete, GovernanceLevel::Owner);

    cleanup(&pool, &[&victim_ns]).await;
}

/// The #2493 arm with an ATTACKER-REACHABLE trigger: the federated
/// `deletions[]` lane routes through this override, which performed NO
/// `namespace_meta` maintenance at all.
#[tokio::test]
async fn exploit_pg_apply_remote_deletion_severs_binding_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:peer-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let attacker_ns = uniq("public-fed-2503");
    let victim_ns = uniq("secure-fed-2503");

    let std_mem = standard_memory(&attacker_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim");
    assert!(
        store
            .resolve_governance_policy(&victim_ns)
            .await
            .expect("resolve")
            .is_some()
    );

    // The federated tombstone-apply path.
    assert!(
        store
            .apply_remote_deletion(&ctx, &std_id)
            .await
            .expect("apply_remote_deletion")
    );

    let (row_exists, standard, _) = raw_meta_row(&pool, &victim_ns).await;
    assert!(row_exists, "#2503: the binding row must survive");
    assert_eq!(
        standard, None,
        "#2493/#2503: apply_remote_deletion omitted namespace_meta maintenance \
         entirely, so a federated delete left the pointer DANGLING on postgres \
         while sqlite cleared it — the two backends must now agree"
    );
    assert_eq!(
        store
            .resolve_governance_policy(&victim_ns)
            .await
            .expect("resolve after")
            .map(|p| p.core.write),
        Some(GovernanceLevel::Owner),
        "#2503: the federated lane must fail closed like every other reap"
    );

    cleanup(&pool, &[&victim_ns]).await;
}

/// The eighth #2493 arm: `archive_by_ids` omitted what BOTH sqlite archive
/// funnels have done since #1642.
#[tokio::test]
async fn exploit_pg_archive_by_ids_severs_binding_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:arch-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let attacker_ns = uniq("public-arch-2503");
    let victim_ns = uniq("secure-arch-2503");

    let std_mem = standard_memory(&attacker_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim");

    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&std_id), Some("manual"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1);

    let (row_exists, standard, _) = raw_meta_row(&pool, &victim_ns).await;
    assert!(
        row_exists,
        "#2503: the binding row must survive the archive"
    );
    assert_eq!(
        standard, None,
        "#2503: archiving a standard on postgres left the pointer dangling — \
         both sqlite archive funnels have severed since #1642"
    );

    cleanup(&pool, &[&victim_ns]).await;
}

/// The decode repair. A severed row used to be a hard sqlx `ColumnDecode`
/// error out of `get_namespace_standard` — a 5xx on the HTTP surface for a
/// state the substrate now deliberately creates.
#[tokio::test]
async fn pg_get_namespace_standard_returns_none_not_error_on_severed_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:decode-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = uniq("decode-2503");

    let std_mem = standard_memory(&ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &ns, &std_id, None)
        .await
        .expect("bind");
    store.delete(&ctx, &std_id).await.expect("delete standard");

    // Must be Ok(None) — NOT Err. This is the #1642 observable, preserved.
    let got = store
        .get_namespace_standard(&ctx, &ns)
        .await
        .expect("#2503: a severed row must decode cleanly, not error");
    assert_eq!(
        got, None,
        "#1642: a reaped standard must not keep resolving"
    );
    // ...and the row is genuinely still there, severed.
    let (row_exists, standard, _) = raw_meta_row(&pool, &ns).await;
    assert!(row_exists);
    assert_eq!(standard, None);

    cleanup(&pool, &[&ns]).await;
}

/// The THIRD governance walk — the in-tx one inside `enforce_governance_action`
/// — must agree with the resolver. Leaving it out would make the ENFORCEMENT
/// decision disagree with the RESOLUTION on exactly this state.
#[tokio::test]
async fn pg_enforce_governance_action_honours_severed_floor_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:enforce-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = uniq("enforce-2503");

    let std_mem = standard_memory(&ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &ns, &std_id, None)
        .await
        .expect("bind");
    store.delete(&ctx, &std_id).await.expect("delete standard");

    // ENFORCE mode explicitly. A raw-library process never runs the boot path
    // that installs the resolved mode, so `active_permissions_mode()` returns
    // the pre-init `Advisory` fallback — under which every decision is
    // downgraded to `Allow` before the walk's verdict can be observed. Without
    // this the cell would pass at the parent commit AND fail after the fix for
    // the same reason: the mode, not the gate.
    ai_memory::config::set_active_permissions_mode(ai_memory::config::PermissionsMode::Enforce);

    // A DIFFERENT agent than the (now unknowable) owner. Under the severed
    // floor `write` is `Owner`, so this must NOT be a clean Allow; pre-#2503
    // the walk fell through and returned Allow unconditionally.
    let stranger = uniq("ai:stranger-2503");
    let decision = store
        .enforce_governance_action(
            ai_memory::store::GovernedAction::Store,
            &ns,
            &stranger,
            None,
            None,
            &serde_json::json!({}),
            None,
        )
        .await
        .expect("enforce_governance_action");
    assert!(
        !matches!(decision, ai_memory::models::GovernanceDecision::Allow),
        "#2503: the in-tx enforcement walk must honour the severed floor \
         (write >= owner), not fall through to allow-on-silence; got {decision:?}"
    );

    cleanup(&pool, &[&ns]).await;
}

// ─────────────────────────────────────────────────────────────────────
// CONTROL cells
// ─────────────────────────────────────────────────────────────────────

/// The #1642 invariant, on postgres: after reaping a standard memory nothing
/// resolves a standard whose backing memory is gone — and the row survives.
#[tokio::test]
async fn control_pg_same_namespace_reap_still_prevents_the_1642_dangle() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:own-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = uniq("team-eng-2503");
    let parent = uniq("team-2503");

    let std_mem = standard_memory(&ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &ns, &std_id, Some(&parent))
        .await
        .expect("bind own namespace");
    store.delete(&ctx, &std_id).await.expect("delete standard");

    assert_eq!(
        store
            .get_namespace_standard(&ctx, &ns)
            .await
            .expect("get standard"),
        None,
        "#1642: a reaped standard must not keep resolving"
    );
    let (row_exists, standard, got_parent) = raw_meta_row(&pool, &ns).await;
    assert!(row_exists);
    assert_eq!(standard, None);
    assert_eq!(got_parent.as_deref(), Some(parent.as_str()));

    cleanup(&pool, &[&ns]).await;
}

/// An ordinary delete of a memory that is nobody's standard must not touch any
/// binding — the sever writes `updated_at`, so without this control the fix
/// could churn every row unnoticed.
#[tokio::test]
async fn control_pg_delete_of_non_standard_memory_is_byte_identical_2503() {
    let Some((store, pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:ctrl-2503");
    let ctx = CallerContext::for_agent(owner.clone());
    let ns = uniq("ctrl-2503");
    let victim_ns = uniq("ctrl-victim-2503");

    let std_mem = standard_memory(&ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim");

    let unrelated = standard_memory(&ns, &owner, &approve_write_policy());
    let unrelated_id = store.store(&ctx, &unrelated).await.expect("store plain");

    let before: Option<(Option<String>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT standard_id, updated_at FROM namespace_meta WHERE namespace = $1")
            .bind(&victim_ns)
            .fetch_optional(&pool)
            .await
            .expect("before probe");

    store
        .delete(&ctx, &unrelated_id)
        .await
        .expect("delete unrelated");

    let after: Option<(Option<String>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT standard_id, updated_at FROM namespace_meta WHERE namespace = $1")
            .bind(&victim_ns)
            .fetch_optional(&pool)
            .await
            .expect("after probe");

    assert_eq!(
        before, after,
        "#2503: deleting a non-standard memory must leave every binding row \
         byte-identical — including updated_at (no churn)"
    );
    assert_eq!(
        store
            .resolve_governance_policy(&victim_ns)
            .await
            .expect("resolve")
            .map(|p| p.core.write),
        Some(GovernanceLevel::Approve),
        "#2503: an unrelated delete must leave the policy exactly as it was"
    );

    cleanup(&pool, &[&victim_ns]).await;
}

/// A namespace that was NEVER governed keeps allow-on-silence (#1569) on
/// postgres too — the floor fires only where an operator configured a standard.
#[tokio::test]
async fn control_pg_ungoverned_namespace_keeps_allow_on_silence_2503() {
    let Some((store, _pool)) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let ns = uniq("never-governed-2503");
    assert_eq!(
        store.resolve_governance_policy(&ns).await.expect("resolve"),
        None,
        "#1569: #2503 must not tighten the never-configured case"
    );
}
