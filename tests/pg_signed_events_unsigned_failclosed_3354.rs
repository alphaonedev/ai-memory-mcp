// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3354 — POSTGRES twin of `tests/signed_events_unsigned_failclosed_3354.rs`.
//!
//! The #3354 control is ONE shared decision fn,
//! `signed_events::refuse_unsigned_append_when_required`, called from the
//! sqlite append chokepoint (`append_signed_event_no_tx`) AND from the postgres
//! append funnel (`pg_append_signed_event_with_chain_in_tx`). K3 parity means a
//! refusal true on one backend can never be silently absent on the other — but
//! parity that is only COMPILED is not parity that is OBSERVED. #3290 is the
//! cautionary precedent in this very file's subject area: the sqlite sever path
//! emitted a signed event and the postgres twin ran a bare silent `UPDATE`, a
//! backend-specific integrity gap that compiled perfectly on both legs.
//!
//! So this suite drives the real postgres funnel through a real public store
//! operation (`PostgresStore::delete` of a namespace standard, which severs the
//! binding and appends `substrate.namespace_standard_severed`) and asserts the
//! two postures behaviourally:
//!
//! - DENIED — under `AI_MEMORY_REQUIRE_SIGNED_AUDIT` the append is refused, the
//!   error surfaces to the caller, NO event row lands, and — because the gate
//!   returns before `tx.commit()` — the enclosing transaction rolls back, so the
//!   severed binding is still intact. A refusal can never leave a half-write.
//! - ALLOWED — by default the same operation succeeds and the row lands with
//!   `attest_level = 'unsigned'` (the pre-#3354 behaviour, deliberately
//!   preserved: dropping an audit row by default would destroy the evidence the
//!   ledger exists to keep).
//!
//! Gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip, and deliberately NOT `#[ignore]` (the PR postgres job does not
//! pass `--include-ignored`, so an ignored test silently never runs) —
//! mirroring `tests/pg_sever_audit_event_3290.rs`.

#![cfg(feature = "sal-postgres")]

use ai_memory::governance::audit::REQUIRE_SIGNED_AUDIT_ENV;
use ai_memory::models::{
    AttestLevel, ConfidenceSource, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier,
};
use ai_memory::signed_events::event_types::SUBSTRATE_NAMESPACE_STANDARD_SEVERED;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

/// `AI_MEMORY_REQUIRE_SIGNED_AUDIT` is process-global, so the require-mode test
/// must not overlap the default-mode one. `tokio::sync::Mutex` (not `std`) so
/// the guard can be held across the `.await`s without tripping
/// `clippy::await_holding_lock`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_require_mode() {
    // SAFETY: single-threaded window — every caller holds `ENV_LOCK`, and the
    // only other reader of this variable is `require_signed_audit_enabled()`.
    unsafe {
        std::env::set_var(REQUIRE_SIGNED_AUDIT_ENV, "1");
    }
}

fn clear_require_mode() {
    // SAFETY: as above.
    unsafe {
        std::env::remove_var(REQUIRE_SIGNED_AUDIT_ENV);
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

async fn live_pg() -> Option<PostgresStore> {
    let url = pg_url()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
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

async fn severed_event_count(store: &PostgresStore) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM signed_events WHERE event_type = $1")
        .bind(SUBSTRATE_NAMESPACE_STANDARD_SEVERED)
        .fetch_one(store.pool())
        .await
        .expect("count severed events")
}

/// The `attest_level` of the newest severance event on the chain.
async fn newest_severed_attest_level(store: &PostgresStore) -> String {
    sqlx::query_scalar(
        "SELECT attest_level FROM signed_events WHERE event_type = $1 \
         ORDER BY COALESCE(sequence, 0) DESC LIMIT 1",
    )
    .bind(SUBSTRATE_NAMESPACE_STANDARD_SEVERED)
    .fetch_one(store.pool())
    .await
    .expect("read newest severed event attest_level")
}

/// The standard currently bound to `ns`, if any — the rollback witness.
async fn bound_standard(store: &PostgresStore, ns: &str) -> Option<String> {
    sqlx::query_scalar("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
        .bind(ns)
        .fetch_optional(store.pool())
        .await
        .expect("read namespace_meta.standard_id")
        .flatten()
}

async fn cleanup(store: &PostgresStore, namespaces: &[&str]) {
    for ns in namespaces {
        let _ = sqlx::query("DELETE FROM namespace_meta WHERE namespace = $1")
            .bind(ns)
            .execute(store.pool())
            .await;
    }
}

/// DENIED — require-mode refuses the unsigned append at the postgres funnel,
/// the caller sees the error, no event lands, and the enclosing transaction
/// rolls back so the severed binding survives intact.
///
/// Pre-#3354 this operation SUCCEEDED and silently appended an `unsigned` row.
#[tokio::test]
async fn pg_unsigned_append_refused_under_require_mode_3354() {
    let _guard = ENV_LOCK.lock().await;
    clear_require_mode();

    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:req-3354");
    let ctx = CallerContext::for_agent(owner.clone());
    let standard_ns = uniq("std-req-3354");
    let victim_ns = uniq("bound-req-3354");

    // Setup runs in DEFAULT mode: the fixture writes must not be refused by the
    // very control under test.
    let std_mem = standard_memory(&standard_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim namespace");
    assert_eq!(
        bound_standard(&store, &victim_ns).await.as_deref(),
        Some(std_id.as_str()),
        "#3354 precondition: the victim namespace is bound to the standard"
    );

    let before = severed_event_count(&store).await;

    set_require_mode();
    let refused = store.delete(&ctx, &std_id).await;
    clear_require_mode();

    let err = refused.expect_err(
        "#3354: under AI_MEMORY_REQUIRE_SIGNED_AUDIT the postgres append funnel must REFUSE \
         a signed_events row this process could not sign — pre-fix the delete succeeded and \
         appended a silently `unsigned` row",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("#3354") || msg.to_lowercase().contains("unsigned"),
        "#3354: the refusal must name the condition so an operator can act on it; got: {msg}"
    );

    assert_eq!(
        severed_event_count(&store).await,
        before,
        "#3354: a REFUSED append must leave the chain exactly where it was — no partial row, \
         no gap in the sequence"
    );
    assert_eq!(
        bound_standard(&store, &victim_ns).await.as_deref(),
        Some(std_id.as_str()),
        "#3354: the gate returns BEFORE tx.commit(), so the whole severing transaction rolls \
         back — a refusal can never leave a half-write (binding severed but unrecorded)"
    );

    cleanup(&store, &[&victim_ns]).await;
}

/// ALLOWED — by default the identical operation succeeds and the row lands
/// `unsigned`. Refusing by DEFAULT would destroy the evidence the ledger exists
/// to keep, which is the strictly worse integrity failure; the default fix ends
/// the SILENCE (boot WARN, `doctor`, qualified verifier verdict), not the row.
#[tokio::test]
async fn pg_unsigned_append_still_succeeds_by_default_3354() {
    let _guard = ENV_LOCK.lock().await;
    clear_require_mode();

    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uniq("ai:def-3354");
    let ctx = CallerContext::for_agent(owner.clone());
    let standard_ns = uniq("std-def-3354");
    let victim_ns = uniq("bound-def-3354");

    let std_mem = standard_memory(&standard_ns, &owner, &approve_write_policy());
    let std_id = store.store(&ctx, &std_mem).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, &victim_ns, &std_id, None)
        .await
        .expect("bind victim namespace");

    let before = severed_event_count(&store).await;
    store
        .delete(&ctx, &std_id)
        .await
        .expect("#3354: default mode must remain byte-identical to pre-fix behaviour");
    assert_eq!(
        severed_event_count(&store).await,
        before + 1,
        "#3354: the severance event still lands by default"
    );
    assert_eq!(
        newest_severed_attest_level(&store).await,
        AttestLevel::Unsigned.as_str(),
        "#3354: with no signing key installed the row is `unsigned` — the condition the fix \
         makes LOUD rather than silently dropping the row"
    );

    cleanup(&store, &[&victim_ns]).await;
}
