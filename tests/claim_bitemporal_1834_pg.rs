// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1834 — postgres twin of `tests/claim_bitemporal_recall_1834.rs`:
//! the claim-bitemporal VALID-time read/write surface on the postgres SAL
//! adapter. Proves (1) `store` persists `valid_from`/`valid_until` and
//! `list`/`recall_hybrid` apply the SAL `Filter.valid_at` AS-OF predicate
//! with the same half-open `[valid_from, valid_until)` END-EXCLUSIVE
//! contract as sqlite ($8 on the list SQL, $10 on the hybrid FTS pool),
//! and (2) `UpdatePatch.valid_until` closes a claim's interval while
//! `valid_from` stays IMMUTABLE (structurally absent from the UPDATE SET).
//!
//! Live-postgres gated via the SKIP-IF-URL-UNSET convention of the shipped
//! `pg_*` suite (`tests/embedding_space_provenance_2167_pg.rs` precedent):
//! each test self-skips with an eprintln when `AI_MEMORY_TEST_POSTGRES_URL`
//! is unset so a plain `cargo test` stays green on nodes without postgres
//! routing, and RUNS the real assertions when it points at a live schema.
//! DELIBERATELY NOT `#[ignore]` — the coverage job does not pass
//! `--include-ignored`, so an ignored twin would show 0% coverage for the
//! pg valid-time predicates it exercises.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test claim_bitemporal_1834_pg
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Memory, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, UpdatePatch};

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

/// A unique, FTS-matchable token shared by every row in this file's
/// fixtures so `recall_hybrid`'s keyword pool selects exactly them.
const TERM: &str = "bitemporalpgclaimzz";

fn mem(
    id: &str,
    namespace: &str,
    title: &str,
    owner: &str,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("{TERM} corpus body for {title}"),
        tags: vec![],
        priority: 5,
        confidence: 0.9,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        valid_from: valid_from.map(str::to_string),
        valid_until: valid_until.map(str::to_string),
        ..Memory::default()
    }
}

fn filter(ns: &str, valid_at: Option<&str>) -> Filter {
    Filter {
        namespace: Some(ns.to_string()),
        tier: None,
        tags_any: vec![],
        agent_id: None,
        since: None,
        until: None,
        valid_at: valid_at.map(str::to_string),
        limit: 50,
        offset: 0,
        active_embedding_space: None,
        // #2580 — metadata-equality pushdown axis unused on this path.
        metadata_eq: None,
        source_uri: None,
        // #3240 D1 — this recall path is not the double-writing HTTP funnel.
        skip_access_ledger: false,
    }
}

/// Seed the canonical three-claim corpus: an EARLY bounded claim
/// `[2026-01-01, 2026-06-01)`, a LATE open-ended claim `[2026-06-01, ∞)`,
/// and a LEGACY row with no VALID-time bounds (valid at every instant).
async fn seed(
    store: &PostgresStore,
    ctx: &CallerContext,
    ns: &str,
    owner: &str,
) -> (String, String, String) {
    let early = uuid::Uuid::new_v4().to_string();
    let late = uuid::Uuid::new_v4().to_string();
    let legacy = uuid::Uuid::new_v4().to_string();
    store
        .store(
            ctx,
            &mem(
                &early,
                ns,
                "early claim",
                owner,
                Some("2026-01-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
        )
        .await
        .expect("store early");
    store
        .store(
            ctx,
            &mem(
                &late,
                ns,
                "late claim",
                owner,
                Some("2026-06-01T00:00:00Z"),
                None,
            ),
        )
        .await
        .expect("store late");
    store
        .store(ctx, &mem(&legacy, ns, "legacy claim", owner, None, None))
        .await
        .expect("store legacy");
    (early, late, legacy)
}

/// Pre-ship 3x7 (#1834) — the pg write funnels canonicalize VALID-time
/// bounds to the fixed UTC rendering; stored-byte assertions expect it.
fn canon(ts: &str) -> String {
    ai_memory::validate::canonicalize_valid_time(ts).expect("canonical rendering")
}

fn titles(rows: &[Memory]) -> Vec<String> {
    let mut t: Vec<String> = rows.iter().map(|m| m.title.clone()).collect();
    t.sort();
    t
}

#[tokio::test]
async fn pg_list_applies_valid_at_half_open_window_1834() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:1834-pg";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("bitemporal1834-{}", uuid::Uuid::new_v4());
    seed(&store, &ctx, &ns, owner).await;

    // No as-of → every row (byte-identical legacy behaviour).
    let all = store
        .list(&ctx, &filter(&ns, None))
        .await
        .expect("list all");
    assert_eq!(
        titles(&all),
        vec!["early claim", "late claim", "legacy claim"],
        "None valid_at must admit every row"
    );

    // Inside the EARLY window → early + legacy (late has not started).
    let march = store
        .list(&ctx, &filter(&ns, Some("2026-03-01T00:00:00Z")))
        .await
        .expect("list march");
    assert_eq!(
        titles(&march),
        vec!["early claim", "legacy claim"],
        "as-of inside [valid_from, valid_until) must select the live claims"
    );

    // Exactly at the EARLY upper bound → END-EXCLUSIVE: early is OUT, the
    // late claim's start is INCLUSIVE so it is IN.
    let boundary = store
        .list(&ctx, &filter(&ns, Some("2026-06-01T00:00:00Z")))
        .await
        .expect("list boundary");
    assert_eq!(
        titles(&boundary),
        vec!["late claim", "legacy claim"],
        "the window must be start-inclusive, end-exclusive"
    );
}

#[tokio::test]
async fn pg_recall_hybrid_fts_pool_applies_valid_at_1834() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:1834-pg-recall";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("bitemporal1834r-{}", uuid::Uuid::new_v4());
    seed(&store, &ctx, &ns, owner).await;

    // No query embedding → the FTS pool ($10 valid_at predicate) is the
    // sole candidate source on the pg hybrid path.
    let hits = store
        .recall_hybrid(&ctx, TERM, None, &filter(&ns, Some("2026-07-01T00:00:00Z")))
        .await
        .expect("recall_hybrid as-of");
    let got: Vec<String> = {
        let mut t: Vec<String> = hits.iter().map(|(m, _)| m.title.clone()).collect();
        t.sort();
        t
    };
    assert_eq!(
        got,
        vec!["late claim", "legacy claim"],
        "an as-of after the early claim's close must drop it from hybrid recall"
    );
}

#[tokio::test]
async fn pg_update_closes_valid_until_while_valid_from_stays_immutable_1834() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:1834-pg-update";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("bitemporal1834u-{}", uuid::Uuid::new_v4());
    let (_, late_id, _) = seed(&store, &ctx, &ns, owner).await;

    // Close the open-ended LATE claim.
    let patch = UpdatePatch {
        valid_until: Some("2026-09-01T00:00:00Z".to_string()),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &late_id, patch)
        .await
        .expect("update valid_until");

    let closed = store.get(&ctx, &late_id).await.expect("get closed");
    assert_eq!(
        closed.valid_until.as_deref(),
        Some(canon("2026-09-01T00:00:00Z").as_str()),
        "the valid_until patch must close the claim's interval (canonical rendering)"
    );
    assert_eq!(
        closed.valid_from.as_deref(),
        Some(canon("2026-06-01T00:00:00Z").as_str()),
        "valid_from is IMMUTABLE — the genesis assertion instant must survive the patch"
    );

    // The closed claim now drops out of a post-close AS-OF list.
    let after = store
        .list(&ctx, &filter(&ns, Some("2026-10-01T00:00:00Z")))
        .await
        .expect("list after close");
    assert!(
        !after.iter().any(|m| m.id == late_id),
        "a closed claim must not be live after its valid_until"
    );
}

/// Pre-ship 3x7 (#1834) — mixed RFC3339 renderings of the SAME instant must
/// filter identically on the pg `::text` predicates. Pre-fix the `$8`/`$10`
/// binds compared raw caller bytes against raw stored bytes, so a
/// `+00:00`-rendered `valid_at` at the boundary of a `Z`-rendered
/// `valid_until` was wrongly INCLUDED (`'Z' > '+'`), and a `+05:00`-offset
/// bound mis-filtered by hours. Post-fix both sides canonicalize to the
/// fixed UTC micros rendering, so byte comparison IS instant comparison.
#[tokio::test]
async fn pg_mixed_renderings_compare_as_instants_1834() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = "ai:1834-pg-canon";
    let ctx = CallerContext::for_agent(owner);
    let ns = format!("bitemporal1834c-{}", uuid::Uuid::new_v4());
    // Seed stores Z-rendered bounds: early [2026-01-01Z, 2026-06-01Z),
    // late [2026-06-01Z, inf), legacy NULL/NULL.
    seed(&store, &ctx, &ns, owner).await;

    // The boundary instant rendered `+00:00` — the SAME instant as the seed's
    // `Z` bound. END-EXCLUSIVE at valid_until + START-INCLUSIVE at valid_from
    // must hold regardless of rendering: early OUT, late IN.
    let boundary_offset = store
        .list(&ctx, &filter(&ns, Some("2026-06-01T00:00:00+00:00")))
        .await
        .expect("list boundary +00:00");
    assert_eq!(
        titles(&boundary_offset),
        vec!["late claim", "legacy claim"],
        "a +00:00-rendered valid_at at the Z-rendered boundary must stay \
         start-inclusive / end-exclusive (equal instants, different bytes)"
    );

    // The same boundary instant rendered as a NON-UTC offset.
    let boundary_kabul = store
        .list(&ctx, &filter(&ns, Some("2026-06-01T05:00:00+05:00")))
        .await
        .expect("list boundary +05:00");
    assert_eq!(
        titles(&boundary_kabul),
        vec!["late claim", "legacy claim"],
        "a +05:00-rendered valid_at of the SAME instant must filter identically"
    );

    // An offset-rendered STORED bound: [2026-06-01T05:00:00+05:00, inf) ==
    // [2026-06-01T00:00:00Z, inf). A UTC as-of 30 minutes later is INSIDE.
    let off_id = uuid::Uuid::new_v4().to_string();
    store
        .store(
            &ctx,
            &mem(
                &off_id,
                &ns,
                "offset claim",
                owner,
                Some("2026-06-01T05:00:00+05:00"),
                None,
            ),
        )
        .await
        .expect("store offset claim");
    let inside = store
        .list(&ctx, &filter(&ns, Some("2026-06-01T00:30:00Z")))
        .await
        .expect("list inside offset window");
    assert!(
        inside.iter().any(|m| m.id == off_id),
        "an offset-rendered valid_from must filter by INSTANT, not bytes \
         (pre-fix: '05:00:00+05:00' > '00:30:00Z' lexicographically => wrongly excluded)"
    );
    let before = store
        .list(&ctx, &filter(&ns, Some("2026-05-31T23:59:59Z")))
        .await
        .expect("list before offset window");
    assert!(
        !before.iter().any(|m| m.id == off_id),
        "an as-of strictly before the offset claim's start must exclude it"
    );

    // The stored bytes are the canonical fixed-UTC rendering.
    let got = store.get(&ctx, &off_id).await.expect("get offset claim");
    assert_eq!(
        got.valid_from.as_deref(),
        Some(canon("2026-06-01T05:00:00+05:00").as_str()),
        "the pg store funnel must persist the canonical fixed-UTC rendering"
    );
}
