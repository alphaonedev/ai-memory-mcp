// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! POSTGRES twins of the v1.0.0 data-integrity cluster #2395 / #2394 / #2385.
//!
//! Each defect existed on BOTH backends with the same SQL shape, so each fix
//! landed on both. These are the live-postgres proofs, following the
//! skip-if-`AI_MEMORY_TEST_POSTGRES_URL`-unset pattern of
//! `tests/pg_fix4_parity_tests.rs`.
//!
//! * **#2395** — `confidence` merged by `GREATEST` while
//!   `confidence_source` / `confidence_signals` / `confidence_decayed_at`
//!   merged by a DIFFERENT rule, so the surviving number and its calibration
//!   record could come from different operands.
//! * **#2394** — `memory_kind` is sticky but `kind_provenance` merged by a
//!   bare `COALESCE`, so provenance labelled a kind the merge rejected.
//! * **#2385** — `archived_memories` had no `cid` / `cid_genesis`, so
//!   `archive_restore` RE-MINTED the genesis address from six reconstructed
//!   inputs instead of carrying it.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres \
//!   --test pg_merge_field_set_coherence_2394_2395_2385 -- --include-ignored
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, KindProvenance, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

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

fn sample(id: &str, ns: &str, title: &str, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: "field-set coherence content".to_string(),
        priority: 5,
        confidence: 0.5,
        source: "test".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

/// #2395 — the operand that LOSES the `GREATEST(confidence)` must not
/// relabel the survivor. Pre-fix the incoming non-default
/// `confidence_source` replaced the label while `GREATEST` kept the OTHER
/// operand's number.
#[tokio::test]
async fn live_losing_operand_cannot_relabel_the_surviving_confidence_2395() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2395-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2395-{run}");
    let title = format!("pg-2395-title-{run}");

    let mut first = sample(&format!("pg-2395-a-{run}"), &ns, &title, owner);
    first.confidence = 0.9;
    first.confidence_source = ConfidenceSource::AutoDerived;
    let id = pg.store(&ctx, &first).await.expect("store first");

    // Incoming LOSES the GREATEST but carries an explicit non-default source.
    let mut second = sample(&format!("pg-2395-b-{run}"), &ns, &title, owner);
    second.confidence = 0.4;
    second.confidence_source = ConfidenceSource::Calibrated;
    pg.store(&ctx, &second).await.expect("store merge");

    let merged = pg.get(&ctx, &id).await.expect("get merged");
    assert!(
        (merged.confidence - 0.9).abs() < 1e-9,
        "GREATEST keeps the stored confidence, got {}",
        merged.confidence
    );
    assert_eq!(
        merged.confidence_source,
        ConfidenceSource::AutoDerived,
        "#2395: the surviving confidence must keep ITS OWN source label"
    );
}

/// #2395 — the operand that WINS carries its own record wholesale, including
/// a plain `caller_provided` label. Pre-fix the `caller_provided` incoming
/// kept the stored `auto_derived` label, so a caller-asserted number wore an
/// auto-derivation badge.
#[tokio::test]
async fn live_winning_operand_carries_its_own_calibration_record_2395() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2395b-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2395b-{run}");
    let title = format!("pg-2395b-title-{run}");

    let mut first = sample(&format!("pg-2395b-a-{run}"), &ns, &title, owner);
    first.confidence = 0.4;
    first.confidence_source = ConfidenceSource::AutoDerived;
    let id = pg.store(&ctx, &first).await.expect("store first");

    let mut second = sample(&format!("pg-2395b-b-{run}"), &ns, &title, owner);
    second.confidence = 0.9;
    second.confidence_source = ConfidenceSource::CallerProvided;
    pg.store(&ctx, &second).await.expect("store merge");

    let merged = pg.get(&ctx, &id).await.expect("get merged");
    assert!((merged.confidence - 0.9).abs() < 1e-9);
    assert_eq!(
        merged.confidence_source,
        ConfidenceSource::CallerProvided,
        "#2395: a caller-asserted value must not wear the stored auto_derived label"
    );
}

/// #2395 — federation twin (`apply_remote_memory`): a peer that loses the
/// `GREATEST` but wins the `updated_at` tiebreak must not relabel the survivor.
/// Both replicas converge on this, so the pre-fix skew was permanent.
#[tokio::test]
async fn live_federation_confidence_tuple_rides_the_max_winner_2395() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2395c-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2395c-{run}");
    let title = format!("pg-2395c-title-{run}");

    let mut local = sample(&format!("pg-2395c-a-{run}"), &ns, &title, owner);
    local.confidence = 0.9;
    local.confidence_source = ConfidenceSource::AutoDerived;
    local.updated_at = "2026-01-01T00:00:00+00:00".to_string();
    let id = pg
        .apply_remote_memory(&ctx, &local)
        .await
        .expect("apply local");

    let mut peer = sample(&format!("pg-2395c-b-{run}"), &ns, &title, owner);
    peer.confidence = 0.4;
    peer.confidence_source = ConfidenceSource::Decayed;
    peer.updated_at = "2026-12-01T00:00:00+00:00".to_string();
    pg.apply_remote_memory(&ctx, &peer)
        .await
        .expect("apply peer");

    let merged = pg.get(&ctx, &id).await.expect("get merged");
    assert!((merged.confidence - 0.9).abs() < 1e-9);
    assert_eq!(
        merged.confidence_source,
        ConfidenceSource::AutoDerived,
        "#2395: a NEWER peer that lost the GREATEST must not relabel the survivor"
    );
}

/// #2394 — the sticky `memory_kind` keeps its OWN provenance; the rejected
/// write's provenance must not be adopted.
#[tokio::test]
async fn live_sticky_kind_keeps_its_own_provenance_2394() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2394-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2394-{run}");
    let title = format!("pg-2394-title-{run}");

    let mut first = sample(&format!("pg-2394-a-{run}"), &ns, &title, owner);
    first.memory_kind = MemoryKind::Reflection;
    KindProvenance::Declared.stamp(&mut first.metadata);
    let id = pg.store(&ctx, &first).await.expect("store first");

    let mut second = sample(&format!("pg-2394-b-{run}"), &ns, &title, owner);
    second.memory_kind = MemoryKind::Observation;
    KindProvenance::Llm.stamp(&mut second.metadata);
    pg.store(&ctx, &second).await.expect("store merge");

    let (kind, provenance): (String, Option<String>) =
        sqlx::query_as("SELECT memory_kind, kind_provenance FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(pg.pool())
            .await
            .expect("read merged kind pair");
    assert_eq!(kind, "reflection", "L1-1 stickiness must hold");
    assert_eq!(
        provenance.as_deref(),
        Some("declared"),
        "#2394: provenance must describe the kind that SURVIVED"
    );
}

/// #2394 — when the incoming kind IS adopted, its provenance is taken
/// verbatim (NULL included), so a marker minted for the SUPERSEDED kind is
/// never inherited.
#[tokio::test]
async fn live_adopted_kind_takes_the_incoming_provenance_verbatim_2394() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2394b-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2394b-{run}");
    let title = format!("pg-2394b-title-{run}");

    let mut first = sample(&format!("pg-2394b-a-{run}"), &ns, &title, owner);
    first.memory_kind = MemoryKind::Observation;
    KindProvenance::Declared.stamp(&mut first.metadata);
    let id = pg.store(&ctx, &first).await.expect("store first");

    // Kind CHANGES and the incoming carries no provenance marker.
    let mut second = sample(&format!("pg-2394b-b-{run}"), &ns, &title, owner);
    second.memory_kind = MemoryKind::Concept;
    pg.store(&ctx, &second).await.expect("store merge");

    let (kind, provenance): (String, Option<String>) =
        sqlx::query_as("SELECT memory_kind, kind_provenance FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(pg.pool())
            .await
            .expect("read merged kind pair");
    assert_eq!(kind, "concept", "the incoming kind was adopted");
    assert_eq!(
        provenance, None,
        "#2394: a provenance minted for the SUPERSEDED kind must not be inherited"
    );
}

/// #2385 — schema v90 columns exist on the postgres archive mirror.
#[tokio::test]
async fn live_archived_memories_has_the_v90_cid_columns_2385() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    for column in ["cid", "cid_genesis"] {
        let present: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_name = 'archived_memories' AND column_name = $1",
        )
        .bind(column)
        .fetch_one(pg.pool())
        .await
        .expect("information_schema probe");
        assert_eq!(present, 1, "archived_memories.{column} must exist at v90");
    }
}

/// #2385 — the genesis address must survive archive→restore byte-for-byte on
/// postgres too, INCLUDING when one of the six re-mint inputs has drifted on
/// the archived row (`metadata.agent_id` here). Pre-fix the restore silently
/// re-addressed the durable row.
#[tokio::test]
async fn live_archive_restore_preserves_the_genesis_cid_2385() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "pg-2385-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("pg-2385-{run}");
    let title = format!("pg-2385-title-{run}");

    let mem = sample(&format!("pg-2385-a-{run}"), &ns, &title, owner);
    let id = pg.store(&ctx, &mem).await.expect("store");
    let live_cid: Option<String> = sqlx::query_scalar("SELECT cid FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(pg.pool())
        .await
        .expect("read live cid");
    assert!(
        live_cid.is_some(),
        "the write funnel must stamp a genesis cid"
    );

    let moved = pg
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("manual"))
        .await
        .expect("archive");
    assert_eq!(moved, 1);

    let archived_cid: Option<String> =
        sqlx::query_scalar("SELECT cid FROM archived_memories WHERE id = $1")
            .bind(&id)
            .fetch_one(pg.pool())
            .await
            .expect("read archived cid");
    assert_eq!(
        archived_cid, live_cid,
        "#2385: the archive must CARRY the genesis cid, not drop it"
    );

    // Drift one of the six re-mint inputs on the archived row.
    sqlx::query(
        "UPDATE archived_memories \
         SET metadata = jsonb_set(metadata, '{agent_id}', '\"ai:mallory\"'::jsonb) \
         WHERE id = $1",
    )
    .bind(&id)
    .execute(pg.pool())
    .await
    .expect("drift the archived agent_id");

    assert!(
        pg.archive_restore(&ctx, &id).await.expect("restore"),
        "restore must report success"
    );
    let restored_cid: Option<String> = sqlx::query_scalar("SELECT cid FROM memories WHERE id = $1")
        .bind(&id)
        .fetch_one(pg.pool())
        .await
        .expect("read restored cid");
    assert_eq!(
        restored_cid, live_cid,
        "#2385: a drifted re-mint input must NOT re-address the durable row"
    );
}

/// #2385 — the v90 arm must actually RUN against a database already at v89,
/// not only against a fresh install. `connect` short-circuits at the tip, so
/// a shared test database that is already at v90 would never prepare the
/// v90 DDL. Rewind the stamp (the DDL is `IF NOT EXISTS`, so the corpus
/// is not rewritten) and reconnect so the arm is parsed and applied on a
/// live server.
#[tokio::test]
async fn live_v90_arm_runs_on_a_database_already_at_v89_2385() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    {
        let mut tx = pg.pool().begin().await.expect("begin v89 rewind");
        sqlx::query("DELETE FROM schema_version")
            .execute(&mut *tx)
            .await
            .expect("clear stamp");
        sqlx::query("INSERT INTO schema_version (version) VALUES (89)")
            .execute(&mut *tx)
            .await
            .expect("rewind to v89");
        tx.commit().await.expect("commit v89 rewind");
    }
    drop(pg);
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("url still set");
    let pg = PostgresStore::connect(&url)
        .await
        .expect("reconnect must apply v90 from v89");
    let v = pg.schema_version().await.expect("stamp");
    assert_eq!(
        v,
        ai_memory::storage::current_schema_version_for_tests(),
        "the ladder must land back on the tip after replaying v90 from v89"
    );
    eprintln!("RAN: live_v90_arm_runs_on_a_database_already_at_v89_2385 (from v89)");
}
