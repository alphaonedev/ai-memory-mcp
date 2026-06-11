// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Fix-round 4 — postgres SAL upsert / federation parity regressions
//! (#1629 / #1631 / #1632-pg-twin).
//!
//! Live-postgres gated tests following the skip-if-env-unset pattern of
//! `tests/pg_fix3_parity_tests.rs` / `tests/store_parity_gaps.rs`:
//! every postgres test self-skips with an eprintln when
//! `AI_MEMORY_TEST_POSTGRES_URL` is unset so a plain `cargo test` stays
//! green on nodes without postgres routing, and RUNS the real
//! assertions when the env var points at a live schema. The sqlite
//! `insert_if_newer` version pin runs unconditionally.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test pg_fix4_parity_tests
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{Citation, ConfidenceSource, Memory, Tier};
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

/// Memory builder stamped with `metadata.agent_id = owner` so the SAL
/// #1412 caller-owns gates pass for a `CallerContext::for_agent` built
/// from the same owner.
fn sample_memory(id: &str, namespace: &str, title: &str, tier: Tier, owner: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: "fix4 parity test content".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 0.8,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        version: 1,
        ..Memory::default()
    }
}

fn sample_citation() -> Citation {
    Citation {
        uri: "https://example.com/evidence".to_string(),
        accessed_at: chrono::Utc::now().to_rfc3339(),
        hash: None,
        span: None,
    }
}

/// #1629 — the pg `(title, namespace)` upsert merge MUST follow the
/// sqlite `storage::insert` ON CONFLICT arms: a re-store of the same
/// `(title, namespace)` WITHOUT citations / confidence provenance /
/// with a lower priority must NOT wipe the stored provenance or
/// downgrade priority/confidence, MUST keep entity_id sticky, MUST
/// follow the incoming `source`, and (#1632 pg twin) MUST bump the
/// Gap-1 optimistic-concurrency `version` counter.
#[tokio::test]
async fn live_upsert_merge_preserves_provenance_1629() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "fix4-1629-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("fix4-1629-{run}");
    let title = format!("fix4-1629-title-{run}");

    // First write: rich provenance.
    let mut first = sample_memory(&format!("fix4-1629-a-{run}"), &ns, &title, Tier::Mid, owner);
    first.priority = 8;
    first.confidence = 0.9;
    first.citations = vec![sample_citation()];
    first.confidence_source = ConfidenceSource::AutoDerived;
    first.entity_id = Some("ent-1629".to_string());
    let id1 = pg.store(&ctx, &first).await.expect("store first");

    let stored1 = pg.get(&ctx, &id1).await.expect("get first");
    assert_eq!(stored1.version, 1, "fresh insert lands at version=1");

    // Second write: same (title, namespace), no provenance, lower
    // priority/confidence, different source + id.
    let mut second = sample_memory(&format!("fix4-1629-b-{run}"), &ns, &title, Tier::Mid, owner);
    second.priority = 3;
    second.confidence = 0.5;
    second.citations = Vec::new();
    second.confidence_source = ConfidenceSource::CallerProvided;
    second.entity_id = None;
    second.source = "import".to_string();
    second.content = "re-stored body".to_string();
    let id2 = pg.store(&ctx, &second).await.expect("store second (merge)");
    assert_eq!(
        id1, id2,
        "(title, namespace) collision merges onto the existing row"
    );

    let merged = pg.get(&ctx, &id1).await.expect("get merged");
    // Content follows the incoming row.
    assert_eq!(merged.content, "re-stored body");
    // #1629(1) — citations preserved when the incoming array is empty.
    assert_eq!(
        merged.citations.len(),
        1,
        "empty incoming citations must preserve the stored evidence"
    );
    assert_eq!(
        merged.citations.first().map(|c| c.uri.as_str()),
        Some("https://example.com/evidence"),
        "citations URI preserved across merge"
    );
    // #1629(2) — caller_provided default keeps the stored signal.
    assert_eq!(
        merged.confidence_source,
        ConfidenceSource::AutoDerived,
        "caller_provided re-store must not wipe the derived provenance"
    );
    // #1629(3) — MAX-merge: no downgrade.
    assert_eq!(merged.priority, 8, "priority must not downgrade on merge");
    assert!(
        (merged.confidence - 0.9).abs() < 1e-9,
        "confidence must not downgrade on merge (got {})",
        merged.confidence
    );
    // #1629(4) — source follows the incoming row (sqlite parity).
    assert_eq!(merged.source, "import");
    // #1629(7) — entity_id sticky: old wins.
    assert_eq!(merged.entity_id.as_deref(), Some("ent-1629"));
    // #1632 pg twin — upsert-merge bumps the version counter.
    assert_eq!(merged.version, 2, "#1632: upsert-merge must bump version");
}

/// #1631 — pg `apply_remote_memory` MUST converge with the sqlite
/// `insert_if_newer` total order: when two peers write the same
/// `(title, namespace)` with IDENTICAL `updated_at` but different
/// ids + content, the max-id content wins on every receiver,
/// regardless of arrival order.
#[tokio::test]
async fn live_federation_equal_timestamp_tiebreak_1631() {
    let Some(pg) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let owner = "fix4-1631-owner";
    let ctx = CallerContext::for_agent(owner);
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("fix4-1631-{run}");
    let ts = chrono::Utc::now().to_rfc3339();

    // Case A: low id arrives first, high id second → high id content wins.
    let title_a = format!("fix4-1631-a-{run}");
    let mut low = sample_memory(
        &format!("a-fix4-1631-{run}"),
        &ns,
        &title_a,
        Tier::Mid,
        owner,
    );
    low.created_at.clone_from(&ts);
    low.updated_at.clone_from(&ts);
    low.content = "from-low-id".to_string();
    let mut high = low.clone();
    high.id = format!("z-fix4-1631-{run}");
    high.content = "from-high-id".to_string();

    let row_id = pg.apply_remote_memory(&ctx, &low).await.expect("apply low");
    pg.apply_remote_memory(&ctx, &high)
        .await
        .expect("apply high");
    let merged = pg.get(&ctx, &row_id).await.expect("get merged A");
    assert_eq!(
        merged.content, "from-high-id",
        "equal updated_at: the max-id write must win (sqlite total-order parity)"
    );

    // Case B: high id arrives first, low id second → high id content stays.
    let title_b = format!("fix4-1631-b-{run}");
    let mut high_b = sample_memory(
        &format!("z-fix4-1631b-{run}"),
        &ns,
        &title_b,
        Tier::Mid,
        owner,
    );
    high_b.created_at.clone_from(&ts);
    high_b.updated_at.clone_from(&ts);
    high_b.content = "from-high-id".to_string();
    let mut low_b = high_b.clone();
    low_b.id = format!("a-fix4-1631b-{run}");
    low_b.content = "from-low-id".to_string();

    let row_id_b = pg
        .apply_remote_memory(&ctx, &high_b)
        .await
        .expect("apply high b");
    pg.apply_remote_memory(&ctx, &low_b)
        .await
        .expect("apply low b");
    let merged_b = pg.get(&ctx, &row_id_b).await.expect("get merged B");
    assert_eq!(
        merged_b.content, "from-high-id",
        "equal updated_at: a lower-id late arrival must NOT overwrite the max-id winner"
    );
}

/// #1631(7) — the sqlite federation receive path (`db::insert_if_newer`)
/// MUST persist the remote row's `version` (the #1029 decide-once
/// contract: version IS replicated state, merged via MAX(local,
/// remote)). Pre-#1631 the column was absent from the bind list so a
/// remote row with version=7 landed at the SQL DEFAULT 1.
#[test]
fn sqlite_insert_if_newer_persists_remote_version_1631() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open sqlite");
    let mut mem = sample_memory(
        "sq-1631-a",
        "fix4-1631-sq",
        "sq-1631-title",
        Tier::Long,
        "sq-owner",
    );
    mem.version = 7;
    let id = ai_memory::db::insert_if_newer(&conn, &mem).expect("insert_if_newer fresh");
    let v: i64 = conn
        .query_row("SELECT version FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("read version");
    assert_eq!(
        v, 7,
        "#1631: a remote row with version=7 must land version=7"
    );

    // MAX-merge: a stale remote version must not roll the local back.
    conn.execute("UPDATE memories SET version = 9 WHERE id = ?1", [&id])
        .expect("bump local version");
    let mut stale = mem.clone();
    stale.id = "sq-1631-b".to_string();
    stale.version = 2;
    stale.updated_at = chrono::Utc::now().to_rfc3339();
    stale.content = "newer content, stale version".to_string();
    let merged_id = ai_memory::db::insert_if_newer(&conn, &stale).expect("insert_if_newer merge");
    assert_eq!(merged_id, id);
    let v2: i64 = conn
        .query_row("SELECT version FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("read merged version");
    assert_eq!(
        v2, 9,
        "#1631: version merges via MAX(local, remote) — no rollback"
    );
}
