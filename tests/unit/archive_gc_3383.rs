// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! GC caller fixtures stay outside src/ per the #3523 structural guard.

use super::*;

fn open_conn() -> rusqlite::Connection {
    crate::db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

#[test]
fn handle_gc_2308_folds_pending_extension_before_dry_run_and_real_gc() {
    // #3383 — pin the legacy operator scope on this test thread only.
    let _caller = crate::identity::test_agent_id::AgentIdOverride::unset();

    // #2308 (FBL-04) regression — the MCP `memory_gc` surface must
    // apply pending recall-driven TTL floor-extensions BEFORE both
    // the dry-run count and the real sweep. Two short-tier rows
    // whose BASE 6h TTL already lapsed; only one was recalled
    // (pure recall → an unfolded `recall_observations` row whose
    // per-access short-tier extension, observed_at + 1h, pushes
    // its real expiry into the future).
    let conn = open_conn();
    let created = (chrono::Utc::now() - chrono::Duration::hours(7)).to_rfc3339();
    let lapsed = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    for id in ["fbl04-recalled", "fbl04-control"] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, \
                                   updated_at, expires_at) \
             VALUES (?1, 'short', 'fbl04', ?1, 'c', ?2, ?2, ?3)",
            rusqlite::params![id, created, lapsed],
        )
        .unwrap();
    }
    crate::observations::record_recall(
        &conn,
        "fbl04-mcp-r1",
        &[crate::observations::Candidate {
            memory_id: "fbl04-recalled",
            retriever: "fts5",
            rank: 1,
            score: 0.5,
        }],
    )
    .unwrap();

    // Dry-run counts POST-fold reality: only the un-recalled
    // control row is reapable (pre-#2308 this counted 2).
    let dry = handle_gc(&conn, &json!({"dry_run": true}), false).expect("gc dry-run ok");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["collected"], 1, "dry-run must match post-fold reality");
    let exists = |id: &str| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!(exists("fbl04-recalled"), 1, "dry-run deletes nothing");
    assert_eq!(exists("fbl04-control"), 1, "dry-run deletes nothing");

    // Real run reaps ONLY the control row; the recalled row's
    // folded extension keeps it alive (pre-#2308 it was reaped —
    // silent crypto-erasure with archive=false).
    let real = handle_gc(&conn, &json!({}), false).expect("gc run ok");
    assert_eq!(real["dry_run"], false);
    assert_eq!(real["collected"], 1);
    assert_eq!(
        exists("fbl04-recalled"),
        1,
        "recalled row survived memory_gc: its TTL extension was folded before eviction"
    );
    assert_eq!(
        exists("fbl04-control"),
        0,
        "control row expired as scheduled"
    );
}

/// #3204 item 7 — a DESTRUCTIVE sweep must refuse when any namespace
/// holding expired rows carries a non-`Any` `delete` policy. Pre-fix
/// `memory_gc` reached the substrate with no governance consult, so a
/// `delete: Approve` legal-hold was no defence: held rows simply
/// expired and vanished. `dry_run` stays ungated; an archiving sweep
/// stays recoverable via `memory_archive_restore` and is exempt.
#[test]
fn gc_destructive_sweep_refuses_delete_governed_namespace_3204() {
    // #3383 — pin the legacy operator scope on this test thread only.
    let _caller = crate::identity::test_agent_id::AgentIdOverride::unset();
    use crate::models::{
        CorePolicy, GovernanceLevel, GovernancePolicy, Memory, MemoryKind, Tier, default_metadata,
    };
    let conn = open_conn();
    let ns = "gov-gc-approve-3204";
    let policy = GovernancePolicy {
        core: CorePolicy {
            delete: GovernanceLevel::Approve,
            ..CorePolicy::default()
        },
        ..Default::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".into(), json!("ai:alice"));
        obj.insert("governance".into(), serde_json::to_value(&policy).unwrap());
    }
    let standard = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: format!("std-{ns}"),
        content: "policy".into(),
        tags: vec![],
        priority: 9,
        confidence: 1.0,
        source: "test".into(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
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
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };
    let sid = db::insert(&conn, &standard).expect("insert standard");
    db::set_namespace_standard(&conn, ns, &sid, None).expect("bind");

    let lapsed = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, \
                               updated_at, expires_at) \
         VALUES ('gc-held-3204', 'short', ?1, 'held', 'c', ?2, ?2, ?3)",
        rusqlite::params![ns, now, lapsed],
    )
    .unwrap();

    let dry = handle_gc(&conn, &json!({"dry_run": true}), false).expect("dry-run ungated");
    assert_eq!(dry["collected"], 1);
    assert_eq!(dry["dry_run"], true);

    let err = handle_gc(&conn, &json!({}), false)
        .expect_err("destructive sweep must refuse a delete-governed namespace");
    assert!(
        err.contains("governance") || err.contains("delete policy") || err.contains(ns),
        "got: {err}"
    );
    let still: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE id = 'gc-held-3204'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        still, 1,
        "held row must survive a refused destructive sweep"
    );

    // Archiving is recoverable; the hold is not defeated, so the
    // documented exemption lets the move proceed.
    let archived = handle_gc(&conn, &json!({}), true).expect("archiving sweep exempt");
    assert_eq!(archived["archived"], true);
    assert_eq!(archived["collected"], 1);
}

/// #3383 — span the chunk boundary in both dispositions. Foreign and
/// unowned rows cannot consume a chunk window or be archived/deleted.
#[test]
fn gc_owner_chunks_and_preview_agree_3383() {
    let _caller = crate::identity::test_agent_id::AgentIdOverride::set("ai:gc-owner-3383");
    for archive in [false, true] {
        let conn = open_conn();
        for n in 0..505 {
            let owner = if n < 502 {
                "ai:gc-owner-3383"
            } else {
                "ai:other-3383"
            };
            conn.execute(
                "INSERT INTO memories(id,tier,namespace,title,content,created_at,updated_at,expires_at,metadata)
                 VALUES(?1,'short','gc-3383',?1,'body','2000','2000','2000',?2)",
                rusqlite::params![format!("gc-{n}"), match n {
                    503 => json!({"agent_id":owner, "target_agent_id":"ai:gc-owner-3383"}),
                    504 => json!({}),
                    _ => json!({"agent_id":owner}),
                }.to_string()],
            ).unwrap();
        }
        let dry = handle_gc(&conn, &json!({"dry_run":true}), archive).unwrap();
        assert_eq!(dry["collected"], 503);
        let real = handle_gc(&conn, &json!({}), archive).unwrap();
        assert_eq!(real["collected"], 503);
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 2);
        assert_eq!(
            db::archive_stats(&conn).unwrap()["archived_total"],
            if archive { 503 } else { 0 }
        );
    }
}

#[test]
fn gc_owner_archive_rolls_back_on_delete_failure_3383() {
    let _caller = crate::identity::test_agent_id::AgentIdOverride::set("ai:gc-owner-3383");
    let conn = open_conn();
    conn.execute(
        "INSERT INTO memories(id,tier,namespace,title,content,created_at,updated_at,expires_at,metadata)
         VALUES('rollback','short','gc-3383','rollback','body','2000','2000','2000',?1)",
        [json!({"agent_id":"ai:gc-owner-3383"}).to_string()],
    ).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_gc_3383 BEFORE DELETE ON memories BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;").unwrap();
    assert!(
        handle_gc(&conn, &json!({}), true)
            .unwrap_err()
            .contains("injected delete failure")
    );
    assert_eq!(
        db::archive_stats(&conn).unwrap()["archived_total"],
        0,
        "archive copy rolls back with failed deletion"
    );
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 1);
}
