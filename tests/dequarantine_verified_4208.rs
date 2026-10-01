// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4208 F2/F3 — pins for `MemoryStore::dequarantine_verified`: the trait
//! default is fail-closed, and `SqliteStore` releases a quarantine only when
//! the stored row is the attested, verified unit (content / title / namespace /
//! kind / author) — never for an unattested incoming row, never on a mismatch.

#![cfg(feature = "sal")]

use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
use ai_memory::store::{CallerContext, MemoryStore, sqlite::SqliteStore};
use serde_json::json;

const ID: &str = "m-4208-unit";

fn mem(content: &str, attest: Option<&str>) -> Memory {
    let mut meta = json!({"agent_id": "ai:author-4208"});
    if let Some(a) = attest {
        meta["attest_level"] = json!(a);
    }
    Memory {
        id: ID.to_string(),
        tier: Tier::Long,
        namespace: "ns-4208".into(),
        title: "title-4208".into(),
        content: content.into(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "user".into(),
        access_count: 0,
        created_at: "2026-06-16T00:00:00+00:00".into(),
        updated_at: "2026-06-16T00:00:00+00:00".into(),
        last_accessed_at: None,
        expires_at: None,
        metadata: meta,
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

struct Fx {
    store: SqliteStore,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn seeded_quarantined(local_content: &str) -> Fx {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("t.db");
    let store = SqliteStore::open(&path).expect("open");
    store
        .store(
            &CallerContext::for_agent("ai:author-4208"),
            &mem(local_content, Some("agent_attested")),
        )
        .await
        .expect("seed");
    let c = rusqlite::Connection::open(&path).expect("raw");
    let n = c
        .execute(
            "UPDATE memories SET lifecycle_state='quarantined' WHERE id=?1",
            [ID],
        )
        .expect("quarantine");
    assert_eq!(n, 1);
    Fx {
        store,
        path,
        _dir: dir,
    }
}

fn state(fx: &Fx) -> String {
    rusqlite::Connection::open(&fx.path)
        .expect("raw")
        .query_row(
            "SELECT lifecycle_state FROM memories WHERE id=?1",
            [ID],
            |r| r.get(0),
        )
        .expect("state")
}

#[tokio::test]
async fn sqlite_releases_when_stored_row_is_the_attested_unit_4208() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    assert!(fx.store.dequarantine_verified(ID, &v).await.expect("call"));
    assert_eq!(state(&fx), "open");
}

#[tokio::test]
async fn sqlite_keeps_quarantine_when_stored_content_differs_4208() {
    let fx = seeded_quarantined("local never-attested text").await;
    let v = mem("signed text", Some("agent_attested"));
    assert!(!fx.store.dequarantine_verified(ID, &v).await.expect("call"));
    assert_eq!(state(&fx), "quarantined");
}

/// F3: identical stored content, but the incoming row is not attested.
#[tokio::test]
async fn sqlite_keeps_quarantine_when_incoming_not_attested_4208() {
    for attest in [None, Some("claimed"), Some("unsigned")] {
        let fx = seeded_quarantined("signed text").await;
        let v = mem("signed text", attest);
        assert!(!fx.store.dequarantine_verified(ID, &v).await.expect("call"));
        assert_eq!(state(&fx), "quarantined", "attest={attest:?}");
    }
}

#[tokio::test]
async fn sqlite_absent_or_open_row_releases_nothing_4208() {
    let fx = seeded_quarantined("signed text").await;
    let v = mem("signed text", Some("agent_attested"));
    let mut other = v.clone();
    other.id = "absent".into();
    assert!(
        !fx.store
            .dequarantine_verified("absent", &other)
            .await
            .expect("absent")
    );
    assert!(fx.store.dequarantine_verified(ID, &v).await.expect("first"));
    assert!(
        !fx.store
            .dequarantine_verified(ID, &v)
            .await
            .expect("already open")
    );
}
