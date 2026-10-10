// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression controls for the campaign X oracle (#7100 F2).
#![cfg(feature = "sal")]

mod common;
#[path = "common/parity_fault.rs"]
mod parity_fault;
#[path = "common/parity_oracle.rs"]
mod parity_oracle;

use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use parity_fault::{CALLER, memory};
use parity_oracle::{RawDb, exec, state_digest};

const NS: &str = "parity/oracle";
const MEMORY_ID: &str = "oracle-memory";
const TITLE: &str = "oracle title";

#[test]
fn error_normalization_preserves_message_without_backend_label() {
    let unavailable = |backend: &str| StoreError::BackendUnavailable {
        backend: backend.to_string(),
        detail: "Pool Exhausted 7".to_string(),
        sqlstate: None,
    };
    let sqlite = parity_oracle::err_variant(&unavailable("sqlite"));
    let postgres = parity_oracle::err_variant(&unavailable("postgres"));
    assert_eq!(
        sqlite, postgres,
        "F4: backend label is not a semantic difference"
    );
    assert_eq!(
        sqlite.1, "backend unavailable: pool exhausted #",
        "F4: retain sanitized detail"
    );
}
const SEED_ACTION: &str = "INSERT INTO actions \
    (id, namespace, kind, state, claimed_by, created_at, updated_at) \
    VALUES ('oracle-action', 'parity/oracle', 'test', 'claimed', 'owner-a', 1, 1)";
const SEED_LEASE: &str = "INSERT INTO leases \
    (action_id, holder, acquired_at, expires_at, heartbeat_at) \
    VALUES ('oracle-action', 'owner-a', 1, 2, 1)";

async fn digest_contract(store: &dyn MemoryStore, raw: &RawDb) {
    store
        .store(
            &CallerContext::for_agent(CALLER),
            &memory(MEMORY_ID, TITLE, NS, CALLER),
        )
        .await
        .expect("seed oracle memory");
    exec(raw, SEED_ACTION).await;
    exec(raw, SEED_LEASE).await;
    let before = state_digest(raw).await;
    assert_eq!(
        before.section("memories"),
        &[vec![MEMORY_ID, TITLE, NS, "long", "active", "1", CALLER]],
        "F2: memory digest includes tier and metadata.agent_id"
    );
    assert_eq!(
        before.section("leases"),
        &[vec!["oracle-action", "owner-a"]],
        "F2: lease identity and holder, not count"
    );
    assert_eq!(
        before.section("actions"),
        &[vec!["oracle-action", "claimed", "owner-a"]],
        "F2: action identity, state and claimant, not count"
    );
    for (section, sql) in [
        ("memories", "UPDATE memories SET tier = 'mid'"),
        (
            "memories",
            "UPDATE memories SET metadata = '{\"agent_id\":\"owner-b\"}'",
        ),
        ("leases", "UPDATE leases SET holder = 'owner-b'"),
        ("actions", "UPDATE actions SET state = 'pending'"),
        ("actions", "UPDATE actions SET claimed_by = 'owner-b'"),
    ] {
        let prior = state_digest(raw).await;
        exec(raw, sql).await;
        let after = state_digest(raw).await;
        assert_ne!(prior.section(section), after.section(section), "F2: {sql}");
    }
}

#[tokio::test]
async fn sqlite_digest_contract() {
    let dir = tempfile::tempdir().expect("oracle tempdir");
    let path = dir.path().join("oracle.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("oracle sqlite");
    digest_contract(&store, &RawDb::Sqlite(path)).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_digest_contract() {
    let Some(url) = common::pg_isolate::isolated_url() else {
        eprintln!("skip: postgres_digest_contract: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    common::lane_db::assert_lane_database(&url);
    let scratch = common::pg_barrier::ScratchDb::create(&url, "ai_memory_oracle_contract")
        .await
        .expect("oracle scratch database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("oracle postgres");
    digest_contract(&store, &RawDb::Pg(store.pool().clone())).await;
    store.pool().close().await;
}

async fn link_audit_control(store: &dyn MemoryStore, raw: &RawDb) {
    use ai_memory::models::{MemoryLink, MemoryLinkRelation};
    const SOURCE: &str = "audit-source";
    const TARGET: &str = "audit-target";
    const EVENT: &str = "memory_link.created";
    let caller = CallerContext::for_agent(CALLER);
    for id in [SOURCE, TARGET] {
        store
            .store(&caller, &memory(id, id, NS, CALLER))
            .await
            .expect("audit endpoint");
    }
    let before = state_digest(raw).await;
    assert!(
        before.section("signed_events").is_empty(),
        "F5: empty initial audit control"
    );
    let link = MemoryLink {
        source_id: SOURCE.to_string(),
        target_id: TARGET.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: parity_fault::STAMP.to_string(),
        signature: None,
        observed_by: Some(CALLER.to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    store
        .link(&caller, &link)
        .await
        .expect("healthy link commits");
    let after = state_digest(raw).await;
    assert_eq!(after.section("links").len(), 1, "F5: link committed");
    assert_eq!(
        after.section("signed_events"),
        &[vec![EVENT, "1"]],
        "F5: live link audit positive control"
    );
}

#[tokio::test]
async fn sqlite_signed_events_positive_control() {
    let dir = tempfile::tempdir().expect("audit tempdir");
    let path = dir.path().join("audit.db");
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("audit sqlite");
    link_audit_control(&store, &RawDb::Sqlite(path)).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "X5 link audit divergence tracked in issue #7095 — un-ignore when fixed"]
async fn postgres_signed_events_positive_control() {
    let Some(url) = common::pg_isolate::isolated_url() else {
        eprintln!(
            "skip: postgres_signed_events_positive_control: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    common::lane_db::assert_lane_database(&url);
    let scratch = common::pg_barrier::ScratchDb::create(&url, "ai_memory_oracle_contract")
        .await
        .expect("audit scratch database");
    let store = ai_memory::store::postgres::PostgresStore::connect(&scratch.url())
        .await
        .expect("audit postgres");
    link_audit_control(&store, &RawDb::Pg(store.pool().clone())).await;
    store.pool().close().await;
}
