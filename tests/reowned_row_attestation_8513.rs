// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8513 (umbrella #8493, data F1) — `memory_share`, atomisation and promotion
//! clone a row to a NEW owner. The clone must never carry the source row's
//! attestation (`attest_level`, `write_signature`, `agent_pubkey`,
//! `pubkey_bound_at`): those were computed over the source owner's bytes and
//! verify for nobody once the owner, namespace, id and `created_at` change.
//! The clone reports its own attestation state (`claimed`) and records the
//! source id and source owner under the system-provenance keys.
//!
//! Postgres parity for the promote path runs under `feature = "sal-postgres"`
//! with the `AI_MEMORY_TEST_POSTGRES_URL` soft-skip house pattern.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{Atomiser, AtomiserConfig};
use ai_memory::config::FeatureTier;
use ai_memory::mcp::share::handle_share;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage;
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const SOURCE_OWNER: &str = "ai:source-owner-8513";
const SIGNATURE_B64: &str = "c291cmNlLXNpZ25hdHVyZS1ieXRlcw==";
const PUBKEY_B64: &str = "c291cmNlLXB1YmtleQ==";
const BOUND_AT: &str = "2026-01-01T00:00:00+00:00";

fn attested_metadata() -> Value {
    json!({
        "agent_id": SOURCE_OWNER,
        "attest_level": "agent_attested",
        "write_signature": SIGNATURE_B64,
        "agent_pubkey": PUBKEY_B64,
        "pubkey_bound_at": BOUND_AT,
    })
}

/// Source metadata carrying EVERY attestation key the reset must strip.
fn fully_attested_metadata(owner: &str) -> Value {
    let mut m = attested_metadata();
    m["agent_id"] = json!(owner);
    m["attestation_downgraded"] = json!(true);
    m["forged_signature_skipped"] = json!(true);
    m
}

fn long_body() -> String {
    (0..30)
        .map(|i| {
            format!(
                "Paragraph {i}: the kubernetes rolling deploy strategy required canary \
                 instance health checks. The pod readiness probe must pass before \
                 traffic shifts. Failures roll back the deployment within 30 seconds. \
                 Operator dashboards track replica counts and error rates."
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn seed_attested(conn: &Connection, namespace: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("reowned-8513-{}", uuid::Uuid::new_v4().simple()),
        content: content.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: attested_metadata(),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    storage::insert(conn, &mem).expect("seed attested source")
}

fn fresh_db() -> (NamedTempFile, Connection) {
    let tmp = NamedTempFile::new().expect("tempfile");
    let conn = storage::open(tmp.path()).expect("open");
    (tmp, conn)
}

/// The three assertions every re-owned clone must satisfy.
fn assert_attestation_reset(clone_metadata: &Value, new_owner: &str, label: &str) {
    for key in [
        "write_signature",
        "agent_pubkey",
        "pubkey_bound_at",
        "attestation_downgraded",
        "forged_signature_skipped",
    ] {
        assert!(
            clone_metadata.get(key).is_none(),
            "{label}: clone must not carry source `{key}`: {clone_metadata}"
        );
    }
    assert_eq!(
        clone_metadata["attest_level"],
        json!("claimed"),
        "{label}: clone reports its own attestation state, not the source's: {clone_metadata}"
    );
    assert_eq!(
        clone_metadata["agent_id"],
        json!(new_owner),
        "{label}: clone owner"
    );
}

#[test]
fn share_never_carries_source_attestation() {
    let (_tmp, conn) = fresh_db();
    let source_id = seed_attested(&conn, "team/alpha", "share me 8513");
    let out = handle_share(
        &conn,
        &json!({ "source_memory_id": source_id, "target_agent_id": "ai:target-8513" }),
        Some(SOURCE_OWNER),
    )
    .expect("share");
    let shared_id = out["shared_memory_id"].as_str().expect("shared id");
    let shared = storage::get(&conn, shared_id)
        .expect("get")
        .expect("shared row");
    assert_attestation_reset(&shared.metadata, "ai:target-8513", "share");
    assert_eq!(
        shared.metadata["attest_reset_reason"],
        json!("reowned_by_share")
    );
    assert_eq!(shared.metadata["shared_from"], json!(source_id));
    assert_eq!(shared.metadata["shared_from_agent_id"], json!(SOURCE_OWNER));
    // The source row keeps its own attestation untouched.
    let src = storage::get(&conn, &source_id).unwrap().unwrap();
    assert_eq!(src.metadata["attest_level"], json!("agent_attested"));
    assert_eq!(src.metadata["write_signature"], json!(SIGNATURE_B64));
}

struct TwoAtoms;

impl Curator for TwoAtoms {
    fn decompose(&self, _b: &str, _m: u32, _r: u32) -> Result<Vec<Atom>, CuratorError> {
        Ok(vec![
            Atom {
                text: "Canary health checks gate every rolling deploy.".to_string(),
            },
            Atom {
                text: "Failed readiness probes roll the deployment back.".to_string(),
            },
        ])
    }
}

#[test]
fn atomise_never_carries_source_attestation() {
    let (_tmp, conn) = fresh_db();
    let source_id = seed_attested(&conn, "team/alpha", &long_body());
    let atomiser = Atomiser::new(
        Box::new(TwoAtoms),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    );
    let caller = "ai:atomiser-8513";
    let res = atomiser
        .atomise_sync(&conn, &source_id, 200, false, caller)
        .expect("atomise");
    assert_eq!(
        res.atom_ids.len(),
        2,
        "atomise must store both atoms the curator returned"
    );
    for atom_id in &res.atom_ids {
        let atom = storage::get(&conn, atom_id).unwrap().expect("atom row");
        assert_attestation_reset(&atom.metadata, caller, "atomise");
        assert_eq!(
            atom.metadata["attest_reset_reason"],
            json!("reowned_by_atomise")
        );
        assert_eq!(atom.metadata["atomised_from"], json!(source_id));
        assert_eq!(atom.metadata["atomised_from_agent_id"], json!(SOURCE_OWNER));
    }
    assert_source_attestation_intact(&conn, &source_id, "atomise");
}

#[test]
fn promote_clone_never_carries_source_attestation() {
    let (_tmp, conn) = fresh_db();
    let source_id = seed_attested(&conn, "team/alpha", "promote me 8513");
    let clone_id =
        storage::promote_to_namespace(&conn, &source_id, "team", Some("ai:promoter-8513"))
            .expect("promote");
    let clone = storage::get(&conn, &clone_id).unwrap().expect("clone");
    assert_attestation_reset(&clone.metadata, "ai:promoter-8513", "promote");
    assert_eq!(
        clone.metadata["attest_reset_reason"],
        json!("reowned_by_promote")
    );
    assert_eq!(clone.metadata["promoted_from"], json!(source_id));
    assert_eq!(
        clone.metadata["promoted_from_agent_id"],
        json!(SOURCE_OWNER)
    );
    assert_source_attestation_intact(&conn, &source_id, "promote");
}

/// A promote with no acting principal keeps the source owner but still resets
/// the attestation: the signed envelope (namespace, `created_at`) changed.
#[test]
fn promote_clone_without_actor_resets_attestation() {
    let (_tmp, conn) = fresh_db();
    let source_id = seed_attested(&conn, "team/beta", "promote anon 8513");
    let clone_id = storage::promote_to_namespace(&conn, &source_id, "team", None).expect("promote");
    let clone = storage::get(&conn, &clone_id).unwrap().expect("clone");
    assert_attestation_reset(&clone.metadata, SOURCE_OWNER, "promote-no-actor");
    assert_eq!(
        clone.metadata["attest_reset_reason"],
        json!("reowned_by_promote")
    );
    assert_eq!(clone.metadata["promoted_from"], json!(source_id));
    assert_eq!(
        clone.metadata["promoted_from_agent_id"],
        json!(SOURCE_OWNER)
    );
    assert_source_attestation_intact(&conn, &source_id, "promote-no-actor");
}

/// The source row keeps its own attestation byte-for-byte (F-2).
fn assert_source_attestation_intact(conn: &Connection, source_id: &str, label: &str) {
    let src = storage::get(conn, source_id)
        .unwrap()
        .unwrap_or_else(|| panic!("{label}: source row must still exist"));
    assert_eq!(
        src.metadata["attest_level"],
        json!("agent_attested"),
        "{label}"
    );
    assert_eq!(
        src.metadata["write_signature"],
        json!(SIGNATURE_B64),
        "{label}"
    );
    assert_eq!(src.metadata["agent_pubkey"], json!(PUBKEY_B64), "{label}");
    assert_eq!(src.metadata["pubkey_bound_at"], json!(BOUND_AT), "{label}");
    assert_eq!(src.metadata["agent_id"], json!(SOURCE_OWNER), "{label}");
}

/// #8532 — consolidate merges N source rows into one row owned by the
/// consolidator. Seeds two fully attested sources (different owners).
fn consolidate_case(substrate_authored: bool, label: &str) {
    let (_tmp, conn) = fresh_db();
    let mut ids = Vec::new();
    for (i, owner) in ["ai:src-a-8532", "ai:src-b-8532"].into_iter().enumerate() {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: "team/alpha".to_string(),
            title: format!("consolidate-src-{i}-{}", uuid::Uuid::new_v4().simple()),
            content: format!("source content {i} 8532"),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: fully_attested_metadata(owner),
            memory_kind: MemoryKind::Observation,
            confidence_source: ConfidenceSource::CallerProvided,
            version: 1,
            ..Memory::default()
        };
        ids.push(storage::insert(&conn, &mem).expect("seed source"));
    }
    let consolidator = "ai:consolidator-8532";
    let new_id = storage::consolidate(
        &conn,
        &ids,
        "consolidated 8532",
        "merged summary 8532",
        "team/alpha",
        &Tier::Long,
        "test",
        consolidator,
        substrate_authored,
    )
    .expect("consolidate");
    let merged = storage::get(&conn, &new_id).unwrap().expect("merged row");
    assert_attestation_reset(&merged.metadata, consolidator, label);
    assert_eq!(
        merged.metadata["attest_reset_reason"],
        json!("reowned_by_consolidate"),
        "{label}"
    );
    // Sources are consumed (hard delete or tombstone) but never mutated.
    for id in &ids {
        if let Some(src) = storage::get(&conn, id).unwrap() {
            assert_eq!(
                src.metadata["attest_level"],
                json!("agent_attested"),
                "{label}"
            );
            assert_eq!(
                src.metadata["write_signature"],
                json!(SIGNATURE_B64),
                "{label}"
            );
        }
    }
}

#[test]
fn consolidate_never_carries_source_attestation_tenant() {
    consolidate_case(false, "consolidate-tenant");
}

#[test]
fn consolidate_never_carries_source_attestation_substrate() {
    consolidate_case(true, "consolidate-substrate");
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{
        BOUND_AT, ConfidenceSource, Memory, PUBKEY_B64, SIGNATURE_B64, SOURCE_OWNER, Tier,
        assert_attestation_reset, fully_attested_metadata, json,
    };
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    #[tokio::test]
    async fn pg_promote_clone_never_carries_source_attestation() {
        let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
            return;
        };
        let Ok(store) = PostgresStore::connect(&url).await else {
            eprintln!("skip: PostgresStore::connect failed");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("skip: raw pool connect failed");
            return;
        };
        let suffix = &uuid::Uuid::new_v4().to_string()[..8];
        let parent_ns = format!("ns8513{suffix}");
        let child_ns = format!("{parent_ns}/child");
        let requester = "ai:promoter-8513";
        let mut ctx = CallerContext::for_agent(requester);
        ctx.bypass_visibility = true;

        let source_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let source = Memory {
            id: source_id.clone(),
            tier: Tier::Mid,
            namespace: child_ns.clone(),
            title: "promote-me-8513".to_string(),
            content: "durable promoted content 8513".to_string(),
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: json!({
                "agent_id": SOURCE_OWNER,
                "attest_level": "agent_attested",
                "write_signature": SIGNATURE_B64,
                "agent_pubkey": PUBKEY_B64,
                "pubkey_bound_at": BOUND_AT,
            }),
            confidence_source: ConfidenceSource::CallerProvided,
            version: 1,
            ..Memory::default()
        };
        store.store(&ctx, &source).await.expect("seed source");

        let pending_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO pending_actions \
             (id, action_type, memory_id, namespace, payload, requested_by, requested_at, status) \
             VALUES ($1, 'promote', $2, $3, $4, $5, $6, 'approved')",
        )
        .bind(&pending_id)
        .bind(&source_id)
        .bind(&child_ns)
        .bind(json!({ "id": source_id, "to_namespace": parent_ns }))
        .bind(requester)
        .bind(chrono::Utc::now())
        .execute(&pool)
        .await
        .expect("insert approved promote pending");

        let clone_id = store
            .execute_pending_action(&ctx, &pending_id)
            .await
            .expect("execute")
            .expect("clone id");
        let clone = store.get(&ctx, &clone_id).await.expect("clone row");
        assert_attestation_reset(&clone.metadata, requester, "pg-promote");
        assert_eq!(
            clone.metadata["attest_reset_reason"],
            json!("reowned_by_promote")
        );
        assert_eq!(clone.metadata["promoted_from"], json!(source_id));
        assert_eq!(
            clone.metadata["promoted_from_agent_id"],
            json!(SOURCE_OWNER)
        );

        let _ = sqlx::query("DELETE FROM pending_actions WHERE id = $1")
            .bind(&pending_id)
            .execute(&pool)
            .await;
        for id in [&source_id, &clone_id] {
            let _ = sqlx::query("DELETE FROM memory_links WHERE source_id = $1 OR target_id = $1")
                .bind(id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
    }

    /// #8532 — sal-postgres consolidate, tenant and substrate (`bypass_visibility`).
    #[tokio::test]
    async fn pg_consolidate_never_carries_source_attestation() {
        let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("skip: no AI_MEMORY_TEST_POSTGRES_URL");
            return;
        };
        let Ok(store) = PostgresStore::connect(&url).await else {
            eprintln!("skip: PostgresStore::connect failed");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("skip: raw pool connect failed");
            return;
        };
        let suffix = &uuid::Uuid::new_v4().to_string()[..8];
        let namespace = format!("ns8532{suffix}");
        let consolidator = "ai:consolidator-8532";
        for substrate in [false, true] {
            let mut ctx = CallerContext::for_agent(consolidator);
            ctx.bypass_visibility = substrate;
            let mut ids = Vec::new();
            for (i, owner) in ["ai:src-a-8532", "ai:src-b-8532"].into_iter().enumerate() {
                let id = uuid::Uuid::new_v4().to_string();
                let now = chrono::Utc::now().to_rfc3339();
                let source = Memory {
                    id: id.clone(),
                    tier: Tier::Mid,
                    namespace: namespace.clone(),
                    title: format!("consolidate-src-{i}-{substrate}-8532"),
                    content: format!("source content {i} {substrate} 8532"),
                    priority: 5,
                    confidence: 1.0,
                    source: "test".to_string(),
                    created_at: now.clone(),
                    updated_at: now,
                    metadata: fully_attested_metadata(owner),
                    confidence_source: ConfidenceSource::CallerProvided,
                    version: 1,
                    ..Memory::default()
                };
                let mut seed_ctx = CallerContext::for_agent(owner);
                seed_ctx.bypass_visibility = true;
                store.store(&seed_ctx, &source).await.expect("seed source");
                ids.push(id);
            }
            let new_id = store
                .consolidate_with_expected_versions(
                    &ctx,
                    &ids,
                    "consolidated 8532",
                    "merged summary 8532",
                    &namespace,
                    &Tier::Mid,
                    "test",
                    consolidator,
                    None,
                )
                .await
                .expect("consolidate");
            let merged = store.get(&ctx, &new_id).await.expect("merged row");
            let label = if substrate {
                "pg-consolidate-substrate"
            } else {
                "pg-consolidate-tenant"
            };
            assert_attestation_reset(&merged.metadata, consolidator, label);
            assert_eq!(
                merged.metadata["attest_reset_reason"],
                json!("reowned_by_consolidate"),
                "{label}"
            );
            for id in ids.iter().chain(std::iter::once(&new_id)) {
                let _ =
                    sqlx::query("DELETE FROM memory_links WHERE source_id = $1 OR target_id = $1")
                        .bind(id)
                        .execute(&pool)
                        .await;
                let _ = sqlx::query("DELETE FROM memories WHERE id = $1")
                    .bind(id)
                    .execute(&pool)
                    .await;
            }
        }
    }
}
