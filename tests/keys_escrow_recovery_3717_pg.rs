// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3717 — PostgreSQL twin of the escrow recovery scenario through the store
//! funnel (`MemoryStore::store` seals, `MemoryStore::get` opens): enroll a
//! recovery key, seal a row (the mint writes the escrow), DESTROY the
//! `.x25519.priv`, unwrap the escrow with the operator's recovery key, and
//! read the SAME row back byte-identical. Live only under
//! `AI_MEMORY_TEST_POSTGRES_URL`; skips otherwise. The sqlite twin drives
//! the real binary: `tests/keys_escrow_recovery_3717.rs`.

#![cfg(feature = "sal-postgres")]

use ai_memory::encryption::escrow::{
    escrow_present, load_recovery_secret, mint_recovery_keypair, recover_private_from_escrow,
};
use ai_memory::encryption::{KeyAbsent, evict_cached_keypair, load_keypair};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use std::collections::BTreeMap;
use std::path::Path;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const PRIV_SUFFIX: &str = ".x25519.priv";

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP keys_escrow_recovery_3717_pg: {PG_URL_ENV} unset");
        return None;
    };
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn make_mem(title: &str, content: &str, agent_id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "global".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": agent_id }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .expect("list key dir")
        .map(|e| {
            let e = e.expect("entry");
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap_or_default(),
            )
        })
        .collect()
}

async fn raw_row(pg: &PostgresStore, id: &str) -> (Option<Vec<u8>>, String) {
    sqlx::query_as::<_, (Option<Vec<u8>>, String)>(
        "SELECT encrypted_envelope, content FROM memories WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pg.pool())
    .await
    .expect("raw row")
}

/// Every test in this binary turns the at-rest gate ON and never turns it off.
fn gate_on() {
    // SAFETY: every test in this binary sets the same value and none removes
    // it; no test reads a different gate state.
    unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_escrowed_key_recovers_after_the_priv_is_destroyed_and_the_row_reads_back_3717() {
    let Some(pg) = connect().await else { return };
    let key_dir = key_dir_sandbox::pin();
    gate_on();
    let agent = format!("agent-3717-pg-{}", uuid::Uuid::new_v4().simple());
    let plaintext = "pg sealed content that must survive the loss of its key — #3717";
    let ctx = CallerContext::for_admin("test-3717");

    // Enroll the deployment recovery key (private half in the operator's
    // off-node 0600 file; public half enrolled beside the agents' keys).
    let off_node = tempfile::tempdir().expect("off-node dir");
    let recovery_file = off_node.path().join("recovery.key");
    mint_recovery_keypair(key_dir, &recovery_file).expect("mint recovery key");

    // The first seal MINTS the agent's key — and, with a recovery key
    // enrolled, its escrow in the same mint.
    let id = MemoryStore::store(&pg, &ctx, &make_mem("pg-escrow", plaintext, &agent))
        .await
        .expect("store seals");
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    assert!(priv_path.is_file(), "the seal minted the live key");
    assert!(escrow_present(&agent, key_dir), "the mint wrote the escrow");
    let priv_bytes = std::fs::read(&priv_path).expect("snapshot .priv");
    let complete = snapshot(key_dir);
    let (env_before, content_before) = raw_row(&pg, &id).await;
    assert!(env_before.is_some(), "the row is sealed");
    let opened = MemoryStore::get(&pg, &ctx, &id).await.expect("open");
    assert_eq!(opened.content, plaintext);

    // Destroy the private half: the read fails typed and mints nothing.
    std::fs::remove_file(&priv_path).expect("delete .priv");
    evict_cached_keypair(&agent);
    let err = MemoryStore::get(&pg, &ctx, &id)
        .await
        .expect_err("a lost key must fail the read");
    assert!(format!("{err}").contains(KeyAbsent::CLASS), "{err}");
    assert!(!priv_path.exists(), "the read minted nothing (#3718)");
    assert!(load_keypair(&agent).expect("Ok(None)").is_none());
    assert_eq!(
        raw_row(&pg, &id).await,
        (env_before, content_before),
        "row untouched"
    );

    // Unwrap the escrow with the operator's recovery key: the private half
    // is restored byte-identical and the SAME row reads back.
    let secret = load_recovery_secret(&recovery_file).expect("read recovery key");
    let recovered =
        recover_private_from_escrow(&agent, key_dir, &secret).expect("recover from escrow");
    assert_eq!(recovered.priv_path, priv_path);
    assert!(!recovered.pub_rewritten, "the public half survived");
    assert_eq!(
        std::fs::read(&priv_path).expect("restored .priv"),
        priv_bytes,
        "byte-identical private half"
    );
    assert_eq!(
        snapshot(key_dir),
        complete,
        "the key directory is exactly as before the loss"
    );
    let back = MemoryStore::get(&pg, &ctx, &id)
        .await
        .expect("the restored key opens the row");
    assert_eq!(back.id, id);
    assert_eq!(back.content, plaintext, "the same row reads back");
}
