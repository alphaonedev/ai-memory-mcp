// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3718 — PostgreSQL twin through the store funnel (`MemoryStore::store`
//! seals, `MemoryStore::get` opens): a read with the agent's `.x25519.priv`
//! missing is the typed `key_absent` class, mints NOTHING, and leaves the
//! row untouched; restoring the file reads the original bytes back.
//! Live only under `AI_MEMORY_TEST_POSTGRES_URL` (a FRESH `ai_memory_f2a_*`
//! database — never `ai_memory_test`); skips otherwise.

#![cfg(feature = "sal-postgres")]

use ai_memory::encryption::{
    KeyAbsent, SealRefusedSealedRowsExist, evict_cached_keypair, load_keypair,
};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use std::collections::BTreeSet;
use std::path::Path;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";
const PRIV_SUFFIX: &str = ".x25519.priv";

async fn connect() -> Option<PostgresStore> {
    let Ok(url) = std::env::var(PG_URL_ENV) else {
        eprintln!("SKIP encryption_key_absent_3718_pg: {PG_URL_ENV} unset");
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

fn listing(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
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

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, bytes).expect("restore .priv");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}
#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("restore .priv");
}

#[tokio::test(flavor = "multi_thread")]
async fn pg_read_with_absent_key_is_typed_never_mints_and_leaves_the_row_3718() {
    let Some(pg) = connect().await else { return };
    let key_dir = key_dir_sandbox::pin();
    gate_on();
    let agent = format!("agent-3718-pg-{}", uuid::Uuid::new_v4().simple());
    let plaintext = "pg sealed secret — #3718";
    let ctx = CallerContext::for_admin("test-3718");

    let id = MemoryStore::store(&pg, &ctx, &make_mem("pg-absent", plaintext, &agent))
        .await
        .expect("store seals");
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    assert!(priv_path.is_file(), "the seal minted the live key");
    let before = listing(key_dir);
    let (env_before, content_before) = raw_row(&pg, &id).await;
    assert!(env_before.is_some(), "the row is sealed");
    let priv_bytes = std::fs::read(&priv_path).expect("snapshot .priv");

    std::fs::remove_file(&priv_path).expect("delete .priv");
    evict_cached_keypair(&agent);

    let err = MemoryStore::get(&pg, &ctx, &id)
        .await
        .expect_err("#3718 (pg): an absent key must fail the read");
    let msg = format!("{err}");
    assert!(msg.contains(KeyAbsent::CLASS), "class must be named: {msg}");
    assert!(msg.contains(&agent) && msg.contains("#3718"), "{msg}");
    assert!(
        !msg.contains("decrypt failed"),
        "not a wrong-recipient failure: {msg}"
    );
    assert!(
        !msg.contains(&key_dir.display().to_string()) && !msg.contains(PRIV_SUFFIX),
        "the caller never sees the key path: {msg}"
    );

    let mut expected = before.clone();
    expected.remove(&format!("{agent}{PRIV_SUFFIX}"));
    assert_eq!(
        listing(key_dir),
        expected,
        "#3718 (pg): the read minted nothing"
    );
    assert_eq!(
        raw_row(&pg, &id).await,
        (env_before, content_before),
        "row untouched"
    );
    assert!(load_keypair(&agent).expect("Ok(None)").is_none());

    write_0600(&priv_path, &priv_bytes);
    evict_cached_keypair(&agent);
    let back = MemoryStore::get(&pg, &ctx, &id)
        .await
        .expect("restored key opens the row");
    assert_eq!(back.content, plaintext);
}

/// Every test in this binary turns the at-rest gate ON and never turns it off,
/// so the concurrent writers of the same value cannot interleave into a
/// different state.
fn gate_on() {
    // SAFETY: every test in this binary sets the same value and none removes
    // it; no test reads a different gate state.
    unsafe { std::env::set_var("AI_MEMORY_ENCRYPT_AT_REST", "1") };
}

async fn sealed_rows(pg: &PostgresStore, agent: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM memories WHERE encrypted_envelope IS NOT NULL \
         AND metadata->>'agent_id' = $1",
    )
    .bind(agent)
    .fetch_one(pg.pool())
    .await
    .expect("count sealed rows")
}

fn wipe_key_material(key_dir: &Path, agent: &str) {
    for name in listing(key_dir) {
        if name.starts_with(agent) {
            std::fs::remove_file(key_dir.join(name)).expect("wipe key material");
        }
    }
    evict_cached_keypair(agent);
}

/// #3718 (review, pg) — written FIRST: no sealed rows + wiped key dir is a
/// fresh agent; its first seal mints normally.
#[tokio::test(flavor = "multi_thread")]
async fn pg_no_sealed_rows_with_wiped_key_dir_mints_normally_3718() {
    let Some(pg) = connect().await else { return };
    let key_dir = key_dir_sandbox::pin();
    gate_on();
    let agent = format!("agent-3718-pg-fresh-{}", uuid::Uuid::new_v4().simple());
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    let ctx = CallerContext::for_admin("test-3718");

    ai_memory::encryption::get_or_create_keypair(&agent).expect("mint out of band");
    wipe_key_material(key_dir, &agent);
    assert!(!priv_path.exists());
    assert_eq!(sealed_rows(&pg, &agent).await, 0, "a fresh agent");

    let id = MemoryStore::store(&pg, &ctx, &make_mem("pg-fresh", "first — #3718", &agent))
        .await
        .expect("#3718 (pg): a fresh agent's first seal mints normally");
    assert!(priv_path.is_file(), "the seal minted the live key");
    assert!(raw_row(&pg, &id).await.0.is_some(), "the row is sealed");
    assert_eq!(sealed_rows(&pg, &agent).await, 1);
}

/// #3718 (review, pg) — sealed rows + wiped key dir REFUSES, names the count,
/// mints nothing, writes nothing; a restored key makes the write succeed.
#[tokio::test(flavor = "multi_thread")]
async fn pg_sealed_rows_with_wiped_key_dir_refuse_to_mint_3718() {
    let Some(pg) = connect().await else { return };
    let key_dir = key_dir_sandbox::pin();
    gate_on();
    let agent = format!("agent-3718-pg-lost-{}", uuid::Uuid::new_v4().simple());
    let priv_path = key_dir.join(format!("{agent}{PRIV_SUFFIX}"));
    let ctx = CallerContext::for_admin("test-3718");

    let first = MemoryStore::store(&pg, &ctx, &make_mem("pg-lost-1", "one — #3718", &agent))
        .await
        .expect("first seal mints");
    let priv_bytes = std::fs::read(&priv_path).expect("snapshot .priv");
    let row_first = raw_row(&pg, &first).await;
    assert_eq!(sealed_rows(&pg, &agent).await, 1);

    wipe_key_material(key_dir, &agent);
    let before = listing(key_dir);

    let err = MemoryStore::store(&pg, &ctx, &make_mem("pg-lost-2", "two — #3718", &agent))
        .await
        .expect_err("#3718 (pg): a seal over sealed rows with no key must refuse");
    let msg = format!("{err}");
    assert!(
        msg.contains(SealRefusedSealedRowsExist::CLASS) && msg.contains("#3718"),
        "class named: {msg}"
    );
    assert!(msg.contains("1 sealed row"), "count named: {msg}");
    assert!(msg.contains(&agent), "agent named: {msg}");
    assert!(
        !msg.contains(&key_dir.display().to_string()) && !msg.contains(PRIV_SUFFIX),
        "the caller never sees the key path: {msg}"
    );
    assert_eq!(listing(key_dir), before, "#3718 (pg): nothing minted");
    assert_eq!(sealed_rows(&pg, &agent).await, 1, "nothing written");
    assert_eq!(raw_row(&pg, &first).await, row_first, "row one untouched");

    write_0600(&priv_path, &priv_bytes);
    evict_cached_keypair(&agent);
    MemoryStore::store(&pg, &ctx, &make_mem("pg-lost-2", "two — #3718", &agent))
        .await
        .expect("restored key seals");
    assert_eq!(sealed_rows(&pg, &agent).await, 2);
    let back = MemoryStore::get(&pg, &ctx, &first)
        .await
        .expect("row one opens");
    assert_eq!(back.content, "one — #3718");
}
