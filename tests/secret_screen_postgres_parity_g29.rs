// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.1 W1 / gap G29 — SAL parity: the credential REDACT backstop masks a
//! secret IDENTICALLY on the sqlite (`db::insert`) and postgres
//! (`PostgresStore::store`) storage funnels.
//!
//! `#[ignore]` + `sal-postgres`; run with a live instance:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://aimem:aimem@127.0.0.1:5432/aimem_test \
//!   cargo test --features sal-postgres --test secret_screen_postgres_parity_g29 \
//!   -- --include-ignored --nocapture
//! ```

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};

const FAKE_KEY: &str = "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56";
const REDACTION_MARKER: &str = "[REDACTED:secret]";

fn mem(namespace: &str, title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["g29-parity".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-g29".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:test:g29" }),
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

async fn maybe_open_pg() -> Option<PostgresStore> {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("test skipped: AI_MEMORY_TEST_POSTGRES_URL not set");
        return None;
    };
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("test skipped: PostgresStore::connect failed: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn secret_redacted_identically_on_sqlite_and_postgres_g29() {
    // The funnel reads the process-wide mode; this binary's single test seeds
    // `redact` so the storage funnel masks (rather than the caller-refuse,
    // which is the validate_content layer not exercised here).
    set_screen_mode(SecretScreenMode::Redact);

    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-g29");
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("g29-parity-{tag}");
    let content = format!("the key is {FAKE_KEY} thanks");

    // postgres funnel (PostgresStore::store → screen_storage_memory).
    let pg_id = pg
        .store(&admin, &mem(&ns, "g29-pg", &content))
        .await
        .expect("pg store");
    let pg_back = pg.get(&admin, &pg_id).await.expect("pg get");

    // sqlite funnel (SqliteStore::store → db::insert redact backstop).
    let dir = tempfile::tempdir().expect("tempdir");
    let sqlite = SqliteStore::open(dir.path().join("mem.db")).expect("open sqlite");
    let sq_id = sqlite
        .store(&admin, &mem(&ns, "g29-sq", &content))
        .await
        .expect("sqlite store");
    let sq_back = sqlite.get(&admin, &sq_id).await.expect("sqlite get");

    // Both backends masked the credential.
    assert!(
        pg_back.content.contains(REDACTION_MARKER) && !pg_back.content.contains(FAKE_KEY),
        "postgres funnel must redact the credential; got: {:?}",
        pg_back.content
    );
    assert!(
        sq_back.content.contains(REDACTION_MARKER) && !sq_back.content.contains(FAKE_KEY),
        "sqlite funnel must redact the credential; got: {:?}",
        sq_back.content
    );
    // …and IDENTICALLY (same redaction shape on both backends).
    assert_eq!(
        pg_back.content, sq_back.content,
        "the redacted content must be byte-identical across backends (SAL parity)"
    );
}
