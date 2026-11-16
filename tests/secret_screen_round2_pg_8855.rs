// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 round 2, ruling (e) on Postgres: the store funnel and the
//! federation receive funnel (`apply_remote_memory`) refuse a write whose
//! redacted copy still screens as a hit, with the exact reason, and store no
//! row. The SQLite cells live in `tests/secret_screen_round2_8855.rs`.
//!
//! Failure messages carry a cell id and a SHA-256 prefix, never an input.
#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use sha2::{Digest, Sha256};

const PW: &str = concat!("Xk9m", "Q2vLp7Rw");
const KIND_RESIDUAL: &str = "redaction_residual";
const KIND_PASSWORD: &str = "password_assignment";

fn residual_reason(kinds: &[&str]) -> String {
    format!(
        "invalid input: content rejected: credential material remains after redaction ({}); \
         the write is refused and no row is stored",
        kinds.join(", ")
    )
}

fn tag(cell: &str, input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("cell={cell} sha256={hex}")
}

fn mem(namespace: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: "round2 pg funnel cell".to_string(),
        content: content.to_string(),
        tags: vec!["round2-8855".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "system".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": "ai:test:round2-8855" }),
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

fn residual_cells() -> Vec<(&'static str, String, Vec<&'static str>)> {
    vec![
        (
            "e.pg.zw.in.key",
            format!("pass\u{200b}word={PW}"),
            vec![KIND_PASSWORD, KIND_RESIDUAL],
        ),
        (
            "e.pg.fullwidth.key",
            format!("\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}={PW}"),
            vec![KIND_PASSWORD, KIND_RESIDUAL],
        ),
        (
            "e.pg.percent.url",
            format!("postgres%3A%2F%2Fsvc%3A{PW}%40db.internal%2Fx"),
            vec![KIND_RESIDUAL, "url_userinfo_password"],
        ),
    ]
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
async fn pg_store_and_receive_funnels_refuse_residual_round2_8855() {
    set_screen_mode(SecretScreenMode::Redact);
    let Some(pg) = maybe_open_pg().await else {
        return;
    };
    let admin = CallerContext::for_admin("operator:test-round2-8855");
    let ns = format!("round2-8855-{}", uuid::Uuid::new_v4().simple());
    let mut failures = Vec::new();
    for (id, input, kinds) in residual_cells() {
        let want = residual_reason(&kinds);
        let stored = mem(&ns, &input);
        let received = mem(&ns, &input);
        for (funnel, m, result) in [
            ("store", &stored, pg.store(&admin, &stored).await),
            (
                "apply_remote_memory",
                &received,
                MemoryStore::apply_remote_memory(&pg, &admin, &received).await,
            ),
        ] {
            match result {
                Ok(_) => failures.push(format!("{} via {funnel}: stored", tag(id, &input))),
                Err(e) if e.to_string() == want => {}
                Err(e) => failures.push(format!(
                    "{} via {funnel}: different reason (len {})",
                    tag(id, &input),
                    e.to_string().len()
                )),
            }
            match pg.get(&admin, &m.id).await {
                Err(StoreError::NotFound { .. }) => {}
                Ok(_) => failures.push(format!("{} via {funnel}: a row exists", tag(id, &input))),
                Err(e) => failures.push(format!(
                    "{} via {funnel}: get failed (len {})",
                    tag(id, &input),
                    e.to_string().len()
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
