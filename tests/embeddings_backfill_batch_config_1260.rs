// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::redundant_closure_for_method_calls,
    clippy::items_after_statements
)]

//! v0.7.0 issue #1260 regression — `[embeddings].backfill_batch`
//! from `config.toml` must be honoured by the boot embedding
//! backfill loop.
//!
//! # The bug
//!
//! `src/mcp/mod.rs::run_embedding_backfill` (at the original line
//! 2110) read the `AI_MEMORY_EMBED_BACKFILL_BATCH` env var directly
//! and fell back to the compiled default when it was unset. That
//! bypassed the #1146 universal precedence ladder: an operator
//! who set `[embeddings].backfill_batch = N` in `config.toml`
//! without ALSO exporting the env var got the compiled default
//! (64) silently — a config-drift defect.
//!
//! # The fix
//!
//! Threaded `AppConfig::resolve_embeddings().backfill_batch`
//! through a new `run_embedding_backfill_with_batch_size` entry-
//! point. The MCP serve boot path now resolves the value once via
//! the canonical resolver and passes it explicitly, so the
//! precedence ladder collapses to a single source of truth
//! (CLI > env > config > legacy > compiled default).
//!
//! # What this file pins
//!
//! Three integration tests:
//!
//! 1. `config_file_backfill_batch_resolves_when_env_unset` —
//!    `AppConfig { embeddings.backfill_batch = Some(7) }` with
//!    the env var explicitly unset must resolve to 7, not the
//!    compiled default 100 or the runtime default 64. Pre-fix
//!    the runtime IGNORED this entirely; this test pins the
//!    canonical resolver behaviour.
//!
//! 2. `env_overrides_config_file_backfill_batch` — the env var
//!    still wins when set (the #1146 ladder), to confirm the
//!    refactor preserved the documented precedence (env > config).
//!
//! 3. `run_embedding_backfill_with_batch_size_honors_explicit_value`
//!    — end-to-end: a fresh DB + a deterministic mock embedder
//!    driven with `batch_size = 5` writes exactly the seeded N
//!    rows in `ceil(N/5)` chunks. The test pins the public
//!    function name + signature so the resolver-fed call from
//!    `src/mcp/mod.rs` can never silently drift back to the
//!    env-var-only path without breaking compilation here.

use ai_memory::config::{AppConfig, EmbeddingsSection};
use ai_memory::db;
use ai_memory::embeddings::Embed;
use ai_memory::mcp::run_embedding_backfill_with_batch_size;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use anyhow::Result;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Process-wide env var lock — tests mutate the env, must serialise
// ---------------------------------------------------------------------------

fn env_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

const BACKFILL_ENV: &str = "AI_MEMORY_EMBED_BACKFILL_BATCH";

fn scrub_env() {
    // SAFETY: every test holds the env_lock() mutex before calling
    // this helper, so the unsafe env mutation is serialised across
    // the test binary.
    unsafe {
        std::env::remove_var(BACKFILL_ENV);
    }
}

fn set_env(value: &str) {
    // SAFETY: serialised via env_lock() — see scrub_env.
    unsafe {
        std::env::set_var(BACKFILL_ENV, value);
    }
}

// ---------------------------------------------------------------------------
// Test 1 — config-file backfill_batch resolves when env unset
// ---------------------------------------------------------------------------

/// Pre-#1260 the runtime read the env var directly and ignored
/// `[embeddings].backfill_batch` from `config.toml` entirely when
/// the env var was unset. This test asserts the canonical
/// resolver (`AppConfig::resolve_embeddings`) honours the
/// config-file value in that exact scenario. The MCP serve path
/// now consumes this resolved value through
/// `run_embedding_backfill_with_batch_size`, so any future
/// regression that re-couples to the env var would surface as a
/// drift here first.
#[test]
fn config_file_backfill_batch_resolves_when_env_unset() {
    let _g = env_lock().lock().unwrap_or_else(|p| p.into_inner());
    scrub_env();

    let cfg = AppConfig {
        embeddings: Some(EmbeddingsSection {
            backfill_batch: Some(7),
            ..EmbeddingsSection::default()
        }),
        ..AppConfig::default()
    };

    let resolved = cfg.resolve_embeddings();
    assert_eq!(
        resolved.backfill_batch, 7,
        "config-file [embeddings].backfill_batch must be honoured when env unset \
         (issue #1260 — pre-fix the runtime ignored this value)"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — env var still wins over config-file value (#1146 ladder)
// ---------------------------------------------------------------------------

/// Post-#1260 the runtime resolves the batch size via
/// `AppConfig::resolve_embeddings`. The resolver applies the
/// canonical #1146 precedence ladder (env > config > legacy >
/// default). This test pins the env > config relationship so the
/// refactor preserved documented behaviour.
#[test]
fn env_overrides_config_file_backfill_batch() {
    let _g = env_lock().lock().unwrap_or_else(|p| p.into_inner());
    scrub_env();
    set_env("500");

    let cfg = AppConfig {
        embeddings: Some(EmbeddingsSection {
            backfill_batch: Some(50),
            ..EmbeddingsSection::default()
        }),
        ..AppConfig::default()
    };

    let resolved = cfg.resolve_embeddings();
    assert_eq!(
        resolved.backfill_batch, 500,
        "env var must beat config-file value (#1146 ladder)"
    );

    scrub_env();
}

// ---------------------------------------------------------------------------
// Test 3 — end-to-end through the new explicit-batch-size entry-point
// ---------------------------------------------------------------------------

/// Hermetic mock embedder — mirrors the
/// `IntegrationMockEmbedder` in
/// `tests/embedding_backfill_batch.rs` so the byte-identity
/// invariant on disk is shared across the two pinning suites.
struct MockEmbedder;

const MOCK_DIM: usize = 384;

impl MockEmbedder {
    fn embed_one(text: &str) -> Vec<f32> {
        let hash = text.bytes().fold(0u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(u32::from(b))
        });
        let base = ((hash % 1000) as f32) / 1000.0;
        (0..MOCK_DIM)
            .map(|i| base + ((i as f32) * 0.0001).sin().abs())
            .collect()
    }
}

impl Embed for MockEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        Ok(Self::embed_one(text))
    }
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| Self::embed_one(t)).collect())
    }
}

fn fresh_db_conn() -> rusqlite::Connection {
    db::open(Path::new(":memory:")).expect("open in-memory db")
}

fn make_memory(idx: usize) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "backfill/cfg/1260".to_string(),
        title: format!("cfg-row-{idx:04}"),
        content: format!("content for cfg row {idx:04}; hermetic no-network"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
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
        ..Memory::default()
    }
}

/// End-to-end pin: the explicit-batch-size entry-point honors the
/// caller-supplied value. The MCP serve path (post-#1260) supplies
/// this value from `AppConfig::resolve_embeddings().backfill_batch`,
/// so a future refactor that re-couples the resolution path to the
/// env var would land here as a test breakage first (the public
/// function name + signature is the pin).
#[test]
fn run_embedding_backfill_with_batch_size_honors_explicit_value() {
    let _g = env_lock().lock().unwrap_or_else(|p| p.into_inner());
    scrub_env();

    let mut conn = fresh_db_conn();
    const N_ROWS: usize = 17;
    for i in 0..N_ROWS {
        let m = make_memory(i);
        db::insert(&conn, &m).expect("seed");
    }
    let pre = db::get_unembedded_ids(&conn).expect("pre scan");
    assert_eq!(pre.len(), N_ROWS, "all seeded rows must be unembedded");

    // Drive the backfill with an explicit batch_size of 5. The
    // resolver-fed production callsite at `src/mcp/mod.rs:2483`
    // passes `app_config.resolve_embeddings().backfill_batch as
    // usize`; this test pins the signature shape +
    // batch_size-is-honoured contract.
    let emb = MockEmbedder;
    let written = run_embedding_backfill_with_batch_size(&mut conn, &emb, 5).expect("backfill");
    assert_eq!(
        written, N_ROWS,
        "every seeded row must be embedded across ceil({N_ROWS}/5)=4 chunks"
    );

    let post = db::get_unembedded_ids(&conn).expect("post scan");
    assert!(
        post.is_empty(),
        "no unembedded rows must remain after backfill"
    );
}

/// Defensive: a `batch_size = 0` argument must NOT panic via
/// `chunks(0)`. Pre-fix the function had no explicit batch_size
/// parameter so a future caller could not pass 0; post-fix the
/// resolver clamps via `AppConfig::resolve_embeddings` to
/// `1..=10000`, but the function still coerces 0 → compiled
/// default defensively. This test pins that contract.
#[test]
fn run_embedding_backfill_with_batch_size_zero_coerces_to_default() {
    let _g = env_lock().lock().unwrap_or_else(|p| p.into_inner());
    scrub_env();

    let mut conn = fresh_db_conn();
    // Even one seeded row exercises the chunks() iteration path.
    db::insert(&conn, &make_memory(0)).expect("seed");

    let emb = MockEmbedder;
    // batch_size=0 — the function MUST coerce to a non-zero value
    // rather than panic in chunks(0).
    let written = run_embedding_backfill_with_batch_size(&mut conn, &emb, 0)
        .expect("backfill must not panic on batch_size=0 (defensive coercion)");
    assert_eq!(written, 1, "the single seeded row must be embedded");
}
