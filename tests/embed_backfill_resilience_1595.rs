// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1595 — integration coverage for the per-row-resilient embedding
//! backfill sweep (`run_embedding_backfill_with_batch_size`).
//!
//! The pre-#1595 loop stopped the whole sweep on the first failing
//! chunk: one over-context-length row meant ZERO rows ever backfilled.
//! The fix routes every chunk through `embed_rows_with_fallback`
//! (chunk-level `embed_batch` fault → per-row `embed` fallback → skip
//! the rows that still fail) and advances a keyset cursor past skipped
//! rows so the sweep always completes.
//!
//! The in-module unit tests pin `embed_rows_with_fallback` with mock
//! embedders. What they CANNOT reach is the full integration: a real
//! sqlite DB, the keyset drain loop, AND the real Ollama-native HTTP
//! wire — including the #1595 `"truncate": true` request field that
//! makes Ollama clip oversize inputs instead of 4xx-poisoning whole
//! chunks. This test stands up a wiremock `/api/embed` server whose
//! generic responder REQUIRES `"truncate": true` in the request body
//! (a request without it 404s, every row would be skipped, and the
//! accounting assertion below fails loudly) and 400-poisons exactly
//! one row's document text.

use std::sync::Arc;

use ai_memory::db;
use ai_memory::embeddings::{Embedder, embedding_document};
use ai_memory::llm::OllamaClient;
use ai_memory::mcp::run_embedding_backfill_with_batch_size;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Insert one un-embedded memory and return its row id.
fn seed(conn: &rusqlite::Connection, ns: &str, title: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
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
    };
    db::insert(conn, &mem).expect("seed insert must succeed")
}

fn unembedded_ids(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM memories WHERE embedding IS NULL ORDER BY id")
        .expect("prepare unembedded query");
    stmt.query_map([], |r| r.get::<_, String>(0))
        .expect("run unembedded query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect unembedded ids")
}

// ---------------------------------------------------------------------------
// One poison row 400s on the wire; every other row embeds; the sweep
// completes with truthful {backfilled, skipped} accounting; a re-run
// re-attempts ONLY the poison row (idempotence past the skip).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn backfill_skips_poison_row_and_completes_sweep_1595() {
    let server = MockServer::start().await;

    // The poison row's exact canonical document text — mounted FIRST so
    // it wins dispatch over the generic 200 responder.
    let poison_doc = embedding_document("poison title", "poison content");
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .and(body_partial_json(json!({ "input": poison_doc })))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": "the input length exceeds the context length" })),
        )
        .mount(&server)
        .await;
    // Generic Ollama-native responder. REQUIRES the #1595
    // `"truncate": true` field: if the client ever drops it, nothing
    // matches, every row is skipped, and the assertions below fail.
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .and(body_partial_json(
            json!({ "model": "fake-embed-model", "truncate": true }),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "embeddings": [[0.1, 0.2, 0.3]] })),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let mut conn =
            db::open(std::path::Path::new(":memory:")).expect("in-memory DB open must succeed");
        let ns = "backfill-1595";
        let _a = seed(&conn, ns, "alpha title", "alpha content");
        let poison_id = seed(&conn, ns, "poison title", "poison content");
        let _z = seed(&conn, ns, "zulu title", "zulu content");
        assert_eq!(unembedded_ids(&conn).len(), 3, "all rows start unembedded");

        // Ollama-native wire shape; probe-free constructor (the mock has
        // no /api/tags route mounted).
        let client = OllamaClient::new_with_url_no_health_check(&uri, "fake-embed-model")
            .expect("probe-free Ollama client construction must succeed");
        let embedder = Embedder::new_remote(Arc::new(client), "fake-embed-model".to_string(), 3);

        // batch_size = 2 forces the keyset drain loop through multiple
        // bounded fetches AND puts the poison row inside a chunk with a
        // healthy sibling, exercising the chunk-fault → per-row fallback.
        let backfilled = run_embedding_backfill_with_batch_size(&mut conn, &embedder, 2)
            .expect("the sweep must complete despite the poison row (#1595)");
        assert_eq!(
            backfilled, 2,
            "exactly the 2 healthy rows must be backfilled; the poison row is skipped",
        );
        assert_eq!(
            unembedded_ids(&conn),
            vec![poison_id.clone()],
            "ONLY the poison row may remain unembedded after the sweep",
        );

        // Re-run: the skipped row is re-attempted (and fails again) —
        // the sweep still completes and reports 0 newly-backfilled rows.
        let rerun = run_embedding_backfill_with_batch_size(&mut conn, &embedder, 2)
            .expect("the re-run sweep must also complete");
        assert_eq!(
            rerun, 0,
            "a re-run backfills nothing new: healthy rows are done, poison still fails",
        );
        assert_eq!(
            unembedded_ids(&conn),
            vec![poison_id],
            "the poison row stays unembedded (re-attempted on every sweep, never wedging it)",
        );
    })
    .await
    .expect("blocking backfill task must not panic");
}

// ---------------------------------------------------------------------------
// Steady-state idempotence: a fully-embedded DB is a true no-op Ok(0).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn backfill_fully_embedded_db_is_noop_1595() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .and(body_partial_json(json!({ "truncate": true })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "embeddings": [[0.4, 0.5]] })),
        )
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        let mut conn =
            db::open(std::path::Path::new(":memory:")).expect("in-memory DB open must succeed");
        let ns = "backfill-steady-1595";
        seed(&conn, ns, "one", "content one");
        seed(&conn, ns, "two", "content two");

        let client = OllamaClient::new_with_url_no_health_check(&uri, "fake-embed-model")
            .expect("probe-free Ollama client construction must succeed");
        let embedder = Embedder::new_remote(Arc::new(client), "fake-embed-model".to_string(), 2);

        let first = run_embedding_backfill_with_batch_size(&mut conn, &embedder, 100)
            .expect("first sweep must succeed");
        assert_eq!(first, 2, "both rows embed on the first sweep");
        assert!(
            unembedded_ids(&conn).is_empty(),
            "no unembedded rows remain"
        );

        let second = run_embedding_backfill_with_batch_size(&mut conn, &embedder, 100)
            .expect("steady-state sweep must succeed");
        assert_eq!(second, 0, "a fully-embedded DB re-run is a true no-op");
    })
    .await
    .expect("blocking backfill task must not panic");
}
