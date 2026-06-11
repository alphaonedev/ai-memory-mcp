// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1598 — end-to-end coverage for the `ai-memory reembed` CLI
//! subcommand (the vector-space migration tool of the API-embeddings
//! train), driven through the real binary (`CARGO_BIN_EXE_ai-memory`,
//! the `tests/mcp_integration.rs` spawn convention).
//!
//! Each test seeds a scratch sqlite DB (under the cargo target dir —
//! never `/tmp`, per the project hard rule) with memories embedded at
//! one dim, then spawns the binary with the `AI_MEMORY_EMBED_*` env
//! vars pointed at a wiremock OpenAI-compatible `/embeddings` server
//! resolving to a DIFFERENT dim:
//!
//! - `--dry-run --json` → the plan JSON is sane (counts, target model
//!   / dim / backend) and NOTHING is written.
//! - live `--json` → every stored vector is REPLACED at the new dim
//!   (verified via the raw sqlite blob length + the
//!   `distinct_embedding_dims` read-back) and the summary JSON carries
//!   truthful `{total, reembedded, skipped}` accounting.
//! - an unknown model id with no dim override → exit code 3
//!   (`EXIT_EMBEDDER_INIT_FAILED`) with stderr naming the
//!   `[embeddings].dim` escape hatch (fail-closed boot ladder, #1598).
//!
//! Env hygiene: the spawned child gets every `AI_MEMORY_EMBED_*` var
//! set EXPLICITLY (overriding anything inherited), so the test is
//! immune to operator-shell contamination without mutating the test
//! process's own environment (no lock needed).

use std::path::{Path, PathBuf};
use std::process::Output;

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Seeded vector dim (the "old" vector space).
const SEED_DIM: usize = 4;
/// Target dim — `bge-small-en` in `KNOWN_EMBEDDING_DIMS` resolves to
/// 384, so the migration changes the corpus's vector space.
const TARGET_DIM: usize = 384;
const TARGET_MODEL: &str = "bge-small-en";
const NAMESPACE: &str = "reembed-e2e-1598";

/// Project-local scratch dir (never `/tmp`): a fresh subdir under the
/// cargo target dir, which always exists at test runtime.
fn scratch_db(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let target_root = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dir = tempfile::Builder::new()
        .prefix(&format!("reembed-1598-{tag}-"))
        .tempdir_in(target_root)
        .expect("scratch dir under the cargo target dir must be creatable");
    let db_path = dir.path().join("reembed-e2e.db");
    (dir, db_path)
}

/// Insert one memory and stamp a `SEED_DIM` embedding onto it.
fn seed_embedded(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NAMESPACE.to_string(),
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
    let id = db::insert(conn, &mem).expect("seed insert must succeed");
    db::set_embedding(conn, &id, &[0.5_f32; SEED_DIM]).expect("seed embedding must land");
    id
}

/// Seed a 3-row corpus, all embedded at `SEED_DIM`. Returns the ids.
fn seed_corpus(db_path: &Path) -> Vec<String> {
    let conn = db::open(db_path).expect("scratch DB open must succeed");
    let ids = vec![
        seed_embedded(&conn, "alpha", "alpha content"),
        seed_embedded(&conn, "beta", "beta content"),
        seed_embedded(&conn, "gamma", "gamma content"),
    ];
    let dims = db::distinct_embedding_dims(&conn, None).expect("dims read-back");
    assert_eq!(dims, vec![SEED_DIM], "corpus starts uniformly at SEED_DIM");
    ids
}

/// Run the real binary's `reembed` subcommand against the scratch DB
/// with the embed env vars pointed at `base_url` / `model`.
fn run_reembed(db_path: &Path, base_url: &str, model: &str, extra_args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("--db")
        .arg(db_path)
        .arg("reembed")
        .arg("--json")
        .args(extra_args)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_BACKEND", "openai-compatible")
        .env("AI_MEMORY_EMBED_BASE_URL", base_url)
        .env("AI_MEMORY_EMBED_MODEL", model)
        .env("AI_MEMORY_EMBED_API_KEY", "reembed-key-1598")
        .env_remove("AI_MEMORY_EMBED_BACKFILL_BATCH")
        .env_remove("AI_MEMORY_DB");
    cmd.output()
        .expect("spawning the ai-memory binary must succeed")
}

/// Parse the last non-empty stdout line as JSON (the `--json` contract:
/// one machine-readable line on stdout; human noise goes to stderr).
fn last_stdout_json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("expected JSON on stdout, got: {stdout:?}"));
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout line must be valid JSON ({e}): {line:?}"))
}

/// Mount the OpenAI-compatible `/embeddings` responder: requires the
/// resolved Bearer key + model id, answers with a `TARGET_DIM` vector.
async fn mount_embeddings_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .and(header("authorization", "Bearer reembed-key-1598"))
        .and(body_partial_json(json!({ "model": TARGET_MODEL })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [ { "embedding": vec![0.125_f32; TARGET_DIM] } ]
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// 3a. --dry-run --json: the plan is sane and nothing is written.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn reembed_dry_run_json_plan_is_sane_and_writes_nothing_1598() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();

    let (_dir, db_path) = scratch_db("dry");
    seed_corpus(&db_path);

    let output = tokio::task::spawn_blocking(move || {
        run_reembed(&db_path, &uri, TARGET_MODEL, &["--dry-run"])
    })
    .await
    .expect("blocking spawn task must not panic");

    assert!(
        output.status.success(),
        "--dry-run must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let plan = last_stdout_json(&output);
    assert_eq!(
        plan["total_rows"], 3,
        "plan counts the whole corpus: {plan}"
    );
    assert_eq!(
        plan["rows_with_embeddings"], 3,
        "all rows carry vectors: {plan}"
    );
    assert_eq!(
        plan["rows_missing_embeddings"], 0,
        "no unembedded rows: {plan}"
    );
    assert_eq!(
        plan["target_dim"], TARGET_DIM,
        "target dim is the resolved model's: {plan}"
    );
    assert_eq!(
        plan["backend"], "openai-compatible",
        "backend provenance: {plan}"
    );
    assert!(
        plan["target_model"]
            .as_str()
            .is_some_and(|m| m.contains(TARGET_MODEL)),
        "target_model must name the resolved model id: {plan}",
    );

    // Loud pre-flight dim disclosure goes to stderr even on dry-run.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PRE-FLIGHT"),
        "dry-run must still print the PRE-FLIGHT dim disclosure: {stderr}",
    );
    // The no-write proof lives in
    // `reembed_dry_run_leaves_vectors_untouched_1598` below.
}

// ---------------------------------------------------------------------------
// 3b. Live run: vectors replaced at the new dim; summary JSON truthful.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn reembed_live_run_replaces_vectors_at_new_dim_1598() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();

    let (_dir, db_path) = scratch_db("live");
    let ids = seed_corpus(&db_path);

    // Raw blob length before: 1-byte header + SEED_DIM LE f32s.
    let blob_len_before = embedding_blob_len(&db_path, &ids[0]);
    assert_eq!(blob_len_before, 1 + SEED_DIM * 4);

    let db_path_for_run = db_path.clone();
    let output =
        tokio::task::spawn_blocking(move || run_reembed(&db_path_for_run, &uri, TARGET_MODEL, &[]))
            .await
            .expect("blocking spawn task must not panic");

    assert!(
        output.status.success(),
        "live reembed must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let summary = last_stdout_json(&output);
    assert_eq!(
        summary["total"], 3,
        "summary scans the whole corpus: {summary}"
    );
    assert_eq!(
        summary["reembedded"], 3,
        "every row is re-embedded: {summary}"
    );
    assert_eq!(
        summary["skipped"], 0,
        "no skips on the happy path: {summary}"
    );
    assert_eq!(
        summary["dim"], TARGET_DIM,
        "summary reports the new dim: {summary}"
    );

    // Vector-space migration landed: every blob is now TARGET_DIM.
    let conn = db::open(&db_path).expect("post-run DB open");
    let dims = db::distinct_embedding_dims(&conn, None).expect("post-run dims read-back");
    assert_eq!(
        dims,
        vec![TARGET_DIM],
        "every stored vector must be REPLACED at the target dim",
    );
    drop(conn);
    for id in &ids {
        assert_eq!(
            embedding_blob_len(&db_path, id),
            1 + TARGET_DIM * 4,
            "raw sqlite blob length must reflect the new dim for row {id}",
        );
    }
}

// ---------------------------------------------------------------------------
// 3c. Dry-run writes nothing (vector read-back after a --dry-run).
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn reembed_dry_run_leaves_vectors_untouched_1598() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();

    let (_dir, db_path) = scratch_db("nowrite");
    let ids = seed_corpus(&db_path);

    let db_path_for_run = db_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        run_reembed(&db_path_for_run, &uri, TARGET_MODEL, &["--dry-run"])
    })
    .await
    .expect("blocking spawn task must not panic");
    assert!(output.status.success());

    let conn = db::open(&db_path).expect("post-dry-run DB open");
    let dims = db::distinct_embedding_dims(&conn, None).expect("dims read-back");
    assert_eq!(dims, vec![SEED_DIM], "--dry-run must not touch any vector");
    drop(conn);
    assert_eq!(embedding_blob_len(&db_path, &ids[0]), 1 + SEED_DIM * 4);
}

// ---------------------------------------------------------------------------
// 3d. Fail-closed boot ladder through the CLI: unknown model + no dim
//     override → exit 3 (EXIT_EMBEDDER_INIT_FAILED), stderr names the
//     [embeddings].dim escape hatch, vectors untouched.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn reembed_unknown_model_without_dim_exits_3_1598() {
    let server = MockServer::start().await;
    let uri = server.uri();

    let (_dir, db_path) = scratch_db("exit3");
    seed_corpus(&db_path);

    let db_path_for_run = db_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        run_reembed(
            &db_path_for_run,
            &uri,
            "model-not-in-known-dims-table-1598",
            &[],
        )
    })
    .await
    .expect("blocking spawn task must not panic");

    assert_eq!(
        output.status.code(),
        Some(3),
        "embedder init failure must exit EXIT_EMBEDDER_INIT_FAILED (3); stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("embedder init failed"),
        "stderr must name the init failure: {stderr}",
    );
    assert!(
        stderr.contains("[embeddings].dim"),
        "stderr must surface the [embeddings].dim escape hatch: {stderr}",
    );

    // Fail-closed: the corpus is untouched.
    let conn = db::open(&db_path).expect("post-failure DB open");
    let dims = db::distinct_embedding_dims(&conn, None).expect("dims read-back");
    assert_eq!(
        dims,
        vec![SEED_DIM],
        "a failed init must not touch any vector"
    );
}

/// Raw sqlite blob length of one row's `embedding` column.
fn embedding_blob_len(db_path: &Path, id: &str) -> usize {
    let conn = rusqlite::Connection::open(db_path).expect("raw sqlite open");
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT embedding FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .expect("embedding blob read-back");
    blob.len()
}
