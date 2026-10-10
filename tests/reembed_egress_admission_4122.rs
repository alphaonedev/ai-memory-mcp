// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4122 (WP-EGRESS #6053) — `ai-memory reembed` goes through the SAME
//! inference-egress admission funnel as the MCP boot / `build_embedder`
//! chokepoints (#1963 / #3822 / #3933): admit the resolved embed endpoint
//! under `AI_MEMORY_INFERENCE_EGRESS`, refuse with an audited, posture-naming
//! error and NOTHING sent, or build the embedder PINNED.
//!
//! Before this fix the verb built the embedder with the unpinned
//! `Embedder::from_resolved`, never consulting the posture: under `deny` it
//! sent the content of EVERY memory in scope to the configured embedding
//! endpoint — the most content-heavy egress the product performs, on the one
//! verb the posture most needs to govern.
//!
//! Driven through the real binary (`CARGO_BIN_EXE_ai-memory`, the
//! `tests/reembed_cli_1598.rs` harness) against a scratch sqlite DB seeded
//! with three embedded memories:
//!
//! - `deny` + a recording loopback endpoint → non-zero exit, ZERO requests
//!   (no content seen), stderr names the posture and never the API key, every
//!   stored vector untouched, one signed `egress.inference_refused` row.
//! - `loopback-only` + an off-host RFC 5737 TEST-NET literal → the same
//!   refusal, by name, before any connect (a run that CONNECTED would sit on
//!   the connect timeout per row).
//! - `allow` control → all three rows re-embedded through the endpoint.
//! - `internal-only` + the loopback endpoint → admitted AND pinned: all three
//!   rows re-embedded (the pinned build path works end to end).
//!
//! A structural leg pins the shape: the verb calls the admission funnel and
//! the pinned builder, and no production call site outside
//! `src/embeddings.rs` builds through the unpinned `Embedder::from_resolved`.
//!
//! Env hygiene: the spawned child gets every relevant var set EXPLICITLY, so
//! the test is immune to operator-shell contamination without mutating its
//! own process environment.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Seeded vector dim (the "old" vector space).
const SEED_DIM: usize = 4;
/// `bge-small-en` resolves to 384 in `KNOWN_EMBEDDING_DIMS`.
const TARGET_DIM: usize = 384;
const TARGET_MODEL: &str = "bge-small-en";
const NAMESPACE: &str = "reembed-egress-4122";
/// The bearer secret the child resolves; it must never reach stderr.
const API_KEY: &str = "reembed-secret-4122";
/// The posture knob and the audit event type.
const POSTURE_VAR: &str = "AI_MEMORY_INFERENCE_EGRESS";

/// Project-local scratch dir (never `/tmp`): a fresh subdir under the
/// cargo target dir, which always exists at test runtime.
fn scratch_db(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let target_root = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dir = tempfile::Builder::new()
        .prefix(&format!("reembed-4122-{tag}-"))
        .tempdir_in(target_root)
        .expect("scratch dir under the cargo target dir must be creatable");
    let db_path = dir.path().join("reembed-egress.db");
    (dir, db_path)
}

/// Insert one memory and stamp a `SEED_DIM` embedding onto it.
fn seed_embedded(conn: &rusqlite::Connection, title: &str, content: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    let id = db::insert(conn, &mem).expect("seed insert must succeed");
    db::set_embedding(
        conn,
        &id,
        &[0.5_f32; SEED_DIM],
        &ai_memory::embeddings::embedding_space_fingerprint("test-space"),
    )
    .expect("seed embedding must land");
    id
}

/// Seed a 3-row corpus, all embedded at `SEED_DIM`.
fn seed_corpus(db_path: &Path) {
    let conn = db::open(db_path).expect("scratch DB open must succeed");
    seed_embedded(&conn, "alpha", "alpha content 4122");
    seed_embedded(&conn, "beta", "beta content 4122");
    seed_embedded(&conn, "gamma", "gamma content 4122");
    let dims = db::distinct_embedding_dims(&conn, None).expect("dims read-back");
    assert_eq!(dims, vec![SEED_DIM], "corpus starts uniformly at SEED_DIM");
}

/// Run the real binary's `reembed` against the scratch DB under `posture`
/// (`None` = unset = `allow`) with the API embed lane pointed at `base_url`.
fn run_reembed(db_path: &Path, base_url: &str, posture: Option<&str>) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("--db")
        .arg(db_path)
        .arg("reembed")
        .arg("--json")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_BACKEND", "openai-compatible")
        .env("AI_MEMORY_EMBED_BASE_URL", base_url)
        .env("AI_MEMORY_EMBED_MODEL", TARGET_MODEL)
        .env("AI_MEMORY_EMBED_API_KEY", API_KEY)
        .env_remove("AI_MEMORY_EMBED_BACKFILL_BATCH")
        .env_remove("AI_MEMORY_DB");
    // No environment proxy may stand in for the endpoint (#4193 class).
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(var);
    }
    match posture {
        Some(p) => cmd.env(POSTURE_VAR, p),
        None => cmd.env_remove(POSTURE_VAR),
    };
    output_within(cmd, db_path)
}

/// Wall-clock ceiling for one `reembed` child (the #3140 discipline: a wedged
/// child is KILLED rather than holding the job cap or the scratch DB lock).
const REEMBED_CHILD_BUDGET: Duration = Duration::from_mins(2);
const REEMBED_CHILD_POLL: Duration = Duration::from_millis(25);

/// `Command::output()` under [`REEMBED_CHILD_BUDGET`], capturing to files
/// beside the scratch DB (never `/tmp`) so the reap cannot deadlock on a full
/// pipe.
fn output_within(mut cmd: std::process::Command, db_path: &Path) -> Output {
    let stem = db_path.with_extension(format!("{}", std::process::id()));
    let out_path = PathBuf::from(format!("{}.stdout", stem.display()));
    let err_path = PathBuf::from(format!("{}.stderr", stem.display()));
    let out_file = std::fs::File::create(&out_path).expect("create stdout capture");
    let err_file = std::fs::File::create(&err_path).expect("create stderr capture");
    let mut child = cmd
        .stdout(out_file)
        .stderr(err_file)
        .spawn()
        .expect("spawning the ai-memory binary must succeed");

    let deadline = std::time::Instant::now() + REEMBED_CHILD_BUDGET;
    let status = loop {
        match child.try_wait().expect("try_wait on the reembed child") {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("`ai-memory reembed` still running after {REEMBED_CHILD_BUDGET:?} (#3140)");
            }
            None => std::thread::sleep(REEMBED_CHILD_POLL),
        }
    };

    let stdout = std::fs::read(&out_path).unwrap_or_default();
    let stderr = std::fs::read(&err_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Parse the last non-empty stdout line as JSON (the `--json` contract).
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

/// Mount the OpenAI-compatible `/embeddings` responder (a `TARGET_DIM` vector).
async fn mount_embeddings_ok(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [ { "embedding": vec![0.125_f32; TARGET_DIM] } ]
        })))
        .mount(server)
        .await;
}

/// Signed `egress.inference_refused` rows in the scratch DB (the
/// `tests/embed_lane_egress_gap_3933.rs` counter).
fn count_egress_refusals(db_path: &Path) -> i64 {
    let conn = db::open(db_path).expect("open db for post-hoc assertion");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [ai_memory::signed_events::event_types::EGRESS_INFERENCE_REFUSED],
        |r| r.get(0),
    )
    .expect("count signed_events rows")
}

fn stored_dims(db_path: &Path) -> Vec<usize> {
    let conn = db::open(db_path).expect("post-run DB open");
    db::distinct_embedding_dims(&conn, None).expect("post-run dims read-back")
}

/// The refusal contract shared by every refusing cell.
fn assert_refused(output: &Output, db_path: &Path, posture: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "#4122 ({posture}): a refused egress must exit non-zero; stderr: {stderr}"
    );
    assert!(
        stderr.contains("refused") && stderr.contains(&format!("{POSTURE_VAR}={posture}")),
        "#4122 ({posture}): stderr must name the refusal and the posture knob; got: {stderr}"
    );
    assert!(
        !stderr.contains(API_KEY),
        "#4122 ({posture}): the endpoint secret must never reach stderr: {stderr}"
    );
    assert_eq!(
        stored_dims(db_path),
        vec![SEED_DIM],
        "#4122 ({posture}): no vector may be written on a refusal"
    );
    assert_eq!(
        count_egress_refusals(db_path),
        1,
        "#4122 ({posture}): exactly one signed egress.inference_refused row is appended"
    );
}

// ─── deny: zero requests, no content seen ────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn deny_posture_sends_nothing_and_refuses_naming_the_posture_4122() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();
    let (_dir, db_path) = scratch_db("deny");
    seed_corpus(&db_path);

    let db_for_run = db_path.clone();
    let output = tokio::task::spawn_blocking(move || run_reembed(&db_for_run, &uri, Some("deny")))
        .await
        .expect("blocking spawn task must not panic");

    assert_refused(&output, &db_path, "deny");
    let seen = server.received_requests().await.unwrap_or_default().len();
    assert_eq!(
        seen, 0,
        "#4122 (deny): the embed endpoint must receive ZERO requests — no memory content leaves"
    );
}

// ─── loopback-only: refused by name before any connect ───────────────────

#[tokio::test(flavor = "multi_thread")]
async fn loopback_only_refuses_an_offhost_endpoint_before_any_connect_4122() {
    // RFC 5737 TEST-NET-1: never routable, so a run that tried to CONNECT
    // would sit on the connect timeout per row instead of refusing by name.
    let offhost = "https://192.0.2.1:9/v1";
    let (_dir, db_path) = scratch_db("loopback");
    seed_corpus(&db_path);

    let db_for_run = db_path.clone();
    let started = std::time::Instant::now();
    let output = tokio::task::spawn_blocking(move || {
        run_reembed(&db_for_run, offhost, Some("loopback-only"))
    })
    .await
    .expect("blocking spawn task must not panic");

    assert_refused(&output, &db_path, "loopback-only");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "#4122 (loopback-only): the refusal is by name, before any connect (took {:?})",
        started.elapsed()
    );
}

// ─── allow control: the fixture re-embeds through the endpoint ───────────

#[tokio::test(flavor = "multi_thread")]
async fn allow_control_reembeds_every_row_through_the_endpoint_4122() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();
    let (_dir, db_path) = scratch_db("allow");
    seed_corpus(&db_path);

    let db_for_run = db_path.clone();
    let output = tokio::task::spawn_blocking(move || run_reembed(&db_for_run, &uri, None))
        .await
        .expect("blocking spawn task must not panic");

    assert!(
        output.status.success(),
        "control (allow): the live reembed exits 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = last_stdout_json(&output);
    assert_eq!(summary["reembedded"], 3, "control (allow): {summary}");
    assert!(
        !server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "control (allow): the endpoint saw the embed requests"
    );
    assert_eq!(stored_dims(&db_path), vec![TARGET_DIM]);
    assert_eq!(count_egress_refusals(&db_path), 0);
}

// ─── internal-only: admitted AND pinned, end to end ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn internal_only_admits_and_pins_the_loopback_endpoint_4122() {
    let server = MockServer::start().await;
    mount_embeddings_ok(&server).await;
    let uri = server.uri();
    let (_dir, db_path) = scratch_db("internal");
    seed_corpus(&db_path);

    let db_for_run = db_path.clone();
    let output =
        tokio::task::spawn_blocking(move || run_reembed(&db_for_run, &uri, Some("internal-only")))
            .await
            .expect("blocking spawn task must not panic");

    assert!(
        output.status.success(),
        "#4122 (internal-only): a loopback endpoint is admitted and the pinned build re-embeds; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = last_stdout_json(&output);
    assert_eq!(summary["reembedded"], 3, "#4122 (internal-only): {summary}");
    assert_eq!(stored_dims(&db_path), vec![TARGET_DIM]);
    assert_eq!(count_egress_refusals(&db_path), 0);
}

// ─── structural: the verb is on the funnel, nothing else is off it ───────

fn read_src(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let p = entry.expect("dir entry").path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn reembed_builds_through_the_admission_funnel_and_the_pinned_builder_4122() {
    let verb = read_src("src/cli/commands/reembed.rs");
    assert!(
        verb.contains("admit_inference_target("),
        "#4122: reembed must admit the embed endpoint through `admit_inference_target`"
    );
    assert!(
        verb.contains("Embedder::from_resolved_pinned("),
        "#4122: reembed must build through the pinned builder"
    );
    assert!(
        !verb.contains("Embedder::from_resolved("),
        "#4122: reembed must not build through the unpinned `Embedder::from_resolved`"
    );

    // No production call site outside the pinned sibling's own delegation
    // (`Self::from_resolved` inside src/embeddings.rs) builds unpinned.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let offenders: Vec<String> = files
        .iter()
        .filter(|p| !p.ends_with("embeddings.rs"))
        .filter(|p| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .contains("Embedder::from_resolved(")
        })
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "#4122: unpinned `Embedder::from_resolved(` call sites outside src/embeddings.rs \
         bypass admission: {offenders:?}"
    );
}

/// #6400 — the admitted pin must reach the embedder builder. Mutant M15
/// (`Ok(pin) => pin` -> `Ok(_pin) => None`) silently drops the resolve-then-pin
/// under `internal-only` while every behavioural cell stays green (the loopback
/// endpoint is reachable pinned or not), so the data flow is pinned by shape:
/// the admission match returns the pin it was given, and that very binding is
/// what `from_resolved_pinned` receives.
#[test]
fn reembed_threads_the_admitted_pin_into_the_pinned_builder_6400() {
    let verb = read_src("src/cli/commands/reembed.rs");
    let start = verb
        .find("let egress_pin = if")
        .expect("#6400: the admission binding `egress_pin` exists");
    let region = &verb[start..];
    let end = region
        .find("Err(EgressDecision::Refuse")
        .expect("#6400: the refusal arm follows the admit arm");
    let admit_arm = &region[..end];
    assert!(
        admit_arm.contains("Ok(pin) => pin,"),
        "#6400: the admit arm must return the pin it was handed:\n{admit_arm}"
    );
    assert!(
        !admit_arm.contains("Ok(_") && !admit_arm.contains("=> None"),
        "#6400: the admit arm must not discard the pin:\n{admit_arm}"
    );
    assert!(
        verb.contains("egress_pin.as_ref(),"),
        "#6400: the admitted pin must be passed to `from_resolved_pinned`"
    );
}
