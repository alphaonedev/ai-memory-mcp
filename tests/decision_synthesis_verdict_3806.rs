// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(
    clippy::field_reassign_with_default,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::float_cmp,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::ptr_arg
)]
//! #3806 W3 — the SYNTHESIS DELETE verdict as ADVICE, pinned RED-first
//! over local wiremock servers (the idiom `tests/decision_merge_judge_3806.rs`
//! + `tests/form_1_synthesis.rs` use). No test here touches a real network.
//!
//! The property under test is a NARROWING veto, not an authority: the
//! decider can refuse a Delete the synthesis pass proposed, and it can
//! never CREATE a delete. So every ABSENCE pin (the candidate survives)
//! pairs with a PRESENCE control on the SAME sink (the same wiring with a
//! confident `yes` DOES delete), so "the delete did not happen" is never
//! satisfiable by a harness in which nothing deletes at all.
//!
//! The seam sits at the SOLE enqueue point (`run_synthesis_pass`'s
//! `SynthesisVerb::Delete` arm), AFTER the authoritative K9 re-check and
//! BEFORE the deferred `db::delete`. The Delete survives ONLY on
//! `MergeJudgement::Permit`; `NoDecider` (`[decision]` unset) is the
//! byte-identical v1.0.0 path; any `Block` — a low-confidence yes, a no,
//! a bare yes with no confidence, or an unavailable provider — is NoOp.
//!
//! The GA floor is `SYNTHESIS_DELETE_CONFIDENCE_FLOOR` = 0.80, the same
//! posture as the merge seam (5-agent vote `4d3ea1c5`, W3/W4).

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ai_memory::config::{AppConfig, LlmSection, ResolvedTtl};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::{SYNTHESIS_DELETE_CONFIDENCE_FLOOR, attach_decider};
use ai_memory::llm::OllamaClient;
use ai_memory::models::Memory;
use ai_memory::storage as db;

mod common;

use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The route the OpenAI-compatible DECISION client (the judge) posts to.
const DECISION_PATH: &str = "/chat/completions";
/// The schema field the yes/no JUDGE task reads back.
const FIELD_VERDICT: &str = "verdict";
/// A body long enough to clear `AUTONOMY_MIN_CONTENT_LEN` so the
/// synthesis hook is eligible during the store call.
const BASE_CONTENT: &str = "This is a substantial body so the AUTONOMY_MIN_CONTENT_LEN gate fires \
                            and the synthesis hook becomes eligible during the store call.";

// ---------------------------------------------------------------------------
// Env + db fixtures (mirrors tests/form_1_synthesis.rs — the proven shape).
// ---------------------------------------------------------------------------

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for
    // the process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// The synthesis pass writes a process-global prompt-size telemetry
/// counter; serialise the cells that engage real synthesis so the
/// counter is not raced (the #2285 guard form_1 uses).
fn synthesis_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn local_runs_root() -> PathBuf {
    // Keep scratch under the repo (project hard rule: never /tmp/tmpfs).
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".local-runs")
}

fn fresh_db_path() -> PathBuf {
    permissive_attestation_for_tests();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    root.join(format!("w3-synth-verdict-{}.db", uuid::Uuid::new_v4()))
}

fn open_db() -> (Connection, PathBuf) {
    let p = fresh_db_path();
    let conn = db::open(&p).expect("open db");
    (conn, p)
}

fn seed_existing(conn: &Connection, title: &str, content: &str, namespace: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: namespace.to_string(),
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
        metadata: json!({"agent_id": "ai:seed"}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ai_memory::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("seed insert")
}

fn mock_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime builds")
    })
}

fn run_store(
    conn: &Connection,
    db_path: &PathBuf,
    llm: &OllamaClient,
    params: Value,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn,
        db_path,
        &params,
        None,
        Some(llm),
        None,
        &ttl,
        true, // autonomous_hooks
        None,
        None,
    )
}

// ---------------------------------------------------------------------------
// Decision-judge mock bodies (mirrors tests/decision_merge_judge_3806.rs).
// ---------------------------------------------------------------------------

/// An OpenAI-compatible chat body whose `content` is `content` VERBATIM
/// and which carries NO logprobs — the "no confidence" shape.
fn decision_body(content: &str) -> Value {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
}

/// A decision body asserting `verdict` at probability `p` (`logprob =
/// ln p`), so the client derives a confidence of exactly `p`.
fn decision_body_with_confidence(verdict: &str, p: f64) -> Value {
    let document = json!({ FIELD_VERDICT: verdict }).to_string();
    // A REAL logprobs stream: its tokens concatenate to the content
    // document, so the verdict's confidence is anchored to the `verdict`
    // field (#3806 P1). The wrapper tokens carry logprob 0 (p = 1) so
    // the derived confidence is exactly `p`.
    json!({"choices": [{
        "message": {"role": "assistant", "content": document},
        "logprobs": {"content": [
            {"token": format!("{{\"{FIELD_VERDICT}\":\""), "logprob": 0.0},
            {"token": verdict, "logprob": p.ln()},
            {"token": "\"}", "logprob": 0.0},
        ]},
    }]})
}

/// Build the one MockServer that serves BOTH lanes of the store call:
/// the synthesis chat lane (`/api/chat`, emits `synthesis_verdicts`) and,
/// when `judge` is `Some`, the decision lane (`/chat/completions`).
///
/// `judge = None` mounts NO decision endpoint — used only for the
/// no-decider (unset) cell, where the client carries no decider at all.
fn mock_server(synthesis_verdicts: Value, judge: Option<Value>) -> MockServer {
    let rt = mock_runtime();
    rt.block_on(async {
        let server = MockServer::start().await;
        // Health probe for OllamaClient::new_with_url.
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        // Synthesis verdict lane (OllamaClient::generate -> /api/chat).
        let body_str = serde_json::to_string(&synthesis_verdicts).unwrap();
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"message": {"content": body_str}, "done": true})),
            )
            .mount(&server)
            .await;
        // auto_tag uses /api/generate; empty so the loop is a no-op.
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"response": ""})))
            .mount(&server)
            .await;
        if let Some(body) = judge {
            Mock::given(method("POST"))
                .and(path(DECISION_PATH))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }
        server
    })
}

/// A MockServer whose DECISION endpoint never answers inside the budget —
/// the provider is UNAVAILABLE (case 2), not declining. The synthesis
/// lane still answers so a Delete verdict is produced to be judged.
fn mock_server_silent_judge(synthesis_verdicts: Value) -> MockServer {
    let rt = mock_runtime();
    rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let body_str = serde_json::to_string(&synthesis_verdicts).unwrap();
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"message": {"content": body_str}, "done": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"response": ""})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(DECISION_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(30))
                    .set_body_json(decision_body("{}")),
            )
            .mount(&server)
            .await;
        server
    })
}

/// An `AppConfig` with a `[decision]` section pointed at `uri`, so
/// `attach_decider` builds the judge client against the mock.
fn cfg_with_decision(uri: &str, fallback: DecisionFallback) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("test-model".to_string()),
        base_url: Some(uri.to_string()),
        ..LlmSection::default()
    });
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(uri.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(fallback),
    });
    cfg
}

/// The synthesis client WITH a judge decider attached through the boot
/// chokepoint (the only way a decider is obtainable).
fn llm_with_decider(
    uri: &str,
    db_path: &std::path::Path,
    fallback: DecisionFallback,
) -> OllamaClient {
    let base = OllamaClient::new_with_url(uri, "test-model").expect("mock client");
    let cfg = cfg_with_decision(uri, fallback);
    attach_decider(Some(base), &cfg, db_path).expect("attach_decider returns the client")
}

fn delete_verdict(candidate_id: &str) -> Value {
    json!({ "verdicts": [{"candidate_id": candidate_id, "verb": "delete"}] })
}

/// Rows surviving in `namespace` after the store call.
fn surviving_ids(conn: &Connection, namespace: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM memories WHERE namespace = ?1")
        .unwrap();
    let rows = stmt
        .query_map([namespace], |r| r.get::<_, String>(0))
        .unwrap();
    rows.collect::<rusqlite::Result<_>>().unwrap()
}

// ---------------------------------------------------------------------------
// P3 — `[decision]` UNSET => byte-identical v1.0.0 (the golden path).
// ---------------------------------------------------------------------------

/// P3: with NO decider attached, a K9-allowed Delete verdict deletes the
/// candidate exactly as v1.0.0 did — `NoDecider` permits. This is the
/// hard-constraint golden pin (the vote's `decision_unset_is_byte_identical_v100`).
#[test]
fn decision_unset_is_byte_identical_v100() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p3");
    let server = mock_server(delete_verdict(&cand), None);
    // Bare client — no decider attached.
    let llm = OllamaClient::new_with_url(&server.uri(), "test-model").expect("mock client");

    let resp = run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p3",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p3");
    assert_eq!(
        ids.len(),
        1,
        "unset decider => v1.0.0 delete+insert = one row"
    );
    assert!(!ids.contains(&cand), "candidate deleted on the v1.0.0 path");
    assert_eq!(resp["synthesis_decisions"]["delete"].as_u64(), Some(1));
}

// ---------------------------------------------------------------------------
// P2 — presence control: a HIGH-confidence Delete DOES delete.
// ---------------------------------------------------------------------------

/// P2: decider attached, `yes` at 0.90 (>= 0.80 floor) => `Permit` =>
/// the candidate IS deleted. Proves the gate is not vacuously blocking
/// every delete (a cell that reds P1 but also blocks P2 is not a pin).
#[test]
fn high_confidence_delete_reaches_db_delete() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p2");
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("yes", 0.90)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p2",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p2");
    assert!(
        !ids.contains(&cand),
        "confident yes permits the delete; candidate removed"
    );
    assert_eq!(ids.len(), 1, "delete + insert = one row");
}

// ---------------------------------------------------------------------------
// P1 — RED-first (sensitivity): a LOW-confidence Delete never reaches db::delete.
// ---------------------------------------------------------------------------

/// P1: decider attached, `yes` at 0.50 (< 0.80 floor) => `Block` =>
/// the candidate SURVIVES; the delete never reaches `db::delete`. FAILS
/// on the pre-W3 tree (there a K9-allowed Delete always deletes) and
/// PASSES after W3.
#[test]
fn low_confidence_delete_never_reaches_db_delete() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p1");
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("yes", 0.50)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p1",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p1");
    assert!(
        ids.contains(&cand),
        "low-confidence delete collapses to NoOp; candidate survives"
    );
    assert_eq!(ids.len(), 2, "the candidate AND the new row both survive");
}

// ---------------------------------------------------------------------------
// P4 + f1 — abstain / no-confidence / confidently-false => NoOp.
// ---------------------------------------------------------------------------

/// P4 (f1 malformed-confidence): a `yes` with NO logprobs carries no
/// confidence, so it clears no `Some(0.80)` floor => `Block` => the
/// candidate SURVIVES. "Missing logprobs => no confidence" (issue #3806).
#[test]
fn bare_yes_without_confidence_collapses_to_noop() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p4a");
    let doc = json!({ FIELD_VERDICT: "yes" }).to_string();
    let server = mock_server(delete_verdict(&cand), Some(decision_body(&doc)));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p4a",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p4a");
    assert!(
        ids.contains(&cand),
        "a yes with no confidence never clears the floor; candidate survives"
    );
}

/// f1 confidently-FALSE: a `no` at high confidence => `Block(DecidedNo)`
/// => the candidate SURVIVES. The decider may only KEEP a candidate,
/// never delete beyond what the synthesis pass proposed.
#[test]
fn confidently_false_verdict_keeps_candidate() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p4b");
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("no", 0.95)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p4b",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p4b");
    assert!(ids.contains(&cand), "a confident no blocks the delete");
}

/// P4 unavailable: the DECISION endpoint never answers inside the budget
/// (case 2). Under the DEFAULT `fallback = abstain`, an unavailable
/// provider on a destructive seam => `Block` => NoOp. The candidate
/// SURVIVES (fail-safe toward non-destruction).
#[test]
fn unavailable_judge_collapses_to_noop() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p4c");
    let server = mock_server_silent_judge(delete_verdict(&cand));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p4c",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p4c");
    assert!(
        ids.contains(&cand),
        "an unavailable judge under fallback=abstain collapses to NoOp"
    );
}

// ---------------------------------------------------------------------------
// P5 — narrowing-only: the decider NEVER creates a delete.
// ---------------------------------------------------------------------------

/// P5: an `add` verdict with a decider attached never becomes a delete —
/// the seam lives ONLY in the Delete arm, so a non-Delete verb never
/// reaches the judge nor `db::delete`. Both rows survive.
#[test]
fn decider_never_escalates_add_to_delete() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "unrelated note", "keep me", "ns-p5");
    // A high-confidence yes is armed, but no Delete verb is ever emitted,
    // so it can only be consulted if the gate widened beyond the Delete arm.
    let server = mock_server(
        json!({ "verdicts": [{"candidate_id": cand, "verb": "add"}] }),
        Some(decision_body_with_confidence("yes", 0.99)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p5",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p5");
    assert!(
        ids.contains(&cand),
        "add verdict never deletes the candidate"
    );
    assert_eq!(ids.len(), 2, "add => the candidate AND the new row survive");
}

// ---------------------------------------------------------------------------
// P6 — K9 stays authoritative even at high confidence.
// ---------------------------------------------------------------------------

/// P6: a K9 `Ask` rule on `memory_delete` suppresses the delete BEFORE
/// the decider seam is consulted — the seam is nested INSIDE the
/// `k9_allows_synthesis_delete` gate — so a permitting judge (`yes` at
/// 0.99) cannot resurrect it. The decider ADDS a gate; it can never
/// REMOVE the authoritative K9 refusal. (The default delete-cap is 1, so
/// a single delete reaches the per-verdict K9 check rather than tripping
/// the SEC-1 batch cap first.)
#[test]
fn k9_ask_refuses_delete_even_at_high_confidence() {
    use ai_memory::permissions::{
        PermissionRule, RuleDecision, clear_active_permission_rules_for_test,
        set_active_permission_rules,
    };
    // Every cell in this file holds `synthesis_lock`, so the process-global
    // permission-rule state P6 sets can never leak into a concurrent cell.
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());

    let (conn, db_path) = open_db();
    let ns = "ns-p6-k9";
    let cand = seed_existing(&conn, "obsolete deploy note", "old", ns);

    clear_active_permission_rules_for_test();
    set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: ns.to_string(),
        op: "memory_delete".to_string(),
        agent_pattern: "*".to_string(),
        decision: RuleDecision::Ask,
        reason: Some("operator must approve synthesis deletes".into()),
    }]);

    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("yes", 0.99)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    let result = run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": ns,
            "on_conflict": "version",
        }),
    );

    // Clear BEFORE asserting so a panic cannot leak the rule into another cell.
    clear_active_permission_rules_for_test();
    result.expect("store ok under K9 ask");

    let ids = surviving_ids(&conn, ns);
    assert!(
        ids.contains(&cand),
        "K9 Ask suppresses the delete before the seam; a permitting judge cannot override K9"
    );
}

// ===========================================================================
// #3806 code-review F4 — the W3 HALF of the mandatory acceptance table, the
// sibling of god-zsg's F4-W4 cells in `tests/decision_merge_judge_3806.rs`.
// Every cell drives the SOLE enqueue point through `run_store` (the only
// reachable path to `judge_synthesis_delete`, which is `pub(crate)`), and
// pairs an ABSENCE (candidate survives) against the presence controls the
// file already carries, so no assertion is vacuous.
// ===========================================================================

/// A store request that proposes the newer memory over `namespace`.
fn store_req(namespace: &str) -> Value {
    json!({
        "title": "current deploy strategy",
        "content": BASE_CONTENT,
        "namespace": namespace,
        "on_conflict": "version",
    })
}

/// `mock_server`'s twin whose DECISION endpoint answers with a RAW body,
/// so an unparseable / out-of-range logprob (`NaN`, `1e999`, a positive
/// logprob ⇒ p > 1) can be put on the wire — none is expressible as a
/// `serde_json::Value`.
fn mock_server_raw_judge(synthesis_verdicts: Value, raw_decision_body: String) -> MockServer {
    let rt = mock_runtime();
    rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let body_str = serde_json::to_string(&synthesis_verdicts).unwrap();
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"message": {"content": body_str}, "done": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"response": ""})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(DECISION_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(raw_decision_body.into_bytes(), "application/json"),
            )
            .mount(&server)
            .await;
        server
    })
}

/// How many times the DECISION endpoint was dialled — the presence /
/// absence discriminator for "the judge was asked" vs "never dialled".
fn decision_hits(server: &MockServer) -> usize {
    mock_runtime().block_on(async {
        server.received_requests().await.map_or(0, |reqs| {
            reqs.iter()
                .filter(|r| r.url.path() == DECISION_PATH)
                .count()
        })
    })
}

/// F4 — the FLOOR boundary over the wire: a `yes` at `floor + 0.01` clears
/// `SYNTHESIS_DELETE_CONFIDENCE_FLOOR` and the candidate IS deleted; the
/// same `yes` at `floor - 0.01` does not and the candidate SURVIVES. The
/// ±0.01 margin is far larger than any `ln`/`exp` round-trip error, so the
/// boundary is pinned without a flaky exact-`0.80` dependency.
#[test]
fn at_the_floor_delete_permits_at_and_above_blocks_below() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());

    // The seam's gate is `is_confident_at_least(floor)` = `c >= floor` (INCLUSIVE,
    // src/decision.rs), so a confidence of EXACTLY the floor must PERMIT. The wire
    // round-trip is bit-exact at this value — `exp(ln(0.80f64)) == 0.80f64` — so an
    // exactly-at-floor cell genuinely discriminates the inclusive `>=` from a `>`
    // refactor (which would block at exactly 0.80, the documented GA floor and the
    // single most likely value emitted/configured). Three points bound the boundary:
    // AT permits, ABOVE permits, BELOW blocks.
    for (label, ns, p, deleted) in [
        ("at", "ns-floor-at", SYNTHESIS_DELETE_CONFIDENCE_FLOOR, true),
        (
            "above",
            "ns-floor-hi",
            SYNTHESIS_DELETE_CONFIDENCE_FLOOR + 0.01,
            true,
        ),
        (
            "below",
            "ns-floor-lo",
            SYNTHESIS_DELETE_CONFIDENCE_FLOOR - 0.01,
            false,
        ),
    ] {
        let (conn, db_path) = open_db();
        let cand = seed_existing(&conn, "obsolete deploy note", "old", ns);
        let server = mock_server(
            delete_verdict(&cand),
            Some(decision_body_with_confidence("yes", p)),
        );
        let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);
        run_store(&conn, &db_path, &llm, store_req(ns)).expect("ok");
        let survives = surviving_ids(&conn, ns).contains(&cand);
        if deleted {
            assert!(
                !survives,
                "{label} the floor ({p}) is at-least-confident and PERMITS the delete; candidate removed"
            );
        } else {
            assert!(
                survives,
                "{label} the floor ({p}) is below the floor and BLOCKS; candidate survives"
            );
        }
    }
}
/// F4 — an unparseable (`NaN`), infinite (`1e999`) or out-of-range
/// (positive logprob ⇒ p > 1) confidence OVER THE WIRE never permits: the
/// client degrades each to ABSENT and the destructive seam BLOCKS, so the
/// candidate survives. The judge WAS dialled each time (presence), so the
/// block is the seam refusing the number, not a silent endpoint.
#[test]
fn a_malformed_or_out_of_range_confidence_never_permits_over_the_wire() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let document = json!({ FIELD_VERDICT: "yes" }).to_string();
    let content = serde_json::to_string(&document).unwrap();
    for (label, logprob) in [
        ("nan", "NaN"),
        ("infinity", "1e999"),
        ("positive_logprob_p_gt_1", "0.5"),
    ] {
        let (conn, db_path) = open_db();
        let ns = format!("ns-wire-{label}");
        let cand = seed_existing(&conn, "obsolete deploy note", "old", &ns);
        let raw = format!(
            r#"{{"choices":[{{"message":{{"role":"assistant","content":{content}}},"logprobs":{{"content":[{{"token":"yes","logprob":{logprob}}}]}}}}]}}"#
        );
        let server = mock_server_raw_judge(delete_verdict(&cand), raw);
        let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);
        run_store(&conn, &db_path, &llm, store_req(&ns))
            .expect("an unusable number is a NoOp, not an error");
        let ids = surviving_ids(&conn, &ns);
        assert!(
            ids.contains(&cand),
            "{label}: a confidence that is not a probability never permits; candidate survives"
        );
        assert_eq!(
            decision_hits(&server),
            1,
            "{label}: the judge WAS asked (presence)"
        );
    }
}

/// F4 — a decision document that PARSES but carries a number and NO
/// `verdict` field is no decision: `Unusable` ⇒ Block ⇒ the candidate
/// survives.
#[test]
fn a_confidence_number_without_a_verdict_blocks() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-noverdict");
    let doc = json!({ "confidence": 0.99 }).to_string();
    let server = mock_server(delete_verdict(&cand), Some(decision_body(&doc)));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);
    run_store(&conn, &db_path, &llm, store_req("ns-noverdict")).expect("a decline is not an error");
    let ids = surviving_ids(&conn, "ns-noverdict");
    assert!(
        ids.contains(&cand),
        "a number without a verdict is no decision; candidate survives"
    );
}

/// F4 / D1 — a `[decision]` section that is CONFIGURED but whose provider
/// was NEVER built (egress refused at boot) is a PERMANENT case 2: the
/// destructive seam blocks under EVERY posture (never the v1.0.0 legacy
/// path), the candidate survives, and the refused destination is never
/// dialled. `abstain` collapses to NoOp; `refuse` errors inside
/// `judge_synthesis_delete` and the Delete arm fails CLOSED to the SAME
/// NoOp (the store still returns `Ok` — a refuse on the ADVICE lane never
/// fails the whole store).
#[test]
fn a_boot_refused_decider_never_dials_and_collapses_to_noop() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let _egress = common::EnvVarGuard::set("AI_MEMORY_INFERENCE_EGRESS", "deny".to_string());
    for fallback in [DecisionFallback::Abstain, DecisionFallback::Refuse] {
        let (conn, db_path) = open_db();
        let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-bootrefused");
        // The endpoint WOULD answer a confident yes — but egress=deny means
        // the provider is never built, so it is never dialled.
        let server = mock_server(
            delete_verdict(&cand),
            Some(decision_body_with_confidence("yes", 0.99)),
        );
        let llm = llm_with_decider(&server.uri(), &db_path, fallback);
        run_store(&conn, &db_path, &llm, store_req("ns-bootrefused"))
            .expect("boot-refused collapses to NoOp under both postures, never a store error");
        let ids = surviving_ids(&conn, "ns-bootrefused");
        assert!(
            ids.contains(&cand),
            "{fallback:?}: a configured-but-unbuilt decider blocks the delete (case 2), never legacy"
        );
        assert_eq!(
            decision_hits(&server),
            0,
            "{fallback:?}: a refused destination is never dialled"
        );
    }
}

/// F4 / D3 — under `fallback = "generative"` the destructive seam does NOT
/// re-ask a generative stand-in (`judge_primary`, never `judge`): an
/// unavailable primary yields a Block, never a generative `yes`. So the
/// candidate SURVIVES — the destructive delete path is never WIDENED by
/// the fallback leg (5-agent vote `4d3ea1c5`; the generative call would
/// otherwise POST memory content for an answer the seam discards).
#[test]
fn a_generative_fallback_never_widens_the_destructive_delete() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-gen-nowiden");
    let server = mock_server_silent_judge(delete_verdict(&cand));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Generative);
    run_store(&conn, &db_path, &llm, store_req("ns-gen-nowiden")).expect("ok");
    let ids = surviving_ids(&conn, "ns-gen-nowiden");
    assert!(
        ids.contains(&cand),
        "generative fallback never widens the destructive delete; candidate survives"
    );
}

/// F4 — the `refuse` posture on the destructive ADVICE lane: an
/// unavailable judge makes `judge_synthesis_delete` error (case 2,
/// refuse), and the Delete arm catches it and fails CLOSED to NoOp. The
/// candidate SURVIVES and the store call still returns `Ok` — a refuse on
/// the narrowing advice lane never fails the whole store.
#[test]
fn refuse_posture_on_an_unavailable_judge_fails_closed_to_noop() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-refuse");
    let server = mock_server_silent_judge(delete_verdict(&cand));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Refuse);
    run_store(&conn, &db_path, &llm, store_req("ns-refuse"))
        .expect("a refuse on the destructive advice lane collapses to NoOp, never a store error");
    let ids = surviving_ids(&conn, "ns-refuse");
    assert!(
        ids.contains(&cand),
        "refuse fails closed to NoOp; candidate survives"
    );
}

// ---------------------------------------------------------------------------
// #3806 P1 (Codex/f2r, withdrawal of 63e3033b0): the confidence must be the
// VERDICT field's own, never an unrelated field's. GOD's routing ruling makes
// this W3 pin a LANDING CONDITION for #3806.
// ---------------------------------------------------------------------------

/// A decision body whose `content` is `document` and whose logprob stream
/// is exactly `tokens` (text, probability), so a cell controls which token
/// carries which confidence.
fn decision_body_with_stream(document: &str, tokens: &[(&str, f64)]) -> Value {
    let content: Vec<Value> = tokens
        .iter()
        .map(|(token, p)| json!({"token": token, "logprob": p.ln()}))
        .collect();
    json!({"choices": [{
        "message": {"role": "assistant", "content": document},
        "logprobs": {"content": content},
    }]})
}

/// P1 pin. The verdict is `yes`, but its token arrives FUSED with the
/// opening quote (`"yes`, p = 0.01), so it never spells the bare label. An
/// unrelated `note` field emits a clean `yes` token at p = 0.99. The
/// verdict's own confidence is 0.01, below the 0.80 floor, so the delete
/// must be blocked and the candidate must survive.
///
/// RED at 63e3033b0: `label_probability` searches the WHOLE stream, finds
/// exactly one clean `yes` run (the note's), and attributes its 0.99 to the
/// verdict, so the candidate is DELETED on a confidence the verdict never
/// had. GREEN on any fix that anchors the confidence to the verdict field.
/// Whether the fix reads the fused token (0.01) or treats it as
/// unlocatable (no confidence), both block the delete.
#[test]
fn unrelated_field_confidence_never_licenses_a_delete_3806_p1() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p1-misattr");
    let document = json!({ FIELD_VERDICT: "yes", "note": "yes" }).to_string();
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_stream(
            &document,
            &[
                ("{\"", 0.99),
                (FIELD_VERDICT, 0.99),
                ("\":", 0.99),
                ("\"yes", 0.01),
                ("\",\"", 0.99),
                ("note", 0.99),
                ("\":\"", 0.99),
                ("yes", 0.99),
                ("\"}", 0.99),
            ],
        )),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p1-misattr",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p1-misattr");
    assert!(
        ids.contains(&cand),
        "the verdict's own confidence is 0.01; an unrelated field's 0.99 must never license the delete"
    );
    assert_eq!(ids.len(), 2, "the candidate AND the new row both survive");
}

/// Control for the P1 pin: the SAME stream shape, but the verdict's own
/// token is a clean `yes` at p = 0.99 and the note says something else, so
/// the verdict really is confident and the delete must go through. This
/// proves the pin is not passing by blocking every delete.
#[test]
fn verdict_field_confidence_still_licenses_a_delete_3806_p1_control() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-p1-control");
    let document = json!({ FIELD_VERDICT: "yes", "note": "stale" }).to_string();
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_stream(
            &document,
            &[
                ("{\"", 0.99),
                (FIELD_VERDICT, 0.99),
                ("\":\"", 0.99),
                ("yes", 0.99),
                ("\",\"", 0.99),
                ("note", 0.99),
                ("\":\"", 0.99),
                ("stale", 0.99),
                ("\"}", 0.99),
            ],
        )),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);

    run_store(
        &conn,
        &db_path,
        &llm,
        json!({
            "title": "current deploy strategy",
            "content": BASE_CONTENT,
            "namespace": "ns-p1-control",
            "on_conflict": "version",
        }),
    )
    .expect("ok");

    let ids = surviving_ids(&conn, "ns-p1-control");
    assert!(
        !ids.contains(&cand),
        "a verdict confident in its own token (0.99) permits the delete"
    );
    assert_eq!(ids.len(), 1, "delete + insert = one row");
}

// ---------------------------------------------------------------------------
// #4173 — a withheld Delete is reported, never silently skipped.
// ---------------------------------------------------------------------------

/// #4173: a Delete the decision seam withheld is named on the store
/// response under `synthesis_deletes_withheld` with its reason code, and
/// the candidate survives. There are three shapes:
/// - `refuse` + an unavailable judge reports `refused_unavailable`.
/// - `abstain` + a low-confidence yes reports `low_confidence`.
/// - A permitted delete (the control) reports NOTHING and the delete
///   applies, so the field is not unconditional.
///
/// RED on 65642b3cf: the response carries no such field, so a caller cannot
/// tell "applied" from "skipped".
#[test]
fn a_withheld_synthesis_delete_is_reported_on_the_response_4173() {
    let _g = synthesis_lock().lock().unwrap_or_else(|p| p.into_inner());

    let withheld = |resp: &Value| resp.get("synthesis_deletes_withheld").cloned();

    // refuse + unavailable
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-4173-refuse");
    let server = mock_server_silent_judge(delete_verdict(&cand));
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Refuse);
    let resp = run_store(&conn, &db_path, &llm, store_req("ns-4173-refuse")).expect("ok");
    assert_eq!(
        withheld(&resp),
        Some(json!([{"id": cand, "reason": "refused_unavailable"}])),
        "refuse posture must report the withheld delete: {resp}"
    );
    assert!(surviving_ids(&conn, "ns-4173-refuse").contains(&cand));

    // abstain + low confidence
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-4173-low");
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("yes", 0.50)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);
    let resp = run_store(&conn, &db_path, &llm, store_req("ns-4173-low")).expect("ok");
    assert_eq!(
        withheld(&resp),
        Some(json!([{"id": cand, "reason": "low_confidence"}])),
        "a low-confidence Block must report the withheld delete: {resp}"
    );
    assert!(surviving_ids(&conn, "ns-4173-low").contains(&cand));

    // control: a permitted delete applies and reports nothing withheld
    let (conn, db_path) = open_db();
    let cand = seed_existing(&conn, "obsolete deploy note", "old", "ns-4173-permit");
    let server = mock_server(
        delete_verdict(&cand),
        Some(decision_body_with_confidence("yes", 0.99)),
    );
    let llm = llm_with_decider(&server.uri(), &db_path, DecisionFallback::Abstain);
    let resp = run_store(&conn, &db_path, &llm, store_req("ns-4173-permit")).expect("ok");
    assert_eq!(
        withheld(&resp),
        None,
        "an applied delete is not withheld: {resp}"
    );
    assert!(
        !surviving_ids(&conn, "ns-4173-permit").contains(&cand),
        "the control delete must actually apply"
    );
}
