// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on a test binary.
#![allow(
    clippy::field_reassign_with_default,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::float_cmp
)]
//! #3806 W4 — the consolidation MERGE JUDGE as a NARROWING third gate
//! behind Jaccard AND cosine, pinned RED-first over local mock HTTP
//! servers (`wiremock`, the idiom `tests/decision_seams_3806.rs` uses).
//! No test here touches a real network.
//!
//! The property under test is a VETO, not an authority: the judge can
//! refuse a consolidation the two fixed gates admitted, and it can never
//! cause one they refused. Every pin therefore pairs an ABSENCE (the
//! merge did not happen; the sources are still there) with a PRESENCE
//! control on the same sinks (the same wiring with a confident yes DOES
//! merge), so "the merge did not happen" is never satisfiable by a
//! harness in which nothing merges at all.
//!
//! The GOD rulings this file pins (3806-W4-DEFAULTS-RULING-GOD-tmux22):
//! (1) an UNAVAILABLE decider blocks under `abstain` AND `generative`
//! and errors under `refuse`; (2) a dry run consults the judge and the
//! report labels the `DecisionSource`; (3) a yes WITHOUT a confidence,
//! or below the floor, BLOCKS — only `Some(true)` at or above
//! [`CONSOLIDATION_MERGE_CONFIDENCE_FLOOR`] permits.

use std::time::Duration;

use rusqlite::Connection;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::autonomy::{AutonomyLlm, AutonomyPassReport, run_autonomy_passes};
use ai_memory::config::{AppConfig, LlmSection};
use ai_memory::db;
use ai_memory::decision::{AbstainReason, DecisionSource};
use ai_memory::decision_config::{DecisionFallback, DecisionSection};
use ai_memory::decision_seams::{
    BREAKER_THRESHOLD, CONSOLIDATION_MERGE_CONFIDENCE_FLOOR, MergeBlockReason, MergeJudgeReport,
    MergeJudgement, attach_decider,
};

/// The judge counters a funnel run carried, from whichever key it used:
/// `merge_judge` (real) or `judge_preview` (dry). Empty when neither is
/// present — the unset case.
fn mj(report: &AutonomyPassReport) -> MergeJudgeReport {
    report
        .merge_judge
        .clone()
        .or_else(|| report.judge_preview.clone())
        .unwrap_or_default()
}

/// The exact key set an UNSET `[decision]` Pass-1 report serializes to —
/// the v1.0.0 shape, frozen from the carrier (`becaa0720`), which the W4
/// judge keys must never join by default (GOD ruling: conditional
/// omission, pinned against the golden output).
const UNSET_REPORT_KEYS_GOLDEN: &[&str] = &[
    "clusters_formed",
    "memories_consolidated",
    "memories_forgotten",
    "priority_adjustments",
    "rollback_entries_written",
    "rollback_entries_simulated",
    "operations_attempted",
    "operations_skipped_cap",
    "rollback_log_degraded",
    "errors",
];
use ai_memory::llm::OllamaClient;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

/// The route the OpenAI-compatible DECISION client posts to.
const DECISION_PATH: &str = "/chat/completions";
/// The route the Ollama-native GENERATIVE client posts to — the v1.0.0
/// summariser, which a BLOCKED cluster must never reach.
const GENERATIVE_PATH: &str = "/api/chat";
/// The schema field the yes/no JUDGE task reads back.
const FIELD_VERDICT: &str = "verdict";
/// The metric seam token W1 preregistered for this seam.
const SEAM: &str = "consolidation_merge";
/// A non-reserved namespace for the fixture rows.
const NS: &str = "w4";
/// Two rows whose title+content are near-identical: Jaccard 1.0 on the
/// text, cosine 1.0 on the aligned embeddings below — the two fixed
/// gates ADMIT this pair, so whether it merges is the judge's call.
const TITLE_A: &str = "deploy window is tuesday 02:00 utc";
const TITLE_B: &str = "deploy window is tuesday 02:00 utc (dup)";
const CONTENT: &str = "the production deploy window is every tuesday at 02:00 utc; \
     the on-call engineer opens the change ticket one hour before";

/// A `[decision]` section pointed at `base_url`.
fn cfg_with_decision(
    decision_url: &str,
    generative_url: &str,
    fallback: DecisionFallback,
) -> AppConfig {
    let mut cfg = cfg_generative_only(generative_url);
    cfg.decision = Some(DecisionSection {
        provider: Some("openai-compatible".to_string()),
        model: Some("vendor/decision-1".to_string()),
        base_url: Some(decision_url.to_string()),
        api_key_env: None,
        api_key_file: None,
        api_key: None,
        timeout_secs: Some(2),
        fallback: Some(fallback),
    });
    cfg
}

/// The same config with NO `[decision]` section — the v1.0.0 shape.
fn cfg_generative_only(generative_url: &str) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.llm = Some(LlmSection {
        backend: Some("ollama".to_string()),
        model: Some("vendor/chat-1".to_string()),
        base_url: Some(generative_url.to_string()),
        ..LlmSection::default()
    });
    cfg
}

/// An OpenAI-compatible chat body whose `content` is `content` VERBATIM
/// and which carries NO `logprobs` block — the "endpoint reports no
/// confidence" shape.
fn decision_body(content: &str) -> Value {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
}

/// The same body WITH a `logprobs` block whose single token spells the
/// verdict at probability `p` (`exp(ln p)`), so the client derives a
/// confidence of exactly `p`.
fn decision_body_with_confidence(verdict: &str, p: f64) -> Value {
    let document = json!({ FIELD_VERDICT: verdict }).to_string();
    json!({"choices": [{
        "message": {"role": "assistant", "content": document},
        "logprobs": {"content": [{"token": verdict, "logprob": p.ln()}]},
    }]})
}

async fn mount_decision(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// A verdict WITHOUT confidence (no logprobs).
async fn mount_verdict_no_confidence(server: &MockServer, verdict: &str) {
    let document = json!({ FIELD_VERDICT: verdict }).to_string();
    mount_decision(server, decision_body(&document)).await;
}

/// A verdict WITH confidence `p`.
async fn mount_verdict(server: &MockServer, verdict: &str, p: f64) {
    mount_decision(server, decision_body_with_confidence(verdict, p)).await;
}

/// PROSE — what a refusal looks like on the wire.
async fn mount_prose(server: &MockServer, prose: &str) {
    mount_decision(server, decision_body(prose)).await;
}

/// The DECISION endpoint never answers inside the budget: the provider
/// is UNAVAILABLE (case 2), not declining.
async fn mount_silent(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(decision_body("{}")),
        )
        .mount(server)
        .await;
}

/// The GENERATIVE summariser, armed with one answer. Whether it is HIT is
/// one of the sinks: a blocked cluster must never reach it.
async fn mount_generative(server: &MockServer, content: &str) {
    Mock::given(method("POST"))
        .and(path(GENERATIVE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "vendor/chat-1",
            "message": {"role": "assistant", "content": content},
            "done": true
        })))
        .mount(server)
        .await;
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// The current value of `ai_memory_decision_outcome_total` for one
/// `seam`/`outcome` pair. The registry is process-global, so every pin
/// measures a DELTA under the file lock.
fn outcome_count(seam: &str, outcome: &str) -> u64 {
    let needle =
        format!("ai_memory_decision_outcome_total{{outcome=\"{outcome}\",seam=\"{seam}\"}} ");
    ai_memory::metrics::render()
        .lines()
        .find_map(|line| line.strip_prefix(needle.as_str()))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or(0)
}

/// Build a generative client against `generative_url` and attach
/// whatever `cfg` implies through the BOOT CHOKEPOINT — the only way a
/// decider is obtainable.
fn client_for(cfg: &AppConfig, generative_url: &str, db: &std::path::Path) -> OllamaClient {
    let client = OllamaClient::new_with_url_no_health_check(generative_url, "vendor/chat-1")
        .expect("the mock client builds");
    attach_decider(Some(client), cfg, db)
        .expect("attach_decider must return the client it was given")
}

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

/// Every test in this binary takes this lock (process-global metrics
/// registry; async so it may be held across `.await`).
static SEAM_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
async fn serialize() -> tokio::sync::MutexGuard<'static, ()> {
    SEAM_LOCK.lock().await
}

fn members() -> Vec<(String, String)> {
    vec![
        (TITLE_A.to_string(), CONTENT.to_string()),
        (TITLE_B.to_string(), CONTENT.to_string()),
    ]
}

// ------------------------------------------------------------ fixtures:
// the sqlite funnel (`run_autonomy_passes` -> `consolidate_cluster`).

fn mem(id: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: CONTENT.to_string(),
        tags: vec!["w4".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({"agent_id": "ai:test"}),
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
        lifecycle_state: LifecycleState::Open,
    }
}

fn unit(values: &[f32]) -> Vec<f32> {
    let norm: f32 = values.iter().map(|v| v * v).sum::<f32>().sqrt();
    values.iter().map(|v| v / norm).collect()
}

/// A fresh sqlite store holding the near-duplicate pair with ALIGNED
/// embeddings (cosine 1.0): both fixed gates admit the pair. Returns the
/// connection and the two rows.
fn store_with_admitted_pair(dir: &std::path::Path) -> (Connection, Vec<Memory>) {
    let conn = db::open(&dir.join("w4.db")).expect("open sqlite");
    let a = mem("w4-a", TITLE_A);
    let b = mem("w4-b", TITLE_B);
    db::insert(&conn, &a).expect("insert a");
    db::insert(&conn, &b).expect("insert b");
    let fp = ai_memory::embeddings::embedding_space_fingerprint("w4-space");
    for id in ["w4-a", "w4-b"] {
        db::set_embedding(&conn, id, &unit(&[1.0, 0.0, 0.0, 0.0]), &fp).expect("embedding");
    }
    (conn, vec![a, b])
}

/// The same pair with ORTHOGONAL embeddings (cosine 0.0): the cosine gate
/// REFUSES the pair before any judge could see it.
fn store_with_refused_pair(dir: &std::path::Path) -> (Connection, Vec<Memory>) {
    let conn = db::open(&dir.join("w4-refused.db")).expect("open sqlite");
    let a = mem("w4-a", TITLE_A);
    let b = mem("w4-b", TITLE_B);
    db::insert(&conn, &a).expect("insert a");
    db::insert(&conn, &b).expect("insert b");
    let fp = ai_memory::embeddings::embedding_space_fingerprint("w4-space");
    db::set_embedding(&conn, "w4-a", &unit(&[1.0, 0.0, 0.0, 0.0]), &fp).expect("embedding a");
    db::set_embedding(&conn, "w4-b", &unit(&[0.0, 1.0, 0.0, 0.0]), &fp).expect("embedding b");
    (conn, vec![a, b])
}

fn row_exists(conn: &Connection, id: &str) -> bool {
    db::get(conn, id).ok().flatten().is_some()
}

fn consolidated_rows(conn: &Connection) -> usize {
    db::list(
        conn,
        Some(NS),
        None,
        100,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list")
    .into_iter()
    .filter(|m| m.title.starts_with("[consolidated]"))
    .count()
}

// ================================================================ seam pins

/// `[decision]` UNSET: the judge is not a party at all. `NoDecider` is
/// returned without consulting anything — and it is NOT a permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unset_is_no_decider_and_consults_nothing() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();
    let cfg = cfg_generative_only(&generative.uri());
    let client = client_for(&cfg, &generative.uri(), db.path());

    let judgement = client.judge_merge(&members()).expect("unset never errors");

    assert_eq!(judgement, MergeJudgement::NoDecider);
    assert!(judgement.permits(), "NoDecider runs the v1.0.0 body");
    assert_eq!(
        judgement.source(),
        None,
        "no judge answered, so no source label"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "the judge never touches the summariser"
    );
}

/// RULING (1): an UNAVAILABLE decider BLOCKS under `abstain`. The silent
/// endpoint is case 2; the outcome label is `timeout`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_blocks_under_abstain() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_silent(&decision).await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count(SEAM, "timeout");
    let judgement = client
        .judge_merge(&members())
        .expect("abstain posture is not an error");

    assert!(
        !judgement.permits(),
        "an unavailable decider must BLOCK, got {judgement:?}"
    );
    assert!(
        matches!(
            judgement,
            MergeJudgement::Block {
                reason: MergeBlockReason::Unavailable(AbstainReason::Timeout),
                ..
            }
        ),
        "the block must name unavailability, got {judgement:?}"
    );
    assert_eq!(outcome_count(SEAM, "timeout"), before + 1);
    assert_eq!(hits(&generative).await, 0);
}

/// RULING (1): an UNAVAILABLE decider BLOCKS under `generative` too. On
/// this seam there is no legacy judge to fall back to — the v1.0.0
/// instrument is NO judge — so "fall back" would WIDEN the destructive
/// path. And the stand-in is NEVER ASKED (5-agent vote `4d3ea1c5`, W4):
/// the seam calls `DecisionProvider::judge_primary`, so the chain's
/// generative leg — a network call carrying the members' content, for
/// an answer the seam would discard — does not fire. The block names the
/// PRIMARY's own abstain (`Timeout`) and lands on the `timeout` series.
///
/// Two controls keep this discriminating rather than vacuous: the block
/// shape is asserted EXACTLY (a `hits == 0` alone would also pass if
/// `construct` had errored and no decider was attached — that path is
/// `NoDecider`, which `permits()`), and a POSITIVE control shows the
/// stand-in IS reachable in this very configuration through a W2 seam.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_blocks_under_generative_and_never_falls_back() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_silent(&decision).await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Generative,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before_timeout = outcome_count(SEAM, "timeout");
    let before_fallback = outcome_count(SEAM, "fallback");
    let judgement = client
        .judge_merge(&members())
        .expect("generative posture is not an error");

    assert!(
        matches!(
            judgement,
            MergeJudgement::Block {
                reason: MergeBlockReason::Unavailable(AbstainReason::Timeout),
                // The PRIMARY network decider's own stamp on its own
                // timeout — never `GenerativeFallback`.
                source: DecisionSource::DecisionModel,
            }
        ),
        "the block must be the PRIMARY's own timeout, not a stand-in's answer, got {judgement:?}"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "ABSENCE: the generative stand-in is never asked on the merge seam — its answer could \
         only be discarded, and the call would carry memory content across the egress boundary"
    );
    assert_eq!(outcome_count(SEAM, "timeout"), before_timeout + 1);
    assert_eq!(
        outcome_count(SEAM, "fallback"),
        before_fallback,
        "nothing was asked of the stand-in, so nothing is labelled `fallback`"
    );

    // POSITIVE CONTROL — same client, same posture: a W2 seam still
    // reaches the stand-in (it answers "yes" to a contradiction judgement),
    // so the zero above is the merge seam declining to ask, not a
    // stand-in that was never wired.
    let verdict = client
        .detect_contradiction_async("the port is 9077", "the port is 9078")
        .await
        .expect("generative posture is not an error on a W2 seam either");
    assert!(verdict, "the stand-in answered yes through the W2 seam");
    assert_eq!(
        hits(&generative).await,
        1,
        "the stand-in is reachable in this configuration — through a seam that HAS a legacy \
         instrument, and only there"
    );
}

/// RULING (1): under `refuse`, unavailability is an ERROR — the
/// consolidation fails loudly rather than proceeding. Still no merge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_errors_under_refuse() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_silent(&decision).await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri(), DecisionFallback::Refuse);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let err = client
        .judge_merge(&members())
        .expect_err("refuse + unavailable is the one error case");
    assert!(
        err.to_string().contains("refuses to consolidate"),
        "the error must name the refusal: {err}"
    );
}

/// A DECLINE (prose, no structured document) BLOCKS — terminal, under
/// every posture including `refuse` — and is COUNTED as an abstain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abstain_blocks_terminally_even_under_refuse() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_prose(&decision, "I'm sorry, I can't help with that.").await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(&decision.uri(), &generative.uri(), DecisionFallback::Refuse);
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count(SEAM, "abstained");
    let judgement = client
        .judge_merge(&members())
        .expect("a decline is never an error");

    assert!(
        matches!(
            judgement,
            MergeJudgement::Block {
                reason: MergeBlockReason::Abstained(_),
                ..
            }
        ),
        "a decline blocks, got {judgement:?}"
    );
    assert_eq!(outcome_count(SEAM, "abstained"), before + 1);
    assert_eq!(
        hits(&decision).await,
        1,
        "a decline costs exactly ONE model call"
    );
    assert_eq!(
        hits(&generative).await,
        0,
        "and is never re-asked of a weaker reader"
    );
}

/// A confident NO blocks and is counted as `decided` — the judge
/// answered and its answer was no.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confident_no_blocks() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "no", 0.95).await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count(SEAM, "decided");
    let judgement = client
        .judge_merge(&members())
        .expect("a decided no is not an error");

    assert!(
        matches!(
            judgement,
            MergeJudgement::Block {
                reason: MergeBlockReason::DecidedNo,
                source: DecisionSource::DecisionModel,
            }
        ),
        "got {judgement:?}"
    );
    assert_eq!(outcome_count(SEAM, "decided"), before + 1);
}

/// RULING (3): a YES with NO confidence (the endpoint returned no
/// logprobs) is treated as an ABSTAIN and BLOCKS. On a path that deletes
/// sources, an uncalibrated yes is not a yes. This pin is RED on a draft
/// that permits on any yes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_yes_without_confidence_blocks() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict_no_confidence(&decision, "yes").await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let before = outcome_count(SEAM, "abstained");
    let judgement = client.judge_merge(&members()).expect("not an error");

    assert!(
        matches!(
            judgement,
            MergeJudgement::Block {
                reason: MergeBlockReason::LowConfidence { confidence: None },
                ..
            }
        ),
        "a yes without a confidence must block as low-confidence, got {judgement:?}"
    );
    assert_eq!(
        outcome_count(SEAM, "abstained"),
        before + 1,
        "recorded as what the seam ACTED on (an abstain), not as a decision"
    );
}

/// RULING (3), boundary: just below the floor BLOCKS; exactly at the
/// floor PERMITS, carrying the confidence and the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_confidence_floor_is_inclusive_and_binding() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    mount_generative(&generative, "summary").await;
    let db = tmpdir();

    // Just below the floor: BLOCK, naming the number.
    let below = MockServer::start().await;
    let just_below = CONSOLIDATION_MERGE_CONFIDENCE_FLOOR - 0.01;
    mount_verdict(&below, "yes", just_below).await;
    let cfg = cfg_with_decision(&below.uri(), &generative.uri(), DecisionFallback::Abstain);
    let client = client_for(&cfg, &generative.uri(), db.path());
    let judgement = client.judge_merge(&members()).expect("not an error");
    match judgement {
        MergeJudgement::Block {
            reason:
                MergeBlockReason::LowConfidence {
                    confidence: Some(c),
                },
            ..
        } => assert!((c - just_below).abs() < 1e-6, "reported confidence {c}"),
        other => panic!("just below the floor must block as low-confidence, got {other:?}"),
    }

    // Exactly at the floor: PERMIT.
    let at = MockServer::start().await;
    mount_verdict(&at, "yes", CONSOLIDATION_MERGE_CONFIDENCE_FLOOR).await;
    let cfg = cfg_with_decision(&at.uri(), &generative.uri(), DecisionFallback::Abstain);
    let client = client_for(&cfg, &generative.uri(), db.path());
    let before = outcome_count(SEAM, "decided");
    let judgement = client.judge_merge(&members()).expect("not an error");
    match judgement {
        MergeJudgement::Permit { confidence, source } => {
            assert!(
                (confidence - CONSOLIDATION_MERGE_CONFIDENCE_FLOOR).abs() < 1e-6,
                "the permit carries the confidence that cleared the floor: {confidence}"
            );
            assert_eq!(source, DecisionSource::DecisionModel);
        }
        other => panic!("at the floor must permit, got {other:?}"),
    }
    assert!(judgement.permits());
    assert_eq!(outcome_count(SEAM, "decided"), before + 1);
    assert_eq!(
        hits(&generative).await,
        0,
        "the judge itself never summarises"
    );
}

// ============================================================== funnel pins

/// The whole funnel, ABSENCE: with the judge deciding NO the admitted pair
/// is NOT consolidated — both sources survive, no `[consolidated]` row,
/// the summariser is never called, and the report counts the block with
/// its source label.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funnel_a_confident_no_withholds_the_consolidation() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "no", 0.95).await;
    mount_generative(&generative, "merged summary").await;
    let dir = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), dir.path());
    let (conn, candidates) = store_with_admitted_pair(dir.path());

    let report = tokio::task::block_in_place(|| {
        run_autonomy_passes(&conn, &client, &candidates, false, false, usize::MAX, None)
    });

    assert_eq!(
        report.clusters_formed, 1,
        "the two fixed gates admit the pair"
    );
    assert_eq!(mj(&report).blocked, 1, "{report:?}");
    assert_eq!(mj(&report).permitted, 0);
    assert_eq!(report.memories_consolidated, 0, "nothing merged");
    assert_eq!(
        mj(&report)
            .sources
            .get(DecisionSource::DecisionModel.as_str()),
        Some(&1),
        "the report labels WHO decided: {:?}",
        mj(&report).sources
    );
    assert!(
        row_exists(&conn, "w4-a") && row_exists(&conn, "w4-b"),
        "sources untouched"
    );
    assert_eq!(consolidated_rows(&conn), 0);
    assert_eq!(
        hits(&generative).await,
        0,
        "a blocked cluster costs no summary call"
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// The whole funnel, PRESENCE control on the same sinks: a confident YES
/// consolidates — sources gone, one `[consolidated]` row, the summariser
/// called once, the permit counted and labelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funnel_a_confident_yes_lets_the_consolidation_proceed() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "yes", 0.95).await;
    mount_generative(&generative, "merged summary").await;
    let dir = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), dir.path());
    let (conn, candidates) = store_with_admitted_pair(dir.path());

    let report = tokio::task::block_in_place(|| {
        run_autonomy_passes(&conn, &client, &candidates, false, false, usize::MAX, None)
    });

    assert_eq!(report.clusters_formed, 1);
    assert_eq!(mj(&report).permitted, 1, "{report:?}");
    assert_eq!(mj(&report).blocked, 0);
    assert_eq!(report.memories_consolidated, 2);
    assert_eq!(
        mj(&report)
            .sources
            .get(DecisionSource::DecisionModel.as_str()),
        Some(&1)
    );
    assert!(
        !row_exists(&conn, "w4-a") && !row_exists(&conn, "w4-b"),
        "sources merged away"
    );
    assert_eq!(consolidated_rows(&conn), 1);
    assert_eq!(
        hits(&generative).await,
        1,
        "one summary call for the permitted cluster"
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// `[decision]` UNSET is byte-identical v1.0.0 on the funnel: the pair
/// merges exactly as before, and the three judge counters are at their
/// zero values — no judge was consulted, so nothing is labelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funnel_unset_merges_as_v100_with_zero_judge_counters() {
    let _serialized = serialize().await;
    let generative = MockServer::start().await;
    mount_generative(&generative, "merged summary").await;
    let dir = tmpdir();
    let cfg = cfg_generative_only(&generative.uri());
    let client = client_for(&cfg, &generative.uri(), dir.path());
    let (conn, candidates) = store_with_admitted_pair(dir.path());

    let report = tokio::task::block_in_place(|| {
        run_autonomy_passes(&conn, &client, &candidates, false, false, usize::MAX, None)
    });

    assert_eq!(
        report.memories_consolidated, 2,
        "v1.0.0 behaviour: the pair merges"
    );
    assert_eq!(mj(&report).blocked, 0);
    assert_eq!(mj(&report).permitted, 0, "no judge => not a permit");
    assert!(mj(&report).sources.is_empty());
    assert!(report.merge_judge.is_none(), "unset: no judge report key");
    assert!(report.judge_preview.is_none(), "unset: no preview key");
    // GOLDEN — the serialized unset report is the v1.0.0 key set exactly:
    // no new default-zero key, no judge key of any spelling.
    let serialized = serde_json::to_value(&report).expect("serialize");
    // `to_value` sorts map keys, so compare the SET against the frozen
    // ten (sorted the same way); the struct's own field ORDER is what
    // `to_string` streams, and it is unchanged too — the W4 fields sit
    // behind `skip_serializing_if`, so when absent they leave no trace.
    let mut keys: Vec<&str> = serialized
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut golden: Vec<&str> = UNSET_REPORT_KEYS_GOLDEN.to_vec();
    golden.sort_unstable();
    assert_eq!(keys, golden, "unset must be byte-identical: {serialized}");
    let streamed = serde_json::to_string(&report).expect("serialize");
    assert!(
        !streamed.contains("judge"),
        "no judge key in an unset report (streamed): {streamed}"
    );
    assert_eq!(consolidated_rows(&conn), 1);
}

/// RULING (2): a DRY RUN consults the judge and labels the source — it
/// previews what the live run would do — while writing nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funnel_dry_run_consults_the_judge_and_writes_nothing() {
    // D4: a dry run reports the judge under `judge_preview`, never under
    // `merge_judge` — a preview labelled by source and block reason, not
    // a claim that any hook would permit. Asserted at the end of this test.
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "no", 0.95).await;
    mount_generative(&generative, "merged summary").await;
    let dir = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), dir.path());
    let (conn, candidates) = store_with_admitted_pair(dir.path());

    let report = tokio::task::block_in_place(|| {
        run_autonomy_passes(&conn, &client, &candidates, true, false, usize::MAX, None)
    });

    assert_eq!(hits(&decision).await, 1, "the dry run ASKS the judge");
    assert_eq!(mj(&report).blocked, 1, "{report:?}");
    assert_eq!(
        mj(&report)
            .sources
            .get(DecisionSource::DecisionModel.as_str()),
        Some(&1),
        "the dry-run report labels the DecisionSource"
    );
    assert!(row_exists(&conn, "w4-a") && row_exists(&conn, "w4-b"));
    assert_eq!(consolidated_rows(&conn), 0, "a dry run writes nothing");
    assert!(
        report.merge_judge.is_none(),
        "D4: a dry run carries no real-run judge key"
    );
    assert!(
        report.judge_preview.is_some(),
        "D4: a dry run carries the labelled preview"
    );
}

/// NEVER WIDENS: a pair the COSINE gate refuses is never shown to the
/// judge, even when the judge would say a confident yes. The judge runs
/// strictly downstream of both fixed gates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn funnel_a_pair_refused_by_cosine_never_reaches_the_judge() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "yes", 0.99).await;
    mount_generative(&generative, "merged summary").await;
    let dir = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), dir.path());
    let (conn, candidates) = store_with_refused_pair(dir.path());

    let report = tokio::task::block_in_place(|| {
        run_autonomy_passes(&conn, &client, &candidates, false, false, usize::MAX, None)
    });

    assert_eq!(report.clusters_formed, 0, "cosine refused the pair");
    assert_eq!(
        hits(&decision).await,
        0,
        "the judge is never consulted about a refused pair"
    );
    assert_eq!(mj(&report).permitted, 0);
    assert_eq!(report.memories_consolidated, 0);
    assert!(row_exists(&conn, "w4-a") && row_exists(&conn, "w4-b"));
}

// ============================================================ R9 breaker

/// The merge seam shares the per-surface circuit breaker (#3806 R9): a
/// DEAD decision endpoint (503) is dialled exactly `BREAKER_THRESHOLD`
/// times, then the breaker answers for it — and every call still BLOCKS
/// as `unavailable`, so the breaker changed the cost of the outage on a
/// consolidation sweep, never its outcome. The generative endpoint is
/// never reached under `abstain`. At the parent (no breaker consult in
/// `judge_merge`) every call dials the dead endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_decider_stops_being_dialled_on_the_merge_seam_too() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DECISION_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&decision)
        .await;
    mount_generative(&generative, "yes").await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let client = client_for(&cfg, &generative.uri(), db.path());

    let sweep = usize::try_from(BREAKER_THRESHOLD).expect("small") * 2;
    for i in 0..sweep {
        let judgement = client
            .judge_merge(&members())
            .expect("abstain posture is not an error");
        assert!(
            matches!(
                judgement,
                MergeJudgement::Block {
                    reason: MergeBlockReason::Unavailable(_),
                    ..
                }
            ),
            "cluster {i}: an outage blocks, breaker open or not, got {judgement:?}"
        );
    }
    assert_eq!(
        hits(&decision).await,
        usize::try_from(BREAKER_THRESHOLD).expect("small"),
        "after {BREAKER_THRESHOLD} consecutive outages the merge seam must stop dialling a dead \
         endpoint for every cluster of the sweep (#3806 R9)"
    );
    assert_eq!(hits(&generative).await, 0, "`abstain` never reaches [llm]");
}

// ======================================================= structural census

/// Every PRODUCTION `impl AutonomyLlm` either overrides `judge_merge` or
/// does not exist. The trait default is `NoDecider` — the PERMISSIVE arm
/// — so a forwarding wrapper that forgets the method would silently run
/// the v1.0.0 body with no judge while every behavioural pin above
/// (which constructs `OllamaClient` directly) stayed green. The two
/// production impls today are `OllamaClient` (the seam) and the
/// hot-reload `SwappableLlm` (which must map a `None` handle to Block).
/// A `mod tests` impl is a stub and is exempt: it is the caller's
/// scripted judge, not a production path.
#[test]
fn every_production_autonomy_llm_impl_overrides_judge_merge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    let mut production_impls = Vec::new();
    let mut missing = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        // Everything at or below the first test module is stub territory.
        let production = text
            .lines()
            .take_while(|l| !l.trim_start().starts_with("mod tests"))
            .fold(String::new(), |mut acc, l| {
                acc.push_str(l);
                acc.push('\n');
                acc
            });
        let mut rest = production.as_str();
        while let Some(at) = rest.find("impl AutonomyLlm for ") {
            let block = &rest[at..];
            // The impl body ends at the first line that is exactly `}`.
            let end = block.find("\n}\n").unwrap_or(block.len());
            let body = &block[..end];
            let name = body["impl AutonomyLlm for ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("?")
                .to_string();
            let rel = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .display()
                .to_string();
            production_impls.push(format!("{rel}::{name}"));
            if !body.contains("fn judge_merge(") {
                missing.push(format!("{rel}::{name}"));
            }
            rest = &block[end..];
        }
    }
    assert!(
        production_impls.len() >= 2,
        "the census must see both production impls (OllamaClient, SwappableLlm), saw {production_impls:?}"
    );
    assert!(
        missing.is_empty(),
        "production `impl AutonomyLlm` without a `judge_merge` override — the trait default is \
         the PERMISSIVE `NoDecider` arm, a fail-open on the delete-the-sources path: {missing:?} \
         (impls seen: {production_impls:?})"
    );
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `DecisionProvider::judge_primary` BODY in `src/` forwards to a
/// `judge_primary` (a wrapper/chain) or to its OWN `self.judge` (a leaf) —
/// never to some inner value's `judge`. The method is REQUIRED, so a
/// wrapper cannot omit it; this pin closes the residual the compiler
/// cannot see: a wrapper written as `self.inner.judge(prompt)`, which
/// would silently restore the chain's generative leg — the zero-value
/// egress #3806 W4 removes — while every verdict pin still passed
/// (the seam's `GenerativeFallback → Block` arm guards the VERDICT, not
/// the CALL). Offered by f2r's review; same shape as the `judge_merge`
/// census above.
#[test]
fn every_judge_primary_body_forwards_to_judge_primary_or_its_own_judge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    let mut bodies_seen = 0usize;
    let mut impls_seen = 0usize;
    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        // The expected body count is DERIVED from the same tree: one per
        // `impl DecisionProvider for`. A hardcoded floor would pass 6-of-7
        // if a seventh impl spelled the signature in a way the selector
        // below does not match (f2r's review of the draft).
        impls_seen += text.matches("impl DecisionProvider for ").count();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("fn judge_primary(") {
            let after = &rest[at..];
            // A trait DECLARATION (`... -> Judgement;`) has no body.
            let sig_end = after.find(['{', ';']).unwrap_or(after.len());
            if after[..sig_end].contains("&self") && after.as_bytes().get(sig_end) == Some(&b'{') {
                // Body = balanced braces from the first `{`.
                let mut depth = 0i32;
                let mut end = sig_end;
                for (i, ch) in after[sig_end..].char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = sig_end + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let body = &after[sig_end..end];
                bodies_seen += 1;
                // Every `.judge(` in the body must be `self.judge(` — the
                // implementor's OWN judge (a leaf). Any other receiver is a
                // wrapper forwarding to the wrong method.
                let mut wrong = false;
                let mut scan = body;
                while let Some(pos) = scan.find(".judge(") {
                    let prefix = &scan[..pos];
                    if !prefix.ends_with("self") {
                        wrong = true;
                    }
                    scan = &scan[pos + ".judge(".len()..];
                }
                let forwards = body.contains("self.judge(") || body.contains(".judge_primary(");
                if wrong || !forwards {
                    offenders.push(format!("{rel}: {}", body.trim()));
                }
                rest = &after[end..];
            } else {
                rest = &after[sig_end..];
            }
        }
    }
    assert!(
        impls_seen >= 6,
        "the walk must see the whole tree (six `impl DecisionProvider for` today), saw {impls_seen}"
    );
    assert_eq!(
        bodies_seen, impls_seen,
        "every `impl DecisionProvider for` must contribute exactly one `fn judge_primary(` body the \
         selector can see — a count mismatch means an impl the census did not read"
    );
    assert!(
        offenders.is_empty(),
        "a `judge_primary` body forwards to an INNER `judge` (or to nothing) — that silently \
         restores the generative leg on the merge seam: {offenders:?}"
    );
}

/// The merge judge is consulted from EXACTLY the two autonomous
/// consolidation funnels — the curator's Pass-1 (`src/autonomy.rs`) and
/// the SAL `ConsolidationPass` (`src/curator/compaction.rs`) — plus the
/// hot-reload wrapper's forward (`src/reload.rs`) and its own definition
/// site. The operator-EXPLICIT consolidations (MCP `memory_consolidate`,
/// CLI `consolidate`, HTTP `power_consolidation`) and the federation
/// receive path must NEVER call it: the judge narrows the substrate's own
/// merges, not an operator's instruction (W125 READY §8 audit item).
#[test]
fn judge_merge_is_called_only_from_the_two_autonomous_funnels() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    let mut callers: Vec<String> = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        let production: String = text
            .lines()
            .take_while(|l| !l.trim_start().starts_with("mod tests"))
            .filter(|l| !l.trim_start().starts_with("//"))
            .fold(String::new(), |mut acc, l| {
                acc.push_str(l);
                acc.push('\n');
                acc
            });
        if production.contains(".judge_merge(") || production.contains("::judge_merge(") {
            let rel = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .display()
                .to_string();
            callers.push(rel);
        }
    }
    let expected = ["autonomy.rs", "curator/compaction.rs", "reload.rs"];
    assert_eq!(
        callers, expected,
        "the merge judge may be consulted only by the two autonomous funnels and the reload \
         forward — an operator-explicit consolidation or a federation path must not appear here"
    );
    for forbidden in [
        "mcp/tools/consolidate.rs",
        "cli/consolidate.rs",
        "handlers/power_consolidation.rs",
    ] {
        let path = root.join(forbidden);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{forbidden}: {e}"));
        assert!(
            !text.contains("judge_merge"),
            "{forbidden}: an operator-explicit consolidation must not consult the merge judge"
        );
    }
}

/// The landed-base ruling: the threshold's home is the seam table,
/// READABLE THROUGH `/capabilities`. With `[decision]` configured the boot
/// report carries `confidence_floors` keyed by seam token — the merge
/// seam at its posture, 0.80 — and serializes it under that key; with
/// `[decision]` unset there is no report at all (pinned elsewhere), so the
/// unset envelope is byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capabilities_report_carries_the_declared_seam_floors() {
    let _serialized = serialize().await;
    let decision = MockServer::start().await;
    let generative = MockServer::start().await;
    mount_verdict(&decision, "yes", 0.95).await;
    let db = tmpdir();
    let cfg = cfg_with_decision(
        &decision.uri(),
        &generative.uri(),
        DecisionFallback::Abstain,
    );
    let _client = client_for(&cfg, &generative.uri(), db.path());
    let report = ai_memory::decision_boot::boot_report().expect("configured: a report exists");
    assert!(
        (report.confidence_floors["consolidation_merge"] - CONSOLIDATION_MERGE_CONFIDENCE_FLOOR)
            .abs()
            < f64::EPSILON,
        "{:?}",
        report.confidence_floors
    );
    let json = serde_json::to_value(&report).expect("serialize");
    assert_eq!(
        json["confidence_floors"]["consolidation_merge"], 0.80,
        "{json}"
    );
    assert!(
        json["confidence_floors"].get("classify_kind").is_none(),
        "undeclared seams are absent"
    );
}
