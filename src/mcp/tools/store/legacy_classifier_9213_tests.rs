// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9213 — every best-effort consumer of the typed LLM reply errors records
//! a degraded outcome that is told apart from a clean verdict.
//!
//! One table, reply form x consumer, exact outcomes. The consumers are the
//! MCP store autonomy hooks (`auto_tag`, the legacy per-pair
//! `detect_contradiction` loop) and the `memory_session_start` summary.
//! Each cell gets a fresh chat endpoint and a fresh client, so the circuit
//! breaker of one cell never leaks into the next.
//!
//! The b29 ruling fcf51b14 (response-only) is pinned cell by cell: the
//! marker is on the response, never in the stored row (Z-2); it is absent,
//! not null or empty, on a clean answer (Z-5); a contradiction entry names
//! the candidate only to a caller who can read it (Z-6); each failure emits
//! one structured WARN without provider text (Z-3); `autonomy_hook_skipped`
//! keeps its eligibility-gate-only scalar shape (Z-4).

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{maybe_run_autonomy_hooks, merge_autonomy_outcome_into_response};
use crate::llm::OllamaClient;
use crate::models::{GovernancePolicy, Memory, Tier};
use crate::storage as db;

/// Wire path of the Ollama chat endpoint.
const OLLAMA_CHAT: &str = "/api/chat";
/// Model name handed to the client under test.
const TEST_MODEL: &str = "degraded-9213-model";
/// Namespace of the seeded memories.
const TEST_NS: &str = "degraded-9213";
/// Wire key of the store-hook degraded marker (never a metadata key).
const KEY_HOOK_DEGRADED: &str = "autonomy_hook_degraded";
/// Wire key of the session-start summary degraded marker.
const KEY_SUMMARY_DEGRADED: &str = "summary_degraded";
/// Content of the new memory and of the candidate. Both share subject
/// tokens so the F-L1 precheck hands the pair to the model.
const NEW_CONTENT: &str = "The deploy pipeline pins region east for every production rollout";
const CANDIDATE_CONTENT: &str = "The deploy pipeline pins region west for every production rollout";

/// The chat reply of one table row.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// HTTP 200 with this Ollama chat body.
    Body(fn() -> Value),
    /// HTTP 500 (an LLM failure that is not a typed reply form).
    ServerError,
}

/// One consumer of the typed reply errors.
#[derive(Clone, Copy, Debug)]
enum Consumer {
    AutoTagHook,
    ContradictionHook,
    SessionStart,
}

const CONSUMERS: [Consumer; 3] = [
    Consumer::AutoTagHook,
    Consumer::ContradictionHook,
    Consumer::SessionStart,
];

/// Expected outcome per consumer: `Ok(value)` is the clean answer the
/// consumer records, `Err(code)` the degraded reason code.
struct Row {
    form: &'static str,
    answer: Answer,
    auto_tag: Result<&'static str, &'static str>,
    contradiction: Result<bool, &'static str>,
    summary: Result<&'static str, &'static str>,
}

fn ollama(content: Option<&str>, done: bool, stop: Option<&str>) -> Value {
    let mut b = json!({"message": {}, "done": done});
    if let Some(c) = content {
        b["message"]["content"] = json!(c);
    }
    if let Some(s) = stop {
        b["done_reason"] = json!(s);
    }
    b
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            form: "clean yes",
            answer: Answer::Body(|| ollama(Some("yes"), true, Some("stop"))),
            auto_tag: Ok("yes"),
            contradiction: Ok(true),
            summary: Ok("yes"),
        },
        Row {
            form: "clean no",
            answer: Answer::Body(|| ollama(Some("no"), true, Some("stop"))),
            auto_tag: Ok("no"),
            contradiction: Ok(false),
            summary: Ok("no"),
        },
        Row {
            form: "truncated",
            answer: Answer::Body(|| ollama(Some("yes"), true, Some("length"))),
            auto_tag: Err("reply_truncated"),
            contradiction: Err("reply_truncated"),
            summary: Err("reply_truncated"),
        },
        Row {
            form: "filtered",
            answer: Answer::Body(|| ollama(Some("yes"), true, Some("content_filter"))),
            auto_tag: Err("reply_filtered"),
            contradiction: Err("reply_filtered"),
            summary: Err("reply_filtered"),
        },
        Row {
            form: "done false",
            answer: Answer::Body(|| ollama(Some("yes"), false, Some("stop"))),
            auto_tag: Err("reply_not_done"),
            contradiction: Err("reply_not_done"),
            summary: Err("reply_not_done"),
        },
        Row {
            form: "no stop reason",
            answer: Answer::Body(|| ollama(Some("yes"), true, None)),
            auto_tag: Err("reply_no_stop_reason"),
            contradiction: Err("reply_no_stop_reason"),
            summary: Err("reply_no_stop_reason"),
        },
        Row {
            form: "load",
            answer: Answer::Body(|| ollama(Some("yes"), true, Some("load"))),
            auto_tag: Err("reply_unrecognised_stop"),
            contradiction: Err("reply_unrecognised_stop"),
            summary: Err("reply_unrecognised_stop"),
        },
        Row {
            form: "tool stop",
            answer: Answer::Body(|| ollama(Some("yes"), true, Some("tool_calls"))),
            auto_tag: Err("reply_tool_stop"),
            contradiction: Err("reply_tool_stop"),
            summary: Err("reply_tool_stop"),
        },
        Row {
            form: "blank",
            answer: Answer::Body(|| ollama(Some(" \n "), true, Some("stop"))),
            auto_tag: Err("reply_empty"),
            contradiction: Err("reply_empty"),
            summary: Err("reply_empty"),
        },
        Row {
            form: "no content",
            answer: Answer::Body(|| ollama(None, true, Some("stop"))),
            auto_tag: Err("reply_no_content"),
            contradiction: Err("reply_no_content"),
            summary: Err("reply_no_content"),
        },
        Row {
            form: "ambiguous verdict",
            answer: Answer::Body(|| ollama(Some("maybe"), true, Some("stop"))),
            auto_tag: Ok("maybe"),
            contradiction: Err("verdict_unclassifiable"),
            summary: Ok("maybe"),
        },
        Row {
            form: "http 500",
            answer: Answer::ServerError,
            auto_tag: Err("llm_error"),
            contradiction: Err("llm_error"),
            summary: Err("llm_error"),
        },
    ]
}

async fn serve(answer: Answer) -> MockServer {
    let server = MockServer::start().await;
    let template = match answer {
        Answer::Body(make) => ResponseTemplate::new(200).set_body_json(make()),
        Answer::ServerError => ResponseTemplate::new(500).set_body_string("boom"),
    };
    Mock::given(method("POST"))
        .and(path(OLLAMA_CHAT))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

/// A memory of `TEST_NS`. Distinct titles keep the `(title, namespace)`
/// upsert of `db::insert` from merging the candidate into the new row.
fn memory(title: &str, content: &str) -> Memory {
    memory_with(title, content, json!({"agent_id": "ai:test"}))
}

/// [`memory`] with explicit row metadata (owner and scope for Z-6).
fn memory_with(title: &str, content: &str, metadata: Value) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: TEST_NS.to_string(),
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
        metadata,
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    }
}

/// What one consumer recorded: the response envelope and, for the store
/// hooks, the persisted metadata of the new memory.
struct Recorded {
    response: Value,
    metadata: Value,
    candidate_id: String,
}

fn run_store_hooks(uri: &str, legacy_pairs: bool) -> Recorded {
    run_store_hooks_as(uri, legacy_pairs, None, json!({"agent_id": "ai:test"}))
}

/// [`run_store_hooks`] with the read caller of the store request and the
/// metadata (owner and scope) of the candidate row.
fn run_store_hooks_as(
    uri: &str,
    legacy_pairs: bool,
    read_caller: Option<&str>,
    candidate_metadata: Value,
) -> Recorded {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    let candidate = memory_with("deploy region west", CANDIDATE_CONTENT, candidate_metadata);
    let candidate_id = db::insert(&conn, &candidate).expect("insert candidate");
    let mem = memory("deploy region east", NEW_CONTENT);
    let actual_id = db::insert(&conn, &mem).expect("insert new");
    assert_ne!(actual_id, candidate_id, "the two seeds must be two rows");
    let existing = if legacy_pairs {
        vec![db::get(&conn, &candidate_id).expect("get").expect("row")]
    } else {
        Vec::new()
    };
    let mut policy = GovernancePolicy::default();
    policy.synthesis.legacy_per_pair_classifier = Some(legacy_pairs);
    let client = OllamaClient::new_with_url_no_health_check(uri, TEST_MODEL).expect("client");
    let outcome = maybe_run_autonomy_hooks(
        &conn,
        &client,
        &mem,
        &actual_id,
        &existing,
        &policy,
        read_caller,
    );
    let mut response = json!({"id": actual_id});
    merge_autonomy_outcome_into_response(&mut response, &outcome);
    let metadata = db::get(&conn, &actual_id)
        .expect("get")
        .expect("row")
        .metadata;
    Recorded {
        response,
        metadata,
        candidate_id,
    }
}

fn run_session_start(uri: &str) -> Value {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    db::insert(&conn, &memory("deploy region east", NEW_CONTENT)).expect("insert");
    let client = OllamaClient::new_with_url_no_health_check(uri, TEST_MODEL).expect("client");
    crate::mcp::handle_session_start(&conn, &json!({"namespace": TEST_NS}), Some(&client), None)
        .expect("session_start never fails on an LLM error")
}

/// The hook marker array of the response. Z-2: the stored row read back
/// never carries the key, whatever the cell; Z-5: when present it is a
/// non-empty array (never null, never `[]`).
fn hook_marker(rec: &Recorded, cell: &str) -> Option<Value> {
    assert_eq!(
        rec.metadata.get(KEY_HOOK_DEGRADED),
        None,
        "{cell}: the degraded marker must never be written to row metadata"
    );
    let on_wire = rec.response.get(KEY_HOOK_DEGRADED).cloned();
    if let Some(m) = &on_wire {
        assert!(
            m.as_array().is_some_and(|a| !a.is_empty()),
            "{cell}: a present marker is a non-empty array, got {m}"
        );
    }
    on_wire
}

/// The `auto_tag` entry a row's reply produces, if that hook degrades.
fn auto_tag_entry(row: &Row) -> Option<Value> {
    row.auto_tag
        .err()
        .map(|code| json!({"hook": "auto_tag", "reason": code}))
}

fn check_auto_tag(row: &Row, rec: &Recorded, cell: &str) {
    let marker = hook_marker(rec, cell);
    match row.auto_tag {
        Ok(tag) => {
            assert_eq!(rec.response["auto_tags"], json!([tag]), "{cell}");
            assert_eq!(rec.metadata["auto_tags"], json!([tag]), "{cell}");
            assert_eq!(marker, None, "{cell}: a clean answer has no marker");
        }
        Err(code) => {
            assert_eq!(rec.response.get("auto_tags"), None, "{cell}");
            assert_eq!(rec.metadata.get("auto_tags"), None, "{cell}");
            assert_eq!(
                marker,
                Some(json!([{"hook": "auto_tag", "reason": code}])),
                "{cell}"
            );
        }
    }
}

fn check_contradiction(row: &Row, rec: &Recorded, cell: &str) {
    let marker = hook_marker(rec, cell);
    let confirmed = rec.response.get("confirmed_contradictions").cloned();
    // The exact, whole marker: the auto_tag entry (when that hook degraded)
    // followed by the contradiction entry (when the verdict degraded).
    let mut expected: Vec<Value> = auto_tag_entry(row).into_iter().collect();
    match row.contradiction {
        Ok(true) => assert_eq!(confirmed, Some(json!([rec.candidate_id])), "{cell}"),
        Ok(false) => assert_eq!(confirmed, None, "{cell}"),
        Err(code) => {
            assert_eq!(confirmed, None, "{cell}");
            expected.push(json!({
                "hook": "detect_contradiction",
                "candidate_id": rec.candidate_id,
                "reason": code,
            }));
        }
    }
    let expected = (!expected.is_empty()).then(|| Value::Array(expected));
    assert_eq!(marker, expected, "{cell}");
}

fn check_session_start(row: &Row, response: &Value, cell: &str) {
    match row.summary {
        Ok(text) => {
            assert_eq!(response["summary"], json!(text), "{cell}");
            assert_eq!(response.get(KEY_SUMMARY_DEGRADED), None, "{cell}");
        }
        Err(code) => {
            assert_eq!(response.get("summary"), None, "{cell}");
            assert_eq!(response[KEY_SUMMARY_DEGRADED], json!(code), "{cell}");
        }
    }
    assert_eq!(
        response["count"],
        json!(1),
        "{cell}: the response stays whole"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn degraded_9213_every_consumer_records_every_reply_error() {
    for row in rows() {
        for consumer in CONSUMERS {
            let cell = format!("{}/{consumer:?}", row.form);
            let server = serve(row.answer).await;
            let uri = server.uri();
            let recorded = tokio::task::spawn_blocking(move || match consumer {
                Consumer::AutoTagHook => (Some(run_store_hooks(&uri, false)), None),
                Consumer::ContradictionHook => (Some(run_store_hooks(&uri, true)), None),
                Consumer::SessionStart => (None, Some(run_session_start(&uri))),
            })
            .await
            .expect("consumer cell joins");
            match (consumer, recorded) {
                (Consumer::AutoTagHook, (Some(rec), None)) => check_auto_tag(&row, &rec, &cell),
                (Consumer::ContradictionHook, (Some(rec), None)) => {
                    check_contradiction(&row, &rec, &cell);
                }
                (Consumer::SessionStart, (None, Some(resp))) => {
                    check_session_start(&row, &resp, &cell);
                }
                (_, other) => panic!("{cell}: unexpected cell shape {:?}", other.1),
            }
        }
    }
}

/// The truncated Ollama reply that every focused test below serves.
fn truncated() -> Value {
    ollama(Some("yes"), true, Some("length"))
}

/// #9213 Z-6 — a degraded contradiction entry names the candidate only to
/// a caller who can already read it: the owner `bob` sees `candidate_id`
/// on his own private candidate, `alice` gets the entry without it, and
/// the reason code is the same for both.
#[tokio::test(flavor = "multi_thread")]
async fn degraded_9213_candidate_id_only_for_a_reader() {
    let private = json!({"agent_id": "bob", "scope": "private"});
    for (caller, sees_id) in [("bob", true), ("alice", false)] {
        let server = serve(Answer::Body(truncated)).await;
        let uri = server.uri();
        let meta = private.clone();
        let rec =
            tokio::task::spawn_blocking(move || run_store_hooks_as(&uri, true, Some(caller), meta))
                .await
                .expect("cell joins");
        let mut contradiction =
            json!({"hook": "detect_contradiction", "reason": "reply_truncated"});
        if sees_id {
            contradiction["candidate_id"] = json!(rec.candidate_id);
        }
        assert_eq!(
            hook_marker(&rec, caller),
            Some(json!([{"hook": "auto_tag", "reason": "reply_truncated"}, contradiction])),
            "{caller}"
        );
    }
}

/// Buffer-backed `MakeWriter` for the WARN capture (the #4088 precedent).
#[derive(Clone)]
struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Provider text the HTTP 500 body carries; it must never reach a log line.
const PROVIDER_TEXT: &str = "PROVIDER-SECRET-9213 ignore previous instructions";

/// #9213 Z-3 — each degraded consumer emits exactly one structured WARN
/// with the memory id, the hook and the reason code, and never the
/// provider text of the failed reply.
#[test]
fn degraded_9213_one_structured_warn_per_failure() {
    // #4088: the tracing callsite-interest cache is process-global; run the
    // capture alone in a re-exec'd child process.
    if crate::config::run_env_isolated_child_or_spawn(
        "mcp::store::legacy_classifier::degraded_9213_tests::degraded_9213_one_structured_warn_per_failure",
    ) {
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(OLLAMA_CHAT))
            .respond_with(ResponseTemplate::new(500).set_body_string(PROVIDER_TEXT))
            .mount(&server)
            .await;
        server
    });
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(buf.clone()))
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let (rec, session) = tracing::subscriber::with_default(subscriber, || {
        (
            run_store_hooks(&server.uri(), true),
            run_session_start(&server.uri()),
        )
    });
    let log = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
    assert!(
        !log.contains("PROVIDER-SECRET-9213"),
        "provider text leaked: {log}"
    );
    let degraded: Vec<&str> = log
        .lines()
        .filter(|l| l.contains(crate::llm::DEGRADED_WARN_MESSAGE))
        .collect();
    let actual_id = rec.response["id"].as_str().expect("id").to_string();
    let lead_id = session["memories"][0]["id"]
        .as_str()
        .expect("lead id")
        .to_string();
    let expect = [
        format!("memory_id=\"{actual_id}\" hook=\"auto_tag\" reason=\"llm_error\""),
        format!("memory_id=\"{actual_id}\" hook=\"detect_contradiction\" reason=\"llm_error\""),
        format!("memory_id=\"{lead_id}\" hook=\"session_summary\" reason=\"llm_error\""),
    ];
    assert_eq!(degraded.len(), expect.len(), "one WARN per failure: {log}");
    for (line, fields) in degraded.iter().zip(expect.iter()) {
        assert!(line.contains(" WARN "), "{line}");
        assert!(line.contains(fields.as_str()), "{line} lacks {fields}");
    }
    assert_eq!(session[KEY_SUMMARY_DEGRADED], json!("llm_error"));
    drop(rt);
}

/// The `handle_store` entry point with the default atomisation wiring.
///
/// Called only inside the isolated child of
/// [`degraded_9213_store_handler_marker_and_skip_reason`], whose environment
/// has the attestation knob removed, so the MCP write surface runs on its
/// compiled default and no process environment variable is written here.
fn store_via_handler(params: &Value, llm: Option<&OllamaClient>) -> Value {
    let conn = db::open(std::path::Path::new(":memory:")).expect("open");
    let resp = super::super::handle_store(
        &conn,
        std::path::Path::new(":memory:"),
        params,
        None,
        llm,
        None,
        &crate::config::ResolvedTtl::default(),
        true,
        None,
        None,
        None,
        crate::hooks::pre_store::AtomiseWiring::default(),
    )
    .expect("store never fails on an LLM error");
    // Z-2 through the whole handler: the committed row has no marker.
    let id = resp["id"].as_str().expect("id");
    let row = db::get(&conn, id).expect("get").expect("row");
    assert_eq!(
        row.metadata.get(KEY_HOOK_DEGRADED),
        None,
        "row metadata: {}",
        row.metadata
    );
    resp
}

/// #9213 Z-1, Z-2, Z-4 and Z-5 through `handle_store`: a failed hook puts
/// the exact marker on the response and nothing in the row, leaving
/// `autonomy_hook_skipped` absent; an eligibility-gate skip keeps its
/// scalar `autonomy_hook_skipped` and has no degraded key at all.
///
/// #3523 arm (e): the handler runs in an isolated child process that starts
/// with the attestation knob removed (the `config::shape` #2967 precedent),
/// so the test writes no process-global environment variable into the
/// shared lib test binary.
#[test]
fn degraded_9213_store_handler_marker_and_skip_reason() {
    if crate::test_support::run_env_isolated_child_or_spawn_scrubbing(
        "mcp::store::legacy_classifier::degraded_9213_tests::degraded_9213_store_handler_marker_and_skip_reason",
        &[crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION],
    ) {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let params =
        json!({"title": "deploy region east", "content": NEW_CONTENT, "namespace": TEST_NS});
    let server = rt.block_on(serve(Answer::Body(truncated)));
    // The handler is synchronous; it runs on this plain test thread while
    // the mock endpoint is served by the runtime's worker threads.
    let client =
        OllamaClient::new_with_url_no_health_check(&server.uri(), TEST_MODEL).expect("client");
    let degraded = store_via_handler(&params, Some(&client));
    assert_eq!(
        degraded[KEY_HOOK_DEGRADED],
        json!([{"hook": "auto_tag", "reason": "reply_truncated"}])
    );
    assert_eq!(degraded.get("autonomy_hook_skipped"), None);
    assert_eq!(degraded.get("auto_tags"), None);

    let skipped = store_via_handler(&params, None);
    assert_eq!(skipped["autonomy_hook_skipped"], json!("no_llm"));
    assert_eq!(skipped.get(KEY_HOOK_DEGRADED), None);
    drop(server);
    drop(rt);
}

/// #9213 Z-5 — one serializer: the two wire keys are spelled only in
/// `field_names.rs` (production) and in this pinning test, so the MCP
/// store, the MCP session start and the HTTP session start (which calls
/// the same `handle_session_start`) cannot drift apart.
#[test]
fn degraded_9213_keys_have_one_spelling() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    let mut hits: Vec<String> = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read");
                if text.contains("\"autonomy_hook_degraded\"")
                    || text.contains("\"summary_degraded\"")
                {
                    let rel = path.strip_prefix(&root).expect("under src");
                    hits.push(rel.to_string_lossy().into_owned());
                }
            }
        }
    }
    hits.sort();
    assert_eq!(
        hits,
        vec![
            "mcp/tools/store/legacy_classifier_9213_tests.rs".to_string(),
            "models/field_names.rs".to_string(),
        ]
    );
}
