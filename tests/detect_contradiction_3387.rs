// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (issue #3523) — the five `*_3387` cross-tenant read-oracle cases,
//! moved OUT of the `cargo test --lib` binary and into their own process.
//!
//! # Why this file exists
//!
//! `src/**/*.rs` compiles into ONE test binary whose `#[test]` functions run
//! in PARALLEL THREADS, and `identity::resolve_read_visibility_caller()`
//! reads `AI_MEMORY_AGENT_ID` from the process-global environment. These
//! five cases pass an EXPLICIT caller and assert an existence-hiding REFUSAL
//! plus ZERO egress, which makes them exactly the #3517 VICTIM shape: a
//! sibling test installing a principal steers every concurrent reader, and a
//! refusal assertion that starts passing for the wrong reason is worse than
//! one that fails. Serializing the MUTATORS cannot fix it — the victims are
//! READERS and they take no lock (#3475).
//!
//! The sound control is PROCESS isolation: a `tests/*.rs` file compiles to
//! its own test binary and therefore its own process, so nothing the `src/**`
//! `#[cfg(test)]` cohort does to the environment is observable here under any
//! scheduling. `scripts/check-test-env-lock.sh` (arms (d) + (e)) ratchets the
//! rule mechanically so the class cannot come back.
//!
//! # Fidelity
//!
//! The five cases and their four helpers moved BYTE-FOR-BYTE. Only three
//! mechanical rewrites were applied: `crate::` -> `ai_memory::`, the
//! `handle_detect_contradiction` call -> the `cfg`-gated public wrapper
//! `handle_detect_contradiction_for_tests` (a verbatim four-argument
//! forward), and the de-indent from `mod tests`. Every assertion — the exact
//! `"memory A not found"` / `"memory B not found"` strings, the
//! invisible-equals-absent equality, the `chat_calls == 0` egress pins and
//! the two ALLOWED cases — is unchanged.
//!
//! # Concurrency
//!
//! Each case drives the synchronous handler through
//! `tokio::task::spawn_blocking` and awaits it, so no blocking
//! `MutexGuard` is ever held across an `.await` (rust-1.98 CONCURRENCY-20).
//! Nothing here mutates the environment, so this binary needs no lock of its
//! own: the whole point is that it shares its process with nothing.

use ai_memory::llm::OllamaClient;
use ai_memory::mcp::tools::handle_detect_contradiction_for_tests;
use ai_memory::storage as db;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fresh_db() -> (rusqlite::Connection, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = db::open(tmp.path()).expect("db::open");
    (conn, tmp)
}

/// v1.0.0 #3387 — seed a `scope`-less (i.e. private-by-default) row owned
/// by `owner`, so the visibility funnel has something to refuse.
fn seed_owned(conn: &rusqlite::Connection, title: &str, content: &str, owner: &str) -> String {
    seed_scoped(conn, title, content, owner, None)
}

/// v1.0.0 #3387 — as [`seed_owned`], with an explicit `metadata.scope`.
fn seed_scoped(
    conn: &rusqlite::Connection,
    title: &str,
    content: &str,
    owner: &str,
    scope: Option<&str>,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let metadata = match scope {
        Some(scope) => json!({"agent_id": owner, "scope": scope}),
        None => json!({"agent_id": owner}),
    };
    let mem = ai_memory::models::Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Mid,
        namespace: "tier-d".to_string(),
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
        lifecycle_state: ai_memory::models::LifecycleState::Open,
    };
    db::insert(conn, &mem).expect("insert")
}

async fn mount_tags_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(server)
        .await;
}

// =================================================================
// v1.0.0 #3387 — cross-tenant read-oracle regression.
//
// Pre-#3387 this tool did an UNSCOPED `db::get` on both ids: a caller
// who gets a bare not-found from `memory_get` on either id still got
// that row's TITLE back in the response AND had its full body shipped
// to the external LLM endpoint. Both the denied and the allowed path
// are pinned below; the denied path additionally asserts ZERO egress.
// =================================================================

/// Mount a chat endpoint that would answer "yes" if it were ever
/// reached, so a regression shows up as a SUCCESSFUL response rather
/// than an incidental transport error.
async fn mount_chat_yes(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": "yes"},
        })))
        .mount(server)
        .await;
}

/// Count POSTs that actually reached the model endpoint.
async fn chat_calls(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("request recording enabled")
        .iter()
        .filter(|r| r.url.path() == "/api/chat")
        .count()
}

/// #3387 DENIED (id_a): a non-owner caller is refused with the same
/// message an absent row yields, and NO LLM call is made.
#[tokio::test(flavor = "multi_thread")]
async fn non_owner_refused_on_id_a_with_no_llm_call_3387() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    mount_chat_yes(&server).await;
    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let (conn, _tmp) = fresh_db();
        let id_a = seed_owned(&conn, "victim-title-a", "victim body a", "ai:victim");
        let id_b = seed_owned(&conn, "victim-title-b", "victim body b", "ai:victim");
        let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
        handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({"id_a": id_a, "id_b": id_b}),
            Some("ai:attacker"),
        )
        .err()
        .unwrap_or_default()
    })
    .await
    .unwrap();
    assert_eq!(
        err, "memory A not found",
        "non-owner must get the existence-hiding refusal, got: {err}"
    );
    assert_eq!(
        chat_calls(&server).await,
        0,
        "refused caller must cause ZERO egress of either memory body"
    );
}

/// #3387 DENIED (id_b): id_a is the caller's own row, id_b is another
/// tenant's — refusal must land on B, still with no LLM call, so the
/// gate cannot be side-stepped by pairing a readable id with a
/// victim id.
#[tokio::test(flavor = "multi_thread")]
async fn non_owner_refused_on_id_b_with_no_llm_call_3387() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    mount_chat_yes(&server).await;
    let uri = server.uri();
    let err = tokio::task::spawn_blocking(move || {
        let (conn, _tmp) = fresh_db();
        let id_a = seed_owned(&conn, "own-title", "own body", "ai:attacker");
        let id_b = seed_owned(&conn, "victim-title-b", "victim body b", "ai:victim");
        let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
        handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({"id_a": id_a, "id_b": id_b}),
            Some("ai:attacker"),
        )
        .err()
        .unwrap_or_default()
    })
    .await
    .unwrap();
    assert_eq!(
        err, "memory B not found",
        "non-owner must get the existence-hiding refusal on B, got: {err}"
    );
    assert_eq!(
        chat_calls(&server).await,
        0,
        "refused caller must cause ZERO egress of either memory body"
    );
}

/// #3387 DENIED, existence-hiding: the refusal for a row that EXISTS
/// but is invisible is byte-identical to the refusal for a row that
/// does not exist, so the tool is not a presence oracle.
#[tokio::test(flavor = "multi_thread")]
async fn invisible_and_absent_refusals_are_identical_3387() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    mount_chat_yes(&server).await;
    let uri = server.uri();
    let (invisible, absent) = tokio::task::spawn_blocking(move || {
        let (conn, _tmp) = fresh_db();
        let id_a = seed_owned(&conn, "victim-title-a", "victim body a", "ai:victim");
        let id_b = seed_owned(&conn, "own-title", "own body", "ai:attacker");
        let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
        let invisible = handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({"id_a": id_a, "id_b": id_b}),
            Some("ai:attacker"),
        )
        .err()
        .unwrap_or_default();
        let absent = handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({
                "id_a": "00000000-0000-0000-0000-000000000000",
                "id_b": id_b
            }),
            Some("ai:attacker"),
        )
        .err()
        .unwrap_or_default();
        (invisible, absent)
    })
    .await
    .unwrap();
    assert_eq!(
        invisible, absent,
        "existing-but-invisible and absent must be indistinguishable"
    );
    assert_eq!(chat_calls(&server).await, 0, "no egress on either refusal");
}

/// #3387 ALLOWED: the owner still gets the full result — the gate
/// degrades nothing for an entitled caller.
#[tokio::test(flavor = "multi_thread")]
async fn owner_caller_still_gets_verdict_3387() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    mount_chat_yes(&server).await;
    let uri = server.uri();
    let out = tokio::task::spawn_blocking(move || {
        let (conn, _tmp) = fresh_db();
        let id_a = seed_owned(&conn, "title-a", "the sky is blue", "ai:owner");
        let id_b = seed_owned(&conn, "title-b", "the sky is green", "ai:owner");
        let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
        handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({"id_a": id_a, "id_b": id_b}),
            Some("ai:owner"),
        )
        .expect("owner must be allowed")
    })
    .await
    .unwrap();
    assert_eq!(out["contradicts"], json!(true));
    assert_eq!(out["memory_a"]["title"], "title-a");
    assert_eq!(out["memory_b"]["title"], "title-b");
    assert_eq!(chat_calls(&server).await, 1, "owner reaches the model once");
}

/// #3387 ALLOWED: a `collective`-scope row stays readable by any
/// caller — the gate is the canonical `is_visible_to_caller`
/// predicate, not a blanket owner-equality check.
#[tokio::test(flavor = "multi_thread")]
async fn collective_scope_row_readable_by_other_caller_3387() {
    let server = MockServer::start().await;
    mount_tags_ok(&server).await;
    mount_chat_yes(&server).await;
    let uri = server.uri();
    let out = tokio::task::spawn_blocking(move || {
        let (conn, _tmp) = fresh_db();
        let id_a = seed_scoped(
            &conn,
            "shared-a",
            "the sky is blue",
            "ai:owner",
            Some("collective"),
        );
        let id_b = seed_scoped(
            &conn,
            "shared-b",
            "the sky is green",
            "ai:owner",
            Some("collective"),
        );
        let client = OllamaClient::new_with_url(&uri, "test-model").unwrap();
        handle_detect_contradiction_for_tests(
            &conn,
            Some(&client),
            &json!({"id_a": id_a, "id_b": id_b}),
            Some("ai:stranger"),
        )
        .expect("collective rows are visible to every caller")
    })
    .await
    .unwrap();
    assert_eq!(out["contradicts"], json!(true));
    assert_eq!(chat_calls(&server).await, 1);
}
