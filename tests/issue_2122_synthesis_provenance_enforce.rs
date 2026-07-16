// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2122 — the synthesis Update-verdict PROVENANCE ROW is a genuine
//! internal writer and must keep working under
//! `AI_MEMORY_REQUIRE_WHY_TRACE=1`.
//!
//! A Form-1 synthesis `update` verdict merges the incoming fact into an
//! existing candidate IN PLACE and then persists a lightweight provenance
//! row (title-suffixed ` (sup ⟶ <target_id>)`) so the `supersedes` edge
//! has a structurally-valid FK endpoint (#1239). That row lands via
//! `db::insert`, whose covenant clause-1 gate refused it when the incoming
//! store carried no `metadata.why_trace` — the insert failure is warn-only,
//! so the supersedes lineage edge was SILENTLY dropped under enforce.
//! Post-#2122 the provenance row is stamped `substrate:system-authored`
//! (stamp-if-absent — a caller-supplied rationale wins), so the edge
//! survives enforce mode.
//!
//! Own-process integration test (env-mutation rationale mirrors
//! `tests/issue_2059_2060_covenant_write_gates.rs`); the harness mirrors
//! `tests/form_1_synthesis_verdict_matrix.rs`.

#![allow(
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value
)]

use std::path::PathBuf;

use ai_memory::config::ResolvedTtl;
use ai_memory::llm::OllamaClient;
use ai_memory::models::Memory;
use ai_memory::storage::{self as db, REQUIRE_WHY_TRACE_ENV, WHY_TRACE_SUBSTRATE_SYSTEM};

use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::OnceLock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn local_runs_root() -> PathBuf {
    std::env::var("TMPDIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".local-runs")
                .join("tmp")
        })
}

/// #1751/#1985 — pin the explicit permissive agent-attestation opt-out so
/// this suite's unsigned store fixtures are not rejected by the
/// attestation layer (which is NOT under test here).
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn open_db() -> (Connection, PathBuf) {
    permissive_attestation_for_tests();
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let p = root.join(format!("issue-2122-synth-{}.db", uuid::Uuid::new_v4()));
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

fn shared_mock_for_synthesis(verdicts_json: Value) -> MockServer {
    let rt = mock_runtime();
    rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
            .mount(&server)
            .await;
        let body_str = serde_json::to_string(&verdicts_json).unwrap();
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
        server
    })
}

const BASE_CONTENT: &str = "This is a substantial body so the AUTONOMY_MIN_CONTENT_LEN gate fires \
                            and the synthesis hook becomes eligible during the store call.";

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shared driver: seed one candidate, mock an `update` verdict against
/// it, run `memory_store` with the given metadata under the given env
/// posture, and return `(conn, target_id, store_result)`.
fn drive_update_verdict(
    ns: &str,
    enforce: bool,
    store_metadata: Option<Value>,
) -> (Connection, String, Result<Value, String>) {
    let (conn, db_path) = open_db();
    // Seed the candidate while the gate is advisory (a pre-covenant row —
    // no why_trace anywhere in the corpus).
    let target_id = seed_existing(
        &conn,
        "kubernetes deployment notes v0",
        "body for candidate 0",
        ns,
    );

    let server = shared_mock_for_synthesis(json!({"verdicts": [{
        "candidate_id": target_id,
        "verb": "update",
        "merged_content": "merged-content-2122",
    }]}));
    let llm = OllamaClient::new_with_url(&server.uri(), "test-model").expect("client");

    let mut params = json!({
        "title": "kubernetes rolling deploy strategy",
        "content": BASE_CONTENT,
        "namespace": ns,
        "on_conflict": "version",
    });
    if let Some(meta) = store_metadata {
        params["metadata"] = meta;
    }
    if enforce {
        unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    } else {
        unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    }
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn,
        &db_path,
        &params,
        None,
        Some(&llm),
        None,
        &ResolvedTtl::default(),
        true,
        None,
        None,
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    (conn, target_id, resp)
}

fn provenance_row(conn: &Connection, ns: &str, target_id: &str) -> (i64, Value) {
    let (count, meta_json): (i64, String) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(metadata), '{}') FROM memories \
             WHERE namespace = ?1 AND title LIKE '% (sup ⟶ ' || ?2 || ')'",
            rusqlite::params![ns, target_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    (count, serde_json::from_str(&meta_json).unwrap())
}

/// #2121 funnel audit (FLAG-1) — under enforce, a why_trace-less tenant
/// `memory_store` whose content draws a synthesis Update verdict is
/// REFUSED before the in-place merge (pre-fix it detoured around the
/// insert gate and persisted caller-derived content).
#[test]
fn synthesis_update_detour_refused_without_why_trace_under_enforce_2121() {
    let _g = env_lock();
    let ns = "ns-2121-synth-refuse";
    let (conn, target_id, resp) = drive_update_verdict(ns, true, None);
    let err = resp.expect_err("why_trace-less store must be refused even on the Update detour");
    assert!(err.contains("why_trace"), "got: {err}");

    // The target row's content was NOT merged (the refusal fired before
    // the in-place update).
    let body: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            [&target_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(body, "body for candidate 0", "no caller content persisted");
    let (prov_count, _) = provenance_row(&conn, ns, &target_id);
    assert_eq!(prov_count, 0, "no provenance row on a refused store");
}

/// #2122 — under enforce, a why_trace-BEARING store whose content draws
/// an Update verdict succeeds; the provenance row lands (the supersedes
/// lineage edge is not silently dropped) carrying the CALLER's rationale
/// (inheritance wins over the substrate stamp — stamp-if-absent).
#[test]
fn synthesis_update_provenance_row_lands_with_caller_why_trace_under_enforce_2122() {
    let _g = env_lock();
    let ns = "ns-2122-synth-enforce";
    let (conn, target_id, resp) = drive_update_verdict(
        ns,
        true,
        Some(json!({"why_trace": "operator asked to record this"})),
    );
    let resp = resp.expect("why_trace-bearing synthesis update store succeeds under enforce");
    assert_eq!(
        resp["duplicate"].as_bool(),
        Some(true),
        "update verdict honoured"
    );

    // The in-place merge landed.
    let body: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = ?1",
            [&target_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(body, "merged-content-2122");

    // The provenance row landed (NOT silently dropped by the gate) with
    // the caller's rationale preserved.
    let (prov_count, meta) = provenance_row(&conn, ns, &target_id);
    assert_eq!(
        prov_count, 1,
        "the supersedes provenance row must land under enforce (#2122)"
    );
    assert_eq!(
        meta.get("why_trace").and_then(Value::as_str),
        Some("operator asked to record this"),
        "a caller-supplied rationale wins over the substrate stamp"
    );

    // And the supersedes edge exists with both endpoints alive.
    let edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_links WHERE target_id = ?1 AND relation = 'supersedes'",
            [&target_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(edge_count, 1, "supersedes lineage edge survives enforce");
}

/// #2122 — under the ADVISORY default a why_trace-less Update-verdict
/// store still lands its provenance row, stamped with the substrate
/// rationale (the internal bookkeeping writer never silently loses the
/// supersedes edge).
#[test]
fn synthesis_update_provenance_row_stamped_substrate_under_advisory_2122() {
    let _g = env_lock();
    let ns = "ns-2122-synth-advisory";
    let (conn, target_id, resp) = drive_update_verdict(ns, false, None);
    let resp = resp.expect("advisory-mode synthesis update store succeeds");
    assert_eq!(resp["duplicate"].as_bool(), Some(true));

    let (prov_count, meta) = provenance_row(&conn, ns, &target_id);
    assert_eq!(prov_count, 1, "provenance row lands under advisory");
    assert_eq!(
        meta.get("why_trace").and_then(Value::as_str),
        Some(WHY_TRACE_SUBSTRATE_SYSTEM),
        "the internal provenance writer records the substrate rationale"
    );
}
