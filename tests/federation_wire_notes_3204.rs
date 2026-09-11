// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3204 item 6 — federation refusal bodies must not echo the environment
//! knob that disables the control that fired.
//!
//! Pre-fix every `/sync/push` + `/sync/since` refusal `note` told the refused
//! peer exactly which `AI_MEMORY_FED_*` escape hatch to have the operator set
//! (`set AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 to allow unenrolled peers`,
//! `set =0 to bypass`). The remediation is for the operator and now rides the
//! refusal-site WARN as a structured `remediation` field; the wire carries a
//! closed-set note that says WHAT was refused.
//!
//! DENIED: the 401 body of an unenrolled-peer push carries no `AI_MEMORY_`
//! name, on the sqlite router and on the fake-PG router (the production
//! postgres dispatch branch, no service needed). ALLOWED: the refusal still
//! refuses with the same typed tag, and the operator log DOES carry the knob.
//! STRUCTURAL: no inline `"note": "…"` literal in the three federation
//! handler files names a knob, so a future site cannot bypass the module.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::sync::{Arc, Mutex};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::federation_wire_notes::{ENV_PREFIX, remediation, wire};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const UNENROLLED_PEER: &str = "peer-3204-unenrolled";

fn build_router(storage_backend: StorageBackend) -> (axum::Router, NamedTempFile) {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let file = NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&path).expect("open DB");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SAL store"));
    let state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_keys = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_keys, state), file)
}

/// A `MakeWriter` that appends every rendered tracing line to a shared buffer.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogSink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("sink")).into_owned()
    }
}

async fn push_unenrolled(router: &axum::Router) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(ai_memory::handlers::routes::SYNC_PUSH)
        .header("content-type", "application/json")
        .header("x-peer-id", UNENROLLED_PEER)
        .body(Body::from(json!({"memories": []}).to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn assert_refusal_hides_knob_and_log_carries_it(backend: StorageBackend, label: &str) {
    // A thread-local default subscriber: `#[tokio::test]` is current-thread,
    // so the handler's WARN lands in this sink.
    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (router, _file) = build_router(backend);
    let (status, body) = push_unenrolled(&router).await;
    // ALLOWED — the control still refuses with its typed tag.
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}: {body}");
    assert_eq!(body["error"], "peer_not_enrolled", "{label}: {body}");
    assert_eq!(body["note"], wire::PEER_NOT_ENROLLED, "{label}: {body}");
    // DENIED — nothing on the wire names a knob or a toggle.
    let rendered = body.to_string();
    assert!(
        !rendered.contains(ENV_PREFIX),
        "{label}: refusal body names an env knob: {body}"
    );
    assert!(
        !rendered.contains("=0") && !rendered.contains("=1"),
        "{label}: refusal body names a toggle: {body}"
    );
    // ALLOWED — the operator log carries the remediation the wire dropped.
    let log = sink.text();
    assert!(
        log.contains("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1")
            && log.contains("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=0"),
        "{label}: refusal-site WARN must carry the remediation knobs: {log}"
    );
    assert!(
        remediation::PEER_ENROLLMENT.contains("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1"),
        "the remediation const is the text the WARN carries"
    );
}

#[tokio::test]
async fn sqlite_unenrolled_peer_refusal_hides_knob_3204() {
    assert_refusal_hides_knob_and_log_carries_it(StorageBackend::Sqlite, "sqlite").await;
}

#[tokio::test]
async fn fake_pg_unenrolled_peer_refusal_hides_knob_3204() {
    assert_refusal_hides_knob_and_log_carries_it(StorageBackend::Postgres, "fake-pg").await;
}

/// Read a Rust string literal starting at `src[start] == '"'`, honouring
/// escapes and the `\`-newline continuation, and return its joined text.
fn read_literal(src: &str, start: usize) -> String {
    let bytes = src.as_bytes();
    debug_assert_eq!(bytes[start], b'"');
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => break,
            b'\\' => {
                if bytes.get(i + 1) == Some(&b'\n') {
                    // Line continuation: skip the newline + leading whitespace.
                    i += 2;
                    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                        i += 1;
                    }
                    continue;
                }
                out.push(bytes[i + 1] as char);
                i += 2;
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// STRUCTURAL — every `"note":` in the federation handler files is either a
/// const from the wire-notes module or an inline literal free of any knob
/// name. Non-vacuity: the scan must see the module sites the fix installed.
#[test]
fn federation_handler_wire_notes_name_no_knob_3204() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/handlers/federation_receive.rs",
        "src/handlers/federation_signing_check.rs",
        "src/handlers/federation_sync_since.rs",
    ];
    let mut module_sites = 0usize;
    let mut inline_sites = 0usize;
    for rel in files {
        let path = root.join(rel);
        let src = std::fs::read_to_string(&path).expect("read handler source");
        let mut from = 0usize;
        while let Some(pos) = src[from..].find("\"note\":") {
            let at = from + pos + "\"note\":".len();
            let rest = &src[at..];
            let value = rest.trim_start();
            let value_start = at + (rest.len() - value.len());
            if value.starts_with("crate::handlers::federation_wire_notes::wire::") {
                module_sites += 1;
            } else if value.starts_with('"') {
                inline_sites += 1;
                let text = read_literal(&src, value_start);
                let line = src[..value_start].matches('\n').count() + 1;
                assert!(
                    !text.contains(ENV_PREFIX),
                    "{rel}:{line}: inline wire note names a knob: {text}"
                );
            }
            from = at;
        }
    }
    assert!(
        module_sites >= 17,
        "the scan must see the module-backed refusal sites (saw {module_sites})"
    );
    let _ = inline_sites;
    // The module's own pins, re-asserted from outside the crate.
    for note in wire::ALL {
        assert!(!note.contains(ENV_PREFIX), "wire note leaks a knob: {note}");
    }
    for hint in remediation::ALL {
        assert!(hint.contains(ENV_PREFIX), "remediation must name the knob: {hint}");
    }
}
