// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3419 (security-high, v1.0.0) — a captured attested direct write must not
//! replay.
//!
//! `identity::attest::prepare_signed_store` validated a caller-presented
//! Ed25519 write signature by shape and by the ±`ATTEST_CREATED_AT_SKEW_SECS`
//! (300 s) freshness window and nothing else. Ed25519 signatures are
//! re-verifiable in perpetuity by construction, so inside that window the SAME
//! captured `POST /api/v1/memories` body verified an UNBOUNDED number of times:
//! a network observer (or anything that logged a request body) could
//! re-submit it to mint duplicate rows, or to RESURRECT a memory the owner had
//! deleted, each landing `attest_level="agent_attested"` with a genuine
//! signature. The federated `/sync/push` surface has had an `X-Memory-Nonce`
//! guard since v0.7.0 (#922); the direct path had none.
//!
//! The control is the durable, bounded `attested_write_ledger` (schema v95 on
//! BOTH backends) consulted through
//! `identity::attest::admit_attested_write_{sync,async}` immediately after the
//! signature verifies and before the row is stored. The admit-once decision is
//! the storage engine's own PRIMARY KEY, not a check-then-act read.
//!
//! DENIED and ALLOWED are asserted on both lanes. The live-postgres module is
//! gated on `feature = "sal-postgres"` + a runtime `AI_MEMORY_TEST_POSTGRES_URL`
//! soft-skip and is deliberately NOT `#[ignore]`d.

#![cfg(feature = "sal")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::attest::{ATTESTED_WRITE_REPLAY_CODE, attested_write_fingerprint};
use ai_memory::models::{Memory, MemoryKind, Tier};

const AGENT: &str = "ai:alice@node";
const NS: &str = "replay3419";

// ===========================================================================
// The storage primitive — the admit-once decision itself (sqlite).
// ===========================================================================

#[test]
fn sqlite_ledger_admits_once_and_refuses_the_replay_3419() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("db::open");
    let fp = attested_write_fingerprint(AGENT, "2026-01-01T00:00:00+00:00", &[7u8; 64]);

    assert!(
        ai_memory::db::admit_attested_write(&conn, &fp, AGENT, "2026-01-01T00:00:00+00:00")
            .expect("admit"),
        "the first sighting of an envelope must be admitted"
    );
    assert!(
        !ai_memory::db::admit_attested_write(&conn, &fp, AGENT, "2026-01-01T00:00:00+00:00")
            .expect("admit"),
        "the SAME envelope must never be admitted twice"
    );

    // A DISTINCT envelope (different signature bytes) is unaffected.
    let other = attested_write_fingerprint(AGENT, "2026-01-01T00:00:00+00:00", &[8u8; 64]);
    assert!(
        ai_memory::db::admit_attested_write(&conn, &other, AGENT, "2026-01-01T00:00:00+00:00")
            .expect("admit"),
        "an honest second write signs differently and must be admitted"
    );
}

/// The fingerprint is length-prefixed per component, so no two distinct
/// triples can collide by concatenation, and it is signer-scoped.
#[test]
fn attested_write_fingerprint_is_unambiguous_3419() {
    assert_ne!(
        attested_write_fingerprint("ab", "c", b""),
        attested_write_fingerprint("a", "bc", b""),
        "length prefixes must prevent a concatenation collision"
    );
    assert_ne!(
        attested_write_fingerprint("ai:alice", "t", b"sig"),
        attested_write_fingerprint("ai:mallory", "t", b"sig"),
        "a signature captured from one signer must not be charged to another"
    );
    assert_eq!(
        attested_write_fingerprint(AGENT, "t", b"sig"),
        attested_write_fingerprint(AGENT, "t", b"sig"),
        "the fingerprint must be deterministic"
    );
}

/// Retention is bounded: a row older than the widest window in which its
/// envelope could still pass the freshness gate is pruned on the next
/// admission, so the ledger is bounded by the write RATE, never by history.
#[test]
fn sqlite_ledger_prunes_past_the_retention_window_3419() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = ai_memory::db::open(&dir.path().join("m.db")).expect("db::open");
    let stale = attested_write_fingerprint(AGENT, "stale", &[1u8; 64]);
    assert!(ai_memory::db::admit_attested_write(&conn, &stale, AGENT, "stale").expect("admit"));

    // Age the row past the retention floor.
    let long_ago =
        chrono::Utc::now().timestamp() - ai_memory::db::ATTESTED_WRITE_LEDGER_RETAIN_SECS - 60;
    conn.execute(
        "UPDATE attested_write_ledger SET seen_at = ?1",
        rusqlite::params![long_ago],
    )
    .expect("age the row");

    // Any admission prunes it, so the table cannot grow without bound.
    let fresh = attested_write_fingerprint(AGENT, "fresh", &[2u8; 64]);
    assert!(ai_memory::db::admit_attested_write(&conn, &fresh, AGENT, "fresh").expect("admit"));
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM attested_write_ledger", [], |r| {
            r.get(0)
        })
        .expect("count");
    assert_eq!(
        remaining, 1,
        "the expired row must be pruned; only the fresh admission remains"
    );
}

// ===========================================================================
// The HTTP surface — `POST /api/v1/memories`, both backend lanes.
// ===========================================================================

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile, std::path::PathBuf) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f, db_path)
}

async fn post_signed(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Compose a signed create body exactly as the handler will re-derive it:
/// `agent_id + namespace + title + kind + created_at + sha256(content)`.
fn signed_body(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    title: &str,
    content: &str,
    created_at: &str,
) -> Value {
    use base64::Engine as _;
    let mem = Memory {
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: created_at.to_string(),
        memory_kind: MemoryKind::Observation,
        tier: Tier::Long,
        ..Memory::default()
    };
    let sig = ai_memory::identity::attest::sign_memory_write(kp, &mem, AGENT).expect("sign");
    json!({
        "namespace": NS,
        "title": title,
        "content": content,
        "tier": Tier::Long.as_str(),
        "created_at": created_at,
        "signature": base64::engine::general_purpose::STANDARD.encode(sig),
    })
}

/// Register the agent and bind its key. The bind REQUIRES an existing
/// registration row (`bind_agent_pubkey` refuses otherwise) — the
/// `provision_agent` pattern from `tests/agent_attestation_integrity.rs`.
fn enroll(db_path: &std::path::Path) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(AGENT).expect("keypair");
    let conn = ai_memory::db::open(db_path).expect("reopen for enroll");
    ai_memory::storage::register_agent(&conn, AGENT, "nhi", &[]).expect("register agent");
    // #3464 — the bind funnel demands proof of possession; this fixture holds
    // the private half, so it runs the real challenge-response handshake.
    ai_memory::storage::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    kp
}

/// The live row's id for `title` in the test namespace, if any.
fn stored_id(db_path: &std::path::Path, title: &str) -> Option<String> {
    let conn = ai_memory::db::open(db_path).expect("reopen for id lookup");
    ai_memory::db::find_by_title_namespace(&conn, title, NS).expect("find_by_title_namespace")
}

fn live_row_count(db_path: &std::path::Path) -> i64 {
    let conn = ai_memory::db::open(db_path).expect("reopen for count");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        rusqlite::params![NS],
        |r| r.get(0),
    )
    .expect("count")
}

async fn replay_is_refused(backend: StorageBackend) {
    let (router, _f, db_path) = build_router(backend);
    let kp = enroll(&db_path);
    // A `created_at` well inside the ±300 s freshness window, so the replay is
    // refused by the LEDGER and not incidentally by the skew gate. Truncated to
    // microseconds and rendered with the `+00:00` offset — the one form both
    // storage backends round-trip byte-for-byte (#3422).
    let created_at = {
        use chrono::SubsecRound as _;
        chrono::Utc::now().trunc_subsecs(6).to_rfc3339()
    };
    let body = signed_body(&kp, "captured write", "the captured body", &created_at);

    // ALLOWED — the first submission of a genuinely signed envelope lands.
    let (status, first) = post_signed(&router, body.clone()).await;
    assert!(
        status.is_success(),
        "the first signed write must be accepted: {status} {first}"
    );
    assert_eq!(live_row_count(&db_path), 1);

    // The issue's headline scenario: the owner DELETES the memory, and the
    // captured body is then replayed inside the freshness window. Deleting
    // first is what makes this the real test — while the original row is still
    // live, the pre-existing UNIQUE (title, namespace) constraint refuses a
    // byte-identical replay before the attestation block is even reached (the
    // `on_conflict=error` default short-circuits in
    // `resolve_create_conflict_title`). The ledger is the ONLY thing standing
    // between a captured envelope and a resurrected `agent_attested` row.
    let id = stored_id(&db_path, "captured write").expect("the created row's id");
    {
        let conn = ai_memory::db::open(&db_path).expect("reopen for delete");
        assert!(ai_memory::db::delete(&conn, &id).expect("delete"));
    }
    assert_eq!(live_row_count(&db_path), 0, "the row must be gone");

    // DENIED — the byte-identical captured body, replayed after the delete.
    let (status, replay) = post_signed(&router, body).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a replayed signed envelope must be refused: {replay}"
    );
    assert_eq!(
        replay["code"].as_str(),
        Some(ATTESTED_WRITE_REPLAY_CODE),
        "the refusal must be the replay guard, not an incidental conflict: {replay}"
    );
    assert_eq!(
        live_row_count(&db_path),
        0,
        "a captured envelope must not resurrect the deleted memory"
    );

    // ALLOWED — a DISTINCT signed write from the same agent still lands: the
    // guard is per-envelope, never a per-agent rate limit.
    let other = signed_body(&kp, "a second, honest write", "different body", &created_at);
    let (status, second) = post_signed(&router, other).await;
    assert!(
        status.is_success(),
        "a distinct signed envelope must still be accepted: {status} {second}"
    );
    assert_eq!(live_row_count(&db_path), 1);
}

#[tokio::test]
async fn sqlite_http_signed_write_replay_is_refused_3419() {
    replay_is_refused(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn postgres_http_signed_write_replay_is_refused_3419() {
    replay_is_refused(StorageBackend::Postgres).await;
}

// ===========================================================================
// Live postgres — the adapter's own admit-once statement.
// ===========================================================================

#[cfg(feature = "sal-postgres")]
mod postgres {
    use super::{AGENT, attested_write_fingerprint};
    use ai_memory::store::MemoryStore;

    async fn live() -> Option<ai_memory::store::postgres::PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                None
            }
        }
    }

    /// DENIED + ALLOWED on the postgres ledger itself.
    #[tokio::test]
    async fn pg_ledger_admits_once_and_refuses_the_replay_3419() {
        let Some(store) = live().await else { return };
        // Unique per run so parallel/repeat runs never collide on the PK.
        let salt = uuid::Uuid::new_v4().to_string();
        let created_at = "2026-01-01T00:00:00+00:00";
        let fp = attested_write_fingerprint(AGENT, &salt, &[7u8; 64]);

        assert!(
            store
                .admit_attested_write(&fp, AGENT, created_at)
                .await
                .expect("admit"),
            "the first sighting of an envelope must be admitted"
        );
        assert!(
            !store
                .admit_attested_write(&fp, AGENT, created_at)
                .await
                .expect("admit"),
            "the SAME envelope must never be admitted twice"
        );
        let other = attested_write_fingerprint(AGENT, &salt, &[8u8; 64]);
        assert!(
            store
                .admit_attested_write(&other, AGENT, created_at)
                .await
                .expect("admit"),
            "an honest second write signs differently and must be admitted"
        );
    }

    /// A malformed fingerprint is refused rather than silently truncated.
    #[tokio::test]
    async fn pg_ledger_refuses_a_short_fingerprint_3419() {
        let Some(store) = live().await else { return };
        assert!(
            store
                .admit_attested_write(b"too short", AGENT, "2026-01-01T00:00:00+00:00")
                .await
                .is_err()
        );
    }
}
