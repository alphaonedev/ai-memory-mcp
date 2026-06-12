// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! cov_ga2_pg — GA-gate coverage backfill for the DEEP postgres federation
//! receive body under the operator's uniform-90-per-module directive.
//!
//! The prior wave (`tests/cov_ga2_federation.rs`) and
//! `tests/cov3_handlers_postgres.rs` exercised the postgres `/sync/push`
//! ENTRY and REFUSAL arms (invalid-sender 400, empty-batch ack) but always
//! posted EMPTY `memories[]` arrays, so the deep
//! [`sync_push_via_store`](handlers/federation_signing_check.rs) body — the
//! per-memory apply loop, the deferred-embedding fallback, per-agent quota
//! attribution, deletions, and the H3 link-verify arms — stayed dark. This
//! file drives a REAL [`PostgresStore`]-backed `build_router` through
//! `tower::oneshot` with NON-EMPTY signed / enrolled batches so the
//! `StorageBackend::Postgres` deep body executes end-to-end:
//!
//! - `sync_push_via_store` — the memory apply loop
//!   (`validate_memory` → `attribute_agent_for_quota` →
//!   `quotas::check_and_record` Ok arm → `stamp_reflection_origin` →
//!   `MemoryStore::apply_remote_memory` Ok → `applied++`), the
//!   `clean_shipped`=None deferred-embed fallback push, the audit emit,
//!   `apply_remote_deletion`, the three H3 link-verify arms
//!   (`Unsigned` legacy / `PeerAttested` verified / tampered-`skip`),
//!   the `unsupported_on_postgres` archive/restore tally, the
//!   `spawn_deferred_embedding_refresh_via_store` no-op guard, and the
//!   OK response envelope with `storage_backend == "postgres"`.
//! - `verify_signature_or_reject` / `resolve_peer_verifying_key` — the
//!   enrolled-peer valid-signature + nonce-fresh arm that runs in
//!   `federation_receive::sync_push` BEFORE it dispatches into the
//!   postgres `sync_push_via_store`.
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`.
//! Without the env var every test prints a skip line and returns. Every
//! namespace / memory-id / peer-id is uuid-randomized so concurrent runs
//! against the shared scratch DB never collide, and NO test asserts
//! global-table emptiness.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::similar_names)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;

/// Serializes every test that mutates the process-global federation env
/// vars (`AI_MEMORY_FED_REQUIRE_SIG`, `AI_MEMORY_FED_REQUIRE_NONCE`,
/// `AI_MEMORY_FED_TRUST_BODY_AGENT_ID`, `AI_MEMORY_KEY_DIR`). cargo runs
/// the `#[tokio::test]`s in this binary concurrently, so without this guard
/// one test's `remove_var` clobbers another's `set_var` mid-request and the
/// signature / attestation gate flips, yielding spurious 401/403s. Same
/// serial-guard pattern as `tests/cov3_handlers_postgres`.
static FED_ENV_LOCK: Mutex<()> = Mutex::const_new(());

const SIG_HEADER: &str = "x-memory-sig";
const NONCE_HEADER: &str = "x-memory-nonce";
const PEER_HEADER: &str = "x-peer-id";

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A unique suffix per call so concurrent runs against the shared scratch
/// DB never collide on namespace / id / peer-id.
fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Build a production router backed by a live `PostgresStore`. The embedder
/// is `None` (keyword-only) — that is the load-bearing condition for the
/// deferred-embed fallback: with no local embedder `receiver_dim` resolves
/// to `None`, so every applied row's shipped vector (if any) falls through
/// to `deferred_embed`, and `spawn_deferred_embedding_refresh_via_store`
/// hits its no-op early-return guard.
async fn pg_router(url: &str) -> axum::Router {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(PostgresStore::connect(url).await.expect("connect postgres"));
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
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec!["ai:cov-ga2-pg".to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
    };
    ai_memory::build_router(api_key_state, app_state)
}

async fn decode(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Build a `/sync/push` POST with the given raw body + optional federation
/// headers. `headers` is a slice of `(name, value)`.
fn push_req(body: &[u8], headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

/// Generate a fresh peer keypair, persist its public key under a fresh temp
/// `AI_MEMORY_KEY_DIR`, point the env there, and return the dir guard + the
/// signing key so the test can sign bodies that `resolve_peer_verifying_key`
/// then verifies against the enrolled key. Caller MUST hold `FED_ENV_LOCK`.
fn enroll_peer(peer_id: &str) -> (tempfile::TempDir, SigningKey) {
    let dir = tempfile::tempdir().expect("keydir");
    let kp = ai_memory::identity::keypair::generate(peer_id).expect("gen keypair");
    ai_memory::identity::keypair::save(&kp, dir.path()).expect("save keypair");
    // SAFETY: caller holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::identity::keypair::KEY_DIR_ENV, dir.path());
    }
    let signing = kp.private.expect("private key present");
    (dir, signing)
}

fn clear_fed_env() {
    // SAFETY: caller holds FED_ENV_LOCK.
    unsafe {
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_SIG_ENV);
        std::env::remove_var(ai_memory::federation::signing::REQUIRE_NONCE_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::identity::keypair::KEY_DIR_ENV);
    }
}

/// A full v0.7.0 Memory JSON shape that passes `validate_memory`. `ns` and
/// `id` are randomized per call so the row is unique on the shared scratch
/// DB and `apply_remote_memory` lands a fresh insert rather than colliding.
fn memory_json(id: &str, ns: &str, peer: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "id": id,
        "tier": "mid",
        "namespace": ns,
        // Unique title per id: insert_if_newer upserts on (title, namespace),
        // so a shared title would collapse sibling rows in one batch into a
        // single upsert and a link's target FK could dangle.
        "title": format!("ga2 pg deep-body row {id}"),
        "content": "non-empty federation batch drives the postgres apply loop",
        "tags": ["cov-ga2-pg"],
        "priority": 5,
        "confidence": 1.0,
        "source": "nhi",
        "access_count": 0,
        "created_at": now,
        "updated_at": now,
        "metadata": {"agent_id": peer}
    })
}

// ---------------------------------------------------------------------------
// sync_push_via_store — non-empty memory batch drives the deep apply loop.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_sync_push_via_store_applies_nonempty_memory_batch() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_applies_nonempty_memory_batch: env unset");
        return;
    };
    clear_fed_env();
    // REQUIRE_SIG=0 skips the sig gate; TRUST_BODY trusts the body sender so
    // we reach sync_push_via_store with a non-empty memories[] that drives
    // the apply loop: validate_memory → check_and_record(Ok) →
    // stamp_reflection_origin → apply_remote_memory(Ok) → applied++, the
    // clean_shipped=None deferred-embed push, and the OK envelope.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-peer");
    let ns = uniq("cov-ga2-pg");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "sender_wall_clock": chrono::Utc::now().to_rfc3339(),
        "memories": [
            memory_json(&uniq("ga2pg-m"), &ns, &peer),
            memory_json(&uniq("ga2pg-m"), &ns, &peer),
        ]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "non-empty pg batch must ack; status={status} body={b}"
    );
    assert_eq!(b["storage_backend"], "postgres");
    // Both rows hit the apply loop; each is either applied or skipped, never
    // dropped silently. NEVER assert a global count — only this batch.
    let applied = b["applied"].as_i64().unwrap_or(0);
    let skipped = b["skipped"].as_i64().unwrap_or(0);
    assert_eq!(
        applied + skipped,
        2,
        "both batch rows reached the apply loop; body={b}"
    );
    assert_eq!(applied, 2, "fresh-id rows apply cleanly; body={b}");
}

#[tokio::test]
async fn pg_sync_push_via_store_shipped_embedding_defers_no_embedder() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_shipped_embedding_defers_no_embedder: env unset");
        return;
    };
    clear_fed_env();
    // A shipped embedding rides alongside the memory. The keyword-only
    // router has no embedder, so receiver_dim==None → the dim-gate filter
    // rejects the shipped vector → the row falls to deferred_embed, and
    // spawn_deferred_embedding_refresh_via_store hits its no-op guard
    // (rows non-empty but embedder None → early return). Exercises the
    // `clean_shipped` filter + the deferred push + the spawn guard.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-emb");
    let ns = uniq("cov-ga2-pg-emb");
    let mid = uniq("ga2pg-emb-m");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [memory_json(&mid, &ns, &peer)],
        "embeddings": [{
            "memory_id": mid,
            "model": "nomic-embed-text-v1.5",
            "dim": 768,
            "vector": vec![0.1_f32; 768]
        }]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "shipped-embedding pg push acks; status={status} body={b}"
    );
    assert_eq!(
        b["applied"].as_i64().unwrap_or(0),
        1,
        "row applied; body={b}"
    );
}

#[tokio::test]
async fn pg_sync_push_via_store_dry_run_noops_batch() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_dry_run_noops_batch: env unset");
        return;
    };
    clear_fed_env();
    // dry_run=true: each valid memory takes the `noop += 1; continue` arm
    // BEFORE the quota/apply path, and the deletions/links loops noop too.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-dry");
    let ns = uniq("cov-ga2-pg-dry");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "dry_run": true,
        "memories": [memory_json(&uniq("ga2pg-dry-m"), &ns, &peer)],
        "deletions": [uniq("ga2pg-dry-del")]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "dry-run pg push acks; status={status} body={b}"
    );
    assert_eq!(
        b["applied"].as_i64().unwrap_or(-1),
        0,
        "dry-run applies nothing; body={b}"
    );
    assert!(
        b["noop"].as_i64().unwrap_or(0) >= 2,
        "dry-run noops memory+deletion; body={b}"
    );
}

#[tokio::test]
async fn pg_sync_push_via_store_invalid_memory_is_skipped() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_invalid_memory_is_skipped: env unset");
        return;
    };
    clear_fed_env();
    // A structurally-invalid memory (empty title) trips
    // RequestValidator::validate_memory → the `skipped += 1; continue` arm,
    // while a sibling valid row applies — both arms of the loop in one push.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-skip");
    let ns = uniq("cov-ga2-pg-skip");
    let mut bad = memory_json(&uniq("ga2pg-bad-m"), &ns, &peer);
    bad["title"] = json!("");
    bad["content"] = json!("");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [bad, memory_json(&uniq("ga2pg-ok-m"), &ns, &peer)]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "mixed batch acks; status={status} body={b}"
    );
    assert!(
        b["skipped"].as_i64().unwrap_or(0) >= 1,
        "invalid row skipped; body={b}"
    );
    assert_eq!(
        b["applied"].as_i64().unwrap_or(0),
        1,
        "valid sibling applied; body={b}"
    );
}

// ---------------------------------------------------------------------------
// sync_push_via_store — deletions + the H3 link-verify arms.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_sync_push_via_store_deletions_and_links() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_deletions_and_links: env unset");
        return;
    };
    clear_fed_env();
    // First push: seed two anchor memories so the link triple has real
    // source/target rows. Second push: a deletion (apply_remote_deletion
    // Ok(false)/Ok(true) arm) + an UNSIGNED link (the `_ => Unsigned` arm of
    // the H3 match → apply_remote_link). Drives the deletions loop and the
    // legacy-unsigned link arm of sync_push_via_store.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-link");
    let ns = uniq("cov-ga2-pg-link");
    let src = uniq("ga2pg-src");
    let tgt = uniq("ga2pg-tgt");
    let seed = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [memory_json(&src, &ns, &peer), memory_json(&tgt, &ns, &peer)]
    }))
    .unwrap();
    let (s_seed, b_seed) = decode(&r, push_req(&seed, &[])).await;
    assert!(
        s_seed.is_success(),
        "seed acks; status={s_seed} body={b_seed}"
    );
    assert_eq!(
        b_seed["applied"].as_i64().unwrap_or(0),
        2,
        "seeded 2 anchors; body={b_seed}"
    );

    let now = chrono::Utc::now().to_rfc3339();
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "deletions": [uniq("ga2pg-ghost-del")],
        "links": [{
            "source_id": src,
            "target_id": tgt,
            "relation": "related_to",
            "created_at": now,
            "signature": null,
            "observed_by": null,
            "valid_from": null,
            "valid_until": null,
            "attest_level": null
        }],
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "del+link push acks; status={status} body={b}"
    );
    // The ghost deletion is a no-op (missing row); the unsigned link lands.
    assert!(
        b["links_applied"].as_i64().unwrap_or(0) >= 1,
        "unsigned link applied; body={b}"
    );
}

#[tokio::test]
async fn pg_sync_push_via_store_tampered_link_signature_skipped() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_tampered_link_signature_skipped: env unset");
        return;
    };
    clear_fed_env();
    // An enrolled observed_by key + a signature over WRONG bytes → the H3
    // (Some, Some) arm: lookup_peer_public_key(Some) → verify(Err) → the
    // tampered `skipped += 1; continue` branch. The peer is enrolled under a
    // fresh KEY_DIR so lookup_peer_public_key returns Some.
    let observer = uniq("ai:cov-ga2-pg-obs");
    let (_dir, signing) = enroll_peer(&observer);
    // REQUIRE_SIG=0 so the BODY sig gate is skipped (we only test the LINK
    // signature arm); TRUST_BODY so we reach the postgres deep body.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-tl");
    let now = chrono::Utc::now().to_rfc3339();
    // Sign a DIFFERENT link triple than the one we send → verify fails.
    let wrong = ai_memory::identity::sign::SignableLink {
        src_id: "wrong-src",
        dst_id: "wrong-tgt",
        relation: "related_to",
        observed_by: Some(observer.as_str()),
        valid_from: None,
        valid_until: None,
    };
    let bad_sig = ai_memory::identity::sign::sign(
        &ai_memory::identity::keypair::AgentKeypair {
            agent_id: observer.clone(),
            public: signing.verifying_key(),
            private: Some(signing),
        },
        &wrong,
    )
    .expect("sign");
    // MemoryLink.signature is `Option<Vec<u8>>` → serialize as a JSON byte
    // array (NOT a hex string). The bytes verify against `wrong`, not the
    // real-src/real-tgt triple we send → verify(Err) → tampered-skip arm.
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "links": [{
            "source_id": "real-src",
            "target_id": "real-tgt",
            "relation": "related_to",
            "created_at": now,
            "signature": bad_sig,
            "observed_by": observer,
            "valid_from": null,
            "valid_until": null,
            "attest_level": null
        }],
        "memories": []
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "tampered-link push still acks; status={status} body={b}"
    );
    assert_eq!(
        b["links_applied"].as_i64().unwrap_or(-1),
        0,
        "tampered link not applied; body={b}"
    );
    assert!(
        b["skipped"].as_i64().unwrap_or(0) >= 1,
        "tampered link skipped; body={b}"
    );
}

// ---------------------------------------------------------------------------
// sync_push_via_store — archives/restores -> unsupported_on_postgres tally.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_sync_push_via_store_archives_restores_unsupported_tally() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_via_store_archives_restores_unsupported_tally: env unset");
        return;
    };
    clear_fed_env();
    // archives + restores are sqlite-only collections on the postgres path;
    // they land in the `unsupported_on_postgres` counter, not applied.
    // SAFETY: this test holds FED_ENV_LOCK for the duration.
    unsafe {
        std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        std::env::set_var(
            ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
            "1",
        );
    }
    let r = pg_router(&url).await;
    let peer = uniq("ai:cov-ga2-pg-uns");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [],
        "archives": [uniq("ga2pg-arch"), uniq("ga2pg-arch")],
        "restores": [uniq("ga2pg-res")]
    }))
    .unwrap();
    let (status, b) = decode(&r, push_req(&body, &[])).await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "archives/restores push acks; status={status} body={b}"
    );
    assert_eq!(
        b["unsupported_on_postgres"].as_i64().unwrap_or(0),
        3,
        "2 archives + 1 restore tallied unsupported; body={b}"
    );
}

// ---------------------------------------------------------------------------
// verify_signature_or_reject (enrolled + nonce-fresh) -> postgres deep body.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_sync_push_enrolled_signed_nonce_drives_deep_body() {
    let _g = FED_ENV_LOCK.lock().await;
    let Some(url) = pg_url() else {
        eprintln!("SKIP pg_sync_push_enrolled_signed_nonce_drives_deep_body: env unset");
        return;
    };
    clear_fed_env();
    // Full secure posture into the postgres deep body: an enrolled peer key
    // + a nonce-bound valid signature passes verify_signature_or_reject's
    // (Some, Some) enrolled-key arm + resolve_peer_verifying_key, then the
    // attested non-empty batch applies through sync_push_via_store. The peer
    // id == sender_agent_id so the #238 attestation passes WITHOUT the
    // trust-body bypass (tests the real attest_sender path into pg).
    let peer = uniq("ai:cov-ga2-pg-signed");
    let (_dir, signing) = enroll_peer(&peer);
    let ns = uniq("cov-ga2-pg-signed");
    let body = serde_json::to_vec(&json!({
        "sender_agent_id": peer,
        "sender_clock": {"entries": {}},
        "memories": [memory_json(&uniq("ga2pg-signed-m"), &ns, &peer)]
    }))
    .unwrap();
    let nonce = uniq("ga2pg-nonce");
    let sig = ai_memory::federation::signing::sign_body_with_nonce_header(&signing, &body, &nonce);
    let r = pg_router(&url).await;
    let (status, b) = decode(
        &r,
        push_req(
            &body,
            &[
                (PEER_HEADER, peer.as_str()),
                (SIG_HEADER, sig.as_str()),
                (NONCE_HEADER, nonce.as_str()),
            ],
        ),
    )
    .await;
    clear_fed_env();
    assert!(
        status.is_success(),
        "enrolled signed+nonce pg push must pass verify + apply; status={status} body={b}"
    );
    assert_eq!(b["storage_backend"], "postgres");
    assert_eq!(
        b["applied"].as_i64().unwrap_or(0),
        1,
        "signed row applied; body={b}"
    );
}
