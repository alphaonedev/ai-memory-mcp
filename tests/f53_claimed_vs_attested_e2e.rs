// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! F-53 (#1947, 5-agent vote `wd8wtmg0n`) — claimed-vs-attested E2E suite.
//!
//! One suite exercising the `attest_level` = `claimed` (bare, unsigned) vs
//! `agent_attested` (cryptographically verified) distinction across the
//! ALREADY-SHIPPED attestation surfaces, PLUS the new FED-RQ-03 policy-refuse
//! case:
//!
//!   * **Write attestation** (federation receive, PERSISTED) — a relayed
//!     memory with a valid per-write content signature against the author's
//!     enrolled key lands `attest_level=agent_attested`; the same push without
//!     a signature lands `claimed`.
//!   * **Signal attestation** (shipped `signals::verify`) — a signed signal
//!     verifies (attested); an unsigned signal does not (accept-and-flag
//!     `claimed`); a tampered/forged signal is rejected.
//!   * **Checkpoint attestation** (shipped `authorize_remote_checkpoint_resolution`)
//!     — a resolution signed by the resolver's enrolled key is `Accept`
//!     (attested); an unsigned one is permissive-`Accept` (claimed-lane) and
//!     fail-closed-`RejectUnsigned` under `require_sig`; a forged one is
//!     `RejectForged` unconditionally.
//!   * **Policy refuse** (FED-RQ-03) — a push governed by a STALE governance
//!     `policy_version` is refused `409`; a current one is accepted.
//!
//! Deliberately NO detect→evict round-trip — the FED-RQ-02 equivocation
//! runtime (auto-eviction) is DEFERRED to v1.x (see ADR-002).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::federation::receive_auth::{
    CheckpointResolutionAuthz, PolicyFreshnessVerdict, authorize_remote_checkpoint_resolution,
    evaluate_inbound_policy_freshness,
};
use ai_memory::identity::sign::{SignableCheckpointResolution, sign_checkpoint_resolution};
use ai_memory::models::{Signal, SignalType};

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const PEER_ID_HEADER: &str = "x-peer-id";

// ---------------------------------------------------------------------------
// Shared federation-receive HTTP harness (in-memory sqlite).
// ---------------------------------------------------------------------------
fn build_router_with_db() -> (axum::Router, ai_memory::handlers::Db) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        std::sync::Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open store"))
    };
    let app_state = ai_memory::handlers::AppState {
        db: db.clone(),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(
        ai_memory::handlers::ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        },
        app_state,
    );
    (router, db)
}

fn reset_env() {
    unsafe {
        std::env::set_var("AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT", "0");
        std::env::remove_var("AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS");
        std::env::remove_var(ai_memory::federation::peer_attestation::PEER_ATTESTATION_ENV);
        std::env::remove_var(ai_memory::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV);
        std::env::remove_var(ai_memory::federation::receive_auth::REQUIRE_WRITE_SIG_ENV);
    }
}

async fn post_push(router: &axum::Router, body: &Value, peer: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/push")
        .header("content-type", "application/json")
        .header(PEER_ID_HEADER, peer)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn stored_attest_level(db: &ai_memory::handlers::Db, id: &str) -> Option<String> {
    let lock = db.lock().await;
    lock.0
        .query_row(
            "SELECT json_extract(metadata, '$.attest_level') FROM memories WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Surface 1 — WRITE attestation (persisted attest_level via /sync/push).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn write_attestation_claimed_vs_agent_attested() {
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();

    let author = "ai:f53-author";
    let kp = ai_memory::identity::keypair::generate(author).expect("keypair");
    // Enroll the author's key on the receiver's governance/identity conn so the
    // per-write content signature can be verified against the bound key.
    {
        let lock = db.lock().await;
        ai_memory::storage::register_agent(&lock.0, author, "nhi", &[]).expect("register");
        ai_memory::storage::bind_agent_pubkey(&lock.0, author, &kp.public_base64()).expect("bind");
    }

    let ns = "f53-write";
    // #3422 — the attestation funnel accepts ONLY the canonical
    // storage-stable rendering (UTC, `+00:00`, microsecond-truncated):
    // it is the one form both backends return byte-for-byte, so the
    // signature stays re-derivable from the persisted row.
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let content = "F-53 write-attestation body, long enough to be meaningful prose.";
    let title = "f53 attested write";

    // Mint the #626 SignableWrite signature (the author self-relays).
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: author,
        namespace: ns,
        title,
        kind: ai_memory::models::MemoryKind::Observation.as_str(),
        created_at: &created_at,
        content_sha256: &content_hash,
    };
    let sig_b64 = base64::engine::general_purpose::STANDARD
        .encode(ai_memory::identity::sign::sign_write(&kp, &write).expect("sign write"));

    let signed_id = uuid::Uuid::new_v4().to_string();
    let signed_body = json!({
        "sender_agent_id": author,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": signed_id,
            "tier": "long",
            "namespace": ns,
            "title": title,
            "content": content,
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": created_at,
            "updated_at": created_at,
            "metadata": {"agent_id": author, "write_signature": sig_b64},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    let (status, body) = post_push(&router, &signed_body, author).await;
    assert_eq!(status, StatusCode::OK, "signed relay accepts; body={body}");

    // A second, UNSIGNED self-authored memory → claimed.
    let claimed_id = uuid::Uuid::new_v4().to_string();
    let claimed_body = json!({
        "sender_agent_id": author,
        "sender_clock": {"entries": {}},
        "memories": [{
            "id": claimed_id,
            "tier": "long",
            "namespace": ns,
            "title": "f53 bare claim",
            "content": "F-53 unsigned body — a bare claim, no write_signature.",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "user",
            "access_count": 0,
            "created_at": created_at,
            "updated_at": created_at,
            "metadata": {"agent_id": author},
            "reflection_depth": 0,
            "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    let (status2, _) = post_push(&router, &claimed_body, author).await;
    assert_eq!(status2, StatusCode::OK, "unsigned relay accepts (claimed)");
    drop(guard);

    assert_eq!(
        stored_attest_level(&db, &signed_id).await.as_deref(),
        Some("agent_attested"),
        "a verified per-write signature stamps agent_attested"
    );
    assert_eq!(
        stored_attest_level(&db, &claimed_id).await.as_deref(),
        Some("claimed"),
        "an unsigned relayed write is a bare claim"
    );
}

// ---------------------------------------------------------------------------
// Surface 2 — SIGNAL attestation (shipped signals::verify).
// ---------------------------------------------------------------------------
fn make_signal(from_agent: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "f53-signal".to_string(),
        from_agent: from_agent.to_string(),
        to_agent: None,
        subject: "f53".to_string(),
        body: json!({"hello": "world"}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1_700_000_000,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: Vec::new(),
        sender_pubkey: Vec::new(),
    }
}

#[tokio::test]
async fn signal_attestation_claimed_vs_attested() {
    let from = "ai:f53-signer";
    let kp = ai_memory::identity::keypair::generate(from).expect("keypair");

    // Attested: self-signed → verifies against its own embedded pubkey.
    let mut attested = make_signal(from);
    ai_memory::signals::sign_into(&mut attested, &kp).expect("sign signal");
    assert!(
        ai_memory::signals::verify(&attested),
        "a signed signal verifies (attested)"
    );
    assert!(
        ai_memory::signals::verify_with_key(&attested, kp.public.as_bytes()),
        "attested signal verifies against the enrolled key"
    );

    // Claimed: unsigned → does not verify (accept-and-flag data lane).
    let claimed = make_signal(from);
    assert!(
        !ai_memory::signals::verify(&claimed),
        "an unsigned signal does not verify (bare claim)"
    );

    // Forged: tamper the body AFTER signing → signature no longer matches.
    let mut forged = attested.clone();
    forged.body = json!({"hello": "tampered"});
    assert!(
        !ai_memory::signals::verify(&forged),
        "a tampered signal is rejected (forged)"
    );
}

// ---------------------------------------------------------------------------
// Surface 3 — CHECKPOINT resolution attestation
// (shipped authorize_remote_checkpoint_resolution).
// ---------------------------------------------------------------------------
fn cp_resolution(resolved_by: &'static str) -> SignableCheckpointResolution<'static> {
    SignableCheckpointResolution {
        checkpoint_id: "f53-cp",
        namespace: "_epoch",
        state: "resolved",
        resolved_by,
        resolution: Some("approved"),
        resolved_at: 1_700_000_900,
    }
}

#[tokio::test]
async fn checkpoint_attestation_claimed_vs_attested() {
    let resolver = ai_memory::identity::keypair::generate("ai:f53-resolver").expect("keypair");
    let r = cp_resolution("ai:f53-resolver");
    let sig = sign_checkpoint_resolution(&resolver, &r).expect("sign resolution");

    // Attested: signed by the resolver's enrolled key → Accept (both modes).
    assert_eq!(
        authorize_remote_checkpoint_resolution(&r, &sig, Some(&resolver.public), true),
        CheckpointResolutionAuthz::Accept(resolver.public),
        "signed + enrolled → attested Accept (fail-closed mode)"
    );

    // Claimed lane: unsigned → permissive Accept, fail-closed RejectUnsigned.
    assert_eq!(
        authorize_remote_checkpoint_resolution(&r, &[], None, false),
        CheckpointResolutionAuthz::AcceptUnverified,
        "unsigned → permissive Accept (claimed data lane)"
    );
    assert_eq!(
        authorize_remote_checkpoint_resolution(&r, &[], None, true),
        CheckpointResolutionAuthz::RejectUnsigned,
        "unsigned → fail-closed reject under require_sig"
    );

    // Forged: signed by a different key → RejectForged unconditionally.
    let mallory = ai_memory::identity::keypair::generate("ai:f53-mallory").expect("keypair");
    let forged = sign_checkpoint_resolution(&mallory, &r).expect("forge");
    assert_eq!(
        authorize_remote_checkpoint_resolution(&r, &forged, Some(&resolver.public), false),
        CheckpointResolutionAuthz::RejectForged,
        "a signature not matching the enrolled resolver key is forged (even permissive)"
    );
}

// ---------------------------------------------------------------------------
// Surface 4 — FED-RQ-03 policy refuse (pure verdict + persisted HTTP 409).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn policy_refuse_stale_vs_current() {
    // Pure verdict distinction (the decision surface).
    assert_eq!(
        evaluate_inbound_policy_freshness(Some(2), 5, true),
        PolicyFreshnessVerdict::RefuseStale {
            sender_seq: 2,
            local_seq: 5
        },
        "behind-local → RefuseStale"
    );
    assert_eq!(
        evaluate_inbound_policy_freshness(Some(5), 5, true),
        PolicyFreshnessVerdict::Accept,
        "current → Accept"
    );

    // Persisted E2E: stale push over HTTP is refused 409 with the typed tag.
    let guard = ENV_LOCK.lock().await;
    reset_env();
    let (router, db) = build_router_with_db();
    {
        let kp = ai_memory::identity::keypair::generate("operator").expect("op key");
        let signing = kp.private.as_ref().expect("op private");
        let lock = db.lock().await;
        for _ in 0..3 {
            ai_memory::governance::policy_version::append_policy_advance_no_tx(
                &lock.0, signing, "operator",
            )
            .expect("advance policy");
        }
    }
    let sender = "ai:f53-stale-peer";
    let now = chrono::Utc::now().to_rfc3339();
    let stale = json!({
        "sender_agent_id": sender,
        "sender_clock": {"entries": {}},
        "sender_policy_seq": 1,
        "memories": [{
            "id": uuid::Uuid::new_v4().to_string(),
            "tier": "long", "namespace": "f53-policy", "title": "stale",
            "content": "governed by a stale policy", "tags": [], "priority": 5,
            "confidence": 1.0, "source": "user", "access_count": 0,
            "created_at": now, "updated_at": now, "metadata": {},
            "reflection_depth": 0, "memory_kind": "observation",
        }],
        "dry_run": false,
    });
    let (status, body) = post_push(&router, &stale, sender).await;
    drop(guard);
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale-policy push 409; body={body}"
    );
    assert_eq!(
        body["error"],
        ai_memory::federation::receive_auth::STALE_POLICY_ERROR_TAG
    );
}
