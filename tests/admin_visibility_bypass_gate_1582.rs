// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1582 (SEC, HIGH) — the read-visibility handlers that OR an
//! admin flag past the per-row `is_visible_to_caller` scope=private
//! filter (`detect_contradictions`, `kg_query`, `get_links`,
//! `list_archived`, `list_pending`, `get_taxonomy`) must use the
//! authn-gated `is_admin_caller_trusted` predicate, NOT the bare
//! `is_admin_caller`.
//!
//! Pre-#1582 those handlers called the BARE predicate, which is a pure
//! allowlist match with no #1570 (H6) authn gate. On a deployment with
//! `[admin].agent_ids` configured but NO `api_key` and the header-trust
//! flag off (the secure default), a wire caller could type a configured
//! admin id into `X-Agent-Id`, get the admin flag, and read every
//! tenant's `scope=private` rows — the exact #1570 class, left
//! unremediated on the read path.
//!
//! This binary pins the SSOT predicate `is_admin_caller_trusted` across
//! the three #1570 postures. It runs in its own process because the
//! `mark_request_authn_configured` marker and the
//! `AI_MEMORY_ADMIN_HEADER_TRUST` env flag are process-global; the
//! three postures are asserted in ONE sequential test for that reason.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::admin_role::{
    ENV_ADMIN_HEADER_TRUST, is_admin_caller, is_admin_caller_trusted, mark_request_authn_configured,
};
use ai_memory::handlers::{AppState, Db};
use tempfile::NamedTempFile;

const ADMIN_ID: &str = "ai:operator-alice";
const NON_ADMIN_ID: &str = "ai:tenant-bob";

/// Build an `AppState` with `ADMIN_ID` allowlisted and NO `api_key`
/// (the unauthenticated default install) — same shape as the #1570
/// fixture.
fn build_state() -> (AppState, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        store,
        llm: Arc::new(None),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(vec![ADMIN_ID.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::config::ResolvedModels::default()),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
    };
    (state, f)
}

/// The three #1582/#1570 postures, asserted sequentially because the
/// authn marker and the env flag are process-global.
#[test]
fn admin_visibility_bypass_is_authn_gated_1582() {
    let (state, _f) = build_state();

    // Sanity — the BARE predicate is posture-independent: it is a pure
    // allowlist match. This is exactly why the read handlers must NOT
    // use it as a privilege grant.
    assert!(
        is_admin_caller(&state, ADMIN_ID),
        "bare predicate matches the allowlisted name regardless of authn"
    );
    assert!(
        !is_admin_caller(&state, NON_ADMIN_ID),
        "bare predicate rejects a non-allowlisted name"
    );

    // Posture 1 — secure default: no api_key, trust flag off. The
    // allowlisted NAME alone must NOT grant the admin visibility bypass.
    mark_request_authn_configured(false);
    unsafe { std::env::remove_var(ENV_ADMIN_HEADER_TRUST) };
    assert!(
        !is_admin_caller_trusted(&state, ADMIN_ID),
        "#1582: a self-asserted admin header on a keyless deployment \
         (trust flag off) must NOT receive the visibility bypass"
    );
    assert!(
        !is_admin_caller_trusted(&state, NON_ADMIN_ID),
        "non-admin never trusted"
    );

    // Posture 2 — operator escape hatch: AI_MEMORY_ADMIN_HEADER_TRUST=1
    // restores the legacy trust-the-header posture.
    unsafe { std::env::set_var(ENV_ADMIN_HEADER_TRUST, "1") };
    assert!(
        is_admin_caller_trusted(&state, ADMIN_ID),
        "#1582: explicit header-trust opt-in honors the allowlisted admin"
    );
    assert!(
        !is_admin_caller_trusted(&state, NON_ADMIN_ID),
        "trust flag still does not admit a non-allowlisted name"
    );
    unsafe { std::env::remove_var(ENV_ADMIN_HEADER_TRUST) };

    // Posture 3 — authenticated deployment: request authn configured
    // (api_key at boot). The middleware guarantees the credential was
    // presented, so the header role-claim is honored.
    mark_request_authn_configured(true);
    assert!(
        is_admin_caller_trusted(&state, ADMIN_ID),
        "#1582: on an authenticated deployment the allowlisted admin is trusted"
    );
    assert!(
        !is_admin_caller_trusted(&state, NON_ADMIN_ID),
        "authn does not admit a non-allowlisted name"
    );

    // Reset the process-global marker for any sibling test.
    mark_request_authn_configured(false);
}
