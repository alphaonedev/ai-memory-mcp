// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2059 / #2060 / #2102 / #2103 / #2105 — TRACT covenant clauses 1+2 on the
//! POSTGRES write funnels. Companion to the sqlite-only
//! `tests/issue_2059_2060_covenant_write_gates.rs`; #2105 filed the
//! zero-postgres-coverage gap as the ROOT CAUSE of the shipped bypasses in
//! #2102 (`why_trace` never wired into `store_batch` / `store_with_embedding` /
//! `apply_remote_memory` / `merge_inbound`) and #2103 (authorship never wired
//! into `MemoryStore::update` / `update_with_archive_on_supersede`). These
//! tests drive REAL postgres writes through each funnel under the enforce env
//! knobs so a future re-bypass fails RED.
//!
//! # Live-postgres gated + serial
//!
//! Skip-if-`AI_MEMORY_TEST_POSTGRES_URL`-unset (the shipped-postgres-suite
//! convention, e.g. `tests/entity_alias_1654.rs`). Env mutation happens ONLY
//! AFTER the skip check, so a local run without a PG URL never touches the
//! process env; when a URL IS present the sal-postgres suite already runs
//! serial (`-- --test-threads=1`, per CLAUDE.md — the shared `ai_memory_test`
//! DB has no per-test schema isolation), so the env-knob mutations do not race.
//! This is a distinct test BINARY from the sqlite covenant file, so the two
//! never share a process.

#![cfg(feature = "sal-postgres")]

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::storage::{
    GOVERNANCE_PRE_WRITE, REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, REQUIRE_WHY_TRACE_ENV,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError, UpdatePatch};

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn pg_mem(id: &str, ns: &str, title: &str, agent_id: &str, why_trace: Option<&str>) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::json!({ "agent_id": agent_id });
    if let Some(wt) = why_trace {
        metadata["why_trace"] = serde_json::Value::String(wt.to_string());
    }
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("content for {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata,
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: ai_memory::models::LifecycleState::Open,
        valid_from: None,
        valid_until: None,
        cid: None,
    }
}

fn is_permission_denied(err: &StoreError) -> bool {
    matches!(err, StoreError::PermissionDenied { .. })
}

/// Serialize the shared-process env mutations (`REQUIRE_WHY_TRACE_ENV` /
/// `REQUIRE_IMMUTABLE_AUTHORSHIP_ENV`). Mirrors `covenant_env_lock()` in the
/// sibling `tests/issue_2059_2060_covenant_write_gates.rs`, but as a
/// `tokio::sync::Mutex` because this file's tests are async and the guard is
/// held across `.await` points (a std `MutexGuard` there trips
/// `clippy::await_holding_lock` and risks a deadlock under a multi-thread
/// runtime). The pg-gated tests skip (return) BEFORE touching the env when no
/// PG url is set, so the only env-mutators that RUN under a default (no-PG)
/// `cargo test` are the two unconditional in-memory sqlite tests below;
/// guarding them keeps the default parallel invocation deterministic (the
/// live-PG suite additionally runs serial via `-- --test-threads=1`, per the
/// module header).
async fn covenant_env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

// ── Clause 1 — why_trace on the postgres store funnels (#2102) ────────────

#[tokio::test]
async fn pg_store_refuses_missing_why_trace_under_enforce() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_store_refuses_missing_why_trace_under_enforce: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("cov-2102-owner");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2102-store-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // store — no why_trace → refused.
    let no_wt = pg_mem(&format!("s-{run}"), &ns, "no wt", "alice", None);
    let err = store
        .store(&ctx, &no_wt)
        .await
        .expect_err("store must refuse a why_trace-less write under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    // store_with_embedding — the primary create-with-embedding hot path.
    let no_wt_e = pg_mem(&format!("se-{run}"), &ns, "no wt embed", "alice", None);
    let err = store
        .store_with_embedding(&ctx, &no_wt_e, None, None)
        .await
        .expect_err("store_with_embedding must refuse under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    // store_batch — bulk create.
    let no_wt_b = pg_mem(&format!("sb-{run}"), &ns, "no wt batch", "alice", None);
    let err = store
        .store_batch(&ctx, std::slice::from_ref(&no_wt_b))
        .await
        .expect_err("store_batch must refuse under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    // With why_trace present, every funnel succeeds under enforce.
    let wt = pg_mem(
        &format!("ok-{run}"),
        &ns,
        "with wt",
        "alice",
        Some("op rationale"),
    );
    store
        .store(&ctx, &wt)
        .await
        .expect("store must allow a why_trace-bearing write under enforce");

    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[tokio::test]
async fn pg_federation_apply_never_refuses_missing_why_trace_under_enforce() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_federation_apply_never_refuses: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("cov-2102-fed");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2102-fed-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // apply_remote_memory — federation receive must NEVER refuse (CRDT).
    let inbound = pg_mem(&format!("ar-{run}"), &ns, "inbound no wt", "peer", None);
    store
        .apply_remote_memory(&ctx, &inbound)
        .await
        .expect("apply_remote_memory must accept a why_trace-less inbound write under enforce");
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── Clause 2 — authorship on the postgres update funnels (#2103) ──────────

#[tokio::test]
async fn pg_update_no_if_match_refuses_authorship_rewrite_under_enforce() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_update_no_if_match_refuses_authorship_rewrite: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    // The acting caller must OWN the seeded row: the pg SAL `update`/`get`
    // enforce the scope=private owner-write gate, so a caller != author
    // fixture is refused on OWNERSHIP before the clause-2 gate under test
    // is ever reached (latent fixture bug — surfaced by the first live-PG
    // --include-ignored run of this file).
    let ctx = CallerContext::for_agent("alice");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2103-upd-{run}");
    let id = format!("u-{run}");
    let mem = pg_mem(&id, &ns, "owned by alice", "alice", Some("seed"));
    store.store(&ctx, &mem).await.expect("store");

    // Default (gate off): the CASE overlay preserves agent_id (no rewrite).
    let rewrite = UpdatePatch {
        metadata: Some(serde_json::json!({"agent_id": "mallory", "why_trace": "seed"})),
        ..Default::default()
    };
    store
        .update(&ctx, &id, rewrite.clone())
        .await
        .expect("gate-off update succeeds (overlay preserves authorship)");
    let got = store.get(&ctx, &id).await.expect("get");
    assert_eq!(
        got.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice"),
        "gate-off overlay must preserve authorship on the no-If-Match path"
    );

    // Enforce: the SAME rewrite via the default (no-If-Match) update path is
    // now REFUSED (pre-#2103 it was a silent, unlogged, non-refusing no-op).
    unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, "1") };
    let err = store
        .update(&ctx, &id, rewrite)
        .await
        .expect_err("enforce must refuse an authorship rewrite on the no-If-Match path");
    assert!(is_permission_denied(&err), "got {err:?}");
    let still = store.get(&ctx, &id).await.expect("get");
    assert_eq!(
        still.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice")
    );
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

#[tokio::test]
async fn pg_supersede_refuses_authorship_rewrite_under_enforce() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_supersede_refuses_authorship_rewrite: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    // Caller must OWN the seeded row (see pg_update fixture note above):
    // the post-refusal `get(&ctx, ..)` visibility-hides a scope=private row
    // owned by a different author, false-failing the liveness assertion.
    let ctx = CallerContext::for_agent("alice");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2103-sup-{run}");
    let id = format!("sup-{run}");
    let mem = pg_mem(&id, &ns, "owned by alice sup", "alice", Some("seed"));
    store.store(&ctx, &mem).await.expect("store");

    unsafe { std::env::set_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, "1") };
    let patch = UpdatePatch {
        title: Some("superseding title".to_string()),
        content: Some("superseding body".to_string()),
        metadata: Some(serde_json::json!({"agent_id": "mallory", "why_trace": "seed"})),
        ..Default::default()
    };
    let err = store
        .update_with_archive_on_supersede(&id, patch, None, ai_memory::models::EditSource::Llm)
        .await
        .expect_err("enforce must refuse an authorship rewrite on the pg supersede twin");
    assert!(is_permission_denied(&err), "got {err:?}");
    // Original row is still live + unchanged.
    let still = store.get(&ctx, &id).await.expect("get");
    assert_eq!(
        still.metadata.get("agent_id").and_then(|v| v.as_str()),
        Some("alice")
    );
    unsafe { std::env::remove_var(REQUIRE_IMMUTABLE_AUTHORSHIP_ENV) };
}

// ── #2110 — authenticated-origin exemption (system principal exempt, tenant
//    gated regardless of forged kind), end-to-end on both SAL backends ──

/// sqlite SAL: no live PG needed — runs always under `--features sal-postgres`.
#[tokio::test]
async fn sqlite_system_principal_exempt_tenant_gated_under_enforce_2110() {
    use ai_memory::store::sqlite::SqliteStore;
    let _env = covenant_env_lock().await;
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let store = SqliteStore::open(":memory:").expect("open in-memory store");

    // Tenant principal forging kind:"reflection" → still REFUSED (no origin
    // exemption; the caller-asserted kind is not trusted — the #2110 fix).
    let tenant = CallerContext::for_agent("ai:tenant-2110");
    let mut forged = pg_mem(
        "sq-forge",
        "ns/2110-sq",
        "forged reflection",
        "tenant",
        None,
    );
    forged.memory_kind = MemoryKind::Reflection;
    assert!(
        store.store(&tenant, &forged).await.is_err(),
        "tenant why_trace-less write refused regardless of forged kind"
    );
    let mut forged_p = pg_mem("sq-forge-p", "ns/2110-sq", "forged persona", "tenant", None);
    forged_p.memory_kind = MemoryKind::Persona;
    assert!(store.store(&tenant, &forged_p).await.is_err());

    // System principal (`for_admin` → bypass_visibility) → EXEMPT + stamped.
    let system = CallerContext::for_admin("ai:curator-2110");
    let sys = pg_mem(
        "sq-sys",
        "ns/2110-sq-sys",
        "system write",
        "ai:curator",
        None,
    );
    let id = store
        .store(&system, &sys)
        .await
        .expect("authenticated system principal is exempt");
    let got = store.get(&system, &id).await.expect("get");
    assert_eq!(
        got.metadata.get("why_trace").and_then(|v| v.as_str()),
        Some("substrate:system-authored")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[tokio::test]
async fn pg_system_principal_exempt_tenant_gated_under_enforce_2110() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_system_principal_exempt_2110: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2110-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant forging kind → REFUSED.
    let tenant = CallerContext::for_agent("ai:tenant-2110");
    let mut forged = pg_mem(
        &format!("pf-{run}"),
        &ns,
        "forged reflection",
        "tenant",
        None,
    );
    forged.memory_kind = MemoryKind::Reflection;
    let err = store
        .store(&tenant, &forged)
        .await
        .expect_err("tenant why_trace-less write refused regardless of forged kind");
    assert!(is_permission_denied(&err), "got {err:?}");

    // System principal → EXEMPT + STAMPED (#2124 — parity with the sqlite
    // twin above, which asserts `substrate:system-authored` persisted; pre
    // #2124 the pg `store` funnel skipped the gate WITHOUT stamping).
    let system = CallerContext::for_admin("ai:curator-2110");
    let sys = pg_mem(
        &format!("ps-{run}"),
        &ns,
        "system write",
        "ai:curator",
        None,
    );
    let id = store
        .store(&system, &sys)
        .await
        .expect("authenticated system principal is exempt on pg");
    let got = store.get(&system, &id).await.expect("get");
    assert_eq!(
        why_trace_of(&got).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
        "#2124 — pg store must stamp the substrate why_trace for the internal principal"
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2113 — the pg reflect funnel (POST /api/v1/reflect) was ungated ──

fn reflect_input(
    ns: &str,
    source_ids: Vec<String>,
    why_trace: Option<&str>,
    title: &str,
) -> ai_memory::db::ReflectInput {
    let mut metadata = serde_json::json!({"agent_id": "ai:tenant-2113"});
    if let Some(wt) = why_trace {
        metadata["why_trace"] = serde_json::Value::String(wt.to_string());
    }
    ai_memory::db::ReflectInput {
        source_ids,
        title: format!("reflection {title} over {ns}"),
        content: "a synthesized reflection".to_string(),
        namespace: Some(ns.to_string()),
        tier: Tier::Mid,
        tags: vec!["r".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        agent_id: "ai:tenant-2113".to_string(),
        metadata,
    }
}

/// A `why_trace` refusal on the reflect funnel surfaces as `HookVeto` on the pg
/// path (mapped explicitly) and as `Database` carrying the `GovernanceRefusal`
/// message on the sqlite path (the `insert_with_conflict` gate refusal
/// propagates verbatim). Both are the covenant refusal — assert on the reason.
fn is_reflect_why_trace_refusal(err: &ai_memory::db::ReflectError) -> bool {
    err.to_string().contains("why_trace")
}

/// sqlite SAL reflect — runs always under `--features sal-postgres`.
#[tokio::test]
async fn sqlite_reflect_refuses_tenant_exempts_system_under_enforce_2113() {
    use ai_memory::store::sqlite::SqliteStore;
    let _env = covenant_env_lock().await;
    let store = SqliteStore::open(":memory:").expect("open in-memory store");
    let system = CallerContext::for_admin("ai:curator-2113");
    let tenant = CallerContext::for_agent("ai:tenant-2113");
    let ns = "ns/2113-sq";

    // Seed a source memory as the system principal (exempt), so the reflect
    // has a valid source_id to synthesize over.
    let src = pg_mem("sq-src-2113", ns, "source", "ai:curator", None);
    store.store(&system, &src).await.expect("seed source");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant reflect with NO why_trace → REFUSED (pre-#2113 this was ungated).
    let err = store
        .reflect(
            &tenant,
            &reflect_input(ns, vec!["sq-src-2113".into()], None, "t1"),
            None,
        )
        .await
        .expect_err("enforce must refuse a why_trace-less tenant reflect");
    assert!(is_reflect_why_trace_refusal(&err), "got {err:?}");

    // System principal (bypass_visibility) → EXEMPT (candidate stamped).
    store
        .reflect(
            &system,
            &reflect_input(ns, vec!["sq-src-2113".into()], None, "sys"),
            None,
        )
        .await
        .expect("authenticated system principal reflect is exempt");

    // A tenant reflect that DOES carry why_trace succeeds under enforce.
    store
        .reflect(
            &tenant,
            &reflect_input(
                ns,
                vec!["sq-src-2113".into()],
                Some("caller rationale"),
                "wt",
            ),
            None,
        )
        .await
        .expect("a why_trace-bearing tenant reflect is allowed under enforce");
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

#[tokio::test]
async fn pg_reflect_refuses_tenant_exempts_system_under_enforce_2113() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_reflect_refuses_tenant_2113: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let system = CallerContext::for_admin("ai:curator-2113");
    let tenant = CallerContext::for_agent("ai:tenant-2113");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2113-{run}");
    let src_id = format!("pg-src-2113-{run}");

    // Seed the source AS THE TENANT (advisory posture — env not yet set):
    // a system-seeded row lands scope=private owned by the curator id, so
    // the tenant reflect visibility-misses it (SourceNotFound) before the
    // why_trace gate under test fires (latent fixture bug — surfaced by
    // the first live-PG --include-ignored run of this file).
    let src = pg_mem(&src_id, &ns, "source", "ai:tenant-2113", None);
    store.store(&tenant, &src).await.expect("seed source");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant reflect with NO why_trace → REFUSED (the #2113 fix; POST /reflect
    // on a postgres daemon got ZERO why_trace enforcement pre-fix).
    let err = store
        .reflect(
            &tenant,
            &reflect_input(&ns, vec![src_id.clone()], None, "t1"),
        )
        .await
        .expect_err("enforce must refuse a why_trace-less tenant pg reflect");
    assert!(is_reflect_why_trace_refusal(&err), "got {err:?}");

    // System principal → EXEMPT.
    store
        .reflect(
            &system,
            &reflect_input(&ns, vec![src_id.clone()], None, "sys"),
        )
        .await
        .expect("authenticated system principal pg reflect is exempt");
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

/// #2113 audit — the pg `update_with_archive_on_supersede` inline INSERT was
/// the last un-gated postgres create funnel. A why_trace-less supersede is
/// refused under enforce; a why_trace-bearing one is allowed.
#[tokio::test]
async fn pg_supersede_refuses_missing_why_trace_under_enforce_2113() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_supersede_refuses_missing_why_trace_2113: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let system = CallerContext::for_admin("ai:curator-sup-2113");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2113sup-{run}");
    let id = format!("sup-wt-{run}");
    // Seed the source as the SYSTEM principal (exempt) so it exists without a
    // why_trace before enforce is engaged.
    let src = pg_mem(&id, &ns, "sup source", "alice", None);
    store.store(&system, &src).await.expect("seed source");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Supersede with a patch carrying NO why_trace → the composed candidate
    // lacks why_trace (preserve_provenance_keys copies agent_id, not why_trace)
    // → REFUSED by the newly-gated inline INSERT.
    let patch_no_wt = UpdatePatch {
        title: Some("superseding title".to_string()),
        content: Some("superseding body".to_string()),
        metadata: Some(serde_json::json!({"agent_id": "alice"})),
        ..Default::default()
    };
    let err = store
        .update_with_archive_on_supersede(
            &id,
            patch_no_wt,
            None,
            ai_memory::models::EditSource::Llm,
        )
        .await
        .expect_err("enforce must refuse a why_trace-less pg supersede");
    assert!(is_permission_denied(&err), "got {err:?}");
    let still = store.get(&system, &id).await.expect("get");
    assert_eq!(
        still.title, "sup source",
        "the refused supersede left the original live"
    );

    // A supersede WITH why_trace succeeds.
    let patch_wt = UpdatePatch {
        title: Some("superseding title 2".to_string()),
        content: Some("superseding body 2".to_string()),
        metadata: Some(serde_json::json!({"agent_id": "alice", "why_trace": "operator edit"})),
        ..Default::default()
    };
    store
        .update_with_archive_on_supersede(&id, patch_wt, None, ai_memory::models::EditSource::Llm)
        .await
        .expect("a why_trace-bearing supersede is allowed under enforce");
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2121 — capture_turn / recover_turn / consolidate key the substrate
//    why_trace stamp on `ctx.bypass_visibility`, never unconditionally ──────

fn pg_capture_write(
    id: &str,
    ns: &str,
    title: &str,
    session: &str,
    turn: i64,
    why_trace: Option<&str>,
) -> ai_memory::models::CaptureTurnWrite {
    ai_memory::models::CaptureTurnWrite {
        memory: pg_mem(id, ns, title, "ai:host", why_trace),
        sha256: {
            let mut h = uuid::Uuid::new_v4().as_bytes().to_vec();
            h.extend_from_slice(&turn.to_le_bytes());
            h.resize(32, 0);
            h
        },
        host_kind: "claude-code".to_string(),
        host_session_id: session.to_string(),
        host_turn_index: turn,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
        signed_event: ai_memory::signed_events::SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "ai:host".to_string(),
            event_type: "memory_capture_turn".to_string(),
            payload_hash: vec![0u8; 32],
            signature: None,
            attest_level: "self_signed".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..ai_memory::signed_events::SignedEvent::default()
        },
    }
}

fn pg_recover_write(
    id: &str,
    ns: &str,
    title: &str,
    seed: u8,
    why_trace: Option<&str>,
) -> ai_memory::models::RecoverTurnWrite {
    ai_memory::models::RecoverTurnWrite {
        memory: pg_mem(id, ns, title, "ai:host", why_trace),
        normalized_sha256: {
            let mut h = uuid::Uuid::new_v4().as_bytes().to_vec();
            h.resize(32, seed);
            h
        },
        raw_sha256: {
            let mut h = uuid::Uuid::new_v4().as_bytes().to_vec();
            h.resize(32, seed.wrapping_add(1));
            h
        },
        host_kind: "claude-code".to_string(),
        transcript_path: "/dev/null".to_string(),
        host_session_id: None,
        host_turn_index: None,
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
    }
}

fn why_trace_of(mem: &Memory) -> Option<String> {
    mem.metadata
        .get("why_trace")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// #2121 (HIGH) — `memory_capture_turn` stores VERBATIM caller content, so
/// the pg adapter must not stamp the substrate rationale for a tenant ctx:
/// a why_trace-less tenant capture is REFUSED under enforce, the
/// authenticated internal principal stays exempt + stamped.
#[tokio::test]
async fn pg_capture_turn_tenant_refused_system_exempt_under_enforce_2121() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_capture_turn_tenant_refused_2121: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let tenant = CallerContext::for_agent("ai:tenant-2121");
    let system = CallerContext::for_admin("ai:system-2121");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2121cap-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant + no why_trace → REFUSED (pre-fix: unconditionally stamped =
    // the #2110 bypass re-committed on the L4 funnel).
    let w1 = pg_capture_write(
        &format!("cap-t-{run}"),
        &ns,
        "tenant capture",
        &format!("sess-t-{run}"),
        1,
        None,
    );
    let err = store
        .capture_turn_idempotent(&tenant, &w1)
        .await
        .expect_err("tenant capture without why_trace must be refused under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    // Tenant + caller-supplied why_trace → allowed.
    let w2 = pg_capture_write(
        &format!("cap-twt-{run}"),
        &ns,
        "tenant capture wt",
        &format!("sess-twt-{run}"),
        2,
        Some("host volunteered this turn"),
    );
    let r2 = store
        .capture_turn_idempotent(&tenant, &w2)
        .await
        .expect("caller-supplied why_trace clears the gate");
    let got2 = store.get(&system, &r2.memory_id).await.expect("get");
    assert_eq!(
        why_trace_of(&got2).as_deref(),
        Some("host volunteered this turn")
    );

    // Authenticated internal principal → exempt + stamped.
    let w3 = pg_capture_write(
        &format!("cap-s-{run}"),
        &ns,
        "system capture",
        &format!("sess-s-{run}"),
        3,
        None,
    );
    let r3 = store
        .capture_turn_idempotent(&system, &w3)
        .await
        .expect("authenticated internal principal is exempt");
    let got3 = store.get(&system, &r3.memory_id).await.expect("get");
    assert_eq!(
        why_trace_of(&got3).as_deref(),
        Some("substrate:system-authored")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

/// #2121 — the L2 recovery twin of the capture test above.
#[tokio::test]
async fn pg_recover_turn_tenant_refused_system_exempt_under_enforce_2121() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_recover_turn_tenant_refused_2121: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let tenant = CallerContext::for_agent("ai:tenant-rec-2121");
    let system = CallerContext::for_admin("ai:system-rec-2121");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2121rec-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let w1 = pg_recover_write(&format!("rec-t-{run}"), &ns, "tenant recover", 11, None);
    let err = store
        .recover_turn_idempotent(&tenant, &w1)
        .await
        .expect_err("tenant recover without why_trace must be refused under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    // Internal L2 walker (bypass ctx — `recover_from_transcript_store` runs
    // `for_admin` post-#2121) → exempt + stamped.
    let w2 = pg_recover_write(&format!("rec-s-{run}"), &ns, "system recover", 12, None);
    let r2 = store
        .recover_turn_idempotent(&system, &w2)
        .await
        .expect("internal L2 recovery is exempt (env #95: never lose a turn)");
    let got = store.get(&system, &r2.memory_id).await.expect("get");
    assert_eq!(
        why_trace_of(&got).as_deref(),
        Some("substrate:system-authored")
    );
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

/// #2121 — `memory_consolidate`'s summary is verbatim caller content: a
/// tenant consolidate over why_trace-less sources is REFUSED under enforce
/// (sources survive), the curator principal stays exempt + stamped, and a
/// why_trace-bearing source's rationale is inherited by a tenant merge.
#[tokio::test]
async fn pg_consolidate_tenant_refused_system_exempt_under_enforce_2121() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_consolidate_tenant_refused_2121: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let tenant = CallerContext::for_agent("ai:tenant-cons-2121");
    let system = CallerContext::for_admin("ai:curator-cons-2121");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2121cons-{run}");

    // Seed why_trace-LESS sources as the TENANT while the gate is advisory
    // (a tenant store does NOT stamp, so the sources stay rationale-free —
    // the legacy/pre-covenant corpus shape).
    let id_a = format!("cons-a-{run}");
    let id_b = format!("cons-b-{run}");
    store
        .store(&tenant, &pg_mem(&id_a, &ns, "src a", "alice", None))
        .await
        .expect("seed a");
    store
        .store(&tenant, &pg_mem(&id_b, &ns, "src b", "alice", None))
        .await
        .expect("seed b");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Tenant consolidate → REFUSED; sources survive (tx dropped).
    let err = store
        .consolidate(
            &tenant,
            &[id_a.clone(), id_b.clone()],
            "tenant merged",
            "verbatim tenant summary",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:tenant-cons-2121",
        )
        .await
        .expect_err("tenant consolidate without why_trace must be refused under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");
    store
        .get(&system, &id_a)
        .await
        .expect("source a survives the refused consolidate");
    store
        .get(&system, &id_b)
        .await
        .expect("source b survives the refused consolidate");

    // Curator principal → exempt + result stamped.
    let new_id = store
        .consolidate(
            &system,
            &[id_a, id_b],
            "curator merged",
            "curator summary",
            &ns,
            &Tier::Long,
            "consolidation",
            "ai:curator-cons-2121",
        )
        .await
        .expect("internal curator consolidate is exempt");
    let got = store.get(&system, &new_id).await.expect("get");
    assert_eq!(
        why_trace_of(&got).as_deref(),
        Some("substrate:system-authored")
    );

    // Inheritance: a tenant consolidate over a why_trace-bearing source
    // clears the gate with the inherited rationale.
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
    let ns2 = format!("cov2121consin-{run}");
    let id_c = format!("cons-c-{run}");
    store
        .store(
            &tenant,
            &pg_mem(&id_c, &ns2, "src c", "alice", Some("caller rationale")),
        )
        .await
        .expect("seed c");
    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let inherited = store
        .consolidate(
            &tenant,
            &[id_c],
            "tenant merged inherit",
            "summary",
            &ns2,
            &Tier::Long,
            "consolidation",
            "ai:tenant-cons-2121",
        )
        .await
        .expect("inherited why_trace clears the gate for a tenant consolidate");
    let got2 = store.get(&system, &inherited).await.expect("get");
    assert_eq!(why_trace_of(&got2).as_deref(), Some("caller rationale"));
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

/// #2122 — the SAL `notify` `why_trace` path on postgres: a why_trace-less
/// tenant notify is refused under enforce (the payload is caller content —
/// no substrate stamp), and the caller-supplied rationale clears the gate.
#[tokio::test]
async fn pg_notify_why_trace_param_path_under_enforce_2122() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_notify_why_trace_param_2122: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let tenant = CallerContext::for_agent("ai:notifier-2122");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let target = format!("ai:recipient-{run}");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    let err = store
        .notify(
            &tenant,
            &target,
            "ping",
            "verbatim payload",
            None,
            None,
            None,
        )
        .await
        .expect_err("notify without why_trace must be refused under enforce");
    assert!(is_permission_denied(&err), "got {err:?}");

    let id = store
        .notify(
            &tenant,
            &target,
            "ping 2",
            "verbatim payload",
            None,
            None,
            Some("coordinating handoff"),
        )
        .await
        .expect("why_trace param clears the gate");
    let got = store.get(&tenant, &id).await.expect("get");
    assert_eq!(why_trace_of(&got).as_deref(), Some("coordinating handoff"));
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2124 (LOW) — cross-backend provenance parity: the pg store FAMILY
//    (`store` / `store_batch` / `store_with_embedding`) must STAMP the same
//    substrate why_trace the sqlite `SqliteStore::store` funnel stamps for the
//    authenticated internal principal (`bypass_visibility`), never SKIP the
//    gate un-stamped. Pre-#2124 the three pg funnels skipped the gate under
//    `bypass_visibility` WITHOUT stamping, so internally-authored rows landed
//    with NO clause-1 rationale on postgres while sqlite recorded
//    `substrate:system-authored` — the drift this test pins closed. ──────────

/// `SQLite` baseline: the write funnels this adapter actually implements
/// stamp on the internal principal. This is the parity ORACLE the pg test
/// below mirrors (runs without a PG url).
///
/// v1.0.0 #2638 / #3242 — `SqliteStore` deliberately does NOT implement
/// `store_with_embedding` or `store_batch` (embeddings are a side table;
/// bulk ingest is `handlers::bulk::bulk_create_sqlite`). Those trait
/// defaults refuse with `UnsupportedCapability` rather than stamp-and-drop
/// the vector / approximate atomicity. The sqlite write that replaced
/// `store_with_embedding` on the HTTP create path is
/// `store_with_embedding_no_overwrite`.
#[tokio::test]
async fn sqlite_store_family_stamps_substrate_why_trace_for_system_2124() {
    use ai_memory::store::sqlite::SqliteStore;
    let store = SqliteStore::open(":memory:").expect("open in-memory store");
    let system = CallerContext::for_admin("ai:curator-2124");

    // store
    let id_s = store
        .store(
            &system,
            &pg_mem("sq-2124-s", "ns/2124", "sys store", "ai:c", None),
        )
        .await
        .expect("store");
    assert_eq!(
        why_trace_of(&store.get(&system, &id_s).await.expect("get")).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
    );

    // store_with_embedding — sqlite must REFUSE (ERRORS-01 / #2638). A
    // success here would mean the default started dropping the vector again.
    match store
        .store_with_embedding(
            &system,
            &pg_mem("sq-2124-e", "ns/2124", "sys embed", "ai:c", None),
            None,
            None,
        )
        .await
    {
        Err(StoreError::UnsupportedCapability { capability }) => {
            assert_eq!(capability, "STORE_WITH_EMBEDDING");
        }
        Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
        Ok(landed) => panic!("sqlite store_with_embedding succeeded ({landed}); it must refuse"),
    }

    // store_with_embedding_no_overwrite — the sqlite create funnel that
    // actually writes. Stamp must match `store`.
    let id_e = store
        .store_with_embedding_no_overwrite(
            &system,
            &pg_mem("sq-2124-e", "ns/2124", "sys embed", "ai:c", None),
            None,
            None,
        )
        .await
        .expect("store_with_embedding_no_overwrite");
    assert_eq!(
        why_trace_of(&store.get(&system, &id_e).await.expect("get")).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
    );

    // store_batch — sqlite must REFUSE (#2638); bulk is not this trait method.
    match store
        .store_batch(
            &system,
            std::slice::from_ref(&pg_mem("sq-2124-b", "ns/2124", "sys batch", "ai:c", None)),
        )
        .await
    {
        Err(StoreError::UnsupportedCapability { capability }) => {
            assert_eq!(capability, "STORE_BATCH");
        }
        Err(other) => panic!("expected UnsupportedCapability, got: {other}"),
        Ok(landed) => panic!("sqlite store_batch succeeded ({landed:?}); it must refuse"),
    }
}

/// Postgres regression: the #2124 fix. Each of the three pg store-family
/// funnels stamps the substrate `why_trace` for the internal principal (parity
/// with the sqlite oracle above). A tenant write on the SAME funnels stays
/// gated (refused under enforce) — proving the stamp is keyed on
/// `bypass_visibility`, not a blanket exemption. Skips when no PG url is set;
/// CI exercises it under `--features sal,sal-postgres --include-ignored`.
#[tokio::test]
async fn pg_store_family_stamps_substrate_why_trace_for_system_2124() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_store_family_stamps_substrate_why_trace_2124: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2124-{run}");
    let system = CallerContext::for_admin("ai:curator-2124");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };

    // store — internal principal → stamped.
    let id_s = store
        .store(
            &system,
            &pg_mem(&format!("s-{run}"), &ns, "sys store", "ai:c", None),
        )
        .await
        .expect("pg store (system) is exempt");
    assert_eq!(
        why_trace_of(&store.get(&system, &id_s).await.expect("get")).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
        "pg store must stamp the substrate why_trace for the internal principal",
    );

    // store_with_embedding — internal principal → stamped.
    let id_e = store
        .store_with_embedding(
            &system,
            &pg_mem(&format!("e-{run}"), &ns, "sys embed", "ai:c", None),
            None,
            None,
        )
        .await
        .expect("pg store_with_embedding (system) is exempt");
    assert_eq!(
        why_trace_of(&store.get(&system, &id_e).await.expect("get")).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
        "pg store_with_embedding must stamp the substrate why_trace",
    );

    // store_batch — internal principal → stamped.
    let ids_b = store
        .store_batch(
            &system,
            std::slice::from_ref(&pg_mem(&format!("b-{run}"), &ns, "sys batch", "ai:c", None)),
        )
        .await
        .expect("pg store_batch (system) is exempt");
    assert_eq!(
        why_trace_of(&store.get(&system, &ids_b[0]).await.expect("get")).as_deref(),
        Some(ai_memory::storage::WHY_TRACE_SUBSTRATE_SYSTEM),
        "pg store_batch must stamp the substrate why_trace",
    );

    // Tenant on the SAME funnels stays gated (the stamp is keyed on the
    // authenticated origin, not a blanket exemption).
    let tenant = CallerContext::for_agent("ai:tenant-2124");
    assert!(
        is_permission_denied(
            &store
                .store(
                    &tenant,
                    &pg_mem(&format!("ts-{run}"), &ns, "tenant store", "t", None)
                )
                .await
                .expect_err("tenant store refused under enforce"),
        ),
        "tenant store without why_trace must stay gated",
    );
    assert!(
        store
            .store_with_embedding(
                &tenant,
                &pg_mem(&format!("te-{run}"), &ns, "tenant embed", "t", None),
                None,
                None,
            )
            .await
            .is_err(),
        "tenant store_with_embedding without why_trace must stay gated",
    );
    assert!(
        store
            .store_batch(
                &tenant,
                std::slice::from_ref(&pg_mem(
                    &format!("tb-{run}"),
                    &ns,
                    "tenant batch",
                    "t",
                    None
                )),
            )
            .await
            .is_err(),
        "tenant store_batch without why_trace must stay gated",
    );

    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

// ── #2141 — GOVERNANCE_PRE_WRITE gate on the DEFAULT (no-If-Match) postgres
//    trait `update` funnel (the #1451 store-benign-then-update-into-refused-
//    shape evasion, postgres twin). ─────────────────────────────────────────

/// A title substring the process-wide governance hook installed below refuses.
/// A benign store (title lacks it) is allowed; an `update` that rewrites the
/// title to CONTAIN it must be refused — the row's stored content would then
/// occupy a shape governance would have refused at store time.
const GOVREFUSE_MARKER_2141: &str = "GOVREFUSE-2141";

/// Install the process-wide substrate `GOVERNANCE_PRE_WRITE` hook exactly once
/// (`OnceLock`). It refuses any write whose `title` contains
/// [`GOVREFUSE_MARKER_2141`] and allows everything else, so the other tests in
/// this binary (which never use the marker) are byte-unaffected. Mirrors the
/// dispatcher pattern in `tests/governance_pre_write_postgres_parity.rs`.
fn ensure_gov_marker_hook_2141() {
    let _ = GOVERNANCE_PRE_WRITE.set(Box::new(|mem: &Memory| {
        if mem.title.contains(GOVREFUSE_MARKER_2141) {
            Err(format!(
                "governance refuses title marker {GOVREFUSE_MARKER_2141}"
            ))
        } else {
            Ok(())
        }
    }));
}

/// #2141 (SEC, HIGH — #1451 parity) — the pg trait `update` (no-If-Match) path
/// consults `consult_governance_pre_write_pg` on the POST-MERGE row. Store a
/// benign memory (title clean → governance allows at store time), then UPDATE
/// its title into a governance-refused shape via the DEFAULT update path
/// (no If-Match) → REFUSED. Pre-#2141 this was a silent ACCEPT (the funnel
/// never consulted the hook), the exact store-benign-then-update-into-refused
/// evasion #1451 closed on sqlite and FX-C5 closed on the pg supersede path.
#[tokio::test]
async fn pg_update_no_if_match_refuses_governance_refused_shape_2141() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_update_no_if_match_refuses_governance_refused_shape_2141: no PG url");
        return;
    };
    ensure_gov_marker_hook_2141();
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("alice");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2141-upd-{run}");
    let id = format!("u2141-{run}");

    // Store a benign memory: the clean title clears the governance hook.
    let mem = pg_mem(&id, &ns, "benign title", "alice", Some("seed"));
    store
        .store(&ctx, &mem)
        .await
        .expect("benign store is allowed");

    // UPDATE the title into the refused shape via the DEFAULT (no-If-Match)
    // trait path → REFUSED, and the row is left unchanged (tx rollback).
    let evade = UpdatePatch {
        title: Some(format!("now {GOVREFUSE_MARKER_2141} laundered")),
        ..Default::default()
    };
    let err = store
        .update(&ctx, &id, evade)
        .await
        .expect_err("update into a governance-refused title must be refused");
    assert!(is_permission_denied(&err), "got {err:?}");
    let still = store.get(&ctx, &id).await.expect("get");
    assert_eq!(
        still.title, "benign title",
        "the refused update must leave the stored row untouched"
    );

    // A benign update via the same path still succeeds (the gate is not a
    // blanket refusal of the funnel).
    let ok = UpdatePatch {
        title: Some("still benign".to_string()),
        ..Default::default()
    };
    store
        .update(&ctx, &id, ok)
        .await
        .expect("a governance-clean update on the no-If-Match path still lands");
    let after = store.get(&ctx, &id).await.expect("get");
    assert_eq!(after.title, "still benign");
}

// ── #2123 item-2 — why_trace cannot be laundered onto a superseding row via
//    inheritance when the patch SUPPLIES a metadata object omitting it. ───────

/// #2123 — the EXISTING row HAS a `why_trace`, and a supersede patch supplies a
/// metadata OBJECT that OMITS `why_trace` → REFUSED under enforce. Pins that
/// `preserve_provenance_keys` overlays ONLY `IMMUTABLE_PROVENANCE_KEYS`
/// (`agent_id` / `derived_from` / `consolidated_from_agents`) and deliberately
/// NOT `why_trace`, so the old row's rationale is NOT silently inherited onto a
/// rewrite. Guards against a future change adding `why_trace` to the preserve
/// set (which would launder every rewrite past the clause-1 gate).
#[tokio::test]
async fn pg_supersede_omitted_why_trace_not_laundered_via_inheritance_2123() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_supersede_omitted_why_trace_2123: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("alice");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2123-sup-{run}");
    let id = format!("sup2123-{run}");
    // Seed the source WITH a why_trace so the ONLY way the superseding row
    // could clear the gate is illegitimate inheritance.
    let src = pg_mem(
        &id,
        &ns,
        "sup source w/ trace",
        "alice",
        Some("original rationale"),
    );
    store
        .store(&ctx, &src)
        .await
        .expect("seed source with why_trace");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Patch SUPPLIES a metadata object but OMITS why_trace → the composed
    // candidate lacks why_trace (agent_id is preserved, why_trace is not) →
    // REFUSED. If a future change added why_trace to the preserve set, this
    // would wrongly inherit "original rationale" and pass.
    let patch = UpdatePatch {
        title: Some("superseding title".to_string()),
        content: Some("superseding body".to_string()),
        metadata: Some(serde_json::json!({"agent_id": "alice"})),
        ..Default::default()
    };
    let err = store
        .update_with_archive_on_supersede(&id, patch, None, ai_memory::models::EditSource::Llm)
        .await
        .expect_err("a metadata-supplying supersede omitting why_trace must be refused");
    assert!(is_permission_denied(&err), "got {err:?}");
    // The original row is still live + carries its original why_trace.
    let still = store.get(&ctx, &id).await.expect("get");
    assert_eq!(still.title, "sup source w/ trace");
    assert_eq!(why_trace_of(&still).as_deref(), Some("original rationale"));
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}

/// #2123 — the WHOLE-OBJECT inheritance path IS allowed: when the patch OMITS
/// metadata ENTIRELY, `patched_metadata` clones the existing metadata verbatim
/// and the source's `why_trace` legitimately rides along, so the superseding
/// row clears the enforce gate. This is the deliberate distinction from the
/// metadata-supplied case above (a whole-object edit that keeps everything vs a
/// selective metadata rewrite that drops the rationale).
#[tokio::test]
async fn pg_supersede_whole_object_omission_inherits_why_trace_2123() {
    let Some(url) = pg_url() else {
        eprintln!("skip pg_supersede_whole_object_omission_2123: no PG url");
        return;
    };
    let store = PostgresStore::connect(&url).await.expect("connect");
    let ctx = CallerContext::for_agent("alice");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let ns = format!("cov2123-inh-{run}");
    let id = format!("inh2123-{run}");
    let src = pg_mem(
        &id,
        &ns,
        "inh source w/ trace",
        "alice",
        Some("inherited rationale"),
    );
    store
        .store(&ctx, &src)
        .await
        .expect("seed source with why_trace");

    unsafe { std::env::set_var(REQUIRE_WHY_TRACE_ENV, "1") };
    // Patch OMITS metadata entirely → existing metadata (incl. why_trace) is
    // inherited whole → ALLOWED under enforce.
    let patch = UpdatePatch {
        title: Some("superseding title inh".to_string()),
        content: Some("superseding body inh".to_string()),
        ..Default::default()
    };
    store
        .update_with_archive_on_supersede(&id, patch, None, ai_memory::models::EditSource::Llm)
        .await
        .expect("a whole-object supersede that omits metadata inherits why_trace and is allowed");
    unsafe { std::env::remove_var(REQUIRE_WHY_TRACE_ENV) };
}
