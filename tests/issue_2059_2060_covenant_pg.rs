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
use ai_memory::storage::{REQUIRE_IMMUTABLE_AUTHORSHIP_ENV, REQUIRE_WHY_TRACE_ENV};
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
        cid: None,
    }
}

fn is_permission_denied(err: &StoreError) -> bool {
    matches!(err, StoreError::PermissionDenied { .. })
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
        .store_with_embedding(&ctx, &no_wt_e, None)
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
    let ctx = CallerContext::for_agent("cov-2103-owner");
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
    let ctx = CallerContext::for_agent("cov-2103-sup");
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

    // System principal → EXEMPT.
    let system = CallerContext::for_admin("ai:curator-2110");
    let sys = pg_mem(
        &format!("ps-{run}"),
        &ns,
        "system write",
        "ai:curator",
        None,
    );
    store
        .store(&system, &sys)
        .await
        .expect("authenticated system principal is exempt on pg");
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

    let src = pg_mem(&src_id, &ns, "source", "ai:curator", None);
    store.store(&system, &src).await.expect("seed source");

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
