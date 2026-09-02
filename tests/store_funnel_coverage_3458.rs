// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3458 — MCP `memory_store` write-funnel regression suite.
//!
//! The #3402/#3403 batch grew the funnel (namespace resolution ladder, the
//! v2 attestation edge, the write-event emit) without matching tests, so the
//! per-module floor for `src/mcp/tools/store/mod.rs` went red. These are the
//! funnel arms asserted at the SAME boundary a real MCP client reaches
//! (`handle_store_for_tests`), not at the lib-internal one:
//!
//! * a store that omits `namespace` resolves the #1590/#2390 ladder before
//!   the `pre_store` gate is consulted, so a default-namespace write is not
//!   silently invisible to namespace-scoped hooks;
//! * a presented `write_v2` envelope is REFUSED at the edge whether it is
//!   structurally malformed or merely unverifiable — never downgraded to the
//!   permissive unsigned path;
//! * the `mcp_client` actor attribution is carried into the audit event;
//! * the #2121/#2122 clause-1 gate is consulted on the exact-dup merge
//!   detour, so re-storing an existing `(title, namespace)` cannot dodge
//!   enforce mode.
//!
//! Dedicated binary: `AI_MEMORY_REQUIRE_WHY_TRACE` is process-global, so it
//! must not leak into sibling suites. Serialized in-file by `env_lock`.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use ai_memory::config::ResolvedTtl;
use ai_memory::storage as db;
use rusqlite::Connection;
use serde_json::{Value, json};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: one-shot, before any test body reads the flag.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

fn open_db(tag: &str) -> (Connection, PathBuf) {
    permissive_attestation_for_tests();
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("tmp");
    std::fs::create_dir_all(&root).ok();
    let p = root.join(format!(
        "store-funnel-3458-{tag}-{}.db",
        uuid::Uuid::new_v4()
    ));
    let conn = db::open(&p).expect("open db");
    (conn, p)
}

fn run_store(
    conn: &Connection,
    db_path: &std::path::Path,
    params: &Value,
    mcp_client: Option<&str>,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn, db_path, params, None, None, None, &ttl, false, mcp_client, None,
    )
}

fn base(title: &str) -> Value {
    json!({
        "title": title,
        "content": format!("Body of {title}, long enough to read as meaningful prose."),
        "namespace": "funnel-3458",
        "agent_id": "ai:alice",
    })
}

/// #2390 (N9) — the namespace a write ACTUALLY lands in is resolved through
/// the #1590 ladder (explicit > `[storage].default_namespace` > compiled
/// default) BEFORE the `pre_store` gate is consulted. A caller that omits
/// `namespace` must still land in — and be gated against — the default one.
#[test]
fn store_without_namespace_resolves_the_compiled_default_ladder_2390() {
    let (conn, path) = open_db("ns-ladder");
    let params = json!({
        "title": "funnel-3458-no-namespace",
        "content": "A body long enough to read as meaningful prose for the default namespace.",
        "agent_id": "ai:alice",
    });
    let resp = run_store(&conn, &path, &params, None).expect("namespace-less store is valid");
    assert_eq!(
        resp["namespace"].as_str(),
        Some(ai_memory::DEFAULT_NAMESPACE),
        "the omitted namespace must resolve through the #1590 ladder"
    );
    let id = resp["id"].as_str().expect("id present");
    let row = db::get(&conn, id).expect("read back").expect("row present");
    assert_eq!(row.namespace, ai_memory::DEFAULT_NAMESPACE);
}

/// #1942/#1941 stage 3 — a presented `write_v2` block is never silently
/// ignored. A structurally malformed block is refused at parse; a
/// well-formed but unverifiable one (no C3-bound principal-root key) is
/// refused by the mandatory §2.3 chain. Both are hard REJECTs, and neither
/// may land a row.
#[test]
fn store_presented_write_v2_is_refused_at_the_edge_1942() {
    use base64::Engine as _;
    let (conn, path) = open_db("v2-edge");
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    // (a) structurally malformed — refused by `parse_presented`.
    let mut malformed = base("funnel-3458-v2-malformed");
    malformed["write_v2"] = json!("not-an-object");
    let err = run_store(&conn, &path, &malformed, None).expect_err("malformed v2 must refuse");
    assert!(err.contains("write_v2"), "got: {err}");

    // (b) well-formed but unverifiable — refused by the §2.3 chain.
    let stamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut unverifiable = base("funnel-3458-v2-unverifiable");
    unverifiable["write_v2"] = json!({
        "cert": {
            "principal": "ai:alice",
            "instance_key_id": b64(&[1u8; 32]),
            "model_version_ref": b64(&[2u8; 32]),
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2099-01-01T00:00:00Z",
        },
        "suite_tag": 1,
        "cert_signature": b64(&[3u8; 64]),
        "write_signature": b64(&[4u8; 64]),
        "created_at": stamp,
    });
    let err = run_store(&conn, &path, &unverifiable, None)
        .expect_err("an unverifiable v2 envelope must refuse");
    assert!(
        !err.is_empty() && !err.contains("claimed"),
        "a presented v2 envelope must never be downgraded to the permissive path, got: {err}"
    );

    for title in ["funnel-3458-v2-malformed", "funnel-3458-v2-unverifiable"] {
        let rows = db::find_contradictions(&conn, title, "funnel-3458").unwrap_or_default();
        assert!(rows.is_empty(), "a refused v2 write must not land a row");
    }
}

/// PR-5 (#487) — the audit actor records the MCP client that made the write.
/// A `mcp_client`-attributed store and an unattributed one must both succeed
/// and echo the same resolved `agent_id`, so attribution never changes the
/// write's identity.
#[test]
fn store_carries_mcp_client_attribution_without_changing_identity_487() {
    let (conn, path) = open_db("mcp-client");
    let attributed = run_store(
        &conn,
        &path,
        &base("funnel-3458-attributed"),
        Some("claude-code"),
    )
    .expect("attributed store");
    let anonymous =
        run_store(&conn, &path, &base("funnel-3458-anonymous"), None).expect("unattributed store");
    assert_eq!(attributed["agent_id"].as_str(), Some("ai:alice"));
    assert_eq!(anonymous["agent_id"].as_str(), Some("ai:alice"));
    assert_ne!(attributed["id"], anonymous["id"]);
}

/// #2121/#2122 — the tool-layer `(title, namespace)` dedup detour applies
/// the incoming CALLER content via `db::update` and returns BEFORE the gated
/// `db::insert`, so it must consult the clause-1 write gate itself.
/// Otherwise enforce mode is dodged by re-storing an existing title.
#[test]
fn store_exact_dup_merge_detour_consults_the_clause_1_gate_2122() {
    let _guard = env_lock();
    let (conn, path) = open_db("dup-gate");
    let mut seed = base("funnel-3458-dup");
    seed["metadata"] = json!({"why_trace": "seeded by the fixture"});
    seed["on_conflict"] = json!("merge");
    run_store(&conn, &path, &seed, None).expect("seed write lands (gate advisory by default)");

    let mut second = base("funnel-3458-dup");
    second["content"] = json!("A different body that would overwrite the first one.");
    second["on_conflict"] = json!("merge");

    let prior = std::env::var(db::REQUIRE_WHY_TRACE_ENV).ok();
    // SAFETY: serialized by this file's `env_lock`, held for the whole test;
    // the prior value is restored immediately after the call below.
    unsafe { std::env::set_var(db::REQUIRE_WHY_TRACE_ENV, "1") };
    let refused = run_store(&conn, &path, &second, None);
    // SAFETY: see above.
    unsafe {
        match &prior {
            Some(v) => std::env::set_var(db::REQUIRE_WHY_TRACE_ENV, v),
            None => std::env::remove_var(db::REQUIRE_WHY_TRACE_ENV),
        }
    }

    let err = refused.expect_err("the dedup detour must consult the same gate the tail enforces");
    assert!(err.contains("why_trace"), "got: {err}");
    let rows = db::find_contradictions(&conn, "funnel-3458-dup", "funnel-3458").unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].content.contains("Body of funnel-3458-dup"),
        "the refused merge must not have overwritten the durable content"
    );
}

/// #1955 R45 — the record-stop fence is the OUTERMOST gate of the write
/// funnel and covers BOTH mutating detours the tool layer can take before
/// the gated insert tail: the exact-dup MERGE (`db::update`) and the
/// governance PENDING queue (`queue_pending_action`). A stopped plane must
/// refuse each, leaving the durable row byte-identical and never returning a
/// `pending` envelope naming a row that was not persisted.
#[test]
fn store_record_stopped_plane_refuses_both_pre_insert_write_detours_1955() {
    use ai_memory::models::{
        ApproverType, CorePolicy, GovernanceLevel, GovernancePolicy, Memory, Tier, default_metadata,
    };
    let (conn, path) = open_db("record-stop");

    // (a) exact-dup MERGE detour.
    let mut dup = base("funnel-3458-stopped-dup");
    dup["on_conflict"] = json!("merge");
    run_store(&conn, &path, &dup, None).expect("seed write lands while the plane is running");
    ai_memory::storage::record_stop::actuate_sqlite(&conn, true, "ai:operator", "all")
        .expect("engage record stop");
    dup["content"] = json!("An overwrite that must never reach the durable row.");
    let dup_err = run_store(&conn, &path, &dup, None);
    ai_memory::storage::record_stop::actuate_sqlite(&conn, false, "ai:operator", "all")
        .expect("release record stop");
    assert!(
        dup_err.is_err(),
        "a stopped plane must refuse the exact-dup merge detour"
    );
    let rows = db::find_contradictions(&conn, "funnel-3458-stopped-dup", "funnel-3458")
        .unwrap_or_default();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].content.contains("Body of funnel-3458-stopped-dup"),
        "a refused merge must leave the durable content byte-identical"
    );

    // (b) governance PENDING queue write.
    let ns = "funnel-3458-approve";
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Approve,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Any,
            approver: ApproverType::Human,
            inherit: true,
            ..CorePolicy::default()
        },
        ..Default::default()
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".to_string(), json!("ai:alice"));
        obj.insert(
            "governance".to_string(),
            serde_json::to_value(&policy).unwrap(),
        );
    }
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("_standards-{ns}"),
        title: format!("std-{ns}"),
        content: "policy".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Default::default()
    };
    let std_id = db::insert(&conn, &standard).expect("insert standard");
    db::set_namespace_standard(&conn, ns, &std_id, None).expect("bind standard");

    let gate = ai_memory::config::lock_permissions_mode_for_test();
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let mut pending = base("funnel-3458-stopped-pending");
    pending["namespace"] = json!(ns);
    pending["agent_id"] = json!("ai:bob");
    ai_memory::storage::record_stop::actuate_sqlite(&conn, true, "ai:operator", "all")
        .expect("engage record stop");
    let pending_result = run_store(&conn, &path, &pending, None);
    ai_memory::storage::record_stop::actuate_sqlite(&conn, false, "ai:operator", "all")
        .expect("release record stop");
    ai_memory::config::clear_permissions_mode_override_for_test();
    drop(gate);
    assert!(
        pending_result.is_err(),
        "a stopped plane must refuse the pending-queue write rather than \
         report a pending id that was never persisted"
    );
}

/// v0.9.0 G10.1 (#1827) — a presented-but-unparseable `capability` token is
/// REFUSED at the envelope edge (fail closed: a presented credential is
/// never downgraded to anonymous), while a capability-LESS caller stays
/// byte-identical to the inert posture.
#[test]
fn store_malformed_capability_token_is_refused_at_the_edge_1827() {
    use ai_memory::governance::capability::CapabilityConfig;
    let (conn, path) = open_db("capability");
    ai_memory::config::set_active_capability_config(CapabilityConfig {
        enabled: true,
        ..CapabilityConfig::default()
    });
    let mut bad = base("funnel-3458-bad-capability");
    bad["capability"] = json!("not-a-capability-token");
    let refused = run_store(&conn, &path, &bad, None);
    let allowed = run_store(&conn, &path, &base("funnel-3458-no-capability"), None);
    ai_memory::config::clear_capability_config_for_test();

    assert!(
        refused.is_err(),
        "an unparseable capability token must refuse the write"
    );
    assert!(allowed.is_ok(), "a capability-less write must still land");
}

/// #1592 / #2402 — the response echo re-reads the POST-WRITE row. When that
/// row is not readable on the ordinary lane (an `on_conflict=merge` upsert
/// whose `(title, namespace)` slot is held by a QUARANTINED row, hidden from
/// `db::get` / `list` / `recall` by the containment posture), the echo must
/// fall back to the request values rather than fail an already-committed
/// write. Degrade, never corrupt.
#[test]
fn store_upsert_onto_a_quarantined_row_echoes_the_request_fallback_2402() {
    let (conn, path) = open_db("quarantine-echo");
    let mut params = base("funnel-3458-quarantined-slot");
    params["on_conflict"] = json!("merge");
    let seeded = run_store(&conn, &path, &params, None).expect("seed write");
    let seeded_id = seeded["id"].as_str().expect("id present").to_string();

    conn.execute(
        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
        rusqlite::params![
            ai_memory::models::LifecycleState::Quarantined.as_str(),
            &seeded_id
        ],
    )
    .expect("quarantine the seeded row");
    assert!(
        db::get(&conn, &seeded_id).expect("read ok").is_none(),
        "a quarantined row must be invisible on the ordinary read lane"
    );

    params["content"] = json!("A second write into the slot the quarantined row holds.");
    let resp = run_store(&conn, &path, &params, None)
        .expect("the write still completes; the echo degrades, it does not fail");
    assert_eq!(
        resp["title"].as_str(),
        Some("funnel-3458-quarantined-slot"),
        "the envelope must stay complete when the post-write row is unreadable"
    );
    assert!(
        resp["tier"].is_string(),
        "the tier echo falls back, never absent"
    );
}
