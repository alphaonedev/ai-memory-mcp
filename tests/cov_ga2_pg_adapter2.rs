// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Coverage agent GA-2 second pass — `PostgresStore` SAL adapter +
//! `federation::sync` quorum-fanout + `cli::schema_init` live-Postgres
//! complement coverage.
//!
//! This suite is the *complement* of the first GA-2 wave
//! (`tests/cov_ga2_postgres.rs`, `tests/cov_ga2_federation.rs`) and the
//! cov4 base (`tests/cov_postgres_{core,governance,kg}.rs`). It targets
//! the arms those suites deliberately left for a second pass:
//!
//! - **`src/store/postgres.rs`** — the governance `Deny` decision arm of
//!   [`MemoryStore::enforce_governance_action`] (the prior wave covered
//!   only the `Allow` + `Approve`→`Pending` arms); the
//!   `reflect_with_hooks` depth-exceeded refusal arm + its
//!   `emit_reflection_depth_exceeded_audit` side-effect (driven via a
//!   `max_reflection_depth: 0` namespace standard); the
//!   `kg_query_cte_filtered` historical (`include_invalidated=true`)
//!   arm + the `kg_timeline` `since`/`until`/`limit`-filtered arm; the
//!   `list_archived` full-projection decode loop on a richly-populated
//!   archived row; `consolidate` (insert-new + delete-sources); the
//!   `update` trait method (owner-gate + COALESCE + `version` bump);
//!   and the `capture_turn_idempotent` distinct-key second-write arm.
//! - **`src/federation/sync.rs`** — the live-peer `AckOutcome::Ack`
//!   (`record_peer_ack` + quorum-met break) and `AckOutcome::IdDrift`
//!   (`record_id_drift`) arms of every `broadcast_*_quorum` fan-out,
//!   exercised against a canned-response mock peer on a loopback
//!   [`tokio::net::TcpListener`]. The prior wave covered only the
//!   no-peer and unreachable-peer (`Fail`) arms.
//! - **`src/cli/schema_init.rs`** — the `init_and_enumerate_postgres` /
//!   `enumerate_postgres` / `bootstrap_memory_graph` live arms, driven
//!   through the public [`ai_memory::cli::schema_init::run`] entry-point
//!   with a `postgres://` URL.
//!
//! Postgres + federation-postgres tests are gated on
//! `AI_MEMORY_TEST_POSTGRES_URL` and skip cleanly when unset. Every id /
//! namespace is uuid-randomised so the suite is rerunnable against a
//! shared persistent DB; assertions filter by the suite's own ids and
//! NEVER assert global-table emptiness.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::time::Duration;

use ai_memory::models::{
    ConfidenceSource, GovernanceDecision, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, GovernedAction, MemoryStore};

// ───────────────────────────────────────────────────────────────────
// Shared fixtures
// ───────────────────────────────────────────────────────────────────

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn mem(id: &str, ns: &str, title: &str, content: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["covtest".to_string(), "ga2-adapter2".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "ga2-adapter2".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ "agent_id": owner }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    }
}

fn link(src: &str, tgt: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: Some("ai:ga2-adapter2".to_string()),
        valid_from: Some(chrono::Utc::now().to_rfc3339()),
        valid_until: None,
        attest_level: None,
    }
}

// ===================================================================
// PostgresStore — governance `Deny` decision arm
// ===================================================================

/// Seed a namespace standard whose governance block sets `write: owner`,
/// so a non-owner `Store` request resolves to a `Deny` (the arm the
/// first wave left uncovered — cov4 covered `Allow`, cov_postgres_kg
/// covered `Approve`→`Pending`).
async fn seed_owner_standard(store: &PostgresStore, ns: &str, owner: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), "policy", owner);
    standard.tier = Tier::Long;
    standard.metadata = serde_json::json!({
        "agent_id": owner,
        "governance": {"write": "owner", "promote": "owner", "delete": "owner"},
    });
    store.store(&ctx, &standard).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, ns, &std_id, None)
        .await
        .expect("set_namespace_standard");
}

#[tokio::test]
async fn enforce_governance_action_denies_non_owner_on_owner_standard() {
    ai_memory::config::override_active_permissions_mode_for_test(
        ai_memory::config::PermissionsMode::Enforce,
    );
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let owner = uid("ai:ga2-owner");
    let intruder = uid("ai:ga2-intruder");
    let ns = uid("cov-deny");
    seed_owner_standard(&store, &ns, &owner).await;

    let payload = serde_json::json!({"title": "intruder write"});
    let decision = store
        .enforce_governance_action(GovernedAction::Store, &ns, &intruder, None, None, &payload)
        .await
        .expect("enforce_governance_action");
    match decision {
        GovernanceDecision::Deny(refusal) => {
            // The refusal carries the operator-readable owner-mismatch
            // reason + the namespace it was scoped to.
            assert!(
                refusal.reason.contains(&intruder),
                "deny reason names the refused caller: {refusal:?}"
            );
        }
        other => panic!("owner-level non-owner Store must Deny; got {other:?}"),
    }

    // Sanity: the owner itself is allowed under the same standard.
    let allowed = store
        .enforce_governance_action(GovernedAction::Store, &ns, &owner, None, None, &payload)
        .await
        .expect("enforce for owner");
    assert!(matches!(allowed, GovernanceDecision::Allow));
}

// ===================================================================
// PostgresStore — reflect depth-exceeded refusal arm
// ===================================================================

/// Seed a namespace standard with `max_reflection_depth: 0` — the
/// documented kill-switch. Any reflection (attempted depth >= 1) then
/// trips the `ReflectError::DepthExceeded` arm + the
/// `emit_reflection_depth_exceeded_audit` signed-events side effect.
async fn seed_reflect_killswitch_standard(store: &PostgresStore, ns: &str, owner: &str) {
    let ctx = CallerContext::for_admin(owner);
    let std_id = uid("std");
    let mut standard = mem(&std_id, ns, &format!("standard:{ns}"), "policy", owner);
    standard.tier = Tier::Long;
    standard.metadata = serde_json::json!({
        "agent_id": owner,
        "governance": {"write": "any", "max_reflection_depth": 0},
    });
    store.store(&ctx, &standard).await.expect("store standard");
    store
        .set_namespace_standard(&ctx, ns, &std_id, None)
        .await
        .expect("set_namespace_standard");
}

#[tokio::test]
async fn reflect_refuses_when_depth_cap_is_zero_killswitch() {
    use ai_memory::db::ReflectError;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2-reflect");
    let owner = uid("ai:ga2-reflect-owner");
    let ns = uid("cov-reflect-cap");
    seed_reflect_killswitch_standard(&store, &ns, &owner).await;

    let a = uid("rda");
    let b = uid("rdb");
    store
        .store(
            &ctx,
            &mem(&a, &ns, "depth obs a", "abody", "ai:ga2-reflect"),
        )
        .await
        .unwrap();
    store
        .store(
            &ctx,
            &mem(&b, &ns, "depth obs b", "bbody", "ai:ga2-reflect"),
        )
        .await
        .unwrap();

    let input = ai_memory::db::ReflectInput {
        source_ids: vec![a.clone(), b.clone()],
        title: uid("over-cap-reflection"),
        content: "this reflection must be refused by the cap=0 standard".to_string(),
        namespace: Some(ns.clone()),
        tier: Tier::Long,
        tags: vec!["reflection".to_string()],
        priority: 6,
        confidence: 0.8,
        source: "nhi".to_string(),
        agent_id: "ai:ga2-reflect".to_string(),
        metadata: serde_json::json!({}),
    };
    let err = store
        .reflect(&ctx, &input)
        .await
        .expect_err("cap=0 standard must refuse every reflection");
    match err {
        ReflectError::DepthExceeded {
            attempted,
            cap,
            namespace,
        } => {
            assert_eq!(cap, 0, "kill-switch cap is 0");
            assert!(attempted >= cap, "attempted depth >= cap triggers refusal");
            assert_eq!(namespace, ns);
        }
        other => panic!("expected DepthExceeded; got {other:?}"),
    }
}

// ===================================================================
// PostgresStore — kg_query historical (include_invalidated) +
// kg_timeline since/until/limit-filtered arms
// ===================================================================

#[tokio::test]
async fn kg_query_cte_filtered_historical_arm_and_timeline_filters() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2-kg");
    let ns = uid("cov-kg-hist");
    let a = uid("ha");
    let b = uid("hb");
    store
        .store(&ctx, &mem(&a, &ns, "hist a", "abody", "ai:ga2-kg"))
        .await
        .unwrap();
    store
        .store(&ctx, &mem(&b, &ns, "hist b", "bbody", "ai:ga2-kg"))
        .await
        .unwrap();
    store.link(&ctx, &link(&a, &b)).await.unwrap();

    // Invalidate the edge so the current-view query hides it.
    let inv = store
        .invalidate_link(&a, &b, "related_to", None)
        .await
        .expect("invalidate_link");
    assert!(inv.found, "the seeded edge must be found + invalidated");

    // Current view (include_invalidated=false): the invalidated edge is
    // filtered out by the `valid_until` predicate.
    let current = store
        .kg_query_cte_filtered(&a, 3, false)
        .await
        .expect("kg_query_cte_filtered current");
    assert!(
        !current.iter().any(|r| r.target_id == b),
        "current view hides the invalidated edge"
    );

    // Historical view (include_invalidated=true): the `TRUE` filter lifts
    // the predicate so the invalidated edge resurfaces.
    let historical = store
        .kg_query_cte_filtered(&a, 3, true)
        .await
        .expect("kg_query_cte_filtered historical");
    assert!(
        historical.iter().any(|r| r.target_id == b),
        "historical view includes the invalidated edge"
    );

    // kg_timeline with since/until/limit filters — exercises the
    // bounded CTE arm (a wide window so our just-written edge lands).
    let since = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let tl = store
        .kg_timeline(&a, Some(&since), Some(&until), Some(25))
        .await
        .expect("kg_timeline filtered");
    assert!(
        tl.iter().any(|r| r.target_id == b),
        "filtered timeline still surfaces the a→b assertion"
    );
}

// ===================================================================
// PostgresStore — consolidate (insert-new + delete-sources)
// ===================================================================

#[tokio::test]
async fn consolidate_inserts_new_and_deletes_sources() {
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2-consol");
    let ns = uid("cov-consol2");
    let a = uid("csa");
    let b = uid("csb");
    store
        .store(
            &ctx,
            &mem(&a, &ns, "consol src a", "abody", "ai:ga2-consol"),
        )
        .await
        .unwrap();
    store
        .store(
            &ctx,
            &mem(&b, &ns, "consol src b", "bbody", "ai:ga2-consol"),
        )
        .await
        .unwrap();

    let new_id = store
        .consolidate(
            &ctx,
            &[a.clone(), b.clone()],
            "consolidated ga2",
            "merged summary over a and b",
            &ns,
            &Tier::Long,
            "ga2-consol",
            "ai:ga2-consol",
        )
        .await
        .expect("consolidate");

    let got = store.get(&ctx, &new_id).await.expect("get consolidated");
    assert_eq!(got.title, "consolidated ga2");
    // Sources were deleted as part of the consolidation.
    assert!(
        matches!(
            store.get(&ctx, &a).await,
            Err(ai_memory::store::StoreError::NotFound { .. })
        ),
        "consolidate deletes source a"
    );
}

// ===================================================================
// PostgresStore — update trait method (owner-gate + COALESCE + version)
// ===================================================================

#[tokio::test]
async fn update_trait_coalesce_patch_bumps_version() {
    use ai_memory::store::UpdatePatch;
    let Some(store) = connect().await else {
        return;
    };
    let agent = uid("ai:ga2-upd");
    let ctx = CallerContext::for_agent(&agent);
    let ns = uid("cov-update");
    let id = uid("upd");
    store
        .store(&ctx, &mem(&id, &ns, "before", "old body", &agent))
        .await
        .unwrap();

    let patch = UpdatePatch {
        title: Some("after".to_string()),
        content: Some("new body".to_string()),
        priority: Some(8),
        ..UpdatePatch::default()
    };
    store
        .update(&ctx, &id, patch)
        .await
        .expect("owner update applies");

    let got = store.get(&ctx, &id).await.expect("get updated");
    assert_eq!(got.title, "after");
    assert_eq!(got.content, "new body");
    assert_eq!(got.priority, 8);
    assert!(
        got.version >= 2,
        "update bumps version (got {})",
        got.version
    );

    // Owner gate: a different (non-owner, non-admin) caller is refused.
    let intruder = CallerContext::for_agent(uid("ai:ga2-upd-intruder"));
    let denied = store
        .update(
            &intruder,
            &id,
            UpdatePatch {
                title: Some("hijack".to_string()),
                ..UpdatePatch::default()
            },
        )
        .await;
    assert!(
        matches!(
            denied,
            Err(ai_memory::store::StoreError::PermissionDenied { .. })
        ),
        "non-owner update is refused: {denied:?}"
    );
}

// ===================================================================
// PostgresStore — list_archived full projection decode loop
// ===================================================================

#[tokio::test]
async fn list_archived_projects_all_columns_for_rich_row() {
    let Some(store) = connect().await else {
        return;
    };
    let agent = uid("ai:ga2-arch");
    let ctx = CallerContext::for_agent(&agent);
    let ns = uid("cov-arch-proj");
    let id = uid("arc");
    // Populate the nullable + provenance columns so the decode loop
    // walks the full projection (citations, source_uri, source_span,
    // confidence_signals, last_accessed_at, expires_at, …).
    let mut m = mem(&id, &ns, "rich archive row", "body with provenance", &agent);
    m.tier = Tier::Long;
    m.source_uri = Some("test:rich-provenance".to_string());
    m.last_accessed_at = Some(chrono::Utc::now().to_rfc3339());
    m.expires_at = Some((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339());
    m.confidence_source = ConfidenceSource::CallerProvided;
    store.store(&ctx, &m).await.unwrap();

    let moved = store
        .archive_by_ids(&ctx, std::slice::from_ref(&id), Some("ga2-projection"))
        .await
        .expect("archive_by_ids");
    assert_eq!(moved, 1);

    // list_archived → list_archived_pg → full per-column decode loop.
    let archived = store
        .list_archived(Some(&ns), 50, 0)
        .await
        .expect("list_archived");
    let row = archived
        .iter()
        .find(|v| v.get("id").and_then(serde_json::Value::as_str) == Some(id.as_str()))
        .expect("our archived row is projected");
    assert_eq!(
        row.get("namespace").and_then(serde_json::Value::as_str),
        Some(ns.as_str())
    );
    assert_eq!(
        row.get("source_uri").and_then(serde_json::Value::as_str),
        Some("test:rich-provenance")
    );
    assert_eq!(
        row.get("archive_reason")
            .and_then(serde_json::Value::as_str),
        Some("ga2-projection")
    );
}

// ===================================================================
// PostgresStore — capture_turn_idempotent distinct-key second write
// ===================================================================

#[tokio::test]
async fn capture_turn_distinct_keys_are_two_inserts() {
    use ai_memory::models::CaptureTurnWrite;
    use ai_memory::signed_events::SignedEvent;
    let Some(store) = connect().await else {
        return;
    };
    let ctx = CallerContext::for_agent("ai:ga2-capture");
    let ns = uid("cov-capture2");
    let session = uid("sess");

    let mk_write = |turn: i64| -> CaptureTurnWrite {
        let sha = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(format!("{session}|{turn}|distinct").as_bytes());
            h.finalize().to_vec()
        };
        let memory = mem(
            &uid("ct"),
            &ns,
            &uid("turn-title"),
            "distinct turn content",
            "ai:ga2-capture",
        );
        let signed_event = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "ai:ga2-capture".to_string(),
            event_type: "memory.capture_turn".to_string(),
            payload_hash: sha.clone(),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        };
        CaptureTurnWrite {
            memory,
            sha256: sha,
            host_kind: "claude-code".to_string(),
            host_session_id: session.clone(),
            host_turn_index: turn,
            recovered_at_ms: chrono::Utc::now().timestamp_millis(),
            signed_event,
        }
    };

    let first = store
        .capture_turn_idempotent(&ctx, &mk_write(0))
        .await
        .expect("turn 0");
    assert!(!first.dedup_hit, "first distinct key is a miss");

    let second = store
        .capture_turn_idempotent(&ctx, &mk_write(1))
        .await
        .expect("turn 1");
    assert!(
        !second.dedup_hit,
        "distinct (session,turn) key is also a miss"
    );
    assert_ne!(
        first.memory_id, second.memory_id,
        "distinct keys mint distinct memories"
    );
}

// ===================================================================
// federation::sync — live mock peer (Ack + IdDrift arms)
// ===================================================================

/// A loopback mock peer that accepts ONE HTTP request, drains the
/// request body, and replies with a canned response. Returns the bound
/// `127.0.0.1:<port>` URL once the listener is up. The accept loop runs
/// detached on the tokio runtime; `payload_status` is the HTTP status
/// line + JSON body the peer replies with.
async fn spawn_mock_peer(status_line: &'static str, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock peer");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        // Serve a bounded number of connections so a peer fan-out plus
        // its single retry are both answered.
        for _ in 0..8 {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let status_line = status_line.to_string();
            let body = body.to_string();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Drain whatever the client sends (we don't parse it).
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    format!("http://{addr}/api/v1/sync/push")
}

/// W=2 quorum config: local commit alone does NOT meet quorum, so a peer
/// ack is REQUIRED to satisfy it — forcing the `record_peer_ack` +
/// `is_quorum_met` break path through the loop.
fn quorum_config_w2(
    peers: Vec<ai_memory::federation::PeerEndpoint>,
) -> ai_memory::federation::FederationConfig {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    ai_memory::federation::FederationConfig {
        policy: ai_memory::replication::QuorumPolicy::new(
            2,
            2,
            Duration::from_secs(2),
            Duration::from_secs(30),
        )
        .unwrap(),
        peers,
        client,
        sender_agent_id: "ai:ga2-adapter2-sender".to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

fn peer(id: &str, url: String) -> ai_memory::federation::PeerEndpoint {
    ai_memory::federation::PeerEndpoint {
        id: id.to_string(),
        sync_push_url: url,
    }
}

fn ga2_memory(id: &str) -> Memory {
    mem(
        id,
        "ga2-fed-ns",
        "ga2 fed mem",
        "fed body",
        "ai:ga2-adapter2-sender",
    )
}

#[tokio::test]
async fn broadcast_archive_quorum_peer_ack_meets_quorum() {
    // 200 + `{}` (no `ids`) → AckOutcome::Ack → record_peer_ack →
    // is_quorum_met true (local + 1 peer == W=2) → loop break.
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-ack", url)]);
    let tracker = ai_memory::federation::sync::broadcast_archive_quorum(&cfg, "arch-ack")
        .await
        .expect("archive quorum returns tracker");
    assert!(
        tracker.finalise(std::time::Instant::now()).is_ok(),
        "local + acking peer meet W=2 quorum"
    );
}

#[tokio::test]
async fn broadcast_delete_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-ack", url)]);
    let tracker = ai_memory::federation::sync::broadcast_delete_quorum(&cfg, "del-ack")
        .await
        .expect("delete quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_link_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-ack", url)]);
    let link = link("ga2-fed-src", "ga2-fed-tgt");
    let tracker = ai_memory::federation::sync::broadcast_link_quorum(&cfg, &link)
        .await
        .expect("link quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_consolidate_quorum_peer_ack_meets_quorum() {
    let url = spawn_mock_peer("200 OK", "{}").await;
    let cfg = quorum_config_w2(vec![peer("peer-ack", url)]);
    let m = ga2_memory("consol-ack");
    let sources = vec!["src-x".to_string(), "src-y".to_string()];
    let tracker = ai_memory::federation::sync::broadcast_consolidate_quorum(&cfg, &m, &sources)
        .await
        .expect("consolidate quorum returns tracker");
    assert!(tracker.finalise(std::time::Instant::now()).is_ok());
}

#[tokio::test]
async fn broadcast_quorum_peer_id_drift_does_not_meet_quorum() {
    // 200 + `{"ids":["someone-else"]}` where the echoed id disagrees with
    // the expected commit id → AckOutcome::IdDrift → record_id_drift,
    // which does NOT count toward quorum. With W=2 and only the local
    // commit counted, finalise must fail QuorumNotMet.
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"a-different-id-entirely\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-drift", url)]);
    let tracker = ai_memory::federation::sync::broadcast_archive_quorum(&cfg, "arch-drift")
        .await
        .expect("archive quorum returns tracker even on id-drift");
    let outcome = tracker.finalise(std::time::Instant::now());
    assert!(
        matches!(
            outcome,
            Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
        ),
        "id-drift does not satisfy quorum: {outcome:?}"
    );
}

#[tokio::test]
async fn broadcast_link_quorum_peer_id_drift_arm() {
    let url = spawn_mock_peer("200 OK", "{\"ids\":[\"nope-not-this-link\"]}").await;
    let cfg = quorum_config_w2(vec![peer("peer-drift", url)]);
    let link = link("ga2-drift-src", "ga2-drift-tgt");
    let tracker = ai_memory::federation::sync::broadcast_link_quorum(&cfg, &link)
        .await
        .expect("link quorum returns tracker on id-drift");
    assert!(
        matches!(
            tracker.finalise(std::time::Instant::now()),
            Err(ai_memory::replication::QuorumError::QuorumNotMet { .. })
        ),
        "link id-drift does not satisfy quorum"
    );
}

// ===================================================================
// cli::schema_init — live postgres init + enumerate + AGE bootstrap arm
// ===================================================================

#[tokio::test]
async fn schema_init_run_postgres_enumerates_live_catalog() {
    let Some(url) = postgres_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);

    let args = ai_memory::cli::schema_init::SchemaInitArgs {
        store_url: url.clone(),
        json: true,
        embedding_dim: 384,
    };
    // Drives run → init_and_enumerate_postgres → connect_with_dim →
    // migrate_embedding_dim → enumerate_postgres (+ bootstrap_memory_graph
    // when AGE is present) → current_embedding_dim.
    ai_memory::cli::schema_init::run(&args, &mut out)
        .await
        .expect("schema-init against live postgres");

    let raw = String::from_utf8(stdout).expect("utf-8 stdout");
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parseable JSON, got {raw}: {e}"));
    assert_eq!(v["kind"], "postgres", "wrong kind: {v}");
    assert!(
        v["schema_version"].as_i64().unwrap() > 0,
        "schema_version > 0 after init: {v}"
    );
    let tables: Vec<&str> = v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(
        tables.contains(&"memories"),
        "memories table present: {tables:?}"
    );
    // embedding_dim is read back from the live catalog post-init.
    assert!(
        v.get("embedding_dim").is_some(),
        "report carries embedding_dim field: {v}"
    );
}

#[tokio::test]
async fn schema_init_run_postgres_human_render() {
    let Some(url) = postgres_url() else {
        return;
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);

    let args = ai_memory::cli::schema_init::SchemaInitArgs {
        store_url: url,
        json: false,
        embedding_dim: 384,
    };
    ai_memory::cli::schema_init::run(&args, &mut out)
        .await
        .expect("schema-init human render against live postgres");

    let rendered = String::from_utf8(stdout).expect("utf-8 stdout");
    assert!(
        rendered.contains("schema initialized at"),
        "human render header present: {rendered}"
    );
    assert!(rendered.contains("schema_version:"), "got: {rendered}");
    assert!(rendered.contains("extensions:"), "got: {rendered}");
}
