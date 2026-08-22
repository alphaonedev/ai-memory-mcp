// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3148 — the federation S40 catch-up batch lane
//! (`federation::sync::bulk_catchup_push`) MUST pass through the same
//! `AgentAction::NetworkRequest` governance egress gate the per-row fanout
//! (`post_once`) honours.
//!
//! ## The defect this pins closed
//!
//! `post_once` consulted `governance::wire_check` before its POST;
//! `bulk_catchup_push` open-coded its own `client.post(&url)…send()` and
//! consulted NOTHING. An operator `refuse` rule for a peer host therefore
//! blocked the per-row fanout while the catch-up lane still shipped FULL
//! memory batches to that same host — ungoverned egress of memory content —
//! and emitted no `governance.check` `signed_events` row, so the audit chain
//! could not even show that the egress had happened (an audit asymmetry).
//!
//! ## Why a dedicated test binary
//!
//! `wire_check::GOVERNANCE_PRE_ACTION` is a process-wide `OnceLock` with no
//! reset (installation is one-shot BY DESIGN — the operator directive that
//! rules can never be bypassed). Cargo gives each integration-test crate its
//! own binary, so this file owns the install for its own process and can
//! assert the REFUSE arm end-to-end without racing a sibling suite.
//!
//! The hook installed here is the REAL rule engine
//! (`governance::agent_action::check_agent_action`) against a real on-disk
//! substrate, so the assertions cover the production path — including the
//! `governance.check` audit row `check_agent_action` emits on every verdict.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::governance::agent_action::{AgentAction, GOVERNANCE_CHECK_EVENT_TYPE};
use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;

/// Sender agent id used for the catch-up body + the `x-peer-id` header.
const SENDER: &str = "ai:catchup-egress-3148";
/// The rule-engine actor the daemon installs for wire-point checks.
const WIRE_ACTOR: &str = "ai:wire-check-3148";

/// A loopback peer that COUNTS accepted connections. The count is the
/// load-bearing assertion: a governed-refused lane must produce ZERO.
async fn spawn_counting_peer() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock peer");
    let addr = listener.local_addr().expect("local_addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_task = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            hits_for_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let body = "{}";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    (format!("http://{addr}/api/v1/sync/push"), hits)
}

fn fixture_memory(id: &str) -> Memory {
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "catchup-egress-3148".to_string(),
        title: format!("catch-up fixture {id}"),
        content: "durable memory text that must never egress ungoverned".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: "2026-08-20T00:00:00+00:00".to_string(),
        updated_at: "2026-08-20T00:00:00+00:00".to_string(),
        metadata: serde_json::json!({}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

fn config(peer_url: &str) -> FederationConfig {
    FederationConfig {
        policy: QuorumPolicy::new(1, 2, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: "peer-refused-3148".to_string(),
            sync_push_url: peer_url.to_string(),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        sender_agent_id: SENDER.to_string(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

/// A refuse-rule for the loopback peer host blocks the BULK catch-up lane,
/// zero bytes reach the peer, and the refusal is recorded on the audit chain
/// as a `governance.check` `signed_events` row.
#[tokio::test]
async fn refuse_rule_blocks_the_bulk_catchup_lane_and_emits_governance_check() {
    // Isolate the operator-pubkey resolution so the unsigned refuse-rule
    // below is honoured on a dev host that happens to have a real
    // `operator.key.pub` staged (CI has none; this makes the two match).
    let key_dir = tempfile::tempdir().expect("key tempdir");
    // SAFETY: single-threaded test setup, before any peer task is spawned.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_dir.path());
    }

    let db_dir = tempfile::tempdir().expect("db tempdir");
    let db_path = db_dir.path().join("egress-3148.sqlite");
    let conn = ai_memory::db::open(&db_path).expect("open substrate");
    rules_store::insert(
        &conn,
        &Rule {
            id: "R-3148-refuse-loopback".to_string(),
            kind: "network_request".to_string(),
            matcher: r#"{"host":"127.0.0.1"}"#.to_string(),
            severity: "refuse".to_string(),
            reason: "no federation egress to the loopback peer".to_string(),
            namespace: "_global".to_string(),
            created_by: "test".to_string(),
            created_at: 0,
            enabled: true,
            signature: None,
            attest_level: ai_memory::models::AttestLevel::Unsigned
                .as_str()
                .to_string(),
        },
    )
    .expect("insert refuse rule");

    // Install the REAL engine as the process-wide wire-point hook (the daemon
    // shape), so the refusal AND its `governance.check` audit row come from
    // production code rather than a stub.
    let hook_conn = Arc::new(std::sync::Mutex::new(conn));
    let hook_conn_for_hook = Arc::clone(&hook_conn);
    ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION
        .set(Box::new(move |action: &AgentAction| {
            let guard = hook_conn_for_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match ai_memory::governance::agent_action::check_agent_action(
                &guard, WIRE_ACTOR, action,
            ) {
                Ok(decision) => match decision {
                    ai_memory::governance::agent_action::Decision::Refuse { reason, .. }
                    | ai_memory::governance::agent_action::Decision::Escalate { reason, .. } => {
                        Err(reason)
                    }
                    _ => Ok(()),
                },
                // Fail CLOSED on a consultation fault (the daemon posture).
                Err(e) => Err(format!("governance:consultation_failed: {e}")),
            }
        }))
        .map_err(|_| ())
        .expect("this binary owns the one-shot hook install");

    let (url, hits) = spawn_counting_peer().await;
    let cfg = config(&url);
    let memories = vec![fixture_memory("mem-catchup-3148")];

    let errors = ai_memory::federation::sync::bulk_catchup_push(&cfg, &memories).await;

    assert_eq!(
        errors.len(),
        1,
        "the governed-refused peer must surface exactly one error row: {errors:?}"
    );
    assert_eq!(errors[0].0, "peer-refused-3148");
    assert!(
        errors[0]
            .1
            .contains("governance refused outbound to 127.0.0.1"),
        "the catch-up error must carry the governance refusal, not a transport error; got: {}",
        errors[0].1
    );
    assert!(
        errors[0]
            .1
            .contains("no federation egress to the loopback peer"),
        "the operator-authored rule reason must reach the caller; got: {}",
        errors[0].1
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a governance-refused catch-up must ship ZERO bytes to the peer"
    );

    // The audit asymmetry is closed: the refusal is on the signed chain.
    let guard = hook_conn
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let events =
        ai_memory::signed_events::list_signed_events(&guard, None, 1000, 0).expect("list events");
    let checks: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == GOVERNANCE_CHECK_EVENT_TYPE)
        .collect();
    assert!(
        !checks.is_empty(),
        "a governed catch-up egress attempt must emit a governance.check signed_events row"
    );
}
