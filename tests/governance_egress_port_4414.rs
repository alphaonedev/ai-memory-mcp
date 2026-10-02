// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4414 — the REAL egress sinks (the LLM client `OllamaClient::generate_async`
//! and the federation peer POST `federation::sync::bulk_catchup_push`) hand the
//! governance gate the URL host PLUS its explicit port, and the engine applies
//! the scheme default for a portless URL. A port-scoped `network_request` rule
//! therefore enforces on both sinks. A sink that dropped the port (the
//! pre-#4414 `host_str()` derivation) would make every cell below that expects a
//! refusal on an explicit non-default port fail.
//!
//! One test binary, one `#[tokio::test]`: the wire-point hook is a process-wide
//! one-shot `OnceLock`, and the rule set is swapped between cells.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_memory::federation::{FederationConfig, PeerEndpoint};
use ai_memory::governance::agent_action::{AgentAction, Decision, check_agent_action};
use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::llm::OllamaClient;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::replication::QuorumPolicy;

type Seen = Arc<Mutex<Vec<(String, String)>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await;
            });
        }
    });
    (port, hits)
}

fn memory() -> Memory {
    Memory {
        id: "mem-4414".into(),
        tier: Tier::Long,
        namespace: "egress-port-4414".into(),
        title: "fixture".into(),
        content: "fixture".into(),
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        created_at: "2026-08-20T00:00:00+00:00".into(),
        updated_at: "2026-08-20T00:00:00+00:00".into(),
        metadata: serde_json::json!({}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

fn fed_config(url: &str) -> FederationConfig {
    FederationConfig {
        policy: QuorumPolicy::new(1, 2, Duration::from_secs(2), Duration::from_secs(30))
            .expect("policy"),
        peers: vec![PeerEndpoint {
            id: "peer-4414".into(),
            sync_push_url: url.into(),
        }],
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        sender_agent_id: "ai:egress-port-4414".into(),
        api_key: None,
        signing_key: None,
        dlq_sink: None,
    }
}

fn set_rule(conn: &Mutex<rusqlite::Connection>, host: Option<&str>) {
    let c = lock(conn);
    c.execute("DELETE FROM governance_rules", [])
        .expect("clear rules");
    if let Some(h) = host {
        rules_store::insert(
            &c,
            &Rule {
                id: "R-4414".into(),
                kind: "network_request".into(),
                matcher: serde_json::json!({ "host": h }).to_string(),
                severity: "refuse".into(),
                reason: "port rule 4414".into(),
                namespace: "_global".into(),
                created_by: "test".into(),
                created_at: 0,
                enabled: true,
                signature: None,
                attest_level: ai_memory::models::AttestLevel::Unsigned.as_str().into(),
            },
        )
        .expect("insert rule");
    }
}

/// Federation sink: was the peer POST refused by governance?
async fn fed_refused(url: &str) -> bool {
    let errors =
        ai_memory::federation::sync::bulk_catchup_push(&fed_config(url), &[memory()]).await;
    errors
        .iter()
        .any(|(_, e)| e.contains("governance refused outbound"))
}

/// LLM sink: was `generate_async` refused by governance? (A fresh client per
/// cell so a transport failure never trips the circuit breaker.)
async fn llm_refused(base_url: &str) -> bool {
    let client = OllamaClient::new_with_url_no_health_check(base_url, "m").expect("client");
    match client.generate_async("hi", None).await {
        Ok(_) => false,
        Err(e) => format!("{e:#}").contains("governance refused outbound"),
    }
}

#[tokio::test]
async fn issue_4414_port_rules_enforce_on_the_real_egress_sinks() {
    let key_dir = tempfile::tempdir().expect("key dir");
    // SAFETY: single-threaded setup before any task is spawned.
    unsafe {
        std::env::set_var("AI_MEMORY_KEY_DIR", key_dir.path());
    }
    let db_dir = tempfile::tempdir().expect("db dir");
    let conn = Arc::new(Mutex::new(
        ai_memory::db::open(&db_dir.path().join("p.sqlite")).expect("open"),
    ));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let (hook_conn, hook_seen) = (Arc::clone(&conn), Arc::clone(&seen));
    ai_memory::governance::wire_check::GOVERNANCE_PRE_ACTION
        .set(Box::new(move |action: &AgentAction| {
            if let AgentAction::NetworkRequest { host, scheme } = action {
                lock(&hook_seen).push((host.clone(), scheme.clone()));
            }
            let g = lock(&hook_conn);
            match check_agent_action(&g, "ai:wire-4414", action) {
                Ok(Decision::Refuse { reason, .. } | Decision::Escalate { reason, .. }) => {
                    Err(reason)
                }
                Ok(_) => Ok(()),
                Err(e) => Err(format!("governance:consultation_failed: {e}")),
            }
        }))
        .map_err(|_| ())
        .expect("this binary owns the one-shot hook install");

    let (port, hits) = counting_listener().await;
    let explicit = format!("http://127.0.0.1:{port}");
    let other = if port == 9 { 10 } else { 9 };

    // ---- explicit non-default port ------------------------------------
    for sink in ["fed", "llm"] {
        let url = if sink == "fed" {
            format!("{explicit}/api/v1/sync/push")
        } else {
            explicit.clone()
        };
        let refused = |u: String| async move {
            if sink == "fed" {
                fed_refused(&u).await
            } else {
                llm_refused(&u).await
            }
        };

        lock(&seen).clear();
        let before = hits.load(Ordering::SeqCst);
        set_rule(&conn, Some(&format!("127.0.0.1:{port}")));
        assert!(
            refused(url.clone()).await,
            "{sink}: rule on the explicit port must refuse"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before,
            "{sink}: refused egress ships nothing"
        );
        assert_eq!(
            lock(&seen).first().map(|(h, s)| (h.clone(), s.clone())),
            Some((format!("127.0.0.1:{port}"), "http".to_string())),
            "{sink}: the sink must pass host AND explicit port"
        );

        set_rule(&conn, Some(&format!("127.0.0.1:{other}")));
        assert!(
            !refused(url.clone()).await,
            "{sink}: a rule on another port must not refuse"
        );

        set_rule(&conn, Some("127.0.0.1"));
        assert!(
            refused(url.clone()).await,
            "{sink}: a portless rule matches any port"
        );
    }

    // ---- portless URLs: the scheme default is the effective port -------
    for sink in ["fed", "llm"] {
        let mk = |scheme: &str| {
            if sink == "fed" {
                format!("{scheme}://127.0.0.1/api/v1/sync/push")
            } else {
                format!("{scheme}://127.0.0.1")
            }
        };
        let refused = |u: String| async move {
            if sink == "fed" {
                fed_refused(&u).await
            } else {
                llm_refused(&u).await
            }
        };

        set_rule(&conn, Some("127.0.0.1:443"));
        assert!(refused(mk("https")).await, "{sink}: https defaults to 443");
        assert!(
            !refused(mk("http")).await,
            "{sink}: http defaults to 80, not 443"
        );

        set_rule(&conn, Some("127.0.0.1:80"));
        assert!(refused(mk("http")).await, "{sink}: http defaults to 80");
        assert!(
            !refused(mk("https")).await,
            "{sink}: https defaults to 443, not 80"
        );

        // An explicit default port is dropped by the URL parser; the engine
        // re-applies the scheme default, so the rule still fires.
        set_rule(&conn, Some("127.0.0.1:443"));
        let explicit_default = if sink == "fed" {
            "https://127.0.0.1:443/api/v1/sync/push".to_string()
        } else {
            "https://127.0.0.1:443".to_string()
        };
        assert!(
            refused(explicit_default).await,
            "{sink}: explicit :443 on https"
        );
    }
}
