// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::atomisation::{
    Atomiser, AtomiserConfig,
    curator::{Atom, Curator, CuratorError},
};
use crate::config::FeatureTier;
use crate::models::{AtomisationPolicy, AutoAtomiseMode, GovernancePolicy, Memory, Tier};
use std::sync::{Mutex, mpsc};
use tower::ServiceExt as _;

struct HeldCurator {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl Curator for HeldCurator {
    fn decompose(&self, _: &str, _: u32, _: u32) -> Result<Vec<Atom>, CuratorError> {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        Ok(vec![
            Atom {
                text: "first shutdown atom".into(),
            },
            Atom {
                text: "second shutdown atom".into(),
            },
        ])
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn http_create_writer_blocks_certification_and_deadline_is_fatal_4062() {
    const CHILD: &str = "AI_MEMORY_4062_HTTP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let witness = tempfile::tempdir().unwrap();
        let key = crate::identity::keypair::generate(crate::governance::audit::WITNESS_KEY_LABEL)
            .unwrap();
        crate::identity::keypair::save(&key, witness.path()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "daemon_runtime::daemon_atomise_shutdown_tests::http_create_writer_blocks_certification_and_deadline_is_fatal_4062", "--nocapture"])
            .env(CHILD, "1")
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .env(crate::governance::audit::WITNESS_KEY_DIR_ENV, witness.path())
            .env(crate::governance::audit::WITNESS_PUBKEY_ENV, key.public_base64())
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let _no_pass = crate::test_support::no_passphrase_guard();
    let _sandbox = crate::identity::test_key_dir::install();
    for deadline_expires in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("http.db");
        let args = super::daemon_runtime_shutdown_tests::bind_failure_args();
        let config = AppConfig {
            tier: Some("keyword".into()),
            ..AppConfig::default()
        };
        let mut bs = bootstrap_serve(&path, &args, &config).await.unwrap();
        bs.app_state.atomise_queue.as_ref().unwrap().close();
        bs.atomise_worker.take().unwrap().join().unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let atomiser = Arc::new(Atomiser::new(
            Box::new(HeldCurator {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            None,
            AtomiserConfig::default(),
            FeatureTier::Smart,
        ));
        let (queue, worker) = crate::background::atomise_worker::spawn_tracked(
            Arc::new(move || Some(atomiser.clone())),
            bs.blocking_tasks.clone(),
        )
        .unwrap();
        bs.app_state.atomise_queue = Some(queue.clone());
        bs.app_state.tier_config = Arc::new(FeatureTier::Smart.config());
        bs.app_state.llm = Arc::new(crate::reload::SwappableLlm::new(Some(
            crate::llm::OllamaClient::new_with_url_no_health_check(
                "http://127.0.0.1:1",
                "latched-curator",
            )
            .unwrap(),
        )));
        let conn = crate::db::open(&path).unwrap();
        let ns = "shutdown4062";
        let policy = GovernancePolicy {
            atomisation: AtomisationPolicy {
                auto_atomise: Some(true),
                auto_atomise_threshold_cl100k: Some(20),
                auto_atomise_max_atom_tokens: Some(50),
                auto_atomise_max_retries: None,
                auto_atomise_mode: Some(AutoAtomiseMode::Deferred),
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().to_rfc3339();
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.into(),
            title: "__standard_shutdown4062".into(),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id":"ai:test", "governance": policy}),
            ..Default::default()
        };
        let id = crate::db::insert(&conn, &standard).unwrap();
        crate::db::set_namespace_standard(&conn, ns, &id, None).unwrap();
        let router = build_router(bs.app_state, bs.api_key_state);
        let response = router.clone().oneshot(axum::http::Request::builder().method("POST")
            .uri("/api/v1/memories").header("content-type", "application/json").header("x-agent-id", "ai:test")
            .body(axum::body::Body::from(serde_json::json!({"tier":"long", "namespace":ns,
                "title":"held HTTP create", "content":"Readiness checks must pass before traffic shifts. ".repeat(100),
                "tags":[], "priority":5, "confidence":1.0, "source":"user", "metadata":{}}).to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        assert!(
            status.is_success(),
            "{status}: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["atomise_outcome"], "queued", "{body}");
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        queue.close();
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM checkpoints WHERE condition_type='audit_head_witness'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let db = bs.db_state.clone();
        let tracker = bs.blocking_tasks.clone();
        let budget = if deadline_expires {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(10)
        };
        let mut shutdown = tokio::spawn(async move {
            super::shutdown::join_background_writers(
                bs.task_handles,
                &tracker,
                Some(worker),
                tokio::time::Instant::now() + budget,
            )
            .await?;
            super::shutdown_witness_flush_and_checkpoint(&db).await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "certification raced the held writer"
        );
        let during: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM checkpoints WHERE condition_type='audit_head_witness'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(during, before);
        if deadline_expires {
            let error = shutdown.await.unwrap().unwrap_err();
            assert!(
                error.is::<FatalShutdownError>(),
                "must select the binary's exit-75 marker: {error}"
            );
            let after: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM checkpoints WHERE condition_type='audit_head_witness'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(after, before, "deadline must omit certification");
            release_tx.send(()).unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while bs.blocking_tasks.load(Ordering::SeqCst) != 0 {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } else {
            release_tx.send(()).unwrap();
            shutdown.await.unwrap().unwrap();
            let completed: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_events WHERE event_type='atomisation_complete'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(completed, 1);
            let head: i64 = conn
                .query_row("SELECT MAX(sequence) FROM signed_events", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let resolution: String = conn.query_row("SELECT resolution FROM checkpoints WHERE condition_type='audit_head_witness' ORDER BY created_at DESC LIMIT 1", [], |row| row.get(0)).unwrap();
            let resolution: serde_json::Value = serde_json::from_str(&resolution).unwrap();
            assert_eq!(resolution["signed_events"]["head_sequence"], head);
        }
    }
}
