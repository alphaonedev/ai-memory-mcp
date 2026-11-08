// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8444: the server speaks the Google `Agent2Agent` (A2A 1.0) standard
//! (JSON-RPC binding, shape S1, posture P1) on the SQLite backend. The
//! PostgreSQL twin is `a2a_standard_8444_pg.rs`; both run the same scenarios.

mod a2a_standard_8444_common;

use a2a_standard_8444_common::{run_suite, sqlite_app_state, sqlite_scope_mover};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2a_standard_binding_sqlite_8444() {
    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, std::path::PathBuf::from),
    )
    .expect("scratch dir");
    let app = sqlite_app_state(&dir.path().join("a2a-8444.db"));
    let mover = sqlite_scope_mover(&app);
    run_suite(app, mover).await;
}

/// In-memory `tracing` writer (the `tests/authz_refusal_trace_3426.rs` idiom).
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// #8444 r5 code INFO-A: EVERY refusal of a completion (the two `-32004`
/// paths and the `-32603` storage or vanished-task paths) leaves the inbox
/// memory stored and unlinked, and logs its id at info. The completion runs
/// on a current-thread runtime so the thread-local subscriber sees every
/// event. The logging sits in the backend-agnostic handler layer, so the
/// SQLite cell stands for both backends.
#[tokio::test(flavor = "current_thread")]
async fn every_completion_refusal_logs_the_unlinked_inbox_memory_8444() {
    use a2a_standard_8444_common::ALICE;
    use ai_memory::storage::a2a_tasks::A2aHistoryEntry;

    let dir = tempfile::tempdir_in(
        std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, std::path::PathBuf::from),
    )
    .expect("scratch dir");
    let app = sqlite_app_state(&dir.path().join("a2a-8444-log.db"));
    let sink = Capture::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let vanished = format!("log-vanished-8444-{}", uuid::Uuid::new_v4());
    let ended = format!("log-ended-8444-{}", uuid::Uuid::new_v4());
    let stuck = format!("log-stuck-8444-{}", uuid::Uuid::new_v4());
    a2a_standard_8444_common::seed_task(
        &app,
        &a2a_standard_8444_common::SeedTask::new(
            ALICE,
            &ended,
            "ctx-log-8444",
            "TASK_STATE_CANCELED",
        ),
    )
    .await;
    a2a_standard_8444_common::seed_task(
        &app,
        &a2a_standard_8444_common::SeedTask::new(
            ALICE,
            &stuck,
            "ctx-log-8444",
            "TASK_STATE_INPUT_REQUIRED",
        ),
    )
    .await;

    for (task_id, code) in [(&vanished, -32603), (&ended, -32004), (&stuck, -32004)] {
        let memory_id = format!("inbox-memory-{}", uuid::Uuid::new_v4());
        let entry = A2aHistoryEntry {
            message_id: uuid::Uuid::new_v4().to_string(),
            role: "ROLE_USER".to_string(),
            context_id: "ctx-log-8444".to_string(),
            task_id: task_id.clone(),
            memory_id: memory_id.clone(),
        };
        let err = ai_memory::handlers::a2a_complete_message(&app, ALICE, task_id, entry)
            .await
            .expect_err("every one of these completions is refused");
        assert_eq!(err.code, code, "{task_id}: {err:?}");
        let logs = String::from_utf8_lossy(
            &sink
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .into_owned();
        let line = logs
            .lines()
            .find(|l| l.contains(&memory_id))
            .unwrap_or_else(|| panic!("{task_id}: no log line names {memory_id}: {logs}"));
        assert!(line.contains("stays unlinked"), "{task_id}: {line}");
        assert!(line.contains(task_id.as_str()), "{task_id}: {line}");
        assert!(line.contains("INFO"), "{task_id}: {line}");
    }
}
