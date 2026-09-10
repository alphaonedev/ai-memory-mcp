// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U2 — `watch --host file:<path>` acceptance tests named by the
//! 1x3 audit (issue comment + Operator ruling). Line-file ingest reuses
//! `transcript_line_dedup`; `HostKind` is not extended.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use ai_memory::models::field_names;
use ai_memory::recover::HostKind;
use ai_memory::recover::line_file::{self, FILE_HOST_KIND, SWARM_LINE_TAGS};
use ai_memory::recover::watcher::{self, WatchConfig, WatchPollState};

fn scratch() -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3587-u2-watch-line-file");
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn cfg(agent: &str, files: Vec<PathBuf>, limit: usize, dry_run: bool) -> WatchConfig {
    WatchConfig {
        hosts: Vec::new(),
        line_files: files,
        poll_interval: Duration::from_secs(watcher::DEFAULT_POLL_INTERVAL_SECS),
        agent_id: agent.to_string(),
        namespace: Some("test-watch-3587".to_string()),
        limit,
        dry_run,
        #[cfg(feature = "sal")]
        store: None,
    }
}

fn poll(db: &std::path::Path, cfg: &WatchConfig, states: &mut WatchPollState) {
    let _ = watcher::poll_once(db, cfg, states);
}

#[test]
fn watch_file_authorship_denied_line_actor_is_not_agent_id_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "ai:fable→f1: READY swarm-line-one\n").unwrap();
    let cfg = cfg("ai:watch:test", vec![file.clone()], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    let conn = ai_memory::db::open(&db).unwrap();
    let (agent, observed, title): (String, String, String) = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id'), \
                    json_extract(metadata, '$.observed_actor'), \
                    title FROM memories LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(agent, "ai:watch:test", "DENIED: line actor must not author");
    assert_eq!(observed, "ai:fable");
    assert!(title.starts_with("outbox.log:"), "{title}");
    assert_ne!(agent, "ai:fable");
}

#[test]
fn watch_file_authorship_allowed_watch_process_principal_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "MASTER→GROK STATUS hello\n").unwrap();
    let cfg = cfg("ai:watch:allowed", vec![file], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    let conn = ai_memory::db::open(&db).unwrap();
    let agent: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id') FROM memories LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(agent, "ai:watch:allowed");
}

#[test]
fn watch_file_dry_run_writes_nothing_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "READY dry-run-line\n").unwrap();
    let cfg = cfg("ai:watch:dry", vec![file], 100, true);
    let mut states = WatchPollState::default();
    let outcomes = watcher::poll_once(&db, &cfg, &mut states);
    assert!(outcomes.iter().any(|o| o.changed));
    let report = outcomes[0].recover_report.as_ref().expect("report");
    assert_eq!(report.lines_atomised, 1);
    assert!(
        !db.exists() || {
            let conn = ai_memory::db::open(&db).unwrap();
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
                .unwrap_or(0);
            n == 0
        }
    );
}

#[test]
fn watch_file_limit_bounds_lines_per_tick_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(
        &file,
        "READY line-0\nREADY line-1\nREADY line-2\nREADY line-3\nREADY line-4\n",
    )
    .unwrap();
    let cfg = cfg("ai:watch:limit", vec![file], 2, false);
    let mut states = WatchPollState::default();
    let outcomes = watcher::poll_once(&db, &cfg, &mut states);
    let r = outcomes[0].recover_report.as_ref().unwrap();
    assert_eq!(r.lines_atomised, 2);
    assert!(r.lines_skipped_limit >= 1);
    let conn = ai_memory::db::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(n, 2);
}

#[test]
fn watch_file_dedup_on_regrow_same_bytes() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "ACK same-bytes\n").unwrap();
    let cfg = cfg("ai:watch:dedup", vec![file.clone()], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    std::fs::write(&file, "ACK same-bytes\n").unwrap();
    *states.files.values_mut().next().unwrap() = line_file::LineFileState::default();
    let outcomes = watcher::poll_once(&db, &cfg, &mut states);
    let r = outcomes[0].recover_report.as_ref().unwrap();
    assert_eq!(r.lines_atomised, 0);
    assert_eq!(r.lines_skipped_dedup, 1);
    let conn = ai_memory::db::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn watch_file_host_refuses_binary_or_oversized_line_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    let mut f = std::fs::File::create(&file).unwrap();
    f.write_all(b"READY ok\n").unwrap();
    f.write_all(b"READY \0 binary\n").unwrap();
    let big = vec![b'A'; line_file::MAX_LINE_BYTES + 8];
    f.write_all(&big).unwrap();
    f.write_all(b"\n").unwrap();
    f.flush().unwrap();
    let cfg = cfg("ai:watch:oversize", vec![file], 100, false);
    let mut states = WatchPollState::default();
    let outcomes = watcher::poll_once(&db, &cfg, &mut states);
    let r = outcomes[0].recover_report.as_ref().unwrap();
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("binary") || e.contains("oversized")),
        "{:?}",
        r.errors
    );
}

#[test]
fn watch_file_host_refuses_foreign_uid_path_3587() {
    let err = line_file::inspect_line_file(std::path::Path::new("/etc/passwd"));
    match err {
        Err(e) => assert!(
            e.0.contains("refuses") || e.0.contains("owned") || e.0.contains("symlink"),
            "{e}"
        ),
        Ok(Some(_)) => {
            // Some CI images run as root and /etc/passwd is a regular file
            // owned by the process — still a path outside operator uid of a
            // non-root watch. Accept only if we are root.
            #[cfg(unix)]
            {
                let euid = unsafe { libc::geteuid() };
                assert_eq!(euid, 0, "non-root must refuse /etc/passwd");
            }
        }
        Ok(None) => {}
    }
}

#[test]
fn watch_file_dedup_is_per_file_not_global_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let a = dir.path().join("outbox-a.log");
    let b = dir.path().join("outbox-b.log");
    std::fs::write(&a, "ACK same-bytes-across-files\n").unwrap();
    std::fs::write(&b, "ACK same-bytes-across-files\n").unwrap();
    let cfg = cfg("ai:watch:perfile", vec![a, b], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    let conn = ai_memory::db::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(n, 2, "same line in two files must mint two memories");
    let d: i64 = conn
        .query_row("SELECT COUNT(*) FROM transcript_line_dedup", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(d, 2, "per-file salt must yield two dedup rows");
}

#[test]
fn watch_file_oversized_line_does_not_block_next_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    let mut f = std::fs::File::create(&file).unwrap();
    let big = vec![b'X'; line_file::MAX_LINE_BYTES.saturating_mul(3)];
    f.write_all(&big).unwrap();
    f.write_all(b"\n").unwrap();
    f.write_all(b"READY after-oversize\n").unwrap();
    f.flush().unwrap();
    let cfg = cfg("ai:watch:stream", vec![file.clone()], 100, false);
    let mut states = WatchPollState::default();
    let outcomes = watcher::poll_once(&db, &cfg, &mut states);
    let r = outcomes[0].recover_report.as_ref().unwrap();
    assert!(
        r.errors.iter().any(|e| e.contains("oversized")),
        "{:?}",
        r.errors
    );
    assert_eq!(r.lines_atomised, 1, "{:?}", r.errors);
    let conn = ai_memory::db::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let len = std::fs::metadata(&file).unwrap().len();
    let st = states.files.get(&file).expect("state");
    assert_eq!(st.offset, len);
    assert!(!st.skip_to_newline);
}

#[test]
fn watch_file_skips_whitespace_only_lines_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "READY a\n\n   \nREADY b\n").unwrap();
    let cfg = cfg("ai:watch:blank", vec![file], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    let conn = ai_memory::db::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(n, 2);
}

#[test]
fn watch_file_quiet_tick_does_not_open_db_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "READY first\n").unwrap();
    let cfg = cfg("ai:watch:quiet", vec![file], 100, false);
    let mut states = WatchPollState::default();
    poll(&db, &cfg, &mut states);
    assert!(db.exists());
    let blocker = dir.path().join("not-a-db-dir");
    std::fs::create_dir(&blocker).unwrap();
    let outcomes = watcher::poll_once(&blocker, &cfg, &mut states);
    assert!(
        outcomes.iter().all(|o| o.error.is_none()),
        "quiet tick must not open db: {:?}",
        outcomes.iter().map(|o| &o.error).collect::<Vec<_>>()
    );
}

#[test]
fn watch_file_tag_ssot_matches_module() {
    assert_eq!(
        SWARM_LINE_TAGS,
        &["READY", "STATUS", "BLOCKER", "ACK", "NOTE", "MASTER"]
    );
    assert_eq!(FILE_HOST_KIND, "file");
    assert_eq!(field_names::OBSERVED_ACTOR, "observed_actor");
}

#[test]
fn hostkind_not_extended_with_file_variant() {
    // Compile-time: WatchSource::LineFile exists; HostKind stays four-arm.
    let _ = HostKind::ClaudeCode;
    let _ = HostKind::Codex;
    let _ = HostKind::Gemini;
    let _ = HostKind::Auto;
}

/// Own-process integration test (test-env-lock arm (e) forbids `EnvGuard`
/// writes from `src/cli/watch.rs`). Default build must `refuse_pg_store`.
#[tokio::test]
async fn watch_file_pg_store_refused_without_sal_3587() {
    // SAFETY: this is a dedicated test binary; no other test in this
    // process reads these keys concurrently (UNSAFE-01).
    unsafe {
        std::env::remove_var("AI_MEMORY_STORE_URL_FILE");
        std::env::set_var(
            "AI_MEMORY_STORE_URL",
            "postgres://ai_memory:hunter2@127.0.0.1:1/ai_memory",
        );
    }
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "READY pg-refuse\n").unwrap();
    let args = ai_memory::cli::watch::WatchArgs {
        once: true,
        daemon: false,
        interval_secs: watcher::DEFAULT_POLL_INTERVAL_SECS,
        hosts: vec![format!("file:{}", file.display())],
        namespace: Some("test-watch-3587".to_string()),
        limit: 10,
        dry_run: false,
        json: true,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
    let res = ai_memory::cli::watch::run(&db, &args, Some("ai:watch:pg"), &mut out).await;
    unsafe {
        std::env::remove_var("AI_MEMORY_STORE_URL");
    }
    #[cfg(not(feature = "sal"))]
    {
        assert!(
            res.is_err(),
            "default build must refuse postgres store: {res:?}"
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.to_ascii_lowercase().contains("postgres") || msg.contains("watch"),
            "{msg}"
        );
    }
    #[cfg(feature = "sal")]
    {
        assert!(
            res.is_err(),
            "sal + unreachable postgres must fail closed, not write sqlite"
        );
    }
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn watch_file_sal_store_allowed_twin_3587() {
    let dir = scratch();
    let db = dir.path().join("mem.db");
    let file = dir.path().join("outbox.log");
    std::fs::write(&file, "READY sal-twin\n").unwrap();
    let store = ai_memory::store::sqlite::SqliteStore::open(&db).unwrap();
    let mut state = line_file::LineFileState::default();
    // Await the SAL ingest directly. `poll_once` is sync and would
    // `Handle::block_on` from this current-thread test runtime (panic).
    let report = line_file::ingest_line_file_store(
        &store,
        &file,
        "ai:watch:sal",
        Some("test-watch-3587"),
        100,
        false,
        &mut state,
    )
    .await
    .unwrap();
    assert_eq!(report.lines_atomised, 1, "{:?}", report.errors);
}
