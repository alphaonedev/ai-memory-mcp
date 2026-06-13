// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1389 / #1395 acceptance — L2 `recover-previous-session` survives an
//! ungraceful termination (SIGKILL / tmux lockup / host crash) between
//! conversation turns.
//!
//! The failure mode (#1388): an agent's last turns are written to the
//! host transcript file but never reach `memory_store` before the
//! process dies. This test simulates that by writing a transcript the
//! agent never atomised, then proves the recovery handler:
//!
//! 1. atomises every lost turn into an observation memory on the first
//!    boot after the crash, and
//! 2. is idempotent across a subsequent daemon restart (the same
//!    transcript is fully dedup-skipped — no duplicate memories).

use std::io::Write;
use std::path::PathBuf;

use ai_memory::recover::{HostKind, RecoverOpts, recover_from_transcript};

/// In-tree scratch root honoring the project no-`/tmp` HARD RULE.
/// Tempdirs land under the repo's gitignored `.local-runs/`, never
/// on a tmpfs path.
fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1395-sigkill-recovery-test")
}

fn fresh_dir() -> tempfile::TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn opts(transcript: std::path::PathBuf, agent: &str) -> RecoverOpts {
    RecoverOpts {
        host: HostKind::ClaudeCode,
        transcript_override: Some(transcript),
        since_iso: None,
        namespace: Some("sigkill-recovery".to_string()),
        limit: 100,
        dry_run: false,
        quiet: false,
        agent_id: agent.to_string(),
    }
}

#[test]
fn recovers_lost_turns_and_is_idempotent_across_restart() {
    let dir = fresh_dir();
    let db = dir.path().join("agent.db");
    let transcript = dir.path().join("session.jsonl");

    // The agent wrote three operator-directive turns to the transcript
    // but the process was SIGKILLed before any reached memory_store.
    let mut f = std::fs::File::create(&transcript).unwrap();
    for (i, text) in [
        "decided to ship v0.7.0 from release/v0.7.0 head",
        "approved the L2 recover-on-boot design",
        "agreed the perf budget: gap-path under 1s for 100 turns",
    ]
    .iter()
    .enumerate()
    {
        writeln!(
            f,
            r#"{{"timestamp":"2026-05-28T1{i}:00:00Z","type":"user","message":{{"content":[{{"type":"text","text":"{text}"}}]}}}}"#
        )
        .unwrap();
    }
    f.flush().unwrap();
    drop(f);

    // First boot after the SIGKILL: nothing stored yet, so the
    // fast-path can't short-circuit and every lost turn is recovered.
    let first =
        recover_from_transcript(&db, &opts(transcript.clone(), "ai:sigkill:agent")).unwrap();
    assert!(
        !first.fast_path_hit,
        "no prior memory -> must take the gap path"
    );
    assert_eq!(
        first.lines_atomised, 3,
        "all three lost turns recovered (errors: {:?})",
        first.errors
    );
    assert_eq!(first.memories_created.len(), 3);
    assert!(first.errors.is_empty(), "errors: {:?}", first.errors);

    // Second boot (daemon restart with the same transcript on disk):
    // every line is already in transcript_line_dedup, so recovery is a
    // no-op — the #1388 fix must not double-write on restart.
    let second = recover_from_transcript(&db, &opts(transcript, "ai:sigkill:agent")).unwrap();
    assert_eq!(second.lines_atomised, 0, "restart must not re-atomise");
    assert_eq!(second.lines_skipped_dedup, 3, "all lines dedup-skipped");
    assert!(second.memories_created.is_empty());
}
