// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]

//! #8912 — `ai-memory sync` must never let an OLDER row from the other store
//! replace a NEWER destination row, and must never resurrect a row the
//! destination forgot. The older side loses with a NAMED, COUNTED outcome
//! (`skipped_by_covenant` / `refused`, precedent `cli/io.rs` import), and a row the
//! destination refused makes the process exit non-zero.
//!
//! Every row drives the REAL binary with `--db` under a scratch tempdir
//! (`tempfile` honours `TMPDIR`), seeds both stores through the library
//! funnel with explicit timestamps, and asserts the destination row and the
//! exact JSON counters.
//!
//! L-6: a row the sync KEPT because the destination is newer is reported
//! through tracing only (`kept_destination`, no wire key) and is never counted
//! as applied: the full real-run report is asserted key by key.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use ai_memory::models::ConfidenceSource;
use ai_memory::{db, models};

const NS: &str = "sync-8912";
const OLDER: &str = "2026-01-01T00:00:00+00:00";
const NEWER: &str = "2026-06-01T00:00:00+00:00";
const DEST_CONTENT: &str = "destination-newer-content";
const SRC_CONTENT: &str = "source-older-content";
const EXIT_INCOMPLETE: i32 = 3;

fn mem(id: &str, title: &str, content: &str, updated_at: &str) -> models::Memory {
    let mut metadata = models::default_metadata();
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("agent_id".to_string(), serde_json::json!("test-agent"));
    }
    models::Memory {
        id: id.to_string(),
        tier: models::Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "import".to_string(),
        access_count: 0,
        created_at: OLDER.to_string(),
        updated_at: updated_at.to_string(),
        metadata,
        memory_kind: models::MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..models::Memory::default()
    }
}

fn seed(path: &Path, m: &models::Memory) {
    let conn = db::open(path).expect("db::open");
    db::insert(&conn, m).expect("db::insert seed");
}

fn tombstone(path: &Path, id: &str) {
    let conn = db::open(path).expect("db::open");
    conn.execute(
        "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id) \
         VALUES (?1, ?2, ?3, 'test-agent')",
        rusqlite::params![id, NS, NEWER],
    )
    .expect("seed tombstone");
}

fn live_row(path: &Path, id: &str) -> Option<(String, String, String)> {
    let conn = db::open(path).expect("db::open");
    db::get(&conn, id)
        .expect("db::get")
        .map(|m| (m.title, m.content, m.updated_at))
}

fn run_sync(local: &Path, remote: &Path, direction: &str) -> (i32, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args([
            "--db",
            local.to_str().expect("utf-8 path"),
            "--json",
            "sync",
        ])
        .arg(remote)
        .args(["--direction", direction])
        .stdin(Stdio::null())
        .output()
        .expect("spawn ai-memory");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let last = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON line on stdout: {stdout}\nstderr: {stderr}"));
    let json: serde_json::Value = serde_json::from_str(last).expect("sync JSON");
    (out.status.code().unwrap_or(-1), json, stderr)
}

/// Which store the case treats as the DESTINATION of the leg under test.
#[derive(Clone, Copy, Debug)]
enum Dest {
    Local,
    Remote,
}

/// What the destination holds when the older source row arrives.
#[derive(Clone, Copy, Debug)]
enum DestState {
    /// The same id, updated later than the source copy.
    NewerSameId,
    /// A different id in the same `(title, namespace)` slot, updated later.
    NewerSameTitle,
    /// The id was forgotten on the destination (tombstone, no live row).
    Tombstoned,
}

struct Case {
    direction: &'static str,
    dest: Dest,
    state: DestState,
    /// Exact expected counters: (written key, written, covenant); `refused` is always 0.
    written_key: &'static str,
    written: u64,
    covenant: u64,
}

const CASES: &[Case] = &[
    Case {
        direction: "pull",
        dest: Dest::Local,
        state: DestState::NewerSameId,
        written_key: "imported",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "pull",
        dest: Dest::Local,
        state: DestState::NewerSameTitle,
        written_key: "imported",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "pull",
        dest: Dest::Local,
        state: DestState::Tombstoned,
        written_key: "imported",
        written: 0,
        covenant: 1,
    },
    Case {
        direction: "push",
        dest: Dest::Remote,
        state: DestState::NewerSameId,
        written_key: "exported",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "push",
        dest: Dest::Remote,
        state: DestState::NewerSameTitle,
        written_key: "exported",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "push",
        dest: Dest::Remote,
        state: DestState::Tombstoned,
        written_key: "exported",
        written: 0,
        covenant: 1,
    },
    // merge, inbound leg: the remote copy is older than the local one. The
    // outbound leg then legitimately pushes the newer local row (pushed 1)
    // except where the local side holds only a tombstone (nothing to push).
    Case {
        direction: "merge",
        dest: Dest::Local,
        state: DestState::NewerSameId,
        written_key: "pulled",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "merge",
        dest: Dest::Local,
        state: DestState::NewerSameTitle,
        written_key: "pulled",
        written: 0,
        covenant: 0,
    },
    Case {
        direction: "merge",
        dest: Dest::Local,
        state: DestState::Tombstoned,
        written_key: "pulled",
        written: 0,
        covenant: 1,
    },
    Case {
        direction: "merge",
        dest: Dest::Remote,
        state: DestState::Tombstoned,
        written_key: "pushed",
        written: 0,
        covenant: 1,
    },
];

#[test]
fn sync_8912_older_source_never_replaces_newer_or_forgotten_destination() {
    let mut failures = Vec::new();
    for (i, case) in CASES.iter().enumerate() {
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let local = dir.path().join("local.db");
        let remote = dir.path().join("remote.db");
        let (dest, src) = match case.dest {
            Dest::Local => (&local, &remote),
            Dest::Remote => (&remote, &local),
        };
        let src_id = uuid::Uuid::new_v4().to_string();
        let title = format!("t-8912-{i}");
        let dest_id = match case.state {
            DestState::NewerSameId => {
                seed(dest, &mem(&src_id, &title, DEST_CONTENT, NEWER));
                Some(src_id.clone())
            }
            DestState::NewerSameTitle => {
                let other = uuid::Uuid::new_v4().to_string();
                seed(dest, &mem(&other, &title, DEST_CONTENT, NEWER));
                Some(other)
            }
            DestState::Tombstoned => {
                // Create the schema, then forget the id on the destination.
                drop(db::open(dest).expect("db::open dest"));
                tombstone(dest, &src_id);
                None
            }
        };
        seed(src, &mem(&src_id, &title, SRC_CONTENT, OLDER));

        let (code, json, stderr) = run_sync(&local, &remote, case.direction);
        let label = format!("{i}: {} {:?} {:?}", case.direction, case.dest, case.state);

        // The destination row is exactly what it was.
        match &dest_id {
            Some(id) => {
                let row = live_row(dest, id);
                let expected = Some((title.clone(), DEST_CONTENT.to_string(), NEWER.to_string()));
                if row != expected {
                    failures.push(format!("{label}: dest row {row:?} != {expected:?}"));
                }
            }
            None => {
                if let Some(row) = live_row(dest, &src_id) {
                    failures.push(format!("{label}: tombstoned id resurrected as {row:?}"));
                }
            }
        }
        if matches!(case.state, DestState::NewerSameTitle) && live_row(dest, &src_id).is_some() {
            failures.push(format!(
                "{label}: older source id admitted beside the newer slot owner"
            ));
        }
        let got = (
            json[case.written_key].as_u64(),
            json["skipped_by_covenant"].as_u64(),
            json["refused"].as_u64(),
        );
        let want = (Some(case.written), Some(case.covenant), Some(0));
        if got != want {
            failures.push(format!(
                "{label}: counters {got:?} != {want:?} (json {json})"
            ));
        }
        if code != 0 {
            failures.push(format!("{label}: exit {code} != 0; stderr {stderr}"));
        }
    }
    assert!(
        failures.is_empty(),
        "#8912 violations:\n{}",
        failures.join("\n")
    );
}

/// A NEWER source row still lands (the guard must not freeze sync), and the
/// count of written rows says so.
#[test]
fn sync_8912_newer_source_still_replaces_older_destination() {
    for (direction, written_key) in [
        ("pull", "imported"),
        ("push", "exported"),
        ("merge", "pulled"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let local = dir.path().join("local.db");
        let remote = dir.path().join("remote.db");
        let (dest, src) = if direction == "push" {
            (&remote, &local)
        } else {
            (&local, &remote)
        };
        let id = uuid::Uuid::new_v4().to_string();
        seed(dest, &mem(&id, "t-8912-fresh", SRC_CONTENT, OLDER));
        seed(src, &mem(&id, "t-8912-fresh", DEST_CONTENT, NEWER));
        let (code, json, stderr) = run_sync(&local, &remote, direction);
        // N-4: the surviving row first, so a red names the lost update.
        let row = live_row(dest, &id).expect("row present");
        assert_eq!(
            (row.1.as_str(), row.2.as_str()),
            (DEST_CONTENT, NEWER),
            "{direction}: the newer source row was lost (destination kept the older copy)"
        );
        assert_eq!(code, 0, "{direction}: stderr {stderr}");
        assert_eq!(json[written_key].as_u64(), Some(1), "{direction}: {json}");
        assert_eq!(json["refused"].as_u64(), Some(0), "{direction}: {json}");
        assert_eq!(
            json["skipped_by_covenant"].as_u64(),
            Some(0),
            "{direction}: {json}"
        );
    }
}

/// A row the destination REFUSES (an id collision the writer rejects) is
/// counted under `refused`, named on stderr, and the process exits
/// `EXIT_EXPORT_INCOMPLETE` (3) instead of reporting a clean sync.
#[test]
fn sync_8912_refused_row_is_counted_and_exits_incomplete() {
    for (direction, written_key) in [("pull", "imported"), ("push", "exported")] {
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let local = dir.path().join("local.db");
        let remote = dir.path().join("remote.db");
        let (dest, src) = if direction == "push" {
            (&remote, &local)
        } else {
            (&local, &remote)
        };
        let id = uuid::Uuid::new_v4().to_string();
        // Same id, different title: the upsert's title slot does not cover the
        // primary key, so the writer refuses the newer source copy.
        seed(dest, &mem(&id, "t-8912-old-title", SRC_CONTENT, OLDER));
        seed(src, &mem(&id, "t-8912-new-title", DEST_CONTENT, NEWER));
        let (code, json, stderr) = run_sync(&local, &remote, direction);
        // N-4: the surviving row first, so a red names the lost destination row.
        let row = live_row(dest, &id).expect("dest row kept");
        assert_eq!(
            (row.0.as_str(), row.1.as_str(), row.2.as_str()),
            ("t-8912-old-title", SRC_CONTENT, OLDER),
            "{direction}: the refused write still replaced the destination row"
        );
        assert_eq!(json[written_key].as_u64(), Some(0), "{direction}: {json}");
        assert_eq!(json["refused"].as_u64(), Some(1), "{direction}: {json}");
        assert_eq!(code, EXIT_INCOMPLETE, "{direction}: stderr {stderr}");
        assert!(
            stderr.contains(&format!("sync: refused memory {id}")),
            "{direction}: refused row not named on stderr: {stderr}"
        );
    }
}

/// The exact JSON report of a real run whose only offered row (per leg) is
/// KEPT because the destination copy is newer. Every key is pinned, so a kept
/// row counted as applied (or under any other counter, or under a new wire
/// key) fails. Text mode names the same zero.
#[test]
fn sync_8912_kept_destination_row_is_not_counted_as_applied() {
    let cases: [(&str, serde_json::Value, &str); 3] = [
        (
            "pull",
            serde_json::json!({
                "direction": "pull",
                "imported": 0,
                "attestation_downgraded": 0,
                "forged_signature_skipped": 0,
                "pubkey_bindings_stripped": 0,
                "key_history_refused": 0,
                "skipped_by_covenant": 0,
                "refused": 0,
            }),
            "pulled 0 memories from remote",
        ),
        (
            "push",
            serde_json::json!({
                "direction": "push",
                "exported": 0,
                "pubkey_bindings_stripped": 0,
                "skipped_by_covenant": 0,
                "refused": 0,
            }),
            "pushed 0 memories to remote",
        ),
        // merge: the inbound copy is older, so the local row is KEPT (pulled 0);
        // the outbound leg then writes that newer local row onto the older
        // remote copy, which is a real write (pushed 1), not the kept row.
        (
            "merge",
            serde_json::json!({
                "direction": "merge",
                "pulled": 0,
                "pushed": 1,
                "attestation_downgraded": 0,
                "forged_signature_skipped": 0,
                "pubkey_bindings_stripped": 0,
                "key_history_refused": 0,
                "skipped_by_covenant": 0,
                "refused": 0,
            }),
            "merged: pulled 0, pushed 1",
        ),
    ];
    for (direction, want, text) in cases {
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let local = dir.path().join("local.db");
        let remote = dir.path().join("remote.db");
        let (dest, src) = if direction == "push" {
            (&remote, &local)
        } else {
            (&local, &remote)
        };
        let id = uuid::Uuid::new_v4().to_string();
        seed(dest, &mem(&id, "t-8912-kept", DEST_CONTENT, NEWER));
        seed(src, &mem(&id, "t-8912-kept", SRC_CONTENT, OLDER));

        let (code, json, stderr) = run_sync(&local, &remote, direction);
        assert_eq!(json, want, "{direction}: full report; stderr {stderr}");
        assert_eq!(code, 0, "{direction}: stderr {stderr}");
        let kept = live_row(dest, &id);
        assert_eq!(
            kept,
            Some((
                "t-8912-kept".to_string(),
                DEST_CONTENT.to_string(),
                NEWER.to_string()
            )),
            "{direction}: the newer destination row is kept byte for byte"
        );
        if direction == "merge" {
            let pushed = live_row(&remote, &id).map(|r| r.1);
            assert_eq!(
                pushed.as_deref(),
                Some(DEST_CONTENT),
                "merge: pushed 1 is the newer local row landing on the remote"
            );
        }

        // Text mode: a fresh pair, same shape, plain report line.
        let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
        let local = dir.path().join("local.db");
        let remote = dir.path().join("remote.db");
        let (dest, src) = if direction == "push" {
            (&remote, &local)
        } else {
            (&local, &remote)
        };
        seed(dest, &mem(&id, "t-8912-kept", DEST_CONTENT, NEWER));
        seed(src, &mem(&id, "t-8912-kept", SRC_CONTENT, OLDER));
        let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .args(["--db", local.to_str().expect("utf-8 path"), "sync"])
            .arg(&remote)
            .args(["--direction", direction])
            .stdin(Stdio::null())
            .output()
            .expect("spawn ai-memory");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{direction} text: {stdout}");
        assert_eq!(
            stdout.lines().map(str::trim_end).collect::<Vec<_>>(),
            vec![text],
            "{direction} text: the whole stdout report"
        );
    }
}

/// N-1 (NOTICE-FIX-9282-r1) — the source copy sits between the destination's
/// original row and the concurrent writer's row.
const MID: &str = "2026-03-01T00:00:00+00:00";
const ORIGINAL_CONTENT: &str = "destination-original-content";
const CONCURRENT_CONTENT: &str = "concurrent-writer-newer-content";
/// How long the blocker holds the destination write lock while `sync` runs:
/// long enough for the process to reach its write, well under the writer's
/// 5 s `busy_timeout`, so a waiting sync is never refused.
const LOCK_HOLD: Duration = Duration::from_millis(1500);

/// N-1 — the archive reason the concurrent writer records (a genuine
/// archival, not an `in_place_edit` snapshot).
const CONCURRENT_ARCHIVE_REASON: &str = "8912-concurrent-archive";

/// N-1 — what the second writer commits while `sync` waits for the lock.
#[derive(Clone, Copy)]
enum Concurrent {
    /// A row NEWER than the source copy under the same id.
    NewerUpdate,
    /// A genuine archival of the id. The `merge` funnel
    /// (`db::insert_if_newer`) re-checks `updated_at` and the forget
    /// tombstone for the same id, but NOT the archive covenant: that check
    /// lives only in `sync_disposition`, so this is the shape in which a
    /// merge verdict read outside the write transaction re-admits the row.
    Archive,
}

/// N-1 — start the blocker (`BEGIN IMMEDIATE` on `dest`), spawn a REAL
/// `sync`, and prove it is waiting on the lock before returning both.
fn spawn_blocked_sync(
    direction: &str,
    local: &Path,
    remote: &Path,
    dest: &Path,
) -> (rusqlite::Connection, std::process::Child) {
    let blocker = db::open(dest).expect("open blocker");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("take the destination write lock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .args([
            "--db",
            local.to_str().expect("utf-8 path"),
            "--json",
            "sync",
        ])
        .arg(remote)
        .args(["--direction", direction])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory");
    std::thread::sleep(LOCK_HOLD);
    assert!(
        child.try_wait().expect("poll sync").is_none(),
        "{direction}: sync finished without waiting for the destination write lock"
    );
    (blocker, child)
}

/// N-1 — run a REAL `sync` while a second writer holds the destination's
/// write lock (`BEGIN IMMEDIATE`); once `sync` is waiting, that writer commits
/// its change (`concurrent`) and releases the lock. The newer-wins / covenant
/// verdict and the write must be one atomic unit: a verdict read before the
/// lock (taken from the stale pre-commit row) would let the older source copy
/// overwrite the concurrent writer's newer row, or re-admit the row the
/// concurrent writer archived.
fn interleave_sync(direction: &str, concurrent: Concurrent) {
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let local = dir.path().join("local.db");
    let remote = dir.path().join("remote.db");
    let (dest, src) = if direction == "push" {
        (&remote, &local)
    } else {
        (&local, &remote)
    };
    let id = uuid::Uuid::new_v4().to_string();
    seed(
        dest,
        &mem(&id, "t-8912-interleave", ORIGINAL_CONTENT, OLDER),
    );
    seed(src, &mem(&id, "t-8912-interleave", SRC_CONTENT, MID));
    let (blocker, child) = spawn_blocked_sync(direction, &local, &remote, dest);
    match concurrent {
        Concurrent::NewerUpdate => {
            blocker
                .execute(
                    "UPDATE memories SET content = ?1, updated_at = ?2, \
                     version = version + 1 WHERE id = ?3",
                    rusqlite::params![CONCURRENT_CONTENT, NEWER, id],
                )
                .expect("concurrent newer write");
        }
        Concurrent::Archive => {
            // `archive_memory` joins the blocker's open transaction (#3957).
            let moved = db::archive_memory(&blocker, &id, Some(CONCURRENT_ARCHIVE_REASON))
                .expect("concurrent archive");
            assert!(moved, "{direction}: the concurrent writer archived the row");
        }
    }
    blocker
        .execute_batch("COMMIT")
        .expect("commit the concurrent write");
    let out = child.wait_with_output().expect("sync output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    match concurrent {
        Concurrent::NewerUpdate => {
            let row = live_row(dest, &id).expect("destination row present");
            assert_eq!(
                row.1, CONCURRENT_CONTENT,
                "#8912 {direction}: a write decided from a stale read overwrote the newer concurrent row"
            );
            assert_eq!(
                row.2, NEWER,
                "#8912 {direction}: the newer updated_at was reverted"
            );
        }
        Concurrent::Archive => {
            assert_eq!(
                live_row(dest, &id),
                None,
                "#8912 {direction}: a write decided from a stale read re-admitted the row the concurrent writer archived"
            );
            assert!(
                db::memory_is_genuinely_archived(&db::open(dest).expect("reopen"), &id)
                    .expect("archive probe"),
                "#8912 {direction}: the concurrent archival is gone"
            );
            let report: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("sync --json report");
            assert_eq!(
                report["pulled"],
                serde_json::json!(0),
                "#8912 {direction}: the archived row is not counted as pulled: {report}"
            );
        }
    }
    assert_eq!(out.status.code(), Some(0), "{direction}: stderr {stderr}");
}

#[test]
fn sync_8912_interleave_pull_never_overwrites_concurrent_newer_row() {
    interleave_sync("pull", Concurrent::NewerUpdate);
}

#[test]
fn sync_8912_interleave_push_never_overwrites_concurrent_newer_row() {
    interleave_sync("push", Concurrent::NewerUpdate);
}

/// N-1 merge — the same-id newer row is masked by `insert_if_newer`'s own
/// `updated_at` re-check, so the merge cell interleaves an ARCHIVAL, which
/// that funnel does not re-check (see [`Concurrent::Archive`]).
#[test]
fn sync_8912_interleave_merge_never_readmits_concurrently_archived_row() {
    interleave_sync("merge", Concurrent::Archive);
}
