// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4304 — one forensic chain across processes.
//!
//! Every process used to read the chain tail once at start and chain from its
//! own head ever after, so a row another process wrote in between was skipped
//! and the chain forked. These cells play the "other process" by appending to
//! the daily file directly (or through a second [`ChainWriter`]) between this
//! process's rows.

use super::*;
use tempfile::TempDir;

fn lock() -> std::sync::MutexGuard<'static, ()> {
    forensic_sink_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn today_file(dir: &Path) -> PathBuf {
    daily_path(dir, &Utc::now())
}

/// Every parseable row of `dir`, in chain order.
fn rows(dir: &Path) -> Vec<ForensicDecision> {
    list_forensic_files(dir)
        .expect("list")
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .expect("read")
                .lines()
                .filter_map(|l| serde_json::from_str::<ForensicDecision>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_one_chain(recs: &[ForensicDecision]) {
    assert_eq!(recs[0].prev_hash, CHAIN_HEAD_PREV_HASH, "starts at genesis");
    for (i, pair) in recs.windows(2).enumerate() {
        assert_eq!(
            pair[1].prev_hash,
            pair[0].self_hash(),
            "row {} must continue row {i}",
            i + 1
        );
    }
}

/// A row "another process" appends: unsigned, chained from `prev`.
fn foreign_row(actor: &str, prev: &str) -> ForensicDecision {
    ForensicDecision {
        ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        actor: actor.to_string(),
        decision: "allow".to_string(),
        kind: "bash".to_string(),
        rule_id: "R4304".to_string(),
        payload: serde_json::json!({}),
        prev_hash: prev.to_string(),
        sig: String::new(),
    }
}

fn append_foreign(dir: &Path, row: &ForensicDecision) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(today_file(dir))
        .expect("open daily file");
    append_record(&mut f, &serde_json::to_string(row).unwrap()).expect("append");
}

fn record(actor: &str) {
    try_record_decision(actor, "allow", "bash", "R4304", ForensicPayload::new()).expect("record");
}

fn writer_for(dir: &Path) -> ChainWriter {
    ChainWriter {
        dir: dir.to_path_buf(),
        signing_key: None,
        cursor: ChainCursor {
            last_hash: CHAIN_HEAD_PREV_HASH.to_string(),
            at: None,
        },
        file: None,
    }
}

fn pending(actor: &str) -> PendingRow {
    PendingRow {
        now: Utc::now(),
        actor: actor.to_string(),
        decision: "allow".to_string(),
        kind: "bash",
        rule_id: "R4304".to_string(),
        payload: serde_json::json!({}),
    }
}

/// The #4304 fork: a row another process appended after this process's last
/// row must be the `prev_hash` of this process's next row. Red on the base
/// (the next row chained from this process's own stale head).
#[test]
fn a_row_appended_by_another_process_is_chained_from_4304() {
    let _g = lock();
    shutdown();
    let tmp = TempDir::new().unwrap();
    init(tmp.path(), None).expect("init");
    record("ai:mine-1");
    let mine = rows(tmp.path());
    append_foreign(tmp.path(), &foreign_row("ai:other", &mine[0].self_hash()));
    record("ai:mine-2");
    shutdown();

    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 3);
    assert_one_chain(&recs);
}

/// Same, through the `init` tail: a row appended between `init` (which read
/// the tail) and the first record must be chained from.
#[test]
fn a_row_appended_after_init_is_chained_from_4304() {
    let _g = lock();
    shutdown();
    let tmp = TempDir::new().unwrap();
    let first = foreign_row("ai:seed", CHAIN_HEAD_PREV_HASH);
    append_foreign(tmp.path(), &first);
    init(tmp.path(), None).expect("init");
    append_foreign(tmp.path(), &foreign_row("ai:other", &first.self_hash()));
    record("ai:mine");
    shutdown();

    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 3);
    assert_one_chain(&recs);
}

/// Two appenders on one directory, alternating: every row continues the one
/// before it, whoever wrote it.
#[test]
fn two_appenders_alternating_keep_one_chain_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    let mut a = writer_for(tmp.path());
    let mut b = writer_for(tmp.path());
    for i in 0..4 {
        a.append(pending(&format!("ai:a-{i}"))).expect("a");
        b.append(pending(&format!("ai:b-{i}"))).expect("b");
    }
    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 8);
    assert_one_chain(&recs);
}

/// A same-length rewrite of the file (same inode, same length) is still a
/// change: the tail is re-read rather than trusted from the cursor.
#[test]
fn a_same_length_rewrite_forces_a_tail_reread_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    let mut w = writer_for(tmp.path());
    w.append(pending("ai:row-a")).expect("first");
    let original = rows(tmp.path()).remove(0);
    let mut swapped = original.clone();
    swapped.actor = "ai:row-z".to_string();
    let body = format!("{}\n", serde_json::to_string(&swapped).unwrap());
    assert_eq!(
        body.len(),
        std::fs::metadata(today_file(tmp.path())).unwrap().len() as usize,
        "the rewrite keeps the length"
    );
    // Past the file system's timestamp granularity, so the rewrite is visible.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut f = OpenOptions::new()
        .write(true)
        .open(today_file(tmp.path()))
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
    drop(f);

    w.append(pending("ai:row-b")).expect("second");
    let recs = rows(tmp.path());
    assert_eq!(recs[0].actor, "ai:row-z");
    assert_eq!(
        recs[1].prev_hash,
        recs[0].self_hash(),
        "chained from the file"
    );
}

/// A cursor cleared by a failed write (here: simulated) resyncs from the file
/// on the next append instead of trusting its head.
#[test]
fn an_unknown_cursor_resyncs_from_the_file_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    let mut w = writer_for(tmp.path());
    w.append(pending("ai:row-a")).expect("first");
    // What a failed write leaves behind: no cursor, a head that is not the
    // file's tail.
    w.cursor.at = None;
    w.cursor.last_hash = "f".repeat(64);
    w.file = None;
    w.append(pending("ai:row-b")).expect("second");
    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 2);
    assert_one_chain(&recs);
}

/// When the lock file cannot be used the append still chains correctly (the
/// tail is re-read every time), and the lock outage is counted.
#[test]
fn an_unusable_lock_file_degrades_to_rereading_and_is_counted_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir(tmp.path().join(FORENSIC_LOCK_FILE)).unwrap();
    let before = crate::metrics::forensic_lock_unavailable_count();
    let mut w = writer_for(tmp.path());
    w.append(pending("ai:row-a")).expect("first");
    append_foreign(
        tmp.path(),
        &foreign_row("ai:other", &rows(tmp.path())[0].self_hash()),
    );
    w.append(pending("ai:row-b")).expect("second");
    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 3);
    assert_one_chain(&recs);
    assert!(crate::metrics::forensic_lock_unavailable_count() >= before + 2);
}

/// The lock file is never mistaken for a log file.
#[test]
fn the_lock_file_is_not_a_forensic_log_file_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    let mut w = writer_for(tmp.path());
    w.append(pending("ai:row-a")).expect("append");
    assert!(tmp.path().join(FORENSIC_LOCK_FILE).exists());
    assert_eq!(list_forensic_files(tmp.path()).unwrap().len(), 1);
}

/// Truncating rows this process wrote is not "another appender": the next row
/// continues this process's head, so the removed rows show as a break.
#[test]
fn a_truncated_file_keeps_the_break_visible_4304() {
    let _g = lock();
    let tmp = TempDir::new().unwrap();
    let mut w = writer_for(tmp.path());
    w.append(pending("ai:row-a")).expect("a");
    w.append(pending("ai:row-b")).expect("b");
    let before = rows(tmp.path());
    let first_line_len = serde_json::to_string(&before[0]).unwrap().len() + 1;
    let f = OpenOptions::new()
        .write(true)
        .open(today_file(tmp.path()))
        .unwrap();
    f.set_len(first_line_len as u64).unwrap();
    drop(f);

    w.append(pending("ai:row-c")).expect("c");
    let recs = rows(tmp.path());
    assert_eq!(recs.len(), 2, "row b is gone");
    assert_eq!(
        recs[1].prev_hash,
        before[1].self_hash(),
        "row c names the removed row b, so the gap stays visible"
    );
}
