// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4199 / #4202 / #4203 — the forensic governance log never forks its chain.
//!
//! The forensic log (`forensic-<YYYY-MM-DD>.jsonl` beside the flat audit
//! trail) is written on every boot. Before #4199 its chain-tail reader
//! collapsed every failure (a directory or file it could not read, no
//! parseable row anywhere), an empty newest daily file (#4202) and a planted
//! future-dated file (#4203) to "no chain", so the next signed row was written
//! with the genesis `prev_hash`: the chain forked silently.
//!
//! The rule now (5-agent vote 4d3ea1c5, decision memory 4ae4ed7d): the tail
//! is the last parseable row of the newest non-future file that has one (a
//! torn last line is still skipped). Only a directory with no non-blank line
//! starts at genesis. When the tail cannot be established the process runs
//! WITHOUT the forensic sink and records the outage (ERROR, metric, doctor
//! Critical, a signed `audit.forensic_sink_unavailable` row); under
//! `AI_MEMORY_REQUIRE_FORENSIC_SINK` (pinned by `asi-hard`) it refuses boot
//! with exit 78, `doctor` exempt.
//!
//! These drive the real binary. `archive purge --namespace` writes one
//! forensic decision row per run (#913), so it is the probe for "the process
//! booted and appended".

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ai_memory::governance::audit::{
    CHAIN_HEAD_PREV_HASH, ForensicDecision, REQUIRE_FORENSIC_SINK_ENV,
};
use ai_memory::signed_events::event_types::FORENSIC_SINK_UNAVAILABLE;

/// `EX_CONFIG` from sysexits.h, the code every boot refusal exits with.
const EX_CONFIG: i32 = 78;

/// The namespace every probe purges (a no-op on an empty archive; the
/// forensic row is written before the storage call).
const PROBE_NAMESPACE: &str = "t4199";

/// An older, healthy day the walk-back cells move the chain to.
const OLDER_DAY: &str = "forensic-2026-01-01.jsonl";

/// A day far in the future (#4203).
const FUTURE_DAY: &str = "forensic-2099-01-01.jsonl";

/// The doctor section this change adds.
const DOCTOR_SECTION: &str = "Forensic audit log (#4199)";

/// The phrase the degraded-boot ERROR carries.
const DEGRADED: &str = "WITHOUT the forensic audit sink";

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

/// The forensic directory: the resolved audit directory. The flat trail is
/// left disabled so only the forensic log is under test.
fn forensic_dir(home: &Path) -> PathBuf {
    home.join("audit")
}

fn db_path(home: &Path) -> PathBuf {
    home.join("forensic.db")
}

fn run_with_env(home: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!(
            "schema_version = 2\ntier = \"keyword\"\n\n[audit]\nenabled = false\npath = \"{}\"\n",
            forensic_dir(home).display()
        ),
    )
    .expect("write config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        );
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.current_dir(home)
        .arg("--db")
        .arg(db_path(home))
        .args(args)
        .output()
        .expect("run isolated CLI")
}

/// One process start that appends one forensic row.
fn purge_once(home: &Path) -> Output {
    purge_with_env(home, &[])
}

fn purge_with_env(home: &Path, env: &[(&str, &str)]) -> Output {
    run_with_env(
        home,
        env,
        &["archive", "purge", "--namespace", PROBE_NAMESPACE],
    )
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Every forensic file, oldest first (the file names sort by date).
fn forensic_files(home: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(forensic_dir(home))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "jsonl")
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("forensic-"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// Every PARSEABLE row across the forensic files that are not future-dated,
/// in chain order. Torn and junk lines are skipped, as the reader skips them.
fn rows(home: &Path) -> Vec<ForensicDecision> {
    forensic_files(home)
        .iter()
        .filter(|p| !p.ends_with(FUTURE_DAY))
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<ForensicDecision>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Assert every row links to the one before it, and the first is genesis.
fn assert_one_unbroken_chain(recs: &[ForensicDecision]) {
    assert!(recs.len() >= 2, "the log holds the seed row and a new one");
    assert_eq!(
        recs[0].prev_hash, CHAIN_HEAD_PREV_HASH,
        "the chain starts at genesis"
    );
    for pair in recs.windows(2) {
        assert_eq!(
            pair[1].prev_hash,
            pair[0].self_hash(),
            "each row continues the previous one (no second genesis)"
        );
    }
}

/// A forensic log holding a genuine row, written by the binary. Returns
/// today's forensic file.
fn log_with_rows(home: &Path) -> PathBuf {
    let out = purge_once(home);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let files = forensic_files(home);
    assert_eq!(files.len(), 1, "the seed run wrote one daily file");
    assert!(!rows(home).is_empty(), "the seed run wrote a row");
    files[0].clone()
}

/// Every byte of every forensic file.
fn snapshot(home: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    forensic_files(home)
        .into_iter()
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap_or_default();
            (p, bytes)
        })
        .collect()
}

/// How many signed outage rows the database holds.
fn outage_rows(home: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db_path(home)).expect("open the test database");
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [FORENSIC_SINK_UNAVAILABLE],
        |r| r.get(0),
    )
    .expect("count outage rows")
}

/// The two tables the recorder could touch, dumped row by row: the schema
/// stamp and the signed-event chain.
fn store_dump(home: &Path) -> (Vec<i64>, Vec<(i64, String, String)>) {
    let conn = rusqlite::Connection::open(db_path(home)).expect("open the test database");
    let stamps = conn
        .prepare("SELECT version FROM schema_version ORDER BY version")
        .expect("prepare")
        .query_map([], |r| r.get(0))
        .expect("query")
        .map(Result::unwrap)
        .collect();
    let events = conn
        .prepare(
            "SELECT sequence, event_type, hex(payload_hash) FROM signed_events ORDER BY sequence",
        )
        .expect("prepare")
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .map(Result::unwrap)
        .collect();
    (stamps, events)
}

/// The doctor severity of the forensic section. `doctor` is never refused.
fn doctor_forensic_severity(home: &Path, env: &[(&str, &str)]) -> String {
    let out = run_with_env(home, env, &["doctor", "--json"]);
    assert_ne!(
        out.status.code(),
        Some(EX_CONFIG),
        "doctor must never be refused: {}",
        stderr(&out)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints a report");
    json["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"] == DOCTOR_SECTION)
        .expect("the forensic section is present")["severity"]
        .as_str()
        .expect("severity")
        .to_string()
}

/// The degraded boot: the process runs, writes NO forensic row (no fork),
/// says so loudly, and attests the outage in `signed_events`; doctor is
/// Critical. Counts the outage rows BEFORE doctor, which also boots.
fn assert_degraded(out: &Output, home: &Path, before: &[(PathBuf, Vec<u8>)], outages: i64) {
    let err = stderr(out);
    assert!(out.status.success(), "the standard posture degrades: {err}");
    assert!(err.contains("ERROR"), "stderr: {err}");
    assert!(err.contains(DEGRADED), "stderr: {err}");
    assert_eq!(
        snapshot(home),
        before,
        "no forensic row may be written (the sink is off; the chain is not forked)"
    );
    assert_eq!(
        outage_rows(home),
        outages + 1,
        "the outage is attested by one signed signed_events row"
    );
}

/// Under require-mode the condition refuses boot and writes nothing.
fn assert_refused(out: &Output, home: &Path, before: &[(PathBuf, Vec<u8>)]) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("refusing to start"), "stderr: {err}");
    assert!(err.contains("forensic audit log"), "stderr: {err}");
    assert_eq!(snapshot(home), before, "a refused boot writes nothing");
}

/// Replace the only forensic file with bytes no row parses from.
fn garbage_only_log(home: &Path) {
    let file = log_with_rows(home);
    std::fs::write(&file, b"not a forensic row\n").expect("replace with garbage");
}

/// Deny reads on `path`. `false` (and restored) when the bits do not deny
/// reads here, e.g. when running as root.
#[cfg(unix)]
fn deny_reads(path: &Path, dir: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o300 } else { 0o200 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    let readable = if dir {
        std::fs::read_dir(path).is_ok()
    } else {
        std::fs::read(path).is_ok()
    };
    if readable {
        restore_reads(path, dir);
        eprintln!("SKIP: permission bits do not deny reads here (running as root?)");
    }
    !readable
}

#[cfg(unix)]
fn restore_reads(path: &Path, dir: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Boot against an unreadable forensic file or directory: degrade by
/// default, refuse under require-mode. Doctor is Critical in both.
#[cfg(unix)]
fn unreadable_case(dir: bool, require: bool) {
    let home = sandbox();
    let file = log_with_rows(home.path());
    let target = if dir { forensic_dir(home.path()) } else { file };
    let before = snapshot(home.path());
    let outages = outage_rows(home.path());
    let env: &[(&str, &str)] = if require {
        &[(REQUIRE_FORENSIC_SINK_ENV, "1")]
    } else {
        &[]
    };
    if !deny_reads(&target, dir) {
        return;
    }
    let out = purge_with_env(home.path(), env);
    let after_outages = outage_rows(home.path());
    let doctor = doctor_forensic_severity(home.path(), env);
    restore_reads(&target, dir);
    if require {
        assert_refused(&out, home.path(), &before);
    } else {
        let err = stderr(&out);
        assert!(out.status.success(), "the standard posture degrades: {err}");
        assert!(err.contains(DEGRADED), "stderr: {err}");
        assert_eq!(snapshot(home.path()), before, "no forensic row is written");
        assert_eq!(after_outages, outages + 1, "one signed outage row");
    }
    assert_eq!(doctor, "critical");
}

#[cfg(unix)]
#[test]
fn an_unreadable_forensic_file_degrades_without_forking_4199() {
    unreadable_case(false, false);
}

#[cfg(unix)]
#[test]
fn an_unreadable_forensic_directory_degrades_without_forking_4199() {
    unreadable_case(true, false);
}

#[cfg(unix)]
#[test]
fn require_mode_refuses_boot_on_an_unreadable_file_4199() {
    unreadable_case(false, true);
}

#[cfg(unix)]
#[test]
fn require_mode_refuses_boot_on_an_unreadable_directory_4199() {
    unreadable_case(true, true);
}

#[test]
fn no_parseable_row_anywhere_degrades_without_forking_4199() {
    // Non-empty forensic files with no parseable row: pre-#4199 this answered
    // "no chain" and the next row restarted at genesis inside a non-empty file.
    let home = sandbox();
    garbage_only_log(home.path());
    let before = snapshot(home.path());
    let outages = outage_rows(home.path());
    let out = purge_once(home.path());
    assert_degraded(&out, home.path(), &before, outages);
    assert_eq!(doctor_forensic_severity(home.path(), &[]), "critical");
}

#[test]
fn require_mode_refuses_boot_when_no_row_parses_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = snapshot(home.path());
    let env = [(REQUIRE_FORENSIC_SINK_ENV, "1")];
    let out = purge_with_env(home.path(), &env);
    assert_refused(&out, home.path(), &before);
    assert_eq!(doctor_forensic_severity(home.path(), &env), "critical");
}

#[test]
fn an_empty_newest_daily_file_continues_the_previous_days_chain_4202() {
    let home = sandbox();
    let today = log_with_rows(home.path());
    std::fs::rename(&today, forensic_dir(home.path()).join(OLDER_DAY))
        .expect("move the chain to an older day");
    std::fs::write(&today, b"").expect("empty newest file (crash after the lazy create)");
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    assert_one_unbroken_chain(&rows(home.path()));
}

#[test]
fn an_unparseable_newest_daily_file_continues_the_previous_days_chain_4202() {
    let home = sandbox();
    let today = log_with_rows(home.path());
    std::fs::rename(&today, forensic_dir(home.path()).join(OLDER_DAY))
        .expect("move the chain to an older day");
    std::fs::write(&today, b"garbage\n").expect("unparseable newest file");
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    assert_one_unbroken_chain(&rows(home.path()));
}

#[test]
fn a_future_dated_junk_file_does_not_change_the_tail_4203() {
    let home = sandbox();
    log_with_rows(home.path());
    let junk = forensic_dir(home.path()).join(FUTURE_DAY);
    std::fs::write(&junk, b"planted junk\n").expect("plant a future-dated file");
    let outages = outage_rows(home.path());
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("dated after today"),
        "stderr: {}",
        stderr(&out)
    );
    assert_one_unbroken_chain(&rows(home.path()));
    // f2r review of 15fde1499: the skip can fork the chain after a backward
    // clock step, so it is attested by a signed row, not only logged.
    assert_eq!(outage_rows(home.path()), outages + 1);
    assert_eq!(
        std::fs::read(&junk).expect("the planted file is still there"),
        b"planted junk\n",
        "a future-dated file is evidence: never deleted, never written"
    );
    assert_eq!(doctor_forensic_severity(home.path(), &[]), "critical");
}

#[test]
fn a_fresh_forensic_log_boots_and_writes_genesis_4199() {
    let home = sandbox();
    assert!(
        forensic_files(home.path()).is_empty(),
        "precondition: no log yet"
    );
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let recs = rows(home.path());
    assert!(!recs.is_empty(), "the first run wrote a row");
    assert_eq!(
        recs[0].prev_hash, CHAIN_HEAD_PREV_HASH,
        "a fresh chain starts at genesis"
    );
    assert_eq!(doctor_forensic_severity(home.path(), &[]), "info");
}

#[test]
fn an_intact_forensic_log_boots_and_appends_to_its_tail_4199() {
    let home = sandbox();
    log_with_rows(home.path());
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_one_unbroken_chain(&rows(home.path()));
    assert_eq!(
        outage_rows(home.path()),
        0,
        "a healthy log records no outage"
    );
}

#[test]
fn a_torn_last_line_is_still_skipped_4199() {
    // The vote keeps the pre-#4199 behaviour: a torn LAST line is skipped and
    // the chain continues from the last parseable row.
    let home = sandbox();
    let file = log_with_rows(home.path());
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .expect("open forensic file");
    std::io::Write::write_all(&mut f, b"{\"ts\":\"2026-09-29T00:00:0\n").expect("tear");
    drop(f);
    let out = purge_once(home.path());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    assert_one_unbroken_chain(&rows(home.path()));
}

/// f2r review of 15fde1499 — `doctor` is the pre-upgrade DETECTOR: with a
/// broken tail it reports Critical and leaves the store untouched (no
/// migration, no outage row).
#[test]
fn doctor_never_writes_the_store_with_a_broken_tail_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = store_dump(home.path());
    assert_eq!(doctor_forensic_severity(home.path(), &[]), "critical");
    assert_eq!(store_dump(home.path()), before, "doctor wrote the store");
}

/// f2r review of 15fde1499 — an egress verb takes the copy without the
/// recorder opening, migrating or appending to the primary first.
#[test]
fn backup_never_writes_the_store_with_a_broken_tail_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = store_dump(home.path());
    let to = home.path().join("backups");
    let out = run_with_env(
        home.path(),
        &[],
        &["backup", "--to", to.to_str().expect("utf-8 path")],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(store_dump(home.path()), before, "backup wrote the store");
}

/// f2r review of 15fde1499 — a stuck tail costs ONE outage row, not one per
/// invocation (the `PreToolUse` hook runs on every agent tool call).
#[test]
fn a_stuck_tail_appends_one_outage_row_across_runs_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = outage_rows(home.path());
    for _ in 0..2 {
        let out = purge_once(home.path());
        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert!(stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    }
    assert_eq!(outage_rows(home.path()), before + 1);
}

/// f2r review of 15fde1499 — the gate from the other side: a read-only verb
/// with a broken tail reports the outage but never writes the store.
#[test]
fn a_read_only_verb_never_writes_the_store_with_a_broken_tail_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = store_dump(home.path());
    let out = run_with_env(home.path(), &[], &["list"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    assert_eq!(store_dump(home.path()), before, "list wrote the store");
}

/// #4205 — a torn last line WITHOUT a trailing newline: the next row must not
/// be glued onto it. Pre-fix the glued row is unparseable and the row after it
/// links past it, so the chain still reads unbroken; only the row COUNT shows
/// the loss.
#[test]
fn a_row_after_an_unterminated_fragment_is_not_glued_to_it_4205() {
    let home = sandbox();
    let file = log_with_rows(home.path());
    let seeded = rows(home.path()).len();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .expect("open forensic file");
    std::io::Write::write_all(&mut f, b"{\"ts\":\"2026-09-29T00:00:0").expect("tear");
    drop(f);
    for _ in 0..2 {
        let out = purge_once(home.path());
        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert!(!stderr(&out).contains(DEGRADED), "stderr: {}", stderr(&out));
    }
    let recs = rows(home.path());
    assert_eq!(recs.len(), seeded + 2, "both new rows parse (none glued)");
    assert_one_unbroken_chain(&recs);
    let text = std::fs::read_to_string(&file).expect("read forensic file");
    assert!(
        text.lines().any(|l| l == "{\"ts\":\"2026-09-29T00:00:0"),
        "the fragment stays its own line"
    );
}

/// f2r review of 15fde1499 — a postgres-backed process never writes its
/// outage into a stray local sqlite store; it says the row was not written.
#[test]
fn a_postgres_backed_process_writes_no_sqlite_outage_row_4199() {
    let home = sandbox();
    garbage_only_log(home.path());
    let before = store_dump(home.path());
    let out = purge_with_env(
        home.path(),
        &[(
            "AI_MEMORY_STORE_URL",
            "postgres://ai_memory@127.0.0.1:1/none",
        )],
    );
    let err = stderr(&out);
    assert!(err.contains(DEGRADED), "stderr: {err}");
    assert!(
        err.contains("recorded in the postgres signed_events"),
        "stderr: {err}"
    );
    assert_eq!(
        store_dump(home.path()),
        before,
        "wrote the local sqlite store"
    );
}
