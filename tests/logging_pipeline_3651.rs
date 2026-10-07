// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3651 — a log pipeline that fails must not look like one that works.
//!
//! Before #3651 the binary caught every logging-initialisation error and
//! kept running ("continuing without"), including the `syslog` sink on a
//! build without `--features syslog`, which the operator documentation
//! promises fails closed at boot. A second subscriber installation was a
//! DEBUG line and reported success. These tests drive the real binary for
//! the boot posture and hold the one in-process global-install test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ai_memory::config::LoggingConfig;
use ai_memory::logging::{self, LogPipelineState};

/// `EX_CONFIG` from sysexits.h, the code every boot refusal exits with.
const EX_CONFIG: i32 = 78;

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

/// Write `[logging]` config into an isolated HOME and run the binary there.
fn run_with_logging(home: &Path, logging_toml: &str, args: &[&str]) -> Output {
    run_with_section(home, "logging", logging_toml, args)
}

/// #5752 — the audit sink's compiled default is `append_only = true`, which
/// sets the platform append-only flag on `audit.log` (`chflags uappnd` on
/// macOS). A flagged file cannot be unlinked, so one left in this scratch
/// directory makes the next `actions/checkout` on a self-hosted runner fail
/// with EPERM. These tests assert the hash chain, not the inode flag, so an
/// `[audit]` body that does not say otherwise gets `append_only = false`.
fn with_scratch_safe_audit(section: &str, body: &str) -> String {
    if section == "audit" && !body.contains("append_only") {
        format!("{body}append_only = false\n")
    } else {
        body.to_string()
    }
}

/// Write one `[section]` of config into an isolated HOME and run the binary.
fn run_with_section(home: &Path, section: &str, body: &str, args: &[&str]) -> Output {
    let body = with_scratch_safe_audit(section, body);
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!("schema_version = 2\ntier = \"keyword\"\n\n[{section}]\n{body}"),
    )
    .expect("write config");
    let db: PathBuf = home.join("pipeline.db");
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .current_dir(home)
        .arg("--db")
        .arg(&db)
        .args(args)
        .output()
        .expect("run isolated CLI")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg(not(feature = "syslog"))]
#[test]
fn syslog_sink_without_the_feature_refuses_boot_3651() {
    // The documented fail-closed promise, now kept: the operator asked for
    // off-host shipping, so neither a silent local fallback nor running with
    // no sink at all is acceptable.
    let home = sandbox();
    let out = run_with_logging(
        home.path(),
        "enabled = true\nsink = \"syslog\"\nsyslog_address = \"127.0.0.1:1\"\n",
        &["stats"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("refusing to start"), "stderr: {err}");
    assert!(err.contains("--features syslog"), "stderr: {err}");
    assert!(!err.contains("continuing without"), "stderr: {err}");
}

#[cfg(unix)]
#[test]
fn unusable_log_directory_refuses_boot_3651() {
    let home = sandbox();
    let blocker = home.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").expect("write blocker");
    let out = run_with_logging(
        home.path(),
        &format!(
            "enabled = true\nsink = \"file\"\nrotation = \"never\"\npath = \"{}\"\n",
            blocker.join("sub").display()
        ),
        &["stats"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("creating log dir"), "stderr: {err}");
    assert!(err.contains("[logging].enabled = false"), "stderr: {err}");
}

#[cfg(not(feature = "syslog"))]
#[test]
fn doctor_still_runs_and_reports_the_failed_sink_3651() {
    let home = sandbox();
    let out = run_with_logging(
        home.path(),
        "enabled = true\nsink = \"syslog\"\nsyslog_address = \"127.0.0.1:1\"\n",
        &["doctor", "--json"],
    );
    let err = stderr(&out);
    assert_ne!(
        out.status.code(),
        Some(EX_CONFIG),
        "doctor must not be refused: {err}"
    );
    assert!(err.contains("`doctor` continues"), "stderr: {err}");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints a report");
    let section = report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"] == "Logging pipeline (#3651)")
        .expect("the logging section is present");
    assert_eq!(section["severity"], "critical", "section: {section}");
    let facts = section["facts"].to_string();
    assert!(facts.contains("FAILED"), "facts: {facts}");
    assert!(facts.contains("--features syslog"), "facts: {facts}");
}

#[test]
fn a_working_file_sink_still_boots_3651() {
    let home = sandbox();
    let logs = home.path().join("logs");
    let out = run_with_logging(
        home.path(),
        &format!(
            "enabled = true\nsink = \"file\"\nrotation = \"never\"\npath = \"{}\"\n",
            logs.display()
        ),
        &["stats"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(logs.is_dir(), "the file sink created its directory");
}

#[test]
fn a_second_subscriber_installation_is_an_error_3651() {
    // The ONLY test in this binary that touches the global subscriber, so
    // the order of tests cannot change what it observes.
    tracing::subscriber::set_global_default(tracing_subscriber::registry())
        .expect("first install in this process");
    let cfg = LoggingConfig {
        enabled: Some(true),
        sink: Some("stdout".to_string()),
        ..Default::default()
    };
    let err = logging::init_file_logging(&cfg)
        .expect_err("a second installation must not report success");
    let msg = format!("{err:#}");
    assert!(msg.contains("already active"), "got: {msg}");

    let status = logging::log_pipeline_status();
    assert_eq!(status.state, LogPipelineState::Failed);
    assert!(
        status
            .failure
            .as_deref()
            .is_some_and(|f| f.contains("already active")),
        "status: {status:?}"
    );
    assert_eq!(status.records_delivered, None, "nothing was measured");
}

// ---- #3651 audit half (5-agent vote 5/5 A, decision memory 25844fe7) --------
// Before the fix `main` printed "audit init failed (continuing without)" and
// ran with NO audit trail, although the docs promise `hash_chain = false`
// "REFUSES boot" and `init_from_config` refuses. These drive the real binary,
// because the lib test only ever proved the FUNCTION refuses.

/// Assert an audit boot refusal: exit 78, the refusal names the cause and the
/// escape hatch, and the old "continuing without" line is gone.
fn assert_audit_refusal(out: &Output, cause: &str) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("refusing to start"), "stderr: {err}");
    assert!(err.contains(cause), "stderr: {err}");
    assert!(err.contains("[audit].enabled = false"), "stderr: {err}");
    assert!(!err.contains("continuing without"), "stderr: {err}");
}

#[test]
fn audit_hash_chain_false_refuses_boot_3651() {
    let home = sandbox();
    let dir = home.path().join("audit");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!(
            "enabled = true\npath = \"{}\"\nhash_chain = false\n",
            dir.display()
        ),
        &["stats"],
    );
    assert_audit_refusal(&out, "hash_chain = false");
}

#[test]
fn audit_schema_version_mismatch_refuses_boot_3651() {
    let home = sandbox();
    let dir = home.path().join("audit");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!(
            "enabled = true\npath = \"{}\"\nschema_version = 999\n",
            dir.display()
        ),
        &["stats"],
    );
    assert_audit_refusal(&out, "schema_version = 999");
}

#[cfg(unix)]
#[test]
fn unusable_audit_directory_refuses_boot_3651() {
    let home = sandbox();
    let blocker = home.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").expect("write blocker");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!(
            "enabled = true\npath = \"{}\"\n",
            blocker.join("sub").display()
        ),
        &["stats"],
    );
    assert_audit_refusal(&out, "audit log");
}

#[test]
fn doctor_still_runs_with_a_refused_audit_trail_3651() {
    let home = sandbox();
    let dir = home.path().join("audit");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!(
            "enabled = true\npath = \"{}\"\nhash_chain = false\n",
            dir.display()
        ),
        &["doctor", "--json"],
    );
    let err = stderr(&out);
    assert_ne!(
        out.status.code(),
        Some(EX_CONFIG),
        "doctor must not be refused: {err}"
    );
    assert!(err.contains("`doctor` continues"), "stderr: {err}");
    let _: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints a report");
}

#[test]
fn a_working_audit_trail_still_boots_3651() {
    let home = sandbox();
    let dir = home.path().join("audit");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!("enabled = true\npath = \"{}\"\n", dir.display()),
        &["stats"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!stderr(&out).contains("refusing to start"));
}

// #4190 — `audit::init` must keep "no chain yet" (`Ok(None)`: start at
// genesis) apart from "a chain whose tail cannot be read" (`Err`: refuse boot,
// exit 78). Before #4190 every read error, and a torn or corrupt last record,
// was treated as "no chain": the process booted and appended a NEW chain at
// genesis into the same file, forking it silently.

fn audit_toml(dir: &Path) -> String {
    format!("enabled = true\npath = \"{}\"\n", dir.display())
}

/// The trail file inside the configured audit directory.
fn trail_file(dir: &Path) -> PathBuf {
    dir.join("audit.log")
}

/// One `store` through the real binary, which emits one audit record.
fn store_once(home: &Path, dir: &Path, title: &str) -> Output {
    store_once_with(home, dir, title, "")
}

/// [`store_once`] with extra `[audit]` keys appended.
fn store_once_with(home: &Path, dir: &Path, title: &str, extra: &str) -> Output {
    run_with_section(
        home,
        "audit",
        &format!("{}{extra}", audit_toml(dir)),
        &["store", "--title", title, "--content", "audit chain 4190"],
    )
}

/// Every parsed record in the trail, in file order.
fn records(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(trail_file(dir))
        .expect("read the audit trail")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("every record is valid JSON"))
        .collect()
}

/// A trail holding one genuine record, written by the binary itself.
fn trail_with_one_record(home: &Path) -> PathBuf {
    let dir = home.join("audit");
    let out = store_once(home, &dir, "first");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(records(&dir).len(), 1, "the seed run wrote one record");
    dir
}

/// Boot against a damaged trail must refuse (exit 78, naming the trail) and
/// must leave every byte of it untouched.
fn assert_damaged_trail_refused(home: &Path, dir: &Path) {
    let before = std::fs::read(trail_file(dir)).expect("read trail before");
    let out = store_once(home, dir, "second");
    assert_audit_refusal(&out, "audit trail tail");
    let after = std::fs::read(trail_file(dir)).expect("read trail after");
    assert_eq!(before, after, "a refused boot must not write to the trail");
}

#[test]
fn a_torn_last_audit_record_refuses_boot_4190() {
    let home = sandbox();
    let dir = trail_with_one_record(home.path());
    // A write torn mid-record: the last line is not a complete event.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(trail_file(&dir))
        .expect("open trail");
    std::io::Write::write_all(&mut f, b"{\"sequence\":2,\"prev_hash\":\"").expect("tear");
    drop(f);
    assert_damaged_trail_refused(home.path(), &dir);
}

#[test]
fn a_trail_of_only_garbage_refuses_boot_4190() {
    // No line parses, so the pre-#4190 scan returned "no chain" and the
    // process re-started the chain at genesis inside a non-empty file.
    let home = sandbox();
    let dir = home.path().join("audit");
    std::fs::create_dir_all(&dir).expect("create audit dir");
    std::fs::write(trail_file(&dir), b"not an audit event\n").expect("write garbage");
    assert_damaged_trail_refused(home.path(), &dir);
}

#[test]
fn a_non_utf8_audit_tail_refuses_boot_4190() {
    let home = sandbox();
    let dir = trail_with_one_record(home.path());
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(trail_file(&dir))
        .expect("open trail");
    std::io::Write::write_all(&mut f, b"\xff\xfe\xfd\n").expect("write invalid UTF-8");
    drop(f);
    assert_damaged_trail_refused(home.path(), &dir);
}

#[cfg(unix)]
#[test]
fn an_unreadable_audit_trail_refuses_boot_4190() {
    use std::os::unix::fs::PermissionsExt;
    // The OS append-only flag (`[audit].append_only`, on by default) forbids
    // the chmod this cell needs on macOS, so this cell runs without it; the
    // refusal under test does not depend on that flag.
    const NO_OS_FLAG: &str = "append_only = false\n";
    let home = sandbox();
    let dir = home.path().join("audit");
    let seed = store_once_with(home.path(), &dir, "first", NO_OS_FLAG);
    assert!(seed.status.success(), "stderr: {}", stderr(&seed));
    assert_eq!(records(&dir).len(), 1, "the seed run wrote one record");
    let trail = trail_file(&dir);
    let before = std::fs::read(&trail).expect("read trail before");
    // Append-only for us, like a trail the process may write but not read.
    std::fs::set_permissions(&trail, std::fs::Permissions::from_mode(0o200)).expect("chmod");
    if std::fs::read(&trail).is_ok() {
        // Running as root: permission bits do not deny reads, so this cell
        // cannot build its precondition. The other variants still cover the
        // refusal; say so rather than passing silently.
        std::fs::set_permissions(&trail, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        eprintln!(
            "SKIP an_unreadable_audit_trail_refuses_boot_4190: permission bits do not deny reads here"
        );
        return;
    }
    let out = store_once_with(home.path(), &dir, "second", NO_OS_FLAG);
    std::fs::set_permissions(&trail, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_audit_refusal(&out, "audit trail tail");
    assert_eq!(
        before,
        std::fs::read(&trail).expect("read trail after"),
        "a refused boot must not write to the trail"
    );
}

#[test]
fn a_fresh_audit_trail_boots_and_writes_genesis_4190() {
    let home = sandbox();
    let dir = home.path().join("audit");
    assert!(!trail_file(&dir).exists(), "precondition: no trail yet");
    let out = store_once(home.path(), &dir, "first");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let recs = records(&dir);
    assert_eq!(recs.len(), 1, "one record");
    assert_eq!(recs[0]["sequence"], 1, "a fresh chain starts at sequence 1");
    assert_eq!(
        recs[0]["prev_hash"],
        ai_memory::audit::CHAIN_HEAD_PREV_HASH,
        "a fresh chain starts at genesis"
    );
}

#[test]
fn an_intact_audit_trail_boots_and_appends_to_its_tail_4190() {
    let home = sandbox();
    let dir = trail_with_one_record(home.path());
    let out = store_once(home.path(), &dir, "second");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let recs = records(&dir);
    assert_eq!(recs.len(), 2, "the second boot appended one record");
    assert_eq!(
        recs[1]["prev_hash"], recs[0]["self_hash"],
        "the new record continues the existing chain, not genesis"
    );
    assert_eq!(
        recs[1]["sequence"].as_u64(),
        recs[0]["sequence"].as_u64().map(|s| s + 1),
        "the sequence continues across the restart"
    );
}

// #5752 — a test that boots the audit sink in a scratch directory must leave
// that directory removable, or the next checkout on a self-hosted runner dies
// with EPERM (#5657). The sink's production default stays append-only; the
// test harness opts its scratch trails out.

/// `true` when the platform append-only flag is set on `path`: `UF_APPEND`
/// from `st_flags` on macOS, `FS_APPEND_FL` from `FS_IOC_GETFLAGS` on Linux.
/// Other platforms have no such flag.
fn has_append_only_flag(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        const UF_APPEND: u32 = 0x0000_0004;
        std::fs::metadata(path).is_ok_and(|m| m.st_flags() & UF_APPEND != 0)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        const FS_APPEND_FL: libc::c_int = 0x0000_0020;
        const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
        let Ok(file) = std::fs::File::open(path) else {
            return false;
        };
        let mut flags: libc::c_int = 0;
        // SAFETY: the descriptor is open for the call and GETFLAGS writes one
        // `int` through the pointer to `flags`.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) };
        rc == 0 && flags & FS_APPEND_FL != 0
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        false
    }
}

#[test]
fn audit_scratch_boot_opts_out_of_the_flag_and_leaves_removable_scratch_5752() {
    let home = sandbox();
    let dir = home.path().join("audit");
    let out = run_with_section(
        home.path(),
        "audit",
        &format!("enabled = true\npath = \"{}\"\n", dir.display()),
        &["store", "--title", "scratch", "--content", "5752"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // The harness config, not the inode, is what a Linux user without
    // CAP_LINUX_IMMUTABLE can observe: the scratch trail opts out.
    let config = std::fs::read_to_string(home.path().join(".config/ai-memory/config.toml"))
        .expect("read the written config");
    assert!(
        config.contains("append_only = false"),
        "a scratch audit trail must opt out of the append-only flag:\n{config}"
    );
    assert!(trail_file(&dir).exists(), "the trail was written");
    assert!(
        !has_append_only_flag(&trail_file(&dir)),
        "the scratch audit.log must not carry the append-only flag"
    );
    home.close()
        .expect("the scratch directory, audit.log included, must be removable");
}

#[test]
fn an_explicit_append_only_setting_is_not_overridden_5752() {
    assert_eq!(
        with_scratch_safe_audit("audit", "enabled = true\nappend_only = true\n"),
        "enabled = true\nappend_only = true\n"
    );
    assert_eq!(
        with_scratch_safe_audit("logging", "level = \"info\"\n"),
        "level = \"info\"\n"
    );
}
