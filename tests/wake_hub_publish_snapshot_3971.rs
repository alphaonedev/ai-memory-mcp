// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3971 / #3637 (M4) — the privileged hand-off of the refreshed allowlist
//! snapshot, driven through the REAL binary.
//!
//! Class invariant (b29 ruling e2166b1e): no step that runs with more
//! privilege than the writer of its input opens that input through a path the
//! writer can redirect, and a refusal publishes nothing.
//!
//! Every row below runs `ai-memory wake-hub --publish-snapshot SRC --allowlist
//! DEST` with an emptied environment (the shipped unit's `env -i`) and asserts
//! the EXACT refusal line, the pinned refusal exit code, and that the
//! destination is byte-unchanged with no stray temp file beside it. The
//! success path needs two real uids and root, so it runs in the privileged CI
//! step (`scripts/wake_hub_publish_root_3971.py`), never on a developer host.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// The prefix every publish-mode refusal line carries.
const REFUSED: &str = "wake-hub: --publish-snapshot refused:";
/// The refusal exit code the packaged unit keys on (W-11).
const EXIT_PUBLISH_REFUSED: i32 = 1;
/// clap's exit code for a usage error (a refused flag combination).
const EXIT_USAGE: i32 = 2;
/// The source ceiling the hub's own reader enforces.
const MAX_SNAPSHOT_BYTES: usize = 1_048_576;
/// Size of the over-size row: four times the ceiling (well past 100K).
const OVERSIZE_BYTES: usize = 4 * MAX_SNAPSHOT_BYTES;
/// Wall-clock ceiling for any refusal, including the over-size and the
/// stalled-FIFO rows (a read that blocked or scanned the input would blow it).
const REFUSAL_CEILING: Duration = Duration::from_secs(10);
/// Bytes pre-seeded at the destination; a refusal must leave them unchanged.
const OLD_DEST: &[u8] = b"old-snapshot";
/// RFC 8032 test vector 1 public key: a valid Ed25519 point, so the snapshot
/// passes the hub's key decoding without minting a key here.
const PUBKEY_B64: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-memory")
}

/// A fresh, valid snapshot (the shape `identity hub-cache` writes).
fn snapshot_json() -> Vec<u8> {
    let now = chrono::Utc::now().to_rfc3339();
    serde_json::to_vec(&serde_json::json!({
        "version": ai_memory::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
        "refreshed_at": now,
        "agents": [{
            "agent_id": "ai:alice",
            "pubkey_b64": PUBKEY_B64,
            "bind_authority": "possession_proof",
            "bound_at": now,
            "revoked_keys": [],
            "readable_prefixes": [],
        }],
    }))
    .expect("encode snapshot")
}

struct Sandbox {
    _root: tempfile::TempDir,
    base: PathBuf,
    stage: PathBuf,
    hub: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        // The walk refuses a symlink at ANY level, and a temp root can sit
        // under one (macOS /var -> /private/var), so canonicalise first.
        let base = std::fs::canonicalize(root.path()).expect("canonicalize");
        let stage = base.join("stage");
        let hub = base.join("hub");
        for dir in [&stage, &hub] {
            std::fs::create_dir(dir).expect("mkdir");
            set_mode(dir, 0o700);
        }
        let sb = Self {
            _root: root,
            base,
            stage,
            hub,
        };
        write_mode(&sb.dest(), OLD_DEST, 0o600);
        sb
    }

    fn src(&self) -> PathBuf {
        self.stage.join("hub-allow.json")
    }

    fn dest(&self) -> PathBuf {
        self.hub.join("hub-allow.json")
    }

    /// The destination is byte-unchanged and nothing else appeared beside it.
    fn assert_nothing_published(&self, row: &str) {
        assert_eq!(
            std::fs::read(self.dest()).expect("read dest"),
            OLD_DEST,
            "{row}: the destination must be byte-unchanged after a refusal"
        );
        let names: Vec<_> = std::fs::read_dir(&self.hub)
            .expect("ls hub")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("hub-allow.json")],
            "{row}: a refusal must leave no temp file in the hub directory"
        );
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).expect("write");
    set_mode(path, mode);
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("cstr");
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// Run the publish mode exactly as the shipped unit does: emptied
/// environment plus the one named variable.
fn publish(src: &Path, dest: &Path) -> Output {
    publish_with(src, dest, &[], &[])
}

fn publish_with(src: &Path, dest: &Path, extra_args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.env_clear().env("AI_MEMORY_NO_CONFIG", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(extra_args)
        .arg("wake-hub")
        .arg("--publish-snapshot")
        .arg(src)
        .arg("--allowlist")
        .arg(dest);
    cmd.output().expect("spawn ai-memory")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_owned()
}

/// Assert one refusal row: exact line, pinned exit code, bounded time, and
/// nothing published.
fn assert_refused(sb: &Sandbox, row: &str, src: &Path, expected: &str) {
    let start = Instant::now();
    let out = publish(src, &sb.dest());
    let took = start.elapsed();
    assert_eq!(
        stderr(&out),
        format!("{REFUSED} {expected}"),
        "{row}: exact refusal line"
    );
    assert_eq!(
        out.status.code(),
        Some(EXIT_PUBLISH_REFUSED),
        "{row}: refusal exit code"
    );
    assert!(out.stdout.is_empty(), "{row}: a refusal prints no report");
    assert!(took < REFUSAL_CEILING, "{row}: took {took:?}");
    sb.assert_nothing_published(row);
}

// ---- W-1: the source refusals ------------------------------------------

#[test]
fn w1_a_symlinked_source_publishes_nothing_3971() {
    let sb = Sandbox::new();
    let secret = sb.stage.join("secret");
    write_mode(&secret, &snapshot_json(), 0o600);
    std::os::unix::fs::symlink(&secret, sb.src()).expect("symlink");
    let expected = format!("source {} is a symlink", sb.src().display());
    assert_refused(&sb, "symlinked source", &sb.src(), &expected);
}

#[test]
fn w1_a_symlinked_parent_directory_publishes_nothing_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    let link = sb.base.join("stage-link");
    std::os::unix::fs::symlink(&sb.stage, &link).expect("symlink");
    let src = link.join("hub-allow.json");
    let expected = format!("directory {} is reached through a symlink", link.display());
    assert_refused(&sb, "symlinked parent", &src, &expected);
}

#[test]
fn w1_a_hard_linked_source_publishes_nothing_3971() {
    let sb = Sandbox::new();
    let other = sb.stage.join("other");
    write_mode(&other, &snapshot_json(), 0o600);
    std::fs::hard_link(&other, sb.src()).expect("hard link");
    let expected = format!(
        "source {} has 2 hard links; exactly 1 is required",
        sb.src().display()
    );
    assert_refused(&sb, "hard-linked source", &sb.src(), &expected);
}

#[test]
fn w1_a_wrong_mode_source_publishes_nothing_3971() {
    // Table over the class: every mode but exactly 0600 is refused.
    for mode in [0o644_u32, 0o640, 0o604, 0o400, 0o700, 0o660, 0o4600] {
        let sb = Sandbox::new();
        write_mode(&sb.src(), &snapshot_json(), mode);
        let expected = format!(
            "source {} must be mode 0600, found {mode:04o}",
            sb.src().display()
        );
        assert_refused(&sb, &format!("mode {mode:04o}"), &sb.src(), &expected);
    }
}

#[test]
fn w1_a_fifo_source_publishes_nothing_without_blocking_3971() {
    let sb = Sandbox::new();
    mkfifo(&sb.src());
    let expected = format!("source {} is not a regular file", sb.src().display());
    assert_refused(&sb, "fifo source", &sb.src(), &expected);
}

#[cfg(target_os = "linux")]
#[test]
fn w1_a_stalled_fifo_source_with_a_live_writer_does_not_wedge_3971() {
    let sb = Sandbox::new();
    mkfifo(&sb.src());
    // Hold a writer that never writes: a blocking read would wedge the root
    // step until TimeoutStartSec. Linux allows O_RDWR on a FIFO.
    let _writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(sb.src())
        .expect("hold the fifo open");
    let expected = format!("source {} is not a regular file", sb.src().display());
    assert_refused(&sb, "stalled fifo", &sb.src(), &expected);
}

#[test]
fn w1_an_over_size_source_publishes_nothing_in_bounded_time_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &vec![b' '; OVERSIZE_BYTES], 0o600);
    let expected = format!(
        "source {} is {OVERSIZE_BYTES} bytes, over the {MAX_SNAPSHOT_BYTES} byte ceiling",
        sb.src().display()
    );
    assert_refused(&sb, "over-size source", &sb.src(), &expected);
}

#[test]
fn w1_a_malformed_or_expired_snapshot_publishes_nothing_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), b"{not json", 0o600);
    let out = publish(&sb.src(), &sb.dest());
    let line = stderr(&out);
    assert!(
        line.starts_with(&format!(
            "{REFUSED} snapshot source {} failed validation:",
            sb.src().display()
        )),
        "{line}"
    );
    assert_eq!(out.status.code(), Some(EXIT_PUBLISH_REFUSED));
    sb.assert_nothing_published("malformed");

    let stale = serde_json::to_vec(&serde_json::json!({
        "version": ai_memory::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
        "refreshed_at": "2020-01-01T00:00:00Z",
        "agents": [],
    }))
    .expect("encode");
    write_mode(&sb.src(), &stale, 0o600);
    let out = publish(&sb.src(), &sb.dest());
    assert!(
        stderr(&out).contains("expired or future-dated"),
        "{}",
        stderr(&out)
    );
    assert_eq!(out.status.code(), Some(EXIT_PUBLISH_REFUSED));
    sb.assert_nothing_published("expired");
}

#[test]
fn w1_a_relative_or_traversing_path_publishes_nothing_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    let rel = Path::new("stage/hub-allow.json");
    assert_refused(
        &sb,
        "relative source",
        rel,
        "stage/hub-allow.json must be an absolute path",
    );
    let dotdot = sb.stage.join("..").join("stage").join("hub-allow.json");
    let expected = format!("{} must not contain parent traversal", dotdot.display());
    assert_refused(&sb, "dotdot source", &dotdot, &expected);
}

// ---- W-8: the ownership invariants ---------------------------------------

#[test]
fn w8_a_group_or_world_writable_source_directory_publishes_nothing_3971() {
    for mode in [0o770_u32, 0o702, 0o1777] {
        let sb = Sandbox::new();
        write_mode(&sb.src(), &snapshot_json(), 0o600);
        set_mode(&sb.stage, mode);
        let expected = format!(
            "source directory {} is group- or world-writable (mode {mode:04o})",
            sb.stage.display()
        );
        assert_refused(&sb, &format!("stage {mode:04o}"), &sb.src(), &expected);
    }
}

#[test]
fn w8_a_group_or_world_writable_destination_directory_publishes_nothing_3971() {
    for mode in [0o770_u32, 0o702, 0o777] {
        let sb = Sandbox::new();
        write_mode(&sb.src(), &snapshot_json(), 0o600);
        set_mode(&sb.hub, mode);
        let expected = format!(
            "destination directory {} is group- or world-writable (mode {mode:04o})",
            sb.hub.display()
        );
        assert_refused(&sb, &format!("hub {mode:04o}"), &sb.src(), &expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn w8_a_root_owned_source_directory_publishes_nothing_3971() {
    // /etc is root-owned and not group-writable on every Linux host; the
    // refusal fires on the directory, before any file in it is opened.
    let sb = Sandbox::new();
    let src = Path::new("/etc/ai-memory-hub-allow-3971.json");
    assert_refused(
        &sb,
        "root-owned source dir",
        src,
        "source directory /etc is owned by root; the staging directory must belong to the unprivileged writer",
    );
}

#[test]
fn w8_a_same_owner_hand_off_publishes_nothing_3971() {
    // Every source check passes (a valid, single-link 0600 snapshot owned by
    // its directory's owner); the hand-off is refused because it would not
    // cross a uid boundary. On a one-uid host this is the LAST check.
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    // SAFETY: getuid has no arguments or memory effects and cannot fail.
    let uid = unsafe { libc::getuid() };
    let expected = format!(
        "destination directory {} has the same owner (uid {uid}) as the source directory; the hand-off must cross a uid boundary",
        sb.hub.display()
    );
    assert_refused(&sb, "same owner", &sb.src(), &expected);
}

// ---- W-9: the mode is exclusive ------------------------------------------

#[test]
fn w9_every_other_mode_or_serving_flag_is_refused_with_publish_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    let sock = sb.base.join("hub.sock");
    let sock = sock.to_str().expect("utf8");
    let rows: &[&[&str]] = &[
        &["--socket", sock],
        &["--hub-id", "hub-3971"],
        &["--max-connections", "4"],
        &["--posture"],
        &["--health"],
        &["--require-admits"],
    ];
    for extra in rows {
        let out = Command::new(bin())
            .env_clear()
            .env("AI_MEMORY_NO_CONFIG", "1")
            .arg("wake-hub")
            .arg("--publish-snapshot")
            .arg(sb.src())
            .arg("--allowlist")
            .arg(sb.dest())
            .args(*extra)
            .output()
            .expect("spawn");
        let line = stderr(&out);
        assert!(
            line.contains("cannot be used with"),
            "{extra:?}: clap must refuse the combination: {line}"
        );
        assert_eq!(out.status.code(), Some(EXIT_USAGE), "{extra:?}");
        assert!(!Path::new(sock).exists(), "{extra:?}: no socket bound");
        sb.assert_nothing_published(&format!("{extra:?}"));
    }
    // --publish-snapshot without a destination is a usage error too.
    let out = Command::new(bin())
        .env_clear()
        .arg("wake-hub")
        .arg("--publish-snapshot")
        .arg(sb.src())
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(EXIT_USAGE), "{}", stderr(&out));
    assert!(stderr(&out).contains("--allowlist"), "{}", stderr(&out));
}

/// A HOME / XDG tree whose config is unparseable and whose database path is
/// not a database: reading either would change the outcome.
struct Hostile {
    home: PathBuf,
    db: PathBuf,
}

fn hostile(sb: &Sandbox) -> Hostile {
    let home = sb.base.join("home");
    let cfg_dir = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir cfg");
    std::fs::write(cfg_dir.join("config.toml"), b"this is = = not toml [[[").expect("cfg");
    let db = sb.base.join("not-a-db.db");
    std::fs::write(&db, b"not a sqlite database").expect("db");
    Hostile { home, db }
}

/// Every file under `root` with its length: a write anywhere shows up.
fn tree(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("ls") {
            let entry = entry.expect("entry");
            let meta = entry.metadata().expect("meta");
            if meta.is_dir() {
                stack.push(entry.path());
            }
            out.push((entry.path(), meta.len()));
        }
    }
    out.sort();
    out
}

#[test]
fn w9_w3_every_accepted_combination_reads_no_config_db_or_key_and_binds_nothing_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    let h = hostile(&sb);
    let db = h.db.to_str().expect("utf8");
    let home = h.home.to_str().expect("utf8");
    let passfile = sb.base.join("pass");
    std::fs::write(&passfile, b"pw").expect("pass");
    let passfile = passfile.to_str().expect("utf8");
    // Every global flag the parser accepts beside the mode.
    let combos: &[&[&str]] = &[
        &[],
        &["--db", db],
        &["--agent-id", "ai:mallory"],
        &["--db-passphrase-file", passfile],
        &["--json"],
        &["--db", db, "--agent-id", "ai:mallory", "--json"],
    ];
    let before = tree(&sb.base);
    let uid = {
        // SAFETY: getuid has no arguments or memory effects and cannot fail.
        unsafe { libc::getuid() }
    };
    let expected = format!(
        "{REFUSED} destination directory {} has the same owner (uid {uid}) as the source directory; the hand-off must cross a uid boundary",
        sb.hub.display()
    );
    for combo in combos {
        // No AI_MEMORY_NO_CONFIG here: a config read would refuse the boot on
        // the unparseable file and change the line.
        let mut cmd = Command::new(bin());
        cmd.env_clear()
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", h.home.join(".config"))
            .args(*combo)
            .arg("wake-hub")
            .arg("--publish-snapshot")
            .arg(sb.src())
            .arg("--allowlist")
            .arg(sb.dest());
        let out = cmd.output().expect("spawn");
        assert_eq!(stderr(&out), expected, "{combo:?}");
        assert_eq!(out.status.code(), Some(EXIT_PUBLISH_REFUSED), "{combo:?}");
        assert_eq!(
            tree(&sb.base),
            before,
            "{combo:?}: the mode wrote nothing (no db, config, key, log or socket)"
        );
    }
}

// ---- W-10: no environment variable changes the mode ------------------------

#[test]
fn w10_no_environment_variable_changes_the_publish_mode_3971() {
    let sb = Sandbox::new();
    write_mode(&sb.src(), &snapshot_json(), 0o600);
    let h = hostile(&sb);
    let baseline = Command::new(bin())
        .env_clear()
        .arg("wake-hub")
        .arg("--publish-snapshot")
        .arg(sb.src())
        .arg("--allowlist")
        .arg(sb.dest())
        .output()
        .expect("spawn");
    let before = tree(&sb.base);
    let db = h.db.to_str().expect("utf8").to_owned();
    let home = h.home.to_str().expect("utf8").to_owned();
    let cfg = h.home.join(".config").to_str().expect("utf8").to_owned();
    let rows: Vec<(&str, String)> = vec![
        ("HOME", home.clone()),
        ("XDG_CONFIG_HOME", cfg),
        (
            "AI_MEMORY_CONFIG",
            format!("{home}/.config/ai-memory/config.toml"),
        ),
        ("AI_MEMORY_DB", db),
        ("AI_MEMORY_AGENT_ID", "ai:mallory".to_owned()),
        ("AI_MEMORY_NO_CONFIG", "0".to_owned()),
        ("AI_MEMORY_LOG_DIR", format!("{home}/logs")),
        ("AI_MEMORY_KEY_DIR", format!("{home}/keys")),
        ("AI_MEMORY_DB_PASSPHRASE", "pw".to_owned()),
        ("RUST_LOG", "trace".to_owned()),
        ("RUST_BACKTRACE", "1".to_owned()),
        ("NO_COLOR", "1".to_owned()),
        ("CLICOLOR_FORCE", "1".to_owned()),
        ("TMPDIR", format!("{home}/tmp")),
        ("PWD", home.clone()),
    ];
    for (key, value) in &rows {
        let out = Command::new(bin())
            .env_clear()
            .env(key, value)
            .arg("wake-hub")
            .arg("--publish-snapshot")
            .arg(sb.src())
            .arg("--allowlist")
            .arg(sb.dest())
            .output()
            .expect("spawn");
        assert_eq!(out.stderr, baseline.stderr, "{key}: stderr changed");
        assert_eq!(out.stdout, baseline.stdout, "{key}: stdout changed");
        assert_eq!(
            out.status.code(),
            baseline.status.code(),
            "{key}: exit changed"
        );
        assert_eq!(tree(&sb.base), before, "{key}: the mode wrote a file");
    }
    assert_eq!(baseline.status.code(), Some(EXIT_PUBLISH_REFUSED));
}
