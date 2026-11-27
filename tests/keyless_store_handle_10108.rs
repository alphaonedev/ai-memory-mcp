// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (`3-agent vote (71472661)` V2-10108-KEYLESS-MARKER, K-7) — the
//! keyless refusal keeps its type past the SAL adapter and the daemon:
//!
//! - `SqliteStore::open` on a keyless v102 database (and on an absent path)
//!   is refused with the typed `DaemonKeyMissing` reachable through the
//!   `std::error::Error::source` chain, never a flattened string, and neither
//!   the database directory nor the key directory changes by a byte;
//! - a keyless `ai-memory --db <stale> serve` on the default profile exits
//!   non-zero with the exact refusal text, never reports unsigned-link mode
//!   over the database it could not bump, and leaves the database unchanged.
//!
//! One test function: every step shares this process's sandbox key directory
//! (the cargo `[env]` guard), so the steps must not run in parallel.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::db;
#[cfg(feature = "sal")]
use ai_memory::governance::daemon_signer::{DaemonKeyCause, DaemonKeyMissing};
use ai_memory::identity::keypair::{DAEMON_KEYPAIR_LABEL, default_key_dir};
use ai_memory::signed_events::AGENT_CUTOVER_EVENT_TYPE;
#[cfg(feature = "sal")]
use ai_memory::store::sqlite::SqliteStore;
use rusqlite::params;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;
#[path = "common/tls.rs"]
mod tls_helper;

/// The v102 rung (the step before the signed-marker bump).
const V102_RUNG: i64 = 102;
/// The public-key file suffix (`identity::keypair::PUB_SUFFIX`).
const PUB_SUFFIX: &str = ".pub";
/// The private-key file suffix (`identity::keypair::PRIV_SUFFIX`).
const PRIV_SUFFIX: &str = ".priv";
/// The suffix a moved-aside key half gets inside the sandbox key directory.
const ASIDE_SUFFIX: &str = ".aside-10108";
/// The `describe()` text of `DaemonKeyCause::PublicOnly`.
const PUBLIC_ONLY_TEXT: &str = "the daemon public key exists without its private key";
/// The WARN `ensure_and_load_daemon_keypair` prints when it degrades the daemon
/// to unsigned-link mode with only the public half on disk.
const UNSIGNED_LINK_WARN: &str = "link/persona/witness signing is DISABLED";
/// The prefix the pre-fix adapter mapping added in front of the typed text.
const FLATTENED_PREFIX: &str = "underlying backend error: daemon key missing";
/// How long the keyless serve child may take to refuse before it is killed.
const SERVE_REFUSAL_DEADLINE: Duration = Duration::from_secs(120);
/// Poll interval while waiting for the serve child to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn half(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!("{DAEMON_KEYPAIR_LABEL}{suffix}"))
}

fn aside(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ASIDE_SUFFIX);
    PathBuf::from(s)
}

fn entries(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

/// Every file in `dir` with its bytes.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    entries(dir)
        .into_iter()
        .map(|name| {
            let bytes = std::fs::read(dir.join(&name)).expect("read file");
            (name, bytes)
        })
        .collect()
}

/// The typed refusal, found by walking `std::error::Error::source` from `err`.
#[cfg(feature = "sal")]
fn typed_refusal<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a DaemonKeyMissing> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(k) = e.downcast_ref::<DaemonKeyMissing>() {
            return Some(k);
        }
        cur = e.source();
    }
    None
}

#[cfg(feature = "sal")]
fn open_refused(path: &Path) -> ai_memory::store::StoreError {
    match SqliteStore::open(path) {
        Ok(_) => panic!(
            "a keyless SqliteStore::open of {} is refused",
            path.display()
        ),
        Err(e) => e,
    }
}

/// Assert the adapter refusal carries the typed cause with its exact text.
#[cfg(feature = "sal")]
fn assert_typed(err: &ai_memory::store::StoreError, cause: DaemonKeyCause, want: &str) {
    let typed = typed_refusal(err)
        .unwrap_or_else(|| panic!("no typed DaemonKeyMissing in the source chain: {err}"));
    assert_eq!(typed.cause(), cause, "{err}");
    assert!(
        typed
            .to_string()
            .starts_with(&format!("daemon key missing: {want};")),
        "{typed}"
    );
}

fn version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("version")
}

/// A database at v102 with no marker: create it at the tip, then take it back.
fn make_v102(path: &Path) {
    let conn = db::open(path).expect("create");
    conn.execute(
        "DELETE FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
    )
    .expect("drop genesis marker");
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("rewind to v102");
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint");
}

/// Run `ai-memory --db <db> serve` with the sandbox env and return its exit
/// status and stderr. A child still running at the deadline is killed and
/// the test fails: a keyless boot must refuse, never serve.
fn keyless_serve(
    db_path: &Path,
    store_url: Option<&str>,
    key_dir: &Path,
    work: &Path,
) -> (std::process::ExitStatus, String) {
    let sandbox = home_sandbox::install();
    let tls = tls_helper::TestTls::generate(&work.join("tls-10108"));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
        .to_string();
    let db_arg = db_path.to_str().expect("utf-8 db path");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    if let Some(url) = store_url {
        // The env channel: an explicit `--db` keeps the local path while the
        // SAL handle binds this URL (#3431), so the two stores differ.
        cmd.env("AI_MEMORY_STORE_URL", url);
    } else {
        cmd.env_remove("AI_MEMORY_STORE_URL");
    }
    let mut child = cmd
        .current_dir(work)
        .env("HOME", sandbox.home())
        .env("XDG_CONFIG_HOME", sandbox.home().join(".config"))
        .env("AI_MEMORY_KEY_DIR", key_dir)
        // The boot ensures the resolved agent's key and installs it as the
        // chain signer (main.rs boot, #3354); naming the daemon label makes
        // that the public-only daemon key, so the serve is genuinely keyless.
        .env("AI_MEMORY_AGENT_ID", DAEMON_KEYPAIR_LABEL)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .env("HF_HUB_OFFLINE", "1")
        .env_remove("AI_MEMORY_DB")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .env_remove("AI_MEMORY_SECURITY_PROFILE")
        .args([
            "--db",
            db_arg,
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port,
        ])
        .args(tls.serve_arg_strs())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory serve");
    let deadline = Instant::now() + SERVE_REFUSAL_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait serve child") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill the serve child");
            child.wait().expect("reap the serve child");
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .expect("stderr pipe")
                .read_to_string(&mut stderr)
                .expect("read stderr");
            panic!("a keyless serve did not refuse within {SERVE_REFUSAL_DEADLINE:?}: {stderr}");
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr pipe")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    (status, stderr)
}

#[test]
fn a_keyless_adapter_open_and_serve_keep_the_typed_refusal_10108() {
    let key_dir = default_key_dir().expect("the sandbox key directory resolves");
    let work = home_sandbox::per_test_dir("keyless-10108-");
    let stale_dir = work.path().join("stale");
    let fresh_dir = work.path().join("fresh");
    let tip_dir = work.path().join("tip");
    for d in [&stale_dir, &fresh_dir, &tip_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let stale = stale_dir.join("stale-10108.db");
    let tip = tip_dir.join("tip-10108.db");

    // With both halves present the create provisions the key.
    make_v102(&stale);
    drop(db::open(&tip).expect("create the tip database"));
    let public = half(&key_dir, PUB_SUFFIX);
    let private = half(&key_dir, PRIV_SUFFIX);
    assert!(
        public.exists() && private.exists(),
        "both halves provisioned"
    );

    // PublicOnly: the private half is moved aside.
    std::fs::rename(&private, aside(&private)).expect("move private aside");
    let before_db = snapshot(&stale_dir);
    let before_keys = snapshot(&key_dir);

    // The SAL adapter keeps the type (it used to flatten it to a string).
    #[cfg(feature = "sal")]
    {
        let err = open_refused(&stale);
        assert_typed(&err, DaemonKeyCause::PublicOnly, PUBLIC_ONLY_TEXT);
        assert_eq!(snapshot(&stale_dir), before_db, "db dir byte-identical");
        assert_eq!(snapshot(&key_dir), before_keys, "no key half healed");
        let fresh = fresh_dir.join("fresh-10108.db");
        let err = open_refused(&fresh);
        assert_typed(&err, DaemonKeyCause::PublicOnly, PUBLIC_ONLY_TEXT);
        assert!(entries(&fresh_dir).is_empty(), "{:?}", entries(&fresh_dir));
    }

    // The daemon serve path on the default profile refuses with the same text:
    // first with the stale database as the one store, then (SAL build) with a
    // tip `--db` and the stale database as the env-channel SAL store, where
    // the refusal must come before the unsigned-link report.
    let stale_url = format!("sqlite://{}", stale.display());
    let mut legs: Vec<(&Path, Option<&str>)> = vec![(&stale, None)];
    if cfg!(feature = "sal") {
        legs.push((&tip, Some(stale_url.as_str())));
    }
    for (db_arg, url) in legs {
        let (status, stderr) = keyless_serve(db_arg, url, &key_dir, work.path());
        assert!(
            !status.success(),
            "a keyless serve exits non-zero: {stderr}"
        );
        assert!(
            stderr.contains(&format!("daemon key missing: {PUBLIC_ONLY_TEXT};")),
            "{url:?}: {stderr}"
        );
        assert!(!stderr.contains(FLATTENED_PREFIX), "{url:?}: {stderr}");
        assert!(!stderr.contains(UNSIGNED_LINK_WARN), "{url:?}: {stderr}");
        assert_eq!(
            snapshot(&stale_dir),
            before_db,
            "serve left the db unchanged"
        );
        assert_eq!(snapshot(&key_dir), before_keys, "serve healed no key half");
    }

    // Both halves back: the funnel opens and bumps.
    std::fs::rename(aside(&private), &private).expect("restore private");
    drop(db::open(&stale).expect("the funnel opens with the key"));
    let conn = rusqlite::Connection::open(&stale).expect("reopen");
    assert!(version(&conn) > V102_RUNG, "the bump ran");
}
