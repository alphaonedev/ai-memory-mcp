// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10145 (`3-agent vote (71472661)` V2-10108-KEYLESS-MARKER, K-1, K-3, K-5,
//! K-6) — the sqlite open funnel without a usable daemon key:
//!
//! - a v102 database that needs the v103 bump is refused with the typed
//!   `DaemonKeyMissing` (`PublicOnly`, `PrivateOnly`) and stays byte-identical,
//!   with no snapshot or other file added beside it;
//! - an absent path is refused before any file is created;
//! - a database already at the tip opens with no key at all;
//! - the refusal never heals a half key (K-6): the key directory is unchanged.
//!
//! One test function: every step shares this process's sandbox key directory
//! (the cargo `[env]` guard), so the steps must not run in parallel.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ai_memory::db;
use ai_memory::governance::daemon_signer::{DaemonKeyCause, DaemonKeyMissing};
use ai_memory::identity::keypair::{DAEMON_KEYPAIR_LABEL, default_key_dir};
use ai_memory::signed_events::AGENT_CUTOVER_EVENT_TYPE;
use rusqlite::params;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// The v102 rung (the step before the signed-marker bump).
const V102_RUNG: i64 = 102;
/// The public-key file suffix (`identity::keypair::PUB_SUFFIX`).
const PUB_SUFFIX: &str = ".pub";
/// The private-key file suffix (`identity::keypair::PRIV_SUFFIX`).
const PRIV_SUFFIX: &str = ".priv";
/// The suffix a moved-aside key half gets inside the sandbox key directory.
const ASIDE_SUFFIX: &str = ".aside-10145";

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

fn refusal_cause(err: &anyhow::Error) -> DaemonKeyCause {
    err.chain()
        .find_map(|e| e.downcast_ref::<DaemonKeyMissing>())
        .unwrap_or_else(|| panic!("not a DaemonKeyMissing refusal: {err:#}"))
        .cause()
}

/// Assert that opening `db_path` is refused with `cause` and that neither the
/// database directory nor the key directory changed by a byte.
fn assert_refused_untouched(db_path: &Path, key_dir: &Path, cause: DaemonKeyCause, want: &str) {
    let db_dir = db_path.parent().expect("db dir");
    let before_db = snapshot(db_dir);
    let before_keys = snapshot(key_dir);
    let err = db::open(db_path).expect_err("a keyless bump is refused");
    assert_eq!(refusal_cause(&err), cause, "{err:#}");
    assert!(
        format!("{err:#}").contains(&format!("daemon key missing: {want};")),
        "{err:#}"
    );
    assert_eq!(
        snapshot(db_dir),
        before_db,
        "the database directory is byte-identical"
    );
    assert_eq!(
        snapshot(key_dir),
        before_keys,
        "no key half is healed or written"
    );
}

fn version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("version")
}

fn markers(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
        |r| r.get(0),
    )
    .expect("count markers")
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

#[test]
fn a_keyless_open_refuses_every_bump_and_touches_nothing_10145() {
    let key_dir = default_key_dir().expect("the sandbox key directory resolves");
    let work = home_sandbox::per_test_dir("keyless-10145-");
    let stale_dir = work.path().join("stale");
    let tip_dir = work.path().join("tip");
    let fresh_dir = work.path().join("fresh");
    for d in [&stale_dir, &tip_dir, &fresh_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let stale = stale_dir.join("stale-10145.db");
    let tip = tip_dir.join("tip-10145.db");
    let fresh = fresh_dir.join("fresh-10145.db");

    // With both halves present: a create provisions the key and writes the marker.
    make_v102(&stale);
    let conn = db::open(&tip).expect("create at the tip");
    let tip_version = version(&conn);
    assert_eq!(markers(&conn), 1);
    drop(conn);

    let public = half(&key_dir, PUB_SUFFIX);
    let private = half(&key_dir, PRIV_SUFFIX);
    assert!(
        public.exists() && private.exists(),
        "the create provisioned both halves"
    );

    // PublicOnly: the private half is moved aside.
    std::fs::rename(&private, aside(&private)).expect("move private aside");
    assert_refused_untouched(
        &stale,
        &key_dir,
        DaemonKeyCause::PublicOnly,
        "the daemon public key exists without its private key",
    );
    // An absent path is refused before the file is created.
    let err = db::open(&fresh).expect_err("a keyless create is refused");
    assert_eq!(refusal_cause(&err), DaemonKeyCause::PublicOnly, "{err:#}");
    assert!(
        entries(&fresh_dir).is_empty(),
        "no file was created: {:?}",
        entries(&fresh_dir)
    );
    // A database at the tip opens with no private key.
    let conn = db::open(&tip).expect("an at-tip database opens keyless");
    assert_eq!(version(&conn), tip_version);
    assert_eq!(markers(&conn), 1);
    drop(conn);

    // PrivateOnly: the private half is back, the public half is moved aside.
    std::fs::rename(aside(&private), &private).expect("restore private");
    std::fs::rename(&public, aside(&public)).expect("move public aside");
    assert_refused_untouched(
        &stale,
        &key_dir,
        DaemonKeyCause::PrivateOnly,
        "the daemon private key exists without its public key",
    );

    // Both halves back: the bump runs and writes exactly one marker.
    std::fs::rename(aside(&public), &public).expect("restore public");
    let conn = db::open(&stale).expect("the bump runs with the key");
    assert_eq!(version(&conn), tip_version);
    assert_eq!(markers(&conn), 1, "the bump wrote one signed marker");
}
