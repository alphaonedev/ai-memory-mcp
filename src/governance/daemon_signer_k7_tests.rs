// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10179 / #10108 K-7 — the partial-daemon-key refusals keep their type.
//!
//! - [`DaemonChainSigner::ledger_writer_boot_refusal`] over every key state
//!   and several agent ids: the exact typed cause, reachable by downcast
//!   through the `anyhow` chain, and the exact context text; `None` when the
//!   daemon key is whole or wholly absent.
//! - (`sal`) `build_curator_store`, which opens through `build_store_handle`
//!   on both the `--db` arm and the `sqlite://` arm: over a public-only key
//!   the error chain still downcasts to the typed cause, and no database file
//!   is created.
//!
//! Each case runs in a child of this lib test binary
//! ([`crate::test_support::spawn_test_child`]: a clean environment with its
//! own HOME, XDG config, witness key directory and `AI_MEMORY_KEY_DIR` under
//! `.local-runs`), so the resolved key directory is the case's own.

use std::path::{Path, PathBuf};

use super::{DaemonChainSigner, DaemonKeyCause, DaemonKeyMissing, partial_daemon_key_boot_refusal};
use crate::identity::keypair::{DAEMON_KEYPAIR_LABEL, agent_priv_path, agent_pub_path};

const MODULE_PATH: &str = "governance::daemon_signer::k7_tests";
/// The child role: the expected cause (`PublicOnly`, `PrivateOnly`, `None`).
const CHILD_EXPECT_ENV: &str = "AI_MEMORY_TEST_K7_EXPECT";
/// The child role (`sal` leg): the directory the fresh databases go in.
#[cfg(feature = "sal")]
const CHILD_DB_DIR_ENV: &str = "AI_MEMORY_TEST_K7_DB_DIR";
/// The line a child prints once every assertion of its case held.
const CHILD_OK_LINE: &str = "K7-CHILD-OK";
/// The agent ids each boot-refusal case is checked under: the daemon label,
/// the #10179 id, and the resolver's fallback id.
const AGENT_IDS: [&str; 3] = [DAEMON_KEYPAIR_LABEL, "agent-10179", "ai-memory"];
/// Expected-cause spellings passed to the child.
const EXPECT_PUBLIC_ONLY: &str = "PublicOnly";
const EXPECT_PRIVATE_ONLY: &str = "PrivateOnly";
const EXPECT_NONE: &str = "None";

/// The daemon key state a case plants in its key directory.
#[derive(Debug, Clone, Copy)]
enum KeyState {
    PublicOnly,
    PrivateOnly,
    Whole,
    Absent,
}

impl KeyState {
    const ALL: [Self; 4] = [
        Self::PublicOnly,
        Self::PrivateOnly,
        Self::Whole,
        Self::Absent,
    ];

    /// The hand-written expected column.
    fn expected(self) -> &'static str {
        match self {
            Self::PublicOnly => EXPECT_PUBLIC_ONLY,
            Self::PrivateOnly => EXPECT_PRIVATE_ONLY,
            Self::Whole | Self::Absent => EXPECT_NONE,
        }
    }
}

fn run_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("k7-10179")
}

/// A fresh run directory under `<repo>/.local-runs/k7-10179/`.
fn run_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = run_root().join(format!("{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the K-7 run dir");
    dir
}

/// Remove a run directory; refuses anything outside `.local-runs/k7-10179`.
fn remove_run_dir(dir: &Path) {
    assert!(
        dir.starts_with(run_root()),
        "refusing to remove {}",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Plant `state` in a fresh key directory under `run` and return it.
fn plant(run: &Path, state: KeyState) -> PathBuf {
    let key_dir = run.join("keys");
    match state {
        KeyState::Absent => {
            std::fs::create_dir_all(&key_dir).expect("create the key dir");
        }
        KeyState::Whole | KeyState::PublicOnly | KeyState::PrivateOnly => {
            DaemonChainSigner::provision(&key_dir).expect("provision a whole daemon key");
        }
    }
    let pub_path = agent_pub_path(&key_dir, DAEMON_KEYPAIR_LABEL);
    let priv_path = agent_priv_path(&key_dir, DAEMON_KEYPAIR_LABEL);
    match state {
        KeyState::PublicOnly => std::fs::remove_file(&priv_path).expect("drop the private half"),
        KeyState::PrivateOnly => std::fs::remove_file(&pub_path).expect("drop the public half"),
        KeyState::Whole | KeyState::Absent => {}
    }
    key_dir
}

/// Spawn `test` as a child with an isolated home and `key_dir` as its keys.
fn spawn_child(test: &str, run: &Path, key_dir: &Path, extra: &[(&str, &str)]) -> String {
    let home = run.join("home");
    let xdg = home.join(".config");
    let witness = home.join("witness");
    for d in [&home, &xdg, &witness] {
        std::fs::create_dir_all(d).expect("create the child home");
    }
    let (home_s, xdg_s, witness_s, keys_s) = (
        home.to_string_lossy().into_owned(),
        xdg.to_string_lossy().into_owned(),
        witness.to_string_lossy().into_owned(),
        key_dir.to_string_lossy().into_owned(),
    );
    let mut env: Vec<(&str, &str)> = vec![
        ("HOME", &home_s),
        ("XDG_CONFIG_HOME", &xdg_s),
        ("AI_MEMORY_WITNESS_KEY_DIR", &witness_s),
        ("AI_MEMORY_KEY_DIR", &keys_s),
    ];
    env.extend_from_slice(extra);
    let out = crate::test_support::spawn_test_child(&format!("{MODULE_PATH}::{test}"), &env);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let detail = format!(
        "status={:?}\nstdout={stdout}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "a K-7 child failed: {detail}");
    assert!(
        stdout.contains("1 passed"),
        "the child must have run exactly one test: {detail}"
    );
    assert!(
        stdout.contains(CHILD_OK_LINE),
        "the child must have reached its assertions: {detail}"
    );
    detail
}

/// The typed cause in an `anyhow` chain, found by downcast (never by text).
fn typed_in_chain(err: &anyhow::Error) -> Option<&DaemonKeyMissing> {
    err.chain()
        .find_map(|e| e.downcast_ref::<DaemonKeyMissing>())
}

fn expected_cause(spelling: &str) -> Option<DaemonKeyCause> {
    match spelling {
        EXPECT_PUBLIC_ONLY => Some(DaemonKeyCause::PublicOnly),
        EXPECT_PRIVATE_ONLY => Some(DaemonKeyCause::PrivateOnly),
        EXPECT_NONE => None,
        other => panic!("unknown expected cause {other:?}"),
    }
}

/// Assert `err` carries `want` as a downcastable source with its exact text.
fn assert_typed(err: &anyhow::Error, want: DaemonKeyCause) {
    let typed = typed_in_chain(err)
        .unwrap_or_else(|| panic!("no typed DaemonKeyMissing in the chain: {err:#}"));
    assert_eq!(typed.cause(), want, "{err:#}");
    assert!(
        typed
            .to_string()
            .starts_with(&format!("daemon key missing: {};", want.describe())),
        "{typed}"
    );
}

/// The child body of the boot-refusal table. `true` when this is a child.
fn run_boot_refusal_child() -> bool {
    let Some(expect) = std::env::var_os(CHILD_EXPECT_ENV) else {
        return false;
    };
    let want = expected_cause(&expect.to_string_lossy());
    for agent_id in AGENT_IDS {
        let got = DaemonChainSigner::ledger_writer_boot_refusal(agent_id);
        match (want, got) {
            (None, None) => {}
            (None, Some(err)) => panic!("{agent_id}: expected no refusal, got {err:#}"),
            (Some(cause), None) => panic!("{agent_id}: expected a {cause:?} refusal, got none"),
            (Some(cause), Some(err)) => {
                assert_typed(&err, cause);
                assert_eq!(
                    err.to_string(),
                    partial_daemon_key_boot_refusal(agent_id),
                    "the context names {agent_id}"
                );
            }
        }
    }
    println!("{CHILD_OK_LINE}");
    true
}

/// #10179 — every key state, under every agent id: a partial daemon key is
/// refused typed whatever the id; a whole or absent key is not refused.
#[test]
fn ledger_writer_boot_refusal_over_every_key_state_10179() {
    if run_boot_refusal_child() {
        return;
    }
    for state in KeyState::ALL {
        let run = run_dir(&format!("{state:?}"));
        let key_dir = plant(&run, state);
        spawn_child(
            "ledger_writer_boot_refusal_over_every_key_state_10179",
            &run,
            &key_dir,
            &[(CHILD_EXPECT_ENV, state.expected())],
        );
        remove_run_dir(&run);
    }
}

/// #10179 — the context text names the id and cites the issue.
#[test]
fn partial_daemon_key_boot_refusal_text_10179() {
    let text = partial_daemon_key_boot_refusal("agent-10179");
    assert!(
        text.starts_with("#10179: refusing to start a ledger-writing command as `agent-10179`:"),
        "{text}"
    );
    assert!(
        text.contains(&format!("`{DAEMON_KEYPAIR_LABEL}` key")),
        "{text}"
    );
}

/// The child body of the curator-store leg. `true` when this is a child.
#[cfg(feature = "sal")]
fn run_curator_store_child() -> bool {
    let Some(db_dir) = std::env::var_os(CHILD_DB_DIR_ENV) else {
        return false;
    };
    let db_dir = PathBuf::from(db_dir);
    let config = crate::config::AppConfig::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    // The `--db` arm (no store URL).
    let db_arm = db_dir.join("db-arm.db");
    let err = match runtime.block_on(crate::daemon_runtime::build_curator_store(
        None, &db_arm, &config,
    )) {
        Ok(_) => panic!("a public-only daemon key must refuse the --db open"),
        Err(e) => e,
    };
    assert_typed(&err, DaemonKeyCause::PublicOnly);
    assert!(!db_arm.exists(), "the refused --db open created no file");
    // The `sqlite://` arm.
    let url_arm = db_dir.join("url-arm.db");
    let url = format!("sqlite://{}", url_arm.display());
    let unused = db_dir.join("unused.db");
    let err = match runtime.block_on(crate::daemon_runtime::build_curator_store(
        Some(&url),
        &unused,
        &config,
    )) {
        Ok(_) => panic!("a public-only daemon key must refuse the sqlite:// open"),
        Err(e) => e,
    };
    assert_typed(&err, DaemonKeyCause::PublicOnly);
    assert!(
        !url_arm.exists(),
        "the refused sqlite:// open created no file"
    );
    assert!(
        !unused.exists(),
        "the --db path is not opened on the url arm"
    );
    println!("{CHILD_OK_LINE}");
    true
}

/// #10108 K-7 — both `build_store_handle` sqlite arms keep the typed cause.
#[cfg(feature = "sal")]
#[test]
fn curator_store_open_keeps_the_typed_refusal_10108() {
    if run_curator_store_child() {
        return;
    }
    let run = run_dir("curator");
    let key_dir = plant(&run, KeyState::PublicOnly);
    let db_dir = run.join("db");
    std::fs::create_dir_all(&db_dir).expect("create the db dir");
    spawn_child(
        "curator_store_open_keeps_the_typed_refusal_10108",
        &run,
        &key_dir,
        &[(CHILD_DB_DIR_ENV, &db_dir.to_string_lossy())],
    );
    remove_run_dir(&run);
}
