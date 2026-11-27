// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 K-4 — the daemon key provision holds across processes. Each test
//! re-runs this lib test binary as children (the sandboxed
//! [`crate::test_support::spawn_test_child`], a clean environment with its own
//! HOME, XDG config and witness key directory under `.local-runs`), so the
//! processes really are separate and only an OS-level lock can serialise them.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::DaemonChainSigner;
use crate::identity::keypair::{DAEMON_KEYPAIR_LABEL, agent_priv_path, agent_pub_path};

const MODULE_PATH: &str = "governance::daemon_signer::k4_tests";
/// The child role: the key directory it provisions.
const CHILD_KEY_DIR_ENV: &str = "AI_MEMORY_TEST_K4_KEY_DIR";
/// The child role: the barrier directory (`ready-<n>` written, `go` awaited).
const CHILD_BARRIER_ENV: &str = "AI_MEMORY_TEST_K4_BARRIER";
/// The child role: its index, for its ready marker.
const CHILD_INDEX_ENV: &str = "AI_MEMORY_TEST_K4_INDEX";
/// The line a child prints with the public half it provisioned.
const PUB_LINE_PREFIX: &str = "K4-PUB=";
/// The line a child prints when provision refused.
const REFUSED_LINE_PREFIX: &str = "K4-REFUSED=";
/// Children per round, and rounds, of the race test.
const RACE_CHILDREN: usize = 8;
const RACE_ROUNDS: usize = 4;
/// Every wait in these tests has a deadline (no unbounded wait).
const WAIT_DEADLINE: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(1);
/// The lock file name the fix places at the key-directory root.
const LOCK_FILE: &str = crate::identity::keypair::KEY_DIR_LOCK_FILE;
/// How long the held-lock test watches for a write it must not see.
const HELD_WINDOW: Duration = Duration::from_millis(750);

/// A fresh run directory under `<repo>/.local-runs/k4-10108/`.
fn run_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("k4-10108")
        .join(format!("{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the K-4 run dir");
    dir
}

/// Remove a run directory; refuses anything outside `.local-runs/k4-10108`.
fn remove_run_dir(dir: &Path) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("k4-10108");
    assert!(
        dir.starts_with(&root),
        "refusing to remove {}",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Wait until `cond` holds, or panic at the deadline.
fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT_DEADLINE;
    while !cond() {
        assert!(
            Instant::now() < deadline,
            "deadline passed waiting for {what}"
        );
        std::thread::sleep(POLL);
    }
}

/// Spawn one provision child against `key_dir` with an isolated home.
fn spawn_provision_child(
    test: &str,
    run: &Path,
    key_dir: &Path,
    barrier: &Path,
    index: usize,
) -> std::process::Output {
    let home = run.join(format!("home-{index}"));
    let xdg = home.join(".config");
    let witness = home.join("witness");
    for d in [&home, &xdg, &witness] {
        std::fs::create_dir_all(d).expect("create the child home");
    }
    let index = index.to_string();
    crate::test_support::spawn_test_child(
        &format!("{MODULE_PATH}::{test}"),
        &[
            ("HOME", &home.to_string_lossy()),
            ("XDG_CONFIG_HOME", &xdg.to_string_lossy()),
            ("AI_MEMORY_WITNESS_KEY_DIR", &witness.to_string_lossy()),
            ("AI_MEMORY_KEY_DIR", &key_dir.to_string_lossy()),
            (CHILD_KEY_DIR_ENV, &key_dir.to_string_lossy()),
            (CHILD_BARRIER_ENV, &barrier.to_string_lossy()),
            (CHILD_INDEX_ENV, &index),
        ],
    )
}

/// The child body: mark ready, wait for `go`, provision, print the result.
/// Returns `true` when this process is a child (the caller returns).
fn run_provision_child() -> bool {
    let (Some(key_dir), Some(barrier), Some(index)) = (
        std::env::var_os(CHILD_KEY_DIR_ENV),
        std::env::var_os(CHILD_BARRIER_ENV),
        std::env::var_os(CHILD_INDEX_ENV),
    ) else {
        return false;
    };
    let barrier = PathBuf::from(barrier);
    let index = index.to_string_lossy().into_owned();
    std::fs::write(barrier.join(format!("ready-{index}")), b"").expect("write ready");
    wait_for("the go marker", || barrier.join("go").exists());
    match DaemonChainSigner::provision(Path::new(&key_dir)) {
        Ok(signer) => println!(
            "{PUB_LINE_PREFIX}{}",
            hex::encode(signer.verifying_key().to_bytes())
        ),
        Err(e) => println!("{REFUSED_LINE_PREFIX}{:?}", e.cause()),
    }
    true
}

/// The `K4-PUB=` or `K4-REFUSED=` line of one child, with its full output.
fn child_result(out: &std::process::Output) -> (Option<String>, String) {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let detail = format!(
        "status={:?}\nstdout={stdout}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "a provision child failed: {detail}");
    assert!(
        stdout.contains("1 passed"),
        "the child must have run exactly one test: {detail}"
    );
    // The harness may print `test <name> ... ` on the same line, before the
    // child's own output, so the marker is found anywhere in a line.
    let line = stdout.lines().find_map(|l| {
        [PUB_LINE_PREFIX, REFUSED_LINE_PREFIX]
            .iter()
            .find_map(|prefix| l.find(prefix).map(|at| l[at..].trim_end().to_owned()))
    });
    (line, detail)
}

/// The public half on disk, hex.
fn disk_pub_hex(key_dir: &Path) -> String {
    let kp = crate::identity::keypair::load(DAEMON_KEYPAIR_LABEL, key_dir).expect("load the key");
    assert!(
        kp.private.is_some(),
        "the key on disk must have both halves"
    );
    hex::encode(kp.public.to_bytes())
}

/// Key files (`*.pub`, `*.priv`) in `key_dir`.
fn key_files(key_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(key_dir)
        .expect("list the key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|x| x == "pub" || x == "priv")
        })
        .collect();
    names.sort();
    names
}

/// N processes start against one empty key directory at the same instant:
/// every one provisions successfully, all of them hold the same public half,
/// it is the one on disk, and the directory holds exactly one key pair.
#[cfg(unix)]
#[test]
fn n_processes_provision_one_daemon_key_10108() {
    const TEST: &str = "n_processes_provision_one_daemon_key_10108";
    if run_provision_child() {
        return;
    }
    let run = run_dir("race");
    for round in 0..RACE_ROUNDS {
        let key_dir = run.join(format!("keys-{round}"));
        let barrier = run.join(format!("barrier-{round}"));
        std::fs::create_dir_all(&barrier).expect("create the barrier");
        let outputs: Vec<std::process::Output> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..RACE_CHILDREN)
                .map(|i| {
                    let (run, key_dir, barrier) = (&run, &key_dir, &barrier);
                    s.spawn(move || spawn_provision_child(TEST, run, key_dir, barrier, i))
                })
                .collect();
            wait_for("every child ready", || {
                (0..RACE_CHILDREN).all(|i| barrier.join(format!("ready-{i}")).exists())
            });
            std::fs::write(barrier.join("go"), b"").expect("write go");
            handles
                .into_iter()
                .map(|h| h.join().expect("join a child thread"))
                .collect()
        });
        let disk = disk_pub_hex(&key_dir);
        for out in &outputs {
            let (line, detail) = child_result(out);
            assert_eq!(
                line.as_deref(),
                Some(format!("{PUB_LINE_PREFIX}{disk}").as_str()),
                "round {round}: every process provisions the one key on disk: {detail}"
            );
        }
        assert_eq!(
            key_files(&key_dir),
            vec![
                format!("{DAEMON_KEYPAIR_LABEL}.priv"),
                format!("{DAEMON_KEYPAIR_LABEL}.pub")
            ],
            "round {round}: exactly one key pair"
        );
    }
    remove_run_dir(&run);
}

/// While another process holds the key-directory lock, provision writes no
/// key file; once the lock is released it completes with the key it wrote.
#[cfg(unix)]
#[test]
fn provision_waits_for_the_key_dir_lock_10108() {
    const TEST: &str = "provision_waits_for_the_key_dir_lock_10108";
    if run_provision_child() {
        return;
    }
    let run = run_dir("held");
    let key_dir = run.join("keys");
    let barrier = run.join("barrier");
    std::fs::create_dir_all(&barrier).expect("create the barrier");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&key_dir)
            .expect("create the key dir");
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(key_dir.join(LOCK_FILE))
        .expect("open the lock file");
    lock.lock().expect("hold the key-dir lock");
    let out = std::thread::scope(|s| {
        let child = s.spawn(|| spawn_provision_child(TEST, &run, &key_dir, &barrier, 0));
        wait_for("the child ready", || barrier.join("ready-0").exists());
        std::fs::write(barrier.join("go"), b"").expect("write go");
        std::thread::sleep(HELD_WINDOW);
        assert_eq!(
            key_files(&key_dir),
            Vec::<String>::new(),
            "no key file may be written while another process holds the lock"
        );
        assert!(!child.is_finished(), "provision must wait for the lock");
        drop(lock);
        child.join().expect("join the child thread")
    });
    let (line, detail) = child_result(&out);
    assert_eq!(
        line.as_deref(),
        Some(format!("{PUB_LINE_PREFIX}{}", disk_pub_hex(&key_dir)).as_str()),
        "after the lock is released the child provisions the key on disk: {detail}"
    );
    remove_run_dir(&run);
}

/// A lock that cannot be taken refuses with its typed cause; no key file is
/// written and the process never proceeds unlocked.
#[cfg(unix)]
#[test]
fn an_unlockable_key_dir_refuses_typed_10108() {
    let run = run_dir("unlockable");
    let key_dir = run.join("keys");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&key_dir)
            .expect("create the key dir");
    }
    // A directory where the lock file goes: it can never be opened as a file.
    std::fs::create_dir(key_dir.join(LOCK_FILE)).expect("plant the blocker");
    let err = DaemonChainSigner::provision(&key_dir).expect_err("an unlockable dir must refuse");
    assert_eq!(err.cause(), super::DaemonKeyCause::KeyDirLockUnavailable);
    assert!(
        err.to_string()
            .contains("the key directory lock could not be taken"),
        "exact refusal text: {err}"
    );
    assert!(!agent_pub_path(&key_dir, DAEMON_KEYPAIR_LABEL).exists());
    assert!(!agent_priv_path(&key_dir, DAEMON_KEYPAIR_LABEL).exists());
    remove_run_dir(&run);
}
