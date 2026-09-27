// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4057 — the wake-hub stale-socket probe must be BOUNDED.
//!
//! Pre-fix, `prepare_socket_path` probed with a BLOCKING
//! `UnixStream::connect`. On Linux a blocking `AF_UNIX` connect to a live
//! listener whose accept queue is FULL sleeps until queue space appears — for
//! a wedged or paused hub, forever — and the probe runs inside
//! `WakeHub::bind`, before any serve loop or shutdown future exists. These
//! tests run the PRODUCTION probe on a watchdog thread, so the pre-fix build
//! fails by timeout instead of hanging the suite.
//!
//! Controls: a live, not-full listener is refused; a genuinely stale socket is
//! unlinked (the one definite-stale outcome, `ECONNREFUSED`).
#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::wake_hub::startup::prepare_socket_path;
use socket2::{Domain, SockAddr, Socket, Type};

/// Longest the probe may take. The fixed probe answers in microseconds; this
/// only has to be comfortably longer than that and far shorter than "hung".
const WATCHDOG: Duration = Duration::from_secs(10);

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700");
    dir
}

/// Run the production probe off-thread and wait at most [`WATCHDOG`].
fn probe_with_watchdog(path: &Path) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let owned: PathBuf = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(prepare_socket_path(&owned));
    });
    rx.recv_timeout(WATCHDOG).unwrap_or_else(|_| {
        panic!(
            "#4057: prepare_socket_path did not return within {WATCHDOG:?} — the \
             stale-socket probe is blocking on a live listener's full accept queue"
        )
    })
}

/// A listener with the smallest possible backlog, never accepting.
fn listener(path: &Path) -> Socket {
    let sock = Socket::new(Domain::UNIX, Type::STREAM, None).expect("socket");
    sock.bind(&SockAddr::unix(path).expect("addr"))
        .expect("bind");
    sock.listen(0).expect("listen");
    sock
}

/// Fill `path`'s accept queue with non-blocking connects until the kernel
/// answers EAGAIN, and keep the connections open so it stays full.
fn fill_backlog(path: &Path) -> Vec<Socket> {
    let mut held = Vec::new();
    for _ in 0..4096 {
        let c = Socket::new(Domain::UNIX, Type::STREAM, None).expect("socket");
        c.set_nonblocking(true).expect("nonblocking");
        match c.connect(&SockAddr::unix(path).expect("addr")) {
            Ok(()) => held.push(c),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return held,
            Err(e) => panic!("unexpected connect error while filling the backlog: {e}"),
        }
    }
    panic!("the accept queue never filled");
}

#[test]
fn a_full_backlog_listener_is_refused_promptly_and_its_socket_kept_4057() {
    let dir = private_dir();
    let path = dir.path().join("hub.sock");
    let _live = listener(&path);
    let _held = fill_backlog(&path);
    let inode = std::fs::symlink_metadata(&path).expect("stat").ino();

    let err = probe_with_watchdog(&path).expect_err("a live listener must never be taken over");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("accept queue is FULL") || msg.contains("already listening"),
        "the refusal must say the socket is live: {msg}"
    );
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .expect("socket preserved")
            .ino(),
        inode,
        "the live listener's socket inode must be preserved"
    );
}

#[test]
fn a_live_listener_with_room_is_refused_4057() {
    let dir = private_dir();
    let path = dir.path().join("hub.sock");
    let live = listener(&path);
    let err = probe_with_watchdog(&path).expect_err("live");
    assert!(format!("{err:#}").contains("already listening"), "{err:#}");
    assert!(path.exists(), "a live socket is never unlinked");
    drop(live);
}

#[test]
fn a_genuinely_stale_socket_is_unlinked_4057() {
    let dir = private_dir();
    let path = dir.path().join("hub.sock");
    drop(listener(&path)); // closed: the path is now a stale socket inode
    assert!(path.exists(), "the stale inode is still on disk");
    probe_with_watchdog(&path).expect("a definitely-stale socket is cleared");
    assert!(
        !path.exists(),
        "the stale socket must be unlinked so bind can proceed"
    );
}
