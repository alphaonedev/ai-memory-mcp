// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4057 — the wake-hub stale-socket probe must be BOUNDED.
//!
//! Pre-fix, `prepare_socket_path` probed with a BLOCKING
//! `UnixStream::connect`. On Linux a blocking `AF_UNIX` connect to a live
//! listener whose accept queue is FULL sleeps in `unix_wait_for_peer` until
//! queue space appears — for a wedged or paused hub, forever — and the probe
//! runs inside `WakeHub::bind`, before any serve loop or shutdown future
//! exists. These tests run the PRODUCTION probe on a watchdog thread, so the
//! pre-fix build fails by timeout instead of hanging the suite.
//!
//! Controls: a live, not-full listener is refused; a genuinely stale socket is
//! unlinked (the one definite-stale outcome, `ECONNREFUSED`).
//!
//! The backlog is filled with this file's OWN non-blocking connects (raw
//! `libc`, the precedent is `tests/serve_integration.rs`'s `libc::kill`), so
//! the cell compiles and runs RED against a base that has no non-blocking
//! connect helper of its own.
#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::wake_hub::startup::prepare_socket_path;

/// Longest the probe may take. The fixed probe answers in microseconds; this
/// only has to be comfortably longer than that and far shorter than "hung".
const WATCHDOG: Duration = Duration::from_secs(10);

/// A queue filled by a listener bound with an explicit backlog of 1 holds a
/// handful of connections; far below any `RLIMIT_NOFILE` in use (#6323).
const BACKLOG_BOUND: usize = 64;

/// More connects than any listen backlog the kernel will grant an
/// unprivileged listener (`somaxconn` defaults to 4096 on modern kernels).
const BACKLOG_FILL_CEILING: usize = 8192;

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

/// A `sockaddr_un` for `path`, plus the number of its bytes in use.
fn unix_sockaddr(path: &Path) -> (libc::sockaddr_un, libc::socklen_t) {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is a plain C struct; all-zero bytes is a valid
    // value for every field.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits");
    assert!(
        bytes.len() < addr.sun_path.len(),
        "test socket path too long for sun_path"
    );
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = libc::c_char::from_ne_bytes([*src]);
    }
    let used = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    (addr, libc::socklen_t::try_from(used).expect("socklen"))
}

/// One NON-blocking `AF_UNIX` connect: it can never sleep on a full queue.
fn nonblocking_connect(path: &Path) -> io::Result<UnixStream> {
    let (addr, len) = unix_sockaddr(path);
    // SAFETY: a plain syscall with constant arguments; the descriptor it
    // returns is checked and then owned by `OwnedFd`, which closes it.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created descriptor nothing else owns.
    let stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    stream.set_nonblocking(true)?;
    // SAFETY: `addr` is fully initialised and outlives the call; `len` is the
    // number of its bytes in use.
    let rc = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            len,
        )
    };
    if rc == 0 {
        Ok(stream)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A listener that never accepts, so its queue can be filled.
fn listener(path: &Path) -> UnixListener {
    UnixListener::bind(path).expect("bind")
}

/// Fill `path`'s accept queue with non-blocking connects until the kernel
/// answers EAGAIN, and keep the connections open so it stays full.
fn fill_backlog(path: &Path) -> Vec<UnixStream> {
    let mut held = Vec::new();
    for _ in 0..BACKLOG_FILL_CEILING {
        match nonblocking_connect(path) {
            Ok(c) => held.push(c),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return held,
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
    let held = fill_backlog(&path);
    assert!(!held.is_empty(), "at least one connect must have queued");
    // #6323: the cell must not depend on the host fd limit or somaxconn.
    assert!(
        held.len() < BACKLOG_BOUND,
        "the listener must use a small explicit backlog, held {}",
        held.len()
    );
    let inode = std::fs::symlink_metadata(&path).expect("stat").ino();

    let err = probe_with_watchdog(&path).expect_err("a live listener must never be taken over");
    let msg = format!("{err:#}");
    // #6324: `fill_backlog` returns only after EAGAIN, so the probe MUST map a
    // full queue to `SocketLiveness::Busy` and say so; "already listening"
    // would mean the probe connected, i.e. the queue was not actually full.
    assert!(
        msg.contains("accept queue is FULL"),
        "the refusal must name the FULL accept queue (Busy mapping): {msg}"
    );
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .expect("socket preserved")
            .ino(),
        inode,
        "the live listener's socket inode must be preserved"
    );
    drop(held);
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
