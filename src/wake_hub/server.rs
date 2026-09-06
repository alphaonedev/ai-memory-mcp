// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` listener and accept loop (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! [`WakeHub::bind`] performs every start-up refusal BEFORE a peer can connect:
//! the peer-credential probe, the `RLIMIT_NOFILE` budget, the socket-directory
//! posture, the `sun_path` length, and the 0600 mode. [`WakeHub::serve`] then
//! runs an accept loop that is bounded (a semaphore whose permit count IS the
//! connection ceiling), non-spinning (an `EMFILE` storm backs off instead of
//! busy-looping), and drainable (SIGTERM closes the listener and asks every
//! connection to flush and go).

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};

use super::codec::codec;
use super::frame::{ErrorCode, Frame, Kind, encode_error};
use super::limits::{DRAIN_DEADLINE_MS, DRAIN_POLL_MS, EgressBudget};
use super::metrics::{HubMetrics, MetricsSnapshot};
use super::startup::{
    FdBudget, assert_peer_credentials_available, configure_fd_limit, enforce_socket_mode,
    prepare_socket_path, read_peer_cred,
};
use super::{HubConfig, HubDeps, HubState, conn};

/// Longest `sun_path` any supported platform accepts, minus a NUL and a little
/// headroom. Linux allows 108 bytes and macOS 104; a path over the limit is
/// SILENTLY TRUNCATED by `bind(2)` on some libcs, which would leave the hub
/// listening somewhere other than where it told the operator it was. Refusing
/// is the only safe answer.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Grace period the accept loop waits for in-flight connections to drain after
/// a shutdown signal. #3471: sourced from [`super::limits::DRAIN_DEADLINE_MS`]
/// so the documented operator-facing bound and the code cannot drift.
const DRAIN_GRACE: Duration = Duration::from_millis(DRAIN_DEADLINE_MS);

/// How often the drain re-checks the connection gauge.
const DRAIN_POLL: Duration = Duration::from_millis(DRAIN_POLL_MS);

/// Back-off after an `accept` failure, so an fd exhaustion storm cannot become
/// a busy loop that starves the connections already served.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Identity of the socket file this process created: `(device, inode)`.
///
/// #3471 — the shutdown unlink uses it to prove the path still holds OUR
/// socket. Without it, a hub restarted while an old instance was still
/// draining would have the old instance delete the NEW instance's socket on
/// its way out, silently blackholing every agent on the host until someone
/// noticed. "Delete only what you created" is the same rule
/// [`super::startup::prepare_socket_path`] enforces at the other end.
///
/// **This identity is only sound because of the shutdown ORDERING, and the two
/// must be changed together.** ext4 and tmpfs hand a freed inode number
/// straight back out, so `(device, inode)` alone cannot tell our socket from a
/// replacement's that happened to be given the same number — APFS allocates
/// monotonically, which is the only reason that hazard is invisible on macOS.
/// What closes it is that [`WakeHub::serve`] compares and unlinks while the
/// listener is STILL OPEN, and a bound `AF_UNIX` listener holds a reference to
/// the inode it is bound to: that inode cannot be freed, so its number cannot
/// be recycled, for as long as we hold the listener — even after the directory
/// entry is unlinked. Drop the listener before the comparison and the identity
/// silently stops meaning anything.
///
/// Note that `fstat` on the listener's own descriptor is NOT the way to read
/// this: for `AF_UNIX` that returns the anonymous SOCKET object (a `sockfs`
/// inode, with no relation to the filesystem entry), never the path's inode.
/// The identity therefore comes from `lstat` on the path at bind time, and it
/// is the open listener — not the descriptor's own stat — that pins it.
type SocketIdent = (u64, u64);

/// A bound, not-yet-serving wake hub.
#[derive(Debug)]
pub struct WakeHub {
    listener: UnixListener,
    state: Arc<HubState>,
    socket_path: PathBuf,
    socket_ident: Option<SocketIdent>,
    fd_budget: FdBudget,
    permits: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
}

impl WakeHub {
    /// Perform every start-up assertion and bind the socket.
    ///
    /// # Errors
    ///
    /// Refuses to bind when the platform does not report peer credentials, when
    /// the fd budget cannot support a useful connection ceiling, when the
    /// socket path is over-long or occupied by something that is not a stale
    /// socket, when the parent directory is not owner-only, or when 0600 does
    /// not stick. Every one of these is a case where serving anyway would mean
    /// enforcing less than the hub advertises.
    ///
    /// Must be called from within a Tokio runtime context (it registers the
    /// listener with the reactor).
    pub fn bind(cfg: HubConfig, deps: HubDeps) -> Result<Self> {
        let probe = assert_peer_credentials_available()?;
        tracing::info!(
            uid = probe.uid,
            pid = ?probe.pid,
            "wake-hub: peer credentials (uid + pid) confirmed available on this platform"
        );

        let fd_budget = configure_fd_limit(cfg.max_connections)?;
        if fd_budget.clamped {
            tracing::warn!(
                configured = cfg.max_connections,
                ceiling = fd_budget.connection_ceiling,
                soft = fd_budget.soft,
                "wake-hub: connection ceiling LOWERED to fit RLIMIT_NOFILE"
            );
        }

        let socket_path = cfg.socket_path.clone();
        check_socket_path_length(&socket_path)?;
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("wake-hub: could not bind {}", socket_path.display()))?;
        enforce_socket_mode(&socket_path)?;
        // #3471 — remember WHICH socket file we created, so the shutdown
        // unlinks only this one. Captured AFTER `enforce_socket_mode` so it
        // describes the file in its final state. Best-effort: a platform that
        // cannot report dev/ino degrades to the "it is still a socket" test,
        // never to deleting a file we cannot identify.
        let socket_ident = socket_ident_of(&socket_path);

        let permits = Arc::new(Semaphore::new(fd_budget.connection_ceiling));
        let (shutdown, _) = watch::channel(false);
        let state = Arc::new(HubState::new(cfg, deps));
        tracing::info!(
            socket = %socket_path.display(),
            ceiling = fd_budget.connection_ceiling,
            soft_nofile = fd_budget.soft,
            hard_nofile = fd_budget.hard,
            desired_nofile = fd_budget.desired,
            drain_deadline_ms = DRAIN_DEADLINE_MS,
            "wake-hub: listening"
        );
        Ok(Self {
            listener,
            state,
            socket_path,
            socket_ident,
            fd_budget,
            permits,
            shutdown,
        })
    }

    /// Where the hub is listening.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The fd budget actually in force.
    #[must_use]
    pub const fn fd_budget(&self) -> FdBudget {
        self.fd_budget
    }

    /// Live counters. Obtainable BEFORE [`Self::serve`] consumes the hub, so a
    /// test or an ops probe can watch a running hub.
    #[must_use]
    pub fn metrics(&self) -> Arc<HubMetrics> {
        Arc::clone(&self.state.metrics)
    }

    /// Snapshot every counter, including the hub-wide egress reservation.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.state.snapshot()
    }

    /// The routing table, shared. Obtainable BEFORE [`Self::serve`] consumes
    /// the hub — the same lifetime story as [`Self::metrics`] — so a co-hosted
    /// daemon can install the #3469 in-process wake sink against a hub it is
    /// about to move into a `serve` task.
    #[must_use]
    pub fn router(&self) -> Arc<super::routing::Router> {
        self.state.router()
    }

    /// The hub-wide egress budget. Obtainable BEFORE [`Self::serve`] consumes
    /// the hub, so an ops probe or a scale test can assert the byte cap is
    /// holding while the hub runs.
    #[must_use]
    pub fn egress_budget(&self) -> Arc<EgressBudget> {
        Arc::clone(self.state.router.egress())
    }

    /// Run the accept loop until `shutdown` resolves, then drain.
    ///
    /// # Errors
    ///
    /// Only for a listener failure that is not recoverable by backing off.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> Result<()> {
        let Self {
            listener,
            state,
            socket_path,
            socket_ident,
            permits,
            shutdown: shutdown_tx,
            ..
        } = self;
        let signal = std::pin::pin!(shutdown);
        accept_loop(&listener, &state, &permits, &shutdown_tx, signal).await;
        // STOP ACCEPTING BY UNLINKING THE PATH — WHILE THE LISTENER IS STILL
        // OPEN (#3471). Two things fall out of that one ordering choice:
        //
        // * It is the cleanest "stop accepting" AF_UNIX offers. A peer that
        //   arrives mid-shutdown fails at the PATH (ENOENT) instead of being
        //   accepted into a hub that is about to stop reading it, while every
        //   already-accepted connection keeps draining on the still-open
        //   listener — an established AF_UNIX connection does not depend on the
        //   path that introduced it.
        // * It is what makes the ownership check SOUND. A bound AF_UNIX
        //   listener holds a reference to the inode it is bound to, so that
        //   inode cannot be freed — and therefore cannot have its number
        //   recycled onto a REPLACEMENT's socket — for as long as we hold the
        //   listener. Compare after dropping it and `(dev, ino)` stops meaning
        //   anything on any filesystem that reuses inode numbers. See
        //   [`SocketIdent`].
        remove_own_socket(&socket_path, socket_ident);
        drain(&state, &socket_path, &shutdown_tx).await;
        // The listener is dropped LAST: it is what pins our inode, and it is
        // what the still-draining sessions were accepted on.
        drop(listener);
        Ok(())
    }
}

/// The bounded SIGTERM / SIGINT drain (#3471).
///
/// Three steps, in this order and no other — the unlink that used to be step
/// four now runs BEFORE this function, while the listener is still open:
///
/// 1. **Stop accepting.** The caller UNLINKS THE SOCKET PATH before calling
///    this, while still holding the listener open, so no peer can join a hub
///    that is on its way out (a fresh connect fails at the path) and every
///    already-accepted session keeps draining. The listener itself is dropped
///    by the caller AFTER this returns. See [`WakeHub::serve`].
/// 2. **Ask every session to go.** The shutdown watch wakes each reader and
///    [`super::routing::Router::request_close_all`] enqueues the writers'
///    `Close` sentinel. NOTHING content-bearing is emitted: there is no
///    goodbye frame, no flush of hub-authored state, no last wake. The hub
///    holds no durable truth, so there is nothing it could owe a peer at
///    shutdown; the already-committed inbox row and the `<=60 s` backstop poll
///    are the guarantee, exactly as they are at every other moment.
/// 3. **Wait, bounded.** At most [`DRAIN_DEADLINE_MS`] for the connection gauge
///    to reach zero. An unbounded wait is a hung `systemctl stop` that ends in
///    `SIGKILL` — strictly worse, because the socket then survives us. The
///    unlink has already happened by then, so even a `SIGKILL` here leaves no
///    stale socket behind.
///
/// Always completes; the caller then exits 0. A drain that timed out is a WARN
/// with the residual count, not a failure exit: the connections it was waiting
/// on are peers that stopped reading, which is their fault to fix and not a
/// reason to tell a supervisor the hub crashed.
async fn drain(state: &Arc<HubState>, socket_path: &Path, shutdown_tx: &watch::Sender<bool>) {
    let _ = shutdown_tx.send(true);
    let asked = state.router().request_close_all();
    tracing::info!(
        sessions = asked,
        deadline_ms = DRAIN_DEADLINE_MS,
        "wake-hub: draining — no new connections, no content emitted"
    );

    let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
    while state.metrics.connections_current() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(DRAIN_POLL).await;
    }
    let residual = state.metrics.connections_current();
    if residual > 0 {
        tracing::warn!(
            residual,
            deadline_ms = DRAIN_DEADLINE_MS,
            "wake-hub: drain deadline reached with connections still open; exiting anyway \
             (a peer that stopped reading must not be able to hold the hub open forever)"
        );
    }
    tracing::info!(socket = %socket_path.display(), residual, "wake-hub: stopped");
}

/// The accept loop proper.
async fn accept_loop(
    listener: &UnixListener,
    state: &Arc<HubState>,
    permits: &Arc<Semaphore>,
    shutdown_tx: &watch::Sender<bool>,
    mut signal: std::pin::Pin<&mut impl Future<Output = ()>>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = signal.as_mut() => return,
            res = listener.accept() => res,
        };
        let stream = match accepted {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                // Never spin. An fd-exhaustion storm that busy-loops here would
                // starve the connections the hub is already serving.
                tracing::warn!(error = %e, "wake-hub: accept failed; backing off");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        state.metrics.accepted();

        // ORDER IS THE CONTROL (#3468 carry-over from the #3467 review):
        // credentials -> authorize -> permit. An unauthorized peer must be
        // dropped before it can consume a connection permit AND before the hub
        // writes it a single byte. The previous order acquired the permit
        // first, so at the ceiling a wrong-uid peer received a `507` — a reply
        // that tells an unauthorized caller the hub exists and is saturated.
        // The 0600 socket already prevents this peer from connecting at all;
        // this is the defense-in-depth layer behind it.
        let cred = match read_peer_cred(stream.as_raw_fd()) {
            Ok(cred) => cred,
            Err(e) => {
                state.metrics.denied_peer_cred();
                tracing::warn!(error = %e, "wake-hub: could not read peer credentials; refusing");
                continue;
            }
        };
        if let Err(deny) = state.deps.peer_authorizer.authorize(cred) {
            // Dropped in silence: no permit taken, no frame written, nothing
            // read. The peer learns only that the connection closed.
            state.metrics.denied_peer_cred();
            tracing::warn!(
                peer_uid = cred.uid,
                peer_pid = ?cred.pid,
                reason = deny.label(),
                "wake-hub: peer DENIED — {deny}"
            );
            drop(stream);
            continue;
        }

        // Only an AUTHORIZED peer is told the hub is at its ceiling, and only
        // an authorized peer can occupy a permit.
        let Ok(permit) = Arc::clone(permits).try_acquire_owned() else {
            state.metrics.denied_ceiling();
            tracing::warn!("wake-hub: at the connection ceiling; refusing a peer");
            reject(stream, ErrorCode::Overflow, "hub at its connection ceiling").await;
            continue;
        };

        let task_state = Arc::clone(state);
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            conn::run(task_state, stream, cred, rx).await;
            drop(permit);
        });
    }
}

/// Best-effort: tell a refused peer why, then drop the connection.
///
/// Bounded by a short timeout so a peer that never reads cannot pin an accept
/// slot by refusing to drain its receive buffer.
async fn reject(mut stream: UnixStream, code: ErrorCode, reason: &str) {
    use tokio::io::AsyncWriteExt;
    use tokio_util::codec::Encoder;

    let Ok(body) = Frame::new(
        Kind::Error,
        String::new(),
        String::new(),
        encode_error(code, reason),
    )
    .encode() else {
        return;
    };
    let mut out = bytes::BytesMut::new();
    if codec().encode(body, &mut out).is_err() {
        return;
    }
    let write = async {
        let _ = stream.write_all(&out).await;
        let _ = stream.shutdown().await;
    };
    let _ = tokio::time::timeout(ACCEPT_BACKOFF, write).await;
}

/// Refuse a `sun_path` the kernel would silently truncate.
fn check_socket_path_length(path: &Path) -> Result<()> {
    let len = path.as_os_str().as_encoded_bytes().len();
    if len > MAX_SOCKET_PATH_BYTES {
        bail!(
            "wake-hub: socket path is {len} bytes, over the {MAX_SOCKET_PATH_BYTES}-byte \
             limit (AF_UNIX sun_path is 108 bytes on Linux and 104 on macOS, and an \
             over-long path is silently TRUNCATED by bind(2) — the hub would end up \
             listening somewhere other than where it reported). Choose a shorter path: {}",
            path.display()
        );
    }
    Ok(())
}

/// `(device, inode)` of the file at `path`, or `None` when it cannot be
/// stat'ed.
fn socket_ident_of(path: &Path) -> Option<SocketIdent> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Unlink our own socket on the way out — and ONLY ours.
///
/// Two conditions, both required (#3471):
///
/// * the path must still `stat` as a SOCKET (a regular file at the path means
///   something else took it over and an operator's file must never be deleted
///   by a shutdown path), and
/// * its `(device, inode)` must still match `ident`, and callers MUST still be
///   holding the listener that pins that inode — see [`SocketIdent`], where the
///   ordering dependency is spelled out.
///
/// The inode check is the one that matters at restart. Without it, a hub that
/// is slow to drain while its replacement has already bound a fresh socket at
/// the same path would delete the REPLACEMENT's socket on the way out. Every
/// agent on the host would then be talking to a live process through a path
/// that no longer exists, and the fault would present as "wakes stopped" long
/// after the restart that caused it. Fail closed: when the identity cannot be
/// established, leave the file alone — a leftover stale socket is cleaned up by
/// the next [`super::startup::prepare_socket_path`], which probes it before
/// unlinking. A leftover costs one refusal at the next start; a wrong unlink
/// costs the whole wake plane.
fn remove_own_socket(path: &Path, ident: Option<SocketIdent>) {
    use std::os::unix::fs::FileTypeExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.file_type().is_socket() {
        tracing::warn!(
            socket = %path.display(),
            "wake-hub: the socket path no longer holds a socket; leaving it in place"
        );
        return;
    }
    match (ident, socket_ident_of(path)) {
        (Some(created), Some(current)) if created == current => {
            let _ = std::fs::remove_file(path);
        }
        (Some(_), Some(_)) => {
            tracing::warn!(
                socket = %path.display(),
                "wake-hub: the socket at this path is NOT the one this process created \
                 (another hub has taken it over); leaving it in place"
            );
        }
        _ => {
            tracing::warn!(
                socket = %path.display(),
                "wake-hub: could not establish socket ownership; leaving it in place for \
                 the next start-up probe to clear"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_over_long_socket_path_is_refused_rather_than_truncated() {
        let long = PathBuf::from(format!("/tmp/{}/s.sock", "d".repeat(MAX_SOCKET_PATH_BYTES)));
        let err = check_socket_path_length(&long).expect_err("must refuse");
        assert!(
            format!("{err}").contains("silently TRUNCATED"),
            "unexpected: {err}"
        );
        assert!(check_socket_path_length(Path::new("/tmp/a/s.sock")).is_ok());
    }

    /// #3471 — the drain unlinks the socket IT created, in the order the hub
    /// actually uses: identity from the LIVE listener, unlink, listener dropped
    /// last.
    #[test]
    fn the_drain_unlinks_the_socket_this_process_created() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("own.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let ident = socket_ident_of(&path);
        assert!(ident.is_some(), "a bound socket must be stat-able");
        remove_own_socket(&path, ident);
        assert!(!path.exists(), "our own socket must be cleaned up");
        drop(listener);
    }

    /// #3471 — a REPLACEMENT hub's socket at the same path is never deleted by
    /// a straggling predecessor's drain, on ANY filesystem. This is the
    /// restart-race that would otherwise blackhole every agent on the host.
    ///
    /// The race is constructed EXPLICITLY and the assertion is on the guard's
    /// DECISION, not on inode arithmetic: the predecessor still holds its
    /// listener open (as it does while it is draining) when the replacement
    /// takes the path over. That is the ordering the hub now uses, and it is
    /// what makes the identity sound — so this test also pins the ORDERING,
    /// not just the comparison.
    ///
    /// The pre-amendment version asserted that two successive binds produce
    /// different inodes. That is true on APFS, which allocates monotonically,
    /// and FALSE on ext4 and tmpfs, which reuse a freed inode number
    /// immediately — so on Linux the test failed its own precondition while the
    /// product hazard it existed to pin went unchecked, and the product itself
    /// was unsound there for the same reason.
    #[test]
    fn a_replacement_socket_at_the_same_path_is_never_unlinked() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("race.sock");

        // The predecessor binds and KEEPS its listener open.
        let first = std::os::unix::net::UnixListener::bind(&path).expect("bind first");
        let first_ident = socket_ident_of(&path);
        assert!(first_ident.is_some(), "a live listener must be stat-able");

        // The replacement takes the path over while the predecessor is still up.
        std::fs::remove_file(&path).expect("clear");
        let _second = std::os::unix::net::UnixListener::bind(&path).expect("bind second");

        // The predecessor now runs its removal path.
        remove_own_socket(&path, first_ident);
        assert!(
            path.exists(),
            "the predecessor's drain must not delete the replacement's socket"
        );
        // It refused for the RIGHT reason, and this holds on every filesystem:
        // the predecessor's LISTENER is still open and a bound AF_UNIX socket
        // holds a reference to its inode, so that inode cannot have been freed
        // — and therefore cannot have been recycled onto the replacement —
        // even though the directory entry was unlinked. Drop `first` before
        // this point and ext4/tmpfs will hand the same number straight back.
        assert_ne!(
            first_ident,
            socket_ident_of(&path),
            "a held descriptor pins its inode, so the replacement's socket is \
             necessarily a different file"
        );
        drop(first);
    }

    /// #3471 — a regular file at the socket path is never deleted, even if the
    /// stored identity happens to match.
    #[test]
    fn a_regular_file_at_the_socket_path_is_never_unlinked() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("precious.db");
        std::fs::write(&path, b"durable truth").expect("write");
        let ident = socket_ident_of(&path);
        remove_own_socket(&path, ident);
        assert_eq!(
            std::fs::read(&path).expect("still there"),
            b"durable truth",
            "a shutdown path must never delete an operator's file"
        );
    }

    /// #3471 — with no recorded identity the drain leaves the file for the next
    /// start-up probe rather than guessing.
    #[test]
    fn an_unidentified_socket_is_left_for_the_start_up_probe() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("unknown.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        remove_own_socket(&path, None);
        assert!(path.exists(), "fail closed: leave what we cannot identify");
    }

    /// #3471 — the drain deadline is bounded and sits under both supervisors'
    /// default stop timeouts (systemd 90 s, launchd 20 s).
    #[test]
    fn the_drain_deadline_is_bounded_and_under_both_supervisor_defaults() {
        assert!(DRAIN_GRACE > Duration::ZERO);
        assert!(
            DRAIN_GRACE < Duration::from_secs(20),
            "a drain longer than launchd's SIGTERM grace ends in SIGKILL"
        );
        assert!(DRAIN_POLL < DRAIN_GRACE);
    }
}
