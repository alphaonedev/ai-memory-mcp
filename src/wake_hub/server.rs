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
/// #3471 — captured immediately after `bind` so the shutdown unlink can prove
/// the path still holds OUR socket. Without it, a hub restarted while an old
/// instance was still draining would have the old instance delete the NEW
/// instance's socket on its way out, silently blackholing every agent on the
/// host until someone noticed. "Delete only what you created" is the same rule
/// [`super::startup::prepare_socket_path`] enforces at the other end.
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
        // #3471 — remember WHICH socket file we created, so the drain unlinks
        // only this one. Best-effort: a platform that cannot report dev/ino
        // degrades to the pre-#3471 "it is still a socket" test, never to
        // deleting a file we cannot identify.
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
        // STOP ACCEPTING FIRST. Closing the listener before anything else is
        // what makes the drain honest: a peer that arrives mid-shutdown is
        // refused by the kernel rather than accepted into a hub that is about
        // to stop reading it.
        drop(listener);
        drain(&state, &socket_path, socket_ident, &shutdown_tx).await;
        Ok(())
    }
}

/// The bounded SIGTERM / SIGINT drain (#3471).
///
/// Four steps, in this order and no other:
///
/// 1. **Stop accepting.** The caller drops the listener BEFORE calling this, so
///    no peer can join a hub that is on its way out.
/// 2. **Ask every session to go.** The shutdown watch wakes each reader and
///    [`super::routing::Router::request_close_all`] enqueues the writers'
///    `Close` sentinel. NOTHING content-bearing is emitted: there is no
///    goodbye frame, no flush of hub-authored state, no last wake. The hub
///    holds no durable truth, so there is nothing it could owe a peer at
///    shutdown; the already-committed inbox row and the `<=60 s` backstop poll
///    are the guarantee, exactly as they are at every other moment.
/// 3. **Wait, bounded.** At most [`DRAIN_DEADLINE_MS`] for the connection gauge
///    to reach zero. An unbounded wait is a hung `systemctl stop` that ends in
///    `SIGKILL` — strictly worse, because the socket then survives us.
/// 4. **Unlink our own socket, and only ours.** See [`remove_own_socket`].
///
/// Always completes; the caller then exits 0. A drain that timed out is a WARN
/// with the residual count, not a failure exit: the connections it was waiting
/// on are peers that stopped reading, which is their fault to fix and not a
/// reason to tell a supervisor the hub crashed.
async fn drain(
    state: &Arc<HubState>,
    socket_path: &Path,
    socket_ident: Option<SocketIdent>,
    shutdown_tx: &watch::Sender<bool>,
) {
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
    remove_own_socket(socket_path, socket_ident);
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
/// * its `(device, inode)` must still match the one this process created.
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

    /// #3471 — the drain unlinks the socket IT created.
    #[test]
    fn the_drain_unlinks_the_socket_this_process_created() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("own.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let ident = socket_ident_of(&path);
        assert!(ident.is_some(), "a bound socket must be stat-able");
        drop(listener);
        remove_own_socket(&path, ident);
        assert!(!path.exists(), "our own socket must be cleaned up");
    }

    /// #3471 — a REPLACEMENT hub's socket at the same path is never deleted by
    /// a straggling predecessor's drain. This is the restart-race that would
    /// otherwise blackhole every agent on the host.
    #[test]
    fn a_replacement_socket_at_the_same_path_is_never_unlinked() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("race.sock");
        let first = std::os::unix::net::UnixListener::bind(&path).expect("bind first");
        let first_ident = socket_ident_of(&path);
        drop(first);
        std::fs::remove_file(&path).expect("clear");
        // The "replacement" binds a NEW socket at the same path.
        let _second = std::os::unix::net::UnixListener::bind(&path).expect("bind second");
        let second_ident = socket_ident_of(&path);
        assert_ne!(
            first_ident, second_ident,
            "a fresh bind must produce a different inode for this test to mean anything"
        );
        remove_own_socket(&path, first_ident);
        assert!(
            path.exists(),
            "the predecessor's drain must not delete the replacement's socket"
        );
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
