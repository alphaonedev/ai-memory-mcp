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
use super::limits::EgressBudget;
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
/// a shutdown signal.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Back-off after an `accept` failure, so an fd exhaustion storm cannot become
/// a busy loop that starves the connections already served.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A bound, not-yet-serving wake hub.
#[derive(Debug)]
pub struct WakeHub {
    listener: UnixListener,
    state: Arc<HubState>,
    socket_path: PathBuf,
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

        let permits = Arc::new(Semaphore::new(fd_budget.connection_ceiling));
        let (shutdown, _) = watch::channel(false);
        let state = Arc::new(HubState::new(cfg, deps));
        tracing::info!(
            socket = %socket_path.display(),
            ceiling = fd_budget.connection_ceiling,
            "wake-hub: listening"
        );
        Ok(Self {
            listener,
            state,
            socket_path,
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
            permits,
            shutdown: shutdown_tx,
            ..
        } = self;
        let signal = std::pin::pin!(shutdown);
        accept_loop(&listener, &state, &permits, &shutdown_tx, signal).await;

        // Drain: tell every connection to flush and go, close the listener, and
        // unlink the socket so a restart is not blocked by our own leftovers.
        let _ = shutdown_tx.send(true);
        drop(listener);
        let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
        while state.metrics.connections_current() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        remove_own_socket(&socket_path);
        tracing::info!(socket = %socket_path.display(), "wake-hub: stopped");
        Ok(())
    }
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

/// Unlink our own socket on the way out, and ONLY if it is still a socket.
fn remove_own_socket(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|m| {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_socket()
    }) {
        let _ = std::fs::remove_file(path);
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
}
