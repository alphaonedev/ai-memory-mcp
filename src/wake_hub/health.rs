// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` health probe (issue
//! [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471), EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # What the probe is
//!
//! An ORDINARY hub client. It connects to the configured Unix socket, waits for
//! the hub's opening challenge frame, and closes. That is the whole probe.
//!
//! # What the probe deliberately is NOT
//!
//! * **Not a privileged side channel.** There is no admin socket, no status
//!   endpoint, no second listener. A health surface that bypassed the hub's own
//!   admission path would be an unauthenticated way to learn the hub's state,
//!   and — worse — it would stop testing the path that actually matters. The
//!   probe proves liveness only because it takes the same road every agent
//!   takes.
//! * **Not a bypass of the peer-credential gate.** The probe is subject to
//!   `SO_PEERCRED` / `getpeereid` like any other peer. Run as the wrong user it
//!   is DENIED and reports `unreachable`, which is the correct answer: from
//!   that user, the hub is unreachable.
//! * **Not an authenticated session.** The probe presents no `hello`, holds no
//!   key material, and is refused entry to everything past the challenge. It
//!   therefore cannot be used to enumerate agents, join topics, or inject a
//!   wake — and it needs no credential to run, which is what makes it usable
//!   from a supervisor's `ExecStartPost` where no agent identity exists.
//!
//! # Cost to the hub
//!
//! One accepted connection for the length of the probe, bounded by
//! [`HEALTH_PROBE_TIMEOUT_MS`], against a pre-auth budget of 4 frames/s. The
//! probe sends ZERO frames, so it consumes no pre-auth tokens at all, and it
//! closes as soon as the challenge arrives rather than sitting on the
//! connection until the handshake deadline. A monitoring loop running it once a
//! second costs the hub one short-lived connection per second out of a
//! 256-connection ceiling.
//!
//! # Fail closed
//!
//! Every outcome that is not "the hub answered with a well-formed challenge" is
//! `unreachable`, and `unreachable` is a non-zero exit. A probe that could not
//! decide must report the failure, never the absence of one: a supervisor that
//! reads "healthy" from an inconclusive probe is worse than no probe.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

use super::codec::codec;
use super::frame::{Frame, Kind};
use super::limits::{HEALTH_PROBE_TIMEOUT_MS, HELLO_NONCE_BYTES};
use super::startup::{SOCKET_DIR_MODE, SOCKET_MODE, current_euid};

/// Why a probe did not reach a healthy hub — or that it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// The hub answered with a well-formed challenge. The ONLY healthy value.
    Reachable,
    /// Nothing exists at the configured socket path.
    SocketMissing,
    /// Something exists at the path but it is not a socket. Reported
    /// separately because the remedy is "fix the path", not "start the hub".
    NotASocket,
    /// The socket exists but nothing is listening: a hub that died without
    /// unlinking, or one that has not finished binding.
    ConnectionRefused,
    /// The kernel refused the connection. On a 0600 socket this is the
    /// peer-credential / ownership answer: from here, the hub is unreachable.
    PermissionDenied,
    /// The hub accepted but did not produce a challenge within the budget.
    Timeout,
    /// The hub answered with something that is not this protocol's challenge.
    UnexpectedFrame,
    /// Any other I/O failure, carried verbatim.
    Io(String),
}

impl HealthStatus {
    /// Is the hub usable from here?
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        matches!(self, Self::Reachable)
    }

    /// Stable machine-readable label. One definition, so the JSON report and
    /// the human report cannot spell an outcome differently.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::SocketMissing => "socket_missing",
            Self::NotASocket => "not_a_socket",
            Self::ConnectionRefused => "connection_refused",
            Self::PermissionDenied => "permission_denied",
            Self::Timeout => "timeout",
            Self::UnexpectedFrame => "unexpected_frame",
            Self::Io(_) => "io_error",
        }
    }

    /// The operator-facing remedy for this outcome.
    #[must_use]
    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::Reachable => "none — the hub answered its challenge",
            Self::SocketMissing => {
                "no socket at the configured path: start `ai-memory wake-hub`, or point \
                 --socket / [wake_hub].socket at the path it actually binds"
            }
            Self::NotASocket => {
                "the configured path holds a file or directory, not a socket: fix the \
                 path — the hub will REFUSE to unlink it, and so does this probe"
            }
            Self::ConnectionRefused => {
                "the socket file is stale: no process is listening on it. The next \
                 `ai-memory wake-hub` start clears it after probing"
            }
            Self::PermissionDenied => {
                "the socket is 0600 inside a 0700 directory and admits only its owner: \
                 run the probe as the user that runs the hub"
            }
            Self::Timeout => {
                "the hub accepted the connection but sent no challenge in time: it is \
                 wedged or saturated — check `wake-hub --posture` and the hub's log"
            }
            Self::UnexpectedFrame => {
                "the listener at this path is not an ai-memory wake-hub, or speaks a \
                 different wire version: check the configured socket path"
            }
            Self::Io(_) => "see the reported error",
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io_error: {e}"),
            other => f.write_str(other.label()),
        }
    }
}

/// Posture of the socket file itself, read WITHOUT connecting.
///
/// Reported alongside reachability because the two faults are independent: a
/// hub can be perfectly reachable through a socket whose directory has been
/// loosened to 0755, and that is a finding an operator needs even though every
/// wake is being delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketPosture {
    /// Mode of the socket file, or `None` when it does not exist.
    pub socket_mode: Option<u32>,
    /// Mode of the socket's parent directory, or `None`.
    pub dir_mode: Option<u32>,
    /// `true` when the socket is owned by the euid running the probe.
    pub socket_owner_is_self: bool,
    /// `true` when the directory is owned by the euid running the probe.
    pub dir_owner_is_self: bool,
}

impl SocketPosture {
    /// Read the posture of `socket_path` and its parent.
    #[must_use]
    pub fn read(socket_path: &Path) -> Self {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let me = current_euid();
        let stat = |p: &Path| std::fs::symlink_metadata(p).ok();
        let sock = stat(socket_path);
        let dir = socket_path.parent().and_then(stat);
        Self {
            socket_mode: sock.as_ref().map(|m| m.permissions().mode() & MODE_MASK),
            dir_mode: dir.as_ref().map(|m| m.permissions().mode() & MODE_MASK),
            socket_owner_is_self: sock.as_ref().is_some_and(|m| m.uid() == me),
            dir_owner_is_self: dir.as_ref().is_some_and(|m| m.uid() == me),
        }
    }

    /// Is every posture requirement met? `None` (absent) counts as NOT met:
    /// a missing socket has no posture to approve.
    #[must_use]
    pub fn is_hardened(&self) -> bool {
        self.socket_mode == Some(SOCKET_MODE)
            && self.dir_mode.is_some_and(|m| m & 0o077 == 0)
            && self.socket_owner_is_self
            && self.dir_owner_is_self
    }

    /// The STABLE JSON shape of the socket posture. One definition, shared by
    /// `wake-hub --posture --json`, `wake-hub --health --json` and the
    /// `doctor` wake-hub section, so three surfaces cannot disagree about what
    /// they found on disk.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hardened": self.is_hardened(),
            (KEY_SOCKET_MODE): self.socket_mode.map(fmt_mode),
            "socket_mode_expected": fmt_mode(SOCKET_MODE),
            "socket_owner_is_self": self.socket_owner_is_self,
            "dir_mode": self.dir_mode.map(fmt_mode),
            "dir_mode_expected": fmt_mode(SOCKET_DIR_MODE),
            "dir_owner_is_self": self.dir_owner_is_self,
        })
    }
}

/// Permission-bit mask, named so the mode arithmetic has one definition.
pub const MODE_MASK: u32 = 0o777;

/// Wire/fact key for the socket's permission mode. Named once here so the
/// posture JSON, the health JSON and the `doctor` fact table cannot spell the
/// same field differently — the same reason [`HealthStatus::label`] exists.
pub const KEY_SOCKET_MODE: &str = "socket_mode";

/// Wire/fact key for the socket DIRECTORY's permission mode.
pub const KEY_SOCKET_DIR_MODE: &str = "socket_dir_mode";

/// What one probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    /// The socket the probe targeted.
    pub socket: PathBuf,
    /// The outcome.
    pub status: HealthStatus,
    /// Round trip from connect to challenge, in milliseconds. `None` when the
    /// probe never got that far.
    pub latency_ms: Option<u64>,
    /// Filesystem posture of the socket and its directory.
    pub posture: SocketPosture,
}

impl HealthReport {
    /// Process exit code: `0` reachable, [`EXIT_UNREACHABLE`] otherwise.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        if self.status.is_reachable() {
            0
        } else {
            EXIT_UNREACHABLE
        }
    }

    /// Render the report in the stable JSON shape.
    ///
    /// The challenge nonce is NEVER rendered — only that one arrived and how
    /// long it took. It is per-connection key-agreement material, and a health
    /// probe's output is the single most likely thing in this surface to end up
    /// in a log aggregator.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "socket": self.socket.display().to_string(),
            "reachable": self.status.is_reachable(),
            "status": self.status.label(),
            "detail": match &self.status {
                HealthStatus::Io(e) => serde_json::Value::from(e.clone()),
                _ => serde_json::Value::Null,
            },
            "remedy": self.status.remedy(),
            "latency_ms": self.latency_ms,
            "timeout_ms": HEALTH_PROBE_TIMEOUT_MS,
            "socket_posture": self.posture.to_json(),
        })
    }
}

/// Exit code for an unreachable hub. `2` matches `ai-memory doctor`'s
/// "critical finding" code, so a supervisor or CI script can treat every
/// ai-memory health verb the same way.
pub const EXIT_UNREACHABLE: i32 = 2;

/// Render a mode as a four-digit octal string.
#[must_use]
pub fn fmt_mode(mode: u32) -> String {
    format!("{mode:04o}")
}

/// Probe the hub at `socket_path`.
///
/// Never fails: every outcome — including "there is no socket" — is a
/// [`HealthReport`], because a probe that returned `Err` would make the caller
/// choose an exit code, and that choice is exactly what must not be made in two
/// places.
pub async fn probe(socket_path: &Path) -> HealthReport {
    let posture = SocketPosture::read(socket_path);
    let report = |status: HealthStatus, latency_ms: Option<u64>| HealthReport {
        socket: socket_path.to_path_buf(),
        status,
        latency_ms,
        posture,
    };

    // Preflight WITHOUT connecting, so the common faults get their own
    // diagnosis instead of one opaque connect error.
    match std::fs::symlink_metadata(socket_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return report(HealthStatus::SocketMissing, None);
        }
        Err(e) => return report(HealthStatus::Io(e.to_string()), None),
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return report(HealthStatus::NotASocket, None);
            }
        }
    }

    let budget = Duration::from_millis(HEALTH_PROBE_TIMEOUT_MS);
    let started = Instant::now();
    let connected = match tokio::time::timeout(budget, UnixStream::connect(socket_path)).await {
        Err(_elapsed) => return report(HealthStatus::Timeout, None),
        Ok(Err(e)) => return report(classify_io(&e), None),
        Ok(Ok(stream)) => stream,
    };

    // The hub speaks FIRST. Read exactly one frame and leave; sending nothing
    // is what keeps the probe outside the identity path entirely.
    let mut reader = FramedRead::new(connected, codec());
    let remaining = budget.saturating_sub(started.elapsed());
    let first = match tokio::time::timeout(remaining, reader.next()).await {
        Err(_elapsed) => return report(HealthStatus::Timeout, None),
        // Stream ended before a frame: the hub closed on us (a denied peer
        // credential lands here — dropped in silence, by design).
        Ok(None) => return report(HealthStatus::PermissionDenied, None),
        Ok(Some(Err(e))) => return report(classify_io(&e), None),
        Ok(Some(Ok(body))) => body,
    };
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match Frame::decode(&first) {
        Ok(f) if f.kind == Kind::Hello && f.payload.len() == HELLO_NONCE_BYTES => {
            report(HealthStatus::Reachable, Some(latency_ms))
        }
        _ => report(HealthStatus::UnexpectedFrame, Some(latency_ms)),
    }
}

/// Map an I/O error to the outcome an operator can act on.
fn classify_io(e: &std::io::Error) -> HealthStatus {
    match e.kind() {
        std::io::ErrorKind::NotFound => HealthStatus::SocketMissing,
        std::io::ErrorKind::ConnectionRefused => HealthStatus::ConnectionRefused,
        std::io::ErrorKind::PermissionDenied => HealthStatus::PermissionDenied,
        std::io::ErrorKind::TimedOut => HealthStatus::Timeout,
        _ => HealthStatus::Io(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reachable_is_healthy_and_everything_else_exits_non_zero() {
        let unhealthy = [
            HealthStatus::SocketMissing,
            HealthStatus::NotASocket,
            HealthStatus::ConnectionRefused,
            HealthStatus::PermissionDenied,
            HealthStatus::Timeout,
            HealthStatus::UnexpectedFrame,
            HealthStatus::Io("boom".into()),
        ];
        for status in unhealthy {
            assert!(!status.is_reachable(), "{status} must not read as healthy");
            let r = HealthReport {
                socket: PathBuf::from("/tmp/x.sock"),
                status,
                latency_ms: None,
                posture: SocketPosture::default(),
            };
            assert_eq!(r.exit_code(), EXIT_UNREACHABLE);
            assert!(
                !r.status.remedy().is_empty(),
                "every outcome needs a remedy"
            );
        }
        assert!(HealthStatus::Reachable.is_reachable());
    }

    #[test]
    fn labels_are_unique_so_an_alert_rule_can_switch_on_them() {
        let all = [
            HealthStatus::Reachable,
            HealthStatus::SocketMissing,
            HealthStatus::NotASocket,
            HealthStatus::ConnectionRefused,
            HealthStatus::PermissionDenied,
            HealthStatus::Timeout,
            HealthStatus::UnexpectedFrame,
            HealthStatus::Io(String::new()),
        ];
        let mut labels: Vec<&str> = all.iter().map(HealthStatus::label).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "duplicate status label");
    }

    #[tokio::test]
    async fn a_missing_socket_is_unreachable_not_an_error() {
        let tmp = tempfile::tempdir().expect("tmp");
        let r = probe(&tmp.path().join("absent.sock")).await;
        assert_eq!(r.status, HealthStatus::SocketMissing);
        assert_eq!(r.exit_code(), EXIT_UNREACHABLE);
        assert!(!r.posture.is_hardened(), "a missing socket has no posture");
    }

    #[tokio::test]
    async fn a_regular_file_at_the_socket_path_is_diagnosed_by_name() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("not-a-socket");
        std::fs::write(&path, b"x").expect("write");
        let r = probe(&path).await;
        assert_eq!(r.status, HealthStatus::NotASocket);
        assert!(
            path.exists(),
            "the probe must never remove what it found at the path"
        );
    }

    #[tokio::test]
    async fn a_stale_socket_with_no_listener_reports_connection_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("stale.sock");
        {
            let _l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        }
        assert!(path.exists(), "the socket file outlives its listener");
        let r = probe(&path).await;
        assert_eq!(r.status, HealthStatus::ConnectionRefused);
        assert_eq!(r.exit_code(), EXIT_UNREACHABLE);
    }

    #[tokio::test]
    async fn a_listener_that_is_not_a_wake_hub_is_not_reported_healthy() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("impostor.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let accept = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                // A length-prefixed body that is not a wake-hub frame.
                let _ = s.write_all(&[0, 0, 0, 4, 1, 2, 3, 4]).await;
                let _ = s.shutdown().await;
            }
        });
        let r = probe(&path).await;
        accept.abort();
        assert!(
            !r.status.is_reachable(),
            "a foreign listener must never read as a healthy hub, got {}",
            r.status
        );
    }

    #[test]
    fn the_socket_posture_reads_mode_and_ownership() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(SOCKET_DIR_MODE))
            .expect("chmod dir");
        let path = tmp.path().join("p.sock");
        let _l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .expect("chmod sock");
        let p = SocketPosture::read(&path);
        assert_eq!(p.socket_mode, Some(SOCKET_MODE));
        assert_eq!(p.dir_mode, Some(SOCKET_DIR_MODE));
        assert!(p.socket_owner_is_self);
        assert!(p.dir_owner_is_self);
        assert!(p.is_hardened());
    }

    #[test]
    fn a_group_readable_socket_directory_is_not_hardened() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o750))
            .expect("chmod dir");
        let path = tmp.path().join("p.sock");
        let _l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .expect("chmod sock");
        let p = SocketPosture::read(&path);
        assert!(
            !p.is_hardened(),
            "a 0600 socket in a 0750 directory is not private"
        );
    }

    #[test]
    fn the_json_shape_never_carries_the_challenge_nonce() {
        let doc = HealthReport {
            socket: PathBuf::from("/tmp/x.sock"),
            status: HealthStatus::Reachable,
            latency_ms: Some(3),
            posture: SocketPosture::default(),
        }
        .to_json();
        assert_eq!(doc["reachable"], true);
        assert_eq!(doc["status"], "reachable");
        assert_eq!(doc["latency_ms"], 3);
        assert_eq!(doc["timeout_ms"], HEALTH_PROBE_TIMEOUT_MS);
        assert!(
            !doc.to_string().contains("nonce"),
            "the per-connection challenge nonce is key-agreement material and must \
             never reach a report that ends up in a log aggregator"
        );
        // The key set is pinned, so a future field carrying material would have
        // to be added here deliberately rather than slipping in unnoticed.
        let keys: Vec<&str> = doc
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "detail",
                "latency_ms",
                "reachable",
                "remedy",
                "socket",
                "socket_posture",
                "status",
                "timeout_ms",
            ],
            "the health report's shape is a contract"
        );
    }

    #[test]
    fn an_io_status_carries_its_detail_instead_of_collapsing_it() {
        let doc = HealthReport {
            socket: PathBuf::from("/tmp/x.sock"),
            status: HealthStatus::Io("disk on fire".into()),
            latency_ms: None,
            posture: SocketPosture::default(),
        }
        .to_json();
        assert_eq!(doc["status"], "io_error");
        assert_eq!(doc["detail"], "disk on fire");
        assert_eq!(doc["reachable"], false);
    }

    #[test]
    fn classify_io_maps_the_actionable_kinds() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            classify_io(&Error::from(ErrorKind::ConnectionRefused)),
            HealthStatus::ConnectionRefused
        );
        assert_eq!(
            classify_io(&Error::from(ErrorKind::PermissionDenied)),
            HealthStatus::PermissionDenied
        );
        assert_eq!(
            classify_io(&Error::from(ErrorKind::NotFound)),
            HealthStatus::SocketMissing
        );
        assert!(matches!(
            classify_io(&Error::other("weird")),
            HealthStatus::Io(_)
        ));
    }
}
