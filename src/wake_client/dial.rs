//! The ONE way a wake-plane client dials the hub socket (#9638).
//!
//! Every client that hands a frame to the wake-hub (the `wake-listen` /
//! `wake-client` session, the `wake-sink` forwarder) calls
//! [`dial_hub_socket`]. It refuses, with a named error and BEFORE any byte is
//! sent, a socket that is not the caller's private socket: wrong owner, a
//! group/other-writable socket, or a group/other-writable directory.
//!
//! Check-then-connect leaves a window in which the path could be swapped. It
//! is closed on the connected descriptor: after `connect` the kernel-attested
//! peer uid (`SO_PEERCRED`, the same [`read_peer_cred`] the hub's accept loop
//! uses) must equal the caller's uid, so a socket another user substituted
//! after the path check is dropped before the first frame is written. The
//! window is also bounded by the preflight itself: the parent directory must
//! be owned by the caller and closed to group/other, so no other user can
//! replace the entry in the first place.
//!
//! A census test (`tests/wake_dial_census_9638.rs`) fails on any other
//! `UnixStream::connect` in `src`.

use std::io;
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use tokio::net::UnixStream;

use super::session::assert_socket_is_owned_by;
use crate::wake_hub::identity::PeerCred;
use crate::wake_hub::startup::{current_euid, read_peer_cred};

/// Reads the credential of the peer on a connected descriptor.
///
/// The one injection seam of the dial (#9638). Production always passes the
/// kernel reader [`read_peer_cred`]; only [`dial_checked`] takes a reader and
/// it is private to this module, so no caller outside it can hand the dial a
/// credential.
type PeerCredReader = fn(RawFd) -> io::Result<PeerCred>;

/// Dial the hub socket at `path` as the current effective user.
///
/// # Errors
///
/// The preflight refusal (owner, mode, directory, symlink, not a socket), the
/// connect failure, or a connected peer that is not owned by the caller.
pub async fn dial_hub_socket(path: &Path) -> Result<UnixStream> {
    dial_checked(path, current_euid(), read_peer_cred).await
}

/// The dial: preflight, connect, then the peer check on the connected
/// descriptor with the credential `read_cred` returns.
async fn dial_checked(path: &Path, euid: u32, read_cred: PeerCredReader) -> Result<UnixStream> {
    // RED (#9638 seam): stubbed to today's behaviour, the injected reader is
    // not consulted yet.
    let _ = read_cred;
    assert_socket_is_owned_by(path, euid)?;
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    check_peer(path, euid, read_peer_cred(stream.as_raw_fd()))?;
    Ok(stream)
}

/// The accept rule for the connected peer: the credential was read and its
/// uid is the caller's own. There is no exemption for uid 0: a root peer is
/// accepted only when the caller is root itself.
fn check_peer(path: &Path, euid: u32, cred: io::Result<PeerCred>) -> Result<()> {
    let peer =
        cred.with_context(|| format!("reading the peer credentials of {}", path.display()))?;
    if peer.uid != euid {
        bail!(
            "the peer of {} is uid {}, not the caller (uid {euid}); the socket was replaced \
             between the check and the connect, so no frame is sent",
            path.display(),
            peer.uid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A private 0700 dir holding a 0600 socket with a live listener.
    fn private_socket_9638() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        tokio::net::UnixListener,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod dir");
        let socket = dir.path().join("d9638.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("chmod socket");
        (dir, socket, listener)
    }

    #[tokio::test]
    async fn an_owner_only_socket_is_dialled_9638() {
        let (_dir, socket, _listener) = private_socket_9638();
        dial_hub_socket(&socket).await.expect("dials");
    }

    /// The wrong-owner case without root: the expected owner is a uid the
    /// socket does not have, so the preflight names the mismatch and nothing
    /// connects.
    #[tokio::test]
    async fn a_socket_owned_by_another_uid_is_refused_before_connect_9638() {
        let (_dir, socket, listener) = private_socket_9638();
        let other = current_euid().wrapping_add(1);
        let err = dial_checked(&socket, other, read_peer_cred)
            .await
            .expect_err("a wrong owner must be refused");
        let dir = socket.parent().expect("parent").display().to_string();
        assert_eq!(
            err.to_string(),
            format!(
                "{dir} is owned by uid {}, not by the caller (uid {other}); refusing to dial a \
                 wake-hub socket in a directory this user does not own",
                current_euid()
            )
        );
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept()).await;
        assert!(accepted.is_err(), "no connection may reach the listener");
    }

    // ---- #9638 peer-credential cells: the credential is injected through the
    // one seam (`dial_checked`'s reader); the socket, the preflight and the
    // connect are real.

    /// The bytes a caller writes once the dial succeeded.
    const FRAME_9638: &[u8] = b"frame-9638";
    /// The error text the injected unreadable credential carries.
    const UNREADABLE_9638: &str = "injected 9638: the peer credential could not be read";
    /// How long the recording peer may wait for the dialler to finish.
    const RECORD_WINDOW_9638: std::time::Duration = std::time::Duration::from_secs(5);

    fn other_uid_peer_9638(_fd: RawFd) -> io::Result<PeerCred> {
        Ok(PeerCred {
            uid: current_euid().wrapping_add(1),
            gid: 0,
            pid: Some(1),
        })
    }

    fn unreadable_peer_9638(_fd: RawFd) -> io::Result<PeerCred> {
        Err(io::Error::other(UNREADABLE_9638))
    }

    fn same_uid_peer_9638(_fd: RawFd) -> io::Result<PeerCred> {
        Ok(PeerCred {
            uid: current_euid(),
            gid: 0,
            pid: Some(1),
        })
    }

    /// Dial as a real caller does and, only when the dial succeeds, send one
    /// frame. Returns the dial result and every byte the peer received.
    async fn dial_then_record_9638(read_cred: PeerCredReader) -> (Result<()>, Vec<u8>, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (_dir, socket, listener) = private_socket_9638();
        let recorder = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept");
            let mut got = Vec::new();
            conn.read_to_end(&mut got).await.expect("read to end");
            got
        });
        let outcome = async {
            let mut stream = dial_checked(&socket, current_euid(), read_cred).await?;
            stream.write_all(FRAME_9638).await?;
            stream.shutdown().await?;
            Ok(())
        }
        .await;
        let got = tokio::time::timeout(RECORD_WINDOW_9638, recorder)
            .await
            .expect("the recording peer finishes")
            .expect("the recording peer does not panic");
        (outcome, got, socket.display().to_string())
    }

    #[tokio::test]
    async fn a_peer_with_another_uid_is_refused_and_gets_zero_bytes_9638() {
        let (outcome, got, socket) = dial_then_record_9638(other_uid_peer_9638).await;
        let err = outcome.expect_err("a peer with another uid must be refused");
        let euid = current_euid();
        assert_eq!(
            err.to_string(),
            format!(
                "the peer of {socket} is uid {}, not the caller (uid {euid}); the socket was \
                 replaced between the check and the connect, so no frame is sent",
                euid.wrapping_add(1)
            )
        );
        assert_eq!(got, Vec::<u8>::new(), "zero bytes may reach a refused peer");
    }

    #[tokio::test]
    async fn an_unreadable_peer_credential_is_refused_and_gets_zero_bytes_9638() {
        let (outcome, got, socket) = dial_then_record_9638(unreadable_peer_9638).await;
        let err = outcome.expect_err("an unreadable credential must be refused, never passed");
        assert_eq!(
            err.to_string(),
            format!(
                "could not read the peer credentials of {socket}; refusing to send a frame to \
                 a peer whose uid is unknown"
            )
        );
        assert_eq!(err.root_cause().to_string(), UNREADABLE_9638);
        assert_eq!(
            got,
            Vec::<u8>::new(),
            "zero bytes may reach an unverified peer"
        );
    }

    #[tokio::test]
    async fn a_same_uid_peer_is_dialled_and_the_frame_flows_9638() {
        let (outcome, got, _socket) = dial_then_record_9638(same_uid_peer_9638).await;
        outcome.expect("a same-uid peer is accepted");
        assert_eq!(got, FRAME_9638, "the frame reaches an accepted peer");
    }

    fn root_peer_9638(_fd: RawFd) -> io::Result<PeerCred> {
        Ok(PeerCred {
            uid: 0,
            gid: 0,
            pid: Some(1),
        })
    }

    /// A root peer over a real dial: refused with zero bytes for a non-root
    /// caller (the lanes and CI never run as root); for a root caller it is
    /// the same uid and the frame flows. Both outcomes are exact.
    #[tokio::test]
    async fn a_root_peer_is_refused_for_a_non_root_caller_and_gets_zero_bytes_9638() {
        let (outcome, got, socket) = dial_then_record_9638(root_peer_9638).await;
        let euid = current_euid();
        if euid == 0 {
            outcome.expect("a root caller accepts a root peer");
            assert_eq!(got, FRAME_9638);
            return;
        }
        let err = outcome.expect_err("a non-root caller must refuse a root peer");
        assert_eq!(
            err.to_string(),
            format!(
                "the peer of {socket} is uid 0, not the caller (uid {euid}); the socket was \
                 replaced between the check and the connect, so no frame is sent"
            )
        );
        assert_eq!(got, Vec::<u8>::new(), "zero bytes may reach a root peer");
    }

    /// Root peer rule: no uid-0 exemption. A non-root caller refuses a root
    /// peer; a root caller accepts a root peer (same uid).
    #[test]
    fn a_root_peer_is_accepted_only_by_a_root_caller_9638() {
        let path = Path::new("/run/hub-9638.sock");
        let root = PeerCred {
            uid: 0,
            gid: 0,
            pid: Some(1),
        };
        let err = check_peer(path, 1_000, Ok(root)).expect_err("a non-root caller refuses root");
        assert_eq!(
            err.to_string(),
            "the peer of /run/hub-9638.sock is uid 0, not the caller (uid 1000); the socket \
             was replaced between the check and the connect, so no frame is sent"
        );
        check_peer(path, 0, Ok(root)).expect("a root caller accepts a root peer");
    }

    #[test]
    fn the_peer_rule_refuses_an_unreadable_credential_9638() {
        let path = Path::new("/run/hub-9638.sock");
        let err = check_peer(path, 1_000, Err(io::Error::other(UNREADABLE_9638)))
            .expect_err("an unreadable credential is a refusal");
        assert_eq!(
            err.to_string(),
            "could not read the peer credentials of /run/hub-9638.sock; refusing to send a \
             frame to a peer whose uid is unknown"
        );
        assert_eq!(err.root_cause().to_string(), UNREADABLE_9638);
    }
}
