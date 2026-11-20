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

use std::os::fd::AsRawFd as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use tokio::net::UnixStream;

use super::session::assert_socket_is_owned_by;
use crate::wake_hub::startup::{current_euid, read_peer_cred};

/// Dial the hub socket at `path` as the current effective user.
///
/// # Errors
///
/// The preflight refusal (owner, mode, directory, symlink, not a socket), the
/// connect failure, or a connected peer that is not owned by the caller.
pub async fn dial_hub_socket(path: &Path) -> Result<UnixStream> {
    dial_hub_socket_as(path, current_euid()).await
}

/// [`dial_hub_socket`] with the expected owner passed in (test seam).
///
/// # Errors
///
/// As [`dial_hub_socket`].
pub(crate) async fn dial_hub_socket_as(path: &Path, euid: u32) -> Result<UnixStream> {
    assert_socket_is_owned_by(path, euid)?;
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    let peer = read_peer_cred(stream.as_raw_fd())
        .with_context(|| format!("reading the peer credentials of {}", path.display()))?;
    if peer.uid != euid {
        bail!(
            "the peer of {} is uid {}, not the caller (uid {euid}); the socket was replaced \
             between the check and the connect, so no frame is sent",
            path.display(),
            peer.uid
        );
    }
    Ok(stream)
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
        let err = dial_hub_socket_as(&socket, other)
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
}
