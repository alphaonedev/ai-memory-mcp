// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` start-up invariants (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! Everything here runs BEFORE the listener accepts, and every one of them is a
//! refusal rather than a warning where a wrong answer would be a security or
//! availability defect:
//!
//! * [`assert_peer_credentials_available`] — the hub's entire authorisation
//!   floor is the kernel-attested peer credential. If this platform cannot
//!   supply a peer pid on an established `AF_UNIX` connection, the hub refuses
//!   to start rather than run with a weaker gate than it advertises. Asserted on
//!   BOTH Linux (`SO_PEERCRED`) and macOS (`LOCAL_PEERPID` + `getpeereid`).
//! * [`configure_fd_limit`] — raise `RLIMIT_NOFILE` toward
//!   [`DESIRED_NOFILE`], then derive the connection ceiling from what we
//!   actually got. macOS's default 256-fd soft limit lands `EMFILE` at exactly
//!   the 256-agent design target; the vote called that out as a plan-killer, so
//!   it is computed and reported at start-up instead of discovered under load.
//! * [`prepare_socket_path`] — the socket's confidentiality rests on a 0700
//!   parent directory and a 0600 socket. Both are verified, and a path that is
//!   NOT a socket is never unlinked.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result, bail};
use libc::socklen_t;

use super::identity::PeerCred;
use super::limits::{DESIRED_NOFILE, FD_HEADROOM, MIN_CONNECTION_CEILING};

/// Directory mode the socket's parent must have: owner-only.
pub const SOCKET_DIR_MODE: u32 = 0o700;

/// Mode the socket itself must have: owner read/write only.
pub const SOCKET_MODE: u32 = 0o600;

/// What the fd budget allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdBudget {
    /// Soft `RLIMIT_NOFILE` in force after the raise attempt.
    pub soft: u64,
    /// Hard `RLIMIT_NOFILE`.
    pub hard: u64,
    /// The soft limit the hub asked for: [`DESIRED_NOFILE`] (#3471). Reported
    /// so an operator can see at a glance whether the unit file's
    /// `LimitNOFILE=` / plist `SoftResourceLimits` actually took effect.
    pub desired: u64,
    /// Connections the hub will admit, after reserving [`FD_HEADROOM`].
    pub connection_ceiling: usize,
    /// `true` when the configured ceiling had to be lowered to fit the fd
    /// budget. The hub still starts — degraded but honest — and says so.
    pub clamped: bool,
}

impl FdBudget {
    /// Did the process reach the soft limit the hub asked for (#3471)?
    ///
    /// `false` means the supervisor did not grant [`DESIRED_NOFILE`] — the
    /// macOS default 256 is the case the issue names — so the hub is running at
    /// a smaller ceiling than its design target. Not a refusal: a smaller hub
    /// is honest, a hub that lies about its capacity is not.
    #[must_use]
    pub const fn meets_desired(self) -> bool {
        self.soft >= self.desired
    }

    /// The smallest soft `RLIMIT_NOFILE` at which the hub will bind at all:
    /// [`MIN_CONNECTION_CEILING`] connections plus [`FD_HEADROOM`] (#3471).
    #[must_use]
    pub fn minimum_soft_nofile() -> u64 {
        // `PERF-07`: no `as` narrowing. A `MIN_CONNECTION_CEILING` that did not
        // fit `u64` would mean the hub can never start, which saturating to
        // `u64::MAX` states exactly.
        FD_HEADROOM.saturating_add(u64::try_from(MIN_CONNECTION_CEILING).unwrap_or(u64::MAX))
    }
}

/// Read this process's effective uid.
#[must_use]
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid` reads a process property, takes no pointer and cannot
    // fail. Same call shape as `src/identity/keypair.rs`.
    unsafe { libc::geteuid() }
}

/// Read kernel-attested peer credentials off a connected `AF_UNIX` socket.
///
/// ONE implementation, used by BOTH the start-up probe and the accept loop, so
/// the probe validates the exact code that gates every real connection rather
/// than a lookalike. Deliberately reactor-free: it is a `getsockopt` on a raw
/// descriptor, not an async operation, so `ai-memory wake-hub --posture` and a
/// future synchronous `doctor` check can call it outside a Tokio runtime.
///
/// # Errors
///
/// The underlying `getsockopt` / `getpeereid` failure, or
/// [`std::io::ErrorKind::Unsupported`] on a platform that cannot report peer
/// credentials at all — which the hub treats as a refusal to start, never as a
/// reason to skip the check.
pub fn read_peer_cred(fd: RawFd) -> io::Result<PeerCred> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .map_err(|_| io::Error::other("ucred size does not fit socklen_t"))?;
        // SAFETY: `cred` is a fully-owned, correctly-typed local and `len` is
        // its exact size; `getsockopt` writes at most `len` bytes into it and
        // updates `len` to what it wrote. `fd` is borrowed from a live socket
        // for the duration of the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut cred).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(PeerCred {
            uid: cred.uid,
            gid: cred.gid,
            pid: Some(cred.pid),
        });
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both out-params are fully-owned, correctly-typed locals.
        let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pid: libc::pid_t = 0;
        let mut len = socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
            .map_err(|_| io::Error::other("pid_t size does not fit socklen_t"))?;
        // SAFETY: `pid` is a fully-owned, correctly-typed local and `len` is
        // its exact size. `LOCAL_PEERPID` on `SOL_LOCAL` is the macOS
        // counterpart of Linux's `SO_PEERCRED` pid field.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::from_mut(&mut pid).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(PeerCred {
            uid,
            gid,
            pid: Some(pid),
        });
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this platform does not report AF_UNIX peer credentials",
        ))
    }
}

/// Prove this platform reports peer credentials — including the pid — on an
/// established `AF_UNIX` connection.
///
/// Uses a real socketpair and the real [`read_peer_cred`], so it tests the
/// kernel path the accept loop will take rather than trusting a `cfg!` table.
/// Needs no Tokio runtime.
///
/// # Errors
///
/// Fails if the socketpair cannot be created, if the credential read fails, or
/// if the platform reports no pid. Any of those means the hub cannot enforce
/// the boundary it advertises, so it refuses to start (fail closed).
pub fn assert_peer_credentials_available() -> Result<PeerCred> {
    let (probe, _peer) = std::os::unix::net::UnixStream::pair().context(
        "wake-hub: could not create an AF_UNIX socketpair for the peer-credential probe",
    )?;
    let cred = read_peer_cred(probe.as_raw_fd()).context(
        "wake-hub: the platform refused to report peer credentials on a connected socket",
    )?;
    if cred.pid.is_none() {
        bail!(
            "wake-hub: this platform reports no peer pid on an AF_UNIX connection. \
             The hub's authorisation floor is the kernel-attested peer credential \
             (SO_PEERCRED on Linux, LOCAL_PEERPID + getpeereid on macOS); without a \
             pid it cannot enforce what it advertises, so it refuses to start rather \
             than run a weaker gate silently."
        );
    }
    Ok(cred)
}

/// Raise `RLIMIT_NOFILE` toward [`DESIRED_NOFILE`] and derive the connection
/// ceiling.
///
/// Never LOWERS an already-higher soft limit, and a failed raise is not fatal:
/// the ceiling is computed from whatever limit is actually in force, so the hub
/// runs smaller rather than lying about its capacity.
///
/// # Errors
///
/// Fails only when the resulting ceiling is below [`MIN_CONNECTION_CEILING`] —
/// a hub that can hold fewer connections than that is not serving, it is
/// pretending to.
pub fn configure_fd_limit(configured_max_connections: usize) -> Result<FdBudget> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes into a fully-owned, correctly-typed local.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("wake-hub: could not read RLIMIT_NOFILE");
    }
    let hard = u64::from(rl.rlim_max);
    let soft_before = u64::from(rl.rlim_cur);
    let target = DESIRED_NOFILE.min(hard).max(soft_before);
    let mut soft = soft_before;
    if target > soft_before {
        let raised = libc::rlimit {
            rlim_cur: target,
            rlim_max: rl.rlim_max,
        };
        // SAFETY: `setrlimit` reads a fully-owned, correctly-typed local.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) } == 0 {
            soft = target;
        } else {
            tracing::warn!(
                soft = soft_before,
                hard,
                target,
                "wake-hub: could not raise RLIMIT_NOFILE; sizing the connection \
                 ceiling to the inherited soft limit"
            );
        }
    }

    let usable = usize::try_from(soft.saturating_sub(FD_HEADROOM)).unwrap_or(usize::MAX);
    // #3471 — the two ways the ceiling can be too small have DIFFERENT
    // remedies, so they get different refusals. Conflating them (as the #3467
    // substrate did) told an operator who had typed `--max-connections 4` to go
    // raise their file-descriptor limit.
    let minimum_soft = FdBudget::minimum_soft_nofile();
    if usable < MIN_CONNECTION_CEILING {
        bail!(
            "wake-hub: RLIMIT_NOFILE soft limit {soft} leaves room for only {usable} \
             connections after reserving {FD_HEADROOM} descriptors of headroom, which is \
             below the {MIN_CONNECTION_CEILING}-connection floor. The hub needs a soft \
             limit of at least {minimum_soft} to bind at all, and asks for \
             {DESIRED_NOFILE}. Raise it for this process — `LimitNOFILE=` in the systemd \
             unit, `SoftResourceLimits`/`HardResourceLimits` NumberOfFiles in the launchd \
             plist (macOS defaults to 256, which lands EMFILE at exactly the 256-agent \
             design target) — and start again."
        );
    }
    if configured_max_connections < MIN_CONNECTION_CEILING {
        bail!(
            "wake-hub: the CONFIGURED connection ceiling is {configured_max_connections}, \
             below the {MIN_CONNECTION_CEILING}-connection floor. The file-descriptor \
             budget is fine (soft limit {soft} allows {usable}); raise \
             `--max-connections` / `[wake_hub].max_connections` instead. A hub that can \
             hold fewer connections than that is not serving, it is pretending to."
        );
    }
    let connection_ceiling = configured_max_connections.min(usable);
    let budget = FdBudget {
        soft,
        hard,
        desired: DESIRED_NOFILE,
        connection_ceiling,
        clamped: connection_ceiling < configured_max_connections,
    };
    if !budget.meets_desired() {
        tracing::warn!(
            soft,
            hard,
            desired = DESIRED_NOFILE,
            ceiling = connection_ceiling,
            "wake-hub: running BELOW the desired file-descriptor budget; the supervisor \
             did not grant it (set LimitNOFILE= in the systemd unit or NumberOfFiles in \
             the launchd plist). The hub is smaller than its design target, not broken."
        );
    }
    Ok(budget)
}

/// Verify (or create) the socket's parent directory and clear the path.
///
/// # Errors
///
/// Refuses when the parent directory is missing-and-uncreatable, is not a
/// directory, is not owned by this process, or is group/other-accessible; and
/// when the socket path itself is occupied by something that is NOT a stale
/// socket.
///
/// # Data integrity
///
/// The ONLY thing this function will ever unlink is a path that `stat`s as a
/// socket AND refuses a connection. A regular file, a directory, a symlink to
/// either, or a socket a live hub is still listening on all produce a refusal.
/// Blind `remove_file` on a configured path is how a typo becomes data loss.
pub fn prepare_socket_path(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "wake-hub: socket path {} has no parent directory",
            path.display()
        )
    })?;
    prepare_socket_dir(parent)?;

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("wake-hub: could not stat socket path {}", path.display())
            });
        }
    };
    if !meta.file_type().is_socket() {
        bail!(
            "wake-hub: {} exists and is NOT a socket. Refusing to remove it — a \
             mistyped socket path must never delete an operator's file.",
            path.display()
        );
    }
    // A BLOCKING connect, deliberately: this runs once at start-up, before the
    // listener exists, and the alternative — unlinking whatever is at the path —
    // is how a mistyped socket path becomes data loss. The probe targets a local
    // AF_UNIX socket, so it resolves immediately in both outcomes.
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!(
            "wake-hub: another wake-hub is already listening on {}. Refusing to \
             take over a live socket.",
            path.display()
        ),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path)
            .with_context(|| {
                format!(
                    "wake-hub: could not remove the stale socket {}",
                    path.display()
                )
            }),
        Err(e) => Err(e).with_context(|| {
            format!(
                "wake-hub: {} is a socket but could not be probed; refusing to \
                 unlink a socket whose state is unknown",
                path.display()
            )
        }),
    }
}

/// Create the parent directory 0700, or verify an existing one.
///
/// # The creation window (#3471, from the #3467 review)
///
/// The leaf is created with [`fs::DirBuilder::mode`], NOT with `create_dir_all`
/// followed by a `chmod`. The pair leaves a window — however brief — in which
/// the directory that is about to hold a 0600 socket exists at the process
/// umask, typically 0755. Anything that can `open` the directory in that window
/// wins a handle whose access rights are fixed at open time, so the later chmod
/// does not take it away. `mkdir(2)` applies the mode atomically at creation,
/// so the directory NEVER exists at umask mode.
///
/// `DirBuilder::mode` is still subject to the umask (`mode & !umask`), so it can
/// only ever make the directory MORE private than 0700, never less. The verify
/// pass below re-reads the mode and refuses anything group- or other-accessible,
/// which is what closes the remaining case: a restrictive umask that produced,
/// say, 0500 is fine, and any umask that could produce 0755 could not have got
/// there through this path at all.
fn prepare_socket_dir(dir: &Path) -> Result<()> {
    if let Err(e) = fs::symlink_metadata(dir) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e).with_context(|| {
                format!(
                    "wake-hub: could not stat socket directory {}",
                    dir.display()
                )
            });
        }
        // Ancestors may legitimately be shared (e.g. `/run/user/1000`); only
        // the LEAF holds the socket and only the leaf is created owner-only.
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "wake-hub: could not create the parent of the socket directory {}",
                    dir.display()
                )
            })?;
        }
        match fs::DirBuilder::new()
            .recursive(false)
            .mode(SOCKET_DIR_MODE)
            .create(dir)
        {
            Ok(()) => {}
            // Lost a race with another starter: fall through to the verify
            // pass, which is the authority on whether the mode is acceptable.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "wake-hub: could not create socket directory {} with mode \
                         {SOCKET_DIR_MODE:04o}",
                        dir.display()
                    )
                });
            }
        }
    }

    // VERIFY, always — for a directory we just created as much as for one we
    // found. A filesystem that ignores permission bits would let `mkdir` report
    // success while leaving the directory world-readable, and the socket's
    // confidentiality rests entirely on this mode.
    let meta = fs::symlink_metadata(dir).with_context(|| {
        format!(
            "wake-hub: could not stat socket directory {}",
            dir.display()
        )
    })?;
    if !meta.is_dir() {
        bail!(
            "wake-hub: socket directory {} is not a directory",
            dir.display()
        );
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "wake-hub: socket directory {} is mode {mode:04o}; it must be \
             {SOCKET_DIR_MODE:04o} (owner-only). The 0600 socket inside it is \
             only as private as the directory that holds it.",
            dir.display()
        );
    }
    Ok(())
}

/// Set 0600 on the bound socket and verify it took.
///
/// # Errors
///
/// Fails if the mode cannot be set or does not read back as [`SOCKET_MODE`].
/// Verification matters: on a filesystem that ignores permission bits the
/// `chmod` succeeds and the socket is still world-reachable, so the hub must
/// refuse rather than assume.
pub fn enforce_socket_mode(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("wake-hub: could not set 0600 on {}", path.display()))?;
    let mode = fs::metadata(path)
        .with_context(|| format!("wake-hub: could not re-stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != SOCKET_MODE {
        bail!(
            "wake-hub: {} is mode {mode:04o} after chmod, not {SOCKET_MODE:04o}. This \
             filesystem does not honour permission bits, so the socket cannot be made \
             private; refusing to serve.",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener as StdUnixListener;

    /// NOTE the plain `#[test]`: the probe must NOT need a Tokio runtime.
    /// It is a `getsockopt` on a raw descriptor, and `ai-memory wake-hub
    /// --posture` (plus the future synchronous `doctor` check) calls it outside
    /// any reactor. A tokio-backed socketpair here would panic with "no reactor
    /// running" — which is exactly the regression this shape pins.
    #[test]
    fn peer_credentials_including_pid_are_available_without_a_runtime() {
        let cred = assert_peer_credentials_available().expect("peer creds");
        assert_eq!(cred.uid, current_euid());
        assert_eq!(
            cred.pid,
            Some(std::process::id().try_into().expect("pid fits i32")),
            "a socketpair's peer is this process"
        );
    }

    #[test]
    fn read_peer_cred_refuses_a_descriptor_that_is_not_a_socket() {
        let tmp = tempfile::NamedTempFile::new().expect("tmp file");
        assert!(
            read_peer_cred(tmp.as_file().as_raw_fd()).is_err(),
            "a non-socket descriptor must be an error, never a fabricated credential"
        );
    }

    #[test]
    fn the_fd_budget_clamps_rather_than_lying_about_capacity() {
        let b = configure_fd_limit(8).expect("budget");
        assert!(b.connection_ceiling <= 8);
        assert!(b.connection_ceiling >= MIN_CONNECTION_CEILING);
        assert!(b.soft > 0);
    }

    #[test]
    fn a_created_socket_dir_is_owner_only() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("nested").join("run");
        let sock = dir.join("wake-hub.sock");
        prepare_socket_path(&sock).expect("prepare");
        let mode = fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_DIR_MODE);
    }

    #[test]
    fn a_group_readable_socket_dir_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("chmod");
        let err = prepare_socket_path(&dir.join("s.sock")).expect_err("must refuse");
        assert!(
            format!("{err}").contains("owner-only"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_non_socket_at_the_socket_path_is_never_unlinked() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(SOCKET_DIR_MODE)).expect("chmod");
        let path = dir.join("precious.db");
        fs::write(&path, b"durable truth").expect("write");
        let err = prepare_socket_path(&path).expect_err("must refuse");
        assert!(
            format!("{err}").contains("NOT a socket"),
            "unexpected: {err}"
        );
        assert_eq!(
            fs::read(&path).expect("still there"),
            b"durable truth",
            "a mistyped socket path must never delete an operator's file"
        );
    }

    #[test]
    fn a_live_socket_is_not_taken_over() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(SOCKET_DIR_MODE)).expect("chmod");
        let path = dir.join("live.sock");
        let _listener = StdUnixListener::bind(&path).expect("bind");
        let err = prepare_socket_path(&path).expect_err("must refuse");
        assert!(
            format!("{err}").contains("already listening"),
            "unexpected: {err}"
        );
        assert!(path.exists(), "the live socket must survive the refusal");
    }

    #[test]
    fn a_stale_socket_is_cleared() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(SOCKET_DIR_MODE)).expect("chmod");
        let path = dir.join("stale.sock");
        {
            let _listener = StdUnixListener::bind(&path).expect("bind");
        }
        assert!(path.exists(), "the socket file outlives the listener");
        prepare_socket_path(&path).expect("stale socket is clearable");
        assert!(!path.exists());
    }

    /// #3471 (from the #3467 review) — the leaf socket directory must NEVER
    /// exist at umask mode, not even for the instant between `mkdir` and
    /// `chmod`. Run under a deliberately PERMISSIVE umask (0o022, which is what
    /// the CI pool uses and what would produce a 0755 directory), so a
    /// regression to `create_dir_all` + `set_permissions` would still leave the
    /// end state at 0700 — the test therefore also asserts the ANCESTOR is not
    /// what is being measured, by creating a nested leaf.
    #[test]
    fn the_socket_directory_leaf_is_created_owner_only_under_a_permissive_umask() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("nested").join("run");
        prepare_socket_dir(&dir).expect("prepare");
        let mode = fs::symlink_metadata(&dir)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, SOCKET_DIR_MODE,
            "the leaf must be owner-only; got {mode:04o}"
        );
        assert_eq!(mode & 0o077, 0, "no group or other bits may survive");
    }

    /// #3471 — the verify pass runs on a directory we just created too, so a
    /// filesystem that ignored the mode is caught rather than trusted.
    #[test]
    fn an_existing_owner_only_directory_is_accepted_unchanged() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("run");
        fs::DirBuilder::new()
            .mode(SOCKET_DIR_MODE)
            .create(&dir)
            .expect("mkdir 0700");
        prepare_socket_dir(&dir).expect("accepted");
        let mode = fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_DIR_MODE);
    }

    /// #3471 — a soft `RLIMIT_NOFILE` below the floor is a REFUSAL that names
    /// the fd budget, and a too-small configured ceiling is a DIFFERENT refusal
    /// that names the configuration. Conflating them sent operators to fix the
    /// wrong thing.
    #[test]
    fn a_too_small_configured_ceiling_names_the_configuration_not_the_fd_limit() {
        let err = configure_fd_limit(MIN_CONNECTION_CEILING - 1).expect_err("must refuse");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("CONFIGURED connection ceiling"),
            "unexpected: {rendered}"
        );
        assert!(
            !rendered.contains("Raise it for this process"),
            "must not send the operator to raise RLIMIT_NOFILE: {rendered}"
        );
    }

    /// #3471 — the fd budget reports what it ASKED for alongside what it got,
    /// so an operator can see whether the unit's `LimitNOFILE=` took effect.
    #[test]
    fn the_fd_budget_reports_the_desired_limit_and_the_binding_floor() {
        let b = configure_fd_limit(MIN_CONNECTION_CEILING).expect("budget");
        assert_eq!(b.desired, DESIRED_NOFILE);
        assert_eq!(b.meets_desired(), b.soft >= DESIRED_NOFILE);
        assert_eq!(
            FdBudget::minimum_soft_nofile(),
            FD_HEADROOM + u64::try_from(MIN_CONNECTION_CEILING).expect("fits"),
        );
        assert!(
            b.soft >= FdBudget::minimum_soft_nofile(),
            "a hub that bound must be above its own binding floor"
        );
    }

    #[test]
    fn enforce_socket_mode_sets_and_verifies_0600() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("s.sock");
        let _listener = StdUnixListener::bind(&path).expect("bind");
        enforce_socket_mode(&path).expect("chmod");
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);
    }
}
