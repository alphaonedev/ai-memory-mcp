// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3829 — MCP stdio-transport precondition guard (defence-in-depth).
//!
//! ## What is actually proven, and by what
//! The load-bearing, PROVABLE claim is a property of OUR CODE:
//! [`crate::mcp`] constructs no listener and no network client for its own
//! transport. That is proven STATICALLY by
//! `scripts/check-mcp-transport-isolation.py` with a planted-violation
//! `--self-test`. See SECURITY.md "MCP transport is stdio-only (#3829)".
//!
//! ## What this runtime guard adds, and what it deliberately does NOT
//! This guard is DEFENCE-IN-DEPTH against ONE misconfiguration class: a
//! supervisor handing a socket DIRECTLY as fd 0 (systemd `StandardInput=socket`
//! with a real socket, `socat …-LISTEN,nofork` dup'ing the raw socket onto the
//! child). It is NOT — and cannot be — a proof that MCP is "not network-served"
//! at the deployment level. A supervisor RELAY defeats any fd check by design:
//! `ssh host ai-memory mcp` and `socat TCP-LISTEN,fork,EXEC:"ai-memory mcp"`
//! (socat terminates the TCP itself and bridges it to the child over a
//! pipe/socketpair) both leave fd 0 a GENUINE pipe while the protocol bytes
//! traverse the network. No inspection of fd 0 can detect that, and ssh-relayed
//! MCP is a legitimate, intended deployment whose transport security is ssh's
//! job. So this guard closes the direct-socket hole; the relay case is out of
//! its reach and is owned by the relay's transport (#3829 amendment 2).
//!
//! ## Positive-evidence discipline (fail-CLOSED)
//! A guard that refuses only on positive evidence of DANGER has a security
//! property equal to the AVAILABILITY OF ITS EVIDENCE CHANNEL, not to the
//! property it guards: an attacker need not forge evidence that fd 0 is a pipe,
//! only make the evidence unobtainable (a seccomp filter returning EPERM on
//! `fstat`/`getsockname` leaves fd 0 fully USABLE while uninspectable), and
//! suppressing a channel is cheaper than forging one (#3829 amendment 2). So
//! this guard requires POSITIVE proof of a safe inherited channel — fd 0 must
//! `fstat` as a pipe, a character device (tty / `/dev/null`), or a regular file
//! — and REFUSES on everything else, INCLUDING cannot-determine (fstat failed,
//! or a socket whose family the kernel would not report, or a socket that can
//! prove not-listening through NEITHER channel — `SO_ACCEPTCONN` unanswered AND
//! no connected peer from `getpeername`) and any unexpected type. The one
//! non-refusing socket case is a positively `AF_UNIX` connected socket, which
//! is WARNED (not refused): a `socketpair`
//! stdio channel is one inherited peer, and an accepted UDS connection is the
//! Unix-domain-socket case whose control is peer-cred + socket mode (the
//! `wake_hub` ruling / #3827), not a transport cipher — that boundary is left
//! to the UDS lane rather than refused here.

/// The classification of fd 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fd0Kind {
    /// Proven a pipe, character device (tty / `/dev/null`), or regular file —
    /// a safe inherited stdio channel. Proceed silently.
    InheritedChannel,
    /// A positively-`AF_UNIX` connected socket (socketpair-stdio, or an
    /// accepted UDS connection). Not a network-served surface; its control is
    /// peer-cred + socket mode (the `wake_hub` ruling / #3827). Proceed, but
    /// record loudly.
    UnixSocket,
    /// Anything NOT proven safe — a listening socket, a non-`AF_UNIX` socket, a
    /// socket whose family could not be read, a socket that can prove neither
    /// not-listening (SO_ACCEPTCONN) nor a connected peer (getpeername), an fd
    /// that could not be inspected (fstat failed), or an unexpected fd type.
    /// REFUSE. The payload names why.
    Refuse(String),
}

/// What `fstat` + the socket probes could determine about fd 0. Split from the
/// syscalls so the fail-CLOSED decision is exhaustively unit-testable with
/// literals — including the uninspectable and exotic-family cases that are
/// awkward or impossible to construct as real descriptors in a test.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fd0Probe {
    /// `fstat` failed (EBADF — closed/invalid; or EPERM/EACCES — the inspection
    /// syscall is seccomp-filtered on a fd that is nonetheless usable).
    Uninspectable,
    Pipe,
    CharDevice,
    Regular,
    Socket {
        /// `None` = the SO_ACCEPTCONN probe did not answer (getsockopt failed:
        /// filtered, or the platform does not report it for this socket), so
        /// the listening state is unknown from THIS channel.
        listening: Option<bool>,
        /// `Some(true)` = `getpeername` succeeded: the socket HAS a connected
        /// peer, which is positive evidence it is NOT a listening socket (a
        /// listener has no peer — `getpeername` fails with ENOTCONN, and no
        /// filter can make it succeed). `Some(false)` = `getpeername` reported
        /// ENOTCONN; `None` = the call failed some other way (denied).
        ///
        /// #3829 macOS: `SO_ACCEPTCONN` is not readable for a `socketpair`
        /// there, so `listening` is `None` for the legitimate socketpair-stdio
        /// channel and the guard refused to start every macOS MCP server. The
        /// peer probe is the SECOND positive-evidence channel: it lets a
        /// connected socket prove itself not-listening on any platform, while
        /// a socket that can prove neither still refuses (fail-CLOSED).
        connected: Option<bool>,
        family: Option<i32>,
    },
    /// A directory, block device, symlink, or any other `S_IFMT` value — never
    /// a legitimate stdio channel.
    OtherType,
}

/// The pure fail-CLOSED decision: proceed ONLY on positive evidence of a safe
/// inherited channel; warn on positively-`AF_UNIX`; refuse everything else.
#[cfg(unix)]
#[must_use]
fn classify(probe: Fd0Probe) -> Fd0Kind {
    match probe {
        // Positive evidence of a safe inherited stdio channel.
        Fd0Probe::Pipe | Fd0Probe::CharDevice | Fd0Probe::Regular => Fd0Kind::InheritedChannel,
        // A socket: refuse unless positively AF_UNIX (which warns / hands the
        // UDS boundary to #3827).
        Fd0Probe::Socket {
            listening: Some(true),
            ..
        } => Fd0Kind::Refuse("a listening socket".to_string()),
        // Listening state unknown from SO_ACCEPTCONN AND no connected peer
        // proven by getpeername: nothing positive says this is not a listener
        // -> refuse, consistent with the fstat + family probes (#3829 f2r
        // residual). A socket with a CONNECTED PEER falls through: a listener
        // has no peer, so `connected: Some(true)` is positive evidence of
        // not-listening even where SO_ACCEPTCONN is unreadable (macOS
        // socketpair, #3829 correction).
        Fd0Probe::Socket {
            listening: None,
            connected: Some(false) | None,
            ..
        } => Fd0Kind::Refuse(
            "a socket whose listening state could not be read (getsockopt \
             SO_ACCEPTCONN unanswered) and that has no connected peer"
                .to_string(),
        ),
        // Positively not-listening (SO_ACCEPTCONN = 0, or a connected peer):
        // warn only on AF_UNIX.
        Fd0Probe::Socket {
            listening: Some(false) | None,
            family: Some(f),
            ..
        } if f == libc::AF_UNIX => Fd0Kind::UnixSocket,
        Fd0Probe::Socket {
            listening: Some(false) | None,
            family: Some(f),
            ..
        } => Fd0Kind::Refuse(format!("a non-AF_UNIX socket (address family {f})")),
        Fd0Probe::Socket {
            listening: Some(false) | None,
            family: None,
            ..
        } => Fd0Kind::Refuse("a socket whose address family could not be read".to_string()),
        // No positive evidence of safety -> refuse (fail-CLOSED). Absence of
        // evidence is not evidence of safety.
        Fd0Probe::Uninspectable => Fd0Kind::Refuse(
            "an fd that could not be inspected — fstat failed (closed, or the \
             inspection syscall is seccomp-filtered)"
                .to_string(),
        ),
        Fd0Probe::OtherType => Fd0Kind::Refuse(
            "an unexpected fd type (not a pipe, character device, regular file, \
             or socket)"
                .to_string(),
        ),
    }
}

/// Probe fd via `fstat` (file type) and, for a socket, `getsockopt`/`getsockname`
/// (listening + address family). Never refuses here — refusal is the pure
/// [`classify`]'s job; this only reports what could be observed.
#[cfg(unix)]
#[must_use]
fn probe_fd(fd: std::os::unix::io::RawFd) -> Fd0Probe {
    // SAFETY: a zeroed `stat` is a valid out-param; `fstat` fills at most its
    //    size and `fd` is borrowed live for the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut st) } != 0 {
        return Fd0Probe::Uninspectable;
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO => Fd0Probe::Pipe,
        libc::S_IFCHR => Fd0Probe::CharDevice,
        libc::S_IFREG => Fd0Probe::Regular,
        libc::S_IFSOCK => {
            let mut listening: Option<bool> = None;
            let mut acceptconn: libc::c_int = 0;
            if let Ok(mut len) = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()) {
                // SAFETY: `acceptconn` is a correctly-typed local; `len` is its
                //    exact size; `getsockopt` writes at most `len` bytes.
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ACCEPTCONN,
                        std::ptr::from_mut(&mut acceptconn).cast(),
                        &raw mut len,
                    )
                };
                if rc == 0 {
                    listening = Some(acceptconn != 0);
                }
            }
            // Second positive-evidence channel (#3829 macOS correction): a
            // connected peer proves not-listening. ENOTCONN is a definite "no
            // peer"; any other failure is cannot-determine.
            let mut connected: Option<bool> = None;
            let mut ps: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            if let Ok(mut plen) =
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            {
                // SAFETY: `ps` is a correctly-typed, correctly-sized out-param.
                let rc = unsafe {
                    libc::getpeername(
                        fd,
                        std::ptr::from_mut(&mut ps).cast::<libc::sockaddr>(),
                        &raw mut plen,
                    )
                };
                if rc == 0 {
                    connected = Some(true);
                } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN) {
                    connected = Some(false);
                }
            }
            let mut family: Option<i32> = None;
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            if let Ok(mut slen) =
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            {
                // SAFETY: `ss` is a correctly-typed, correctly-sized out-param.
                let rc = unsafe {
                    libc::getsockname(
                        fd,
                        std::ptr::from_mut(&mut ss).cast::<libc::sockaddr>(),
                        &raw mut slen,
                    )
                };
                if rc == 0 {
                    family = Some(i32::from(ss.ss_family));
                }
            }
            Fd0Probe::Socket {
                listening,
                connected,
                family,
            }
        }
        _ => Fd0Probe::OtherType,
    }
}

/// Classify a raw descriptor for the transport-isolation precondition. This is
/// the syscall wiring; the fail-CLOSED decision lives in the pure [`classify`].
#[cfg(unix)]
#[must_use]
pub fn classify_fd(fd: std::os::unix::io::RawFd) -> Fd0Kind {
    classify(probe_fd(fd))
}

/// Enforce, at MCP init, that fd 0 is a PROVEN inherited stdio channel.
///
/// Refuses (aborting MCP startup before the stdio loop opens) unless fd 0 is a
/// pipe, character device, or regular file, or a positively-`AF_UNIX` socket
/// (which warns). Every other case — a network/listening socket, a socket whose
/// family cannot be read, an uninspectable fd, or an unexpected type — refuses,
/// fail-CLOSED. A no-op on non-unix. This is defence-in-depth against a direct
/// socket on fd 0; a supervisor RELAY (ssh/socat) is out of reach of any fd
/// check (see the module docs and SECURITY.md #3829).
///
/// # Errors
/// Returns an error whenever fd 0 is not a proven inherited channel or an
/// `AF_UNIX` socket.
pub fn enforce_stdin_is_inherited_channel() -> anyhow::Result<()> {
    #[cfg(unix)]
    match classify_fd(libc::STDIN_FILENO) {
        Fd0Kind::InheritedChannel => {}
        Fd0Kind::UnixSocket => {
            tracing::warn!(
                target: "mcp.transport",
                "MCP stdin (fd 0) is a Unix-domain socket, not an inherited \
                 pipe/tty. A socketpair handed by the host is fine (one \
                 inherited peer). But if this is an accepted socat/systemd \
                 UNIX-LISTEN connection, its peer is any process with \
                 filesystem access to the socket path — secure it with a 0600 \
                 socket, a 0700 parent directory, and peer-credential checks \
                 (the wake-hub model / #3827), NOT a transport cipher (#3829)."
            );
        }
        Fd0Kind::Refuse(detail) => {
            anyhow::bail!(
                "refusing MCP stdio startup: fd 0 is {detail}. `ai-memory mcp` \
                 is a stdin/stdout JSON-RPC loop and must be driven over an \
                 inherited pipe/tty from the MCP host, never a socket handed in \
                 by a supervisor (systemd StandardInput=socket, or a socat \
                 …-LISTEN,EXEC). To serve memory over a network, run the HTTP \
                 daemon: `ai-memory serve --tls-cert <cert> --tls-key <key>` \
                 carries TLS. (Note: a RELAY such as `ssh host ai-memory mcp` \
                 leaves fd 0 a genuine pipe and is NOT refused — its transport \
                 security is the relay's; this guard covers a socket handed \
                 DIRECTLY as fd 0, #3829.)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::{Fd0Kind, Fd0Probe, classify, classify_fd};
    use std::os::unix::io::AsRawFd;

    // --- pure classifier: exhaustive over the decision axes ---

    #[test]
    fn proven_safe_channels_proceed() {
        assert_eq!(classify(Fd0Probe::Pipe), Fd0Kind::InheritedChannel);
        assert_eq!(classify(Fd0Probe::CharDevice), Fd0Kind::InheritedChannel);
        assert_eq!(classify(Fd0Probe::Regular), Fd0Kind::InheritedChannel);
    }

    #[test]
    fn uninspectable_refuses() {
        // #3829 amendment 2: cannot-determine is NOT evidence of safety.
        assert!(matches!(
            classify(Fd0Probe::Uninspectable),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn unexpected_type_refuses() {
        assert!(matches!(classify(Fd0Probe::OtherType), Fd0Kind::Refuse(_)));
    }

    #[test]
    fn listening_socket_refuses_any_family() {
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(true),
                connected: Some(false),
                family: Some(libc::AF_UNIX)
            }),
            Fd0Kind::Refuse(_)
        ));
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(true),
                connected: Some(false),
                family: None
            }),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn listening_undetermined_refuses() {
        // #3829 f2r residual: SO_ACCEPTCONN denied (getsockopt filtered) leaves
        // the listening state unknown. An AF_UNIX listener would otherwise take
        // the WARN arm; cannot-determine must REFUSE, consistent with amendment 2.
        for connected in [Some(false), None] {
            assert!(matches!(
                classify(Fd0Probe::Socket {
                    listening: None,
                    connected,
                    family: Some(libc::AF_UNIX)
                }),
                Fd0Kind::Refuse(_)
            ));
            assert!(matches!(
                classify(Fd0Probe::Socket {
                    listening: None,
                    connected,
                    family: None
                }),
                Fd0Kind::Refuse(_)
            ));
        }
    }

    #[test]
    fn connected_peer_is_positive_evidence_of_not_listening() {
        // #3829 macOS correction: SO_ACCEPTCONN is not readable for a socketpair
        // there, so `listening` is None for the legitimate socketpair-stdio
        // channel. A CONNECTED PEER (getpeername succeeded) is positive evidence
        // the socket is not a listener — a listener has no peer — so the
        // AF_UNIX warn arm stands on that evidence alone…
        assert_eq!(
            classify(Fd0Probe::Socket {
                listening: None,
                connected: Some(true),
                family: Some(libc::AF_UNIX)
            }),
            Fd0Kind::UnixSocket
        );
        // …while the family and listening refusals are untouched: a connected
        // non-AF_UNIX socket still refuses, an unreadable family still refuses,
        // and a positively LISTENING socket refuses whatever the peer probe says
        // (the two channels can only disagree under a fault; fail-CLOSED wins).
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: None,
                connected: Some(true),
                family: Some(libc::AF_INET)
            }),
            Fd0Kind::Refuse(_)
        ));
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: None,
                connected: Some(true),
                family: None
            }),
            Fd0Kind::Refuse(_)
        ));
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(true),
                connected: Some(true),
                family: Some(libc::AF_UNIX)
            }),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn inet_families_refuse() {
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(false),
                connected: Some(true),
                family: Some(libc::AF_INET)
            }),
            Fd0Kind::Refuse(_)
        ));
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(false),
                connected: Some(true),
                family: Some(libc::AF_INET6)
            }),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn non_unix_non_inet_families_refuse() {
        // The class the AF_INET-only default missed: AF_VSOCK (40, guest<->host
        // VM), AF_BLUETOOTH (31), AF_TIPC (30), legacy AF_IPX (4) / AF_APPLETALK
        // (5) on Linux. Literals so the test needs no exotic const; ANY
        // non-AF_UNIX family must refuse.
        for fam in [40, 31, 30, 4, 5] {
            assert!(
                matches!(
                    classify(Fd0Probe::Socket {
                        listening: Some(false),
                        connected: Some(true),
                        family: Some(fam)
                    }),
                    Fd0Kind::Refuse(_)
                ),
                "address family {fam} must refuse"
            );
        }
    }

    #[test]
    fn unreadable_family_refuses() {
        // Confirmed a socket, getsockname failed -> not provably AF_UNIX ->
        // refuse (fail-CLOSED).
        assert!(matches!(
            classify(Fd0Probe::Socket {
                listening: Some(false),
                connected: Some(true),
                family: None
            }),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn af_unix_connected_warns_not_refuses() {
        // The load-bearing near-miss: a legitimate socketpair-stdio channel
        // must WARN, never refuse.
        assert_eq!(
            classify(Fd0Probe::Socket {
                listening: Some(false),
                connected: Some(true),
                family: Some(libc::AF_UNIX)
            }),
            Fd0Kind::UnixSocket
        );
    }

    // --- classify_fd wiring against real descriptors ---

    #[test]
    fn real_pipe_is_inherited() {
        let (reader, _writer) = std::io::pipe().expect("pipe");
        assert_eq!(classify_fd(reader.as_raw_fd()), Fd0Kind::InheritedChannel);
    }

    #[test]
    fn real_char_device_is_inherited() {
        let f = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert_eq!(classify_fd(f.as_raw_fd()), Fd0Kind::InheritedChannel);
    }

    #[test]
    fn real_regular_file_is_inherited() {
        let f = std::fs::File::open("Cargo.toml").expect("open Cargo.toml");
        assert_eq!(classify_fd(f.as_raw_fd()), Fd0Kind::InheritedChannel);
    }

    #[test]
    fn real_listening_inet_socket_refuses() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        assert!(matches!(classify_fd(l.as_raw_fd()), Fd0Kind::Refuse(_)));
    }

    #[test]
    fn real_connected_inet_stream_refuses() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = l.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(addr).expect("connect loopback");
        assert!(matches!(
            classify_fd(client.as_raw_fd()),
            Fd0Kind::Refuse(_)
        ));
    }

    #[test]
    fn real_unix_socketpair_warns() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        assert_eq!(classify_fd(a.as_raw_fd()), Fd0Kind::UnixSocket);
    }

    #[test]
    fn real_invalid_fd_refuses() {
        // fstat(-1) -> EBADF -> Uninspectable -> Refuse. Proves the wiring of
        // the fail-CLOSED cannot-determine path.
        assert!(matches!(classify_fd(-1), Fd0Kind::Refuse(_)));
    }
}
