// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3470 — one wake-listener session on the hub's Unix domain socket.
//!
//! # An ordinary client, deliberately
//!
//! Exactly like the #3469 forwarder, this speaks the hub's public protocol and
//! nothing else: the hub opens with a challenge, the listener answers with a
//! signed `hello`, and every frame in both directions goes through the same
//! [`crate::wake_hub::codec`] under the same
//! [`crate::wake_hub::limits::MAX_FRAME_BYTES`] ceiling. There is no
//! privileged side channel; the hub applies its peer-credential gate, its
//! identity verifier, its token buckets and its queue bounds to a listener
//! exactly as it does to any peer.
//!
//! # No topics
//!
//! The listener asserts an EMPTY topic list. A substrate wake is addressed
//! directly to the recipient and the hub's route table is keyed by the
//! identity the hello authenticated, so this session can only ever be handed
//! wakes for its own inbox — the own-inbox scope #3468's verifier grants.
//! Subscribing to a topic would be asking for wakes the delegation does not
//! cover.
//!
//! # The socket is checked the way the hub checks it
//!
//! Before connecting, the path is required to be a socket owned by the caller
//! with no group or other bits, inside an owner-only directory — the mirror of
//! [`crate::wake_hub::startup::prepare_socket_path`] on the listening side. A
//! listener that dialled a socket some other local user could have created
//! would be handing its handshake to whoever won that race.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::StreamExt as _;
use tokio_util::codec::{Encoder as _, FramedRead, LengthDelimitedCodec};

use super::bundle::HubJoinBundle;
use crate::wake_hub::codec::codec;
use crate::wake_hub::frame::{
    CTX_DECODING_HUB_FRAME, CTX_HUB_CLOSED, CTX_UNPARSEABLE_REFUSAL, Frame, HelloPayload, Kind,
    WakeMeta, WelcomePayload, decode_error, decode_topics, encode_topics,
};
use crate::wake_hub::identity::{hello_transcript, topics_hash};
use crate::wake_hub::limits::{DEFAULT_HANDSHAKE_TIMEOUT_MS, HELLO_NONCE_BYTES};
use crate::wake_hub::startup::{SOCKET_DIR_MODE, SOCKET_MODE, current_euid};

/// Everything one session needs, and nothing about what to do with a wake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The hub's socket.
    pub socket_path: PathBuf,
    /// The hub's identifier, bound into the handshake transcript so a
    /// signature minted for one hub cannot be replayed at another.
    pub hub_id: String,
    /// Deadline for completing the handshake.
    pub handshake_timeout: Duration,
}

impl SessionConfig {
    /// Bounded defaults for a hub listening at `socket_path`.
    #[must_use]
    pub fn new(socket_path: PathBuf, hub_id: impl Into<String>) -> Self {
        Self {
            socket_path,
            hub_id: hub_id.into(),
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
        }
    }
}

/// What one poll of a live session produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// A wake hint addressed to this listener.
    Wake(Box<WakeMeta>),
    /// v1.0.0 #3532 — the hub ACKNOWLEDGED a subscription change: it holds
    /// (or, for an `unsubscribe`, has dropped) exactly these topics for this
    /// session, and it applied that change BEFORE minting this frame. A
    /// caller waiting for its subscription to go live waits for this, never
    /// for a timer.
    ///
    /// It is an EVENT and not the return value of
    /// [`Session::send_subscribe`] on purpose: a wake for a topic that was
    /// already live can legitimately arrive between the request and its ack,
    /// and a blocking `subscribe()` that read frames itself would have to
    /// swallow or buffer that wake. Surfacing both through the one ordered
    /// event stream means nothing is lost and nothing is reordered.
    Subscribed(Vec<String>),
    /// A frame this version has no opinion about (liveness already answered).
    /// Surfaced rather than swallowed so the caller can keep its own idle
    /// accounting honest.
    Idle,
}

/// A live, authenticated session.
pub struct Session {
    reader: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    writer: OwnedWriteHalf,
    agent_id: String,
    welcome: WelcomePayload,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("agent_id", &self.agent_id)
            .field("welcome", &self.welcome)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// What the hub told this session at admission.
    #[must_use]
    pub const fn welcome(&self) -> &WelcomePayload {
        &self.welcome
    }

    /// Read the next event, answering liveness in place.
    ///
    /// # Errors
    ///
    /// Any framing failure, an `error` frame from the hub (terminal for this
    /// session), or EOF. Every one of them ends the session and the caller
    /// backs off; none of them can lose a durable row, because the row is
    /// already committed and the backstop poll still finds it.
    pub async fn next_event(&mut self) -> Result<SessionEvent> {
        let Some(next) = self.reader.next().await else {
            bail!(CTX_HUB_CLOSED);
        };
        let body = next.context("framing error from the hub")?;
        let frame = Frame::decode(&body).context(CTX_DECODING_HUB_FRAME)?;
        match frame.kind {
            Kind::Wake => {
                let meta = WakeMeta::decode(&frame.payload)
                    .context("decoding the wake metadata the hub routed")?;
                Ok(SessionEvent::Wake(Box::new(meta)))
            }
            Kind::Ping => {
                let pong = Frame::new(Kind::Pong, self.agent_id.clone(), frame.from, Bytes::new())
                    .encode()
                    .context("encoding a pong")?;
                write_framed(&mut self.writer, pong).await?;
                Ok(SessionEvent::Idle)
            }
            // #3532 — the hub echoes an APPLIED subscription change back. An
            // ack that does not decode is reported as `Idle`, never as a
            // failure: the subscription itself is a routing hint, and dropping
            // a live session over an unreadable acknowledgement would trade a
            // durable-row-safe hint for an outage. It stays UNACKNOWLEDGED, so
            // a caller waiting on liveness keeps waiting rather than being
            // told a lie.
            Kind::Subscribe | Kind::Unsubscribe => {
                Ok(decode_topics(&frame.payload)
                    .map_or(SessionEvent::Idle, SessionEvent::Subscribed))
            }
            Kind::Error => {
                let (code, reason) =
                    decode_error(&frame.payload).unwrap_or((0, CTX_UNPARSEABLE_REFUSAL.to_owned()));
                bail!("the hub refused this session: {code} {reason}");
            }
            // A future hub may send frames this version has no opinion about.
            // Ignore rather than close: a listener that dropped its session
            // over an unknown frame would trade wake latency for nothing.
            _ => Ok(SessionEvent::Idle),
        }
    }

    /// Ask the hub to add `topics` to this session's subscription set
    /// (v1.0.0 #3532).
    ///
    /// This only WRITES. The subscription is not live when this returns — it
    /// is live once [`Session::next_event`] yields
    /// [`SessionEvent::Subscribed`] naming these topics, which the hub emits
    /// only after its router already holds them. A caller that treats the
    /// write as liveness reintroduces exactly the race #3532 closed: a peer's
    /// topic wake in that window fans out to nobody.
    ///
    /// # Errors
    ///
    /// An invalid or over-count topic list, an encoding failure, or a write
    /// failure. None of them can lose a durable row: the inbox is the truth
    /// and the backstop poll still finds it.
    pub async fn send_subscribe(&mut self, topics: &[String]) -> Result<()> {
        self.send_subscription(Kind::Subscribe, topics).await
    }

    /// Ask the hub to drop `topics` from this session's subscription set.
    ///
    /// Acknowledged the same way as [`Session::send_subscribe`]: the removal
    /// has taken effect once the matching [`SessionEvent::Subscribed`]
    /// arrives, and not before.
    ///
    /// # Errors
    ///
    /// As [`Session::send_subscribe`].
    pub async fn send_unsubscribe(&mut self, topics: &[String]) -> Result<()> {
        self.send_subscription(Kind::Unsubscribe, topics).await
    }

    async fn send_subscription(&mut self, kind: Kind, topics: &[String]) -> Result<()> {
        let payload = encode_topics(topics).context("encoding the topic list")?;
        let body = Frame::new(kind, self.agent_id.clone(), "", payload)
            .encode()
            .with_context(|| format!("encoding a {kind} frame"))?;
        write_framed(&mut self.writer, body).await
    }
}

/// Connect, handshake, and return the live session.
///
/// # Errors
///
/// The socket preflight, any connect or I/O failure, a handshake timeout, or a
/// refusal from the hub. Every one is a case where continuing would mean a
/// listener that looks attached and is woken by nobody.
pub async fn connect(cfg: &SessionConfig, bundle: &HubJoinBundle) -> Result<Session> {
    assert_socket_is_owner_only(&cfg.socket_path)?;
    let stream = UnixStream::connect(&cfg.socket_path)
        .await
        .with_context(|| format!("connecting to {}", cfg.socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, codec());
    let welcome = handshake(cfg, bundle, &mut reader, &mut write_half).await?;
    Ok(Session {
        reader,
        writer: write_half,
        agent_id: bundle.agent_id().to_owned(),
        welcome,
    })
}

/// The client half of the handshake: challenge in, signed hello out, welcome
/// back — and the welcome is VERIFIED, not assumed.
async fn handshake(
    cfg: &SessionConfig,
    bundle: &HubJoinBundle,
    reader: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    write_half: &mut OwnedWriteHalf,
) -> Result<WelcomePayload> {
    let challenge = read_one(reader, cfg.handshake_timeout)
        .await
        .context("waiting for the hub's challenge")?;
    if challenge.kind != Kind::Hello || challenge.payload.len() != HELLO_NONCE_BYTES {
        bail!(
            "the hub's first frame was {} ({} payload bytes), not a {HELLO_NONCE_BYTES}-byte \
             hello challenge",
            challenge.kind,
            challenge.payload.len()
        );
    }
    let mut nonce = [0u8; HELLO_NONCE_BYTES];
    nonce.copy_from_slice(&challenge.payload);

    // NO topics: own-inbox only (#3468). See the module docs.
    let topics: Vec<String> = Vec::new();
    let transcript = hello_transcript(
        &cfg.hub_id,
        &nonce,
        bundle.agent_id(),
        &topics_hash(&topics),
    );
    let signed = bundle.sign_hello(&transcript);
    let payload = HelloPayload {
        pubkey: signed.pubkey,
        signature: signed.signature,
        delegation: signed.delegation,
        topics,
    }
    .encode()
    .context("encoding the hello payload")?;
    let hello = Frame::new(Kind::Hello, bundle.agent_id(), "", payload)
        .encode()
        .context("encoding the hello frame")?;
    write_framed(write_half, hello).await?;

    let reply = read_one(reader, cfg.handshake_timeout)
        .await
        .context("waiting for the hub's welcome")?;
    match reply.kind {
        Kind::Welcome => WelcomePayload::decode(&reply.payload).map_err(|e| {
            // A welcome we cannot parse is not a welcome. Refusing here keeps
            // the listener from running against a peer whose admission it
            // never actually read.
            anyhow::anyhow!("the hub's welcome did not decode ({e})")
        }),
        Kind::Error => {
            let (code, reason) =
                decode_error(&reply.payload).unwrap_or((0, CTX_UNPARSEABLE_REFUSAL.to_owned()));
            bail!("the hub refused the handshake: {code} {reason}");
        }
        other => bail!("the hub answered the hello with {other}, not a welcome"),
    }
}

/// Read exactly one decoded frame, bounded by `timeout`.
async fn read_one(
    reader: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    timeout: Duration,
) -> Result<Frame> {
    let Ok(next) = tokio::time::timeout(timeout, reader.next()).await else {
        bail!("timed out");
    };
    match next {
        None => bail!(CTX_HUB_CLOSED),
        Some(Err(e)) => bail!("framing error: {e}"),
        Some(Ok(body)) => Frame::decode(&body).context(CTX_DECODING_HUB_FRAME),
    }
}

/// Write one already-encoded frame body with the hub's own length prefix.
///
/// The codec is the hub's, so the write side is bound by the SAME
/// `max_frame_length` the read side enforces.
async fn write_framed(write_half: &mut OwnedWriteHalf, body: Bytes) -> Result<()> {
    let mut out = BytesMut::with_capacity(body.len() + 4);
    codec()
        .encode(body, &mut out)
        .context("length-prefixing a frame")?;
    write_half
        .write_all(&out)
        .await
        .context("writing to the hub")?;
    write_half.flush().await.context("flushing to the hub")?;
    Ok(())
}

/// Refuse to dial a socket this host does not keep private.
///
/// The mirror of the hub's own bind-time posture: an owner-only directory
/// (`0700`) holding an owner-only socket (`0600`), both owned by the caller.
///
/// # Errors
///
/// When the path is missing, is not a socket, is a symlink, is owned by
/// another uid, or carries any group/other permission bit — on the socket or
/// on its parent directory.
pub fn assert_socket_is_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let euid = current_euid();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let dir = std::fs::metadata(parent).with_context(|| {
            format!(
                "cannot stat {} — the wake-hub socket directory must exist and be owner-only \
                 ({SOCKET_DIR_MODE:04o})",
                parent.display()
            )
        })?;
        if dir.uid() != euid {
            bail!(
                "{} is owned by uid {}, not by the caller (uid {euid}); refusing to dial a \
                 wake-hub socket in a directory this user does not own",
                parent.display(),
                dir.uid()
            );
        }
        if dir.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} is mode {:04o}; the wake-hub socket directory must be {SOCKET_DIR_MODE:04o}. \
                 Another local user could otherwise replace the socket and take this listener's \
                 handshake.",
                parent.display(),
                dir.permissions().mode() & 0o7777
            );
        }
    }

    let meta = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "no wake-hub socket at {}. Start one with `ai-memory wake-hub`, or point \
             --socket at the running hub.",
            path.display()
        )
    })?;
    if meta.file_type().is_symlink() {
        bail!(
            "{} is a symlink; a socket reached through a link is a socket whose ownership was \
             checked on the wrong path",
            path.display()
        );
    }
    if !meta.file_type().is_socket() {
        bail!("{} is not a socket", path.display());
    }
    if meta.uid() != euid {
        bail!(
            "{} is owned by uid {}, not by the caller (uid {euid}); refusing to hand a \
             handshake to another user's socket",
            path.display(),
            meta.uid()
        );
    }
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} is mode {:04o}; a wake-hub socket must be {SOCKET_MODE:04o}",
            path.display(),
            meta.permissions().mode() & 0o7777
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    // A hostile peer after admission: socketpair isolates the actual production
    // event decoder without bypassing it. This is not credential evidence.
    async fn received_event_3578(body: Bytes) -> Result<SessionEvent> {
        let (client, peer) = UnixStream::pair().expect("socket pair");
        let (reader, writer) = client.into_split();
        let mut session = Session {
            reader: FramedRead::new(reader, codec()),
            writer,
            agent_id: "ai:listener-3578".into(),
            welcome: WelcomePayload {
                session: 1,
                pending_count: 0,
                pending_ids: 0,
                lagged: false,
                reconnect_base_ms: 25,
                reconnect_jitter_ms: 0,
            },
        };
        let (_, mut peer_writer) = peer.into_split();
        write_framed(&mut peer_writer, body)
            .await
            .expect("send hostile frame");
        tokio::time::timeout(Duration::from_secs(5), session.next_event())
            .await
            .expect("bounded event read")
    }

    #[tokio::test]
    async fn valid_binary_hints_reach_the_renderable_event_boundary_3578() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../sdk/fixtures/wake_meta_3578.json"))
                .expect("shared vectors");
        for case in vectors["allowed"].as_array().expect("allowed cases") {
            let raw = hex::decode(case["hex"].as_str().expect("hex")).expect("bytes");
            let expected = WakeMeta::decode(&raw).expect("allowed hint");
            let body = Frame::new(Kind::Wake, "producer", "ai:listener-3578", raw.into())
                .encode()
                .expect("allowed frame");
            assert_eq!(
                received_event_3578(body).await.expect("wake event"),
                SessionEvent::Wake(Box::new(expected))
            );
        }
    }

    #[tokio::test]
    async fn hostile_binary_frames_are_refused_before_a_renderable_event_3578() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../sdk/fixtures/wake_meta_3578.json"))
                .expect("shared vectors");
        let allowed = &vectors["allowed"][1];
        let raw = hex::decode(allowed["hex"].as_str().expect("hex")).expect("bytes");
        let valid = Frame::new(
            Kind::Wake,
            "producer",
            "ai:listener-3578",
            raw.clone().into(),
        )
        .encode()
        .expect("valid frame");
        let mut denied = Vec::new();
        for case in vectors["denied"].as_array().expect("denied cases") {
            let payload = hex::decode(case["hex"].as_str().expect("hex")).expect("bytes");
            // Construct the wire body directly so even the 257-byte fixture
            // reaches the receiver instead of failing in the local encoder.
            let mut body = valid[..valid.len() - raw.len()].to_vec();
            let len = u16::try_from(payload.len())
                .expect("fixture length")
                .to_be_bytes();
            body[10..12].copy_from_slice(&len);
            body.extend_from_slice(&payload);
            if payload.len() <= 256 {
                assert_eq!(
                    Frame::decode(&body)
                        .expect("valid frame wrapping bad metadata")
                        .payload
                        .as_ref(),
                    payload
                );
            } else {
                assert!(matches!(
                    Frame::decode(&body),
                    Err(crate::wake_hub::frame::FrameError::PayloadTooLarge { .. })
                ));
            }
            denied.push((case["name"].to_string(), Bytes::from(body)));
        }
        for kind in [11, 12, 13] {
            let mut body = valid.to_vec();
            body[5] = kind;
            denied.push((format!("reserved kind {kind}"), body.into()));
        }
        assert_eq!(
            denied.len(),
            8,
            "five metadata refusals and three reserved kinds"
        );
        for (name, body) in denied {
            let event = received_event_3578(body).await;
            assert!(event.is_err(), "{name} reached an event: {event:?}");
        }
    }

    /// DENIED: every socket posture that would let another local user take a
    /// listener's handshake. The listener checks the same two objects the hub
    /// hardened when it bound.
    #[tokio::test]
    async fn the_socket_preflight_refuses_every_non_private_posture_3470() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod dir");
        let path = dir.path().join("h.sock");

        // Missing socket.
        let err = assert_socket_is_owner_only(&path).expect_err("no socket, no listener");
        assert!(format!("{err:#}").contains("wake-hub"), "{err:#}");

        // A regular file is not a socket.
        std::fs::write(&path, b"").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let err = assert_socket_is_owner_only(&path).expect_err("a file is not a hub");
        assert!(format!("{err:#}").contains("not a socket"), "{err:#}");
        std::fs::remove_file(&path).expect("rm");

        // A real socket at 0600 in a 0700 directory is the accepted posture.
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_socket_is_owner_only(&path).expect("0600 socket in a 0700 dir is the standard");

        // Group/other bits on the socket.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = assert_socket_is_owner_only(&path).expect_err("a 0666 socket is refused");
        assert!(format!("{err:#}").contains("0666"), "{err:#}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        // Group/other bits on the directory.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod dir");
        let err = assert_socket_is_owner_only(&path).expect_err("a 0755 dir is refused");
        assert!(format!("{err:#}").contains("directory"), "{err:#}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        drop(listener);
    }

    #[test]
    fn the_session_config_defaults_are_bounded_3470() {
        let cfg = SessionConfig::new(PathBuf::from("/x/h.sock"), "hub");
        assert_eq!(
            cfg.handshake_timeout,
            Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            "a handshake with no deadline is a session that can hang forever"
        );
        assert!(!cfg.handshake_timeout.is_zero());
    }
}
