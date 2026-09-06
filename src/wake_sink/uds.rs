// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the SEPARATE-PROCESS bridge: `agent_notified` bus → the
//! hub's Unix domain socket.
//!
//! # An ordinary client, deliberately
//!
//! The forwarder speaks the hub's public protocol and nothing else: the hub
//! opens with a challenge, the forwarder answers with a signed `hello`, and
//! from then on it writes `wake` frames through the same
//! [`crate::wake_hub::codec`] every peer uses, under the same
//! [`crate::wake_hub::limits::MAX_FRAME_BYTES`] ceiling. There is no privileged
//! side channel and no second admission path — the hub applies its
//! peer-credential gate, its identity verifier, its token buckets and its queue
//! bounds to the daemon exactly as it does to an agent.
//!
//! # It joins as one unclaimable name
//!
//! The session authenticates as
//! [`crate::identity::sentinels::WAKE_HUB_PRODUCER`], and
//! [`UdsWakeSink::spawn`] REFUSES to start for a credential that claims any
//! other id. "May wake any agent on this host" is therefore an operator grant
//! to one reserved name that no wire caller can register, rather than an
//! authority an agent could talk its way into.
//!
//! # Fail closed, with no flag to open it
//!
//! The shipped [`NoJoinCredential`] refuses to sign, so
//! [`UdsWakeSink::spawn`] refuses to open a socket it could not authenticate
//! on. This mirrors [`crate::wake_hub::identity::DenyAllVerifier`] on the hub
//! side: a switch that disables identity is a switch that eventually gets set
//! in production, so there isn't one.
//!
//! # Bounded, and never backpressure onto a notify
//!
//! [`crate::inbox_wake::InboxWakeSink::on_wake`] runs on the bus pump and only
//! ever performs an encode and a `try_send` into a BOUNDED channel — no
//! `.await`, no lock, no I/O (`CONCURRENCY-20`, `CONCURRENCY-22`). A full
//! channel, an absent hub or a broken socket costs a HINT and a counter, never
//! a committed notify. Reconnects back off exponentially to
//! [`super::BACKSTOP_POLL_MAX`] and are jittered, so a hub restart cannot
//! produce a synchronised reconnect blast across a fleet.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use bytes::{Bytes, BytesMut};
use rand_core::RngCore as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_util::codec::{Encoder as _, FramedRead};

use super::{BACKSTOP_POLL_MAX, SinkMetrics, build_substrate_wake, record_refusal};
use crate::identity::sentinels::WAKE_HUB_PRODUCER;
use crate::inbox_wake::{InboxEvent, InboxWakeSink};
use crate::wake_hub::codec::codec;
use crate::wake_hub::frame::{
    CTX_DECODING_HUB_FRAME, CTX_HUB_CLOSED, CTX_UNPARSEABLE_REFUSAL, DEBUG_FIELD_DELEGATION_BYTES,
    Frame, HelloPayload, Kind, decode_error,
};
use crate::wake_hub::identity::{hello_transcript, topics_hash};
use crate::wake_hub::limits::{
    DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_RECIPIENT_QUEUE_FRAMES, DEFAULT_RECONNECT_BASE_MS,
    DEFAULT_RECONNECT_JITTER_MS, HELLO_NONCE_BYTES, PUBKEY_BYTES, SIGNATURE_BYTES,
};

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

/// Why a credential could not produce a handshake signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// No signing material is configured. The shipped default.
    NotConfigured,
    /// Material is present but signing failed.
    SigningFailed,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => f.write_str(
                "no wake-hub join credential is configured; enrol the producer identity and \
                 mint an a2a-hub/join/v1 delegation for it",
            ),
            Self::SigningFailed => f.write_str("wake-hub join credential could not sign"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// The public half of one signed handshake: everything the hub needs and
/// nothing secret.
#[derive(Clone, PartialEq, Eq)]
pub struct HelloCredential {
    /// The DELEGATED Ed25519 public key this session authenticates with.
    pub pubkey: [u8; PUBKEY_BYTES],
    /// Signature over the hub-issued hello transcript.
    pub signature: [u8; SIGNATURE_BYTES],
    /// The scoped `a2a-hub/join/v1` delegation binding the key to the
    /// enrolled principal (#3468).
    pub delegation: Bytes,
}

impl std::fmt::Debug for HelloCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sizes only. A Debug line is a log line, and dumping handshake
        // material into one buys nothing an operator needs.
        f.debug_struct("HelloCredential")
            .field("pubkey_bytes", &self.pubkey.len())
            .field("signature_bytes", &self.signature.len())
            .field(DEBUG_FIELD_DELEGATION_BYTES, &self.delegation.len())
            .finish()
    }
}

/// Signs the forwarder's way onto the hub.
///
/// Held behind a trait so the shipped binary contains NO usable credential:
/// production wires one from enrolled key material, and tests supply their own,
/// exactly as [`crate::wake_hub::identity::HelloVerifier`] is arranged on the
/// hub side.
pub trait JoinCredential: Send + Sync + 'static {
    /// The agent id this credential authenticates as.
    ///
    /// [`UdsWakeSink::spawn`] refuses anything but
    /// [`WAKE_HUB_PRODUCER`], so a mis-wired credential cannot make the daemon
    /// join as some other agent.
    fn agent_id(&self) -> &str;

    /// Sign one hub-issued hello transcript.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] when no material is configured or signing failed.
    /// Either way the forwarder closes the connection rather than continuing
    /// unauthenticated.
    fn sign_hello(&self, transcript: &[u8]) -> Result<HelloCredential, CredentialError>;
}

/// The shipped credential: refuses.
///
/// A daemon with no enrolled producer identity must not open a socket it cannot
/// authenticate on, so this makes [`UdsWakeSink::spawn`] fail at start-up with
/// an actionable message instead of silently running a forwarder that every
/// handshake rejects.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoJoinCredential;

impl JoinCredential for NoJoinCredential {
    fn agent_id(&self) -> &str {
        ""
    }

    fn sign_hello(&self, _transcript: &[u8]) -> Result<HelloCredential, CredentialError> {
        Err(CredentialError::NotConfigured)
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Operator-tunable forwarder parameters. Every default is bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdsSinkConfig {
    /// The hub's socket.
    pub socket_path: PathBuf,
    /// The hub's identifier, bound into the handshake transcript so a signature
    /// minted for one hub cannot be replayed at another.
    pub hub_id: String,
    /// Depth of the bounded hand-off channel, in frames. This is the ONLY
    /// buffer between a committed notify and the socket; when it is full a hint
    /// is dropped and counted rather than queued without bound.
    pub queue_frames: usize,
    /// Deadline for completing the handshake.
    pub handshake_timeout: Duration,
    /// First reconnect delay. Doubles per consecutive failure, capped at
    /// [`BACKSTOP_POLL_MAX`].
    pub reconnect_base: Duration,
    /// Random span added to every reconnect delay, so a hub restart does not
    /// produce a synchronised reconnect blast.
    pub reconnect_jitter: Duration,
}

impl UdsSinkConfig {
    /// Bounded defaults for a hub listening at `socket_path`.
    #[must_use]
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            hub_id: crate::wake_hub::DEFAULT_HUB_ID.to_owned(),
            queue_frames: DEFAULT_RECIPIENT_QUEUE_FRAMES,
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            reconnect_base: Duration::from_millis(u64::from(DEFAULT_RECONNECT_BASE_MS)),
            reconnect_jitter: Duration::from_millis(u64::from(DEFAULT_RECONNECT_JITTER_MS)),
        }
    }
}

// ---------------------------------------------------------------------------
// The sink
// ---------------------------------------------------------------------------

/// Forwards bus wakes to a hub running in another process.
pub struct UdsWakeSink {
    tx: mpsc::Sender<Bytes>,
    metrics: Arc<SinkMetrics>,
}

impl std::fmt::Debug for UdsWakeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdsWakeSink")
            .field("queued", &(self.tx.max_capacity() - self.tx.capacity()))
            .field("metrics", &self.metrics.snapshot())
            .finish()
    }
}

impl UdsWakeSink {
    fn from_parts(tx: mpsc::Sender<Bytes>, metrics: Arc<SinkMetrics>) -> Self {
        Self { tx, metrics }
    }

    /// This sink's live counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<SinkMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Start the forwarder task and return the sink that feeds it.
    ///
    /// # Errors
    ///
    /// Refuses — before any socket is opened — when the credential is not the
    /// enrolled producer identity (including the shipped [`NoJoinCredential`],
    /// whose id is empty), when the hand-off channel would be unbounded or
    /// zero-depth, or when there is no Tokio runtime to host the forwarder.
    /// Every one of these is a case where starting anyway would mean a daemon
    /// that looks attached and wakes nobody.
    pub fn spawn(cfg: UdsSinkConfig, credential: Arc<dyn JoinCredential>) -> Result<Self> {
        if credential.agent_id() != WAKE_HUB_PRODUCER {
            bail!(
                "wake sink: refusing to start — the join credential authenticates as {:?}, \
                 but a substrate wake forwarder may only join as the reserved {WAKE_HUB_PRODUCER} \
                 identity. Enrol that principal and mint it an a2a-hub/join/v1 delegation \
                 (#3468); there is deliberately no flag that relaxes this.",
                credential.agent_id()
            );
        }
        if cfg.queue_frames == 0 {
            bail!("wake sink: refusing to start — the hand-off channel must have depth");
        }
        let handle = tokio::runtime::Handle::try_current().context(
            "wake sink: refusing to start — no Tokio runtime on this thread to host the \
             wake-hub forwarder",
        )?;

        let metrics = Arc::new(SinkMetrics::default());
        let (tx, rx) = mpsc::channel::<Bytes>(cfg.queue_frames);
        let task_metrics = Arc::clone(&metrics);
        handle.spawn(async move { forwarder_loop(cfg, credential, task_metrics, rx).await });
        Ok(Self::from_parts(tx, metrics))
    }
}

impl InboxWakeSink for UdsWakeSink {
    fn on_wake(&self, event: &InboxEvent) {
        self.metrics.wakes_seen();
        let wake = match build_substrate_wake(event) {
            Ok(wake) => wake,
            Err(refusal) => {
                record_refusal(&self.metrics, event.recipient_agent_id(), &refusal);
                return;
            }
        };
        if wake.shed {
            self.metrics.meta_shed();
        }
        // `try_send` never suspends: the bus pump must not be parked by a slow
        // or absent hub.
        match self.tx.try_send(wake.frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.dropped_transport_full();
                tracing::warn!(
                    recipient = %wake.recipient,
                    "wake sink: hand-off channel to the wake-hub is full; hint dropped — \
                     the recipient still finds the row on its backstop poll"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics.dropped_hub_down();
                tracing::warn!(
                    recipient = %wake.recipient,
                    "wake sink: the wake-hub forwarder has stopped; hint dropped"
                );
            }
        }
    }

    fn on_lagged(&self, missed: u64) {
        self.metrics.bus_lagged(missed);
        tracing::warn!(
            missed,
            "wake sink: the wake bus dropped frames before this sink saw them; those \
             recipients learn of their mail on the next backstop poll, and the NEXT \
             wake they receive carries a higher seq_high_watermark so they can collapse \
             that wait to one catch-up inbox read"
        );
    }
}

/// Attach a separate-process hub to the process-wide wake bus.
///
/// # Errors
///
/// Every refusal in [`UdsWakeSink::spawn`], plus a refusal when a wake sink is
/// already installed on this process (never a silent swap — that would strand
/// frames in the old forwarder).
pub fn install_uds(
    cfg: UdsSinkConfig,
    credential: Arc<dyn JoinCredential>,
) -> Result<Arc<SinkMetrics>> {
    let sink = UdsWakeSink::spawn(cfg, credential)?;
    let metrics = sink.metrics();
    if !crate::inbox_wake::install_sink(Arc::new(sink)) {
        // Dropping the sink closes the hand-off channel, so the forwarder task
        // we just started shuts itself down rather than lingering.
        bail!(
            "wake sink: a wake sink is already installed on this process, or there is no \
             Tokio runtime; refusing to replace it"
        );
    }
    tracing::info!(
        "wake sink: wake-hub forwarder attached to the agent_notified bus; clients must \
         still poll their inbox at least every {BACKSTOP_POLL_MAX:?}"
    );
    Ok(metrics)
}

// ---------------------------------------------------------------------------
// Forwarder
// ---------------------------------------------------------------------------

/// Reconnect delay for the `attempt`-th consecutive failure (1-based),
/// exponential and capped at [`BACKSTOP_POLL_MAX`].
///
/// The cap is the backstop itself: waiting longer than the interval at which a
/// client polls anyway would buy nothing and only widen the window in which a
/// recovered hub sits idle.
#[must_use]
pub fn backoff_for(base: Duration, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    base.saturating_mul(1u32 << shift).min(BACKSTOP_POLL_MAX)
}

/// How long a connection must LAST before it is treated as healthy and the
/// reconnect ladder resets.
///
/// Resetting on every successful connect would turn a hub that accepts and
/// immediately drops into a reconnect hot loop; never resetting at all would
/// leave a long-lived daemon permanently at the cap after one long outage, so a
/// later hub restart would take a minute to notice instead of a quarter-second.
/// Requiring a session that actually did work gives both properties.
const HEALTHY_SESSION: Duration = Duration::from_secs(30);

/// A uniformly random delay in `0..=span`.
fn jitter(span: Duration) -> Duration {
    let span_ms = u32::try_from(span.as_millis()).unwrap_or(u32::MAX);
    if span_ms == 0 {
        return Duration::ZERO;
    }
    let draw = rand_core::OsRng.next_u32() % (span_ms.saturating_add(1));
    Duration::from_millis(u64::from(draw))
}

/// Connect, serve, back off, repeat — until the sink is dropped.
async fn forwarder_loop(
    cfg: UdsSinkConfig,
    credential: Arc<dyn JoinCredential>,
    metrics: Arc<SinkMetrics>,
    mut rx: mpsc::Receiver<Bytes>,
) {
    let mut attempt: u32 = 0;
    loop {
        let started = tokio::time::Instant::now();
        match connect_and_pump(&cfg, credential.as_ref(), &metrics, &mut rx).await {
            Ok(()) => {
                tracing::info!("wake sink: forwarder stopped because the sink was dropped");
                return;
            }
            Err(e) => {
                if started.elapsed() >= HEALTHY_SESSION {
                    // This connection carried wakes for a while before it
                    // broke, so the ladder it inherited describes an outage
                    // that is over. Resetting only HERE — and not on every
                    // successful connect — is what keeps a hub that accepts
                    // and instantly drops from becoming a reconnect hot loop.
                    attempt = 0;
                }
                attempt = attempt.saturating_add(1);
                let wait = backoff_for(cfg.reconnect_base, attempt) + jitter(cfg.reconnect_jitter);
                tracing::warn!(
                    attempt,
                    wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    "wake sink: wake-hub connection failed ({e}); retrying with jittered backoff"
                );
                tokio::time::sleep(wait).await;
            }
        }
        if rx.is_closed() {
            // The sink is gone, so nothing more will be produced and no amount
            // of further retrying can matter. Whatever is still queued degrades
            // to the recipients' backstop poll, which is exactly the contract
            // this plane advertises — and a forwarder that retried forever
            // against a dead producer would be an unbounded task in a
            // long-lived daemon.
            tracing::info!("wake sink: forwarder stopping; the sink was dropped");
            return;
        }
    }
}

/// One connection's lifetime. `Ok(())` means the SINK went away (a clean stop);
/// every other outcome is an error the caller backs off on.
async fn connect_and_pump(
    cfg: &UdsSinkConfig,
    credential: &dyn JoinCredential,
    metrics: &SinkMetrics,
    rx: &mut mpsc::Receiver<Bytes>,
) -> Result<()> {
    let stream = UnixStream::connect(&cfg.socket_path)
        .await
        .with_context(|| format!("connecting to {}", cfg.socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, codec());
    handshake(cfg, credential, &mut reader, &mut write_half).await?;
    tracing::info!(
        socket = %cfg.socket_path.display(),
        "wake sink: authenticated to the wake-hub as {WAKE_HUB_PRODUCER}"
    );

    loop {
        tokio::select! {
            biased;
            incoming = reader.next() => {
                match incoming {
                    None => bail!(CTX_HUB_CLOSED),
                    // The codec refuses an over-ceiling length prefix BEFORE a
                    // byte of body is buffered, so an oversize declaration
                    // lands here rather than in an allocation.
                    Some(Err(e)) => bail!("framing error from the hub: {e}"),
                    Some(Ok(body)) => handle_hub_frame(&body, &mut write_half).await?,
                }
            }
            item = rx.recv() => {
                let Some(frame) = item else { return Ok(()) };
                if let Err(e) = write_framed(&mut write_half, frame).await {
                    metrics.dropped_hub_down();
                    return Err(e);
                }
                metrics.delivered();
            }
        }
    }
}

/// The client half of the handshake.
async fn handshake(
    cfg: &UdsSinkConfig,
    credential: &dyn JoinCredential,
    reader: &mut FramedRead<
        tokio::net::unix::OwnedReadHalf,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    write_half: &mut OwnedWriteHalf,
) -> Result<()> {
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

    // NO topics. A substrate wake is addressed directly to the recipient, so
    // the forwarder subscribes to nothing — there is no topic it could receive
    // another agent's wake on (#3468's own-inbox scope, until #3505).
    let topics: Vec<String> = Vec::new();
    let transcript = hello_transcript(
        &cfg.hub_id,
        &nonce,
        WAKE_HUB_PRODUCER,
        &topics_hash(&topics),
    );
    let credential = credential
        .sign_hello(&transcript)
        .context("signing the hub's hello transcript")?;
    let payload = HelloPayload {
        pubkey: credential.pubkey,
        signature: credential.signature,
        delegation: credential.delegation,
        topics,
    }
    .encode()
    .context("encoding the hello payload")?;
    let hello = Frame::new(Kind::Hello, WAKE_HUB_PRODUCER, "", payload)
        .encode()
        .context("encoding the hello frame")?;
    write_framed(write_half, hello).await?;

    let reply = read_one(reader, cfg.handshake_timeout)
        .await
        .context("waiting for the hub's welcome")?;
    match reply.kind {
        Kind::Welcome => Ok(()),
        Kind::Error => {
            let (code, reason) =
                decode_error(&reply.payload).unwrap_or((0, CTX_UNPARSEABLE_REFUSAL.to_owned()));
            bail!("the hub refused the handshake: {code} {reason}");
        }
        other => bail!("the hub answered the hello with {other}, not a welcome"),
    }
}

/// Frames the hub sends US. The forwarder consumes nothing but liveness and
/// refusals; it is a producer, not a recipient.
async fn handle_hub_frame(body: &[u8], write_half: &mut OwnedWriteHalf) -> Result<()> {
    let frame = Frame::decode(body).context(CTX_DECODING_HUB_FRAME)?;
    match frame.kind {
        Kind::Ping => {
            let pong = Frame::new(Kind::Pong, WAKE_HUB_PRODUCER, frame.from, Bytes::new())
                .encode()
                .context("encoding a pong")?;
            write_framed(write_half, pong).await
        }
        Kind::Error => {
            let (code, reason) =
                decode_error(&frame.payload).unwrap_or((0, CTX_UNPARSEABLE_REFUSAL.to_owned()));
            // A refusal is terminal for THIS connection: the hub has told us a
            // frame was rejected, and continuing to push into a session it may
            // have torn down would silently lose wakes.
            bail!("the hub refused a frame: {code} {reason}");
        }
        // Nothing else is meaningful to a producer. Ignore rather than close:
        // a future hub may send frames this version has no opinion about.
        _ => Ok(()),
    }
}

/// Read exactly one decoded frame, bounded by `timeout`.
async fn read_one(
    reader: &mut FramedRead<
        tokio::net::unix::OwnedReadHalf,
        tokio_util::codec::LengthDelimitedCodec,
    >,
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
/// `max_frame_length` the read side enforces: the forwarder can never emit a
/// frame the hub would refuse to read.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::frame::WakeMeta;
    use tokio_util::codec::Decoder as _;

    /// A credential that signs nothing but claims an identity, so the
    /// start-up refusals can be exercised without key material.
    struct NamedCredential(String);

    impl NamedCredential {
        fn new(id: &str) -> Arc<dyn JoinCredential> {
            Arc::new(Self(id.to_owned()))
        }
    }

    impl JoinCredential for NamedCredential {
        fn agent_id(&self) -> &str {
            &self.0
        }

        fn sign_hello(&self, _transcript: &[u8]) -> Result<HelloCredential, CredentialError> {
            Err(CredentialError::SigningFailed)
        }
    }

    fn event(recipient: &str) -> InboxEvent {
        InboxEvent::AgentNotified {
            seq: 11,
            recipient_agent_id: recipient.into(),
            correlation_id: "sha256:corr".into(),
            inbox_row_id: "row-11".into(),
            namespace: "_inbox/bob".into(),
            sender_agent_id: "ai:alice".into(),
            content_digest: format!("sha256:{}", "22".repeat(32)),
            notified_at: "2026-09-05T00:00:00Z".into(),
        }
    }

    fn sink_with_depth(depth: usize) -> (UdsWakeSink, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(depth);
        (
            UdsWakeSink::from_parts(tx, Arc::new(SinkMetrics::default())),
            rx,
        )
    }

    /// DENIED: the shipped credential refuses to sign, and the sink refuses to
    /// open a socket it could not authenticate on.
    #[tokio::test]
    async fn the_shipped_credential_refuses_and_the_sink_refuses_to_start_3469() {
        assert_eq!(
            NoJoinCredential.sign_hello(b"transcript"),
            Err(CredentialError::NotConfigured)
        );
        let err = UdsWakeSink::spawn(
            UdsSinkConfig::with_socket_path(PathBuf::from("/tmp/never-opened-3469.sock")),
            Arc::new(NoJoinCredential),
        )
        .expect_err("must refuse to start");
        assert!(format!("{err}").contains(WAKE_HUB_PRODUCER), "{err}");
    }

    /// DENIED: a credential for ANY other identity is refused at start-up, so
    /// the daemon can never join the hub as an agent.
    #[tokio::test]
    async fn a_credential_for_another_identity_is_refused_at_startup_3469() {
        for claimed in ["ai:alice", "daemon", ""] {
            let err = UdsWakeSink::spawn(
                UdsSinkConfig::with_socket_path(PathBuf::from("/tmp/never-opened-3469.sock")),
                NamedCredential::new(claimed),
            )
            .expect_err("must refuse to start");
            assert!(format!("{err}").contains("may only join as"), "{err}");
        }
    }

    /// A zero-depth hand-off channel would mean an unbounded or blocking
    /// hand-off; refused.
    #[tokio::test]
    async fn a_zero_depth_handoff_is_refused_3469() {
        let mut cfg = UdsSinkConfig::with_socket_path(PathBuf::from("/tmp/never-opened-3469.sock"));
        cfg.queue_frames = 0;
        let err =
            UdsWakeSink::spawn(cfg, NamedCredential::new(WAKE_HUB_PRODUCER)).expect_err("refuse");
        assert!(format!("{err}").contains("depth"), "{err}");
    }

    /// ALLOWED: what the sink queues is a hub-legal `wake` frame, byte-identical
    /// to what the hub's own codec decodes.
    #[tokio::test]
    async fn what_is_queued_is_exactly_what_the_hub_codec_decodes_3469() {
        let (sink, mut rx) = sink_with_depth(4);
        sink.on_wake(&event("bob"));
        let body = rx.try_recv().expect("one queued frame");

        // Round-trip through the hub's own length-delimited codec.
        let mut wire = BytesMut::new();
        codec().encode(body.clone(), &mut wire).expect("encode");
        let decoded_body = codec()
            .decode(&mut wire)
            .expect("decode")
            .expect("one frame");
        assert_eq!(decoded_body, body);

        let frame = Frame::decode(&decoded_body).expect("frame");
        assert_eq!(frame.kind, Kind::Wake);
        assert_eq!(frame.from, WAKE_HUB_PRODUCER);
        assert_eq!(frame.to, "bob");
        let meta = WakeMeta::decode(&frame.payload).expect("meta");
        assert_eq!(meta.inbox_row_id, "row-11");
        assert_eq!(meta.seq_high_watermark, 11);
    }

    /// DENIED: a full hand-off channel drops and counts; it never blocks the
    /// bus pump and never fails the committed notify.
    #[tokio::test]
    async fn a_full_handoff_channel_drops_and_counts_3469() {
        let (sink, _rx) = sink_with_depth(1);
        sink.on_wake(&event("bob"));
        sink.on_wake(&event("bob"));
        let s = sink.metrics().snapshot();
        assert_eq!(s.wakes_seen, 2);
        assert_eq!(s.dropped_transport_full, 1);
        assert_eq!(s.total_dropped(), 1);
    }

    /// DENIED: a stopped forwarder drops and counts on its own line, so "the
    /// hub went away" never looks like "the fleet went quiet".
    #[tokio::test]
    async fn a_closed_forwarder_drops_on_its_own_counter_3469() {
        let (sink, rx) = sink_with_depth(4);
        drop(rx);
        sink.on_wake(&event("bob"));
        assert_eq!(sink.metrics().snapshot().dropped_hub_down, 1);
    }

    /// DENIED: an unaddressable recipient never reaches the transport.
    #[tokio::test]
    async fn an_unaddressable_recipient_never_reaches_the_transport_3469() {
        let (sink, mut rx) = sink_with_depth(4);
        sink.on_wake(&event("#_inbox/bob"));
        assert!(rx.try_recv().is_err(), "a topic must never be forwarded");
        assert_eq!(sink.metrics().snapshot().dropped_unaddressable, 1);
    }

    #[tokio::test]
    async fn bus_lag_is_counted_not_swallowed_3469() {
        let (sink, _rx) = sink_with_depth(4);
        sink.on_lagged(4);
        assert_eq!(sink.metrics().snapshot().bus_lagged, 4);
    }

    #[test]
    fn reconnect_backoff_is_exponential_and_capped_at_the_backstop_3469() {
        let base = Duration::from_millis(250);
        assert_eq!(backoff_for(base, 1), base);
        assert_eq!(backoff_for(base, 2), Duration::from_millis(500));
        assert_eq!(backoff_for(base, 3), Duration::from_secs(1));
        // Never longer than the interval the client polls at anyway.
        assert_eq!(backoff_for(base, 30), BACKSTOP_POLL_MAX);
        assert!(backoff_for(Duration::from_secs(3600), 1) <= BACKSTOP_POLL_MAX);
    }

    #[test]
    fn the_healthy_session_threshold_sits_inside_the_backstop_3469() {
        assert!(HEALTHY_SESSION > Duration::ZERO);
        assert!(
            HEALTHY_SESSION < BACKSTOP_POLL_MAX,
            "a session that outlasts the backstop poll is not the bar for 'healthy'; \
             the ladder would then never reset in the case it exists for"
        );
    }

    #[test]
    fn reconnect_jitter_is_bounded_and_not_constant_3469() {
        let span = Duration::from_millis(750);
        let draws: Vec<Duration> = (0..64).map(|_| jitter(span)).collect();
        assert!(draws.iter().all(|d| *d <= span), "jitter must stay in span");
        assert!(
            draws.iter().any(|d| *d != draws[0]),
            "a constant 'jitter' would leave a fleet reconnecting in lockstep"
        );
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn defaults_are_bounded_3469() {
        let cfg = UdsSinkConfig::with_socket_path(PathBuf::from("/tmp/x.sock"));
        assert!(cfg.queue_frames > 0);
        assert!(cfg.handshake_timeout > Duration::ZERO);
        assert!(cfg.reconnect_jitter > Duration::ZERO, "must be jittered");
        assert_eq!(cfg.hub_id, crate::wake_hub::DEFAULT_HUB_ID);
    }

    #[test]
    fn credential_debug_renders_sizes_not_material_3469() {
        let rendered = format!(
            "{:?}",
            HelloCredential {
                pubkey: [7u8; PUBKEY_BYTES],
                signature: [8u8; SIGNATURE_BYTES],
                delegation: Bytes::from_static(b"WIRE-MATERIAL-3469"),
            }
        );
        assert!(rendered.contains("pubkey_bytes"), "{rendered}");
        assert!(!rendered.contains("WIRE-MATERIAL-3469"), "{rendered}");
    }
}
