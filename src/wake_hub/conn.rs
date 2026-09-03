// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! One `wake-hub` connection (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! # Shape
//!
//! Two tasks per connection. The READER ([`run`]) owns the read half and the
//! whole state machine; the WRITER ([`writer_loop`]) owns the write half and
//! one bounded channel. Nothing else ever touches the socket, so per-recipient
//! ordering is a property of the channel rather than of a lock discipline
//! someone has to maintain.
//!
//! # State machine
//!
//! ```text
//!   accept -> peer-cred gate -> hub sends hello(nonce)
//!          -> [PRE-AUTH: 4 frames/s, 8 burst, 5 s deadline]
//!          -> client hello -> verifier -> welcome(+pending) -> [AUTHENTICATED]
//! ```
//!
//! Pre-auth is deliberately austere: a peer that has proved nothing gets a
//! handful of frames and a deadline. Every authenticated frame is charged
//! against a 500/s, burst-2000 token bucket, and a topic wake is charged
//! one extra token per ADDITIONAL recipient, so fan-out amplification is
//! visible to the limiter that is supposed to bound it.
//!
//! # `from` is never trusted
//!
//! After the hello the session is bound to ONE agent id. A frame whose `from`
//! is anything else is refused with `403` and routed nowhere, and the hub
//! stamps the authenticated id on every frame it emits — so even a bug in the
//! check could not turn into a forged sender on the wire.

use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Notify, mpsc, watch};
use tokio_stream::StreamExt;
use tokio_util::codec::{Encoder, FramedRead};

use super::HubState;
use super::codec::codec;
use super::frame::{
    ErrorCode, Frame, HelloPayload, Kind, WakeMeta, WelcomePayload, decode_topics, encode_error,
};
use super::identity::{
    DenyReason, HelloRequest, MembershipAction, MembershipRequest, PeerCred, VerifiedAgent,
};
use super::limits::{EgressBudget, HELLO_NONCE_BYTES, TokenBucket};
use super::routing::{Delivery, Egress, EgressAccount, EgressHandle, SessionId};

/// How long teardown waits for the writer to flush before aborting it. A peer
/// that has stopped reading must not be able to pin a connection slot.
const WRITER_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Everything one connection needs after the peer-credential gate.
struct Conn {
    state: Arc<HubState>,
    peer: PeerCred,
    session: SessionId,
    handle: EgressHandle,
    nonce: [u8; HELLO_NONCE_BYTES],
    agent: Option<VerifiedAgent>,
    bucket: TokenBucket,
    preauth: TokenBucket,
}

/// Serve one accepted connection to completion.
///
/// Never panics and never propagates: a connection failure is that
/// connection's problem — logged, counted, and the hub keeps serving.
pub(super) async fn run(
    state: Arc<HubState>,
    stream: UnixStream,
    peer: PeerCred,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(session) = state.router.alloc_session() else {
        tracing::error!(
            "wake-hub: session handle space exhausted; refusing the connection rather \
             than reusing a live handle"
        );
        return;
    };
    state.metrics.connection_opened();

    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, codec());

    let (tx, rx) = mpsc::channel::<Egress>(state.router.queue_frames());
    let account = Arc::new(EgressAccount::new());
    let closer = Arc::new(Notify::new());
    let handle = EgressHandle::new(
        tx,
        Arc::clone(&account),
        Arc::clone(state.router.egress()),
        Arc::clone(&closer),
        state.router.queue_cap_bytes(),
    );
    let writer_task = tokio::spawn(writer_loop(write_half, rx, account, Arc::clone(&state)));

    let now = Instant::now();
    let mut conn = Conn {
        peer,
        session,
        handle,
        nonce: state.new_nonce(),
        agent: None,
        bucket: TokenBucket::new(state.cfg.rate_per_sec, state.cfg.rate_burst, now),
        preauth: TokenBucket::new(state.cfg.preauth_rate_per_sec, state.cfg.preauth_burst, now),
        state: Arc::clone(&state),
    };

    // The hub speaks first: `hello` carrying THIS connection's challenge nonce.
    // Binding the nonce to the connection is what stops a signature harvested
    // from one handshake being replayed onto another.
    let challenge = Bytes::copy_from_slice(&conn.nonce);
    if conn.send(Kind::Hello, String::new(), challenge) {
        read_loop(&mut conn, &mut reader, &closer, &mut shutdown).await;
    }
    teardown(conn, writer_task).await;
}

/// The reader half's event loop.
async fn read_loop(
    conn: &mut Conn,
    reader: &mut FramedRead<
        tokio::net::unix::OwnedReadHalf,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    closer: &Notify,
    shutdown: &mut watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + conn.state.cfg.handshake_timeout;
    loop {
        let next = tokio::select! {
            biased;
            () = closer.notified() => return,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
                continue;
            }
            // The handshake deadline arms only while unauthenticated: an
            // established session is long-lived by design.
            () = tokio::time::sleep_until(deadline), if conn.agent.is_none() => {
                tracing::debug!(session = conn.session, "wake-hub: handshake deadline expired");
                return;
            }
            item = reader.next() => item,
        };
        let Some(item) = next else { return };
        let body = match item {
            Ok(b) => b,
            Err(e) => {
                // The codec refuses an over-long length prefix BEFORE buffering
                // the body, so an oversize frame lands here.
                conn.state.metrics.denied_malformed();
                tracing::debug!(session = conn.session, error = %e, "wake-hub: framing error");
                let _ = conn.send_error(ErrorCode::TooLarge, "frame exceeds the wire ceiling");
                return;
            }
        };
        conn.state.metrics.frames_in();
        if !conn.handle_body(&body) {
            return;
        }
    }
}

impl Conn {
    /// Handle one decoded body. Returns `false` when the connection must close.
    fn handle_body(&mut self, body: &[u8]) -> bool {
        let now = Instant::now();
        let admitted = if self.agent.is_some() {
            self.bucket.try_take(1, now)
        } else {
            self.preauth.try_take(1, now)
        };
        if !admitted {
            self.state.metrics.rate_limited();
            return self.send_error(ErrorCode::RateLimited, "frame rate exceeded");
        }

        let frame = match Frame::decode(body) {
            Ok(f) => f,
            Err(e) => {
                self.state.metrics.denied_malformed();
                tracing::debug!(session = self.session, error = %e, "wake-hub: refused frame");
                return self.send_error(e.wire_code(), "malformed frame");
            }
        };

        match self.agent.clone() {
            None => self.handle_preauth(&frame),
            Some(agent) => self.handle_authenticated(&agent, &frame, now),
        }
    }

    /// Pre-auth: the ONLY frame accepted is the client's `hello`.
    fn handle_preauth(&mut self, frame: &Frame) -> bool {
        if frame.kind != Kind::Hello {
            self.state.metrics.denied_hello();
            let _ = self.send_error(
                ErrorCode::Unauthorized,
                DenyReason::UnknownAgent.wire_reason(),
            );
            return false;
        }
        let payload = match HelloPayload::decode(&frame.payload) {
            Ok(p) => p,
            Err(e) => {
                self.state.metrics.denied_malformed();
                tracing::debug!(error = %e, "wake-hub: malformed hello");
                let _ = self.send_error(ErrorCode::Malformed, "malformed hello");
                return false;
            }
        };
        let req = HelloRequest {
            hub_id: &self.state.cfg.hub_id,
            nonce: &self.nonce,
            claimed_agent_id: &frame.from,
            pubkey: &payload.pubkey,
            signature: &payload.signature,
            delegation: &payload.delegation,
            topics: &payload.topics,
            peer: self.peer,
        };
        let verified = match self.state.deps.verifier.verify(&req) {
            Ok(v) => v,
            Err(deny) => {
                self.state.metrics.denied_hello();
                tracing::info!(
                    session = self.session,
                    peer_uid = self.peer.uid,
                    reason = deny.label(),
                    "wake-hub: hello DENIED — {deny}"
                );
                // One wire answer for every identity refusal: a peer must not be
                // able to tell "unknown agent" from "bad signature" by probing.
                let _ = self.send_error(deny.wire_code(), deny.wire_reason());
                return false;
            }
        };
        self.admit(verified, &payload.topics)
    }

    /// Install a verified session.
    fn admit(&mut self, verified: VerifiedAgent, topics: &[String]) -> bool {
        let agent = verified.agent_id.clone();
        if !self.state.router.subscribe(&agent, topics) {
            let _ = self.send_error(ErrorCode::Forbidden, "too many topics for one session");
            return false;
        }
        if !self.state.router.note_known(&agent) {
            tracing::warn!(
                agent = %agent,
                "wake-hub: offline-coalescing table is full; this session gets no \
                 pending set (wakes while offline degrade to the backstop poll)"
            );
        }
        if let Some(prior) = self
            .state
            .router
            .register(&agent, self.session, self.handle.clone())
        {
            // A second hello for the same agent id wins; the older session is
            // told why and closed rather than left silently blackholed.
            if let Ok(b) = Frame::new(
                Kind::Error,
                self.state.cfg.hub_id.clone(),
                agent.clone(),
                encode_error(ErrorCode::Replaced, "session replaced"),
            )
            .encode()
            {
                let _ = prior.handle.try_enqueue(b);
            }
            prior.handle.request_close();
            tracing::info!(
                agent = %agent,
                replaced = prior.session,
                by = self.session,
                "wake-hub: session replaced"
            );
        }

        let pending = self.state.router.take_pending(&agent);
        let welcome = WelcomePayload {
            session: self.session,
            pending_count: pending.count(),
            pending_ids: u32::try_from(pending.ids().len()).unwrap_or(u32::MAX),
            lagged: pending.lagged(),
            reconnect_base_ms: self.state.cfg.reconnect_base_ms,
            reconnect_jitter_ms: self.state.cfg.reconnect_jitter_ms,
        };
        self.agent = Some(verified);
        if !self.send(Kind::Welcome, agent.clone(), welcome.encode()) {
            return false;
        }
        // Replay the coalesced ids as wakes. Best-effort: the welcome already
        // carried the authoritative count and the `lagged` marker, so a full
        // queue costs a hint, never a fact.
        for id in pending.ids() {
            let meta = WakeMeta {
                inbox_row_id: id.clone(),
                ..WakeMeta::default()
            };
            let Ok(payload) = meta.encode() else { continue };
            if !self.send(Kind::Wake, agent.clone(), payload) {
                break;
            }
        }
        tracing::info!(session = self.session, agent = %agent, "wake-hub: session established");
        true
    }

    /// Authenticated frame dispatch.
    fn handle_authenticated(&mut self, agent: &VerifiedAgent, frame: &Frame, now: Instant) -> bool {
        // `from` is bound to the hello identity. This is the forged-sender gate.
        if frame.from != agent.agent_id {
            self.state.metrics.denied_forged_from();
            tracing::warn!(
                session = self.session,
                bound = %agent.agent_id,
                claimed = %frame.from,
                "wake-hub: refused a frame whose `from` is not the authenticated identity"
            );
            return self.send_error(
                ErrorCode::Forbidden,
                "from does not match the session identity",
            );
        }
        match frame.kind {
            Kind::Wake => self.route_wake(agent, frame, now),
            Kind::Ping => self.send(Kind::Pong, agent.agent_id.clone(), Bytes::new()),
            Kind::Pong => true,
            Kind::Subscribe | Kind::Unsubscribe => self.handle_subscription(agent, frame),
            Kind::Join => self.handle_membership(agent, frame, MembershipAction::Join),
            Kind::Depart => self.handle_membership(agent, frame, MembershipAction::Depart),
            // A second hello on an established session, or a hub-only kind sent
            // by a client, is a protocol error — never a re-authentication.
            Kind::Hello | Kind::Welcome | Kind::Error => {
                self.state.metrics.denied_malformed();
                self.send_error(ErrorCode::Forbidden, "kind not accepted from a client")
            }
        }
    }

    /// Route one wake: direct to an agent, or fanned out over a topic.
    fn route_wake(&mut self, agent: &VerifiedAgent, frame: &Frame, now: Instant) -> bool {
        let meta = match WakeMeta::decode(&frame.payload) {
            Ok(m) => m,
            Err(e) => {
                self.state.metrics.denied_malformed();
                tracing::debug!(error = %e, "wake-hub: malformed wake metadata");
                return self.send_error(e.wire_code(), "malformed wake metadata");
            }
        };
        if frame.to.is_empty() {
            return self.send_error(ErrorCode::UnknownDestination, "empty destination");
        }

        let recipients = if frame.to_is_topic() {
            self.state
                .router
                .topic_recipients(&frame.to, &agent.agent_id)
        } else {
            vec![frame.to.clone()]
        };

        // Fan-out AMPLIFICATION is charged to the sender. `handle_body`
        // already charged one token for the frame itself, which pays for the
        // first delivery; every ADDITIONAL recipient costs one more. A direct
        // wake therefore costs 1 and a 256-way broadcast costs 256, so
        // amplification cannot hide behind a per-frame cap — which is exactly
        // the defect the adversarial vote found in the original spec.
        let amplification = u32::try_from(recipients.len().saturating_sub(1)).unwrap_or(u32::MAX);
        if amplification > 0 && !self.bucket.try_take(amplification, now) {
            self.state.metrics.rate_limited();
            return self.send_error(ErrorCode::RateLimited, "fan-out exceeds the frame budget");
        }

        // Encode ONCE; every recipient shares this buffer by refcount.
        let encoded = match (Frame {
            from: agent.agent_id.clone(),
            to: frame.to.clone(),
            kind: Kind::Wake,
            ts_ms: frame.ts_ms,
            ttl_ms: frame.ttl_ms,
            payload: frame.payload.clone(),
        })
        .encode()
        {
            Ok(b) => b,
            Err(e) => {
                self.state.metrics.denied_malformed();
                return self.send_error(e.wire_code(), "wake could not be re-encoded");
            }
        };

        self.state.metrics.wakes_routed();
        self.state
            .metrics
            .add_fanout(u64::try_from(recipients.len()).unwrap_or(u64::MAX));

        let mut overflowed = false;
        let mut unknown = false;
        for r in &recipients {
            match self.state.router.deliver(r, &encoded, &meta.inbox_row_id) {
                Delivery::Delivered | Delivery::Coalesced => {}
                Delivery::Overflow => overflowed = true,
                Delivery::DroppedUnknown => unknown = true,
            }
        }
        // Refuse LOUDLY to the sender. Overflow outranks unknown: a full queue
        // is a capacity fact the sender can back off on, an unknown destination
        // is a routing fact it can correct.
        if overflowed {
            return self.send_error(
                ErrorCode::Overflow,
                "recipient queue or hub egress budget full",
            );
        }
        if unknown && !frame.to_is_topic() {
            return self.send_error(ErrorCode::UnknownDestination, "no such agent");
        }
        true
    }

    /// Add or remove topics.
    fn handle_subscription(&mut self, agent: &VerifiedAgent, frame: &Frame) -> bool {
        let topics = match decode_topics(&frame.payload) {
            Ok(t) => t,
            Err(e) => {
                self.state.metrics.denied_malformed();
                return self.send_error(e.wire_code(), "malformed topic list");
            }
        };
        if frame.kind == Kind::Subscribe {
            if self.state.router.subscribe(&agent.agent_id, &topics) {
                true
            } else {
                self.send_error(ErrorCode::Forbidden, "too many topics for one session")
            }
        } else {
            self.state.router.unsubscribe(&agent.agent_id, &topics);
            true
        }
    }

    /// Nonce-bound `join` / `depart`.
    ///
    /// Both are refused by the shipped verifier. Membership admission and
    /// revocation are audit-spine events in the durable identity root (#3468),
    /// so a hub with no verifier wired must not be able to grant or destroy
    /// membership.
    fn handle_membership(
        &mut self,
        agent: &VerifiedAgent,
        frame: &Frame,
        action: MembershipAction,
    ) -> bool {
        let req = MembershipRequest {
            action,
            hub_id: &self.state.cfg.hub_id,
            nonce: &self.nonce,
            agent_id: &agent.agent_id,
            pubkey: &agent.pubkey,
            signature: &frame.payload,
            peer: self.peer,
        };
        if let Err(deny) = self.state.deps.verifier.verify_membership(&req) {
            self.state.metrics.denied_hello();
            tracing::info!(
                session = self.session,
                agent = %agent.agent_id,
                action = ?action,
                reason = deny.label(),
                "wake-hub: membership change DENIED — {deny}"
            );
            return self.send_error(deny.wire_code(), deny.wire_reason());
        }
        if action == MembershipAction::Join {
            // Hub-core keeps NO membership state of its own — the verifier IS
            // the allowlist, and admission/revocation are audit-spine events in
            // the durable identity root (#3468). A verified `join` is therefore
            // a no-op here BY DESIGN, not an oversight: there is nothing for a
            // disposable, content-free transport to durably admit.
            tracing::info!(
                agent = %agent.agent_id,
                "wake-hub: join verified; membership state lives in the ai-memory \
                 identity root, not the hub"
            );
            return true;
        }
        if action == MembershipAction::Depart {
            // Disconnect is NOT depart; depart is. Forget the agent's routing
            // and offline state, then close.
            self.state.router.forget(&agent.agent_id);
            tracing::info!(agent = %agent.agent_id, "wake-hub: agent departed");
            return false;
        }
        true
    }

    /// Enqueue a frame from the hub. Returns `false` when the connection must
    /// close because its own control frame would not fit.
    fn send(&self, kind: Kind, to: String, payload: Bytes) -> bool {
        match Frame::new(kind, self.state.cfg.hub_id.clone(), to, payload).encode() {
            Ok(bytes) => self.handle.try_enqueue(bytes),
            Err(e) => {
                tracing::error!(error = %e, kind = %kind, "wake-hub: refused to emit its own frame");
                false
            }
        }
    }

    /// Send an `error` to the peer. Returns `false` for the fatal codes — the
    /// ones after which continuing to read would be pretending the peer is
    /// still speaking the protocol.
    fn send_error(&self, code: ErrorCode, reason: &'static str) -> bool {
        let to = self
            .agent
            .as_ref()
            .map_or_else(String::new, |a| a.agent_id.clone());
        let queued = self.send(Kind::Error, to, encode_error(code, reason));
        queued
            && !matches!(
                code,
                ErrorCode::Unauthorized | ErrorCode::Malformed | ErrorCode::TooLarge
            )
    }
}

/// Release everything one connection owns.
///
/// Ordering matters: unregister the route, drop the last sender (which closes
/// the writer channel), wait a BOUNDED time for the writer, then release the
/// session handle and the connection gauge — so a connection is always fully
/// reaped, even against a peer that has stopped reading.
async fn teardown(conn: Conn, mut writer_task: tokio::task::JoinHandle<()>) {
    let Conn {
        state,
        session,
        handle,
        agent,
        ..
    } = conn;
    if let Some(agent) = &agent {
        // Compare-and-remove: a slow teardown must never delete the route a
        // REPLACEMENT session already installed.
        if state.router.unregister(&agent.agent_id, session) {
            state.router.unsubscribe_all(&agent.agent_id);
        }
    }
    handle.request_close();
    // Dropping the last sender is what closes the writer channel, so the writer
    // task terminates even when its queue was full and the `Close` sentinel
    // could not be enqueued.
    drop(handle);
    // BOUNDED wait. A peer that stops reading leaves the writer parked in
    // `write_all` once the kernel buffers fill; waiting on it forever would
    // pin this connection's semaphore permit and never decrement
    // `connections_current`, so the ceiling would leak one slot per such peer
    // and the SIGTERM drain would always time out. Abort instead — the writer
    // releases every byte it still accounts for from its `Drop`, so an abort
    // at any point leaks nothing from the budgets.
    if tokio::time::timeout(WRITER_DRAIN_GRACE, &mut writer_task)
        .await
        .is_err()
    {
        tracing::warn!(
            session,
            "wake-hub: writer did not drain within the grace period (peer stopped \
             reading); aborting it so the connection slot is not pinned"
        );
        writer_task.abort();
    }
    state.router.release_session(session);
    state.metrics.connection_closed();
}

/// Drain the writer channel to the socket.
///
/// The ONLY place bytes leave the hub. Egress reservations are released here
/// and — for anything still sitting in the channel when the task ends or is
/// aborted — in [`WriterQueue`]'s `Drop`, so the byte budgets can never be
/// left holding a reservation for a connection that is gone.
async fn writer_loop(
    mut write_half: OwnedWriteHalf,
    rx: mpsc::Receiver<Egress>,
    account: Arc<EgressAccount>,
    state: Arc<HubState>,
) {
    let mut encoder = codec();
    let mut out = BytesMut::new();
    let mut queue = WriterQueue {
        rx,
        account,
        egress: Arc::clone(state.router.egress()),
    };
    while let Some(item) = queue.rx.recv().await {
        let Egress::Frame(bytes) = item else { break };
        let len = bytes.len();
        out.clear();
        // The SAME `max_frame_length` the reader enforces, applied on the way
        // out: the hub can never emit a frame it would refuse to read.
        let framed = encoder.encode(bytes, &mut out).is_ok();
        // Release BEFORE awaiting the write. The budgets exist to bound what
        // the HUB is holding; once encoded, the frame is one bounded buffer on
        // its way to the kernel (at most `MAX_FRAME_BYTES` per connection).
        // Releasing first is also what makes this task safe to abort at any
        // await point without stranding a reservation.
        queue.release(len);
        if !framed || write_half.write_all(&out).await.is_err() {
            break;
        }
        state.metrics.add_frames_out(1);
    }
    drop(queue);
    let _ = write_half.shutdown().await;
}

/// The writer's end of one connection's queue, with its byte accounting.
///
/// `Drop` releases every reservation still sitting in the channel, so a writer
/// that is aborted (or unwound) can never leak bytes out of the per-recipient
/// or hub-wide budget — a leak there would permanently shrink the hub's
/// capacity, which is the slow-motion version of the overflow it exists to
/// prevent.
struct WriterQueue {
    rx: mpsc::Receiver<Egress>,
    account: Arc<EgressAccount>,
    egress: Arc<EgressBudget>,
}

impl WriterQueue {
    fn release(&self, len: usize) {
        self.account.release(len);
        self.egress.release(len);
    }
}

impl Drop for WriterQueue {
    fn drop(&mut self) {
        // Infallible by construction: saturating releases, no allocation, no
        // panic (`OWNERSHIP-25` — a panic here during unwinding would abort).
        self.rx.close();
        while let Ok(item) = self.rx.try_recv() {
            if let Egress::Frame(bytes) = item {
                let len = bytes.len();
                self.account.release(len);
                self.egress.release(len);
            }
        }
    }
}
