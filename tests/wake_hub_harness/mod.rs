// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the `ai-memory wake-hub` integration suites (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! Lives in `tests/wake_hub_harness/` — a directory with no `main.rs`, so
//! cargo does NOT build it as its own integration-test target. Only the
//! binaries that declare `mod wake_hub_harness;` compile it (the same idiom
//! `tests/common/` uses), which keeps it off the other ~740 test binaries.
//!
//! # The test verifier is real cryptography, not a stub
//!
//! [`TestVerifier`] performs a genuine Ed25519 `verify_strict` over the
//! domain-separated transcript the hub builds. That matters: a stub verifier
//! that returned `Ok` for everything would make the ALLOWED path pass while
//! proving nothing about the transcript, and would leave the bad-signature
//! DENIED path untestable. It lives HERE and not in `src/` so the shipped
//! binary contains no permissive verifier at all.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::wake_hub::frame::{
    Frame, HelloPayload, Kind, WakeMeta, decode_error, decode_topics, encode_topics,
};
use ai_memory::wake_hub::identity::{
    DenyReason, HelloRequest, HelloVerifier, MembershipRequest, PeerAuthorizer, SameUidAuthorizer,
    VerifiedAgent, hello_transcript, membership_transcript, topics_hash,
};
use ai_memory::wake_hub::limits::EgressBudget;
use ai_memory::wake_hub::metrics::HubMetrics;
use ai_memory::wake_hub::routing::Router;
use ai_memory::wake_hub::{HubConfig, HubDeps, WakeHub};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use std::os::unix::fs::PermissionsExt;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Allowlist-backed verifier that checks a real signature over the real
/// transcript.
#[derive(Debug, Default)]
pub struct TestVerifier {
    allow: HashMap<String, VerifyingKey>,
    /// When set, `verify_topics` refuses EVERY topic — the shape of the
    /// #3468/#3505 scope gate turning a subscribe down, isolated from the
    /// handshake gate. Off by default, so an existing suite is unaffected.
    refuse_topics: bool,
}

impl TestVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, agent_id: &str, key: &SigningKey) -> &mut Self {
        self.allow.insert(agent_id.to_string(), key.verifying_key());
        self
    }

    /// Refuse every topic this verifier is asked about (#3532).
    pub fn refuse_topics(&mut self) -> &mut Self {
        self.refuse_topics = true;
        self
    }
}

impl HelloVerifier for TestVerifier {
    fn verify(&self, req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason> {
        let expected = self
            .allow
            .get(req.claimed_agent_id)
            .ok_or(DenyReason::UnknownAgent)?;
        let presented =
            VerifyingKey::from_bytes(req.pubkey).map_err(|_| DenyReason::BadSignature)?;
        if presented != *expected {
            return Err(DenyReason::KeyMismatch);
        }
        let sig = ed25519_dalek::Signature::from_slice(req.signature)
            .map_err(|_| DenyReason::BadSignature)?;
        expected
            .verify(&req.transcript(), &sig)
            .map_err(|_| DenyReason::BadSignature)?;
        Ok(VerifiedAgent {
            agent_id: req.claimed_agent_id.to_string(),
            pubkey: *req.pubkey,
        })
    }

    fn verify_topics(&self, _agent_id: &str, _topics: &[String]) -> Result<(), DenyReason> {
        if self.refuse_topics {
            return Err(DenyReason::UnknownAgent);
        }
        Ok(())
    }

    fn verify_membership(&self, req: &MembershipRequest<'_>) -> Result<(), DenyReason> {
        let expected = self
            .allow
            .get(req.agent_id)
            .ok_or(DenyReason::UnknownAgent)?;
        let sig = ed25519_dalek::Signature::from_slice(req.signature)
            .map_err(|_| DenyReason::BadSignature)?;
        expected
            .verify(&req.transcript(), &sig)
            .map_err(|_| DenyReason::BadSignature)
    }
}

/// A bound, running hub plus everything a test needs to drive and stop it.
pub struct Harness {
    pub socket: PathBuf,
    pub hub_id: String,
    pub metrics: Arc<HubMetrics>,
    /// The ceiling the hub computed for itself from `RLIMIT_NOFILE`, which may
    /// be lower than the configured `max_connections` (macOS defaults to a
    /// 256-fd soft limit, the exact case the adversarial vote flagged).
    pub connection_ceiling: usize,
    /// The hub's routing table, taken BEFORE `serve` consumed the hub (#3469).
    router: Arc<Router>,
    egress: Arc<EgressBudget>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// Bind and serve a hub with the given config mutation and gates.
    ///
    /// # Panics
    ///
    /// On any start-up refusal — in a test that IS the failure.
    pub fn start(
        mutate: impl FnOnce(&mut HubConfig),
        verifier: Arc<dyn HelloVerifier>,
        authorizer: Arc<dyn PeerAuthorizer>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // The socket's privacy rests on an owner-only parent; assert it here
        // rather than trusting the ambient umask (the pool runs tests under
        // `umask 022`, and #3198's key-dir guard exists for the same reason).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        // Short name: AF_UNIX `sun_path` is 104 bytes on macOS and the CI
        // TMPDIR there is already ~50 characters deep.
        let socket = dir.path().join("h.sock");
        let mut cfg = HubConfig::with_socket_path(socket.clone());
        mutate(&mut cfg);
        let hub_id = cfg.hub_id.clone();
        let hub = WakeHub::bind(
            cfg,
            HubDeps {
                peer_authorizer: authorizer,
                verifier,
            },
        )
        .expect("wake-hub bind");
        let metrics = hub.metrics();
        let router = hub.router();
        let egress = hub.egress_budget();
        let connection_ceiling = hub.fd_budget().connection_ceiling;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = hub
                .serve(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Self {
            socket,
            hub_id,
            metrics,
            connection_ceiling,
            router,
            egress,
            shutdown: Some(tx),
            task: Some(task),
            _dir: dir,
        }
    }

    /// The hub's routing table, so a test can inject a substrate wake the way
    /// a co-hosted daemon does (#3469).
    #[must_use]
    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// Bytes currently reserved in the hub-wide egress budget.
    #[must_use]
    pub fn snapshot_egress(&self) -> usize {
        self.egress.used()
    }

    /// The common case: a real-signature verifier and the same-uid peer gate.
    pub fn with_verifier(verifier: TestVerifier) -> Self {
        Self::start(
            |_| {},
            Arc::new(verifier),
            Arc::new(SameUidAuthorizer::for_current_process()),
        )
    }

    /// Connect a raw client.
    pub async fn connect(&self) -> Client {
        Client::connect(&self.socket, &self.hub_id).await
    }

    /// Stop the hub and wait for the accept loop to drain.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), t).await;
        }
    }
}

/// A raw wake-hub client: length-prefixed frames straight onto the socket, so
/// a test can send bytes the library API would refuse to construct.
pub struct Client {
    stream: UnixStream,
    hub_id: String,
    pub nonce: [u8; 32],
    pub agent_id: String,
    /// The scoped delegation this client presents in its `hello` (#3468).
    /// Empty by default, which every production verifier refuses.
    pub delegation: Bytes,
}

impl Client {
    /// Connect and consume the hub's `hello` challenge.
    ///
    /// # Panics
    ///
    /// On a connect or handshake I/O failure.
    pub async fn connect(path: &Path, hub_id: &str) -> Self {
        let stream = UnixStream::connect(path).await.expect("connect");
        let mut c = Self {
            stream,
            hub_id: hub_id.to_string(),
            nonce: [0u8; 32],
            agent_id: String::new(),
            delegation: Bytes::new(),
        };
        let challenge = c
            .read_frame()
            .await
            .expect("hub speaks first with a challenge");
        assert_eq!(
            challenge.kind,
            Kind::Hello,
            "the hub's first frame is the challenge"
        );
        assert_eq!(challenge.payload.len(), 32, "challenge nonce is 32 bytes");
        c.nonce.copy_from_slice(&challenge.payload);
        c
    }

    /// Complete the handshake with a real signature over the real transcript.
    ///
    /// # Panics
    ///
    /// On an I/O failure.
    pub async fn hello(&mut self, agent_id: &str, key: &SigningKey, topics: &[String]) {
        let nonce = self.nonce;
        let payload = self.signed_hello(agent_id, key, topics, &nonce);
        self.agent_id = agent_id.to_string();
        self.send(Frame::new(Kind::Hello, agent_id, "", payload))
            .await;
    }

    /// Build a signed `hello` payload, optionally over a nonce the hub did NOT
    /// issue (the replay case).
    ///
    /// # Panics
    ///
    /// On a topic-list encoding failure.
    pub fn signed_hello(
        &self,
        agent_id: &str,
        key: &SigningKey,
        topics: &[String],
        nonce: &[u8; 32],
    ) -> Bytes {
        let transcript = hello_transcript(&self.hub_id, nonce, agent_id, &topics_hash(topics));
        let sig = key.sign(&transcript);
        HelloPayload {
            pubkey: key.verifying_key().to_bytes(),
            signature: sig.to_bytes(),
            delegation: self.delegation.clone(),
            topics: topics.to_vec(),
        }
        .encode()
        .expect("hello payload")
    }

    /// Sign a nonce-bound membership frame.
    #[must_use]
    pub fn signed_membership(
        &self,
        action: ai_memory::wake_hub::identity::MembershipAction,
        agent_id: &str,
        key: &SigningKey,
    ) -> Bytes {
        let t = membership_transcript(action, &self.hub_id, &self.nonce, agent_id);
        Bytes::copy_from_slice(&key.sign(&t).to_bytes())
    }

    /// Send a `subscribe` for `topics`.
    ///
    /// # Panics
    ///
    /// On a topic-list encoding failure.
    pub async fn subscribe(&mut self, topics: &[String]) {
        let payload = encode_topics(topics).expect("topics");
        let from = self.agent_id.clone();
        self.send(Frame::new(Kind::Subscribe, from, "", payload))
            .await;
    }

    /// Send a `subscribe` and WAIT for the hub's #3532 acknowledgement,
    /// returning the topics it acknowledged.
    ///
    /// This is the deterministic replacement for "subscribe, then round-trip a
    /// ping so the router is known to have processed it": the hub registers
    /// the topics BEFORE it mints the ack, so when this returns, a wake any
    /// peer addresses to those topics is routed against a table that already
    /// contains this session. No sleeps, no ping, no ordering assumption
    /// beyond the one the connection itself guarantees.
    ///
    /// STRICT on purpose: it asserts the ack is the very NEXT frame. A wake
    /// for a topic this session already held could legitimately arrive first
    /// on a live hub, so a production client must drain while it waits (see
    /// `SessionEvent::Subscribed`) — but a test that hits that case has a
    /// peer racing its own subscribe, and failing loudly is the right answer
    /// there.
    ///
    /// # Panics
    ///
    /// On a topic-list encoding failure, a timeout, or an answer that is not
    /// the matching acknowledgement.
    pub async fn subscribe_acked(&mut self, topics: &[String]) -> Vec<String> {
        self.subscription_acked(Kind::Subscribe, topics).await
    }

    /// Send an `unsubscribe` and wait for its acknowledgement.
    ///
    /// The dual guarantee: once this returns, no further wake for those topics
    /// will be routed to this session.
    ///
    /// # Panics
    ///
    /// As [`Client::subscribe_acked`].
    pub async fn unsubscribe_acked(&mut self, topics: &[String]) -> Vec<String> {
        self.subscription_acked(Kind::Unsubscribe, topics).await
    }

    async fn subscription_acked(&mut self, kind: Kind, topics: &[String]) -> Vec<String> {
        let payload = encode_topics(topics).expect("topics");
        let from = self.agent_id.clone();
        self.send(Frame::new(kind, from, "", payload)).await;
        let ack = self.expect_frame().await;
        assert_eq!(
            ack.kind, kind,
            "#3532: a {kind} the hub applied is acknowledged with a {kind}, got {}",
            ack.kind
        );
        let acked = decode_topics(&ack.payload).expect("the ack carries a topic list");
        assert_eq!(
            acked, topics,
            "#3532: the ack must name exactly the topics that were applied"
        );
        acked
    }

    /// Send a `wake` to `to` referencing `inbox_row_id`.
    ///
    /// # Panics
    ///
    /// On a metadata encoding failure.
    pub async fn wake(&mut self, to: &str, inbox_row_id: &str) {
        let payload = WakeMeta {
            inbox_row_id: inbox_row_id.to_string(),
            namespace: "hive".into(),
            sender: self.agent_id.clone(),
            digest: vec![7u8; 32],
            seq_high_watermark: 1,
        }
        .encode()
        .expect("wake meta");
        let from = self.agent_id.clone();
        self.send(Frame::new(Kind::Wake, from, to, payload)).await;
    }

    /// Encode and write one frame.
    ///
    /// # Panics
    ///
    /// On an encode or I/O failure.
    pub async fn send(&mut self, frame: Frame) {
        let body = frame.encode().expect("encode");
        self.write_raw_framed(&body).await;
    }

    /// Write an arbitrary body with a correct length prefix.
    ///
    /// # Panics
    ///
    /// On an I/O failure.
    pub async fn write_raw_framed(&mut self, body: &[u8]) {
        let len = u32::try_from(body.len()).expect("len");
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .expect("write len");
        self.stream.write_all(body).await.expect("write body");
        self.stream.flush().await.expect("flush");
    }

    /// Write a raw length prefix and nothing else — used to make the hub
    /// evaluate an oversize declaration without sending the bytes.
    ///
    /// # Panics
    ///
    /// On an I/O failure.
    pub async fn write_length_prefix(&mut self, declared: u32) {
        self.stream
            .write_all(&declared.to_be_bytes())
            .await
            .expect("write len");
        self.stream.flush().await.expect("flush");
    }

    /// Half-close: shut down only our WRITE side, so the hub sees EOF on its
    /// reader while we keep the read side open and never drain it. This is the
    /// shape that pins a connection slot if teardown waits unboundedly on a
    /// parked writer.
    ///
    /// # Panics
    ///
    /// On an I/O failure.
    pub async fn shutdown_write(&mut self) {
        self.stream.shutdown().await.expect("shutdown write half");
    }

    /// Read one frame, or `None` at EOF.
    pub async fn read_frame(&mut self) -> Option<Frame> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await.ok()?;
        let n = usize::try_from(u32::from_be_bytes(len)).ok()?;
        let mut body = vec![0u8; n];
        self.stream.read_exact(&mut body).await.ok()?;
        Frame::decode(&body).ok()
    }

    /// Read one frame, failing the test on timeout.
    ///
    /// # Panics
    ///
    /// When no frame arrives within two seconds.
    pub async fn expect_frame(&mut self) -> Frame {
        tokio::time::timeout(std::time::Duration::from_secs(2), self.read_frame())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection closed while a frame was expected")
    }

    /// Read one frame and assert it is an `error` with `code`, returning the
    /// reason string.
    ///
    /// # Panics
    ///
    /// When the frame is not an error, or the code differs.
    pub async fn expect_error(&mut self, code: u16) -> String {
        let f = self.expect_frame().await;
        assert_eq!(
            f.kind,
            Kind::Error,
            "expected an error frame, got {}",
            f.kind
        );
        let (got, reason) = decode_error(&f.payload).expect("error payload");
        assert_eq!(got, code, "expected error {code}, got {got} ({reason})");
        reason
    }

    /// Assert the hub closed the connection.
    ///
    /// # Panics
    ///
    /// When a frame arrives instead of EOF, or nothing happens in two seconds.
    pub async fn expect_closed(&mut self) {
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let mut b = [0u8; 1];
                match self.stream.read(&mut b).await {
                    Ok(0) | Err(_) => return true,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            matches!(closed, Ok(true)),
            "the hub should have closed the connection"
        );
    }
}

// ---------------------------------------------------------------------------
// Shared live-store guard (#3468 rule, applied to every pg cell of the wake-hub
// suites after the 3017ea05 coverage red)
// ---------------------------------------------------------------------------

/// The database segment of a `postgres://user:pass@host:port/db?params` URL.
pub fn database_name(url: &str) -> &str {
    url.split('/')
        .next_back()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
}

/// The port segment of a `postgres://user:pass@host:port/db` URL, if any.
pub fn port_of(url: &str) -> Option<u16> {
    let authority = url.split("//").nth(1)?.split('/').next()?;
    let host_port = authority.rsplit('@').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// The certified tier's port on both nodes; the `:9077` test-fleet daemon's
/// shared `ai_memory_test` database lives there and nowhere else.
pub const SHARED_LIVE_STORE_PORT: u16 = 5445;

/// True only for the shared live store: the `ai_memory_test` database on the
/// certified tier's port. A same-named database on any other port — the CI
/// coverage workflow's throwaway service container on `:5432` — is not the
/// live store and may be used. A guard on the NAME alone can never run in
/// that workflow (seen on the `3017ea05` campaign), so this is the one
/// predicate every pg cell in these suites must use.
pub fn is_shared_live_store(url: &str) -> bool {
    database_name(url) == "ai_memory_test" && port_of(url) == Some(SHARED_LIVE_STORE_PORT)
}

#[test]
fn shared_live_store_guard_cases() {
    assert!(is_shared_live_store(
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test?sslmode=verify-full"
    ));
    assert!(is_shared_live_store(
        "postgres://ai_memory:pw@localhost:5445/ai_memory_test"
    ));
    // CI coverage service container: same name, throwaway port — ALLOWED.
    assert!(!is_shared_live_store(
        "postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test"
    ));
    // Isolated lane / gate databases on the certified tier — ALLOWED.
    assert!(!is_shared_live_store(
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_gate_if1c?sslmode=verify-full"
    ));
    assert_eq!(
        database_name("postgres://u:p@h:5445/ai_memory_test?x=1"),
        "ai_memory_test"
    );
    assert_eq!(port_of("postgres://u:p@h:5445/db"), Some(5445));
    assert_eq!(port_of("postgres://u:p@h/db"), None);
}
