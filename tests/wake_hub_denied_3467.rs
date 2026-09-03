// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` — the DENIED half of the charter's both-paths bar
//! (issue [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! Every case here drives a REAL Unix domain socket in a tempdir, so the gate
//! under test is the one the shipped binary runs, not a mock of it. The ALLOWED
//! twin is `tests/wake_hub_allowed_3467.rs`.
//!
//! Coverage: wrong peer uid, the shipped deny-all verifier, unknown agent, bad
//! signature, a replayed nonce, a non-`hello` first frame, malformed frames, an
//! oversize frame, the removed `request`/`reply`/`notify` payload kinds, an
//! over-long id, a forged `from`, queue overflow, the connection-slot reap after
//! that overflow, the pre-auth rate limit, the per-session topic cap, and
//! membership changes without a wired verifier.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::wake_hub::frame::{
    ErrorCode, Frame, Kind, RESERVED_PAYLOAD_KINDS, WakeMeta, decode_error, encode_topics,
};
use ai_memory::wake_hub::identity::{
    DenyReason, HelloRequest, HelloVerifier, SameUidAuthorizer, VerifiedAgent,
};
use ai_memory::wake_hub::limits::{MAX_FRAME_BYTES, MAX_ID_BYTES};
use ai_memory::wake_hub::{HubConfig, HubDeps};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use wake_hub_harness::{Harness, TestVerifier};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn verifier_allowing(agents: &[(&str, &SigningKey)]) -> TestVerifier {
    let mut verifier = TestVerifier::new();
    for (id, signing_key) in agents {
        verifier.allow(id, signing_key);
    }
    verifier
}

fn wake_metadata(inbox_row_id: &str) -> Bytes {
    WakeMeta {
        inbox_row_id: inbox_row_id.to_string(),
        ..WakeMeta::default()
    }
    .encode()
    .expect("wake metadata")
}

// ---------------------------------------------------------------------------
// Peer credentials
// ---------------------------------------------------------------------------

/// A bare socket wrapper for the pre-challenge case, where the harness
/// `Client` (which asserts that a challenge arrives) would be wrong to use.
struct RawPeer {
    stream: tokio::net::UnixStream,
}

impl RawPeer {
    async fn read_frame(&mut self) -> Option<Frame> {
        use tokio::io::AsyncReadExt;
        let mut len = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), self.stream.read_exact(&mut len))
            .await
            .ok()?
            .ok()?;
        let declared = usize::try_from(u32::from_be_bytes(len)).ok()?;
        let mut body = vec![0u8; declared];
        self.stream.read_exact(&mut body).await.ok()?;
        Frame::decode(&body).ok()
    }
}

#[tokio::test]
async fn denied_wrong_peer_uid_is_refused_before_a_byte_is_read() {
    // SAFETY: `geteuid` reads a process property and cannot fail.
    let mine = unsafe { libc::geteuid() };
    let hub = Harness::start(
        |_| {},
        Arc::new(TestVerifier::new()),
        Arc::new(SameUidAuthorizer::with_uid(mine.wrapping_add(1))),
    );

    let stream = tokio::net::UnixStream::connect(&hub.socket)
        .await
        .expect("the socket accepts a connection");
    let mut peer = RawPeer { stream };
    // The refusal is a 401 and then EOF — and critically the hub never sent the
    // `hello` challenge, because it refused before reading or writing any
    // protocol at all.
    if let Some(first) = peer.read_frame().await {
        assert_eq!(
            first.kind,
            Kind::Error,
            "a denied peer gets an error, never a challenge"
        );
        let (code, _) = decode_error(&first.payload).expect("error payload");
        assert_eq!(code, ErrorCode::Unauthorized.as_u16());
    }

    let mut counters = hub.metrics.snapshot(0);
    for _ in 0..100 {
        if counters.denied_peer_cred > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        counters = hub.metrics.snapshot(0);
    }
    assert_eq!(counters.denied_peer_cred, 1, "the refusal must be counted");
    assert_eq!(
        counters.frames_in, 0,
        "a denied peer's bytes are never parsed"
    );
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_the_shipped_verifier_refuses_every_hello() {
    // No verifier override at all: exactly what `ai-memory wake-hub` runs.
    let hub = Harness::start(
        |_| {},
        HubDeps::default().verifier,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut client = hub.connect().await;
    client.hello("agent-a", &key(1), &[]).await;
    let reason = client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    assert_eq!(reason, "unauthorized", "the wire answer carries no detail");
    client.expect_closed().await;
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 1);
    hub.stop().await;
}

#[tokio::test]
async fn denied_unknown_agent_and_bad_signature_are_indistinguishable_on_the_wire() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));

    // (1) an agent the allowlist has never heard of
    let mut stranger = hub.connect().await;
    stranger.hello("agent-zzz", &key(9), &[]).await;
    let unknown_reason = stranger
        .expect_error(ErrorCode::Unauthorized.as_u16())
        .await;
    stranger.expect_closed().await;

    // (2) a known agent signing with the wrong key
    let mut impostor = hub.connect().await;
    impostor.hello("agent-a", &key(2), &[]).await;
    let bad_sig_reason = impostor
        .expect_error(ErrorCode::Unauthorized.as_u16())
        .await;
    impostor.expect_closed().await;

    assert_eq!(
        unknown_reason, bad_sig_reason,
        "an attacker must not be able to enumerate valid agent ids by comparing refusals"
    );
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 2);
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_signature_over_a_nonce_the_hub_did_not_issue() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));

    // Harvest a real, valid signature from one connection...
    let first = hub.connect().await;
    let harvested_nonce = first.nonce;
    let harvested = first.signed_hello("agent-a", &key_a, &[], &harvested_nonce);

    // ...and replay it verbatim onto a SECOND connection, which carries a
    // different challenge. The transcript binds the nonce, so it must fail.
    let mut second = hub.connect().await;
    assert_ne!(
        second.nonce, harvested_nonce,
        "each connection gets a fresh challenge"
    );
    second
        .send(Frame::new(Kind::Hello, "agent-a", "", harvested))
        .await;
    second.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    second.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_non_hello_first_frame_never_reaches_the_router() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));
    let mut client = hub.connect().await;
    // A wake before authenticating.
    client
        .send(Frame::new(
            Kind::Wake,
            "agent-a",
            "agent-b",
            wake_metadata("row-1"),
        ))
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    client.expect_closed().await;
    assert_eq!(
        hub.metrics.snapshot(0).wakes_routed,
        0,
        "an unauthenticated wake must never be routed"
    );
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_a_malformed_frame_is_refused_and_closes_the_connection() {
    let hub = Harness::with_verifier(TestVerifier::new());
    let mut client = hub.connect().await;
    // Valid length prefix, garbage body: wrong magic.
    client
        .write_raw_framed(b"NOPE\x01\x01\x00\x00\x00\x00\x00\x00")
        .await;
    client.expect_error(ErrorCode::Malformed.as_u16()).await;
    client.expect_closed().await;
    assert!(hub.metrics.snapshot(0).denied_malformed >= 1);
    hub.stop().await;
}

#[tokio::test]
async fn denied_an_oversize_frame_is_refused_on_the_length_prefix_alone() {
    let hub = Harness::with_verifier(TestVerifier::new());
    let mut client = hub.connect().await;
    // Announce a 4 GiB frame and send NOTHING. The codec's max_frame_length
    // must refuse on the header, before a byte of body is buffered — that is
    // the difference between a bounded hub and a one-connection OOM.
    client.write_length_prefix(u32::MAX).await;
    client.expect_error(ErrorCode::TooLarge.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_frame_one_byte_over_the_ceiling_is_refused() {
    let hub = Harness::with_verifier(TestVerifier::new());
    let mut client = hub.connect().await;
    client.write_raw_framed(&[0u8; MAX_FRAME_BYTES + 1]).await;
    client.expect_error(ErrorCode::TooLarge.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_the_removed_payload_kinds_are_refused_by_number() {
    for reserved in RESERVED_PAYLOAD_KINDS {
        let hub = Harness::with_verifier(TestVerifier::new());
        let mut client = hub.connect().await;
        // A well-formed frame whose kind byte is request / reply / notify.
        let mut body = Frame::new(Kind::Wake, "agent-a", "agent-b", Bytes::new())
            .encode()
            .expect("encode")
            .to_vec();
        body[5] = reserved;
        client.write_raw_framed(&body).await;
        client.expect_error(ErrorCode::Malformed.as_u16()).await;
        client.expect_closed().await;
        hub.stop().await;
    }
}

#[tokio::test]
async fn denied_an_id_over_the_ceiling_is_refused_not_truncated() {
    let hub = Harness::with_verifier(TestVerifier::new());
    let mut client = hub.connect().await;
    // Hand-build a body that declares a 128-byte `from` but carries 129, which
    // is how an over-long id can even be expressed on a wire whose length field
    // is one byte. Either way it is a refusal, never a truncation.
    let mut body = Vec::new();
    body.extend_from_slice(b"AWH1");
    body.push(1); // version
    body.push(Kind::Wake.as_u8());
    body.push(0); // flags
    body.push(u8::try_from(MAX_ID_BYTES).expect("128 fits u8")); // from_len
    body.push(0); // to_len
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_be_bytes()); // payload_len
    body.extend_from_slice(&0u64.to_be_bytes()); // ts_ms
    body.extend_from_slice(&0u32.to_be_bytes()); // ttl_ms
    body.resize(body.len() + MAX_ID_BYTES + 1, b'x');
    client.write_raw_framed(&body).await;
    client.expect_error(ErrorCode::Malformed.as_u16()).await;
    client.expect_closed().await;
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// Authenticated-session refusals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_a_forged_from_is_refused_and_routed_nowhere() {
    let key_a = key(1);
    let key_b = key(2);
    let hub = Harness::with_verifier(verifier_allowing(&[
        ("agent-a", &key_a),
        ("agent-b", &key_b),
    ]));

    let mut recipient = hub.connect().await;
    recipient.hello("agent-b", &key_b, &[]).await;
    assert_eq!(recipient.expect_frame().await.kind, Kind::Welcome);

    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    // agent-a claims to be agent-b.
    sender
        .send(Frame::new(
            Kind::Wake,
            "agent-b",
            "agent-b",
            wake_metadata("row-1"),
        ))
        .await;
    sender.expect_error(ErrorCode::Forbidden.as_u16()).await;

    let counters = hub.metrics.snapshot(0);
    assert_eq!(counters.denied_forged_from, 1);
    assert_eq!(
        counters.wakes_routed, 0,
        "a forged `from` must never be routed"
    );

    // And the session survives: refusing loudly is not the same as hanging up.
    sender.wake("agent-b", "row-2").await;
    let delivered = recipient.expect_frame().await;
    assert_eq!(delivered.kind, Kind::Wake);
    assert_eq!(
        delivered.from, "agent-a",
        "the hub stamps the authenticated identity"
    );
    hub.stop().await;
}

#[tokio::test]
async fn denied_an_unknown_destination_answers_the_sender_not_silence() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));
    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);
    sender.wake("nobody-here", "row-1").await;
    sender
        .expect_error(ErrorCode::UnknownDestination.as_u16())
        .await;
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_full_queue_answers_507_to_the_sender() {
    // Long ids and a full-size wake payload make each queued frame ~500 B, so a
    // deaf recipient's socket buffer and the hub's byte budget are reached in a
    // bounded number of sends rather than tens of thousands.
    let sender_id = "s".repeat(120);
    let deaf_id = "d".repeat(120);
    let key_sender = key(1);
    let key_deaf = key(2);
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            // Take the rate limiter out of the picture so what is being
            // measured is unambiguously the BYTE budget.
            hub_cfg.rate_per_sec = 1_000_000;
            hub_cfg.rate_burst = 1_000_000;
            hub_cfg.queue_bytes = 8 * 1_024;
            hub_cfg.global_egress_bytes = 32 * 1_024;
        },
        Arc::new(verifier_allowing(&[
            (sender_id.as_str(), &key_sender),
            (deaf_id.as_str(), &key_deaf),
        ])),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    // The deaf recipient authenticates and then never reads again.
    let mut deaf = hub.connect().await;
    deaf.hello(&deaf_id, &key_deaf, &[]).await;
    assert_eq!(deaf.expect_frame().await.kind, Kind::Welcome);

    let mut sender = hub.connect().await;
    sender.hello(&sender_id, &key_sender, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    // Sized so the whole encoding stays inside the 256 B wake-metadata cap:
    // 44 B of framing + a 120 B sender + a 4 B namespace leaves 88 B for the id.
    let big_row = "r".repeat(80);
    let mut saw_507 = false;
    'flood: for _round in 0..200 {
        for _ in 0..50 {
            sender.wake(&deaf_id, &big_row).await;
        }
        // Interleave reads so the sender's own error queue cannot fill.
        while let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(50), sender.read_frame()).await
        {
            if frame.kind == Kind::Error {
                let (code, _) = decode_error(&frame.payload).expect("error payload");
                assert_eq!(
                    code,
                    ErrorCode::Overflow.as_u16(),
                    "the only refusal expected here is the byte-budget one"
                );
                saw_507 = true;
                break 'flood;
            }
        }
    }
    assert!(
        saw_507,
        "a recipient that stops draining must produce a 507 to the SENDER, never a \
         silent drop and never unbounded growth"
    );
    assert!(
        hub.metrics.snapshot(0).overflow >= 1,
        "the overflow must be counted"
    );

    // ---- and the parked writer must not pin the connection slot ------------
    // The deaf peer's writer is now blocked in `write_all` (its receive buffer
    // is full and it never reads). Half-close its WRITE side so the hub's
    // reader sees EOF and tears the connection down. If teardown waited on the
    // writer unboundedly, `connections_current` would never fall and the hub
    // would leak one ceiling slot per such peer.
    deaf.shutdown_write().await;
    let mut reaped = false;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if hub.metrics.snapshot(0).connections_current <= 1 {
            reaped = true;
            break;
        }
    }
    assert!(
        reaped,
        "a peer that stops reading must not pin its connection slot — teardown \
         aborts a parked writer after a bounded grace, and the writer releases \
         every byte it still accounts for from its Drop"
    );
    assert!(
        hub.snapshot_egress() <= 32 * 1_024,
        "the hub-wide egress reservation must never exceed its configured cap, and \
         a reaped connection must have returned every byte it held: {} B",
        hub.snapshot_egress()
    );
    hub.stop().await;
}

#[tokio::test]
async fn denied_the_pre_auth_rate_limit_bites_before_authentication() {
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            hub_cfg.preauth_rate_per_sec = 1;
            hub_cfg.preauth_burst = 2;
            // Long deadline so what trips is the bucket, not the timeout.
            hub_cfg.handshake_timeout = Duration::from_secs(30);
        },
        Arc::new(TestVerifier::new()),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut client = hub.connect().await;
    // Well-formed but unauthenticated pings: each costs one pre-auth token.
    let mut saw_429 = false;
    for _ in 0..8 {
        client
            .send(Frame::new(Kind::Ping, "agent-a", "", Bytes::new()))
            .await;
        // Edition-2024 let-chain: clippy::collapsible_if requires the nested
        // condition be folded into the `if let`.
        if let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(200), client.read_frame()).await
            && frame.kind == Kind::Error
        {
            let (code, _) = decode_error(&frame.payload).expect("error payload");
            if code == ErrorCode::RateLimited.as_u16() {
                saw_429 = true;
            } else {
                // The first non-hello frame is refused as unauthorized; that is
                // the other correct pre-auth answer.
                assert_eq!(code, ErrorCode::Unauthorized.as_u16());
            }
            break;
        }
    }
    assert!(
        saw_429 || hub.metrics.snapshot(0).denied_hello >= 1,
        "a pre-auth peer must hit either the austere bucket or the unauthorized gate"
    );
    hub.stop().await;
}

#[tokio::test]
async fn denied_a_subscription_over_the_session_cap_changes_nothing() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));
    let mut client = hub.connect().await;
    client.hello("agent-a", &key_a, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    // MAX_TOPICS_PER_SESSION is 32 and MAX_TOPICS_PER_FRAME is 8, so five full
    // frames take the session one topic past its cap.
    let mut refused = false;
    for round in 0..5 {
        let topics: Vec<String> = (0..8).map(|idx| format!("#t{round}-{idx}")).collect();
        let payload = encode_topics(&topics).expect("topics");
        client
            .send(Frame::new(Kind::Subscribe, "agent-a", "", payload))
            .await;
        if let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(200), client.read_frame()).await
        {
            assert_eq!(frame.kind, Kind::Error);
            let (code, _) = decode_error(&frame.payload).expect("error payload");
            assert_eq!(code, ErrorCode::Forbidden.as_u16());
            refused = true;
        }
    }
    assert!(
        refused,
        "a subscription past the cap must be refused whole, never silently truncated"
    );
    hub.stop().await;
}

/// A verifier that accepts a hello but keeps the DEFAULT (refusing) membership
/// behaviour, isolating the membership gate from the handshake gate.
#[derive(Debug)]
struct DepartRefusingVerifier(TestVerifier);

impl HelloVerifier for DepartRefusingVerifier {
    fn verify(&self, req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason> {
        self.0.verify(req)
    }
    // `verify_membership` is deliberately NOT overridden: the trait default is
    // the fail-closed refusal, and this test pins that it is what ships.
}

#[tokio::test]
async fn denied_membership_changes_without_a_wired_verifier() {
    let key_a = key(1);
    let mut inner = TestVerifier::new();
    inner.allow("agent-a", &key_a);
    let hub = Harness::start(
        |_| {},
        Arc::new(DepartRefusingVerifier(inner)),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut client = hub.connect().await;
    client.hello("agent-a", &key_a, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    client
        .send(Frame::new(
            Kind::Depart,
            "agent-a",
            "",
            Bytes::from_static(b"not-a-real-signature"),
        ))
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    hub.stop().await;
}
