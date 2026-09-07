// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` — a `subscribe` is ACKNOWLEDGED, and the acknowledgement means
//! the router already holds the topic (issue
//! [#3532](https://github.com/alphaonedev/ai-memory-mcp/issues/3532),
//! follow-up to [#3505](https://github.com/alphaonedev/ai-memory-mcp/issues/3505)).
//!
//! # The gap this closes
//!
//! Before #3532 an accepted `subscribe` was answered with NOTHING. A client
//! could not know when its subscription went live, and a peer's topic wake
//! sent inside that window fanned out to nobody. The inbox row is the durable
//! truth and the backstop poll still finds it, so the cost was LATENCY, not
//! loss — but it was unobservable latency, and unobservable is the property a
//! fleet cannot manage. It is also what forced the #3505 suite to work around
//! the race with a ping/pong round-trip after every subscribe.
//!
//! # What is actually proved here
//!
//! Not "a frame comes back" — that would be satisfied by an ack the hub minted
//! before it did anything. The load-bearing property is the ORDER:
//!
//! * `the_ack_is_never_emitted_before_the_subscription_is_live_3532` reads the
//!   hub's OWN routing table at the instant the ack is observed and requires
//!   the subscriber to already be in it.
//! * `a_peer_wake_sent_after_the_ack_is_delivered_3532` is the behavioural
//!   twin: a peer addresses the topic strictly after the ack, and the wake
//!   arrives — with no sleep, no ping and no retry anywhere in the test.
//!
//! and the fail-open half, which is what makes the change additive rather than
//! a wire break:
//!
//! * `an_old_style_client_that_ignores_the_ack_still_receives_wakes_3532`
//!   never reads the ack as an ack and keeps working.
//! * `a_refused_subscribe_is_answered_with_an_error_and_never_an_ack_3532`
//!   keeps "acknowledged" meaning "applied": a refusal is never dressed as
//!   one.

mod wake_hub_harness;

use std::time::Duration;

use ai_memory::wake_hub::frame::{ErrorCode, Frame, Kind, decode_topics, encode_topics};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use wake_hub_harness::{Harness, TestVerifier};

const TOPIC: &str = "#hive";
const SUBSCRIBER: &str = "agent-sub";
const PEER: &str = "agent-peer";

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

/// The hub answers an applied `subscribe` with a `subscribe` carrying exactly
/// the topic list it took — and nothing else.
///
/// The payload is asserted BYTE-for-byte against a fresh encoding of the same
/// list, which is the structural form of the #3466 wake-only posture: an ack
/// that is byte-identical to the request cannot smuggle a payload, an identity
/// claim or an authority the client did not itself send.
#[tokio::test]
async fn an_applied_subscribe_is_acknowledged_with_its_own_topic_list_3532() {
    let sub_key = key(11);
    let hub = Harness::with_verifier(verifier_allowing(&[(SUBSCRIBER, &sub_key)]));

    let mut client = hub.connect().await;
    client.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    let topics = vec![TOPIC.to_string(), "#swarm".to_string()];
    let payload = encode_topics(&topics).expect("topics");
    client
        .send(Frame::new(Kind::Subscribe, SUBSCRIBER, "", payload.clone()))
        .await;

    let ack = client.expect_frame().await;
    assert_eq!(
        ack.kind,
        Kind::Subscribe,
        "the ack echoes the request's kind rather than consuming a new wire \
         number an older reader would refuse"
    );
    assert_eq!(ack.from, hub.hub_id, "the hub stamps its own id");
    assert_eq!(ack.to, SUBSCRIBER, "addressed to the session that asked");
    assert_eq!(
        ack.payload, payload,
        "the ack is byte-identical to the request's topic list, so it can carry \
         nothing the client did not send"
    );
    assert_eq!(decode_topics(&ack.payload).expect("topics"), topics);
    hub.stop().await;
}

/// STRUCTURAL: at the instant the ack is observed, the hub's routing table
/// ALREADY names this session as a recipient of the topic.
///
/// This is the guarantee itself, read off the hub's own state rather than
/// inferred from a delivery. An implementation that acknowledged first and
/// registered afterwards would pass a "does an ack come back" test and fail
/// this one.
#[tokio::test]
async fn the_ack_is_never_emitted_before_the_subscription_is_live_3532() {
    let sub_key = key(12);
    let hub = Harness::with_verifier(verifier_allowing(&[(SUBSCRIBER, &sub_key)]));

    let mut client = hub.connect().await;
    client.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    client.subscribe_acked(&[TOPIC.to_string()]).await;

    assert!(
        hub.router()
            .topic_recipients(TOPIC, "")
            .iter()
            .any(|id| id == SUBSCRIBER),
        "#3532: the router must already hold the subscription when the ack is \
         observed — otherwise the ack promises something that is not yet true"
    );
    assert_eq!(hub.router().subscription_count(SUBSCRIBER), 1);
    hub.stop().await;
}

/// BEHAVIOURAL twin: a peer addresses the topic strictly AFTER the subscriber
/// observed its ack, and the wake is delivered. No sleeps, no ping, no retry.
///
/// Pre-#3532 the only way to order these two connections was to round-trip a
/// ping on the subscriber's connection; without it the peer's wake could be
/// routed first and fan out to nobody (the deterministic Linux failure that
/// produced this issue).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_wake_sent_after_the_ack_is_delivered_3532() {
    let sub_key = key(13);
    let peer_key = key(14);
    let hub = Harness::with_verifier(verifier_allowing(&[
        (SUBSCRIBER, &sub_key),
        (PEER, &peer_key),
    ]));

    let mut subscriber = hub.connect().await;
    subscriber.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(subscriber.expect_frame().await.kind, Kind::Welcome);

    let mut peer = hub.connect().await;
    peer.hello(PEER, &peer_key, &[]).await;
    assert_eq!(peer.expect_frame().await.kind, Kind::Welcome);

    // The ack is the ONLY thing ordering the two connections.
    subscriber.subscribe_acked(&[TOPIC.to_string()]).await;
    peer.wake(TOPIC, "row-3532-after-ack").await;

    let wake = subscriber.expect_frame().await;
    assert_eq!(
        wake.kind,
        Kind::Wake,
        "a wake after the ack must be delivered"
    );
    assert_eq!(wake.to, TOPIC);
    assert_eq!(wake.from, PEER, "the hub stamps the authenticated sender");
    hub.stop().await;
}

/// FAIL-OPEN: a client written before #3532 — one that subscribes and never
/// treats the echo as anything — still receives its wakes on a session that
/// stays live.
///
/// The ack is deliberately spelled as an echo of kinds 5/6 rather than a new
/// wire number precisely so this holds: `Kind::from_u8` REFUSES an unknown
/// kind byte (and the Python SDK reader raises on one), so a brand-new kind
/// would have ended this session instead of being ignored by it. Here the
/// frame decodes, carries no wake, and costs the old client nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_style_client_that_ignores_the_ack_still_receives_wakes_3532() {
    let sub_key = key(15);
    let peer_key = key(16);
    let hub = Harness::with_verifier(verifier_allowing(&[
        (SUBSCRIBER, &sub_key),
        (PEER, &peer_key),
    ]));

    let mut old = hub.connect().await;
    old.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(old.expect_frame().await.kind, Kind::Welcome);

    let mut peer = hub.connect().await;
    peer.hello(PEER, &peer_key, &[]).await;
    assert_eq!(peer.expect_frame().await.kind, Kind::Welcome);

    // Pre-#3532 shape: fire the subscribe with no idea an ack exists, then
    // order the peer behind the router mutation the way this suite used to —
    // by round-tripping a ping on the subscriber's own connection. That remedy
    // still works; the only difference is that an extra frame it has no
    // opinion about now arrives before the pong, and it skips it.
    old.subscribe(&[TOPIC.to_string()]).await;
    old.send(Frame::new(Kind::Ping, SUBSCRIBER, "", Bytes::new()))
        .await;
    let mut skipped = 0;
    loop {
        let frame = old.expect_frame().await;
        assert_ne!(
            frame.kind,
            Kind::Error,
            "the ack must never refuse an old client's session"
        );
        if frame.kind == Kind::Pong {
            break;
        }
        skipped += 1;
        assert!(skipped <= 2, "the hub emitted more than the one ack");
    }
    assert_eq!(
        skipped, 1,
        "exactly one unopinionated frame — the ack — preceded the pong"
    );

    peer.wake(TOPIC, "row-3532-old-client").await;
    let wake = old.expect_frame().await;
    assert_eq!(
        wake.kind,
        Kind::Wake,
        "#3532: an old-style client must still receive its wakes"
    );
    assert_eq!(wake.to, TOPIC);
    assert_eq!(wake.from, PEER);
    hub.stop().await;
}

/// The dual: an APPLIED `unsubscribe` is acknowledged, and once the ack is
/// observed no further wake for that topic is routed here.
///
/// This retires the second documented ping workaround ("round-trip a ping so
/// the unsubscribe is known to have been processed").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_unsubscribe_is_acknowledged_and_stops_the_fanout_3532() {
    let sub_key = key(17);
    let peer_key = key(18);
    let hub = Harness::with_verifier(verifier_allowing(&[
        (SUBSCRIBER, &sub_key),
        (PEER, &peer_key),
    ]));

    let mut subscriber = hub.connect().await;
    subscriber.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(subscriber.expect_frame().await.kind, Kind::Welcome);

    let mut peer = hub.connect().await;
    peer.hello(PEER, &peer_key, &[]).await;
    assert_eq!(peer.expect_frame().await.kind, Kind::Welcome);

    subscriber.subscribe_acked(&[TOPIC.to_string()]).await;
    peer.wake(TOPIC, "row-3532-before-unsub").await;
    assert_eq!(subscriber.expect_frame().await.kind, Kind::Wake);

    subscriber.unsubscribe_acked(&[TOPIC.to_string()]).await;
    assert!(
        hub.router().topic_recipients(TOPIC, "").is_empty(),
        "the route is already gone when the ack is observed"
    );

    peer.wake(TOPIC, "row-3532-after-unsub").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), subscriber.read_frame())
            .await
            .is_err(),
        "no wake for an acknowledged-removed topic may arrive"
    );

    // ...and the session itself is untouched: a direct wake still lands.
    peer.wake(SUBSCRIBER, "row-3532-direct").await;
    assert_eq!(subscriber.expect_frame().await.kind, Kind::Wake);
    hub.stop().await;
}

/// FAIL-CLOSED: a REFUSED `subscribe` gets its `error` and never an ack, so
/// "acknowledged" can only ever mean "applied".
///
/// The refusal here is the identity gate (#3468/#3505 `verify_topics`), the
/// one that closes the connection — a hub that acknowledged before verifying
/// would have told the client it was listening to a topic it may not read.
#[tokio::test]
async fn a_refused_subscribe_is_answered_with_an_error_and_never_an_ack_3532() {
    let sub_key = key(19);
    let mut verifier = verifier_allowing(&[(SUBSCRIBER, &sub_key)]);
    verifier.refuse_topics();
    let hub = Harness::with_verifier(verifier);

    let mut client = hub.connect().await;
    client.hello(SUBSCRIBER, &sub_key, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    let payload = encode_topics(&[TOPIC.to_string()]).expect("topics");
    client
        .send(Frame::new(Kind::Subscribe, SUBSCRIBER, "", payload))
        .await;
    client.expect_error(ErrorCode::Unauthorized.as_u16()).await;

    assert!(
        hub.router().topic_recipients(TOPIC, "").is_empty(),
        "a refused subscribe leaves no route behind"
    );
    hub.stop().await;
}
