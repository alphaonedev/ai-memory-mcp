// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` — the ALLOWED half of the charter's both-paths bar
//! (issue [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! The headline case is `allowed_topic_fanout_reaches_64_recipients_in_order`:
//! hello -> welcome -> subscribe -> a wake fanned out to N = 64 recipients,
//! asserting that EVERY recipient receives EVERY wake and that each one sees
//! them in the order the sender produced them. Per-recipient ordering is the
//! property the one-queue-one-writer-task-per-recipient design exists to
//! provide, so it is pinned here rather than assumed.
//!
//! The DENIED twin is `tests/wake_hub_denied_3467.rs`.

mod wake_hub_harness;

use std::sync::Arc;
use std::time::Duration;

use ai_memory::wake_hub::frame::{
    ErrorCode, Frame, Kind, WakeMeta, WelcomePayload, decode_error, encode_topics,
};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_hub::{HubConfig, limits};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use wake_hub_harness::{Harness, TestVerifier};

/// Fan-out width. 64 is the width the issue names.
const RECIPIENTS: usize = 64;

/// Wakes each recipient must see, in order.
const WAKES: usize = 6;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn agent(index: usize) -> String {
    format!("agent-{index:03}")
}

/// A key that is a deterministic function of the agent index, so a test can
/// re-derive it without threading a table around.
fn agent_key(index: usize) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = u8::try_from(index % 251).expect("fits");
    seed[1] = u8::try_from(index / 251).expect("fits");
    seed[2] = 0xA2;
    SigningKey::from_bytes(&seed)
}

fn verifier_allowing(agents: &[(&str, &SigningKey)]) -> TestVerifier {
    let mut verifier = TestVerifier::new();
    for (id, signing_key) in agents {
        verifier.allow(id, signing_key);
    }
    verifier
}

#[tokio::test]
async fn allowed_hello_welcome_carries_the_session_and_reconnect_guidance() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));

    let mut client = hub.connect().await;
    client
        .hello("agent-a", &key_a, &["#hive".to_string()])
        .await;
    let frame = client.expect_frame().await;
    assert_eq!(frame.kind, Kind::Welcome);
    assert_eq!(frame.from, hub.hub_id, "the welcome comes from the hub");

    let welcome = WelcomePayload::decode(&frame.payload).expect("welcome payload");
    assert_ne!(welcome.session, 0, "0 is reserved for `no session`");
    assert_eq!(
        welcome.pending_count, 0,
        "a first connection has nothing pending"
    );
    assert!(!welcome.lagged);
    assert_eq!(welcome.reconnect_base_ms, limits::DEFAULT_RECONNECT_BASE_MS);
    assert!(
        welcome.reconnect_jitter_ms > 0,
        "reconnects MUST be jittered or 256 agents re-handshake in lockstep after a restart"
    );
    hub.stop().await;
}

#[tokio::test]
async fn allowed_a_direct_wake_reaches_the_recipient_with_its_metadata_intact() {
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

    sender.wake("agent-b", "row-42").await;
    let delivered = recipient.expect_frame().await;
    assert_eq!(delivered.kind, Kind::Wake);
    assert_eq!(delivered.from, "agent-a");
    assert_eq!(delivered.to, "agent-b");
    let metadata = WakeMeta::decode(&delivered.payload).expect("wake metadata");
    assert_eq!(metadata.inbox_row_id, "row-42");
    assert_eq!(metadata.namespace, "hive");
    assert_eq!(
        metadata.digest.len(),
        32,
        "a wake carries the DIGEST, never the body"
    );
    assert!(
        delivered.payload.len() <= limits::MAX_WAKE_META_BYTES,
        "a routed wake can never exceed the metadata ceiling"
    );

    let counters = hub.metrics.snapshot(0);
    assert_eq!(counters.wakes_routed, 1);
    assert_eq!(counters.fanout_deliveries, 1);
    hub.stop().await;
}

#[tokio::test]
async fn allowed_ping_is_answered_with_pong() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));
    let mut client = hub.connect().await;
    client.hello("agent-a", &key_a, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);
    client
        .send(Frame::new(Kind::Ping, "agent-a", "", Bytes::new()))
        .await;
    assert_eq!(client.expect_frame().await.kind, Kind::Pong);
    hub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowed_topic_fanout_reaches_64_recipients_in_order() {
    let sender_key = key(200);
    let mut verifier = TestVerifier::new();
    verifier.allow("sender", &sender_key);
    for index in 0..RECIPIENTS {
        let signing_key = agent_key(index);
        verifier.allow(&agent(index), &signing_key);
    }
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            hub_cfg.max_connections = RECIPIENTS + 8;
        },
        Arc::new(verifier),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    // Connect and subscribe every recipient.
    let mut recipients = Vec::with_capacity(RECIPIENTS);
    for index in 0..RECIPIENTS {
        let mut client = hub.connect().await;
        client
            .hello(&agent(index), &agent_key(index), &["#hive".to_string()])
            .await;
        assert_eq!(
            client.expect_frame().await.kind,
            Kind::Welcome,
            "recipient {index} must be welcomed"
        );
        recipients.push(client);
    }

    let mut sender = hub.connect().await;
    sender.hello("sender", &sender_key, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    // The sender is NOT subscribed, so a topic wake never echoes back to it.
    for seq in 0..WAKES {
        sender.wake("#hive", &format!("row-{seq}")).await;
    }

    for (index, client) in recipients.iter_mut().enumerate() {
        for seq in 0..WAKES {
            let frame = client.expect_frame().await;
            assert_eq!(frame.kind, Kind::Wake, "recipient {index} frame {seq}");
            assert_eq!(
                frame.to, "#hive",
                "the topic is preserved so the recipient knows why"
            );
            assert_eq!(
                frame.from, "sender",
                "the hub stamps the authenticated sender"
            );
            let metadata = WakeMeta::decode(&frame.payload).expect("wake metadata");
            assert_eq!(
                metadata.inbox_row_id,
                format!("row-{seq}"),
                "recipient {index} must see wake {seq} in the order the sender produced it"
            );
        }
    }

    // And the sender got nothing back: no self-wake, no error.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), sender.read_frame())
            .await
            .is_err(),
        "a sender must never be woken by its own broadcast"
    );

    let counters = hub.metrics.snapshot(0);
    assert_eq!(counters.wakes_routed, u64::try_from(WAKES).expect("fits"));
    assert_eq!(
        counters.fanout_deliveries,
        u64::try_from(WAKES * RECIPIENTS).expect("fits"),
        "every wake must have reached every subscriber"
    );
    assert_eq!(
        counters.overflow, 0,
        "the default budgets must absorb a 64-way fan-out"
    );
    assert_eq!(counters.rate_limited, 0);
    hub.stop().await;
}

#[tokio::test]
async fn allowed_unsubscribe_stops_the_fanout_without_dropping_the_session() {
    let key_a = key(1);
    let key_b = key(2);
    let hub = Harness::with_verifier(verifier_allowing(&[
        ("agent-a", &key_a),
        ("agent-b", &key_b),
    ]));

    let mut recipient = hub.connect().await;
    recipient
        .hello("agent-b", &key_b, &["#hive".to_string()])
        .await;
    assert_eq!(recipient.expect_frame().await.kind, Kind::Welcome);

    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    sender.wake("#hive", "row-1").await;
    assert_eq!(recipient.expect_frame().await.kind, Kind::Wake);

    let payload = encode_topics(&["#hive".to_string()]).expect("topics");
    recipient
        .send(Frame::new(Kind::Unsubscribe, "agent-b", "", payload))
        .await;
    // Round-trip a ping so the unsubscribe is known to have been processed.
    recipient
        .send(Frame::new(Kind::Ping, "agent-b", "", Bytes::new()))
        .await;
    assert_eq!(recipient.expect_frame().await.kind, Kind::Pong);

    sender.wake("#hive", "row-2").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), recipient.read_frame())
            .await
            .is_err(),
        "an unsubscribed session must stop receiving the topic"
    );
    // ...but it is still a live session.
    sender.wake("agent-b", "row-3").await;
    assert_eq!(recipient.expect_frame().await.kind, Kind::Wake);
    hub.stop().await;
}

#[tokio::test]
async fn allowed_offline_wakes_coalesce_and_are_replayed_on_reconnect() {
    let key_a = key(1);
    let key_b = key(2);
    let hub = Harness::start(
        |hub_cfg: &mut HubConfig| {
            hub_cfg.pending_max_ids = 2;
        },
        Arc::new(verifier_allowing(&[
            ("agent-a", &key_a),
            ("agent-b", &key_b),
        ])),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    // agent-b authenticates once so the hub KNOWS it, then disconnects.
    {
        let mut first = hub.connect().await;
        first.hello("agent-b", &key_b, &[]).await;
        assert_eq!(first.expect_frame().await.kind, Kind::Welcome);
    }

    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);

    // Wait for the disconnect to be observed, then wake the offline agent.
    let mut coalesced = false;
    for _ in 0..100 {
        sender.wake("agent-b", "row-1").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        if hub.metrics.snapshot(0).pending_coalesced > 0 {
            coalesced = true;
            break;
        }
    }
    assert!(
        coalesced,
        "wakes for a known-but-offline agent must coalesce"
    );
    // The same row again (must coalesce to ONE id), then two more distinct rows
    // so the bounded id set overflows into `lagged`.
    sender.wake("agent-b", "row-1").await;
    sender.wake("agent-b", "row-2").await;
    sender.wake("agent-b", "row-3").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut reconnect = hub.connect().await;
    reconnect.hello("agent-b", &key_b, &[]).await;
    let frame = reconnect.expect_frame().await;
    assert_eq!(frame.kind, Kind::Welcome);
    let welcome = WelcomePayload::decode(&frame.payload).expect("welcome payload");
    assert!(
        welcome.pending_count >= 4,
        "the count keeps counting: {}",
        welcome.pending_count
    );
    assert_eq!(
        welcome.pending_ids, 2,
        "the id set is bounded at pending_max_ids"
    );
    assert!(
        welcome.lagged,
        "an incomplete id set MUST be advertised so the client does a catch-up read"
    );
    // The retained ids are then replayed as wakes.
    for _ in 0..welcome.pending_ids {
        let replay = reconnect.expect_frame().await;
        assert_eq!(replay.kind, Kind::Wake);
        assert!(
            !WakeMeta::decode(&replay.payload)
                .expect("wake metadata")
                .inbox_row_id
                .is_empty()
        );
    }
    hub.stop().await;
}

#[tokio::test]
async fn allowed_a_second_hello_replaces_the_session_and_tells_the_old_one_why() {
    let key_a = key(1);
    let hub = Harness::with_verifier(verifier_allowing(&[("agent-a", &key_a)]));

    let mut first = hub.connect().await;
    first.hello("agent-a", &key_a, &[]).await;
    let first_welcome =
        WelcomePayload::decode(&first.expect_frame().await.payload).expect("welcome payload");

    let mut second = hub.connect().await;
    second.hello("agent-a", &key_a, &[]).await;
    let second_welcome =
        WelcomePayload::decode(&second.expect_frame().await.payload).expect("welcome payload");
    assert_ne!(first_welcome.session, second_welcome.session);

    // The displaced session is told, not silently blackholed.
    let notice = first.expect_frame().await;
    assert_eq!(notice.kind, Kind::Error);
    let (code, _) = decode_error(&notice.payload).expect("error payload");
    assert_eq!(code, ErrorCode::Replaced.as_u16());
    first.expect_closed().await;

    assert_eq!(hub.metrics.snapshot(0).sessions_replaced, 1);
    hub.stop().await;
}

#[tokio::test]
async fn allowed_the_replacement_session_keeps_receiving_after_the_old_one_tears_down() {
    // Regression for the compare-and-remove in `Router::unregister`: without
    // it, the displaced connection's teardown deletes the route its
    // REPLACEMENT installed, silently blackholing the agent.
    let key_a = key(1);
    let key_b = key(2);
    let hub = Harness::with_verifier(verifier_allowing(&[
        ("agent-a", &key_a),
        ("agent-b", &key_b),
    ]));

    let mut displaced = hub.connect().await;
    displaced.hello("agent-b", &key_b, &[]).await;
    assert_eq!(displaced.expect_frame().await.kind, Kind::Welcome);

    let mut live = hub.connect().await;
    live.hello("agent-b", &key_b, &[]).await;
    assert_eq!(live.expect_frame().await.kind, Kind::Welcome);

    // Let the displaced session finish tearing down.
    drop(displaced);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut sender = hub.connect().await;
    sender.hello("agent-a", &key_a, &[]).await;
    assert_eq!(sender.expect_frame().await.kind, Kind::Welcome);
    sender.wake("agent-b", "row-live").await;

    let delivered = live.expect_frame().await;
    assert_eq!(delivered.kind, Kind::Wake);
    assert_eq!(
        WakeMeta::decode(&delivered.payload)
            .expect("wake metadata")
            .inbox_row_id,
        "row-live"
    );
    hub.stop().await;
}
