// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the wake-hub bus sink, end to end.
//!
//! The unit tests in `src/wake_sink/**` cover the decision table. This suite
//! proves the same decisions hold when they are reached the way production
//! reaches them: a REAL `memory_notify` on a REAL store, publishing on the REAL
//! #3465 bus, through a sink installed by the REAL
//! `inbox_wake::install_sink`, landing on the REAL #3467 router — and, for the
//! separate-process shape, across a REAL Unix domain socket into a REAL hub.
//!
//! Nothing here is stubbed except the two things that MUST be supplied from
//! outside the shipped binary: the hub's identity verifier and the forwarder's
//! join credential, both of which ship refusing.
//!
//! The postgres twin lives in `tests/wake_sink_postgres_3469.rs`.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

mod wake_hub_harness;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::sentinels::WAKE_HUB_PRODUCER;
use ai_memory::inbox_wake::{InboxEvent, InboxWakeSink};
use ai_memory::wake_hub::frame::{Frame, Kind, WakeMeta};
use ai_memory::wake_hub::identity::{
    DenyReason, HelloRequest, HelloVerifier, MembershipRequest, VerifiedAgent,
};
use ai_memory::wake_hub::limits::{
    DEFAULT_GLOBAL_EGRESS_BYTES, DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS,
    DEFAULT_RECIPIENT_QUEUE_BYTES, DEFAULT_RECIPIENT_QUEUE_FRAMES, EgressBudget,
};
use ai_memory::wake_hub::metrics::HubMetrics;
use ai_memory::wake_hub::pending::PendingStore;
use ai_memory::wake_hub::routing::{Egress, EgressAccount, EgressHandle, Router};
use ai_memory::wake_sink::in_process::{InProcessWakeSink, install_in_process};
use ai_memory::wake_sink::uds::{
    CredentialError, HelloCredential, JoinCredential, NoJoinCredential, UdsSinkConfig, UdsWakeSink,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use tokio::sync::{Notify, mpsc};
use wake_hub_harness::{Harness, TestVerifier};

/// A per-test recipient. The wake bus is process-wide, so every test uses a
/// unique id rather than assuming it is the only publisher.
fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn temp_db() -> PathBuf {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    db_path
}

/// A live router with one registered recipient whose writer queue this test
/// holds — the same shape a connected hub session installs.
struct HubProbe {
    router: Arc<Router>,
    queue: mpsc::Receiver<Egress>,
}

fn hub_probe(recipient: &str) -> HubProbe {
    let egress = Arc::new(EgressBudget::new(DEFAULT_GLOBAL_EGRESS_BYTES));
    let router = Arc::new(Router::new(
        DEFAULT_RECIPIENT_QUEUE_FRAMES,
        DEFAULT_RECIPIENT_QUEUE_BYTES,
        Arc::clone(&egress),
        PendingStore::new(DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS),
        Arc::new(HubMetrics::default()),
    ));
    let (tx, queue) = mpsc::channel(DEFAULT_RECIPIENT_QUEUE_FRAMES);
    let handle = EgressHandle::new(
        tx,
        Arc::new(EgressAccount::new()),
        egress,
        Arc::new(Notify::new()),
        DEFAULT_RECIPIENT_QUEUE_BYTES,
    );
    assert!(
        router.register(recipient, 1, handle).is_none(),
        "a fresh router displaces nothing"
    );
    HubProbe { router, queue }
}

/// Drain the recipient's writer queue until a `wake` shows up.
async fn next_wake(queue: &mut mpsc::Receiver<Egress>) -> Option<Frame> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, queue.recv()).await {
            Ok(Some(Egress::Frame(bytes))) => {
                let frame = Frame::decode(&bytes).expect("the hub must only queue legal frames");
                if frame.kind == Kind::Wake {
                    return Some(frame);
                }
            }
            Ok(Some(Egress::Close)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Co-hosted: notify -> bus -> installed sink -> router
// ---------------------------------------------------------------------------

/// ALLOWED, and the wiring proof for the whole issue: a committed
/// `memory_notify` reaches a co-hosted hub's router as a `wake` naming the
/// durable row — through `inbox_wake::install_sink`, with nothing stubbed
/// between the two.
///
/// This is the ONE test in this binary that installs a process-wide sink;
/// `install_sink` deliberately refuses a second installation.
#[tokio::test]
async fn notify_reaches_a_cohosted_hub_through_the_installed_sink_3469() {
    let recipient = uid("bob");
    let secret = "SUPER-SECRET-NOTIFY-BODY-3469";
    let title = "SUBJECT-LINE-3469";
    let mut probe = hub_probe(&recipient);

    let metrics = install_in_process(Arc::clone(&probe.router))
        .expect("this binary installs exactly one wake sink");

    let db_path = temp_db();
    let conn = ai_memory::db::open(&db_path).expect("open");
    let envelope = ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": recipient,
            "title": title,
            "payload": secret,
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");
    let row_id = envelope["id"].as_str().expect("id").to_owned();

    let frame = next_wake(&mut probe.queue)
        .await
        .expect("the wake must reach the recipient's writer queue");
    assert_eq!(frame.kind, Kind::Wake);
    assert_eq!(
        frame.to, recipient,
        "a wake is addressed to its inbox owner"
    );
    assert!(
        !frame.to_is_topic(),
        "substrate wakes are never topic-routed"
    );
    assert_eq!(
        frame.from, WAKE_HUB_PRODUCER,
        "a substrate wake must be stamped with the reserved producer id, not with \
         the notifying agent's identity"
    );

    let meta = WakeMeta::decode(&frame.payload).expect("wake metadata");
    assert_eq!(
        meta.inbox_row_id, row_id,
        "the wake must name the durable row"
    );
    assert_eq!(meta.namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(
        meta.digest.len(),
        32,
        "a 32-byte content digest, never a body"
    );
    assert!(
        meta.seq_high_watermark > 0,
        "the self-heal watermark must be populated"
    );
    assert!(
        meta.seq_high_watermark <= ai_memory::inbox_wake::seq_high_watermark(),
        "the watermark is the producer's own monotonic wake sequence"
    );

    // NEITHER the body NOR the title may appear anywhere on the wire.
    let wire = String::from_utf8_lossy(&frame.encode().expect("re-encode")).into_owned();
    assert!(!wire.contains(secret), "the body must never reach the hub");
    assert!(!wire.contains(title), "nor the title");

    let snap = metrics.snapshot();
    assert!(snap.wakes_seen >= 1);
    assert!(snap.delivered >= 1);
    assert_eq!(snap.dropped_unaddressable, 0);
    assert_eq!(snap.dropped_unencodable, 0);
}

/// DENIED: a wake for another agent never lands on this recipient's queue.
/// The router is keyed by the identity a hello authenticated, so own-inbox-only
/// is a structural property, not a filter someone has to remember to apply.
#[tokio::test]
async fn a_wake_for_another_agent_never_lands_on_this_queue_3469() {
    let mine = uid("carol");
    let theirs = uid("mallory");
    let mut probe = hub_probe(&mine);
    let sink = InProcessWakeSink::for_router(Arc::clone(&probe.router));

    sink.on_wake(&InboxEvent::AgentNotified {
        seq: 1,
        recipient_agent_id: theirs.clone(),
        correlation_id: "sha256:c".into(),
        inbox_row_id: "row-theirs".into(),
        namespace: format!("_inbox/{theirs}"),
        sender_agent_id: "ai:alice".into(),
        content_digest: format!("sha256:{}", "33".repeat(32)),
        notified_at: "2026-09-05T00:00:00Z".into(),
    });

    assert!(
        probe.queue.try_recv().is_err(),
        "another agent's wake must never be queued here"
    );
    // The unknown recipient is a counted DROP, not a silent one.
    assert_eq!(sink.metrics().snapshot().dropped_unknown, 1);
}

// ---------------------------------------------------------------------------
// Co-hosted, against a REAL bound hub
// ---------------------------------------------------------------------------

/// The `Arc<Router>` accessor must outlive the hub value: `WakeHub::serve`
/// CONSUMES the hub, so a co-hosted daemon that took a borrow could not keep
/// feeding it. Takes the router, moves the hub into `serve`, and proves a wake
/// still reaches a live session afterwards.
#[tokio::test]
async fn the_router_accessor_survives_the_serve_move_3469() {
    let recipient = uid("dora");
    let key = SigningKey::from_bytes(&[31u8; 32]);
    let mut verifier = TestVerifier::new();
    verifier.allow(&recipient, &key);

    let harness = Harness::with_verifier(verifier);
    let router = harness.router();

    let mut client = harness.connect().await;
    client.hello(&recipient, &key, &[]).await;
    let welcome = client.expect_frame().await;
    assert_eq!(welcome.kind, Kind::Welcome);

    let sink = InProcessWakeSink::for_router(router);
    sink.on_wake(&InboxEvent::AgentNotified {
        seq: 77,
        recipient_agent_id: recipient.clone(),
        correlation_id: "sha256:c".into(),
        inbox_row_id: "row-live".into(),
        namespace: format!("_inbox/{recipient}"),
        sender_agent_id: "ai:alice".into(),
        content_digest: format!("sha256:{}", "44".repeat(32)),
        notified_at: "2026-09-05T00:00:00Z".into(),
    });

    let frame = client.expect_frame().await;
    assert_eq!(frame.kind, Kind::Wake);
    assert_eq!(frame.from, WAKE_HUB_PRODUCER);
    let meta = WakeMeta::decode(&frame.payload).expect("meta");
    assert_eq!(meta.inbox_row_id, "row-live");
    assert_eq!(meta.seq_high_watermark, 77);
    assert_eq!(sink.metrics().snapshot().delivered, 1);

    harness.stop().await;
}

// ---------------------------------------------------------------------------
// Separate process: the UDS forwarder
// ---------------------------------------------------------------------------

/// A credential backed by a real Ed25519 key, supplied by the TEST — the
/// shipped binary has none.
struct TestCredential(SigningKey);

impl JoinCredential for TestCredential {
    fn agent_id(&self) -> &str {
        WAKE_HUB_PRODUCER
    }

    fn sign_hello(&self, transcript: &[u8]) -> Result<HelloCredential, CredentialError> {
        Ok(HelloCredential {
            pubkey: self.0.verifying_key().to_bytes(),
            signature: self.0.sign(transcript).to_bytes(),
            delegation: bytes::Bytes::new(),
        })
    }
}

/// ALLOWED, separate-process shape: the daemon-side forwarder joins the hub
/// over its socket as the reserved producer identity, and a wake it forwards
/// reaches the recipient's own session — carrying the row id and the digest,
/// and never a body.
#[tokio::test]
async fn the_uds_forwarder_delivers_a_wake_across_a_real_socket_3469() {
    let recipient = uid("erin");
    let producer_key = SigningKey::from_bytes(&[41u8; 32]);
    let recipient_key = SigningKey::from_bytes(&[42u8; 32]);
    let mut verifier = TestVerifier::new();
    verifier.allow(WAKE_HUB_PRODUCER, &producer_key);
    verifier.allow(&recipient, &recipient_key);

    let harness = Harness::with_verifier(verifier);
    let mut client = harness.connect().await;
    client.hello(&recipient, &recipient_key, &[]).await;
    assert_eq!(client.expect_frame().await.kind, Kind::Welcome);

    let mut cfg = UdsSinkConfig::with_socket_path(harness.socket.clone());
    cfg.hub_id = harness.hub_id.clone();
    let sink = UdsWakeSink::spawn(cfg, Arc::new(TestCredential(producer_key)))
        .expect("the forwarder must start for an enrolled producer credential");

    sink.on_wake(&InboxEvent::AgentNotified {
        seq: 5150,
        recipient_agent_id: recipient.clone(),
        correlation_id: "sha256:c".into(),
        inbox_row_id: "row-uds".into(),
        namespace: format!("_inbox/{recipient}"),
        sender_agent_id: "ai:alice".into(),
        content_digest: format!("sha256:{}", "55".repeat(32)),
        notified_at: "2026-09-05T00:00:00Z".into(),
    });

    let frame = client.expect_frame().await;
    assert_eq!(frame.kind, Kind::Wake);
    assert_eq!(
        frame.from, WAKE_HUB_PRODUCER,
        "the hub stamps the identity it authenticated, and that identity is the \
         reserved producer name"
    );
    assert_eq!(frame.to, recipient);
    let meta = WakeMeta::decode(&frame.payload).expect("meta");
    assert_eq!(meta.inbox_row_id, "row-uds");
    assert_eq!(meta.sender, "ai:alice", "the real sender rides in metadata");
    assert_eq!(meta.digest.len(), 32);
    assert_eq!(meta.seq_high_watermark, 5150);

    harness.stop().await;
}

/// DENIED: the shipped credential refuses, so the forwarder refuses to START
/// rather than opening a socket it could not authenticate on. No flag swaps it.
#[tokio::test]
async fn the_shipped_credential_refuses_to_start_a_forwarder_3469() {
    let harness = Harness::with_verifier(TestVerifier::new());
    let cfg = UdsSinkConfig::with_socket_path(harness.socket.clone());
    let err = UdsWakeSink::spawn(cfg, Arc::new(NoJoinCredential))
        .expect_err("a daemon with no enrolled producer identity must not attach");
    let rendered = format!("{err}");
    assert!(rendered.contains(WAKE_HUB_PRODUCER), "{rendered}");
    // Nothing was opened: the hub saw no connection at all.
    assert_eq!(harness.metrics.snapshot(0).accepted, 0);
    harness.stop().await;
}

/// DENIED: a forwarder the hub will not admit delivers nothing, and says so on
/// its counters rather than looking like a quiet fleet.
#[tokio::test]
async fn a_forwarder_the_hub_refuses_delivers_nothing_3469() {
    /// Refuses every hello — the shipped hub posture until #3468 is wired.
    struct RefuseAll;
    impl HelloVerifier for RefuseAll {
        fn verify(&self, _req: &HelloRequest<'_>) -> Result<VerifiedAgent, DenyReason> {
            Err(DenyReason::IdentityNotConfigured)
        }
        fn verify_membership(&self, _req: &MembershipRequest<'_>) -> Result<(), DenyReason> {
            Err(DenyReason::IdentityNotConfigured)
        }
    }

    let harness = Harness::start(
        |_| {},
        Arc::new(RefuseAll),
        Arc::new(ai_memory::wake_hub::identity::SameUidAuthorizer::for_current_process()),
    );
    let mut cfg = UdsSinkConfig::with_socket_path(harness.socket.clone());
    cfg.hub_id = harness.hub_id.clone();
    cfg.queue_frames = 2;
    let sink = UdsWakeSink::spawn(
        cfg,
        Arc::new(TestCredential(SigningKey::from_bytes(&[9u8; 32]))),
    )
    .expect("starting is allowed; being admitted is not");

    for i in 0..4u64 {
        sink.on_wake(&InboxEvent::AgentNotified {
            seq: i + 1,
            recipient_agent_id: uid("frank"),
            correlation_id: "sha256:c".into(),
            inbox_row_id: format!("row-{i}"),
            namespace: "_inbox/frank".into(),
            sender_agent_id: "ai:alice".into(),
            content_digest: format!("sha256:{}", "66".repeat(32)),
            notified_at: "2026-09-05T00:00:00Z".into(),
        });
    }

    // Bounded: the hand-off channel holds two and the rest are counted drops.
    // Nothing blocked, nothing grew without bound, and NOTHING was delivered.
    let snap = sink.metrics().snapshot();
    assert_eq!(snap.wakes_seen, 4);
    assert_eq!(
        snap.delivered, 0,
        "an unadmitted forwarder delivers nothing"
    );
    assert_eq!(snap.dropped_transport_full, 2);
    assert!(snap.total_dropped() >= 2, "every drop is counted: {snap:?}");

    harness.stop().await;
}

// ---------------------------------------------------------------------------
// The SAL funnel
// ---------------------------------------------------------------------------

/// ALLOWED, SAL funnel (sqlite adapter): a direct `MemoryStore::notify` also
/// reaches the hub, so the wake does not depend on which surface the write
/// arrived through. The postgres adapter twin lives in
/// `tests/wake_sink_postgres_3469.rs`.
#[cfg(feature = "sal")]
#[tokio::test]
async fn the_sqlite_sal_notify_funnel_reaches_the_hub_3469() {
    use ai_memory::store::MemoryStore as _;

    let recipient = uid("gwen");
    let mut probe = hub_probe(&recipient);
    let sink = InProcessWakeSink::for_router(Arc::clone(&probe.router));
    let mut rx = ai_memory::inbox_wake::subscribe();

    let db_path = temp_db();
    let store = ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore");
    let ctx = ai_memory::store::CallerContext::for_agent("ai:alice");
    let row_id = store
        .notify(&ctx, &recipient, "ping", "body", Some(5), None, None)
        .await
        .expect("sal notify");

    // Pump the bus by hand here: the ONE process-wide installed sink belongs to
    // the wiring test above, and `install_sink` refuses a second installation.
    let event = loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a wake must be published")
            .expect("bus open");
        if ev.recipient_agent_id() == recipient {
            break ev;
        }
    };
    sink.on_wake(&event);

    let frame = next_wake(&mut probe.queue).await.expect("wake queued");
    let meta = WakeMeta::decode(&frame.payload).expect("meta");
    assert_eq!(meta.inbox_row_id, row_id);
    assert_eq!(meta.namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(frame.from, WAKE_HUB_PRODUCER);
}
