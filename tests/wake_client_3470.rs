// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3470 — the wake-hub CLIENT, end to end.
//!
//! The unit tests in `src/wake_client/**` and `src/cli/wake_listen.rs` cover
//! the decision tables. This suite proves the same decisions hold when they
//! are reached the way production reaches them: a REAL `memory_notify` on a
//! REAL store, publishing on the REAL #3465 bus, through the REAL #3469
//! in-process sink, into the REAL #3467 router, across a REAL Unix domain
//! socket, admitted by the REAL #3468 `ScopedDelegationVerifier` — and read
//! back through the REAL `memory_inbox` funnel.
//!
//! Nothing is stubbed. In particular the identity path is the PRODUCTION one:
//! the listener presents the on-disk bundle shape
//! `ai-memory identity delegate --scope a2a-hub` writes, and the hub verifies
//! it with the shipped verifier over a real allowlist. There is no permissive
//! test verifier here, because the whole point of the client is that it can
//! authenticate against the one the operator actually runs.
//!
//! The postgres twin lives in `tests/wake_client_postgres_3470.rs`.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE any
// `cfg`, so they still apply on a leg where the module docs above are linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

mod wake_hub_harness;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ai_memory::cli::wake_listen::{
    Resolved, WakeListenArgs, catch_up_read, resolve, wait_for_wake,
};
use ai_memory::identity::hub_delegation::{A2A_HUB_SCOPE, DelegationWire, sign_hub_delegation};
use ai_memory::identity::keypair;
use ai_memory::wake_client::{
    HubJoinBundle, SessionConfig, WakeClientConfig, WakeReason, WakeSignal, WakeStream,
};
use ai_memory::wake_hub::delegation_verifier::{
    AllowlistCache, EnrolledRoot, RootBindAuthority, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::frame::{Frame, Kind, WakeMeta};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_sink::BACKSTOP_POLL_MAX;
use ai_memory::wake_sink::in_process::install_in_process;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use std::os::unix::fs::PermissionsExt as _;
use wake_hub_harness::Harness;

/// Per-test agent id — the wake bus is process-wide, so nothing assumes it is
/// the only publisher.
fn uid(prefix: &str) -> String {
    format!("ai:{prefix}-{}", uuid::Uuid::new_v4())
}

fn temp_db() -> PathBuf {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    std::mem::forget(f);
    db_path
}

/// Everything `ai-memory identity delegate --scope a2a-hub` leaves on disk,
/// staged the way it writes it: an enrolled keypair plus a 0600 bundle that
/// holds a DELEGATED seed and never the enrolled private half.
struct StagedIdentity {
    dir: tempfile::TempDir,
    agent_id: String,
    enrolled_public: ed25519_dalek::VerifyingKey,
}

impl StagedIdentity {
    fn stage(agent_id: &str, hub_id: &str, ttl_secs: i64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let enrolled = keypair::generate(agent_id).expect("generate enrolled");
        keypair::save(&enrolled, dir.path()).expect("save enrolled");
        let root = enrolled.private.clone().expect("private half");

        let delegate = keypair::generate(agent_id).expect("generate delegate");
        let delegate_private = delegate.private.clone().expect("private half");
        let now = chrono::Utc::now();
        let mut wire = DelegationWire {
            principal: agent_id.to_owned(),
            scope: A2A_HUB_SCOPE.to_owned(),
            delegate_key_id: delegate.public.to_bytes(),
            hub_id: hub_id.to_owned(),
            not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            not_after: (now + chrono::Duration::seconds(ttl_secs))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            signature: [0u8; 64],
        };
        wire.signature = sign_hub_delegation(&root, &wire.as_delegation()).expect("sign");
        let bundle = json!({
            "version": 1,
            "agent_id": agent_id,
            "hub_id": hub_id,
            "delegation_b64": URL_SAFE_NO_PAD.encode(wire.encode().expect("encode")),
            "delegate_private_b64": URL_SAFE_NO_PAD.encode(delegate_private.to_bytes()),
            "not_before": wire.not_before,
            "not_after": wire.not_after,
        });
        let path = HubJoinBundle::default_path(dir.path(), agent_id);
        std::fs::write(&path, serde_json::to_vec_pretty(&bundle).expect("json")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        Self {
            dir,
            agent_id: agent_id.to_owned(),
            enrolled_public: enrolled.public,
        }
    }

    fn key_dir(&self) -> &Path {
        self.dir.path()
    }

    fn bundle_path(&self) -> PathBuf {
        HubJoinBundle::default_path(self.dir.path(), &self.agent_id)
    }
}

/// The SHIPPED verifier over a real allowlist — no permissive test double.
fn production_verifier(staged: &StagedIdentity) -> Arc<ScopedDelegationVerifier<AllowlistCache>> {
    let mut cache = AllowlistCache::new();
    cache.insert(
        &staged.agent_id,
        EnrolledRoot {
            pubkey: staged.enrolled_public,
            authority: RootBindAuthority::PossessionProof,
        },
    );
    Arc::new(ScopedDelegationVerifier::new(cache))
}

fn listener_config() -> WakeClientConfig {
    WakeClientConfig {
        // Tight enough that a test never waits a minute for the backstop, and
        // still inside the normative bound.
        poll_interval: Duration::from_secs(5),
        ..WakeClientConfig::default()
    }
}

fn start_listener(harness: &Harness, staged: &StagedIdentity) -> WakeStream {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let bundle = HubJoinBundle::load(
        &staged.bundle_path(),
        &harness.hub_id,
        staged.key_dir(),
        &now,
    )
    .expect("the bundle `identity delegate` writes must load");
    WakeStream::start(
        listener_config(),
        Some((
            SessionConfig::new(harness.socket.clone(), harness.hub_id.clone()),
            Arc::new(bundle),
        )),
    )
    .expect("start")
}

/// Await the next signal, failing the test rather than hanging forever.
async fn next_signal(stream: &mut WakeStream) -> WakeSignal {
    tokio::time::timeout(Duration::from_secs(15), stream.next())
        .await
        .expect("timed out waiting for a wake signal")
        .expect("the listener's producers must not stop")
}

/// Await a signal that came from the HUB, skipping backstop ticks.
async fn next_hub_signal(stream: &mut WakeStream) -> WakeSignal {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no hub-driven signal arrived"
        );
        let signal = next_signal(stream).await;
        if signal.reason.is_hub_driven() {
            return signal;
        }
        stream.note_read();
    }
}

/// Encode a substrate-shaped wake the way #3469's producer does.
fn substrate_wake(to: &str, row_id: &str, seq: u64) -> bytes::Bytes {
    let payload = WakeMeta {
        inbox_row_id: row_id.to_owned(),
        namespace: ai_memory::inbox_namespace(to),
        sender: "ai:alice".to_owned(),
        digest: vec![9u8; 32],
        seq_high_watermark: seq,
    }
    .encode()
    .expect("wake meta");
    Frame::new(
        Kind::Wake,
        ai_memory::identity::sentinels::WAKE_HUB_PRODUCER,
        to,
        payload,
    )
    .encode()
    .expect("wake frame")
}

// ---------------------------------------------------------------------------
// The wiring proof
// ---------------------------------------------------------------------------

/// ALLOWED, and the wiring proof for the whole issue: a committed
/// `memory_notify` reaches a `wake-listen` session over a real socket, past
/// the SHIPPED delegation verifier, and the listener turns that hint into ONE
/// catch-up inbox read that returns the durable row.
///
/// This is the ONE test in this binary that installs a process-wide sink;
/// `install_sink` deliberately refuses a second installation.
#[tokio::test]
async fn a_real_notify_wakes_a_real_listener_and_it_reads_the_durable_row_3470() {
    let agent = uid("listener");
    let staged = StagedIdentity::stage(&agent, "hub-3470-wiring", 3_600);
    let harness = Harness::start(
        |cfg| cfg.hub_id = "hub-3470-wiring".to_owned(),
        production_verifier(&staged),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let _metrics =
        install_in_process(harness.router()).expect("this binary installs exactly one wake sink");

    let mut stream = start_listener(&harness, &staged);
    let welcome = next_hub_signal(&mut stream).await;
    assert_eq!(
        welcome.reason,
        WakeReason::Welcome,
        "an admitted session is welcomed, and the welcome is itself a catch-up read"
    );
    stream.note_read();

    // A REAL notify on a REAL store.
    let db_path = temp_db();
    let conn = ai_memory::db::open(&db_path).expect("open");
    let secret = "SUPER-SECRET-NOTIFY-BODY-3470";
    let envelope = ai_memory::mcp::handle_notify(
        &conn,
        &db_path,
        &json!({
            "target_agent_id": agent,
            "title": "SUBJECT-LINE-3470",
            "payload": secret,
        }),
        &ai_memory::config::ResolvedTtl::default(),
        Some("ai:alice"),
    )
    .expect("notify");
    let row_id = envelope["id"].as_str().expect("id").to_owned();

    let wake = next_hub_signal(&mut stream).await;
    assert_eq!(wake.reason, WakeReason::Wake);
    let meta = wake.meta.as_ref().expect("a wake carries its hint");
    assert_eq!(
        meta.inbox_row_id, row_id,
        "the hint must name the durable row the notify committed"
    );
    assert_eq!(meta.namespace, ai_memory::inbox_namespace(&agent));
    assert!(
        meta.sender.contains("alice"),
        "the hint names the writer as METADATA — the resolved caller identity, \
         not a claim the hub checked: {}",
        meta.sender
    );
    assert_eq!(meta.digest.len(), 32, "a digest, never a body");
    assert!(meta.seq_high_watermark > 0);
    let rendered = format!("{meta:?}");
    assert!(
        !rendered.contains(secret) && !rendered.contains("SUBJECT-LINE-3470"),
        "no body and no title may reach a listener: {rendered}"
    );

    // ONE catch-up read, through the existing inbox funnel, returns the row.
    let inbox = catch_up_read(&db_path, &agent, false, None)
        .await
        .expect("catch-up read");
    assert_eq!(inbox["count"].as_u64(), Some(1));
    let messages = inbox["messages"].as_array().expect("messages");
    assert_eq!(messages[0]["id"].as_str(), Some(row_id.as_str()));
    stream.note_read();

    drop(stream);
    harness.stop().await;
}

// ---------------------------------------------------------------------------
// Self-heal
// ---------------------------------------------------------------------------

/// A `seq_high_watermark` gap costs EXACTLY ONE extra catch-up read and is
/// reported as a gap, so an operator can tell "the hub dropped hints" from
/// "nothing happened".
#[tokio::test]
async fn a_watermark_gap_is_reported_and_costs_one_extra_read_3470() {
    let agent = uid("gap");
    let staged = StagedIdentity::stage(&agent, "hub-3470-gap", 3_600);
    let harness = Harness::start(
        |cfg| cfg.hub_id = "hub-3470-gap".to_owned(),
        production_verifier(&staged),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut stream = start_listener(&harness, &staged);
    assert_eq!(
        next_hub_signal(&mut stream).await.reason,
        WakeReason::Welcome
    );
    stream.note_read();

    let router = harness.router();
    assert_eq!(
        router.deliver(&agent, &substrate_wake(&agent, "row-a", 5), "row-a"),
        ai_memory::wake_hub::routing::Delivery::Delivered,
        "the listener's session must be routable"
    );
    let first = next_hub_signal(&mut stream).await;
    assert_eq!(
        first.reason,
        WakeReason::Wake,
        "the baseline wake is no gap"
    );
    assert_eq!(first.missed, 0);
    stream.note_read();

    assert_eq!(
        router.deliver(&agent, &substrate_wake(&agent, "row-b", 9), "row-b"),
        ai_memory::wake_hub::routing::Delivery::Delivered
    );
    let gapped = next_hub_signal(&mut stream).await;
    assert_eq!(gapped.reason, WakeReason::Gap);
    assert_eq!(
        gapped.missed, 3,
        "three wakes happened that this listener did not see"
    );
    assert_eq!(
        gapped.meta.as_ref().map(|m| m.inbox_row_id.as_str()),
        Some("row-b")
    );
    stream.note_read();

    drop(stream);
    harness.stop().await;
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

/// DENIED: an agent the hub's allowlist does not know cannot join — and the
/// listener DEGRADES rather than dying: the bounded backstop poll keeps
/// delivering while the reconnect ladder runs.
#[tokio::test]
async fn an_unenrolled_listener_is_refused_and_degrades_to_the_backstop_3470() {
    let allowed = uid("enrolled");
    let staged_allowed = StagedIdentity::stage(&allowed, "hub-3470-deny", 3_600);
    // A DIFFERENT agent, staged against the same hub but absent from the
    // allowlist the hub was built with.
    let stranger = uid("stranger");
    let staged_stranger = StagedIdentity::stage(&stranger, "hub-3470-deny", 3_600);

    let harness = Harness::start(
        |cfg| cfg.hub_id = "hub-3470-deny".to_owned(),
        production_verifier(&staged_allowed),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let mut stream = start_listener(&harness, &staged_stranger);
    // The hub refuses the handshake, so the ONLY signal that can arrive is
    // the backstop — which is exactly the documented degraded mode.
    let signal = next_signal(&mut stream).await;
    assert_eq!(
        signal.reason,
        WakeReason::Backstop,
        "a refused listener still reads its inbox on the bounded poll"
    );
    let snap = stream.metrics().snapshot();
    assert_eq!(snap.sessions, 0, "no session was ever admitted");
    assert!(
        snap.reconnects >= 1,
        "the refusal must drive the bounded reconnect ladder"
    );

    drop(stream);
    harness.stop().await;
}

/// DENIED, before a byte reaches the wire: a bundle minted for another hub,
/// a group-readable bundle, and a bundle whose agent is not the one this
/// listener watches.
#[tokio::test]
async fn the_bundle_gate_refuses_before_the_socket_is_dialled_3470() {
    let agent = uid("gate");
    let staged = StagedIdentity::stage(&agent, "hub-3470-gate", 3_600);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Wrong hub.
    let err = HubJoinBundle::load(
        &staged.bundle_path(),
        "some-other-hub",
        staged.key_dir(),
        &now,
    )
    .expect_err("a delegation is bound to ONE hub");
    assert!(format!("{err:#}").contains("hub"), "{err:#}");

    // Group-readable bundle.
    std::fs::set_permissions(staged.bundle_path(), std::fs::Permissions::from_mode(0o640))
        .expect("chmod");
    let err = HubJoinBundle::load(
        &staged.bundle_path(),
        "hub-3470-gate",
        staged.key_dir(),
        &now,
    )
    .expect_err("another local user must not be able to join as this agent");
    assert!(format!("{err:#}").contains("0640"), "{err:#}");
    std::fs::set_permissions(staged.bundle_path(), std::fs::Permissions::from_mode(0o600))
        .expect("chmod");

    // A listener may only join as the agent whose inbox it reads.
    let listen = WakeListenArgs {
        agent_id: Some(uid("someone-else")),
        socket: Some(PathBuf::from("/dev/null")),
        hub_id: Some("hub-3470-gate".to_owned()),
        key_dir: Some(staged.key_dir().to_path_buf()),
        bundle: Some(staged.bundle_path()),
        poll_secs: Some(5),
        unread_only: false,
        limit: None,
        json: false,
        exec: None,
        once: true,
        no_hub: false,
    };
    let resolved =
        resolve(&listen, &ai_memory::config::AppConfig::default(), None).expect("resolve");
    let err = ai_memory::cli::wake_listen::start_stream(&resolved)
        .expect_err("a bundle for another agent is not this listener's credential");
    assert!(
        format!("{err:#}").contains("may only join as the agent"),
        "{err:#}"
    );
}

// ---------------------------------------------------------------------------
// `inbox --wait`
// ---------------------------------------------------------------------------

/// `ai-memory inbox --wait` on a host with NO hub returns on the bounded
/// backstop rather than blocking forever — a lost or absent hub degrades
/// LATENCY and nothing else.
#[tokio::test]
async fn inbox_wait_returns_on_the_bounded_backstop_with_no_hub_3470() {
    let agent = uid("waiter");
    let listen = WakeListenArgs {
        agent_id: Some(agent),
        socket: None,
        hub_id: None,
        key_dir: Some(PathBuf::from("/nonexistent-3470")),
        bundle: None,
        poll_secs: Some(1),
        unread_only: false,
        limit: None,
        json: false,
        exec: None,
        once: true,
        no_hub: true,
    };
    let resolved: Resolved =
        resolve(&listen, &ai_memory::config::AppConfig::default(), None).expect("resolve");
    assert!(resolved.client.poll_interval <= BACKSTOP_POLL_MAX);

    let started = std::time::Instant::now();
    let signal = wait_for_wake(&resolved, Some(Duration::from_secs(20)))
        .await
        .expect("wait")
        .expect("the backstop must fire inside its own bound");
    assert_eq!(signal.reason, WakeReason::Backstop);
    assert!(
        started.elapsed() < BACKSTOP_POLL_MAX * 2,
        "the wait must be bounded by the poll interval, not open-ended"
    );

    // A timeout is a bounded, honest "nothing arrived" — never an error, and
    // never a reason for the caller to skip the durable read.
    let mut slow = listen;
    slow.poll_secs = Some(30);
    let resolved = resolve(&slow, &ai_memory::config::AppConfig::default(), None).expect("resolve");
    let none = wait_for_wake(&resolved, Some(Duration::from_millis(250)))
        .await
        .expect("a timeout is not a failure");
    assert!(none.is_none());
}

// ---------------------------------------------------------------------------
// Fixture server for the SDK real-socket legs
// ---------------------------------------------------------------------------

/// Serve a REAL hub, with the REAL file-backed delegation verifier, so the
/// Python and TypeScript SDK suites can run their opt-in real-socket legs
/// against the shipped Rust implementation rather than a mock.
///
/// `#[ignore]` because it is a fixture, not an assertion: it blocks for a
/// while by design. Run it as
///
/// ```bash
/// AI_MEMORY_TEST_WAKE_HUB_DIR=<dir> AI_MEMORY_TEST_WAKE_HUB_SECS=90 \
///   cargo test --test wake_client_3470 -- --ignored --nocapture
/// ```
///
/// It writes `<dir>/fixture.json` naming the socket, the 0600 delegation
/// bundle and the hub id, then keeps the allowlist snapshot fresh (the hub
/// refuses a cache older than `identity::hub_cache::MAX_CACHE_AGE_SECS`)
/// until the window closes.
#[tokio::test]
#[ignore = "fixture server for the SDK real-socket legs; run with --ignored"]
async fn serves_a_real_hub_for_the_sdk_clients_3470() {
    let Ok(dir) = std::env::var("AI_MEMORY_TEST_WAKE_HUB_DIR") else {
        eprintln!("skip: set AI_MEMORY_TEST_WAKE_HUB_DIR to a 0700 directory");
        return;
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let secs: u64 = std::env::var("AI_MEMORY_TEST_WAKE_HUB_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);

    let hub_id = "ai-memory-wake-hub";
    let agent = uid("sdk-listener");
    let staged = StagedIdentity::stage(&agent, hub_id, 3_600);

    // The bundle the SDKs load, at a path they can reach, mode 0600.
    let bundle_path = dir.join("bundle.json");
    std::fs::copy(staged.bundle_path(), &bundle_path).expect("copy bundle");
    std::fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod bundle");

    // The REAL derived allowlist file the shipped verifier reads.
    let allow_path = dir.join("allow.json");
    let write_allowlist = || {
        let now = chrono::Utc::now();
        let doc = serde_json::json!({
            "version": 2,
            "refreshed_at": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "agents": [{
                "agent_id": agent,
                "pubkey_b64": ai_memory::identity::keypair::encode_public_base64(
                    &staged.enrolled_public,
                ),
                "bind_authority": "possession_proof",
                "bound_at": (now - chrono::Duration::seconds(5))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "revoked_keys": [],
            }],
        });
        std::fs::write(&allow_path, serde_json::to_vec_pretty(&doc).expect("json"))
            .expect("write allowlist");
        std::fs::set_permissions(&allow_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod allowlist");
    };
    write_allowlist();

    let verifier = Arc::new(ScopedDelegationVerifier::new(
        ai_memory::wake_hub::delegation_verifier::ReloadingAllowlist::new(allow_path.clone())
            .expect("the shipped file-backed resolver must load a fresh snapshot"),
    ));
    let harness = Harness::start(
        |cfg| cfg.hub_id = "ai-memory-wake-hub".to_owned(),
        verifier,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let fixture = serde_json::json!({
        "socket": harness.socket.display().to_string(),
        "bundle": bundle_path.display().to_string(),
        "hub_id": harness.hub_id,
        "agent_id": agent,
    });
    std::fs::write(
        dir.join("fixture.json"),
        serde_json::to_vec_pretty(&fixture).expect("json"),
    )
    .expect("write fixture");
    println!("wake-hub fixture ready: {fixture}");

    // Keep the snapshot fresh: the hub REFUSES a cache older than
    // MAX_CACHE_AGE_SECS, which is the point — a stale allowlist cannot
    // extend authority.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(15)).await;
        write_allowlist();
    }
    harness.stop().await;
}
