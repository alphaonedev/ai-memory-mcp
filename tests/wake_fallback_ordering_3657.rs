// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3657 (review rework) — the fallback gauge's ORDERING and OWNERSHIP,
//! pinned on a MULTI-THREAD runtime.
//!
//! `UdsWakeSink::spawn` stamps `connecting` before it spawns the forwarder
//! task, and from then on only that task writes the gauge. On a
//! multi-thread runtime the task may run on another worker before `spawn`
//! returns; if `connecting` were stamped after the spawn it could land on top
//! of the task's own `hub live` or `backstop`. This test uses a hub that
//! ACCEPTS the socket but never answers the hello, so the only writes that
//! can happen are: `connecting` (from `spawn`, synchronously) and, after the
//! handshake deadline, `backstop` (from the task). The gauge must read
//! `connecting` the instant `install_uds` returns — on every worker thread
//! interleaving — and `backstop` after the deadline, never `unobserved` in
//! between and never `connecting` after the task has spoken.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::sentinels::WAKE_HUB_PRODUCER;
use ai_memory::metrics::{
    self, WAKE_FALLBACK_BACKSTOP, WAKE_FALLBACK_CONNECTING, WAKE_FALLBACK_UNOBSERVED,
};
use ai_memory::wake_sink::uds::{
    CredentialError, HelloCredential, JoinCredential, UdsSinkConfig, install_uds,
};
use ed25519_dalek::{Signer as _, SigningKey};

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

async fn wait_for_state(want: i64, budget: Duration) -> i64 {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let now = metrics::wake_fallback_state();
        if now == want || tokio::time::Instant::now() >= deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connecting_is_stamped_before_the_task_can_write_on_a_multi_thread_runtime_3657() {
    assert_eq!(
        metrics::wake_fallback_state(),
        WAKE_FALLBACK_UNOBSERVED,
        "a fresh process has observed nothing"
    );
    // A tempdir-scoped socket path (never /tmp, #3669 / operator directive).
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("mute-hub.sock");
    // A hub that accepts and then says NOTHING: the forwarder connects, waits
    // for the hello challenge, and only the handshake deadline can move it.
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind mute hub");
    let held: Arc<tokio::sync::Mutex<Vec<tokio::net::UnixStream>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let keep = Arc::clone(&held);
    let acceptor = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            keep.lock().await.push(stream);
        }
    });

    let mut cfg = UdsSinkConfig::with_socket_path(socket);
    cfg.handshake_timeout = Duration::from_millis(600);
    // Long reconnect delays so the task's second attempt cannot fold a fresh
    // `connecting` into the window this test observes `backstop` in.
    cfg.reconnect_base = Duration::from_secs(30);
    let _metrics = install_uds(
        cfg,
        Arc::new(TestCredential(SigningKey::from_bytes(&[7u8; 32]))),
    )
    .expect("the forwarder installs for an enrolled producer credential");
    // ORDERING: the very first read after install — with no await in between
    // — sees `connecting`. The task may already be running on another worker,
    // but it cannot have written anything yet: the mute hub has not answered,
    // and the deadline is 600 ms away.
    assert_eq!(
        metrics::wake_fallback_state(),
        WAKE_FALLBACK_CONNECTING,
        "#3657 review: `connecting` must be visible the instant install returns"
    );
    // It stays `connecting` while the handshake is pending ...
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(metrics::wake_fallback_state(), WAKE_FALLBACK_CONNECTING);
    // ... and the OWNING TASK flips it to `backstop` when the deadline passes.
    assert_eq!(
        wait_for_state(WAKE_FALLBACK_BACKSTOP, Duration::from_secs(5)).await,
        WAKE_FALLBACK_BACKSTOP,
        "the forwarder task owns the terminal transition"
    );
    // Nothing else writes it back: `connecting` was a one-time pre-spawn stamp.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(metrics::wake_fallback_state(), WAKE_FALLBACK_BACKSTOP);
    acceptor.abort();
}

/// The race the pre-rework order actually lost: a hub that fails INSTANTLY
/// (no socket at the path) lets the forwarder task write `backstop` within
/// microseconds of being spawned. If `connecting` were stamped AFTER
/// `handle.spawn`, on a multi-thread runtime the task's `backstop` can land
/// first and the late stamp then buries it — the gauge advertises a
/// forwarder that is already dead, and nothing ever corrects it (the task is
/// in a 30 s back-off and writes nothing more). With the stamp BEFORE the
/// spawn, `backstop` is the last word every time. Repeated so a lucky
/// interleaving cannot hide the defect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_connecting_never_buries_the_owning_tasks_backstop_3657() {
    let dir = tempfile::tempdir().expect("tempdir");
    for round in 0..40u32 {
        let mut cfg = UdsSinkConfig::with_socket_path(dir.path().join("absent-hub.sock"));
        cfg.reconnect_base = Duration::from_secs(30);
        cfg.reconnect_jitter = Duration::ZERO;
        let sink = ai_memory::wake_sink::uds::UdsWakeSink::spawn(
            cfg,
            Arc::new(TestCredential(SigningKey::from_bytes(&[9u8; 32]))),
        )
        .expect("spawn");
        // The owning task's terminal write must be the LAST write: it lands
        // (the connect fails at once) and is never overwritten.
        assert_eq!(
            wait_for_state(WAKE_FALLBACK_BACKSTOP, Duration::from_secs(3)).await,
            WAKE_FALLBACK_BACKSTOP,
            "round {round}: a late `connecting` buried the task's `backstop`"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            metrics::wake_fallback_state(),
            WAKE_FALLBACK_BACKSTOP,
            "round {round}: the gauge must not revert after the owner wrote it"
        );
        drop(sink);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
