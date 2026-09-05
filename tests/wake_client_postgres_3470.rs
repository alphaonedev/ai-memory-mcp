// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3470 — the POSTGRES half of the wake-hub client control.
//!
//! `tests/wake_client_3470.rs` pins the sqlite lanes. The listener itself is
//! backend-blind — it carries no store handle and reads nothing until a hint
//! arrives — but the two ends it joins are NOT: `SqliteStore::notify` and
//! `PostgresStore::notify` are separate implementations of the same trait
//! method, and the row a hint names has to be readable back on the same
//! backend that committed it. So "a committed notify wakes a real listener,
//! and the row it named is there" is proved on both.
//!
//! What this file proves that the sqlite file cannot: the wake a POSTGRES
//! notify produces reaches a REAL `wake-listen` session over a REAL socket,
//! past the SHIPPED delegation verifier, naming a row that
//! `PostgresStore::get` then returns with its body intact — while the hint
//! itself carried a digest and never a body.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset, so the
//! default CI leg is unaffected.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE the
// `#![cfg]` so they still apply on a leg where the cfg empties the crate but
// the `//!` module docs above are still linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]
#![cfg(feature = "sal-postgres")]

mod wake_hub_harness;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::hub_delegation::{A2A_HUB_SCOPE, DelegationWire, sign_hub_delegation};
use ai_memory::identity::keypair;
use ai_memory::inbox_wake::{InboxEvent, InboxWakeSink as _, subscribe};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore as _};
use ai_memory::wake_client::{
    HubJoinBundle, SessionConfig, WakeClientConfig, WakeReason, WakeSignal, WakeStream,
};
use ai_memory::wake_hub::delegation_verifier::{
    AllowlistCache, EnrolledRoot, RootBindAuthority, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_sink::in_process::InProcessWakeSink;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use std::os::unix::fs::PermissionsExt as _;
use wake_hub_harness::Harness;

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("ai:{prefix}-{}", uuid::Uuid::new_v4())
}

/// The artefacts `ai-memory identity delegate --scope a2a-hub` leaves behind:
/// an enrolled keypair plus a 0600 bundle holding a DELEGATED seed and never
/// the enrolled private half.
struct StagedIdentity {
    dir: tempfile::TempDir,
    agent_id: String,
    enrolled_public: ed25519_dalek::VerifyingKey,
}

impl StagedIdentity {
    fn stage(agent_id: &str, hub_id: &str) -> Self {
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
            not_after: (now + chrono::Duration::seconds(3_600))
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
        WakeClientConfig {
            poll_interval: Duration::from_secs(5),
            ..WakeClientConfig::default()
        },
        Some((
            SessionConfig::new(harness.socket.clone(), harness.hub_id.clone()),
            Arc::new(bundle),
        )),
    )
    .expect("start")
}

async fn next_hub_signal(stream: &mut WakeStream) -> WakeSignal {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no hub-driven signal arrived"
        );
        let signal = tokio::time::timeout(Duration::from_secs(15), stream.next())
            .await
            .expect("timed out waiting for a wake signal")
            .expect("the listener's producers must not stop");
        if signal.reason.is_hub_driven() {
            return signal;
        }
        stream.note_read();
    }
}

/// Drain the process-wide bus until a wake for `recipient` arrives.
async fn wake_for(
    rx: &mut tokio::sync::broadcast::Receiver<InboxEvent>,
    recipient: &str,
) -> Option<InboxEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => return Some(ev),
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// ALLOWED, postgres funnel: a committed `PostgresStore::notify` wakes a REAL
/// `wake-listen` session over a REAL socket past the SHIPPED verifier, the
/// hint names the durable row, and `PostgresStore::get` returns that row with
/// its body — a body the wake plane never carried.
#[tokio::test]
async fn a_postgres_notify_wakes_a_real_listener_and_the_row_reads_back_3470() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let recipient = uid("listener-pg");
    let staged = StagedIdentity::stage(&recipient, "hub-3470-pg");
    let harness = Harness::start(
        |cfg| cfg.hub_id = "hub-3470-pg".to_owned(),
        production_verifier(&staged),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut stream = start_listener(&harness, &staged);
    assert_eq!(
        next_hub_signal(&mut stream).await.reason,
        WakeReason::Welcome,
        "an admitted session is welcomed, and the welcome IS a catch-up read"
    );
    stream.note_read();

    // The #3469 sink, driven from the bus exactly as `serve` drives it — the
    // whole point is that the LISTENER cannot tell which backend committed.
    let sink = InProcessWakeSink::for_router(harness.router());
    let mut rx = subscribe();

    let secret = "SUPER-SECRET-NOTIFY-BODY-3470-PG";
    let ctx = CallerContext::for_agent("ai:alice");
    let row_id = store
        .notify(
            &ctx,
            &recipient,
            "SUBJECT-LINE-3470-PG",
            secret,
            Some(5),
            None,
            None,
        )
        .await
        .expect("pg notify");
    let event = wake_for(&mut rx, &recipient)
        .await
        .expect("the postgres adapter must publish a wake");
    sink.on_wake(&event);

    let wake = next_hub_signal(&mut stream).await;
    assert_eq!(wake.reason, WakeReason::Wake);
    let meta = wake.meta.as_ref().expect("a wake carries its hint");
    assert_eq!(
        meta.inbox_row_id, row_id,
        "the hint must name the row the postgres notify committed"
    );
    assert_eq!(meta.namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(meta.digest.len(), 32, "a digest, never a body");
    assert!(meta.seq_high_watermark > 0);
    let rendered = format!("{meta:?}");
    assert!(
        !rendered.contains(secret) && !rendered.contains("SUBJECT-LINE-3470-PG"),
        "no body and no title may reach a listener: {rendered}"
    );

    // The catch-up read, on the backend that committed it: the DURABLE row is
    // the record, and it is there with its body.
    let row = store.get(&ctx, &row_id).await.expect("the row is readable");
    assert_eq!(row.id, row_id);
    assert_eq!(row.namespace, ai_memory::inbox_namespace(&recipient));
    assert!(
        row.content.contains(secret),
        "the body lives in the durable row, which is exactly why the hint need not carry it"
    );
    stream.note_read();

    drop(stream);
    harness.stop().await;
}

/// DENIED, postgres funnel: a postgres notify for ANOTHER agent never reaches
/// this listener. The hub's route table is keyed by the identity a hello
/// authenticated, so own-inbox scope holds on this backend too.
#[tokio::test]
async fn a_postgres_wake_for_another_agent_never_reaches_this_listener_3470() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let mine = uid("carol-pg");
    let theirs = uid("mallory-pg");
    let staged = StagedIdentity::stage(&mine, "hub-3470-pg-deny");
    let harness = Harness::start(
        |cfg| cfg.hub_id = "hub-3470-pg-deny".to_owned(),
        production_verifier(&staged),
        Arc::new(SameUidAuthorizer::for_current_process()),
    );
    let mut stream = start_listener(&harness, &staged);
    assert_eq!(
        next_hub_signal(&mut stream).await.reason,
        WakeReason::Welcome
    );
    stream.note_read();

    let sink = InProcessWakeSink::for_router(harness.router());
    let mut rx = subscribe();
    let ctx = CallerContext::for_agent("ai:alice");
    store
        .notify(&ctx, &theirs, "ping", "body", Some(5), None, None)
        .await
        .expect("pg notify");
    let event = wake_for(&mut rx, &theirs).await.expect("wake published");
    sink.on_wake(&event);

    // Only the bounded backstop may fire; a hub-driven signal here would mean
    // one agent's mail woke another.
    let signal = tokio::time::timeout(Duration::from_secs(12), stream.next())
        .await
        .expect("the backstop must still deliver")
        .expect("producers alive");
    assert_eq!(
        signal.reason,
        WakeReason::Backstop,
        "another agent's wake must never reach this listener"
    );
    assert_eq!(sink.metrics().snapshot().dropped_unknown, 1);

    drop(stream);
    harness.stop().await;
}
