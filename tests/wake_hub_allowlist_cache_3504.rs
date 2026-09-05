// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` allowlist-snapshot reuse and refresh, end to end
//! (issue [#3504](https://github.com/alphaonedev/ai-memory-mcp/issues/3504),
//! follow-up to [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! The unit tests in `src/wake_hub/allowlist_reload.rs` cover the decision
//! table in isolation. This suite proves the same properties the way
//! production reaches them: a snapshot published by the REAL exporter
//! (`ai-memory identity hub-cache` -> `identity::hub_cache::publish`), read by
//! the REAL verifier, over a REAL Unix domain socket.
//!
//! Two halves, and the second is why the file is not unit tests:
//!
//! * The CACHE half proves that reuse changed the cost and NOT the decision —
//!   one parse for many hellos, a replaced file honoured immediately, and an
//!   expired or mode-widened snapshot still refused.
//! * The REFRESHER half proves the loop an operator is told to run (the
//!   systemd timer / launchd job) publishes ATOMICALLY at mode 0600 and can
//!   only ever NARROW authority, on BOTH backends — the postgres derivation is
//!   a separate implementation of the same export, so "the refresh never
//!   widens authority" has to be proved twice.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

mod wake_hub_harness;

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::identity::hub_cache;
use ai_memory::identity::hub_delegation::{A2A_HUB_SCOPE, DelegationWire, sign_hub_delegation};
use ai_memory::wake_hub::allowlist_reload::SnapshotFreshness;
use ai_memory::wake_hub::delegation_verifier::{
    ALLOWLIST_FILE_VERSION, AllowlistCache, AllowlistFile, ReloadingAllowlist,
    RootKeyResolver as _, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::frame::{ErrorCode, Kind};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use wake_hub_harness::Harness;

const AGENT: &str = "agent-cache-3504";
const HUB: &str = "ai-memory-wake-hub";

fn enrolled_key() -> SigningKey {
    SigningKey::from_bytes(&[91u8; 32])
}

fn delegated_key() -> SigningKey {
    SigningKey::from_bytes(&[92u8; 32])
}

/// An owner-only directory, so the snapshot inside it is not merely 0600 but
/// unreachable to anyone else in the first place.
fn owner_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    dir
}

/// A snapshot naming one agent, stamped `age_secs` in the past, published the
/// way the exporter publishes.
fn publish_snapshot(path: &Path, key: &SigningKey, age_secs: i64) {
    let refreshed = chrono::Utc::now() - chrono::Duration::seconds(age_secs);
    let file = AllowlistFile {
        version: ALLOWLIST_FILE_VERSION,
        refreshed_at: Some(refreshed.to_rfc3339()),
        agents: vec![ai_memory::wake_hub::delegation_verifier::AllowlistEntry {
            agent_id: AGENT.to_owned(),
            pubkey_b64: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            bind_authority: "possession_proof".to_owned(),
            bound_at: "2026-09-01T00:00:00Z".to_owned(),
            revoked_keys: Vec::new(),
            // #3505 — this suite's agent proves no namespace read scope, so
            // its topics stay own-inbox only exactly as before.
            readable_namespaces: Vec::new(),
        }],
    };
    hub_cache::publish(path, &file).expect("publish");
}

/// Mint a delegation the way `ai-memory identity delegate` does.
fn mint(ttl_secs: i64) -> Bytes {
    let now = chrono::Utc::now();
    let mut wire = DelegationWire {
        principal: AGENT.to_owned(),
        scope: A2A_HUB_SCOPE.to_owned(),
        delegate_key_id: delegated_key().verifying_key().to_bytes(),
        hub_id: HUB.to_owned(),
        not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        not_after: (now + chrono::Duration::seconds(ttl_secs))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        signature: [0u8; 64],
    };
    wire.signature = sign_hub_delegation(&enrolled_key(), &wire.as_delegation()).expect("mint");
    Bytes::from(wire.encode().expect("encode"))
}

/// The defect #3504 fixes, over a REAL socket: every hello re-read and
/// re-parsed the snapshot, so the hub did O(connections) JSON parses per
/// second at the 1 Hz per-session revalidation. The permission gate must
/// still run on every one of them.
#[tokio::test]
async fn many_hellos_against_one_snapshot_parse_it_once_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 1);

    let verifier = Arc::new(ScopedDelegationVerifier::new(
        ReloadingAllowlist::new(path).expect("arm"),
    ));
    let hub = Harness::start(
        |_| {},
        Arc::clone(&verifier) as Arc<dyn ai_memory::wake_hub::identity::HelloVerifier>,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    for _ in 0..8 {
        let mut client = hub.connect().await;
        client.delegation = mint(3_600);
        client
            .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
            .await;
        assert_eq!(
            client.expect_frame().await.kind,
            Kind::Welcome,
            "the snapshot admits this agent"
        );
    }

    let resolver = verifier.resolver();
    assert!(
        resolver.open_count() >= 8,
        "the 0600 / owner / regular-file gate must run on EVERY hello, not once; \
         opens = {}",
        resolver.open_count()
    );
    assert_eq!(
        resolver.parse_count(),
        1,
        "an unchanged snapshot must be parsed once for all eight hellos"
    );
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 0);
    hub.stop().await;
}

/// A REFRESH lands a new inode; the hub must honour it on the very next
/// hello, inside the reuse TTL. This is what keeps a revocation effective
/// within the hub's one-second session revalidation.
#[tokio::test]
async fn a_refreshed_snapshot_is_honoured_on_the_next_hello_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 1);

    let verifier = Arc::new(ScopedDelegationVerifier::new(
        ReloadingAllowlist::new(path.clone()).expect("arm"),
    ));
    let hub = Harness::start(
        |_| {},
        Arc::clone(&verifier) as Arc<dyn ai_memory::wake_hub::identity::HelloVerifier>,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let mut admitted = hub.connect().await;
    admitted.delegation = mint(3_600);
    admitted
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    assert_eq!(admitted.expect_frame().await.kind, Kind::Welcome);
    assert_eq!(verifier.resolver().parse_count(), 1);

    // The refresher republishes with a DIFFERENT enrolled root — the shape a
    // key rotation takes. No sleep: the reuse key is the file's identity, so
    // a replacement is picked up immediately, not after the TTL.
    publish_snapshot(&path, &SigningKey::from_bytes(&[93u8; 32]), 1);

    let mut refused = hub.connect().await;
    refused.delegation = mint(3_600);
    refused
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    refused.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    refused.expect_closed().await;
    assert_eq!(
        verifier.resolver().parse_count(),
        2,
        "a replaced snapshot must force a re-read even inside the reuse TTL"
    );
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 1);
    hub.stop().await;
}

/// The regression the issue asks for by name: a STALE file is still refused
/// after the cache lands. The parse is warm and the delegation is perfect —
/// only the snapshot's own age refuses it.
#[tokio::test]
async fn a_stale_snapshot_is_still_refused_after_the_cache_landed_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 1);

    let verifier = Arc::new(ScopedDelegationVerifier::new(
        ReloadingAllowlist::new(path.clone()).expect("arm"),
    ));
    let hub = Harness::start(
        |_| {},
        Arc::clone(&verifier) as Arc<dyn ai_memory::wake_hub::identity::HelloVerifier>,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let mut admitted = hub.connect().await;
    admitted.delegation = mint(3_600);
    admitted
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    assert_eq!(admitted.expect_frame().await.kind, Kind::Welcome);

    // The refresher stopped: republish the SAME agent and key with a
    // `refreshed_at` past the ceiling.
    publish_snapshot(
        &path,
        &enrolled_key(),
        ai_memory::identity::hub_cache::MAX_CACHE_AGE_SECS + 5,
    );

    let mut refused = hub.connect().await;
    refused.delegation = mint(3_600);
    refused
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    refused.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    refused.expect_closed().await;
    assert_eq!(hub.metrics.snapshot(0).denied_hello, 1);
    hub.stop().await;
}

/// A snapshot whose mode is widened is refused IMMEDIATELY — the permission
/// gate runs before any reuse, so a still-warm parse cannot serve it.
#[tokio::test]
async fn a_mode_widened_snapshot_is_refused_immediately_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 1);

    let verifier = Arc::new(ScopedDelegationVerifier::new(
        ReloadingAllowlist::new(path.clone()).expect("arm"),
    ));
    let hub = Harness::start(
        |_| {},
        Arc::clone(&verifier) as Arc<dyn ai_memory::wake_hub::identity::HelloVerifier>,
        Arc::new(SameUidAuthorizer::for_current_process()),
    );

    let mut admitted = hub.connect().await;
    admitted.delegation = mint(3_600);
    admitted
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    assert_eq!(admitted.expect_frame().await.kind, Kind::Welcome);
    let parses_before = verifier.resolver().parse_count();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("widen");

    let mut refused = hub.connect().await;
    refused.delegation = mint(3_600);
    refused
        .hello(AGENT, &delegated_key(), &[format!("#_inbox/{AGENT}")])
        .await;
    refused.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    refused.expect_closed().await;
    assert_eq!(
        verifier.resolver().parse_count(),
        parses_before,
        "the refusal must precede any read of the widened file"
    );
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// The refresher
// ---------------------------------------------------------------------------

/// Every file the refresh left behind in the snapshot directory.
fn dir_entries(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|entry| entry.expect("entry").path())
        .collect();
    found.sort();
    found
}

/// The refresh publishes ATOMICALLY: a new inode carrying mode 0600 is
/// renamed into place inside the SAME directory, so a hub reading
/// concurrently sees the whole old snapshot or the whole new one — never a
/// truncated file, and never one that is briefly world-readable.
#[test]
fn a_refresh_replaces_the_snapshot_atomically_at_0600_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");

    // Start from a DELIBERATELY over-permissive file to prove the publish
    // does not merely preserve whatever mode it finds.
    let mut seed = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .expect("seed");
    seed.write_all(b"{}").expect("seed write");
    drop(seed);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("seed chmod");
    let before = std::fs::metadata(&path).expect("stat");

    publish_snapshot(&path, &enrolled_key(), 1);

    let after = std::fs::metadata(&path).expect("stat");
    assert_eq!(
        after.permissions().mode() & 0o7777,
        0o600,
        "the published snapshot must be owner-only regardless of what was there"
    );
    assert_ne!(
        before.ino(),
        after.ino(),
        "an atomic publish renames a NEW inode into place; an in-place rewrite \
         would expose a truncated file to a concurrent hub read"
    );
    assert_eq!(
        before.dev(),
        after.dev(),
        "the temp file must be created in the SAME directory, or the rename \
         would not be atomic"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec![path.clone()],
        "no temp file may be left behind"
    );
    // And the result is what the hub actually reads.
    assert!(
        AllowlistCache::load_from_file(&path)
            .expect("load")
            .resolve(AGENT)
            .is_ok()
    );
}

/// A refresh can only ever NARROW authority: an agent dropped from the next
/// snapshot is refused, and nothing about the publish widens the file's own
/// reachability.
#[test]
fn a_refresh_that_drops_an_agent_narrows_authority_3504() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 1);
    let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
    assert!(resolver.resolve(AGENT).is_ok());

    // The operator dropped the agent from the refresher's argument list.
    hub_cache::publish(
        &path,
        &AllowlistFile {
            version: ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(chrono::Utc::now().to_rfc3339()),
            agents: Vec::new(),
        },
    )
    .expect("publish");

    assert!(
        resolver.resolve(AGENT).is_err(),
        "omission from the refreshed snapshot is how revocation works"
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777,
        0o600
    );
}

/// `wake-hub --posture` reports the snapshot's age and whether the hub will
/// still accept it, in BOTH renderings — an operator whose refresher has
/// stopped must see it before the agents do.
#[test]
fn the_posture_reports_the_snapshot_age_in_both_renderings_3504() {
    use ai_memory::cli::wake_hub::{WakeHubArgs, print_posture, resolve_config};

    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish_snapshot(&path, &enrolled_key(), 3);

    let mut args = WakeHubArgs {
        socket: Some(dir.path().join("never-bound-3504.sock")),
        hub_id: None,
        max_connections: None,
        allowlist: Some(path.clone()),
        posture: true,
        // #3471's ops surface added this field; the posture path under test is
        // the non-probe one, so it stays false.
        health: false,
        json: false,
    };
    let cfg = resolve_config(&args, &ai_memory::config::AppConfig::default()).expect("resolve");

    let mut so = Vec::new();
    let mut se = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    print_posture(&cfg, &args, &mut out).expect("posture");
    let text = String::from_utf8(so).expect("utf8");
    assert!(
        text.contains("allowlist snapshot:"),
        "human posture must carry the snapshot age: {text}"
    );

    args.json = true;
    let mut so = Vec::new();
    let mut se = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut so, &mut se);
    print_posture(&cfg, &args, &mut out).expect("posture");
    let doc: serde_json::Value = serde_json::from_slice(&so).expect("json");
    assert_eq!(
        doc["allowlist_snapshot"]["max_age_secs"],
        hub_cache::MAX_CACHE_AGE_SECS
    );
    assert_eq!(doc["allowlist_snapshot"]["within_max_age"], true);
    let age = doc["allowlist_snapshot"]["age_secs"]
        .as_i64()
        .expect("age is a number");
    assert!(
        (2..=6).contains(&age),
        "expected an age near 3 s, got {age}"
    );

    // A snapshot the refresher has stopped updating reports the truth.
    publish_snapshot(&path, &enrolled_key(), hub_cache::MAX_CACHE_AGE_SECS + 5);
    let stale = SnapshotFreshness::observe(Some(&path));
    assert!(!stale.within_max_age);
    assert!(stale.summary().contains("REFUSED"));
    assert!(
        !dir.path().join("never-bound-3504.sock").exists(),
        "--posture must never bind anything"
    );
}

/// The SQLITE half of the refresher: the real derivation, audit and publish
/// the timer/launchd job runs, proved end to end against the hub's own
/// loader — and proved to NARROW, never widen, when a principal is revoked.
#[test]
fn sqlite_refresh_derives_publishes_and_narrows_3504() {
    let dir = owner_only_dir();
    let db = dir.path().join("identity.db");
    let path = dir.path().join("allow.json");
    let agent = "ai:refresh-3504";

    let conn = ai_memory::db::open(&db).expect("open");
    ai_memory::db::register_agent(&conn, agent, "nhi", &[]).expect("register");
    let key = ai_memory::identity::keypair::generate(agent).expect("keygen");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, agent, &key).expect("bind");

    let agents = vec![agent.to_owned()];
    let first = hub_cache::derive_sqlite(&conn, &agents).expect("derive");
    assert_eq!(first.agents.len(), 1);
    hub_cache::audit_sqlite(&conn, None, &first).expect("audit");
    hub_cache::publish(&path, &first).expect("publish");
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "the refresher publishes owner-only");
    assert_eq!(
        AllowlistCache::load_from_file(&path)
            .expect("load")
            .resolve(agent)
            .expect("resolved")
            .pubkey,
        key.public
    );

    // Revoke, re-derive, republish: the SAME loop the timer runs, and the
    // authority is gone on the next read.
    ai_memory::db::revoke_agent_pubkey(&conn, agent).expect("revoke");
    let second = hub_cache::derive_sqlite(&conn, &agents).expect("derive");
    assert!(
        second.agents.is_empty(),
        "a revoked principal must never survive a refresh"
    );
    hub_cache::audit_sqlite(&conn, Some(&first), &second).expect("audit");
    hub_cache::publish(&path, &second).expect("publish");
    assert!(
        AllowlistCache::load_from_file(&path)
            .expect("load")
            .resolve(agent)
            .is_err()
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777,
        0o600,
        "a narrowing refresh must not widen the file either"
    );
}

/// The POSTGRES half. The derivation is a separate implementation of the same
/// export, so the refresher's two load-bearing properties — publishes 0600
/// atomically, and can only narrow — have to be proved against it too.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_refresh_derives_publishes_and_narrows_3504() {
    use ai_memory::identity::pubkey_bind::{PossessionProof, sign_bind_challenge};
    use ai_memory::store::{CallerContext, MemoryStore as _};

    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("live isolated PostgreSQL URL required; never skip");
    let database = url.split('/').next_back().unwrap_or_default();
    let database = database.split('?').next().unwrap_or_default();
    assert_ne!(
        database, "ai_memory_test",
        "refusing to run against the shared live store; point \
         AI_MEMORY_TEST_POSTGRES_URL at this lane's own isolated database"
    );
    assert!(
        !database.is_empty(),
        "AI_MEMORY_TEST_POSTGRES_URL must name a database"
    );

    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect");
    let agent = format!("ai:refresh-3504-pg-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(&agent);
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: agent.clone(),
                agent_type: "nhi".to_owned(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register");

    let key = ai_memory::identity::keypair::generate(&agent).expect("keygen");
    let challenge = store
        .issue_pubkey_bind_challenge(&ctx, &agent, &key.public_base64(), &agent)
        .await
        .expect("challenge");
    let signature = sign_bind_challenge(key.private.as_ref().expect("private"), &challenge);
    let consumed = store
        .consume_pubkey_bind_challenge(&ctx, &agent, &challenge.nonce_b64)
        .await
        .expect("consume")
        .expect("challenge row");
    let proof = PossessionProof::verify_challenge_response(
        consumed,
        &agent,
        &key.public_base64(),
        &signature,
    )
    .expect("proof");
    store
        .bind_agent_pubkey(&ctx, &agent, &key.public_base64(), proof)
        .await
        .expect("bind");

    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    let agents = vec![agent.clone()];

    let first = store.derive_hub_cache(&agents).await.expect("derive");
    assert_eq!(first.agents.len(), 1);
    store.audit_hub_cache(None, &first).await.expect("audit");
    hub_cache::publish(&path, &first).expect("publish");
    let published = std::fs::metadata(&path).expect("stat");
    assert_eq!(
        published.permissions().mode() & 0o7777,
        0o600,
        "the postgres-derived refresh publishes owner-only too"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec![path.clone()],
        "no temp file may be left behind"
    );
    assert_eq!(
        AllowlistCache::load_from_file(&path)
            .expect("load")
            .resolve(&agent)
            .expect("resolved")
            .pubkey,
        key.public
    );

    // The hub honours the refreshed file immediately, and the reuse never
    // outlives the authority: revoke, republish, refused on the next call.
    let resolver = ReloadingAllowlist::new(path.clone()).expect("arm");
    assert!(resolver.resolve(&agent).is_ok());

    store
        .revoke_agent_pubkey(&ctx, &agent)
        .await
        .expect("revoke");
    let second = store.derive_hub_cache(&agents).await.expect("derive");
    assert!(
        second.agents.is_empty(),
        "a revoked principal must never survive a refresh"
    );
    store
        .audit_hub_cache(Some(&first), &second)
        .await
        .expect("audit");
    let before_ino = std::fs::metadata(&path).expect("stat").ino();
    hub_cache::publish(&path, &second).expect("publish");
    assert_ne!(
        before_ino,
        std::fs::metadata(&path).expect("stat").ino(),
        "an atomic publish renames a new inode into place"
    );
    assert!(
        resolver.resolve(&agent).is_err(),
        "the reused parse must never outlive the authority it came from"
    );
}
