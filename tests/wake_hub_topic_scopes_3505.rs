// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory wake-hub` namespace topic scopes, end to end (issue
//! [#3505](https://github.com/alphaonedev/ai-memory-mcp/issues/3505),
//! follow-up to [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)).
//!
//! #3468 admitted exactly ONE topic per session — the principal's own inbox.
//! #3505 widens that to the namespaces the agent PROVABLY reads, and the whole
//! security argument rests on two halves that this suite proves separately:
//!
//! * The **derivation** half. The exporter decides what "provably reads" means
//!   by reusing the store's own namespace read scope
//!   (`crate::visibility::namespace_read_scope_admits`: #1921 subtree scopes,
//!   #3348 substrate exclusions). Both backends must agree, because the
//!   postgres exporter is a SECOND implementation of the same export — so
//!   "the snapshot names exactly the readable namespaces" is proved twice.
//! * The **verification** half. The hub matches the carried set EXACTLY, over
//!   a real socket, with no store lookup — and, load-bearing, it re-checks
//!   EVERY live subscription once a second, so narrowing the snapshot drops a
//!   subscription that is already open.
//!
//! The revalidation cell is the one that would be missing if this were only a
//! unit suite: before #3505 a topic added by a later `subscribe` frame was
//! never re-checked at all, so it could outlive the proof that admitted it.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

mod wake_hub_harness;

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ai_memory::identity::hub_cache;
use ai_memory::identity::hub_delegation::{A2A_HUB_SCOPE, DelegationWire, sign_hub_delegation};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::wake_hub::delegation_verifier::{
    ALLOWLIST_FILE_VERSION, AllowlistCache, AllowlistEntry, AllowlistFile, ReloadingAllowlist,
    RootKeyResolver as _, ScopedDelegationVerifier,
};
use ai_memory::wake_hub::frame::{ErrorCode, Kind};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_hub::limits::MAX_READABLE_NAMESPACES;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use serde_json::json;
use wake_hub_harness::Harness;

const HUB: &str = "ai-memory-wake-hub";

/// Two agents in the SAME team subtree, so both provably read the shared
/// namespace and one can wake the other over it.
///
/// The ids are deliberately FIVE segments deep. `namespace_read_scope_prefixes`
/// takes the team / unit / org ancestors — indices 1..=3 of the ancestor walk,
/// exactly `compute_visibility_prefixes` — so at four segments the org prefix
/// would be the bare root `ai` and every namespace under it would be admitted,
/// leaving the suite unable to distinguish "inside the scope" from "anywhere".
const ALICE: &str = "ai/acme/eng/team1/alice";
const BOB: &str = "ai/acme/eng/team1/bob";
/// A namespace inside their #1921 team subtree.
const SHARED: &str = "ai/acme/eng/team1/shared";
/// A namespace OUTSIDE every ancestor either of them holds.
const FOREIGN: &str = "zz/other/secret";

fn root_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn session_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn owner_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    dir
}

/// Mint a scoped delegation the way `ai-memory identity delegate` does.
fn mint(agent: &str, root: &SigningKey, session: &SigningKey) -> Bytes {
    let now = chrono::Utc::now();
    let mut wire = DelegationWire {
        principal: agent.to_owned(),
        scope: A2A_HUB_SCOPE.to_owned(),
        delegate_key_id: session.verifying_key().to_bytes(),
        hub_id: HUB.to_owned(),
        not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        not_after: (now + chrono::Duration::seconds(3_600))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        signature: [0u8; 64],
    };
    wire.signature = sign_hub_delegation(root, &wire.as_delegation()).expect("mint");
    Bytes::from(wire.encode().expect("encode"))
}

fn row(agent: &str, root: &SigningKey, readable: &[&str]) -> AllowlistEntry {
    AllowlistEntry {
        agent_id: agent.to_owned(),
        pubkey_b64: ai_memory::identity::keypair::encode_public_base64(&root.verifying_key()),
        bind_authority: "possession_proof".to_owned(),
        bound_at: "2026-09-01T00:00:00Z".to_owned(),
        revoked_keys: Vec::new(),
        readable_namespaces: readable.iter().map(|n| (*n).to_string()).collect(),
    }
}

/// Publish a snapshot through the REAL publication path (atomic, 0600).
fn publish(path: &Path, rows: Vec<AllowlistEntry>) {
    let file = AllowlistFile {
        version: ALLOWLIST_FILE_VERSION,
        refreshed_at: Some(chrono::Utc::now().to_rfc3339()),
        agents: rows,
    };
    hub_cache::publish(path, &file).expect("publish");
}

/// Write a snapshot from RAW JSON, so a test can assert what happens for a
/// document the current exporter would never emit.
fn write_raw(path: &Path, body: &serde_json::Value) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("create snapshot");
    file.write_all(serde_json::to_vec(body).expect("encode").as_slice())
        .expect("write snapshot");
    drop(file);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A hub whose verifier reads the REAL snapshot on disk on every check.
fn hub_over(path: PathBuf) -> Harness {
    Harness::start(
        |_| {},
        Arc::new(ScopedDelegationVerifier::new(
            ReloadingAllowlist::new(path).expect("arm"),
        )),
        Arc::new(SameUidAuthorizer::for_current_process()),
    )
}

/// Connect + hello for one agent, asserting the welcome.
async fn join(
    hub: &Harness,
    agent: &str,
    root_seed: u8,
    session_seed: u8,
) -> wake_hub_harness::Client {
    let mut client = hub.connect().await;
    client.delegation = mint(agent, &root_key(root_seed), &session_key(session_seed));
    client
        .hello(
            agent,
            &session_key(session_seed),
            &[format!("#_inbox/{agent}")],
        )
        .await;
    let welcome = client.expect_frame().await;
    assert_eq!(welcome.kind, Kind::Welcome, "{agent} must be admitted");
    client
}

// ---------------------------------------------------------------------------
// Derivation — the snapshot names exactly what the store predicate admits
// ---------------------------------------------------------------------------

/// Every namespace the corpus holds, plus what each side of the predicate says
/// about ALICE. Shared by the sqlite and postgres cells so the two backends
/// are compared against ONE expectation, not two hand-written ones.
fn corpus() -> Vec<&'static str> {
    vec![
        SHARED,                   // inside the team subtree -> ADMITTED
        "ai/acme/eng/bob",        // a sibling agent's namespace, same subtree -> ADMITTED
        "ai/acme/eng",            // the team prefix itself -> ADMITTED
        "ai/acme",                // the unit prefix -> ADMITTED
        "ai",                     // ABOVE the org prefix -> DENIED
        FOREIGN,                  // another tenant entirely -> DENIED
        "_agents",                // #3348 substrate -> DENIED
        "_inbox/ai/acme/eng/bob", // #3348 substrate, another agent's mail -> DENIED
    ]
}

fn expected_for_alice() -> Vec<String> {
    let mut want = vec![
        "ai/acme".to_string(),
        "ai/acme/eng".to_string(),
        "ai/acme/eng/bob".to_string(),
        SHARED.to_string(),
    ];
    want.sort();
    want
}

/// The pure predicate: what the exporter will emit, stated once.
#[test]
fn the_proven_set_is_exactly_what_the_store_read_scope_admits_3505() {
    let existing: Vec<String> = corpus().into_iter().map(ToString::to_string).collect();
    let got = hub_cache::readable_namespaces_for(ALICE, &existing).expect("derive");
    assert_eq!(
        got,
        expected_for_alice(),
        "the derivation must emit the #1921 subtree and nothing else"
    );

    // DENIED, itemised, so a future widening names which rule it broke.
    for denied in ["ai", FOREIGN, "_agents", "_inbox/ai/acme/eng/team1/bob"] {
        assert!(
            !got.iter().any(|n| n == denied),
            "{denied} must never reach the snapshot"
        );
    }
    // And the substrate exclusion holds even for the agent's OWN inbox: the
    // hub's own-inbox arm is the proof for that topic, never a carried row.
    let own_inbox = format!("_inbox/{ALICE}");
    assert!(
        hub_cache::readable_namespaces_for(ALICE, std::slice::from_ref(&own_inbox))
            .expect("derive")
            .is_empty(),
        "#3348 substrate namespaces stay out of the carried set"
    );
}

fn memory_in(namespace: &str, id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("row in {namespace}"),
        content: "content".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "wake-hub-3505".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": ALICE, "scope": "team"}),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// The SQLITE half, through the real `derive_sqlite` export.
#[test]
fn sqlite_derivation_carries_the_proven_set_into_the_snapshot_3505() {
    let dir = owner_only_dir();
    let conn = ai_memory::db::open(&dir.path().join("identity.db")).expect("open");
    for (i, namespace) in corpus().into_iter().enumerate() {
        ai_memory::db::insert(&conn, &memory_in(namespace, &format!("m-3505-{i}")))
            .expect("insert");
    }
    ai_memory::db::register_agent(&conn, ALICE, "nhi", &[]).expect("register");
    let key = ai_memory::identity::keypair::generate(ALICE).expect("keygen");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, ALICE, &key).expect("bind");

    let snapshot = hub_cache::derive_sqlite(&conn, &[ALICE.to_owned()]).expect("derive");
    assert_eq!(snapshot.agents.len(), 1);
    assert_eq!(
        snapshot.agents[0].readable_namespaces,
        expected_for_alice(),
        "the sqlite exporter must carry exactly the store-admitted set"
    );

    // And the hub reads it back through its own loader unchanged.
    let path = dir.path().join("allow.json");
    hub_cache::publish(&path, &snapshot).expect("publish");
    let cache = AllowlistCache::load_from_file(&path).expect("load");
    assert_eq!(
        cache.readable_namespaces(ALICE).expect("resolve"),
        expected_for_alice()
    );
}

/// The POSTGRES half. The pg exporter is a SEPARATE implementation of the same
/// export, so "the snapshot names exactly the readable namespaces" has to hold
/// there too or the two backends admit different topics for one agent.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_derivation_carries_the_same_proven_set_3505() {
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

    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect");

    // A unique subtree per run, so a shared database cannot make the
    // expectation depend on what an earlier run left behind.
    let tag = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let alice = format!("pg{tag}/acme/eng/team1/alice");
    let ctx = CallerContext::for_agent(&alice);
    let admitted: Vec<String> = vec![
        format!("pg{tag}/acme"),
        format!("pg{tag}/acme/eng"),
        format!("pg{tag}/acme/eng/team1/shared"),
    ];
    let denied: Vec<String> = vec![
        format!("pg{tag}"),
        format!("zz{tag}/other"),
        "_agents".to_string(),
    ];
    for (i, namespace) in admitted.iter().chain(denied.iter()).enumerate() {
        let mut mem = memory_in(namespace, &format!("m-3505-pg-{tag}-{i}"));
        mem.metadata = json!({"agent_id": alice, "scope": "team"});
        store.store(&ctx, &mem).await.expect("store");
    }

    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: alice.clone(),
                agent_type: "nhi".to_owned(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .expect("register");
    let key = ai_memory::identity::keypair::generate(&alice).expect("keygen");
    let challenge = store
        .issue_pubkey_bind_challenge(&ctx, &alice, &key.public_base64(), &alice)
        .await
        .expect("challenge");
    let signature = sign_bind_challenge(key.private.as_ref().expect("private"), &challenge);
    let consumed = store
        .consume_pubkey_bind_challenge(&ctx, &alice, &challenge.nonce_b64)
        .await
        .expect("consume")
        .expect("challenge row");
    let proof = PossessionProof::verify_challenge_response(
        consumed,
        &alice,
        &key.public_base64(),
        &signature,
    )
    .expect("proof");
    store
        .bind_agent_pubkey(&ctx, &alice, &key.public_base64(), proof)
        .await
        .expect("bind");

    let snapshot = store
        .derive_hub_cache(std::slice::from_ref(&alice))
        .await
        .expect("derive");
    assert_eq!(snapshot.agents.len(), 1);
    let mut want = admitted.clone();
    want.sort();
    assert_eq!(
        snapshot.agents[0].readable_namespaces, want,
        "the postgres exporter must carry the SAME set the sqlite one does"
    );
    for refused in &denied {
        assert!(
            !snapshot.agents[0]
                .readable_namespaces
                .iter()
                .any(|n| n == refused),
            "{refused} must never reach the postgres-derived snapshot"
        );
    }
}

// ---------------------------------------------------------------------------
// Verification — over a real socket
// ---------------------------------------------------------------------------

/// ALLOWED: a proven namespace is subscribable, and a wake routed to that
/// topic reaches the session.
#[tokio::test]
async fn allowed_a_proven_namespace_topic_delivers_a_wake_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(21), &[SHARED]),
            row(BOB, &root_key(23), &[SHARED]),
        ],
    );
    let hub = hub_over(path);

    let mut alice = join(&hub, ALICE, 21, 22).await;
    let mut bob = join(&hub, BOB, 23, 24).await;

    let topic = format!("#{SHARED}");
    alice.subscribe(std::slice::from_ref(&topic)).await;
    // A `subscribe` the hub accepts answers with nothing, so prove acceptance
    // by the delivery below rather than by an absent error frame.
    bob.wake(&topic, "row-3505-a").await;

    let wake = alice.expect_frame().await;
    assert_eq!(wake.kind, Kind::Wake, "a proven topic must deliver");
    assert_eq!(wake.to, topic);
    assert_eq!(wake.from, BOB, "the hub stamps the authenticated sender");
    hub.stop().await;
}

/// DENIED: a namespace the snapshot does NOT prove is refused, and the session
/// receives nothing on it.
#[tokio::test]
async fn denied_an_unproven_namespace_topic_is_refused_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(31), &[SHARED]),
            row(BOB, &root_key(33), &[SHARED, FOREIGN]),
        ],
    );
    let hub = hub_over(path);

    let mut alice = join(&hub, ALICE, 31, 32).await;
    let bob = join(&hub, BOB, 33, 34).await;

    // ALICE's snapshot row does not name FOREIGN, even though BOB's does —
    // the proof is per principal, never per hub.
    let foreign = format!("#{FOREIGN}");
    alice.subscribe(std::slice::from_ref(&foreign)).await;
    let reason = alice.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    assert_eq!(
        reason, "unauthorized",
        "the wire carries one refusal string, never which rule fired"
    );
    // #3468's posture, unchanged: an identity refusal closes the connection.
    alice.expect_closed().await;

    // And the refused topic routes to NOBODY — the refusal was not merely a
    // message while the router quietly took the subscription.
    assert!(
        hub.router().topic_recipients(&foreign, BOB).is_empty(),
        "a refused subscribe must leave no route behind"
    );
    drop(bob);
    hub.stop().await;
}

/// The load-bearing revocation property: a namespace REMOVED by a refresh
/// drops the already-open subscription inside the one-second revalidation,
/// with no reconnect and no cooperation from the client.
#[tokio::test]
async fn a_namespace_removed_by_a_refresh_drops_the_subscription_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(41), &[SHARED]),
            row(BOB, &root_key(43), &[SHARED]),
        ],
    );
    let hub = hub_over(path.clone());

    let mut alice = join(&hub, ALICE, 41, 42).await;
    let mut bob = join(&hub, BOB, 43, 44).await;

    let topic = format!("#{SHARED}");
    alice.subscribe(std::slice::from_ref(&topic)).await;
    bob.wake(&topic, "row-3505-before").await;
    assert_eq!(
        alice.expect_frame().await.kind,
        Kind::Wake,
        "the subscription is live before the refresh"
    );

    // The refresher republishes WITHOUT the namespace — the operator narrowed
    // the agent's read scope. A new inode lands, so the hub sees it on the
    // very next identity check inside the reuse TTL.
    publish(
        &path,
        vec![
            row(ALICE, &root_key(41), &[]),
            row(BOB, &root_key(43), &[SHARED]),
        ],
    );
    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;

    bob.wake(&topic, "row-3505-after").await;
    // The session SURVIVES — narrowing costs subscriptions, not the agent's
    // own inbox — so a direct wake still lands and proves the topic wake did
    // not merely arrive late.
    bob.wake(&format!("#_inbox/{ALICE}"), "row-3505-inbox")
        .await;
    let delivered = alice.expect_frame().await;
    assert_eq!(delivered.kind, Kind::Wake);
    assert_eq!(
        delivered.to,
        format!("#_inbox/{ALICE}"),
        "the dropped topic must deliver nothing after the refresh"
    );
    hub.stop().await;
}

// ---------------------------------------------------------------------------
// Snapshot format — bounds, substrate, and both mismatch directions
// ---------------------------------------------------------------------------

/// An oversize proven set is REFUSED, on both sides of the file.
#[test]
fn an_oversize_proven_set_is_refused_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    let over: Vec<String> = (0..=MAX_READABLE_NAMESPACES)
        .map(|i| format!("ai/acme/eng/ns{i}"))
        .collect();
    let over_refs: Vec<&str> = over.iter().map(String::as_str).collect();

    // The LOADER refuses the whole snapshot rather than serving a truncation.
    publish(&path, vec![row(ALICE, &root_key(51), &over_refs)]);
    let err = AllowlistCache::load_from_file(&path).expect_err("over the ceiling");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("ceiling"), "{rendered}");
    assert!(
        ReloadingAllowlist::new(path).is_err(),
        "the live resolver must refuse to arm on an oversize snapshot"
    );

    // And the EXPORTER refuses to publish one, naming the agent so an operator
    // can act on it.
    let err = hub_cache::readable_namespaces_for(ALICE, &over).expect_err("over the ceiling");
    let rendered = format!("{err:#}");
    assert!(rendered.contains(ALICE), "{rendered}");
    assert!(rendered.contains("ceiling"), "{rendered}");
    // Exactly AT the ceiling is fine — proving the bound is `>`, not `>=`.
    assert_eq!(
        hub_cache::readable_namespaces_for(ALICE, &over[..MAX_READABLE_NAMESPACES])
            .expect("at the ceiling")
            .len(),
        MAX_READABLE_NAMESPACES
    );
}

/// A snapshot naming a SUBSTRATE namespace is refused at load, and even if one
/// reached the verifier it could not admit the topic. Defense in depth: the
/// hub does not depend on the exporter being correct to keep another agent's
/// inbox out of reach.
#[test]
fn a_substrate_namespace_in_a_snapshot_is_refused_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![row(ALICE, &root_key(61), &[&format!("_inbox/{BOB}")])],
    );
    let err = AllowlistCache::load_from_file(&path).expect_err("substrate namespace");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("SUBSTRATE"), "{rendered}");
}

/// An entry that OMITS the field — every snapshot an older exporter ever wrote
/// — yields own-inbox only. Never "everything".
#[tokio::test]
async fn an_older_format_snapshot_yields_own_inbox_only_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    write_raw(
        &path,
        &json!({
            "version": ALLOWLIST_FILE_VERSION,
            "refreshed_at": chrono::Utc::now().to_rfc3339(),
            "agents": [{
                "agent_id": ALICE,
                "pubkey_b64": ai_memory::identity::keypair::encode_public_base64(
                    &root_key(71).verifying_key(),
                ),
                "bind_authority": "possession_proof",
                "bound_at": "2026-09-01T00:00:00Z",
            }],
        }),
    );

    let cache = AllowlistCache::load_from_file(&path).expect("an older snapshot still loads");
    assert!(
        cache
            .readable_namespaces(ALICE)
            .expect("resolve")
            .is_empty(),
        "an absent field means own-inbox only, never a wildcard"
    );

    // End to end: the own inbox is admitted, a namespace topic is not.
    let hub = hub_over(path);
    let mut alice = join(&hub, ALICE, 71, 72).await;
    alice.subscribe(&[format!("#{SHARED}")]).await;
    alice.expect_error(ErrorCode::Unauthorized.as_u16()).await;
    alice.expect_closed().await;
    hub.stop().await;
}

/// The reverse direction — an OLDER hub reading a NEWER snapshot — fails
/// CLOSED through `deny_unknown_fields`, which is why #3505 did not bump
/// `ALLOWLIST_FILE_VERSION`. An unknown field refuses the whole file rather
/// than being part-honoured.
#[test]
fn an_unknown_entry_field_refuses_the_snapshot_whole_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    write_raw(
        &path,
        &json!({
            "version": ALLOWLIST_FILE_VERSION,
            "refreshed_at": chrono::Utc::now().to_rfc3339(),
            "agents": [{
                "agent_id": ALICE,
                "pubkey_b64": ai_memory::identity::keypair::encode_public_base64(
                    &root_key(81).verifying_key(),
                ),
                "bind_authority": "possession_proof",
                "bound_at": "2026-09-01T00:00:00Z",
                "readable_namespaces": [SHARED],
                "some_grant_from_2027": ["everything"],
            }],
        }),
    );
    let err = AllowlistCache::load_from_file(&path).expect_err("unknown field");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("malformed"), "{rendered}");
    assert_eq!(
        ALLOWLIST_FILE_VERSION, 2,
        "#3505 is additive: bumping this would make a newer hub refuse every \
         older snapshot instead of narrowing it to own-inbox only"
    );
}
