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
//!   by reusing the store's own #1921 read scope
//!   (`crate::visibility::namespace_read_scope_prefixes`: the agent's team /
//!   unit / org ancestors). Both backends must agree, because the postgres
//!   exporter is a SECOND implementation of the same export — so "the snapshot
//!   carries exactly the store's own prefixes" is proved twice. It carries
//!   PREFIXES rather than an expanded namespace list precisely so the export
//!   cannot grow with the corpus and eventually refuse to publish at all.
//! * The **verification** half. The hub applies the store's OWN subtree
//!   containment test to the carried prefixes, over a real socket, with no
//!   store lookup — on SUBSCRIBE and on SEND, because a topic has two doors —
//!   and, load-bearing, it re-checks EVERY live subscription once a second, so
//!   narrowing the snapshot drops a subscription that is already open.
//!
//! Two cells would be missing if this were only a unit suite: the revalidation
//! one (before #3505 a topic added by a later `subscribe` frame was never
//! re-checked at all, so it could outlive the proof that admitted it), and the
//! SEND gate (an ungated topic send would let any authenticated peer publish
//! fabricated hints to a whole team namespace it cannot read).

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
use ai_memory::wake_hub::frame::{ErrorCode, Frame, Kind};
use ai_memory::wake_hub::identity::SameUidAuthorizer;
use ai_memory::wake_hub::limits::MAX_READABLE_PREFIXES;
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
/// A third principal in a DIFFERENT tenant: authenticated, enrolled, and
/// holding no read scope over `SHARED`. The send-gate cells need a peer that
/// is legitimate at the identity layer and unproven at the topic layer,
/// because that is the exact shape an ungated send would have handed a
/// fleet-wide fan-out to.
const CAROL: &str = "zz/other/team9/carol";
/// A namespace inside CAROL's own subtree, so she is not a principal who
/// simply proves nothing — her scope is real, and simply does not reach
/// `SHARED`.
const CAROL_NS: &str = "zz/other/team9/notes";

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
        readable_prefixes: readable.iter().map(|n| (*n).to_string()).collect(),
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

/// Every namespace the corpus holds, and what the hub says about ALICE for
/// each. Shared by the sqlite and postgres cells so the two backends are
/// compared against ONE expectation, not two hand-written ones.
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

/// ALICE's #1921 `team` / `unit` / `org` ancestors, sorted — exactly what the
/// exporter carries, and derived from her ID ALONE.
fn expected_prefixes_for_alice() -> Vec<String> {
    let mut want = vec![
        "ai/acme".to_string(),
        "ai/acme/eng".to_string(),
        "ai/acme/eng/team1".to_string(),
    ];
    want.sort();
    want
}

/// The pure derivation: what the exporter emits, stated once — and the
/// admission verdict the hub then reaches for each corpus namespace, so the
/// two halves of the proof are pinned against ONE table.
#[test]
fn the_proven_prefixes_are_the_store_read_scope_and_admit_exactly_it_3505() {
    let got = hub_cache::readable_prefixes_for(ALICE);
    assert_eq!(
        got,
        expected_prefixes_for_alice(),
        "the derivation must emit the #1921 team / unit / org ancestors and nothing else"
    );
    assert!(
        got.len() <= MAX_READABLE_PREFIXES,
        "the derivation is bounded BY CONSTRUCTION, never by a refusal"
    );

    // The hub's admission rule, applied to the same corpus the exporter used
    // to be handed. ADMITTED entries are covered by a carried prefix; DENIED
    // ones are not, and the two substrate rows are refused by the #3348 gate
    // even though `_inbox/...` shares no prefix anyway.
    let admits = |namespace: &str| {
        !ai_memory::visibility::is_substrate_namespace(namespace)
            && got
                .iter()
                .any(|prefix| ai_memory::visibility::namespace_subtree_contains(prefix, namespace))
    };
    for admitted in [SHARED, "ai/acme/eng/bob", "ai/acme/eng", "ai/acme"] {
        assert!(admits(admitted), "{admitted} must be admitted");
    }
    for denied in ["ai", FOREIGN, "_agents", "_inbox/ai/acme/eng/bob"] {
        assert!(!admits(denied), "{denied} must never be admitted");
    }
    // Containment is SEGMENT-WISE, never a bare string prefix: on its own,
    // `ai/acme/eng` admits `ai/acme/eng/x` and refuses `ai/acme/engineering`.
    // Asserted against the predicate directly, because ALICE also holds the
    // BROADER `ai/acme` prefix, under which `ai/acme/engineering` legitimately
    // IS in scope — testing it through her whole set would prove nothing.
    assert!(ai_memory::visibility::namespace_subtree_contains(
        "ai/acme/eng",
        "ai/acme/eng/x"
    ));
    assert!(
        !ai_memory::visibility::namespace_subtree_contains("ai/acme/eng", "ai/acme/engineering"),
        "a bare starts_with would widen every scope to a sibling name"
    );
    // And the agent's OWN inbox is never carried: the hub's own-inbox arm is
    // the proof for that topic.
    assert!(!admits(&format!("_inbox/{ALICE}")), "#3348 stays excluded");
}

/// A FLAT agent id has no team / unit / org ancestor, so it proves nothing —
/// which is what makes the reserved `wake-hub-producer` unable to address a
/// namespace topic under the #3505 send gate.
#[test]
fn a_flat_agent_id_proves_no_namespace_scope_3505() {
    assert!(
        hub_cache::readable_prefixes_for(ai_memory::identity::sentinels::WAKE_HUB_PRODUCER)
            .is_empty(),
        "the reserved producer holds no namespace read scope"
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
        snapshot.agents[0].readable_prefixes,
        expected_prefixes_for_alice(),
        "the sqlite exporter must carry exactly the store's own prefixes"
    );

    // AVAILABILITY, the property the prefix form exists for: the corpus above
    // holds more in-scope namespaces than the hub's per-agent ceiling, and the
    // export still SUCCEEDS at a fixed size. An expanded list would have
    // refused here, publishing nothing — after which the snapshot ages out and
    // the hub refuses every hello, fleet-wide, because the corpus grew.
    for i in 0..=MAX_READABLE_PREFIXES {
        ai_memory::db::insert(
            &conn,
            &memory_in(
                &format!("ai/acme/eng/team1/bulk{i}"),
                &format!("m-3505-bulk-{i}"),
            ),
        )
        .expect("insert");
    }
    let again = hub_cache::derive_sqlite(&conn, &[ALICE.to_owned()]).expect("derive");
    assert_eq!(
        again.agents[0].readable_prefixes,
        expected_prefixes_for_alice(),
        "the exported set is a property of the AGENT ID, never of the corpus"
    );

    // And the hub reads it back through its own loader unchanged.
    let path = dir.path().join("allow.json");
    hub_cache::publish(&path, &snapshot).expect("publish");
    let cache = AllowlistCache::load_from_file(&path).expect("load");
    assert_eq!(
        cache.readable_prefixes(ALICE).expect("resolve"),
        expected_prefixes_for_alice()
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
    // The prefixes the export must carry: alice's team / unit / org ancestors.
    let mut want: Vec<String> = vec![
        format!("pg{tag}/acme"),
        format!("pg{tag}/acme/eng"),
        format!("pg{tag}/acme/eng/team1"),
    ];
    want.sort();
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
    let carried = &snapshot.agents[0].readable_prefixes;
    assert_eq!(
        carried, &want,
        "the postgres exporter must carry the SAME prefixes the sqlite one does"
    );
    // The admission verdict those prefixes then produce, checked against the
    // same corpus both halves of this suite use.
    let admits = |namespace: &str| {
        !ai_memory::visibility::is_substrate_namespace(namespace)
            && carried
                .iter()
                .any(|prefix| ai_memory::visibility::namespace_subtree_contains(prefix, namespace))
    };
    for allowed in &admitted {
        assert!(
            admits(allowed),
            "{allowed} must be admitted on postgres too"
        );
    }
    for refused in &denied {
        assert!(
            !admits(refused),
            "{refused} must never be admitted by the postgres-derived snapshot"
        );
    }
}

/// Subscribe and PROVE the hub has processed it before any peer addresses the
/// topic.
///
/// A `subscribe` the hub accepts answers with nothing, so the only way to know
/// the router now holds the topic is a round-trip on the SAME connection: the
/// hub handles one connection's frames in order, so the `pong` arriving means
/// the `subscribe` before it was handled. Without this, a peer's topic wake
/// sent right after can be routed first — fan-out to nobody, no error frame,
/// so the subscriber waits forever. Linux's readiness ordering made that the
/// DETERMINISTIC outcome (8/8 on the 157d4fda merge gate) while macOS hid it;
/// `wake_hub_allowed_3467` sequences its unsubscribe the same way.
async fn subscribe_synced(client: &mut wake_hub_harness::Client, topic: &str) {
    client
        .subscribe(std::slice::from_ref(&topic.to_string()))
        .await;
    let from = client.agent_id.clone();
    client
        .send(Frame::new(Kind::Ping, from, "", Bytes::new()))
        .await;
    assert_eq!(
        client.expect_frame().await.kind,
        Kind::Pong,
        "the subscribe round-trip must answer with a pong"
    );
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
    // The pong proves the subscription is live before BOB addresses it; the
    // delivery below is then the ALLOWED half of the #3505 SEND gate: BOB's
    // row proves the namespace, so his topic-addressed wake is admitted and
    // fans out.
    subscribe_synced(&mut alice, &topic).await;
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

/// DENIED, the SEND half: a peer OUTSIDE the namespace's scope cannot publish
/// to it, and the subscriber receives nothing.
///
/// Subscribe was never the only door onto a topic. Before #3505 nobody could
/// subscribe to `#<namespace>`, so an ungated topic SEND reached nobody and
/// cost nothing; the moment a proven namespace became subscribable, an ungated
/// send would have let any authenticated peer fan fabricated hints out to a
/// whole team's subscribers, forcing catch-up reads fleet-wide while paying
/// only its own bucket.
#[tokio::test]
async fn denied_a_topic_send_outside_the_senders_scope_is_refused_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(91), &[SHARED]),
            row(BOB, &root_key(93), &[SHARED]),
            // CAROL is enrolled and authenticates fine; her proven scope is
            // real and simply does not reach SHARED.
            row(CAROL, &root_key(95), &[CAROL_NS]),
        ],
    );
    let hub = hub_over(path);

    let mut alice = join(&hub, ALICE, 91, 92).await;
    let mut carol = join(&hub, CAROL, 95, 96).await;
    let mut bob = join(&hub, BOB, 93, 94).await;

    let topic = format!("#{SHARED}");
    alice.subscribe(std::slice::from_ref(&topic)).await;

    // CAROL addresses a namespace she cannot read.
    carol.wake(&topic, "row-3505-forged").await;
    let reason = carol.expect_error(ErrorCode::Forbidden.as_u16()).await;
    assert!(
        reason.contains("scope"),
        "the sender is told its scope is the problem: {reason}"
    );
    // Nothing reached the subscriber.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(400), alice.read_frame())
            .await
            .is_err(),
        "a refused topic send must deliver to NOBODY"
    );

    // `Forbidden` refuses ONE frame; CAROL's session survives, so a
    // mis-addressed wake never becomes a reconnect storm — proved by a wake
    // she IS allowed to send landing on the very same connection.
    carol
        .wake(&format!("#_inbox/{ALICE}"), "row-3505-carol-inbox")
        .await;
    let survived = alice.expect_frame().await;
    assert_eq!(survived.from, CAROL, "the refused session is still usable");

    // And the topic itself still works for a peer that DOES prove it, so the
    // gate refused the sender rather than breaking the route.
    bob.wake(&topic, "row-3505-legit").await;
    let wake = alice.expect_frame().await;
    assert_eq!(wake.kind, Kind::Wake);
    assert_eq!(wake.to, topic);
    assert_eq!(wake.from, BOB, "the proven sender still fans out");
    hub.stop().await;
}

/// SCOPE of the send gate: a SUBSTRATE topic (`#_inbox/<agent>`) stays
/// ungated, because it is the pre-#3505 own-inbox addressing and is
/// ADDRESS-EQUIVALENT to the direct `to = <agent-id>` wake, which is ungated
/// and always has been.
///
/// The verifier grants exactly ONE substrate subscription — a principal's own
/// inbox — so such a topic has at most one subscriber and carries no fan-out
/// amplification to charge. Gating it would refuse one spelling of a wake while
/// leaving the identical direct spelling open: no security gained, every
/// peer-to-peer inbox wake broken.
#[tokio::test]
async fn a_substrate_inbox_topic_send_stays_ungated_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(111), &[SHARED]),
            // CAROL proves NOTHING that ALICE holds — she still may wake
            // ALICE's inbox, exactly as she may wake ALICE directly.
            row(CAROL, &root_key(113), &[CAROL_NS]),
        ],
    );
    let hub = hub_over(path);

    let mut alice = join(&hub, ALICE, 111, 112).await;
    let mut carol = join(&hub, CAROL, 113, 114).await;

    // The topic spelling.
    carol
        .wake(&format!("#_inbox/{ALICE}"), "row-3505-inbox-topic")
        .await;
    let wake = alice.expect_frame().await;
    assert_eq!(wake.kind, Kind::Wake);
    assert_eq!(wake.to, format!("#_inbox/{ALICE}"));
    assert_eq!(wake.from, CAROL);

    // The direct spelling, which was never gated and still is not — the two
    // must not disagree, or the gate would be a spelling rule rather than an
    // authorization one.
    carol.wake(ALICE, "row-3505-inbox-direct").await;
    let direct = alice.expect_frame().await;
    assert_eq!(direct.kind, Kind::Wake);
    assert_eq!(direct.to, ALICE);
    hub.stop().await;
}

/// DENIED, the empty-scope case: a principal carrying NO proven prefixes — the
/// shape of the reserved `wake-hub-producer` (#3469), which is why it cannot
/// publish to a namespace topic — is refused, while its DIRECT wakes are
/// untouched.
#[tokio::test]
async fn denied_a_topic_send_from_an_empty_scope_peer_is_refused_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    publish(
        &path,
        vec![
            row(ALICE, &root_key(101), &[SHARED]),
            row(BOB, &root_key(103), &[]),
        ],
    );
    let hub = hub_over(path);

    let mut alice = join(&hub, ALICE, 101, 102).await;
    let mut bob = join(&hub, BOB, 103, 104).await;

    let topic = format!("#{SHARED}");
    alice.subscribe(std::slice::from_ref(&topic)).await;

    bob.wake(&topic, "row-3505-empty-scope").await;
    bob.expect_error(ErrorCode::Forbidden.as_u16()).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(400), alice.read_frame())
            .await
            .is_err(),
        "an empty-scope peer must reach no topic subscriber"
    );

    // The DIRECT wake — the only thing the producer ever needed — is unchanged.
    bob.wake(&format!("#_inbox/{ALICE}"), "row-3505-direct")
        .await;
    let wake = alice.expect_frame().await;
    assert_eq!(wake.kind, Kind::Wake);
    assert_eq!(wake.to, format!("#_inbox/{ALICE}"));
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
    subscribe_synced(&mut alice, &topic).await;
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

/// An oversize prefix set is REFUSED at LOAD. The exporter can never produce
/// one — the set is bounded by construction — so an oversize file is evidence
/// the snapshot is not what it claims to be, and the loader refuses it whole
/// rather than serving a truncation whose surviving entries would depend on
/// parse order.
#[test]
fn an_oversize_prefix_set_is_refused_at_load_3505() {
    let dir = owner_only_dir();
    let path = dir.path().join("allow.json");
    let over: Vec<String> = (0..=MAX_READABLE_PREFIXES)
        .map(|i| format!("ai/acme/eng/ns{i}"))
        .collect();
    let over_refs: Vec<&str> = over.iter().map(String::as_str).collect();

    publish(&path, vec![row(ALICE, &root_key(51), &over_refs)]);
    let err = AllowlistCache::load_from_file(&path).expect_err("over the ceiling");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("ceiling"), "{rendered}");
    assert!(rendered.contains(ALICE), "{rendered}");
    assert!(
        ReloadingAllowlist::new(path.clone()).is_err(),
        "the live resolver must refuse to arm on an oversize snapshot"
    );

    // Exactly AT the ceiling loads — proving the bound is `>`, not `>=`.
    publish(
        &path,
        vec![row(
            ALICE,
            &root_key(51),
            &over_refs[..MAX_READABLE_PREFIXES],
        )],
    );
    assert_eq!(
        AllowlistCache::load_from_file(&path)
            .expect("at the ceiling")
            .readable_prefixes(ALICE)
            .expect("resolve")
            .len(),
        MAX_READABLE_PREFIXES
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
    let err = AllowlistCache::load_from_file(&path).expect_err("substrate prefix");
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
        cache.readable_prefixes(ALICE).expect("resolve").is_empty(),
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
                "readable_prefixes": [SHARED],
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
