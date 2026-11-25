// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal-postgres")]

//! #10108 (GA standard 3) — the postgres legs of the agent-row invariants.
//!
//! - I1: a `signed_events` row carries an agent label only with the 64-byte
//!   signature of that agent; otherwise `unsigned` with a NULL signature.
//! - I2 (D2): the `memory_link.invalidated` row has a NULL signature (it
//!   used to carry the prior link signature under the `unsigned` label, a
//!   signature over a different pre-image).
//! - I4 (D5): a postgres link create (local signed, local unsigned, inbound
//!   federated) appends the `memory_link.created` row the sqlite path
//!   appends.
//!
//! Each row is found by a key derived from the test's own inputs (the
//! `SignableLink` pre-image of the stamps written out below, or a per-run
//! actor id), never from the code under test. The expected `(label, length)`
//! pairs are written out. Soft-skips without `AI_MEMORY_TEST_POSTGRES_URL`.

use ai_memory::identity::sign::{SignableLink, canonical_cbor};
use ai_memory::models::{Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::signed_events::payload_hash;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

/// Micro-precision stamps; postgres round-trips them byte-identically.
const CREATED_AT: &str = "2026-03-04T05:06:07.123456+00:00";
const VALID_FROM: &str = "2026-03-04T05:06:08.654321+00:00";
const REL_STR: &str = "related_to";
const NS: &str = "agent-row/10108";

/// A row as the test reads it: `(attest_level, octet_length(signature))`.
type Row = (String, Option<i32>);

const SELF_SIGNED_ROW: (&str, Option<i32>) = ("self_signed", Some(64));
const PEER_ATTESTED_ROW: (&str, Option<i32>) = ("peer_attested", Some(64));
const UNSIGNED_ROW: (&str, Option<i32>) = ("unsigned", None);

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

fn seed_ctx() -> CallerContext {
    let mut ctx = CallerContext::for_agent("ai:test-10108-seed");
    ctx.bypass_visibility = true;
    ctx
}

fn memory(title: &str, id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        tier: Tier::Mid,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "agent-row-10108".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "alice" }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn link(src: &str, dst: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: dst.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: CREATED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

fn signable<'a>(src: &'a str, dst: &'a str, observed_by: Option<&'a str>) -> SignableLink<'a> {
    SignableLink {
        src_id: src,
        dst_id: dst,
        relation: REL_STR,
        observed_by,
        created_at: Some(CREATED_AT),
        valid_from: Some(VALID_FROM),
        valid_until: None,
    }
}

/// The `memory_link.created` pre-image hash of a link written with the
/// stamps above.
fn created_hash(src: &str, dst: &str, observed_by: Option<&str>) -> Vec<u8> {
    payload_hash(&canonical_cbor(&signable(src, dst, observed_by)).expect("canonical cbor"))
}

struct Fixture {
    store: PostgresStore,
    pool: sqlx::PgPool,
    src: String,
    dst: String,
}

async fn fixture(url: &str) -> Fixture {
    permissive_attestation_for_tests();
    let store = PostgresStore::connect(url).await.expect("connect pg");
    let pool = sqlx::PgPool::connect(url).await.expect("pool");
    let src = uuid::Uuid::new_v4().to_string();
    let dst = uuid::Uuid::new_v4().to_string();
    let ctx = seed_ctx();
    store.store(&ctx, &memory("src", &src)).await.expect("store src");
    store.store(&ctx, &memory("dst", &dst)).await.expect("store dst");
    Fixture { store, pool, src, dst }
}

async fn rows_by_hash(pool: &sqlx::PgPool, event_type: &str, hash: &[u8]) -> Vec<Row> {
    sqlx::query_as(
        "SELECT attest_level, octet_length(signature) FROM signed_events \
         WHERE event_type = $1 AND payload_hash = $2 ORDER BY sequence",
    )
    .bind(event_type)
    .bind(hash)
    .fetch_all(pool)
    .await
    .expect("read signed_events by payload_hash")
}

async fn rows_by_agent(pool: &sqlx::PgPool, event_type: &str, agent_id: &str) -> Vec<Row> {
    sqlx::query_as(
        "SELECT attest_level, octet_length(signature) FROM signed_events \
         WHERE event_type = $1 AND agent_id = $2 ORDER BY sequence",
    )
    .bind(event_type)
    .bind(agent_id)
    .fetch_all(pool)
    .await
    .expect("read signed_events by agent_id")
}

fn want(rows: &[(&str, Option<i32>)]) -> Vec<Row> {
    rows.iter().map(|(l, n)| ((*l).to_string(), *n)).collect()
}

/// Leave the shared table as found: the rows this run appended carry its
/// fresh ids in their pre-image or agent id, so only they are removed.
async fn cleanup(f: &Fixture, hashes: &[Vec<u8>], agent: Option<&str>) {
    for h in hashes {
        sqlx::query("DELETE FROM signed_events WHERE payload_hash = $1")
            .bind(h)
            .execute(&f.pool)
            .await
            .expect("cleanup signed_events by hash");
    }
    if let Some(a) = agent {
        sqlx::query("DELETE FROM signed_events WHERE agent_id = $1")
            .bind(a)
            .execute(&f.pool)
            .await
            .expect("cleanup signed_events by agent");
    }
    sqlx::query("DELETE FROM memory_links WHERE source_id = $1 AND target_id = $2")
        .bind(&f.src)
        .bind(&f.dst)
        .execute(&f.pool)
        .await
        .expect("cleanup memory_links");
    sqlx::query("DELETE FROM memories WHERE id = $1 OR id = $2")
        .bind(&f.src)
        .bind(&f.dst)
        .execute(&f.pool)
        .await
        .expect("cleanup memories");
}

#[tokio::test]
async fn pg_signed_link_create_appends_self_signed_created_row_10108() {
    let Some(url) = pg_url() else { return };
    let f = fixture(&url).await;
    let agent = format!("ai:linker-10108-{}", uuid::Uuid::new_v4());
    let kp = ai_memory::identity::keypair::generate(&agent).expect("keypair");
    let attest = f
        .store
        .link_signed(&seed_ctx(), &link(&f.src, &f.dst), Some(&kp))
        .await
        .expect("link_signed");
    assert_eq!(attest, "self_signed");
    let hash = created_hash(&f.src, &f.dst, Some(&agent));
    let got = rows_by_hash(&f.pool, "memory_link.created", &hash).await;
    cleanup(&f, &[hash], Some(&agent)).await;
    assert_eq!(got, want(&[SELF_SIGNED_ROW]), "#10108 D5: pg signed link create row");
}

#[tokio::test]
async fn pg_unsigned_link_create_appends_unsigned_created_row_10108() {
    let Some(url) = pg_url() else { return };
    let f = fixture(&url).await;
    let attest = f
        .store
        .link_signed(&seed_ctx(), &link(&f.src, &f.dst), None)
        .await
        .expect("link_signed unsigned");
    assert_eq!(attest, "unsigned");
    let hash = created_hash(&f.src, &f.dst, None);
    let got = rows_by_hash(&f.pool, "memory_link.created", &hash).await;
    cleanup(&f, &[hash], None).await;
    assert_eq!(got, want(&[UNSIGNED_ROW]), "#10108 D5: pg unsigned link create row");
}

/// The postgres CHECK that refuses an agent label without a 64-byte
/// signature on `memory_links` (the sqlite trigger's twin).
const LINK_SIG_CHECK_REFUSAL: &str = "memory_links_attest_signature_atomic_ck";

/// What an inbound write must leave: these rows, or a refusal whose error
/// names the given text and leaves no row.
#[derive(Clone, Copy)]
enum Outcome {
    Rows(&'static [(&'static str, Option<i32>)]),
    Refused(&'static str),
}

/// The three inbound shapes: a verified 64-byte peer signature, a short
/// signature under the peer label, and a plain unsigned relay.
#[tokio::test]
async fn pg_inbound_link_rows_are_truthful_10108() {
    let Some(url) = pg_url() else { return };
    let cases: [(&str, &str, Option<usize>, Outcome); 3] = [
        ("peer_64", "peer_attested", Some(64), Outcome::Rows(&[PEER_ATTESTED_ROW])),
        ("peer_short", "peer_attested", Some(10), Outcome::Refused(LINK_SIG_CHECK_REFUSAL)),
        ("unsigned", "unsigned", None, Outcome::Rows(&[UNSIGNED_ROW])),
    ];
    let mut failures = Vec::new();
    for (name, label, sig_len, expected) in cases {
        let f = fixture(&url).await;
        let peer = format!("ai:peer-10108-{}", uuid::Uuid::new_v4());
        let kp = ai_memory::identity::keypair::generate(&peer).expect("peer keypair");
        let full = ai_memory::identity::sign::sign(&kp, &signable(&f.src, &f.dst, Some(&peer)))
            .expect("peer sign");
        let mut l = link(&f.src, &f.dst);
        l.observed_by = Some(peer.clone());
        l.signature = sig_len.map(|n| full[..n].to_vec());
        let res = f.store.apply_remote_link(&seed_ctx(), &l, label).await;
        let hash = created_hash(&f.src, &f.dst, Some(&peer));
        let got = rows_by_hash(&f.pool, "memory_link.created", &hash).await;
        cleanup(&f, &[hash], Some(&peer)).await;
        match (expected, res) {
            (Outcome::Rows(rows), Ok(())) if got != want(rows) => {
                failures.push(format!("{name}: stored {got:?}, expected {:?}", want(rows)));
            }
            (Outcome::Rows(_), Ok(())) => {}
            (Outcome::Rows(_), Err(e)) => failures.push(format!("{name}: writer failed: {e}")),
            (Outcome::Refused(text), Err(e)) if e.to_string().contains(text) && got.is_empty() => {}
            (Outcome::Refused(text), r) => failures.push(format!(
                "{name}: expected refusal naming {text} and no row, got {r:?} with rows {got:?}"
            )),
        }
    }
    assert!(failures.is_empty(), "#10108 pg inbound rows:\n{}", failures.join("\n"));
}

#[tokio::test]
async fn pg_link_invalidated_row_signature_is_null_10108() {
    let Some(url) = pg_url() else { return };
    let f = fixture(&url).await;
    let agent = format!("ai:linker-10108-{}", uuid::Uuid::new_v4());
    let actor = format!("ai:invalidator-10108-{}", uuid::Uuid::new_v4());
    let kp = ai_memory::identity::keypair::generate(&agent).expect("keypair");
    f.store
        .link_signed(&seed_ctx(), &link(&f.src, &f.dst), Some(&kp))
        .await
        .expect("link_signed");
    let found = f
        .store
        .invalidate_link(&f.src, &f.dst, REL_STR, None, Some(&actor))
        .await
        .expect("invalidate_link")
        .found;
    let got = rows_by_agent(&f.pool, "memory_link.invalidated", &actor).await;
    cleanup(&f, &[created_hash(&f.src, &f.dst, Some(&agent))], Some(&actor)).await;
    assert!(found, "the signed link must be found");
    assert_eq!(got, want(&[UNSIGNED_ROW]), "#10108 D2: pg invalidated row");
}
