// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]
#![cfg(feature = "sal")]

//! #3291 — `memory_links.created_at` is attested in the `SignableLink`
//! pre-image. A self-signed edge that did not commit to its own timestamp
//! could have that stamp forged; tampering it now fails verify.
//!
//! Sqlite-only (no postgres required). Pattern follows
//! `tests/sal_parity_link_window_3178.rs`.

use std::path::PathBuf;

use ai_memory::identity::verify::VerifyError;
use ai_memory::models::{Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore};
use serde_json::json;

const CREATED_AT: &str = "2026-01-02T03:04:05.123456+00:00";
const VALID_FROM: &str = "2026-02-03T04:05:06.654321+00:00";
const VALID_UNTIL: &str = "2027-03-04T05:06:07.111222+00:00";
/// Distinct RFC3339 used to forge `created_at` after persist.
const FORGED_CREATED_AT: &str = "2026-12-31T23:59:59.000000+00:00";

fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated write.
    ONCE.call_once(|| unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    });
}

fn fresh_db_path() -> (tempfile::TempDir, PathBuf) {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("sal-parity-3291");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let path = dir.path().join("memories.db");
    (dir, path)
}

fn memory(ns: &str, title: &str, owner: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        priority: 5,
        confidence: 1.0,
        source: "parity-3291".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": owner }),
        memory_kind: MemoryKind::Observation,
        version: 1,
        ..Memory::default()
    }
}

fn windowed_link(src: &str, dst: &str) -> MemoryLink {
    MemoryLink {
        source_id: src.to_string(),
        target_id: dst.to_string(),
        relation: MemoryLinkRelation::RelatedTo,
        created_at: CREATED_AT.to_string(),
        signature: None,
        observed_by: None,
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: Some(VALID_UNTIL.to_string()),
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

struct RawLink {
    created_at: String,
    valid_from: Option<String>,
    valid_until: Option<String>,
    signature: Option<Vec<u8>>,
    observed_by: Option<String>,
}

fn read_raw_link(path: &std::path::Path, src: &str, dst: &str) -> RawLink {
    let conn = ai_memory::db::open(path).expect("reopen sqlite for raw read");
    conn.query_row(
        "SELECT created_at, valid_from, valid_until, signature, observed_by \
         FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        rusqlite::params![src, dst],
        |r| {
            Ok(RawLink {
                created_at: r.get(0)?,
                valid_from: r.get(1)?,
                valid_until: r.get(2)?,
                signature: r.get(3)?,
                observed_by: r.get(4)?,
            })
        },
    )
    .expect("link row")
}

fn signable_from_row<'a>(
    src: &'a str,
    dst: &'a str,
    row: &'a RawLink,
) -> ai_memory::identity::sign::SignableLink<'a> {
    ai_memory::identity::sign::SignableLink {
        src_id: src,
        dst_id: dst,
        relation: MemoryLinkRelation::RelatedTo.as_str(),
        observed_by: row.observed_by.as_deref(),
        created_at: Some(row.created_at.as_str()),
        valid_from: row.valid_from.as_deref(),
        valid_until: row.valid_until.as_deref(),
    }
}

async fn seeded_pair(store: &SqliteStore, ctx: &CallerContext) -> (String, String) {
    let tag = uuid::Uuid::new_v4();
    let a = store
        .store(
            ctx,
            &memory("parity/3291", &format!("link-src-{tag}"), "alice"),
        )
        .await
        .expect("store src");
    let b = store
        .store(
            ctx,
            &memory("parity/3291", &format!("link-dst-{tag}"), "alice"),
        )
        .await
        .expect("store dst");
    (a, b)
}

#[tokio::test]
async fn sqlite_link_signed_signature_commits_to_created_at_3291() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let kp = ai_memory::identity::keypair::generate("ai:link-3291").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");

    let row = read_raw_link(&path, &src, &dst);
    assert_eq!(row.created_at, CREATED_AT, "created_at must be the claim");
    let sig = row.signature.clone().expect("signature blob present");

    let from_row = signable_from_row(&src, &dst, &row);
    let expected = ai_memory::identity::sign::sign(&kp, &from_row).expect("re-sign from row");
    assert_eq!(
        sig, expected,
        "the persisted signature must be re-derivable from the persisted row including created_at"
    );
    ai_memory::identity::verify::verify(&kp.public, &from_row, &sig)
        .expect("row-derived pre-image must verify");
}

#[tokio::test]
async fn sqlite_tampered_created_at_fails_verify_3291() {
    permissive_attestation_for_tests();
    let (_dir, path) = fresh_db_path();
    let store = SqliteStore::open(&path).expect("open SqliteStore");
    let ctx = CallerContext::for_agent("alice");
    let (src, dst) = seeded_pair(&store, &ctx).await;

    let kp = ai_memory::identity::keypair::generate("ai:link-3291").expect("keypair");
    store
        .link_signed(&ctx, &windowed_link(&src, &dst), Some(&kp))
        .await
        .expect("link_signed");

    let row = read_raw_link(&path, &src, &dst);
    let sig = row.signature.clone().expect("signature blob present");

    let conn = ai_memory::db::open(&path).expect("reopen for tamper");
    conn.execute(
        "UPDATE memory_links SET created_at = ?1 WHERE source_id = ?2 AND target_id = ?3",
        rusqlite::params![FORGED_CREATED_AT, &src, &dst],
    )
    .expect("forge created_at");
    drop(conn);

    let forged = read_raw_link(&path, &src, &dst);
    assert_eq!(forged.created_at, FORGED_CREATED_AT);
    let from_row = signable_from_row(&src, &dst, &forged);
    let err = ai_memory::identity::verify::verify(&kp.public, &from_row, &sig)
        .expect_err("forged created_at must fail verify");
    assert_eq!(err, VerifyError::Tampered);
}
