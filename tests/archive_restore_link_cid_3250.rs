// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3250 — `memory_links.source_cid` / `target_cid` must survive
//! archive→restore. Schema v91 adds the columns to `archived_memory_links`
//! so the snapshot CARRIES the v75 lineage-DAG pins instead of dropping
//! them (every pre-v91 funnel re-inserted NULL).
//!
//! The pins are NOT in the Ed25519 `SignableLink` preimage (COND 2,
//! #1859) — a restored signature still verifies either way. This file
//! pins BOTH halves: the cid round-trip AND the signature still
//! verifying after restore.

use ai_memory::db;
use ai_memory::identity::{keypair, sign as link_sign, verify as link_verify};
use ai_memory::models::{Memory, MemoryLinkRelation, Tier, default_metadata};
use rusqlite::{Connection, params};

const NS: &str = "link-cid-3250";

fn open_db() -> Connection {
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn seed(conn: &Connection, title: &str) -> (String, String) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String("ai:3250".into());
    let id = db::insert(
        conn,
        &Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: NS.to_string(),
            title: title.to_string(),
            content: format!("durable text for {title}"),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Memory::default()
        },
    )
    .expect("seed");
    let cid: String = conn
        .query_row(
            "SELECT cid FROM memories WHERE id = ?1",
            params![&id],
            |r| r.get::<_, Option<String>>(0),
        )
        .expect("read cid")
        .expect("write funnel stamps a genesis cid");
    (id, cid)
}

fn edge_cids(conn: &Connection, src: &str, tgt: &str) -> (Option<String>, Option<String>) {
    conn.query_row(
        "SELECT source_cid, target_cid FROM memory_links \
         WHERE source_id = ?1 AND target_id = ?2",
        params![src, tgt],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("read live edge cids")
}

fn archived_edge_cids(conn: &Connection, src: &str, tgt: &str) -> (Option<String>, Option<String>) {
    conn.query_row(
        "SELECT source_cid, target_cid FROM archived_memory_links \
         WHERE source_id = ?1 AND target_id = ?2",
        params![src, tgt],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("read archived edge cids")
}

/// Stamp the lineage pins directly so this test does not flip the
/// process-global `lineage_dag` atomic (unseeded tests read `false`).
fn stamp_edge_cids(conn: &Connection, src: &str, tgt: &str, source_cid: &str, target_cid: &str) {
    conn.execute(
        "UPDATE memory_links SET source_cid = ?1, target_cid = ?2 \
         WHERE source_id = ?3 AND target_id = ?4",
        params![source_cid, target_cid, src, tgt],
    )
    .expect("stamp edge cids");
}

/// The archive snapshot must CARRY the pins into cold storage, not drop them.
#[test]
fn archive_carries_link_cids_into_cold_storage_3250() {
    let conn = open_db();
    let (a, a_cid) = seed(&conn, "cid-src");
    let (b, b_cid) = seed(&conn, "cid-dst");
    db::create_link(&conn, &a, &b, MemoryLinkRelation::DerivedFrom.as_str()).expect("link");
    stamp_edge_cids(&conn, &a, &b, &a_cid, &b_cid);

    assert!(db::archive_memory(&conn, &a, None).expect("archive A"));
    let (got_src, got_tgt) = archived_edge_cids(&conn, &a, &b);
    assert_eq!(got_src.as_deref(), Some(a_cid.as_str()));
    assert_eq!(got_tgt.as_deref(), Some(b_cid.as_str()));
}

/// Restore must re-insert the carried pins onto `memory_links`.
#[test]
fn restore_round_trips_link_cids_3250() {
    let conn = open_db();
    let (a, a_cid) = seed(&conn, "restore-src");
    let (b, b_cid) = seed(&conn, "restore-dst");
    db::create_link(&conn, &a, &b, MemoryLinkRelation::DerivedFrom.as_str()).expect("link");
    stamp_edge_cids(&conn, &a, &b, &a_cid, &b_cid);

    assert!(db::archive_memory(&conn, &a, None).expect("archive A"));
    assert!(db::restore_archived(&conn, &a).expect("restore A"));
    let (got_src, got_tgt) = edge_cids(&conn, &a, &b);
    assert_eq!(
        got_src.as_deref(),
        Some(a_cid.as_str()),
        "source_cid round-trip"
    );
    assert_eq!(
        got_tgt.as_deref(),
        Some(b_cid.as_str()),
        "target_cid round-trip"
    );
}

/// Pre-v91 snapshots (NULL cids) restore as NULL — never invent a pin.
#[test]
fn pre_v91_null_cids_restore_as_null_3250() {
    let conn = open_db();
    let (a, _) = seed(&conn, "legacy-src");
    let (b, _) = seed(&conn, "legacy-dst");
    db::create_link(&conn, &a, &b, MemoryLinkRelation::RelatedTo.as_str()).expect("link");
    // Do NOT stamp cids — the live edge is NULL (lineage_dag off).
    assert!(db::archive_memory(&conn, &a, None).expect("archive A"));
    let (arch_src, arch_tgt) = archived_edge_cids(&conn, &a, &b);
    assert!(arch_src.is_none() && arch_tgt.is_none(), "NULL snapshot");
    assert!(db::restore_archived(&conn, &a).expect("restore A"));
    let (got_src, got_tgt) = edge_cids(&conn, &a, &b);
    assert!(
        got_src.is_none() && got_tgt.is_none(),
        "legacy NULL must not be invented into a cid"
    );
}

/// A signed edge still verifies after archive→restore (cids are not in
/// the SignableLink preimage — COND 2). Pins still round-trip.
#[test]
fn signed_edge_still_verifies_after_restore_3250() {
    let conn = open_db();
    let kp = keypair::generate("ai:3250-signer").expect("gen key");
    let (a, a_cid) = seed(&conn, "signed-src");
    let (b, b_cid) = seed(&conn, "signed-dst");
    let level = db::create_link_signed(
        &conn,
        &a,
        &b,
        MemoryLinkRelation::DerivedFrom.as_str(),
        Some(&kp),
    )
    .expect("signed link");
    assert_eq!(level, "self_signed");
    stamp_edge_cids(&conn, &a, &b, &a_cid, &b_cid);

    let (sig, observed_by, valid_from, created_at): (
        Vec<u8>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT signature, observed_by, valid_from, created_at FROM memory_links \
             WHERE source_id = ?1 AND target_id = ?2",
            params![&a, &b],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("read signature");

    assert!(db::archive_memory(&conn, &a, None).expect("archive A"));
    assert!(db::restore_archived(&conn, &a).expect("restore A"));

    let (sig2, observed_by2, valid_from2, created_at2): (
        Vec<u8>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT signature, observed_by, valid_from, created_at FROM memory_links \
             WHERE source_id = ?1 AND target_id = ?2",
            params![&a, &b],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("read restored signature");
    assert_eq!(sig, sig2, "signature bytes survive archive→restore");
    assert_eq!(observed_by, observed_by2);
    assert_eq!(valid_from, valid_from2);
    assert_eq!(created_at, created_at2);

    let signable = link_sign::SignableLink {
        src_id: &a,
        dst_id: &b,
        relation: MemoryLinkRelation::DerivedFrom.as_str(),
        observed_by: observed_by2.as_deref(),
        created_at: created_at2.as_deref(),
        valid_from: valid_from2.as_deref(),
        valid_until: None,
    };
    link_verify::verify(&kp.public, &signable, &sig2)
        .expect("restored signed edge must still verify (cids are not in the preimage)");

    let (got_src, got_tgt) = edge_cids(&conn, &a, &b);
    assert_eq!(got_src.as_deref(), Some(a_cid.as_str()));
    assert_eq!(got_tgt.as_deref(), Some(b_cid.as_str()));
}

/// Fresh bootstrap SCHEMA ships the v91 columns (no ladder required).
#[test]
fn bootstrap_schema_has_archived_memory_links_cid_columns_3250() {
    let conn = open_db();
    let cols: Vec<String> = {
        let mut stmt = conn
            .prepare("PRAGMA table_info(archived_memory_links)")
            .expect("pragma");
        stmt.query_map([], |r| r.get::<_, String>(1))
            .expect("map")
            .collect::<rusqlite::Result<_>>()
            .expect("cols")
    };
    assert!(
        cols.iter().any(|c| c == "source_cid"),
        "bootstrap SCHEMA must ship archived_memory_links.source_cid"
    );
    assert!(
        cols.iter().any(|c| c == "target_cid"),
        "bootstrap SCHEMA must ship archived_memory_links.target_cid"
    );
}

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::*;
    use ai_memory::models::MemoryLink;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    fn pg_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    fn pg_mem(id: &str, ns: &str, title: &str) -> Memory {
        Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: format!("pg 3250 {title}"),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            metadata: serde_json::json!({ "agent_id": "ai:sal-test" }),
            ..Memory::default()
        }
    }

    /// Live-pg twin: archive_by_ids + archive_restore round-trips the
    /// lineage-DAG pins. Skips when `AI_MEMORY_TEST_POSTGRES_URL` is unset.
    #[tokio::test]
    async fn archive_restore_round_trips_link_cids_pg_3250() {
        let Some(url) = pg_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store = PostgresStore::connect(&url).await.expect("connect");
        let ctx = CallerContext::for_agent("ai:sal-test");
        let unique = uuid::Uuid::new_v4();
        let ns = format!("link-cid-3250-{unique}");
        let a_id = format!("3250-a-{unique}");
        let b_id = format!("3250-b-{unique}");
        store
            .store(&ctx, &pg_mem(&a_id, &ns, "pg-src"))
            .await
            .expect("store a");
        store
            .store(&ctx, &pg_mem(&b_id, &ns, "pg-dst"))
            .await
            .expect("store b");

        let a_cid: String = sqlx::query_scalar("SELECT cid FROM memories WHERE id = $1")
            .bind(&a_id)
            .fetch_one(store.pool())
            .await
            .expect("a cid");
        let b_cid: String = sqlx::query_scalar("SELECT cid FROM memories WHERE id = $1")
            .bind(&b_id)
            .fetch_one(store.pool())
            .await
            .expect("b cid");

        store
            .link(
                &ctx,
                &MemoryLink {
                    source_id: a_id.clone(),
                    target_id: b_id.clone(),
                    relation: MemoryLinkRelation::DerivedFrom,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    signature: None,
                    observed_by: None,
                    valid_from: None,
                    valid_until: None,
                    attest_level: None,
                    source_cid: None,
                    target_cid: None,
                },
            )
            .await
            .expect("link");
        sqlx::query(
            "UPDATE memory_links SET source_cid = $1, target_cid = $2 \
             WHERE source_id = $3 AND target_id = $4",
        )
        .bind(&a_cid)
        .bind(&b_cid)
        .bind(&a_id)
        .bind(&b_id)
        .execute(store.pool())
        .await
        .expect("stamp cids");

        let moved = store
            .archive_by_ids(&ctx, std::slice::from_ref(&a_id), Some("test-3250"))
            .await
            .expect("archive_by_ids");
        assert_eq!(moved, 1);

        let (arch_src, arch_tgt): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT source_cid, target_cid FROM archived_memory_links \
             WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&a_id)
        .bind(&b_id)
        .fetch_one(store.pool())
        .await
        .expect("archived pins");
        assert_eq!(
            arch_src.as_deref(),
            Some(a_cid.as_str()),
            "snapshot carries source_cid"
        );
        assert_eq!(
            arch_tgt.as_deref(),
            Some(b_cid.as_str()),
            "snapshot carries target_cid"
        );

        assert!(
            store.archive_restore(&ctx, &a_id).await.expect("restore"),
            "restore reports success"
        );
        let (live_src, live_tgt): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT source_cid, target_cid FROM memory_links \
             WHERE source_id = $1 AND target_id = $2",
        )
        .bind(&a_id)
        .bind(&b_id)
        .fetch_one(store.pool())
        .await
        .expect("restored pins");
        assert_eq!(live_src.as_deref(), Some(a_cid.as_str()));
        assert_eq!(live_tgt.as_deref(), Some(b_cid.as_str()));

        let _ = store.delete(&ctx, &a_id).await;
        let _ = store.delete(&ctx, &b_id).await;
    }
}
