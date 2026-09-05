// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2385 — GENESIS IDENTITY must survive archive→restore byte-for-byte.
//!
//! The v74 (#1825) contract is that a memory's BLAKE3 content address is fixed
//! at creation. `archived_memories` never gained the `cid` / `cid_genesis`
//! columns, so every archive `INSERT ... SELECT` DROPPED the address and both
//! `restore_archived*` paths RE-MINTED it — recomputing
//! `stamp_cid(agent_id, namespace, title, memory_kind, created_at, plaintext)`
//! from six reconstructed inputs.
//!
//! A re-mint reproduces the original address only if ALL SIX are byte-identical
//! at restore time. When one is not — a rewritten `metadata.agent_id`, or a
//! decrypt failure whose `unwrap_or` fallback hashes the CIPHERTEXT placeholder
//! — the restored row silently acquires a DIFFERENT address, and every
//! `memory_links.source_cid` / `target_cid` mirror resolving to the old one
//! dangles. No write intent, no error: silent identity corruption of the
//! durable tier.
//!
//! Schema v90 adds the two columns so the identity is a CARRIED fact. Rows
//! archived BEFORE v90 keep the re-mint fallback (their genesis address cannot
//! be proven from the archive, and inventing one would be the very corruption
//! this closes).

use ai_memory::db;
use ai_memory::models::{Memory, Tier, default_metadata};
use rusqlite::{Connection, params};

const NS: &str = "cid-identity-2385";

fn open_db() -> Connection {
    let _ = ai_memory::identity::test_key_dir::install();
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn seed(conn: &Connection, agent_id: &str) -> (String, String) {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = default_metadata();
    metadata["agent_id"] = serde_json::Value::String(agent_id.to_string());
    let id = ai_memory::storage::insert(
        conn,
        &Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: NS.to_string(),
            title: format!("cid-row-{}", uuid::Uuid::new_v4()),
            content: "durable genesis text".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ..Memory::default()
        },
    )
    .expect("seed");
    let cid = live_cid(conn, &id).expect("the write funnel must stamp a genesis cid");
    (id, cid)
}

fn live_cid(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row("SELECT cid FROM memories WHERE id = ?1", params![id], |r| {
        r.get::<_, Option<String>>(0)
    })
    .ok()
    .flatten()
}

fn archived_cid(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT cid FROM archived_memories WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

/// The archive funnel must CARRY the address into cold storage, not drop it.
#[test]
fn archive_carries_the_genesis_cid_into_cold_storage_2385() {
    let conn = open_db();
    let (id, cid) = seed(&conn, "ai:alice");
    ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");

    assert_eq!(
        archived_cid(&conn, &id).as_deref(),
        Some(cid.as_str()),
        "#2385: archived_memories must carry the v74 genesis cid"
    );
    let genesis_present: bool = conn
        .query_row(
            "SELECT cid_genesis IS NOT NULL FROM archived_memories WHERE id = ?1",
            params![&id],
            |r| r.get::<_, i64>(0).map(|n| n != 0),
        )
        .expect("read cid_genesis");
    assert!(
        genesis_present,
        "#2385: the canonical genesis PRE-IMAGE must travel with the address"
    );
}

/// The round trip is the contract: same address in, same address out.
#[test]
fn archive_then_restore_preserves_the_genesis_cid_2385() {
    let conn = open_db();
    let (id, cid) = seed(&conn, "ai:alice");
    ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");
    assert!(
        ai_memory::storage::restore_archived(&conn, &id).expect("restore"),
        "restore must report success"
    );
    assert_eq!(
        live_cid(&conn, &id).as_deref(),
        Some(cid.as_str()),
        "#2385: the restored row must keep its ORIGINAL genesis address"
    );
}

/// The defect made concrete. `metadata.agent_id` is one of the six re-mint
/// inputs; mutate it on the ARCHIVED row and the pre-#2385 restore silently
/// minted a different address. With the columns carried, the stored identity
/// wins and the drift is structurally impossible.
#[test]
fn restore_identity_survives_an_agent_id_drift_in_the_archive_2385() {
    let conn = open_db();
    let (id, cid) = seed(&conn, "ai:alice");
    ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");

    // Rewrite one of the six re-mint inputs on the archived row.
    conn.execute(
        "UPDATE archived_memories \
         SET metadata = json_set(metadata, '$.agent_id', 'ai:mallory') WHERE id = ?1",
        params![&id],
    )
    .expect("drift the archived agent_id");

    ai_memory::storage::restore_archived(&conn, &id).expect("restore");
    assert_eq!(
        live_cid(&conn, &id).as_deref(),
        Some(cid.as_str()),
        "#2385: a drifted re-mint input must NOT re-address the durable row"
    );
}

/// Rows archived BEFORE v90 have both columns NULL. They keep the legacy
/// re-mint — degrade, never refuse, and never invent an address we cannot
/// prove.
#[test]
fn legacy_pre_v90_archive_row_still_restores_via_the_remint_fallback_2385() {
    let conn = open_db();
    let (id, _cid) = seed(&conn, "ai:alice");
    ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");
    conn.execute(
        "UPDATE archived_memories SET cid = NULL, cid_genesis = NULL WHERE id = ?1",
        params![&id],
    )
    .expect("simulate a pre-v90 archive row");

    assert!(
        ai_memory::storage::restore_archived(&conn, &id).expect("restore"),
        "a legacy archive row must still restore"
    );
    assert!(
        live_cid(&conn, &id).is_some(),
        "#2385: the legacy fallback must still mint an address rather than \
         leaving the restored row unaddressed"
    );
}

/// The (`cid`, `cid_genesis`) PAIR is selected atomically — the #2395 lesson
/// applied to this restore. A carried address with a re-derived pre-image
/// would be a row whose own verify disagrees with itself.
#[test]
fn restore_selects_the_cid_pair_from_one_operand_2385() {
    let conn = open_db();
    let (id, cid) = seed(&conn, "ai:alice");
    ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");
    let archived_genesis: Option<Vec<u8>> = conn
        .query_row(
            "SELECT cid_genesis FROM archived_memories WHERE id = ?1",
            params![&id],
            |r| r.get(0),
        )
        .expect("read archived genesis");

    ai_memory::storage::restore_archived(&conn, &id).expect("restore");
    let (restored_cid, restored_genesis): (Option<String>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT cid, cid_genesis FROM memories WHERE id = ?1",
            params![&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read restored pair");
    assert_eq!(restored_cid.as_deref(), Some(cid.as_str()));
    assert_eq!(
        restored_genesis, archived_genesis,
        "#2385: the address and its pre-image must come from the SAME operand"
    );
}

// ---------------------------------------------------------------------------
// v90 migration mechanics
// ---------------------------------------------------------------------------

fn trigger_names(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
        .expect("prepare trigger scan");
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query triggers");
    rows.map(|r| r.expect("trigger name")).collect()
}

/// The v90 arm is additive and probe-guarded, so replaying it is a no-op —
/// and, because it performs NO full-table rebuild, every trigger survives.
/// (The v63→v65 lesson: a `SQLite` full-table rebuild silently drops ALL
/// triggers, so a migration test that does not scan them proves nothing.)
#[test]
fn v90_migration_is_idempotent_and_preserves_every_trigger_2385() {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-2385-")
        .tempdir()
        .expect("scratch dir");
    let path = dir.path().join("memories.db");

    let triggers_before;
    let cid_before;
    let id;
    {
        let conn = db::open(&path).expect("first open migrates to the tip");
        let seeded = seed(&conn, "ai:alice");
        id = seeded.0;
        cid_before = seeded.1;
        ai_memory::storage::archive_memory(&conn, &id, Some("manual")).expect("archive");
        triggers_before = trigger_names(&conn);
        assert!(
            !triggers_before.is_empty(),
            "the fixture must actually have triggers or this proves nothing"
        );
    }

    // Rewind the stamp so the ladder replays the v90 arm over a POPULATED
    // database, twice.
    for _ in 0..2 {
        {
            let raw = Connection::open(&path).expect("raw reopen");
            raw.execute("DELETE FROM schema_version", [])
                .expect("clear");
            raw.execute("INSERT INTO schema_version (version) VALUES (89)", [])
                .expect("rewind to v89");
        }
        let conn = db::open(&path).expect("replay the v90 arm");
        assert_eq!(
            trigger_names(&conn),
            triggers_before,
            "v90 must not drop or recreate a single trigger (the v63/v65 lesson)"
        );
        assert_eq!(
            archived_cid(&conn, &id).as_deref(),
            Some(cid_before.as_str()),
            "the replay must not disturb a carried address"
        );
        let v: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .expect("stamp");
        assert_eq!(
            v,
            ai_memory::storage::migrations::current_schema_version(),
            "the ladder must land back on the tip"
        );
    }
}

/// The archive mirror must carry the columns on a FRESH install too (the
/// bootstrap creates `archived_memories` in the v4 arm, and the v90 arm adds
/// the pair on the same first pass).
#[test]
fn a_fresh_database_ships_the_v90_archive_cid_columns_2385() {
    let conn = open_db();
    for column in ["cid", "cid_genesis"] {
        let present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('archived_memories') WHERE name = ?1",
                params![column],
                |r| r.get(0),
            )
            .expect("pragma probe");
        assert_eq!(present, 1, "archived_memories.{column} must exist at v90");
    }
}
