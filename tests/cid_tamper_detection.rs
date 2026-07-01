// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G8 (#1825) — content-id (cid) tamper-detection + genesis-stamp
//! parity tests.
//!
//! Pins the CLAIM BOUNDARY (§26.5 honesty): a cid gives PARTIAL-corruption
//! detection (a stray bit-flip in `cid` or `cid_genesis` is caught), NOT
//! at-rest forgery-evidence — a consistent re-forge that rewrites BOTH
//! columns from tampered fields verifies clean.

use ai_memory::db;
use ai_memory::identity::cid;
use ai_memory::models::{Memory, Tier};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

fn mem(id: &str, title: &str, content: &str) -> Memory {
    let now = "2026-06-30T00:00:00Z".to_string();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "cid-tamper".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "ai:tamper@host" }),
        ..Default::default()
    }
}

#[test]
fn tamper_is_detected() {
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    let id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&id, "genesis title", "genesis body")).unwrap();

    let stored = db::get(&conn, &id).unwrap().unwrap();
    let stored_cid = stored.cid.clone().expect("genesis INSERT stamped a cid");
    let genesis = db::read_cid_genesis(&conn, &id)
        .unwrap()
        .expect("cid_genesis present");

    // Clean pair verifies.
    assert!(cid::verify_cid(&stored_cid, &genesis).is_ok());

    // Mutate cid_genesis → mismatch (the recomputed BLAKE3 diverges).
    let mut bad_genesis = genesis.clone();
    *bad_genesis.last_mut().unwrap() ^= 0x01;
    conn.execute(
        "UPDATE memories SET cid_genesis = ?1 WHERE id = ?2",
        rusqlite::params![bad_genesis, id],
    )
    .unwrap();
    let g2 = db::read_cid_genesis(&conn, &id).unwrap().unwrap();
    assert!(
        cid::verify_cid(&stored_cid, &g2).is_err(),
        "tampered genesis must mismatch"
    );

    // Restore genesis, mutate the cid string → mismatch.
    conn.execute(
        "UPDATE memories SET cid_genesis = ?1, cid = ?2 WHERE id = ?3",
        rusqlite::params![genesis, "b3:deadbeef", id],
    )
    .unwrap();
    let bad_cid = db::get(&conn, &id).unwrap().unwrap().cid.unwrap();
    let g3 = db::read_cid_genesis(&conn, &id).unwrap().unwrap();
    assert!(
        cid::verify_cid(&bad_cid, &g3).is_err(),
        "tampered cid must mismatch"
    );
}

// The SAL VerifyReport assertion is only compiled when the `sal` feature
// (which brings in `store::sqlite::SqliteStore` + the `MemoryStore` trait)
// is enabled — the default `cargo test` profile is sqlite-core only.
#[cfg(feature = "sal")]
#[tokio::test]
async fn verify_report_cid_ok_flips_on_tamper() {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    let tmp = TempDir::new().unwrap();
    let store = SqliteStore::open(tmp.path().join("ai-memory.db")).expect("open store");
    let ctx = CallerContext::for_agent("ai:tamper@host");
    let id = Uuid::new_v4().to_string();
    store
        .store(&ctx, &mem(&id, "vr title", "vr body"))
        .await
        .expect("store");

    // Clean row: cid_ok == Some(true), no mismatch string.
    let clean = store.verify(&ctx, &id).await.expect("verify clean");
    assert_eq!(clean.cid_ok, Some(true), "clean row verifies its cid");
    assert!(clean.cid_mismatch.is_none());

    // Tamper cid_genesis via a SEPARATE handle to the same DB file, then
    // re-verify through the SAL: cid_ok flips to Some(false).
    {
        let raw = db::open(&tmp.path().join("ai-memory.db")).unwrap();
        let g = db::read_cid_genesis(&raw, &id).unwrap().unwrap();
        let mut bad = g;
        bad[0] ^= 0xFF;
        raw.execute(
            "UPDATE memories SET cid_genesis = ?1 WHERE id = ?2",
            rusqlite::params![bad, id],
        )
        .unwrap();
    }
    let dirty = store.verify(&ctx, &id).await.expect("verify dirty");
    assert_eq!(dirty.cid_ok, Some(false), "tampered genesis flips cid_ok");
    assert!(
        dirty.cid_mismatch.is_some(),
        "mismatch carries a description"
    );
}

#[test]
fn consistent_reforge_not_caught_by_cid_alone() {
    // THREAT BOUNDARY: rewriting BOTH cid AND cid_genesis from a NEW
    // (tampered) genesis is self-consistent, so cid verification PASSES.
    // This is the explicit non-claim: cid is NOT at-rest forgery-evidence.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    let id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&id, "original", "original body")).unwrap();

    // Attacker forges a DIFFERENT genesis and stamps both columns from it.
    let forged = cid::stamp_cid(
        "ai:tamper@host",
        "cid-tamper",
        "TAMPERED TITLE",
        "observation",
        "2026-06-30T00:00:00Z",
        "TAMPERED BODY",
    );
    conn.execute(
        "UPDATE memories SET cid = ?1, cid_genesis = ?2 WHERE id = ?3",
        rusqlite::params![forged.cid, forged.genesis, id],
    )
    .unwrap();

    let re_cid = db::get(&conn, &id).unwrap().unwrap().cid.unwrap();
    let re_genesis = db::read_cid_genesis(&conn, &id).unwrap().unwrap();
    assert!(
        cid::verify_cid(&re_cid, &re_genesis).is_ok(),
        "a consistent re-forge PASSES cid verification — cid alone is not forgery-evidence"
    );
}

#[test]
fn in_place_edit_leaves_cid_stable_verify_passes() {
    // cid is GENESIS identity: an in-place content edit does NOT change
    // `cid`/`cid_genesis`, so verification still passes against the
    // original genesis even though the live content diverged.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    let id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&id, "edit title", "before edit")).unwrap();

    let cid0 = db::get(&conn, &id).unwrap().unwrap().cid.unwrap();
    let genesis0 = db::read_cid_genesis(&conn, &id).unwrap().unwrap();

    // In-place edit the content.
    db::update(
        &conn,
        &id,
        None,
        Some("AFTER the in-place edit"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let after = db::get(&conn, &id).unwrap().unwrap();
    assert_eq!(after.content, "AFTER the in-place edit", "content mutated");
    assert_eq!(
        after.cid.as_deref(),
        Some(cid0.as_str()),
        "cid is stable across edit"
    );
    let genesis1 = db::read_cid_genesis(&conn, &id).unwrap().unwrap();
    assert_eq!(genesis1, genesis0, "cid_genesis is stable across edit");
    assert!(
        cid::verify_cid(&cid0, &genesis1).is_ok(),
        "verify still passes against the unchanged genesis"
    );
}

#[test]
fn no_genesis_insert_path_leaves_cid_null_parity() {
    // T4 parity: every SQLite genesis INSERT path stamps a non-NULL cid.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();

    // insert()
    let id_insert = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&id_insert, "parity a", "body a")).unwrap();

    // insert_if_newer() — federation newer-wins fresh insert.
    let id_newer = Uuid::new_v4().to_string();
    db::insert_if_newer(&conn, &mem(&id_newer, "parity b", "body b")).unwrap();

    // insert_with_conflict(Error) — the reflect first-write path.
    let id_conflict = Uuid::new_v4().to_string();
    db::insert_with_conflict(
        &conn,
        &mem(&id_conflict, "parity c", "body c"),
        db::ConflictMode::Error,
    )
    .unwrap();

    for id in [&id_insert, &id_newer, &id_conflict] {
        let stored = db::get(&conn, id).unwrap().unwrap();
        assert!(
            stored.cid.is_some(),
            "genesis insert must stamp a cid (id={id})"
        );
        assert!(
            db::read_cid_genesis(&conn, id).unwrap().is_some(),
            "genesis insert must stamp cid_genesis (id={id})"
        );
    }

    // The stored cid recomputes deterministically from its genesis.
    let stored = db::get(&conn, &id_insert).unwrap().unwrap();
    let genesis = db::read_cid_genesis(&conn, &id_insert).unwrap().unwrap();
    assert!(cid::verify_cid(stored.cid.as_deref().unwrap(), &genesis).is_ok());
}
