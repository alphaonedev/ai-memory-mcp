// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G8 (#1825) — content-id (cid) federation stability tests.
//!
//! The cid is a DETERMINISTIC, MODE-INDEPENDENT function of a memory's
//! GENESIS fields, so two federated nodes that saw the same genesis mint
//! the SAME `b3:` address even under DIFFERENT
//! `AI_MEMORY_SECRET_SCREEN_MODE` settings and DIFFERENT UUIDs. A merge
//! never overwrites the surviving local genesis, and an inbound cid
//! mismatch is flagged (accept-and-flag), never refused.

use ai_memory::db;
use ai_memory::identity::cid;
use ai_memory::models::{Memory, Tier};
use ai_memory::secret_screen::{REDACTION_PLACEHOLDER, ScreenOutcome, screen};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

fn secret_mem(id: &str, content: &str) -> Memory {
    let now = "2026-06-30T00:00:00Z".to_string();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "fed-cid".to_string(),
        title: "shared genesis title".to_string(),
        content: content.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "ai:node@fed" }),
        ..Default::default()
    }
}

#[test]
fn cross_node_same_genesis_same_cid() {
    // SECRET-BEARING content (a GitHub-PAT-shaped token screen() redacts).
    // This is NOT a vacuous secret-free pass — the raw token must be
    // screened out of the pre-image, and the cid must equal the cid over
    // the pre-redacted form.
    let token = "ghp_0123456789abcdefABCDEF0123456789abcdef";
    let content = format!("deploy key {token} embedded in the note");
    assert!(
        matches!(screen(&content), ScreenOutcome::Hit { .. }),
        "test content must actually trip a credential detector (non-vacuous)"
    );

    // Node A and Node B: SAME genesis fields, DIFFERENT UUIDs (the UUID is
    // NOT part of the cid pre-image). screen() never consults the
    // process-wide AI_MEMORY_SECRET_SCREEN_MODE, so this equality holds
    // regardless of each node's configured mode.
    let node_a = cid::stamp_memory_cid(&secret_mem(&Uuid::new_v4().to_string(), &content));
    let node_b = cid::stamp_memory_cid(&secret_mem(&Uuid::new_v4().to_string(), &content));
    assert_eq!(
        node_a.cid, node_b.cid,
        "same genesis (diff UUID) → same cid"
    );

    // Non-vacuous: the raw token is unrecoverable from the stored
    // pre-image, and the cid equals the cid over the redacted form.
    let hay = String::from_utf8_lossy(&node_a.genesis);
    assert!(
        !hay.contains(token),
        "raw secret must not survive in cid_genesis"
    );
    let redacted = content.replace(token, REDACTION_PLACEHOLDER);
    let manual = cid::stamp_memory_cid(&secret_mem("irrelevant-id", &redacted));
    assert_eq!(
        node_a.cid, manual.cid,
        "cid is computed over screen(content) — mode-independent redaction"
    );

    // And the STORED cid matches across two independent node DBs.
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let conn_a = db::open(&tmp_a.path().join("ai-memory.db")).unwrap();
    let conn_b = db::open(&tmp_b.path().join("ai-memory.db")).unwrap();
    let ida = Uuid::new_v4().to_string();
    let idb = Uuid::new_v4().to_string();
    db::insert(&conn_a, &secret_mem(&ida, &content)).unwrap();
    db::insert(&conn_b, &secret_mem(&idb, &content)).unwrap();
    let ca = db::get(&conn_a, &ida).unwrap().unwrap().cid.unwrap();
    let cb = db::get(&conn_b, &idb).unwrap().unwrap().cid.unwrap();
    assert_eq!(ca, cb, "two nodes, different UUIDs, same stored cid");
}

#[test]
fn federation_merge_preserves_local_genesis_cid() {
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();

    // Local genesis.
    let local_id = Uuid::new_v4().to_string();
    let mut local = secret_mem(&local_id, "local genesis body");
    local.updated_at = "2026-06-30T00:00:00Z".to_string();
    db::insert(&conn, &local).unwrap();
    let local_genesis_cid = db::get(&conn, &local_id).unwrap().unwrap().cid.unwrap();

    // Inbound federation row: SAME (title, namespace), DIFFERENT id +
    // content + a NEWER updated_at so the newer-wins merge overwrites
    // content — but the surviving row must KEEP the local genesis cid.
    let mut inbound = secret_mem(&Uuid::new_v4().to_string(), "inbound newer body");
    inbound.updated_at = "2027-01-01T00:00:00Z".to_string();
    db::insert_if_newer(&conn, &inbound).unwrap();

    let surviving = db::get(&conn, &local_id).unwrap().unwrap();
    assert_eq!(surviving.content, "inbound newer body", "newer content won");
    assert_eq!(
        surviving.cid.as_deref(),
        Some(local_genesis_cid.as_str()),
        "merge preserves the LOCAL genesis cid"
    );
}

#[test]
fn inbound_cid_mismatch_is_flagged_not_refused() {
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();

    // An inbound row arrives carrying a BOGUS cid (as if a peer computed
    // it wrong or tampered). The receive path recomputes the cid locally
    // and NEVER refuses the write.
    let id = Uuid::new_v4().to_string();
    let mut inbound = secret_mem(&id, "inbound body");
    inbound.cid = Some("b3:deadbeefdeadbeef".to_string());

    let res = db::insert_if_newer(&conn, &inbound);
    assert!(res.is_ok(), "a bogus inbound cid must NOT refuse the write");

    let stored = db::get(&conn, &id).unwrap().unwrap();
    let stored_cid = stored.cid.clone().unwrap();
    assert_ne!(
        stored_cid, "b3:deadbeefdeadbeef",
        "the locally-recomputed cid replaces the bogus inbound claim"
    );
    // And the stored pair is self-consistent (verify passes).
    let genesis = db::read_cid_genesis(&conn, &id).unwrap().unwrap();
    assert!(cid::verify_cid(&stored_cid, &genesis).is_ok());
}
