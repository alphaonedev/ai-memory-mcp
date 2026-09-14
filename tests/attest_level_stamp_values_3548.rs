// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3548 (vocabulary ruling, option 2) — a memory row's top-level
//! `metadata.attest_level` has ONE owner and a CLOSED value set:
//! `identity::verify::ATTEST_LEVEL_MEMORY_STAMP_VALUES`, exactly four values
//! from two writer subsystems, and `memory_recall`'s `content_attestation` is
//! a verbatim pass-through of it. Three things are pinned so the owner is an
//! ENFORCEMENT rather than a comment:
//!
//! * the set is EXACTLY four (never "at least") — a fifth writer must add
//!   its value here, with its subsystem, or fail;
//! * the API reference's enumeration is BOUND to the constant — a documented
//!   list that drifts from the code reads as authoritative and is worse
//!   than none;
//! * both real writers stamp a member: the identity write path
//!   (`stamp_attestation`, unsigned ⇒ `claimed`) and the L4 capture channel
//!   (`handle_capture_turn`, no host signature ⇒ `self_signed`), and the
//!   gate refuses an unlisted value.

#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeSet;

use ai_memory::identity::verify::{ATTEST_LEVEL_MEMORY_STAMP_VALUES, memory_stamp_value};

fn expected_set() -> BTreeSet<&'static str> {
    [
        ai_memory::identity::verify::AttestLevel::Claimed.as_str(),
        ai_memory::identity::verify::AttestLevel::AgentAttested.as_str(),
        ai_memory::models::link::AttestLevel::SelfSigned.as_str(),
        ai_memory::models::link::AttestLevel::SignedByPeer.as_str(),
    ]
    .into_iter()
    .collect()
}

#[test]
fn memory_stamp_value_set_is_exactly_four_3548() {
    let set: BTreeSet<&str> = ATTEST_LEVEL_MEMORY_STAMP_VALUES.iter().copied().collect();
    assert_eq!(
        ATTEST_LEVEL_MEMORY_STAMP_VALUES.len(),
        4,
        "EXACTLY four — a fifth writer adds itself here"
    );
    assert_eq!(
        set,
        expected_set(),
        "the two identity variants plus the two L4 capture values, nothing else"
    );
    for v in &set {
        assert_eq!(memory_stamp_value(v), Ok(*v));
    }
    for v in [
        "unsigned",
        "peer_attested",
        "operator_signed",
        "loader_observed",
        "",
        "Claimed",
    ] {
        assert!(
            memory_stamp_value(v).is_err(),
            "{v:?} is not a memory stamp"
        );
    }
}

/// The `content_attestation` bullet in docs/API_REFERENCE.md enumerates the
/// values as `  - \`value\` — …` sub-bullets; that list must equal the
/// constant, exactly.
#[test]
fn api_reference_enumeration_is_bound_to_the_constant_3548() {
    let doc = std::fs::read_to_string("docs/API_REFERENCE.md").expect("API_REFERENCE.md");
    let start = doc
        .find("- `content_attestation` — **v1.0.0")
        .expect("the content_attestation bullet exists");
    let end = doc[start..]
        .find("Not this field:")
        .map(|i| start + i)
        .expect("the bullet closes with the non-member note");
    let documented: BTreeSet<&str> = doc[start..end]
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- `"))
        .filter_map(|rest| rest.split('`').next())
        .filter(|v| *v != "content_attestation")
        .collect();
    let code: BTreeSet<&str> = ATTEST_LEVEL_MEMORY_STAMP_VALUES.iter().copied().collect();
    assert_eq!(
        documented, code,
        "docs/API_REFERENCE.md must enumerate exactly identity::verify::ATTEST_LEVEL_MEMORY_STAMP_VALUES"
    );
}

fn scratch_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch dir under the repo");
    let conn = ai_memory::db::open(&dir.path().join("stamp-3548.db")).expect("db::open");
    (dir, conn)
}

#[test]
fn identity_write_path_stamps_a_member_3548() {
    use ai_memory::identity::attest::stamp_attestation;
    let (_dir, conn) = scratch_db();
    let mut mem = ai_memory::models::Memory {
        id: "m-stamp-3548".into(),
        namespace: "stamp-3548".into(),
        title: "unsigned store".into(),
        content: "a plain store with no signature".into(),
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("insert");
    let level = stamp_attestation(&mut mem, "ai:author-3548", None, None, false).expect("stamp");
    let stamped = mem.metadata["attest_level"]
        .as_str()
        .expect("stamped")
        .to_string();
    assert_eq!(stamped, level.as_str());
    assert_eq!(
        memory_stamp_value(&stamped),
        Ok("claimed"),
        "an unsigned store is `claimed`"
    );
}

#[test]
fn l4_capture_path_stamps_a_member_3548() {
    let (_dir, conn) = scratch_db();
    let resp = ai_memory::mcp::handle_capture_turn(
        &conn,
        &serde_json::json!({
            "host_session_id": "sess-stamp-3548",
            "host_turn_index": 1,
            "role": "user",
            "content": "a captured turn with enough prose to be stored as a memory row",
        }),
        Some("ai:author-3548-l4"),
    )
    .expect("capture_turn through the real handler");
    let id = resp["memory_id"].as_str().expect("memory_id").to_string();
    let row = ai_memory::db::get(&conn, &id)
        .expect("get")
        .expect("captured row");
    let stamped = row.metadata["attest_level"]
        .as_str()
        .expect("stamped")
        .to_string();
    assert_eq!(
        memory_stamp_value(&stamped),
        Ok("self_signed"),
        "an L4 capture without a host signature is `self_signed`, a member of the owned set"
    );
}
