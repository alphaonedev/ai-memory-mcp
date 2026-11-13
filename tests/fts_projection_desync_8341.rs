// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8341 — deterministic reproduction of `SQLITE_CORRUPT_VTAB` (267) on the
//! external-content `memories_fts` index.
//!
//! Invariant: after any write the store's own funnels accept, the FTS5 index
//! agrees with the `memories` content table (`'integrity-check'` succeeds).
//!
//! Every case runs on ONE connection opened by `ai_memory::db::open`, so a
//! failure here cannot come from a second connection or a shared file.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::models::field_names;

/// `SQLITE_CORRUPT_VTAB` (`SQLITE_CORRUPT | (1 << 8)`).
const SQLITE_CORRUPT_VTAB_8341: i32 = 267;
const INTEGRITY_CHECK_8341: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
const VICTIM_8341: &str = "ai:fts-desync-victim-8341";

fn open_db_8341(recursive_triggers: bool) -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    if recursive_triggers {
        conn.execute_batch("PRAGMA recursive_triggers=ON")
            .expect("recursive_triggers");
    }
    (f, conn)
}

/// The extended SQLite code anywhere in an error chain, or `None`.
fn sqlite_code_8341(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
            _ => None,
        })
}

fn fts_check_8341(conn: &rusqlite::Connection) -> Result<(), i32> {
    match conn.execute_batch(INTEGRITY_CHECK_8341) {
        Ok(()) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _)) => Err(e.extended_code),
        Err(other) => panic!("integrity-check failed with a non-SQLite error: {other}"),
    }
}

/// A `_agents` roster row whose content and metadata carry a key the history
/// ledger does not hold, so the v97 authoritative projection trigger rewrites
/// `content` inside the write.
fn roster_row_8341(id: &str, key: &str, stamp: &str) -> ai_memory::models::Memory {
    let metadata = serde_json::json!({
        "agent_id": VICTIM_8341,
        (field_names::AGENT_PUBKEY): key,
        (field_names::PUBKEY_BOUND_AT): stamp,
        (field_names::ATTEST_LEVEL): "claimed",
    });
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: ai_memory::models::agent_registration_title(VICTIM_8341),
        content: serde_json::to_string(&metadata).expect("mirror"),
        created_at: stamp.to_string(),
        updated_at: stamp.to_string(),
        metadata,
        ..ai_memory::models::Memory::default()
    }
}

fn plain_row_8341(id: &str, stamp: &str) -> ai_memory::models::Memory {
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "fts-8341".to_string(),
        title: format!("plain {id}"),
        content: "plain content without any projected field".to_string(),
        created_at: stamp.to_string(),
        updated_at: stamp.to_string(),
        ..ai_memory::models::Memory::default()
    }
}

/// Each step of a case: a store write, then the FTS invariant. Returns the
/// first violation as (step, code).
fn run_case_8341(case: &str, recursive: bool) -> Result<(), (String, i32)> {
    let (_f, conn) = open_db_8341(recursive);
    let attacker = ai_memory::identity::keypair::generate("ai:fts-desync-attacker-8341")
        .expect("keypair")
        .public_base64();
    let stamp = ai_memory::identity::attest::now_attestable_rfc3339();
    let mut steps: Vec<(
        &str,
        Box<dyn Fn(&rusqlite::Connection) -> anyhow::Result<()>>,
    )> = Vec::new();
    match case {
        "plain_insert_update" => {
            let row = plain_row_8341("plain-8341", &stamp);
            steps.push((
                "insert",
                Box::new(move |c| ai_memory::db::insert(c, &row).map(drop)),
            ));
            steps.push((
                "update",
                Box::new(|c| {
                    ai_memory::db::update(
                        c,
                        "plain-8341",
                        None,
                        Some("rewritten plain content"),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .map(drop)
                }),
            ));
        }
        "roster_insert_projected" => {
            let row = roster_row_8341("roster-8341", &attacker, &stamp);
            steps.push((
                "insert",
                Box::new(move |c| ai_memory::db::insert(c, &row).map(drop)),
            ));
        }
        "roster_insert_if_newer_after_bind" => {
            let row = roster_row_8341("roster-8341", &attacker, &stamp);
            steps.push((
                "insert",
                Box::new(move |c| ai_memory::db::insert(c, &row).map(drop)),
            ));
            steps.push((
                "bind",
                Box::new(|c| {
                    let kp = ai_memory::identity::keypair::generate(VICTIM_8341)?;
                    ai_memory::db::bind_agent_pubkey_with_keypair(c, VICTIM_8341, &kp).map(drop)
                }),
            ));
            let attacker2 = attacker.clone();
            steps.push((
                "insert_if_newer",
                Box::new(move |c| {
                    let mut fed = ai_memory::db::get(c, "roster-8341")?
                        .ok_or_else(|| anyhow::anyhow!("row vanished"))?;
                    fed.updated_at = "2099-01-01T00:00:00Z".to_string();
                    fed.metadata
                        .as_object_mut()
                        .ok_or_else(|| anyhow::anyhow!("metadata"))?
                        .insert(
                            field_names::AGENT_PUBKEY.to_string(),
                            serde_json::Value::String(attacker2.clone()),
                        );
                    fed.content = serde_json::to_string(&fed.metadata)?;
                    ai_memory::db::insert_if_newer(c, &fed).map(drop)
                }),
            ));
        }
        other => panic!("unknown case {other}"),
    }
    for (name, step) in &steps {
        if let Err(e) = step(&conn) {
            let code = sqlite_code_8341(&e)
                .unwrap_or_else(|| panic!("{case}/{name}: non-SQLite error {e:#}"));
            return Err(((*name).to_string(), code));
        }
        fts_check_8341(&conn).map_err(|code| (format!("{name}+integrity-check"), code))?;
    }
    Ok(())
}

const CASES_8341: [&str; 3] = [
    "plain_insert_update",
    "roster_insert_projected",
    "roster_insert_if_newer_after_bind",
];

/// Control: the checker itself passes on a write the projection does not touch.
#[test]
fn fts_index_tracks_plain_writes_8341() {
    for recursive in [false, true] {
        assert_eq!(
            run_case_8341(CASES_8341[0], recursive),
            Ok(()),
            "recursive={recursive}"
        );
    }
}

/// The invariant over every roster-write funnel, with the production default
/// (`recursive_triggers` OFF) and with it ON.
#[test]
fn fts_index_tracks_projected_roster_writes_8341() {
    let mut violations = Vec::new();
    for case in &CASES_8341[1..] {
        for recursive in [false, true] {
            if let Err((step, code)) = run_case_8341(case, recursive) {
                assert_eq!(
                    code, SQLITE_CORRUPT_VTAB_8341,
                    "{case} recursive={recursive} {step}"
                );
                violations.push(format!(
                    "{case} recursive={recursive} at {step}: code {code}"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "memories_fts out of step with memories (SQLITE_CORRUPT_VTAB {SQLITE_CORRUPT_VTAB_8341}):\n{}",
        violations.join("\n")
    );
}
