// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4978 — `count_active_governance_rules` reports a read FAULT as an error,
//! never as `0` active rules, and `memory_capabilities` fails instead of
//! advertising `permissions.active_rules = 0` over a store it could not read.
//!
//! The helper runs the same `json_extract` join #4956 fixed in
//! `doctor_governance_coverage` but ended in `.unwrap_or(0)`: a bound standard
//! whose metadata is not valid JSON, or a missing `namespace_meta` table,
//! produced `Ok(0)` and a capabilities envelope with `active_rules = 0`
//! (swallowed Result, rust-1.98 ERRORS-19 / ERRORS-02; never fail open).

use ai_memory::config::{FeatureTier, ResolvedModels};
use ai_memory::mcp::{CapabilitiesAccept, handle_capabilities_with_conn};
use tempfile::TempDir;

fn fresh_conn() -> (TempDir, rusqlite::Connection) {
    let tmp = TempDir::new().expect("tempdir");
    let conn = ai_memory::db::open(&tmp.path().join("ai-memory.db")).expect("open");
    (tmp, conn)
}

/// Plants a namespace standard whose memory carries `metadata` verbatim (a
/// bound standard the count must read through `json_extract`).
fn plant_standard_with_metadata(conn: &rusqlite::Connection, metadata: &str) {
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at, metadata) \
         VALUES ('std4978', 'long', 'ns4978', 'standard', 'standard', \
                 '2026-10-03T00:00:00Z', '2026-10-03T00:00:00Z', ?1)",
        rusqlite::params![metadata],
    )
    .expect("plant standard memory");
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at) \
         VALUES ('ns4978', 'std4978', '2026-10-03T00:00:00Z')",
        [],
    )
    .expect("bind the standard");
}

fn capabilities(conn: &rusqlite::Connection) -> Result<serde_json::Value, String> {
    let tier = FeatureTier::Keyword.config();
    handle_capabilities_with_conn(
        &tier,
        &ResolvedModels::from_tier_preset(&tier),
        None,
        false,
        Some(conn),
        CapabilitiesAccept::V2,
    )
}

#[test]
fn count_active_rules_errors_on_invalid_standard_metadata_4978() {
    let (_t, conn) = fresh_conn();
    plant_standard_with_metadata(&conn, "{not json");
    assert!(
        ai_memory::db::count_active_governance_rules(&conn).is_err(),
        "a malformed bound standard must be a read fault, not 0 active rules"
    );
}

#[test]
fn count_active_rules_errors_when_namespace_meta_is_missing_4978() {
    let (_t, conn) = fresh_conn();
    conn.execute_batch("ALTER TABLE namespace_meta RENAME TO namespace_meta_gone")
        .expect("rename away");
    assert!(
        ai_memory::db::count_active_governance_rules(&conn).is_err(),
        "a missing namespace_meta must be a read fault, not 0 active rules"
    );
}

/// The healthy path is unchanged: a valid governed standard counts as one.
#[test]
fn count_active_rules_counts_a_valid_governed_standard_4978() {
    let (_t, conn) = fresh_conn();
    plant_standard_with_metadata(&conn, r#"{"governance": {"write": "any"}}"#);
    assert_eq!(
        ai_memory::db::count_active_governance_rules(&conn).expect("count"),
        1
    );
    let caps = capabilities(&conn).expect("capabilities over a readable store");
    assert_eq!(caps["permissions"]["active_rules"], 1, "{caps}");
}

/// `memory_capabilities` must not advertise `active_rules = 0` over a store
/// whose rule count could not be read: the call fails through the existing
/// error channel (no wire-shape change).
#[test]
fn capabilities_fail_when_the_rule_count_cannot_be_read_4978() {
    let (_t, conn) = fresh_conn();
    plant_standard_with_metadata(&conn, "{not json");
    let err = capabilities(&conn).expect_err("a count read fault must fail the capabilities call");
    assert!(
        err.contains("governance") || err.contains("rules"),
        "the error names what could not be read: {err}"
    );
}
