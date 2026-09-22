// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3777 — the ONE lane-database predicate every guarded postgres cell uses.
//!
//! Three cells pinned their own lane's database NAME (`ai_memory_codex_3555`,
//! `ai_memory_codex_3646`) while CI mints `ai_memory_test_ci_<run>_<attempt>_
//! <leg>` and every other lane mints its own, so the enterprise-fed required
//! checks were red on an environment mismatch, never on the behaviour under
//! test — the same defect #3508 fixed for the #3468 lane. Two more files
//! carried private copies of the port-aware shared-store guard. This file is
//! the single predicate (rule (s)); no test carries a lane literal.
//!
//! What is refused and why:
//!
//! - `ai_memory` — the operator's live database, on any port;
//! - `ai_memory_test` on the certified tier's port (`5445`) — the `:9077`
//!   test-fleet daemon's SHARED live store. The same name on any other port
//!   is the coverage workflow's throwaway service container
//!   (`.github/workflows/coverage.yml`: `POSTGRES_DB=ai_memory_test` on
//!   `:5432`) and is accepted — a name-only refusal could never run there
//!   (the `3017ea05` lesson recorded in the wake-hub harness);
//! - anything not prefixed `ai_memory_` (`postgres`, `template1`, an empty
//!   path) — never a dedicated lane.
//!
//! Every dedicated lane, gate or CI database (`ai_memory_codex_<n>`,
//! `ai_memory_gate_<n>`, `ai_memory_test_ci_<run>_<attempt>_<leg>`,
//! `ai_memory_f2a_<tag>`) is accepted.
//!
//! Include from a test binary with
//! `#[path = "common/lane_db.rs"] mod lane_db;` (or `mod common;` and
//! `common::lane_db`), then `lane_db::assert_lane_database(&url)`.

#![allow(dead_code)]

/// The database segment of a `postgres://user:pass@host:port/db?params` URL
/// (empty when absent). The query is cut off FIRST: since #3705 every lane
/// URL carries `sslrootcert=/…/ca.crt`, and taking the last `/`-segment of
/// the whole URL yields `ca.crt` — the wake-hub harness copy did exactly
/// that, so its shared-store guard never fired on a verify-full URL.
pub fn database_name(url: &str) -> &str {
    url.split('?')
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// The port segment of a `postgres://user:pass@host:port/db` URL, if any.
pub fn port_of(url: &str) -> Option<u16> {
    let authority = url.split("//").nth(1)?.split('/').next()?;
    let host_port = authority.rsplit('@').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// The certified tier's port on both nodes; the `:9077` test-fleet daemon's
/// shared `ai_memory_test` database lives there and nowhere else.
pub const SHARED_LIVE_STORE_PORT: u16 = 5445;

/// The operator's live database name, refused on every port.
pub const OPERATOR_DATABASE: &str = "ai_memory";

/// The shared live store's database name (refused on the certified port only).
pub const SHARED_LIVE_STORE_DATABASE: &str = "ai_memory_test";

/// Every dedicated lane, gate or CI database starts with this.
pub const LANE_DATABASE_PREFIX: &str = "ai_memory_";

/// True only for the shared live store: `ai_memory_test` on the certified
/// tier's port.
pub fn is_shared_live_store(url: &str) -> bool {
    database_name(url) == SHARED_LIVE_STORE_DATABASE && port_of(url) == Some(SHARED_LIVE_STORE_PORT)
}

/// Why `url` is NOT a dedicated lane database, or `None` when it is one.
/// The reason names the database and the rule, never the credentials.
pub fn lane_database_refusal(url: &str) -> Option<String> {
    let name = database_name(url);
    if name.is_empty() {
        return Some("AI_MEMORY_TEST_POSTGRES_URL must name a database".to_string());
    }
    if name == OPERATOR_DATABASE {
        return Some(format!(
            "`{name}` is the operator's live database; point AI_MEMORY_TEST_POSTGRES_URL at \
             this lane's own isolated database"
        ));
    }
    if is_shared_live_store(url) {
        return Some(format!(
            "`{name}` on :{SHARED_LIVE_STORE_PORT} is the shared live store; point \
             AI_MEMORY_TEST_POSTGRES_URL at this lane's own isolated database"
        ));
    }
    if !name.starts_with(LANE_DATABASE_PREFIX) {
        return Some(format!(
            "`{name}` is not a dedicated lane database (expected the `{LANE_DATABASE_PREFIX}` \
             prefix: a lane, gate or CI database)"
        ));
    }
    None
}

/// Refuse to run a postgres cell against anything but a dedicated lane
/// database. The one guard every guarded pg cell calls.
///
/// # Panics
/// With the refusal reason when `url` is the operator database, the shared
/// live store, or not a lane-prefixed database.
pub fn assert_lane_database(url: &str) {
    if let Some(why) = lane_database_refusal(url) {
        panic!("#3777: refusing to run against a non-lane database: {why}");
    }
}

/// The predicate's cells (rule (s)): red on the operator database, the shared
/// live store and a non-lane name; green on a CI-shaped and a lane-shaped
/// name, and on the coverage workflow's same-named throwaway container.
#[test]
fn lane_database_predicate_cases_3777() {
    // Refused.
    assert!(
        lane_database_refusal("postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test").is_some()
    );
    assert!(
        lane_database_refusal(
            "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test?sslmode=verify-full"
        )
        .is_some()
    );
    assert!(lane_database_refusal("postgres://u:p@h:5445/ai_memory").is_some());
    assert!(lane_database_refusal("postgres://u:p@h:5432/ai_memory").is_some());
    assert!(lane_database_refusal("postgres://u:p@h:5445/postgres").is_some());
    assert!(lane_database_refusal("postgres://u:p@h:5445/template1").is_some());
    assert!(lane_database_refusal("postgres://u:p@h:5445/").is_some());
    assert!(lane_database_refusal("postgres://u:p@h:5445/codex_3555").is_some());
    let caught = std::panic::catch_unwind(|| {
        assert_lane_database("postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test");
    });
    let msg = caught
        .expect_err("the shared live store panics")
        .downcast::<String>()
        .map(|s| *s)
        .unwrap_or_default();
    assert!(
        msg.contains("#3777") && msg.contains("shared live store"),
        "{msg}"
    );
    assert!(!msg.contains(":pw@"), "never the credentials: {msg}");
    // The #3705 URL shape: `sslrootcert=/…/ca.crt` in the query must not be
    // mistaken for the database (the harness copy did exactly that).
    let verify_full = "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt";
    assert_eq!(database_name(verify_full), "ai_memory_test");
    assert!(is_shared_live_store(verify_full));
    assert!(lane_database_refusal(verify_full).is_some());
    assert_eq!(
        lane_database_refusal(
            "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_leg?sslmode=verify-full&sslrootcert=/home/x/pg/certs/ca.crt"
        ),
        None
    );
    // Accepted: CI-shaped, lane-shaped, gate-shaped.
    assert_eq!(
        lane_database_refusal(
            "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test_ci_123_1_x?sslmode=verify-full"
        ),
        None
    );
    assert_eq!(
        lane_database_refusal("postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_codex_3555"),
        None
    );
    assert_eq!(
        lane_database_refusal("postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_gate_tip4"),
        None
    );
    assert_eq!(
        lane_database_refusal("postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_f2a_3777"),
        None
    );
    // The coverage workflow's throwaway container: same name, throwaway port.
    assert_eq!(
        lane_database_refusal("postgres://ai_memory:ai_memory_test@localhost:5432/ai_memory_test"),
        None
    );
    assert!(is_shared_live_store(
        "postgres://ai_memory:pw@localhost:5445/ai_memory_test"
    ));
    assert!(!is_shared_live_store(
        "postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test"
    ));
    assert_eq!(database_name("postgres://u:p@h:5445/db?x=1"), "db");
    assert_eq!(port_of("postgres://u:p@h:5445/db?x=1"), Some(5445));
    assert_eq!(port_of("postgres://u:p@h/db"), None);
}
