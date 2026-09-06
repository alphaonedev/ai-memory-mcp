// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 V08-PE-3 (#1937) — the test-pinned GATE for the MINIMAL signed
//! spawn-audit chokepoint (ratified spec: the `4d3ea1c5` minimal shape,
//! #1840 closing 2×5 vote).
//!
//! # The anti-regression core (acceptance item 2)
//!
//! [`chokepoint_no_raw_command_new_in_production`] is a static gate: it walks
//! every production line of `src/**/*.rs` (test modules + comments stripped)
//! and asserts NO raw `Command::new(` escapes the ONE allowlisted chokepoint
//! module `src/spawn_audit.rs`. A NEW un-audited production spawn site — a
//! `std::process::Command::new` / `tokio::process::Command::new` added
//! anywhere else — makes this test FAIL, so CI blocks it. This is designed to
//! be non-tautological (M-TAUTOLOGICAL-TESTS): it does not hardcode the known
//! site list, it asserts the structural invariant "all production spawns route
//! through the audited helper", which a new spawn would violate by
//! construction.
//!
//! [`every_known_production_site_routes_through_the_chokepoint`] complements
//! the perma-ban with a POSITIVE enumeration: each of the six wired
//! production spawn sites references the audited helper + its caller const, so
//! a refactor that silently drops the audit from a site is also caught.
//!
//! # Real emission, verified as a first-class event (acceptance items 1 + 3)
//!
//! [`emit_is_a_first_class_verifiable_event`] appends a `process.spawn_audited`
//! row and asserts `verify_audit_trail` walks + verifies it exactly like every
//! other signed event. [`chokepoint_emits_via_seeded_db_path`] exercises the
//! full `audited_command` path (best-effort emission via the seeded DB).
//!
//! # sqlite + postgres parity (acceptance item 4)
//!
//! The `postgres_parity` module (feature `sal-postgres`, `#[ignore]` unless
//! `AI_MEMORY_TEST_POSTGRES_URL` is set) appends the identical spawn-audit row
//! shape through `PostgresStore::emit_spawn_audit` and asserts the postgres
//! `verify_audit_trail` twin walks + verifies it.

use ai_memory::signed_events::{event_types::PROCESS_SPAWN_AUDITED, verify_audit_trail};
use ai_memory::spawn_audit::{
    self, CALLER_CLI_DOCTOR_GPU, CALLER_CLI_NAMESPACE_GIT, CALLER_CLI_WAKE_LISTEN_HOOK,
    CALLER_CLI_WRAP_AGENT, CALLER_HOOK_DAEMON, CALLER_HOOK_EXEC,
};
use std::path::{Path, PathBuf};

/// The single allowlisted production module that may construct a raw
/// `Command::new` — it IS the audited chokepoint.
const CHOKEPOINT_REL_PATH: &str = "src/spawn_audit.rs";

/// The spawn-constructor token the gate perma-bans outside the chokepoint.
/// Matches both `std::process::Command::new` and `tokio::process::Command::new`
/// (both spell the constructor `Command::new`).
const SPAWN_CTOR_TOKEN: &str = "Command::new";

fn repo_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Recursively collect every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Is this a comment / doc-comment / block-comment continuation line? Mirrors
/// the production-vs-comment heuristic the `scripts/check-*.sh` gates use.
fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

/// Scan a file's PRODUCTION lines (everything before the first `mod tests`,
/// comments stripped) and return the 1-based line numbers that contain a raw
/// spawn constructor.
fn production_spawn_ctor_lines(path: &Path) -> Vec<usize> {
    let src =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut hits = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        // Stop at the unit-test module boundary — test spawns are exempt
        // (they exercise real subprocesses and are not production paths).
        if trimmed.starts_with("mod tests") || trimmed.starts_with("pub mod tests") {
            break;
        }
        if is_comment_line(trimmed) {
            continue;
        }
        if line.contains(SPAWN_CTOR_TOKEN) {
            hits.push(idx + 1);
        }
    }
    hits
}

#[test]
fn chokepoint_no_raw_command_new_in_production() {
    let src_dir = repo_src_dir();
    let chokepoint = Path::new(env!("CARGO_MANIFEST_DIR")).join(CHOKEPOINT_REL_PATH);
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find .rs files under {}",
        src_dir.display()
    );

    let mut violations: Vec<String> = Vec::new();
    for path in &files {
        if path == &chokepoint {
            continue; // the audited chokepoint IS allowed to build a Command.
        }
        for line_no in production_spawn_ctor_lines(path) {
            let rel = path.strip_prefix(&src_dir).unwrap_or(path);
            violations.push(format!("src/{}:{line_no}", rel.display()));
        }
    }

    assert!(
        violations.is_empty(),
        "#1937 spawn-audit gate: raw `{SPAWN_CTOR_TOKEN}` found in production code OUTSIDE the \
         audited chokepoint `{CHOKEPOINT_REL_PATH}`. Every production subprocess launch MUST go \
         through `spawn_audit::audited_command` / `audited_tokio_command` so it emits a signed \
         `process.spawn_audited` row. Offending site(s):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn every_known_production_site_routes_through_the_chokepoint() {
    // Positive enumeration: each wired production spawn site references the
    // audited helper AND its caller const. Catches a refactor that silently
    // drops the audit from a site (the perma-ban above only catches ADDING a
    // raw spawn, not REMOVING an audited one).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases: &[(&str, &str, &str)] = &[
        (
            "src/cli/helpers.rs",
            "audited_command",
            "CALLER_CLI_NAMESPACE_GIT",
        ),
        (
            "src/cli/doctor.rs",
            "audited_command",
            "CALLER_CLI_DOCTOR_GPU",
        ),
        (
            "src/cli/wrap.rs",
            "audited_command",
            "CALLER_CLI_WRAP_AGENT",
        ),
        (
            "src/hooks/executor.rs",
            "audited_tokio_command",
            "CALLER_HOOK_EXEC",
        ),
        (
            "src/hooks/executor.rs",
            "audited_tokio_command",
            "CALLER_HOOK_DAEMON",
        ),
        // #3470 — the `ai-memory wake-listen --exec` wake hook. A long-lived
        // listener launching an operator-supplied shell is exactly the shape
        // this audit exists for.
        (
            "src/cli/wake_listen.rs",
            "audited_tokio_command",
            "CALLER_CLI_WAKE_LISTEN_HOOK",
        ),
    ];
    for (rel, helper, caller_const) in cases {
        let src =
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            src.contains(helper),
            "{rel} must route its production spawn through `spawn_audit::{helper}`"
        );
        assert!(
            src.contains(caller_const),
            "{rel} must attribute its spawn via `spawn_audit::{caller_const}`"
        );
    }
}

fn fresh_db(label: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("spawn-audit-gate-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    drop(ai_memory::db::open(&path).expect("init db"));
    (dir, path)
}

fn spawn_row_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        [PROCESS_SPAWN_AUDITED],
        |r| r.get(0),
    )
    .expect("count spawn rows")
}

#[test]
fn emit_is_a_first_class_verifiable_event() {
    let (_dir, path) = fresh_db("emit");
    {
        let conn = ai_memory::db::open(&path).expect("open");
        spawn_audit::emit_spawn_audit(&conn, "git", CALLER_CLI_NAMESPACE_GIT).expect("emit");
    }
    let conn = ai_memory::db::open(&path).expect("reopen");
    assert_eq!(spawn_row_count(&conn), 1, "exactly one spawn-audit row");
    // Item 3: verify_audit_trail walks + verifies the spawn row like any other.
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(
        report.chain_intact,
        "chain intact with the spawn row: {report:?}"
    );
    assert!(report.is_clean(), "clean audit trail: {report:?}");
    assert_eq!(report.total_events, 1, "the spawn row is counted");
}

#[test]
fn chokepoint_emits_via_seeded_db_path() {
    // Exercise the FULL production chokepoint path: seed the process-wide audit
    // DB, then mint a Command via `audited_command` and confirm the best-effort
    // emission landed a signed spawn row that verifies. This test is the ONLY
    // seeder in this binary (the OnceLock is first-writer-wins), so the path is
    // deterministic.
    let (_dir, path) = fresh_db("seeded");
    spawn_audit::seed_spawn_audit_db_path(&path);
    let _cmd = spawn_audit::audited_command("true", CALLER_CLI_WRAP_AGENT);
    let conn = ai_memory::db::open(&path).expect("reopen");
    assert!(
        spawn_row_count(&conn) >= 1,
        "audited_command must emit at least one spawn-audit row via the seeded DB"
    );
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert!(report.chain_intact, "chain intact: {report:?}");
}

#[test]
fn caller_slugs_are_stable_wire_values() {
    // The caller slugs are persisted (via the payload_hash pre-image) and read
    // by downstream auditors — pin their exact wire values so a rename is a
    // conscious, reviewed change.
    assert_eq!(CALLER_CLI_NAMESPACE_GIT, "cli::helpers::auto_namespace");
    assert_eq!(CALLER_CLI_DOCTOR_GPU, "cli::doctor::nvidia_gpu_detected");
    assert_eq!(
        CALLER_CLI_WRAP_AGENT,
        "cli::wrap::build_command_for_strategy"
    );
    assert_eq!(CALLER_HOOK_EXEC, "hooks::executor::exec_fire");
    assert_eq!(CALLER_HOOK_DAEMON, "hooks::executor::daemon_connect");
    assert_eq!(
        CALLER_CLI_WAKE_LISTEN_HOOK,
        "cli::wake_listen::run_exec_hook"
    );
    assert_eq!(PROCESS_SPAWN_AUDITED, "process.spawn_audited");
}

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn pg_spawn_audit_row_persists_and_verifies() {
        let Some(pg) = live_pg().await else {
            return;
        };
        // Append the identical spawn-audit row shape through the postgres twin.
        pg.emit_spawn_audit("git", CALLER_CLI_NAMESPACE_GIT).await;

        // The row persisted with the parity payload_hash (same pre-image bytes
        // as the sqlite emitter).
        let want_hash = spawn_audit::spawn_audit_payload_hash("git", CALLER_CLI_NAMESPACE_GIT);
        let row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, payload_hash FROM signed_events \
             WHERE event_type = $1 AND payload_hash = $2 \
             ORDER BY sequence DESC LIMIT 1",
        )
        .bind(PROCESS_SPAWN_AUDITED)
        .bind(&want_hash)
        .fetch_optional(pg.pool())
        .await
        .expect("query pg spawn row");
        let (id, got_hash) = row.expect("a process.spawn_audited row must persist on postgres");
        assert_eq!(got_hash, want_hash, "payload_hash parity with sqlite");

        // The postgres verify_audit_trail twin walks + verifies it (K3 parity):
        // a single freshly-appended spawn row keeps the chain intact.
        let report = pg.verify_audit_trail(None, None).await.expect("pg verify");
        assert!(
            report.chain_intact,
            "pg verify twin must keep the chain intact with the spawn row: {report:?}"
        );

        // Cleanup (append-only table; direct-SQL delete is the sanctioned
        // test escape hatch, same as tests/audit_witness_truncation_1822.rs).
        sqlx::query("DELETE FROM signed_events WHERE id = $1")
            .bind(&id)
            .execute(pg.pool())
            .await
            .ok();
    }
}
