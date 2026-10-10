// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6122 — integration tests must not leak sqlite `-wal` / `-shm` side files.
//!
//! The pattern under test is the one ~200 suites share: a scratch database on
//! a `NamedTempFile`, WAL-mode connections held by a long-lived owner (router,
//! store), and the file dropped before the owner. Each run is isolated in a
//! private directory so the count is exact.

#[path = "common/sqlite_tempfile.rs"]
mod sqlite_tempfile;

use sqlite_tempfile::{SqliteTempFile, side_files};

/// Orphaned side files left in `dir` after the scope of the scratch file.
fn leftovers(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn scratch_dir(tag: &str) -> tempfile::TempDir {
    // Directly under the gitignored `.local-runs/`; each `TempDir` removes
    // itself on drop, so nothing from this guard outlives a passing run (and
    // there is no shared parent for parallel tests to race on).
    let root = std::path::Path::new(".local-runs");
    std::fs::create_dir_all(root).expect("scratch root");
    tempfile::Builder::new()
        .prefix(&format!("tmp-leak-guard-6122-{tag}-"))
        .tempdir_in(root)
        .expect("scratch dir")
}

#[test]
fn file_dropped_before_connection_leaves_no_side_files_6122() {
    let dir = scratch_dir("order");
    {
        let f = SqliteTempFile::new_in(dir.path()).expect("tempfile");
        let conn = ai_memory::db::open(f.path()).expect("db::open");
        // Mirrors the suites: the connection outlives the file handle.
        drop(f);
        drop(conn);
    }
    let left = leftovers(dir.path());
    assert!(
        left.is_empty(),
        "#6122: {} orphaned side file(s) left behind: {left:?}",
        left.len()
    );
}

#[test]
fn many_scopes_leave_no_side_files_6122() {
    let dir = scratch_dir("many");
    for _ in 0..20 {
        let f = SqliteTempFile::new_in(dir.path()).expect("tempfile");
        let _conn = ai_memory::db::open(f.path()).expect("db::open");
        let _reader = ai_memory::db::open(f.path()).expect("reopen");
        // `f` declared first, so it drops LAST here; the leak needs the
        // reverse order, which the explicit drop below forces.
        drop(f);
    }
    let left = leftovers(dir.path());
    assert!(
        left.is_empty(),
        "#6122: {} orphaned side file(s) after 20 scopes: {left:?}",
        left.len()
    );
}

#[test]
fn side_files_names_cover_wal_shm_journal_6122() {
    let names: Vec<String> = side_files(std::path::Path::new("/x/.tmpAb"))
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert_eq!(
        names,
        ["/x/.tmpAb-wal", "/x/.tmpAb-shm", "/x/.tmpAb-journal"]
    );
}

/// Every `tests/**/*.rs` source (recursive: the `curator` and `forensic`
/// binaries compile `tests/curator/*.rs` / `tests/forensic/*.rs` through
/// `#[path]`), minus the helper that owns the raw handle and this guard.
fn suite_sources() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read tests dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    walk(std::path::Path::new("tests"), &mut paths);
    let mut sources = Vec::new();
    for path in paths {
        let name = path.to_string_lossy().replace('\\', "/");
        if name == "tests/tmp_leak_guard_6122.rs" || name == "tests/common/sqlite_tempfile.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read suite");
        sources.push((name, src));
    }
    sources.sort();
    sources
}

/// Ceiling: ZERO integration suites (any depth under `tests/`) may bind a
/// sqlite database, opened through `db::open`, `SqliteStore::open`,
/// `storage::open`, `storage::open_read_only`, `open_db` or
/// `Connection::open`, to a raw `tempfile::NamedTempFile` (the ceiling only
/// falls). Use `common/sqlite_tempfile.rs::SqliteTempFile`, which owns the
/// `-wal` / `-shm`.
#[test]
fn no_suite_binds_sqlite_to_raw_named_tempfile_6122() {
    let opens_sqlite = |s: &str| {
        [
            "db::open",
            "SqliteStore::open",
            "open_db",
            "Connection::open",
            "storage::open",
            "open_read_only",
        ]
        .iter()
        .any(|needle| s.contains(needle))
    };
    let offenders: Vec<String> = suite_sources()
        .into_iter()
        .filter(|(_, src)| src.contains("NamedTempFile") && opens_sqlite(src))
        .map(|(name, _)| name)
        .collect();
    assert!(
        offenders.is_empty(),
        "#6122: {} suite(s) bind sqlite to a raw NamedTempFile (orphans -wal/-shm): {offenders:?}",
        offenders.len()
    );
}

/// `std::mem::forget(<temp handle>)` leaks the scratch file (and its sidecars)
/// on every run by design. Sites that already existed when the guard landed are
/// listed here with their count; the list only shrinks. A new site, or one in a
/// file that is not listed, fails. Migration of the listed
/// files is tracked in #6458.
const KNOWN_MEM_FORGET_SITES: &[(&str, usize)] = &[
    ("tests/authority_boundary_3549.rs", 1),
    ("tests/conformance_export_roundtrip_2030.rs", 1),
    ("tests/cov_fupb_approvals.rs", 1),
    ("tests/cov_fupb_fed_signing.rs", 1),
    ("tests/cov_fupb_system_parity.rs", 1),
    ("tests/cov_ga2_handlers_b.rs", 1),
    ("tests/f53_claimed_vs_attested_e2e.rs", 1),
    ("tests/fed_archive_restore_lane_3075.rs", 2),
    ("tests/fed_checkpoint_lane_3075_pg.rs", 1),
    ("tests/fed_consolidate_source_attest_parity_2863.rs", 1),
    ("tests/fed_inbound_stamp_3624.rs", 1),
    ("tests/fed_outbound_checkpoint_route_2391.rs", 1),
    ("tests/fed_owner_floor_4285.rs", 1),
    ("tests/fed_pending_identity_quorum_2710_2720.rs", 1),
    ("tests/fed_rq_03_policy_refuse_stale.rs", 1),
    ("tests/federation_1936_checkpoint_fed.rs", 3),
    ("tests/federation_causal_order_3699.rs", 1),
    ("tests/federation_checkpoint_ns_scope_2708.rs", 2),
    ("tests/federation_delete_ns_scope_2488.rs", 1),
    ("tests/federation_dequarantine_crossid_3901.rs", 1),
    ("tests/federation_legacy_row_visibility_978.rs", 1),
    ("tests/federation_merge_scope_recheck_4023.rs", 2),
    ("tests/federation_namespace_meta_descendant_2536.rs", 1),
    ("tests/federation_ns_meta_scope_2479.rs", 1),
    ("tests/federation_peer_enrolled_2912.rs", 1),
    ("tests/federation_pending_ns_scope_2478.rs", 1),
    ("tests/federation_pending_reject_ns_2532.rs", 1),
    ("tests/federation_pending_resurrection_2529.rs", 1),
    ("tests/federation_receive_coord_screen_3049.rs", 1),
    ("tests/federation_signal_authorship_1843.rs", 1),
    ("tests/federation_stable_peer_id_2442.rs", 1),
    ("tests/federation_sync_push_tofu_1056.rs", 1),
    ("tests/federation_sync_since_watermark_2441.rs", 1),
    ("tests/federation_sync_state_merge_1709.rs", 1),
    ("tests/federation_write_ns_scope_2447.rs", 1),
    ("tests/g_issue_238_sender_attestation.rs", 1),
    ("tests/g_issue_239_sync_scope.rs", 1),
    ("tests/g_phase_e_1_links_validation.rs", 1),
    ("tests/governance_policy_read_fault_4043.rs", 1),
    ("tests/import_conflict_2878.rs", 1),
    ("tests/import_roundtrip_2569_2570.rs", 1),
    ("tests/inbox_wake_3465.rs", 1),
    ("tests/integration.rs", 1),
    ("tests/k10_approval_http.rs", 1),
    ("tests/k10_approval_postgres_dispatch_1618.rs", 2),
    ("tests/k10_approval_security.rs", 1),
    ("tests/k10_approval_sse.rs", 1),
    ("tests/memories_au_trigger_column_scoped_v53.rs", 1),
    ("tests/mtls_cert_peer_binding_2045.rs", 1),
    ("tests/node_local_containment_item3_r2_3266.rs", 1),
    ("tests/non_version_bumping_sites_1036.rs", 1),
    ("tests/portability_export_completeness_2571.rs", 1),
    ("tests/portability_import_archived_lane_gates_3150.rs", 1),
    ("tests/portability_import_redact_attest_2353.rs", 1),
    ("tests/portability_roundtrip_2006.rs", 1),
    ("tests/postgres_subscription_dispatch.rs", 1),
    ("tests/r40_approval_chokepoint.rs", 2),
    ("tests/recover_watermark_uses_agent_id_idx.rs", 1),
    ("tests/reflect_pg_caller_identity_2857.rs", 1),
    ("tests/security_admin_role_invalid_agent_id_984.rs", 1),
    ("tests/security_authz_isolation_cluster.rs", 1),
    ("tests/skill_composition_test.rs", 1),
    ("tests/skills_fail_closed_on_postgres_3183.rs", 1),
    ("tests/skills_jail_caller_text_3762.rs", 1),
    ("tests/sync_since_visibility_gate_948.rs", 1),
    ("tests/v070_a1_authn.rs", 3),
    ("tests/wake_client_3470.rs", 1),
    ("tests/wake_sink_3469.rs", 2),
];

/// Violations of the `mem::forget(` ceiling for `sources` against `table`.
fn forget_violations(table: &[(&str, usize)], sources: &[(String, String)]) -> Vec<String> {
    let mut over = Vec::new();
    for (name, src) in sources {
        let found = src.matches("mem::forget(").count();
        let allowed = table.iter().find(|(n, _)| n == name).map_or(0, |(_, c)| *c);
        if found > allowed {
            over.push(format!("{name}: {found} site(s), ceiling {allowed}"));
        }
    }
    over
}

#[test]
fn no_new_mem_forget_of_temp_handle_6122() {
    let over = forget_violations(KNOWN_MEM_FORGET_SITES, &suite_sources());
    assert!(
        over.is_empty(),
        "#6122: std::mem::forget of a temp handle leaks the scratch file every run; \
         keep the handle bound for the test lifetime instead: {over:?}"
    );
}

fn fixture(name: &str, forgets: usize) -> (String, String) {
    let body = "std::mem::forget(handle);\n".repeat(forgets);
    (name.to_owned(), format!("fn t() {{\n{body}}}\n"))
}

/// #6787: a listed file whose count FELL below its pin is a stale entry; the
/// pin must be lowered in the same commit, or a later forget re-spends it.
#[test]
fn forget_pin_rejects_stale_lowered_count_6787() {
    let sources = [fixture("tests/a.rs", 1)];
    let over = forget_violations(&[("tests/a.rs", 2)], &sources);
    assert!(
        over.iter().any(|v| v.contains("tests/a.rs")),
        "#6787: a pin of 2 over 1 real site must fail (lower the entry): {over:?}"
    );
}

/// #6787: a listed file that no longer exists or has zero sites is stale.
#[test]
fn forget_pin_rejects_missing_or_zero_listed_file_6787() {
    let sources = [fixture("tests/zero.rs", 0)];
    let over = forget_violations(&[("tests/gone.rs", 1), ("tests/zero.rs", 1)], &sources);
    assert!(
        over.iter().any(|v| v.contains("tests/gone.rs")),
        "#6787: a listed file that no longer exists must fail: {over:?}"
    );
    assert!(
        over.iter().any(|v| v.contains("tests/zero.rs")),
        "#6787: a listed file at 0 sites must fail: {over:?}"
    );
}

/// #6804 (mutant M4): raising one real pin by one, with the source unchanged,
/// must be caught.
#[test]
fn forget_pin_rejects_raised_real_entry_6804() {
    let raised: Vec<(&str, usize)> = KNOWN_MEM_FORGET_SITES
        .iter()
        .map(|&(n, c)| {
            if n == "tests/wake_client_3470.rs" {
                (n, c + 1)
            } else {
                (n, c)
            }
        })
        .collect();
    let over = forget_violations(&raised, &suite_sources());
    assert!(
        over.iter().any(|v| v.contains("tests/wake_client_3470.rs")),
        "#6804: raising a pin without a new site must fail: {over:?}"
    );
}
