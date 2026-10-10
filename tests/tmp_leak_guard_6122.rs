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

/// Source-text classifiers used by the ceilings (#6788). Each one is a pure
/// function so a fixture string pins every shape it must recognise.
///
/// Literal sqlite open needles; aliases and bare imports are resolved by
/// `use_statements` below.
const OPEN_NEEDLES: &[&str] = &[
    "db::open",
    "SqliteStore::open",
    "open_db",
    "Connection::open",
    "storage::open",
    "open_read_only",
    "open_with_flags",
];

/// Free functions that open a sqlite database when imported by name.
const OPEN_FNS: &[&str] = &["open", "open_db", "open_read_only", "open_with_flags"];

/// Types / modules whose `::open` opens sqlite; `use X as Y` makes `Y::open`.
const OPEN_OWNERS: &[&str] = &["Connection", "SqliteStore", "storage", "db"];

/// Shapes that leak a temp handle without `mem::forget(`; zero ceiling
/// (checked only in files that hold a temp handle, see `holds_temp_handle`).
/// `persist` is deliberately absent: it moves the file to a caller-chosen
/// path, which is a move, not a leak of the scratch location.
const LEAK_SHAPES: &[&str] = &[
    "ManuallyDrop::new(",
    "Box::leak(",
    ".into_path()",
    ".into_temp_path()",
    ".keep()",
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Tokens (identifiers) of `s`.
fn tokens(s: &str) -> Vec<&str> {
    s.split(|c: char| !is_ident(c))
        .filter(|t| !t.is_empty())
        .collect()
}

/// The text of every `use ...;` statement in `src`.
fn use_statements(src: &str) -> Vec<&str> {
    src.match_indices("use ")
        .filter(|(i, _)| !src[..*i].chars().next_back().is_some_and(is_ident))
        .map(|(i, _)| {
            let rest = &src[i..];
            &rest[..rest.find(';').unwrap_or(rest.len())]
        })
        .collect()
}

/// Names bound by `<name> as <alias>` in `statement` for each `name` in `names`.
fn aliases_of(statement: &str, names: &[&str]) -> Vec<String> {
    let t = tokens(statement);
    t.windows(3)
        .filter(|w| w[1] == "as" && names.contains(&w[0]))
        .map(|w| w[2].to_owned())
        .collect()
}

/// Number of calls `name(` that is a bare call: not a method call
/// (`x.name(`), not a path call (`a::name(`), not a definition (`fn name(`).
fn bare_calls(src: &str, name: &str) -> usize {
    let needle = format!("{name}(");
    src.match_indices(&needle)
        .filter(|(i, _)| {
            let before = &src[..*i];
            let prev = before.chars().next_back();
            let is_def = before.trim_end().ends_with("fn") && prev.is_some_and(char::is_whitespace);
            !prev.is_some_and(|c| is_ident(c) || c == '.' || c == ':') && !is_def
        })
        .count()
}

/// Occurrences of `path::name(` where `path` starts at an identifier boundary.
fn path_calls(src: &str, path_and_name: &str) -> usize {
    let needle = format!("{path_and_name}(");
    src.match_indices(&needle)
        .filter(|(i, _)| !src[..*i].chars().next_back().is_some_and(is_ident))
        .count()
}

fn is_std_mem_statement(statement: &str) -> bool {
    let t = tokens(statement);
    (t.contains(&"std") || t.contains(&"core")) && t.contains(&"mem")
}

/// Call sites of `std::mem::forget`: the qualified `mem::forget(`, a bare
/// `forget(` when it is imported (also by glob), an alias of `forget`, and a
/// call through an alias of `mem`.
fn forget_sites(src: &str) -> usize {
    let mut sites = src.matches("mem::forget(").count();
    let mut bare_imported = false;
    let mut fn_aliases = Vec::new();
    let mut mem_aliases = Vec::new();
    for st in use_statements(src)
        .into_iter()
        .filter(|s| is_std_mem_statement(s))
    {
        let t = tokens(st);
        bare_imported |= t.windows(2).any(|w| w[0] == "forget" && w[1] != "as")
            || t.last() == Some(&"forget")
            || st.contains("mem::*");
        fn_aliases.extend(aliases_of(st, &["forget"]));
        mem_aliases.extend(aliases_of(st, &["mem"]));
    }
    if bare_imported {
        sites += bare_calls(src, "forget");
    }
    for alias in &fn_aliases {
        sites += bare_calls(src, alias);
    }
    for alias in mem_aliases.iter().filter(|a| a.as_str() != "mem") {
        sites += path_calls(src, &format!("{alias}::forget"));
    }
    sites
}

/// A file that holds a `tempfile` handle (directory or file).
fn holds_temp_handle(src: &str) -> bool {
    ["tempfile", "TempDir", "tempdir", "TempPath"]
        .iter()
        .any(|m| src.contains(m))
}

fn leak_shape_hits(src: &str) -> Vec<&'static str> {
    if !holds_temp_handle(src) {
        return Vec::new();
    }
    LEAK_SHAPES
        .iter()
        .copied()
        .filter(|shape| src.contains(shape))
        .collect()
}

/// A raw `tempfile::NamedTempFile`, however it is built: the type name, or the
/// `tempfile::Builder` terminals `.tempfile(` / `.tempfile_in(` / `.make(` /
/// `.make_in(`.
fn holds_raw_named_tempfile(src: &str) -> bool {
    src.contains("NamedTempFile")
        || src.contains(".tempfile(")
        || src.contains(".tempfile_in(")
        || (src.contains("Builder::new") && (src.contains(".make(") || src.contains(".make_in(")))
}

/// Does `src` open a sqlite database? Literal needles, aliases of the owning
/// type / module (`use rusqlite::Connection as Conn;`), aliases of the open
/// function (`use ai_memory::db::open as o;`), bare imports of an open
/// function and globs over the owning modules.
fn opens_sqlite(src: &str) -> bool {
    if OPEN_NEEDLES.iter().any(|needle| src.contains(needle)) {
        return true;
    }
    for st in use_statements(src) {
        let t = tokens(st);
        let sqlite_path = t
            .iter()
            .any(|w| matches!(*w, "ai_memory" | "rusqlite" | "crate" | "super"));
        if !sqlite_path {
            continue;
        }
        if aliases_of(st, OPEN_OWNERS)
            .iter()
            .any(|a| src.contains(&format!("{a}::open")))
        {
            return true;
        }
        if aliases_of(st, OPEN_FNS)
            .iter()
            .any(|a| bare_calls(src, a) > 0)
        {
            return true;
        }
        let imports_open_fn = t
            .windows(2)
            .any(|w| OPEN_FNS.contains(&w[0]) && w[1] != "as")
            || t.last().is_some_and(|l| OPEN_FNS.contains(l));
        if imports_open_fn {
            return true;
        }
        let glob_owner = OPEN_OWNERS
            .iter()
            .chain(["rusqlite"].iter())
            .any(|o| st.contains(&format!("{o}::*")));
        if glob_owner && OPEN_FNS.iter().any(|f| bare_calls(src, f) > 0) {
            return true;
        }
    }
    false
}

/// A suite that binds a sqlite database to a raw, non-`SqliteTempFile` handle.
fn is_raw_sqlite_offender(src: &str) -> bool {
    holds_raw_named_tempfile(src) && opens_sqlite(src)
}

/// Ceiling: ZERO integration suites (any depth under `tests/`) may bind a
/// sqlite database to a raw `tempfile::NamedTempFile` (the ceiling only
/// falls). Use `common/sqlite_tempfile.rs::SqliteTempFile`, which owns the
/// `-wal` / `-shm`.
#[test]
fn no_suite_binds_sqlite_to_raw_named_tempfile_6122() {
    let offenders: Vec<String> = suite_sources()
        .into_iter()
        .filter(|(_, src)| is_raw_sqlite_offender(src))
        .map(|(name, _)| name)
        .collect();
    assert!(
        offenders.is_empty(),
        "#6122: {} suite(s) bind sqlite to a raw NamedTempFile (orphans -wal/-shm): {offenders:?}",
        offenders.len()
    );
}

/// Zero ceiling (#6788): no suite may leak a temp handle through
/// `ManuallyDrop`, `Box::leak`, `into_path()` or `keep()` either.
#[test]
fn no_suite_leaks_temp_handle_by_other_means_6788() {
    let hits: Vec<String> = suite_sources()
        .into_iter()
        .filter_map(|(name, src)| {
            let shapes = leak_shape_hits(&src);
            (!shapes.is_empty()).then(|| format!("{name}: {shapes:?}"))
        })
        .collect();
    assert!(
        hits.is_empty(),
        "#6788: a temp handle is leaked on purpose (the scratch file outlives the run): {hits:?}"
    );
}

/// Pinned sum of `KNOWN_MEM_FORGET_SITES` counts (#6804).
const KNOWN_MEM_FORGET_TOTAL: usize = 78;
/// Pinned number of files in `KNOWN_MEM_FORGET_SITES` (#6804).
const KNOWN_MEM_FORGET_FILES: usize = 68;

/// `std::mem::forget(<temp handle>)` leaks the scratch file (and its sidecars)
/// on every run by design. Sites that already existed when the guard landed are
/// listed here with their EXACT count, and the table is pinned in total below.
/// A new site, a site in an unlisted file, a count that fell without its entry
/// being lowered, or an entry for a file that is gone or at zero all fail. The
/// ceiling therefore only falls: every migration in #6458 lowers its entry,
/// `KNOWN_MEM_FORGET_TOTAL` and (when a file reaches 0 and is removed from the
/// table) `KNOWN_MEM_FORGET_FILES` in the same commit. Raising any of the three
/// needs coordinated edits that are visible in review.
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

/// Violations of the exact `mem::forget(` pin for `sources` against `table`.
fn forget_violations(table: &[(&str, usize)], sources: &[(String, String)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (name, src) in sources {
        let found = forget_sites(src);
        let pinned = table.iter().find(|(n, _)| n == name).map_or(0, |(_, c)| *c);
        match found.cmp(&pinned) {
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                bad.push(format!(
                    "{name}: {found} site(s), pinned {pinned} (new site)"
                ));
            }
            std::cmp::Ordering::Less => {
                bad.push(format!(
                    "{name}: {found} site(s), pinned {pinned} (stale: lower the entry)"
                ));
            }
        }
    }
    for (name, pinned) in table {
        if !sources.iter().any(|(n, _)| n == name) {
            bad.push(format!(
                "{name}: pinned {pinned} but the file no longer exists (stale: remove the entry)"
            ));
        }
    }
    bad
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

/// #6804: the table cannot be raised without also raising the pinned totals.
#[test]
fn known_forget_table_matches_pinned_totals_6804() {
    let total: usize = KNOWN_MEM_FORGET_SITES.iter().map(|(_, c)| *c).sum();
    assert_eq!(
        total, KNOWN_MEM_FORGET_TOTAL,
        "#6804: KNOWN_MEM_FORGET_SITES sums to {total}, pinned {KNOWN_MEM_FORGET_TOTAL}"
    );
    assert_eq!(
        KNOWN_MEM_FORGET_SITES.len(),
        KNOWN_MEM_FORGET_FILES,
        "#6804: KNOWN_MEM_FORGET_SITES lists {} files, pinned {KNOWN_MEM_FORGET_FILES}",
        KNOWN_MEM_FORGET_SITES.len()
    );
    let mut names: Vec<&str> = KNOWN_MEM_FORGET_SITES.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        KNOWN_MEM_FORGET_SITES.len(),
        "#6804: KNOWN_MEM_FORGET_SITES has a duplicate file entry"
    );
    assert!(
        KNOWN_MEM_FORGET_SITES.iter().all(|(_, c)| *c > 0),
        "#6804: KNOWN_MEM_FORGET_SITES has a zero entry; remove the file"
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

fn offender(src: &str) -> bool {
    is_raw_sqlite_offender(src)
}

/// #6788 (a): `use std::mem::forget; forget(h)` and the aliased forms.
#[test]
fn forget_sites_count_imported_and_aliased_forget_6788() {
    let cases: &[(&str, usize)] = &[
        ("use std::mem::forget;\nfn t() { forget(h); }", 1),
        ("use core::mem::forget;\nfn t() { forget(h); }", 1),
        (
            "use std::mem::{self, forget};\nfn t() { forget(h); mem::forget(g); }",
            2,
        ),
        ("use std::mem::*;\nfn t() { forget(h); }", 1),
        ("use core::mem::forget as leak;\nfn t() { leak(h); }", 1),
        ("use std::mem as m;\nfn t() { m::forget(h); }", 1),
        ("use std::{mem as m, fmt};\nfn t() { m::forget(h); }", 1),
        ("fn t() { std::mem::forget(h); }", 1),
        // not a forget of a handle
        ("fn forget(x: u8) {}\nfn t() { forget(1); }", 0),
        ("use std::mem::forget;", 0),
        ("fn t() { obj.forget(1); unforget(2); }", 0),
        ("fn t() { other::forget(1); }", 0),
    ];
    for (src, want) in cases {
        assert_eq!(forget_sites(src), *want, "#6788: forget_sites({src:?})");
    }
}

/// #6788 (a): `ManuallyDrop`, `Box::leak`, `into_path()`, `into_temp_path()`
/// and `keep()` on a temp handle are zero-ceiling leak shapes.
#[test]
fn leak_shapes_are_flagged_on_temp_handles_6788() {
    for shape in [
        "ManuallyDrop::new(dir)",
        "Box::leak(Box::new(dir))",
        "dir.into_path()",
        "f.into_temp_path()",
        "dir.keep()",
    ] {
        let src = format!("let dir = tempfile::tempdir().unwrap();\nlet _p = {shape};\n");
        assert!(
            !leak_shape_hits(&src).is_empty(),
            "#6788: leak shape not flagged: {shape}"
        );
        let unrelated = format!("let _p = {shape};\n");
        assert!(
            leak_shape_hits(&unrelated).is_empty(),
            "#6788: {shape} in a file with no temp handle must not be flagged"
        );
    }
}

/// #6788 (b): `tempfile::Builder::new()...tempfile()` is a raw `NamedTempFile`.
#[test]
fn builder_tempfile_is_a_raw_named_tempfile_6788() {
    for build in [
        "tempfile::Builder::new().suffix(\".db\").tempfile().unwrap()",
        "tempfile::Builder::new()\n    .prefix(\"x\")\n    .tempfile_in(dir)\n    .unwrap()",
        "tempfile::Builder::new().make(|p| std::fs::File::create(p)).unwrap()",
    ] {
        let src = format!("fn t() {{ let f = {build};\nlet c = ai_memory::db::open(f.path()); }}");
        assert!(offender(&src), "#6788: Builder shape not flagged: {build}");
    }
    // not offenders
    assert!(!offender(
        "fn t() { let f = SqliteTempFile::new().unwrap(); let c = ai_memory::db::open(f.path()); }"
    ));
    assert!(!offender(
        "fn t() { let f = tempfile::tempfile().unwrap(); let c = ai_memory::db::open(p); }"
    ));
    assert!(!offender(
        "fn t() { let f = tempfile::NamedTempFile::new().unwrap(); f.as_file(); }"
    ));
}

/// #6788 (c): aliased and bare-imported sqlite opens are recognised.
#[test]
fn aliased_and_imported_sqlite_opens_are_recognised_6788() {
    let raw = "let f = tempfile::NamedTempFile::new().unwrap();";
    for opener in [
        "use rusqlite::Connection as Conn;\nfn t() { Conn::open(f.path()); }",
        "use rusqlite::{params, Connection as Conn};\nfn t() { Conn::open(f.path()); }",
        "use ai_memory::db as d;\nfn t() { d::open(f.path()); }",
        "use ai_memory::storage as st;\nfn t() { st::open_read_only(f.path()); }",
        "use ai_memory::store::sqlite::SqliteStore as S;\nfn t() { S::open(f.path()); }",
        "use ai_memory::db::open as open_it;\nfn t() { open_it(f.path()); }",
        "use ai_memory::db::open;\nfn t() { open(f.path()); }",
        "use ai_memory::db::{open, other};\nfn t() { open(f.path()); }",
        "use ai_memory::storage::open_read_only;\nfn t() { open_read_only(p); }",
        "use ai_memory::db::*;\nfn t() { open(f.path()); }",
        "fn t() { rusqlite::Connection::open_with_flags(f.path(), fl); }",
    ] {
        let src = format!("{opener}\n{raw}");
        assert!(offender(&src), "#6788: open shape not recognised: {opener}");
    }
    // `File::open` / unrelated opens are not sqlite opens.
    assert!(!offender(&format!(
        "use std::fs::File;\nfn t() {{ File::open(p); }}\n{raw}"
    )));
    assert!(!offender(&format!(
        "use std::fs::OpenOptions;\nfn t() {{ OpenOptions::new().open(p); }}\n{raw}"
    )));
}

/// #6805: `SqliteTempFile` backs ~200 suites, so its creation properties are
/// pinned: owner-only mode (0600) for the database AND its `-wal` / `-shm`, a
/// random name that differs per call, and the process temp dir (`new`) / the
/// given dir (`new_in`) as the parent.
#[cfg(unix)]
#[test]
fn sqlite_tempfile_is_private_random_and_in_temp_dir_6805() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| {
        std::fs::metadata(p)
            .expect("stat scratch file")
            .permissions()
            .mode()
            & 0o777
    };
    let dir = scratch_dir("mode");

    let in_dir = SqliteTempFile::new_in(dir.path()).expect("new_in");
    assert_eq!(mode(in_dir.path()), 0o600, "#6805: new_in() file mode");
    assert_eq!(
        in_dir.path().parent().map(std::path::Path::to_path_buf),
        Some(dir.path().to_path_buf()),
        "#6805: new_in(dir) must create inside dir"
    );

    let in_tmp = SqliteTempFile::new().expect("new");
    assert_eq!(mode(in_tmp.path()), 0o600, "#6805: new() file mode");
    let parent = in_tmp.path().parent().expect("parent of new()");
    assert_eq!(
        parent.canonicalize().expect("canonical parent"),
        std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp dir"),
        "#6805: new() must create inside std::env::temp_dir()"
    );

    // Random: distinct, non-trivial names across many creations.
    let mut names = std::collections::BTreeSet::new();
    let batch: Vec<SqliteTempFile> = (0..16)
        .map(|_| SqliteTempFile::new_in(dir.path()).expect("batch new_in"))
        .collect();
    for f in &batch {
        let name = f
            .path()
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        assert!(
            name.len() >= ".tmp".len() + 6,
            "#6805: scratch name {name:?} has no random part"
        );
        assert!(
            names.insert(name.clone()),
            "#6805: duplicate scratch name {name:?}"
        );
    }

    // The sidecars sqlite creates inherit the owner-only mode.
    let conn = ai_memory::db::open(in_dir.path()).expect("db::open");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS t6805 (x INTEGER); INSERT INTO t6805 VALUES (1);",
    )
    .expect("write forces the -wal");
    for side in side_files(in_dir.path()).iter().take(2) {
        assert!(
            side.exists(),
            "#6805: {} must exist while open",
            side.display()
        );
        assert_eq!(mode(side), 0o600, "#6805: {} mode", side.display());
    }
    drop(conn);
}
