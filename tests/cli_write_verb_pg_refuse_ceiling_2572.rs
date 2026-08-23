// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2572 — the class-(a) CLI write-verb Postgres-refusal FUNNEL ceiling.
//!
//! # The defect this closes
//!
//! Every "class-(a)" CLI verb (`store` / `link` / `update` / `promote` /
//! `forget` / `delete` / `gc` / `archive` / `consolidate` / `namespace` /
//! `reown` / `share` / `offload` / `reflect` / `atomise` / `reembed` / `mine` /
//! `sync` / `calibrate confidence`, plus their read siblings that share a file)
//! opens the local SQLite `--db` directly via `db::open` (or, for
//! `calibrate confidence`, a raw `Connection::open`). `db::open` CREATES a
//! missing file and runs the whole migration ladder on it, so on a
//! Postgres-served deployment (`AI_MEMORY_STORE_URL=postgres://…`, the
//! `AI_MEMORY_STORE_URL_FILE` `0600` channel, or `--store-url`) the write
//! phantom-landed in a throwaway SQLite file the served store NEVER reads —
//! reported as success while the data was silently LOST (the exact #2490 class
//! PR #2568 closed for `export`/`import`/`backup`/`restore`), and a read
//! returned an empty conjured database (a WRONG result).
//!
//! Disposition decided by a UNANIMOUS 5-agent adversarial vote (memory
//! `4d3ea1c5`, 5/5 REFUSE over Route); Route-through-SAL is deferred to #2772.
//!
//! # The contract
//!
//! Each class-(a) verb now routes through the shared
//! `crate::cli::backup::refuse_pg_store` funnel BEFORE any `db::open` / raw
//! open. This test freezes the funnel-CALL inventory: `(file, count)` over
//! `backup::refuse_pg_store(` in every production (non-`#[cfg(test)]`) `src/`
//! file. A NEW call in an unlisted file fails; a REMOVED call drops a count and
//! fails; so the ledger cannot rot in either direction, mirroring the
//! `tests/db_open_funnel_ceiling_2445.rs` precedent. The fix for a violation is
//! to add/keep the guard and update the pin — NOT to widen it silently.

use std::path::{Path, PathBuf};

/// The frozen guard-CALL inventory: `(file, count, disposition)`.
///
/// `count` is the number of PRODUCTION `crate::cli::backup::refuse_pg_store(`
/// call sites in that file (the `fn refuse_pg_store` DEFINITION in
/// `src/cli/backup.rs` is NOT a call — it lacks the `backup::` path prefix — so
/// it is correctly excluded). Test-module sites are excluded by
/// [`production_prefix`]. Total = 30 across 19 files.
const GUARDED: &[(&str, usize, &str)] = &[
    ("src/cli/store.rs", 1, "`store` write."),
    (
        "src/cli/link.rs",
        2,
        "`link` + `resolve` (supersede) writes.",
    ),
    ("src/cli/update.rs", 1, "`update` write."),
    ("src/cli/promote.rs", 1, "`promote` write."),
    (
        "src/cli/forget.rs",
        3,
        "`forget` erasure write + the two query-only receipt readers \
         (`--show-receipt` / `--verify-receipt`), which short-circuit before \
         `cmd_forget`'s own guard and so carry their own.",
    ),
    (
        "src/cli/crud.rs",
        3,
        "`get` / `list` reads (phantom-empty on pg = WRONG result) + `delete` write.",
    ),
    (
        "src/cli/gc.rs",
        3,
        "`gc` eviction write + `stats` / `namespaces` reads.",
    ),
    (
        "src/cli/archive.rs",
        1,
        "one open serves all `archive` sub-actions (list/stats reads, restore/purge writes).",
    ),
    (
        "src/cli/consolidate.rs",
        2,
        "`consolidate` + `auto-consolidate` writes.",
    ),
    (
        "src/cli/namespace.rs",
        3,
        "`set-standard` / `clear-standard` governance-standard writes + `get-standard` read.",
    ),
    (
        "src/cli/reown.rs",
        1,
        "`reown` re-ownership write (the CLI_REFERENCE overclaim fix).",
    ),
    ("src/cli/share.rs", 1, "`share` write."),
    (
        "src/cli/offload.rs",
        2,
        "`offload` DB-backed substrate write + `deref` read (NOT a filesystem-local cold store).",
    ),
    (
        "src/cli/sync.rs",
        1,
        "the LOCAL-store leg only; the `--remote-db` leg is an explicit second \
         sqlite FILE argument, not the configured store, and is unguarded by design.",
    ),
    (
        "src/cli/io.rs",
        1,
        "`mine` write. `export` / `import` in the same file were closed by \
         #2490/#2568 and guard themselves via `resolve_sqlite_store` directly \
         (NOT this wrapper), so they are correctly NOT counted here.",
    ),
    ("src/cli/commands/reflect.rs", 1, "`reflect` write."),
    ("src/cli/commands/atomise.rs", 1, "`atomise` write."),
    (
        "src/cli/commands/reembed.rs",
        1,
        "`reembed` read-then-write (guarded before the embedder build).",
    ),
    (
        "src/cli/commands/calibrate_confidence.rs",
        1,
        "`calibrate confidence` — a WRITE (UPDATEs `confidence_shadow_observations`) \
         despite its \"read-only\" docstring; guarded at its raw `Connection::open` site.",
    ),
];

/// Files that open the local SQLite but are DELIBERATELY carved out of the
/// guard (verified node-local-by-design; guarding them would fail-close the
/// governance spine on a pg deployment). They must carry ZERO guard calls.
const CARVE_OUTS: &[(&str, &str)] = &[
    (
        "src/cli/governance_check_action.rs",
        "the PreToolUse governance hook + `governance check-action` — the \
         highest-frequency local write surface; the on-disk governance store is \
         node-local and must remain reachable on a pg deployment.",
    ),
    (
        "src/cli/governance_install_defaults.rs",
        "`governance install-defaults` seeds the node-local governance ruleset.",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Byte offset of the first test-module marker, or the whole file when there is
/// none. Mirrors the boundary heuristic the shell gates + the #2445 funnel test
/// use, so all agree on what "production code" means.
fn production_prefix(src: &str) -> &str {
    let cut = ["#[cfg(test)]", "mod tests {", "pub mod tests {"]
        .iter()
        .filter_map(|m| src.find(m))
        .min();
    cut.map_or(src, |i| &src[..i])
}

/// Count production `crate::cli::backup::refuse_pg_store(` CALL sites (matched
/// by the `backup::refuse_pg_store(` substring, which the `fn` definition lacks)
/// on non-comment lines.
fn count_guard_calls(src: &str) -> usize {
    production_prefix(src)
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with('*')
        })
        .filter(|l| l.contains("backup::refuse_pg_store("))
        .count()
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_class_a_guard_call_is_enumerated_2572() {
    let root = repo_root();
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();

    let mut observed: Vec<(String, usize)> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        let n = count_guard_calls(&src);
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .expect("under repo root")
                .to_string_lossy()
                .replace('\\', "/");
            observed.push((rel, n));
        }
    }

    let mut problems = Vec::new();
    for (file, n) in &observed {
        match GUARDED.iter().find(|(f, _, _)| f == file) {
            Some((_, pinned, _)) if pinned == n => {}
            Some((_, pinned, why)) => problems.push(format!(
                "{file}: {n} guard call(s), pin says {pinned}.\n    \
                 Disposition on record: {why}\n    \
                 If you ADDED a class-(a) verb: keep its `refuse_pg_store` guard and \
                 bump the pin. If you REMOVED one: lower the pin (a class-(a) verb \
                 that no longer refuses Postgres is a #2572 regression)."
            )),
            None => problems.push(format!(
                "{file}: {n} `refuse_pg_store` call(s) with NO recorded disposition.\n    \
                 Add the file to GUARDED in tests/cli_write_verb_pg_refuse_ceiling_2572.rs \
                 with the verb it guards, so the funnel inventory stays exhaustive (#2572)."
            )),
        }
    }
    for (file, _, _) in GUARDED {
        if !observed.iter().any(|(f, _)| f == file) {
            problems.push(format!(
                "{file}: pinned as guarded but has NO `refuse_pg_store` call — a \
                 class-(a) verb lost its Postgres refusal (#2572), or the entry is \
                 stale. Do not leave the ledger able to rot."
            ));
        }
    }

    let total: usize = GUARDED.iter().map(|(_, n, _)| n).sum();
    assert_eq!(
        total, 30,
        "the pinned class-(a) guard total drifted from 30 (#2572)"
    );
    assert!(
        problems.is_empty(),
        "class-(a) CLI Postgres-refusal funnel ceiling (#2572):\n  - {}",
        problems.join("\n  - ")
    );
}

#[test]
fn carve_outs_stay_node_local_and_unguarded_2572() {
    let root = repo_root();
    for (file, why) in CARVE_OUTS {
        let src = std::fs::read_to_string(root.join(file)).unwrap_or_else(|_| {
            panic!("carve-out {file} must exist — if it moved, update CARVE_OUTS ({why})")
        });
        assert_eq!(
            count_guard_calls(&src),
            0,
            "{file} is a deliberate node-local carve-out and must NOT call \
             `refuse_pg_store` — guarding it would fail-close the governance spine \
             on a Postgres deployment ({why})"
        );
        assert!(
            production_prefix(&src).contains("Connection::open("),
            "{file} is only meaningful as a carve-out because it opens a raw local \
             sqlite connection; if that changed, re-examine the carve-out ({why})"
        );
    }
}

#[test]
fn the_shared_guard_funnel_names_the_http_daemon_remedy_2572() {
    let root = repo_root();
    let backup = std::fs::read_to_string(root.join("src/cli/backup.rs")).expect("read backup.rs");
    assert!(
        backup.contains("pub(crate) fn refuse_pg_store("),
        "the single shared class-(a) funnel `refuse_pg_store` must be defined in src/cli/backup.rs"
    );
    assert!(
        backup.contains("pub(crate) const PG_CLI_ALTERNATIVE"),
        "the HTTP-daemon remedy hint const must exist"
    );
    // The refusal names the pg-native alternative (the HTTP daemon), not
    // `pg_dump` — a write cannot be recovered by a dump. The doc fix on
    // CLI_REFERENCE.md points `reown` at the same remedy, so the two must agree.
    let alt_start = backup
        .find("PG_CLI_ALTERNATIVE: &str")
        .expect("PG_CLI_ALTERNATIVE literal");
    let alt = &backup[alt_start..alt_start + 400];
    assert!(
        alt.contains("HTTP daemon"),
        "the class-(a) refusal must route the operator to the HTTP daemon: {alt}"
    );
}

#[test]
fn the_production_boundary_heuristic_is_load_bearing_2572() {
    // A gate whose boundary heuristic silently matched nothing would pass
    // forever. Prove all three arms fire.
    assert_eq!(
        count_guard_calls("let p = crate::cli::backup::refuse_pg_store(db_path, \"x\", out)?;"),
        1,
        "a production guard call must be counted"
    );
    assert_eq!(
        count_guard_calls(
            "#[cfg(test)]\nmod t { fn f() { backup::refuse_pg_store(p, \"x\", o); } }"
        ),
        0,
        "a test-module guard call must NOT be counted"
    );
    assert_eq!(
        count_guard_calls("// backup::refuse_pg_store(p) in a comment"),
        0,
        "a commented reference must NOT be counted"
    );
    assert_eq!(
        count_guard_calls("pub(crate) fn refuse_pg_store(db_path: &Path) {}"),
        0,
        "the `fn` DEFINITION (no `backup::` prefix) must NOT be counted as a call"
    );
}

// ---------------------------------------------------------------------------
// R-203 — behavioral proof against the real binary.
//
// These drive the shipped `AI_MEMORY_STORE_URL` env channel (#1927) so the test
// source stays valid at the parent commit (no new struct fields) and the guard
// fires on the exact surface an operator hits. At the parent commit a class-(a)
// verb pointed at a Postgres store phantom-created a SQLite file and exited 0;
// post-fix it refuses non-zero WITHOUT touching disk, so each assertion below
// FAILS against the parent and PASSES after (R-203). The refusal fires on the
// URL SCHEME before any connection, so NO live Postgres is required.
// ---------------------------------------------------------------------------

use std::process::Command;

use assert_cmd::cargo::cargo_bin;
use tempfile::TempDir;

/// v1.0.0 #3140 — the port is `1`, an address nothing ever listens on.
///
/// This is a REFUSAL probe: the guard must fire on the URL scheme, before
/// any connection. Aiming it at the real Postgres port (5432) made the
/// assertion VACUOUS on any host running Postgres — a regression that moved
/// the refusal after connect would still pass, and a regression that removed
/// it could WRITE to that live database. Pointing at a dead address means a
/// refusal can never be manufactured by a live server; the reason-text
/// assertions below keep it from being manufactured by a connection error
/// either.
const PG_STORE_URL: &str = "postgres://ai_memory:hunter2@127.0.0.1:1/ai_memory";
const PG_PASSWORD: &str = "hunter2";

/// Run a fast (non-daemon) CLI verb once and capture its output. `store_url`,
/// when `Some`, is injected via the owner-only `AI_MEMORY_STORE_URL` channel.
fn run_verb(db: &Path, store_url: Option<&str>, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(cargo_bin("ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_STORE_URL")
        .env_remove("AI_MEMORY_STORE_URL_FILE")
        .arg("--db")
        .arg(db.to_str().expect("utf-8 db path"))
        .args(args);
    if let Some(url) = store_url {
        cmd.env("AI_MEMORY_STORE_URL", url);
    }
    cmd.output().expect("spawn ai-memory")
}

#[test]
fn store_write_refuses_on_a_postgres_store_url_without_phantom_writing_2572() {
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("must-not-be-created.db");
    assert!(!db.exists());

    let out = run_verb(
        &db,
        Some(PG_STORE_URL),
        &["store", "--title", "t", "--content", "c"],
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    assert!(
        !out.status.success(),
        "`store` must exit non-zero on a postgres:// store URL; status={:?} out={combined}",
        out.status
    );
    assert!(
        combined.contains("#2572") || combined.contains("HTTP daemon"),
        "the refusal must name the #2572 remedy (the HTTP daemon): {combined}"
    );
    assert!(
        !combined.contains(PG_PASSWORD),
        "the refusal must redact the DSN password: {combined}"
    );
    // The silent-wrong-store signature: a conjured SQLite file (+ WAL).
    assert!(
        !db.exists(),
        "must NOT create the local sqlite db after refusing postgres:// (#2572)"
    );
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    assert!(
        !wal.exists(),
        "must NOT create a WAL for a refused wrong-store write (#2572)"
    );
}

#[test]
fn read_verb_namespaces_refuses_on_a_postgres_store_url_2572() {
    // A phantom-empty read on a pg deployment is a WRONG result, not a degrade;
    // the read siblings refuse too.
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("must-not-be-created.db");

    let out = run_verb(&db, Some(PG_STORE_URL), &["namespaces"]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.status.success(),
        "`namespaces` must refuse a postgres:// store URL; out={combined}"
    );
    assert!(
        combined.contains("#2572") || combined.contains("HTTP daemon"),
        "the refusal must name the #2572 remedy: {combined}"
    );
    assert!(
        !db.exists(),
        "must NOT conjure a sqlite db for a refused read (#2572)"
    );
}

#[test]
fn store_without_store_url_still_writes_sqlite_2572() {
    // Over-refuse guard: with no store URL configured (the ordinary local-sqlite
    // deployment) the guard is byte-transparent and the write lands.
    let tmp = TempDir::new().expect("tempdir");
    let db = tmp.path().join("ok.db");

    let out = run_verb(&db, None, &["store", "--title", "t", "--content", "c"]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "`store` on a local-sqlite deployment must still succeed (over-refuse guard); out={combined}"
    );
    assert!(
        db.exists(),
        "a legitimate local-sqlite `store` must create the --db (over-refuse guard, #2572)"
    );
}
