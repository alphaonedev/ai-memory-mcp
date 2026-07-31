// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #2445 — the db-open FUNNEL ceiling.
//!
//! # The defect this closes
//!
//! `src/storage/connection.rs` asserted for two releases that "`db::open` is
//! the funnel every interface crosses". It is the funnel every interface BOOT
//! crosses; it is NOT the funnel every WRITE crosses. When #2445 catalogued the
//! surfaces, four production CLI paths opened a raw `rusqlite::Connection` and
//! WROTE through it without ever touching `db::open` — one of them the
//! PreToolUse governance hook, the highest-frequency write surface in the
//! product. Both the #2445 downgrade guard and #1946's open-time
//! rollback-evidence check were silently absent on all four.
//!
//! Adding a guard to `db::open` while leaving raw-open bypasses unenumerated
//! reproduces the #2488 failure mode INSIDE the fix for it: the audit is true
//! for exactly one merge, then rots. So the inventory is MECHANICAL.
//!
//! # The contract
//!
//! Every production (non-`#[cfg(test)]`) raw sqlite connection construction in
//! `src/` must appear in [`ALLOWLIST`] with a stated disposition. A NEW one
//! fails this test; a REMOVED one also fails it, so the ledger cannot rot in
//! either direction. The fix for a violation is to route through
//! `crate::db::open` or to call `crate::storage::assert_schema_not_ahead` right
//! after the raw open — NOT to widen the allowlist without a reason.

use std::path::{Path, PathBuf};

/// The frozen inventory: `(file, count, disposition)`.
///
/// `count` is the number of PRODUCTION raw-open sites in that file. Test-module
/// sites are excluded by [`production_prefix`] and are not counted.
const ALLOWLIST: &[(&str, usize, &str)] = &[
    (
        "src/storage/connection.rs",
        3,
        "THE funnel itself — `open`, `open_read_only`, `open_unmigrated`. \
         Everything below is a bypass OF this file, which is why it is listed \
         first and why its own count is pinned.",
    ),
    (
        "src/cli/governance_check_action.rs",
        2,
        "GUARDED at both sites via `assert_schema_not_ahead` (#2445). Kept off \
         `db::open` deliberately: the `--from-pretool-stdin` arm is the \
         PreToolUse hook and sits on the agent's critical path, so it must not \
         pay the bootstrap + ladder cost on every tool call.",
    ),
    (
        "src/cli/governance_install_defaults.rs",
        1,
        "GUARDED via `assert_schema_not_ahead` (#2445). Writes \
         `UPDATE governance_rules SET enabled = 1`.",
    ),
    (
        "src/cli/commands/calibrate_confidence.rs",
        1,
        "GUARDED via `assert_schema_not_ahead` (#2445). Writes \
         `confidence_shadow_observations` through `calibrate_from_shadow`.",
    ),
    (
        "src/subscriptions.rs",
        6,
        "ORDERING-COVERED, not structurally covered — and that distinction is \
         the whole reason this entry exists. Every one of these six is reached \
         only from the webhook dispatcher, which is spawned by a `serve` \
         process whose `bootstrap_serve` already crossed `db::open`. They write \
         `subscription_events` / `subscription_dlq` / `subscriptions`, never \
         `memories`. The coverage is a property of ONE call graph, so the day \
         someone adds a standalone dispatcher or a `--dispatch-only` mode it \
         stops holding — at which point this count moves and this test fails, \
         which is the signal to guard them.",
    ),
    (
        "src/vectorlite.rs",
        1,
        "NOT an ai-memory database at all — `Connection::open_in_memory()` \
         backing the OFF-by-default vectorlite ANN index, a derived and \
         disposable artifact rebuilt from the durable text on every boot. It \
         holds no `schema_version` relation, so there is nothing for the \
         downgrade guard to check. (Surfaced BY this gate, not by the manual \
         #2445 funnel sweep — which is the point of making the inventory \
         mechanical.)",
    ),
    (
        "src/cli/schema_init.rs",
        1,
        "READ-ONLY catalog enumeration (`sqlite_master` + `schema_version`), \
         and it runs only after `migrate::open_store` has already opened and \
         guarded the same file in-process.",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Byte offset of the first test-module marker, or the whole file when there is
/// none. Mirrors the production-vs-test boundary heuristic the shell gates use
/// (`scripts/check-vendor-literals.sh`, `scripts/qc-codegraph-precheck.sh`) so
/// the three agree on what "production code" means.
fn production_prefix(src: &str) -> &str {
    let cut = ["#[cfg(test)]", "mod tests {", "pub mod tests {"]
        .iter()
        .filter_map(|m| src.find(m))
        .min();
    cut.map_or(src, |i| &src[..i])
}

/// Count raw sqlite connection constructions on non-comment lines.
fn count_raw_opens(src: &str) -> usize {
    production_prefix(src)
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with('*')
        })
        .filter(|l| {
            l.contains("Connection::open(")
                || l.contains("Connection::open_with_flags(")
                || l.contains("Connection::open_in_memory(")
        })
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
fn every_production_raw_sqlite_open_is_enumerated_2445() {
    let root = repo_root();
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();

    let mut observed: Vec<(String, usize)> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        let n = count_raw_opens(&src);
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .expect("under repo root")
                .to_string_lossy()
                .replace('\\', "/");
            observed.push((rel, n));
        }
    }

    let mut unexpected = Vec::new();
    for (file, n) in &observed {
        match ALLOWLIST.iter().find(|(f, _, _)| f == file) {
            Some((_, pinned, _)) if pinned == n => {}
            Some((_, pinned, why)) => unexpected.push(format!(
                "{file}: {n} production raw-open site(s), allowlist pins {pinned}.\n    \
                 Disposition on record: {why}\n    \
                 If you ADDED one: route it through `crate::db::open`, or call \
                 `crate::storage::assert_schema_not_ahead` immediately after the raw \
                 open, then bump the pin. If you REMOVED one: lower the pin."
            )),
            None => unexpected.push(format!(
                "{file}: {n} production raw-open site(s) with NO recorded disposition.\n    \
                 A raw `rusqlite::Connection` bypasses the #2445 schema-downgrade guard \
                 AND the #1946 open-time rollback-evidence check. Route it through \
                 `crate::db::open`, or call `crate::storage::assert_schema_not_ahead` \
                 immediately after opening, then add it to ALLOWLIST in \
                 tests/db_open_funnel_ceiling_2445.rs with the reason."
            )),
        }
    }
    for (file, _, _) in ALLOWLIST {
        if !observed.iter().any(|(f, _)| f == file) {
            unexpected.push(format!(
                "{file}: allowlisted but has NO production raw-open site — remove the \
                 stale entry so the ledger cannot rot"
            ));
        }
    }

    assert!(
        unexpected.is_empty(),
        "db-open funnel ceiling (#2445):\n  - {}",
        unexpected.join("\n  - ")
    );
}

#[test]
fn the_production_test_boundary_heuristic_is_load_bearing_2445() {
    // A gate whose boundary heuristic silently matched nothing would pass
    // forever. Prove both halves fire.
    assert_eq!(
        count_raw_opens("let c = rusqlite::Connection::open(p)?;"),
        1,
        "a production raw open must be counted"
    );
    assert_eq!(
        count_raw_opens("#[cfg(test)]\nmod t { fn f() { Connection::open(p); } }"),
        0,
        "a test-module raw open must NOT be counted"
    );
    assert_eq!(
        count_raw_opens("// Connection::open(p) in a comment"),
        0,
        "a commented reference must NOT be counted"
    );
}
