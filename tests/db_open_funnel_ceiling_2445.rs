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
        "src/curator/mod.rs",
        1,
        "GUARDED via `assert_schema_not_ahead` (#2445). The curator daemon \
         re-opens the file each cycle off `db::open` so it does not pay \
         bootstrap + ladder on every interval tick. Hidden until B15 stopped \
         cutting production at the first interior `#[cfg(test)]` (`use crate::db` \
         near the top of this file).",
    ),
    (
        "src/cli/schema_init.rs",
        1,
        "READ-ONLY catalog enumeration (`sqlite_master` + `schema_version`), \
         and it runs only after `migrate::open_store` has already opened and \
         guarded the same file in-process.",
    ),
    (
        "src/cli/backup.rs",
        1,
        "LIVENESS probe for `restore` (#3131). Opens READ_WRITE so \
         `PRAGMA locking_mode=exclusive` + `BEGIN EXCLUSIVE` can detect a \
         live daemon; it is NOT `db::open` because a probe must not run the \
         bootstrap/ladder against the operator's live file. Schema-downgrade \
         and rollback-evidence are applied immediately after the exclusive \
         lock via `assert_schema_not_ahead` (#2445). The probe still \
         checkpoints a hot WAL on close — that is why consent runs first.",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Strip a leading visibility qualifier so `pub(super) mod foo {` and
/// `pub fn open` share the same item-start checks.
fn strip_vis(t: &str) -> &str {
    let t = t.trim_start();
    let Some(rest) = t.strip_prefix("pub") else {
        return t;
    };
    let rest = rest.trim_start();
    if rest.starts_with('(') {
        if let Some(idx) = rest.find(')') {
            return rest[idx + 1..].trim_start();
        }
        return rest;
    }
    rest
}

fn is_cfg_test_attr(t: &str) -> bool {
    let t = t.trim_start();
    t.starts_with("#[cfg(test)]")
        || t.starts_with("#[cfg(any(test")
        || t.starts_with("#[cfg(all(test")
}

fn is_inline_mod(t: &str) -> bool {
    let t = strip_vis(t);
    t.starts_with("mod ") && t.contains('{')
}

fn is_fn_start(t: &str) -> bool {
    let t = strip_vis(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    let t = t.strip_prefix("const ").unwrap_or(t);
    let t = t.strip_prefix("unsafe ").unwrap_or(t);
    t.starts_with("fn ")
}

fn is_comment_or_empty(t: &str) -> bool {
    let t = t.trim_start();
    t.is_empty() || t.starts_with("//") || t.starts_with('*')
}

/// Attributes immediately above `item_idx` include `#[cfg(test)]`.
fn attrs_above_include_cfg_test(lines: &[&str], item_idx: usize) -> bool {
    for line in lines[..item_idx].iter().rev() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with("///") || t.starts_with("//!") || t.starts_with("//") {
            continue;
        }
        if is_cfg_test_attr(t) {
            return true;
        }
        if t.starts_with("#[") {
            continue;
        }
        return false;
    }
    false
}

/// True when the raw-open sits inside a `#[cfg(test)] fn` (e.g.
/// `vectorlite::broken_for_test`). An interior `#[cfg(test)]` on a
/// `static`/`use` (B11 `DB_PASSPHRASE`) must NOT trip this.
fn enclosing_fn_is_cfg_test(lines: &[&str], idx: usize) -> bool {
    for i in (0..idx).rev() {
        let t = lines[i].trim_start();
        if is_comment_or_empty(t) || t.starts_with("#[") {
            continue;
        }
        if is_fn_start(t) {
            return attrs_above_include_cfg_test(lines, i);
        }
        let head = strip_vis(t);
        if head.starts_with("impl ")
            || head.starts_with("struct ")
            || head.starts_with("enum ")
            || head.starts_with("trait ")
            || head.starts_with("use ")
            || head.starts_with("static ")
            || head.starts_with("const ")
            || head.starts_with("type ")
            || head.starts_with("mod ")
        {
            return false;
        }
    }
    false
}

/// Byte offset of the first `#[cfg(test)]` test *module*, or the whole
/// file when there is none. Matches `scripts/qc-codegraph-precheck.sh`
/// and `scripts/check-hardcoded-literals.sh`: only a cfg(test) whose
/// next item opens an inline `mod … {` ends the production region.
/// Interior `#[cfg(test)]` on `use`/`fn`/`static` (Wave-2 B11
/// `DB_PASSPHRASE` seam in `connection.rs`) must NOT hide later
/// production `Connection::open*` sites.
fn production_prefix(src: &str) -> &str {
    let mut pending_attr_start: Option<usize> = None;
    let mut line_start = 0;
    for line in src.split_inclusive('\n') {
        let content = line.trim_start().trim_end_matches(['\n', '\r']);
        if is_comment_or_empty(content) {
            line_start += line.len();
            continue;
        }
        if is_cfg_test_attr(content) {
            if pending_attr_start.is_none() {
                pending_attr_start = Some(line_start);
            }
            line_start += line.len();
            continue;
        }
        if content.starts_with("#[") {
            line_start += line.len();
            continue;
        }
        if let Some(cut) = pending_attr_start {
            if is_inline_mod(content) {
                return &src[..cut];
            }
            pending_attr_start = None;
        }
        line_start += line.len();
    }
    src
}

/// Count production raw sqlite connection constructions.
fn count_raw_opens(src: &str) -> usize {
    let src = production_prefix(src);
    let lines: Vec<&str> = src.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(i, l)| {
            let t = l.trim_start();
            if t.starts_with("//") || t.starts_with('*') {
                return false;
            }
            let is_open = l.contains("Connection::open(")
                || l.contains("Connection::open_with_flags(")
                || l.contains("Connection::open_in_memory(");
            is_open && !enclosing_fn_is_cfg_test(&lines, *i)
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
        count_raw_opens("#[cfg(test)]\nmod tests { fn f() { Connection::open(p); } }"),
        0,
        "a test-module raw open must NOT be counted"
    );
    assert_eq!(
        count_raw_opens("#[cfg(test)]\nstatic X: i32 = 0;\nConnection::open(p);"),
        1,
        "an interior #[cfg(test)] seam must NOT hide later production opens"
    );
    assert_eq!(
        count_raw_opens(
            "#[cfg(test)]\nmod transport_helpers_tests {\nConnection::open_in_memory();\n}"
        ),
        0,
        "a cfg(test) module that is not named `tests` must NOT be counted"
    );
    assert_eq!(
        count_raw_opens("#[cfg(test)]\nfn broken_for_test() {\nConnection::open_in_memory();\n}"),
        0,
        "a cfg(test) helper fn must NOT be counted"
    );
    assert_eq!(
        count_raw_opens("// Connection::open(p) in a comment"),
        0,
        "a commented reference must NOT be counted"
    );
}

/// v1.0.0 #2445 — ALWAYS-COMPILED, ALWAYS-RUN structural guard that both
/// backends still gate BEFORE their bootstrap DDL.
///
/// The behavioural postgres suite (`tests/postgres_schema_downgrade_guard_2445.rs`)
/// self-skips without `AI_MEMORY_TEST_POSTGRES_URL`, so on an ordinary CI run —
/// which is most of them — deleting the postgres guard would be caught by
/// nothing at all. This is a source-text assertion precisely because it must
/// hold with no live server: it costs one file read and it reds a normal run.
///
/// It asserts ORDER, not mere presence. "The guard exists somewhere in the
/// file" is satisfied by a guard placed AFTER the bootstrap replays, which is
/// the exact variant #2445 rejected (an older binary's `CREATE … IF NOT EXISTS`
/// set running over a newer database is the #2424 class).
///
/// Credit: the ordering-and-parity idea is carried forward from the WIP branch
/// `fix/2445-downgrade-guard` @ `91573bdb`, preserved by the orchestrator when
/// an earlier lane on this issue terminated mid-R-203.
#[test]
fn both_backends_gate_before_their_bootstrap_ddl_2445() {
    let root = repo_root();
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).expect("read source");

    // ---- sqlite: db::open ----
    let sqlite = read("src/storage/connection.rs");
    let guard = sqlite
        .find("resolve_schema_posture(&conn,")
        .expect("src/storage/connection.rs must call the downgrade guard in `open`");
    let bootstrap = sqlite
        .find("conn.execute_batch(SCHEMA)")
        .expect("`open` must still apply the bootstrap SCHEMA");
    assert!(
        guard < bootstrap,
        "sqlite: the #2445 downgrade guard must run BEFORE `execute_batch(SCHEMA)` — a \
         guard placed after it lets an older binary's bootstrap replay over a newer \
         database (the #2424 class), which is the variant #2445 rejected"
    );

    // ---- postgres: connect bootstrap ----
    let pg = read("src/store/postgres.rs");
    let pg_guard = pg
        .find("crate::storage::schema_guard::evaluate(")
        .expect("src/store/postgres.rs must call the downgrade guard in the connect bootstrap");
    let pg_bootstrap = pg
        .find("sqlx::raw_sql(&init_sql)")
        .expect("the connect bootstrap must still apply INIT_SCHEMA");
    assert!(
        pg_guard < pg_bootstrap,
        "postgres: the #2445 downgrade guard must run BEFORE `raw_sql(init_sql)`"
    );

    // ---- both L2 funnels keep the strictly-greater refusal ----
    assert!(
        read("src/storage/migrations.rs").contains("if version > CURRENT_SCHEMA_VERSION"),
        "sqlite `migrate` must keep the `>` refusal (defense-in-depth behind `db::open`)"
    );
    assert!(
        pg.contains("if current_version > CURRENT_SCHEMA_VERSION"),
        "`migrate_locked` must keep the `>` refusal (defense-in-depth behind `connect`)"
    );

    // ---- the `==` fast path must survive on both, byte-for-byte ----
    assert!(
        read("src/storage/migrations.rs").contains("if version == CURRENT_SCHEMA_VERSION"),
        "sqlite must keep the `==` no-op fast path — collapsing it back into `>=` is the \
         defect #2445 fixed"
    );
    assert!(
        pg.contains("if current_version == CURRENT_SCHEMA_VERSION"),
        "postgres must keep the `==` no-op fast path"
    );
}
