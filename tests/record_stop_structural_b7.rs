// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Wave-2 B7 — STRUCTURAL record-stop completeness.
//!
//! Scans `src/**/*.rs` for write-SQL (`INSERT INTO` / `INSERT OR … INTO` /
//! `UPDATE … SET` / `DELETE FROM`) in the enclosing function and asserts
//! that function calls a record-stop gate, or is on the reviewed
//! exception allowlist. A new write-SQL function that is neither gated
//! nor allowlisted fails this test — that is the durable round-N
//! guarantee (LESSON-5). `append_signed_event` stays ungated so resume
//! can persist the attestation.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const GATE_MARKERS: &[&str] = &[
    "gate_storage_conn",
    "gate_storage_conn_rusqlite",
    "gate_record_stop",
    "refuse_if_record_stopped",
    "record_stop_status",
];

/// Functions that MUST be gated (the B7 enumerated siblings). If any of
/// these appear ungated the test fails even if they were accidentally
/// added to the allowlist.
const MUST_BE_GATED: &[&str] = &[
    "queue_pending_action",
    "entity_register",
    "ensure_row",
    "enforce_governance_action",
    "quota_status",
    "quota_status_ns",
    "pending_decide",
    "governance_approve_with_consensus",
    "reflect_with_hooks",
    "update_embedding",
    "fold_recall_accesses",
];

/// Sqlite SSOT fn → postgres SAL method. If the sqlite twin's body
/// contains a record-stop gate, the pg method must too (B7' parity —
/// an allowlist exemption cannot mask a gated-sqlite / ungated-pg split).
const SQLITE_PG_TWINS: &[(&str, &str)] = &[
    ("decide_pending_action", "pending_decide"),
    (
        "approve_with_approver_type",
        "governance_approve_with_consensus",
    ),
    ("set_namespace_standard", "set_namespace_standard"),
    ("clear_namespace_standard", "clear_namespace_standard"),
    ("bind_agent_api_key", "bind_agent_api_key"),
    ("set_embeddings_batch", "set_embeddings_batch"),
    ("queue_pending_action", "enforce_governance_action"),
    ("set_embedding", "update_embedding"),
    ("fold_recall_accesses", "fold_recall_accesses"),
];

fn write_sql_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    let upper = line.to_ascii_uppercase();
    (upper.contains("INSERT INTO") || upper.contains("INSERT OR"))
        && (upper.contains(" INTO ") || upper.contains("INTO\n") || upper.contains("INTO "))
        || upper.contains("DELETE FROM")
        || (upper.contains("UPDATE ") && upper.contains(" SET"))
}

fn is_fn_start(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    let mut t = line.trim_start();

    // #3934 — recognise ANY visibility, not just `pub(crate)`/`pub`. A
    // `pub(super) fn` / `pub(self) fn` / `pub(in a::b) fn` line was NOT a
    // function start under the old two-case strip, so its body merged into
    // the PRECEDING recognised fn and B7 read gate presence from the merged
    // text (both directions: an ungated `pub(restricted)` write "passed" on
    // the preceding fn's gate, and a private helper inherited a following
    // `pub(restricted)` fn's gate). Strip `pub` plus an optional balanced
    // parenthesised restriction (`(crate)`/`(super)`/`(self)`/`(in path)`),
    // then any `const`/`unsafe`/`async` qualifiers.
    if t.starts_with("pub(") {
        // Restriction parens are non-nested (`crate`/`super`/`self`/`in a::b`),
        // so the first `)` closes them.
        if let Some(close) = t.find(')') {
            t = t[close + 1..].trim_start();
        }
    } else if let Some(rest) = t.strip_prefix("pub ") {
        t = rest.trim_start();
    } else if let Some(rest) = t.strip_prefix("pub\t") {
        t = rest.trim_start();
    }
    loop {
        let next = t
            .strip_prefix("const ")
            .or_else(|| t.strip_prefix("unsafe "))
            .or_else(|| t.strip_prefix("async "));
        match next {
            Some(rest) => t = rest.trim_start(),
            None => break,
        }
    }
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        return Some((indent, name));
    }
    None
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn strip_test_mod(src: &str) -> &str {
    // Only drop a trailing `#[cfg(test)] mod tests { … }` so in-file
    // `#[cfg(test)]` helpers earlier in a large module are not mistaken
    // for the end of production code (storage/mod.rs, postgres.rs).
    let needle = "\n#[cfg(test)]\nmod tests {";
    if let Some(idx) = src.rfind(needle) {
        return &src[..idx];
    }
    src
}

fn skip_path(rel: &str) -> bool {
    // Trees whose writes are not record-plane content, or already sit
    // behind an entry gate (MCP dispatch / federation chokepoint /
    // schema). A new write-SQL fn in a NON-skipped path still fails.
    rel.contains("/mcp/tools/")
        || rel.ends_with("tests.rs")
        || rel.ends_with("/migrations.rs")
        || rel.contains("/cli/")
        || rel.starts_with("src/federation/")
        || rel.starts_with("src/background/")
        || rel.starts_with("src/confidence/")
        || rel.starts_with("src/atomisation/")
        || rel.starts_with("src/offload/")
        || rel.starts_with("src/observations/")
        || rel.starts_with("src/portability/")
        || rel.starts_with("src/erasure/")
        || rel.starts_with("src/governance/")
        || rel.starts_with("src/handlers/")
        || rel.starts_with("src/transcripts/")
        || rel.starts_with("src/subscriptions.rs")
        || rel.starts_with("src/vectorlite.rs")
        || rel.starts_with("src/revisions.rs")
}

fn is_test_fn(lines: &[&str], start: usize) -> bool {
    for j in (0..start).rev().take(12) {
        let t = lines[j].trim();
        if t.starts_with("#[test") || t.starts_with("#[tokio::test") {
            return true;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("#[") {
            continue;
        }
        break;
    }
    false
}

fn rel_src(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn fn_body_has_gate(src: &str, fn_name: &str) -> bool {
    let needle = format!("fn {fn_name}");
    let Some(idx) = src.find(&needle) else {
        return false;
    };
    let rest = &src[idx..];
    let end = rest
        .find("\n    async fn ")
        .or_else(|| rest.find("\npub fn "))
        .unwrap_or(rest.len().min(8000));
    let body = &rest[..end];
    GATE_MARKERS.iter().any(|g| body.contains(g))
}

/// #3934 — the boundary+gate core B7 uses, factored so the self-test can
/// drive it with EITHER the shipped `is_fn_start` or a frozen pre-fix copy.
/// Returns the write-SQL functions whose attributed body (nearest preceding
/// fn start .. next fn start) carries no [`GATE_MARKERS`] marker. This is the
/// exact detection the #3934 widening affects; the main test layers the
/// skip/test/migrate/allowlist/const-boundary filters on top of the same
/// core.
fn ungated_write_fns_for(
    text: &str,
    start_of: impl Fn(&str) -> Option<(usize, String)>,
) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let starts: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| start_of(l).map(|(_, n)| (i, n)))
        .collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        if !write_sql_line(line) {
            continue;
        }
        let Some(&(start, ref name)) = starts.iter().rev().find(|(s, _)| *s <= idx) else {
            continue;
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        let end = starts
            .iter()
            .find(|(s, _)| *s > start)
            .map_or(lines.len(), |(s, _)| *s);
        let body = &lines[start..end];
        let has_gate = body
            .iter()
            .any(|l| GATE_MARKERS.iter().any(|g| l.contains(g)));
        if !has_gate {
            out.push(name.clone());
        }
    }
    out
}

/// #3934 R-203 — the EXACT pre-fix `is_fn_start` (strips only `pub(crate) `
/// / `pub ` then `async `), frozen so the self-test can prove the blind spot
/// the widening closes: this predicate ACCEPTS (fails to flag) a planted
/// ungated `pub(super)` write fn, while the shipped [`is_fn_start`] REDs it.
fn is_fn_start_prefix_frozen(line: &str) -> Option<(usize, String)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    if let Some(rest) = t.strip_prefix("fn ") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        return Some((indent, name));
    }
    None
}

/// #3934 — sensitivity + R-203 specificity for the `is_fn_start` widening.
/// A gated fn is followed by an ungated `pub(super)` write fn (and, for good
/// measure, an ungated `pub(in crate::x)` write fn). The SHIPPED scanner must
/// flag both (RED = the blind spot is closed); the FROZEN pre-fix scanner
/// must NOT flag either (it merges each into the preceding gated fn — the bug
/// this reproduces). A gated `pub(self)` write fn must NOT be flagged by the
/// shipped scanner (no false positive).
#[test]
fn b7_scanner_sees_pub_restricted_write_fns_3934() {
    let planted = r#"
    pub(crate) async fn gated_before(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute("UPDATE memories SET x = 1", [])?;
        Ok(())
    }

    pub(super) async fn plant_pub_super_ungated(conn: &Connection) -> Result<()> {
        conn.execute("UPDATE memories SET y = 2", [])?;
        Ok(())
    }

    pub(in crate::store) fn plant_pub_in_ungated(conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM memories WHERE z = 3", [])?;
        Ok(())
    }

    pub(self) async fn plant_pub_self_gated(conn: &Connection) -> Result<()> {
        gate_record_stop(conn)?;
        conn.execute("UPDATE memories SET w = 4", [])?;
        Ok(())
    }
"#;

    let shipped = ungated_write_fns_for(planted, is_fn_start);
    assert!(
        shipped.contains(&"plant_pub_super_ungated".to_string()),
        "sensitivity: the widened scanner must FLAG an ungated pub(super)          write fn (got {shipped:?})"
    );
    assert!(
        shipped.contains(&"plant_pub_in_ungated".to_string()),
        "sensitivity: the widened scanner must FLAG an ungated pub(in ..)          write fn (got {shipped:?})"
    );
    assert!(
        !shipped.contains(&"plant_pub_self_gated".to_string()),
        "specificity: a GATED pub(self) write fn must NOT be flagged (got {shipped:?})"
    );

    // R-203 — the frozen pre-fix predicate reproduces the blind spot: it does
    // NOT recognise the pub(super)/pub(in ..) fn starts, so their writes merge
    // into the preceding gated fn and are read as gated (accepted, not flagged).
    let frozen = ungated_write_fns_for(planted, is_fn_start_prefix_frozen);
    assert!(
        !frozen.contains(&"plant_pub_super_ungated".to_string())
            && !frozen.contains(&"plant_pub_in_ungated".to_string()),
        "R-203: the frozen pre-fix scanner must be BLIND to pub(restricted)          write fns (that is the #3934 bug); got {frozen:?}"
    );
}

#[test]
fn record_stop_write_sql_fns_are_gated_or_allowlisted_b7() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = root.join("src");
    let mut files = Vec::new();
    walk_rs(&src_root, &mut files);

    let allow: HashSet<(String, String)> = include_str!("record_stop_b7_allowlist.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.split('\t');
            (
                parts.next().expect("allowlist file").to_string(),
                parts.next().expect("allowlist fn").to_string(),
            )
        })
        .collect();

    let mut ungated: Vec<(String, String, usize)> = Vec::new();
    let mut gated_hits: HashMap<String, bool> = MUST_BE_GATED
        .iter()
        .map(|n| ((*n).to_string(), false))
        .collect();

    for path in files {
        let rel = rel_src(&path, root);
        if skip_path(&rel) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let text = strip_test_mod(&raw);
        let lines: Vec<&str> = text.lines().collect();

        // Pair every write-SQL line with the nearest preceding `fn`
        // (impl methods sit at indent 4; do not swallow them as nested
        // inside an earlier indent-0 helper).
        let mut starts: Vec<(usize, String)> = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if let Some((_, name)) = is_fn_start(line) {
                starts.push((idx, name));
            }
        }
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for (idx, line) in lines.iter().enumerate() {
            if !write_sql_line(line) {
                continue;
            }
            let Some(&(start, ref name)) = starts.iter().rev().find(|(s, _)| *s <= idx) else {
                continue;
            };
            // #3484 — write SQL held in a module/impl-level `const`/`static`
            // item is not inside the preceding fn; attributing it there
            // flagged `embed_skip::from_stored` for `SQL_INSERT_IGNORE`.
            // (Const-reference tracking, so the fn that EXECUTES the const
            // is scanned instead, is #3485.)
            let fn_indent = lines[start].len() - lines[start].trim_start().len();
            let item_boundary_between = lines[start + 1..=idx].iter().any(|l| {
                let indent = l.len() - l.trim_start().len();
                let t = l.trim_start();
                let t = t
                    .strip_prefix("pub(crate) ")
                    .or_else(|| t.strip_prefix("pub "))
                    .unwrap_or(t);
                indent <= fn_indent
                    && (t.starts_with("const ")
                        || t.starts_with("static ")
                        || t.starts_with("mod "))
            });
            if item_boundary_between {
                continue;
            }
            let key = (rel.clone(), name.clone());
            if !seen.insert(key.clone()) {
                continue;
            }
            if is_test_fn(&lines, start)
                || name.starts_with("migrate_v")
                || name.starts_with("test_")
            {
                continue;
            }
            let end = starts
                .iter()
                .find(|(s, _)| *s > start)
                .map_or(lines.len(), |(s, _)| *s);
            let body = &lines[start..end];
            let has_gate = body
                .iter()
                .any(|l| GATE_MARKERS.iter().any(|g| l.contains(g)));
            if has_gate {
                if let Some(flag) = gated_hits.get_mut(name) {
                    *flag = true;
                }
                continue;
            }
            if allow.contains(&key) {
                continue;
            }
            ungated.push((rel.clone(), name.clone(), start + 1));
        }
    }

    let mut missing_required = Vec::new();
    for (name, hit) in &gated_hits {
        if !hit {
            missing_required.push(name.clone());
        }
    }
    missing_required.sort();

    let mut extra: Vec<String> = ungated
        .iter()
        .map(|(f, n, line)| format!("{f}:{line} {n}"))
        .collect();
    extra.sort();

    assert!(
        missing_required.is_empty(),
        "B7 required functions are not gated: {}",
        missing_required.join(", ")
    );
    assert!(
        extra.is_empty(),
        "B7 structural completeness: write-SQL functions are neither gated nor allowlisted:\n  {}\n(add a gate or a reviewed ALLOWLIST row)",
        extra.join("\n  ")
    );

    let sqlite_src = fs::read_to_string(root.join("src/storage/mod.rs")).expect("storage/mod.rs");
    let pg_src = fs::read_to_string(root.join("src/store/postgres.rs")).expect("postgres.rs");
    let allow_txt = include_str!("record_stop_b7_allowlist.txt");
    let mut parity_fail = Vec::new();
    for (sqlite_fn, pg_fn) in SQLITE_PG_TWINS {
        if !fn_body_has_gate(&sqlite_src, sqlite_fn) {
            continue;
        }
        if !fn_body_has_gate(&pg_src, pg_fn) {
            parity_fail.push(format!("sqlite {sqlite_fn} is gated but pg {pg_fn} is not"));
        }
        let exempt = allow_txt.lines().any(|l| {
            l.starts_with("src/store/postgres.rs\t") && l.ends_with(&format!("\t{pg_fn}"))
        });
        if exempt {
            parity_fail.push(format!(
                "pg {pg_fn} is allowlisted while sqlite twin {sqlite_fn} gates — remove from allowlist"
            ));
        }
    }
    assert!(
        parity_fail.is_empty(),
        "B7 pg/sqlite gate parity failures:\n  {}",
        parity_fail.join("\n  ")
    );
}
