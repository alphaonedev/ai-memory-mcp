// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 P0-1 (#1869, T11) — caller-completeness regression guard.
//!
//! Recall is UNCONDITIONALLY pure as of v1.0.0 (#1953 removed the
//! deprecated `AI_MEMORY_RECALL_TOUCH_SYNC=1` legacy flag along with
//! every production call site of the explicit touch verbs
//! (`touch_many` / `touch_after_recall`) that used to sit on a RECALL
//! path). A NEW caller of either verb on a recall path would silently
//! reopen the purity hole the kill-test (`tests/recall_purity_p01.rs`)
//! closed — so this guard pins the per-file call-site census. Adding a
//! caller is allowed ONLY after review: either it stays off any recall
//! path, or it is a legitimate explicit-verb consumer (extend the pin
//! with a comment).
//!
//! The census counts textual invocations `touch_many(` /
//! `.touch_after_recall(` per production source file, excluding the
//! definitions themselves and comment lines. Test modules inside
//! production files are included deliberately (cheap, and a new
//! callsite anywhere still deserves review).

use std::collections::BTreeMap;
use std::path::Path;

fn census(pattern: &str, defs: &[&str]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            let mut count = 0_usize;
            for line in text.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if defs.iter().any(|d| trimmed.contains(d)) {
                    continue;
                }
                count += trimmed.matches(pattern).count();
            }
            if count > 0 {
                let rel = path
                    .strip_prefix(root.parent().unwrap())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, count);
            }
        }
    }
    out
}

#[test]
fn touch_many_call_sites_are_pinned() {
    let got = census("touch_many(", &["pub fn touch_many("]);
    let expected: BTreeMap<String, usize> = [
        // store/sqlite.rs — inside the ungated EXPLICIT verb
        // SqliteStore::touch_after_recall. v1.0.0 (#1953) removed the
        // ONLY recall-path callers (handlers/recall.rs sqlite HTTP
        // phase-2 writer + storage/mod.rs's db::recall /
        // apply_recall_post_ops), which were gated on the
        // now-deleted recall_touch_sync_enabled().
        ("src/store/sqlite.rs".to_string(), 1),
    ]
    .into();
    assert_eq!(
        got, expected,
        "touch_many call-site census drifted — a NEW caller on a recall path reopens \
         the #1869 purity hole. Review the new site: keep it off any recall path, or \
         extend this pin with a comment (explicit verb)."
    );
}

#[test]
fn touch_after_recall_call_sites_are_pinned() {
    let got = census(".touch_after_recall(", &["async fn touch_after_recall("]);
    let expected: BTreeMap<String, usize> = [
        // store/mod.rs — trait-default unit test.
        ("src/store/mod.rs".to_string(), 1),
        // store/postgres.rs — live_ explicit-verb tests (4 calls).
        ("src/store/postgres.rs".to_string(), 4),
        // store/sqlite.rs — explicit-verb unit tests (2 calls).
        ("src/store/sqlite.rs".to_string(), 2),
    ]
    .into();
    // v1.0.0 (#1953) removed the ONLY recall-path caller
    // (handlers/recall.rs postgres HTTP branch, gated on the
    // now-deleted recall_touch_sync_enabled()) — no entry remains.
    assert_eq!(
        got, expected,
        "touch_after_recall call-site census drifted — a NEW caller on a recall path \
         reopens the #1869 purity hole. Review the new site (see the touch_many pin)."
    );
}
