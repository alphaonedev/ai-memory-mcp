// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2577 — mechanical funnel census for the recall-path
//! query-embedding budget.
//!
//! **Why a census and not just a behavioural test.** `#2445` learned this
//! the hard way with `tests/db_open_funnel_ceiling_2445.rs`: `db::open` was
//! the funnel every interface BOOT crossed but NOT the funnel every WRITE
//! crossed, and four production paths bypassed it entirely. The same shape
//! applies here — a behavioural test proves the funnel bounds the call it
//! exercises, it does NOT prove that a future call site went through the
//! funnel at all. A new `emb.embed_query(...)` added to a read path six
//! months from now would silently reintroduce the unbounded 30 s hang and
//! every behavioural test would still pass.
//!
//! So: every production `embed_query` call site in `src/` must be either
//! the bounded funnel (`crate::embeddings::recall_query_embedding`) or the
//! funnel's own internals. There is currently NO allowlist, and adding one
//! should be a deliberate, justified act.

use std::path::Path;

/// The single bounded funnel every read-path query embedding crosses.
const FUNNEL: &str = "recall_query_embedding";

/// The only file permitted to call `embed_query` directly: it DEFINES the
/// funnel and the trait, so its internal calls are the implementation.
const FUNNEL_OWNER: &str = "embeddings.rs";

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// No production code outside the funnel's owning module may call
/// `embed_query` directly — it must go through the bounded funnel.
#[test]
fn every_production_embed_query_goes_through_the_bounded_funnel_2577() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty(), "no source files found under {src:?}");

    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        if file
            .file_name()
            .is_some_and(|n| n.to_string_lossy() == FUNNEL_OWNER)
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        // Skip in-src `#[cfg(test)]` bodies: a test double is free to call
        // the trait method directly. Mirrors the production-vs-test
        // boundary used by `scripts/check-vendor-literals.sh`.
        let production = text.split("mod tests {").next().unwrap_or(&text);

        for (idx, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            // `embed_query_bounded` is the trait method the funnel itself
            // dispatches to; a direct `embed_query(` is the unbounded one.
            let unbounded = line.contains("embed_query(")
                && !line.contains("embed_query_bounded(")
                && !line.contains("fn embed_query(");
            if unbounded {
                violations.push(format!("{}:{}: {}", file.display(), idx + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "these production sites call `embed_query` directly instead of the \
         bounded funnel `{FUNNEL}` (#2577). An unbounded embed on a read \
         path hangs that read for the full 30 s GENERATE_TIMEOUT, and on \
         MCP stdio it blocks EVERY subsequent tool call. Route them \
         through the funnel:\n  {}",
        violations.join("\n  ")
    );
}

/// The funnel is actually reachable from the recall surfaces — a census
/// that only forbids the direct call would pass trivially if every
/// surface simply stopped embedding at all.
#[test]
fn the_recall_surfaces_call_the_funnel_2577() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for surface in [
        "handlers/recall.rs",
        "mcp/tools/recall.rs",
        "cli/recall.rs",
        "mcp/tools/load_family.rs",
        "handlers/transport.rs",
    ] {
        let path = src.join(surface);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(FUNNEL),
            "{surface} must obtain its query embedding through `{FUNNEL}` \
             so the #2577 budget + cache + degrade apply there"
        );
    }
}
