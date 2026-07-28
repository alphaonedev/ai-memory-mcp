// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2391 — production-reachability gate for the federation outbound fanout.
//!
//! Every `pub async fn broadcast_*_quorum` in `src/federation/sync.rs` is an
//! OUTBOUND leg: the only mechanism by which a locally-applied write reaches
//! peers. A broadcast fn with no production caller is DEAD CODE that the
//! coverage floor still reports GREEN — because the integration suite calls it
//! directly. That combination is the worst possible failure mode for a
//! federation transport: the roadmap records the transport as "landed", the
//! coverage gate agrees, and two real nodes never exchange the payload.
//!
//! That is exactly what happened to `broadcast_checkpoint_resolution_quorum`
//! (FED-RQ-01 / #1936): the receive leg was fully wired
//! (`handlers::federation_receive` + `checkpoints::apply_inbound_resolution`),
//! the broadcast fn was written and tested, but no HTTP handler ever called it
//! — so the §25.2 epoch-freeze contract's ONLY cross-node mechanism was
//! structurally unreachable in production for the whole v1.0.0 line.
//!
//! This gate makes that class of defect impossible to reintroduce: a
//! `broadcast_*_quorum` must either have a caller OUTSIDE `src/federation/`
//! (i.e. a real handler that holds `AppState::federation`) or be deleted.
//! Calling it from the test suite does NOT satisfy the gate — that is the
//! precise blind spot being closed.
//!
//! R-203: this test FAILS at the parent of the #2391 fix commit (one
//! unreachable fn) and PASSES after the HTTP resolve surface is wired.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Strip `//`-style line comments so a doc-comment mention of a broadcast fn
/// is never mistaken for a call site. Block comments are not used for call
/// sites in this tree; line-comment stripping is sufficient and keeps the
/// scanner dependency-free.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Recursively collect `.rs` files under `dir`, skipping the `federation`
/// subtree (definition + unit-test sites) and inline `tests.rs` test modules.
/// What remains is production code that could hold an `AppState`.
fn collect_production_sources(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // The broadcast fns are DEFINED in src/federation/ and unit-tested
            // in src/federation/mod.rs — neither is a production caller.
            if path.file_name().is_some_and(|n| n == "federation") {
                continue;
            }
            collect_production_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            // `src/**/tests.rs` are inline `#[cfg(test)]` modules.
            if path.file_name().is_some_and(|n| n == "tests.rs") {
                continue;
            }
            if let Ok(src) = fs::read_to_string(&path) {
                out.push(strip_line_comments(&src));
            }
        }
    }
}

#[test]
fn issue_2391_every_broadcast_quorum_fn_has_a_production_caller() {
    let sync_src = fs::read_to_string("src/federation/sync.rs")
        .expect("read src/federation/sync.rs")
        .replace("\r\n", "\n");

    // Harvest every outbound fanout entry point by its declaration.
    let mut broadcasts: BTreeSet<String> = BTreeSet::new();
    for line in sync_src.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub async fn ") else {
            continue;
        };
        let Some(name) = rest.split('(').next() else {
            continue;
        };
        // `contains` rather than `ends_with` so suffixed variants
        // (`broadcast_store_quorum_with_embedding`) are held to the same bar.
        if name.starts_with("broadcast_") && name.contains("_quorum") {
            broadcasts.insert(name.to_string());
        }
    }

    assert!(
        broadcasts.len() >= 14,
        "expected the full outbound fanout surface (>=14 broadcast_*_quorum fns), \
         found {}: {broadcasts:?}. If the surface shrank, confirm the removal was \
         intentional and lower this floor in the same commit.",
        broadcasts.len(),
    );

    let mut production = Vec::new();
    collect_production_sources(Path::new("src"), &mut production);
    assert!(
        !production.is_empty(),
        "no production sources scanned — the test must run from the crate root"
    );

    let unreachable: Vec<&String> = broadcasts
        .iter()
        .filter(|name| {
            // A call site is `<name>(` — the trailing paren keeps
            // `broadcast_store_quorum` from matching
            // `broadcast_store_quorum_with_embedding`.
            let call = format!("{name}(");
            !production.iter().any(|src| src.contains(&call))
        })
        .collect();

    assert!(
        unreachable.is_empty(),
        "#2391 federation outbound leg unreachable: {unreachable:?} have NO caller \
         outside src/federation/, so they can never fire in production — even though \
         the test suite calls them directly and the coverage floor reports them GREEN. \
         Every broadcast_*_quorum must be wired to a handler that holds \
         AppState::federation, or be deleted. Do not satisfy this gate by adding a \
         test-only caller.",
    );
}
