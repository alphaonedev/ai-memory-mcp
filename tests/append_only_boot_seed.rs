// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PR-2 (#1823 G6) — production boot-seed of the append-only revision spine.
//!
//! `AppConfig::resolve_storage()` has always resolved `append_only`
//! (`AI_MEMORY_APPEND_ONLY` env > `[storage].append_only` > compiled default
//! `false`) and exposed it process-wide via
//! `crate::config::{set_append_only, append_only_enabled}` — but until PR-2
//! `set_append_only` had **ZERO non-test callers**. The resolved value was
//! never seeded at boot, so `append_only_enabled()` read only the unseeded
//! process atomic (`false`) in every shipped binary: `AI_MEMORY_APPEND_ONLY=1`
//! and `[storage].append_only=true` were BOTH inert, and every
//! `append_only_enabled()` branch site across `src/storage/mod.rs`,
//! `src/revisions.rs` and `src/store/postgres.rs` never executed in
//! production — a shipped, certification-adjacent forensic control that did
//! nothing (the #1823 append-only spine was dead code).
//!
//! PR-2 wires the seed at BOTH production boot funnels, and this guard is the
//! mechanical pin that keeps them wired:
//!
//!  1. `daemon_runtime::run` — the common serve / mcp / CLI config-resolution
//!     point, right beside the sibling `set_lineage_dag` seed (`#2233`).
//!  2. `src/main.rs` — the `#1889` synchronous pre-runtime phase, BEFORE the
//!     tokio runtime is built and BEFORE any CLI subcommand dispatches through
//!     `daemon_runtime::run`, so a CLI write process (`ai-memory store` /
//!     `undo-edit` / `curator` — the real offline-write attack surface) is
//!     armed the moment `main` resolves config.
//!
//! This is a STATIC-SOURCE guard (the `append_only_spine_guard_g6` precedent):
//! it asserts the seed CALL SITES exist in the source, so a future refactor
//! that removes either one re-reds CI and cannot silently re-introduce the
//! dead-code defect. The runtime behaviour those seeds unlock (the resolved
//! flag reaching `append_only_enabled()`) is covered by the arming this PR
//! ships; the durable-default invariant (resolved default `false`) is proven
//! separately. Both seeds resolve the value from config — a hardcoded
//! `true`/`false` would defeat the operator precedence, so the assertions pin
//! the resolved-expression form, not merely the function name.

use std::path::PathBuf;

/// Read a repo-relative source file (relative to `CARGO_MANIFEST_DIR`).
fn read_src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `daemon_runtime::run` boot funnel must seed the append-only spine from
/// the RESOLVED `[storage]` config, right beside the sibling lineage-DAG seed.
#[test]
fn set_append_only_seeded_in_daemon_run_beside_lineage() {
    let src = read_src("src/daemon_runtime.rs");

    let seed = "set_append_only(resolved_storage.append_only)";
    let seed_off = src.find(seed).unwrap_or_else(|| {
        panic!(
            "daemon_runtime::run must seed the append-only spine: \
             `crate::config::{seed}` not found — the #1823 spine reverts to dead code \
             (set_append_only would again have zero non-test callers)"
        )
    });

    // Prove it is the `run()` boot-seed block, not a stray reference.
    let run_off = src
        .find("pub async fn run(")
        .expect("daemon_runtime::run entry point present");
    assert!(
        seed_off > run_off,
        "the append-only seed must live inside the daemon_runtime::run boot funnel"
    );

    // Prove it sits RIGHT BESIDE the sibling lineage-DAG seed (the #2233
    // precedent this PR mirrors) — the append-only seed FIRST, then the
    // lineage-DAG seed, separated only by their two doc-comment blocks — so
    // both process-wide storage flags are seeded from one config-resolution
    // point. The 3 KiB window is the size of those two comment blocks; a
    // larger gap means an unrelated seed drifted between them.
    let lineage_off = src
        .find("set_lineage_dag(resolved_storage.lineage_dag)")
        .expect("lineage-DAG boot seed (set_lineage_dag) present in daemon_runtime::run");
    assert!(
        seed_off < lineage_off && lineage_off - seed_off < 3_000,
        "the append-only seed must sit right beside (just before) the lineage-DAG seed in the \
         run() boot block (append_only @ {seed_off}, lineage_dag @ {lineage_off})"
    );
}

/// `src/main.rs` must seed the append-only spine in the `#1889` pre-runtime
/// phase, BEFORE it dispatches to `daemon_runtime::run` — so a CLI write
/// process (the offline-write surface) is armed before any subcommand runs.
#[test]
fn set_append_only_seeded_in_main_before_cli_dispatch() {
    let src = read_src("src/main.rs");

    let seed = "set_append_only(app_config.resolve_storage().append_only)";
    let seed_off = src.find(seed).unwrap_or_else(|| {
        panic!(
            "src/main.rs must seed the append-only spine before CLI dispatch: \
             `config::{seed}` not found — a CLI write process (the real offline-write \
             attack surface) would boot with the #1823 spine un-armed"
        )
    });

    let dispatch_off = src
        .find("daemon_runtime::run(")
        .expect("src/main.rs dispatches to daemon_runtime::run");
    assert!(
        seed_off < dispatch_off,
        "the append-only seed in src/main.rs must run BEFORE the `daemon_runtime::run` dispatch \
         (the #1889 synchronous pre-runtime phase) — seed @ {seed_off}, dispatch @ {dispatch_off}"
    );
}
