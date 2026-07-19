// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]
// The `BOOT_LOCK` std `Mutex` is a cross-test serialiser held across the
// `run()` `.await` so two tests cannot race the process-wide lineage atomics /
// global tracing subscriber. There is no real contention (both tests are the
// only holders and the guarded section is short), so an async-aware mutex buys
// nothing; this mirrors the sanctioned pattern in `tests/v070_a1_authn.rs`.
#![allow(clippy::await_holding_lock)]

//! #2233 — production boot-seed of the v75 lineage-DAG master flag.
//!
//! `AppConfig::resolve_storage()` resolves `lineage_dag` (compiled default
//! `true`) + `consolidate_tombstone_sources`, but until #2233 the resolved
//! values were DISCARDED at the `daemon_runtime::run` production boot funnel
//! (`let _ = (resolved_storage.lineage_dag, …)`), so the process-wide atomic
//! `crate::config::lineage_dag_enabled()` read the unseeded `false` default in
//! every production process (serve / mcp / CLI). The v75 `source_cid` /
//! `target_cid` mirror, the acyclicity guard, and the lineage query surface
//! were therefore all silently INERT despite the documented `true` default —
//! the #2233 defaults-lie.
//!
//! These tests exercise the REAL production boot path
//! (`ai_memory::daemon_runtime::run`). Because this is an INTEGRATION-test
//! binary, the `ai_memory` lib is linked WITHOUT `cfg(test)`, so the
//! `#[cfg(not(test))]`-gated seed in `run()` fires exactly as it does in the
//! shipped `ai-memory` binary (the gate exists only so the lib's own
//! `cargo test --lib` `run()` dispatch tests do not flip the behavior-changing
//! process-wide atomic ON for a concurrent storage/consolidate unit test).
//!
//! Pinned here:
//!  * `boot_seed_reflects_resolved_config` — after a production-shaped
//!    `run()` boot, `lineage_dag_enabled()` reflects the resolved config
//!    (`true` by default; `false` when `[storage].lineage_dag = false`; the
//!    sub-flag independently reflects `[storage].consolidate_tombstone_sources`).
//!  * `mirror_population_fires_after_production_boot` — the v75
//!    `memory_links.source_cid` / `target_cid` content-id mirror actually
//!    populates on a link write AFTER a production boot (the feature is no
//!    longer inert), contrasted against the byte-identical-legacy inert state
//!    with the flag forced off.
//!
//! ## Concurrency
//!
//! The lineage flags are process-wide `AtomicBool`s and `run()` installs the
//! global tracing subscriber + seeds several process-wide `OnceLock`s, so both
//! tests serialize on a file-local `Mutex`.

use std::path::Path;
use std::sync::Mutex;

use ai_memory::config::{AppConfig, StorageSection};
use ai_memory::daemon_runtime::{Cli, run};
use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use clap::Parser as _;

/// Serializes the two tests: both drive `run()` (global subscriber + process
/// atomics) and read the shared process-wide lineage atomics.
static BOOT_LOCK: Mutex<()> = Mutex::new(());

fn boot_guard() -> std::sync::MutexGuard<'static, ()> {
    BOOT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drive the real production boot funnel with a read-only `stats` command
/// against a fresh file-backed DB. `run()` resolves storage config and (in a
/// non-`cfg(test)` lib build — which is the case for this integration binary)
/// seeds the lineage atomics before dispatching the command.
async fn production_boot(cfg: &AppConfig) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("boot-seed-2233.db");
    let cli = Cli::try_parse_from(["ai-memory", "--db", db_path.to_str().unwrap(), "stats"])
        .expect("parse cli");
    run(cli, cfg)
        .await
        .expect("production boot (stats) dispatch");
}

/// AppConfig whose `[storage]` section pins the lineage flags explicitly, so
/// the resolver's env layer is irrelevant and the test is deterministic
/// regardless of any ambient `AI_MEMORY_LINEAGE_DAG` in the CI environment.
fn cfg_with_lineage(lineage: Option<bool>, tombstone: Option<bool>) -> AppConfig {
    AppConfig {
        storage: Some(StorageSection {
            lineage_dag: lineage,
            consolidate_tombstone_sources: tombstone,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn boot_seed_reflects_resolved_config() {
    let _g = boot_guard();

    // (1) Compiled default: master ON, sub-flag tracks the master.
    production_boot(&AppConfig::default()).await;
    assert!(
        ai_memory::config::lineage_dag_enabled(),
        "compiled-default production boot must seed lineage_dag_enabled() = true \
         (the documented `true` default; pre-#2233 this read the unseeded false)"
    );
    assert!(
        ai_memory::config::consolidate_tombstone_sources_enabled(),
        "default sub-flag tracks the master (both on) after production boot"
    );

    // (2) Explicitly configured OFF: the seed reflects config, not a hardcoded
    //     posture — `false` restores byte-identical legacy behavior.
    production_boot(&cfg_with_lineage(Some(false), None)).await;
    assert!(
        !ai_memory::config::lineage_dag_enabled(),
        "`[storage].lineage_dag = false` production boot must seed OFF"
    );
    assert!(
        !ai_memory::config::consolidate_tombstone_sources_enabled(),
        "sub-flag is additionally gated by the master; master OFF ⇒ sub-flag reads OFF"
    );

    // (3) Master ON, sub-flag independently OFF: the two flags are seeded
    //     independently from their resolved values.
    production_boot(&cfg_with_lineage(Some(true), Some(false))).await;
    assert!(
        ai_memory::config::lineage_dag_enabled(),
        "master re-seeded ON reflects config"
    );
    assert!(
        !ai_memory::config::consolidate_tombstone_sources_enabled(),
        "sub-flag seeded OFF is honored even when the master is ON"
    );

    // Restore the process-wide default posture so a later test in this binary
    // (which shares the atomics) is not surprised by residue.
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
}

/// A memory with an EXPLICIT `created_at` so the acyclicity guard's strict `>`
/// compare is deterministic (child newer than parent).
fn make_mem(id: &str, title: &str, content: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        namespace: "lineage-boot-2233".to_string(),
        tier: Tier::Mid,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        ..Default::default()
    }
}

/// Write A (older) and a reflection R (newer), link `R --reflects_on--> A`, and
/// return the edge's `(source_cid, target_cid)` mirror.
fn write_reflects_edge(conn: &rusqlite::Connection) -> (Option<String>, Option<String>) {
    let a = "00000000-0000-0000-0000-00000000aa01";
    let r = "00000000-0000-0000-0000-00000000bb02";
    db::insert(
        conn,
        &make_mem(a, "A", "base a", "2026-01-01T00:00:00+00:00"),
    )
    .unwrap();
    db::insert(
        conn,
        &make_mem(r, "R", "reflection", "2026-03-01T00:00:00+00:00"),
    )
    .unwrap();
    db::create_link(conn, r, a, "reflects_on").unwrap();
    conn.query_row(
        "SELECT source_cid, target_cid FROM memory_links WHERE source_id = ?1 AND target_id = ?2",
        [r, a],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn mirror_population_fires_after_production_boot() {
    let _g = boot_guard();

    // Baseline: with the flag forced OFF (byte-identical legacy), a lineage
    // edge binds NULL cids — the v75 mirror is inert. This is the state the
    // whole feature was stuck in across every production process pre-#2233.
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
    {
        let conn = db::open(Path::new(":memory:")).expect("open in-memory db");
        let (src, tgt) = write_reflects_edge(&conn);
        assert!(
            src.is_none() && tgt.is_none(),
            "flag OFF ⇒ v75 cid mirror is inert (source_cid/target_cid bind NULL)"
        );
    }

    // Now run the REAL production boot funnel (default config ⇒ master ON).
    // Pre-#2233 this was a no-op discard and the mirror stayed inert forever.
    production_boot(&AppConfig::default()).await;
    assert!(
        ai_memory::config::lineage_dag_enabled(),
        "production boot must have seeded the lineage-DAG master flag ON"
    );

    // After the production boot, the SAME link write now populates the v75
    // content-id mirror — the feature is live, not inert.
    {
        let conn = db::open(Path::new(":memory:")).expect("open in-memory db");
        let a = "00000000-0000-0000-0000-00000000aa01";
        let (src, tgt) = write_reflects_edge(&conn);
        let a_cid: Option<String> = conn
            .query_row("SELECT cid FROM memories WHERE id = ?1", [a], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            src.is_some(),
            "after production boot the edge must carry the source cid mirror \
             (v75 feature is no longer inert)"
        );
        assert_eq!(
            tgt, a_cid,
            "edge target_cid mirrors memories.cid at link-creation time after boot"
        );
    }

    // Restore the default posture for any sibling test.
    ai_memory::config::set_lineage_dag(false);
    ai_memory::config::set_consolidate_tombstone_sources(false);
}
