// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1037 + #1104 — HNSW `rebuild()` sync-shim spin-wait
//! regression pin.
//!
//! Per #1037 the synchronous `VectorIndex::rebuild()` shim was
//! extended with a bounded spin-wait on the `rebuild_in_flight` atomic
//! AFTER `handle.join()` returns. This defends against the race where
//! `rebuild()` is called while an earlier `rebuild_async` is still
//! warming up — without the spin-wait the sync caller observed a stale
//! `active` graph.
//!
//! The audit lens (SR-6 #2) flagged that the existing
//! `d1_968_tests::rebuild_failure_leaves_active_unchanged_968` test
//! passes both BEFORE and AFTER the #1037 fix (it exercises the
//! no-op-handle path, not the new spin-wait window). This file pins
//! the spin-wait structurally so a future refactor that drops the
//! `while self.rebuild_in_flight.load(...)` loop fails this test.

#![allow(clippy::missing_panics_doc)]

/// v0.7.0 #1037 + #1104 — the sync `rebuild()` shim MUST carry the
/// bounded spin-wait on `rebuild_in_flight` after `handle.join()`.
///
/// Structural pin: reads `src/hnsw.rs` as a string and asserts the
/// load-bearing markers are present:
///   1. The `rebuild_in_flight.load(...)` predicate inside a `while`
///      loop.
///   2. The `REBUILD_WAIT_TIMEOUT` budget constant.
///   3. The `REBUILD_WAIT_POLL_INTERVAL` poll interval constant.
///   4. The `try_swap_warming()` call following the wait.
///
/// A future refactor that drops the spin-wait re-introduces the
/// pre-#1037 stale-graph race; the structural pin catches the
/// commit that removes the load-bearing pattern.
#[test]
fn sync_rebuild_waits_for_in_flight_async_rebuild_1037() {
    let body = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/hnsw.rs"))
        .expect("read src/hnsw.rs");

    // Marker 1: the spin-wait while loop on the atomic.
    assert!(
        body.contains("while self.rebuild_in_flight.load("),
        "#1037 + #1104: src/hnsw.rs MUST carry the bounded spin-wait \
         `while self.rebuild_in_flight.load(...)` in the sync rebuild \
         shim — a regression that removes it re-introduces the \
         pre-#1037 stale-graph race"
    );

    // Marker 2: the timeout budget constant must exist.
    assert!(
        body.contains("REBUILD_WAIT_TIMEOUT"),
        "#1037 + #1104: REBUILD_WAIT_TIMEOUT constant MUST be \
         declared so the spin-wait has a bounded budget. A bareback \
         spin-loop without a timeout could deadlock the sync caller."
    );

    // Marker 3: the poll interval constant must exist.
    assert!(
        body.contains("REBUILD_WAIT_POLL_INTERVAL"),
        "#1037 + #1104: REBUILD_WAIT_POLL_INTERVAL constant MUST be \
         declared so the spin-wait sleeps between polls rather than \
         hot-spinning the CPU."
    );

    // Marker 4: the swap call after the wait.
    assert!(
        body.contains("self.try_swap_warming();"),
        "#1037 + #1104: the sync rebuild shim MUST call \
         `self.try_swap_warming()` after the spin-wait so any \
         in-flight rebuild's warming graph swaps into active before \
         the sync caller returns"
    );

    // Marker 5: the JoinHandle.join() must happen BEFORE the spin-
    // wait (the wait is for any OTHER in-flight rebuild that this
    // sync caller didn't spawn). Sanity-check the ordering.
    let join_idx = body
        .find("let _ = handle.join();")
        .expect("#1037: handle.join() call must be present in the sync rebuild shim");
    let wait_idx = body
        .find("while self.rebuild_in_flight.load(")
        .expect("#1037: spin-wait must be present");
    assert!(
        join_idx < wait_idx,
        "#1037 + #1104: the spin-wait MUST follow `handle.join()` so \
         the sync caller observes a stable `active` graph regardless \
         of whether THIS call's handle was the no-op-instant variant \
         (another async rebuild already in flight) or the spawned-\
         build variant"
    );
}
