// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8687 — class guard for the atomise-worker test gate.
//!
//! Invariant: every wait on the atomise worker in the touched test binaries is
//! deterministic (a join or an awaited gate), no `std::thread::sleep` runs in
//! the shared gate helper (it is called from tokio worker threads,
//! CONCURRENCY-22), and the binaries share ONE gate helper.

use std::path::{Path, PathBuf};

const GATE_HELPER: &str = "tests/common/atomise_gate.rs";
const CORE_TESTS: &str = "tests/auto_atomise/core.rs";
const HTTP_2984: &str = "tests/atomise_async_http_write_2984.rs";
const FORM_2: &str = "tests/form_2_synchronous_atomise.rs";
/// The blocking sleep that must never appear in the gate helper.
const BLOCKING_SLEEP: &str = "std::thread::sleep";
/// The duplicate gate type retired by the port onto the shared helper.
const DUPLICATE_GATE_TYPE: &str = "struct ProviderGate";
/// The wall-clock poll the atom-landing waits must not use.
const WALL_CLOCK_POLL: &str = "poll_until(";

fn read(rel: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Source lines with `//` comment lines removed, so prose may mention a term.
fn code_lines(src: &str) -> Vec<&str> {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

#[test]
fn gate_helper_never_sleeps_a_thread_8687() {
    let code = code_lines(&read(GATE_HELPER)).join("\n");
    assert!(
        !code.contains(BLOCKING_SLEEP),
        "{GATE_HELPER} must not call {BLOCKING_SLEEP}: it runs on tokio worker threads (CONCURRENCY-22)"
    );
}

#[test]
fn only_one_atomise_gate_type_exists_8687() {
    let code = code_lines(&read(CORE_TESTS)).join("\n");
    assert!(
        !code.contains(DUPLICATE_GATE_TYPE),
        "{CORE_TESTS} must use {GATE_HELPER}, not define its own `{DUPLICATE_GATE_TYPE}`"
    );
    assert!(
        code.contains("common/atomise_gate.rs"),
        "{CORE_TESTS} must include {GATE_HELPER}"
    );
}

#[test]
fn atom_landing_waits_join_the_worker_not_a_wall_clock_poll_8687() {
    for rel in [HTTP_2984, FORM_2] {
        let code = code_lines(&read(rel)).join("\n");
        assert!(
            !code.contains(WALL_CLOCK_POLL),
            "{rel} must join the worker (spawn_joinable), not poll on a wall-clock deadline"
        );
        assert!(
            code.contains("spawn_joinable"),
            "{rel} must spawn the worker with spawn_joinable so the test can join it"
        );
    }
}
