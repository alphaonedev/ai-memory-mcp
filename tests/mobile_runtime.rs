// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — mobile-runtime test entry.
//
// This is the Cargo-integration-test binary that wraps the scoped
// mobile-test subset under `tests/mobile/`. The submodules carry the
// actual test functions; this file just `mod`-includes them so they
// land in a single test binary (cuts compile + link cost ~5x on the
// runner vs. one binary per submodule).
//
// Tests are `#[cfg]`-gated by selection criterion, not by target_os.
// On a host runner (linux / macOS / windows during normal CI), each
// test runs against the host's file-system / sqlite / network stack
// and serves as a smoke that the harness itself compiles + executes.
// On a mobile runner (iOS Simulator via `.github/workflows/mobile-
// runtime.yml`'s ios-sim job, Android emulator via the android-emu
// job), the tests run against the device sandbox + device sqlite +
// device tcp stack.
//
// Selection rationale: see `tests/mobile/README.md`.

#[path = "mobile/harness.rs"]
mod harness;

#[path = "mobile/tests_fs_sandbox.rs"]
mod tests_fs_sandbox;

#[path = "mobile/tests_sqlite_fts.rs"]
mod tests_sqlite_fts;

#[path = "mobile/tests_hnsw_recall.rs"]
mod tests_hnsw_recall;

#[path = "mobile/tests_embedder_cpu.rs"]
mod tests_embedder_cpu;

#[path = "mobile/tests_llm_tls.rs"]
mod tests_llm_tls;
