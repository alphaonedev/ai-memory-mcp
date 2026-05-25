// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Regression pin for issue #1231: `entrypoint.plan-c.sh` must NOT
// `export AI_MEMORY_AGENT_ID=daemon` before exec'ing `ai-memory serve`.
//
// Why this pins:
//
// The wire-side validator `validate::validate_agent_id` (hardened by
// #977, commit `d81df2d7c`) rejects every member of
// `RESERVED_AGENT_IDS` (`daemon`, …) when supplied via env var or
// wire callers. The daemon's `serve` boot path takes the
// `AI_MEMORY_AGENT_ID` env-var branch (`identity::resolve_agent_id`
// step 2, `src/identity/mod.rs:153`) and bails with
//
//     Error: agent_id 'daemon' is reserved for internal use and
//     cannot be supplied by wire callers
//
// which crashloops the Docker container. The daemon's own
// self-signing keypair is loaded by the LITERAL label
// `DAEMON_KEYPAIR_LABEL = "daemon"` via
// `crate::identity::keypair::load("daemon", &dir)` — that path does
// NOT read `AI_MEMORY_AGENT_ID`, so removing the env-var override is
// safe. The fix is a 1-line delete in `entrypoint.plan-c.sh`; this
// test fails if any future change re-introduces the override.
//
// Companion test `validate_agent_id_rejects_daemon_reserved_1231`
// pins the inverse contract: `validate_agent_id("daemon")` must
// bail. If a future refactor weakens the reserved-id gate without
// also removing the entrypoint comment, the contract drift surfaces
// here too.

use std::fs;
use std::path::PathBuf;

fn entrypoint_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("entrypoint.plan-c.sh")
}

#[test]
fn entrypoint_does_not_export_agent_id_daemon_1231() {
    let path = entrypoint_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    // The fix removes the unconditional `export AI_MEMORY_AGENT_ID=daemon`
    // line. The contract is: no live (non-comment) line in the
    // entrypoint may set the env var to the reserved sentinel.
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim_start();
        // Skip comment-only lines so the explanatory # comment that
        // documents the gone-forever override stays legal.
        if line.starts_with('#') {
            continue;
        }
        assert!(
            !line.contains("AI_MEMORY_AGENT_ID=daemon"),
            "issue #1231 regression: entrypoint.plan-c.sh line {} sets \
             AI_MEMORY_AGENT_ID to the reserved sentinel `daemon`. \
             The wire validator (#977) rejects it and the daemon \
             container crashloops with `agent_id 'daemon' is reserved \
             for internal use and cannot be supplied by wire callers`. \
             Offending line: {raw:?}",
            lineno + 1
        );
    }
}

#[test]
fn validate_agent_id_rejects_daemon_reserved_1231() {
    // Pin the inverse contract — if a future refactor weakens the
    // reserved-id gate, the entrypoint fix becomes moot AND this
    // test fails, surfacing the drift before re-shipping.
    let err = ai_memory::validate::validate_agent_id("daemon")
        .expect_err("validate_agent_id must reject the reserved sentinel `daemon`");
    let msg = format!("{err}");
    assert!(
        msg.contains("reserved for internal use"),
        "issue #1231 regression: expected reject-reserved-id error, got: {msg}"
    );
}
