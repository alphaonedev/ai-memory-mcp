// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Regression pin for issue #1225: `.dockerignore` must exclude `.claude/`
// (Claude Code agent worktree caches) and `.cargo-target/` (the
// non-suffixed cargo target dir that sibling agent worktrees use).
//
// Why this pins:
// During the #1182 NO FAIL MISSION lan-parity stack-up against the
// final v0.7.0 binary (commit 1cb95bbe7), `docker compose -f
// infra/lan-parity-test/docker-compose.yml up -d --build` failed at
// the build-context COPY step with ResourceExhausted because the
// build daemon pulled in 36 GB from `.claude/worktrees/agent-*/
// .cargo-*-target/...` (sibling-agent multi-GB debug caches).
// The fix is a 3-line .dockerignore edit; this test fails if any
// future cleanup re-removes those lines.

use std::fs;
use std::path::PathBuf;

fn dockerignore_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".dockerignore")
}

#[test]
fn dockerignore_excludes_claude_worktrees_1225() {
    let path = dockerignore_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let lines: Vec<&str> = contents.lines().map(str::trim).collect();

    assert!(
        lines.contains(&".claude/"),
        "issue #1225 regression: .dockerignore is missing `.claude/`. \
         Without this exclusion, docker build pulls in multi-GB sibling-agent \
         worktree caches (.claude/worktrees/agent-*/.cargo-*-target/...) \
         and exhausts the Colima VM root fs. Lines: {lines:?}"
    );
}

#[test]
fn dockerignore_excludes_cargo_target_variant_1225() {
    let path = dockerignore_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let lines: Vec<&str> = contents.lines().map(str::trim).collect();

    // Belt-and-suspenders: even with `.claude/` excluded, sibling agents
    // occasionally use plain `.cargo-target/` (no suffix) as their target
    // dir at the repo root. The pre-existing wildcard `.cargo-*-target/`
    // does NOT match the suffix-less form because the `*` requires at
    // least the `-` separator. Explicit listing is the safe fix.
    assert!(
        lines.contains(&".cargo-target/"),
        "issue #1225 regression: .dockerignore should also exclude the \
         suffix-less `.cargo-target/` — the existing wildcard \
         `.cargo-*-target/` does NOT match it. Lines: {lines:?}"
    );
}
