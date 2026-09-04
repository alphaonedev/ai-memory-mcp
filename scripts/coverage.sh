#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/coverage.sh
#
# v0.9.0 pre-GA (#1853) flake-hardening — a discoverable, documented local
# wrapper that runs `cargo llvm-cov` with the EXACT same invocation as
# `.github/workflows/coverage.yml`'s "Generate coverage JSON" step, then the
# same "Enforce per-module thresholds" step.
#
# WHY THIS EXISTS: `cargo llvm-cov` runs the whole test binary suite under
# instrumentation. The `sal-postgres` feature's tests share ONE
# `ai_memory_test` database with no per-test schema isolation (see the
# `--test-threads=1` comment in coverage.yml, v0.8.0 #1709 SHIP-HARDEN): two
# postgres-backed tests running CONCURRENTLY under llvm-cov can deadlock on
# shared table/index locks (postgres `40P01`) or otherwise race on shared
# rows, surfacing as a spurious local coverage-run failure that CI's serial
# `-- --test-threads=1` never hits. Before this script existed, a
# contributor/agent running `cargo llvm-cov --features sal,sal-postgres ...`
# locally WITHOUT the trailing `-- --test-threads=1` would get exactly that
# class of false failure and could misdiagnose it as a product bug. This
# wrapper is the single discoverable place that pins the serialisation so
# nobody has to rediscover the coverage.yml comment by hand.
#
# Usage:
#   scripts/coverage.sh
#     - runs the full instrumented sweep + threshold check, exit 0 on PASS.
#   AI_MEMORY_TEST_POSTGRES_URL=postgres://... scripts/coverage.sh
#     - point only at a disposable scratch Postgres (PG16 + age + vector
#       extensions) so the sal-postgres suite executes instead of skipping.
#       The explicitly aggregated v96 proof mutates the memories.embedding
#       column's DDL and restores it during teardown; never target a live or
#       shared database. Unset = postgres-gated
#       tests self-skip via their `postgres_url()` guard (see
#       tests/common::postgres_url), same as any other postgres-gated test.
#   scripts/coverage.sh --no-threshold-check
#     - generate coverage/current.json only; skip the threshold gate (useful
#       when iterating on a single module's tests before a full sweep).
#
# Mirrors (byte-for-byte on the llvm-cov invocation) the "Generate coverage
# JSON" + "Enforce per-module thresholds" steps in
# `.github/workflows/coverage.yml`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_THRESHOLDS=0
if [[ "${1:-}" == "--no-threshold-check" ]]; then
    SKIP_THRESHOLDS=1
fi

if ! command -v cargo-llvm-cov >/dev/null 2>&1 && ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "scripts/coverage.sh: cargo-llvm-cov is not installed." >&2
    echo "  Install it with: cargo install cargo-llvm-cov" >&2
    echo "  (CI installs it via taiki-e/install-action@cargo-llvm-cov.)" >&2
    exit 1
fi

mkdir -p coverage

echo "scripts/coverage.sh: running cargo llvm-cov --features sal,sal-postgres --lib --tests --workspace -- --test-threads=1"
if [[ -z "${AI_MEMORY_TEST_POSTGRES_URL:-}" ]]; then
    echo "scripts/coverage.sh: AI_MEMORY_TEST_POSTGRES_URL is unset — the sal-postgres" >&2
    echo "  suite will self-skip (postgres_url() guard) rather than exercise the" >&2
    echo "  postgres backend. Set it only to a disposable scratch PG16 (+ age +" >&2
    echo "  vector extensions) to match CI: the aggregated v96 proof mutates the" >&2
    echo "  memories.embedding DDL before restoring it. Never use a live/shared DB." >&2
fi

# v0.8.0 #1709 SHIP-HARDEN — `-- --test-threads=1` is REQUIRED, not optional:
# see the header comment above and the identical rationale in
# .github/workflows/coverage.yml.
cargo llvm-cov \
    --no-report \
    --features sal,sal-postgres \
    --lib --tests \
    --workspace \
    -- --test-threads=1

# #3496 — the v96 conversion proof is intentionally ignored by ordinary test
# sweeps because it mutates Postgres DDL. This coverage wrapper owns a serial,
# explicitly configured database, so aggregate that behavior/security proof
# before rendering the report. `--no-clean` preserves the first sweep's raw
# profiles; this named filter does not broaden execution to unrelated ignored
# tests. Without an explicitly supplied database, retain this wrapper's
# documented self-skip behavior. Exact CI-equivalent floors require Postgres.
if [[ -n "${AI_MEMORY_TEST_POSTGRES_URL:-}" ]]; then
    cargo llvm-cov \
        --no-clean \
        --features sal,sal-postgres \
        --lib --workspace \
        --json \
        --output-path coverage/current.json \
        -- schema_init_postgres_embedding_dim_conversion \
           --ignored --test-threads=1
else
    echo "scripts/coverage.sh: PostgreSQL v96 conversion coverage not aggregated;" >&2
    echo "  exact CI-equivalent module floors require AI_MEMORY_TEST_POSTGRES_URL." >&2
    cargo llvm-cov report \
        --workspace \
        --json \
        --output-path coverage/current.json
fi

if [[ "$SKIP_THRESHOLDS" -eq 1 ]]; then
    echo "scripts/coverage.sh: --no-threshold-check set — skipping coverage/check-thresholds.sh"
    echo "scripts/coverage.sh: coverage JSON written to coverage/current.json"
    exit 0
fi

bash coverage/check-thresholds.sh \
    coverage/thresholds.toml \
    coverage/current.json
