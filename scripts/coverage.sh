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
#     - point at a live Postgres (PG16 + age + vector extensions) so the
#       sal-postgres suite executes instead of skipping. Unset = those
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
    echo "  postgres backend. Set it to a live PG16 (+ age +vector extensions) instance" >&2
    echo "  to match CI's coverage.yml service-container run." >&2
fi

# v0.8.0 #1709 SHIP-HARDEN — `-- --test-threads=1` is REQUIRED, not optional:
# see the header comment above and the identical rationale in
# .github/workflows/coverage.yml.
cargo llvm-cov \
    --features sal,sal-postgres \
    --lib --tests \
    --json \
    --output-path coverage/current.json \
    --workspace \
    -- --test-threads=1

if [[ "$SKIP_THRESHOLDS" -eq 1 ]]; then
    echo "scripts/coverage.sh: --no-threshold-check set — skipping coverage/check-thresholds.sh"
    echo "scripts/coverage.sh: coverage JSON written to coverage/current.json"
    exit 0
fi

bash coverage/check-thresholds.sh \
    coverage/thresholds.toml \
    coverage/current.json
