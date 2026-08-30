#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# CONFIG-1 full-spectrum AI-NHI acceptance harness runner (sqlite-bundled
# build). Compiles the default-feature `ai-memory` binary and runs the
# `tests/acceptance/acceptance_nhi_sqlite.rs` suite, which boots the compiled
# `ai-memory serve` sqlite daemon and drives the full tool surface end-to-end
# as ONE attested NHI identity (X-Agent-Id + Ed25519 write-attestation), plus
# the durability-across-restart, at-rest-encryption, crypto-erase, and MCP
# stdio smoke invariants.
#
# CONFIG-1 is the sqlite half — no Postgres needed. CONFIG-2 (federated pg +
# at-rest mesh) is a separate harness.
#
# Usage:
#   scripts/acceptance/run_sqlite.sh                 # run every test
#   scripts/acceptance/run_sqlite.sh <FILTER>        # run matching tests
#   AI_MEMORY_TEST_TIMING_BUDGET_MULT=3 scripts/acceptance/run_sqlite.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FILTER="${1:-}"

echo "==> CONFIG-1 acceptance (sqlite): building + running acceptance_nhi_sqlite"
# Single-threaded: each test spawns its own daemon child on an ephemeral port
# and the suite is subprocess-heavy; --test-threads=1 keeps port pressure and
# peak memory low without changing what is asserted.
exec cargo test --test acceptance_nhi_sqlite "$FILTER" -- --nocapture --test-threads=1
