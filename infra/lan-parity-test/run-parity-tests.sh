#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Runs the SAL-postgres cross-adapter parity tests against the scoped
# LAN-parity PG+AGE container exposed on 127.0.0.1:15432. Captures the
# full log under .local-runs/ for ship-gate audit trail.
#
# WHY `-- --test-threads=1` IS MANDATORY (do not remove):
#   The sal-postgres suite shares ONE `ai_memory_test` database with NO
#   per-test schema isolation (see CLAUDE.md §"Local coverage"). Running
#   it WITHOUT serialising threads lets two postgres-backed tests grab the
#   same advisory-lock key (`SELECT pg_advisory_lock($1)`) and DEADLOCK on
#   shared Postgres locks. This actually happened during the v1.0.0 cert
#   campaign: a parallel run wedged after 7007 passing tests, with a stack
#   of sessions blocked on `pg_advisory_lock` (the oldest stuck 6h27m),
#   until the run had to be killed. Serialising with `--test-threads=1`
#   is the same posture CI's coverage.yml already uses.
#
# The suite runs in TWO serialized passes: the default pass, then a second
# pass with `--include-ignored` so the `#[ignore]`-gated live-pg tests are
# exercised too. The script exits non-zero if EITHER pass fails.
#
# Pre-flight:
#   docker compose -f infra/lan-parity-test/docker-compose.yml up -d pg-age
#   (wait for pg-age healthcheck → healthy)
#
# Usage:
#   ./infra/lan-parity-test/run-parity-tests.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
LOG="$REPO_ROOT/.local-runs/lan-parity-${TIMESTAMP}.log"
mkdir -p "$(dirname "$LOG")"

PG_URL="postgres://ai_memory:ai_memory_test@127.0.0.1:15432/ai_memory_test"

echo "[lan-parity] PG URL: ${PG_URL/ai_memory_test@/<redacted>@}"
echo "[lan-parity] Log:    $LOG"
echo "[lan-parity] Pre-flight PG reach check..."
PGPASSWORD=ai_memory_test psql -h 127.0.0.1 -p 15432 -U ai_memory -d ai_memory_test \
    -c "SELECT 'pg+age reachable' AS status;" >/dev/null
echo "[lan-parity] PG+AGE reachable. Running cargo SAL-postgres tests..."
echo ""

# Pass 1 — default suite, serialized (--test-threads=1 mandatory; see header).
echo "[lan-parity] Pass 1/2: default suite (serialized)..."
AI_MEMORY_TEST_POSTGRES_URL="$PG_URL" \
AI_MEMORY_NO_CONFIG=1 \
cargo test --features sal,sal-postgres --release -- --test-threads=1 2>&1 | tee "$LOG"
EXIT_DEFAULT=${PIPESTATUS[0]}
echo ""
echo "[lan-parity] Pass 1/2 cargo exit code: $EXIT_DEFAULT"

# Pass 2 — #[ignore]-gated live-pg tests, serialized. Appended to the same log.
echo ""
echo "[lan-parity] Pass 2/2: #[ignore]-gated live-pg tests (serialized)..."
AI_MEMORY_TEST_POSTGRES_URL="$PG_URL" \
AI_MEMORY_NO_CONFIG=1 \
cargo test --features sal,sal-postgres --release -- --include-ignored --test-threads=1 2>&1 | tee -a "$LOG"
EXIT_IGNORED=${PIPESTATUS[0]}
echo ""
echo "[lan-parity] Pass 2/2 cargo exit code: $EXIT_IGNORED"

# Propagate failure from EITHER pass (non-zero if either did not pass).
EXIT=0
if [ "$EXIT_DEFAULT" -ne 0 ]; then
    EXIT="$EXIT_DEFAULT"
elif [ "$EXIT_IGNORED" -ne 0 ]; then
    EXIT="$EXIT_IGNORED"
fi

echo ""
echo "[lan-parity] Overall exit code: $EXIT (default=$EXIT_DEFAULT, ignored=$EXIT_IGNORED)"
echo "[lan-parity] Log preserved at: $LOG"
exit "$EXIT"
